(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*)

namespace B2R2.MiddleEnd.Executor

open System
open B2R2
open B2R2.ABI
open B2R2.FrontEnd

/// Provides the register and stack machinery that every executor state
/// accessor shares, over the value domain the accessor hands it. An accessor
/// keeps what `create` returns and forwards to it, so that none of this is
/// written twice.
[<RequireQualifiedAccess>]
module StateAccess =
  /// Word-sized register type of the given binary.
  let wordType (hdl: BinHandle) = hdl.ISA.WordSize |> WordSize.toRegType

  /// Word size of the given binary in bytes.
  let wordBytes hdl = wordType hdl |> RegType.toByteWidth

  (* The conventional Linux stack top for the word size: the end of the user
     address space, less a guard page. A word-size-independent constant would
     silently truncate on a narrower ISA, leaving a stack pointer that does not
     match what the accessor advertises. *)
  /// Stack top that initializing the default stack starts the stack at.
  let defaultStackTop (hdl: BinHandle) =
    match hdl.ISA.WordSize with
    | WordSize.Bit64 -> 0x7fffffffe000UL
    | _ -> 0xbfffe000UL

  /// Register ID the given name stands for. Every register factory normalizes
  /// the case of a name itself, so a name arrives here as it was spelled.
  let registerByName (hdl: BinHandle) (name: string) =
    hdl.RegisterFactory.GetRegisterID(name = name)

  let private orRaise (domain: IStateDomain<_, _, _>) what = function
    | Ok value ->
      value
    | Error e ->
      raise
        (InvalidOperationException $"Cannot {what}: {domain.FormatError e}.")

  let private tryGetStackPointer hdl (domain: IStateDomain<_, _, _>) =
    match (hdl: BinHandle).RegisterFactory.StackPointer with
    | Some rid ->
      domain.TryGetRegisterValue rid
      |> Result.bind (fun value -> domain.TryGetAddr value)
    | None ->
      Error(domain.RegisterUnavailable "Stack pointer")

  let private stackPointer hdl domain =
    tryGetStackPointer hdl domain |> orRaise domain "read the stack pointer"

  let private trySetStackPointer hdl (domain: IStateDomain<_, _, _>) addr =
    match (hdl: BinHandle).RegisterFactory.StackPointer with
    | Some rid -> domain.SetRegisterValue(rid, domain.WordValue addr) |> Ok
    | None -> Error(domain.RegisterUnavailable "Stack pointer")

  let private setStackPointer hdl domain addr =
    trySetStackPointer hdl domain addr
    |> orRaise domain "set the stack pointer"

  let private initializeFramePointer hdl (domain: IStateDomain<_, _, _>) =
    match (hdl: BinHandle).RegisterFactory.FramePointer with
    | Some rid ->
      domain.SetRegisterValue(rid, domain.WordValue(stackPointer hdl domain))
    | None ->
      raise
        (InvalidOperationException "Frame pointer register is unavailable.")

  let private getRegister hdl (domain: IStateDomain<_, _, _>) rid =
    let name = (hdl: BinHandle).RegisterFactory.GetRegisterName rid
    domain.TryGetRegisterValue rid |> orRaise domain $"read register {name}"

  let private zeroRegisters hdl (domain: IStateDomain<_, _, _>) rids =
    let zero = domain.Zero(wordType hdl)
    rids |> Array.iter (fun rid -> domain.SetRegisterValue(rid, zero))

  let private zeroRegistersByName hdl domain names =
    names |> Array.map (registerByName hdl) |> zeroRegisters hdl domain

  (* An ABI that passes this argument on the stack contributes no register for
     it, and one that takes fewer arguments than asked for contributes nothing
     at all; neither is a register write an accessor can carry out. *)
  let private setArgument hdl (domain: IStateDomain<_, _, _>) idx value =
    if idx < 0 then raise (ArgumentOutOfRangeException(nameof idx)) else ()
    match Array.tryItem idx (hdl: BinHandle).Conventions.Calling.IntArgs with
    | Some(ArgLocation.Reg rid) ->
      domain.SetRegisterValue(rid, value)
    | _ ->
      raise
        (InvalidOperationException
          $"Argument {idx} is not passed in a register under this ABI.")

  let private getReturnValue (hdl: BinHandle) domain =
    getRegister hdl domain hdl.Conventions.Calling.IntReturnRegister

  let private allocateStackBuffer hdl domain size =
    if size < 0 then raise (ArgumentOutOfRangeException(nameof size)) else ()
    let addr = stackPointer hdl domain - uint64 size
    setStackPointer hdl domain addr
    addr

  let private tryPushToStack hdl (domain: IStateDomain<_, _, _>) value =
    match tryGetStackPointer hdl domain with
    | Error e ->
      Error e
    | Ok sp ->
      let addr = sp - uint64 (wordBytes hdl)
      trySetStackPointer hdl domain addr
      |> Result.map (fun () ->
        domain.WriteValue(addr, value)
        addr)

  let private tryPopFromStack hdl (domain: IStateDomain<_, _, _>) =
    match tryGetStackPointer hdl domain with
    | Error e ->
      Error e
    | Ok addr ->
      match domain.TryReadValue(addr, wordType hdl) with
      | Ok value ->
        trySetStackPointer hdl domain (addr + uint64 (wordBytes hdl))
        |> Result.map (fun () -> value)
      | Error e ->
        Error e

  let private readValue hdl (domain: IStateDomain<_, _, _>) addr typ =
    domain.TryReadValue(addr, typ)
    |> orRaise domain $"read a value at {addr:x}"

  /// Builds the shared machinery over the given value domain, for a state
  /// that runs against the given binary.
  let create hdl (domain: IStateDomain<'State, 'Value, 'Error>) =
    { new IStateAccessor<'State, 'Value, 'Error> with

        member _.State = domain.State

        member _.WordType = wordType hdl

        member _.WordBytes = wordBytes hdl

        member _.StackPointer = stackPointer hdl domain

        member _.DefaultStackTop = defaultStackTop hdl

        member _.WordValue value = domain.WordValue value

        member _.SetStackPointer addr = setStackPointer hdl domain addr

        member _.InitializeStack stackTop =
          setStackPointer hdl domain stackTop

        member _.InitializeDefaultStack() =
          setStackPointer hdl domain (defaultStackTop hdl)

        member _.InitializeFramePointer() = initializeFramePointer hdl domain

        member _.SetRegister(name: string, value) =
          domain.SetRegisterValue(registerByName hdl name, value)

        member _.SetRegister(rid: RegisterID, value) =
          domain.SetRegisterValue(rid, value)

        member _.GetRegister(name: string) =
          getRegister hdl domain (registerByName hdl name)

        member _.GetRegister(rid: RegisterID) = getRegister hdl domain rid

        member _.ZeroRegisters(names: string[]) =
          zeroRegistersByName hdl domain names

        member _.ZeroRegisters(rids: RegisterID[]) =
          zeroRegisters hdl domain rids

        member _.SetArgument(idx, value) = setArgument hdl domain idx value

        member _.GetReturnValue() = getReturnValue hdl domain

        member _.AllocateStackBuffer size =
          allocateStackBuffer hdl domain size

        member _.PushToStack value =
          tryPushToStack hdl domain value
          |> orRaise domain "push to the stack"

        member _.PopFromStack() =
          tryPopFromStack hdl domain |> orRaise domain "pop from the stack"

        member _.ReadValue(addr, typ) = readValue hdl domain addr typ

        member _.WriteValue(addr, value) = domain.WriteValue(addr, value)

        member _.TryGetStackPointer() = tryGetStackPointer hdl domain

        member _.TrySetStackPointer addr = trySetStackPointer hdl domain addr

        member _.TryPushToStack value = tryPushToStack hdl domain value

        member _.TryPopFromStack() = tryPopFromStack hdl domain }

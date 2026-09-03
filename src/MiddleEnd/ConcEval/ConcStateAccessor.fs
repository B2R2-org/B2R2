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

namespace B2R2.MiddleEnd.ConcEval

open System
open System.Text
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.Executor

/// Provides structured access to a concrete state.
type ConcStateAccessor(hdl: BinHandle, state: ConcState) as this =
  let regFactory = hdl.RegisterFactory
  let wordType = hdl.ISA.WordSize |> WordSize.toRegType
  let wordBytes = RegType.toByteWidth wordType
  let endian = hdl.ISA.Endian
  let cc = hdl.Conventions.Calling

  (* The conventional Linux stack top for the word size: the end of the user
     address space, less a guard page. A word-size-independent constant would
     silently truncate on a narrower ISA, leaving a stack pointer that does not
     match what this accessor advertises. *)
  let defaultStackTop =
    match hdl.ISA.WordSize with
    | WordSize.Bit64 -> 0x7fffffffe000UL
    | _ -> 0xbfffe000UL

  let wordValue (value: uint64) = BitVector(value, wordType)

  let registerByName (name: string) =
    regFactory.GetRegisterID(name = name.ToUpperInvariant())

  let getDefinedReg rid =
    match state.TryGetReg rid with
    | Def v ->
      v
    | Undef ->
      let name = regFactory.GetRegisterName rid
      raise (InvalidOperationException $"Register {name} is not initialized.")

  let readByte addr =
    match state.Memory.ByteRead addr with
    | ValueSome b ->
      b
    | ValueNone ->
      raise (InvalidOperationException $"Cannot read memory at {addr:x}.")

  let getStackPointerRegister () =
    match regFactory.StackPointer with
    | Some rid ->
      rid
    | None ->
      raise (InvalidOperationException
        "Stack pointer register is unavailable.")

  let getFramePointerRegister () =
    match regFactory.FramePointer with
    | Some rid ->
      rid
    | None ->
      raise (InvalidOperationException
        "Frame pointer register is unavailable.")

  let getStackPointer () =
    let bv = getStackPointerRegister () |> getDefinedReg
    bv.ToUInt64()

  let setStackPointer addr =
    let sp = getStackPointerRegister ()
    state.SetReg(sp, wordValue addr)

  let pushToStack value =
    let addr = getStackPointer () - uint64 wordBytes
    setStackPointer addr
    Memory.write addr value endian state.Memory
    addr

  let popFromStack () =
    let addr = getStackPointer ()
    let value =
      match Memory.read addr endian wordType state.Memory with
      | Ok v ->
        v
      | Error _ ->
        raise (InvalidOperationException $"Stack pop failed at {addr:x}.")
    setStackPointer (addr + uint64 wordBytes)
    value

  let tryGetStackPointer () =
    match regFactory.StackPointer with
    | Some rid ->
      match state.TryGetReg rid with
      | Def v -> Ok(v.ToUInt64())
      | Undef -> Error ErrorCase.InvalidRegister
    | None ->
      Error ErrorCase.InvalidRegister

  let trySetStackPointer addr =
    match regFactory.StackPointer with
    | Some rid -> state.SetReg(rid, wordValue addr) |> Ok
    | None -> Error ErrorCase.InvalidRegister

  let tryPushToStack value =
    match tryGetStackPointer () with
    | Error e ->
      Error e
    | Ok sp ->
      let addr = sp - uint64 wordBytes
      trySetStackPointer addr
      |> Result.map (fun () ->
        Memory.write addr value endian state.Memory
        addr)

  let tryPopFromStack () =
    match tryGetStackPointer () with
    | Error e ->
      Error e
    | Ok addr ->
      match Memory.read addr endian wordType state.Memory with
      | Ok value ->
        trySetStackPointer (addr + uint64 wordBytes)
        |> Result.map (fun () -> value)
      | Error e ->
        Error e

  let initializeFramePointer () =
    let fp = getFramePointerRegister ()
    state.SetReg(fp, wordValue (getStackPointer ()))

  let setRegisterByName name value = state.SetReg(registerByName name, value)

  let setRegister rid value = state.SetReg(rid, value)

  let getRegisterByName name = registerByName name |> getDefinedReg

  let getRegister rid = getDefinedReg rid

  let zeroRegistersByName names =
    let zero = BitVector.Zero wordType
    names |> Array.iter (fun name -> setRegisterByName name zero)

  let zeroRegisters rids =
    let zero = BitVector.Zero wordType
    rids |> Array.iter (fun rid -> setRegister rid zero)

  let setArgument idx value =
    if idx < 0 then raise (ArgumentOutOfRangeException(nameof idx)) else ()
    let rid = cc.IntArgRegister idx
    state.SetReg(rid, value)

  let getReturnValue () = cc.IntReturnRegister |> getDefinedReg

  let tryReadByte addr =
    match state.Memory.ByteRead addr with
    | ValueSome b -> Ok b
    | ValueNone -> Error ErrorCase.InvalidMemoryRead

  let rec collectCString (bytes: ResizeArray<byte>) addr idx maxLength =
    if idx >= maxLength then
      Error ErrorCase.InvalidFormat
    else
      match tryReadByte (addr + uint64 idx) with
      | Ok 0uy -> Ok(Encoding.ASCII.GetString(bytes.ToArray()))
      | Ok b -> bytes.Add b; collectCString bytes addr (idx + 1) maxLength
      | Error e -> Error e

  let readCString addr maxLength =
    if maxLength < 0 then raise (ArgumentOutOfRangeException(nameof maxLength))
    else ()
    collectCString (ResizeArray<byte>()) addr 0 maxLength

  let allocateStackBuffer size =
    if size < 0 then raise (ArgumentOutOfRangeException(nameof size)) else ()
    let addr = getStackPointer () - uint64 size
    setStackPointer addr
    addr

  /// Stack top that InitializeDefaultStack starts the stack at. The value
  /// depends on the word size of the binary this accessor was built from.
  member _.DefaultStackTop = defaultStackTop

  /// The underlying concrete state.
  member _.State = state

  /// Target word-sized register type.
  member _.WordType = wordType

  /// Target word size in bytes.
  member _.WordBytes = wordBytes

  /// Current stack pointer value.
  member _.StackPointer = getStackPointer ()

  /// Creates a word-sized concrete value.
  member _.WordValue value = wordValue value

  /// Set the current stack pointer value.
  member _.SetStackPointer addr = setStackPointer addr

  /// Initialize the stack pointer with the given stack top.
  member _.InitializeStack stackTop = setStackPointer stackTop

  /// Initialize the stack pointer with the default stack top.
  member _.InitializeDefaultStack() = setStackPointer defaultStackTop

  /// Initialize the frame pointer with the current stack pointer.
  member _.InitializeFramePointer() = initializeFramePointer ()

  /// Set a register value by name.
  member _.SetRegister(name: string, value) = setRegisterByName name value

  /// Set a register value by register ID.
  member _.SetRegister(rid: RegisterID, value) = setRegister rid value

  /// Get a register value by name.
  member _.GetRegister(name: string) = getRegisterByName name

  /// Get a register value by register ID.
  member _.GetRegister(rid: RegisterID) = getRegister rid

  /// Clear selected registers to zero.
  member _.ZeroRegisters(names: string[]) = zeroRegistersByName names

  /// Clear selected registers to zero.
  member _.ZeroRegisters(rids: RegisterID[]) = zeroRegisters rids

  /// Set an integer or pointer argument for the supported ABI.
  member _.SetArgument(idx, value) = setArgument idx value

  /// Get the return value for the supported ABI.
  member _.GetReturnValue() = getReturnValue ()

  /// Allocate a buffer from the current stack and return its address.
  member _.AllocateStackBuffer size = allocateStackBuffer size

  /// Push a word-sized value to the stack and return its address.
  member _.PushToStack value = pushToStack value

  /// Pop a word-sized value from the stack.
  member _.PopFromStack() = popFromStack ()

  /// Current stack pointer value, failing instead of raising when the stack
  /// pointer register is unavailable.
  member _.TryGetStackPointer() = tryGetStackPointer ()

  /// Sets the current stack pointer value, failing instead of raising when the
  /// stack pointer register is unavailable.
  member _.TrySetStackPointer addr = trySetStackPointer addr

  /// Pushes a word-sized value to the stack and returns its address, failing
  /// instead of raising when the stack pointer is unavailable.
  member _.TryPushToStack value = tryPushToStack value

  /// Pops a word-sized value from the stack, failing instead of raising when
  /// the stack pointer is unavailable or the memory read fails.
  member _.TryPopFromStack() = tryPopFromStack ()

  /// Push a word-sized pointer value to the stack and return its address.
  member _.PushPointer(value: Addr) = wordValue value |> pushToStack

  /// Pop a word-sized pointer value from the stack.
  member _.PopPointer() =
    let bv = popFromStack ()
    bv.ToUInt64()

  /// Write a word-sized pointer value to memory.
  member _.WritePointer(addr: Addr, value: Addr) =
    Memory.write addr (wordValue value) endian state.Memory

  /// Read a word-sized pointer value from memory.
  member _.ReadPointer(addr: Addr) =
    match Memory.read addr endian wordType state.Memory with
    | Ok v ->
      v.ToUInt64()
    | Error _ ->
      raise (InvalidOperationException $"Cannot read a pointer at {addr:x}.")

  /// Reads a value of the given type from memory.
  member _.ReadValue(addr: Addr, typ: RegType) =
    match Memory.read addr endian typ state.Memory with
    | Ok v ->
      v
    | Error _ ->
      raise (InvalidOperationException $"Cannot read a value at {addr:x}.")

  /// Writes a value to memory, using the type the value carries.
  member _.WriteValue(addr: Addr, value: BitVector) =
    Memory.write addr value endian state.Memory

  /// Write a concrete integer value to memory.
  member _.WriteInteger(addr: Addr, value: uint64, typ: RegType) =
    Memory.write addr (BitVector(value, typ)) endian state.Memory

  /// Write concrete bytes to memory.
  member _.WriteBytes(addr: Addr, bytes: byte[]) =
    bytes
    |> Array.iteri (fun idx b -> state.Memory.ByteWrite(addr + uint64 idx, b))

  /// Read concrete bytes from memory.
  member _.ReadBytes(addr: Addr, length: int) =
    if length < 0 then raise (ArgumentOutOfRangeException(nameof length))
    else ()
    Array.init length (fun idx -> readByte (addr + uint64 idx))

  /// Read a null-terminated ASCII string from memory. Reaching maxLength
  /// without a terminator is an error, not a truncation.
  member _.ReadCString(addr: Addr, maxLength: int) =
    match readCString addr maxLength with
    | Ok str ->
      str
    | Error _ ->
      raise (InvalidOperationException
        $"No string terminator within {maxLength} bytes at {addr:x}.")

  /// Reads a null-terminated ASCII string from memory, failing instead of
  /// raising when the memory is unreadable or has no terminator within
  /// maxLength bytes.
  member _.TryReadCString(addr: Addr, maxLength: int) =
    readCString addr maxLength

  interface IStateAccessor<ConcState, BitVector, ErrorCase> with

    member _.State = this.State

    member _.WordType = this.WordType

    member _.WordBytes = this.WordBytes

    member _.StackPointer = this.StackPointer

    member _.DefaultStackTop = this.DefaultStackTop

    member _.WordValue value = this.WordValue value

    member _.SetStackPointer addr = this.SetStackPointer addr

    member _.InitializeStack stackTop = this.InitializeStack stackTop

    member _.InitializeDefaultStack() = this.InitializeDefaultStack()

    member _.InitializeFramePointer() = this.InitializeFramePointer()

    member _.SetRegister(name: string, value) = this.SetRegister(name, value)

    member _.SetRegister(rid: RegisterID, value) = this.SetRegister(rid, value)

    member _.GetRegister(name: string) = this.GetRegister name

    member _.GetRegister(rid: RegisterID) = this.GetRegister rid

    member _.ZeroRegisters(names: string[]) = this.ZeroRegisters names

    member _.ZeroRegisters(rids: RegisterID[]) = this.ZeroRegisters rids

    member _.SetArgument(idx, value) = this.SetArgument(idx, value)

    member _.GetReturnValue() = this.GetReturnValue()

    member _.AllocateStackBuffer size = this.AllocateStackBuffer size

    member _.PushToStack value = this.PushToStack value

    member _.PopFromStack() = this.PopFromStack()

    member _.ReadValue(addr, typ) = this.ReadValue(addr, typ)

    member _.WriteValue(addr, value) = this.WriteValue(addr, value)

    member _.TryGetStackPointer() = this.TryGetStackPointer()

    member _.TrySetStackPointer addr = this.TrySetStackPointer addr

    member _.TryPushToStack value = this.TryPushToStack value

    member _.TryPopFromStack() = this.TryPopFromStack()

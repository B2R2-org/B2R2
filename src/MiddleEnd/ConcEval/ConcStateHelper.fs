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
open B2R2.MiddleEnd.ConcEval.EvalUtils
open B2R2.MiddleEnd.Executor

/// Provides convenience helpers for a concrete EvalState.
type ConcStateHelper(hdl: BinHandle, state: EvalState, os: OS) as this =
  static let defaultStackTop = 0x7fffffffe000UL

  let regFactory = hdl.RegisterFactory
  let wordType = hdl.File.ISA.WordSize |> WordSize.toRegType
  let wordBytes = RegType.toByteWidth wordType
  let endian = hdl.File.ISA.Endian

  let wordValue (value: uint64) = BitVector(value, wordType)

  let registerByName (name: string) =
    regFactory.GetRegisterID(name = name.ToUpperInvariant())

  let getDefinedReg rid =
    match state.TryGetReg rid with
    | Def v -> v
    | Undef ->
      let name = regFactory.GetRegisterName rid
      raise (InvalidOperationException $"Register {name} is not initialized.")

  let readByte addr =
    match state.Memory.ByteRead addr with
    | Ok b -> b
    | Error _ -> raise (InvalidMemException addr)

  let getStackPointerRegister () =
    match regFactory.StackPointer with
    | Some rid -> rid
    | None ->
      raise (InvalidOperationException
        "Stack pointer register is unavailable.")

  let getFramePointerRegister () =
    match regFactory.FramePointer with
    | Some rid -> rid
    | None ->
      raise (InvalidOperationException
        "Frame pointer register is unavailable.")

  let getStackPointer () =
    getStackPointerRegister ()
    |> getDefinedReg
    |> BitVector.ToUInt64

  let setStackPointer addr =
    let sp = getStackPointerRegister ()
    state.SetReg(sp, wordValue addr)

  let pushToStack value =
    let addr = getStackPointer () - uint64 wordBytes
    setStackPointer addr
    state.Memory.Write(addr, value, endian)
    addr

  let popFromStack () =
    let addr = getStackPointer ()
    let value =
      match state.Memory.Read(addr, endian, wordType) with
      | Ok v -> v
      | Error _ -> raise (InvalidMemException addr)
    setStackPointer (addr + uint64 wordBytes)
    value

  let initializeFramePointer () =
    let fp = getFramePointerRegister ()
    state.SetReg(fp, wordValue (getStackPointer ()))

  let setRegisterByName name value =
    state.SetReg(registerByName name, value)

  let setRegister rid value =
    state.SetReg(rid, value)

  let getRegisterByName name =
    registerByName name |> getDefinedReg

  let getRegister rid =
    getDefinedReg rid

  let zeroRegistersByName names =
    let zero = BitVector.Zero wordType
    names |> Array.iter (fun name -> setRegisterByName name zero)

  let zeroRegisters rids =
    let zero = BitVector.Zero wordType
    rids |> Array.iter (fun rid -> setRegister rid zero)

  let setArgument idx value =
    if idx < 0 then
      raise (ArgumentOutOfRangeException(nameof idx))
    let rid = CallingConvention.FunctionArgRegister(hdl, os, idx + 1)
    state.SetReg(rid, value)

  let getReturnValue () =
    CallingConvention.ReturnRegister hdl |> getDefinedReg

  let allocateStackBuffer size =
    if size < 0 then
      raise (ArgumentOutOfRangeException(nameof size))
    let addr = getStackPointer () - uint64 size
    setStackPointer addr
    addr

  new(hdl, state) = ConcStateHelper(hdl, state, OS.Linux)

  /// The underlying concrete state.
  member _.RawState = state

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

  /// Default stack top used by concrete states.
  static member DefaultStackTop = defaultStackTop

  /// Set a register value by name.
  member _.SetRegister(name: string, value) =
    setRegisterByName name value

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

  /// Push a word-sized pointer value to the stack and return its address.
  member _.PushPointer(value: Addr) =
    wordValue value |> pushToStack

  /// Pop a word-sized pointer value from the stack.
  member _.PopPointer() =
    popFromStack () |> BitVector.ToUInt64

  /// Write a word-sized pointer value to memory.
  member _.WritePointer(addr: Addr, value: Addr) =
    state.Memory.Write(addr, wordValue value, endian)

  /// Read a word-sized pointer value from memory.
  member _.ReadPointer(addr: Addr) =
    match state.Memory.Read(addr, endian, wordType) with
    | Ok v -> BitVector.ToUInt64 v
    | Error _ -> raise (InvalidMemException addr)

  /// Write a concrete integer value to memory.
  member _.WriteInteger(addr: Addr, value: uint64, typ: RegType) =
    state.Memory.Write(addr, BitVector(value, typ), endian)

  /// Write concrete bytes to memory.
  member _.WriteBytes(addr: Addr, bytes: byte[]) =
    bytes
    |> Array.iteri (fun idx b -> state.Memory.ByteWrite(addr + uint64 idx, b))

  /// Read concrete bytes from memory.
  member _.ReadBytes(addr: Addr, length: int) =
    if length < 0 then
      raise (ArgumentOutOfRangeException(nameof length))
    Array.init length (fun idx -> readByte (addr + uint64 idx))

  /// Read a null-terminated ASCII string from memory.
  member _.ReadCString(addr: Addr, maxLength: int) =
    if maxLength < 0 then
      raise (ArgumentOutOfRangeException(nameof maxLength))
    let bytes = ResizeArray<byte>()
    let mutable idx = 0
    let mutable finished = false
    while not finished && idx < maxLength do
      match readByte (addr + uint64 idx) with
      | 0uy -> finished <- true
      | b ->
        bytes.Add b
        idx <- idx + 1
    Encoding.ASCII.GetString(bytes.ToArray())

  interface IStateHelper<EvalState, BitVector> with

    member _.RawState = this.RawState

    member _.WordType = this.WordType

    member _.WordBytes = this.WordBytes

    member _.StackPointer = this.StackPointer

    member _.SetStackPointer addr = this.SetStackPointer addr

    member _.InitializeStack stackTop = this.InitializeStack stackTop

    member _.InitializeFramePointer() = this.InitializeFramePointer()

    member _.SetRegister(name: string, value) =
      this.SetRegister(name, value)

    member _.SetRegister(rid: RegisterID, value) =
      this.SetRegister(rid, value)

    member _.GetRegister(name: string) = this.GetRegister name

    member _.GetRegister(rid: RegisterID) = this.GetRegister rid

    member _.ZeroRegisters(names: string[]) = this.ZeroRegisters names

    member _.ZeroRegisters(rids: RegisterID[]) = this.ZeroRegisters rids

    member _.SetArgument(idx, value) = this.SetArgument(idx, value)

    member _.GetReturnValue() = this.GetReturnValue()

    member _.AllocateStackBuffer size = this.AllocateStackBuffer size

    member _.PushToStack value = this.PushToStack value

    member _.PopFromStack() = this.PopFromStack()

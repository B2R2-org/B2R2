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

/// Provides convenience helpers for a concrete EvalState.
type ConcStateHelper(hdl: BinHandle, state: EvalState, ?os: OS) =
  let regFactory = hdl.RegisterFactory
  let os = defaultArg os OS.Linux
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

  /// Exposes the underlying concrete evaluation state.
  member _.RawState with get() = state

  /// Target word-sized register type.
  member _.WordType with get() = wordType

  /// Target word size in bytes.
  member _.WordBytes with get() = wordBytes

  /// Current concrete stack pointer value.
  member _.StackPointer with get() =
    getStackPointerRegister ()
    |> getDefinedReg
    |> BitVector.ToUInt64

  /// Set the current concrete stack pointer value.
  member _.SetStackPointer addr =
    let sp = getStackPointerRegister ()
    state.SetReg(sp, wordValue addr)

  /// Initialize the stack pointer with the given stack top.
  member this.InitializeStack(stackTop: Addr) = this.SetStackPointer stackTop

  /// Initialize the frame pointer with the current stack pointer.
  member this.InitializeFramePointer() =
    let fp = getFramePointerRegister ()
    state.SetReg(fp, wordValue this.StackPointer)

  /// Set a register value by name.
  member _.SetRegister(name: string, value: BitVector) =
    state.SetReg(registerByName name, value)

  /// Set a register value by register ID.
  member _.SetRegister(rid: RegisterID, value: BitVector) =
    state.SetReg(rid, value)

  /// Get a register value by name.
  member _.GetRegister(name: string) = registerByName name |> getDefinedReg

  /// Get a register value by register ID.
  member _.GetRegister(rid: RegisterID) = getDefinedReg rid

  /// Set an integer or pointer argument for the supported concrete ABI.
  member _.SetArgument(idx, value: BitVector) =
    if idx < 0 then
      raise (ArgumentOutOfRangeException(nameof idx))
    let rid = CallingConvention.FunctionArgRegister(hdl, os, idx + 1)
    state.SetReg(rid, value)

  /// Get the return value for the supported concrete ABI.
  member _.GetReturnValue() =
    CallingConvention.ReturnRegister hdl |> getDefinedReg

  /// Allocate a buffer from the current stack and return its address.
  member this.AllocateStackBuffer size =
    if size < 0 then
      raise (ArgumentOutOfRangeException(nameof size))
    let addr = this.StackPointer - uint64 size
    this.SetStackPointer addr
    addr

  /// Push a word-sized pointer value to the stack and return its address.
  member this.PushPointer(value: Addr) =
    let addr = this.StackPointer - uint64 wordBytes
    this.SetStackPointer addr
    this.WritePointer(addr, value)
    addr

  /// Pop a word-sized pointer value from the stack.
  member this.PopPointer() =
    let addr = this.StackPointer
    let value = this.ReadPointer addr
    this.SetStackPointer(addr + uint64 wordBytes)
    value

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

  /// Clear selected registers to concrete zero.
  member this.ZeroRegisters(names: string[]) =
    let zero = BitVector.Zero wordType
    names |> Array.iter (fun name -> this.SetRegister(name, zero))

  /// Clear selected registers to concrete zero.
  member this.ZeroRegisters(rids: RegisterID[]) =
    let zero = BitVector.Zero wordType
    rids |> Array.iter (fun rid -> this.SetRegister(rid, zero))

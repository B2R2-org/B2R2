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

namespace B2R2.MiddleEnd.SymEval

open System
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.Executor

/// Represents a symbolic byte buffer laid out at a concrete address.
type SymByteBuffer =
  { /// Logical name used as the symbolic byte variable prefix.
    Name: string
    /// Concrete start address of the buffer.
    Address: Addr
    /// Symbolic bytes in address order.
    Bytes: SymExpr list
    /// True when a null terminator was written after the symbolic bytes.
    NullTerminated: bool }
with
  /// Symbolic values suitable for SymRunOptions.QueryValues.
  member this.Values = this.Bytes

  interface IQueryExpr with
    member this.QueryValues = this.Bytes

/// Provides convenience helpers for a symbolic state.
type SymStateAccessor(hdl: BinHandle, state: SymState, os: OS) as this =
  static let defaultStringBound = 64

  static let defaultStackTop = 0x7fffffffe000UL

  let regFactory = hdl.RegisterFactory
  let endian = hdl.File.ISA.Endian
  let wordType = hdl.File.ISA.WordSize |> WordSize.toRegType
  let wordBytes = RegType.toByteWidth wordType

  let wordValue (addr: Addr) = SymExpr.Const(BitVector(addr, wordType))

  let byteType = 8<rt>

  let registerByName (name: string) =
    regFactory.GetRegisterID(name = name)

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

  let getConcreteAddr = function
    | SymExpr.Const bv -> BitVector.ToUInt64 bv
    | expr ->
      raise (InvalidOperationException $"Expected concrete address: {expr}.")

  let tryGetConcreteAddr = function
    | SymExpr.Const bv -> Ok(BitVector.ToUInt64 bv)
    | expr -> Error(UnsupportedSymbolicAddress expr)

  let tryGetConcreteReg rid =
    match state.TryGetReg rid with
    | Ok value -> tryGetConcreteAddr value
    | Error _ -> Error(UninitializedRegister rid)

  let getStackPointer () =
    getStackPointerRegister ()
    |> state.GetReg
    |> getConcreteAddr

  let tryGetStackPointer () =
    match regFactory.StackPointer with
    | Some rid -> tryGetConcreteReg rid
    | None -> Error(UnsupportedOperation "Stack pointer is unavailable.")

  let setStackPointer addr =
    state.SetReg(getStackPointerRegister (), wordValue addr)

  let trySetStackPointer addr =
    match regFactory.StackPointer with
    | Some rid -> state.SetReg(rid, wordValue addr); Ok()
    | None -> Error(UnsupportedOperation "Stack pointer is unavailable.")

  let setArgument idx value =
    if idx < 0 then raise (ArgumentOutOfRangeException(nameof idx))
    else ()
    let rid = CallingConvention.FunctionArgRegister(hdl, os, idx + 1)
    state.SetReg(rid, value)

  let allocateStackBuffer size =
    if size < 0 then raise (ArgumentOutOfRangeException(nameof size))
    else ()
    let addr = getStackPointer () - uint64 size
    setStackPointer addr
    addr

  let pushToStack value =
    let addr = getStackPointer () - uint64 wordBytes
    setStackPointer addr
    state.Memory.Store(addr, value, endian)
    addr

  let tryPushToStack value =
    match tryGetStackPointer () with
    | Error e -> Error e
    | Ok sp ->
      let addr = sp - uint64 wordBytes
      trySetStackPointer addr
      |> Result.map (fun () ->
        state.Memory.Store(addr, value, endian)
        addr)

  let popFromStack () =
    let addr = getStackPointer ()
    match state.Memory.Load(addr, endian, wordType) with
    | Ok value ->
      setStackPointer (addr + uint64 wordBytes)
      value
    | Error e ->
      raise (InvalidOperationException $"Stack pop failed: {e}.")

  let tryPopFromStack () =
    match tryGetStackPointer () with
    | Error e -> Error e
    | Ok addr ->
      match state.Memory.Load(addr, endian, wordType) with
      | Ok value ->
        trySetStackPointer (addr + uint64 wordBytes)
        |> Result.map (fun () -> value)
      | Error e -> Error e

  let checkBufferLength length =
    if length < 0 then raise (ArgumentOutOfRangeException(nameof length))
    else ()

  let checkBufferName name =
    if String.IsNullOrWhiteSpace name then
      raise (ArgumentException("Buffer name cannot be empty.", nameof name))
    else
      ()

  let symbolicByte name idx =
    SymExpr.Var($"{name}_{idx}", byteType)

  let writeNullTerminator addr length =
    state.Memory.ByteWrite(addr + uint64 length, SymExpr.zero byteType)

  let writeSymbolicBuffer name addr length nullTerminate =
    checkBufferName name
    checkBufferLength length
    let bytes =
      [ 0 .. length - 1 ]
      |> List.map (symbolicByte name)
    bytes
    |> List.iteri (fun idx byte ->
      state.Memory.ByteWrite(addr + uint64 idx, byte))
    if nullTerminate then writeNullTerminator addr length
    else ()
    { Name = name
      Address = addr
      Bytes = bytes
      NullTerminated = nullTerminate }

  new(hdl, state) = SymStateAccessor(hdl, state, OS.Linux)

  /// Default maximum symbolic C-string payload size.
  static member DefaultStringBound = defaultStringBound

  /// Default stack top used by symbolic states.
  static member DefaultStackTop = defaultStackTop

  /// The underlying symbolic state.
  member _.State = state

  /// Target word-sized register type.
  member _.WordType = wordType

  /// Target word size in bytes.
  member _.WordBytes = wordBytes

  /// Current stack pointer value.
  member _.StackPointer = getStackPointer ()

  /// Set the current stack pointer value.
  member _.SetStackPointer addr = setStackPointer addr

  /// Initialize the stack pointer with the given stack top.
  member _.InitializeStack stackTop = setStackPointer stackTop

  /// Initialize the stack pointer with the default stack top.
  member _.InitializeDefaultStack() = setStackPointer defaultStackTop

  /// Initialize the frame pointer with the current stack pointer.
  member _.InitializeFramePointer() =
    state.SetReg(getFramePointerRegister (), wordValue (getStackPointer ()))

  /// Set a register value by name.
  member _.SetRegister(name: string, value) =
    state.SetReg(registerByName name, value)

  /// Set a register value by register ID.
  member _.SetRegister(rid: RegisterID, value) = state.SetReg(rid, value)

  /// Get a register value by name.
  member _.GetRegister(name: string) = registerByName name |> state.GetReg

  /// Get a register value by register ID.
  member _.GetRegister(rid: RegisterID) = state.GetReg rid

  /// Clear selected registers to zero.
  member _.ZeroRegisters(names: string[]) =
    names
    |> Array.iter (fun name ->
      state.SetReg(registerByName name, SymExpr.zero wordType))

  /// Clear selected registers to zero.
  member _.ZeroRegisters(rids: RegisterID[]) =
    rids
    |> Array.iter (fun rid -> state.SetReg(rid, SymExpr.zero wordType))

  /// Set an integer or pointer argument for the supported ABI.
  member _.SetArgument(idx, value) = setArgument idx value

  /// Get the return value for the supported ABI.
  member _.GetReturnValue() =
    CallingConvention.ReturnRegister hdl |> state.GetReg

  /// Allocate a buffer from the current stack and return its address.
  member _.AllocateStackBuffer size = allocateStackBuffer size

  /// Push a word-sized value to the stack and return its address.
  member _.PushToStack value = pushToStack value

  /// Pop a word-sized value from the stack.
  member _.PopFromStack() = popFromStack ()

  /// Creates symbolic byte variables without writing them to memory.
  member _.CreateSymbolicBytes(name, length) =
    checkBufferName name
    checkBufferLength length
    [ 0 .. length - 1 ]
    |> List.map (symbolicByte name)

  /// Creates a word-sized concrete symbolic expression.
  member _.WordValue addr = wordValue addr

  /// Reads a register as a concrete address.
  member _.TryGetConcreteRegister rid = tryGetConcreteReg rid

  /// Reads the stack pointer as a concrete address.
  member _.TryGetStackPointer() = tryGetStackPointer ()

  /// Sets the stack pointer when the architecture provides one.
  member _.TrySetStackPointer addr = trySetStackPointer addr

  /// Pushes a word-sized value to the stack without throwing on failure.
  member _.TryPushToStack value = tryPushToStack value

  /// Pops a word-sized value from the stack without throwing on failure.
  member _.TryPopFromStack() = tryPopFromStack ()

  /// Writes a symbolic byte buffer to memory at a concrete address.
  member _.WriteSymbolicBuffer(name, addr, length) =
    writeSymbolicBuffer name addr length false

  /// Writes a symbolic byte buffer to memory at a concrete address.
  member _.WriteSymbolicBuffer(name, addr, length, nullTerminate) =
    writeSymbolicBuffer name addr length nullTerminate

  /// Allocates a stack buffer and fills it with symbolic bytes.
  member this.AllocateSymbolicBuffer(name, length) =
    this.AllocateSymbolicBuffer(name, length, false)

  /// Allocates a stack buffer and fills it with symbolic bytes.
  member _.AllocateSymbolicBuffer(name, length, nullTerminate) =
    let size = length + if nullTerminate then 1 else 0
    this.AllocateStackBuffer size
    |> fun addr -> writeSymbolicBuffer name addr length nullTerminate

  /// Sets an argument register to point to a symbolic byte buffer.
  member _.SetArgumentBuffer(idx, buffer: SymByteBuffer) =
    this.SetArgument(idx, wordValue buffer.Address)

  /// Allocates a null-terminated symbolic C-string buffer on the stack.
  member this.AllocateSymbolicString(name) =
    this.AllocateSymbolicString(name, defaultStringBound)

  /// Allocates a null-terminated symbolic C-string buffer on the stack.
  member this.AllocateSymbolicString(name, maxLength) =
    this.AllocateSymbolicBuffer(name, maxLength, true)

  /// Allocates a symbolic C string and passes it as an argument.
  member this.SetArgumentSymbolicString(idx, name) =
    this.SetArgumentSymbolicString(idx, name, defaultStringBound)

  /// Allocates a symbolic C string and passes it as an argument.
  member this.SetArgumentSymbolicString(idx, name, maxLength) =
    let buffer =
      this.AllocateSymbolicBuffer(name, maxLength, true)
    this.SetArgumentBuffer(idx, buffer)
    buffer

  interface IStateAccessor<SymState, SymExpr> with

    member _.State = this.State

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

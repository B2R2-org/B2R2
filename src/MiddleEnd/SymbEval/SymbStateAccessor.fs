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

namespace B2R2.MiddleEnd.SymbEval

open System
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.Executor

/// Represents a symbolic byte buffer laid out at a concrete address.
type SymbByteBuffer =
  { /// Logical name used as the symbolic byte variable prefix.
    Name: string
    /// Concrete start address of the buffer.
    Address: Addr
    /// Symbolic bytes in address order.
    Bytes: SymbExpr list
    /// True when a null terminator was written after the symbolic bytes.
    NullTerminated: bool }
with
  /// Symbolic values suitable for SymbRunOptions.QueryValues.
  member this.Values = this.Bytes

  interface IQueryExpr with
    member this.QueryValues = this.Bytes

/// Provides convenience helpers for a symbolic state. What the shared
/// machinery needs of the symbolic value domain is the object below; the
/// members of this type beyond IStateAccessor are what only a symbolic state
/// can answer, which is every access that lays out symbolic bytes.
type SymbStateAccessor(hdl: BinHandle, state: SymbState) =
  static let defaultStringBound = 64

  let endian = hdl.ISA.Endian
  let wordType = StateAccess.wordType hdl
  let byteType = 8<rt>

  let wordValue (addr: Addr) = SymbExpr.Const(BitVector(addr, wordType))

  let domain =
    { new IStateDomain<SymbState, SymbExpr, SymbEvalError> with

        member _.State = state

        member _.WordValue value = wordValue value

        member _.Zero typ = SymbExpr.zero typ

        member _.TryGetRegisterValue rid =
          match state.TryGetReg rid with
          | ValueSome value -> Ok value
          | ValueNone -> Error(UninitializedRegister rid)

        member _.SetRegisterValue(rid, value) = state.SetReg(rid, value)

        member _.TryReadValue(addr, typ) =
          SymbMemoryOperation.load addr endian typ state.Memory

        member _.WriteValue(addr, value) =
          SymbMemoryOperation.store addr value endian state.Memory

        (* A symbolic value stands for an address only when it has folded to a
           constant; anything else names no cell this accessor can reach. *)
        member _.TryGetAddr value =
          match value with
          | Const bv -> Ok(bv.ToUInt64())
          | expr -> Error(UnsupportedSymbolicAddress expr)

        member _.RegisterUnavailable role =
          UnsupportedOperation $"{role} is unavailable."

        member _.FormatError error = $"{error}" }

  let shared = StateAccess.create hdl domain

  let checkBufferLength length =
    if length < 0 then raise (ArgumentOutOfRangeException(nameof length))
    else ()

  let checkBufferName name =
    if String.IsNullOrWhiteSpace name then
      raise (ArgumentException("Buffer name cannot be empty.", nameof name))
    else
      ()

  let symbolicByte name idx = SymbExpr.Var($"{name}_{idx}", byteType)

  let writeNullTerminator addr length =
    state.Memory.ByteWrite(addr + uint64 length, SymbExpr.zero byteType)

  let writeSymbolicBuffer name addr length nullTerminate =
    checkBufferName name
    checkBufferLength length
    let bytes =
      [ 0 .. length - 1 ]
      |> List.map (symbolicByte name)
    bytes
    |> List.iteri (fun idx byte ->
      state.Memory.ByteWrite(addr + uint64 idx, byte))
    if nullTerminate then writeNullTerminator addr length else ()
    { Name = name
      Address = addr
      Bytes = bytes
      NullTerminated = nullTerminate }

  /// Default maximum symbolic C-string payload size.
  static member DefaultStringBound = defaultStringBound

  /// The underlying symbolic state.
  member _.State = state

  /// Target word-sized register type.
  member _.WordType = wordType

  /// Target word size in bytes.
  member _.WordBytes = shared.WordBytes

  /// Current stack pointer value.
  member _.StackPointer = shared.StackPointer

  /// Stack top that InitializeDefaultStack starts the stack at. The value
  /// depends on the word size of the binary this accessor was built from.
  member _.DefaultStackTop = shared.DefaultStackTop

  /// Creates a word-sized concrete symbolic expression.
  member _.WordValue addr = wordValue addr

  /// Sets the current stack pointer value.
  member _.SetStackPointer addr = shared.SetStackPointer addr

  /// Initializes the stack pointer with the given stack top.
  member _.InitializeStack stackTop = shared.InitializeStack stackTop

  /// Initializes the stack pointer with the default stack top.
  member _.InitializeDefaultStack() = shared.InitializeDefaultStack()

  /// Initializes the frame pointer with the current stack pointer.
  member _.InitializeFramePointer() = shared.InitializeFramePointer()

  /// Sets a register value by name.
  member _.SetRegister(name: string, value) = shared.SetRegister(name, value)

  /// Sets a register value by register ID.
  member _.SetRegister(rid: RegisterID, value) =
    shared.SetRegister(rid, value)

  /// Gets a register value by name.
  member _.GetRegister(name: string) = shared.GetRegister name

  /// Gets a register value by register ID.
  member _.GetRegister(rid: RegisterID) = shared.GetRegister rid

  /// Sets the selected registers to zero by name.
  member _.ZeroRegisters(names: string[]) = shared.ZeroRegisters names

  /// Sets the selected registers to zero by register ID.
  member _.ZeroRegisters(rids: RegisterID[]) = shared.ZeroRegisters rids

  /// Sets an integer or pointer argument for the supported ABI.
  member _.SetArgument(idx, value) = shared.SetArgument(idx, value)

  /// Gets the return value for the supported ABI.
  member _.GetReturnValue() = shared.GetReturnValue()

  /// Allocates a buffer from the current stack and returns its address.
  member _.AllocateStackBuffer size = shared.AllocateStackBuffer size

  /// Pushes a word-sized value to the stack and returns its address.
  member _.PushToStack value = shared.PushToStack value

  /// Pops a word-sized value from the stack.
  member _.PopFromStack() = shared.PopFromStack()

  /// Reads a value of the given type from memory.
  member _.ReadValue(addr: Addr, typ: RegType) = shared.ReadValue(addr, typ)

  /// Writes a value to memory, using the type the value carries.
  member _.WriteValue(addr: Addr, value: SymbExpr) =
    shared.WriteValue(addr, value)

  /// Reads the stack pointer as a concrete address.
  member _.TryGetStackPointer() = shared.TryGetStackPointer()

  /// Sets the stack pointer when the architecture provides one.
  member _.TrySetStackPointer addr = shared.TrySetStackPointer addr

  /// Pushes a word-sized value to the stack without throwing on failure.
  member _.TryPushToStack value = shared.TryPushToStack value

  /// Pops a word-sized value from the stack without throwing on failure.
  member _.TryPopFromStack() = shared.TryPopFromStack()

  /// Reads a register as a concrete address.
  member _.TryGetConcreteRegister rid =
    domain.TryGetRegisterValue rid
    |> Result.bind (fun value -> domain.TryGetAddr value)

  /// Creates symbolic byte variables without writing them to memory.
  member _.CreateSymbolicBytes(name, length) =
    checkBufferName name
    checkBufferLength length
    [ 0 .. length - 1 ]
    |> List.map (symbolicByte name)

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
    shared.AllocateStackBuffer size
    |> fun addr -> writeSymbolicBuffer name addr length nullTerminate

  /// Sets an argument register to point to a symbolic byte buffer.
  member _.SetArgumentBuffer(idx, buffer: SymbByteBuffer) =
    shared.SetArgument(idx, wordValue buffer.Address)

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
    let buffer = this.AllocateSymbolicBuffer(name, maxLength, true)
    this.SetArgumentBuffer(idx, buffer)
    buffer

  interface IStateAccessor<SymbState, SymbExpr, SymbEvalError> with

    member _.State = state

    member _.WordType = wordType

    member _.WordBytes = shared.WordBytes

    member _.StackPointer = shared.StackPointer

    member _.DefaultStackTop = shared.DefaultStackTop

    member _.WordValue value = wordValue value

    member _.SetStackPointer addr = shared.SetStackPointer addr

    member _.InitializeStack stackTop = shared.InitializeStack stackTop

    member _.InitializeDefaultStack() = shared.InitializeDefaultStack()

    member _.InitializeFramePointer() = shared.InitializeFramePointer()

    member _.SetRegister(name: string, value) = shared.SetRegister(name, value)

    member _.SetRegister(rid: RegisterID, value) =
      shared.SetRegister(rid, value)

    member _.GetRegister(name: string) = shared.GetRegister name

    member _.GetRegister(rid: RegisterID) = shared.GetRegister rid

    member _.ZeroRegisters(names: string[]) = shared.ZeroRegisters names

    member _.ZeroRegisters(rids: RegisterID[]) = shared.ZeroRegisters rids

    member _.SetArgument(idx, value) = shared.SetArgument(idx, value)

    member _.GetReturnValue() = shared.GetReturnValue()

    member _.AllocateStackBuffer size = shared.AllocateStackBuffer size

    member _.PushToStack value = shared.PushToStack value

    member _.PopFromStack() = shared.PopFromStack()

    member _.ReadValue(addr, typ) = shared.ReadValue(addr, typ)

    member _.WriteValue(addr, value) = shared.WriteValue(addr, value)

    member _.TryGetStackPointer() = shared.TryGetStackPointer()

    member _.TrySetStackPointer addr = shared.TrySetStackPointer addr

    member _.TryPushToStack value = shared.TryPushToStack value

    member _.TryPopFromStack() = shared.TryPopFromStack()

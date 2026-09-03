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

/// Provides structured access to a concrete state. What the shared machinery
/// needs of the concrete value domain is the object below; the members of
/// this type beyond IStateAccessor are what only a concrete state can answer,
/// which is every access that reads or writes bytes.
type ConcStateAccessor(hdl: BinHandle, state: ConcState) =
  let endian = hdl.ISA.Endian
  let wordType = StateAccess.wordType hdl
  let wordValue (value: Addr) = BitVector(value, wordType)

  let domain =
    { new IStateDomain<ConcState, BitVector, ErrorCase> with

        member _.State = state

        member _.WordValue value = wordValue value

        member _.Zero typ = BitVector.Zero typ

        member _.TryGetRegisterValue rid =
          match state.TryGetReg rid with
          | Def v -> Ok v
          | Undef -> Error ErrorCase.InvalidRegister

        member _.SetRegisterValue(rid, value) = state.SetReg(rid, value)

        member _.TryReadValue(addr, typ) =
          Memory.read addr endian typ state.Memory

        member _.WriteValue(addr, value) =
          Memory.write addr value endian state.Memory

        (* Every concrete value is an address already, so reading one as an
           address is the one primitive that cannot fail in this domain. *)
        member _.TryGetAddr value = Ok(value.ToUInt64())

        member _.RegisterUnavailable _ = ErrorCase.InvalidRegister

        member _.FormatError error = ErrorCase.toMessage error }

  let shared = StateAccess.create hdl domain

  let readByte addr =
    match state.Memory.ByteRead addr with
    | ValueSome b ->
      b
    | ValueNone ->
      raise (InvalidOperationException $"Cannot read memory at {addr:x}.")

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

  /// The underlying concrete state.
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

  /// Creates a word-sized concrete value.
  member _.WordValue value = wordValue value

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
  member _.WriteValue(addr: Addr, value: BitVector) =
    shared.WriteValue(addr, value)

  /// Current stack pointer value, failing instead of raising when the stack
  /// pointer register is unavailable.
  member _.TryGetStackPointer() = shared.TryGetStackPointer()

  /// Sets the current stack pointer value, failing instead of raising when the
  /// stack pointer register is unavailable.
  member _.TrySetStackPointer addr = shared.TrySetStackPointer addr

  /// Pushes a word-sized value to the stack and returns its address, failing
  /// instead of raising.
  member _.TryPushToStack value = shared.TryPushToStack value

  /// Pops a word-sized value from the stack, failing instead of raising when
  /// the stack pointer is unavailable or the memory read fails.
  member _.TryPopFromStack() = shared.TryPopFromStack()

  /// Pushes a word-sized pointer value to the stack and returns its address.
  member _.PushPointer(value: Addr) = wordValue value |> shared.PushToStack

  /// Pops a word-sized pointer value from the stack.
  member _.PopPointer() = shared.PopFromStack().ToUInt64()

  /// Writes a word-sized pointer value to memory.
  member _.WritePointer(addr: Addr, value: Addr) =
    shared.WriteValue(addr, wordValue value)

  /// Reads a word-sized pointer value from memory.
  member _.ReadPointer(addr: Addr) =
    shared.ReadValue(addr, wordType).ToUInt64()

  /// Writes a concrete integer value to memory.
  member _.WriteInteger(addr: Addr, value: uint64, typ: RegType) =
    shared.WriteValue(addr, BitVector(value, typ))

  /// Writes concrete bytes to memory.
  member _.WriteBytes(addr: Addr, bytes: byte[]) =
    bytes
    |> Array.iteri (fun idx b -> state.Memory.ByteWrite(addr + uint64 idx, b))

  /// Reads concrete bytes from memory.
  member _.ReadBytes(addr: Addr, length: int) =
    if length < 0 then raise (ArgumentOutOfRangeException(nameof length))
    else ()
    Array.init length (fun idx -> readByte (addr + uint64 idx))

  /// Reads a null-terminated ASCII string from memory. Reaching maxLength
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

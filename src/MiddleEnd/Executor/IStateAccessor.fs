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

open B2R2

/// <namespacedoc>
///   <summary>
///   Contains functions and types related to IR execution.
///   </summary>
/// </namespacedoc>
///
/// <summary>
/// Provides structured access to an executor-specific state. The contract
/// covers what every executor can express in terms of its own value type;
/// byte-oriented memory access is deliberately absent, because a symbolic
/// state has no bytes to hand back.
/// </summary>
type IStateAccessor<'State, 'Value, 'Error> =
  /// The underlying executor-specific state.
  abstract State: 'State

  /// Target word-sized register type.
  abstract WordType: RegType

  /// Target word size in bytes.
  abstract WordBytes: int

  /// Current stack pointer value.
  abstract StackPointer: Addr

  /// Stack top that InitializeDefaultStack starts the stack at.
  abstract DefaultStackTop: Addr

  /// Create a word-sized value out of the given integer.
  abstract WordValue: value: Addr -> 'Value

  /// Set the current stack pointer value.
  abstract SetStackPointer: addr: Addr -> unit

  /// Initialize the stack pointer with the given stack top.
  abstract InitializeStack: stackTop: Addr -> unit

  /// Initialize the stack pointer with the default stack top.
  abstract InitializeDefaultStack: unit -> unit

  /// Initialize the frame pointer with the current stack pointer.
  abstract InitializeFramePointer: unit -> unit

  /// Set a register value by name.
  abstract SetRegister: name: string * value: 'Value -> unit

  /// Set a register value by register ID.
  abstract SetRegister: rid: RegisterID * value: 'Value -> unit

  /// Get a register value by name.
  abstract GetRegister: name: string -> 'Value

  /// Get a register value by register ID.
  abstract GetRegister: rid: RegisterID -> 'Value

  /// Set the selected registers to zero by name.
  abstract ZeroRegisters: names: string[] -> unit

  /// Set the selected registers to zero by register ID.
  abstract ZeroRegisters: rids: RegisterID[] -> unit

  /// Set an integer or pointer argument for the supported ABI.
  abstract SetArgument: idx: int * value: 'Value -> unit

  /// Get the return value for the supported ABI.
  abstract GetReturnValue: unit -> 'Value

  /// Allocate a buffer from the current stack and return its address.
  abstract AllocateStackBuffer: size: int -> Addr

  /// Push a word-sized value to the stack and return its address.
  abstract PushToStack: value: 'Value -> Addr

  /// Pop a word-sized value from the stack.
  abstract PopFromStack: unit -> 'Value

  /// Read a value of the given type from memory.
  abstract ReadValue: addr: Addr * typ: RegType -> 'Value

  /// Write a value to memory, using the type the value carries.
  abstract WriteValue: addr: Addr * value: 'Value -> unit

  /// Current stack pointer value, failing instead of raising when the stack
  /// pointer register is unavailable.
  abstract TryGetStackPointer: unit -> Result<Addr, 'Error>

  /// Set the current stack pointer value, failing instead of raising when the
  /// stack pointer register is unavailable.
  abstract TrySetStackPointer: addr: Addr -> Result<unit, 'Error>

  /// Push a word-sized value to the stack and return its address, failing
  /// instead of raising.
  abstract TryPushToStack: value: 'Value -> Result<Addr, 'Error>

  /// Pop a word-sized value from the stack, failing instead of raising.
  abstract TryPopFromStack: unit -> Result<'Value, 'Error>

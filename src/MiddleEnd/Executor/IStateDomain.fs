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

/// Provides what the shared state access machinery needs of a state: the
/// state itself, and the nine operations that are all the machinery knows
/// about its value domain.
type IStateDomain<'State, 'Value, 'Error> =
  /// The underlying executor-specific state.
  abstract State: 'State

  /// Build a word-sized value out of the given integer.
  abstract WordValue: value: Addr -> 'Value

  /// Build the value that reads back as zero at the given type.
  abstract Zero: typ: RegType -> 'Value

  /// Read a register, failing when it holds no value of this domain.
  abstract TryGetRegisterValue: rid: RegisterID -> Result<'Value, 'Error>

  /// Write a register.
  abstract SetRegisterValue: rid: RegisterID * value: 'Value -> unit

  /// Read a value of the given type from memory, failing when the memory
  /// cannot be read.
  abstract TryReadValue: addr: Addr * typ: RegType -> Result<'Value, 'Error>

  /// Write a value to memory, using the type the value carries.
  abstract WriteValue: addr: Addr * value: 'Value -> unit

  /// Read a value as a concrete address, failing when it is not one.
  abstract TryGetAddr: value: 'Value -> Result<Addr, 'Error>

  /// Build the error that stands for the ABI providing no register for the
  /// given role.
  abstract RegisterUnavailable: role: string -> 'Error

  /// Render an error of this domain for an exception message.
  abstract FormatError: error: 'Error -> string

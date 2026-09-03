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

/// Represents a byte-addressed memory used in an evaluation. The value type
/// decides what a cell holds: a concrete evaluation holds bytes, and a
/// symbolic one holds 8-bit expressions.
type IMemory<'V> =
  /// Reads the value at the given address, or `ValueNone` when the address
  /// holds no value.
  abstract ByteRead: Addr -> 'V voption

  /// Writes the given value to the given address. Every address is writable
  /// and an unmapped address becomes mapped on write, so a write never fails;
  /// a read comes back empty only because an unmapped address has no value to
  /// return.
  abstract ByteWrite: Addr * 'V -> unit

  /// Returns an independent copy of this memory.
  abstract Clone: unit -> IMemory<'V>

  /// Clears up the memory contents; discards every value written to the
  /// memory.
  abstract Clear: unit -> unit

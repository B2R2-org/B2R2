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

/// Represents the initial memory used for creating an execution state.
type InitialMemory<'Memory> =
  /// Start with an empty memory.
  | EmptyMemory
  /// Use the given executor-specific memory.
  | PreinitializedMemory of memory: 'Memory
  /// Use binary file sections (e.g., .rodata, .data) for memory reads.
  | BinSectionBackedMemory

/// Represents options for creating an execution state.
type StateCreationOptions<'Memory, 'Value> =
  { /// Initial memory.
    Memory: InitialMemory<'Memory>
    /// Initial registers.
    Registers: (RegisterID * 'Value)[] }

/// Represents an executor that executes binary code from a given address.
type IExecutor<'State, 'Memory, 'Value, 'RunOptions, 'RunResult> =
  /// Create an executor-specific initial state with default options.
  abstract CreateState: unit -> 'State

  /// Create an executor-specific initial state with the given options.
  abstract CreateState: options: StateCreationOptions<'Memory, 'Value> -> 'State

  /// Execute from the given start address with the provided state.
  abstract Run:
    start: Addr *
    state: 'State *
    options: 'RunOptions -> 'RunResult

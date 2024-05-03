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

namespace B2R2.MiddleEnd.ControlFlowGraph

open B2R2
open B2R2.BinIR

/// An abstract information about a function to be used in an intra-procedural
/// CFG. This exists per function call, not per function definition. Therefore,
/// one function can have multiple `FunctionAbstraction` instances.
[<AllowNullLiteral>]
type FunctionAbstraction (entryPoint,
                          unwindingBytes,
                          rundown,
                          isExternal) =
  /// Entry point of this function.
  member _.EntryPoint with get(): Addr = entryPoint

  /// How many bytes of the stack does this function unwind when return?
  member _.UnwindingBytes with get(): int option = unwindingBytes

  /// A rundown of the function in SSA form.
  member _.Rundown with get(): SSARundown = rundown

  /// Is this an external function?
  member _.IsExternal with get(): bool = isExternal

/// A rundown of a function in SSA form, where each SSA statement is associated
/// with a program point.
and SSARundown = (ProgramPoint * SSA.Stmt) array

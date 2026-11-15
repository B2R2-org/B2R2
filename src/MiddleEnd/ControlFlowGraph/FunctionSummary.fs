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
open B2R2.ABI

/// Represents what an intra-procedural CFG knows about a function it calls,
/// summarizing the callee in place of its body. This exists per function call,
/// not per function definition. Therefore, one function can have multiple
/// `FunctionSummary` instances.
type FunctionSummary<'Stmt>(entryPoint,
                            unwindingBytes,
                            rundown,
                            isExternal,
                            returningStatus,
                            pointerWrites) =
  /// Creates a summary of a function that may write anything around where the
  /// pointers it gets point, as nothing tells otherwise.
  new(entryPoint, unwindingBytes, rundown, isExternal, returningStatus) =
    FunctionSummary(entryPoint,
                    unwindingBytes,
                    rundown,
                    isExternal,
                    returningStatus,
                    UnknownPointerWrites)

  /// Gets the entry point of this function.
  member _.EntryPoint with get(): Addr = entryPoint

  /// Gets how many bytes of the stack this function unwinds on return.
  member _.UnwindingBytes with get(): int = unwindingBytes

  /// Gets a rundown of the function in SSA form.
  member _.Rundown with get(): Rundown<'Stmt> = rundown

  /// Checks if this is an external function.
  member _.IsExternal with get(): bool = isExternal

  /// Gets what the non-returning function analysis found for this function.
  member _.ReturningStatus with get(): NonReturningStatus = returningStatus

  /// Gets what this function writes through the pointers it gets, such as one
  /// to an object on the stack of its caller, which the caller then no longer
  /// knows once this function returns.
  member _.PointerWrites with get(): PointerWrites = pointerWrites

/// Represents a rundown of a function, which is really just an array of
/// statements summarizing the function.
and Rundown<'Stmt> = 'Stmt array

/// Represents the result of the non-returning function analysis.
and NonReturningStatus =
  /// This function will never return. For example, the "exit" function should
  /// have this property.
  | NoRet
  /// Regular case: *not* no-return (i.e., this is a returning function).
  | NotNoRet
  /// Conditionally no-return; function does not return only if the argument
  /// at the given location is non-zero.
  | ConditionalNoRet of ArgLocation
  /// We don't know yet: we need further analyses.
  | UnknownNoRet

/// Represents what a function writes through the pointers that it gets in its
/// argument registers.
and PointerWrites =
  /// Nothing tells what the function writes, so it may write anything around
  /// where a pointer it gets points.
  | UnknownPointerWrites
  /// The function writes through the pointer in each of the given argument
  /// registers what the extent tells, and nothing through any other.
  | PointerWritesOf of Map<RegisterID, WriteExtent>

/// Represents the bytes around where a pointer points that a function writes
/// through the pointer.
and WriteExtent =
  /// The bytes from the low offset up to, but not including, the high one,
  /// both counted from where the pointer points.
  | WrittenBytes of lo: int * hi: int
  /// Any bytes around where the pointer points, as an index or another offset
  /// leaves them unknown.
  | AnyBytes

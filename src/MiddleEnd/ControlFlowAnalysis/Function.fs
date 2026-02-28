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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open System.Collections.Generic
open B2R2
open B2R2.MiddleEnd.ControlFlowGraph

/// Represents a function in a binary, which is essentially a continuous chunk
/// of code. Functions may overlap with each other in rare cases. Function
/// overlapping is rare because we will create a new function when there is an
/// incoming edge in the middle of a funcion,
type Function(entryPoint,
              name,
              cfg,
              isNoRet,
              callees,
              callers,
              jmptbls,
              isExtern) =

  new(entryPoint, name, noret, callers, jmptbls, isExtern) =
    let dummy = LowUIRCFG()
    Function(entryPoint, name, dummy, noret, null, callers, jmptbls, isExtern)

  /// Function entry point address.
  member _.EntryPoint with get(): Addr = entryPoint

  /// Unique ID of the function. A binary can have multiple functions with the
  /// same name, but they will have different IDs.
  member _.ID with get(): string = Addr.toFuncName entryPoint

  /// Name of the function.
  member _.Name with get(): string = name

  /// Function's control flow graph.
  member _.CFG with get(): LowUIRCFG = cfg

  /// Return the non-returning status of this function.
  member _.NoRet with get(): NonReturningStatus = isNoRet

  /// Mapping from a callsite to its callee kind.
  member _.Callees with get(): SortedList<CallSite, CalleeKind> = callees

  /// Callers of this function.
  member _.Callers with get(): HashSet<Addr> = callers

  /// Jump tables associated with this function.
  member _.JumpTables with get(): List<JmpTableInfo> = jmptbls

  /// Whether this function is an external function.
  member _.IsExternal with get(): bool = isExtern

  interface ILinkage with
    member _.IsExternal with get() = isExtern

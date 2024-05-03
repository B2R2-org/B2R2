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

/// Function is a chunk of code in a binary. Functions may overlap with each
/// other in rare cases. Function overlapping is rare because we will create a
/// new function when there is an incoming edge in the middle of a funcion,
type Function<'V, 'E when 'V :> IRBasicBlock and 'V: equality and 'E: equality>
  public (entryPoint, name, ircfg, isNoRet, callees, callers, isExtern) =

  new (entryPoint, name, noret, callers, isExtern) =
    Function (entryPoint, name, null, noret, null, callers, isExtern)

  /// Function entry point address.
  member _.EntryPoint with get(): Addr = entryPoint

  /// Unique ID of the function. A binary can have multiple functions with the
  /// same name, but they will have different IDs.
  member _.ID with get(): string = Addr.toFuncName entryPoint

  /// Name of the function.
  member _.Name with get(): string = name

  /// Function's control flow graph.
  member _.CFG with get(): IRCFG<'V, 'E> = ircfg

  /// Return the non-returning status of this function.
  member _.NoRet with get(): NonReturningStatus = isNoRet

  /// Call site information of this function.
  member _.Callees with get(): SortedList<Addr, CalleeKind> = callees

  /// Callers of this function.
  member _.Callers with get(): HashSet<Addr> = callers

  interface ILinkage with
    member _.IsExternal with get() = isExtern

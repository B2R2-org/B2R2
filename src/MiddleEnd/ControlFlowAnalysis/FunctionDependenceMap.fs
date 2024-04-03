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

/// Map from a function (callee) to its caller functions. This is not
/// thread-safe, and thus should be used only by CTFTaskManager.
type FunctionDependenceMap () =
  let dict = Dictionary<Addr, List<Addr>> ()

  let getCallerList (callee: Addr) =
    if dict.ContainsKey callee then
      dict[callee]
    else
      let newList = List<Addr> ()
      dict[callee] <- newList
      newList

  /// Add a dependency between two functions.
  member _.AddDependency (caller: Addr, callee: Addr) =
    let lst = getCallerList callee
    lst.Add caller

  /// Remove a callee function from the map, and return its caller functions.
  member _.RemoveAndGetCallers (callee: Addr) =
    let callers = dict[callee]
    dict.Remove callee |> ignore
    callers

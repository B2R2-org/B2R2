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

open System.Collections.Generic

/// Represents a collection of variables used in an evaluation state. The key
/// type decides what kind of variables the collection holds: registers are
/// keyed by their <see cref='T:B2R2.RegisterID'/>, and temporaries by the
/// integer that names them. The value type decides what an evaluation binds
/// them to: a concrete one binds bit-vectors, a symbolic one expressions.
type Variables<'K, 'V when 'K: equality> private(vars) =
  let vars: Dictionary<'K, 'V> = vars

  /// Instantiates an empty collection of variables.
  new() = Variables(Dictionary())

  /// Returns the number of the variables that are currently defined.
  member _.Count with get() = vars.Count

  /// Returns the value of the given variable, or `ValueNone` when the variable
  /// is not defined.
  member _.TryGet k =
    match vars.TryGetValue k with
    | true, v -> ValueSome v
    | false, _ -> ValueNone

  /// Returns the value of the given variable, raising an exception when the
  /// variable is not defined.
  member _.Get k = vars[k]

  /// Defines the given variable to have the given value, overwriting any
  /// value it already had.
  member _.Set(k, v) = vars[k] <- v

  /// Undefines the given variable; undefining one that is not defined does
  /// nothing.
  member _.Unset k = vars.Remove k |> ignore

  /// Returns every defined variable as an array of key and value pairs, in no
  /// particular order.
  member _.ToArray() =
    vars |> Seq.map (fun (KeyValue(k, v)) -> k, v) |> Seq.toArray

  /// Returns an independent copy of this collection of variables.
  member _.Clone() = Variables(Dictionary(vars))

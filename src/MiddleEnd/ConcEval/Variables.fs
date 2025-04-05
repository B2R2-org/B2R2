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

namespace B2R2.MiddleEnd.ConcEval

open System.Collections.Generic
open B2R2

type Variables (vars) =
  let vars: Dictionary<int, BitVector> = vars

  new () = Variables (Dictionary ())

  member _.TryGet k =
    match vars.TryGetValue k with
    | true, v -> Ok v
    | false, _ -> Error ErrorCase.InvalidRegister

  member _.Get k = vars[k]

  member _.Set k v = vars[k] <- v

  member _.Unset k =
    vars.Remove k |> ignore

  member _.Count () =
    vars.Count

  member _.ToArray () =
    vars |> Seq.map (fun (KeyValue (k, v))  -> k, v) |> Seq.toArray

  member _.Clone () =
    Variables (Dictionary (vars))

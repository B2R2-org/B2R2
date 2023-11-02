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

module B2R2.Utils

open System
open System.Diagnostics

[<StackTraceHidden>]
let futureFeature () =
  let trace = StackTrace (true)
  printfn "FATAL ERROR: NOT IMPLEMENTED FEATURE."
  trace.ToString () |> printfn "%s"
  raise <| NotImplementedException ()

[<StackTraceHidden>]
let impossible () =
  let trace = StackTrace (true)
  printfn "FATAL ERROR: THIS IS INVALID AND SHOULD NEVER HAPPEN."
  trace.ToString () |> printfn "%s"
  raise <| InvalidOperationException ()

let inline (===) a b = LanguagePrimitives.PhysicalEquality a b

let inline tupleResultToOpt result =
  match result with
  | false, _ -> None
  | true, a -> Some a

let inline fstOfTriple (a, _, _) = a

let inline sndOfTriple (_, a, _) = a

let inline thdOfTriple (_, _, a) = a

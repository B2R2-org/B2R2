(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

let assertEqual a b exn = if a = b then () else raise exn

let assertByCond cond exn = if cond then () else raise exn

let futureFeature () =
  let trace = Diagnostics.StackTrace (true)
  printfn "FATAL ERROR: NOT IMPLEMENTED FEATURE."
  trace.ToString () |> printfn "%s"
  raise <| NotImplementedException ()

let impossible () =
  let trace = Diagnostics.StackTrace (true)
  printfn "FATAL ERROR: THIS IS INVALID AND SHOULD NEVER HAPPEN."
  trace.ToString () |> printfn "%s"
  raise <| InvalidOperationException ()

let inline tap (f: 'a -> unit) (v: 'a) : 'a =
  f v; v

let inline curry f a b = f (a, b)

let inline uncurry f (a, b) = f a b

let inline (===) a b = LanguagePrimitives.PhysicalEquality a b

let inline tupleToOpt result =
  match result with
  | false, _ -> None
  | true, a -> Some a

let writeB2R2 newLine =
  Console.ForegroundColor <- ConsoleColor.DarkCyan
  Console.Write ("B")
  Console.ForegroundColor <- ConsoleColor.DarkYellow
  Console.Write ("2")
  Console.ForegroundColor <- ConsoleColor.DarkCyan
  Console.Write ("R")
  Console.ForegroundColor <- ConsoleColor.DarkYellow
  Console.Write ("2")
  Console.ResetColor ()
  if newLine then Console.WriteLine () else ()

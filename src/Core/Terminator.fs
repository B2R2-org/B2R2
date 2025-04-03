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

/// A set of terminating functions, which are used to terminate the program
/// when a non-recoverable error is encountered.
[<RequireQualifiedAccess>]
module B2R2.Terminator

open System
open System.Diagnostics

/// Not implemented features encountered, so raise an exception and die.
[<StackTraceHidden>]
let futureFeature () =
  let trace = StackTrace (true)
  printfn "FATAL ERROR: NOT IMPLEMENTED FEATURE."
  trace.ToString () |> printfn "%s"
  raise <| NotImplementedException ()

/// Fatal error. This should never happen.
[<StackTraceHidden>]
let impossible () =
  let trace = StackTrace (true)
  printfn "FATAL ERROR: THIS IS INVALID AND SHOULD NEVER HAPPEN."
  trace.ToString () |> printfn "%s"
  raise <| InvalidOperationException ()

/// Exit the whole program with a fatal error message.
let fatalExit (msg: string) =
  Console.Error.WriteLine msg
  exit 1

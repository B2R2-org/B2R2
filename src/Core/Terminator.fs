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

/// <namespacedoc>
///   <summary>
///   B2R2 is the top-level namespace, representing the whole project.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Provides a set of terminating functions, which are used to terminate the
/// program when a non-recoverable error is encountered.
/// </summary>
[<RequireQualifiedAccess>]
module B2R2.Terminator

open System
open System.Diagnostics

/// Terminates the program with a message indicating that the program is
/// not implemented yet and will be implemented in the future.
[<StackTraceHidden>]
let futureFeature () =
  let trace = StackTrace(true)
  Console.Error.WriteLine "FATAL ERROR: NOT IMPLEMENTED FEATURE"
  Console.Error.WriteLine(trace.ToString())
  raise <| NotImplementedException()

/// Terminates the program with a message indicating this should never happen.
/// This is a bug and should be reported.
[<StackTraceHidden>]
let impossible () =
  let trace = StackTrace(true)
  Console.Error.WriteLine "FATAL ERROR: THIS IS INVALID AND SHOULD NEVER HAPPEN"
  Console.Error.WriteLine(trace.ToString())
  raise <| InvalidOperationException()

/// Exits the whole program including any child processes with a fatal error
/// message. This function does not raise an exception, but directly exits the
/// program.
let fatalExit (msg: string) =
  Console.Error.WriteLine msg
  exit 1

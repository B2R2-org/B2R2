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

namespace B2R2.Logging

/// <namespacedoc>
///   <summary>
///   Contains logging-related types and functions.
///   </summary>
/// </namespacedoc>
///
/// <summary>
/// Represents the verbosity level of logging messages.
/// </summary>
type LogLevel =
  /// Most succinct = level 1.
  | L1 = 1
  /// Normal = level 2.
  | L2 = 2
  /// Verbose = level 3.
  | L3 = 3
  /// Most verbose = level 4.
  | L4 = 4

/// Provides functions to convert between LogLevel and string.
[<RequireQualifiedAccess>]
module LogLevel =
  /// Gets LogLevel from a given string. Higher the log level, more verbose
  /// the logging output.
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant() with
    | "1" | "l1" | "quiet" | "q" -> LogLevel.L1
    | "3" | "l3" | "verbose" | "v" -> LogLevel.L3
    | "4" | "l4" -> LogLevel.L4
    | _ -> LogLevel.L2

  /// Returns a string representing the given LogLevel.
  [<CompiledName "ToString">]
  let toString = function
    | LogLevel.L1 -> "L1"
    | LogLevel.L2 -> "L2"
    | LogLevel.L3 -> "L3"
    | LogLevel.L4 -> "L4"
    | _ -> B2R2.Terminator.impossible ()

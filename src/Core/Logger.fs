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

namespace B2R2

open System.IO

/// How verbose do we want to log messages?
type LogLevel =
  /// Most succinct = level 1.
  | L1 = 1
  /// Normal = level 2.
  | L2 = 2
  /// Verbose = level 3.
  | L3 = 3
  /// Most verbose = level 4.
  | L4 = 4

/// Helper module for LogLevel
[<RequireQualifiedAccess>]
module LogLevel =
  let ofString (str: string) =
    match str.ToLower () with
    | "1" | "l1" | "quiet" | "q" -> LogLevel.L1
    | "3" | "l3" | "verbose" | "v" -> LogLevel.L3
    | "4" | "l4" -> LogLevel.L4
    | _ -> LogLevel.L2

  let toString = function
    | LogLevel.L1 -> "L1"
    | LogLevel.L2 -> "L2"
    | LogLevel.L3 -> "L3"
    | LogLevel.L4 -> "L4"
    | _ -> Utils.impossible ()

/// Basic logging facility.
type ILogger =
  /// Log string (without newline).
  abstract Log: string * ?lev:LogLevel -> unit

  /// Log string with a new line.
  abstract LogLine: string * ?lev:LogLevel -> unit

/// Log to a file.
type FileLogger(filepath, ?level: LogLevel) =
  let fs = File.CreateText (filepath, AutoFlush = true)
  let llev = defaultArg level LogLevel.L2

  override __.Finalize () =
    fs.Close ()

  interface ILogger with
    member __.Log (str, ?lvl) =
      let lvl = defaultArg lvl LogLevel.L2
      if lvl <= llev then fs.Write str else ()

    member __.LogLine (str, ?lvl) =
      let lvl = defaultArg lvl LogLevel.L2
      if lvl <= llev then fs.WriteLine str else ()

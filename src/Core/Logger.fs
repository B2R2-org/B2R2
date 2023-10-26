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

open System
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
  /// Get LogLevel from a given string.
  let ofString (str: string) =
    match str.ToLowerInvariant () with
    | "1" | "l1" | "quiet" | "q" -> LogLevel.L1
    | "3" | "l3" | "verbose" | "v" -> LogLevel.L3
    | "4" | "l4" -> LogLevel.L4
    | _ -> LogLevel.L2

  /// Return a string representing the given LogLevel.
  let toString = function
    | LogLevel.L1 -> "L1"
    | LogLevel.L2 -> "L2"
    | LogLevel.L3 -> "L3"
    | LogLevel.L4 -> "L4"
    | _ -> Utils.impossible ()

/// Basic logging facility.
type ILogger =
  /// Write a log message (without newline). If the given verbosity level (lvl)
  /// is lower than it of the logger's, this will print out the given message.
  /// If the logger's verbosity level is L4, then this function will always
  /// print out messages regardless of the given `lvl`.
  abstract Log: string * ?lvl:LogLevel -> unit

  /// Write a log message with a newline. If the given verbosity level (lvl) is
  /// lower than it of the logger's, this will print out the given message. If
  /// the logger's verbosity level is L4, then this function will always print
  /// out messages regardless of the given `lvl`.
  abstract LogLine: string * ?lvl:LogLevel -> unit

/// Log to a file.
type FileLogger(filepath, ?level: LogLevel) =
  let fs = File.CreateText (filepath, AutoFlush = true)
  let llev = defaultArg level LogLevel.L2

  interface IDisposable with
    member __.Dispose () = fs.Dispose ()

  interface ILogger with
    member __.Log (str, ?lvl) =
      let lvl = defaultArg lvl LogLevel.L2
      if lvl <= llev then fs.Write str else ()

    member __.LogLine (str, ?lvl) =
      let lvl = defaultArg lvl LogLevel.L2
      if lvl <= llev then fs.WriteLine str else ()

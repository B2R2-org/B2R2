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

open System

/// Provides the interface for a logger that can be used to log messages with
/// different verbosity levels.
type ILogger =
  inherit IDisposable

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

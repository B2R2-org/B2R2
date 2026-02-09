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

/// Represents the main logging facility, shared by all B2R2 components.
type Log =
  static let mutable out = new ConsolePrinter() :> IPrinter

  static let mutable isCached = false

  /// Represents the main console printer.
  static member Out = out

  /// Enables caching for the main console printer.
  static member EnableCaching() =
    if isCached then
      ()
    else
      out <- new ConsoleCachedPrinter() :> IPrinter
      isCached <- true

  /// Disables caching for the main console printer.
  static member DisableCaching() =
    if isCached then
      out.Flush()
      out <- new ConsolePrinter() :> IPrinter
      isCached <- false
    else
      ()

  /// Sets the log level for the main console printer.
  static member SetLogLevel(level: LogLevel) =
    if isCached then
      out <- new ConsoleCachedPrinter(level) :> IPrinter
    else
      out <- new ConsolePrinter(level) :> IPrinter
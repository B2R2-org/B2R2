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

open B2R2

/// Represents a printer that does *not* print anything. This is the same as
/// redirecting outputs to /dev/null.
type ConsoleNullPrinter() =
  interface IPrinter with
    member _.TableConfig with get() = Terminator.impossible ()

    member _.Dispose() = ()

    member _.Print(_: string, _: LogLevel) = ()

    member _.Print(_: ColoredString, _: LogLevel) = ()

    member _.Print(_: OutString, _: LogLevel) = ()

    member _.PrintLine(_: string, _: LogLevel) = ()

    member _.PrintLine(_: ColoredString, _: LogLevel) = ()

    member _.PrintLine(_: OutString, _: LogLevel) = ()

    member _.PrintLine(_: LogLevel) = ()

    member _.PrintRow(_: string[]) = ()

    member _.PrintRow(_: ColoredString[]) = ()

    member _.PrintRow(_: OutString[]) = ()

    member _.PrintSectionTitle _ = ()

    member _.PrintSubsectionTitle(_: string) = ()

    member _.PrintSubsubsectionTitle(_: string) = ()

    member _.Flush() = ()

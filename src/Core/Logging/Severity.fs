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

/// <summary>
/// Represents how severe a diagnostic message is. This is an enum rather than a
/// union so that its cases need qualification, which keeps <c>Error</c> from
/// shadowing the <c>Result</c> constructor of the same name.
/// </summary>
type Severity =
  /// The work continued in spite of the condition. Suppressed at L1.
  | Warning = 1
  /// The work could not be carried out as requested. Never suppressed.
  | Error = 2

/// Provides functions to convert a Severity into its display form.
[<RequireQualifiedAccess>]
module Severity =
  /// Returns the label that prefixes a message of the given severity.
  [<CompiledName "ToString">]
  let toString = function
    | Severity.Warning -> "Warning"
    | Severity.Error -> "Error"
    | _ -> "Unknown"

  /// Returns true when a message of the given severity is shown at the given
  /// log level. Errors are always shown; warnings need L2 or above.
  [<CompiledName "IsShownAt">]
  let isShownAt (level: LogLevel) severity =
    severity = Severity.Error || level >= LogLevel.L2

  /// Returns the plain-text prefix that a serialized sink writes before a
  /// message of the given severity.
  [<CompiledName "ToPrefix">]
  let toPrefix severity =
    "[*] " + toString severity + ": "

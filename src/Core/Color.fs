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

/// Represents colors to print out in the console. When printing to a file,
/// colors are ignored.
type Color =
  /// Red color.
  | Red
  /// Green color.
  | Green
  /// Yellow color.
  | Yellow
  /// Blue color.
  | Blue
  /// Dark cyan color.
  | DarkCyan
  /// Dark yellow color.
  | DarkYellow
  /// No color.
  | NoColor
  /// Red highlight color.
  | RedHighlight
  /// Green highlight color.
  | GreenHighlight
with
  static member FromByte(b: byte) =
    if Byte.isNull b then NoColor
    elif Byte.isPrintable b then Green
    elif Byte.isWhitespace b then Blue
    elif Byte.isControl b then Red
    else Yellow

  override this.ToString() =
    match this with
    | NoColor -> "nocolor"
    | Red -> "red"
    | Green -> "green"
    | Yellow -> "yellow"
    | Blue -> "blue"
    | DarkCyan -> "darkcyan"
    | DarkYellow -> "darkyellow"
    | RedHighlight -> "redhighlight"
    | GreenHighlight -> "greenhighlight"

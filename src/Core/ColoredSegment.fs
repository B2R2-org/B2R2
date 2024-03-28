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

/// String segment with color. Multiple segments can be concatenated to form a
/// colored string.
type ColoredSegment = Color * string

[<RequireQualifiedAccess>]
module ColoredSegment =
  let private getColor b =
    if Byte.isNull b then NoColor
    elif Byte.isPrintable b then Green
    elif Byte.isWhitespace b then Blue
    elif Byte.isControl b then Red
    else Yellow

  /// Return a colored hexadeciaml representation of a byte.
  [<CompiledName "HexOfByte">]
  let hexOfByte b =
    getColor b, b.ToString ("X2")

  /// Return a colored ASCII representation of a byte.
  [<CompiledName "AsciiOfByte">]
  let asciiOfByte b =
    getColor b, Byte.getRepresentation b

  /// Append a string (of the same color) to a colored segment.
  [<CompiledName "AppendString">]
  let appendString tail (segment: ColoredSegment) =
    let color, string = segment
    ColoredSegment (color, string + tail)

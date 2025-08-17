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

namespace B2R2.RearEnd.Utils

open B2R2

/// Represents a string segment with a single color. Multiple segments can be
/// concatenated to form a colored string.
type internal ColoredSegment = Color * string

[<RequireQualifiedAccess>]
module internal ColoredSegment =
  /// Returns a colored hexadecimal representation of a byte.
  let hexOfByte b =
    Color.FromByte b, b.ToString "X2"

  /// Returns a colored ASCII representation of a byte.
  let asciiOfByte b =
    Color.FromByte b, Byte.getRepresentation b

  /// Appends a string (of the same color) to a colored segment.
  let appendString tail (segment: ColoredSegment) =
    let color, string = segment
    ColoredSegment(color, string + tail)

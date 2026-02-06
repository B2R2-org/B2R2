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

/// Represents an output string generated from rear-end applications.
type OutString =
  /// Normal string without color.
  | OutputNormal of string
  /// Colored string.
  | OutputColored of ColoredString
  /// A new line.
  | OutputNewLine
with
  override this.ToString() =
    match this with
    | OutputNormal s -> s
    | OutputColored cs -> cs.ToString()
    | OutputNewLine -> "\n"

  /// Pads the output string to the left with spaces up to the specified width.
  member this.PadLeft(width) =
    match this with
    | OutputNormal s -> OutputNormal(s.PadLeft width)
    | OutputColored cs -> OutputColored(cs.PadLeft width)
    | OutputNewLine -> this

  /// Pads the output string to the right with spaces up to the specified width.
  member this.PadRight(width) =
    match this with
    | OutputNormal s -> OutputNormal(s.PadRight width)
    | OutputColored cs -> OutputColored(cs.PadRight width)
    | OutputNewLine -> this

  /// Renders the output string using the provided function.
  member this.Render fn =
    match this with
    | OutputNormal s -> fn NoColor s
    | OutputColored cs -> cs.Render fn
    | OutputNewLine -> fn NoColor System.Environment.NewLine

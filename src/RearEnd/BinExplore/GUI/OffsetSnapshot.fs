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

namespace B2R2.RearEnd.BinExplore.GUI

/// Represents the shared file-offset snapshot consumed by views such as the
/// status bar and hex overview. `Selection` describes the currently focused
/// byte range, while `Viewport` describes the byte range currently visible in
/// the hexdump view.
type OffsetSnapshot =
  { Selection: OffsetRangeInfo option
    Viewport: OffsetRangeInfo option }

/// Represents metadata associated with a single file-offset range, including
/// the covered byte range itself and the corresponding section information.
and OffsetRangeInfo =
  { Range: FileOffsetRange
    SectionRange: SectionRange }

/// Represents a file offset range.
and FileOffsetRange =
  { Start: uint32
    End: uint32 }

/// Represents the section range corresponding to a file offset range.
and SectionRange =
  | NoSection
  | SingleSection of string
  | MultipleSections of string * string

[<RequireQualifiedAccess>]
module OffsetSnapshot =
  let empty =
    { Selection = None
      Viewport = None }

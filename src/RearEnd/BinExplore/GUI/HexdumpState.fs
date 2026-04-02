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

open B2R2

/// Represents the full hexdump state, including the shared document and all
/// active view instances.
type HexdumpState =
  { Document: HexDocument
    Caret: int64 option
    Selection: HexSelection option
    AnnotationSpans: HexSpanStyle list
    HighlightSpans: HexSpanStyle list
    View: HexViewState }

/// Represents the shared hexdump document data.
and HexDocument =
  { BaseAddress: Addr
    Length: int64
    Bytes: byte[] }

/// Represents style information applied to a byte span.
and HexSpanStyle =
  { Start: int64
    Length: int64
    Foreground: string option
    Background: string option
    Priority: int }

/// Represents a contiguous selection inside the hexdump.
and HexSelection =
  { Anchor: int64
    Caret: int64 }

/// Represents layout and scroll state for a specific hexdump view.
and HexViewState =
  { ScrollRow: int64
    ScrollOffsetY: float
    ViewportWidth: float
    ViewportHeight: float
    CharWidth: float
    RowHeight: float
    BytesPerRow: int
    AddressDigits: int
    IsSelecting: bool
    HoveredByte: int64 option
    ScrollGuard: HexScrollGuard }

/// Represents a one-shot scroll guard for programmatic hexdump jumps.
and HexScrollGuard =
  | NoScrollGuard
  | IgnoreNextProgrammatic of deltaY: float
  | IgnoreNextEcho of deltaY: float

[<RequireQualifiedAccess>]
module HexViewState =
  let init numDigits =
    { ScrollRow = 0L
      ScrollOffsetY = 0.0
      ViewportWidth = 0.0
      ViewportHeight = 0.0
      CharWidth = 0.0
      RowHeight = 0.0
      BytesPerRow = 16
      AddressDigits = numDigits
      IsSelecting = false
      HoveredByte = None
      ScrollGuard = NoScrollGuard }

[<RequireQualifiedAccess>]
module HexDocument =
  let ofBytes baseAddress (bytes: byte[]) =
    { BaseAddress = baseAddress
      Length = bytes.LongLength
      Bytes = bytes }

[<RequireQualifiedAccess>]
module HexdumpState =
  let ofBytes baseAddress bytes numDigits =
    { Document = HexDocument.ofBytes baseAddress bytes
      Caret = None
      Selection = None
      AnnotationSpans = []
      HighlightSpans = []
      View = HexViewState.init numDigits }

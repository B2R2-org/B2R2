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

namespace B2R2.FrontEnd.BinFile.PE

open B2R2.FrontEnd.BinLifter

/// Represents one data directory, which names a table of the image by where
/// it begins and how far it runs.
type internal DataDirectory =
  { /// Where the table begins, relative to the image base.
    RVA: int
    /// How many bytes the table takes up.
    Size: int }

[<RequireQualifiedAccess>]
module internal DataDirectory =
  /// The number of bytes one data directory takes on disk.
  let [<Literal>] EntrySize = 8

  /// How many data directories an optional header ends with, which is what
  /// NumberOfRvaAndSizes counts and what every image in use gives it.
  let [<Literal>] Count = 16

  /// Returns the data directory the given offset of the given span reads as.
  let read (span: ByteSpan) (reader: IBinReader) offset =
    { RVA = reader.ReadInt32(span, offset)
      Size = reader.ReadInt32(span, offset + 4) }

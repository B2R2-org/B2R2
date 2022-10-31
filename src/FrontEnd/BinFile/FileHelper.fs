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

module internal B2R2.FrontEnd.BinFile.FileHelper

open B2R2

let peekUIntOfType (span: ByteSpan) (reader: IBinReader) bitType o =
  if bitType = WordSize.Bit32 then reader.ReadUInt32 (span, o) |> uint64
  else reader.ReadUInt64 (span, o)

let readUIntOfType span reader bitType o =
  let inline sizeByCls bitType = if bitType = WordSize.Bit32 then 4 else 8
  struct (peekUIntOfType span reader bitType o, o + sizeByCls bitType)

let peekHeaderB (span: ByteSpan) (reader: IBinReader) cls offset d32 d64 =
  reader.ReadByte (span, offset + (if cls = WordSize.Bit32 then d32 else d64))

let peekHeaderU16 (span: ByteSpan) (reader: IBinReader) cls offset d32 d64 =
  reader.ReadUInt16 (span, offset + (if cls = WordSize.Bit32 then d32 else d64))

let peekHeaderI32 (span: ByteSpan) (reader: IBinReader) cls offset d32 d64 =
  reader.ReadInt32 (span, offset + (if cls = WordSize.Bit32 then d32 else d64))

let peekHeaderU32 (span: ByteSpan) (reader: IBinReader) cls offset d32 d64 =
  reader.ReadUInt32 (span, offset + (if cls = WordSize.Bit32 then d32 else d64))

let peekHeaderNative span reader cls offset d32 d64 =
  let offset = offset + (if cls = WordSize.Bit32 then d32 else d64)
  peekUIntOfType span reader cls offset

let rec private cstrLoop (span: ByteSpan) acc pos =
  let byte = span[pos]
  if byte = 0uy then List.rev (0uy :: acc) |> List.toArray
  else cstrLoop span (byte :: acc) (pos + 1)

let peekCString (span: ByteSpan) offset =
  let bs = cstrLoop span [] offset
  ByteArray.extractCString bs 0

let addInvRange set saddr eaddr =
  if saddr = eaddr then set
  else IntervalSet.add (AddrRange (saddr, eaddr - 1UL)) set

let addLastInvRange wordSize (set, saddr) =
  let laddr =
    if wordSize = WordSize.Bit32 then 0xFFFFFFFFUL else 0xFFFFFFFFFFFFFFFFUL
  IntervalSet.add (AddrRange (saddr, laddr)) set

/// Trim the target range based on my range (myrange) in such a way that the
/// resulting range is always included in myrange.
let trimByRange myrange target =
  let l = max (AddrRange.GetMin myrange) (AddrRange.GetMin target)
  let h = min (AddrRange.GetMax myrange) (AddrRange.GetMax target)
  AddrRange (l, h)

let getNotInFileIntervals fileBase fileSize (range: AddrRange) =
  let lastAddr = fileBase + fileSize - 1UL
  if range.Max < fileBase then Seq.singleton range
  elif range.Max <= lastAddr && range.Min < fileBase then
    Seq.singleton (AddrRange (range.Min, fileBase - 1UL))
  elif range.Max > lastAddr && range.Min < fileBase then
    [ AddrRange (range.Min, fileBase - 1UL)
      AddrRange (lastAddr + 1UL, range.Max) ]
    |> List.toSeq
  elif range.Max > lastAddr && range.Min <= lastAddr then
    Seq.singleton (AddrRange (lastAddr + 1UL, range.Max))
  elif range.Max > lastAddr && range.Min > lastAddr then Seq.singleton range
  else Seq.empty

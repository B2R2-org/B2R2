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

module internal B2R2.BinFile.FileHelper

open B2R2

let peekUIntOfType (reader: BinReader) bitType o =
  if bitType = WordSize.Bit32 then reader.PeekUInt32 (o) |> uint64
  else reader.PeekUInt64 (o)

let readUIntOfType reader bitType o =
  let inline sizeByCls bitType = if bitType = WordSize.Bit32 then 4 else 8
  struct (peekUIntOfType reader bitType o, o + sizeByCls bitType)

let peekHeaderB (reader: BinReader) cls offset d32 d64 =
  offset + (if cls = WordSize.Bit32 then d32 else d64)
  |> reader.PeekByte

let peekHeaderU16 (reader: BinReader) cls offset d32 d64 =
  offset + (if cls = WordSize.Bit32 then d32 else d64)
  |> reader.PeekUInt16

let peekHeaderI32 (reader: BinReader) cls offset d32 d64 =
  offset + (if cls = WordSize.Bit32 then d32 else d64)
  |> reader.PeekInt32

let peekHeaderU32 (reader: BinReader) cls offset d32 d64 =
  offset + (if cls = WordSize.Bit32 then d32 else d64)
  |> reader.PeekUInt32

let peekHeaderNative reader cls offset d32 d64 =
  offset + (if cls = WordSize.Bit32 then d32 else d64)
  |> peekUIntOfType reader cls

let peekCString (reader: BinReader) offset =
  let rec loop acc pos =
    let byte = reader.PeekByte pos
    if byte = 0uy then List.rev (0uy :: acc) |> List.toArray
    else loop (byte :: acc) (pos + 1)
  let bs = loop [] offset
  ByteArray.extractCString bs 0

let peekCStringOfSize (reader: BinReader) offset (size: int) =
  let bs = reader.PeekBytes (size, offset)
  let bs = if bs.[bs.Length - 1] <> 0uy then Array.append bs [| 0uy |] else bs
  ByteArray.extractCString bs 0

let addInvRange set saddr eaddr =
  if saddr = eaddr then set
  else IntervalSet.add (AddrRange (saddr, eaddr)) set

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

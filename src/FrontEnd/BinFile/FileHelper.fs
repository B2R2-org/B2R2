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

open System
open System.IO
open B2R2

/// Pick a number based on the word size.
let inline pickNum wordSize o32 o64 =
  if wordSize = WordSize.Bit32 then o32 else o64

let readUIntOfType (span: ByteSpan) (reader: IBinReader) cls o =
  if cls = WordSize.Bit32 then reader.ReadUInt32 (span, o) |> uint64
  else reader.ReadUInt64 (span, o)

let readNative span reader cls d32 d64 =
  readUIntOfType span reader cls (pickNum cls d32 d64)

let rec private cstrLoop (span: ByteSpan) acc pos =
  let byte = span[pos]
  if byte = 0uy then List.rev (0uy :: acc) |> List.toArray
  else cstrLoop span (byte :: acc) (pos + 1)

let readCString (span: ByteSpan) offset =
  let bs = cstrLoop span [] offset
  ByteArray.extractCString bs 0

let readCStringFromStream (stream: Stream) offset =
  stream.Seek (int64 offset, SeekOrigin.Begin) |> ignore
  let rec loop acc =
    let b = stream.ReadByte ()
    if b = 0 then List.rev (char 0 :: acc) |> List.toArray
    elif b < 0 then raise InvalidFileFormatException
    else loop (char b :: acc)
  loop [] |> String

let addInvalidRange set saddr eaddr =
  if saddr = eaddr then set
  else IntervalSet.add (AddrRange (saddr, eaddr - 1UL)) set

let addLastInvalidRange wordSize (set, saddr) =
  let laddr =
    if wordSize = WordSize.Bit32 then 0xFFFFFFFFUL else 0xFFFFFFFFFFFFFFFFUL
  IntervalSet.add (AddrRange (saddr, laddr)) set

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

let readOrDie (s: Stream) buf =
  let count = s.Read (buf, 0, buf.Length)
  if count = buf.Length then ()
  else raise InvalidFileFormatException

let readChunk (stream: Stream) (offset: uint64) size =
  let buf = Array.zeroCreate size
  (stream: Stream).Seek (int64 offset, SeekOrigin.Begin) |> ignore
  readOrDie stream buf
  buf

let readUInt32 (stream: Stream) (reader: IBinReader) (offset: uint64) =
  let buf = Array.zeroCreate 4
  stream.Seek (int64 offset, SeekOrigin.Begin) |> ignore
  readOrDie stream buf
  reader.ReadUInt32 (buf, 0)

let readInt32 (stream: Stream) (reader: IBinReader) (offset: int) =
  let buf = Array.zeroCreate 4
  stream.Seek (int64 offset, SeekOrigin.Begin) |> ignore
  readOrDie stream buf
  reader.ReadInt32 (buf, 0)

let readInt16 (stream: Stream) (reader: IBinReader) (offset: int) =
  let buf = Array.zeroCreate 4
  stream.Seek (int64 offset, SeekOrigin.Begin) |> ignore
  readOrDie stream buf
  reader.ReadInt16 (buf, 0)

let readNativeFromStream (stream: Stream) (reader: IBinReader) cls offset =
  let buf = Array.zeroCreate <| WordSize.toByteWidth cls
  stream.Seek (int64 offset, SeekOrigin.Begin) |> ignore
  readOrDie stream buf
  if cls = WordSize.Bit32 then reader.ReadUInt32 (buf, 0) |> uint64
  else reader.ReadUInt64 (buf, 0)

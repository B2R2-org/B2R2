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

/// Parses the Apple-specific compact unwind table (`__TEXT,__unwind_info`),
/// which replaces DWARF `__eh_frame` on modern macOS (especially arm64). We
/// only recover what the format-agnostic exception model needs: per-function
/// address ranges and their LSDA pointers. The compact register-restore
/// encodings are intentionally ignored.
module internal B2R2.FrontEnd.BinFile.Mach.CompactUnwind

open System
open B2R2.FrontEnd.BinLifter

let [<Literal>] private RegularPage = 2u

let [<Literal>] private CompressedPage = 3u

let [<Literal>] private FuncOffsetMask = 0x00FFFFFFu

/// First-level index entry: the function offset it starts at, the section
/// offset of its second-level page, and the section offset of its LSDA index
/// array. The last entry is a sentinel whose function offset marks the end of
/// the final function and whose page offset is zero.
[<Struct>]
type private IndexEntry =
  { FuncOffset: uint32
    PageOffset: uint32
    LSDAOffset: uint32 }

let private readIndex (span: ByteSpan) (reader: IBinReader) off count =
  let entries = Array.zeroCreate count
  let mutable i = 0
  while i < count do
    let b = off + i * 12
    entries[i] <-
      { FuncOffset = reader.ReadUInt32(span, b)
        PageOffset = reader.ReadUInt32(span, b + 4)
        LSDAOffset = reader.ReadUInt32(span, b + 8) }
    i <- i + 1
  entries

/// Reads every LSDA index array, mapping a function offset to its LSDA offset.
let private readLSDAMap (span: ByteSpan) (reader: IBinReader) (index: _[]) =
  let map = Collections.Generic.Dictionary<uint32, uint32>()
  let mutable i = 0
  while i < index.Length - 1 do
    let mutable off = int index[i].LSDAOffset
    let endOff = int index[i + 1].LSDAOffset
    while off < endOff do
      map[reader.ReadUInt32(span, off)] <- reader.ReadUInt32(span, off + 4)
      off <- off + 8
    i <- i + 1
  map

/// Collects every function start offset (image-relative) from the second-level
/// pages, in ascending order.
let private collectFuncOffsets span (reader: IBinReader) (index: _[]) =
  let offs = Collections.Generic.List<uint32>()
  let mutable i = 0
  while i < index.Length - 1 do
    let pageOff = int index[i].PageOffset
    if pageOff <> 0 then
      let kind = reader.ReadUInt32(span = span, offset = pageOff)
      let entryStart = pageOff + int (reader.ReadUInt16(span, pageOff + 4))
      let entryCount = int (reader.ReadUInt16(span, pageOff + 6))
      let mutable e = 0
      if kind = RegularPage then
        while e < entryCount do
          offs.Add(reader.ReadUInt32(span, entryStart + e * 8))
          e <- e + 1
      elif kind = CompressedPage then
        let funcBase = index[i].FuncOffset
        while e < entryCount do
          let v = reader.ReadUInt32(span, entryStart + e * 4)
          offs.Add(funcBase + (v &&& FuncOffsetMask))
          e <- e + 1
      else ()
    else ()
    i <- i + 1
  offs

/// Parses `__unwind_info`, returning per-function (start, end, LSDA address)
/// tuples with addresses resolved against the image base (the __TEXT vmaddr).
let parse (bytes: byte[]) (reader: IBinReader) secOffset secSize imageBase =
  let span = ReadOnlySpan(bytes, secOffset, secSize)
  if secSize < 28 || reader.ReadUInt32(span, 0) <> 1u then
    []
  else
    let indexOff = int (reader.ReadUInt32(span, 20))
    let indexCount = int (reader.ReadUInt32(span, 24))
    if indexCount < 2 then
      []
    else
      let index = readIndex span reader indexOff indexCount
      let lsdaMap = readLSDAMap span reader index
      let funcs = collectFuncOffsets span reader index
      let lastEnd = index[indexCount - 1].FuncOffset
      [ for j in 0 .. funcs.Count - 1 do
          let fo = funcs[j]
          let fend = if j < funcs.Count - 1 then funcs[j + 1] else lastEnd
          let lsda =
            match lsdaMap.TryGetValue fo with
            | true, lo -> Some(imageBase + uint64 lo)
            | _ -> None
          imageBase + uint64 fo, imageBase + uint64 fend, lsda ]

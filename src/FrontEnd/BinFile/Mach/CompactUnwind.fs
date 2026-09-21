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
/// address ranges, their LSDA pointers and their personality routines. The
/// compact register-restore encodings are intentionally ignored.
module internal B2R2.FrontEnd.BinFile.Mach.CompactUnwind

open System
open B2R2.FrontEnd.BinLifter

let [<Literal>] private RegularPage = 2u

let [<Literal>] private CompressedPage = 3u

let [<Literal>] private FuncOffsetMask = 0x00FFFFFFu

let [<Literal>] private PersonalityMask = 0x30000000u

let [<Literal>] private PersonalityShift = 28

/// Section offsets and counts from the `__unwind_info` header, which the entry
/// encodings index into.
[<Struct>]
type private Header =
  { CommonEncodingsOffset: uint32
    CommonEncodingsCount: uint32
    PersonalityOffset: uint32
    PersonalityCount: uint32
    IndexOffset: uint32
    IndexCount: uint32 }

/// First-level index entry: the function offset it starts at, the section
/// offset of its second-level page, and the section offset of its LSDA index
/// array. The last entry is a sentinel whose function offset marks the end of
/// the final function and whose page offset is zero.
[<Struct>]
type private IndexEntry =
  { FuncOffset: uint32
    PageOffset: uint32
    LSDAOffset: uint32 }

/// Second-level page entry, pairing a function with its compact encoding. The
/// field is named apart from IndexEntry.FuncOffset, as an untyped record field
/// otherwise resolves to whichever type declares it last.
[<Struct>]
type private Entry =
  { /// Image-relative offset the function starts at.
    Start: uint32
    /// Compact encoding that describes how to unwind the function.
    Encoding: uint32 }

let private readHeader (span: ByteSpan) (reader: IBinReader) =
  { CommonEncodingsOffset = reader.ReadUInt32(span, 4)
    CommonEncodingsCount = reader.ReadUInt32(span, 8)
    PersonalityOffset = reader.ReadUInt32(span, 12)
    PersonalityCount = reader.ReadUInt32(span, 16)
    IndexOffset = reader.ReadUInt32(span, 20)
    IndexCount = reader.ReadUInt32(span, 24) }

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

/// Reads the personality array, whose entries are image-relative offsets to
/// the pointer-sized slots that hold the personality routines.
let private readPersonalities span (reader: IBinReader) hdr imageBase =
  let count = int hdr.PersonalityCount
  let slots = Array.zeroCreate count
  let mutable i = 0
  while i < count do
    let off = int hdr.PersonalityOffset + i * 4
    let slot = reader.ReadUInt32(span = span, offset = off)
    slots[i] <- imageBase + uint64 slot
    i <- i + 1
  slots

/// Reads the encoding a compressed-page entry names, which indexes the
/// section-wide common encodings array or, past its end, the page's own one.
let private readEncoding span (reader: IBinReader) hdr pageOff idx =
  if idx < hdr.CommonEncodingsCount then
    let off = int hdr.CommonEncodingsOffset + int idx * 4
    reader.ReadUInt32(span = span, offset = off)
  else
    let localOff = pageOff + int (reader.ReadUInt16(span, pageOff + 8))
    let localCount = uint32 (reader.ReadUInt16(span, pageOff + 10))
    let localIdx = idx - hdr.CommonEncodingsCount
    if localIdx < localCount then
      reader.ReadUInt32(span, localOff + int localIdx * 4)
    else
      0u

/// Collects every function of the second-level pages, in ascending order of
/// their image-relative start offsets.
let private collectEntries span (reader: IBinReader) hdr (index: _[]) =
  let entries = Collections.Generic.List<Entry>()
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
          let b = entryStart + e * 8
          let enc = reader.ReadUInt32(span, b + 4)
          entries.Add { Start = reader.ReadUInt32(span, b); Encoding = enc }
          e <- e + 1
      elif kind = CompressedPage then
        let funcBase = index[i].FuncOffset
        while e < entryCount do
          let v = reader.ReadUInt32(span, entryStart + e * 4)
          let enc = readEncoding span reader hdr pageOff (v >>> 24)
          entries.Add { Start = funcBase + (v &&& FuncOffsetMask)
                        Encoding = enc }
          e <- e + 1
      else
        ()
    else
      ()
    i <- i + 1
  entries

/// Returns the slot holding the personality routine that the given compact
/// encoding names, or None when it names none (a personality index of zero).
let private toPersonality (slots: _[]) enc =
  let idx = int ((enc &&& PersonalityMask) >>> PersonalityShift)
  if idx = 0 || idx > slots.Length then None
  else Some slots[idx - 1]

/// Parses `__unwind_info`, returning a frame per function with its addresses
/// resolved against the image base (the __TEXT vmaddr).
let parse (bytes: byte[]) (reader: IBinReader) secOffset secSize imageBase =
  let span = ReadOnlySpan(bytes, secOffset, secSize)
  if secSize < 28 || reader.ReadUInt32(span, 0) <> 1u then
    []
  else
    let hdr = readHeader span reader
    let indexCount = int hdr.IndexCount
    if indexCount < 2 then
      []
    else
      let index = readIndex span reader (int hdr.IndexOffset) indexCount
      let lsdaMap = readLSDAMap span reader index
      let slots = readPersonalities span reader hdr imageBase
      let entries = collectEntries span reader hdr index
      let lastEnd = index[indexCount - 1].FuncOffset
      [ for j in 0 .. entries.Count - 1 do
          let entry = entries[j]
          let fend =
            if j < entries.Count - 1 then entries[j + 1].Start else lastEnd
          let lsda =
            match lsdaMap.TryGetValue entry.Start with
            | true, lo -> Some(imageBase + uint64 lo)
            | _ -> None
          { FuncStart = imageBase + uint64 entry.Start
            FuncEnd = imageBase + uint64 fend
            LSDAPointer = lsda
            PersonalityRoutine = toPersonality slots entry.Encoding } ]

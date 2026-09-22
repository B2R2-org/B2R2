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

open System
open B2R2
open B2R2.FrontEnd.BinFile.ByteWriter

/// Writes an editable image back out as the bytes of a PE file. Every field
/// goes back where the parser read it from, so that emitting an image nothing
/// has touched hands back the file it came from, byte for byte.
[<RequireQualifiedAccess>]
module internal Emitter =
  /// PE is a little-endian format throughout, whatever the machine the code
  /// it carries is for.
  let private endian = Endian.Little

  /// The number of bytes the name field of a section header takes.
  let [<Literal>] private NameSize = 8

  /// Writes the one field of the COFF header an edit here can change. The
  /// rest is left as the original file has it, nothing modelling it.
  let private writeCoffHeader (span: Span<byte>) (img: Image) =
    let count = uint16 img.Sections.Length
    writeUInt16 span endian (img.CoffHeaderOffset + 2) count

  /// Writes the standard fields, which are those a COFF image of any system
  /// has. The base of data is a 32-bit image's alone: a 64-bit one spends
  /// that field and the one after it on an image base twice as wide.
  let private writeStandardFields (span: Span<byte>) (img: Image) at =
    let hdr = img.OptionalHeader
    writeUInt16 span endian at (uint16 hdr.Magic)
    writeUInt8 span (at + 2) hdr.MajorLinkerVersion
    writeUInt8 span (at + 3) hdr.MinorLinkerVersion
    writeUInt32 span endian (at + 4) (uint32 hdr.SizeOfCode)
    writeUInt32 span endian (at + 8) (uint32 hdr.SizeOfInitializedData)
    writeUInt32 span endian (at + 12) (uint32 hdr.SizeOfUninitializedData)
    writeUInt32 span endian (at + 16) (uint32 hdr.AddressOfEntryPoint)
    writeUInt32 span endian (at + 20) (uint32 hdr.BaseOfCode)
    if hdr.Magic = PEMagic.PE32 then
      writeUInt32 span endian (at + 24) (uint32 hdr.BaseOfData)
      writeUInt32 span endian (at + 28) (uint32 hdr.ImageBase)
    else
      writeUInt64 span endian (at + 24) hdr.ImageBase

  /// Writes one of the four sizes the header ends with. Each is a word of
  /// the image's own width, so which of them is meant says where it sits.
  let private writeSize (span: Span<byte>) magic at idx (v: uint64) =
    if magic = PEMagic.PE32 then
      writeUInt32 span endian (at + 72 + idx * 4) (uint32 v)
    else
      writeUInt64 span endian (at + 72 + idx * 8) v

  /// Writes the Windows-specific fields that follow the standard ones. The
  /// size of the image is the one of them the layout has the last word on,
  /// a section the image added being what makes it grow; the sizes counting
  /// what the sections hold are left as the linker wrote them, those being
  /// no part of how a file is loaded and no two linkers counting them alike.
  let private writeWindowsFields (span: Span<byte>) (img: Image) at imageSize =
    let hdr = img.OptionalHeader
    writeUInt32 span endian (at + 32) (uint32 hdr.SectionAlignment)
    writeUInt32 span endian (at + 36) (uint32 hdr.FileAlignment)
    writeUInt16 span endian (at + 40) hdr.MajorOperatingSystemVersion
    writeUInt16 span endian (at + 42) hdr.MinorOperatingSystemVersion
    writeUInt16 span endian (at + 44) hdr.MajorImageVersion
    writeUInt16 span endian (at + 46) hdr.MinorImageVersion
    writeUInt16 span endian (at + 48) hdr.MajorSubsystemVersion
    writeUInt16 span endian (at + 50) hdr.MinorSubsystemVersion
    writeUInt32 span endian (at + 56) (uint32 (imageSize: int))
    writeUInt32 span endian (at + 60) (uint32 hdr.SizeOfHeaders)
    writeUInt32 span endian (at + 64) hdr.CheckSum
    writeUInt16 span endian (at + 68) (uint16 hdr.Subsystem)
    writeUInt16 span endian (at + 70) (uint16 hdr.DllCharacteristics)
    writeSize span hdr.Magic at 0 hdr.SizeOfStackReserve
    writeSize span hdr.Magic at 1 hdr.SizeOfStackCommit
    writeSize span hdr.Magic at 2 hdr.SizeOfHeapReserve
    writeSize span hdr.Magic at 3 hdr.SizeOfHeapCommit
    let countAt = if hdr.Magic = PEMagic.PE32 then at + 92 else at + 108
    writeUInt32 span endian countAt (uint32 hdr.NumberOfRvaAndSizes)

  /// Writes the data directories the header ends with, all sixteen of them.
  let private writeDirectories (span: Span<byte>) (img: Image) at =
    let hdr = img.OptionalHeader
    let start = at + (if hdr.Magic = PEMagic.PE32 then 96 else 112)
    for i = 0 to DataDirectory.Count - 1 do
      let entAt = start + i * DataDirectory.EntrySize
      writeUInt32 span endian entAt (uint32 hdr.Directories[i].RVA)
      writeUInt32 span endian (entAt + 4) (uint32 hdr.Directories[i].Size)

  let private writeOptionalHeader (span: Span<byte>) (img: Image) layout =
    let at = img.OptionalHeaderOffset
    writeStandardFields span img at
    writeWindowsFields span img at layout.SizeOfImage
    writeDirectories span img at

  /// Writes one section header into the span covering its own entry. The
  /// name goes back as the eight bytes it was read as, the string the parsed
  /// header holds having lost whatever padding followed it.
  let private writeSectionHdr (dst: Span<byte>) entry offset rva =
    let sec = entry.SecHeader
    ReadOnlySpan(entry.NameBytes).CopyTo(dst.Slice(0, NameSize))
    writeUInt32 dst endian 8 (uint32 sec.VirtualSize)
    writeUInt32 dst endian 12 (uint32 (rva: int))
    writeUInt32 dst endian 16 (uint32 sec.SizeOfRawData)
    writeUInt32 dst endian 20 (uint32 (offset: int))
    writeUInt32 dst endian 24 (uint32 sec.PointerToRelocations)
    writeUInt32 dst endian 28 (uint32 sec.PointerToLineNumbers)
    writeUInt16 dst endian 32 sec.NumberOfRelocations
    writeUInt16 dst endian 34 sec.NumberOfLineNumbers
    writeUInt32 dst endian 36 (uint32 sec.SectionCharacteristics)

  let private writeSectionHeaders (span: Span<byte>) (img: Image) layout =
    let entSize = SectionHeaders.EntrySize
    for i = 0 to img.Sections.Length - 1 do
      let dst = span.Slice(img.SectionHeaderTblOffset + i * entSize, entSize)
      let offset, rva = layout.SectionOffsets[i], layout.SectionRVAs[i]
      writeSectionHdr dst img.Sections[i] offset rva

  /// Puts the bytes of every section the image was given where the layout
  /// says they go, which is where the file already kept them wherever the
  /// section keeps the place the file gave it.
  let private writeContents (out: byte[]) (img: Image) (layout: Layout) =
    for i = 0 to img.Sections.Length - 1 do
      match img.Sections[i].Content with
      | InFile ->
        ()
      | Given bytes ->
        Array.blit bytes 0 out layout.SectionOffsets[i] bytes.Length

  /// Lays the byte edits over what the structures have written. They come
  /// last so that one of them can reach whatever no structure here models,
  /// and oldest first so that a later edit of the same bytes is the one that
  /// stands.
  let private applyPatches (out: byte[]) (img: Image) =
    for patch in List.rev img.Patches do
      Array.blit patch.Bytes 0 out patch.Offset patch.Bytes.Length

  /// Writes the checksum of the file into the field holding it: the ones'
  /// complement sum of the whole file taken a word at a time, with the
  /// length of the file added to it. The field counts as zero towards the
  /// sum, so it is zeroed first rather than skipped over, which is what a
  /// reader checking the file has to do as well.
  let private writeChecksum (out: byte[]) (img: Image) =
    let at = img.OptionalHeaderOffset + 64
    writeUInt32 (Span out) endian at 0u
    let mutable sum = 0u
    for i in 0 .. 2 .. out.Length - 1 do
      let hi = if i + 1 < out.Length then uint32 out[i + 1] else 0u
      sum <- sum + (uint32 out[i] ||| (hi <<< 8))
      sum <- (sum &&& 0xffffu) + (sum >>> 16)
    let sum = ((sum &&& 0xffffu) + (sum >>> 16)) + uint32 out.Length
    writeUInt32 (Span out) endian at sum

  /// Returns the bytes of the PE file the given image describes.
  let emit (img: Image) =
    let layout = Layout.compute img
    let out = Array.zeroCreate layout.Size
    Array.blit img.Original 0 out 0 img.KeptLength
    writeContents out img layout
    let span = Span out
    writeCoffHeader span img
    writeOptionalHeader span img layout
    writeSectionHeaders span img layout
    applyPatches out img
    if img.RecomputeChecksum then writeChecksum out img else ()
    out

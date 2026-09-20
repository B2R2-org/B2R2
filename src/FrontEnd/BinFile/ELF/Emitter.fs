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

namespace B2R2.FrontEnd.BinFile.ELF

open System
open B2R2.FrontEnd.BinFile.FileHelper
open B2R2.FrontEnd.BinFile.ByteWriter

/// Writes an editable image back out as the bytes of an ELF file. Every field
/// goes back where the parser read it from, so that emitting an image nothing
/// has touched hands back the file it came from, byte for byte.
[<RequireQualifiedAccess>]
module internal Emitter =
  /// The value e_phnum and e_shstrndx carry when what they hold is too large
  /// for their sixteen bits; e_shnum carries zero for the same reason.
  let [<Literal>] private ExtendedNum = 0xffffus

  /// Returns the field as it goes back on disk. An escape stays the escape,
  /// because the value it hides is written where a reader looks for it, in the
  /// initial section header; any other field holds the value itself.
  let private encodeNum escape encoded value =
    if encoded = escape then escape else uint16 (value: int)

  /// Writes every ELF header field the image models. The identification bytes
  /// are not among them: e_ident is only ever read in part, so it is left as
  /// the original file has it rather than rebuilt out of the pieces.
  let private writeHeader (span: Span<byte>) (img: Image) layout =
    let hdr = img.Header
    let endian, cls = hdr.Endian, hdr.Class
    writeUInt16 span endian 16 (uint16 hdr.ELFType)
    writeInt16 span endian 18 (int16 hdr.MachineType)
    writeUIntByWordSize span endian cls 24 (hdr.EntryPoint - img.BaseAddress)
    writeUIntByWordSizeAndOffset span endian cls 28 32 hdr.PHdrTblOffset
    writeUIntByWordSizeAndOffset span endian cls 32 40 layout.SHdrTblOffset
    writeUInt32 span endian (selectByWordSize cls 36 48) hdr.ELFFlags
    writeUInt16 span endian (selectByWordSize cls 40 52) hdr.HeaderSize
    writeUInt16 span endian (selectByWordSize cls 42 54) hdr.PHdrEntrySize
    writeUInt16 span endian (selectByWordSize cls 46 58) hdr.SHdrEntrySize
    let phNum = encodeNum ExtendedNum img.EncodedPHdrNum hdr.PHdrNum
    let shNum = encodeNum 0us img.EncodedSHdrNum layout.SHdrNum
    let strIdx = encodeNum ExtendedNum img.EncodedSHdrStrIdx hdr.SHdrStrIdx
    writeUInt16 span endian (selectByWordSize cls 44 56) phNum
    writeUInt16 span endian (selectByWordSize cls 48 60) shNum
    writeUInt16 span endian (selectByWordSize cls 50 62) strIdx

  /// Writes one program header into the span covering its own entry.
  let private writeProgramHdr (dst: Span<byte>) (img: Image) ph =
    let endian, cls = img.Header.Endian, img.Header.Class
    writeUInt32 dst endian 0 (uint32 ph.PHType)
    writeUInt32 dst endian (selectByWordSize cls 24 4) (uint32 ph.PHFlags)
    writeUIntByWordSizeAndOffset dst endian cls 4 8 ph.PHOffset
    let addr = ph.PHAddr - img.BaseAddress
    writeUIntByWordSizeAndOffset dst endian cls 8 16 addr
    writeUIntByWordSizeAndOffset dst endian cls 12 24 ph.PHPhyAddr
    writeUIntByWordSizeAndOffset dst endian cls 16 32 ph.PHFileSize
    writeUIntByWordSizeAndOffset dst endian cls 20 40 ph.PHMemSize
    writeUIntByWordSizeAndOffset dst endian cls 28 48 ph.PHAlignment

  let private writeProgramHeaders (span: Span<byte>) (img: Image) layout =
    let entSize = selectByWordSize img.Header.Class 32 56
    let tblOffset = int img.Header.PHdrTblOffset
    for i = 0 to layout.ProgramHeaders.Length - 1 do
      let dst = span.Slice(tblOffset + i * entSize, entSize)
      writeProgramHdr dst img layout.ProgramHeaders[i]

  /// Returns the section header as it goes on disk. The initial one is where
  /// a file using the extended numbering keeps its section count, so what its
  /// sh_size holds is that count rather than a size of its own.
  let private effectiveHeader (img: Image) layout idx =
    let sec = img.Sections[idx].SecHeader
    let sec =
      { sec with
          SecOffset = layout.SectionOffsets[idx]
          SecAddr = layout.SectionAddrs[idx] }
    if idx = 0 && img.EncodedSHdrNum = 0us && img.Header.SHdrNum > 0 then
      { sec with SecSize = uint64 layout.SHdrNum }
    else
      sec

  /// Writes one section header into the span covering its own entry.
  let private writeSectionHdr (dst: Span<byte>) (img: Image) entry sec =
    let endian, cls = img.Header.Endian, img.Header.Class
    writeUInt32 dst endian 0 entry.NameOffset
    writeUInt32 dst endian 4 (uint32 sec.SecType)
    writeUIntByWordSize dst endian cls 8 (uint64 sec.SecFlags)
    let addr = sec.SecAddr - img.BaseAddress
    writeUIntByWordSizeAndOffset dst endian cls 12 16 addr
    writeUIntByWordSizeAndOffset dst endian cls 16 24 sec.SecOffset
    writeUIntByWordSizeAndOffset dst endian cls 20 32 sec.SecSize
    writeUInt32 dst endian (selectByWordSize cls 24 40) sec.SecLink
    writeUInt32 dst endian (selectByWordSize cls 28 44) sec.SecInfo
    writeUIntByWordSizeAndOffset dst endian cls 32 48 sec.SecAlignment
    writeUIntByWordSizeAndOffset dst endian cls 36 56 sec.SecEntrySize

  let private writeSectionHeaders (span: Span<byte>) (img: Image) layout =
    let entSize = int img.Header.SHdrEntrySize
    let tblOffset = int layout.SHdrTblOffset
    for i = 0 to img.Sections.Length - 1 do
      let dst = span.Slice(tblOffset + i * entSize, entSize)
      writeSectionHdr dst img img.Sections[i] (effectiveHeader img layout i)

  /// Puts the bytes of every section the image was given where the layout
  /// says they go, which is where the file already kept them wherever they
  /// are as many as were there.
  let private writeContents (out: byte[]) (img: Image) layout =
    for i = 0 to img.Sections.Length - 1 do
      match img.Sections[i].Content with
      | InFile ->
        ()
      | Given bytes ->
        Array.blit bytes 0 out (int layout.SectionOffsets[i]) bytes.Length

  /// Lays the byte edits over what the structures have written. They come
  /// last so that one of them can reach whatever no structure here models,
  /// and oldest first so that a later edit of the same bytes is the one that
  /// stands.
  let private applyPatches (out: byte[]) (img: Image) =
    for patch in List.rev img.Patches do
      Array.blit patch.Bytes 0 out patch.Offset patch.Bytes.Length

  /// Returns the bytes of the ELF file the given image describes.
  let emit (img: Image) =
    let layout = Layout.compute img
    let out = Array.zeroCreate layout.Size
    Array.blit img.Original 0 out 0 img.Original.Length
    writeContents out img layout
    let span = Span out
    writeHeader span img layout
    writeProgramHeaders span img layout
    writeSectionHeaders span img layout
    applyPatches out img
    out

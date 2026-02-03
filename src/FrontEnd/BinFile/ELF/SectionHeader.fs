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
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.FileHelper

/// Represents a section header in ELF.
type SectionHeader =
  { /// Unique section number.
    SecNum: int
    /// The name of the section (sh_name).
    SecName: string
    /// Categorizes the section's contents and semantics (sh_type).
    SecType: SectionType
    /// Misc. attributes about the section (sh_flags).
    SecFlags: SectionFlags
    /// The address at which the section's first byte should reside. If this
    /// section will not appear in the process memory, this value is 0.
    SecAddr: Addr
    /// Byte offset from the beginning of the file to the first byte in the
    /// section (sh_offset).
    SecOffset: uint64
    /// The section's size in bytes (sh_size).
    SecSize: uint64
    /// A section header table index link. The interpretation of this field
    /// depends on the section type (sh_link).
    SecLink: uint32
    /// Extra information. The interpretation of this info depends
    /// on the section type.
    SecInfo: uint32
    /// Some sections have address alignment constraints.
    SecAlignment: uint64
    /// Some sections hold a table of fixed-size entries, such as a symbol
    /// table. For such a section, this member gives the size in bytes of each
    /// entry.
    SecEntrySize: uint64 }

[<RequireQualifiedAccess>]
module internal SectionHeaders =
  /// Return the section file offset and size, which represents the section
  /// names separated by null character.
  let private parseSectionNameTableInfo hdr ({ Reader = reader } as toolBox) =
    let secPtr = hdr.SHdrTblOffset + uint64 (hdr.SHdrStrIdx * hdr.SHdrEntrySize)
    let cls = hdr.Class
    let ptrSize = WordSize.toByteWidth cls
    let shAddrOffset = 8UL + uint64 (ptrSize * 2)
    let shAddrPtr = secPtr + shAddrOffset (* pointer to sh_offset *)
    let shAddrSize = ptrSize * 2 (* sh_offset, sh_size *)
    try
      let span = ReadOnlySpan(toolBox.Bytes, int shAddrPtr, shAddrSize)
      let offset = readUIntByWordSize span reader cls 0
      let size = readUIntByWordSize span reader cls (selectByWordSize cls 4 8)
      ReadOnlySpan(toolBox.Bytes, int offset, int size)
    with _ ->
      eprintfn $"Warning: Failed to parse section name table."
      ReadOnlySpan<byte>()

  let private peekSecType (span: ByteSpan) (reader: IBinReader) =
    reader.ReadUInt32(span, 4)
    |> LanguagePrimitives.EnumOfValue: SectionType

  let private peekSecFlags span reader cls =
    readUIntByWordSize span reader cls 8
    |> LanguagePrimitives.EnumOfValue: SectionFlags

  let private parseSectionHdr toolBox num nameTbl (secHdr: ByteSpan) =
    let reader = toolBox.Reader
    let nameOffset = reader.ReadInt32(secHdr, 0)
    let cls = toolBox.Header.Class
    let baseAddr = toolBox.BaseAddress
    { SecNum = num
      SecName = ByteArray.extractCStringFromSpan nameTbl nameOffset
      SecType = peekSecType secHdr reader
      SecFlags = peekSecFlags secHdr reader cls
      SecAddr = readUIntByWordSizeAndOffset secHdr reader cls 12 16 + baseAddr
      SecOffset = readUIntByWordSizeAndOffset secHdr reader cls 16 24
      SecSize = readUIntByWordSizeAndOffset secHdr reader cls 20 32
      SecLink = reader.ReadUInt32(secHdr, selectByWordSize cls 24 40)
      SecInfo = reader.ReadUInt32(secHdr, selectByWordSize cls 28 44)
      SecAlignment = readUIntByWordSizeAndOffset secHdr reader cls 32 48
      SecEntrySize = readUIntByWordSizeAndOffset secHdr reader cls 36 56 }

  let parse ({ Bytes = bytes } as toolBox) =
    let hdr = toolBox.Header
    let nameTbl = parseSectionNameTableInfo hdr toolBox
    let secHdrEntrySize = int hdr.SHdrEntrySize
    let secHdrCount = int hdr.SHdrNum
    let secHeaders = Array.zeroCreate secHdrCount
    let mutable offset = int hdr.SHdrTblOffset
    for i = 0 to secHdrCount - 1 do
      let span = ReadOnlySpan(bytes, offset, secHdrEntrySize)
      let hdr = parseSectionHdr toolBox i nameTbl span
      secHeaders[i] <- hdr
      offset <- offset + secHdrEntrySize
    secHeaders

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

module internal B2R2.FrontEnd.BinFile.ELF.Section

open System
open System.IO
open B2R2
open B2R2.FrontEnd.BinFile.FileHelper

let [<Literal>] SecText = ".text"
let [<Literal>] SecROData = ".rodata"

/// Section information.
type SectionInfo = {
  /// Section by address.
  SecByAddr: ARMap<ELFSection>
  /// Section by name.
  SecByName: Map<string, ELFSection>
  /// Section by its number.
  SecByNum: ELFSection[]
  /// Static symbol section numbers.
  StaticSymSecNums: int list
  /// Dynamic symbol section numbers.
  DynSymSecNums: int list
  /// GNU version symbol section.
  VerSymSec: ELFSection option
  /// GNU version need section.
  VerNeedSec: ELFSection option
  /// GNU version definition section.
  VerDefSec: ELFSection option
}

let readNameTableRawData offset size (stream: Stream) =
  let nameTable = Array.zeroCreate (int size)
  stream.Seek (int64 offset, SeekOrigin.Begin) |> ignore
  readOrDie stream nameTable
  nameTable

/// Return the section file offset and size, which represents the section names
/// separated by null character.
let parseSectionNameTableInfo hdr (reader: IBinReader) (stream: Stream) =
  let secPtr = hdr.SHdrTblOffset + uint64 (hdr.SHdrStrIdx * hdr.SHdrEntrySize)
  let ptrSize = WordSize.toByteWidth hdr.Class
  let shAddrOffset = 8L + int64 (ptrSize * 2)
  let shAddrPtr = int64 secPtr + shAddrOffset (* pointer to sh_offset *)
  let buf = Array.zeroCreate (ptrSize * 2) (* sh_offset, sh_size *)
  stream.Seek (shAddrPtr, SeekOrigin.Begin) |> ignore
  readOrDie stream buf
  let span = ReadOnlySpan buf
  let struct (offset, next) = readUIntOfType span reader hdr.Class 0
  let size = peekUIntOfType span reader hdr.Class next
  readNameTableRawData offset size stream

let peekSecType (span: ByteSpan) (reader: IBinReader) =
  reader.ReadUInt32 (span, 4)
  |> LanguagePrimitives.EnumOfValue: SectionType

let peekSecFlags span reader cls =
  peekUIntOfType span reader cls 8
  |> LanguagePrimitives.EnumOfValue: SectionFlag

let parseSection baseAddr num nameTbl cls (span: ByteSpan) reader =
  let nameOffset = (reader: IBinReader).ReadInt32 (span, 0)
  { SecNum = num
    SecName = ByteArray.extractCString nameTbl nameOffset
    SecType = peekSecType span reader
    SecFlags = peekSecFlags span reader cls
    SecAddr = peekHeaderNative span reader cls 12 16 + baseAddr
    SecOffset = peekHeaderNative span reader cls 16 24
    SecSize = peekHeaderNative span reader cls 20 32
    SecLink = peekHeaderU32 span reader cls 24 40
    SecInfo = peekHeaderU32 span reader cls 28 44
    SecAlignment = peekHeaderNative span reader cls 32 48
    SecEntrySize = peekHeaderNative span reader cls 36 56 }

let parse stream reader hdr baseAddr =
  let nameTbl = parseSectionNameTableInfo hdr reader stream
  let secHdrCount = int hdr.SHdrNum
  let secHeaders = Array.zeroCreate secHdrCount
  let cls = hdr.Class
  let buf = Array.zeroCreate (int hdr.SHdrEntrySize)
  let rec parseLoop count =
    if count = secHdrCount then secHeaders
    else
      readOrDie stream buf
      let span = ReadOnlySpan buf
      let sec = parseSection baseAddr count nameTbl cls span reader
      secHeaders[count] <- sec
      parseLoop (count + 1)
  stream.Seek (int64 hdr.SHdrTblOffset, SeekOrigin.Begin) |> ignore
  parseLoop 0


////

let private readDynamicEntry reader cls span =
  let struct (dtag, next) = readUIntOfType span reader cls 0
  let dval = peekUIntOfType span reader cls next
  { DTag = LanguagePrimitives.EnumOfValue dtag; DVal = dval }

let parseDynamicSection cls reader (stream: Stream) (sec: ELFSection) =
  let numEntries = int sec.SecSize / int sec.SecEntrySize
  let entries = Array.zeroCreate numEntries
  let entryBuf = Array.zeroCreate (int sec.SecEntrySize)
  let rec parseLoop n =
    if n = numEntries then entries
    else
      readOrDie stream entryBuf
      let entry = readDynamicEntry reader cls (ReadOnlySpan entryBuf)
      entries[n] <- entry
      if entry.DTag = DynamicTag.DT_NULL && entry.DVal = 0UL then entries[0..n]
      else parseLoop (n + 1)
  stream.Seek (int64 sec.SecOffset, SeekOrigin.Begin) |> ignore
  parseLoop 0

let getDynamicSectionEntries hdr stream reader secHeaders =
  let dynamicSection =
    secHeaders |> Array.tryFind (fun s -> s.SecType = SectionType.SHTDynamic)
  match dynamicSection with
  | Some sec -> parseDynamicSection hdr.Class reader stream sec
  | None -> [||]

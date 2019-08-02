(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

module internal B2R2.BinFile.ELF.Section

open System
open B2R2
open B2R2.BinFile.FileHelper

/// Return the raw memory contents that represent the section names separated by
/// null character.
let parseSectionNameContents eHdr (reader: BinReader) =
  let off = eHdr.SHdrTblOffset + uint64 (eHdr.SHdrStrIdx * eHdr.SHdrEntrySize)
  let padding = (8 + (WordSize.toByteWidth eHdr.Class * 2))
  let pos = Convert.ToInt32 off + padding
  let struct (strOffset, nextOffset) = readUIntOfType reader eHdr.Class pos
  let size = peekUIntOfType reader eHdr.Class nextOffset
  reader.PeekBytes (Convert.ToInt32 size, Convert.ToInt32 strOffset)

let peekSecType (reader: BinReader) offset: SectionType =
  offset + 4 |> reader.PeekUInt32 |> LanguagePrimitives.EnumOfValue

let peekSecFlags (reader: BinReader) cls offset : SectionFlag =
  offset + 8
  |> peekUIntOfType reader cls
  |> LanguagePrimitives.EnumOfValue

let parseSection num strBytes cls (reader: BinReader) offset =
  { SecNum = num
    SecName = reader.PeekInt32 offset |> ByteArray.extractCString strBytes
    SecType = peekSecType reader offset
    SecFlags = peekSecFlags reader cls offset
    SecAddr = peekHeaderNative reader cls offset 12 16
    SecOffset = peekHeaderNative reader cls offset 16 24
    SecSize = peekHeaderNative reader cls offset 20 32
    SecLink = peekHeaderU32 reader cls offset 24 40
    SecInfo = peekHeaderU32 reader cls offset 28 44
    SecAlignment = peekHeaderNative reader cls offset 32 48
    SecEntrySize = peekHeaderNative reader cls offset 36 56 }

let inline hasSHFTLS flags =
  flags &&& SectionFlag.SHFTLS = SectionFlag.SHFTLS

let inline hasSHFAlloc flags =
  flags &&& SectionFlag.SHFAlloc = SectionFlag.SHFAlloc

let nextSecOffset cls offset =
  offset + (if cls = WordSize.Bit32 then 40 else 64)

let secHasValidAddr sec =
  (* .tbss has a meaningless virtual address as per
     https://stackoverflow.com/questions/25501044/. *)
  let secEndAddr = sec.SecAddr + sec.SecSize
  sec.SecAddr <> 0x0UL
  && not <| hasSHFTLS sec.SecFlags
  && secEndAddr > sec.SecAddr

let addSecToAddrMap sec map =
  if secHasValidAddr sec then
    let endAddr = sec.SecAddr + sec.SecSize
    ARMap.addRange sec.SecAddr endAddr sec map
  else map

let accSymbTabNum lst predicate sec =
  if predicate sec.SecType then sec.SecNum :: lst else lst

let isStatic t = t = SectionType.SHTSymTab

let isDynamic t = t = SectionType.SHTDynSym

let updateVerSec predicate sec = function
  | None -> if predicate sec.SecType then Some sec else None
  | s -> s

let isVerSym t = t = SectionType.SHTGNUVerSym

let isVerNeed t = t = SectionType.SHTGNUVerNeed

let isVerDef t = t = SectionType.SHTGNUVerDef

let parse eHdr reader =
  let nameContents = parseSectionNameContents eHdr reader
  let rec parseLoop secByNum info sIdx offset =
    if int eHdr.SHdrNum = sIdx then
      { info with SecByNum = List.rev secByNum |> Array.ofList }
    else
      let sec = parseSection sIdx nameContents eHdr.Class reader offset
      let nextOffset = nextSecOffset eHdr.Class offset
      let nextInfo =
        { info with
            SecByAddr = addSecToAddrMap sec info.SecByAddr
            SecByName = Map.add sec.SecName sec info.SecByName
            StaticSymSecNums = accSymbTabNum info.StaticSymSecNums isStatic sec
            DynSymSecNums = accSymbTabNum info.DynSymSecNums isDynamic sec
            VerSymSec = updateVerSec isVerSym sec info.VerSymSec
            VerNeedSec = updateVerSec isVerNeed sec info.VerNeedSec
            VerDefSec = updateVerSec isVerDef sec info.VerDefSec }
      parseLoop (sec :: secByNum) nextInfo (sIdx + 1) nextOffset
  let emptyInfo =
    { SecByAddr = ARMap.empty
      SecByName = Map.empty
      SecByNum = [||]
      StaticSymSecNums = []
      DynSymSecNums = []
      VerSymSec = None
      VerNeedSec = None
      VerDefSec = None }
  Convert.ToInt32 eHdr.SHdrTblOffset
  |> parseLoop [] emptyInfo 0

let parseDynamicSection (reader: BinReader) (sec: ELFSection) =
  let secStart = int sec.SecOffset
  let secEnd = secStart + int sec.SecSize
  let readSize = int (sec.SecEntrySize / 2UL)
  let readType: WordSize = LanguagePrimitives.EnumOfValue (readSize * 8)
  let rec readLoop acc offset =
    if offset >= secEnd then List.rev acc
    else
      let tag = peekUIntOfType reader readType offset
      let value = peekUIntOfType reader readType (offset + readSize)
      let entry = { DTag = LanguagePrimitives.EnumOfValue tag; DVal = value }
      let nextOffset = offset + readSize + readSize
      (* Ignore after null entry *)
      let nextOffset = if value = 0UL && tag = 0UL then secEnd else nextOffset
      readLoop (entry :: acc) nextOffset
  readLoop [] secStart
  |> Some

let getDynamicSectionEntries reader secInfo =
  secInfo.SecByNum
  |> Array.tryFind (fun s -> s.SecType = SectionType.SHTDynamic)
  |> Option.bind (parseDynamicSection reader)
  |> Option.defaultValue []

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
open B2R2
open B2R2.FrontEnd.BinFile.FileHelper

let [<Literal>] SecText = ".text"
let [<Literal>] SecROData = ".rodata"

/// Return the raw memory contents that represent the section names separated by
/// null character.
let parseSectionNameContents eHdr span reader =
  let off = eHdr.SHdrTblOffset + uint64 (eHdr.SHdrStrIdx * eHdr.SHdrEntrySize)
  let padding = (8 + (WordSize.toByteWidth eHdr.Class * 2))
  let pos = Convert.ToInt32 off + padding
  let struct (strOffset, nextOffset) = readUIntOfType span reader eHdr.Class pos
  let size = peekUIntOfType span reader eHdr.Class nextOffset
  span.Slice (Convert.ToInt32 strOffset, Convert.ToInt32 size)

let peekSecType (span: ByteSpan) (reader: IBinReader) offset =
  reader.ReadUInt32 (span, offset + 4)
  |> LanguagePrimitives.EnumOfValue: SectionType

let peekSecFlags span reader cls offset =
  peekUIntOfType span reader cls (offset + 8)
  |> LanguagePrimitives.EnumOfValue: SectionFlag

let parseSection baseAddr num names cls (span: ByteSpan) reader ofs =
  let nameOffset = (reader: IBinReader).ReadInt32 (span, ofs)
  { SecNum = num
    SecName = ByteArray.extractCStringFromSpan names nameOffset
    SecType = peekSecType span reader ofs
    SecFlags = peekSecFlags span reader cls ofs
    SecAddr = peekHeaderNative span reader cls ofs 12 16 + baseAddr
    SecOffset = peekHeaderNative span reader cls ofs 16 24
    SecSize = peekHeaderNative span reader cls ofs 20 32
    SecLink = peekHeaderU32 span reader cls ofs 24 40
    SecInfo = peekHeaderU32 span reader cls ofs 28 44
    SecAlignment = peekHeaderNative span reader cls ofs 32 48
    SecEntrySize = peekHeaderNative span reader cls ofs 36 56 }

let inline hasSHFTLS flags =
  flags &&& SectionFlag.SHFTLS = SectionFlag.SHFTLS

let inline hasSHFAlloc flags =
  flags &&& SectionFlag.SHFAlloc = SectionFlag.SHFAlloc

let nextSecOffset cls offset =
  offset + (if cls = WordSize.Bit32 then 40 else 64)

let secHasValidAddr baseAddr sec =
  (* .tbss has a meaningless virtual address as per
     https://stackoverflow.com/questions/25501044/. *)
  let secEndAddr = sec.SecAddr + sec.SecSize
  sec.SecAddr <> baseAddr
  && not <| hasSHFTLS sec.SecFlags
  && secEndAddr > sec.SecAddr

let addSecToAddrMap baseAddr sec map =
  if secHasValidAddr baseAddr sec then
    let endAddr = sec.SecAddr + sec.SecSize - 1UL
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

let rec parseLoop baseAddr eHdr span reader names secByNum info sIdx offset =
  if int eHdr.SHdrNum = sIdx then
    { info with SecByNum = List.rev secByNum |> Array.ofList }
  else
    let sec = parseSection baseAddr sIdx names eHdr.Class span reader offset
    let secByNum = sec :: secByNum
    let offset' = nextSecOffset eHdr.Class offset
    let info' =
      { info with
          SecByAddr = addSecToAddrMap baseAddr sec info.SecByAddr
          SecByName = Map.add sec.SecName sec info.SecByName
          StaticSymSecNums = accSymbTabNum info.StaticSymSecNums isStatic sec
          DynSymSecNums = accSymbTabNum info.DynSymSecNums isDynamic sec
          VerSymSec = updateVerSec isVerSym sec info.VerSymSec
          VerNeedSec = updateVerSec isVerNeed sec info.VerNeedSec
          VerDefSec = updateVerSec isVerDef sec info.VerDefSec }
    parseLoop baseAddr eHdr span reader names secByNum info' (sIdx + 1) offset'

let parse baseAddr eHdr span reader =
  let nameContents = parseSectionNameContents eHdr span reader
  let emptyInfo =
    { SecByAddr = ARMap.empty
      SecByName = Map.empty
      SecByNum = [||]
      StaticSymSecNums = []
      DynSymSecNums = []
      VerSymSec = None
      VerNeedSec = None
      VerDefSec = None }
  let offset = Convert.ToInt32 eHdr.SHdrTblOffset
  parseLoop baseAddr eHdr span reader nameContents [] emptyInfo 0 offset

let rec private readDynSecLoop acc span reader secEnd readType readSize offset =
  if offset >= secEnd then List.rev acc
  else
    let tag = peekUIntOfType span reader readType offset
    let value = peekUIntOfType span reader readType (offset + readSize)
    let ent = { DTag = LanguagePrimitives.EnumOfValue tag; DVal = value }
    let nextOffset = offset + readSize + readSize
    (* Ignore after null entry *)
    let nextOffset = if value = 0UL && tag = 0UL then secEnd else nextOffset
    readDynSecLoop (ent :: acc) span reader secEnd readType readSize nextOffset

let parseDynamicSection span reader (sec: ELFSection) =
  let secStart = int sec.SecOffset
  let secEnd = secStart + int sec.SecSize
  let readSize = int (sec.SecEntrySize / 2UL)
  let readType: WordSize = LanguagePrimitives.EnumOfValue (readSize * 8)
  readDynSecLoop [] span reader secEnd readType readSize secStart

let getDynamicSectionEntries span reader secInfo =
  let sec =
    secInfo.SecByNum
    |> Array.tryFind (fun s -> s.SecType = SectionType.SHTDynamic)
  match sec with
  | Some sec -> parseDynamicSection span reader sec
  | None -> []

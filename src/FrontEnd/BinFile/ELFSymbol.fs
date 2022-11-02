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

module internal B2R2.FrontEnd.BinFile.ELF.Symbol

open System
open System.Collections.Generic
open B2R2
open B2R2.Monads.Maybe
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

let getSymbKind ndx = function
  | SymbolType.STTObject -> SymObjectType
  | SymbolType.STTGNUIFunc
  | SymbolType.STTFunc ->
    if ndx = SHNUndef then SymNoType
    else SymFunctionType
  | SymbolType.STTSection -> SymSectionType
  | SymbolType.STTFile ->SymFileType
  | _ -> SymNoType

let versionToLibName version =
  match version with
  | Some version -> version.VerName
  | None -> ""

let toB2R2Symbol vis (symb: ELFSymbol) =
  { Address = symb.Addr
    Name = symb.SymName
    Kind = getSymbKind symb.SecHeaderIndex symb.SymType
    Visibility = vis
    LibraryName = versionToLibName symb.VerInfo
    ArchOperationMode = symb.ArchOperationMode }

let verName (strTab: ByteSpan) vnaNameOffset =
  if vnaNameOffset >= strTab.Length then ""
  else ByteArray.extractCStringFromSpan strTab vnaNameOffset

let rec parseNeededVerFromSecAux span (reader: IBinReader) strTab tbl pos =
  let idx = reader.ReadUInt16 (span=span, offset=pos + 6) (* vna_other *)
  let nameOffset = reader.ReadInt32 (span, pos + 8)
  (tbl: Dictionary<_, _>)[idx] <- verName strTab nameOffset
  let next = reader.ReadInt32 (span, pos + 12)
  if next = 0 then ()
  else parseNeededVerFromSecAux span reader strTab tbl (pos + next)

let rec parseNeededVerFromSec span (reader: IBinReader) strTab tbl pos =
  let auxOffset =
    reader.ReadInt32 (span=span, offset=pos + 8) + pos (* vn_aux + pos *)
  parseNeededVerFromSecAux span reader strTab tbl auxOffset
  let next = reader.ReadInt32 (span, pos + 12) (* vn_next *)
  if next = 0 then ()
  else parseNeededVerFromSec span reader strTab tbl (pos + next)

let parseNeededVersionTable tbl span reader strTab = function
  | None -> ()
  | Some sec ->
    parseNeededVerFromSec span reader strTab tbl (Convert.ToInt32 sec.SecOffset)

let rec parseDefinedVerFromSec span (reader: IBinReader) strTab tbl pos =
  let auxOffset =
    reader.ReadInt32 (span=span, offset=pos + 12) + pos (* vd_aux + pos *)
  let idx = reader.ReadUInt16 (span, pos + 4) (* vd_ndx *)
  let nameOffset = reader.ReadInt32 (span, auxOffset) (* vda_name *)
  (tbl: Dictionary<_, _>)[idx] <- verName strTab nameOffset
  let next = reader.ReadInt32 (span, pos + 16) (* vd_next *)
  if next = 0 then ()
  else parseDefinedVerFromSec span reader strTab tbl (pos + next)

let parseDefinedVersionTable tbl span reader strTab = function
  | None -> ()
  | Some sec ->
    parseDefinedVerFromSec span reader strTab tbl
      (Convert.ToInt32 sec.SecOffset)

let rec accumulateVerTbl (span: ByteSpan) reader secs tbl nlst =
  match nlst with
  | n :: rest ->
    let symTblSec = secs.SecByNum[n]
    let ss = secs.SecByNum[Convert.ToInt32 symTblSec.SecLink]
    let size = Convert.ToInt32 ss.SecSize
    let offset = Convert.ToInt32 ss.SecOffset
    let strTab = span.Slice (offset, size)
    parseNeededVersionTable tbl span reader strTab secs.VerNeedSec
    parseDefinedVersionTable tbl span reader strTab secs.VerDefSec
    accumulateVerTbl span reader secs tbl rest
  | [] -> tbl

let parseVersionTable secs (span: ByteSpan) reader =
  let tbl = Dictionary ()
  accumulateVerTbl span reader secs tbl secs.DynSymSecNums

let parseVersData span (reader: IBinReader) symIdx verSymSec =
  let pos = verSymSec.SecOffset + (symIdx * 2UL) |> Convert.ToInt32
  let versData = reader.ReadUInt16 (span=span, offset=pos)
  if versData > 1us then Some versData
  else None

let retrieveVer (vtbl: Dictionary<_, _>) verData =
  let t = if verData &&& 0x8000us = 0us then VerRegular else VerHidden
  match vtbl.TryGetValue (verData &&& 0x7fffus) with
  | true, verStr -> Some { VerType = t; VerName = verStr }
  | false, _ -> None

let adjustSymAddr baseAddr addr =
  if addr = 0UL then 0UL
  else addr + baseAddr

let readSymAddr baseAddr span reader cls parent txtOffset offset =
  let symAddrOffset = if cls = WordSize.Bit32 then 4 else 8
  let symAddr = peekUIntOfType span reader cls (offset + symAddrOffset)
  match (parent: ELFSection option) with
  | None -> symAddr
  | Some sec ->
    (* This is to give a meaningful address to static symbols in a relocatable
       object. We let .text section's address to be zero, and assume that the
       .text section always precedes the other sections. See
       https://github.com/B2R2-org/B2R2/issues/25 for more details. *)
    if sec.SecAddr = baseAddr && sec.SecOffset > txtOffset then
      sec.SecOffset - txtOffset + symAddr
    else symAddr
  |> adjustSymAddr baseAddr

let readSymSize span reader cls offset =
  let symSizeOffset = if cls = WordSize.Bit32 then 8 else 16
  peekUIntOfType span reader cls (offset + symSizeOffset)

let computeArchOpMode eHdr symbolName =
  if eHdr.MachineType = Architecture.ARMv7
    || eHdr.MachineType = Architecture.AARCH32
  then
    if symbolName = "$a" then ArchOperationMode.ARMMode
    elif symbolName = "$t" then ArchOperationMode.ThumbMode
    else ArchOperationMode.NoMode
  else ArchOperationMode.NoMode

let getVerInfo span reader vtbl symIdx secs =
  match secs.VerSymSec with
  | Some ssec ->
    parseVersData span reader symIdx ssec >>= retrieveVer vtbl
  | None -> None

let getSymbol baseAddr secs strTab vtbl eHdr span reader txt symIdx pos =
  let cls = eHdr.Class
  let nameIdx = (reader: IBinReader).ReadUInt32 (span=span, offset=pos)
  let sname = ByteArray.extractCStringFromSpan strTab (Convert.ToInt32 nameIdx)
  let info = peekHeaderB span reader cls pos 12 4
  let other = peekHeaderB span reader cls pos 13 5
  let ndx =  peekHeaderU16 span reader cls pos 14 6 |> int
  let parent = Array.tryItem ndx secs.SecByNum
  let secIdx = SectionHeaderIdx.IndexFromInt ndx
  let verInfo = getVerInfo span reader vtbl symIdx secs
  { Addr = readSymAddr baseAddr span reader cls parent txt pos
    SymName = sname
    Size = readSymSize span reader cls pos
    Bind = info >>> 4 |> LanguagePrimitives.EnumOfValue
    SymType = info &&& 0xfuy |> LanguagePrimitives.EnumOfValue
    Vis = other &&& 0x3uy |> LanguagePrimitives.EnumOfValue
    SecHeaderIndex = secIdx
    ParentSection = parent
    VerInfo = verInfo
    ArchOperationMode = computeArchOpMode eHdr sname }

let getVerSymSection symTblSec secByType =
  if symTblSec.SecType = SectionType.SHTDynSym then
    Map.tryFind SectionType.SHTGNUVerSym secByType
  else None

let nextSymOffset eHdr offset =
  offset + if eHdr.Class = WordSize.Bit32 then 16 else 24

let getTextSectionOffset secs =
  match Map.tryFind Section.SecText secs.SecByName with
  | None -> 0UL
  | Some sec -> sec.SecOffset

let rec parseSymAux
  baseAddr eHdr secs span reader txt vtbl stbl cnt max offset acc =
  if cnt = max then List.rev acc
  else
    let sym = getSymbol baseAddr secs stbl vtbl eHdr span reader txt cnt offset
    let cnt = cnt + 1UL
    let offset = nextSymOffset eHdr offset
    let acc = sym :: acc
    parseSymAux baseAddr eHdr secs span reader txt vtbl stbl cnt max offset acc

let parseSymbols baseAddr eHdr secs (span: ByteSpan) reader vtbl acc symTblSec =
  let cls = eHdr.Class
  let ss = secs.SecByNum[Convert.ToInt32 symTblSec.SecLink] (* Get the sec. *)
  let size = Convert.ToInt32 ss.SecSize
  let offset = Convert.ToInt32 ss.SecOffset
  let max = symTblSec.SecSize / (if cls = WordSize.Bit32 then 16UL else 24UL)
  let txt = getTextSectionOffset secs
  let stbl = span.Slice (offset, size)
  let offset = Convert.ToInt32 symTblSec.SecOffset
  parseSymAux baseAddr eHdr secs span reader txt vtbl stbl 0UL max offset acc

let getMergedSymbolTbl numbers (symTbls: Dictionary<_, _>) =
  numbers
  |> List.fold (fun acc n -> Array.append (symTbls[n]) acc) [||]

let private getStaticSymArrayInternal secInfo symTbl =
  getMergedSymbolTbl secInfo.StaticSymSecNums symTbl

let getStaticSymArray elf =
  getStaticSymArrayInternal elf.SecInfo elf.SymInfo.SecNumToSymbTbls

let private getDynamicSymArrayInternal secInfo symTbl =
  getMergedSymbolTbl secInfo.DynSymSecNums symTbl

let getDynamicSymArray elf =
  getDynamicSymArrayInternal elf.SecInfo elf.SymInfo.SecNumToSymbTbls

let buildSymbolMap staticSymArr dynamicSymArr =
  let map = Dictionary<Addr, ELFSymbol> ()
  let iterator sym =
    if sym.Addr > 0UL then map[sym.Addr] <- sym
    else ()
  staticSymArr |> Array.iter iterator
  dynamicSymArr |> Array.iter iterator
  map

let rec getSymTabs map baseAddr eHdr secs span reader vtbl = function
  | (n, symTblSec) :: rest ->
    let symbols = parseSymbols baseAddr eHdr secs span reader vtbl [] symTblSec
    (map: Dictionary<int, ELFSymbol[]>)[n] <- Array.ofList symbols
    getSymTabs map baseAddr eHdr secs span reader vtbl rest
  | [] -> ()

let parse baseAddr eHdr secs span reader =
  let vtbl = parseVersionTable secs span reader
  let symTabNumbers = List.append secs.StaticSymSecNums secs.DynSymSecNums
  let symSecs = List.map (fun n -> n, secs.SecByNum[n]) symTabNumbers
  let symTbls = Dictionary ()
  getSymTabs symTbls baseAddr eHdr secs span reader vtbl symSecs
  let staticSymArr = getStaticSymArrayInternal secs symTbls
  let dynamicSymArr = getDynamicSymArrayInternal secs symTbls
  { VersionTable = vtbl
    SecNumToSymbTbls = symTbls
    AddrToSymbTable = buildSymbolMap staticSymArr dynamicSymArr }

let updateGlobals symInfo (globals: Map<Addr, ELFSymbol>) =
  let tbl = symInfo.AddrToSymbTable
  globals |> Map.iter (fun a s -> tbl[a] <- s)
  globals

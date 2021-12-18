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
open B2R2
open B2R2.Monads.Maybe
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

let getSymbKind ndx = function
  | SymbolType.STTObject -> SymbolKind.ObjectType
  | SymbolType.STTGNUIFunc
  | SymbolType.STTFunc ->
    if ndx = SHNUndef then SymbolKind.NoType
    else SymbolKind.FunctionType
  | SymbolType.STTSection -> SymbolKind.SectionType
  | SymbolType.STTFile ->SymbolKind.FileType
  | _ -> SymbolKind.NoType

let versionToLibName version =
  match version with
  | Some version -> version.VerName
  | None -> ""

let toB2R2Symbol target (symb: ELFSymbol) =
  { Address = symb.Addr
    Name = symb.SymName
    Kind = getSymbKind symb.SecHeaderIndex symb.SymType
    Target = target
    LibraryName = versionToLibName symb.VerInfo
    ArchOperationMode = symb.ArchOperationMode }

let verName (strTab: ReadOnlySpan<byte>) vnaNameOffset =
  if vnaNameOffset >= strTab.Length then ""
  else ByteArray.extractCStringFromSpan strTab vnaNameOffset

let rec parseNeededVerFromSecAux (reader: BinReader) strTab map pos =
  let idx = reader.PeekUInt16 (pos + 6) (* vna_other *)
  let nameOffset = reader.PeekInt32 (pos + 8)
  let map = Map.add idx (verName strTab nameOffset) map
  let next = reader.PeekInt32 (pos + 12)
  if next = 0 then map
  else parseNeededVerFromSecAux reader strTab map (pos + next)

let rec parseNeededVerFromSec (reader: BinReader) strTab map pos =
  let auxOffset = reader.PeekInt32 (pos + 8) + pos (* vn_aux + pos *)
  let map = parseNeededVerFromSecAux reader strTab map auxOffset
  let next = reader.PeekInt32 (pos + 12) (* vn_next *)
  if next = 0 then map
  else parseNeededVerFromSec reader strTab map (pos + next)

let parseNeededVersionTable tbl reader strTab = function
  | None -> tbl
  | Some sec ->
    parseNeededVerFromSec reader strTab tbl (Convert.ToInt32 sec.SecOffset)

let rec parseDefinedVerFromSec (reader: BinReader) strTab map pos =
  let auxOffset = reader.PeekInt32 (pos + 12) + pos (* vd_aux + pos *)
  let idx = reader.PeekUInt16 (pos + 4) (* vd_ndx *)
  let nameOffset = reader.PeekInt32 auxOffset (* vda_name *)
  let map = Map.add idx (verName strTab nameOffset) map
  let next = reader.PeekInt32 (pos + 16) (* vd_next *)
  if next = 0 then map
  else parseDefinedVerFromSec reader strTab map (pos + next)

let parseDefinedVersionTable tbl (reader: BinReader) strTab = function
  | None -> tbl
  | Some sec ->
    parseDefinedVerFromSec reader strTab tbl (Convert.ToInt32 sec.SecOffset)

let parseVersionTable secs (reader: BinReader) =
  secs.DynSymSecNums
  |> List.fold (fun tbl n ->
       let symTblSec = secs.SecByNum[n]
       let ss = secs.SecByNum[Convert.ToInt32 symTblSec.SecLink]
       let size = Convert.ToInt32 ss.SecSize
       let offset = Convert.ToInt32 ss.SecOffset
       let strTab = reader.PeekSpan (size, offset)
       let tbl = parseNeededVersionTable tbl reader strTab secs.VerNeedSec
       parseDefinedVersionTable tbl reader strTab secs.VerDefSec) Map.empty

let parseVersData (reader: BinReader) symIdx verSymSec =
  let pos = verSymSec.SecOffset + (symIdx * 2UL) |> Convert.ToInt32
  let versData = reader.PeekUInt16 pos
  if versData > 1us then Some versData
  else None

let retrieveVer vtbl verData =
  let t = if verData &&& 0x8000us = 0us then VerRegular else VerHidden
  match Map.tryFind (verData &&& 0x7fffus) vtbl with
  | None -> None
  | Some verStr -> Some { VerType = t; VerName = verStr }

let adjustSymAddr baseAddr addr =
  if addr = 0UL then 0UL
  else addr + baseAddr

let readSymAddr baseAddr reader cls (parent: ELFSection option) txtOffset offset =
  let symAddrOffset = if cls = WordSize.Bit32 then 4 else 8
  let symAddr = offset + symAddrOffset |> peekUIntOfType reader cls
  match parent with
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

let readSymSize (reader: BinReader) cls offset =
  let symSizeOffset = if cls = WordSize.Bit32 then 8 else 16
  offset + symSizeOffset |> peekUIntOfType reader cls

let computeArchOpMode eHdr symbolName =
  if eHdr.MachineType = Architecture.ARMv7
    || eHdr.MachineType = Architecture.AARCH32
  then
    if symbolName = "$a" then ArchOperationMode.ARMMode
    elif symbolName = "$t" then ArchOperationMode.ThumbMode
    else ArchOperationMode.NoMode
  else ArchOperationMode.NoMode

let getSymbol baseAddr secs strTab vtbl eHdr reader txt symIdx pos =
  let cls = eHdr.Class
  let nameIdx = (reader: BinReader).PeekUInt32 pos
  let sname = ByteArray.extractCStringFromSpan strTab (Convert.ToInt32 nameIdx)
  let info = peekHeaderB reader cls pos 12 4
  let other = peekHeaderB reader cls pos 13 5
  let ndx =  peekHeaderU16 reader cls pos 14 6 |> int
  let parent = Array.tryItem ndx secs.SecByNum
  let secIdx = SectionHeaderIdx.IndexFromInt ndx
  let vssec = secs.VerSymSec
  let verInfo = vssec >>= parseVersData reader symIdx >>= retrieveVer vtbl
  { Addr = readSymAddr baseAddr reader cls parent txt pos
    SymName = sname
    Size = readSymSize reader cls pos
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
  match Map.tryFind ".text" secs.SecByName with
  | None -> 0UL
  | Some sec -> sec.SecOffset

let rec parseSymAux baseAddr eHdr secs reader txt vtbl stbl cnt max offset acc =
  if cnt = max then List.rev acc
  else
    let sym = getSymbol baseAddr secs stbl vtbl eHdr reader txt cnt offset
    let cnt = cnt + 1UL
    let offset = nextSymOffset eHdr offset
    let acc = sym :: acc
    parseSymAux baseAddr eHdr secs reader txt vtbl stbl cnt max offset acc

let parseSymbols baseAddr eHdr secs (reader: BinReader) vtbl acc symTblSec =
  let cls = eHdr.Class
  let ss = secs.SecByNum[Convert.ToInt32 symTblSec.SecLink] (* Get the sec. *)
  let size = Convert.ToInt32 ss.SecSize
  let offset = Convert.ToInt32 ss.SecOffset
  let max = symTblSec.SecSize / (if cls = WordSize.Bit32 then 16UL else 24UL)
  let txt = getTextSectionOffset secs
  let stbl = reader.PeekSpan (size, offset) (* Get the str table *)
  let offset = Convert.ToInt32 symTblSec.SecOffset
  parseSymAux baseAddr eHdr secs reader txt vtbl stbl 0UL max offset acc

let getMergedSymbolTbl numbers symTbls =
  numbers
  |> List.fold (fun acc n -> Array.append (Map.find n symTbls) acc) [||]

let private getStaticSymArrayInternal secInfo symTbl =
  getMergedSymbolTbl secInfo.StaticSymSecNums symTbl

let getStaticSymArray elf =
  getStaticSymArrayInternal elf.SecInfo elf.SymInfo.SecNumToSymbTbls

let private getDynamicSymArrayInternal secInfo symTbl =
  getMergedSymbolTbl secInfo.DynSymSecNums symTbl

let getDynamicSymArray elf =
  getDynamicSymArrayInternal elf.SecInfo elf.SymInfo.SecNumToSymbTbls

let buildSymbolMap staticSymArr dynamicSymArr =
  let folder map sym =
    if sym.Addr > 0UL then Map.add sym.Addr sym map
    else map
  let map = staticSymArr |> Array.fold folder Map.empty
  dynamicSymArr |> Array.fold folder map

let parse baseAddr eHdr secs reader =
  let vtbl = parseVersionTable secs reader
  let symTabNumbers = List.append secs.StaticSymSecNums secs.DynSymSecNums
  let getSymTables sec =
    List.fold (fun map (n, symTblSec) ->
      let symbols = parseSymbols baseAddr eHdr secs reader vtbl [] symTblSec
      Map.add n (Array.ofList symbols) map) Map.empty sec
  let symTbls =
    List.map (fun n -> n, secs.SecByNum[n]) symTabNumbers |> getSymTables
  let staticSymArr = getStaticSymArrayInternal secs symTbls
  let dynamicSymArr = getDynamicSymArrayInternal secs symTbls
  { VersionTable = vtbl
    SecNumToSymbTbls = symTbls
    AddrToSymbTable = buildSymbolMap staticSymArr dynamicSymArr }

let updatePLTSymbols (plt: ARMap<ELFSymbol>) symInfo =
  let update map = plt |> ARMap.fold (fun map r s -> Map.add r.Min s map) map
  { symInfo with AddrToSymbTable = update symInfo.AddrToSymbTable }

let updateGlobals (globals: Map<Addr, ELFSymbol>) symInfo =
  let update map = globals |> Map.fold (fun map a s -> Map.add a s map) map
  { symInfo with AddrToSymbTable = update symInfo.AddrToSymbTable }

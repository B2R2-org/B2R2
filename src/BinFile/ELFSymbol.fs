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

module internal B2R2.BinFile.ELF.Symbol

open System
open B2R2
open B2R2.Monads.Maybe
open B2R2.BinFile
open B2R2.BinFile.FileHelper

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
    LibraryName = versionToLibName symb.VerInfo }

let verName strTab vnaNameOffset =
  if vnaNameOffset >= Array.length strTab then ""
  else ByteArray.extractCString strTab vnaNameOffset

let parseNeededVersionTable tbl (reader: BinReader) strTab = function
  | None -> tbl
  | Some sec ->
    let rec loopAux map pos =
      let idx = reader.PeekUInt16 (pos + 6) (* vna_other *)
      let nameOffset = reader.PeekInt32 (pos + 8)
      let map = Map.add idx (verName strTab nameOffset) map
      let next = reader.PeekInt32 (pos + 12)
      if next = 0 then map else loopAux map (pos + next)
    let rec loopSec map pos =
      let auxOffset = reader.PeekInt32 (pos + 8) + pos (* vn_aux + pos *)
      let map = loopAux map auxOffset
      let next = reader.PeekInt32 (pos + 12) (* vn_next *)
      if next = 0 then map
      else loopSec map (pos + next)
    Convert.ToInt32 sec.SecOffset |> loopSec tbl

let parseDefinedVersionTable tbl (reader: BinReader) strTab = function
  | None -> tbl
  | Some sec ->
    let rec loopSec map pos =
      let auxOffset = reader.PeekInt32 (pos + 12) + pos (* vd_aux + pos *)
      let idx = reader.PeekUInt16 (pos + 4) (* vd_ndx *)
      let nameOffset = reader.PeekInt32 auxOffset (* vda_name *)
      let map = Map.add idx (verName strTab nameOffset) map
      let next = reader.PeekInt32 (pos + 16) (* vd_next *)
      if next = 0 then map
      else loopSec map (pos + next)
    Convert.ToInt32 sec.SecOffset |> loopSec tbl

let parseVersionTable secs (reader: BinReader) =
  secs.DynSymSecNums
  |> List.fold (fun tbl n ->
       let symTblSec = secs.SecByNum.[n]
       let ss = secs.SecByNum.[Convert.ToInt32 symTblSec.SecLink]
       let strTab = reader.PeekBytes (ss.SecSize, ss.SecOffset)
       let tbl = parseNeededVersionTable tbl reader strTab secs.VerDefSec
       parseDefinedVersionTable tbl reader strTab secs.VerDefSec) Map.empty

let parseVersData (reader: BinReader) symIdx verSymSec =
  let pos = verSymSec.SecOffset + (symIdx * 2UL) |> Convert.ToInt32
  let versData = reader.PeekUInt16 pos
  if versData > 1us then Some versData
  else None

let retrieveVer verTbl verData =
  let t = if verData &&& 0x8000us = 0us then VerRegular else VerHidden
  match Map.tryFind (verData &&& 0x7fffus) verTbl with
  | None -> None
  | Some verStr -> Some { VerType = t; VerName = verStr }

let readSymAddr (reader: BinReader) cls offset =
  let symAddrOffset = if cls = WordSize.Bit32 then 4 else 8
  offset + symAddrOffset |> peekUIntOfType reader cls

let readSymSize (reader: BinReader) cls offset =
  let symSizeOffset = if cls = WordSize.Bit32 then 8 else 16
  offset + symSizeOffset |> peekUIntOfType reader cls

let parseSymb secs verSymSec strTab verTbl cls (reader: BinReader) symIdx pos =
  let nameIdx = reader.PeekUInt32 pos
  let info = peekHeaderB reader cls pos 12 4
  let other = peekHeaderB reader cls pos 13 5
  let ndx =  peekHeaderU16 reader cls pos 14 6 |> int
  let secIdx = SectionHeaderIdx.IndexFromInt ndx
  let verInfo = verSymSec >>= parseVersData reader symIdx >>= retrieveVer verTbl
  { Addr = readSymAddr reader cls pos
    SymName = ByteArray.extractCString strTab (Convert.ToInt32 nameIdx)
    Size = readSymSize reader cls pos
    Bind = info >>> 4 |> LanguagePrimitives.EnumOfValue
    SymType = info &&& 0xfuy |> LanguagePrimitives.EnumOfValue
    Vis = other &&& 0x3uy |> LanguagePrimitives.EnumOfValue
    SecHeaderIndex = secIdx
    ParentSection = Array.tryItem ndx secs.SecByNum
    VerInfo = verInfo }

let getVerSymSection symTblSec secByType =
  if symTblSec.SecType = SectionType.SHTDynSym then
    Map.tryFind SectionType.SHTGNUVerSym secByType
  else None

let nextSymOffset cls offset =
  offset + if cls = WordSize.Bit32 then 16 else 24

let parseSymbols cls secs (reader: BinReader) verTbl acc symTblSec =
  let ss = secs.SecByNum.[Convert.ToInt32 symTblSec.SecLink] (* Get the sec. *)
  let stbl = reader.PeekBytes (ss.SecSize, ss.SecOffset) (* Get the str table *)
  let verSymSec = secs.VerSymSec
  let sNum = symTblSec.SecSize / (if cls = WordSize.Bit32 then 16UL else 24UL)
  let rec loop count acc offset =
    if count = sNum then List.rev acc
    else let sym = parseSymb secs verSymSec stbl verTbl cls reader count offset
         loop (count + 1UL) (sym :: acc) (nextSymOffset cls offset)
  Convert.ToInt32 symTblSec.SecOffset |> loop 0UL acc

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

let parse eHdr secs reader =
  let cls = eHdr.Class
  let verTbl = parseVersionTable secs reader
  let symTabNumbers = List.append secs.StaticSymSecNums secs.DynSymSecNums
  let getSymTables sec =
    List.fold (fun map (n, symTblSec) ->
      let symbols = parseSymbols cls secs reader verTbl [] symTblSec
      Map.add n (Array.ofList symbols) map) Map.empty sec
  let symTbls =
    List.map (fun n -> n, secs.SecByNum.[n]) symTabNumbers |> getSymTables
  let staticSymArr = getStaticSymArrayInternal secs symTbls
  let dynamicSymArr = getDynamicSymArrayInternal secs symTbls
  { VersionTable = verTbl
    SecNumToSymbTbls = symTbls
    AddrToSymbTable = buildSymbolMap staticSymArr dynamicSymArr }

let updatePLTSymbols (plt: ARMap<ELFSymbol>) symInfo =
  let update map = plt |> ARMap.fold (fun map r s -> Map.add r.Min s map) map
  { symInfo with AddrToSymbTable = update symInfo.AddrToSymbTable }

let updateGlobals (globals: Map<Addr, ELFSymbol>) symInfo =
  let update map = globals |> Map.fold (fun map a s -> Map.add a s map) map
  { symInfo with AddrToSymbTable = update symInfo.AddrToSymbTable }

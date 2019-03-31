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
open B2R2.BinFile.FileHelper

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
  match Map.tryFind SectionType.SHTDynSym secs.SecByType with
  | None -> Map.empty
  | Some symTblSec ->
    let ss = secs.SecByNum.[Convert.ToInt32 symTblSec.SecLink]
    let strTab = reader.PeekBytes (ss.SecSize, ss.SecOffset)
    let verNeedSec = Map.tryFind SectionType.SHTGNUVerNeed secs.SecByType
    let verDefSec = Map.tryFind SectionType.SHTGNUVerDef secs.SecByType
    let tbl = parseNeededVersionTable Map.empty reader strTab verNeedSec
    parseDefinedVersionTable tbl reader strTab verDefSec

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
  let info = readHeaderB reader cls pos 12 4
  let other = readHeaderB reader cls pos 13 5
  let ndx =  readHeader16 reader cls pos 14 6 |> int
  let secIdx = SectionHeaderIdx.IndexFromInt ndx
  let verInfo = verSymSec >>= parseVersData reader symIdx >>= retrieveVer verTbl
  {
    Addr = readSymAddr reader cls pos
    SymName = ByteArray.extractCString strTab (Convert.ToInt32 nameIdx)
    Size = readSymSize reader cls pos
    Bind = info >>> 4 |> LanguagePrimitives.EnumOfValue
    SymType = info &&& 0xfuy |> LanguagePrimitives.EnumOfValue
    Vis = other &&& 0x3uy |> LanguagePrimitives.EnumOfValue
    SecHeaderIndex = secIdx
    ParentSection = Array.tryItem ndx secs.SecByNum
    VerInfo = verInfo
  }

let getVerSymSection symTblSec secByType =
  if symTblSec.SecType = SectionType.SHTDynSym then
    Map.tryFind SectionType.SHTGNUVerSym secByType
  else None

let nextSymOffset cls offset =
  offset + if cls = WordSize.Bit32 then 16 else 24

let parseSymbols cls secs (reader: BinReader) verTbl acc symTblSec =
  let ss = secs.SecByNum.[Convert.ToInt32 symTblSec.SecLink] (* Get the sec. *)
  let stbl = reader.PeekBytes (ss.SecSize, ss.SecOffset) (* Get the str table *)
  let verSymSec = getVerSymSection symTblSec secs.SecByType
  let sNum = symTblSec.SecSize / (if cls = WordSize.Bit32 then 16UL else 24UL)
  let rec loop count acc offset =
    if count = sNum then List.rev acc
    else let sym = parseSymb secs verSymSec stbl verTbl cls reader count offset
         loop (count + 1UL) (sym :: acc) (nextSymOffset cls offset)
  Convert.ToInt32 symTblSec.SecOffset |> loop 0UL acc

let genChunkMapBySTType chunk sym map map2 =
  match sym.SymType with
  | SymbolType.STTSection ->
    Map.add sym.Addr { chunk with SecELFSymbol = Some sym } map, map2
  | SymbolType.STTNoType ->
    Map.add sym.Addr { chunk with MappingELFSymbol = Some sym } map,
    Map.add sym.Addr sym map2
  | SymbolType.STTFunc ->
    Map.add sym.Addr { chunk with FuncELFSymbol = Some sym } map, map2
  | _ -> Map.add sym.Addr chunk map, map2

let insertAddrChunkMap (map, map2) sym =
  let empty =
    { SecELFSymbol = None; FuncELFSymbol = None; MappingELFSymbol = None }
  match Map.tryFind sym.Addr map with
  | Some c -> genChunkMapBySTType c sym map map2
  | None -> genChunkMapBySTType empty sym map map2

let computeRangeSet map =
  let folder map = function
    | [| (sAddr, chunk); (eAddr, _) |] ->
      ARMap.add (AddrRange (sAddr, eAddr)) chunk map
    | _ -> failwith "Fatal error"
  Map.toSeq map
  |> Seq.filter (fun (addr, _) -> addr <> 0UL)
  |> Seq.windowed 2
  |> Seq.fold folder ARMap.empty

let getChunks (symTbl: ELFSymbol []) (dynSym: ELFSymbol []) =
  let targetMap = if symTbl.Length = 0 then dynSym else symTbl
  let chunkMap, mappingSymbs =
    Array.fold insertAddrChunkMap (Map.empty, Map.empty) targetMap
  struct (computeRangeSet chunkMap, computeRangeSet mappingSymbs)

let parse eHdr secs reader =
  let cls = eHdr.Class
  let verTbl = parseVersionTable secs reader
  let getSymSec typ = Map.tryFind typ secs.SecByType
  let getSym sec = Option.fold (parseSymbols cls secs reader verTbl) [] sec
  let symTblByNum = getSymSec SectionType.SHTSymTab |> getSym |> Array.ofList
  let dynSymTblByNum = getSymSec SectionType.SHTDynSym |> getSym |> Array.ofList
  let struct (symChunks, mappingSymbs) = getChunks symTblByNum dynSymTblByNum
  {
    VersionTable = verTbl
    DynSymArr = dynSymTblByNum
    StaticSymArr = symTblByNum
    SymChunks = symChunks
    MappingELFSymbols = mappingSymbs
  }

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
open System.IO
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

let rec parseNeededVerFromSecAux span (reader: IBinReader) verTbl strTbl pos =
  let idx = reader.ReadUInt16 (span=span, offset=pos + 6) (* vna_other *)
  let nameOffset = reader.ReadInt32 (span, pos + 8)
  (verTbl: Dictionary<_, _>)[idx] <- verName strTbl nameOffset
  let next = reader.ReadInt32 (span, pos + 12)
  if next = 0 then ()
  else parseNeededVerFromSecAux span reader verTbl strTbl (pos + next)

let rec parseNeededVerFromSec span reader verTbl strTbl offset =
  let auxOffset = (* vn_aux + current file offset *)
    (reader: IBinReader).ReadInt32 (span=span, offset=offset + 8) + offset
  parseNeededVerFromSecAux span reader verTbl strTbl auxOffset
  let next = reader.ReadInt32 (span, offset + 12) (* vn_next *)
  if next = 0 then ()
  else parseNeededVerFromSec span reader verTbl strTbl (offset + next)

let parseNeededVersionTable (stream: Stream) reader verTbl strTbl = function
  | None -> ()
  | Some { SecOffset = offset; SecSize = size } ->
    let buf = Array.zeroCreate (int size)
    stream.Seek (int64 offset, SeekOrigin.Begin) |> ignore
    readOrDie stream buf
    let span = ReadOnlySpan buf
    parseNeededVerFromSec span reader verTbl strTbl 0

let rec parseDefinedVerFromSec span (reader: IBinReader) verTbl strTbl offset =
  let auxOffset = (* vd_aux + current file offset *)
    reader.ReadInt32 (span=span, offset=offset + 12) + offset
  let idx = reader.ReadUInt16 (span, offset + 4) (* vd_ndx *)
  let nameOffset = reader.ReadInt32 (span, auxOffset) (* vda_name *)
  (verTbl: Dictionary<_, _>)[idx] <- verName strTbl nameOffset
  let next = reader.ReadInt32 (span, offset + 16) (* vd_next *)
  if next = 0 then ()
  else parseDefinedVerFromSec span reader verTbl strTbl (offset + next)

let parseDefinedVersionTable (stream: Stream) reader verTbl strTbl = function
  | None -> ()
  | Some { SecOffset = offset; SecSize = size } ->
    let buf = Array.zeroCreate (int size)
    stream.Seek (int64 offset, SeekOrigin.Begin) |> ignore
    readOrDie stream buf
    let span = ReadOnlySpan buf
    parseDefinedVerFromSec span reader verTbl strTbl 0

let findVerNeedSection shdrs =
  shdrs
  |> Array.tryFind (fun s -> s.SecType = SectionType.SHTGNUVerNeed)

let findVerDefSection shdrs =
  shdrs
  |> Array.tryFind (fun s -> s.SecType = SectionType.SHTGNUVerDef)

let getStaticSymbolSectionNumbers shdrs =
  shdrs
  |> Array.choose (fun s ->
    if s.SecType = SectionType.SHTSymTab then Some s.SecNum else None)

let getDynamicSymbolSectionNumbers shdrs =
  shdrs
  |> Array.choose (fun s ->
    if s.SecType = SectionType.SHTDynSym then Some s.SecNum else None)

let parseVersionTable (stream: Stream) reader shdrs =
  let verTbl = Dictionary ()
  let verNeedSec = findVerNeedSection shdrs
  let verDefSec = findVerDefSection shdrs
  for n in getDynamicSymbolSectionNumbers shdrs do
    let symSection = shdrs[n]
    let strSection = shdrs[Convert.ToInt32 symSection.SecLink]
    let size = Convert.ToInt32 strSection.SecSize
    let offset = Convert.ToInt32 strSection.SecOffset
    let strBuf = Array.zeroCreate size
    stream.Seek (int64 offset, SeekOrigin.Begin) |> ignore
    readOrDie stream strBuf
    let strTbl = ReadOnlySpan strBuf
    parseNeededVersionTable stream reader verTbl strTbl verNeedSec
    parseDefinedVersionTable stream reader verTbl strTbl verDefSec
  verTbl

let retrieveVer (verTbl: Dictionary<_, _>) verData =
  let t = if verData &&& 0x8000us = 0us then VerRegular else VerHidden
  match verTbl.TryGetValue (verData &&& 0x7fffus) with
  | true, verStr -> Some { VerType = t; VerName = verStr }
  | false, _ -> None

let adjustSymAddr baseAddr addr =
  if addr = 0UL then 0UL
  else addr + baseAddr

let readSymAddr baseAddr span reader cls parent txtOffset =
  let symAddrOffset = if cls = WordSize.Bit32 then 4 else 8
  let symAddr = peekUIntOfType span reader cls symAddrOffset
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

let readSymSize span reader cls =
  let symSizeOffset = if cls = WordSize.Bit32 then 8 else 16
  peekUIntOfType span reader cls symSizeOffset

let computeArchOpMode hdr symbolName =
  if hdr.MachineType = Architecture.ARMv7
    || hdr.MachineType = Architecture.AARCH32
  then
    if symbolName = "$a" then ArchOperationMode.ARMMode
    elif symbolName = "$t" then ArchOperationMode.ThumbMode
    else ArchOperationMode.NoMode
  else ArchOperationMode.NoMode

let parseVersData (reader: IBinReader) symIdx verInfoTbl =
  let pos = symIdx * 2
  let versData = reader.ReadUInt16 (bs=verInfoTbl, offset=pos)
  if versData > 1us then Some versData
  else None

let getVerInfo reader verTbl verInfoTblOpt symIdx =
  match verInfoTblOpt with
  | Some verInfoTbl ->
    parseVersData reader symIdx verInfoTbl >>= retrieveVer verTbl
  | None -> None

let getSymbol
  reader hdr baseAddr shdrs strTbl verTbl symTbl verInfoTbl txt symIdx =
  let cls = hdr.Class
  let nameIdx = (reader: IBinReader).ReadUInt32 (span=symTbl, offset=0)
  let sname = ByteArray.extractCStringFromSpan strTbl (Convert.ToInt32 nameIdx)
  let info = peekHeaderB symTbl cls 12 4
  let other = peekHeaderB symTbl cls 13 5
  let ndx =  peekHeaderU16 symTbl reader cls 14 6 |> int
  let parent = Array.tryItem ndx shdrs
  let secIdx = SectionHeaderIdx.IndexFromInt ndx
  let verInfo = getVerInfo reader verTbl verInfoTbl symIdx
  { Addr = readSymAddr baseAddr symTbl reader cls parent txt
    SymName = sname
    Size = readSymSize symTbl reader cls
    Bind = info >>> 4 |> LanguagePrimitives.EnumOfValue
    SymType = info &&& 0xfuy |> LanguagePrimitives.EnumOfValue
    Vis = other &&& 0x3uy |> LanguagePrimitives.EnumOfValue
    SecHeaderIndex = secIdx
    ParentSection = parent
    VerInfo = verInfo
    ArchOperationMode = computeArchOpMode hdr sname }

let nextSymOffset cls offset =
  offset + if cls = WordSize.Bit32 then 16 else 24

let getTextSectionOffset shdrs =
  match shdrs |> Array.tryFind (fun s -> s.SecName = Section.SecText) with
  | None -> 0UL
  | Some sec -> sec.SecOffset

let private readSection (stream: Stream) offset size =
  let buf = Array.zeroCreate size
  (stream: Stream).Seek (int64 offset, SeekOrigin.Begin) |> ignore
  readOrDie stream buf
  buf

let parseSymbols stream reader hdr baseAddr shdrs verTbl verInfoTbl symTblSec =
  let cls = hdr.Class
  let txt = getTextSectionOffset shdrs
  let ssec = shdrs[Convert.ToInt32 symTblSec.SecLink] (* Get the string sec. *)
  let offset = Convert.ToInt32 ssec.SecOffset
  let size = Convert.ToInt32 ssec.SecSize
  let stringBuf = readSection stream offset size
  let offset = Convert.ToInt32 symTblSec.SecOffset
  let size = Convert.ToInt32 symTblSec.SecSize
  let verInfoTbl = (* symbol versioning is only valid for dynamic symbols. *)
    if symTblSec.SecType = SectionType.SHTDynSym then verInfoTbl else None
  let symTblBuf = readSection stream offset size
  let numEntries =
    int symTblSec.SecSize / (if cls = WordSize.Bit32 then 16 else 24)
  let symbols = Array.zeroCreate numEntries
  let rec parseLoop cnt ofs =
    if cnt = numEntries then symbols
    else
      let strTbl = ReadOnlySpan stringBuf
      let symTbl = (ReadOnlySpan symTblBuf).Slice ofs
      let sym =
        getSymbol
          reader hdr baseAddr shdrs strTbl verTbl symTbl verInfoTbl txt cnt
      symbols[cnt] <- sym
      parseLoop (cnt + 1) (nextSymOffset cls ofs)
  parseLoop 0 0

let getVerInfoTable (stream: Stream) shdrs =
  shdrs
  |> Array.tryFind (fun s -> s.SecType = SectionType.SHTGNUVerSym)
  |> function
    | Some sec ->
      let buf = Array.zeroCreate (int sec.SecSize)
      stream.Seek (int64 sec.SecOffset, SeekOrigin.Begin) |> ignore
      readOrDie stream buf
      Some buf
    | None -> None

let parseSymTabs stream reader hdr baseAddr symTbl shdrs verTbl symSecs =
  let verInfoTbl = getVerInfoTable stream shdrs
  for (n, symTblSec) in symSecs do
    let symbols =
      parseSymbols stream reader hdr baseAddr shdrs verTbl verInfoTbl symTblSec
    (symTbl: Dictionary<int, ELFSymbol[]>)[n] <- symbols

let getSymbolSections shdrs =
  shdrs
  |> Array.choose (fun s ->
    if s.SecType = SectionType.SHTSymTab || s.SecType = SectionType.SHTDynSym
    then Some s.SecNum
    else None)
  |> Array.map (fun n -> n, shdrs[n])

let getMergedSymbolTbl (symTbls: Dictionary<_, _>) numbers =
  numbers
  |> Array.fold (fun acc n -> Array.append (symTbls[n]) acc) [||]

let getStaticSymArray shdrs symTbl =
  getStaticSymbolSectionNumbers shdrs
  |> getMergedSymbolTbl symTbl

let getDynamicSymArray shdrs symTbl =
  getDynamicSymbolSectionNumbers shdrs
  |> getMergedSymbolTbl symTbl

let buildSymbolMap staticSymArr dynamicSymArr =
  let map = Dictionary<Addr, ELFSymbol> ()
  let iterator sym =
    if sym.Addr > 0UL then map[sym.Addr] <- sym
    else ()
  staticSymArr |> Array.iter iterator
  dynamicSymArr |> Array.iter iterator
  map

let parse stream reader hdr baseAddr (shdrs: Lazy<_>) =
  let shdrs = shdrs.Value
  let verTbl = parseVersionTable stream reader shdrs
  let symSecs = getSymbolSections shdrs
  let symTbl = Dictionary ()
  parseSymTabs stream reader hdr baseAddr symTbl shdrs verTbl symSecs
  let staticSymArr = getStaticSymArray shdrs symTbl
  let dynamicSymArr = getDynamicSymArray shdrs symTbl
  { VersionTable = verTbl
    SecNumToSymbTbls = symTbl
    AddrToSymbTable = buildSymbolMap staticSymArr dynamicSymArr }

let updateGlobals symInfo (globals: Map<Addr, ELFSymbol>) =
  let tbl = symInfo.AddrToSymbTable
  globals |> Map.iter (fun a s -> tbl[a] <- s)
  globals

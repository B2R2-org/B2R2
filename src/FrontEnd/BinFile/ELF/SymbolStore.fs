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
open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.FileHelper

module private VersionTable =
  let verName (strTab: ByteSpan) vnaNameOffset =
    if vnaNameOffset >= strTab.Length then ""
    else ByteArray.extractCStringFromSpan strTab vnaNameOffset

  let rec parseNeededVerFromSecAux span (reader: IBinReader) verTbl strTbl pos =
    let idx = reader.ReadUInt16(span = span, offset = pos + 6) (* vna_other *)
    let nameOffset = reader.ReadInt32(span, pos + 8)
    (verTbl: Dictionary<_, _>)[idx] <- verName strTbl nameOffset
    let next = reader.ReadInt32(span, pos + 12)
    if next = 0 then ()
    else parseNeededVerFromSecAux span reader verTbl strTbl (pos + next)

  let rec parseNeededVerFromSec span reader verTbl strTbl offset =
    let auxOffset = (* vn_aux + current file offset *)
      (reader: IBinReader).ReadInt32(span = span, offset = offset + 8) + offset
    parseNeededVerFromSecAux span reader verTbl strTbl auxOffset
    let next = reader.ReadInt32(span, offset + 12) (* vn_next *)
    if next = 0 then ()
    else parseNeededVerFromSec span reader verTbl strTbl (offset + next)

  let parseNeededVersionTable toolBox verTbl strTbl = function
    | None -> ()
    | Some { SecOffset = offset; SecSize = size } ->
      let span = ReadOnlySpan(toolBox.Bytes, int offset, int size)
      parseNeededVerFromSec span toolBox.Reader verTbl strTbl 0

  let rec parseDefinedVerFromSec span (reader: IBinReader) verTbl strTbl ofs =
    let auxOffset = (* vd_aux + current file offset *)
      reader.ReadInt32(span = span, offset = ofs + 12) + ofs
    let idx = reader.ReadUInt16(span, ofs + 4) (* vd_ndx *)
    let nameOffset = reader.ReadInt32(span, auxOffset) (* vda_name *)
    (verTbl: Dictionary<_, _>)[idx] <- verName strTbl nameOffset
    let next = reader.ReadInt32(span, ofs + 16) (* vd_next *)
    if next = 0 then ()
    else parseDefinedVerFromSec span reader verTbl strTbl (ofs + next)

  let parseDefinedVersionTable toolBox verTbl strTbl = function
    | None -> ()
    | Some { SecOffset = offset; SecSize = size } ->
      let span = ReadOnlySpan(toolBox.Bytes, int offset, int size)
      parseDefinedVerFromSec span toolBox.Reader verTbl strTbl 0

  let parse toolBox shdrs (dynamicSections: SectionHeader[]) =
    let verTbl = Dictionary()
    let verNeedSec =
      shdrs |> Array.tryFind (fun s -> s.SecType = SectionType.SHT_GNU_verneed)
    let verDefSec =
      shdrs |> Array.tryFind (fun s -> s.SecType = SectionType.SHT_GNU_verdef)
    for symSection in dynamicSections do
      let strSection = shdrs[Convert.ToInt32 symSection.SecLink]
      let size = Convert.ToInt32 strSection.SecSize
      let strTbl = ReadOnlySpan(toolBox.Bytes, int strSection.SecOffset, size)
      parseNeededVersionTable toolBox verTbl strTbl verNeedSec
      parseDefinedVersionTable toolBox verTbl strTbl verDefSec
    verTbl

module private SymbolTables =
  let getTextSectionOffset shdrs =
    match shdrs |> Array.tryFind (fun s -> s.SecName = Section.Text) with
    | None -> 0UL
    | Some sec -> sec.SecOffset

  let adjustSymAddr baseAddr addr =
    if addr = 0UL then 0UL
    else addr + baseAddr

  let readSymAddr baseAddr span reader cls parent txtOffset =
    let symAddr = readUIntByWordSize span reader cls (selectByWordSize cls 4 8)
    match (parent: SectionHeader option) with
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

  let computeLinkerSymbolKind hdr symbolName =
    if hdr.MachineType = MachineType.EM_ARM then
      if symbolName = "$a" then ARMLinkerSymbol.ARM
      elif symbolName = "$t" then ARMLinkerSymbol.Thumb
      else ARMLinkerSymbol.None
    else ARMLinkerSymbol.None

  let parseVersData (reader: IBinReader) symIdx verInfoTbl =
    let pos = symIdx * 2
    let versData = reader.ReadUInt16(span = verInfoTbl, offset = pos)
    if versData > 1us then Some versData
    else None

  let retrieveVer (verTbl: Dictionary<_, _>) verData =
    let isHidden = verData &&& 0x8000us <> 0us
    match verTbl.TryGetValue(verData &&& 0x7fffus) with
    | true, verStr -> Some { IsHidden = isHidden; VerName = verStr }
    | false, _ -> None

  let getVerInfo toolBox verTbl verInfoTblOpt symIdx =
    match verInfoTblOpt with
    | Some verInfoTbl ->
      let offset, size = int verInfoTbl.SecOffset, int verInfoTbl.SecSize
      let span = ReadOnlySpan(toolBox.Bytes, offset, size)
      parseVersData toolBox.Reader symIdx span
      |> Option.bind (retrieveVer verTbl)
    | None -> None

  let getSymbol toolBox shdrs strTbl verTbl symbol verInfoTbl txtOffset symIdx =
    let cls = toolBox.Header.Class
    let reader = toolBox.Reader
    let nameIdx = reader.ReadUInt32(span = symbol, offset = 0)
    let sname = ByteArray.extractCStringFromSpan strTbl (int nameIdx)
    let info = symbol[selectByWordSize cls 12 4]
    let other = symbol[selectByWordSize cls 13 5]
    let ndx = reader.ReadUInt16(symbol, selectByWordSize cls 14 6) |> int
    let parent = Array.tryItem ndx shdrs
    let secIdx = SectionHeaderIdx.IndexFromInt ndx
    let verInfo = getVerInfo toolBox verTbl verInfoTbl symIdx
    { Addr = readSymAddr toolBox.BaseAddress symbol reader cls parent txtOffset
      SymName = sname
      Size = readUIntByWordSize symbol reader cls (selectByWordSize cls 8 16)
      Bind = info >>> 4 |> LanguagePrimitives.EnumOfValue
      SymType = info &&& 0xfuy |> LanguagePrimitives.EnumOfValue
      Vis = other &&& 0x3uy |> LanguagePrimitives.EnumOfValue
      SecHeaderIndex = secIdx
      ParentSection = parent
      VerInfo = verInfo
      ARMLinkerSymbol = computeLinkerSymbolKind toolBox.Header sname }

  let parseSymbols toolBox (shdrs: _[]) verTbl verInfoTbl txtSec symTblSec =
    let cls = toolBox.Header.Class
    let ssec = shdrs[Convert.ToInt32 symTblSec.SecLink] (* Get string sect. *)
    let offset = int ssec.SecOffset
    let size = Convert.ToInt32 ssec.SecSize
    let strTbl = ReadOnlySpan(toolBox.Bytes, offset, size)
    let offset = int symTblSec.SecOffset
    let size = Convert.ToInt32 symTblSec.SecSize
    let symTbl = ReadOnlySpan(toolBox.Bytes, offset, size)
    let numEntries = int symTblSec.SecSize / (selectByWordSize cls 16 24)
    let symbols = Array.zeroCreate numEntries
    for i = 0 to numEntries - 1 do
      let offset = i * (selectByWordSize cls 16 24)
      let entry = symTbl.Slice offset
      let sym = getSymbol toolBox shdrs strTbl verTbl entry verInfoTbl txtSec i
      symbols[i] <- sym
    symbols

  let parse toolBox shdrs versionTable staticSymbSecs dynamicSymbSecs =
    let symbolTable = Dictionary<int, Symbol[]>()
    let verInfoTbl =
      shdrs |> Array.tryFind (fun s -> s.SecType = SectionType.SHT_GNU_versym)
    let txtSec = getTextSectionOffset shdrs
    for s in staticSymbSecs do
      let symbols = parseSymbols toolBox shdrs versionTable None txtSec s
      symbolTable[s.SecNum] <- symbols
    for s in dynamicSymbSecs do
      let symbols = parseSymbols toolBox shdrs versionTable verInfoTbl txtSec s
      symbolTable[s.SecNum] <- symbols
    symbolTable

  let buildSymbolMap (symbolTables: Dictionary<int, Symbol[]>) =
    let map = Dictionary<Addr, Symbol>()
    for tbl in symbolTables.Values do
      for sym in tbl do
        if sym.Addr > 0UL || sym.SymType = SymbolType.STT_FUNC then
          map[sym.Addr] <- sym
        else ()
    map

/// Represents the main data structure for storing ELF symbol information.
type SymbolStore internal(toolBox, shdrs) =
  let staticSymbSecs =
    shdrs |> Array.filter (fun s -> s.SecType = SectionType.SHT_SYMTAB)

  let dynamicSymbSecs =
    shdrs |> Array.filter (fun s -> s.SecType = SectionType.SHT_DYNSYM)

  /// IDs to symbol versions required to link.
  let versionTable = VersionTable.parse toolBox shdrs dynamicSymbSecs

  /// A mapping from a section number to the corresponding symbol table.
  let symbolTables =
    SymbolTables.parse toolBox shdrs versionTable staticSymbSecs dynamicSymbSecs

  /// Address to symbol mapping.
  let symbolMap = lazy SymbolTables.buildSymbolMap symbolTables

  /// Returns parsed static symbols.
  member _.StaticSymbols with get() =
    staticSymbSecs
    |> Array.collect (fun s -> symbolTables[s.SecNum])

  /// Returns parsed dynamic symbols.
  member _.DynamicSymbols with get() =
    dynamicSymbSecs
    |> Array.collect (fun s -> symbolTables[s.SecNum])

  /// Adds a symbol to the symbol map. If the address already exists, it will
  /// be overwritten.
  member _.AddSymbol(addr: Addr, sym: Symbol) = symbolMap.Value[addr] <- sym

  /// Finds a symbol by its address.
  member _.FindSymbol(addr: Addr) = symbolMap.Value[addr]

  /// Tries to find a symbol by its address.
  member _.TryFindSymbol(addr: Addr) =
    match symbolMap.Value.TryGetValue addr with
    | true, sym -> Ok sym
    | false, _ -> Error ErrorCase.ItemNotFound

  /// Tries to find a symbol array in ELF by its section number.
  member _.TryFindSymbolTable(secNum: int) =
    match symbolTables.TryGetValue secNum with
    | true, tbl -> Ok tbl
    | false, _ -> Error ErrorCase.ItemNotFound

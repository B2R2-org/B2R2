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
    | None ->
      ()
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
    | None ->
      ()
    | Some { SecOffset = offset; SecSize = size } ->
      let span = ReadOnlySpan(toolBox.Bytes, int offset, int size)
      parseDefinedVerFromSec span toolBox.Reader verTbl strTbl 0

  let parse toolBox verNeedSec verDefSec (layouts: SymbolTableLayout[]) =
    let verTbl = Dictionary()
    for layout in layouts do
      let strSection = layout.Strings
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

  let adjustSymAddr baseAddr addr = if addr = 0UL then 0UL else addr + baseAddr

  let readSymAddr baseAddr span reader cls parent txtOffset =
    let symAddr = readUIntByWordSize span reader cls (selectByWordSize cls 4 8)
    match (parent: SectionHeader option) with
    | None ->
      symAddr
    | Some sec ->
      (* This is to give a meaningful address to static symbols in a relocatable
         object. We let .text section's address to be zero, and assume that the
         .text section always precedes the other sections. See
         https://github.com/B2R2-org/B2R2/issues/25 for more details. *)
      if sec.SecAddr = baseAddr && sec.SecOffset > txtOffset then
        sec.SecOffset - txtOffset + symAddr
      else
        symAddr
    |> adjustSymAddr baseAddr

  let retrieveVer (verTbl: Dictionary<_, _>) verData =
    let isHidden = verData &&& 0x8000us <> 0us
    match verTbl.TryGetValue(verData &&& 0x7fffus) with
    | true, verStr -> Some { IsHidden = isHidden; VerName = verStr }
    | false, _ -> None

  /// Returns the version info for the given raw version value, reusing the
  /// result computed for the same raw value in this symbol table. The whole
  /// 16-bit value is the key, so a hidden version is not confused with the
  /// visible version of the same index.
  let resolveVer verTbl (cache: Dictionary<uint16, _>) verData =
    match cache.TryGetValue verData with
    | true, verInfo ->
      verInfo
    | false, _ ->
      let verInfo = retrieveVer verTbl verData
      cache[verData] <- verInfo
      verInfo

  let getVerInfo toolBox verTbl cache (verInfoTbl: ByteSpan) symIdx =
    let reader = toolBox.Reader
    let verData = reader.ReadUInt16(span = verInfoTbl, offset = symIdx * 2)
    if verData > 1us then resolveVer verTbl cache verData else None

  /// For STT_SECTION symbols, the symbol name is actually the section name.
  /// This function adjusts the symbol name for such symbols.
  let adjustSymbolName symName symbolType parent =
    match symbolType, parent with
    | SymbolType.STT_SECTION, Some sec -> sec.SecName
    | _ -> symName

  /// Returns the span of the symbol version section, or an empty span when
  /// there is no such section. The section is left untouched when the symbol
  /// table is empty, as no version value is read then.
  let sliceVerInfoTbl toolBox verInfoTbl numEntries =
    match verInfoTbl with
    | Some sec when numEntries > 0 ->
      ReadOnlySpan(toolBox.Bytes, int sec.SecOffset, int sec.SecSize)
    | _ ->
      ReadOnlySpan.Empty

  /// Returns the span of the extended section index table, or an empty span
  /// when no such table sits beside the symbol table being parsed.
  let sliceExtIdxTbl toolBox extIdxTbl =
    match extIdxTbl with
    | Some sec ->
      ReadOnlySpan(toolBox.Bytes, int sec.SecOffset, int sec.SecSize)
    | None ->
      ReadOnlySpan.Empty

  /// Returns the version name table, which is evaluated only when the symbol
  /// table being parsed carries version information. A static symbol table
  /// thus never builds the table.
  let forceVerTbl (verTbl: Lazy<Dictionary<uint16, string>>) hasVerInfo =
    if hasVerInfo then verTbl.Value else Dictionary()

  /// Returns the section header index the given symbol names. A symbol of a
  /// section numbered past what st_shndx can hold carries SHN_XINDEX there
  /// instead, and leaves the number itself at the symbol's own index of the
  /// extended table. Without that table the escape is all there is to report.
  let getSecHeaderIdx toolBox (extIdxTbl: ByteSpan) (symbol: ByteSpan) symIdx =
    let reader = toolBox.Reader
    let cls = toolBox.Header.Class
    let ndx = reader.ReadUInt16(symbol, selectByWordSize cls 14 6) |> int
    match SectionHeaderIdx.IndexFromInt ndx with
    | SHN_XINDEX when extIdxTbl.Length >= (symIdx + 1) * 4 ->
      reader.ReadUInt32(extIdxTbl, symIdx * 4)
      |> int
      |> SectionHeaderIdx.IndexFromInt
    | idx ->
      idx

  /// Returns the section defining the symbol, which is the one its index names
  /// where that index names a section of the table at all.
  let getParentSection shdrs secIdx =
    match secIdx with
    | SectionIndex n -> Array.tryItem n shdrs
    | _ -> None

  let getSymbol toolBox shdrs strTbl symbol verInfo txtOffset secIdx =
    let cls = toolBox.Header.Class
    let reader = toolBox.Reader
    let nameIdx = reader.ReadUInt32(span = symbol, offset = 0)
    let sname = ByteArray.extractCStringFromSpan strTbl (int nameIdx)
    let info = symbol[selectByWordSize cls 12 4]
    let symType: SymbolType = info &&& 0xfuy |> LanguagePrimitives.EnumOfValue
    let other = symbol[selectByWordSize cls 13 5]
    let parent = getParentSection shdrs secIdx
    { Addr = readSymAddr toolBox.BaseAddress symbol reader cls parent txtOffset
      SymName = adjustSymbolName sname symType parent
      Size = readUIntByWordSize symbol reader cls (selectByWordSize cls 8 16)
      Bind = info >>> 4 |> LanguagePrimitives.EnumOfValue
      SymType = symType
      Vis = other &&& 0x3uy |> LanguagePrimitives.EnumOfValue
      SecHeaderIndex = secIdx
      ParentSection = parent
      VerInfo = verInfo
      MappingSymbol = MappingSymbol.parse toolBox.Header.MachineType sname }

  let parseSymbols toolBox (shdrs: _[]) verTbl txtSec layout =
    let cls = toolBox.Header.Class
    let ssec = layout.Strings
    let offset = int ssec.SecOffset
    let size = Convert.ToInt32 ssec.SecSize
    let strTbl = ReadOnlySpan(toolBox.Bytes, offset, size)
    let symTblSec = layout.Symbols
    let offset = int symTblSec.SecOffset
    let size = Convert.ToInt32 symTblSec.SecSize
    let symTbl = ReadOnlySpan(toolBox.Bytes, offset, size)
    let numEntries = int symTblSec.SecSize / (selectByWordSize cls 16 24)
    let verInfoTbl = layout.Versions
    let extIdxSpan = sliceExtIdxTbl toolBox layout.ExtendedIndices
    let verInfoSpan = sliceVerInfoTbl toolBox verInfoTbl numEntries
    let hasVerInfo = Option.isSome verInfoTbl
    let verTbl = forceVerTbl verTbl hasVerInfo
    let verCache = Dictionary<uint16, SymVerInfo option>()
    let symbols = Array.zeroCreate numEntries
    for i = 0 to numEntries - 1 do
      let offset = i * (selectByWordSize cls 16 24)
      let entry = symTbl.Slice offset
      let verInfo =
        if hasVerInfo then getVerInfo toolBox verTbl verCache verInfoSpan i
        else None
      let secIdx = getSecHeaderIdx toolBox extIdxSpan entry i
      symbols[i] <- getSymbol toolBox shdrs strTbl entry verInfo txtSec secIdx
    symbols

  /// Registers a lazily parsed symbol table for each of the given sections, so
  /// that reading one table never parses the others.
  let register toolBox shdrs verTbl tbls layouts =
    let txtSec = getTextSectionOffset shdrs
    for layout in layouts do
      let symbols = lazy (parseSymbols toolBox shdrs verTbl txtSec layout)
      (tbls: Dictionary<int, Lazy<Symbol[]>>)[layout.Symbols.SecNum] <- symbols

  let addToSymbolMap (map: Dictionary<Addr, Symbol>) (symbols: Symbol[]) =
    for sym in symbols do
      if sym.Addr > 0UL || sym.SymType = SymbolType.STT_FUNC then
        map[sym.Addr] <- sym
      else
        ()

/// Represents the main data structure for storing ELF symbol information.
type internal SymbolStore internal(toolBox, shdrs, dynTables: DynamicTables) =
  let sectionsOfType t = shdrs |> Array.filter (fun s -> s.SecType = t)

  let tryFindSectionOfType t = shdrs |> Array.tryFind (fun s -> s.SecType = t)

  /// Pairs a symbol table section with the string table its sh_link names, and
  /// with the extended index table whose sh_link names it back.
  let layoutOf versions (sec: SectionHeader) =
    let extends s =
      s.SecType = SectionType.SHT_SYMTAB_SHNDX && int s.SecLink = sec.SecNum
    { Symbols = sec
      Strings = shdrs[Convert.ToInt32 sec.SecLink]
      Versions = versions
      ExtendedIndices = Array.tryFind extends shdrs }

  let staticLayouts =
    sectionsOfType SectionType.SHT_SYMTAB |> Array.map (layoutOf None)

  /// The dynamic symbol tables, taken from the section headers when they name
  /// any, and from what the dynamic array names when they are gone.
  let dynamicLayouts =
    match sectionsOfType SectionType.SHT_DYNSYM with
    | [||] ->
      match dynTables.Symbols, dynTables.Strings with
      | Some symbols, Some strings ->
        [| { Symbols = symbols
             Strings = strings
             Versions = dynTables.SymbolVersions
             ExtendedIndices = None } |]
      | _ ->
        [||]
    | secs ->
      let versions = tryFindSectionOfType SectionType.SHT_GNU_versym
      secs |> Array.map (layoutOf versions)

  /// IDs to symbol versions required to link.
  let versionTable =
    lazy
      let needs =
        tryFindSectionOfType SectionType.SHT_GNU_verneed
        |> Option.orElse dynTables.VersionNeeds
      let defs =
        tryFindSectionOfType SectionType.SHT_GNU_verdef
        |> Option.orElse dynTables.VersionDefs
      VersionTable.parse toolBox needs defs dynamicLayouts

  /// A mapping from a section number to the corresponding symbol table, each
  /// of which is parsed when it is first read.
  let symbolTables =
    let tbls = Dictionary<int, Lazy<Symbol[]>>()
    SymbolTables.register toolBox shdrs versionTable tbls staticLayouts
    SymbolTables.register toolBox shdrs versionTable tbls dynamicLayouts
    tbls

  /// Address to symbol mapping. The static tables precede the dynamic ones, so
  /// the winner of an address is independent of the evaluation order.
  let symbolMap =
    lazy
      let map = Dictionary<Addr, Symbol>()
      for layout in Array.append staticLayouts dynamicLayouts do
        let tbl = symbolTables[layout.Symbols.SecNum]
        SymbolTables.addToSymbolMap map tbl.Value
      map

  /// Symbols added by the other parsers, e.g., the PLT parser. They take
  /// precedence over the symbols of the symbol tables, so adding one never
  /// parses a symbol table.
  let addedSymbols = Dictionary<Addr, Symbol>()

  let collect (layouts: SymbolTableLayout[]) =
    layouts |> Array.collect (fun l -> symbolTables[l.Symbols.SecNum].Value)

  let staticSymbols = lazy collect staticLayouts

  let dynamicSymbols = lazy collect dynamicLayouts

  /// Returns parsed static symbols.
  member _.StaticSymbols with get() = staticSymbols.Value

  /// Returns parsed dynamic symbols.
  member _.DynamicSymbols with get() = dynamicSymbols.Value

  /// Adds a symbol to the symbol map. If the address already exists, it will
  /// be overwritten.
  member _.AddSymbol(addr: Addr, sym: Symbol) = addedSymbols[addr] <- sym

  /// Finds a symbol by its address.
  member _.FindSymbol(addr: Addr) =
    match addedSymbols.TryGetValue addr with
    | true, sym -> sym
    | false, _ -> symbolMap.Value[addr]

  /// Tries to find a symbol by its address.
  member _.TryFindSymbol(addr: Addr) =
    match addedSymbols.TryGetValue addr with
    | true, sym ->
      Ok sym
    | false, _ ->
      match symbolMap.Value.TryGetValue addr with
      | true, sym -> Ok sym
      | false, _ -> Error ErrorCase.ItemNotFound

  /// Tries to find a symbol array in ELF by its section number.
  member _.TryFindSymbolTable(secNum: int) =
    match symbolTables.TryGetValue secNum with
    | true, tbl -> Ok tbl.Value
    | false, _ -> Error ErrorCase.ItemNotFound

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

namespace B2R2.FrontEnd.BinFile.Mach

open System
open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

/// Represents symbol info.
type internal SymbolStore =
  { /// All symbols in symbol-table order (indexable by relocation symbolnum).
    SymbolArray: Symbol[]
    /// Address to symbol mapping.
    SymbolMap: SlotMap
    /// Imported symbols.
    Imports: BinImport[] }

/// Represents a map from the address of a slot to the symbol that slot names,
/// which is how the stub and the pointer tables of an image are read. A large
/// image fills thousands of such slots, so the lookup is a hashed one rather
/// than a tree walk.
and internal SlotMap = Dictionary<Addr, Symbol>

module internal SymbolStore =
  let [<Literal>] private IndirectSymbolLocal = 0x80000000

  let [<Literal>] private IndirectSymbolABS = 0x40000000

  let private chooseDyLib = function
    | DyLib(_, _, c) -> Some c
    | _ -> None

  let private chooseSymTab = function
    | SymTab(_, _, c) -> Some c
    | _ -> None

  let private chooseDynSymTab = function
    | DySymTab(_, _, c) -> Some c
    | _ -> None

  let private chooseFuncStarts = function
    | FuncStarts(_, _, c) -> Some c
    | _ -> None

  let private parseFuncStarts toolBox cmds =
    let bytes, reader = toolBox.Bytes, toolBox.Reader
    let addrSet = HashSet<Addr>()
    for cmd in cmds do
      let dataSpan = ReadOnlySpan(bytes, cmd.DataOffset, int cmd.DataSize)
      let saddr, count = reader.ReadUInt64LEB128(dataSpan, 0)
      let saddr = saddr + toolBox.BaseAddress
      addrSet.Add saddr |> ignore
      let mutable offset = count
      let mutable fnAddr = saddr
      while offset < int cmd.DataSize do
        let data, count = reader.ReadUInt64LEB128(dataSpan, offset)
        fnAddr <- fnAddr + data
        addrSet.Add fnAddr |> ignore
        offset <- offset + count
    addrSet

  let private countSymbols symtabs =
    symtabs |> Array.fold (fun cnt symtab -> int symtab.NumOfSym + cnt) 0

  /// Resolves the library a two-level namespace symbol is bound to. The
  /// ordinal is a 1-based index into the dylibs the file loads; the values
  /// outside that range are the special lookups (self, flat, dynamic, or the
  /// executable), which name no library of their own.
  let private getLibraryVerInfo (flags: MachFlag) (libs: _[]) nDesc =
    if flags.HasFlag MachFlag.MH_TWOLEVEL then
      let ord = nDesc >>> 8 &&& 0xffs |> int
      if ord >= 1 && ord <= libs.Length then Some libs[ord - 1] else None
    else
      None

  /// Places a symbol's value in the address space. An absolute symbol names a
  /// value rather than a location, so the load address never moves it, and an
  /// undefined symbol has no value to move.
  let private adjustSymVal toolBox nType addr =
    if addr = 0UL || nType &&& 0x0e = int SymbolType.N_ABS then addr
    else toolBox.BaseAddress + addr

  let private parseNList toolBox libs strTab symTab offset =
    let reader = toolBox.Reader
    let header = toolBox.Header
    let strIdx = reader.ReadInt32(span = symTab, offset = offset) (* n_strx *)
    let nDesc = reader.ReadInt16(symTab, offset + 6) (* n_desc *)
    let nType = symTab[offset + 4] |> int (* n_type *)
    { SymName = ByteArray.extractCStringFromSpan strTab strIdx
      SymType = nType |> LanguagePrimitives.EnumOfValue
      IsExternal = nType &&& 0x1 = 0x1
      SecNum = symTab[offset + 5] |> int (* n_sect *)
      SymDesc = nDesc
      VerInfo = getLibraryVerInfo header.Flags libs nDesc
      SymAddr = readUIntByWordSize symTab reader header.Class (offset + 8)
                |> adjustSymVal toolBox nType }

  let private parseSymTable ({ Bytes = bytes } as toolBox) libs symTabCmds =
    let numSymbols = countSymbols symTabCmds
    let symbols = Array.zeroCreate numSymbols
    let mutable idx = 0
    for symTabCmd in symTabCmds do
      let strOff, strSize = symTabCmd.StrOff, int symTabCmd.StrSize
      let strTab = ReadOnlySpan(bytes, strOff, strSize)
      let entrySize = 8 + WordSize.toByteWidth toolBox.Header.Class
      let symTabSize = int symTabCmd.NumOfSym * entrySize
      let symTab = ReadOnlySpan(bytes, symTabCmd.SymOff, symTabSize)
      for n = 0 to int symTabCmd.NumOfSym - 1 do
        let offset = n * entrySize
        symbols[idx] <- parseNList toolBox libs strTab symTab offset
        idx <- idx + 1
    symbols

  let private addFuncs secText (starts: HashSet<Addr>) symbols =
    starts.ExceptWith(symbols |> Seq.map (fun s -> s.SymAddr))
    starts
    |> Seq.toArray
    |> Array.map (fun addr ->
      { SymName = Addr.toFuncName addr
        SymType = SymbolType.N_SECT
        IsExternal = false
        SecNum = secText + 1
        SymDesc = -1s (* To indicate this is B2R2-created symbols. *)
        VerInfo = None
        SymAddr = addr })
    |> Array.append symbols

  let private obtainStaticSymbols symbols =
    symbols |> Array.filter Symbol.IsStatic

  let private countDynSymbs dyntabs =
    dyntabs
    |> Array.fold (fun cnt dyntab -> int dyntab.NumIndirectSym + cnt) 0

  /// DynSym table contains indices to the symbol table.
  let private parseDynSymTable toolBox dyntabs =
    let reader = toolBox.Reader
    let numSymbs = countDynSymbs dyntabs
    let indices = Array.zeroCreate numSymbs
    let mutable i = 0
    for dyntab in dyntabs do
      let tabOffset = int dyntab.IndirectSymOff
      let tabSize = int dyntab.NumIndirectSym * 4
      let tabBuf = ReadOnlySpan(toolBox.Bytes, tabOffset, tabSize)
      for n = 0 to int dyntab.NumIndirectSym - 1 do
        let offset = n * 4
        let symidx = reader.ReadInt32(tabBuf, offset)
        indices[i] <- symidx
        i <- i + 1
    indices

  let private isUndefinedEntry entry =
    entry = IndirectSymbolLocal || entry = IndirectSymbolABS

  /// Returns the symbol that the indirect table names at the given index, or
  /// None where the entry is a local or absolute placeholder, and where
  /// either table is shorter than the section claims it to be.
  let private tryGetSlotSymbol (symbols: _[]) (dynsymtbl: _[]) at =
    if at < 0 || at >= dynsymtbl.Length then
      ValueNone
    else
      let entry = dynsymtbl[at]
      if isUndefinedEntry entry || entry < 0 || entry >= symbols.Length then
        ValueNone
      else
        ValueSome symbols[entry]

  /// Adds every slot of one indirect section to the map, at the address the
  /// slot sits at.
  let private addSlots (map: SlotMap) symbols dynsymtbl sec len cnt =
    for idx = 0 to cnt - 1 do
      match tryGetSlotSymbol symbols dynsymtbl (sec.SecReserved1 + idx) with
      | ValueSome symbol -> map[sec.SecAddr + uint64 (idx * len)] <- symbol
      | ValueNone -> ()

  /// __stubs section is similar to PLT in ELF.
  let private parseSymbolStubs secs symbols dynsymtbl =
    let map = SlotMap()
    for sec in secs do
      match sec.SecType with
      | SectionType.S_SYMBOL_STUBS when sec.SecReserved2 > 0 ->
        let entryLen = sec.SecReserved2
        let entryCnt = int (sec.SecSize / uint64 entryLen)
        addSlots map symbols dynsymtbl sec entryLen entryCnt
      | _ ->
        ()
    map

  /// Symbol pointers are similar to GOT in ELF.
  let private parseSymbolPtrs macHdr secs symbols dynsymtbl =
    let map = SlotMap()
    let entryLen = WordSize.toByteWidth macHdr.Class
    for sec in secs do
      match sec.SecType with
      | SectionType.S_LAZY_SYMBOL_POINTERS
      | SectionType.S_NON_LAZY_SYMBOL_POINTERS ->
        let entryCnt = int (sec.SecSize / uint64 entryLen)
        addSlots map symbols dynsymtbl sec entryLen entryCnt
      | _ ->
        ()
    map

  let getSymbolLibName symbol =
    match symbol.VerInfo with
    | None -> ""
    | Some v -> v.DyLibName

  /// Maps each symbol name to the stub that calls it. A name reached by more
  /// than one stub keeps the one at the highest address.
  let private buildStubNameMap (stubs: SlotMap) =
    let nameMap = Dictionary<string, Addr>()
    for KeyValue(addr, symbol) in stubs do
      match nameMap.TryGetValue symbol.SymName with
      | true, prev when prev > addr -> ()
      | _ -> nameMap[symbol.SymName] <- addr
    nameMap

  /// Returns the entries of a slot map in address order, which is the order a
  /// reader expects the tables of an image to be listed in.
  let private inAddrOrder (map: SlotMap) =
    map |> Seq.sortBy (fun (KeyValue(addr, _)) -> addr)

  let private createImports stubs ptrtbls =
    let nameMap = buildStubNameMap stubs
    [| for KeyValue(addr, symbol) in inAddrOrder ptrtbls do
         match nameMap.TryGetValue symbol.SymName with
         | true, stubAddr ->
           { Name = symbol.SymName
             LibraryName = getSymbolLibName symbol
             TrampolineAddress = Some stubAddr
             TableAddress = addr }
         | false, _ ->
           () |]

  let private buildSymbolMap (stubs: SlotMap) (ptrtbls: SlotMap) staticsymbs =
    let dict = SlotMap()
    for KeyValue(addr, symbol) in stubs do
      dict[addr] <- symbol
    for KeyValue(addr, symbol) in ptrtbls do
      dict[addr] <- symbol
    for symbol in staticsymbs do
      dict[symbol.SymAddr] <- symbol
    dict

  let parse toolBox cmds secs =
    let secText = Section.getTextSectionIndex secs
    let libs = Array.choose chooseDyLib cmds
    let symtabs = Array.choose chooseSymTab cmds
    let dyntabs = Array.choose chooseDynSymTab cmds
    let fnStarts = parseFuncStarts toolBox (Array.choose chooseFuncStarts cmds)
    let symbs = parseSymTable toolBox libs symtabs |> addFuncs secText fnStarts
    let staticsymbs = obtainStaticSymbols symbs
    let dynsymIndices = parseDynSymTable toolBox dyntabs
    let stubs = parseSymbolStubs secs symbs dynsymIndices
    let ptrtbls = parseSymbolPtrs toolBox.Header secs symbs dynsymIndices
    let imports = createImports stubs ptrtbls
    { SymbolArray = symbs
      SymbolMap = buildSymbolMap stubs ptrtbls staticsymbs
      Imports = imports }

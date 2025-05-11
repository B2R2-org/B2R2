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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

/// Symbol type (N_TYPE).
type SymbolType =
  /// The symbol is undefined.
  | N_UNDF = 0x0
  /// The symbol is absolute. The linker does not update the value of an
  /// absolute symbol.
  | N_ABS = 0x2
  /// The symbol is defined in the section number given in n_sect.
  | N_SECT = 0xe
  /// The symbol is undefined and the image is using a prebound value for the
  /// symbol.
  | N_PBUD = 0xc
  /// The symbol is defined to be the same as another symbol.
  | N_INDR = 0xa
  /// Global symbol.
  | N_GSYM = 0x20
  /// Procedure name (f77 kludge).
  | N_FNAME = 0x22
  /// Procedure.
  | N_FUN = 0x24
  /// Static symbol.
  | N_STSYM = 0x26
  /// .lcomm symbol.
  | N_LCSYM = 0x28
  /// Begin nsect sym.
  | N_BNSYM = 0x2e
  /// AST file path.
  | N_AST = 0x32
  /// Emitted with gcc2_compiled and in gcc source.
  | N_OPT = 0x3c
  /// Register sym.
  | N_RSYM = 0x40
  /// Source line.
  | N_SLINE = 0x44
  /// End nsect sym.
  | N_ENSYM = 0x4e
  /// Structure element.
  | N_SSYM = 0x60
  /// Source file name.
  | N_SO = 0x64
  /// Object file name.
  | N_OSO = 0x66
  /// Local symbol.
  | N_LSYM = 0x80
  /// Include file beginning.
  | N_BINCL = 0x82
  /// "#included" file name: name,,n_sect,0,address.
  | N_SOL = 0x84
  /// Compiler parameters.
  | N_PARAMS = 0x86
  /// Compiler version.
  | N_VERSION= 0x88
  /// Compiler optimization level.
  | N_OLEVEL = 0x8a
  /// Parameter.
  | N_PSYM = 0xa0
  /// Include file end.
  | N_EINCL = 0xa2
  /// Alternate entry.
  | N_ENTRY = 0xa4
  /// Left bracket.
  | N_LBRAC = 0xc0
  /// Deleted include file.
  | N_EXCL = 0xc2
  /// Right bracket.
  | N_RBRAC = 0xe0
  /// Begin common.
  | N_BCOMM = 0xe2
  /// End common.
  | N_ECOMM = 0xe4
  /// End common (local name).
  | N_ECOML = 0xe8
  /// Second stab entry with length information.
  | N_LENG = 0xfe
  /// Global pascal symbol.
  | N_PC = 0x30

/// Mach-O symbol.
type MachSymbol = {
  /// Symbol name.
  SymName: string
  /// Symbol type (N_TYPE field of n_type).
  SymType: SymbolType
  /// Is this an external symbol?
  IsExternal: bool
  /// The number of the section that this symbol can be found.
  SecNum: int
  /// Providing additional information about the nature of this symbol for
  /// non-stab symbols.
  SymDesc: int16
  /// External library version info.
  VerInfo: DyLibCmd option
  /// Address of the symbol.
  SymAddr: Addr
}

/// Export info.
type ExportInfo = {
  /// Symbol name.
  ExportSymName: string
  /// Exported symbol address.
  ExportAddr: Addr
}

/// Symbol info
type SymInfo = {
  /// All symbols.
  Symbols: MachSymbol[]
  /// Address to symbol mapping.
  SymbolMap: Map<Addr, MachSymbol>
  /// Linkage table.
  LinkageTable: LinkageTableEntry list
  /// Export info.
  Exports: ExportInfo[]
}

module internal Symbol =
  let [<Literal>] private IndirectSymbolLocal = 0x80000000

  let [<Literal>] private IndirectSymbolABS = 0x40000000

  let private chooseDyLib = function
    | DyLib c -> Some c
    | _ -> None

  let private chooseSymTab = function
    | SymTab c -> Some c
    | _ -> None

  let private chooseDynSymTab = function
    | DySymTab c -> Some c
    | _ -> None

  let private chooseDyLdInfo = function
    | DyLdInfo c -> Some c
    | _ -> None

  let private chooseFuncStarts = function
    | FuncStarts c -> Some c
    | _ -> None

  let private parseFuncStarts toolBox cmds =
    let bytes, reader = toolBox.Bytes, toolBox.Reader
    let addrSet = HashSet<Addr> ()
    for cmd in cmds do
      let dataSpan = ReadOnlySpan (bytes, cmd.DataOffset, int cmd.DataSize)
      let saddr, count = reader.ReadUInt64LEB128 (dataSpan, 0)
      let saddr = saddr + toolBox.BaseAddress
      addrSet.Add saddr |> ignore
      let mutable offset = count
      let mutable fnAddr = saddr
      while offset < int cmd.DataSize do
        let data, count = reader.ReadUInt64LEB128 (dataSpan, offset)
        fnAddr <- fnAddr + data
        addrSet.Add fnAddr |> ignore
        offset <- offset + count
    addrSet

  let private countSymbols symtabs =
    symtabs |> Array.fold (fun cnt symtab -> int symtab.NumOfSym + cnt) 0

  let private getLibraryVerInfo (flags: MachFlag) libs nDesc =
    if flags.HasFlag (MachFlag.MH_TWOLEVEL) then
      let ord = nDesc >>> 8 &&& 0xffs |> int
      if ord = 0 || ord = 254 then None
      else Some <| Array.get libs (ord - 1)
    else None

  let private adjustSymVal toolBox addr = (* TODO: needs to consider n_type *)
    if addr = 0UL then 0UL
    else toolBox.BaseAddress + uint64 addr

  let private parseNList toolBox libs strTab symTab offset =
    let reader = toolBox.Reader
    let header = toolBox.Header
    let strIdx = reader.ReadInt32 (span=symTab, offset=offset) (* n_strx *)
    let nDesc = reader.ReadInt16 (symTab, offset + 6) (* n_desc *)
    let nType = symTab[offset + 4] |> int (* n_type *)
    { SymName = ByteArray.extractCStringFromSpan strTab strIdx
      SymType = nType |> LanguagePrimitives.EnumOfValue
      IsExternal = nType &&& 0x1 = 0x1
      SecNum = symTab[offset + 5] |> int (* n_sect *)
      SymDesc = nDesc
      VerInfo = getLibraryVerInfo header.Flags libs nDesc
      SymAddr = readUIntByWordSize symTab reader header.Class (offset + 8)
                |> adjustSymVal toolBox }

  let private parseSymTable ({ Bytes = bytes } as toolBox) libs symTabCmds =
    let numSymbols = countSymbols symTabCmds
    let symbols = Array.zeroCreate numSymbols
    let mutable idx = 0
    for symTabCmd in symTabCmds do
      let strOff, strSize = symTabCmd.StrOff, int symTabCmd.StrSize
      let strTab = ReadOnlySpan (bytes, strOff, strSize)
      let entrySize = 8 + WordSize.toByteWidth toolBox.Header.Class
      let symTabSize = int symTabCmd.NumOfSym * entrySize
      let symTab = ReadOnlySpan (bytes, symTabCmd.SymOff, symTabSize)
      for n = 0 to int symTabCmd.NumOfSym - 1 do
        let offset = n * entrySize
        symbols[idx] <- parseNList toolBox libs strTab symTab offset
        idx <- idx + 1
    symbols

  let private addFuncs secText (starts: HashSet<Addr>) symbols =
    let symbolAddrs = symbols |> Array.map (fun s -> s.SymAddr) |> HashSet
    starts.ExceptWith symbolAddrs
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

  let isStatic s =
    let isDebuggingInfo s = int s.SymType &&& 0xe0 <> 0
    (* REFERENCED_DYNAMICALLY field of n_desc is set. This means this symbol
       will not be stripped (thus, this symbol is dynamic). *)
    let isReferrencedDynamically s = s.SymDesc &&& 0x10s <> 0s
    isDebuggingInfo s
    || (s.SecNum > 0 && s.SymAddr > 0UL && s.VerInfo = None
       && (isReferrencedDynamically s |> not))

  let isDynamic s = isStatic s |> not

  let private obtainStaticSymbols symbols =
    symbols |> Array.filter isStatic

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
      let tabBuf = ReadOnlySpan (toolBox.Bytes, tabOffset, tabSize)
      for n = 0 to int dyntab.NumIndirectSym - 1 do
        let offset = n * 4
        let symidx = reader.ReadInt32 (tabBuf, offset)
        indices[i] <- symidx
        i <- i + 1
    indices

  let private isUndefinedEntry entry =
     entry = IndirectSymbolLocal || entry = IndirectSymbolABS

  let rec private parseSymbStub map symbols dynsymtbl sec idx len cnt =
    if cnt = 0UL then map
    else
      let entry = Array.get dynsymtbl (sec.SecReserved1 + idx)
      if isUndefinedEntry entry then
        parseSymbStub map symbols dynsymtbl sec (idx + 1) len (cnt - 1UL)
      else
        let symbol = Array.get symbols entry
        let map' = Map.add (sec.SecAddr + uint64 (idx * len)) symbol map
        parseSymbStub map' symbols dynsymtbl sec (idx + 1) len (cnt - 1UL)

  /// __stubs section is similar to PLT in ELF.
  let private parseSymbolStubs secs symbols dynsymtbl =
    let folder acc sec =
      match sec.SecType with
      | SectionType.S_SYMBOL_STUBS ->
        let entryLen = sec.SecReserved2
        let entryCnt = sec.SecSize / uint64 entryLen
        parseSymbStub acc symbols dynsymtbl sec 0 entryLen entryCnt
      | _ -> acc
    secs |> Array.fold folder Map.empty

  /// Symbol pointer tables are similar to GOT in ELF.
  let private parseSymbolPtrs macHdr secs symbols dynsymtbl =
    let folder acc sec =
      match sec.SecType with
      | SectionType.S_LAZY_SYMBOL_POINTERS
      | SectionType.S_NON_LAZY_SYMBOL_POINTERS ->
        let entryLen = WordSize.toByteWidth macHdr.Class
        let entryCnt = sec.SecSize / uint64 entryLen
        parseSymbStub acc symbols dynsymtbl sec 0 entryLen entryCnt
      | _ -> acc
    secs |> Array.fold folder Map.empty

  let getSymbolLibName symbol =
    match symbol.VerInfo with
    | None -> ""
    | Some v -> v.DyLibName

  let private accumulateLinkageInfo nameMap lst addr symbol =
    match Map.tryFind symbol.SymName nameMap with
    | None -> lst
    | Some stubAddr ->
      let lib = getSymbolLibName symbol
      { FuncName = symbol.SymName
        LibraryName = lib
        TrampolineAddress = stubAddr
        TableAddress = addr } :: lst

  let private createLinkageTable stubs ptrtbls =
    let nameMap = Map.fold (fun m a s -> Map.add s.SymName a m) Map.empty stubs
    ptrtbls |> Map.fold (accumulateLinkageInfo nameMap) []

  let rec readStr (span: ByteSpan) pos acc =
    match span[pos] with
    | 0uy ->
      List.rev acc |> List.toArray |> Text.Encoding.ASCII.GetString, pos + 1
    | b -> readStr span (pos + 1) (b :: acc)

  let buildExportEntry name addr =
    { ExportSymName = name; ExportAddr = addr }

  let rec private parseTrie toolBox (span: ByteSpan) offset str acc =
    let reader = toolBox.Reader
    if span[offset] = 0uy then (* non-terminal *)
      let nChilds, len = reader.ReadUInt64LEB128 (span, offset + 1)
      parseChildren toolBox span (offset + 1 + len) nChilds str acc
    else
      let _, shift = reader.ReadUInt64LEB128 (span, offset)
      let flagOffset = offset + shift
      let _flag = span[flagOffset]
      let symbOffset, _ = reader.ReadUInt64LEB128 (span, flagOffset + 1)
      buildExportEntry str (symbOffset + toolBox.BaseAddress) :: acc
  and private parseChildren toolBox span offset nChilds str acc =
    if nChilds = 0UL then acc
    else
      let pref, nextOffset = readStr span offset []
      let reader = toolBox.Reader
      let nextNode, len = reader.ReadUInt64LEB128 (span, nextOffset)
      let acc = parseTrie toolBox span (int nextNode) (str + pref) acc
      parseChildren toolBox span (nextOffset + len) (nChilds - 1UL) str acc

  /// The symbols exported by a dylib are encoded in a trie.
  let private parseExportTrieHead toolBox exportSpan =
    parseTrie toolBox exportSpan 0 "" []

  let private parseExports toolBox dyldinfo =
    match Array.tryHead dyldinfo with
    | None -> [||]
    | Some info ->
      let exportSize = int info.ExportSize
      let exportSpan = ReadOnlySpan (toolBox.Bytes, info.ExportOff, exportSize)
      parseExportTrieHead toolBox exportSpan
      |> List.toArray

  let private buildSymbolMap stubs ptrtbls staticsymbs =
    let map = Map.fold (fun map k v -> Map.add k v map) stubs ptrtbls
    Array.fold (fun map s -> Map.add s.SymAddr s map) map staticsymbs

  let parse toolBox cmds secs =
    let secText = Section.getTextSectionIndex secs
    let libs = Array.choose chooseDyLib cmds
    let symtabs = Array.choose chooseSymTab cmds
    let dyntabs = Array.choose chooseDynSymTab cmds
    let dyldinfo = Array.choose chooseDyLdInfo cmds
    let fnStarts = parseFuncStarts toolBox (Array.choose chooseFuncStarts cmds)
    let symbs = parseSymTable toolBox libs symtabs |> addFuncs secText fnStarts
    let staticsymbs = obtainStaticSymbols symbs
    let dynsymIndices = parseDynSymTable toolBox dyntabs
    let stubs = parseSymbolStubs secs symbs dynsymIndices
    let ptrtbls = parseSymbolPtrs toolBox.Header secs symbs dynsymIndices
    let linkage = createLinkageTable stubs ptrtbls
    let exports = parseExports toolBox dyldinfo
    { Symbols = symbs |> Array.filter (fun s -> s.SymType <> SymbolType.N_OPT)
      SymbolMap = buildSymbolMap stubs ptrtbls staticsymbs
      LinkageTable = linkage
      Exports = exports }

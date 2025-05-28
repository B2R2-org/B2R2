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
type SymbolStore = {
  /// All symbols.
  Values: Symbol[]
  /// Address to symbol mapping.
  SymbolMap: Map<Addr, Symbol>
  /// Linkage table.
  LinkageTable: LinkageTableEntry list
}

module internal SymbolStore =
  let [<Literal>] private IndirectSymbolLocal = 0x80000000

  let [<Literal>] private IndirectSymbolABS = 0x40000000

  let private chooseDyLib = function
    | DyLib (_, _, c) -> Some c
    | _ -> None

  let private chooseSymTab = function
    | SymTab (_, _, c) -> Some c
    | _ -> None

  let private chooseDynSymTab = function
    | DySymTab (_, _, c) -> Some c
    | _ -> None

  let private chooseFuncStarts = function
    | FuncStarts (_, _, c) -> Some c
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

  /// Symbol pointers are similar to GOT in ELF.
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

  let private buildSymbolMap stubs ptrtbls staticsymbs =
    let map = Map.fold (fun map k v -> Map.add k v map) stubs ptrtbls
    Array.fold (fun map s -> Map.add s.SymAddr s map) map staticsymbs

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
    let linkage = createLinkageTable stubs ptrtbls
    { Values = symbs |> Array.filter (fun s -> s.SymType <> SymbolType.N_OPT)
      SymbolMap = buildSymbolMap stubs ptrtbls staticsymbs
      LinkageTable = linkage }

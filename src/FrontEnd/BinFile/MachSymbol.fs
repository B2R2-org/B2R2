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

module internal B2R2.FrontEnd.BinFile.Mach.Symbol

open System
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

let [<Literal>] IndirectSymbolLocal = 0x80000000
let [<Literal>] IndirectSymbolABS = 0x40000000

let chooseDyLib = function
  | DyLib c -> Some c
  | _ -> None

let chooseSymTab = function
  | SymTab c -> Some c
  | _ -> None

let chooseDynSymTab = function
  | DySymTab c -> Some c
  | _ -> None

let chooseDyLdInfo = function
  | DyLdInfo c -> Some c
  | _ -> None

let chooseFuncStarts = function
  | FuncStarts c -> Some c
  | _ -> None

let parseFuncStarts baseAddr (reader: BinReader) cmds =
  let rec update set addr offset lastOffset =
    if offset >= lastOffset then set
    else
      let data, count = reader.PeekUInt64LEB128 offset
      let addr = addr + data
      update (Set.add addr set) addr (offset + count) lastOffset
  cmds
  |> List.fold (fun set c ->
    let offset = c.DataOffset
    let saddr, count = reader.PeekUInt64LEB128 offset
    let saddr = saddr + baseAddr
    let set = Set.add saddr set
    update set saddr (offset + count) (offset + int c.DataSize)) Set.empty

let getLibraryVerInfo (flags: MachFlag) libs nDesc =
  if flags.HasFlag (MachFlag.MHTwoLevel) then
    let ord = nDesc >>> 8 &&& 0xffs |> int
    if ord = 0 || ord = 254 then None
    else Some <| Array.get libs (ord - 1)
  else None

let adjustSymAddr baseAddr addr =
  if addr = 0UL then 0UL
  else baseAddr + addr

let parseNList acc baseAddr (reader: BinReader) macHdr libs strtab offset =
  let strIdx = reader.PeekInt32 offset
  let nDesc = reader.PeekInt16 (offset + 6)
  let nType = reader.PeekByte (offset + 4) |> int
  { SymName = ByteArray.extractCStringFromSpan strtab strIdx
    SymType = nType |> LanguagePrimitives.EnumOfValue
    IsExternal = nType &&& 0x1 = 0x1
    SecNum = reader.PeekByte (offset + 5) |> int
    SymDesc = nDesc
    VerInfo = getLibraryVerInfo macHdr.Flags libs nDesc
    SymAddr = peekUIntOfType reader macHdr.Class (offset + 8)
              |> adjustSymAddr baseAddr } :: acc

/// Parse SymTab, which is essentially an array of n_list.
let rec symTab acc baseAddr reader macHdr libs strtab offset numSymbs =
  if numSymbs = 0u then acc
  else
    let acc = parseNList acc baseAddr reader macHdr libs strtab offset
    let offset' = offset + 8 + WordSize.toByteWidth macHdr.Class
    symTab acc baseAddr reader macHdr libs strtab offset' (numSymbs - 1u)

let parseSymTable baseAddr (reader: BinReader) macHdr libs symtabs =
  let foldSymTabs acc symtab =
    let strtabSize = Convert.ToInt32 symtab.StrSize
    let strtab = reader.PeekSpan (strtabSize, symtab.StrOff)
    symTab acc baseAddr reader macHdr libs strtab symtab.SymOff symtab.NumOfSym
  symtabs |> List.fold foldSymTabs [] |> List.rev |> List.toArray

let addFuncs secTxt starts symbols =
  let symbolAddrs = symbols |> Array.map (fun s -> s.SymAddr) |> Set.ofArray
  Set.difference starts symbolAddrs
  |> Set.toArray
  |> Array.map (fun addr ->
    { SymName = Addr.toFuncName addr
      SymType = SymbolType.NSect
      IsExternal = false
      SecNum = secTxt + 1
      SymDesc = -1s (* To indicate this is B2R2-created symbols. *)
      VerInfo = None
      SymAddr = addr })
  |> Array.append symbols

let isStatic s =
  let isDebuggingInfo s = int s.SymType &&& 0xe0 <> 0
  /// REFERENCED_DYNAMICALLY field  of n_desc is set. This means this symbol
  /// will not be stripped (thus, this symbol is dynamic).
  let isReferrencedDynamically s = s.SymDesc &&& 0x10s <> 0s
  isDebuggingInfo s
  || (s.SecNum > 0 && s.SymAddr > 0UL && s.VerInfo = None
     && (isReferrencedDynamically s |> not))

let isDynamic s = isStatic s |> not

let obtainStaticSymbols symbols =
  symbols |> Array.filter isStatic

let rec parseDynTab acc (reader: BinReader) offset numSymbs =
  if numSymbs = 0u then acc
  else let idx = reader.PeekInt32 offset
       parseDynTab (idx :: acc) reader (offset + 4) (numSymbs- 1u)

/// DynSym table contains indices to the symbol table.
let parseDynSymTable reader dyntabs =
  let foldDynTabs acc dyntab =
    let tabOffset = Convert.ToInt32 dyntab.IndirectSymOff
    parseDynTab acc reader tabOffset dyntab.NumIndirectSym
  dyntabs |> List.fold foldDynTabs [] |> List.rev |> List.toArray

let isUndefinedEntry entry =
   entry = IndirectSymbolLocal || entry = IndirectSymbolABS

let rec parseSymbStub map symbols dynsymtbl sec idx len cnt =
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
let parseSymbolStubs secs symbols dynsymtbl =
  let folder acc sec =
    match sec.SecType with
    | SectionType.SymbolStubs ->
      let entryLen = sec.SecReserved2
      let entryCnt = sec.SecSize / uint64 entryLen
      parseSymbStub acc symbols dynsymtbl sec 0 entryLen entryCnt
    | _ -> acc
  secs.SecByNum |> Array.fold folder Map.empty

/// Symbol pointer tables are similar to GOT in ELF.
let parseSymbolPtrs macHdr secs symbols dynsymtbl =
  let folder acc sec =
    match sec.SecType with
    | SectionType.LazySymbolPointers
    | SectionType.NonLazySymbolPointers ->
      let entryLen = WordSize.toByteWidth macHdr.Class
      let entryCnt = sec.SecSize / uint64 entryLen
      parseSymbStub acc symbols dynsymtbl sec 0 entryLen entryCnt
    | _ -> acc
  secs.SecByNum |> Array.fold folder Map.empty

let getSymbolLibName symbol =
  match symbol.VerInfo with
  | None -> ""
  | Some v -> v.DyLibName

let accumulateLinkageInfo nameMap lst addr symbol =
  match Map.tryFind symbol.SymName nameMap with
  | None -> lst
  | Some stubAddr ->
    let lib = getSymbolLibName symbol
    { FuncName = symbol.SymName
      LibraryName = lib
      TrampolineAddress = stubAddr
      TableAddress = addr } :: lst

let createLinkageTable stubs ptrtbls =
  let nameMap = Map.fold (fun m a s -> Map.add s.SymName a m) Map.empty stubs
  ptrtbls |> Map.fold (accumulateLinkageInfo nameMap) []

let rec readStr (reader: BinReader) pos acc =
  match reader.PeekByte pos with
  | 0uy ->
    List.rev acc |> List.toArray |> Text.Encoding.ASCII.GetString, pos + 1
  | b -> readStr reader (pos + 1) (b :: acc)

let buildExportEntry name addr =
  { ExportSymName = name; ExportAddr = addr }

/// The symbols exported by a dylib are encoded in a trie.
let parseExportTrieHead baseAddr (reader: BinReader) trieOffset =
  let rec parseExportTrie offset str acc =
    let b = reader.PeekByte offset
    if b = 0uy then (* non-terminal *)
      let numChildren, len = reader.PeekUInt64LEB128 (offset + 1)
      parseChildren (offset + 1 + len) numChildren str acc
    else
      let _, shift= reader.PeekUInt64LEB128 offset
      let _flag = reader.PeekByte (offset + shift)
      let symbOffset, _ = reader.PeekUInt64LEB128 (offset + shift + 1)
      buildExportEntry str (symbOffset + baseAddr) :: acc
  and parseChildren offset numChildren str acc =
    if numChildren = 0UL then acc
    else
      let pref, nextOffset = readStr reader offset []
      let nextNode, len = reader.PeekUInt64LEB128 nextOffset
      let acc = parseExportTrie (int nextNode + trieOffset) (str + pref) acc
      parseChildren (nextOffset + len) (numChildren - 1UL) str acc
  parseExportTrie trieOffset "" []

let parseExports baseAddr (reader: BinReader) dyldinfo =
  match List.tryHead dyldinfo with
  | None -> []
  | Some info ->
    parseExportTrieHead baseAddr reader info.ExportOff

let buildSymbolMap stubs ptrtbls staticsymbs =
  let map = Map.fold (fun map k v -> Map.add k v map) stubs ptrtbls
  Array.fold (fun map s -> Map.add s.SymAddr s map) map staticsymbs

let parse baseAddr reader macHdr cmds secs secTxt =
  let libs = List.choose chooseDyLib cmds |> List.toArray
  let symtabs = List.choose chooseSymTab cmds
  let dyntabs = List.choose chooseDynSymTab cmds
  let dyldinfo = List.choose chooseDyLdInfo cmds
  let starts =
    List.choose chooseFuncStarts cmds |> parseFuncStarts baseAddr reader
  let symbs =
    parseSymTable baseAddr reader macHdr libs symtabs |> addFuncs secTxt starts
  let staticsymbs = obtainStaticSymbols symbs
  let dynsymIndices = parseDynSymTable reader dyntabs
  let stubs = parseSymbolStubs secs symbs dynsymIndices
  let ptrtbls = parseSymbolPtrs macHdr secs symbs dynsymIndices
  let linkage = createLinkageTable stubs ptrtbls
  let exports = parseExports baseAddr reader dyldinfo
  { Symbols = symbs |> Array.filter (fun s -> s.SymType <> SymbolType.NOpt)
    SymbolMap = buildSymbolMap stubs ptrtbls staticsymbs
    LinkageTable = linkage
    Exports = exports }

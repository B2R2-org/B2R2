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
open System.Collections.Generic
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

let parseFuncStarts baseAddr (span: ByteSpan) reader cmds =
  let set = HashSet<Addr> ()
  for cmd in cmds do
    let offset = cmd.DataOffset
    let saddr, count = (reader: IBinReader).ReadUInt64LEB128 (span, offset)
    let saddr = saddr + baseAddr
    set.Add saddr |> ignore
    let lastOffset = offset + int cmd.DataSize
    let mutable offset = offset + count
    let mutable fnAddr = saddr
    while offset < lastOffset do
      let data, count = (reader: IBinReader).ReadUInt64LEB128 (span, offset)
      fnAddr <- fnAddr + data
      set.Add fnAddr |> ignore
      offset <- offset + count
  set |> Set

let getLibraryVerInfo (flags: MachFlag) libs nDesc =
  if flags.HasFlag (MachFlag.MHTwoLevel) then
    let ord = nDesc >>> 8 &&& 0xffs |> int
    if ord = 0 || ord = 254 then None
    else Some <| Array.get libs (ord - 1)
  else None

let adjustSymAddr baseAddr addr =
  if addr = 0UL then 0UL
  else baseAddr + addr

let parseNList baseAddr (span: ByteSpan) reader macHdr libs strtab offset =
  let strIdx = (reader: IBinReader).ReadInt32 (span, offset)
  let nDesc = reader.ReadInt16 (span, offset + 6)
  let nType = span[offset + 4] |> int
  { SymName = ByteArray.extractCStringFromSpan strtab strIdx
    SymType = nType |> LanguagePrimitives.EnumOfValue
    IsExternal = nType &&& 0x1 = 0x1
    SecNum = span[offset + 5] |> int
    SymDesc = nDesc
    VerInfo = getLibraryVerInfo macHdr.Flags libs nDesc
    SymAddr = peekUIntOfType span reader macHdr.Class (offset + 8)
              |> adjustSymAddr baseAddr }

/// Parse SymTab, which is essentially an array of n_list.
let rec symTab lst baseAddr span reader macHdr libs strtab offset numSymbs =
  if numSymbs = 0u then ()
  else
    let symb = parseNList baseAddr span reader macHdr libs strtab offset
    (lst: List<MachSymbol>).Add symb
    let offset' = offset + 8 + WordSize.toByteWidth macHdr.Class
    symTab lst baseAddr span reader macHdr libs strtab offset' (numSymbs - 1u)

let parseSymTable baseAddr (span: ByteSpan) reader macHdr libs symtabs =
  let lst = List<MachSymbol> ()
  for symtab in symtabs do
    let strtabSize = Convert.ToInt32 symtab.StrSize
    let strtab = span.Slice (symtab.StrOff, strtabSize)
    symTab lst baseAddr span reader macHdr libs strtab
           symtab.SymOff symtab.NumOfSym
  lst |> Seq.toArray

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
  /// REFERENCED_DYNAMICALLY field of n_desc is set. This means this symbol
  /// will not be stripped (thus, this symbol is dynamic).
  let isReferrencedDynamically s = s.SymDesc &&& 0x10s <> 0s
  isDebuggingInfo s
  || (s.SecNum > 0 && s.SymAddr > 0UL && s.VerInfo = None
     && (isReferrencedDynamically s |> not))

let isDynamic s = isStatic s |> not

let obtainStaticSymbols symbols =
  symbols |> Array.filter isStatic

let rec parseDynTab lst (span: ByteSpan) reader offset numSymbs =
  if numSymbs = 0u then ()
  else
    let idx = (reader: IBinReader).ReadInt32 (span, offset)
    (lst: List<int>).Add idx
    parseDynTab lst span reader (offset + 4) (numSymbs- 1u)

/// DynSym table contains indices to the symbol table.
let parseDynSymTable span reader dyntabs =
  let lst = List<int> ()
  for dyntab in dyntabs do
    let tabOffset = Convert.ToInt32 dyntab.IndirectSymOff
    parseDynTab lst span reader tabOffset dyntab.NumIndirectSym
  lst |> Seq.toArray

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

let rec readStr (span: ByteSpan) pos acc =
  match span[pos] with
  | 0uy ->
    List.rev acc |> List.toArray |> Text.Encoding.ASCII.GetString, pos + 1
  | b -> readStr span (pos + 1) (b :: acc)

let buildExportEntry name addr =
  { ExportSymName = name; ExportAddr = addr }

let rec parseExportTrie bAddr span reader trieOfs ofs str acc =
  let b = (span: ByteSpan)[ofs]
  if b = 0uy then (* non-terminal *)
    let nChilds, len =
      (reader: IBinReader).ReadUInt64LEB128 (span, ofs + 1)
    parseChildren bAddr span reader trieOfs (ofs + 1 + len) nChilds str acc
  else
    let _, shift= reader.ReadUInt64LEB128 (span, ofs)
    let _flag = span[ofs + shift]
    let symbOffset, _ = reader.ReadUInt64LEB128 (span, ofs + shift + 1)
    buildExportEntry str (symbOffset + bAddr) :: acc
and parseChildren bAddr span reader trieOfs ofs nChilds str acc =
  if nChilds = 0UL then acc
  else
    let pref, nextOffset = readStr span ofs []
    let nextNode, len = reader.ReadUInt64LEB128 (span, nextOffset)
    let acc =
      parseExportTrie bAddr span reader trieOfs
                      (int nextNode + trieOfs) (str + pref) acc
    parseChildren bAddr span reader trieOfs
                  (nextOffset + len) (nChilds - 1UL) str acc

/// The symbols exported by a dylib are encoded in a trie.
let parseExportTrieHead baseAddr span reader trieOffset =
  parseExportTrie baseAddr span reader trieOffset trieOffset "" []

let parseExports baseAddr span reader dyldinfo =
  match List.tryHead dyldinfo with
  | None -> []
  | Some info ->
    parseExportTrieHead baseAddr span reader info.ExportOff

let buildSymbolMap stubs ptrtbls staticsymbs =
  let map = Map.fold (fun map k v -> Map.add k v map) stubs ptrtbls
  Array.fold (fun map s -> Map.add s.SymAddr s map) map staticsymbs

let parse baseAddr span reader macHdr cmds secs secTxt =
  let libs = List.choose chooseDyLib cmds |> List.toArray
  let symtabs = List.choose chooseSymTab cmds
  let dyntabs = List.choose chooseDynSymTab cmds
  let dyldinfo = List.choose chooseDyLdInfo cmds
  let fnStarts =
    parseFuncStarts baseAddr span reader (List.choose chooseFuncStarts cmds)
  let symbs =
    parseSymTable baseAddr span reader macHdr libs symtabs
    |> addFuncs secTxt fnStarts
  let staticsymbs = obtainStaticSymbols symbs
  let dynsymIndices = parseDynSymTable span reader dyntabs
  let stubs = parseSymbolStubs secs symbs dynsymIndices
  let ptrtbls = parseSymbolPtrs macHdr secs symbs dynsymIndices
  let linkage = createLinkageTable stubs ptrtbls
  let exports = parseExports baseAddr span reader dyldinfo
  { Symbols = symbs |> Array.filter (fun s -> s.SymType <> SymbolType.NOpt)
    SymbolMap = buildSymbolMap stubs ptrtbls staticsymbs
    LinkageTable = linkage
    Exports = exports }

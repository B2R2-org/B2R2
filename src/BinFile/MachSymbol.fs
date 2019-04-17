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

module B2R2.BinFile.Mach.Symbol

open System
open B2R2
open B2R2.BinFile
open B2R2.BinFile.FileHelper

let [<Literal>] IndirectSymbolLocal = 0x80000000
let [<Literal>] IndirectSymbolABS = 0x40000000

let chooseDyLib = function
  | DyLib s -> Some s
  | _ -> None

let chooseSymTab = function
  | SymTab s -> Some s
  | _ -> None

let chooseDynSymTab = function
  | DySymTab s -> Some s
  | _ -> None

let getLibraryVerInfo (flags: MachFlag) libs nDesc =
  if flags.HasFlag (MachFlag.MHTwoLevel) then
    let ord = nDesc >>> 8 &&& 0xffs |> int
    if ord = 0 || ord = 254 then None
    else Some <| Array.get libs (ord - 1)
  else None

let parseNList acc (reader: BinReader) macHdr libs strtab offset =
  let strIdx = reader.PeekInt32 offset
  let nDesc = reader.PeekInt16 (offset + 6)
  let nType = reader.PeekByte (offset + 4) |> int
  { SymName = ByteArray.extractCString strtab strIdx
    SymType = nType |> LanguagePrimitives.EnumOfValue
    IsExternal = nType &&& 0x1 = 0x1
    SecNum = reader.PeekByte (offset + 5)
    SymDesc = nDesc
    VerInfo = getLibraryVerInfo macHdr.Flags libs nDesc
    SymAddr = peekUIntOfType reader macHdr.Class (offset + 8) } :: acc

/// Parse SymTab, which is essentially an array of n_list.
let rec parseSymTab acc reader macHdr libs strtab offset numSymbs =
  if numSymbs = 0u then acc
  else let acc = parseNList acc reader macHdr libs strtab offset
       let offset' = offset + 8 + WordSize.toByteWidth macHdr.Class
       parseSymTab acc reader macHdr libs strtab offset' (numSymbs - 1u)

let parseSymTable (reader: BinReader) offset macHdr libs symtabs =
  let foldSymTabs acc symtab =
    let strtabSize = Convert.ToInt32 symtab.StrSize
    let strtab = reader.PeekBytes (strtabSize, offset + symtab.StrOff)
    let symOff = offset + symtab.SymOff
    parseSymTab acc reader macHdr libs strtab symOff symtab.NumOfSym
  symtabs |> List.fold foldSymTabs [] |> List.rev |> List.toArray

let obtainStaticSymbols symbols =
  let isStatic s =
    s.SymType = SymbolType.NStSym || s.SymType = SymbolType.NFun
  symbols |> Array.filter (fun s -> isStatic s && s.SecNum > 0uy)

let rec parseDynTab acc (reader: BinReader) offset numSymbs =
  if numSymbs = 0u then acc
  else let idx = reader.PeekInt32 offset
       parseDynTab (idx :: acc) reader (offset + 4) (numSymbs- 1u)

/// DynSym table contains indices to the symbol table.
let parseDynSymTable reader offset dyntabs =
  let foldDynTabs acc dyntab =
    let tabOffset = Convert.ToInt32 dyntab.IndirectSymOff + offset
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

let buildSymbolMap stubs ptrtbls staticsymbs =
  let map = Map.fold (fun map k v -> Map.add k v map) stubs ptrtbls
  Array.fold (fun map s -> Map.add s.SymAddr s map) map staticsymbs

let parse macHdr cmds secs reader offset =
  let libs = List.choose chooseDyLib cmds |> List.toArray
  let symtabs = List.choose chooseSymTab cmds
  let dyntabs = List.choose chooseDynSymTab cmds
  let symbols = parseSymTable reader offset macHdr libs symtabs
  let staticsymbs = obtainStaticSymbols symbols
  let dynsymIndices = parseDynSymTable reader offset dyntabs
  let stubs = parseSymbolStubs secs symbols dynsymIndices
  let ptrtbls = parseSymbolPtrs macHdr secs symbols dynsymIndices
  let linkage = createLinkageTable stubs ptrtbls
  { Symbols = symbols |> Array.filter (fun s -> s.SymType <> SymbolType.NOpt)
    SymbolMap = buildSymbolMap stubs ptrtbls staticsymbs
    LinkageTable = linkage }

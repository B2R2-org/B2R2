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

module internal B2R2.FrontEnd.BinFile.ELF.Helper

open System
open System.Collections.Generic
open B2R2
open B2R2.Collections
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

let toFileType = function
  | ELFFileType.ET_EXEC -> FileType.ExecutableFile
  | ELFFileType.ET_DYN -> FileType.LibFile
  | ELFFileType.ET_CORE -> FileType.CoreFile
  | ELFFileType.ET_REL -> FileType.ObjFile
  | _ -> FileType.UnknownFile

let isNXEnabled progHeaders =
  let predicate e = e.PHType = ProgramHeaderType.PT_GNU_STACK
  match Array.tryFind predicate progHeaders with
  | Some s -> s.PHFlags.HasFlag Permission.Executable |> not
  | _ -> false

let isRelocatable toolBox secHeaders =
  let pred (e: DynamicSectionEntry) = e.DTag = DynamicTag.DT_DEBUG
  toolBox.Header.ELFFileType = ELFFileType.ET_DYN
  && DynamicSection.readEntries toolBox secHeaders |> Array.exists pred

let inline private computeSubstitute offsetToAddr delta (ptr: Addr) =
  if offsetToAddr then ptr + delta
  else (* Addr to offset *) ptr - delta

let translateWithSecs offsetToAddr ptr sections =
  let txtOffset =
    match Array.tryFind (fun s -> s.SecName = Section.SecText) sections with
    | Some text -> text.SecOffset
    | None -> 0UL
  sections
  |> Array.tryFind (fun s ->
    let secBase =
      if offsetToAddr then s.SecOffset
      else s.SecOffset - txtOffset + s.SecAddr
    s.SecType = SectionType.SHT_PROGBITS
    && s.SecFlags.HasFlag SectionFlag.SHF_EXECINSTR
    && secBase <= ptr && (secBase + s.SecSize) > ptr)
  |> function
    | None -> raise InvalidAddrReadException
    | Some s -> computeSubstitute offsetToAddr (s.SecAddr - txtOffset) ptr

let translateWithSegs offsetToAddr ptr segments =
  segments
  |> Array.tryFind (fun seg ->
    let segBase, segSize =
      if offsetToAddr then seg.PHOffset, seg.PHFileSize
      else seg.PHAddr, seg.PHMemSize
    ptr >= segBase && ptr < segBase + segSize)
  |> function
    | Some seg -> computeSubstitute offsetToAddr (seg.PHAddr - seg.PHOffset) ptr
    | None -> raise InvalidAddrReadException

let translate loadableSegments sections offsetToAddr ptr =
  if Array.isEmpty loadableSegments then
    translateWithSecs offsetToAddr ptr sections
  else translateWithSegs offsetToAddr ptr loadableSegments

let translateAddrToOffset loadableSegs sections addr =
  translate loadableSegs sections false addr

let translateOffsetToAddr loadableSegs sections offset =
  translate loadableSegs sections true offset

let isFuncSymb s =
  s.SymType = SymbolType.STT_FUNC || s.SymType = SymbolType.STT_GNU_IFUNC

let inline tryFindFuncSymb symbolInfo addr =
  match symbolInfo.AddrToSymbTable.TryGetValue addr with
  | true, s ->
    if isFuncSymb s then Ok s.SymName
    else Error ErrorCase.SymbolNotFound
  | false, _ -> Error ErrorCase.SymbolNotFound

let getStaticSymbols shdrs symbols =
  Symbol.getStaticSymArray shdrs symbols.SecNumToSymbTbls
  |> Array.map (Symbol.toB2R2Symbol SymbolVisibility.StaticSymbol)

let getDynamicSymbols excludeImported shdrs symbols =
  let excludeImported = defaultArg excludeImported false
  let alwaysTrue = fun _ -> true
  let filter =
    if excludeImported then (fun s -> s.SecHeaderIndex <> SHN_UNDEF)
    else alwaysTrue
  Symbol.getDynamicSymArray shdrs symbols.SecNumToSymbTbls
  |> Array.filter filter
  |> Array.map (Symbol.toB2R2Symbol SymbolVisibility.DynamicSymbol)

let getSymbols shdrs symbols =
  let s = getStaticSymbols shdrs symbols
  let d = getDynamicSymbols None shdrs symbols
  Array.append s d

let getRelocSymbols relocInfo =
  let translate reloc =
    reloc.RelSymbol
    |> Option.bind (fun s ->
         { s with Addr = reloc.RelOffset }
         |> Symbol.toB2R2Symbol SymbolVisibility.DynamicSymbol
         |> Some)
  relocInfo.RelocByName.Values
  |> Seq.choose translate
  |> Seq.toArray

let secFlagToSectionKind sec =
  if sec.SecFlags &&& SectionFlag.SHF_EXECINSTR = SectionFlag.SHF_EXECINSTR then
    if PLT.isPLTSectionName sec.SecName then SectionKind.LinkageTableSection
    else SectionKind.CodeSection
  elif sec.SecFlags &&& SectionFlag.SHF_WRITE = SectionFlag.SHF_WRITE then
    if sec.SecName = Section.SecBSS then SectionKind.UninitializedDataSection
    else SectionKind.InitializedDataSection
  elif sec.SecName = Section.SecROData then SectionKind.ReadOnlyDataSection
  else
    SectionKind.ExtraSection

let elfSectionToSection sec =
  { Address = sec.SecAddr
    FileOffset = uint32 sec.SecOffset
    Kind = secFlagToSectionKind sec
    Size = uint32 sec.SecSize
    Name = sec.SecName }

let getSections shdrs =
  shdrs
  |> Array.map elfSectionToSection

let getSectionsByAddr shdrs addr =
  shdrs
  |> Array.filter (fun section ->
    section.SecAddr <= addr && addr < section.SecAddr + section.SecSize)
  |> Array.map elfSectionToSection

let getSectionsByName shdrs name =
  shdrs
  |> Array.filter (fun section -> section.SecName = name)
  |> Array.map elfSectionToSection

let getTextSection shdrs =
  shdrs
  |> Array.filter (fun sec ->
    (SectionFlag.SHF_EXECINSTR &&& sec.SecFlags = SectionFlag.SHF_EXECINSTR)
    && sec.SecName.StartsWith Section.SecText)
  |> Array.tryExactlyOne
  |> function
    | Some sec -> elfSectionToSection sec
    | None -> raise SectionNotFoundException

let getSegments segments =
  segments
  |> Array.map ProgramHeader.toSegment

let getRelocatedAddr relocInfo relocAddr =
  match relocInfo.RelocByAddr.TryGetValue relocAddr with
  | true, rel ->
    match rel.RelType with
    | RelocationX86 RelocationX86.R_386_32
    | RelocationX64 RelocationX64.R_X86_64_64 ->
      match rel.RelSymbol with
      | Some sym -> sym.Addr + rel.RelAddend |> Ok
      | _ -> Error ErrorCase.ItemNotFound
    | RelocationX86 RelocationX86.R_386_JUMP_SLOT
    | RelocationX64 RelocationX64.R_X86_64_JUMP_SLOT ->
      match rel.RelSymbol with
      | Some sym -> sym.Addr |> Ok
      | _ -> Error ErrorCase.ItemNotFound
    | RelocationX86 RelocationX86.R_386_IRELATIVE
    | RelocationX64 RelocationX64.R_X86_64_IRELATIVE ->
      Ok rel.RelAddend
    | _ -> Error ErrorCase.ItemNotFound
  | _ -> Error ErrorCase.ItemNotFound

let getFuncAddrsFromLibcArr span toolBox loadables shdrs relocInfo section =
  let readType = toolBox.Header.Class
  let entrySize = WordSize.toByteWidth readType
  let secSize = int section.SecSize
  let lst = List<Addr> ()
  let addr = translateOffsetToAddr loadables shdrs section.SecOffset
  for ofs in [| 0 .. entrySize .. secSize - entrySize |] do
    readUIntByWordSize span toolBox.Reader readType ofs
    |> (fun fnAddr ->
      if fnAddr = 0UL then
        match getRelocatedAddr relocInfo (addr + uint64 ofs) with
        | Ok relocatedAddr -> lst.Add relocatedAddr
        | Error _ -> ()
      else lst.Add fnAddr)
  lst |> seq

let getAddrsFromInitArray toolBox shdrs loadables relocInfo =
  match Array.tryFind (fun s -> s.SecName = ".init_array") shdrs with
  | Some s ->
    let span = ReadOnlySpan (toolBox.Bytes, int s.SecOffset, int s.SecSize)
    getFuncAddrsFromLibcArr span toolBox loadables shdrs relocInfo s
  | None -> Seq.empty

let getAddrsFromFiniArray toolBox shdrs loadables relocInfo =
  match Array.tryFind (fun s -> s.SecName = ".fini_array") shdrs with
  | Some s ->
    let span = ReadOnlySpan (toolBox.Bytes, int s.SecOffset, int s.SecSize)
    getFuncAddrsFromLibcArr span toolBox loadables shdrs relocInfo s
  | None -> Seq.empty

let getAddrsFromSpecialSections shdrs =
  [ ".init"; ".fini" ]
  |> Seq.choose (fun secName ->
    match Array.tryFind (fun s -> s.SecName = secName) shdrs with
    | Some sec -> Some sec.SecAddr
    | None -> None)

let addExtraFunctionAddrs toolBox shdrs loadables relocInfo exnInfoOpt addrs =
  let addrSet =
    [ addrs
      getAddrsFromInitArray toolBox shdrs loadables relocInfo
      getAddrsFromFiniArray toolBox shdrs loadables relocInfo
      getAddrsFromSpecialSections shdrs ]
    |> Seq.concat
    |> Set.ofSeq
  match exnInfoOpt with
  | Some exnInfo ->
    exnInfo.ExceptionFrames
    |> List.fold (fun set cfi ->
      cfi.FDERecord
      |> Array.fold (fun set fde -> Set.add fde.PCBegin set) set
    ) addrSet
    |> Set.toArray
  | None -> addrSet |> Set.toArray

let private computeInvalidRanges wordSize phdrs getNextStartAddr =
  phdrs
  |> Array.sortBy (fun seg -> seg.PHAddr)
  |> Array.fold (fun (set, saddr) seg ->
       let n = getNextStartAddr seg
       addInvalidRange set saddr seg.PHAddr, n) (IntervalSet.empty, 0UL)
  |> addLastInvalidRange wordSize

let invalidRangesByVM hdr phdrs =
  computeInvalidRanges hdr.Class phdrs (fun s -> s.PHAddr + s.PHMemSize)

let invalidRangesByFileBounds hdr phdrs =
  computeInvalidRanges hdr.Class phdrs (fun s -> s.PHAddr + s.PHFileSize)

let private computeExecutableRangesFromSections shdrs =
  let txtOffset =
    match Array.tryFind (fun s -> s.SecName = Section.SecText) shdrs with
    | Some text -> text.SecOffset
    | None -> 0UL
  shdrs
  |> Array.fold (fun set sec ->
    if sec.SecType = SectionType.SHT_PROGBITS
      && sec.SecFlags.HasFlag SectionFlag.SHF_EXECINSTR
    then
      let offset = sec.SecOffset - txtOffset
      let addr = sec.SecAddr + offset
      let range = AddrRange (addr, addr + sec.SecSize - 1UL)
      IntervalSet.add range set
    else set
  ) IntervalSet.empty

let private addIntervalWithoutSection secS secE s e set =
  let set =
    if s < secS && secS < e then IntervalSet.add (AddrRange (s, secS - 1UL)) set
    else set
  let set =
    if secE < e then IntervalSet.add (AddrRange (secE + 1UL, e)) set
    else set
  set

let private addIntervalWithoutROSection rodata seg set =
  let roS = rodata.SecAddr
  let roE = roS + rodata.SecSize - 1UL
  let segS = seg.PHAddr
  let segE = segS + seg.PHMemSize - 1UL
  if roE < segS || segE < roS then
    IntervalSet.add (AddrRange (segS, segE)) set
  else addIntervalWithoutSection roS roE segS segE set

let private addExecutableInterval excludingSection s set =
  match excludingSection with
  | Some sec -> addIntervalWithoutROSection sec s set
  | None ->
    IntervalSet.add (AddrRange (s.PHAddr, s.PHAddr + s.PHMemSize - 1UL)) set

let executableRanges shdrs loadables =
  (* Exclude .rodata even though it is included within an executable segment. *)
  let rodata =
    match Array.tryFind (fun s -> s.SecName = Section.SecROData) shdrs with
    | Some rodata when rodata.SecAddr <> 0UL -> Some rodata
    | _ -> None
  if Array.isEmpty loadables then computeExecutableRangesFromSections shdrs
  else
    loadables
    |> Array.filter (fun seg ->
      seg.PHFlags &&& Permission.Executable = Permission.Executable)
    |> Array.fold (fun set seg ->
      addExecutableInterval rodata seg set) IntervalSet.empty

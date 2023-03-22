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
open B2R2.FrontEnd.BinFile

let convFileType = function
  | ELFFileType.Executable -> FileType.ExecutableFile
  | ELFFileType.SharedObject -> FileType.LibFile
  | ELFFileType.Core -> FileType.CoreFile
  | ELFFileType.Relocatable -> FileType.ObjFile
  | _ -> FileType.UnknownFile

let isNXEnabled elf =
  let predicate e = e.PHType = ProgramHeaderType.PTGNUStack
  match List.tryFind predicate elf.ProgHeaders with
  | Some s -> s.PHFlags.HasFlag Permission.Executable |> not
  | _ -> false

let isRelocatable span elf =
  let pred (e: DynamicSectionEntry) = e.DTag = DynamicTag.DT_DEBUG
  elf.ELFHdr.ELFFileType = ELFFileType.SharedObject
  && Section.getDynamicSectionEntries span elf.BinReader elf.SecInfo
     |> List.exists pred

let inline getTextStartAddr elf =
  (Map.find Section.SecText elf.SecInfo.SecByName).SecAddr

let inline private computeSubstitute offsetToAddr delta (ptr: Addr) =
  if offsetToAddr then ptr + delta
  else (* Addr to offset *) ptr - delta

let translateWithSecs offsetToAddr ptr secInfo =
  let secs = secInfo.SecByNum
  let txtOffset =
    match Map.tryFind Section.SecText secInfo.SecByName with
    | Some text -> text.SecOffset
    | None -> 0UL
  secs
  |> Array.tryFind (fun s ->
    let secBase =
      if offsetToAddr then s.SecOffset
      else s.SecOffset - txtOffset + s.SecAddr
    s.SecType = SectionType.SHTProgBits
    && s.SecFlags.HasFlag SectionFlag.SHFExecInstr
    && secBase <= ptr && (secBase + s.SecSize) > ptr)
  |> function
    | None -> raise InvalidAddrReadException
    | Some s -> computeSubstitute offsetToAddr (s.SecAddr - txtOffset) ptr

let rec translateWithSegs offsetToAddr ptr = function
  | seg :: tl ->
    let segBase, segSize =
      if offsetToAddr then seg.PHOffset, seg.PHFileSize
      else seg.PHAddr, seg.PHMemSize
    if ptr >= segBase && ptr < segBase + segSize then
      computeSubstitute offsetToAddr (seg.PHAddr - seg.PHOffset) ptr
    else translateWithSegs offsetToAddr ptr tl
  | [] -> raise InvalidAddrReadException

let translate offsetToAddr ptr elf =
  match elf.LoadableSegments with
  | [] -> translateWithSecs offsetToAddr ptr elf.SecInfo
  | segs -> translateWithSegs offsetToAddr ptr segs

let translateAddrToOffset addr elf =
  translate false addr elf

let translateOffsetToAddr offset elf =
  translate true offset elf

let isFuncSymb s =
  s.SymType = SymbolType.STTFunc || s.SymType = SymbolType.STTGNUIFunc

let inline tryFindFuncSymb elf addr =
  match elf.SymInfo.AddrToSymbTable.TryGetValue addr with
  | true, s ->
    if isFuncSymb s then Ok s.SymName
    else Error ErrorCase.SymbolNotFound
  | false, _ -> Error ErrorCase.SymbolNotFound

let getStaticSymbols elf =
  Symbol.getStaticSymArray elf
  |> Array.map (Symbol.toB2R2Symbol SymbolVisibility.StaticSymbol)
  |> Array.toSeq

let getDynamicSymbols excludeImported elf =
  let excludeImported = defaultArg excludeImported false
  let alwaysTrue = fun _ -> true
  let filter =
    if excludeImported then (fun s -> s.SecHeaderIndex <> SHNUndef)
    else alwaysTrue
  Symbol.getDynamicSymArray elf
  |> Array.filter filter
  |> Array.map (Symbol.toB2R2Symbol SymbolVisibility.DynamicSymbol)
  |> Array.toSeq

let getSymbols elf =
  let s = getStaticSymbols elf
  let d = getDynamicSymbols None elf
  Seq.append s d

let getRelocSymbols elf =
  let translate reloc =
    reloc.RelSymbol
    |> Option.bind (fun s ->
         { s with Addr = reloc.RelOffset }
         |> Symbol.toB2R2Symbol SymbolVisibility.DynamicSymbol
         |> Some)
  elf.RelocInfo.RelocByName.Values
  |> Seq.choose translate

let secFlagToSectionKind sec =
  if sec.SecFlags &&& SectionFlag.SHFExecInstr = SectionFlag.SHFExecInstr then
    if PLT.isPLTSectionName sec.SecName then SectionKind.LinkageTableSection
    else SectionKind.ExecutableSection
  elif sec.SecFlags &&& SectionFlag.SHFWrite = SectionFlag.SHFWrite then
    SectionKind.WritableSection
  else
    SectionKind.ExtraSection

let elfSectionToSection sec =
  { Address = sec.SecAddr
    FileOffset = sec.SecOffset
    Kind = secFlagToSectionKind sec
    Size = sec.SecSize
    Name = sec.SecName }

let getSections elf =
  elf.SecInfo.SecByNum
  |> Array.map elfSectionToSection
  |> Array.toSeq

let getSectionsByAddr elf addr =
  match ARMap.tryFindByAddr addr elf.SecInfo.SecByAddr with
  | Some s -> elfSectionToSection s |> Seq.singleton
  | None -> Seq.empty

let getSectionsByName elf name =
  match Map.tryFind name elf.SecInfo.SecByName with
  | Some s -> elfSectionToSection s |> Seq.singleton
  | None -> Seq.empty

let getTextSections elf =
  elf.SecInfo.SecByNum
  |> Array.filter (fun sec ->
    (SectionFlag.SHFExecInstr &&& sec.SecFlags = SectionFlag.SHFExecInstr)
    && sec.SecName.StartsWith Section.SecText)
  |> Array.map elfSectionToSection
  |> Array.toSeq

let getSegments elf isLoadable =
  if isLoadable then elf.LoadableSegments else elf.ProgHeaders
  |> List.map ProgHeader.toSegment
  |> List.toSeq

let getPLT elf =
  elf.PLT
  |> ARMap.fold (fun acc _ entry -> entry :: acc) []
  |> List.sortBy (fun entry -> entry.TrampolineAddress)
  |> List.toSeq

let isInPLT elf addr =
  ARMap.containsAddr addr elf.PLT

let inline isValidAddr elf addr =
  IntervalSet.containsAddr addr elf.InvalidAddrRanges |> not

let inline isValidRange elf range =
  IntervalSet.findAll range elf.InvalidAddrRanges |> List.isEmpty

let inline isInFileAddr elf addr =
  IntervalSet.containsAddr addr elf.NotInFileRanges |> not

let inline isInFileRange elf range =
  IntervalSet.findAll range elf.NotInFileRanges |> List.isEmpty

let inline isExecutableAddr elf addr =
  IntervalSet.containsAddr addr elf.ExecutableRanges

let getNotInFileIntervals elf range =
  IntervalSet.findAll range elf.NotInFileRanges
  |> List.map (FileHelper.trimByRange range)
  |> List.toSeq

let getRelocatedAddr elf relocAddr =
  match elf.RelocInfo.RelocByAddr.TryGetValue relocAddr with
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

let getFunctionAddrsFromLibcArray span elf s =
  let offset = int s.SecOffset
  let readType = elf.ELFHdr.Class
  let entrySize = WordSize.toByteWidth readType
  let size = int s.SecSize
  let lst = List<Addr> ()
  let addr = translateOffsetToAddr s.SecOffset elf
  for o in [| offset .. entrySize .. offset + size - entrySize |] do
    FileHelper.peekUIntOfType span elf.BinReader readType o
    |> (fun fnAddr ->
      if fnAddr = 0UL then
        match getRelocatedAddr elf (addr + uint64 (o - offset)) with
        | Ok relocatedAddr -> lst.Add relocatedAddr
        | Error _ -> ()
      else lst.Add fnAddr)
  lst |> seq

let getAddrsFromInitArray span elf =
  match Map.tryFind ".init_array" elf.SecInfo.SecByName with
  | Some s -> getFunctionAddrsFromLibcArray span elf s
  | None -> Seq.empty

let getAddrsFromFiniArray span elf =
  match Map.tryFind ".fini_array" elf.SecInfo.SecByName with
  | Some s -> getFunctionAddrsFromLibcArray span elf s
  | None -> Seq.empty

let getAddrsFromSpecialSections elf =
  [ ".init"; ".fini" ]
  |> Seq.choose (fun secName ->
    match Map.tryFind secName elf.SecInfo.SecByName with
    | Some sec -> Some sec.SecAddr
    | None -> None)

let addExtraFunctionAddrs span elf useExceptionInfo addrs =
  let addrSet =
    [ addrs
      getAddrsFromInitArray span elf
      getAddrsFromFiniArray span elf
      getAddrsFromSpecialSections elf ]
    |> Seq.concat
    |> Set.ofSeq
  if useExceptionInfo then (* XXX *)
    elf.ExceptionFrames
    |> List.fold (fun set cfi ->
      cfi.FDERecord
      |> Array.fold (fun set fde -> Set.add fde.PCBegin set) set
    ) addrSet
    |> Set.toSeq
  else addrSet |> Set.toSeq

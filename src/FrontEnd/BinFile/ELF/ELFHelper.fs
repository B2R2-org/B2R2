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
open System.IO
open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinFile

let toFileType = function
  | ELFFileType.Executable -> FileType.ExecutableFile
  | ELFFileType.SharedObject -> FileType.LibFile
  | ELFFileType.Core -> FileType.CoreFile
  | ELFFileType.Relocatable -> FileType.ObjFile
  | _ -> FileType.UnknownFile

let isNXEnabled progHeaders =
  let predicate e = e.PHType = ProgramHeaderType.PTGNUStack
  match Array.tryFind predicate progHeaders with
  | Some s -> s.PHFlags.HasFlag Permission.Executable |> not
  | _ -> false

let isRelocatable hdr stream reader secHeaders =
  let pred (e: DynamicSectionEntry) = e.DTag = DynamicTag.DT_DEBUG
  hdr.ELFFileType = ELFFileType.SharedObject
  && Section.getDynamicSectionEntries hdr stream reader secHeaders
     |> Array.exists pred

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
    s.SecType = SectionType.SHTProgBits
    && s.SecFlags.HasFlag SectionFlag.SHFExecInstr
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
  s.SymType = SymbolType.STTFunc || s.SymType = SymbolType.STTGNUIFunc

let inline tryFindFuncSymb symbolInfo addr =
  match symbolInfo.AddrToSymbTable.TryGetValue addr with
  | true, s ->
    if isFuncSymb s then Ok s.SymName
    else Error ErrorCase.SymbolNotFound
  | false, _ -> Error ErrorCase.SymbolNotFound

let getStaticSymbols shdrs symbols =
  Symbol.getStaticSymArray shdrs symbols.SecNumToSymbTbls
  |> Array.map (Symbol.toB2R2Symbol SymbolVisibility.StaticSymbol)
  |> Array.toSeq

let getDynamicSymbols excludeImported shdrs symbols =
  let excludeImported = defaultArg excludeImported false
  let alwaysTrue = fun _ -> true
  let filter =
    if excludeImported then (fun s -> s.SecHeaderIndex <> SHNUndef)
    else alwaysTrue
  Symbol.getDynamicSymArray shdrs symbols.SecNumToSymbTbls
  |> Array.filter filter
  |> Array.map (Symbol.toB2R2Symbol SymbolVisibility.DynamicSymbol)
  |> Array.toSeq

let getSymbols shdrs symbols =
  let s = getStaticSymbols shdrs symbols
  let d = getDynamicSymbols None shdrs symbols
  Seq.append s d

let getRelocSymbols relocInfo =
  let translate reloc =
    reloc.RelSymbol
    |> Option.bind (fun s ->
         { s with Addr = reloc.RelOffset }
         |> Symbol.toB2R2Symbol SymbolVisibility.DynamicSymbol
         |> Some)
  relocInfo.RelocByName.Values
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
    FileOffset = uint32 sec.SecOffset
    Kind = secFlagToSectionKind sec
    Size = uint32 sec.SecSize
    Name = sec.SecName }

let getSections shdrs =
  shdrs
  |> Array.map elfSectionToSection
  |> Array.toSeq

let getSectionsByAddr shdrs addr =
  shdrs
  |> Array.tryFind (fun section ->
    section.SecAddr <= addr && addr < section.SecAddr + section.SecSize)
  |> function
    | Some section -> elfSectionToSection section |> Seq.singleton
    | None -> Seq.empty

let getSectionsByName shdrs name =
  shdrs
  |> Array.tryFind (fun section -> section.SecName = name)
  |> function
    | Some section -> elfSectionToSection section |> Seq.singleton
    | None -> Seq.empty

let getTextSection shdrs =
  shdrs
  |> Array.filter (fun sec ->
    (SectionFlag.SHFExecInstr &&& sec.SecFlags = SectionFlag.SHFExecInstr)
    && sec.SecName.StartsWith Section.SecText)
  |> Array.tryExactlyOne
  |> function
    | Some sec -> elfSectionToSection sec
    | None -> raise SectionNotFoundException

let getSegments segments =
  segments
  |> Array.map ProgHeader.toSegment
  |> Array.toSeq

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

let getFuncAddrsFromLibcArr span reader hdr loadables shdrs relocInfo section =
  let readType = hdr.Class
  let entrySize = WordSize.toByteWidth readType
  let secSize = int section.SecSize
  let lst = List<Addr> ()
  let addr = translateOffsetToAddr loadables shdrs section.SecOffset
  for ofs in [| 0 .. entrySize .. secSize - entrySize |] do
    FileHelper.peekUIntOfType span reader readType ofs
    |> (fun fnAddr ->
      if fnAddr = 0UL then
        match getRelocatedAddr relocInfo (addr + uint64 ofs) with
        | Ok relocatedAddr -> lst.Add relocatedAddr
        | Error _ -> ()
      else lst.Add fnAddr)
  lst |> seq

let private readSection (stream: Stream) sec =
  let buf = Array.zeroCreate (int sec.SecSize)
  stream.Seek (int64 sec.SecOffset, SeekOrigin.Begin) |> ignore
  FileHelper.readOrDie stream buf
  buf

let getAddrsFromInitArray stream reader hdr shdrs loadables relocInfo =
  match Array.tryFind (fun s -> s.SecName = ".init_array") shdrs with
  | Some s ->
    let span = ReadOnlySpan (readSection stream s)
    getFuncAddrsFromLibcArr span reader hdr loadables shdrs relocInfo s
  | None -> Seq.empty

let getAddrsFromFiniArray stream reader hdr shdrs loadables relocInfo =
  match Array.tryFind (fun s -> s.SecName = ".fini_array") shdrs with
  | Some s ->
    let span = ReadOnlySpan (readSection stream s)
    getFuncAddrsFromLibcArr span reader hdr loadables shdrs relocInfo s
  | None -> Seq.empty

let getAddrsFromSpecialSections shdrs =
  [ ".init"; ".fini" ]
  |> Seq.choose (fun secName ->
    match Array.tryFind (fun s -> s.SecName = secName) shdrs with
    | Some sec -> Some sec.SecAddr
    | None -> None)

let addExtraFunctionAddrs
  stream reader hdr shdrs loadables relocInfo exnInfoOpt addrs =
  let addrSet =
    [ addrs
      getAddrsFromInitArray stream reader hdr shdrs loadables relocInfo
      getAddrsFromFiniArray stream reader hdr shdrs loadables relocInfo
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
    |> Set.toSeq
  | None -> addrSet |> Set.toSeq

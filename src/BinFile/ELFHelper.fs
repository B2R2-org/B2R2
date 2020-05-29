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

module internal B2R2.BinFile.ELF.Helper

open System
open B2R2
open B2R2.BinFile

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

let isRelocatable elf =
  let pred (e: DynamicSectionEntry) = e.DTag = DynamicSectionTag.DTDebug
  elf.ELFHdr.ELFFileType = ELFFileType.SharedObject
  && Section.getDynamicSectionEntries elf.BinReader elf.SecInfo
     |> List.exists pred

let inline getTextStartAddr elf =
  (Map.find ".text" elf.SecInfo.SecByName).SecAddr

let inline private inMem seg addr =
  let vAddr = seg.PHAddr
  addr >= vAddr && addr < vAddr + seg.PHMemSize

let translateWithSecs addr (secs: ELFSection []) =
  secs
  |> Array.tryFindIndex (fun s ->
    s.SecType = SectionType.SHTProgBits
    && s.SecAddr <= addr && (s.SecAddr + s.SecSize) > addr)
  |> function
    | None -> raise InvalidAddrReadException
    | Some idx -> secs.[idx].SecOffset + addr |> Convert.ToInt32

let rec translateWithSegs addr = function
  | seg :: tl ->
    if inMem seg addr then Convert.ToInt32 (addr - seg.PHAddr + seg.PHOffset)
    else translateWithSegs addr tl
  | [] -> raise InvalidAddrReadException

let translateAddr addr elf =
  match elf.LoadableSegments with
  | [] -> translateWithSecs addr elf.SecInfo.SecByNum
  | segs -> translateWithSegs addr segs

let isFuncSymb s =
  s.SymType = SymbolType.STTFunc || s.SymType = SymbolType.STTGNUIFunc

let inline tryFindFuncSymb elf addr (name: byref<string>) =
  match Map.tryFind addr elf.SymInfo.AddrToSymbTable with
  | None -> false
  | Some s ->
    if isFuncSymb s then name <- s.SymName; true
    else false

let getStaticSymbols elf =
  Symbol.getStaticSymArray elf
  |> Array.map (Symbol.toB2R2Symbol TargetKind.StaticSymbol)
  |> Array.toSeq

let getDynamicSymbols excludeImported elf =
  let excludeImported = defaultArg excludeImported false
  let alwaysTrue = fun _ -> true
  let filter =
    if excludeImported then (fun s -> s.SecHeaderIndex <> SHNUndef)
    else alwaysTrue
  Symbol.getDynamicSymArray elf
  |> Array.filter filter
  |> Array.map (Symbol.toB2R2Symbol TargetKind.DynamicSymbol)
  |> Array.toSeq

let getSymbols elf =
  let s = getStaticSymbols elf
  let d = getDynamicSymbols None elf
  Seq.append s d

let getRelocSymbols elf =
  let translate (_, reloc) =
    reloc.RelSymbol
    |> Option.bind (fun s ->
         { s with Addr = reloc.RelOffset }
         |> Symbol.toB2R2Symbol TargetKind.DynamicSymbol
         |> Some)
  elf.RelocInfo.RelocByName
  |> Map.toSeq
  |> Seq.choose translate

let secFlagToSectionKind flag entrySize =
  if flag &&& SectionFlag.SHFExecInstr = SectionFlag.SHFExecInstr then
    if entrySize > 0UL then SectionKind.LinkageTableSection
    else SectionKind.ExecutableSection
  elif flag &&& SectionFlag.SHFWrite = SectionFlag.SHFWrite then
    SectionKind.WritableSection
  else
    SectionKind.ExtraSection

let elfSectionToSection sec =
  { Address = sec.SecAddr
    Kind = secFlagToSectionKind sec.SecFlags sec.SecEntrySize
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

let getSegments elf isLoadable =
  if isLoadable then elf.LoadableSegments else elf.ProgHeaders
  |> List.map ProgHeader.toSegment
  |> List.toSeq

let getPLT elf =
  let create pltAddr (symb: ELFSymbol) =
    { FuncName = symb.SymName
      LibraryName = Symbol.versionToLibName symb.VerInfo
      TrampolineAddress = pltAddr
      TableAddress = symb.Addr }
  elf.PLT
  |> ARMap.fold (fun acc addrRange s -> create addrRange.Min s :: acc) []
  |> List.sortBy (fun entry -> entry.TrampolineAddress)
  |> List.toSeq

let isPLT elf addr =
  ARMap.containsAddr addr elf.PLT

let inline isValidAddr elf addr =
  IntervalSet.containsAddr addr elf.InvalidAddrRanges |> not

let inline isValidRange elf range =
  IntervalSet.findAll range elf.InvalidAddrRanges |> List.isEmpty

let inline isInFileAddr elf addr =
  IntervalSet.containsAddr addr elf.NotInFileRanges |> not

let inline isInFileRange elf range =
  IntervalSet.findAll range elf.NotInFileRanges |> List.isEmpty

let getNotInFileIntervals elf range =
  IntervalSet.findAll range elf.NotInFileRanges
  |> List.map (FileHelper.trimByRange range)
  |> List.toSeq

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

module internal B2R2.BinFile.Mach.Helper

open System
open B2R2
open B2R2.BinFile

let getISA mach =
  let cputype = mach.MachHdr.CPUType
  let cpusubtype = mach.MachHdr.CPUSubType
  let arch = Header.cpuTypeToArch cputype cpusubtype
  let endian = Header.magicToEndian mach.MachHdr.Magic
  ISA.Init arch endian

let convFileType = function
  | MachFileType.MHExecute -> FileType.ExecutableFile
  | MachFileType.MHObject -> FileType.ObjFile
  | MachFileType.MHDylib
  | MachFileType.MHFvmlib -> FileType.LibFile
  | MachFileType.MHCore -> FileType.CoreFile
  | _ -> FileType.UnknownFile

let machTypeToSymbKind sym secText =
  if (sym.SymType = SymbolType.NFun && sym.SymName.Length > 0)
    || (sym.SymType.HasFlag SymbolType.NSect
      && sym.SecNum = (secText + 1)
      && sym.SymDesc = 0s) then
    SymbolKind.FunctionType
  elif sym.SymType = SymbolType.NSO
    || sym.SymType = SymbolType.NOSO then
    SymbolKind.FileType
  else
    SymbolKind.NoType

let machSymbolToSymbol secText target sym =
  { Address = sym.SymAddr
    Name = sym.SymName
    Kind = machTypeToSymbKind sym secText
    Target = target
    LibraryName = Symbol.getSymbolLibName sym }

let getStaticSymbols mach =
  mach.SymInfo.Symbols
  |> Array.filter Symbol.isStatic
  |> Array.map (machSymbolToSymbol mach.SecText TargetKind.StaticSymbol)

let isStripped mach =
  getStaticSymbols mach
  |> Array.exists (fun s -> s.Kind = SymbolKind.FunctionType)
  |> not

let isNXEnabled mach =
  not (mach.MachHdr.Flags.HasFlag MachFlag.MHAllowStackExecution)
  || mach.MachHdr.Flags.HasFlag MachFlag.MHNoHeapExecution

let inline getTextStartAddr mach =
  (Map.find "__text" mach.Sections.SecByName).SecAddr

let inline translateAddr mach addr =
  match ARMap.tryFindByAddr addr mach.SegmentMap with
  | Some s -> Convert.ToInt32 (addr - s.VMAddr + s.FileOff)
  | None -> raise InvalidAddrReadException

let getDynamicSymbols excludeImported mach =
  let excludeImported = defaultArg excludeImported false
  let filter = Array.filter (fun (s: MachSymbol) -> s.SymAddr > 0UL)
  mach.SymInfo.Symbols
  |> Array.filter Symbol.isDynamic
  |> fun arr -> if excludeImported then filter arr else arr
  |> Array.map (machSymbolToSymbol mach.SecText TargetKind.DynamicSymbol)

let getSymbols mach =
  let s = getStaticSymbols mach
  let d = getDynamicSymbols None mach
  Array.append s d |> Array.toSeq

let secFlagToSectionKind isExecutable = function
  | SectionType.NonLazySymbolPointers
  | SectionType.LazySymbolPointers
  | SectionType.SymbolStubs -> SectionKind.LinkageTableSection
  | _ ->
    if isExecutable then SectionKind.ExecutableSection
    else SectionKind.ExtraSection

let machSectionToSection segMap (sec: MachSection) =
  let seg = ARMap.findByAddr sec.SecAddr segMap
  let perm: Permission = seg.InitProt |> LanguagePrimitives.EnumOfValue
  let isExecutable = perm.HasFlag Permission.Executable
  { Address = sec.SecAddr
    Kind = secFlagToSectionKind isExecutable sec.SecType
    Size = sec.SecSize
    Name = sec.SecName }

let getSections mach =
  mach.Sections.SecByNum
  |> Array.map (machSectionToSection mach.SegmentMap)
  |> Array.toSeq

let getSectionsByAddr mach addr =
  match ARMap.tryFindByAddr addr mach.Sections.SecByAddr with
  | Some s -> Seq.singleton (machSectionToSection mach.SegmentMap s)
  | None -> Seq.empty

let getSectionsByName mach name =
  match Map.tryFind name mach.Sections.SecByName with
  | Some s -> Seq.singleton (machSectionToSection mach.SegmentMap s)
  | None -> Seq.empty

let getTextSections mach =
  mach.Sections.SecByNum.[mach.SecText]
  |> machSectionToSection mach.SegmentMap
  |> Seq.singleton

let getPLT mach =
  mach.SymInfo.LinkageTable
  |> List.sortBy (fun entry -> entry.TrampolineAddress)
  |> List.toSeq

let isPLT mach addr =
  mach.SymInfo.LinkageTable
  |> List.exists (fun entry -> entry.TrampolineAddress = addr)

let inline tryFindFuncSymb mach addr (name: byref<string>) =
  match Map.tryFind addr mach.SymInfo.SymbolMap with
  | Some s -> name <- s.SymName; true
  | None -> false

let inline isValidAddr mach addr =
  IntervalSet.containsAddr addr mach.InvalidAddrRanges |> not

let inline isValidRange mach range =
  IntervalSet.findAll range mach.InvalidAddrRanges |> List.isEmpty

let inline isInFileAddr mach addr =
  IntervalSet.containsAddr addr mach.NotInFileRanges |> not

let inline isInFileRange mach range =
  IntervalSet.findAll range mach.NotInFileRanges |> List.isEmpty

let inline isExecutableAddr mach addr =
  IntervalSet.containsAddr addr mach.ExecutableRanges

let inline getNotInFileIntervals mach range =
  IntervalSet.findAll range mach.NotInFileRanges
  |> List.map (FileHelper.trimByRange range)
  |> List.toSeq

// vim: set tw=80 sts=2 sw=2:

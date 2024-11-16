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

module internal B2R2.FrontEnd.BinFile.Mach.Helper

open System
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

/// Mach-specific virtual memory permission (for maxprot and initprot). Note
/// that these values are different than the B2R2.Permission type.
[<FlagsAttribute>]
type MachVMProt =
  /// File is readable.
  | Readable = 1
  /// File is writable.
  | Writable = 2
  /// File is executable.
  | Executable = 4

let getISA hdr =
  let cputype = hdr.CPUType
  let cpusubtype = hdr.CPUSubType
  let arch = CPUType.toArch cputype cpusubtype
  let endian = Header.magicToEndian hdr.Magic
  ISA.Init arch endian

let convFileType = function
  | MachFileType.MH_EXECUTE -> FileType.ExecutableFile
  | MachFileType.MH_OBJECT -> FileType.ObjFile
  | MachFileType.MH_DYLIB
  | MachFileType.MH_FVMLIB -> FileType.LibFile
  | MachFileType.MH_CORE -> FileType.CoreFile
  | _ -> FileType.UnknownFile

let isMainCmd = function
  | Main _ -> true
  | _ -> false

let getMainOffset cmds =
  match cmds |> Array.tryFind isMainCmd with
  | Some (Main m) -> m.EntryOff
  | _ -> 0UL

let getTextSegOffset segs =
  let isTextSegment s = s.SegCmdName = LoadCommand.TextSegName
  match segs |> Array.tryFind isTextSegment with
  | Some s -> s.VMAddr
  | _ -> raise InvalidFileFormatException

let computeEntryPoint segs cmds =
  let mainOffset = getMainOffset cmds
  if mainOffset = 0UL then None
  else Some (mainOffset + getTextSegOffset segs)

let machTypeToSymbKind sym secText =
  if (sym.SymType = SymbolType.N_FUN && sym.SymName.Length > 0)
    || (sym.SymType.HasFlag SymbolType.N_SECT
      && sym.SecNum = (secText + 1)
      && sym.SymDesc = 0s) then
    SymFunctionType
  elif sym.SymType = SymbolType.N_SO
    || sym.SymType = SymbolType.N_OSO then
    SymFileType
  else
    SymNoType

let machSymbolToSymbol secText vis sym =
  { Address = sym.SymAddr
    Name = sym.SymName
    Kind = machTypeToSymbKind sym secText
    Visibility = vis
    LibraryName = Symbol.getSymbolLibName sym
    ArchOperationMode = ArchOperationMode.NoMode }

let getStaticSymbols secs symInfo =
  let secText = Section.getTextSectionIndex secs
  symInfo.Symbols
  |> Array.filter Symbol.isStatic
  |> Array.map (machSymbolToSymbol secText SymbolVisibility.StaticSymbol)

let isStripped secs symInfo =
  getStaticSymbols secs symInfo
  |> Array.exists (fun s -> s.Kind = SymFunctionType)
  |> not

let isNXEnabled hdr =
  not (hdr.Flags.HasFlag MachFlag.MH_ALLOW_STACK_EXECUTION)
  || hdr.Flags.HasFlag MachFlag.MH_NO_HEAP_EXECUTION

let translateAddr segMap addr =
  match ARMap.tryFindByAddr addr segMap with
  | Some s -> Convert.ToInt32 (addr - s.VMAddr + s.FileOff)
  | None -> raise InvalidAddrReadException

let private computeInvalidRanges toolBox segCmds getNextStartAddr =
  segCmds
  |> Array.filter (fun seg -> seg.SegCmdName <> "__PAGEZERO")
  |> Array.sortBy (fun seg -> seg.VMAddr)
  |> Array.fold (fun (set, saddr) seg ->
       let n = getNextStartAddr seg
       addInvalidRange set saddr seg.VMAddr, n) (IntervalSet.empty, 0UL)
  |> addLastInvalidRange toolBox.Header.Class

let invalidRangesByVM toolBox segCmds =
  computeInvalidRanges toolBox segCmds (fun seg -> seg.VMAddr + seg.VMSize)

let invalidRangesByFileBounds toolBox segCmds =
  computeInvalidRanges toolBox segCmds (fun seg -> seg.VMAddr + seg.FileSize)

let executableRanges segCmds =
  segCmds
  |> Array.filter (fun seg ->
    let perm: Permission = seg.MaxProt |> LanguagePrimitives.EnumOfValue
    perm &&& Permission.Executable = Permission.Executable)
  |> Array.fold (fun set s ->
    IntervalSet.add (AddrRange (s.VMAddr, s.VMAddr + s.VMSize - 1UL)) set
    ) IntervalSet.empty

let secFlagToSectionKind isExecutable = function
  | SectionType.S_NON_LAZY_SYMBOL_POINTERS
  | SectionType.S_LAZY_SYMBOL_POINTERS
  | SectionType.S_SYMBOL_STUBS -> SectionKind.LinkageTableSection
  | _ ->
    if isExecutable then SectionKind.CodeSection
    else SectionKind.ExtraSection

let machSectionToSection segMap (sec: MachSection) =
  let seg = ARMap.findByAddr sec.SecAddr segMap
  let perm: MachVMProt = seg.InitProt |> LanguagePrimitives.EnumOfValue
  let isExecutable = perm.HasFlag MachVMProt.Executable
  { Address = sec.SecAddr
    FileOffset = sec.SecOffset
    Kind = secFlagToSectionKind isExecutable sec.SecType
    Size = uint32 sec.SecSize
    Name = sec.SecName }

let getSections secs segMap =
  secs
  |> Array.map (machSectionToSection segMap)

let getSectionsByAddr secs segMap addr =
  secs
  |> Array.filter (fun s -> addr >= s.SecAddr && addr < s.SecAddr + s.SecSize)
  |> Array.map (machSectionToSection segMap)

let getSectionsByName secs segMap name =
  secs
  |> Array.filter (fun s -> s.SecName = name)
  |> Array.map (machSectionToSection segMap)

let getTextSection (secs: MachSection[]) segMap =
  let secText = Section.getTextSectionIndex secs
  secs[secText]
  |> machSectionToSection segMap

let getPLT symInfo =
  symInfo.LinkageTable
  |> List.sortBy (fun entry -> entry.TrampolineAddress)
  |> List.toArray

let isPLT symInfo addr =
  symInfo.LinkageTable
  |> List.exists (fun entry -> entry.TrampolineAddress = addr)

let tryFindFuncSymb symInfo addr =
  match Map.tryFind addr symInfo.SymbolMap with
  | Some s -> Ok s.SymName
  | None -> Error ErrorCase.SymbolNotFound

let getDynamicSymbols excludeImported secs symInfo =
  let secText = Section.getTextSectionIndex secs
  let excludeImported = defaultArg excludeImported false
  let filter = Array.filter (fun (s: MachSymbol) -> s.SymAddr > 0UL)
  symInfo.Symbols
  |> Array.filter Symbol.isDynamic
  |> fun arr -> if excludeImported then filter arr else arr
  |> Array.map (machSymbolToSymbol secText SymbolVisibility.DynamicSymbol)

let getSymbols secs symInfo =
  let s = getStaticSymbols secs symInfo
  let d = getDynamicSymbols None secs symInfo
  Array.append s d

// vim: set tw=80 sts=2 sw=2:

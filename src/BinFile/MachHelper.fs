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

module internal B2R2.BinFile.Mach.Helper

open B2R2
open B2R2.BinFile

let isMainCmd = function
  | Main _ -> true
  | _ -> false

let getMainOffset cmds =
  match cmds |> List.tryFind isMainCmd with
  | Some (Main m) -> m.EntryOff
  | _ -> 0UL

let getTextOffset segs =
  let isTextSegment (s: SegCmd) = s.SegName = "__TEXT"
  match segs |> List.tryFind isTextSegment with
  | Some s -> s.VMAddr
  | _ -> raise FileFormatMismatchException

let parseMach reader  =
  let machHdr = Header.parse reader 0
  let cmds = LoadCommands.parse reader machHdr
  let segs = Segment.extract cmds
  let segmap = Segment.buildMap segs
  let secs = Section.parseSections reader machHdr.Class segs
  let symInfo = Symbol.parse machHdr cmds secs reader
  { EntryPoint = getTextOffset segs + getMainOffset cmds
    SymInfo = symInfo
    MachHdr = machHdr
    Segments = segs
    SegmentMap = segmap
    Sections = secs
    BinReader = reader }

let updateReaderForFat bytes isa reader =
  if Header.isFat reader 0 then
    let offset, size = Fat.computeOffsetAndSize reader isa
    let bytes = Array.sub bytes offset size
    BinReader.Init (bytes)
  else reader

let initMach bytes isa =
  let reader = BinReader.Init (bytes) |> updateReaderForFat bytes isa
  if Header.isMach reader 0 then ()
  else raise FileFormatMismatchException
  Header.peekEndianness reader 0
  |> BinReader.RenewReader reader
  |> parseMach

let transFileType = function
  | MachFileType.MHExecute -> FileType.ExecutableFile
  | MachFileType.MHObject -> FileType.ObjFile
  | MachFileType.MHDylib | MachFileType.MHFvmlib -> FileType.LibFile
  | MachFileType.MHCore -> FileType.CoreFile
  | _ -> FileType.UnknownFile

let tryFindFunctionSymb mach addr =
  match Map.tryFind addr mach.SymInfo.SymbolMap with
  | Some s -> Some s.SymName
  | None -> None

let machTypeToSymbKind (sym: MachSymbol) =
  if sym.SymType.HasFlag SymbolType.NFun then
    SymbolKind.FunctionType
  elif sym.SymType.HasFlag SymbolType.NSO
    || sym.SymType.HasFlag SymbolType.NOSO then
    SymbolKind.FileType
  else
    SymbolKind.NoType

let machSymbolToSymbol target (sym: MachSymbol) =
  { Address = sym.SymAddr
    Name = sym.SymName
    Kind = machTypeToSymbKind sym
    Target = target
    LibraryName = Symbol.getSymbolLibName sym }

let getAllStaticSymbols mach =
  mach.SymInfo.Symbols
  |> Array.filter Symbol.isStatic
  |> Array.map (fun s -> machSymbolToSymbol TargetKind.StaticSymbol s)

let getAllDynamicSymbols excludeImported mach =
  let filter = Array.filter (fun (s: MachSymbol) -> s.SymAddr > 0UL)
  mach.SymInfo.Symbols
  |> Array.filter Symbol.isDynamic
  |> fun arr -> if excludeImported then filter arr else arr
  |> Array.map (machSymbolToSymbol TargetKind.DynamicSymbol)

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

// vim: set tw=80 sts=2 sw=2:

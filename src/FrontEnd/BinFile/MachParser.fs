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

module internal B2R2.FrontEnd.BinFile.Mach.Parser

open System
open B2R2
open B2R2.FrontEnd.BinFile

let isMainCmd = function
  | Main _ -> true
  | _ -> false

let getMainOffset cmds =
  match cmds |> List.tryFind isMainCmd with
  | Some (Main m) -> m.EntryOff
  | _ -> 0UL

let getTextSegOffset segs =
  let isTextSegment s = s.SegCmdName = "__TEXT"
  match segs |> List.tryFind isTextSegment with
  | Some s -> s.VMAddr
  | _ -> raise FileFormatMismatchException

let computeEntryPoint segs cmds =
  let mainOffset = getMainOffset cmds
  if mainOffset = 0UL then None
  else Some (mainOffset + getTextSegOffset segs)

let invRanges wordSize segs getNextStartAddr =
  segs
  |> List.filter (fun seg -> seg.SegCmdName <> "__PAGEZERO")
  |> List.sortBy (fun seg -> seg.VMAddr)
  |> List.fold (fun (set, saddr) seg ->
       let n = getNextStartAddr seg
       FileHelper.addInvRange set saddr seg.VMAddr, n) (IntervalSet.empty, 0UL)
  |> FileHelper.addLastInvRange wordSize

let execRanges segs =
  segs
  |> List.filter (fun seg ->
    let perm: Permission = seg.MaxProt |> LanguagePrimitives.EnumOfValue
    perm &&& Permission.Executable = Permission.Executable)
  |> List.fold (fun set s ->
    IntervalSet.add (AddrRange (s.VMAddr, s.VMAddr + s.VMSize - 1UL)) set
    ) IntervalSet.empty

let computeBaseAddr machHdr baseAddr =
  if machHdr.Flags.HasFlag MachFlag.MHPIE then defaultArg baseAddr 0UL
  else 0UL

let parseMach baseAddr span reader  =
  let machHdr = Header.parse span reader
  let baseAddr = computeBaseAddr machHdr baseAddr
  let cls = machHdr.Class
  let cmds = LoadCommands.parse baseAddr span reader machHdr
  let segs = Segment.extract cmds
  let segmap = Segment.buildMap segs
  let secs = Section.parseSections baseAddr span reader cls segs
  let secText = Section.getTextSectionIndex secs.SecByNum
  let symInfo = Symbol.parse baseAddr span reader machHdr cmds secs secText
  let relocs =
    Reloc.parseRelocs span reader secs.SecByNum
    |> Array.map (Reloc.toSymbol symInfo.Symbols secs.SecByNum)
  { EntryPoint = computeEntryPoint segs cmds
    BaseAddr = baseAddr
    SymInfo = symInfo
    MachHdr = machHdr
    Segments = segs
    SegmentMap = segmap
    Sections = secs
    SecText = secText
    Relocations = relocs
    Cmds = cmds
    InvalidAddrRanges = invRanges cls segs (fun s -> s.VMAddr + s.VMSize)
    NotInFileRanges = invRanges cls segs (fun s -> s.VMAddr + s.FileSize)
    ExecutableRanges = execRanges segs
    BinReader = reader }

let private computeOffsetAndSize span reader isa =
  let fatArch = Fat.loadFats span reader |> Fat.findMatchingFatRecord isa
  struct (fatArch.Offset, fatArch.Size)

let updateSpanForFat isa span reader =
  if Header.isFat span reader then
    let struct (offset, size) = computeOffsetAndSize span reader isa
    span.Slice (offset, size)
  else span

let parse baseAddr (bytes: byte[]) isa =
  let span = ReadOnlySpan bytes
  let span = updateSpanForFat isa span BinReader.binReaderBE
  if Header.isMach span BinReader.binReaderLE then ()
  else raise FileFormatMismatchException
  match Header.peekEndianness span BinReader.binReaderLE with
  | Endian.Little -> parseMach baseAddr span BinReader.binReaderLE
  | Endian.Big -> parseMach baseAddr span BinReader.binReaderBE
  | _ -> Utils.impossible ()
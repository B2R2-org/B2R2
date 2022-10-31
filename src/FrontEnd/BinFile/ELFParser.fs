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

module internal B2R2.FrontEnd.BinFile.ELF.Parser

open System
open B2R2
open B2R2.FrontEnd.BinFile

let private parseGlobalSymbols reloc =
  let folder map (KeyValue (addr, rel: RelocationEntry)) =
    match rel.RelType with
    | RelocationX86 RelocationX86.R_386_GLOB_DATA
    | RelocationX64 RelocationX64.R_X86_64_GLOB_DATA
    | RelocationARMv7 RelocationARMv7.R_ARM_GLOB_DATA
    | RelocationARMv8 RelocationARMv8.R_AARCH64_GLOB_DATA
    | RelocationMIPS RelocationMIPS.R_MIPS_GLOB_DAT
    | RelocationSH4 RelocationSH4.R_SH_GLOB_DAT ->
      Map.add addr (Option.get rel.RelSymbol) map
    | _ -> map
  reloc.RelocByAddr |> Seq.fold folder Map.empty

let private isRelocatableFile (eHdr: ELFHeader) =
  eHdr.ELFFileType = ELFFileType.Relocatable

let private computeUnwindingTable exns =
  exns
  |> List.fold (fun tbl (f: CallFrameInformation) ->
    f.FDERecord |> Array.fold (fun tbl fde ->
      fde.UnwindingInfo |> List.fold (fun tbl i ->
        Map.add i.Location i tbl) tbl
      ) tbl) Map.empty

let private invRanges wordSize segs getNextStartAddr =
  segs
  |> List.sortBy (fun seg -> seg.PHAddr)
  |> List.fold (fun (set, saddr) seg ->
       let n = getNextStartAddr seg
       FileHelper.addInvRange set saddr seg.PHAddr, n) (IntervalSet.empty, 0UL)
  |> FileHelper.addLastInvRange wordSize

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

let private execRanges secs segs =
  (* Exclude .rodata even though it is included within an executable segment. *)
  let rodata =
    match Map.tryFind Section.SecROData secs.SecByName with
    | Some rodata when rodata.SecAddr <> 0UL -> Some rodata
    | _ -> None
  segs
  |> List.filter (fun seg ->
    seg.PHFlags &&& Permission.Executable = Permission.Executable)
  |> List.fold (fun set seg ->
    addExecutableInterval rodata seg set) IntervalSet.empty

let private parseExn span rdr cls secs isa rbay rel =
  let exns = ExceptionFrames.parse span rdr cls secs isa rbay rel
  let lsdas = ELFGccExceptTable.parse span rdr cls secs
  match exns with
  | [] when isa.Arch = Architecture.ARMv7 ->
    ELFARMExceptionHandler.parse span rdr cls secs isa rbay rel
  | _ ->
    let unwinds = computeUnwindingTable exns
    struct (exns, lsdas, unwinds)

let private parseELFForEmulation eHdr baseAddr rdr proghdrs segs =
  let isa = ISA.Init eHdr.MachineType eHdr.Endian
  { ELFHdr = eHdr
    BaseAddr = baseAddr
    ProgHeaders = proghdrs
    LoadableSegments = segs
    LoadableSecNums = Set.empty
    SecInfo = Unchecked.defaultof<SectionInfo>
    SymInfo = Unchecked.defaultof<ELFSymbolInfo>
    RelocInfo = Unchecked.defaultof<RelocInfo>
    PLT = ARMap.empty
    Globals = Map.empty
    ExceptionFrames = []
    LSDAs = Map.empty
    InvalidAddrRanges = IntervalSet.empty
    NotInFileRanges = IntervalSet.empty
    ExecutableRanges = IntervalSet.empty
    ISA = isa
    UnwindingTbl = Map.empty
    BinReader = rdr }

let private parseELFFull eHdr baseAddr rbay span rdr proghdrs segs =
  let isa = ISA.Init eHdr.MachineType eHdr.Endian
  let cls = eHdr.Class
  let secs = Section.parse baseAddr eHdr span rdr
  let loadableSecNums = ProgHeader.getLoadableSecNums secs segs
  let symbs = Symbol.parse baseAddr eHdr secs span rdr
  let reloc = Relocs.parse baseAddr eHdr secs symbs span rdr
  let plt = PLT.parse eHdr.MachineType secs reloc symbs span rdr
  let globals = parseGlobalSymbols reloc |> Symbol.updateGlobals symbs
  let rel = if isRelocatableFile eHdr then Some reloc else None
  let struct (exns, lsdas, unwinds) = parseExn span rdr cls secs isa rbay rel
  { ELFHdr = eHdr
    BaseAddr = baseAddr
    ProgHeaders = proghdrs
    LoadableSegments = segs
    LoadableSecNums = loadableSecNums
    SecInfo = secs
    SymInfo = symbs
    RelocInfo = reloc
    PLT = plt
    Globals = globals
    ExceptionFrames = exns
    LSDAs = lsdas
    InvalidAddrRanges = invRanges cls segs (fun s -> s.PHAddr + s.PHMemSize)
    NotInFileRanges = invRanges cls segs (fun s -> s.PHAddr + s.PHFileSize)
    ExecutableRanges = execRanges secs segs
    ISA = isa
    UnwindingTbl = unwinds
    BinReader = rdr }

let private parseELF baseAddr rbay span forEmu (rdr: IBinReader) =
  let eHdr, baseAddr = Header.parse span rdr baseAddr
  let proghdrs = ProgHeader.parse baseAddr eHdr span rdr
  let segs = ProgHeader.getLoadableProgHeaders proghdrs
  if forEmu then parseELFForEmulation eHdr baseAddr rdr proghdrs segs
  else parseELFFull eHdr baseAddr rbay span rdr proghdrs segs

let parse (bytes: byte[]) baseAddr rbay forEmu =
  let span = ReadOnlySpan bytes
  if Header.isELF span then ()
  else raise InvalidFileFormatException
  match Header.peekEndianness span with
  | Endian.Little -> parseELF baseAddr rbay span forEmu BinReader.binReaderLE
  | Endian.Big -> parseELF baseAddr rbay span forEmu BinReader.binReaderBE
  | _ -> Utils.impossible ()

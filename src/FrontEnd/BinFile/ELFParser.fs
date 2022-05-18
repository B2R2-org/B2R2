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
    | RelocationX86 RelocationX86.Reloc386GlobData
    | RelocationX64 RelocationX64.RelocX64GlobData ->
      Map.add addr (Option.get rel.RelSymbol) map
    | _ -> map
  reloc.RelocByAddr |> Seq.fold folder Map.empty

let inline private loadCallSiteTable lsdaPointer gccexctbl =
  let lsda = Map.find lsdaPointer gccexctbl
  lsda.CallSiteTable

let rec private loopCallSiteTable fde acc = function
  | [] -> acc
  | csrec :: rest ->
    let acc =
      let landingPad =
        if csrec.LandingPad = 0UL then 0UL
        else fde.PCBegin + csrec.LandingPad
      let blockStart = fde.PCBegin + csrec.Position
      let blockEnd = fde.PCBegin + csrec.Position + csrec.Length - 1UL
      ARMap.add (AddrRange (blockStart, blockEnd)) landingPad acc
    loopCallSiteTable fde acc rest

let private buildExceptionTable fde gccexctbl tbl =
  match fde.LSDAPointer with
  | None -> tbl
  | Some lsdaPointer ->
    loopCallSiteTable fde tbl (loadCallSiteTable lsdaPointer gccexctbl)

let private accumulateExceptionTableInfo fde gccexctbl map =
  fde
  |> Array.fold (fun map fde ->
     let functionRange = AddrRange (fde.PCBegin, fde.PCEnd - 1UL)
     let exceptTable = buildExceptionTable fde gccexctbl ARMap.empty
     if ARMap.isEmpty exceptTable then map
     else ARMap.add functionRange exceptTable map) map

let private isRelocatable (eHdr: ELFHeader) =
  eHdr.ELFFileType = ELFFileType.Relocatable

let private computeExceptionTable excframes gccexctbl =
  excframes
  |> List.fold (fun map frame ->
    accumulateExceptionTableInfo frame.FDERecord gccexctbl map) ARMap.empty

let private computeUnwindingTable excframes =
  excframes
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

let private parseELF baseAddr regbay span (reader: IBinReader) =
  let eHdr, baseAddr = Header.parse span reader baseAddr
  let isa = ISA.Init eHdr.MachineType eHdr.Endian
  let cls = eHdr.Class
  let secs = Section.parse baseAddr eHdr span reader
  let proghdrs = ProgHeader.parse baseAddr eHdr span reader
  let segs = ProgHeader.getLoadableProgHeaders proghdrs
  let loadableSecNums = ProgHeader.getLoadableSecNums secs segs
  let symbs = Symbol.parse baseAddr eHdr secs span reader
  let reloc = Relocs.parse baseAddr eHdr secs symbs span reader
  let plt = PLT.parse eHdr.MachineType secs reloc span reader
  let globals = parseGlobalSymbols reloc
  let symbs = Symbol.updatePLTSymbols plt symbs |> Symbol.updateGlobals globals
  let excrel = if isRelocatable eHdr then Some reloc else None
  let excframes = ExceptionFrames.parse span reader cls secs isa regbay excrel
  let lsdas = ELFGccExceptTable.parse span reader cls secs
  let exctbls = computeExceptionTable excframes lsdas
  let unwindings = computeUnwindingTable excframes
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
    ExceptionFrame = excframes
    ExceptionTable = exctbls
    LSDAs = lsdas
    InvalidAddrRanges = invRanges cls segs (fun s -> s.PHAddr + s.PHMemSize)
    NotInFileRanges = invRanges cls segs (fun s -> s.PHAddr + s.PHFileSize)
    ExecutableRanges = execRanges secs segs
    ISA = isa
    UnwindingTbl = unwindings
    BinReader = reader }

let parse (bytes: byte[]) baseAddr regbay =
  let span = ReadOnlySpan bytes
  if Header.isELF span then ()
  else raise FileFormatMismatchException
  match Header.peekEndianness span with
  | Endian.Little -> parseELF baseAddr regbay span BinReader.binReaderLE
  | Endian.Big -> parseELF baseAddr regbay span BinReader.binReaderBE
  | _ -> Utils.impossible ()

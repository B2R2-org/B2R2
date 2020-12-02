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

open B2R2
open B2R2.FrontEnd.BinFile

let parseGlobalSymbols reloc =
  let folder map addr (rel: RelocationEntry) =
    match rel.RelType with
    | RelocationX86 RelocationX86.Reloc386GlobData
    | RelocationX64 RelocationX64.RelocX64GlobData ->
      Map.add addr (Option.get rel.RelSymbol) map
    | _ -> map
  reloc.RelocByAddr |> Map.fold folder Map.empty

let rec loadCallSiteTable lsdaPointer = function
  | [] -> []
  | lsda :: rest ->
    if lsdaPointer = lsda.LSDAAddr then lsda.CallSiteTable
    else loadCallSiteTable lsdaPointer rest

let rec loopCallSiteTable fde acc = function
  | [] -> acc
  | rcrd :: rest ->
    let acc =
      let landingPad =
        if rcrd.LandingPad = uint64 0 then rcrd.LandingPad
        else fde.PCBegin + rcrd.LandingPad
      let blockStart = fde.PCBegin + rcrd.Position
      let blockEnd = fde.PCBegin + rcrd.Position + rcrd.Length
      ARMap.add (AddrRange (blockStart, blockEnd)) landingPad acc
    loopCallSiteTable fde acc rest

let buildExceptionTable fde gccexctbl tbl =
  match fde.LSDAPointer with
  | None -> tbl
  | Some lsdaPointer ->
    loopCallSiteTable fde tbl (loadCallSiteTable lsdaPointer gccexctbl)

let accumulateExceptionTableInfo fde gccexctbl map =
  fde
  |> Array.fold (fun map fde ->
     let functionRange = AddrRange (fde.PCBegin, fde.PCEnd)
     let exceptTable = buildExceptionTable fde gccexctbl ARMap.empty
     if ARMap.isEmpty exceptTable then map
     else ARMap.add functionRange exceptTable map) map

let computeExceptionTable excframes gccexctbl =
  excframes
  |> List.fold (fun map frame ->
    accumulateExceptionTableInfo frame.FDERecord gccexctbl map) ARMap.empty

let computeUnwindingTable excframes =
  excframes
  |> List.fold (fun tbl (f: CallFrameInformation) ->
    f.FDERecord |> Array.fold (fun tbl fde ->
      fde.UnwindingInfo |> List.fold (fun tbl i ->
        Map.add i.Location i tbl) tbl
      ) tbl) Map.empty

let invRanges wordSize segs getNextStartAddr =
  segs
  |> List.sortBy (fun seg -> seg.PHAddr)
  |> List.fold (fun (set, saddr) seg ->
       let n = getNextStartAddr seg
       FileHelper.addInvRange set saddr seg.PHAddr, n) (IntervalSet.empty, 0UL)
  |> FileHelper.addLastInvRange wordSize

let execRanges segs =
  segs
  |> List.filter (fun seg ->
    seg.PHFlags &&& Permission.Executable = Permission.Executable)
  |> List.fold (fun set seg ->
    IntervalSet.add (AddrRange (seg.PHAddr, seg.PHAddr + seg.PHMemSize)) set
    ) IntervalSet.empty

let private parseELF baseAddr regbay offset reader =
  let eHdr = Header.parse baseAddr offset reader
  let isa = ISA.Init eHdr.MachineType eHdr.Endian
  let cls = eHdr.Class
  let secs = Section.parse baseAddr eHdr reader
  let proghdrs = ProgHeader.parse baseAddr eHdr reader
  let segs = ProgHeader.getLoadableProgHeaders proghdrs
  let loadableSecNums = ProgHeader.getLoadableSecNums secs segs
  let symbs = Symbol.parse baseAddr eHdr secs reader
  let reloc = Relocs.parse baseAddr eHdr secs symbs reader
  let plt = PLT.parse eHdr.MachineType secs reloc reader
  let globals = parseGlobalSymbols reloc
  let symbs = Symbol.updatePLTSymbols plt symbs |> Symbol.updateGlobals globals
  let excframes = ExceptionFrames.parse reader cls secs isa regbay
  let gccexctbl = ELFGccExceptTable.parse reader cls secs
  let exctbls = computeExceptionTable excframes gccexctbl
  let unwindings = computeUnwindingTable excframes
  { ELFHdr = eHdr
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
    InvalidAddrRanges = invRanges cls segs (fun s -> s.PHAddr + s.PHMemSize)
    NotInFileRanges = invRanges cls segs (fun s -> s.PHAddr + s.PHFileSize)
    ExecutableRanges = execRanges segs
    BinReader = reader
    ISA = isa
    UnwindingTbl = unwindings }

let parse bytes baseAddr regbay =
  let reader = BinReader.Init (bytes, Endian.Little)
  if Header.isELF reader 0 then ()
  else raise FileFormatMismatchException
  Header.peekEndianness reader 0
  |> BinReader.RenewReader reader
  |> parseELF baseAddr regbay 0

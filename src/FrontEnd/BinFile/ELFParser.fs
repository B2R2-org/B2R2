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

let pltSkipBytes = function
  | Arch.IntelX86
  | Arch.IntelX64 -> 0x10UL
  | Arch.ARMv7 -> 0x14UL
  | Arch.AARCH64 -> 0x20UL
  | _ -> Utils.futureFeature ()

let isThumbPltELFSymbol sAddr (plt: ELFSection) (reader: BinReader) =
  let offset = Convert.ToInt32 (sAddr - plt.SecAddr + plt.SecOffset)
  let pltThumbStubBytes = ReadOnlySpan [| 0x78uy; 0x47uy; 0xc0uy; 0x46uy |]
  let span = reader.PeekSpan (4, offset)
  span.SequenceEqual pltThumbStubBytes

let findPltSize sAddr plt reader = function
  | Arch.IntelX86
  | Arch.IntelX64 -> 0x10UL
  | Arch.ARMv7 ->
    if isThumbPltELFSymbol sAddr plt reader then 0x10UL else 0x0CUL
  | Arch.AARCH64 -> 0x10UL
  | _ -> failwith "Implement"

let updateSecondPLT arch sndAddr symb map =
  match sndAddr with
  | None -> map, sndAddr
  | Some addr ->
    let nextAddr = addr + pltSkipBytes arch
    let r = AddrRange (addr, nextAddr)
    ARMap.add r symb map, Some nextAddr

let parsePLT arch sections (reloc: RelocInfo) reader =
  let sndStartAddr =
    Map.tryFind ".plt.sec" sections.SecByName
    |> Option.map (fun plt -> plt.SecAddr)
  match Map.tryFind ".plt" sections.SecByName with
  | Some plt ->
    let pltStartAddr = plt.SecAddr + pltSkipBytes arch
    let folder (map, sAddr, sndAddr) _ (rel: RelocationEntry) =
      match rel.RelType with
      | RelocationX86 RelocationX86.Reloc386JmpSlot
      | RelocationX64 RelocationX64.RelocX64JmpSlot
      | RelocationARMv7 RelocationARMv7.RelocARMJmpSlot
      | RelocationARMv8 RelocationARMv8.RelocAARCH64JmpSlot ->
        let nextStartAddr = sAddr + findPltSize sAddr plt reader arch
        let addrRange = AddrRange (sAddr, nextStartAddr)
        let symb = Option.get rel.RelSymbol
        let symb = { symb with Addr = rel.RelOffset }
        let map = ARMap.add addrRange symb map
        let map, nextSndAddr = updateSecondPLT arch sndAddr symb map
        map, nextStartAddr, nextSndAddr
      | _ -> map, sAddr, sndAddr
    Map.fold folder (ARMap.empty, pltStartAddr, sndStartAddr) reloc.RelocByAddr
    |> function (m, _, _) -> m
  | None -> ARMap.empty

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
     let functionStart = fde.PCBegin
     let exceptTable = buildExceptionTable fde gccexctbl ARMap.empty
     if ARMap.isEmpty exceptTable then map
     else Map.add functionStart exceptTable map) map

let computeExceptionTable excframes gccexctbl =
  excframes
  |> List.fold (fun map frame ->
    accumulateExceptionTableInfo frame.FDERecord gccexctbl map) Map.empty

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

let private parseELF baseAddr offset reader =
  let eHdr = Header.parse baseAddr offset reader
  let cls = eHdr.Class
  let secs = Section.parse baseAddr eHdr reader
  let proghdrs = ProgHeader.parse baseAddr eHdr reader
  let segs = ProgHeader.getLoadableProgHeaders proghdrs
  let loadableSecNums = ProgHeader.getLoadableSecNums secs segs
  let symbs = Symbol.parse baseAddr eHdr secs reader
  let reloc = Relocs.parse baseAddr eHdr secs symbs reader
  let plt = parsePLT eHdr.MachineType secs reloc reader
  let globals = parseGlobalSymbols reloc
  let symbs = Symbol.updatePLTSymbols plt symbs |> Symbol.updateGlobals globals
  let excframes = ExceptionFrames.parse reader cls secs
  let gccexctbl = ELFGccExceptTable.parse reader cls secs
  let exctbls = computeExceptionTable excframes gccexctbl
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
    BinReader = reader }

let parse baseAddr bytes =
  let reader = BinReader.Init (bytes, Endian.Little)
  if Header.isELF reader 0 then ()
  else raise FileFormatMismatchException
  Header.peekEndianness reader 0
  |> BinReader.RenewReader reader
  |> parseELF baseAddr 0

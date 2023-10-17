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
open System.IO
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

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

let computeInvalidRanges wordSize phdrs getNextStartAddr =
  phdrs
  |> Array.sortBy (fun seg -> seg.PHAddr)
  |> Array.fold (fun (set, saddr) seg ->
       let n = getNextStartAddr seg
       addInvRange set saddr seg.PHAddr, n) (IntervalSet.empty, 0UL)
  |> addLastInvRange wordSize

let invalidRangesByVM wordSize (phdrs: Lazy<ProgramHeader[]>) =
  computeInvalidRanges wordSize phdrs.Value (fun s -> s.PHAddr + s.PHMemSize)

let invalidRangesByFileBounds wordSize (phdrs: Lazy<ProgramHeader[]>) =
  computeInvalidRanges wordSize phdrs.Value (fun s -> s.PHAddr + s.PHFileSize)

let private computeExecutableRangesFromSections shdrs =
  let txtOffset =
    match Array.tryFind (fun s -> s.SecName = Section.SecText) shdrs with
    | Some text -> text.SecOffset
    | None -> 0UL
  shdrs
  |> Array.fold (fun set sec ->
    if sec.SecType = SectionType.SHTProgBits
      && sec.SecFlags.HasFlag SectionFlag.SHFExecInstr
    then
      let offset = sec.SecOffset - txtOffset
      let addr = sec.SecAddr + offset
      let range = AddrRange (addr, addr + sec.SecSize - 1UL)
      IntervalSet.add range set
    else set
  ) IntervalSet.empty

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

let executableRanges (shdrs: Lazy<_>) (loadables: Lazy<_>) =
  let shdrs, loadables = shdrs.Value, loadables.Value
  (* Exclude .rodata even though it is included within an executable segment. *)
  let rodata =
    match Array.tryFind (fun s -> s.SecName = Section.SecROData) shdrs with
    | Some rodata when rodata.SecAddr <> 0UL -> Some rodata
    | _ -> None
  if Array.isEmpty loadables then computeExecutableRangesFromSections shdrs
  else
    loadables
    |> Array.filter (fun seg ->
      seg.PHFlags &&& Permission.Executable = Permission.Executable)
    |> Array.fold (fun set seg ->
      addExecutableInterval rodata seg set) IntervalSet.empty

let parseException stream reader hdr (shdrs: Lazy<_>) rbay (reloc: Lazy<_>) =
  let shdrs = shdrs.Value
  let cls = hdr.Class
  let isa = ISA.Init hdr.MachineType hdr.Endian
  let relocInfo =
    if hdr.ELFFileType = ELFFileType.Relocatable then Some reloc.Value
    else None
  let exns = ExceptionFrames.parse stream reader cls shdrs isa rbay relocInfo
  let lsdas = ELFGccExceptTable.parse stream reader cls shdrs
  match exns with
  | [] when isa.Arch = Architecture.ARMv7 ->
    ELFARMExceptionHandler.parse stream reader cls shdrs
  | _ ->
    let unwinds = computeUnwindingTable exns
    { ExceptionFrames = exns; LSDAs = lsdas; UnwindingTbl = unwinds }

/// Parse the ELF header and returns a triple: (header, preferred base address,
/// and IBinReader).
let parseHeader baseAddrOpt (s: Stream) =
  let buf = Array.zeroCreate 64 (* ELF is maximum 64-byte long. *)
  readOrDie s buf
  let span = ReadOnlySpan buf
  if not <| Header.isELF span then raise InvalidFileFormatException
  else
    let endian = Header.peekEndianness span
    let reader = BinReader.Init endian
    let struct (hdr, baseAddr) = Header.parse span reader baseAddrOpt
    struct (reader, hdr, baseAddr)

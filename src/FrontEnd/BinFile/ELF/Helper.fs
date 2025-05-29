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

module internal B2R2.FrontEnd.BinFile.ELF.Helper

open System
open System.Collections.Generic
open B2R2
open B2R2.Collections
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

let inline private computeSubstitute offsetToAddr delta (ptr: Addr) =
  if offsetToAddr then ptr + delta
  else (* Addr to offset *) ptr - delta

let translateWithSecs offsetToAddr ptr sections =
  let txtOffset =
    match Array.tryFind (fun s -> s.SecName = Section.Text) sections with
    | Some text -> text.SecOffset
    | None -> 0UL
  sections
  |> Array.tryFind (fun s ->
    let secBase =
      if offsetToAddr then s.SecOffset
      else s.SecOffset - txtOffset + s.SecAddr
    s.SecType = SectionType.SHT_PROGBITS
    && s.SecFlags.HasFlag SectionFlags.SHF_EXECINSTR
    && secBase <= ptr && (secBase + s.SecSize) > ptr)
  |> function
    | None -> raise InvalidAddrReadException
    | Some s -> computeSubstitute offsetToAddr (s.SecAddr - txtOffset) ptr

let translateWithSegs offsetToAddr ptr segments =
  segments
  |> Array.tryFind (fun seg ->
    let segBase, segSize =
      if offsetToAddr then seg.PHOffset, seg.PHFileSize
      else seg.PHAddr, seg.PHMemSize
    ptr >= segBase && ptr < segBase + segSize)
  |> function
    | Some seg -> computeSubstitute offsetToAddr (seg.PHAddr - seg.PHOffset) ptr
    | None -> raise InvalidAddrReadException

let translate loadableSegments sections offsetToAddr ptr =
  if Array.isEmpty loadableSegments then
    translateWithSecs offsetToAddr ptr sections
  else translateWithSegs offsetToAddr ptr loadableSegments

let translateAddrToOffset loadableSegs sections addr =
  translate loadableSegs sections false addr

let translateOffsetToAddr loadableSegs sections offset =
  translate loadableSegs sections true offset

let inline tryFindFuncSymb (symbs: SymbolStore) addr =
  match symbs.TryFindSymbol addr with
  | Ok s ->
    if Symbol.IsFunction s then Ok s.SymName
    else Error ErrorCase.SymbolNotFound
  | Error _ -> Error ErrorCase.SymbolNotFound

let getRelocatedAddr (relocInfo: RelocationInfo) relocAddr =
  match relocInfo.TryFind relocAddr with
  | Ok rel ->
    match rel.RelKind with
    | RelocationKindX86 RelocationX86.R_386_32
    | RelocationKindX64 RelocationX64.R_X86_64_64 ->
      match rel.RelSymbol with
      | Some sym -> sym.Addr + rel.RelAddend |> Ok
      | _ -> Error ErrorCase.ItemNotFound
    | RelocationKindX86 RelocationX86.R_386_JUMP_SLOT
    | RelocationKindX64 RelocationX64.R_X86_64_JUMP_SLOT ->
      match rel.RelSymbol with
      | Some sym -> sym.Addr |> Ok
      | _ -> Error ErrorCase.ItemNotFound
    | RelocationKindX86 RelocationX86.R_386_IRELATIVE
    | RelocationKindX64 RelocationX64.R_X86_64_IRELATIVE ->
      Ok rel.RelAddend
    | _ -> Error ErrorCase.ItemNotFound
  | _ -> Error ErrorCase.ItemNotFound

let getFuncAddrsFromLibcArr span toolBox loadables shdrs relocInfo section =
  let readType = toolBox.Header.Class
  let entrySize = WordSize.toByteWidth readType
  let secSize = int section.SecSize
  let lst = List<Addr> ()
  let addr = translateOffsetToAddr loadables shdrs section.SecOffset
  for ofs in [| 0 .. entrySize .. secSize - entrySize |] do
    readUIntByWordSize span toolBox.Reader readType ofs
    |> (fun fnAddr ->
      if fnAddr = 0UL then
        match getRelocatedAddr relocInfo (addr + uint64 ofs) with
        | Ok relocatedAddr -> lst.Add relocatedAddr
        | Error _ -> ()
      else lst.Add fnAddr)
  lst.ToArray ()

let getAddrsFromInitArray toolBox shdrs loadables relocInfo =
  match Array.tryFind (fun s -> s.SecName = Section.InitArray) shdrs with
  | Some s ->
    let span = ReadOnlySpan (toolBox.Bytes, int s.SecOffset, int s.SecSize)
    getFuncAddrsFromLibcArr span toolBox loadables shdrs relocInfo s
  | None -> [||]

let getAddrsFromFiniArray toolBox shdrs loadables relocInfo =
  match Array.tryFind (fun s -> s.SecName = Section.FiniArray) shdrs with
  | Some s ->
    let span = ReadOnlySpan (toolBox.Bytes, int s.SecOffset, int s.SecSize)
    getFuncAddrsFromLibcArr span toolBox loadables shdrs relocInfo s
  | None -> [||]

let getAddrsFromSpecialSections shdrs =
  [| Section.Init; Section.Fini |]
  |> Array.choose (fun secName ->
    match Array.tryFind (fun s -> s.SecName = secName) shdrs with
    | Some sec -> Some sec.SecAddr
    | None -> None)

let findExtraFnAddrs toolBox shdrs loadables relocInfo =
  [ getAddrsFromInitArray toolBox shdrs loadables relocInfo
    getAddrsFromFiniArray toolBox shdrs loadables relocInfo
    getAddrsFromSpecialSections shdrs ]
  |> Array.concat

let private computeInvalidRanges wordSize phdrs getNextStartAddr =
  phdrs
  |> Array.sortBy (fun seg -> seg.PHAddr)
  |> Array.fold (fun (set, saddr) seg ->
    let n = getNextStartAddr seg
    addInvalidRange set saddr seg.PHAddr, n) (IntervalSet.empty, 0UL)
  |> addLastInvalidRange wordSize

let invalidRangesByVM hdr phdrs =
  computeInvalidRanges hdr.Class phdrs (fun s -> s.PHAddr + s.PHMemSize)

let invalidRangesByFileBounds hdr phdrs =
  computeInvalidRanges hdr.Class phdrs (fun s -> s.PHAddr + s.PHFileSize)

let private computeExecutableRangesFromSections shdrs =
  let txtOffset =
    match Array.tryFind (fun s -> s.SecName = Section.Text) shdrs with
    | Some text -> text.SecOffset
    | None -> 0UL
  shdrs
  |> Array.fold (fun set sec ->
    if sec.SecType = SectionType.SHT_PROGBITS
      && sec.SecFlags.HasFlag SectionFlags.SHF_EXECINSTR
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

let executableRanges shdrs loadables =
  (* Exclude .rodata even though it is included within an executable segment. *)
  let rodata =
    match Array.tryFind (fun s -> s.SecName = Section.ROData) shdrs with
    | Some rodata when rodata.SecAddr <> 0UL -> Some rodata
    | _ -> None
  if Array.isEmpty loadables then computeExecutableRangesFromSections shdrs
  else
    loadables
    |> Array.filter (fun seg ->
      let perm = ProgramHeader.FlagsToPerm seg.PHFlags
      perm.HasFlag Permission.Executable)
    |> Array.fold (fun set seg ->
      addExecutableInterval rodata seg set) IntervalSet.empty

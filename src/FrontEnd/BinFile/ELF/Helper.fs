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

/// Returns the file offset of the text section, which is where an object file
/// puts every address it assigns. Its sections are each laid out from zero, so
/// what tells one from another is how far into the file the section begins,
/// counted from where the text does.
let getTextOffset shdrs =
  match Array.tryFind (fun s -> s.SecName = Section.Text) shdrs with
  | Some text -> text.SecOffset
  | None -> 0UL

/// Returns the address at which the given section begins, which is where the
/// text does plus however much further into the file it sits.
let private baseOfSection (s: SectionHeader) txtOffset =
  s.SecOffset - txtOffset + s.SecAddr

/// Checks whether the given section holds the given address. Only sections
/// that carry file content (SHT_PROGBITS) are addressable, so NOBITS sections
/// such as .bss are excluded.
let private sectionHolds (s: SectionHeader) txtOffset addr =
  let secBase = baseOfSection s txtOffset
  s.SecType = SectionType.SHT_PROGBITS
  && secBase <= addr
  && addr < secBase + s.SecSize

/// The section the last lookup settled on, which the next one tries before
/// scanning the table. It is a hint and never an answer: it is taken only
/// where it passes the very test a scan would apply, so a stale one costs a
/// bounds check and nothing else.
let mutable private lastSectionHit = 0

/// Returns the index of the section holding the given address, or -1 where
/// none of them does. The scan is written out rather than picked so that it
/// allocates nothing: every read of an address in an object file goes through
/// it.
let private findSectionHolding (shdrs: SectionHeader[]) txtOffset addr =
  let hint = lastSectionHit
  if hint < shdrs.Length && sectionHolds shdrs[hint] txtOffset addr then
    hint
  else
    let mutable idx = 0
    let mutable found = -1
    while found < 0 && idx < shdrs.Length do
      if sectionHolds shdrs[idx] txtOffset addr then found <- idx
      else idx <- idx + 1
    if found >= 0 then lastSectionHit <- found else ()
    found

/// Returns a bounded pointer for the given address using section information.
/// This is used for ELF object files (ET_REL), which have no loadable
/// segments, so their sections are all there is to find an address in.
let getBoundedPtrBySections (shdrs: SectionHeader[]) txtOffset addr =
  match findSectionHolding shdrs txtOffset addr with
  | -1 ->
    BinFilePointer.Null
  | idx ->
    let s = shdrs[idx]
    let secBase = baseOfSection s txtOffset
    let offset = int (s.SecOffset + (addr - secBase))
    let maxOffset = int s.SecOffset + int s.SecSize - 1
    BinFilePointer.CreateFileBacked(
      addr, secBase + s.SecSize - 1UL, offset, maxOffset
    )

/// Checks whether the given segment maps the given address, whether or not
/// the file keeps bytes for it.
let private segmentMaps (ph: ProgramHeader) addr =
  addr >= ph.PHAddr && addr < ph.PHAddr + ph.PHMemSize

/// The segment the last lookup settled on, which the next one tries before
/// scanning, on the same terms as the hint the sections keep.
let mutable private lastSegmentHit = 0

/// Returns the index of the segment mapping the given address, or -1 where
/// none of them does.
let private findSegmentMapping (phdrs: ProgramHeader[]) addr =
  let hint = lastSegmentHit
  if hint < phdrs.Length && segmentMaps phdrs[hint] addr then
    hint
  else
    let mutable idx = 0
    let mutable found = -1
    while found < 0 && idx < phdrs.Length do
      if segmentMaps phdrs[idx] addr then found <- idx else idx <- idx + 1
    if found >= 0 then lastSegmentHit <- found else ()
    found

/// Returns a bounded pointer for the given address using the segments the
/// file loads. An address past what a segment keeps in the file is still its
/// own, the rest of that segment being zero at run time and nowhere on disk,
/// and the pointer it gets is virtual rather than file-backed.
let getBoundedPtrBySegments (phdrs: ProgramHeader[]) addr =
  match findSegmentMapping phdrs addr with
  | -1 ->
    BinFilePointer.Null
  | idx ->
    let ph = phdrs[idx]
    if addr < ph.PHAddr + ph.PHFileSize then
      let offset = int ph.PHOffset + int (addr - ph.PHAddr)
      let maxOffset = int ph.PHOffset + int ph.PHFileSize - 1
      let maxAddr = ph.PHAddr + ph.PHFileSize - 1UL
      BinFilePointer.CreateFileBacked(addr, maxAddr, offset, maxOffset)
    else
      BinFilePointer.CreateVirtual(addr, ph.PHAddr + ph.PHMemSize - 1UL)

/// Returns a bounded pointer for the given address, found through the segments
/// the file loads, or through its sections where it loads none. The text
/// offset the section scan needs is asked of the caller, which knows it for
/// as long as the file is open, rather than looked for on every read.
let getBoundedPtr shdrs txtOffset phdrs loadables addr =
  if Array.isEmpty loadables then
    getBoundedPtrBySections shdrs txtOffset addr
  else
    getBoundedPtrBySegments phdrs addr

let getRelocatedAddr toolBox (relocInfo: RelocationInfo) relocAddr =
  match relocInfo.TryFind relocAddr with
  | Ok rel ->
    match RelocationKind.GetSemantics rel.RelKind, rel.RelSymbol with
    | ValueSome SymbolPlusAddend, Some sym ->
      Ok(sym.Addr + rel.RelAddend)
    | ValueSome SymbolOnly, Some sym ->
      Ok sym.Addr
    | ValueSome BasePlusAddend, _
    | ValueSome IFuncResolver, _
    | ValueSome SymbolPlusAddend, None ->
      (* The addend is a link-time address, so it shifts with the load base. *)
      Ok(toolBox.BaseAddress + rel.RelAddend)
    | _ ->
      Error ErrorCase.ItemNotFound
  | _ ->
    Error ErrorCase.ItemNotFound

let tryGetInternalFuncAddr toolBox (reloc: RelocationEntry) =
  match reloc.RelSymbol with
  | Some relSym ->
    if relSym.SymType = SymbolType.STT_FUNC then
      match relSym.ParentSection with
      | Some parent ->
        if parent.SecName = Section.Text then Ok relSym.Addr
        else Error ErrorCase.SymbolNotFound
      | _ ->
        Error ErrorCase.SymbolNotFound
    else
      Error ErrorCase.SymbolNotFound
  | None ->
    (* An ifunc slot names no symbol: what it holds is a resolver defined in
       this very file, so the address it computes is an internal one. *)
    match RelocationKind.GetSemantics reloc.RelKind with
    | ValueSome IFuncResolver ->
      Ok(toolBox.BaseAddress + reloc.RelAddend)
    | _ ->
      Error ErrorCase.SymbolNotFound

let getFuncAddrsFromLibcArr span toolBox relocInfo section =
  let readType = toolBox.Header.Class
  let entrySize = WordSize.toByteWidth readType
  let secSize = int section.SecSize
  let lst = List<Addr>()
  let addr = section.SecAddr
  for ofs in 0 .. entrySize .. secSize - entrySize do
    readUIntByWordSize span toolBox.Reader readType ofs
    |> (fun fnAddr ->
      if fnAddr = 0UL then
        match getRelocatedAddr toolBox relocInfo (addr + uint64 ofs) with
        | Ok relocatedAddr -> lst.Add relocatedAddr
        | Error _ -> ()
      else
        lst.Add fnAddr)
  lst.ToArray()

/// Returns the function addresses the named array section holds. The three
/// libc constructor tables are laid out alike, each an array of pointers.
let private getAddrsFromFuncArray toolBox shdrs relocInfo secName =
  match Array.tryFind (fun s -> s.SecName = secName) shdrs with
  | Some s ->
    let span = ReadOnlySpan(toolBox.Bytes, int s.SecOffset, int s.SecSize)
    getFuncAddrsFromLibcArr span toolBox relocInfo s
  | None ->
    [||]

let private getAddrsFromSpecialSections shdrs =
  [| Section.Init; Section.Fini |]
  |> Array.choose (fun secName ->
    match Array.tryFind (fun s -> s.SecName = secName) shdrs with
    | Some sec -> Some sec.SecAddr
    | None -> None)

let findExtraFnAddrs toolBox shdrs relocInfo =
  let fromArray = getAddrsFromFuncArray toolBox shdrs relocInfo
  [ fromArray Section.PreinitArray
    fromArray Section.InitArray
    fromArray Section.FiniArray
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
  let txtOffset = getTextOffset shdrs
  shdrs
  |> Array.fold (fun set sec ->
    if sec.SecType = SectionType.SHT_PROGBITS
      && sec.SecFlags.HasFlag SectionFlags.SHF_EXECINSTR
    then
      let offset = sec.SecOffset - txtOffset
      let addr = sec.SecAddr + offset
      let range = AddrRange.create addr (addr + sec.SecSize - 1UL)
      IntervalSet.add range set
    else
      set
  ) IntervalSet.empty

let private addIntervalWithoutSection secS secE s e set =
  let set =
    if s < secS && secS < e then
      IntervalSet.add (AddrRange.create s (secS - 1UL)) set
    else
      set
  let set =
    if secE < e then IntervalSet.add (AddrRange.create (secE + 1UL) e) set
    else set
  set

let private addIntervalWithoutROSection rodata seg set =
  let roS = rodata.SecAddr
  let roE = roS + rodata.SecSize - 1UL
  let segS = seg.PHAddr
  let segE = segS + seg.PHMemSize - 1UL
  if roE < segS || segE < roS then
    IntervalSet.add (AddrRange.create segS segE) set
  else
    addIntervalWithoutSection roS roE segS segE set

let private addExecutableInterval excludingSection s set =
  match excludingSection with
  | Some sec ->
    addIntervalWithoutROSection sec s set
  | None ->
    let endAddr = s.PHAddr + s.PHMemSize - 1UL
    IntervalSet.add (AddrRange.create s.PHAddr endAddr) set

let executableRanges shdrs loadables =
  (* Exclude .rodata even though it is included within an executable segment. *)
  let rodata =
    match Array.tryFind (fun s -> s.SecName = Section.ROData) shdrs with
    | Some rodata when rodata.SecAddr <> 0UL -> Some rodata
    | _ -> None
  if Array.isEmpty loadables then
    computeExecutableRangesFromSections shdrs
  else
    loadables
    |> Array.filter (fun seg ->
      let perm = ProgramHeader.FlagsToPerm seg.PHFlags
      perm.HasFlag Permission.Executable)
    |> Array.fold (fun set seg ->
      addExecutableInterval rodata seg set) IntervalSet.empty

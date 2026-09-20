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

/// Returns a bounded pointer for the given address using section information.
/// This is used for ELF object files (ET_REL), which have no loadable segments;
/// only sections that carry file content (SHT_PROGBITS) are addressable, so
/// NOBITS sections such as .bss are excluded.
let getBoundedPtrBySections (shdrs: SectionHeader[]) addr =
  let txtOffset =
    match Array.tryFind (fun s -> s.SecName = Section.Text) shdrs with
    | Some text -> text.SecOffset
    | None -> 0UL
  shdrs
  |> Array.tryPick (fun s ->
    let secBase = s.SecOffset - txtOffset + s.SecAddr
    if s.SecType = SectionType.SHT_PROGBITS
       && secBase <= addr
       && addr < secBase + s.SecSize then
      let offset = int (s.SecOffset + (addr - secBase))
      let maxOffset = int s.SecOffset + int s.SecSize - 1
      BinFilePointer.CreateFileBacked(
        addr, secBase + s.SecSize - 1UL, offset, maxOffset
      )
      |> Some
    else
      None)
  |> Option.defaultValue BinFilePointer.Null

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
  for ofs in [| 0 .. entrySize .. secSize - entrySize |] do
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

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

namespace B2R2.FrontEnd.BinFile.ELF

open System
open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.FileHelper

module private RelocMap =
  let readInfoWithArch { Reader = reader; Header = hdr } span =
    let info = readUIntByWordSizeAndOffset span reader hdr.Class 4 8
    match hdr.MachineType, hdr.Class with
    | MachineType.EM_MIPS, WordSize.Bit64 ->
      (* MIPS64el has a a 32-bit LE symbol index followed by four individual
         byte fields. *)
      if hdr.Endian = Endian.Little then
        (info &&& 0xffffffffUL) <<< 32
        ||| ((info >>> 56) &&& 0xffUL)
        ||| ((info >>> 40) &&& 0xff00UL)
        ||| ((info >>> 24) &&& 0xff0000UL)
        ||| ((info >>> 8) &&& 0xff000000UL)
      else
        info
    | _ ->
      info

  let inline getRelocSIdx hdr (i: uint64) =
    if hdr.Class = WordSize.Bit32 then i >>> 8 else i >>> 32

  /// Returns the mask selecting the relocation type out of r_info. ELF64 gives
  /// the type 32 bits, except under the MIPS n64 ABI, which packs three 8-bit
  /// types there and puts the primary one first.
  let getRelocTypeMask hdr =
    match hdr.MachineType, hdr.Class with
    | MachineType.EM_MIPS, WordSize.Bit64 -> 0xFFUL
    | _ -> selectByWordSize hdr.Class 0xFFUL 0xFFFFFFFFUL

  /// Reads the addend a REL-format entry leaves in the slot it relocates.
  let readImplicitAddend toolBox locate addr =
    let cls = toolBox.Header.Class
    let width = uint64 (WordSize.toByteWidth cls)
    match locate addr width with
    | Some(offset, _) ->
      let span = ReadOnlySpan(toolBox.Bytes, int offset, int width)
      readUIntByWordSize span toolBox.Reader cls 0
    | None ->
      0UL

  let getRelocAddend toolBox locate span sec addr =
    let cls = toolBox.Header.Class
    if sec.SecType = SectionType.SHT_RELA then
      readUIntByWordSizeAndOffset span toolBox.Reader cls 8 16
    else
      readImplicitAddend toolBox locate addr

  let getRelocEntry toolBox locate symTbl span sec =
    let hdr = toolBox.Header
    let cls = hdr.Class
    let info = readInfoWithArch toolBox span
    let reader = toolBox.Reader
    let addr = readUIntByWordSize span reader cls 0 + toolBox.BaseAddress
    let idx = getRelocSIdx hdr info |> int
    { RelOffset = addr
      RelKind =
        RelocationKind.Create(hdr.MachineType, getRelocTypeMask hdr &&& info)
      (* Index 0 is the reserved STN_UNDEF entry, so it names no symbol. *)
      RelSymbol = if idx = 0 then None else Array.tryItem idx symTbl
      RelAddend = getRelocAddend toolBox locate span sec addr
      RelSecNumber = sec.SecNum
      RelTargetSecNumber = int sec.SecInfo }

  let tryFindSymbTable idx (symbs: SymbolStore) =
    match symbs.TryFindSymbolTable idx with
    | Ok tbl -> tbl
    | Error _ -> [||]

  let inline accumulateRelocInfo (entries: ResizeArray<_>) rel =
    entries.Add rel

  let parseRelocSection toolBox locate symTbl relocMap sec =
    let hdr = toolBox.Header
    let hasAddend = sec.SecType = SectionType.SHT_RELA
    let entrySize =
      if hasAddend then (uint64 <| WordSize.toByteWidth hdr.Class * 3)
      else (uint64 <| WordSize.toByteWidth hdr.Class * 2)
    let numEntries = int (sec.SecSize / entrySize)
    let span = ReadOnlySpan(toolBox.Bytes, int sec.SecOffset, int sec.SecSize)
    for i = 0 to (numEntries - 1) do
      let offset = i * int entrySize
      getRelocEntry toolBox locate symTbl (span.Slice offset) sec
      |> accumulateRelocInfo relocMap

  /// Applies f to every address a RELR bitmap marks. Bit 0 is the tag that
  /// makes the entry a bitmap, so bit i + 1 marks the i-th word from cursor.
  let applyRelrBitmap (width: uint64) (cursor: uint64) bitmap f =
    let mutable bits = bitmap >>> 1
    let mutable addr = cursor
    while bits <> 0UL do
      if bits &&& 1UL <> 0UL then f addr else ()
      bits <- bits >>> 1
      addr <- addr + width

  /// Walks a RELR table, applying f to each link-time address it relocates.
  /// Entries are word-sized. An even one is an address: it relocates that one
  /// word and leaves the cursor right past it. An odd one is a bitmap over the
  /// words from the cursor, which afterwards skips every bit the entry can
  /// hold: one fewer than the word has bits, as the lowest one is the tag.
  let iterRelrTable cls reader (span: ByteSpan) f =
    let width = uint64 (WordSize.toByteWidth cls)
    let stride = (width * 8UL - 1UL) * width
    let mutable cursor = 0UL
    for i = 0 to span.Length / int width - 1 do
      let entry = readUIntByWordSize span reader cls (i * int width)
      if entry &&& 1UL = 0UL then
        f entry
        cursor <- entry + width
      else
        applyRelrBitmap width cursor entry f
        cursor <- cursor + stride

  let parseRelrSection toolBox locate relocMap sec kind =
    let cls = toolBox.Header.Class
    let span = ReadOnlySpan(toolBox.Bytes, int sec.SecOffset, int sec.SecSize)
    let accumulate offset =
      let addr = offset + toolBox.BaseAddress
      { RelOffset = addr
        RelKind = kind
        (* RELR only ever packs relative relocations, which name no symbol and
           take as their addend whatever the slot already holds. *)
        RelSymbol = None
        RelAddend = readImplicitAddend toolBox locate addr
        RelSecNumber = sec.SecNum
        RelTargetSecNumber = int sec.SecInfo }
      |> accumulateRelocInfo relocMap
    iterRelrTable cls toolBox.Reader span accumulate

  let isRelocSection s =
    match s.SecType with
    | SectionType.SHT_REL
    | SectionType.SHT_RELA
    | SectionType.SHT_RELR -> true
    | _ -> false

  /// Returns the symbol table a relocation table names. A table the dynamic
  /// array located links to no section, so it takes the sole dynamic table.
  let getSymbolTable (symbs: SymbolStore) sec =
    if sec.SecNum < 0 then symbs.DynamicSymbols
    else tryFindSymbTable (int sec.SecLink) symbs

  let parse toolBox shdrs phdrs dynTables symbs =
    let relocMap = ResizeArray()
    let locate = DynamicTables.makeContentLocator shdrs phdrs
    let relative = RelocationKind.TryCreateRelative toolBox.Header.MachineType
    let tables =
      match Array.filter isRelocSection shdrs with
      | [||] -> (dynTables: DynamicTables).Relocations
      | sections -> sections
    for sec in tables do
      match sec.SecType, relative with
      | SectionType.SHT_REL, _
      | SectionType.SHT_RELA, _ when sec.SecSize > 0UL ->
        let symTbl = getSymbolTable symbs sec
        parseRelocSection toolBox locate symTbl relocMap sec
      | SectionType.SHT_RELR, ValueSome kind when sec.SecSize > 0UL ->
        parseRelrSection toolBox locate relocMap sec kind
      | _ ->
        ()
    relocMap

/// Represents relocation information, which internally stores a collection of
/// relocation entries, indexed both by the slot each one relocates and by the
/// address it applies to.
type internal RelocationInfo internal(toolBox, shdrs, phdrs, dyn, symbs) =
  /// The entries indexed by the slot each relocates -- which is what the
  /// section and the offset name together -- and by the address each applies
  /// at. Indexing by the offset alone would let the sections of a relocatable
  /// object, each of which counts its offsets from zero, overwrite one
  /// another's entries; the address names an entry in every other file. Both
  /// are filled in one walk, so the parsed list itself is dropped here rather
  /// than kept alive as a field of every instance.
  let slotMap, relocMap =
    let slotMap = Dictionary()
    let relocMap = Dictionary()
    for e in RelocMap.parse toolBox shdrs phdrs dyn symbs do
      slotMap[struct(e.RelTargetSecNumber, e.RelOffset)] <- e
      relocMap[e.RelOffset] <- e
    slotMap, relocMap

  /// Returns all relocation entries.
  member _.Entries with get() = slotMap.Values

  /// Checks if there exists a relocation entry at the given address.
  member _.Contains addr = relocMap.ContainsKey addr

  /// Finds a relocation entry at the given address.
  member _.Find addr = relocMap[addr]

  /// Tries to find a relocation entry at the given address.
  member _.TryFind addr =
    match relocMap.TryGetValue addr with
    | true, v -> Ok v
    | _ -> Error ErrorCase.ItemNotFound

  /// Tries to find the relocation entry that applies at the given offset of
  /// the section numbered secNum. This is how a relocatable object names one,
  /// as its offsets run from the start of each section rather than from the
  /// start of the image.
  member _.TryFindInSection(secNum, offset) =
    match slotMap.TryGetValue(struct(secNum, offset)) with
    | true, v -> Ok v
    | _ -> Error ErrorCase.ItemNotFound

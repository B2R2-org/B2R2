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

  /// Checks whether the section holds the given stretch of addresses as file
  /// content, which is what lets it answer for the bytes stored there.
  let isContentSection addr width s =
    s.SecFlags.HasFlag SectionFlags.SHF_ALLOC
    && s.SecType <> SectionType.SHT_NOBITS
    && addr >= s.SecAddr && addr + width <= s.SecAddr + s.SecSize

  /// Checks the same of a loadable segment. Whatever a segment maps past its
  /// file size is zero-filled at load time, so it backs no content.
  let isContentSegment addr width ph =
    ph.PHType = ProgramHeaderType.PT_LOAD
    && addr >= ph.PHAddr && addr + width <= ph.PHAddr + ph.PHFileSize

  /// Returns a function mapping an address and a width to the file offset the
  /// bytes are stored at, or None when nothing in the file backs them. The
  /// section headers answer precisely; the loadable segments cover binaries
  /// that no longer have any.
  let makeContentLocator (shdrs: SectionHeader[]) (phdrs: ProgramHeader[]) =
    fun addr width ->
      let fromSegments () =
        Array.tryFind (isContentSegment addr width) phdrs
        |> Option.map (fun ph -> ph.PHOffset + (addr - ph.PHAddr))
      Array.tryFind (isContentSection addr width) shdrs
      |> Option.map (fun s -> s.SecOffset + (addr - s.SecAddr))
      |> Option.orElseWith fromSegments

  /// Reads the addend a REL-format entry leaves in the slot it relocates.
  let readImplicitAddend toolBox locate addr =
    let cls = toolBox.Header.Class
    let width = uint64 (WordSize.toByteWidth cls)
    match locate addr width with
    | Some offset ->
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
      RelKind = RelocationKind(hdr.MachineType, getRelocTypeMask hdr &&& info)
      (* Index 0 is the reserved STN_UNDEF entry, so it names no symbol. *)
      RelSymbol = if idx = 0 then None else Array.tryItem idx symTbl
      RelAddend = getRelocAddend toolBox locate span sec addr
      RelSecNumber = sec.SecNum }

  let tryFindSymbTable idx (symbs: SymbolStore) =
    match symbs.TryFindSymbolTable idx with
    | Ok tbl -> tbl
    | Error _ -> [||]

  let inline accumulateRelocInfo (relocMap: Dictionary<_, _>) rel =
    relocMap[rel.RelOffset] <- rel

  let parseRelocSection toolBox locate symbs relocMap sec =
    let hdr = toolBox.Header
    let hasAddend = sec.SecType = SectionType.SHT_RELA
    let entrySize =
      if hasAddend then (uint64 <| WordSize.toByteWidth hdr.Class * 3)
      else (uint64 <| WordSize.toByteWidth hdr.Class * 2)
    let numEntries = int (sec.SecSize / entrySize)
    let symTbl = tryFindSymbTable (int sec.SecLink) symbs
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
        RelSecNumber = sec.SecNum }
      |> accumulateRelocInfo relocMap
    iterRelrTable cls toolBox.Reader span accumulate

  let isRelocSection s =
    match s.SecType with
    | SectionType.SHT_REL
    | SectionType.SHT_RELA
    | SectionType.SHT_RELR -> true
    | _ -> false

  /// Returns the value the dynamic array gives the tag, if it carries it.
  let tryFindDynValue (dynEntries: DynamicArrayEntry[]) tag =
    Array.tryFind (fun e -> e.DTag = tag) dynEntries |> Option.map _.DVal

  /// Locates the table a pair of dynamic tags describes, returning its address
  /// along with the file offset and the size of its bytes.
  let tryFindDynTable toolBox locate dynEntries addrTag sizeTag =
    let sizeOpt = tryFindDynValue dynEntries sizeTag
    match tryFindDynValue dynEntries addrTag, sizeOpt with
    | Some addr, Some size ->
      let addr = addr + toolBox.BaseAddress
      locate addr size |> Option.map (fun ofs -> addr, int ofs, int size)
    | _ ->
      None

  /// Describes a table the dynamic array points to as a section header would,
  /// so that it reaches the parsers by the one path they already take.
  let toDynSection secType addr offset size =
    { SecNum = -1
      SecName = ""
      SecType = secType
      SecFlags = SectionFlags.SHF_ALLOC
      SecAddr = addr
      SecOffset = uint64 offset
      SecSize = uint64 size
      SecLink = 0u
      SecInfo = 0u
      SecAlignment = 0UL
      SecEntrySize = 0UL }

  /// Returns whether DT_JMPREL points at a REL or a RELA table, which is what
  /// DT_PLTREL says and nothing else in the file does.
  let getPLTRelocType dynEntries =
    match tryFindDynValue dynEntries DTag.DT_PLTREL with
    | Some v when v = uint64 DTag.DT_REL -> SectionType.SHT_REL
    | _ -> SectionType.SHT_RELA

  /// Returns the relocation tables the dynamic array points to. PT_DYNAMIC
  /// names every one of them, so a binary keeps them all after its section
  /// headers are stripped.
  let getDynRelocTables toolBox locate dynEntries =
    let tableOf secType addrTag sizeTag =
      tryFindDynTable toolBox locate dynEntries addrTag sizeTag
      |> Option.map (fun (addr, ofs, sz) -> toDynSection secType addr ofs sz)
      |> Option.toArray
    let jmpType = getPLTRelocType dynEntries
    [| yield! tableOf SectionType.SHT_RELA DTag.DT_RELA DTag.DT_RELASZ
       yield! tableOf SectionType.SHT_REL DTag.DT_REL DTag.DT_RELSZ
       yield! tableOf SectionType.SHT_RELR DTag.DT_RELR DTag.DT_RELRSZ
       yield! tableOf jmpType DTag.DT_JMPREL DTag.DT_PLTRELSZ |]

  let parse toolBox shdrs phdrs dynEntries symbs =
    let relocMap = Dictionary()
    let locate = makeContentLocator shdrs phdrs
    let relative = RelocationKind.TryCreateRelative toolBox.Header.MachineType
    let tables =
      match Array.filter isRelocSection shdrs with
      | [||] -> getDynRelocTables toolBox locate dynEntries
      | sections -> sections
    for sec in tables do
      match sec.SecType, relative with
      | SectionType.SHT_REL, _
      | SectionType.SHT_RELA, _ when sec.SecSize > 0UL ->
        parseRelocSection toolBox locate symbs relocMap sec
      | SectionType.SHT_RELR, ValueSome kind when sec.SecSize > 0UL ->
        parseRelrSection toolBox locate relocMap sec kind
      | _ ->
        ()
    relocMap

/// Represents relocation information, which internally stores a collection of
/// relocation entries indexed by their addresses.
type internal RelocationInfo internal(toolBox, shdrs, phdrs, dyn, symbs) =
  let relocMap = RelocMap.parse toolBox shdrs phdrs dyn symbs

  /// Returns all relocation entries.
  member _.Entries with get() = relocMap.Values

  /// Checks if there exists a relocation entry at the given address.
  member _.Contains addr = relocMap.ContainsKey addr

  /// Finds a relocation entry at the given address.
  member _.Find addr = relocMap[addr]

  /// Tries to find a relocation entry at the given address.
  member _.TryFind addr =
    match relocMap.TryGetValue addr with
    | true, v -> Ok v
    | _ -> Error ErrorCase.ItemNotFound

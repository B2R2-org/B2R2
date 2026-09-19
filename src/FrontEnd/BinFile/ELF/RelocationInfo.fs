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

  /// Reads the addend a REL-format entry leaves in the slot it relocates. Only
  /// allocated sections carrying file content can hold one.
  let readImplicitAddend toolBox (shdrs: SectionHeader[]) addr =
    let cls = toolBox.Header.Class
    let width = uint64 (WordSize.toByteWidth cls)
    let isHost s =
      s.SecFlags.HasFlag SectionFlags.SHF_ALLOC
      && s.SecType <> SectionType.SHT_NOBITS
      && addr >= s.SecAddr && addr + width <= s.SecAddr + s.SecSize
    match Array.tryFind isHost shdrs with
    | Some s ->
      let offset = int (s.SecOffset + (addr - s.SecAddr))
      let span = ReadOnlySpan(toolBox.Bytes, offset, int width)
      readUIntByWordSize span toolBox.Reader cls 0
    | None ->
      0UL

  let getRelocAddend toolBox shdrs span sec addr =
    let cls = toolBox.Header.Class
    if sec.SecType = SectionType.SHT_RELA then
      readUIntByWordSizeAndOffset span toolBox.Reader cls 8 16
    else
      readImplicitAddend toolBox shdrs addr

  let getRelocEntry toolBox shdrs symTbl span sec =
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
      RelAddend = getRelocAddend toolBox shdrs span sec addr
      RelSecNumber = sec.SecNum }

  let tryFindSymbTable idx (symbs: SymbolStore) =
    match symbs.TryFindSymbolTable idx with
    | Ok tbl -> tbl
    | Error _ -> [||]

  let inline accumulateRelocInfo (relocMap: Dictionary<_, _>) rel =
    relocMap[rel.RelOffset] <- rel

  let parseRelocSection toolBox shdrs symbs relocMap sec (span: ByteSpan) =
    let hdr = toolBox.Header
    let hasAddend = sec.SecType = SectionType.SHT_RELA
    let entrySize =
      if hasAddend then (uint64 <| WordSize.toByteWidth hdr.Class * 3)
      else (uint64 <| WordSize.toByteWidth hdr.Class * 2)
    let numEntries = int (sec.SecSize / entrySize)
    let symTbl = tryFindSymbTable (int sec.SecLink) symbs
    for i = 0 to (numEntries - 1) do
      let offset = i * int entrySize
      getRelocEntry toolBox shdrs symTbl (span.Slice offset) sec
      |> accumulateRelocInfo relocMap

  let parse toolBox shdrs symbs =
    let relocMap = Dictionary()
    for sec in shdrs do
      match sec.SecType with
      | SectionType.SHT_REL
      | SectionType.SHT_RELA ->
        if sec.SecSize = 0UL then
          ()
        else
          let offset, size = int sec.SecOffset, int sec.SecSize
          let span = ReadOnlySpan(toolBox.Bytes, offset, size)
          parseRelocSection toolBox shdrs symbs relocMap sec span
      | _ ->
        ()
    relocMap

/// Represents relocation information, which internally stores a collection of
/// relocation entries indexed by their addresses.
type internal RelocationInfo internal(toolBox, shdrs, symbs) =
  let relocMap = RelocMap.parse toolBox shdrs symbs

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

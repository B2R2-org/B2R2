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

namespace B2R2.FrontEnd.BinFile.Mach

open System
open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents what a relocation entry names as its target.
type internal RelocSymbol =
  /// Index into the symbol table, which an external entry uses.
  | SymIndex of idx: int
  /// One-based number of the section the target lies in, which a local entry
  /// uses.
  | SecOrdinal of num: int
  /// The address the target is measured from, which is how a scattered entry
  /// names it. Scattered entries exist because that address is not the one the
  /// field holds, so neither of the other two cases can say it.
  | RelocValue of value: Addr

/// Represents relocation information in a Mach-O binary file.
type internal RelocationInfo =
  { /// Offset in the section to what is being relocated.
    RelocAddr: int
    /// RelocSymbol
    RelocSymbol: RelocSymbol
    /// Relocation length.
    RelocLength: RegType
    /// Relocation type (r_type). The values are specific to the architecture,
    /// so this stays a plain number: 0 is X86_64_RELOC_UNSIGNED on x86-64 and
    /// GENERIC_RELOC_VANILLA on i386, to name two that do not agree.
    RelocType: int
    /// Parent section
    RelocSection: Section
    /// Is this address part of an instruction that uses PC-relative addressing?
    IsPCRel: bool }
with
  member this.GetName(symbols: Symbol[], sections: Section[]) =
    match this.RelocSymbol with
    | SymIndex n when n < symbols.Length ->
      symbols[n].SymName
    | SecOrdinal n when n >= 1 && n <= sections.Length ->
      sections[n - 1].SecName
    | _ ->
      ""

module internal Reloc =
  let private parseRelocSymbol data =
    let n = data &&& 0xFFFFFF
    if (data >>> 27) &&& 1 = 1 then SymIndex(n) else SecOrdinal(n)

  let private toRelocLength encoded =
    match encoded with
    | 0 -> 8<rt>
    | 1 -> 16<rt>
    | 2 -> 32<rt>
    | _ -> 64<rt>

  let private countRelocs secs =
    secs |> Array.fold (fun cnt sec -> cnt + sec.SecNumOfReloc) 0

  /// Parses a scattered entry, whose first word packs every field the ordinary
  /// layout spreads over two, leaving the second word to hold the address the
  /// target is measured from.
  let private parseScattered (span: ByteSpan) (reader: IBinReader) sec word =
    { RelocAddr = word &&& 0xFFFFFF
      RelocSymbol = RelocValue(uint64 (reader.ReadUInt32(span, 4)))
      RelocLength = toRelocLength ((word >>> 28) &&& 3)
      RelocType = (word >>> 24) &&& 0xF
      RelocSection = sec
      IsPCRel = (word >>> 30) &&& 1 = 1 }

  let private parseReloc (span: ByteSpan) (reader: IBinReader) sec =
    let addr = reader.ReadInt32(span, 0)
    if addr < 0 then
      parseScattered span reader sec addr
    else
      let data = reader.ReadInt32(span, 4)
      { RelocAddr = addr
        RelocSymbol = parseRelocSymbol data
        RelocLength = toRelocLength ((data >>> 25) &&& 3)
        RelocType = (data >>> 28) &&& 0xF
        RelocSection = sec
        IsPCRel = (data >>> 24) &&& 1 = 1 }

  let parse { Bytes = bytes; Reader = reader } secs =
    let numRelocs = countRelocs secs
    let relocs = Array.zeroCreate numRelocs
    let mutable i = 0
    for sec in secs do
      let relOffset, relSize = int sec.SecRelOff, int sec.SecNumOfReloc * 8
      let relSpan = ReadOnlySpan(bytes, relOffset, relSize)
      for n = 0 to sec.SecNumOfReloc - 1 do
        let offset = n * 8
        relocs[i] <- parseReloc (relSpan.Slice offset) reader sec
        i <- i + 1
    relocs

  /// Builds a map from a relocated virtual address to its relocation entry.
  let buildMap (relocs: RelocationInfo[]) =
    relocs
    |> Array.fold (fun map reloc ->
      Map.add (reloc.RelocSection.SecAddr + uint64 reloc.RelocAddr) reloc map)
      Map.empty

  /// Reads the signed in-place addend stored at the relocation site. Mach-O,
  /// unlike ELF RELA, keeps the addend inside the relocated field itself.
  let private readAddend (bytes: byte[]) (reader: IBinReader) reloc =
    let offset = int reloc.RelocSection.SecOffset + reloc.RelocAddr
    match reloc.RelocLength with
    | 8<rt> -> int64 (reader.ReadInt8(bytes, offset))
    | 16<rt> -> int64 (reader.ReadInt16(bytes, offset))
    | 32<rt> -> int64 (reader.ReadInt32(bytes, offset))
    | _ -> reader.ReadInt64(bytes, offset)

  /// Converts a Mach-O relocation entry into a format-agnostic BinRelocation.
  let toBinRelocation toolBox (symbols: Symbol[]) reloc =
    let addend = readAddend toolBox.Bytes toolBox.Reader reloc
    let symName =
      match reloc.RelocSymbol with
      | SymIndex n when n < symbols.Length -> Some symbols[n].SymName
      | _ -> None
    let result: FrontEnd.BinFile.BinRelocation =
      { Address = reloc.RelocSection.SecAddr + uint64 reloc.RelocAddr
        SymbolName = symName
        Addend = Some addend }
    result

  /// Computes the relocated target address for the given virtual address. The
  /// semantics follow relocatable object files (MH_OBJECT): an external entry
  /// resolves to (symbol address + addend), while a local entry keeps the
  /// absolute target value in place, so the addend is the target itself. A
  /// PC-relative entry says nothing here, because its field is measured from
  /// the end of the instruction it sits in and the entry records neither that
  /// instruction's length nor where it starts.
  let getRelocatedAddr toolBox relocMap (symbolStore: SymbolStore) relocAddr =
    let symbols = symbolStore.SymbolArray
    match Map.tryFind relocAddr relocMap with
    | Some reloc when not reloc.IsPCRel ->
      let addend = readAddend toolBox.Bytes toolBox.Reader reloc
      match reloc.RelocSymbol with
      | SymIndex n when n < symbols.Length ->
        int64 symbols[n].SymAddr + addend |> uint64 |> Ok
      | SymIndex _ ->
        Error ErrorCase.ItemNotFound
      | _ ->
        uint64 addend |> Ok
    | _ ->
      Error ErrorCase.ItemNotFound

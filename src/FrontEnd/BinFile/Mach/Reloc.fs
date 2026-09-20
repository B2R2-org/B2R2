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
  { /// Virtual address of the field being relocated. An entry records this as
    /// an offset, from its own section in a relocatable object and from the
    /// image base in a linked image, so it is resolved when the entry is read.
    RelocAddr: Addr
    /// File offset of that same field, which is where its addend sits.
    RelocOffset: int
    /// RelocSymbol
    RelocSymbol: RelocSymbol
    /// Relocation length.
    RelocLength: RegType
    /// Relocation type (r_type). The values are specific to the architecture,
    /// so this stays a plain number: 0 is X86_64_RELOC_UNSIGNED on x86-64 and
    /// GENERIC_RELOC_VANILLA on i386, to name two that do not agree.
    RelocType: int
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
  /// Size of one relocation_info entry, scattered or not.
  let [<Literal>] private EntrySize = 8

  let private chooseDySymTab = function
    | DySymTab(_, _, c) -> Some c
    | _ -> None

  let private parseRelocSymbol data =
    let n = data &&& 0xFFFFFF
    if (data >>> 27) &&& 1 = 1 then SymIndex(n) else SecOrdinal(n)

  let private toRelocLength encoded =
    match encoded with
    | 0 -> 8<rt>
    | 1 -> 16<rt>
    | 2 -> 32<rt>
    | _ -> 64<rt>

  /// Places a field of a relocatable object, whose r_address counts from the
  /// section the entry belongs to.
  let private placeInSection sec relAddr =
    struct (sec.SecAddr + uint64 relAddr, int sec.SecOffset + relAddr)

  /// Returns the file offset at which the given virtual address is stored.
  let private fileOffsetOf (segCmds: SegCmd[]) addr =
    segCmds
    |> Array.tryFind (fun s ->
      addr >= s.VMAddr && addr < s.VMAddr + s.FileSize)
    |> Option.map (fun s -> int (s.FileOff + addr - s.VMAddr))

  /// Places a field of a linked image, whose r_address counts from the image
  /// base. An address that no segment maps gets a negative file offset, which
  /// the caller drops.
  let private placeInImage segCmds imageBase relAddr =
    let addr = imageBase + uint64 relAddr
    match fileOffsetOf segCmds addr with
    | Some offset -> struct (addr, offset)
    | None -> struct (addr, -1)

  /// Parses one entry. A scattered entry packs into its first word every field
  /// that the ordinary layout spreads over two, leaving the second word to
  /// hold the address its target is measured from. Where the relocated field
  /// lives is not in the entry either way, so the caller places it.
  let private parseEntry (span: ByteSpan) (reader: IBinReader) place =
    let word = reader.ReadInt32(span, 0)
    if word < 0 then
      let struct (addr, offset) = place (word &&& 0xFFFFFF)
      { RelocAddr = addr
        RelocOffset = offset
        RelocSymbol = RelocValue(uint64 (reader.ReadUInt32(span, 4)))
        RelocLength = toRelocLength ((word >>> 28) &&& 3)
        RelocType = (word >>> 24) &&& 0xF
        IsPCRel = (word >>> 30) &&& 1 = 1 }
    else
      let data = reader.ReadInt32(span, 4)
      let struct (addr, offset) = place word
      { RelocAddr = addr
        RelocOffset = offset
        RelocSymbol = parseRelocSymbol data
        RelocLength = toRelocLength ((data >>> 25) &&& 3)
        RelocType = (data >>> 28) &&& 0xF
        IsPCRel = (data >>> 24) &&& 1 = 1 }

  /// Reads a table of entries, ignoring one that runs past the end of the
  /// file rather than reading whatever lies there.
  let private parseTable toolBox off count place =
    let bytes, reader = toolBox.Bytes, toolBox.Reader
    let fits = off >= 0 && count >= 0 && off + count * EntrySize <= bytes.Length
    let relocs = Array.zeroCreate (if fits then count else 0)
    for n = 0 to relocs.Length - 1 do
      let span = ReadOnlySpan(bytes, off + n * EntrySize, EntrySize)
      relocs[n] <- parseEntry span reader place
    relocs

  let private parseSectionTables toolBox secs =
    secs
    |> Array.collect (fun sec ->
      let count = sec.SecNumOfReloc
      parseTable toolBox (int sec.SecRelOff) count (placeInSection sec))

  /// Parses the external and local relocation tables of LC_DYSYMTAB. They
  /// belong to a linked image rather than to a relocatable object, whose
  /// entries hang off the sections instead, so their r_address counts from the
  /// image base and no section is involved.
  let private parseImageTables toolBox segCmds cmds =
    let imageBase = Segment.tryGetImageBase segCmds |> Option.defaultValue 0UL
    let place = placeInImage segCmds imageBase
    cmds
    |> Array.choose chooseDySymTab
    |> Array.collect (fun c ->
      Array.append
        (parseTable toolBox (int c.ExtRelOff) (int c.NumExtRel) place)
        (parseTable toolBox (int c.LocalRelOff) (int c.NumLocalRel) place))
    |> Array.filter (fun reloc -> reloc.RelocOffset >= 0)

  let parse toolBox segCmds secs cmds =
    Array.append (parseSectionTables toolBox secs)
                 (parseImageTables toolBox segCmds cmds)

  /// Builds a map from a relocated virtual address to its relocation entry.
  let buildMap (relocs: RelocationInfo[]) =
    relocs
    |> Array.fold (fun map reloc -> Map.add reloc.RelocAddr reloc map) Map.empty

  /// Reads the signed in-place addend stored at the relocation site. Mach-O,
  /// unlike ELF RELA, keeps the addend inside the relocated field itself.
  let private readAddend (bytes: byte[]) (reader: IBinReader) reloc =
    let offset = reloc.RelocOffset
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
      { Address = reloc.RelocAddr
        SymbolName = symName
        Addend = Some addend }
    result

  /// Computes the relocated target address for the given virtual address. An
  /// external entry resolves to (symbol address + addend), while a local one
  /// keeps the unslid target in place, so the addend is the target and only
  /// the load address moves it. A PC-relative entry says nothing here, because
  /// its field is measured from the end of the instruction it sits in and the
  /// entry records neither that instruction's length nor where it starts.
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
        uint64 addend + toolBox.BaseAddress |> Ok
    | _ ->
      Error ErrorCase.ItemNotFound

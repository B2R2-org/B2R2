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

/// Represents a relocation symbol, which can either be a symbol index or a
/// section ordinal.
type RelocSymbol =
  | SymIndex of idx: int (* Symbol table index *)
  | SecOrdinal of num: int (* Section number *)

/// Represents relocation information in a Mach-O binary file.
type RelocationInfo =
  { /// Offset in the section to what is being relocated.
    RelocAddr: int
    /// RelocSymbol
    RelocSymbol: RelocSymbol
    /// Relocation length.
    RelocLength: RegType
    /// Parent section
    RelocSection: Section
    /// Is this address part of an instruction that uses PC-relative addressing?
    IsPCRel: bool }
with
  member this.GetName(symbols: Symbol[], sections: Section[]) =
    match this.RelocSymbol with
    | SymIndex n -> symbols[n].SymName
    | SecOrdinal n -> sections[n-1].SecName

module internal Reloc =
  let private parseRelocSymbol data =
    let n = data &&& 0xFFFFFF
    if (data >>> 27) &&& 1 = 1 then SymIndex(n)
    else SecOrdinal(n)

  let private parseRelocLength data =
    match (data >>> 25) &&& 3 with
    | 0 -> 8<rt>
    | 1 -> 16<rt>
    | 2 -> 32<rt>
    | _ -> 64<rt>

  let private countRelocs secs =
    secs |> Array.fold (fun cnt sec -> cnt + sec.SecNumOfReloc) 0

  let private parseReloc (span: ByteSpan) (reader: IBinReader) sec =
    let addr = reader.ReadInt32(span, 0)
    let data = reader.ReadInt32(span, 4)
    let sym = parseRelocSymbol data
    let len = parseRelocLength data
    let rel = (data >>> 24) &&& 1 = 1
    { RelocAddr = addr
      RelocSymbol = sym
      RelocLength = len
      RelocSection = sec
      IsPCRel = rel }

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
      | SymIndex n -> Some symbols[n].SymName
      | SecOrdinal _ -> None
    let result: FrontEnd.BinFile.BinRelocation =
      { Address = reloc.RelocSection.SecAddr + uint64 reloc.RelocAddr
        SymbolName = symName
        Addend = Some addend }
    result

  /// Computes the relocated target address for the given virtual address. The
  /// semantics follow relocatable object files (MH_OBJECT): an external entry
  /// resolves to (symbol address + addend), while a local (section) entry keeps
  /// the absolute target value in place, so the addend is the target itself.
  let getRelocatedAddr toolBox relocMap (symbolStore: SymbolStore) relocAddr =
    let symbols = symbolStore.SymbolArray
    match Map.tryFind relocAddr relocMap with
    | Some reloc ->
      let addend = readAddend toolBox.Bytes toolBox.Reader reloc
      match reloc.RelocSymbol with
      | SymIndex n -> int64 symbols[n].SymAddr + addend |> uint64 |> Ok
      | SecOrdinal _ -> uint64 addend |> Ok
    | None -> Error ErrorCase.ItemNotFound

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
open B2R2
open B2R2.FrontEnd.BinFile.FileHelper

/// Represents the tables the dynamic array points to, each described the way a
/// section header describes it. A binary keeps its dynamic array in a segment
/// of its own, so these outlive the section header table and let the parsers
/// reach the same bytes by the path they already take.
type internal DynamicTables =
  { /// The relocation tables: DT_RELA, DT_REL, DT_RELR and DT_JMPREL.
    Relocations: SectionHeader[]
    /// The dynamic symbol table, DT_SYMTAB.
    Symbols: SectionHeader option
    /// The string table the symbol names come from, DT_STRTAB.
    Strings: SectionHeader option
    /// The per-symbol version index table, DT_VERSYM.
    SymbolVersions: SectionHeader option
    /// The version requirement table, DT_VERNEED.
    VersionNeeds: SectionHeader option
    /// The version definition table, DT_VERDEF.
    VersionDefs: SectionHeader option }

/// Provides functions to rebuild the tables the dynamic array points to.
[<RequireQualifiedAccess>]
module internal DynamicTables =
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

  /// Returns a function mapping an address and a width to where those bytes
  /// begin in the file and how many the region holding them has left. The
  /// section headers answer precisely; the loadable segments cover binaries
  /// that no longer have any. A table whose size no dynamic tag gives is read
  /// up to that remainder, as it ends at a terminator of its own.
  let makeContentLocator (shdrs: SectionHeader[]) (phdrs: ProgramHeader[]) =
    fun addr width ->
      let fromSegments () =
        Array.tryFind (isContentSegment addr width) phdrs
        |> Option.map (fun ph ->
          ph.PHOffset + (addr - ph.PHAddr), ph.PHAddr + ph.PHFileSize - addr)
      Array.tryFind (isContentSection addr width) shdrs
      |> Option.map (fun s ->
        s.SecOffset + (addr - s.SecAddr), s.SecAddr + s.SecSize - addr)
      |> Option.orElseWith fromSegments

  /// Holds what every lookup here needs: the file, the dynamic array that
  /// names the tables, and the translation from an address to a file offset.
  type private Context =
    { ToolBox: Toolbox
      Entries: DynamicArrayEntry[]
      Locate: Addr -> uint64 -> (uint64 * uint64) option }

  /// Returns the address the given tag holds, taken relative to the load base.
  let private tryFindAddr ctx tag =
    DynamicArray.tryFindValue ctx.Entries tag
    |> Option.map (fun v -> v + ctx.ToolBox.BaseAddress)

  /// Describes a table of the given size at the given address as a section
  /// header would. SecNum is -1 because no section header table numbered it.
  let private toSection secType addr (offset, size) =
    { SecNum = -1
      SecName = ""
      SecType = secType
      SecFlags = SectionFlags.SHF_ALLOC
      SecAddr = addr
      SecOffset = offset
      SecSize = size
      SecLink = 0u
      SecInfo = 0u
      SecAlignment = 0UL
      SecEntrySize = 0UL }

  /// Describes the table the given tag locates, sized to the given count of
  /// bytes or to what the region holding it has left, whichever is smaller. A
  /// table no tag gives the size of asks for all of it and stops at the
  /// terminator it carries.
  let private tryFindSizedTable ctx secType addrTag size =
    tryFindAddr ctx addrTag
    |> Option.bind (fun addr ->
      ctx.Locate addr 0UL
      |> Option.map (fun (offset, room) ->
        toSection secType addr (offset, min size room)))

  /// Describes the table the given tag locates, reading it to the end of the
  /// region that holds it.
  let private tryFindTailTable ctx secType addrTag =
    tryFindSizedTable ctx secType addrTag UInt64.MaxValue

  /// Describes the table a pair of tags locates, one naming its address and
  /// the other the size of its bytes.
  let private tryFindTaggedTable ctx secType addrTag sizeTag =
    DynamicArray.tryFindValue ctx.Entries sizeTag
    |> Option.bind (tryFindSizedTable ctx secType addrTag)

  /// Returns whether DT_JMPREL points at a REL or a RELA table, which is what
  /// DT_PLTREL says and nothing else in the file does.
  let private getPLTRelocType ctx =
    match DynamicArray.tryFindValue ctx.Entries DTag.DT_PLTREL with
    | Some v when v = uint64 DTag.DT_REL -> SectionType.SHT_REL
    | _ -> SectionType.SHT_RELA

  /// Returns every relocation table the dynamic array names.
  let private getRelocations ctx =
    let tableOf secType addrTag sizeTag =
      tryFindTaggedTable ctx secType addrTag sizeTag |> Option.toArray
    let jmpType = getPLTRelocType ctx
    [| yield! tableOf SectionType.SHT_RELA DTag.DT_RELA DTag.DT_RELASZ
       yield! tableOf SectionType.SHT_REL DTag.DT_REL DTag.DT_RELSZ
       yield! tableOf SectionType.SHT_RELR DTag.DT_RELR DTag.DT_RELRSZ
       yield! tableOf jmpType DTag.DT_JMPREL DTag.DT_PLTRELSZ |]

  /// Returns the entry count the DT_HASH table implies. Its second word is
  /// nchain, which the ABI fixes at one chain per symbol.
  let private tryCountFromHash ctx =
    tryFindAddr ctx DTag.DT_HASH
    |> Option.bind (fun addr -> ctx.Locate addr 8UL)
    |> Option.map (fun (offset, _) ->
      let span = ReadOnlySpan(ctx.ToolBox.Bytes, int offset, 8)
      int (ctx.ToolBox.Reader.ReadUInt32(span, 4)))

  /// Returns the entry count the distance from DT_SYMTAB to DT_STRTAB
  /// implies. The string table is what every linker lays out right behind the
  /// symbol table, and so the only thing that bounds it from above.
  let private tryCountFromStrTab ctx entrySize =
    let strAddr = tryFindAddr ctx DTag.DT_STRTAB
    match tryFindAddr ctx DTag.DT_SYMTAB, strAddr with
    | Some symAddr, Some strAddr when strAddr > symAddr ->
      Some(int ((strAddr - symAddr) / entrySize))
    | _ ->
      None

  /// Returns how many entries the dynamic symbol table has. No dynamic tag
  /// gives that count outright. DT_HASH carries it in its nchain word, and
  /// failing that the string table behind the symbol table bounds it. The GNU
  /// hash table is no help here even when the binary carries one: it indexes
  /// only the symbols the binary exports, and so counts none of the undefined
  /// ones that precede them.
  let private tryCountSymbols ctx entrySize =
    match tryCountFromHash ctx with
    | Some count -> Some count
    | None -> tryCountFromStrTab ctx entrySize

  /// Returns the size of one symbol table entry, which DT_SYMENT gives and
  /// the word size fixes anyway.
  let private getSymbolEntrySize ctx =
    let cls = ctx.ToolBox.Header.Class
    DynamicArray.tryFindValue ctx.Entries DTag.DT_SYMENT
    |> Option.defaultValue (uint64 (selectByWordSize cls 16 24))

  /// Returns the dynamic symbol table and the per-symbol version indices, the
  /// sizes of which follow from the symbol count rather than from a tag.
  let private getSymbolTables ctx =
    let entrySize = getSymbolEntrySize ctx
    match tryCountSymbols ctx entrySize with
    | Some count ->
      let dynsym = SectionType.SHT_DYNSYM
      let versym = SectionType.SHT_GNU_versym
      let symbols =
        tryFindSizedTable ctx dynsym DTag.DT_SYMTAB (uint64 count * entrySize)
      let versions =
        tryFindSizedTable ctx versym DTag.DT_VERSYM (uint64 count * 2UL)
      symbols, versions
    | None ->
      None, None

  /// Rebuilds the tables the dynamic array points to.
  let reconstruct toolBox shdrs phdrs dynEntries =
    let ctx =
      { ToolBox = toolBox
        Entries = dynEntries
        Locate = makeContentLocator shdrs phdrs }
    let symbols, symbolVersions = getSymbolTables ctx
    let strTab = SectionType.SHT_STRTAB
    { Relocations = getRelocations ctx
      Symbols = symbols
      Strings = tryFindTaggedTable ctx strTab DTag.DT_STRTAB DTag.DT_STRSZ
      SymbolVersions = symbolVersions
      VersionNeeds =
        tryFindTailTable ctx SectionType.SHT_GNU_verneed DTag.DT_VERNEED
      VersionDefs =
        tryFindTailTable ctx SectionType.SHT_GNU_verdef DTag.DT_VERDEF }

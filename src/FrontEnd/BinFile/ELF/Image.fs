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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper
open B2R2.FrontEnd.BinFile.ByteWriter
open B2R2.FrontEnd.BinFile.ELF.Helper

/// Represents an ELF file that can be edited and written back out. It keeps
/// the bytes it was parsed from, because a parsed view is not all of a file:
/// whatever no structure here models is emitted by copying it from the
/// original, which is what lets an untouched image reproduce its file.
type internal Image =
  { /// The file contents this image was parsed from.
    Original: byte[]
    /// The load base the addresses here were parsed against, which every
    /// address field has added to it and must have taken back off to go on
    /// disk.
    BaseAddress: Addr
    /// A reader for the contents of the image, which hold section indices of
    /// their own wherever a symbol or a group names a section.
    Reader: IBinReader
    /// The ELF header.
    Header: Header
    /// The program header table.
    ProgramHeaders: ProgramHeader[]
    /// The section header table.
    Sections: SectionEntry[]
    /// The segments the image needs the file to have, in the order they were
    /// asked for. Where each one goes is not settled until the layout says
    /// where the section it covers went.
    PendingLoads: PendingLoad list
    /// The byte edits laid over the original, newest first. They are the last
    /// word on what the emitted file holds, going on after every structure
    /// here has been written, so that one of them can reach what nothing here
    /// models.
    Patches: BytePatch list
    /// The e_phnum field as the file holds it.
    EncodedPHdrNum: uint16
    /// The e_shnum field as the file holds it.
    EncodedSHdrNum: uint16
    /// The e_shstrndx field as the file holds it.
    EncodedSHdrStrIdx: uint16 }

/// Represents one section of an editable image. The parsed header says all of
/// a section but where its name is kept, a name being a string in that view
/// and an offset into the section name table on disk.
and internal SectionEntry =
  { /// The parsed section header.
    SecHeader: SectionHeader
    /// The sh_name field: an offset into the section name table.
    NameOffset: uint32
    /// Where the bytes of the section come from.
    Content: SectionContent
    /// The room the original file gave the section; None for a section the
    /// image made, which the file never gave a place to.
    Origin: SectionOrigin option }

/// Represents the room the original file gave a section.
and internal SectionOrigin =
  { /// The file offset the section was at.
    OriginOffset: uint64
    /// How many bytes of the file it took up there, which is none for a
    /// section that occupies memory alone.
    OriginSize: uint64 }

/// Represents where a section's bytes come from.
and internal SectionContent =
  /// From the original file, at the offset the section header names, which is
  /// where they stay.
  | InFile
  /// From the image, which needs room of its own wherever what was there is no
  /// longer the size of what goes there now.
  | Given of byte[]

/// Represents a symbol an image is asked to add.
and SymbolSpec =
  { /// The name the symbol goes under.
    SymSpecName: string
    /// The address the symbol is at.
    SymSpecAddr: Addr
    /// How many bytes the symbol covers.
    SymSpecSize: uint64
    /// What kind of thing the symbol names.
    SymSpecType: SymbolType
    /// How far the symbol reaches.
    SymSpecBind: SymbolBind
    /// The index of the section the symbol is defined in.
    SymSpecSecIdx: int }

/// Represents a section an image is asked to add.
and SectionSpec =
  { /// The name the section goes under.
    SpecName: string
    /// What the section holds, in the terms sh_type has for it.
    SpecType: SectionType
    /// The attributes of the section.
    SpecFlags: SectionFlags
    /// What the offset of the section is made a multiple of.
    SpecAlignment: uint64
    /// The bytes the section holds.
    SpecContent: byte[] }

/// Represents a segment an image needs the file to have, so that the section
/// it covers is there at run time and not in the file alone.
and internal PendingLoad =
  { /// The index of the section the segment covers.
    LoadSectionIdx: int
    /// The permissions the segment is mapped with.
    LoadFlags: int }

/// Represents a run of bytes put at one file offset of an image.
and internal BytePatch =
  { /// The file offset the run starts at.
    Offset: int
    /// The bytes that go there.
    Bytes: byte[] }

[<RequireQualifiedAccess>]
module internal Image =
  /// Returns the sh_name field of every section header, read straight from the
  /// file because the parsed header has resolved it to a string.
  let private readNameOffsets (toolBox: Toolbox) count =
    let hdr, reader = toolBox.Header, toolBox.Reader
    let entSize = int hdr.SHdrEntrySize
    let tblOffset = int hdr.SHdrTblOffset
    let offsets = Array.zeroCreate count
    for i = 0 to count - 1 do
      offsets[i] <- reader.ReadUInt32(toolBox.Bytes, tblOffset + i * entSize)
    offsets

  /// Returns a half-word header field as the file holds it, which is what the
  /// extended numbering hides a real value behind.
  let private readEncoded (toolBox: Toolbox) off32 off64 =
    let cls = toolBox.Header.Class
    let offset = selectByWordSize cls off32 off64
    toolBox.Reader.ReadUInt16(toolBox.Bytes, offset)

  /// Creates an editable image out of the given ELF file contents.
  let ofBytes (bytes: byte[]) baseAddrOpt =
    let toolBox = Toolbox.Init(bytes, Header.parse baseAddrOpt bytes)
    let shdrs = SectionHeaders.parse toolBox
    let nameOffsets = readNameOffsets toolBox shdrs.Length
    let toEntry sec offset =
      let fileSize =
        if sec.SecType = SectionType.SHT_NOBITS then 0UL else sec.SecSize
      let origin = { OriginOffset = sec.SecOffset; OriginSize = fileSize }
      { SecHeader = sec
        NameOffset = offset
        Content = InFile
        Origin = Some origin }
    { Original = bytes
      Reader = toolBox.Reader
      BaseAddress = toolBox.BaseAddress
      Header = toolBox.Header
      ProgramHeaders = ProgramHeaders.parse toolBox
      Sections = Array.map2 toEntry shdrs nameOffsets
      PendingLoads = []
      Patches = []
      EncodedPHdrNum = readEncoded toolBox 44 56
      EncodedSHdrNum = readEncoded toolBox 48 60
      EncodedSHdrStrIdx = readEncoded toolBox 50 62 }

  /// Returns the image with the given bytes put at the given file offset.
  let patchByOffset offset (bytes: byte[]) img =
    if offset < 0 || offset + bytes.Length > img.Original.Length then
      raise InvalidAddrWriteException
    else
      let patch = { Offset = offset; Bytes = Array.copy bytes }
      { img with Patches = patch :: img.Patches }

  /// Returns the image with the given bytes put where the file keeps the given
  /// address. Raises InvalidAddrWriteException when the address is not one the
  /// file holds bytes for, which is what an address in a NOBITS section is.
  let patchByAddr addr bytes img =
    let shdrs = img.Sections |> Array.map (fun s -> s.SecHeader)
    let loadables = ProgramHeaders.filterLoadables img.ProgramHeaders
    let txtOffset = getTextOffset shdrs
    let table = makeRegionTable shdrs txtOffset img.ProgramHeaders loadables
    let ptr = table.GetBoundedPointer addr
    if ptr.CanReadFileBytes && Array.length bytes <= ptr.ReadableAmount then
      patchByOffset ptr.Offset bytes img
    else
      raise InvalidAddrWriteException

  /// Returns the image whose entry point is the given address.
  let setEntryPoint addr (img: Image) =
    { img with Header = { img.Header with EntryPoint = addr } }

  /// Returns the image whose section of the given name carries the given
  /// attributes. Raises SectionNotFoundException when it has no such section.
  let setSectionFlags name flags img =
    let isNamed entry = entry.SecHeader.SecName = name
    if img.Sections |> Array.exists isNamed |> not then
      raise SectionNotFoundException
    else
      let reflag entry =
        if isNamed entry then
          { entry with SecHeader = { entry.SecHeader with SecFlags = flags } }
        else
          entry
      { img with Sections = Array.map reflag img.Sections }

  /// Returns the bytes a section holds, whether they are ones the image was
  /// given or ones the original file still has.
  let contentOf (img: Image) entry =
    match entry.Content with
    | Given bytes ->
      bytes
    | InFile ->
      match entry.Origin with
      | Some origin when origin.OriginSize > 0UL ->
        let offset = int origin.OriginOffset
        img.Original[offset..offset + int origin.OriginSize - 1]
      | _ ->
        [||]

  /// Returns where the given name already sits in the given string table, if
  /// it sits there at all. An entry of such a table is any of its suffixes, so
  /// a name is there wherever a terminator follows it.
  let private findInStrTable (table: byte[]) (name: string) =
    let needle = Text.Encoding.Latin1.GetBytes(name + "\000")
    let idx = ReadOnlySpan(table).IndexOf(ReadOnlySpan needle)
    if idx < 0 then None else Some(uint32 idx)

  /// Returns the image with the given name in the string table at the given
  /// index, along with the offset the name sits at. A name the table already
  /// holds is used where it is rather than put there a second time.
  let private internString idx name (img: Image) =
    if idx <= 0 || idx >= img.Sections.Length then
      raise (UnsupportedEditException "The file has no such string table.")
    else
      let entry = img.Sections[idx]
      let table = contentOf img entry
      match findInStrTable table name with
      | Some offset ->
        img, offset
      | None ->
        let addition = Text.Encoding.Latin1.GetBytes(name + "\000")
        let grown = Array.append table addition
        let sec = { entry.SecHeader with SecSize = uint64 grown.Length }
        let sections = Array.copy img.Sections
        sections[idx] <- { entry with SecHeader = sec; Content = Given grown }
        { img with Sections = sections }, uint32 table.Length

  /// Returns the image with the given name in its section name table, along
  /// with the offset the name sits at.
  let private internName name (img: Image) =
    internString img.Header.SHdrStrIdx name img

  /// Returns the program header entries that a segment the image adds can be
  /// put in. An unused entry goes first; a note segment comes after it, the
  /// notes it names being described by their sections as well, so that one is
  /// spent only where nothing is going spare. An entry past the last segment
  /// the file loads is preferred to either, because what the image adds is
  /// mapped above everything else and loadable segments go in address order.
  let spareSlots (img: Image) =
    let phdrs = img.ProgramHeaders
    let indicesOf t =
      [ for i in 0 .. phdrs.Length - 1 do
          if phdrs[i].PHType = t then i else () ]
    let slots =
      indicesOf ProgramHeaderType.PT_NULL @ indicesOf ProgramHeaderType.PT_NOTE
    match indicesOf ProgramHeaderType.PT_LOAD |> List.tryLast with
    | None ->
      slots
    | Some last ->
      match slots |> List.filter (fun i -> i > last) with
      | [] -> slots
      | trailing -> trailing

  /// Returns the permissions a segment covering a section of the given
  /// attributes is mapped with. It is always readable.
  let private loadFlagsOf (flags: SectionFlags) =
    let w = if flags.HasFlag SectionFlags.SHF_WRITE then 2 else 0
    let x = if flags.HasFlag SectionFlags.SHF_EXECINSTR then 1 else 0
    4 ||| w ||| x

  /// Returns the image with a segment asked for over the section at the given
  /// index, which is what puts it in memory rather than in the file alone.
  let private requestLoad flags at (img: Image) =
    if List.length img.PendingLoads >= List.length (spareSlots img) then
      raise (UnsupportedEditException "No program header entry is going spare.")
    else
      let load = { LoadSectionIdx = at; LoadFlags = loadFlagsOf flags }
      { img with PendingLoads = img.PendingLoads @ [ load ] }

  /// The section index from which on the numbers are reserved, so that a
  /// symbol can no longer say in st_shndx which section defines it.
  let [<Literal>] private ReservedIndex = 0xff00

  /// Raises where the image would hold more sections than its file can say it
  /// has. One already using the extended numbering keeps that count in the
  /// initial section header, which has room for any of them.
  let private checkSectionCount (img: Image) =
    let extended = img.EncodedSHdrNum = 0us && img.Header.SHdrNum > 0
    if not extended && img.Sections.Length + 1 >= ReservedIndex then
      raise (UnsupportedEditException "The section count would be reserved.")
    else
      ()

  /// Returns the index remapped, refusing one the reserved range would
  /// swallow: a symbol defined that far up the table has to say so through
  /// SHN_XINDEX, which is a table of its own for the file to keep.
  let private mapSymIndex map ndx =
    let mapped: int = map ndx
    if mapped >= ReservedIndex then
      raise (UnsupportedEditException "A symbol index would be reserved.")
    else
      uint16 mapped

  /// Returns the symbol table with the section index of every entry remapped.
  /// One naming a reserved index names no section of the table and stands.
  let private remapSymbols (img: Image) map (table: byte[]) =
    let cls, endian = img.Header.Class, img.Header.Endian
    let entSize = selectByWordSize cls 16 24
    let field = selectByWordSize cls 14 6
    let out = Array.copy table
    let span = Span out
    for i = 0 to out.Length / entSize - 1 do
      let pos = i * entSize + field
      let ndx = int (img.Reader.ReadUInt16(out, pos))
      if ndx > 0 && ndx < ReservedIndex then
        writeUInt16 span endian pos (mapSymIndex map ndx)
      else
        ()
    out

  /// Returns a table of section indices a word wide each with every one of
  /// them remapped, the given number of leading words being something other
  /// than an index. Nothing here is narrow enough to reach the reserved range.
  let private remapIndexWords (img: Image) map from (table: byte[]) =
    let endian = img.Header.Endian
    let out = Array.copy table
    let span = Span out
    for i = from to out.Length / 4 - 1 do
      let ndx = int (img.Reader.ReadUInt32(out, i * 4))
      if ndx > 0 then writeUInt32 span endian (i * 4) (uint32 (map ndx)) else ()
    out

  /// Returns the contents of the section with whatever section indices they
  /// hold remapped. Only a few kinds of section keep any of their own.
  let private remapContent (img: Image) map entry =
    match entry.SecHeader.SecType with
    | SectionType.SHT_SYMTAB
    | SectionType.SHT_DYNSYM ->
      Given(remapSymbols img map (contentOf img entry))
    | SectionType.SHT_SYMTAB_SHNDX ->
      Given(remapIndexWords img map 0 (contentOf img entry))
    | SectionType.SHT_GROUP ->
      (* The first word of a group is its flags rather than a member of it. *)
      Given(remapIndexWords img map 1 (contentOf img entry))
    | _ ->
      entry.Content

  /// Returns whether sh_info of the section names a section. A relocation
  /// section names what it relocates, and any section says as much by a flag;
  /// a symbol table keeps a symbol index there instead, and so does a group.
  let private infoNamesSection (sec: SectionHeader) =
    sec.SecFlags.HasFlag SectionFlags.SHF_INFO_LINK
    || sec.SecType = SectionType.SHT_REL
    || sec.SecType = SectionType.SHT_RELA

  /// Returns the section as it stands once every index it holds is remapped
  /// and it is itself numbered anew.
  let private remapEntry (img: Image) map num entry =
    let sec = entry.SecHeader
    let info =
      if infoNamesSection sec then uint32 (map (int sec.SecInfo))
      else sec.SecInfo
    let sec =
      { sec with
          SecNum = num
          SecLink = uint32 (map (int sec.SecLink))
          SecInfo = info }
    { entry with SecHeader = sec; Content = remapContent img map entry }

  /// Returns the index a section ends up with once one is put in at the given
  /// place. The initial section keeps its number, nothing going before it.
  let private shiftedBy at i = if i < at then i else i + 1

  /// Returns the image with every index that names a section moved up by one
  /// from the given place: the ones in the section headers, the one the ELF
  /// header keeps for the name table, the ones inside symbol tables and
  /// groups, and the ones the image itself holds for segments it has asked
  /// for.
  let private shiftSections at (img: Image) =
    let map = shiftedBy at
    let remap i entry = remapEntry img map (map i) entry
    let sections = Array.mapi remap img.Sections
    let shiftLoad load = { load with LoadSectionIdx = map load.LoadSectionIdx }
    { img with
        Header = { img.Header with SHdrStrIdx = map img.Header.SHdrStrIdx }
        Sections = sections
        PendingLoads = List.map shiftLoad img.PendingLoads }

  /// Returns the section the given specification describes, numbered for the
  /// place it is going to.
  let private specToEntry (img: Image) at nameOffset spec =
    let sec =
      { SecNum = at
        SecName = spec.SpecName
        SecType = spec.SpecType
        SecFlags = spec.SpecFlags
        (* Every address here has the load base added to it, so the one that
           goes on disk as zero is the load base itself. The layout is what
           gives a loaded section an address of its own. *)
        SecAddr = img.BaseAddress
        SecOffset = 0UL
        SecSize = uint64 spec.SpecContent.Length
        SecLink = 0u
        SecInfo = 0u
        SecAlignment = spec.SpecAlignment
        SecEntrySize = 0UL }
    { SecHeader = sec
      NameOffset = nameOffset
      Content = Given(Array.copy spec.SpecContent)
      Origin = None }

  /// Returns the image with the given section put at the given index. Every
  /// index naming a section from there on moves up by one to follow it, and
  /// the bytes of the section go on the end of the file all the same, nothing
  /// requiring the sections to be laid out in the order they are numbered.
  let insertSection spec at (img: Image) =
    if at <= 0 || at > img.Sections.Length then
      raise (UnsupportedEditException "No section can go at that index.")
    elif img.Sections.Length <> img.Header.SHdrNum then
      raise (UnsupportedEditException "The section header table is truncated.")
    else
      checkSectionCount img
      let img, nameOffset = internName spec.SpecName img
      let entry = specToEntry img at nameOffset spec
      let img = shiftSections at img
      let before, after = img.Sections[0..at - 1], img.Sections[at..]
      let sections = Array.concat [ before; [| entry |]; after ]
      let img = { img with Sections = sections }
      if spec.SpecFlags.HasFlag SectionFlags.SHF_ALLOC then
        requestLoad spec.SpecFlags at img
      else
        img

  /// Returns the image with the given section put after the ones it has,
  /// where it leaves every index the file already uses naming what it named.
  let addSection spec (img: Image) =
    insertSection spec img.Sections.Length img

  /// Returns the image whose section at the given index holds the given bytes.
  let private replaceContent idx (bytes: byte[]) (img: Image) =
    let entry = img.Sections[idx]
    let sec = entry.SecHeader
    if sec.SecType = SectionType.SHT_NOBITS then
      raise (UnsupportedEditException "A NOBITS section holds no bytes.")
    elif uint64 bytes.Length <> sec.SecSize
         && sec.SecFlags.HasFlag SectionFlags.SHF_ALLOC then
      raise (UnsupportedEditException "A loaded section cannot be resized.")
    else
      let sec = { sec with SecSize = uint64 bytes.Length }
      let content = Given(Array.copy bytes)
      let entry = { entry with SecHeader = sec; Content = content }
      let sections = Array.copy img.Sections
      sections[idx] <- entry
      { img with Sections = sections }

  /// Returns the image whose section of the given name holds the given bytes.
  let setSectionContent name bytes (img: Image) =
    let isNamed entry = entry.SecHeader.SecName = name
    match Array.tryFindIndex isNamed img.Sections with
    | Some idx -> replaceContent idx bytes img
    | None -> raise SectionNotFoundException

  /// Returns the entry of a symbol table as the file holds it. The address
  /// every image keeps has the load base added to it, and the one that goes
  /// on disk is what is left once that is taken back off.
  let private encodeSymbol (img: Image) nameOffset spec =
    let cls, endian = img.Header.Class, img.Header.Endian
    let entry: byte[] = Array.zeroCreate (selectByWordSize cls 16 24)
    let span = Span entry
    let bind = byte spec.SymSpecBind <<< 4
    let info = bind ||| (byte spec.SymSpecType &&& 0xfuy)
    let addr = spec.SymSpecAddr
    let value = if addr = 0UL then 0UL else addr - img.BaseAddress
    writeUInt32 span endian 0 nameOffset
    writeUIntByWordSizeAndOffset span endian cls 4 8 value
    writeUIntByWordSizeAndOffset span endian cls 8 16 spec.SymSpecSize
    writeUInt8 span (selectByWordSize cls 12 4) info
    let secIdx = uint16 spec.SymSpecSecIdx
    writeUInt16 span endian (selectByWordSize cls 14 6) secIdx
    entry

  /// Returns whether the file keeps a table of extended section indices for
  /// the symbol table at the given index. Such a table has an entry per
  /// symbol, so the two only ever grow together.
  let private hasExtIdxTable idx (img: Image) =
    let isExtIdxOf entry =
      entry.SecHeader.SecType = SectionType.SHT_SYMTAB_SHNDX
      && int entry.SecHeader.SecLink = idx
    img.Sections |> Array.exists isExtIdxOf

  /// Returns the image with the given symbol on the end of the symbol table
  /// at the given index.
  let private appendSymbol idx spec (img: Image) =
    let strIdx = int img.Sections[idx].SecHeader.SecLink
    let img, nameOffset = internString strIdx spec.SymSpecName img
    let table = contentOf img img.Sections[idx]
    let entry = encodeSymbol img nameOffset spec
    replaceContent idx (Array.append table entry) img

  /// Returns the image with the given symbol added to the table of symbols it
  /// keeps for itself. The symbol goes last, where it leaves every index a
  /// relocation already uses naming what it named; only a symbol the linker
  /// calls global can go there, the local ones all coming first.
  let addSymbol spec (img: Image) =
    let isSymTab entry = entry.SecHeader.SecType = SectionType.SHT_SYMTAB
    match Array.tryFindIndex isSymTab img.Sections with
    | None ->
      raise (UnsupportedEditException "The file has no symbol table.")
    | Some _ when spec.SymSpecBind = SymbolBind.STB_LOCAL ->
      raise (UnsupportedEditException "A local symbol cannot go last.")
    | Some idx when hasExtIdxTable idx img ->
      raise (UnsupportedEditException "The extended index table would grow.")
    | Some idx ->
      appendSymbol idx spec img

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

namespace B2R2.FrontEnd.BinFile.PE

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.PE.PEUtils

/// Represents a PE file that can be edited and written back out. It keeps the
/// bytes it was parsed from, because a parsed view is not all of a file:
/// whatever no structure here models is emitted by copying it from the
/// original, which is what lets an untouched image reproduce its file.
type internal Image =
  { /// The file contents this image was parsed from.
    Original: byte[]
    /// How many bytes of that file the image still holds. It is the whole of
    /// it until the certificate comes off the end, that being the one edit
    /// here that shortens a file rather than lengthening it.
    KeptLength: int
    /// The load base the addresses here were taken against, which is what an
    /// address given to this image is relative to. The addresses the file
    /// itself holds are relative to the image base and stay as they are.
    BaseAddress: Addr
    /// The optional header as the edits leave it.
    OptionalHeader: OptionalHeader
    /// The sections as the edits leave them.
    Sections: SectionEntry[]
    /// Where the COFF header begins, which is where the count of sections
    /// goes back.
    CoffHeaderOffset: int
    /// Where the optional header begins, which is where every field of it
    /// goes back.
    OptionalHeaderOffset: int
    /// Where the section header table begins.
    SectionHeaderTblOffset: int
    /// Whether the checksum is to be worked out afresh from the bytes the
    /// emitter lays down. A file keeps the checksum it came with otherwise,
    /// which is what leaves one that was never right — as a file nothing
    /// ever checked is — the way its linker left it.
    RecomputeChecksum: bool
    /// The byte edits laid over the original, newest first. They are the last
    /// word on what the emitted file holds, going on after every structure
    /// here has been written, so that one of them can reach what nothing here
    /// models.
    Patches: BytePatch list }

/// Represents one section of an editable image. The parsed header says all of
/// a section but how its name goes on disk, a name being a string in that
/// view and eight bytes of a fixed field in the file.
and internal SectionEntry =
  { /// The parsed section header.
    SecHeader: SectionHeader
    /// The eight bytes the name field holds.
    NameBytes: byte[]
    /// Where the bytes of the section come from.
    Content: SectionContent
    /// The room the original file gave the section; None for a section the
    /// image made, which the file never gave a place to.
    Origin: SectionOrigin option }

/// Represents the room the original file gave a section.
and internal SectionOrigin =
  { /// The file offset the section was at.
    OriginOffset: int
    /// How many bytes of the file it took up there, which is none for a
    /// section that occupies memory alone.
    OriginSize: int }

/// Represents where a section's bytes come from.
and internal SectionContent =
  /// From the original file, at the offset the section header names, which is
  /// where they stay.
  | InFile
  /// From the image, which is only ever as many bytes as were there, so they
  /// go where the file already kept them.
  | Given of byte[]

/// Represents a section an image is asked to add.
and SectionSpec =
  { /// The name the section goes under, which has to fit the eight bytes a
    /// section header gives it.
    SpecName: string
    /// What the section holds and how it is to be mapped.
    SpecCharacteristics: SectionCharacteristics
    /// The bytes the section holds.
    SpecContent: byte[] }

/// Represents a run of bytes put at one file offset of an image.
and internal BytePatch =
  { /// The file offset the run starts at.
    Offset: int
    /// The bytes that go there.
    Bytes: byte[] }

[<RequireQualifiedAccess>]
module internal Image =
  /// The number of bytes the name field of a section header takes.
  let [<Literal>] private NameSize = 8

  /// Returns the eight bytes of the name field of the section header at the
  /// given index, read from the file because the parsed header has resolved
  /// them to a string.
  let private readNameBytes (bytes: byte[]) tblOffset i =
    let offset = tblOffset + i * SectionHeaders.EntrySize
    bytes[offset..offset + NameSize - 1]

  /// Creates an editable image out of the given PE file contents. An object
  /// file is no file to make one of: it carries no optional header, and so
  /// names no base to place anything against and no alignment to place it on.
  let ofBytes (bytes: byte[]) baseAddrOpt =
    let hdr = Header.parse bytes (BinReader.Init Endian.Little)
    match hdr.OptionalHeader with
    | None ->
      raise (UnsupportedEditException "An object file cannot be written.")
    | Some opt ->
      let tblOffset = hdr.SectionHeaderTblOffset
      let toEntry i sec =
        { SecHeader = sec
          NameBytes = readNameBytes bytes tblOffset i
          Content = InFile
          Origin =
            Some { OriginOffset = sec.PointerToRawData
                   OriginSize = sec.SizeOfRawData } }
      { Original = bytes
        KeptLength = bytes.Length
        BaseAddress = defaultArg baseAddrOpt opt.ImageBase
        OptionalHeader = opt
        Sections = Array.mapi toEntry hdr.SectionHeaders
        CoffHeaderOffset = hdr.CoffHeaderOffset
        OptionalHeaderOffset = hdr.OptionalHeaderOffset
        SectionHeaderTblOffset = tblOffset
        RecomputeChecksum = false
        Patches = [] }

  /// Returns the image with the given bytes put at the given file offset.
  let patchByOffset offset (bytes: byte[]) img =
    if offset < 0 || offset + bytes.Length > img.KeptLength then
      raise InvalidAddrWriteException
    else
      let patch = { Offset = offset; Bytes = Array.copy bytes }
      { img with Patches = patch :: img.Patches }

  /// Returns the file offset the given address reads at, along with how
  /// many bytes the section holding it still has there, or none where the
  /// file holds no bytes for the address at all. A section is free to take
  /// up less of the file than it does of memory, and what is past its bytes
  /// is nothing the file has a place for.
  let private tryPlaceOf (img: Image) addr =
    if addr < img.BaseAddress then
      None
    else
      let rva = int (addr - img.BaseAddress)
      let secs = img.Sections |> Array.map _.SecHeader
      match findMappedSectionIndex secs rva with
      | -1 ->
        None
      | idx ->
        let sec = secs[idx]
        let offset = rva - sec.VirtualAddress + sec.PointerToRawData
        Some(offset, sec.PointerToRawData + sec.SizeOfRawData - offset)

  /// Returns the image with the given bytes put where the file keeps the
  /// given address. A run reaching past the bytes its section holds is one
  /// the file has no room for, wherever the run began: what follows those
  /// bytes is the next section, not more of this one.
  let patchByAddr addr (bytes: byte[]) img =
    match tryPlaceOf img addr with
    | Some(offset, room) when bytes.Length <= room ->
      patchByOffset offset bytes img
    | _ ->
      raise InvalidAddrWriteException

  /// Returns the image entered at the given address. The header names where
  /// an image is entered relative to the image base, so an address below the
  /// base this one was taken against is no address of it at all.
  let setEntryPoint addr (img: Image) =
    if addr < img.BaseAddress then
      raise (UnsupportedEditException "The address is below the image base.")
    else
      let rva = int (addr - img.BaseAddress)
      { img with OptionalHeader = { img.OptionalHeader with
                                      AddressOfEntryPoint = rva } }

  /// Returns the image whose section of the given name carries the given
  /// attributes. Raises SectionNotFoundException when it has no such section.
  let setSectionCharacteristics name chars img =
    let isNamed entry = entry.SecHeader.Name = name
    if img.Sections |> Array.exists isNamed |> not then
      raise SectionNotFoundException
    else
      let recharacterize entry =
        if isNamed entry then
          let sec = { entry.SecHeader with SectionCharacteristics = chars }
          { entry with SecHeader = sec }
        else
          entry
      { img with Sections = Array.map recharacterize img.Sections }

  /// Returns the bytes a section holds, whether they are ones the image was
  /// given or ones the original file still has.
  let contentOf (img: Image) entry =
    match entry.Content with
    | Given bytes ->
      bytes
    | InFile ->
      match entry.Origin with
      | Some origin when origin.OriginSize > 0 ->
        let offset = origin.OriginOffset
        img.Original[offset..offset + origin.OriginSize - 1]
      | _ ->
        [||]

  /// Returns the image whose section of the given name holds the given bytes.
  /// A section can be given only as many bytes as the file already holds for
  /// it: every one of them sits at an address the section alignment fixes, so
  /// none can grow without moving every section above it, and with them every
  /// address the file has already been relocated and indexed by.
  let setSectionContent name (bytes: byte[]) img =
    let isNamed entry = entry.SecHeader.Name = name
    match Array.tryFindIndex isNamed img.Sections with
    | None ->
      raise SectionNotFoundException
    | Some idx ->
      let entry = img.Sections[idx]
      if bytes.Length <> entry.SecHeader.SizeOfRawData then
        raise (UnsupportedEditException "A section cannot be resized.")
      else
        let sections = Array.copy img.Sections
        sections[idx] <- { entry with Content = Given(Array.copy bytes) }
        { img with Sections = sections }

  /// Returns where the bytes the file itself placed begin, which is what its
  /// headers have to fit before. A section the image added is not among them:
  /// it has no place until the layout gives it one, and the zero standing in
  /// for that place until then is no bound on anything. A file whose sections
  /// hold no bytes at all leaves the headers the whole of what it says they
  /// take.
  let private firstRawOffset (img: Image) =
    img.Sections
    |> Array.choose (fun entry ->
      let sec = entry.SecHeader
      if entry.Origin.IsSome && sec.SizeOfRawData > 0 then
        Some sec.PointerToRawData
      else
        None)
    |> function
      | [||] -> img.OptionalHeader.SizeOfHeaders
      | offsets -> Array.min offsets

  /// Returns how many section headers the file has room for. They have to
  /// fit before the bytes of the first section, and inside what the file
  /// says its headers take, that being all a loader maps of them.
  let headerSlots (img: Image) =
    let hdrEnd = min img.OptionalHeader.SizeOfHeaders (firstRawOffset img)
    (hdrEnd - img.SectionHeaderTblOffset) / SectionHeaders.EntrySize

  /// Returns the eight bytes the given name goes on disk as. A name too long
  /// for them is one no image can carry: the string table that would hold
  /// the rest of it is an object file's, and no loader reads one.
  let private nameBytesOf (name: string) =
    let bytes = Text.Encoding.Latin1.GetBytes name
    if bytes.Length > NameSize then
      raise (UnsupportedEditException "The name is too long for a section.")
    else
      Array.append bytes (Array.zeroCreate (NameSize - bytes.Length))

  /// Returns the section the given specification describes. Where it goes is
  /// not settled until the layout says so, both the address and the offset
  /// here standing at zero until then.
  let private specToEntry (img: Image) spec =
    let content = Array.copy spec.SpecContent
    let fileAlign = img.OptionalHeader.FileAlignment
    let sec =
      { Name = spec.SpecName
        VirtualSize = content.Length
        VirtualAddress = 0
        SizeOfRawData = alignUp content.Length fileAlign
        PointerToRawData = 0
        PointerToRelocations = 0
        PointerToLineNumbers = 0
        NumberOfRelocations = 0us
        NumberOfLineNumbers = 0us
        SectionCharacteristics = spec.SpecCharacteristics }
    { SecHeader = sec
      NameBytes = nameBytesOf spec.SpecName
      Content = Given content
      Origin = None }

  /// Returns the image with the given section put after the ones it has. The
  /// header of it goes in the room the file left between its section header
  /// table and the bytes of its first section, there being nowhere else for
  /// one to go: a header moved anywhere else is a header no loader reads.
  let addSection spec (img: Image) =
    if img.Sections.Length + 1 > headerSlots img then
      raise (UnsupportedEditException "No section header is going spare.")
    else
      let entry = specToEntry img spec
      { img with Sections = Array.append img.Sections [| entry |] }

  /// Returns the image with the certificate taken off the end of it: the
  /// directory naming it is emptied and the bytes it named go, which is what
  /// shortens the file. A certificate covers the bytes as they were, so it is
  /// no use to a file anything has changed. The directory is the one of the
  /// sixteen whose first field is a file offset rather than an address, which
  /// is why nothing here maps it through a section.
  let removeCertificate (img: Image) =
    let kind = DirectoryKind.CertificateTable
    let dir = img.OptionalHeader.Directory kind
    if dir.RVA = 0 || dir.Size = 0 then
      raise (UnsupportedEditException "The file carries no certificate.")
    elif dir.RVA + dir.Size <> img.KeptLength then
      raise (UnsupportedEditException "The certificate is not the end of it.")
    else
      let dirs = Array.copy img.OptionalHeader.Directories
      dirs[int kind] <- { RVA = 0; Size = 0 }
      { img with
          OptionalHeader = { img.OptionalHeader with Directories = dirs }
          KeptLength = dir.RVA }

  /// Returns the image whose checksum the emitter is to work out afresh. A
  /// file is left with the one it came with otherwise, that being the only
  /// way an image nothing has touched can reproduce a file whose checksum
  /// was never right to begin with.
  let updateChecksum (img: Image) = { img with RecomputeChecksum = true }

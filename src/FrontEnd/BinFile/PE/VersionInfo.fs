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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.PE.PEUtils

/// Represents what an image's version resource says it is: the version of the
/// file itself, and of the product it was shipped as a part of. Only a build
/// told to stamps one in, so most images carry no version resource at all.
type VersionInfo =
  { /// The file's own version.
    File: VersionNumber
    /// The version of the product it belongs to.
    Product: VersionNumber }

/// Represents a four-part version number, the way a Windows image records
/// one.
and VersionNumber =
  { /// The first part, which names the generation.
    Major: int
    /// The second.
    Minor: int
    /// The third, which on Windows itself is the build.
    Build: int
    /// The fourth, which servicing raises without the build moving.
    Revision: int }

/// Reads the version resource of a PE image.
[<RequireQualifiedAccess>]
module internal VersionInfo =
  /// The resource type a version resource is, which the specification calls
  /// RT_VERSION.
  let [<Literal>] private VersionType = 16u

  /// What the fixed part of a version resource opens with, which is how it is
  /// told from the strings that follow it.
  let [<Literal>] private Signature = 0xfeef04bdu

  /// How much room the head of a resource directory takes, before its
  /// entries.
  let [<Literal>] private DirectoryHeaderSize = 16

  /// How much room one entry of one takes.
  let [<Literal>] private EntrySize = 8

  /// The bit an entry sets to say that what it points at is another directory
  /// rather than the bytes themselves.
  let [<Literal>] private SubdirectoryBit = 0x80000000u

  /// How much room a resource's data entry takes: where its bytes are, how
  /// many of them, and two words nothing here reads.
  let [<Literal>] private DataEntrySize = 16

  /// How much room the fixed part of a version resource takes.
  let [<Literal>] private FixedPartSize = 0x34

  /// Whether a structure of the given size reads inside the bytes.
  let private fits (bytes: byte[]) at size =
    at >= 0 && size >= 0 && at + size <= bytes.Length

  /// How many entries the directory at the offset has, and how many of those
  /// come before the numbered ones. Only a numbered entry carries the id a
  /// resource type or a language is known by.
  let private entryCount (bytes: byte[]) (reader: IBinReader) at =
    let span = ReadOnlySpan bytes
    let named = int (reader.ReadUInt16(span, at + 12))
    struct (named, named + int (reader.ReadUInt16(span, at + 14)))

  /// Where the entry at the given index points, and whether what it points at
  /// is another directory. Both are counted from the start of the resource
  /// directory rather than of the file.
  let private entryAt (bytes: byte[]) (reader: IBinReader) at i =
    let span = ReadOnlySpan bytes
    let off = at + DirectoryHeaderSize + i * EntrySize
    let key = reader.ReadUInt32(span, off)
    let ptr = reader.ReadUInt32(span, off + 4)
    let isDir = ptr &&& SubdirectoryBit <> 0u
    struct (key, int (ptr &&& ~~~SubdirectoryBit), isDir)

  /// Where the directory at the offset keeps the entry of the given type, or
  /// its first entry of any type when none is asked for -- which is how the
  /// levels below the type are read, an image carrying one version resource
  /// under one name in one language.
  let private tryFindEntry bytes reader at wanted =
    if not (fits bytes at DirectoryHeaderSize) then
      None
    else
      let struct (named, total) = entryCount bytes reader at
      let rec scan i =
        if i >= total || not (fits bytes (at + DirectoryHeaderSize) (i * 8 + 8))
        then
          None
        else
          let struct (key, ptr, isDir) = entryAt bytes reader at i
          match wanted with
          | Some id when i < named || key <> id -> scan (i + 1)
          | _ -> Some(struct (ptr, isDir))
      scan 0

  /// One step down the tree: the subdirectory the matching entry names.
  let private descend bytes reader root at wanted =
    match tryFindEntry bytes reader at wanted with
    | Some(struct (ptr, true)) -> Some(root + ptr)
    | _ -> None

  /// The last step: the data entry the first entry of the directory names.
  let private descendToData bytes reader root at =
    match tryFindEntry bytes reader at None with
    | Some(struct (ptr, false)) -> Some(root + ptr)
    | _ -> None

  /// Where the version resource's data entry sits, walking the three levels a
  /// resource directory has: the type, the name given to a resource of that
  /// type, and the language it was written for.
  let private tryFindDataEntry bytes reader root =
    match descend bytes reader root root (Some VersionType) with
    | None ->
      None
    | Some byName ->
      match descend bytes reader root byName None with
      | None -> None
      | Some byLang -> descendToData bytes reader root byLang

  /// Where the bytes a data entry names sit in the file. The entry names them
  /// by the address the image would load at, not by an offset into the
  /// resource directory like everything above it.
  let private tryFindBytes (bytes: byte[]) (reader: IBinReader) secs at =
    if not (fits bytes at DataEntrySize) then
      None
    else
      let rva = int (reader.ReadUInt32(ReadOnlySpan bytes, at))
      match tryGetRawOffset secs rva with
      | -1 -> None
      | off -> Some off

  /// Where the fixed part of a version block sits: past the key naming it and
  /// the padding that brings what follows to a word boundary. The key is wide
  /// and closed by a NUL, like every string in the block.
  let private fixedPartOf (bytes: byte[]) (reader: IBinReader) at =
    let span = ReadOnlySpan bytes
    let mutable i = at + 6
    while fits bytes i 2 && reader.ReadUInt16(span, i) <> 0us do
      i <- i + 2
    alignUp (i + 2) 4

  /// The version the eight bytes at the offset carry: each half of each word,
  /// the more significant parts first.
  let private numberAt (bytes: byte[]) (reader: IBinReader) at =
    let span = ReadOnlySpan bytes
    let ms = reader.ReadUInt32(span, at)
    let ls = reader.ReadUInt32(span, at + 4)
    { Major = int (ms >>> 16)
      Minor = int (ms &&& 0xffffu)
      Build = int (ls >>> 16)
      Revision = int (ls &&& 0xffffu) }

  /// What the version block at the offset says, or none when what reads there
  /// is not one.
  let private tryReadBlock bytes reader at =
    let fixedAt = fixedPartOf bytes reader at
    if not (fits bytes fixedAt FixedPartSize) then
      None
    elif reader.ReadUInt32(ReadOnlySpan bytes, fixedAt) <> Signature then
      None
    else
      Some
        { File = numberAt bytes reader (fixedAt + 8)
          Product = numberAt bytes reader (fixedAt + 16) }

  /// Returns what the image's version resource says it is, or none for an
  /// image carrying no such resource.
  let tryFind bytes reader secs (hdr: OptionalHeader) =
    let dir = hdr.Directory DirectoryKind.ResourceTable
    match tryGetDirectoryOffset secs dir with
    | Some root when dir.Size > 0 ->
      match tryFindDataEntry bytes reader root with
      | None ->
        None
      | Some entry ->
        match tryFindBytes bytes reader secs entry with
        | None -> None
        | Some at -> tryReadBlock bytes reader at
    | _ ->
      None

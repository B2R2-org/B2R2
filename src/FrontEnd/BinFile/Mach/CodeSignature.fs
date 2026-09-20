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
open System.Security.Cryptography
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile

/// Represents the code signature embedded in a Mach-O file, which names the
/// code, hashes it page by page, and carries the entitlements it is granted.
/// It is what the kernel checks an image against before it runs it.
type internal CodeSignature =
  { /// File offset of the superblob.
    SignOffset: int
    /// Size of the superblob.
    SignSize: uint32
    /// The code directory, which is what a cdhash names.
    CodeDirectory: CodeDirectory
    /// The entitlements plist as it stands, or an empty array when the
    /// signature grants none. A signature of the last few years carries the
    /// same plist DER-encoded as well; this is the XML one.
    Entitlements: byte[] }

/// Represents the code directory of a code signature: the blob naming the
/// code, saying how it is hashed, and holding the hash of every page of it.
and internal CodeDirectory =
  { /// What the signature calls the code, e.g. com.apple.ls.
    Identifier: string
    /// The team the signer belongs to, empty when the signature names none,
    /// as an ad-hoc one does not.
    TeamIdentifier: string
    /// The hash naming this code: the whole code directory hashed and cut to
    /// twenty bytes, which is what every tool prints a cdhash at.
    CDHash: byte[]
    /// The algorithm the hashes use.
    HashType: CodeHashType
    /// How much of the image, from its start, the signature covers. What
    /// follows is the signature itself, which cannot hash itself.
    CodeLimit: uint64
    /// The size of the pages the hashes are taken over. Zero means the code
    /// is hashed whole rather than page by page.
    PageSize: int
    /// What the signature says about how the code is to be run.
    SignFlags: CodeSignFlag }

/// Represents the hash algorithm a code directory names.
and internal CodeHashType =
  /// An algorithm this parser does not know.
  | Unknown = 0
  /// SHA-1, which nothing signed since OS X 10.11 uses on its own.
  | SHA1 = 1
  /// SHA-256.
  | SHA256 = 2
  /// SHA-256 cut to twenty bytes, which a signature carries beside a full
  /// one so that a reader expecting SHA-1 lengths can still read it.
  | SHA256Truncated = 3
  /// SHA-384.
  | SHA384 = 4

/// Represents the flags a code directory carries, which say what the code is
/// allowed and how strictly it is to be held to its signature.
and [<Flags>] internal CodeSignFlag =
  /// The code is valid, which only a running process is marked.
  | CS_VALID = 0x1
  /// Signed by nobody: the signature vouches for the bytes alone.
  | CS_ADHOC = 0x2
  /// A debugger may attach to the process.
  | CS_GET_TASK_ALLOW = 0x4
  /// The code belongs to the installer.
  | CS_INSTALLER = 0x8
  /// Library validation is forced on regardless of the rest.
  | CS_FORCED_LV = 0x10
  /// The process may run invalid pages.
  | CS_INVALID_ALLOWED = 0x20
  /// The signature is to be enforced as the process runs.
  | CS_HARD = 0x100
  /// The process is killed when a page fails to validate.
  | CS_KILL = 0x200
  /// The certificate expiry date is checked.
  | CS_CHECK_EXPIRATION = 0x400
  /// The process is restricted from loading unsigned libraries.
  | CS_RESTRICT = 0x800
  /// The signature is enforced even where it need not be.
  | CS_ENFORCEMENT = 0x1000
  /// Library validation is required.
  | CS_REQUIRE_LV = 0x2000
  /// The entitlements have been validated.
  | CS_ENTITLEMENTS_VALIDATED = 0x4000
  /// The process may write unrestricted NVRAM variables.
  | CS_NVRAM_UNRESTRICTED = 0x8000
  /// The code opts into the hardened runtime.
  | CS_RUNTIME = 0x10000
  /// The linker signed the code rather than codesign(1) did, which is what
  /// an ad-hoc signature on a freshly built arm64 binary is.
  | CS_LINKER_SIGNED = 0x20000

/// <summary>
/// Provides a parser for the code signature of a Mach-O file. Every value a
/// code signing structure holds is big-endian, whichever way round the
/// Mach-O around it is, so none of this can be read with the file's own
/// reader. The signer sits in a CMS blob that this steps over: reading it
/// would take a PKCS#7 and certificate parser, and it says nothing about
/// what the image is or does.
/// </summary>
[<RequireQualifiedAccess>]
module internal CodeSignature =
  /// The reader for everything inside the signature, which is big-endian.
  let private reader = BinReader.Init Endian.Big

  /// CSMAGIC_EMBEDDED_SIGNATURE: the superblob an image embeds.
  let [<Literal>] private SuperBlobMagic = 0xFADE0CC0u

  /// CSMAGIC_CODEDIRECTORY.
  let [<Literal>] private CodeDirMagic = 0xFADE0C02u

  /// CSSLOT_CODEDIRECTORY: the slot holding the code directory.
  let [<Literal>] private CodeDirSlot = 0u

  /// CSSLOT_ENTITLEMENTS: the slot holding the XML entitlements.
  let [<Literal>] private EntitlementsSlot = 5u

  /// The length every tool prints a cdhash at, whichever hash it cuts down.
  let [<Literal>] private CDHashLength = 20

  /// The shortest code directory this can read: the header up to the page
  /// size, rounded out to the scatter offset that follows it.
  let [<Literal>] private MinCodeDirSize = 44

  /// The version from which a code directory carries a team identifier.
  let [<Literal>] private TeamVersion = 0x20200u

  /// The version from which it carries a 64-bit code limit.
  let [<Literal>] private CodeLimit64Version = 0x20300u

  let private chooser = function
    | CodeSign(_, _, c) -> Some c
    | _ -> None

  /// Checks that the superblob the load command names is one the file holds,
  /// so a truncated or corrupt image is reported as bad rather than read
  /// past its own end.
  let private checkBounds (bytes: byte[]) offset size =
    if offset < 0 || size < 12 || offset + size > bytes.Length then
      raise InvalidFileFormatException
    else
      ()

  /// Returns how many blobs of the superblob the file has index entries for,
  /// so a count larger than the blob itself is read as far as it goes.
  let private indexCount (bytes: byte[]) sigOff size =
    let count = int (reader.ReadUInt32(bytes, sigOff + 8))
    min count ((size - 12) / 8) |> max 0

  /// Returns where each blob of the superblob sits, as a slot type and a
  /// file offset. The offsets a superblob gives count from its own start.
  let private readBlobIndex (bytes: byte[]) sigOff count =
    Array.init count (fun i ->
      let entry = sigOff + 12 + i * 8
      let blobOff = reader.ReadUInt32(bytes, entry + 4)
      reader.ReadUInt32(bytes, entry), sigOff + int blobOff)

  /// Returns where the given slot sits, or None when there is no such blob.
  let private tryFindSlot index slot =
    index
    |> Array.tryPick (fun (s, off) -> if s = slot then Some off else None)

  /// Checks that the code directory is a blob the file holds whole and that
  /// it is long enough for the header to be read out of.
  let private isReadableCodeDir (bytes: byte[]) cdOff =
    cdOff >= 0
    && cdOff + MinCodeDirSize <= bytes.Length
    && reader.ReadUInt32(bytes, cdOff) = CodeDirMagic
    && cdOff + int (reader.ReadUInt32(bytes, cdOff + 4)) <= bytes.Length
    && int (reader.ReadUInt32(bytes, cdOff + 4)) >= MinCodeDirSize

  /// Returns the version the code directory can be read at, which is its own
  /// unless the blob is too short for the fields that version claims. Such a
  /// header costs a field rather than a throw.
  let private readableVersion (bytes: byte[]) cdOff cdLen =
    let version = reader.ReadUInt32(bytes, cdOff + 8)
    if version >= CodeLimit64Version && cdLen >= 64 then version
    elif version >= TeamVersion && cdLen >= 52 then TeamVersion
    else 0u

  /// Returns the string the code directory names at the given offset from
  /// its own start. A zero offset, which the team field carries when the
  /// signature names no team, names no string.
  let private readCDString (bytes: byte[]) cdOff strOff =
    if strOff = 0u then ""
    else ByteArray.extractCString bytes (cdOff + int strOff)

  /// Returns the team identifier the code directory names, which only a
  /// version from 0x20200 on has the room for.
  let private readTeamId (bytes: byte[]) cdOff version =
    if version < TeamVersion then ""
    else readCDString bytes cdOff (reader.ReadUInt32(bytes, cdOff + 48))

  let private hashOf hashType (span: ByteSpan) =
    match hashType with
    | CodeHashType.SHA1 -> SHA1.HashData span
    | CodeHashType.SHA256
    | CodeHashType.SHA256Truncated -> SHA256.HashData span
    | CodeHashType.SHA384 -> SHA384.HashData span
    | _ -> [||]

  /// Returns the hash naming the code: the code directory hashed whole by
  /// the algorithm it names, cut to the length a cdhash is printed at.
  let private computeCDHash (bytes: byte[]) cdOff cdLen hashType =
    let hash = hashOf hashType (ReadOnlySpan(bytes, cdOff, cdLen))
    if hash.Length > CDHashLength then hash[..CDHashLength - 1] else hash

  /// Returns how much of the image the signature covers. The 32-bit field
  /// runs out at four gigabytes, so a version from 0x20300 on carries a
  /// 64-bit one to fall back on.
  let private readCodeLimit (bytes: byte[]) cdOff version =
    let limit = reader.ReadUInt32(bytes, cdOff + 32)
    if limit <> 0u || version < CodeLimit64Version then uint64 limit
    else reader.ReadUInt64(bytes, cdOff + 56)

  /// Returns the size of the pages the hashes are taken over, which the
  /// directory gives as a power of two. Zero says the code is hashed whole.
  let private readPageSize (bytes: byte[]) cdOff =
    let log2 = int (reader.ReadUInt8(bytes, cdOff + 39))
    if log2 = 0 then 0 else 1 <<< log2

  /// Parses the code directory at the given offset, which is the blob a
  /// cdhash names and the one blob a superblob cannot do without.
  let private parseCodeDir (bytes: byte[]) cdOff =
    let cdLen = int (reader.ReadUInt32(bytes, cdOff + 4))
    let version = readableVersion bytes cdOff cdLen
    let flags = int (reader.ReadUInt32(bytes, cdOff + 12))
    let identOff = reader.ReadUInt32(bytes, cdOff + 20)
    let raw = int (reader.ReadUInt8(bytes, cdOff + 37))
    let hashType: CodeHashType = LanguagePrimitives.EnumOfValue raw
    { Identifier = readCDString bytes cdOff identOff
      TeamIdentifier = readTeamId bytes cdOff version
      CDHash = computeCDHash bytes cdOff cdLen hashType
      HashType = hashType
      CodeLimit = readCodeLimit bytes cdOff version
      PageSize = readPageSize bytes cdOff
      SignFlags = LanguagePrimitives.EnumOfValue flags }

  /// Returns the plist an entitlements blob holds, which is whatever follows
  /// the magic and the length that every blob of a superblob begins with.
  let private readEntitlements (bytes: byte[]) off =
    if off < 0 || off + 8 > bytes.Length then
      [||]
    else
      let length = int (reader.ReadUInt32(bytes, off + 4))
      if length <= 8 || off + length > bytes.Length then [||]
      else bytes[off + 8..off + length - 1]

  /// Returns the entitlements the given slot holds, or an empty array when
  /// the signature grants none.
  let private toEntitlements bytes slot =
    match slot with
    | Some off -> readEntitlements bytes off
    | None -> [||]

  /// Parses a superblob whose magic has already been read. One holding no
  /// code directory names no code, so it is read as no signature at all.
  let private parseSuperBlob (bytes: byte[]) cmd sigOff size =
    let index = readBlobIndex bytes sigOff (indexCount bytes sigOff size)
    match tryFindSlot index CodeDirSlot with
    | Some cdOff when isReadableCodeDir bytes cdOff ->
      let ents = tryFindSlot index EntitlementsSlot |> toEntitlements bytes
      Some { SignOffset = cmd.BlobOffset
             SignSize = cmd.BlobSize
             CodeDirectory = parseCodeDir bytes cdOff
             Entitlements = ents }
    | _ ->
      None

  /// Parses the code signature of the image, or None when it carries none.
  /// A superblob whose magic this parser does not know names none either:
  /// what such a blob holds says nothing this can read about the code.
  let parse toolBox cmds =
    match Array.tryPick chooser cmds with
    | None ->
      None
    | Some cmd ->
      let bytes = toolBox.Bytes
      let sigOff, size = cmd.BlobOffset, int cmd.BlobSize
      checkBounds bytes sigOff size
      if reader.ReadUInt32(bytes, sigOff) <> SuperBlobMagic then None
      else parseSuperBlob bytes cmd sigOff size

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

open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.PE.PEUtils

/// <summary>
/// Represents every header of a PE file, along with where in the file each of
/// them was read from, which is what an edit of one has to go back to.
/// </summary>
type internal Header =
  { /// The COFF file header.
    CoffHeader: CoffHeader
    /// The optional header, which an object file carries none of.
    OptionalHeader: OptionalHeader option
    /// The CLI header, which only a managed image carries.
    CorHeader: CorHeader option
    /// The section header table.
    SectionHeaders: SectionHeader[]
    /// Where the COFF header begins.
    CoffHeaderOffset: int
    /// Where the optional header begins; -1 for an object file.
    OptionalHeaderOffset: int
    /// Where the section header table begins.
    SectionHeaderTblOffset: int
    /// Where the CLI header begins; -1 for an image carrying none.
    CorHeaderOffset: int }
with
  /// Returns whether the file is an object file, which carries a COFF header
  /// and sections but no optional header to load them by.
  member this.IsCoffOnly with get() = this.OptionalHeader.IsNone

[<RequireQualifiedAccess>]
module internal Header =
  /// The signature a DOS header begins with, which reads "MZ".
  let [<Literal>] private DOSSignature = 0x5a4dus

  /// The signature the headers of an image begin with, which reads "PE\0\0".
  let [<Literal>] private PESignature = 0x00004550u

  /// The signature an anonymous object and an import library begin with,
  /// neither of which is a file read here.
  let [<Literal>] private AnonymousSignature = 0xffffus

  /// Where the DOS header keeps the offset of the PE signature, which the
  /// specification calls e_lfanew.
  let [<Literal>] private SignatureOffsetLocation = 0x3c

  /// Returns whether the file has room at the given offset for that many
  /// bytes.
  let private fits (bytes: byte[]) offset size =
    offset >= 0 && int64 offset + int64 size <= int64 bytes.Length

  let private readUInt16At (bytes: byte[]) (reader: IBinReader) offset =
    if fits bytes offset 2 then reader.ReadUInt16(bs = bytes, offset = offset)
    else raise InvalidFileFormatException

  let private readInt32At (bytes: byte[]) (reader: IBinReader) offset =
    if fits bytes offset 4 then reader.ReadInt32(bs = bytes, offset = offset)
    else raise InvalidFileFormatException

  let private readUInt32At (bytes: byte[]) (reader: IBinReader) offset =
    if fits bytes offset 4 then reader.ReadUInt32(bs = bytes, offset = offset)
    else raise InvalidFileFormatException

  /// Returns whether the file begins the way an object file does. One that is
  /// no image at all is taken for an object, which is what a reader has to
  /// do: an object file carries no signature to know it by. The one shape
  /// ruled out is what an anonymous object and an import library begin with,
  /// neither of them being a file this reads.
  let private isCoffOnly bytes reader =
    let signature = readUInt16At bytes reader 0
    if signature = DOSSignature then false
    elif signature <> 0us then true
    elif readUInt16At bytes reader 2 <> AnonymousSignature then true
    else raise InvalidFileFormatException

  /// Returns where the COFF header of an image begins, which is right past
  /// the signature that e_lfanew points at.
  let private findCoffHeaderOffset bytes reader =
    let offset = readInt32At bytes reader SignatureOffsetLocation
    if readUInt32At bytes reader offset <> PESignature then
      raise InvalidFileFormatException
    else
      offset + 4

  /// Returns the optional header of an image, along with where it begins and
  /// where the section header table that follows it begins. An object file
  /// has neither, and its sections follow the COFF header directly.
  let private parseOptionalHeader bytes reader coffOffset isObj =
    let offset = coffOffset + CoffHeader.Size
    if isObj then
      None, -1, offset
    else
      let hdr = OptionalHeader.parse bytes reader offset
      Some hdr, offset, offset + OptionalHeader.sizeOf hdr.Magic

  /// Returns where the CLI header of a managed image is in the file, or -1
  /// where the image names none or names one no section maps.
  let private findCorHeaderOffset secs (hdr: OptionalHeader) =
    let dir = hdr.Directory DirectoryKind.CorHeaderTable
    if dir.RVA = 0 then
      -1
    else
      tryGetDirectoryOffset secs dir |> Option.defaultValue -1

  /// Returns every header of the given PE file.
  let parse (bytes: byte[]) reader =
    let isObj = isCoffOnly bytes reader
    let coffOffset = if isObj then 0 else findCoffHeaderOffset bytes reader
    let coff = CoffHeader.parse bytes reader coffOffset
    let opt, optOffset, secOffset =
      parseOptionalHeader bytes reader coffOffset isObj
    let secCount = int coff.NumberOfSections
    let secs = SectionHeaders.parse bytes reader secOffset secCount
    let corOffset =
      opt |> Option.map (findCorHeaderOffset secs) |> Option.defaultValue -1
    { CoffHeader = coff
      OptionalHeader = opt
      CorHeader = CorHeader.tryParse bytes reader corOffset
      SectionHeaders = secs
      CoffHeaderOffset = coffOffset
      OptionalHeaderOffset = optOffset
      SectionHeaderTblOffset = secOffset
      CorHeaderOffset = corOffset }

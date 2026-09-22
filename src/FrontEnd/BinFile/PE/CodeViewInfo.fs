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

/// Represents what the CodeView entry of a debug directory says about the PDB
/// an image was built with. The GUID and the age together name one build of
/// it, and the PDB written by that build repeats both.
type internal CodeViewInfo =
  { /// The GUID naming the build, which is what a build ID is here.
    Guid: byte[]
    /// How many times the PDB has been written since it was made, which an
    /// incremental link raises rather than writing a new GUID.
    Age: int
    /// The path the linker wrote the PDB to, as it wrote it.
    PDBPath: string }

[<RequireQualifiedAccess>]
module internal CodeViewInfo =
  /// The debug directory entry kind that names a PDB, which the specification
  /// calls DEBUG_TYPE_CODEVIEW.
  let [<Literal>] private CodeViewType = 2u

  /// The signature of the CodeView record form that carries a GUID, which
  /// reads as "RSDS". It is what every toolchain since VC7 writes; the older
  /// NB10 form names its PDB by a timestamp instead and is not read here.
  let [<Literal>] private Signature = 0x53445352u

  /// The number of bytes one debug directory entry takes on disk.
  let [<Literal>] EntrySize = 28

  /// The number of bytes an RSDS record takes before the path ending it.
  let [<Literal>] private RecordHeaderSize = 24

  /// Returns the path an RSDS record ends with. A path filling the record to
  /// its last byte ends there rather than at a terminator, and the linker
  /// writes it in UTF-8 whatever the code page of the machine it ran on.
  let private readPath (span: ByteSpan) =
    let tail = span.Slice RecordHeaderSize
    let len = tail.IndexOf 0uy
    let len = if len < 0 then tail.Length else len
    Text.Encoding.UTF8.GetString(tail.Slice(0, len))

  /// Returns what the RSDS record at the given file offset says, or none when
  /// no whole record of that form reads there.
  let private tryReadRecord (bytes: byte[]) (reader: IBinReader) offset size =
    let fits = offset >= 0 && offset + size <= bytes.Length
    if size < RecordHeaderSize || not fits then
      None
    else
      let span = ReadOnlySpan(bytes, offset, size)
      if reader.ReadUInt32(span, 0) <> Signature then
        None
      else
        { Guid = span.Slice(4, 16).ToArray()
          Age = reader.ReadInt32(span, 20)
          PDBPath = readPath span } |> Some

  /// Returns the first CodeView record the entries starting at the given
  /// offset name. An entry names its record twice, by address and by file
  /// offset, and the offset is what a reader of the file on disk can follow.
  let rec private findRecord (bytes: byte[]) reader offset count =
    if count = 0 || offset + EntrySize > bytes.Length then
      None
    else
      let span = ReadOnlySpan(bytes, offset, EntrySize)
      let size = (reader: IBinReader).ReadInt32(span, 16)
      let ptr = reader.ReadInt32(span, 24)
      let found =
        if reader.ReadUInt32(span, 12) = CodeViewType then
          tryReadRecord bytes reader ptr size
        else
          None
      match found with
      | Some _ -> found
      | None -> findRecord bytes reader (offset + EntrySize) (count - 1)

  /// Returns what the debug directory of the given image says about the PDB
  /// it was built with, or none for an image that says nothing: one built
  /// without debug information, and one whose entries are all of other kinds.
  let tryFind bytes reader secs (hdr: OptionalHeader) =
    let dir = hdr.Directory DirectoryKind.Debug
    match tryGetDirectoryOffset secs dir with
    | Some offset when dir.Size >= EntrySize ->
      findRecord bytes reader offset (dir.Size / EntrySize)
    | _ ->
      None

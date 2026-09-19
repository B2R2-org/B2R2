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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.FileHelper

/// Represents a note, which is a vendor-defined record that ELF files carry
/// in PT_NOTE segments and SHT_NOTE sections.
type internal Note =
  { /// Vendor that owns the note. The owner alone gives meaning to NoteType,
    /// as every vendor numbers its own notes from one.
    NoteOwner: string
    /// Kind of the note, which only its owner interprets.
    NoteType: uint32
    /// Descriptor of the note, whose layout its owner and its kind decide.
    NoteDesc: byte[] }

/// Represents the kinds of notes that the GNU toolchain writes.
and internal GNUNoteType =
  /// Names the OS and the lowest kernel version that the binary runs on.
  | NT_GNU_ABI_TAG = 1u
  /// Names a synthetic hardware capability list, which Linux never writes.
  | NT_GNU_HWCAP = 2u
  /// Names this particular build, which is what ties it to its debug info.
  | NT_GNU_BUILD_ID = 3u
  /// Names the version of the gold linker that linked the binary.
  | NT_GNU_GOLD_VERSION = 4u
  /// Holds the program properties that the binary asks of its loader.
  | NT_GNU_PROPERTY_TYPE_0 = 5u

/// Represents the kinds of notes that a core dump writes.
and internal CoreNoteType =
  /// Holds the state of one thread, including its general registers.
  | NT_PRSTATUS = 1u
  /// Holds the floating-point registers of one thread.
  | NT_FPREGSET = 2u
  /// Holds facts about the process, such as its name and its arguments.
  | NT_PRPSINFO = 3u
  /// Holds the whole task structure of the process.
  | NT_TASKSTRUCT = 4u
  /// Holds the auxiliary vector that the kernel handed the process.
  | NT_AUXV = 6u
  /// Holds what the kernel knows about the signal that stopped the process.
  | NT_SIGINFO = 0x53494749u
  /// Holds the file-backed memory mappings of the process.
  | NT_FILE = 0x46494c45u

[<RequireQualifiedAccess>]
module internal Notes =
  /// Represents the owner name that the GNU toolchain writes on its notes.
  let [<Literal>] GNUOwner = "GNU"

  /// Represents the owner name that a core dump writes on its own notes.
  let [<Literal>] CoreOwner = "CORE"

  /// Rounds the given size up to the four-byte boundary that a note pads its
  /// name and its descriptor to. The gABI ties the padding to the alignment
  /// of the segment, but every toolchain pads by four even where the segment
  /// asks for eight.
  let private padToFour (n: int64) = (n + 3L) &&& ~~~3L

  /// Reads the owner name, which fills the name field of a note as a
  /// NUL-terminated string. A note that names no owner leaves the field
  /// empty, with no string in it to read.
  let private readOwnerName (span: ByteSpan) offset size =
    if size <= 0 then "" else readCStringOfSize span offset size

  /// Reads the note that starts at the given offset, along with where the
  /// next one starts. A note that reaches past the end of the range is
  /// dropped, and so is every note behind it, since a partial note leaves
  /// nothing to say where the next one begins. A record naming neither an
  /// owner nor a descriptor goes the same way: it carries nothing, and what
  /// reads as one is the padding that alignment leaves between two notes.
  let private tryReadNote (reader: IBinReader) (span: ByteSpan) offset =
    if int64 offset + 12L > int64 span.Length then
      None
    else
      let nameSize = int64 (reader.ReadUInt32(span, offset))
      let descSize = int64 (reader.ReadUInt32(span, offset + 4))
      let descOffset = int64 offset + 12L + padToFour nameSize
      let isEmpty = nameSize = 0L && descSize = 0L
      if isEmpty || descOffset + descSize > int64 span.Length then
        None
      else
        let owner = readOwnerName span (offset + 12) (int nameSize)
        let desc = span.Slice(int descOffset, int descSize).ToArray()
        let noteType = reader.ReadUInt32(span, offset + 8)
        let note = { NoteOwner = owner; NoteType = noteType; NoteDesc = desc }
        Some(note, int (descOffset + padToFour descSize))

  let rec private parseLoop reader (span: ByteSpan) offset acc =
    match tryReadNote reader span offset with
    | Some(note, nextOffset) ->
      parseLoop reader span nextOffset (note :: acc)
    | None ->
      List.rev acc |> List.toArray

  /// Reads every note that the given file range lays out.
  let private parseRange ({ Bytes = bytes } as toolBox) (offset, size) =
    let length = uint64 bytes.Length
    if offset > length || size > length - offset then
      [||]
    else
      let span = ReadOnlySpan(bytes, int offset, int size)
      parseLoop toolBox.Reader span 0 []

  /// Returns where the notes sit in the file. A PT_NOTE segment names them in
  /// a linked binary and in a core dump, and an SHT_NOTE section names them
  /// in a relocatable object, which has no segments at all. A linked binary
  /// has both, naming the same bytes, so a section counts only when no
  /// segment already covers it.
  let private findRanges shdrs phdrs =
    let segments =
      phdrs
      |> Array.filter (fun ph -> ph.PHType = ProgramHeaderType.PT_NOTE)
      |> Array.map (fun ph -> ph.PHOffset, ph.PHFileSize)
    let isCovered (offset, size) =
      segments
      |> Array.exists (fun (o, s) -> offset >= o && offset + size <= o + s)
    shdrs
    |> Array.filter (fun s -> s.SecType = SectionType.SHT_NOTE)
    |> Array.map (fun s -> s.SecOffset, s.SecSize)
    |> Array.filter (isCovered >> not)
    |> Array.append segments

  /// Reads every note that the file carries.
  let parse toolBox shdrs phdrs =
    findRanges shdrs phdrs |> Array.collect (parseRange toolBox)

  let private isNote owner noteType (note: Note) =
    note.NoteOwner = owner && note.NoteType = noteType

  /// Returns the note that the given owner numbers with the given kind.
  let tryFind owner noteType notes = Array.tryFind (isNote owner noteType) notes

  /// Returns the build ID that names this particular build, which the
  /// NT_GNU_BUILD_ID note carries, or an empty array when there is no such
  /// note.
  let findBuildId notes =
    match tryFind GNUOwner (uint32 GNUNoteType.NT_GNU_BUILD_ID) notes with
    | Some note -> note.NoteDesc
    | None -> [||]

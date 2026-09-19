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

/// Represents one file-backed memory mapping that a core dump records in its
/// NT_FILE note, which is what says at which address the dump had loaded a
/// binary of its own.
type internal CoreMapping =
  { /// Address at which the mapping starts.
    MappingStart: Addr
    /// Address right past the end of the mapping.
    MappingEnd: Addr
    /// Offset into the mapped file at which the mapping begins.
    MappingFileOffset: uint64
    /// Path of the mapped file.
    MappingPath: string }

/// Represents the state of one thread that a core dump records in its
/// NT_PRSTATUS note, one note per thread.
and internal ProcessStatus =
  { /// Signal that stopped the thread.
    CurrentSignal: int
    /// ID of the process.
    ProcessID: int
    /// ID of the parent process.
    ParentProcessID: int
    /// Everything the note holds past its fixed prefix: the block of general
    /// registers, then the flag that says whether floating-point registers
    /// follow, then the padding that the alignment of the structure adds.
    /// Splitting it further takes the register layout of the architecture,
    /// which every ABI lays out its own way.
    RegisterBlock: byte[] }

[<RequireQualifiedAccess>]
module internal CoreNotes =
  let private readWord reader cls (desc: byte[]) offset =
    readUIntByWordSize (ReadOnlySpan desc) reader cls offset

  /// Returns how many mappings the note says it holds, bounded by what the
  /// descriptor has room for. A count larger than that is nonsense, and the
  /// offsets computed from it would overflow.
  let private readMappingCount reader cls (desc: byte[]) =
    let wordSize = WordSize.toByteWidth cls
    if desc.Length < wordSize * 2 then
      0
    else
      let count = readWord reader cls desc 0
      if count > uint64 desc.Length then 0 else int count

  /// Reads the paths of the mappings, which follow the addresses as one run
  /// of NUL-terminated strings, in the order the addresses come in.
  let rec private readPathLoop (desc: byte[]) offset count acc =
    if count = 0 || offset >= desc.Length then
      List.rev acc |> List.toArray
    else
      let path = ByteArray.extractCString desc offset
      let next = offset + path.Length + 1
      readPathLoop desc next (count - 1) (path :: acc)

  /// Builds the mappings out of the block of addresses and the paths that
  /// follow it. Each mapping counts its file offset in pages.
  let private toMappings reader cls (desc: byte[]) pageSize paths =
    let wordSize = WordSize.toByteWidth cls
    paths
    |> Array.mapi (fun i path ->
      let offset = wordSize * (2 + i * 3)
      let fileOffset = readWord reader cls desc (offset + wordSize * 2)
      { MappingStart = readWord reader cls desc offset
        MappingEnd = readWord reader cls desc (offset + wordSize)
        MappingFileOffset = fileOffset * pageSize
        MappingPath = path })

  /// Reads the mapping table, which is a count and a page size, then one
  /// triple of words per mapping, then all of their paths in the same order.
  let private readMappings toolBox (desc: byte[]) =
    let reader, cls = toolBox.Reader, toolBox.Header.Class
    let wordSize = WordSize.toByteWidth cls
    let count = readMappingCount reader cls desc
    let pathOffset = wordSize * (2 + count * 3)
    if pathOffset > desc.Length then
      [||]
    else
      let pageSize = readWord reader cls desc wordSize
      readPathLoop desc pathOffset count []
      |> toMappings reader cls desc pageSize

  /// Reads the file-backed memory mappings that the NT_FILE note of a core
  /// dump records, or none when the file carries no such note.
  let parseMappings toolBox notes =
    let fileNote = uint32 CoreNoteType.NT_FILE
    match Notes.tryFind Notes.CoreOwner fileNote notes with
    | Some note -> readMappings toolBox note.NoteDesc
    | None -> [||]

  /// Returns how wide the fixed prefix of a prstatus note is, which is what
  /// comes before the registers: the signal information, the two signal
  /// masks, the four process IDs, and the four CPU times.
  let private prefixSize cls = selectByWordSize cls 72 112

  let private isStatusNote prefix note =
    note.NoteOwner = Notes.CoreOwner
    && note.NoteType = uint32 CoreNoteType.NT_PRSTATUS
    && note.NoteDesc.Length >= prefix

  let private readStatus toolBox (desc: byte[]) =
    let reader, cls = toolBox.Reader, toolBox.Header.Class
    let span = ReadOnlySpan desc
    let pidOffset = selectByWordSize cls 24 32
    { CurrentSignal = int (reader.ReadUInt16(span, 12))
      ProcessID = reader.ReadInt32(span, pidOffset)
      ParentProcessID = reader.ReadInt32(span, pidOffset + 4)
      RegisterBlock = desc[prefixSize cls..] }

  /// Reads the thread states that the NT_PRSTATUS notes of a core dump
  /// record. A note too short to hold the fixed prefix records no state that
  /// can be read, so it is left out.
  let parseStatuses toolBox notes =
    let prefix = prefixSize toolBox.Header.Class
    notes
    |> Array.filter (isStatusNote prefix)
    |> Array.map (fun note -> readStatus toolBox note.NoteDesc)

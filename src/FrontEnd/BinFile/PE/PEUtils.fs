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

module internal B2R2.FrontEnd.BinFile.PE.PEUtils

open System
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

/// Returns the value rounded up to the next multiple of the alignment.
let alignUp (value: int) alignment =
  if alignment <= 1 then value
  else (value + alignment - 1) / alignment * alignment

/// Some PE files have a section header indicating that the corresponding
/// section's size is zero even if it contains actual data, i.e.,
/// sHdr.VirtualSize = 0, but sHdr.SizeOfRawData <> 0. Thus, we should use this
/// function to get the size of sections.
let getVirtualSectionSize (sec: SectionHeader) =
  let virtualSize = sec.VirtualSize
  if virtualSize = 0 then sec.SizeOfRawData else virtualSize

/// The section the last lookup settled on. Reading an image walks its RVAs
/// in the order the sections lay them out, so the answer is nearly always the
/// one just given, and trying it first turns a scan of the whole table into a
/// single test. It is a hint and never an answer: it is taken only where it
/// passes the very test a scan would apply to it, so a stale one -- left by
/// another image, or by a read that jumped elsewhere -- costs a bounds check
/// and nothing else.
let mutable private lastHit = 0

/// Returns whether the given section reaches the given RVA, by however far
/// the given function says a section reaches.
let inline private reaches ([<InlineIfLambda>] reach) (s: SectionHeader) rva =
  s.VirtualAddress <= rva && rva < s.VirtualAddress + reach s

/// Returns the index of the first section that reaches the given RVA, or -1
/// where none of them does. The scan is written out rather than folded so
/// that it allocates nothing: it is what every read of an RVA begins with,
/// and reading the exception data of one image alone begins hundreds of
/// thousands of them.
let inline private scanIndexBy ([<InlineIfLambda>] reach) secs rva =
  let mutable i = 0
  let mutable found = -1
  while found < 0 && i < Array.length secs do
    if reaches reach secs[i] rva then found <- i else i <- i + 1
  found

/// Returns the index of the section that reaches the given RVA, by however
/// far the given function says a section reaches, or -1 where none of them
/// does. Sections a loader accepts do not overlap, so the one the hint names
/// where it holds is the one a scan of the table would have found.
let inline private findIndexBy ([<InlineIfLambda>] reach) secs rva =
  let hint = lastHit
  if hint < Array.length secs && reaches reach secs[hint] rva then
    hint
  else
    let found = scanIndexBy reach secs rva
    if found >= 0 then lastHit <- found else ()
    found

/// <summary>
/// Returns the index of the section a loader maps the given RVA into, or -1
/// where no section does. How far a section reaches in memory is what its
/// virtual size says, which is the room a loader gives it.
/// </summary>
let findContainingSectionIndex secs rva =
  findIndexBy _.VirtualSize secs rva

/// <summary>
/// Returns the index of the section whose bytes in the file the given RVA
/// reads, or -1 where no section holds bytes for it. This is the one to use
/// where the bytes on disk are what is wanted, a section of an object file
/// being free to take up less of the file than it does of memory.
/// </summary>
let findMappedSectionIndex secs rva =
  findIndexBy _.SizeOfRawData secs rva

/// Returns the index of the section the given RVA belongs to, by what the
/// loader maps first and by what the file holds where that finds nothing.
let findSectionIndex secs rva =
  let idx = findContainingSectionIndex secs rva
  if idx < 0 then findMappedSectionIndex secs rva else idx

/// Returns the file offset the given data directory reads at, or none where
/// no section maps the address it names.
let tryGetDirectoryOffset secs (dir: DataDirectory) =
  match findContainingSectionIndex secs dir.RVA with
  | -1 ->
    None
  | idx ->
    let sec: SectionHeader = secs[idx]
    Some(dir.RVA - sec.VirtualAddress + sec.PointerToRawData)

/// Returns the file offset at which the given RVA reads, or -1 where no
/// section holds bytes for it. Whether an RVA reads anywhere and where it
/// reads are the one scan of the section table, so a caller that has an
/// answer for either asks this once rather than asking the two in turn.
let tryGetRawOffset secs rva =
  match findMappedSectionIndex secs rva with
  | -1 ->
    -1
  | idx ->
    let sHdr: SectionHeader = secs[idx]
    rva + sHdr.PointerToRawData - sHdr.VirtualAddress

/// Returns the file offset at which the given RVA reads. An RVA no section
/// maps names no byte of the file, which is a fact about the file rather than
/// an index to read on with, so it raises rather than indexing past the table.
let getRawOffset secs rva =
  match tryGetRawOffset secs rva with
  | -1 -> raise InvalidFileFormatException
  | offset -> offset

let readStr secs (bytes: byte[]) rva =
  if rva = 0 then ""
  else readCString (ReadOnlySpan bytes) (getRawOffset secs rva)

let inline addrFromRVA baseAddr rva = uint64 rva + baseAddr

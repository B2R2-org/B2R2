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

/// <summary>
/// Returns the index of the section a loader maps the given RVA into, or -1
/// where no section does. How far a section reaches in memory is what its
/// virtual size says, which is the room a loader gives it.
/// </summary>
let findContainingSectionIndex (secs: SectionHeader[]) rva =
  secs
  |> Array.tryFindIndex (fun s ->
    s.VirtualAddress <= rva && rva < s.VirtualAddress + s.VirtualSize)
  |> Option.defaultValue -1

/// <summary>
/// Returns the index of the section whose bytes in the file the given RVA
/// reads, or -1 where no section holds bytes for it. This is the one to use
/// where the bytes on disk are what is wanted, a section of an object file
/// being free to take up less of the file than it does of memory.
/// </summary>
let findMappedSectionIndex (secs: SectionHeader[]) rva =
  secs
  |> Array.tryFindIndex (fun s ->
    s.VirtualAddress <= rva && rva < s.VirtualAddress + s.SizeOfRawData)
  |> Option.defaultValue -1

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

/// Returns the file offset at which the given RVA reads. An RVA no section
/// maps names no byte of the file, which is a fact about the file rather than
/// an index to read on with, so it raises rather than indexing past the table.
let getRawOffset secs rva =
  match findMappedSectionIndex secs rva with
  | -1 ->
    raise InvalidFileFormatException
  | idx ->
    let sHdr: SectionHeader = secs[idx]
    rva + sHdr.PointerToRawData - sHdr.VirtualAddress

let readStr secs (bytes: byte[]) rva =
  if rva = 0 then ""
  else readCString (ReadOnlySpan bytes) (getRawOffset secs rva)

let inline addrFromRVA baseAddr rva = uint64 rva + baseAddr

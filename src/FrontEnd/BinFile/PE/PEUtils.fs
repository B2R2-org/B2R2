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
open System.Reflection.PortableExecutable
open B2R2.FrontEnd.BinFile.FileHelper

/// <summary>
/// This is equivalent to GetContainingSectionIndex function except that we are
/// using our own section header array here. This should be used instead of
/// GetContainingSectionIndex when analyzing binaries that contain sections
/// whose file size is less than its memory size, e.g., COFF binaries.
/// </summary>
let findMappedSectionIndex (secs: SectionHeader[]) rva =
  secs
  |> Array.tryFindIndex (fun s ->
    s.VirtualAddress <= rva && rva < s.VirtualAddress + s.SizeOfRawData)
  |> Option.defaultValue -1

let findSectionIndex (hdrs: PEHeaders) secs rva =
  let idx = hdrs.GetContainingSectionIndex rva
  if idx < 0 then findMappedSectionIndex secs rva
  else idx

let getRawOffset secs rva =
  let idx = findMappedSectionIndex secs rva
  let sHdr = secs[idx]
  rva + sHdr.PointerToRawData - sHdr.VirtualAddress

let readStr secs (bytes: byte[]) rva =
  if rva = 0 then ""
  else readCString (ReadOnlySpan bytes) (getRawOffset secs rva)

let inline addrFromRVA baseAddr rva = uint64 rva + baseAddr

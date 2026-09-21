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

module internal B2R2.FrontEnd.BinFile.PE.LoadConfig

open B2R2
open B2R2.FrontEnd.BinFile.FileHelper
open B2R2.FrontEnd.BinFile.PE.Helper
open B2R2.FrontEnd.BinFile.PE.PEUtils

/// Where the 32-bit load configuration keeps the SafeSEH handler table, the
/// count beside it, the Control Flow Guard function table, the count beside
/// that, and the guard flags.
let private offsets32 = 0x40, 0x44, 0x50, 0x54, 0x58

/// The same for the 64-bit form, whose pointer fields are twice as wide.
let private offsets64 = 0x60, 0x68, 0x80, 0x88, 0x90

/// Returns where the load configuration sits in the file and how far it
/// reaches, or none where the file names none or names one landing nowhere.
/// The structure carries its own size, which is what says which of its
/// fields a given build actually wrote.
let private tryFindLoadConfig pe =
  match pe.Header.OptionalHeader with
  | None ->
    None
  | Some hdr ->
    let dir = hdr.Directory DirectoryKind.LoadConfigTable
    let rva = dir.RVA
    if dir.Size = 0 || findMappedSectionIndex pe.SectionHeaders rva = -1 then
      None
    else
      Some(getRawOffset pe.SectionHeaders rva)

/// Reads a table of function RVAs, which both the SafeSEH table and the
/// guard function table are. The guard table pads every entry with as many
/// bytes as the guard flags ask for, so the stride is given rather than
/// assumed. The table is named by an address the image would load at, so it
/// is the preferred base that turns it back into an RVA, not the base the
/// file was opened with.
let private readFunctionTable (bytes: byte[]) pe tableVA count stride =
  let imageBase = getImageBase pe
  let secs = pe.SectionHeaders
  if tableVA <= imageBase || count <= 0UL || count > 0x100000UL then
    [||]
  else
    let rva = int (tableVA - imageBase)
    let last = rva + (int count - 1) * stride
    if findMappedSectionIndex secs rva = -1
      || findMappedSectionIndex secs last = -1 then
      [||]
    else
      let start = getRawOffset secs rva
      [| for i in 0 .. int count - 1 do
           let entry = pe.BinReader.ReadInt32(bytes, start + i * stride)
           if entry <> 0 then addrFromRVA pe.BaseAddr entry else () |]

/// Reads one pointer-sized field of the load configuration, which is what
/// both of its tables are named by.
let private readPtr (bytes: byte[]) pe offset =
  readUIntByWordSize (System.ReadOnlySpan bytes) pe.BinReader pe.WordSize offset

/// Returns the addresses the load configuration vouches for as functions:
/// the exception handlers an x86 image lists under SafeSEH, and the call
/// targets a Control Flow Guard image lists for the loader to check against.
/// Both are tables the loader reads as addresses of functions, so each entry
/// starts one, and nothing else in the file need name it.
let getFunctionAddresses bytes pe =
  match tryFindLoadConfig pe with
  | None ->
    [||]
  | Some offset ->
    let sehTbl, sehCnt, guardTbl, guardCnt, guardFlags =
      if pe.WordSize = WordSize.Bit32 then offsets32 else offsets64
    let size = pe.BinReader.ReadInt32(bs = bytes, offset = offset)
    let width = WordSize.toByteWidth pe.WordSize
    let handlers =
      if size < sehCnt + width then
        [||]
      else
        let table = readPtr bytes pe (offset + sehTbl)
        readFunctionTable bytes pe table (readPtr bytes pe (offset + sehCnt)) 4
    let guarded =
      if size < guardFlags + 4 then
        [||]
      else
        let flags = pe.BinReader.ReadInt32(bytes, offset + guardFlags)
        let stride = 4 + ((flags >>> 28) &&& 0xF)
        let table = readPtr bytes pe (offset + guardTbl)
        let count = readPtr bytes pe (offset + guardCnt)
        readFunctionTable bytes pe table count stride
    Array.append handlers guarded

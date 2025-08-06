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
open System.Reflection.PortableExecutable
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.FileHelper
open B2R2.FrontEnd.BinFile.PE.PEUtils

/// Represents a collection of imported symbols in a PE file, which is located
/// at the .idata section.
type ImportedSymbolStore = Map<Addr, ImportedSymbol>

/// Represents an imported symbol.
and ImportedSymbol =
  /// Import by ordinal.
  | ByOrdinal of ordinal: int16 * dllname: string
  /// Import by name.
  | ByName of hint: int16 * funname: string * dllname: string

module internal ImportedSymbolStore =
  let private parseImportDirectoryTblAux bs reader secs entrySize rva readFn =
    if rva = 0 then [||]
    else
      let rec loop acc offset =
        let tbl = readFn bs reader secs offset
        if IDTEntry.IsNull tbl then acc
        else loop (tbl :: acc) (offset + entrySize)
      getRawOffset secs rva |> loop [] |> List.rev |> List.toArray

  let private readIDTEntry (bs: byte[]) (reader: IBinReader) secs pos =
    { ImportLookupTableRVA = reader.ReadInt32(bs, pos)
      ForwarderChain = reader.ReadInt32(bs, pos + 8)
      ImportDLLName = reader.ReadInt32(bs, pos + 12) |> readStr secs bs
      ImportAddressTableRVA = reader.ReadInt32(bs, pos + 16)
      DelayLoad = false }

  let private readDelayLoadIDTEntry (bs: byte[]) (reader: IBinReader) secs pos =
    { ImportLookupTableRVA = reader.ReadInt32(bs, pos + 16)
      ForwarderChain = 0
      ImportDLLName = reader.ReadInt32(bs, pos + 4) |> readStr secs bs
      ImportAddressTableRVA = reader.ReadInt32(bs, pos + 12)
      DelayLoad = true }

  let private parseIDT bytes reader (headers: PEHeaders) secs =
    let rva = headers.PEHeader.ImportTableDirectory.RelativeVirtualAddress
    parseImportDirectoryTblAux bytes reader secs 20 rva readIDTEntry

  let private parseDelayLoadIDT bytes reader (headers: PEHeaders) secs =
    let rva = headers.PEHeader.DelayImportTableDirectory.RelativeVirtualAddress
    parseImportDirectoryTblAux bytes reader secs 32 rva readDelayLoadIDTEntry

  let private parseILTEntry bytes (reader: IBinReader) secs idt mask rva =
    let dllname = idt.ImportDLLName
    if rva &&& mask <> 0UL then
      ByOrdinal(uint16 rva |> int16, dllname)
    else
      let rva = 0x7fffffffUL &&& rva |> int
      let hint = reader.ReadInt16(bs = bytes, offset = getRawOffset secs rva)
      let funname = readStr secs bytes (rva + 2)
      ByName(hint, funname, dllname)

  let private computeRVAMaskForILT wordSize =
    if wordSize = WordSize.Bit32 then 0x80000000UL
    else 0x8000000000000000UL

  let private parseILT (bytes: byte[]) reader secs wordSize map idt =
    let skip = if wordSize = WordSize.Bit32 then 4 else 8
    let mask = computeRVAMaskForILT wordSize
    let rec loop map rvaOffset pos =
      let rva = readUIntByWordSize (ReadOnlySpan bytes) reader wordSize pos
      if rva = 0UL then map
      else
        let entry = parseILTEntry bytes reader secs idt mask rva
        let map = Map.add (idt.ImportAddressTableRVA + rvaOffset) entry map
        loop map (rvaOffset + skip) (pos + skip)
    if idt.ImportLookupTableRVA <> 0 then idt.ImportLookupTableRVA
    else idt.ImportAddressTableRVA
    |> getRawOffset secs
    |> loop map 0

  let parse bytes reader (headers: PEHeaders) secs wordSize =
    let mainImportTbl = parseIDT bytes reader headers secs
    let delayImportTbl = parseDelayLoadIDT bytes reader headers secs
    Array.append mainImportTbl delayImportTbl
    |> Array.toList
    |> List.fold (parseILT bytes reader secs wordSize) Map.empty

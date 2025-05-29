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

open B2R2

/// Each entry in the export address table is a field that uses one of two
/// formats: ExportRVA and ForwarderRVA.
type private EATEntry =
  /// The address of the exported symbol when loaded into memory, relative to
  /// the image base. For example, the address of an exported function.
  | ExportRVA of int
  /// The pointer to a null-terminated ASCII string in the export section. This
  /// string must be within the range that is given by the export table data
  /// directory entry.
  | ForwarderRVA of int

[<AutoOpen>]
module private ExportedSymbolStore =
  open System
  open System.Reflection.PortableExecutable
  open B2R2.Collections
  open B2R2.FrontEnd.BinLifter
  open B2R2.FrontEnd.BinFile.PE.PEUtils

  let readExportDirectoryTable bs (reader: IBinReader) tbl secs =
    { ExportDLLName = readStr secs bs (reader.ReadInt32 (span=tbl, offset=12))
      OrdinalBase = reader.ReadInt32 (tbl, 16)
      AddressTableEntries = reader.ReadInt32 (tbl, 20)
      NumNamePointers = reader.ReadInt32 (tbl, 24)
      ExportAddressTableRVA = reader.ReadInt32 (tbl, 28)
      NamePointerRVA = reader.ReadInt32 (tbl, 32)
      OrdinalTableRVA = reader.ReadInt32 (tbl, 36) }

  let inline getEATEntry (lowerBound, upperBound) rva =
    if rva < lowerBound || rva > upperBound then ExportRVA rva
    else ForwarderRVA rva

  let parseEAT bytes (reader: IBinReader) secs range edt =
    match edt.ExportAddressTableRVA with
    | 0 -> [||]
    | rva ->
      let offset = getRawOffset secs rva
      let span = ReadOnlySpan (bytes, offset, edt.AddressTableEntries * 4)
      let addrTbl = Array.zeroCreate edt.AddressTableEntries
      for i = 0 to edt.AddressTableEntries - 1 do
        let rva = reader.ReadInt32 (span, i * 4)
        addrTbl[i] <- getEATEntry range rva
      addrTbl

  /// Parse Export Name Pointer Table (ENPT).
  let parseENPT (bytes: byte[]) (reader: IBinReader) secs edt =
    let rec loop acc cnt pos1 pos2 =
      if cnt = 0 then acc
      else
        let rva = reader.ReadInt32 (bytes, pos1)
        let str = readStr secs bytes rva
        let ord = reader.ReadInt16 (bytes, pos2)
        loop ((str, ord) :: acc) (cnt - 1) (pos1 + 4) (pos2 + 2)
    if edt.NamePointerRVA = 0 then []
    else
      let offset1 = edt.NamePointerRVA |> getRawOffset secs
      let offset2 = edt.OrdinalTableRVA |> getRawOffset secs
      loop [] edt.NumNamePointers offset1 offset2

  /// Decide the name of an exported address. The address may have been exported
  /// only with ordinal, and does not have a corresponding name in export name
  /// pointer table. In such case, consider its name as "#<Ordinal>".
  let decideNameWithTable nameTbl ordBase idx =
    match List.tryFind (fun (_, ord) -> int16 idx = ord) nameTbl with
    | None -> sprintf "#%d" (int16 idx + ordBase) // Exported with an ordinal.
    | Some (name, _) -> name // ENTP has a corresponding name for this entry.

  let decodeForwardInfo (str: string) =
    let strInfo = str.Split('.')
    let dllName, funcName = strInfo[0], strInfo[1]
    (dllName, funcName)

  let buildExportTable bytes reader baseAddr secs range edt =
    let addrTbl = parseEAT bytes reader secs range edt
    let nameTbl = parseENPT bytes reader secs edt
    let ordinalBase = int16 edt.OrdinalBase
    let folder (expMap, forwMap) idx = function
      | ExportRVA rva ->
        let addr = addrFromRVA baseAddr rva
        let name = decideNameWithTable nameTbl ordinalBase idx
        let expMap =
          if not (Map.containsKey addr expMap) then Map.add addr [name] expMap
          else Map.add addr (name :: Map.find addr expMap) expMap
        expMap, forwMap
      | ForwarderRVA rva ->
        let name = decideNameWithTable nameTbl ordinalBase idx
        let forwardStr = readStr secs bytes rva
        let forwardInfo = decodeForwardInfo forwardStr
        let forwMap = Map.add name forwardInfo forwMap
        expMap, forwMap
    Array.foldi folder (Map.empty, Map.empty) addrTbl |> fst

  let parse baseAddr bytes reader (headers: PEHeaders) secs =
    match headers.PEHeader.ExportTableDirectory.RelativeVirtualAddress with
    | 0 -> Map.empty, Map.empty
    | rva ->
      let size = headers.PEHeader.ExportTableDirectory.Size
      let range = (rva, rva + size)
      let offset = getRawOffset secs rva
      let tbl = ReadOnlySpan (bytes, offset, size)
      readExportDirectoryTable bytes reader tbl secs
      |> buildExportTable bytes reader baseAddr secs range

/// Represents the exported symbols in a PE file.
type ExportedSymbolStore private (exportMap, forwardMap) =

  new () =
    ExportedSymbolStore (Map.empty, Map.empty)

  new (baseAddr, bytes, reader, hdrs, secs) =
    let exportMap, forwardMap = parse baseAddr bytes reader hdrs secs
    ExportedSymbolStore (exportMap, forwardMap)

  /// Returns the addresses of all exported symbols.
  member _.Addresses with get () = exportMap.Keys

  /// Returns the number of exported symbols.
  member _.Count with get () = exportMap.Count

  /// Returns the exported symbols as a map from address to symbol names.
  member _.Exports with get () = exportMap

  /// Returns the forwarded symbols as a map from forward target name to
  /// a tuple of (binary name, function name).
  member _.Forwards with get () = forwardMap

  /// Tries to find exported symbol name(s) by the given address.
  member _.TryFind (addr: Addr) =
    Map.tryFind addr exportMap

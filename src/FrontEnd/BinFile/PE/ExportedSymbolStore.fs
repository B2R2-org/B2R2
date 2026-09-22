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
  open System.Collections.Generic
  open B2R2.Collections
  open B2R2.FrontEnd.BinLifter
  open B2R2.FrontEnd.BinFile.PE.PEUtils

  let readExportDirectoryTable bs (reader: IBinReader) tbl secs =
    { ExportDLLName = readStr secs bs (reader.ReadInt32(span = tbl,
                                                        offset = 12))
      OrdinalBase = reader.ReadInt32(tbl, 16)
      AddressTableEntries = reader.ReadInt32(tbl, 20)
      NumNamePointers = reader.ReadInt32(tbl, 24)
      ExportAddressTableRVA = reader.ReadInt32(tbl, 28)
      NamePointerRVA = reader.ReadInt32(tbl, 32)
      OrdinalTableRVA = reader.ReadInt32(tbl, 36) }

  let inline getEATEntry (lowerBound, upperBound) rva =
    if rva < lowerBound || rva > upperBound then ExportRVA rva
    else ForwarderRVA rva

  let parseEAT bytes (reader: IBinReader) secs range edt =
    match edt.ExportAddressTableRVA with
    | 0 ->
      [||]
    | rva ->
      let offset = getRawOffset secs rva
      let span = ReadOnlySpan(bytes, offset, edt.AddressTableEntries * 4)
      let addrTbl = Array.zeroCreate edt.AddressTableEntries
      for i = 0 to edt.AddressTableEntries - 1 do
        let rva = reader.ReadInt32(span, i * 4)
        addrTbl[i] <- getEATEntry range rva
      addrTbl

  /// Parses the Export Name Pointer Table (ENPT) into the name each ordinal
  /// goes under, which is what reading an entry of the export address table
  /// takes. It is read back an entry at a time, so it is kept by ordinal
  /// rather than walked: a table naming every one of the thousands of
  /// functions a library exports would otherwise be walked once per function.
  /// Two names of one ordinal is an alias export, and the last of them the
  /// table lists is the one kept, there being one name to give the one
  /// address the two of them share.
  let parseENPT (bytes: byte[]) (reader: IBinReader) secs edt =
    let names = Dictionary<int16, string>()
    let rec loop cnt pos1 pos2 =
      if cnt = 0 then
        names
      else
        let rva = reader.ReadInt32(bytes, pos1)
        let str = readStr secs bytes rva
        let ord = reader.ReadInt16(bytes, pos2)
        names[ord] <- str
        loop (cnt - 1) (pos1 + 4) (pos2 + 2)
    if edt.NamePointerRVA = 0 then
      names
    else
      let offset1 = edt.NamePointerRVA |> getRawOffset secs
      let offset2 = edt.OrdinalTableRVA |> getRawOffset secs
      loop edt.NumNamePointers offset1 offset2

  /// Decide the name of an exported address. The address may have been exported
  /// only with ordinal, and does not have a corresponding name in export name
  /// pointer table. In such case, consider its name as "[<Ordinal>]".
  let decideNameWithTable (nameTbl: Dictionary<int16, string>) ordBase idx =
    match nameTbl.TryGetValue(int16 idx) with
    | false, _ -> $"[{(int16 idx + ordBase)}]" (* Exported with an ordinal. *)
    | true, name -> name (* ENPT has a corresponding name for this entry. *)

  /// Parts a forwarder string into the library it names and the function it
  /// names there. The last dot is what parts them, a library name being free
  /// to carry dots of its own where a function name is not. A string with no
  /// dot at all names no library, so there is nothing to forward to.
  let decodeForwardInfo (str: string) =
    match str.LastIndexOf '.' with
    | -1 -> None
    | idx -> Some(str.Substring(0, idx), str.Substring(idx + 1))

  let buildExportTable bytes reader baseAddr secs range edt =
    let addrTbl = parseEAT bytes reader secs range edt
    let nameTbl = parseENPT bytes reader secs edt
    let ordinalBase = int16 edt.OrdinalBase
    let folder (expMap, forwMap) idx = function
      | ExportRVA rva ->
        let addr = addrFromRVA baseAddr rva
        let name = decideNameWithTable nameTbl ordinalBase idx
        let expMap =
          if not (Map.containsKey addr expMap) then Map.add addr [ name ] expMap
          else Map.add addr (name :: Map.find addr expMap) expMap
        expMap, forwMap
      | ForwarderRVA rva ->
        let name = decideNameWithTable nameTbl ordinalBase idx
        let forwardStr = readStr secs bytes rva
        match decodeForwardInfo forwardStr with
        | Some forwardInfo -> expMap, Map.add name forwardInfo forwMap
        | None -> expMap, forwMap
    Array.foldi folder (Map.empty, Map.empty) addrTbl

  let parse baseAddr bytes reader (hdr: OptionalHeader) secs =
    let dir = hdr.Directory DirectoryKind.ExportTable
    match dir.RVA with
    | 0 ->
      "", Map.empty, Map.empty
    | rva ->
      let size = dir.Size
      let range = (rva, rva + size)
      let offset = getRawOffset secs rva
      let tbl = ReadOnlySpan(bytes, offset, size)
      let edt = readExportDirectoryTable bytes reader tbl secs
      let build = buildExportTable bytes reader baseAddr secs range
      let exports, forwards = build edt
      edt.ExportDLLName, exports, forwards

/// Represents the exported symbols in a PE file.
type internal ExportedSymbolStore private(dllName, exportMap, forwardMap) =

  new() = ExportedSymbolStore("", Map.empty, Map.empty)

  new(baseAddr, bytes, reader, hdr, secs) =
    let dllName, exports, forwards = parse baseAddr bytes reader hdr secs
    ExportedSymbolStore(dllName, exports, forwards)

  /// Returns the name the export directory gives this image, which is what an
  /// import of it names, or an empty string where it exports nothing.
  member _.DLLName with get(): string = dllName

  /// Returns the addresses of all exported symbols.
  member _.Addresses with get() = exportMap.Keys

  /// Returns the number of exported symbols.
  member _.Count with get() = exportMap.Count

  /// Returns the exported symbols as a map from address to symbol names.
  member _.Exports with get() = exportMap

  /// Returns the forwarded symbols as a map from forward target name to
  /// a tuple of (binary name, function name).
  member _.Forwards with get() = forwardMap

  /// Tries to find exported symbol name(s) by the given address.
  member _.TryFind(addr: Addr) = Map.tryFind addr exportMap

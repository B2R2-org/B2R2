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

namespace B2R2.FrontEnd.BinFile.Mach

open System
open B2R2

/// Parses the LC_DYLD_CHAINED_FIXUPS payload. Only the DYLD_CHAINED_PTR_64 and
/// DYLD_CHAINED_PTR_64_OFFSET pointer formats are handled; other formats (e.g.
/// the arm64e formats carrying pointer-authentication bits) are skipped.
module internal ChainedFixup =
  /// DYLD_CHAINED_PTR_64: absolute target in the rebase entry.
  let [<Literal>] private PtrFormat64 = 2us

  /// DYLD_CHAINED_PTR_64_OFFSET: target is an offset from the image base.
  let [<Literal>] private PtrFormat64Offset = 6us

  /// page_start value marking a page with no fixups.
  let [<Literal>] private PageStartNone = 0xFFFFus

  let private chooser = function
    | ChainedFixups(_, _, c) -> Some c
    | _ -> None

  /// Reads the import symbol names (DYLD_CHAINED_IMPORT format) into an array
  /// indexable by the ordinal stored in a bind entry.
  let private parseImports toolBox importsOff symbolsOff count =
    let bytes, reader = toolBox.Bytes, toolBox.Reader
    let strLen = bytes.Length - symbolsOff
    let names = Array.zeroCreate count
    for i = 0 to count - 1 do
      let import = reader.ReadUInt32(bytes, importsOff + i * 4)
      let nameOff = int ((import >>> 9) &&& 0x7FFFFFu)
      let span = ReadOnlySpan(bytes, symbolsOff, strLen)
      names[i] <- ByteArray.extractCStringFromSpan span nameOff
    names

  /// Decodes a single 64-bit chained entry into a fixup.
  let private decodeEntry baseAddr (imports: string[]) slotAddr entry =
    if (entry >>> 63) &&& 1UL = 1UL then
      let ordinal = int (entry &&& 0xFFFFFFUL)
      let addend = int64 ((entry >>> 24) &&& 0xFFUL)
      let name = if ordinal < imports.Length then imports[ordinal] else ""
      { FixupAddr = slotAddr; FixupTarget = Bind(name, addend) }
    else
      let low36 = entry &&& 0xFFFFFFFFFUL
      let high8 = (entry >>> 36) &&& 0xFFUL
      let target = baseAddr + ((high8 <<< 56) ||| low36)
      { FixupAddr = slotAddr; FixupTarget = Rebase target }

  /// Walks a single page chain, accumulating fixups until next is zero.
  let private walkChain toolBox baseAddr imports seg pageOff start acc =
    let bytes, reader = toolBox.Bytes, toolBox.Reader
    let mutable off = start
    let mutable go = true
    let mutable acc = acc
    while go do
      let slotAddr = seg.VMAddr + uint64 (pageOff + off)
      let entry = reader.ReadUInt64(bytes, int seg.FileOff + pageOff + off)
      acc <- decodeEntry baseAddr imports slotAddr entry :: acc
      let next = int ((entry >>> 51) &&& 0xFFFUL)
      if next = 0 then go <- false else off <- off + next * 4
    acc

  /// Parses the dyld_chained_starts_in_segment and walks each page chain.
  let private parseSegment toolBox baseAddr imports seg infoOff acc =
    let bytes, reader = toolBox.Bytes, toolBox.Reader
    let ptrFormat = reader.ReadUInt16(bytes, infoOff + 6)
    if ptrFormat <> PtrFormat64 && ptrFormat <> PtrFormat64Offset then acc
    else
      let pageSize = int (reader.ReadUInt16(bytes, infoOff + 4))
      let pageCount = int (reader.ReadUInt16(bytes, infoOff + 20))
      let mutable acc = acc
      for p = 0 to pageCount - 1 do
        let start = reader.ReadUInt16(bytes, infoOff + 22 + p * 2)
        if start <> PageStartNone then
          acc <- walkChain toolBox baseAddr imports seg (p * pageSize)
                           (int start) acc
        else ()
      acc

  let parse toolBox cmds (segCmds: SegCmd[]) =
    match Array.tryPick chooser cmds with
    | None -> [||]
    | Some cmd ->
      let bytes, reader = toolBox.Bytes, toolBox.Reader
      let dataOff = cmd.FixupsDataOffset
      let startsOff = dataOff + int (reader.ReadUInt32(bytes, dataOff + 4))
      let importsOff = dataOff + int (reader.ReadUInt32(bytes, dataOff + 8))
      let symbolsOff = dataOff + int (reader.ReadUInt32(bytes, dataOff + 12))
      let count = int (reader.ReadUInt32(bytes, dataOff + 16))
      let imports = parseImports toolBox importsOff symbolsOff count
      let segCount = int (reader.ReadUInt32(bytes, startsOff))
      let baseAddr = toolBox.BaseAddress
      let mutable acc = []
      for i = 0 to segCount - 1 do
        let segInfoOff = reader.ReadUInt32(bytes, startsOff + 4 + i * 4)
        if segInfoOff <> 0u && i < segCmds.Length then
          acc <- parseSegment toolBox baseAddr imports segCmds[i]
                              (startsOff + int segInfoOff) acc
        else ()
      acc |> List.rev |> List.toArray

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

/// Parses the LC_DYLD_CHAINED_FIXUPS payload. The DYLD_CHAINED_PTR_64 and
/// DYLD_CHAINED_PTR_64_OFFSET (x86_64 / plain arm64) formats are handled, as
/// are the arm64e formats; pointer-authentication bits in arm64e entries are
/// discarded, keeping only the target/ordinal. Unknown formats are skipped.
/// A rebase entry names its target either as an unslid virtual address or as
/// an offset from the image base, depending on the format and, for arm64e, on
/// whether the entry is authenticated, so each decoder is told which base to
/// add.
module internal ChainedFixup =
  /// DYLD_CHAINED_PTR_64: absolute target in the rebase entry.
  let [<Literal>] private PtrFormat64 = 2us

  /// DYLD_CHAINED_PTR_64_OFFSET: target is an offset from the image base.
  let [<Literal>] private PtrFormat64Offset = 6us

  /// DYLD_CHAINED_PTR_ARM64E: arm64e with 16-bit bind ordinals.
  let [<Literal>] private PtrFormatArm64e = 1us

  /// DYLD_CHAINED_PTR_ARM64E_USERLAND: arm64e with 16-bit bind ordinals.
  let [<Literal>] private PtrFormatArm64eUserland = 9us

  /// DYLD_CHAINED_PTR_ARM64E_USERLAND24: arm64e with 24-bit bind ordinals.
  let [<Literal>] private PtrFormatArm64eUserland24 = 12us

  /// page_start value marking a page with no fixups.
  let [<Literal>] private PageStartNone = 0xFFFFus

  /// DYLD_CHAINED_PTR_START_MULTI: the page_start value is an index into the
  /// overflow list that follows the page_start array, rather than an offset
  /// into the page. A page holding several chains is described that way.
  let [<Literal>] private PageStartMulti = 0x8000us

  /// DYLD_CHAINED_PTR_START_LAST: marks the final entry of one page's overflow
  /// list. It is the same bit that PageStartMulti is, reused in a place where
  /// only the one meaning can apply.
  let [<Literal>] private PageStartLast = 0x8000us

  let private chooser = function
    | ChainedFixups(_, _, c) -> Some c
    | _ -> None

  /// Reads the imports (DYLD_CHAINED_IMPORT format) into an array of (symbol
  /// name, library name) pairs, indexable by the ordinal in a bind entry.
  let private parseImports toolBox dylibs importsOff symbolsOff count =
    let bytes, reader = toolBox.Bytes, toolBox.Reader
    let strLen = bytes.Length - symbolsOff
    let imports = Array.zeroCreate count
    for i = 0 to count - 1 do
      let import = reader.ReadUInt32(bytes, importsOff + i * 4)
      let nameOff = int ((import >>> 9) &&& 0x7FFFFFu)
      let lo = int (import &&& 0xFFu)
      let libOrd = if lo >= 0x80 then lo - 0x100 else lo
      let span = ReadOnlySpan(bytes, symbolsOff, strLen)
      let name = ByteArray.extractCStringFromSpan span nameOff
      imports[i] <- name, Fixup.resolveLibrary dylibs libOrd
    imports

  /// Decodes a DYLD_CHAINED_PTR_64 entry into a fixup. Its rebase target is an
  /// unslid virtual address under the plain format and an image-relative
  /// offset under the _OFFSET one, which is what rebaseBase tells apart.
  let private decodePtr64 rebaseBase (imports: _[]) slotAddr entry =
    if (entry >>> 63) &&& 1UL = 1UL then
      let ordinal = int (entry &&& 0xFFFFFFUL)
      let addend = int64 ((entry >>> 24) &&& 0xFFUL)
      let name, lib =
        if ordinal < imports.Length then imports[ordinal] else ("", "")
      { FixupAddr = slotAddr; FixupTarget = Bind(name, lib, addend) }
    else
      let low36 = entry &&& 0xFFFFFFFFFUL
      let high8 = (entry >>> 36) &&& 0xFFUL
      let target = rebaseBase + ((high8 <<< 56) ||| low36)
      { FixupAddr = slotAddr; FixupTarget = Rebase target }

  /// next field of a DYLD_CHAINED_PTR_64 entry (12 bits; 4-byte stride).
  let private nextPtr64 entry = int ((entry >>> 51) &&& 0xFFFUL)

  /// Decodes an arm64e entry into a fixup. The bind ordinal width depends on
  /// the format (ordinalMask); pointer-authentication bits are discarded. An
  /// authenticated rebase always names an image-relative offset, while a plain
  /// one names whatever the format says, so the two carry their own base.
  let private decodeArm64e bases (imports: _[]) ordinalMask slotAddr entry =
    let bind = (entry >>> 62) &&& 1UL = 1UL
    let auth = (entry >>> 63) &&& 1UL = 1UL
    if bind then
      let ordinal = int (entry &&& ordinalMask)
      let addend = if auth then 0L else int64 ((entry >>> 32) &&& 0x7FFFFUL)
      let name, lib =
        if ordinal < imports.Length then imports[ordinal] else ("", "")
      { FixupAddr = slotAddr; FixupTarget = Bind(name, lib, addend) }
    else
      let authBase, plainBase = bases
      let target =
        if auth then
          authBase + (entry &&& 0xFFFFFFFFUL)
        else
          let low43 = entry &&& 0x7FFFFFFFFFFUL
          let high8 = (entry >>> 43) &&& 0xFFUL
          plainBase + ((high8 <<< 56) ||| low43)
      { FixupAddr = slotAddr; FixupTarget = Rebase target }

  /// next field of an arm64e entry (11 bits; 8-byte stride).
  let private nextArm64e entry = int ((entry >>> 51) &&& 0x7FFUL)

  /// Selects the (decoder, next-extractor, stride) for a pointer format. An
  /// unslid target is placed by the load address (slide) alone, whereas an
  /// image-relative one is placed by the image base, which already includes
  /// that slide.
  let private selectDecoder slide imgBase imports ptrFormat =
    match ptrFormat with
    | PtrFormat64 ->
      Some(decodePtr64 slide imports, nextPtr64, 4)
    | PtrFormat64Offset ->
      Some(decodePtr64 imgBase imports, nextPtr64, 4)
    | PtrFormatArm64e ->
      Some(decodeArm64e (imgBase, slide) imports 0xFFFFUL, nextArm64e, 8)
    | PtrFormatArm64eUserland ->
      Some(decodeArm64e (imgBase, imgBase) imports 0xFFFFUL, nextArm64e, 8)
    | PtrFormatArm64eUserland24 ->
      Some(decodeArm64e (imgBase, imgBase) imports 0xFFFFFFUL, nextArm64e, 8)
    | _ ->
      None

  /// Walks a single page chain, accumulating fixups until next is zero.
  let private walkChain toolBox seg pageOff start walker acc =
    let bytes, reader = toolBox.Bytes, toolBox.Reader
    let decode, nextOf, stride = walker
    let mutable off = start
    let mutable go = true
    let mutable acc = acc
    while go do
      let slotAddr = seg.VMAddr + uint64 (pageOff + off)
      let entry = reader.ReadUInt64(bytes, int seg.FileOff + pageOff + off)
      acc <- decode slotAddr entry :: acc
      let next = nextOf entry
      if next = 0 then go <- false else off <- off + next * stride
    acc

  /// Walks every chain of a page that holds more than one. Its page_start
  /// value indexes an overflow list that follows the page_start array, each
  /// entry of which starts one chain, up to the entry marked as the last.
  let rec private walkMulti toolBox seg startsAt idx pageOff walker acc =
    let bytes, reader = toolBox.Bytes, toolBox.Reader
    let entry = reader.ReadUInt16(bytes, startsAt + idx * 2)
    let start = int (entry &&& ~~~PageStartLast)
    let acc = walkChain toolBox seg pageOff start walker acc
    if entry &&& PageStartLast <> 0us then
      acc
    else
      walkMulti toolBox seg startsAt (idx + 1) pageOff walker acc

  /// Parses the dyld_chained_starts_in_segment and walks each page chain.
  let private parseSegment toolBox bases imports seg infoOff acc =
    let bytes, reader = toolBox.Bytes, toolBox.Reader
    let slide, imgBase = bases
    let ptrFormat = reader.ReadUInt16(bytes, infoOff + 6)
    match selectDecoder slide imgBase imports ptrFormat with
    | None ->
      acc
    | Some walker ->
      let pageSize = int (reader.ReadUInt16(bytes, infoOff + 4))
      let pageCount = int (reader.ReadUInt16(bytes, infoOff + 20))
      let startsAt = infoOff + 22
      let mutable acc = acc
      for p = 0 to pageCount - 1 do
        let pageOff = p * pageSize
        let start = reader.ReadUInt16(bytes, startsAt + p * 2)
        if start = PageStartNone then
          ()
        elif start &&& PageStartMulti <> 0us then
          let idx = int (start &&& ~~~PageStartMulti)
          acc <- walkMulti toolBox seg startsAt idx pageOff walker acc
        else
          acc <- walkChain toolBox seg pageOff (int start) walker acc
      acc

  let parse toolBox cmds (segCmds: SegCmd[]) =
    match Array.tryPick chooser cmds with
    | None ->
      [||]
    | Some cmd ->
      let bytes, reader = toolBox.Bytes, toolBox.Reader
      let dataOff = cmd.FixupsDataOffset
      let startsOff = dataOff + int (reader.ReadUInt32(bytes, dataOff + 4))
      let importsOff = dataOff + int (reader.ReadUInt32(bytes, dataOff + 8))
      let symbolsOff = dataOff + int (reader.ReadUInt32(bytes, dataOff + 12))
      let count = int (reader.ReadUInt32(bytes, dataOff + 16))
      let dylibs = Fixup.dylibNames cmds
      let imports = parseImports toolBox dylibs importsOff symbolsOff count
      let segCount = int (reader.ReadUInt32(bytes, startsOff))
      let imgBase =
        Segment.tryGetImageBase segCmds |> Option.defaultValue 0UL
      let bases = toolBox.BaseAddress, imgBase
      let mutable acc = []
      for i = 0 to segCount - 1 do
        let segInfoOff = reader.ReadUInt32(bytes, startsOff + 4 + i * 4)
        if segInfoOff <> 0u && i < segCmds.Length then
          let offset = startsOff + int segInfoOff
          acc <- parseSegment toolBox bases imports segCmds[i] offset acc
        else
          ()
      acc |> List.rev |> List.toArray

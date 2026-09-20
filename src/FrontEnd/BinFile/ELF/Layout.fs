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

open B2R2

/// Represents where everything of an emitted image goes. Whatever the file
/// already had a place for keeps it, so that nothing a segment maps ever
/// moves; what is left over goes on the end of the file.
type internal Layout =
  { /// Where the bytes of each section go, by section index.
    SectionOffsets: uint64[]
    /// The address each section is loaded at, by section index, with the load
    /// base added the way every address of an image has it.
    SectionAddrs: uint64[]
    /// The program header table, with every segment the image asked for put
    /// in a spare entry of it.
    ProgramHeaders: ProgramHeader[]
    /// Where the section header table goes.
    SHdrTblOffset: uint64
    /// How many entries that table has.
    SHdrNum: int
    /// How long the emitted file is.
    Size: int }

[<RequireQualifiedAccess>]
module internal Layout =
  /// Returns the offset rounded up to the next multiple of the alignment.
  let private align (offset: uint64) alignment =
    if alignment <= 1UL then offset
    else (offset + alignment - 1UL) / alignment * alignment

  /// Returns whether the section keeps the place the file gave it. Bytes the
  /// image was given fit there only where they are as many as were there, and
  /// a section the image made was never given a place at all.
  let private staysPut entry =
    match entry.Content, entry.Origin with
    | InFile, _ -> true
    | Given _, Some origin -> origin.OriginSize = entry.SecHeader.SecSize
    | Given _, None -> false

  /// Returns how many sections the image has that the original file had not.
  let private countAdded (img: Image) =
    img.Sections
    |> Array.sumBy (fun entry -> if entry.Origin.IsNone then 1 else 0)

  /// Returns where each section goes, along with where the end of the file
  /// has reached once every section needing room of its own has taken it.
  let private placeSections (img: Image) =
    let offsets = Array.zeroCreate img.Sections.Length
    let mutable cursor = uint64 img.Original.Length
    for i = 0 to img.Sections.Length - 1 do
      let entry = img.Sections[i]
      if staysPut entry then
        offsets[i] <- entry.SecHeader.SecOffset
      else
        let offset = align cursor entry.SecHeader.SecAlignment
        offsets[i] <- offset
        cursor <- offset + entry.SecHeader.SecSize
    offsets, cursor

  /// Returns the page size the file was linked for, which is what it aligns
  /// a loadable segment to.
  let private pageSizeOf (img: Image) =
    img.ProgramHeaders
    |> Array.tryFind (fun ph -> ph.PHType = ProgramHeaderType.PT_LOAD)
    |> function
      | Some ph when ph.PHAlignment > 1UL -> ph.PHAlignment
      | _ -> 0x1000UL

  /// Returns the address past everything the file already loads, which is
  /// where a segment the image adds can go without meeting one that is there.
  let private freeAddrOf (img: Image) pageSize =
    let isLoad ph = ph.PHType = ProgramHeaderType.PT_LOAD
    let ends =
      img.ProgramHeaders
      |> Array.filter isLoad
      |> Array.map (fun ph -> ph.PHAddr + ph.PHMemSize)
    let top = if Array.isEmpty ends then img.BaseAddress else Array.max ends
    align top pageSize + pageSize

  /// Returns the segment covering the section at the given offset. Its address
  /// is congruent to that offset modulo the page size, which is what a loader
  /// requires of a segment it maps.
  let private loadHeaderOf load offset size addr pageSize =
    { PHType = ProgramHeaderType.PT_LOAD
      PHFlags = load.LoadFlags
      PHOffset = offset
      PHAddr = addr
      PHPhyAddr = addr
      PHFileSize = size
      PHMemSize = size
      PHAlignment = pageSize }

  /// Puts every segment the image asked for into a spare entry of the program
  /// header table, and returns that table along with the address each of the
  /// sections they cover ended up at.
  let private placeLoads (img: Image) (offsets: uint64[]) (addrs: uint64[]) =
    let phdrs = Array.copy img.ProgramHeaders
    let pageSize = pageSizeOf img
    let mutable free = freeAddrOf img pageSize
    let slots = Image.spareSlots img
    List.iteri (fun i load ->
      let idx = load.LoadSectionIdx
      let offset = offsets[idx]
      let size = img.Sections[idx].SecHeader.SecSize
      let addr = free + offset % pageSize
      addrs[idx] <- addr
      phdrs[List.item i slots] <-
        loadHeaderOf load offset size addr pageSize
      free <- align (addr + size) pageSize + pageSize) img.PendingLoads
    phdrs

  /// Returns the address of every section, which is the one it already had
  /// wherever the file gave it one.
  let private placeAddrs (img: Image) =
    img.Sections |> Array.map (fun entry -> entry.SecHeader.SecAddr)

  /// Returns where everything of the given image goes.
  let compute (img: Image) =
    let offsets, cursor = placeSections img
    let addrs = placeAddrs img
    let phdrs = placeLoads img offsets addrs
    let added = countAdded img
    let shNum = img.Header.SHdrNum + added
    let entSize = uint64 img.Header.SHdrEntrySize
    let grew = added > 0 || cursor > uint64 img.Original.Length
    let wordWidth = uint64 (WordSize.toByteWidth img.Header.Class)
    let shOffset =
      if grew then align cursor wordWidth else img.Header.SHdrTblOffset
    let size =
      if grew then shOffset + uint64 shNum * entSize
      else uint64 img.Original.Length
    { SectionOffsets = offsets
      SectionAddrs = addrs
      ProgramHeaders = phdrs
      SHdrTblOffset = shOffset
      SHdrNum = shNum
      Size = int size }

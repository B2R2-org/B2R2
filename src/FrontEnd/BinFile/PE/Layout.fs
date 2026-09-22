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

open B2R2.FrontEnd.BinFile.PE.PEUtils

/// Represents where everything of an emitted image goes. Whatever the file
/// already had a place for keeps it, so that nothing a loader maps ever
/// moves; what is left over goes on the end of the file.
type internal Layout =
  { /// Where the bytes of each section go, by section index.
    SectionOffsets: int[]
    /// Where each section is loaded, relative to the image base, by section
    /// index.
    SectionRVAs: int[]
    /// How many bytes the image takes in memory once loaded.
    SizeOfImage: int
    /// How long the emitted file is.
    Size: int }

[<RequireQualifiedAccess>]
module internal Layout =
  /// Returns where the bytes of each section go, along with where the end of
  /// the file has reached once every section needing room of its own has
  /// taken it. A section the file already placed keeps that place, and so do
  /// the bytes the original ends with that no section holds: an overlay is
  /// nothing this models, and what reproduces it is leaving it alone.
  let private placeSections (img: Image) =
    let fileAlign = img.OptionalHeader.FileAlignment
    let offsets = Array.zeroCreate img.Sections.Length
    let mutable cursor = img.KeptLength
    for i = 0 to img.Sections.Length - 1 do
      match img.Sections[i].Origin with
      | Some origin ->
        offsets[i] <- origin.OriginOffset
      | None ->
        let offset = alignUp cursor fileAlign
        offsets[i] <- offset
        cursor <- offset + img.Sections[i].SecHeader.SizeOfRawData
    offsets, cursor

  /// Returns the address past everything the file already loads, which is
  /// where a section the image adds can go without meeting one that is there.
  let private freeRVA (img: Image) =
    let secAlign = img.OptionalHeader.SectionAlignment
    let endOf entry =
      let sec = entry.SecHeader
      alignUp (sec.VirtualAddress + getVirtualSectionSize sec) secAlign
    img.Sections
    |> Array.fold (fun free entry ->
      if entry.Origin.IsSome then max free (endOf entry) else free) 0

  /// Returns where each section is loaded. One the file already placed keeps
  /// the address it was given; one the image made goes above everything the
  /// file loads, on the next boundary the section alignment allows.
  let private placeRVAs (img: Image) =
    let secAlign = img.OptionalHeader.SectionAlignment
    let rvas = Array.zeroCreate img.Sections.Length
    let mutable free = freeRVA img
    for i = 0 to img.Sections.Length - 1 do
      let sec = img.Sections[i].SecHeader
      match img.Sections[i].Origin with
      | Some _ ->
        rvas[i] <- sec.VirtualAddress
      | None ->
        rvas[i] <- free
        free <- alignUp (free + getVirtualSectionSize sec) secAlign
    rvas

  /// Returns how many bytes the image takes in memory, which is where the
  /// section loaded highest reaches, rounded up the way the address of every
  /// section is. This is what the linker of each of the fixtures wrote, which
  /// is what lets an image nothing has touched work the field out afresh and
  /// change nothing by it.
  let private sizeOfImage (img: Image) (rvas: int[]) =
    let secAlign = img.OptionalHeader.SectionAlignment
    let mutable top = alignUp img.OptionalHeader.SizeOfHeaders secAlign
    for i = 0 to img.Sections.Length - 1 do
      let size = getVirtualSectionSize img.Sections[i].SecHeader
      top <- max top (alignUp (rvas[i] + size) secAlign)
    top

  /// Returns where everything of the given image goes.
  let compute (img: Image) =
    let offsets, cursor = placeSections img
    let rvas = placeRVAs img
    { SectionOffsets = offsets
      SectionRVAs = rvas
      SizeOfImage = sizeOfImage img rvas
      Size = cursor }

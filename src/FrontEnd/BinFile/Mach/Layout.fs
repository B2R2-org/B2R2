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

open B2R2.FrontEnd.BinFile.FileHelper

/// Represents where everything of an emitted image goes. Whatever the file
/// already had a place for keeps it, so that nothing a segment maps ever
/// moves; a run of __LINKEDIT moves only as far as the runs before it have
/// grown, and what the image added goes on the end of the file.
type internal Layout =
  { /// Where each load command goes.
    CommandOffsets: int[]
    /// Where the description of each section goes.
    StructOffsets: int[]
    /// Where the bytes of each section go, by section index.
    SectionOffsets: uint32[]
    /// Where each run of __LINKEDIT goes, in the order the image holds them.
    LinkEditOffsets: uint32[]
    /// Where each of those runs goes, by the kind of run it is, which is how
    /// the commands naming them are brought up to date.
    LinkEditPlaces: Map<LinkEditKind, uint32>
    /// How many bytes longer the runs have made the segment holding them.
    LinkEditGrowth: int64
    /// The page size the image is mapped in.
    PageSize: uint64
    /// How many load commands the emitted file carries.
    NumCmds: uint32
    /// How many bytes those commands take up.
    SizeOfCmds: uint32
    /// How long the emitted file is.
    Size: int }

[<RequireQualifiedAccess>]
module internal Layout =
  /// Returns where each load command goes, which is one after another from
  /// the end of the header on, as a Mach-O keeps them.
  let private placeCommands (img: Image) =
    let offsets = Array.zeroCreate img.Commands.Length
    let mutable at = int img.ToolBox.HeaderOffset
                     + selectByWordSize img.Class 28 32
    for i = 0 to img.Commands.Length - 1 do
      offsets[i] <- at
      at <- at + int img.Commands[i].Command.CmdSize
    offsets

  /// Returns where the description of each section goes, which is inside the
  /// command naming the segment it belongs to, after the fields of that
  /// command and after every description before it.
  let private placeStructs (img: Image) (cmdOffsets: int[]) =
    let segSize = selectByWordSize img.Class 56 72
    let secSize = selectByWordSize img.Class 68 80
    img.Sections
    |> Array.map (fun entry ->
      cmdOffsets[entry.OwnerIdx] + segSize + entry.SecIndexInSeg * secSize)

  /// Returns where each run of __LINKEDIT goes, which is where the file kept
  /// it moved along by however much the runs before it have grown. Keeping
  /// the gaps between them is what lets a file nothing has grown come back
  /// byte for byte.
  let private placeLinkEdit (img: Image) =
    let offsets = Array.zeroCreate img.LinkEdit.Length
    let mutable delta = 0L
    for i = 0 to img.LinkEdit.Length - 1 do
      let run = img.LinkEdit[i]
      offsets[i] <- uint32 (int64 run.RunOrigin + delta)
      delta <- delta + int64 (Image.sizeOfRun run) - int64 run.RunOriginSize
    offsets

  /// Returns where everything of the given image goes.
  let compute (img: Image) =
    let cmdOffsets = placeCommands img
    let linkEditOffsets = placeLinkEdit img
    let places =
      Array.map2 (fun run offset -> run.RunKind, offset)
        img.LinkEdit linkEditOffsets
    { CommandOffsets = cmdOffsets
      StructOffsets = placeStructs img cmdOffsets
      SectionOffsets =
        img.Sections |> Array.map (fun entry -> entry.Section.SecOffset)
      LinkEditOffsets = linkEditOffsets
      LinkEditPlaces = Map.ofArray places
      LinkEditGrowth = Image.linkEditGrowth img
      PageSize = Image.pageSizeOf img
      NumCmds = uint32 img.Commands.Length
      SizeOfCmds = uint32 (Image.sizeOfCmds img)
      Size = int (Image.fileEndOf img) }

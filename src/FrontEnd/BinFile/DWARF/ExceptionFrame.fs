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

namespace B2R2.FrontEnd.BinFile.DWARF

open System
open B2R2
open B2R2.FrontEnd.BinLifter

/// Locates a DWARF section within an image, bundling the coordinates needed to
/// read a `.eh_frame`-like section regardless of the container format: the raw
/// bytes, the section's file offset and byte size, and the virtual address its
/// first byte maps to.
type internal DWARFSection =
  { /// Raw bytes of the image the section lives in.
    Image: byte[]
    /// File offset to the start of the section.
    Offset: int
    /// Size of the section in bytes.
    Size: int
    /// Virtual address that the section's first byte maps to.
    Address: Addr }

/// Represents the exception frame, which is a list of CFI records.
type internal ExceptionFrame = CFI list

/// Represents the Call Frame Information (CFI), which is the main information
/// block of .eh_frame. This exists roughly for every object file, although one
/// object file may have multiple CFIs. Each CFI record contains a CIE record
/// followed by 1 or more FDE records.
and internal CFI =
  { /// CIE record.
    CIE: CIE
    /// FDE records.
    FDEs: FDE[] }

[<RequireQualifiedAccess>]
module internal ExceptionFrame =
  let computeNextOffset (span: ByteSpan) (reader: IBinReader) offset len =
    if len = -1 then
      let len = reader.ReadUInt64(span, offset)
      let offset = offset + 8
      int len + offset, offset
    else len + offset, offset

  let accumulateCFIs cfis cie fdes =
    match cie with
    | Some cie ->
      { CIE = cie
        FDEs = List.rev fdes |> List.toArray } :: cfis
    | None -> cfis

  /// Parses CFI records (a list of CIEs each followed by their FDEs) from a
  /// `.eh_frame`-equivalent section. The reloc callback supplies FDE
  /// begin-address relocations for relocatable objects (None-returning for
  /// other files).
  let parseFromSection (reader: IBinReader) cls isa regs reloc sec =
    let rec parseLoop cie cies fdes offset cfis =
      let span = ReadOnlySpan(sec.Image, sec.Offset, sec.Size)
      if offset >= span.Length then
        accumulateCFIs cfis cie fdes
      else
        let originalOffset = offset
        let len, offset = reader.ReadInt32(span, offset), offset + 4
        if len = 0 then accumulateCFIs cfis cie fdes
        else
          let nextOfs, offset = computeNextOffset span reader offset len
          let mybase = offset
          let id, offset = reader.ReadInt32(span, offset), offset + 4
          if id = 0 then
            let cfis = accumulateCFIs cfis cie fdes
            let cie = CIE.parse reader span cls isa regs offset nextOfs
            let cies = Map.add originalOffset cie cies
            let cie = Some cie
            parseLoop cie cies [] nextOfs cfis
          else
            let cieOffset = mybase - id (* id = a CIE pointer, when id <> 0 *)
            let sAddr = sec.Address
            let pcie = Map.tryFind cieOffset cies
            let fde =
              FDE.parse cls isa regs span reader sAddr offset nextOfs reloc pcie
            let fdes = fde :: fdes
            parseLoop cie cies fdes nextOfs cfis
    parseLoop None Map.empty [] 0 []
    |> List.rev

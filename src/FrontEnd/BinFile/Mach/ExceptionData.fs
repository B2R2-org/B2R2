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
open B2R2.FrontEnd.BinFile.DWARF

/// Represents Mach-O exception information parsed from the DWARF CFI records in
/// `__TEXT,__eh_frame` and the LSDA table in `__TEXT,__gcc_except_tab`.
type internal ExceptionData =
  { /// Exception frames (CFI records).
    ExceptionFrame: ExceptionFrame
    /// LSDA table mapping each LSDA address to its parsed LSDA.
    LSDATable: LSDATable }

module internal ExceptionData =
  let [<Literal>] private EHFrameSection = "__eh_frame"

  let [<Literal>] private GccExceptTableSection = "__gcc_except_tab"

  /// Mach-O executables and dylibs carry no FDE begin-address relocations, so
  /// the resolver always yields None.
  let private noReloc: RelocationResolver = fun _ -> None

  let private parseFrames toolBox cls isa (secs: Section[]) regFactory =
    match Array.tryFind (fun s -> s.SecName = EHFrameSection) secs,
          regFactory with
    | Some sec, Some rf ->
      let dwSec: DWARFSection =
        { Image = toolBox.Bytes
          Offset = int sec.SecOffset
          Size = int sec.SecSize
          Address = sec.SecAddr }
      ExceptionFrame.parseFromSection toolBox.Reader cls isa rf noReloc dwSec
    | _ -> []

  let private parseLSDAs toolBox cls (secs: Section[]) =
    match Array.tryFind (fun s -> s.SecName = GccExceptTableSection) secs with
    | Some sec ->
      let offset, size = int sec.SecOffset, int sec.SecSize
      let span = ReadOnlySpan(toolBox.Bytes, offset, size)
      LSDATable.parseFromSection cls span toolBox.Reader sec.SecAddr 0 Map.empty
    | None -> Map.empty

  let parse toolBox secs regFactory =
    let cls = toolBox.Header.Class
    let isa = toolBox.ISA
    { ExceptionFrame = parseFrames toolBox cls isa secs regFactory
      LSDATable = parseLSDAs toolBox cls secs }

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
open B2R2.FrontEnd.BinFile.DWARF

/// Represents a per-function exception frame descriptor, independent of whether
/// it came from DWARF CFI (`__eh_frame`) or compact unwind (`__unwind_info`).
type internal FrameInfo =
  { /// Start address of the function (inclusive).
    FuncStart: Addr
    /// End address of the function (exclusive).
    FuncEnd: Addr
    /// Address of the LSDA governing this frame, if any.
    LSDAPointer: Addr option }

/// Represents Mach-O exception information: per-function frames plus the LSDA
/// table (in `__TEXT,__gcc_except_tab`) that resolves their handlers.
and internal ExceptionData =
  { Frames: FrameInfo list
    LSDATable: LSDATable }

module internal ExceptionData =
  let [<Literal>] private EHFrameSection = "__eh_frame"

  let [<Literal>] private GccExceptTableSection = "__gcc_except_tab"

  /// Mach-O carries no FDE begin-address relocations, so the resolver always
  /// yields None.
  let private noReloc: RelocationResolver = fun _ -> None

  let private parseLSDAs toolBox cls (secs: Section[]) =
    match Array.tryFind (fun s -> s.SecName = GccExceptTableSection) secs with
    | Some sec ->
      let offset, size = int sec.SecOffset, int sec.SecSize
      let span = ReadOnlySpan(toolBox.Bytes, offset, size)
      LSDATable.parseFromSection cls span toolBox.Reader sec.SecAddr 0 Map.empty
    | None -> Map.empty

  /// Parses frames from DWARF CFI in `__eh_frame`. Requires a register factory
  /// (for CIE decoding); returns [] when either is absent.
  let private parseEHFrames toolBox cls isa (secs: Section[]) regFactory =
    match Array.tryFind (fun s -> s.SecName = EHFrameSection) secs,
          regFactory with
    | Some sec, Some rf ->
      let dwSec: DWARFSection =
        { Image = toolBox.Bytes
          Offset = int sec.SecOffset
          Size = int sec.SecSize
          Address = sec.SecAddr }
      ExceptionFrame.parseFromSection toolBox.Reader cls isa rf noReloc dwSec
      |> List.collect (fun cfi ->
        [ for fde in cfi.FDEs ->
            { FuncStart = fde.PCBegin
              FuncEnd = fde.PCEnd
              LSDAPointer = fde.LSDAPointer } ])
    | _ -> []

  /// Parses frames from Apple compact unwind in `__unwind_info` (the common
  /// case on modern macOS, especially arm64). No register factory is needed.
  let private parseCompactUnwind toolBox (segCmds: SegCmd[]) (secs: Section[]) =
    match Array.tryFind (fun s -> s.SecName = Section.UnwindInfo) secs with
    | Some sec ->
      let imageBase = Helper.getTextSegOffset segCmds
      CompactUnwind.parse
        toolBox.Bytes toolBox.Reader (int sec.SecOffset) (int sec.SecSize)
        imageBase
      |> List.map (fun (s, e, l) ->
        { FuncStart = s; FuncEnd = e; LSDAPointer = l })
    | None -> []

  let parse toolBox segCmds secs regFactory =
    let cls = toolBox.Header.Class
    let isa = toolBox.ISA
    let ehFrames = parseEHFrames toolBox cls isa secs regFactory
    let frames =
      if List.isEmpty ehFrames then parseCompactUnwind toolBox segCmds secs
      else ehFrames
    { Frames = frames; LSDATable = parseLSDAs toolBox cls secs }

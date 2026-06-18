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

module internal B2R2.FrontEnd.BinFile.Mach.Helper

open System
open B2R2
open B2R2.Collections
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

/// Mach-specific virtual memory permission (for maxprot and initprot). Note
/// that these values are different than the B2R2.Permission type.
[<Flags>]
type internal MachVMProt =
  /// File is readable.
  | Readable = 1
  /// File is writable.
  | Writable = 2
  /// File is executable.
  | Executable = 4

let isMainCmd = function
  | Main _ -> true
  | _ -> false

let getMainOffset cmds =
  match cmds |> Array.tryFind isMainCmd with
  | Some(Main(_, _, m)) -> m.EntryOff
  | _ -> 0UL

let getTextSegOffset segs =
  let isTextSegment s = s.SegCmdName = Segment.Text
  match segs |> Array.tryFind isTextSegment with
  | Some s -> s.VMAddr
  | _ -> raise InvalidFileFormatException

let computeEntryPoint segs cmds =
  let mainOffset = getMainOffset cmds
  if mainOffset = 0UL then None
  else Some(mainOffset + getTextSegOffset segs)

let isNXEnabled hdr =
  not (hdr.Flags.HasFlag MachFlag.MH_ALLOW_STACK_EXECUTION)
  || hdr.Flags.HasFlag MachFlag.MH_NO_HEAP_EXECUTION

let private computeInvalidRanges toolBox segCmds getNextStartAddr =
  segCmds
  |> Array.filter (fun seg -> seg.SegCmdName <> "__PAGEZERO")
  |> Array.sortBy (fun seg -> seg.VMAddr)
  |> Array.fold (fun (set, saddr) seg ->
       let n = getNextStartAddr seg
       addInvalidRange set saddr seg.VMAddr, n) (IntervalSet.empty, 0UL)
  |> addLastInvalidRange toolBox.Header.Class

let invalidRangesByVM toolBox segCmds =
  computeInvalidRanges toolBox segCmds (fun seg -> seg.VMAddr + seg.VMSize)

let invalidRangesByFileBounds toolBox segCmds =
  computeInvalidRanges toolBox segCmds (fun seg -> seg.VMAddr + seg.FileSize)

/// Converts a Mach VM protection value (initprot/maxprot) to a B2R2 Permission.
/// The two use different bit layouts, so a direct cast would be wrong (e.g.,
/// Mach READ = 1 collides with B2R2 Permission.Executable = 1).
let machVMProtToPermission (prot: int) =
  let mp: MachVMProt = LanguagePrimitives.EnumOfValue prot
  (if mp.HasFlag MachVMProt.Readable then Permission.Readable else enum 0)
  ||| (if mp.HasFlag MachVMProt.Writable then Permission.Writable else enum 0)
  ||| (if mp.HasFlag MachVMProt.Executable then Permission.Executable
       else enum 0)

let executableRanges segCmds =
  segCmds
  |> Array.filter (fun seg ->
    let prot: MachVMProt = LanguagePrimitives.EnumOfValue seg.InitProt
    prot.HasFlag MachVMProt.Executable)
  |> Array.fold (fun set s ->
    IntervalSet.add (AddrRange.create s.VMAddr (s.VMAddr + s.VMSize - 1UL)) set
    ) IntervalSet.empty

let getPLT symInfo =
  symInfo.Imports
  |> Array.sortBy (fun entry -> entry.TrampolineAddress)

let isPLT symInfo addr =
  symInfo.Imports
  |> Array.exists (fun entry -> entry.TrampolineAddress = Some addr)

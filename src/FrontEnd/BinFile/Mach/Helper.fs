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
type MachVMProt =
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
  | Some (Main (_, _, m)) -> m.EntryOff
  | _ -> 0UL

let getTextSegOffset segs =
  let isTextSegment s = s.SegCmdName = Segment.Text
  match segs |> Array.tryFind isTextSegment with
  | Some s -> s.VMAddr
  | _ -> raise InvalidFileFormatException

let computeEntryPoint segs cmds =
  let mainOffset = getMainOffset cmds
  if mainOffset = 0UL then None
  else Some (mainOffset + getTextSegOffset segs)

let getStaticSymbols symInfo =
  symInfo.Values
  |> Array.filter Symbol.IsStatic

let isStripped secs symInfo =
  let secText = Section.getTextSectionIndex secs
  getStaticSymbols symInfo
  |> Array.exists (fun s -> Symbol.IsFunc secText s)
  |> not

let isNXEnabled hdr =
  not (hdr.Flags.HasFlag MachFlag.MH_ALLOW_STACK_EXECUTION)
  || hdr.Flags.HasFlag MachFlag.MH_NO_HEAP_EXECUTION

let translateAddr segMap addr =
  match NoOverlapIntervalMap.tryFindByAddr addr segMap with
  | Some s -> Convert.ToInt32 (addr - s.VMAddr + s.FileOff)
  | None -> raise InvalidAddrReadException

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

let executableRanges segCmds =
  segCmds
  |> Array.filter (fun seg ->
    let perm: Permission = seg.MaxProt |> LanguagePrimitives.EnumOfValue
    perm &&& Permission.Executable = Permission.Executable)
  |> Array.fold (fun set s ->
    IntervalSet.add (AddrRange (s.VMAddr, s.VMAddr + s.VMSize - 1UL)) set
    ) IntervalSet.empty

let getPLT symInfo =
  symInfo.LinkageTable
  |> List.sortBy (fun entry -> entry.TrampolineAddress)
  |> List.toArray

let isPLT symInfo addr =
  symInfo.LinkageTable
  |> List.exists (fun entry -> entry.TrampolineAddress = addr)

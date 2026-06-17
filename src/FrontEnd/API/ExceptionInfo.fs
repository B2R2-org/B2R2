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

namespace B2R2.FrontEnd

open System.Collections.Generic
open B2R2
open B2R2.Collections
open B2R2.FrontEnd.BinFile

/// <summary>
/// Represents parsed exception information of a binary code. We currently only
/// support ELF binaries.
/// </summary>
type ExceptionInfo(liftingUnit: LiftingUnit) =
  /// If a handler has a direct branch to another function, then we consider the
  /// frame containing the handler as a non-function frame.
  let checkIfFrameIsFunction (frame: BinExceptionFrame) handler =
    match liftingUnit.ParseBBlock(addr = handler) with
    | Ok(blk) ->
      let last = blk[blk.Length - 1]
      if not last.IsCall then
        match last.DirectBranchTarget() with
        | true, jmpTarget ->
          frame.FunctionStart <= jmpTarget && jmpTarget <= frame.FunctionEnd
        | _ -> true
      else true
    | _ -> true

  let loopHandlers (frame: BinExceptionFrame) acc =
    frame.Handlers
    |> Array.fold (fun (tbl, isFunc) handler ->
      match handler.Handler with
      | Some landingPad ->
        let range = AddrRange.create handler.BlockStart handler.BlockEnd
        let tbl = NoOverlapIntervalMap.add range landingPad tbl
        tbl, checkIfFrameIsFunction frame landingPad
      | None -> tbl, isFunc) (acc, true)

  let fnRanges = Dictionary<Addr, Addr>()

  let buildExceptionTable acc (frame: BinExceptionFrame) =
    let tbl, isFunc = loopHandlers frame acc
    if isFunc then fnRanges[frame.FunctionStart] <- frame.FunctionEnd
    else ()
    tbl

  let exnTbl =
    BinFileOps.getExceptionFrames liftingUnit.File
    |> Array.fold buildExceptionTable NoOverlapIntervalMap.empty

  new(hdl: BinHandle) = ExceptionInfo(hdl.NewLiftingUnit())

  /// Returns the exception handler mapping.
  member _.ExceptionMap with get() = exnTbl

  /// Returns an array of function entry points identified by the exception
  /// table.
  member _.FunctionEntryPoints with get() = fnRanges.Keys |> Seq.toArray

  /// Returns the coverage of the exception table, which is the ratio of
  /// addresses in the .text section that are covered by the exception table.
  member _.ExceptionCoverage with get() =
    let ptr = BinFileOps.getCodeSectionPointer liftingUnit.File
    let txtSize = float (ptr.MaxAddr - ptr.Addr)
    let mutable covered = 0.0
    for KeyValue(startAddr, endAddr) in fnRanges do
      if ptr.Addr <= startAddr && startAddr <= ptr.MaxAddr then
        covered <- covered + float (endAddr - startAddr + 1UL)
      else ()
    covered / txtSize

  /// Checks if the given address is a function entry point according to the
  /// FDE records in the exception table.
  member _.ContainsFunctionEntryPoint addr = fnRanges.ContainsKey addr

  /// Finds the exception target (landing pad) for a given instruction address.
  /// If the address is not in the exception table, it returns None.
  member _.TryFindExceptionTarget insAddr =
    NoOverlapIntervalMap.tryFindByAddr insAddr exnTbl

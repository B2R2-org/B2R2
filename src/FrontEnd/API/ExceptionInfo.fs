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
open System.Runtime.CompilerServices
open B2R2
open B2R2.Collections
open B2R2.FrontEnd.BinFile

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.API.Tests")>]
do ()

/// Computes how much of an address window a set of ranges covers.
[<RequireQualifiedAccess>]
module internal ExceptionCoverage =
  /// <summary>
  /// Returns the fraction of the inclusive window [lo, hi] covered by the given
  /// ranges, which map an inclusive range start to its inclusive end. Each one
  /// is clamped to the window, so a range reaching outside it neither inflates
  /// the result nor is dropped from it. The result is zero for an empty window.
  /// Overlapping ranges are counted twice, so the caller is responsible for
  /// passing disjoint ones.
  /// </summary>
  let compute lo hi (ranges: Dictionary<Addr, Addr>) =
    if hi < lo then
      0.0
    else
      let mutable covered = 0UL
      for KeyValue(startAddr, endAddr) in ranges do
        let s, e = max startAddr lo, min endAddr hi
        if s <= e then covered <- covered + (e - s + 1UL) else ()
      float covered / float (hi - lo + 1UL)

/// Maps handler block ranges to the landing pads they dispatch to.
[<RequireQualifiedAccess>]
module internal HandlerTable =
  /// Adds a handler block range. Handler blocks nest, since a try block inside
  /// another try block yields a range contained in an outer one, so overlapping
  /// ranges are kept rather than rejected. The last landing pad wins when the
  /// exact same range shows up twice.
  let add (range: AddrRange) landingPad tbl =
    IntervalMap.addOrReplace range (range, landingPad) tbl

  /// Returns the landing pad of the narrowest block covering the given address,
  /// which is the innermost one and hence the one that catches first at run
  /// time, or None when no block covers the address.
  let tryFindTarget addr tbl =
    match IntervalMap.findAll (AddrRange.singleton addr) tbl with
    | [] ->
      None
    | candidates ->
      candidates
      |> List.minBy (fun (range: AddrRange, _) -> range.Max - range.Min)
      |> snd
      |> Some

  /// Returns every block range with its landing pad, ordered by range start.
  let toArray tbl =
    IntervalMap.fold (fun acc _ pair -> pair :: acc) [] tbl
    |> List.rev
    |> List.toArray

/// <summary>
/// Represents parsed exception information of a binary code. This works for the
/// formats that expose an exception table, namely ELF, PE, and Mach-O; for the
/// others every member reports an empty result.
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
        let tbl = HandlerTable.add range landingPad tbl
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
    |> Array.fold buildExceptionTable IntervalMap.empty

  new(hdl: BinHandle) = ExceptionInfo(hdl.NewLiftingUnit())

  /// <summary>
  /// Every handler block range paired with the landing pad it dispatches to,
  /// ordered by range start. Blocks nest, so a range containing another comes
  /// before the one nested inside it.
  /// </summary>
  member _.ExceptionRanges with get() = HandlerTable.toArray exnTbl

  /// Returns an array of function entry points identified by the exception
  /// table.
  member _.FunctionEntryPoints with get() = fnRanges.Keys |> Seq.toArray

  /// <summary>
  /// The fraction of the code section, in [0, 1], covered by the frames that
  /// the exception table identifies as functions. This counts only the frames
  /// judged to be functions, not every frame in the table. The result is zero
  /// when the binary has no code section to measure against, which is the case
  /// for formats that carry no section structure.
  /// </summary>
  member _.ExceptionCoverage with get() =
    let ptr = BinFileOps.getCodeSectionPointer liftingUnit.File
    (* A null pointer would otherwise read as a one-byte window at address zero,
       which reports full coverage for a frame that happens to start there. *)
    if ptr.IsNull then 0.0
    else ExceptionCoverage.compute ptr.Addr ptr.MaxAddr fnRanges

  /// Checks if the given address is a function entry point according to the
  /// FDE records in the exception table.
  member _.ContainsFunctionEntryPoint addr = fnRanges.ContainsKey addr

  /// <summary>
  /// Finds the exception target (landing pad) for a given instruction address,
  /// or None when no handler block covers it. Handler blocks nest, so the
  /// innermost block covering the address wins, matching the block that catches
  /// first at run time.
  /// </summary>
  member _.TryFindExceptionTarget insAddr =
    HandlerTable.tryFindTarget insAddr exnTbl

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

namespace B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Represents the base strategy for identifying function entry points.
type FunctionIdentification(hdl: BinHandle, exnInfo: ExceptionInfo) =
  /// Checks if the given instruction jumps, rather than calls, into the given
  /// frame.
  let isJumpInto (frame: BinExceptionFrame) (ins: IInstruction) =
    match ins.DirectBranchTarget() with
    | true, target when not ins.IsCall ->
      frame.FunctionStart <= target && target <= frame.FunctionEnd
    | _ ->
      false

  /// Checks if the code of the given frame jumps into the given part, decoding
  /// the code from the given address on. Code that does not decode ends the
  /// search.
  let rec jumpsInto (lu: LiftingUnit) (frame: BinExceptionFrame) part addr =
    if addr > frame.FunctionEnd then
      false
    else
      match lu.TryParseInstruction(addr: Addr) with
      | Ok ins when isJumpInto part ins -> true
      | Ok ins -> jumpsInto lu frame part (addr + uint64 ins.Length)
      | Error _ -> false

  /// Checks if the latter of the given frames, which follows the former in the
  /// exception table, holds a part that a compiler split off the function of
  /// the former, such as a GCC cold part. GCC emits the frame of the part right
  /// after that of the function, and GNU ld places the part below the
  /// function, which jumps into it, whereas a function that merely comes after
  /// another lies above it.
  let isSplitOff lu (prev: BinExceptionFrame, frame: BinExceptionFrame) =
    frame.FunctionStart < prev.FunctionStart
    && jumpsInto lu prev frame prev.FunctionStart

  /// Finds the entries of the parts that compilers split off functions. GCC
  /// names each such part with a symbol of its own, and the exception table
  /// gives it the frame of a function when its function runs without a frame,
  /// yet its code carries on that function.
  let findSplitOffParts () =
    let lu = hdl.NewLiftingUnit()
    BinFileOps.getExceptionFrames hdl.File
    |> Seq.pairwise
    |> Seq.filter (isSplitOff lu)
    |> Seq.map (fun (_, frame) -> frame.FunctionStart)

  /// Returns an initial sequence of entry points obtained from
  /// the binary itself (e.g., from its symbol information). Therefore, if the
  /// binary is stripped, the returned sequence will be incomplete, and we need
  /// to expand it during the main recovery phase. The parts that compilers
  /// split off functions are left out, as they are no functions of their own.
  let getInitialEntryPoints () =
    let file = hdl.File
    let addrs = HashSet(BinFileOps.getFunctionAddresses file)
    for addr in exnInfo.FunctionEntryPoints do addrs.Add addr |> ignore
    file.EntryPoint
    |> Option.iter (fun addr ->
      if file.Format <> FileFormat.RawBinary && addr = 0UL then ()
      else addrs.Add addr |> ignore)
    addrs.ExceptWith(findSplitOffParts ())
    addrs |> Seq.toArray

  interface IFunctionIdentifiable with
    member _.Identify() = getInitialEntryPoints ()

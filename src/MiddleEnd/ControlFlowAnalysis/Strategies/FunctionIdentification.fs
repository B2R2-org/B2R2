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

open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Base strategy for identifying function entry points.
type FunctionIdentification<'FnCtx,
                            'GlCtx when 'FnCtx :> IResettable
                                    and 'FnCtx: (new: unit -> 'FnCtx)
                                    and 'GlCtx: (new: unit -> 'GlCtx)>
  public (hdl: BinHandle, exnInfo: ExceptionInfo) =

  let getFunctionOperationMode entry =
    match hdl.File.ISA.Arch with
    | Architecture.ARMv7 ->
      if entry &&& 1UL = 1UL then
        entry - 1UL, ArchOperationMode.ThumbMode
      else entry, ArchOperationMode.ARMMode
    | _ -> entry, ArchOperationMode.NoMode

  /// This function returns an initial sequence of entry points obtained from
  /// the binary itself (e.g., from its symbol information). Therefore, if the
  /// binary is stripped, the returned sequence will be incomplete, and we need
  /// to expand it during the main recovery phase.
  let getInitialEntryPoints () =
    let file = hdl.File
    let entries =
      file.GetFunctionAddresses ()
      |> Set.ofSeq
      |> Set.union exnInfo.FunctionEntryPoints
    file.EntryPoint
    |> Option.fold (fun acc addr ->
      if file.Type = FileType.LibFile && addr = 0UL then acc
      else Set.add addr acc) entries
    |> Set.toArray
    |> Array.map getFunctionOperationMode

  interface ICFGBuildingStrategy<'FnCtx, 'GlCtx> with
    member __.ActionPrioritizer with get() =
      { new IPrioritizable with member _.GetPriority _ = 0 }

    member __.FindCandidates (_builders) =
      getInitialEntryPoints ()

    member __.OnAction (_ctx, _queue, _action) = MoveOn
    member __.OnFinish (_ctx) = MoveOn
    member __.OnCyclicDependency (_) = Utils.impossible ()


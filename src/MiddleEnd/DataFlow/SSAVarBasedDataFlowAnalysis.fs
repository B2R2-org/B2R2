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

namespace B2R2.MiddleEnd.DataFlow.SSA

open B2R2.BinIR.SSA
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.DataFlow

/// SSA variable-based data flow analysis framework, which is based on the idea
/// of sparse conditional constant propagation algorithm by Wegman et al.
type SSAVarBasedDataFlowAnalysis<'Lattice>
  public (hdl, analysis: ISSAVarBasedDataFlowAnalysis<'Lattice>) =

  let processFlow (state: SSAVarBasedDataFlowState<_>) ssaCFG =
    match state.FlowWorkList.TryDequeue () with
    | false, _ -> ()
    | true, (parentId, myId) ->
      state.ExecutedEdges.Add (parentId, myId) |> ignore
      let blk = (ssaCFG: IDiGraph<SSABasicBlock, _>).FindVertexByID myId
      blk.VData.Internals.Statements
      |> Array.iter (fun (ppoint, stmt) ->
        analysis.Transfer ssaCFG blk ppoint stmt state)
      match blk.VData.Internals.LastStmt with
      | Jmp _ -> ()
      | _ -> (* Fall-through cases. *)
        ssaCFG.GetSuccs blk
        |> Seq.iter (fun succ ->
          state.MarkExecutable myId succ.ID)

  let processSSA (state: SSAVarBasedDataFlowState<_>) ssaCFG =
    match state.SSAWorkList.TryDequeue () with
    | false, _ -> ()
    | true, def ->
      match state.SSAEdges.Uses.TryGetValue def with
      | false, _ -> ()
      | _, uses ->
        for (vid, idx) in uses do
          let v = (ssaCFG: IDiGraph<SSABasicBlock, _>).FindVertexByID vid
          if state.GetNumIncomingExecutedEdges ssaCFG v > 0 then
            let ppoint, stmt = v.VData.Internals.Statements[idx]
            analysis.Transfer ssaCFG v ppoint stmt state
          else ()

  interface IDataFlowAnalysis<SSAVarPoint,
                              'Lattice,
                              SSAVarBasedDataFlowState<'Lattice>,
                              SSABasicBlock> with
    member _.InitializeState _vs =
      SSAVarBasedDataFlowState<'Lattice> (hdl, analysis)
      |> analysis.OnInitialize

    member _.Compute cfg (state: SSAVarBasedDataFlowState<'Lattice>) =
      state.SSAEdges <- SSAEdges cfg
      cfg.GetRoots ()
      |> Seq.iter (fun root -> state.FlowWorkList.Enqueue (0, root.ID))
      while state.FlowWorkList.Count > 0 || state.SSAWorkList.Count > 0 do
        processFlow state cfg
        processSSA state cfg
      state

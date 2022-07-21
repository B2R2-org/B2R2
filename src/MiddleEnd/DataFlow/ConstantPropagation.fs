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

namespace B2R2.MiddleEnd.DataFlow

open B2R2
open B2R2.BinIR.SSA
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// The constant propagation framework, which is a modified version of sparse
/// conditional constant propagation of Wegman et al.
[<AbstractClass>]
type ConstantPropagation<'L when 'L: equality> (ssaCFG) =
  inherit DataFlowAnalysis<'L, SSABasicBlock> ()

  /// Constant propagation state.
  abstract State: CPState<'L>

  member private __.GetNumIncomingExecutedEdges st (blk: SSAVertex) =
    let myid = blk.GetID ()
    DiGraph.GetPreds (ssaCFG, blk)
    |> List.map (fun p -> p.GetID (), myid)
    |> List.filter (fun (src, dst) -> CPState.isExecuted st src dst)
    |> List.length

  member private __.ProcessSSA st =
    while st.SSAWorkList.Count > 0 do
      let def = st.SSAWorkList.Pop ()
      match Map.tryFind def st.SSAEdges.Uses with
      | Some uses ->
        uses
        |> Set.iter (fun (vid, idx) ->
          let v = DiGraph.FindVertexByID (ssaCFG, vid)
          if __.GetNumIncomingExecutedEdges st v > 0 then
            let ppoint, stmt = v.VData.SSAStmtInfos[idx]
            st.CPCore.Transfer st ssaCFG v ppoint stmt
          else ())
      | None -> ()

  member private __.ProcessFlow st =
    if st.FlowWorkList.Count > 0 then
      let parentid, myid = st.FlowWorkList.Dequeue ()
      st.ExecutedEdges.Add (parentid, myid) |> ignore
      let blk = DiGraph.FindVertexByID (ssaCFG, myid)
      blk.VData.SSAStmtInfos
      |> Array.iter (fun (ppoint, stmt) ->
        st.CPCore.Transfer st ssaCFG blk ppoint stmt)
      if blk.VData.IsFakeBlock () then ()
      else
        match blk.VData.GetLastStmt () with
        | Jmp _ -> ()
        | _ -> (* Fall-through cases. *)
          DiGraph.GetSuccs (ssaCFG, blk)
          |> List.iter (fun succ ->
            let succid = succ.GetID ()
            CPState.markExecutable st myid succid)
    else ()

  member __.Compute (root: Vertex<_>) =
    __.State.FlowWorkList.Enqueue (0, root.GetID ())
    while __.State.FlowWorkList.Count > 0 || __.State.SSAWorkList.Count > 0 do
      __.ProcessFlow __.State
      __.ProcessSSA __.State
    __.State

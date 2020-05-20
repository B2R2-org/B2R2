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

namespace B2R2.DataFlow

open B2R2.BinIR.SSA
open B2R2.BinGraph

/// Modified version of sparse conditional constant propagation of Wegman et al.
type ConstantPropagation (hdl, ssaCFG: SSACFG) =
  inherit DataFlowAnalysis<CPValue, SSABBlock> ()

  override __.Top = Undef

  member private __.GetNumIncomingExecutableEdges st (blk: Vertex<SSABBlock>) =
    let myid = blk.GetID ()
    blk.Preds
    |> List.map (fun p -> p.GetID (), myid)
    |> List.filter (fun (src, dst) -> CPState.isExecutable st src dst)
    |> List.length

  member private __.ProcessSSA st =
    while st.SSAWorkList.Count > 0 do
      let def = st.SSAWorkList.Dequeue ()
      match Map.tryFind def st.SSAEdges.Uses with
      | Some uses ->
        uses
        |> Set.iter (fun (vid, idx) ->
          let v = ssaCFG.FindVertexByID vid
          if __.GetNumIncomingExecutableEdges st v > 0 then
            CPTransfer.evalStmt st v v.VData.Stmts.[idx]
          else ())
      | None -> ()

  member private __.ProcessFlow st =
    if st.FlowWorkList.Count > 0 then
      let _, myid = st.FlowWorkList.Dequeue ()
      let blk = ssaCFG.FindVertexByID myid
      blk.VData.Stmts
      |> Array.iter (fun stmt -> CPTransfer.evalStmt st blk stmt)
      match blk.VData.GetLastStmt () with
      | Jmp _ -> ()
      | _ ->
        blk.Succs
        |> List.iter (fun succ ->
          let succid = succ.GetID ()
          CPState.markExecutable st myid succid)
    else ()

  member __.Compute (root: Vertex<SSABBlock>) =
    let st = CPState.initState hdl ssaCFG
    st.FlowWorkList.Enqueue (0, root.GetID ())
    while st.FlowWorkList.Count > 0 || st.SSAWorkList.Count > 0 do
      __.ProcessFlow st
      __.ProcessSSA st
    st

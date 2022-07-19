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

module B2R2.MiddleEnd.ControlFlowGraph.SSAEdges

open B2R2
open B2R2.BinIR
open B2R2.MiddleEnd.BinGraph

type SSAStmtLocation = VertexID * int

type EdgeInfo = {
  /// A mapping from an SSA var to a set of use locations.
  Uses: Map<SSA.Variable, Set<SSAStmtLocation>>
  /// A mapping from an SSA var to its def stmt.
  Defs: Map<SSA.Variable, SSA.Stmt>
}

let private addUse var loc info =
  match Map.tryFind var info.Uses with
  | Some set -> Set.add loc set
  | None -> Set.singleton loc
  |> fun set -> { info with Uses = Map.add var set info.Uses }

let private addUses vars loc info =
  vars |> List.fold (fun acc v -> addUse v loc acc) info

let private addDef var stmt info =
  { info with Defs = Map.add var stmt info.Defs }

let private addDefs vars stmt info =
  vars |> List.fold (fun acc v -> addDef v stmt acc) info

let rec private computeUses loc expr acc =
  match expr with
  | SSA.Var v -> addUse v loc acc
  | SSA.Load (mem, _, addr) -> addUse mem loc acc |> computeUses loc addr
  | SSA.Store (mem, _, addr, v) ->
    addUse mem loc acc |> computeUses loc addr |> computeUses loc v
  | SSA.UnOp (_, _, e) -> computeUses loc e acc
  | SSA.BinOp (_, _, e1, e2) -> computeUses loc e1 acc |> computeUses loc e2
  | SSA.RelOp (_, _, e1, e2) -> computeUses loc e1 acc |> computeUses loc e2
  | SSA.Ite (cond, _, e1, e2) ->
    computeUses loc cond acc |> computeUses loc e1 |> computeUses loc e2
  | SSA.Cast (_, _, e) -> computeUses loc e acc
  | SSA.Extract (e, _, _) -> computeUses loc e acc
  | SSA.ReturnVal (_, _, v) -> addUse v loc acc
  | _ -> acc

/// Compute SSA edge map (SSA Var -> a set of (VertexID, Stmt idx)). From a
/// given ssa var, this function returns a set of SSA-edge destination.
let compute ssaCFG =
  let emptyInfo = { Uses = Map.empty; Defs = Map.empty }
  emptyInfo
  |> DiGraph.foldVertex ssaCFG (fun acc (v: SSAVertex) ->
    let vid = v.GetID ()
    v.VData.SSAStmtInfos
    |> Array.foldi (fun acc idx (_, stmt) ->
      match stmt with
      | SSA.LMark _ -> acc
      | SSA.ExternalCall (expr, inVars, outVars) ->
        let loc = vid, idx
        computeUses loc expr acc
        |> addDefs outVars stmt
        |> addUses inVars loc
      | SSA.SideEffect _ -> acc
      | SSA.Jmp (SSA.IntraJmp _) -> acc
      | SSA.Jmp (SSA.IntraCJmp (cond, _, _)) -> computeUses (vid, idx) cond acc
      | SSA.Jmp (SSA.InterJmp (target)) -> computeUses (vid, idx) target acc
      | SSA.Jmp (SSA.InterCJmp (cond, t1, t2)) ->
        let loc = vid, idx
        computeUses loc cond acc |> computeUses loc t1 |> computeUses loc t2
      | SSA.Def (v, e) ->
        let loc = vid, idx
        addDef v stmt acc
        |> computeUses loc e
      | SSA.Phi (v, ns) ->
        let loc = vid, idx
        let acc = addDef v stmt acc
        ns
        |> Array.fold (fun acc n ->
          let u = { v with Identifier = n }
          addUse u loc acc) acc
      ) acc |> fst)

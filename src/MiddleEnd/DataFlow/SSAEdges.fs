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

open System.Collections.Generic
open B2R2.BinIR
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

type private SSAStmtLocation = VertexID * int

/// SSA edges in a CFG.
[<AllowNullLiteral>]
type SSAEdges<'E when 'E: equality> (ssaCFG: SSACFG<'E>) =
  let uses = Dictionary<SSA.Variable, Set<SSAStmtLocation>> ()
  let defs = Dictionary<SSA.Variable, SSA.Stmt> ()

  let addUse var loc =
    match uses.TryGetValue var with
    | true, set ->
      uses[var] <- Set.add loc set
    | false, _ ->
      uses[var] <- Set.singleton loc

  let addUses vars loc =
    vars |> List.iter (fun v -> addUse v loc)

  let addDef var stmt =
    defs[var] <- stmt

  let addDefs vars stmt =
    vars |> List.iter (fun v -> addDef v stmt)

  let rec computeUses loc expr =
    match expr with
    | SSA.Var v ->
      addUse v loc
    | SSA.Load (mem, _, addr) ->
      addUse mem loc
      computeUses loc addr
    | SSA.Store (mem, _, addr, v) ->
      addUse mem loc
      computeUses loc addr
      computeUses loc v
    | SSA.UnOp (_, _, e) ->
      computeUses loc e
    | SSA.BinOp (_, _, e1, e2) ->
      computeUses loc e1
      computeUses loc e2
    | SSA.RelOp (_, _, e1, e2) ->
      computeUses loc e1
      computeUses loc e2
    | SSA.Ite (cond, _, e1, e2) ->
      computeUses loc cond
      computeUses loc e1
      computeUses loc e2
    | SSA.Cast (_, _, e) ->
      computeUses loc e
    | SSA.Extract (e, _, _) ->
      computeUses loc e
    | SSA.ReturnVal (_, _, e) ->
      computeUses loc e
    | _ -> ()

  /// Compute SSA edge map (SSA Var -> a set of (VertexID, Stmt idx)). From a
  /// given ssa var, this function returns a set of SSA-edge destination.
  let compute (ssaCFG: SSACFG<_>) =
    ssaCFG.IterVertex (fun (v: IVertex<SSABasicBlock>) ->
      let vid = v.ID
      for idx = 0 to v.VData.LiftedSSAStmts.Length - 1 do
        let stmt = snd v.VData.LiftedSSAStmts[idx]
        match stmt with
        | SSA.LMark _ -> ()
        | SSA.ExternalCall (expr, inVars, outVars) ->
          let loc = vid, idx
          computeUses loc expr
          addDefs outVars stmt
          addUses inVars loc
        | SSA.SideEffect _ -> ()
        | SSA.Jmp (SSA.IntraJmp _) -> ()
        | SSA.Jmp (SSA.IntraCJmp (cond, _, _)) ->
          computeUses (vid, idx) cond
        | SSA.Jmp (SSA.InterJmp (target)) ->
          computeUses (vid, idx) target
        | SSA.Jmp (SSA.InterCJmp (cond, t1, t2)) ->
          let loc = vid, idx
          computeUses loc cond
          computeUses loc t1
          computeUses loc t2
        | SSA.Def (v, e) ->
          let loc = vid, idx
          addDef v stmt
          computeUses loc e
        | SSA.Phi (v, ns) ->
          let loc = vid, idx
          addDef v stmt
          ns
          |> Array.iter (fun n -> addUse { v with Identifier = n } loc)
    )

  do compute ssaCFG

  /// A mapping from an SSA var to a set of use locations.
  member _.Uses with get() = uses

  /// A mapping from an SSA var to its def stmt.
  member _.Defs with get() = defs

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

module B2R2.MiddleEnd.DataFlow.SensitiveDFHelper

open B2R2
open B2R2.BinIR
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.DataFlow.LowUIRSensitiveDataFlow

let maxExpansionDepth = 64

let rec expandExpr state e = expandExprAux Set.empty 0 state e

and expandExprAux visited depth (state: State<_, _>) e =
  let depth = depth + 1
  match e with
  | _ when depth > maxExpansionDepth -> e
  | SSA.Var var when Set.contains var visited -> e
  | SSA.Var var ->
    let visited = Set.add var visited
    (* Note that we use fake definition for variables that are not defined in
       the current function. This is because we cannot find the definition of
       such variables, and we assume that they are defined in the caller
       function. *)
    match state.TryFindSSADefStmtFromSSAVar var with
    | Some(SSA.Def(_, e)) -> expandExprAux visited depth state e
    | None -> e
    | _ -> Terminator.impossible ()
  | SSA.ExprList [ e ] -> expandExprAux visited depth state e
  | SSA.ExprList el ->
    el |> List.map (expandExprAux visited depth state) |> SSA.ExprList
  | SSA.BinOp(op, rt, e1, e2) ->
    let e1' = expandExprAux visited depth state e1
    let e2' = expandExprAux visited depth state e2
    SSA.BinOp(op, rt, e1', e2')
  | SSA.UnOp(op, rt, e) ->
    let e' = expandExprAux visited depth state e
    SSA.UnOp(op, rt, e')
  | SSA.Extract(e, rt, i) ->
    let e' = expandExprAux visited depth state e
    SSA.Extract(e', rt, i)
  | SSA.Cast(castKind, rt, e) ->
    let e' = expandExprAux visited depth state e
    SSA.Cast(castKind, rt, e')
  | SSA.Load(memVar, rt, e) ->
    let e' = expandExprAux visited depth state e
    SSA.Load(memVar, rt, e')
  | SSA.Ite(cond, rt, tExpr, fExpr) ->
    let cond' = expandExprAux visited depth state cond
    let tExpr' = expandExprAux visited depth state tExpr
    let fExpr' = expandExprAux visited depth state fExpr
    SSA.Ite(cond', rt, tExpr', fExpr')
  | SSA.RelOp(op, rt, e1, e2) ->
    let e1' = expandExprAux visited depth state e1
    let e2' = expandExprAux visited depth state e2
    SSA.RelOp(op, rt, e1', e2')
  | SSA.Store(memVar, rt, addr, value) ->
    let addr' = expandExprAux visited depth state addr
    let value' = expandExprAux visited depth state value
    SSA.Store(memVar, rt, addr', value')
  | SSA.Num _
  | SSA.FuncName _
  | SSA.Undefined _ -> e

/// Returns the list of root variables for the given variables.
let rec findRootVars (state: State<_, _>) acc worklist =
  match worklist with
  | [] -> acc
  | var :: rest ->
    match state.TryFindSSADefStmtFromSSAVar var with
    | Some(SSA.Def(_, e)) ->
      match e with
      | SSA.Var rdVar -> findRootVars state acc (rdVar :: rest)
      | SSA.ExprList exprs ->
        exprs
        |> List.choose (function
          | SSA.Var rdVar -> Some rdVar
          | _ -> None)
        |> List.append rest
        |> findRootVars state acc
      | _ -> findRootVars state (var :: acc) rest
    | _ -> findRootVars state (var :: acc) rest

/// Returns the list of root variables, considering AND operators with jump
/// destination addresses. Note that this function must be given a non-expanded
/// expression.
let rec findRootVarsFromJumpDstVar (state: State<_, _>) acc worklist =
  match worklist with
  | [] -> acc
  | var :: rest ->
    match state.TryFindSSADefStmtFromSSAVar var with
    | Some(SSA.Def(_, e)) ->
      match e with
      | SSA.Var rdVar -> findRootVarsFromJumpDstVar state acc (rdVar :: rest)
      | SSA.BinOp(BinOpType.AND, _, SSA.ExprList [ SSA.Var var1 ],
                                    SSA.ExprList [ SSA.Var var2 ]) ->
        match expandExpr state (SSA.Var var1),
              expandExpr state (SSA.Var var2) with
        | SSA.Num bv_bitmask, SSA.Num _bv_dst
          when bv_bitmask.BigValue = bigint 0xffffffffUL ->
          findRootVarsFromJumpDstVar state acc (var2 :: rest)
        | SSA.Num _bv_dst, SSA.Num bv_bitmask
          when bv_bitmask.BigValue = bigint 0xffffffffUL ->
          findRootVarsFromJumpDstVar state acc (var1 :: rest)
        | _ -> acc
      | SSA.ExprList exprs ->
        exprs
        |> List.choose (function
          | SSA.Var rdVar -> Some rdVar
          | _ -> None)
        |> List.append rest
        |> findRootVarsFromJumpDstVar state acc
      | _ -> findRootVarsFromJumpDstVar state (var :: acc) rest
    | _ -> findRootVarsFromJumpDstVar state (var :: acc) rest

let extractVarsFromExpr e =
  match e with
  | SSA.Var var -> [ var ]
  | SSA.ExprList exprs ->
    exprs
    |> List.choose (function
      | SSA.Var var -> Some var
      | _ -> None)
  | _ -> []

let findRootVarsFromJumpDstExpr state e =
  extractVarsFromExpr e
  |> findRootVarsFromJumpDstVar state []

let findRootVarsFromExpr state e =
  extractVarsFromExpr e
  |> findRootVars state []

let getDefSiteVertex (g: IDiGraph<_, _>) (state: State<_, _>) var =
  let svp = state.SSAVarToDefSVP var
  let spp = svp.SensitiveProgramPoint
  let pp = spp.ProgramPoint
  if ProgramPoint.IsFake pp then
    g.SingleRoot
  else
    assert state.StmtOfBBLs.ContainsKey pp
    snd state.StmtOfBBLs[pp]

let getTerminator (state: State<_, _>) v tag =
  let sstmts = state.GetSSAStmts(v, tag)
  assert (not << Seq.isEmpty) sstmts
  Array.last sstmts

let constantFoldSensitiveVPs (state: State<_, _>)
                             vars =
  vars
  |> List.map state.DomainSubState.GetAbsValue
  |> List.fold ConstantDomain.join ConstantDomain.Undef

let constantFoldSSAVars (state: State<_, _>) vars =
  vars
  |> List.map state.SSAVarToDefSVP
  |> constantFoldSensitiveVPs state

let private tryJoinExprs e1 e2 =
  match e1, e2 with
  | SSA.ExprList vars1, SSA.ExprList vars2 ->
    vars1 @ vars2
    |> SSA.ExprList
    |> Some
  | SSA.Var _v1, SSA.Var _v2 ->
    [ e1; e2 ]
    |> SSA.ExprList
    |> Some
  | SSA.Var _v1, SSA.ExprList exprs2 ->
    SSA.ExprList(e1 :: exprs2)
    |> Some
  | SSA.ExprList exprs1, SSA.Var _v2 ->
    SSA.ExprList(e2 :: exprs1)
    |> Some
  | SSA.Num bv1, SSA.Num bv2 when bv1 = bv2 ->
    SSA.Num bv1
    |> Some
  | _ -> None

/// Over-approximates the terminator of a vertex `v` by considering all possible
/// tags. This returns None if the vertex has inconsistent terminators for
/// different tags.
let tryOverApproximateTerminator (state: State<_, _>) v =
  assert state.PerVertexPossibleExeCtxs.ContainsKey v
  let tags = state.PerVertexPossibleExeCtxs[v]
  let terminators = Seq.map (getTerminator state v) tags
  assert (not <| Seq.isEmpty terminators)
  let first = Seq.head terminators
  Seq.tail terminators
  |> Seq.fold (fun acc t ->
    match acc, t with
    | Some(SSA.Jmp jmp1), SSA.Jmp jmp2 ->
      match jmp1, jmp2 with
      | SSA.InterJmp dst1, SSA.InterJmp dst2 ->
        tryJoinExprs dst1 dst2
        |> Option.map (fun dst -> SSA.Jmp(SSA.InterJmp dst))
      | SSA.InterCJmp(cond1, tDst1, fDst1),
        SSA.InterCJmp(cond2, tDst2, fDst2) ->
        let cond = tryJoinExprs cond1 cond2
        let tDst = tryJoinExprs tDst1 tDst2
        let fDst = tryJoinExprs fDst1 fDst2
        match cond, tDst, fDst with
        (* Currently, we allow the condtion to be None, as we do not care if
           conditions can be joined or not. *)
        | _, None, _
        | _, _, None -> None
        | _, Some tDst, Some fDst ->
          Some <| SSA.Jmp(SSA.InterCJmp(cond1, tDst, fDst))
      | _ -> None
    | Some(SSA.SideEffect eff1), SSA.SideEffect eff2 when eff1 = eff2 ->
      Some <| SSA.SideEffect eff1
    | _ -> None) (Some first)

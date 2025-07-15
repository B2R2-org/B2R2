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

/// TODO: Rename. We may introduce a modulle named `SensitiveDFA`, and put
/// related stuffs into that module.
module B2R2.MiddleEnd.DataFlow.SensitiveDFAHelper

open B2R2.BinIR
open B2R2.MiddleEnd.DataFlow

let getTerminator (state: SensitiveLowUIRDataFlowState<_, _, _>) v tag =
  let sstmts = state.GetSSAStmts v tag
  assert (not << Seq.isEmpty) sstmts
  Array.last sstmts

let constantFoldSensitiveVPs (state: SensitiveLowUIRDataFlowState<_, _, _>)
                             vars =
  vars
  |> List.map state.DomainSubState.GetAbsValue
  |> List.fold ConstantDomain.join ConstantDomain.Undef

let constantFoldSSAVars (state: SensitiveLowUIRDataFlowState<_, _, _>) vars =
  vars
  |> List.map (state.SSAVarToUid >> state.UidToDef)
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
    SSA.ExprList (e1 :: exprs2)
    |> Some
  | SSA.ExprList exprs1, SSA.Var _v2 ->
    SSA.ExprList (e2 :: exprs1)
    |> Some
  | SSA.Num bv1, SSA.Num bv2 when bv1 = bv2 ->
    SSA.Num bv1
    |> Some
  | _ -> None

/// Over-approximates the terminator of a vertex `v` by considering all possible
/// tags. This returns None if the vertex has inconsistent terminators for
/// different tags.
let tryOverApproximateTerminator (state: SensitiveLowUIRDataFlowState<_, _, _>)
                                 v =
  assert state.PerVertexPossibleTags.ContainsKey v
  let tags = state.PerVertexPossibleTags[v]
  let terminators = Seq.map (getTerminator state v) tags
  assert (not <| Seq.isEmpty terminators)
  let first = Seq.head terminators
  Seq.tail terminators
  |> Seq.fold (fun acc t ->
    match acc, t with
    | Some (SSA.Jmp jmp1), SSA.Jmp jmp2 ->
      match jmp1, jmp2 with
      | SSA.InterJmp dst1, SSA.InterJmp dst2 ->
        tryJoinExprs dst1 dst2
        |> Option.map (fun dst -> SSA.Jmp (SSA.InterJmp dst))
      | SSA.InterCJmp (cond1, tDst1, fDst1),
        SSA.InterCJmp (cond2, tDst2, fDst2) ->
        let cond = tryJoinExprs cond1 cond2
        let tDst = tryJoinExprs tDst1 tDst2
        let fDst = tryJoinExprs fDst1 fDst2
        match cond, tDst, fDst with
        (* Currently, we allow the condtion to be None, as we do not care if
           conditions can be joined or not. *)
        | _, None, _
        | _, _, None -> None
        | _, Some tDst, Some fDst ->
          Some <| SSA.Jmp (SSA.InterCJmp (cond1, tDst, fDst))
      | _ -> None
    | Some (SSA.SideEffect eff1), SSA.SideEffect eff2 when eff1 = eff2 ->
      Some <| SSA.SideEffect eff1
    | _ -> None) (Some first)

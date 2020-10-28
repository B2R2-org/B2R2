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

module B2R2.MiddleEnd.DataFlow.UVPropTransfer

open B2R2
open B2R2.BinIR
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinEssence
open B2R2.MiddleEnd.Lens
open B2R2.BinIR.SSA

let evalLoad st m rt addr =
  match addr with
  | StackValue.Const addr -> BitVector.toUInt64 addr |> CPState.findMem st m rt
  | _ -> Touched

let evalReturn (st: CPState<UVPropValue>) addr ret v =
  match v.Kind with
  | RegVar _ -> CPState.findReg st v
  | _ -> Utils.impossible ()

let rec evalExpr ess cfg stackSt st blk = function
  | Num _ -> Touched
  | Var v -> CPState.findReg st v
  | Nil -> Touched
  | Load (m, rt, addr) ->
    StackTransfer.evalExpr ess cfg stackSt blk addr |> evalLoad st m rt
  | UnOp _ -> Touched
  | FuncName _ -> Touched
  | BinOp _ -> Touched
  | RelOp _ -> Touched
  | Ite _ -> Touched
  | Cast _ -> Touched
  | Extract _ -> Touched
  | Undefined _ -> Touched
  | ReturnVal (addr, ret, v) -> evalReturn st addr ret v
  | _ -> Utils.impossible ()

let evalMemDef ess cfg stackSt st blk mDst e =
  let dstid = mDst.Identifier
  match e with
  | Store (mSrc, rt, addr, v) ->
    let c = evalExpr ess cfg stackSt st blk v
    let addr = StackTransfer.evalExpr ess cfg stackSt blk addr
    let oldMem = st.MemState.TryGetValue dstid |> Utils.tupleToOpt
    CPState.copyMem st dstid mSrc.Identifier
    match addr with
    | StackValue.Const addr ->
      let addr = BitVector.toUInt64 addr
      match oldMem with
      | Some (oldMem, _) ->
        CPState.storeToDefinedMem oldMem st mDst rt addr c
      | None -> CPState.storeToFreshMem st mDst rt addr c
    | _ ->
      if st.MemState.[dstid] |> snd |> Set.isEmpty |> not then
        st.SSAWorkList.Push mDst
  | ReturnVal (_, _, mSrc) -> CPState.copyMem st dstid mSrc.Identifier
  | _ ->  Utils.impossible ()

let inline updateConst st r v =
  if not (st.RegState.ContainsKey r) then
    st.RegState.[r] <- v
    st.SSAWorkList.Push r
  elif st.RegState.[r] = v then ()
  elif UVPropValue.goingUp st.RegState.[r] v then ()
  else
    st.RegState.[r] <- UVPropValue.meet st.RegState.[r] v
    st.SSAWorkList.Push r

let evalDef ess cfg stackSt st blk v e =
  match v.Kind with
  | RegVar _ | TempVar _ ->
    evalExpr ess cfg stackSt st blk e |> updateConst st v
  | MemVar -> evalMemDef ess cfg stackSt st blk v e
  | PCVar _ -> ()

let executableSources cfg st (blk: Vertex<_>) srcIDs =
  let preds = DiGraph.getPreds cfg blk
  srcIDs
  |> Array.mapi (fun i srcID ->
    let p = List.item i preds
    if not <| CPState.isExecuted st (p.GetID ()) (blk.GetID ()) then None
    else Some srcID)
  |> Array.choose id

let evalPhi mergePointMap cfg st blk dst srcIDs =
  match executableSources cfg st blk srcIDs with
  | [||] -> ()
  | executableSrcIDs ->
    match dst.Kind with
    | RegVar _ | TempVar _ ->
      match CPState.tryFindReg st dst with
      | Some Touched -> ()
      | _ ->
        executableSrcIDs
        |> Array.map (fun i ->
          { dst with Identifier = i } |> CPState.tryFindReg st)
        |> Array.choose id
        |> Array.reduce UVPropValue.meet
        |> fun merged -> updateConst st dst merged
    | MemVar ->
      let dstid = dst.Identifier
      let oldMem = st.MemState.TryGetValue dstid |> Utils.tupleToOpt
      let mergePoints =
        match Map.tryFind blk mergePointMap with
        | Some mergePoints -> mergePoints
        | None -> Set.empty
      CPState.mergeMemWithMergePoints st oldMem mergePoints dst executableSrcIDs
    | PCVar _ -> ()

let markAllSuccessors cfg st (blk: Vertex<SSABBlock>) =
  let myid = blk.GetID ()
  DiGraph.getSuccs cfg blk
  |> List.iter (fun succ ->
    let succid = succ.GetID ()
    CPState.markExecutable st myid succid)

let markSuccessorsConditionally cfg st (blk: Vertex<SSABBlock>) cond =
  let myid = blk.GetID ()
  DiGraph.getSuccs cfg blk
  |> List.iter (fun succ ->
    if cond succ then
      let succid = succ.GetID ()
      CPState.markExecutable st myid succid
    else ())

let evalInterJmp cfg st blk =
  (fun (succ: Vertex<SSABBlock>) ->
    DiGraph.findEdgeData cfg blk succ <> CallFallThroughEdge)
  |> markSuccessorsConditionally cfg st blk

let evalJmp cfg st blk = function
  | InterJmp _ -> evalInterJmp cfg st blk
  | _ -> markAllSuccessors cfg st blk

let evalStmt stackSt mergePointMap ess cfg st blk _ppoint = function
  | Def (v, e) -> evalDef ess cfg stackSt st blk v e
  | Phi (v, ns) -> evalPhi mergePointMap cfg st blk v ns
  | Jmp jmpTy -> evalJmp cfg st blk jmpTy
  | LMark _ | SideEffect _ -> ()

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

module B2R2.MiddleEnd.DataFlow.StackTransfer

open B2R2
open B2R2.BinIR
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinEssence
open B2R2.MiddleEnd.Lens
open B2R2.BinIR.SSA

let evalBinOp op c1 c2 =
  match op with
  | BinOpType.ADD -> StackValue.add c1 c2
  | BinOpType.SUB -> StackValue.sub c1 c2
  | BinOpType.AND -> StackValue.``and`` c1 c2
  | _ -> NotAConst

let isStackRelatedRegister (st: CPState<StackValue>) regid =
  st.BinHandle.RegisterBay.IsStackPointer regid ||
    st.BinHandle.RegisterBay.IsFramePointer regid

let evalReturn (st: CPState<StackValue>) v =
  match v.Kind with
  | RegVar (rt, rid, _) ->
    let hdl = st.BinHandle
    if isStackRelatedRegister st rid then
      let c = CPState.findReg st v
      let wordByte = RegType.toByteWidth rt |> uint64
      let wordSize = Const (BitVector.ofUInt64 wordByte rt)
      if hdl.RegisterBay.IsStackPointer rid then
        evalBinOp BinOpType.ADD c wordSize
      else c
    else NotAConst
  | _ -> Utils.impossible ()

let rec evalExpr st = function
  | Num bv -> Const bv
  | Var v -> CPState.findReg st v
  | Nil -> NotAConst
  | Load _ -> NotAConst
  | UnOp _ -> NotAConst
  | FuncName _ -> NotAConst
  | BinOp (op, _, e1, e2) ->
    let c1 = evalExpr st e1
    let c2 = evalExpr st e2
    evalBinOp op c1 c2
  | RelOp _ -> NotAConst
  | Ite _ -> NotAConst
  | Cast _ -> NotAConst
  | Extract _ -> NotAConst
  | Undefined _ -> NotAConst
  | ReturnVal (_, _, v) -> evalReturn st v
  | _ -> Utils.impossible ()

let inline updateConst st r v =
  if not (st.RegState.ContainsKey r) then
    st.RegState.[r] <- v
    st.SSAWorkList.Push r
  elif st.RegState.[r] = v then ()
  elif st.GoingUp st.RegState.[r] v then ()
  else
    st.RegState.[r] <- st.Meet st.RegState.[r] v
    st.SSAWorkList.Push r

let evalDef (st: CPState<StackValue>) v e =
  match v.Kind with
  | RegVar (_, regid, _) when isStackRelatedRegister st regid ->
    evalExpr st e |> updateConst st v
  | RegVar _ -> updateConst st v NotAConst
  | TempVar _ -> evalExpr st e |> updateConst st v
  | MemVar -> ()
  | PCVar _ -> ()

let executableSources cfg st (blk: Vertex<_>) srcIDs =
  srcIDs
  |> Array.mapi (fun i srcID ->
    let p = DiGraph.getPreds cfg blk |> List.item i
    if not <| CPState.isExecuted st (p.GetID ()) (blk.GetID ()) then None
    else Some srcID)
  |> Array.choose id

let evalPhi cfg st blk dst srcIDs =
  match executableSources cfg st blk srcIDs with
  | [||] -> ()
  | executableSrcIDs ->
    match dst.Kind with
    | RegVar _ | TempVar _ ->
      executableSrcIDs
      |> Array.map (fun i ->
        { dst with Identifier = i } |> CPState.tryFindReg st)
      |> Array.choose id
      |> Array.reduce st.Meet
      |> fun merged -> updateConst st dst merged
    | MemVar -> ()
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

let evalStmt cfg st blk _ppoint = function
  | Def (v, e) -> evalDef st v e
  | Phi (v, ns) -> evalPhi cfg st blk v ns
  | Jmp jmpTy -> evalJmp cfg st blk jmpTy
  | LMark _ | SideEffect _ -> ()

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

module B2R2.DataFlow.CopyTransfer

open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.Intel
open B2R2.BinIR
open B2R2.BinGraph
open B2R2.BinEssence
open B2R2.Lens
open B2R2.BinIR.SSA

let private isGetPCThunkCode = function
  | 0xc324048bUL | 0xc3241c8bUL | 0xc3240c8bUL | 0xc324148bUL
  | 0xc324348bUL | 0xc3243c8bUL | 0xc3242c8bUL -> true
  | _ -> false

/// This is a heuristic to discover __x86.get_pc_thunk- family functions.
/// 1. If a function name symbol exists and its name matches, then we know it is
/// __x86.get_pc_thunk- family
/// 2. But there are some cases we don't have symbols for them. In such cases,
/// we directly compare first 4 bytes of byte code. Because __x86.get_pc_thunk-
/// family only has 4 bytes for its function body and their values are fixed.
let private isGetPCThunk hdl addr =
  if addr = 0UL then false
  else
    match hdl.FileInfo.TryFindFunctionSymbolName addr |> Utils.tupleToOpt with
    | Some name -> name.StartsWith "__x86.get_pc_thunk"
    | None -> BinHandler.ReadUInt (hdl, addr, 4) |> isGetPCThunkCode

let evalLoad st m rt addr =
  match addr with
  | StackValue.Const addr -> BitVector.toUInt64 addr |> CPState.findMem st m rt
  | _ -> NotAConst

let evalBinOp op c1 c2 =
  match op with
  | BinOpType.ADD -> CopyValue.add c1 c2
  | _ -> NotAConst

let evalReturn (st: CPState<CopyValue>) addr ret v =
  match v.Kind with
  | RegVar (rt, rid, _) ->
    let hdl = st.BinHandler
    if isGetPCThunk hdl addr then
      Thunk (BitVector.ofUInt64 ret rt)
    elif CallingConvention.isNonVolatile hdl rid then
      CPState.findReg st v
    else NotAConst
  | _ -> Utils.impossible ()

let rec evalExpr stackSt st = function
  | Num bv -> Const bv
  | Var v -> CPState.findReg st v
  | Nil -> NotAConst
  | Load (m, rt, addr) ->
    StackTransfer.evalExpr stackSt addr |> evalLoad st m rt
  | UnOp _ -> NotAConst
  | FuncName _ -> NotAConst
  | BinOp (op, _, e1, e2) ->
    let c1 = evalExpr stackSt st e1
    let c2 = evalExpr stackSt st e2
    evalBinOp op c1 c2
  | RelOp _ -> NotAConst
  | Ite _ -> NotAConst
  | Cast _ -> NotAConst
  | Extract _ -> NotAConst
  | Undefined _ -> NotAConst
  | ReturnVal (addr, ret, v) -> evalReturn st addr ret v
  | _ -> Utils.impossible ()

let evalMemDef stackSt st mDst e =
  let dstid = mDst.Identifier
  match e with
  | Store (mSrc, rt, addr, v) ->
    let c = evalExpr stackSt st v
    let addr = StackTransfer.evalExpr stackSt addr
    let oldMem = st.MemState.TryGetValue dstid |> Utils.tupleToOpt
    CPState.copyMem st dstid mSrc.Identifier
    match addr with
    | StackValue.Const addr ->
      let addr = BitVector.toUInt64 addr
      match oldMem with
      | Some (oldMem, _) -> CPState.storeToDefinedMem oldMem st mDst rt addr c
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
  elif st.GoingUp st.RegState.[r] v then ()
  else
    st.RegState.[r] <- st.Meet st.RegState.[r] v
    st.SSAWorkList.Push r

let evalDef stackSt (st: CPState<CopyValue>) v e =
  match v.Kind with
  | RegVar _ | TempVar _ -> evalExpr stackSt st e |> updateConst st v
  | MemVar -> evalMemDef stackSt st v e
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
    | MemVar ->
      let dstid = dst.Identifier
      let oldMem = st.MemState.TryGetValue dstid |> Utils.tupleToOpt
      CPState.mergeMem st oldMem dst executableSrcIDs
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

let evalIntraCJmp cfg st blk cond trueLbl falseLbl =
  match cond with
  | Const bv ->
    (fun (succ: Vertex<SSABBlock>) ->
      let target = if BitVector.isTrue bv then trueLbl else falseLbl
      match succ.VData.SSAStmtInfos.[0] with
      | _, LMark lbl -> lbl = target
      | _ -> false)
    |> markSuccessorsConditionally cfg st blk
  | _ -> markAllSuccessors cfg st blk

let evalInterJmp cfg st blk = function
  | Num addr ->
    (fun (succ: Vertex<SSABBlock>) ->
      succ.VData.PPoint.Address = BitVector.toUInt64 addr)
    |> markSuccessorsConditionally cfg st blk
  | _ ->
    let insInfos = blk.VData.InsInfos
    if insInfos.[Array.length insInfos - 1].Instruction.IsCall () then
      (fun (succ: Vertex<SSABBlock>) ->
        succ.VData.PPoint |> ProgramPoint.IsFake)
      |> markSuccessorsConditionally cfg st blk
    else markAllSuccessors cfg st blk

let evalInterCJmp cfg st blk cond trueExpr falseExpr =
  match cond, trueExpr, falseExpr with
  | Const bv, Num trueAddr, Num falseAddr ->
    (fun (succ: Vertex<SSABBlock>) ->
      let target = if BitVector.isTrue bv then trueAddr else falseAddr
      succ.VData.PPoint.Address = BitVector.toUInt64 target)
    |> markSuccessorsConditionally cfg st blk
  | Const bv, Var _, Num falseAddr ->
    (fun (succ: Vertex<SSABBlock>) ->
      if BitVector.isTrue bv then
        succ.VData.PPoint.Address <> BitVector.toUInt64 falseAddr
      else succ.VData.PPoint.Address = BitVector.toUInt64 falseAddr)
    |> markSuccessorsConditionally cfg st blk
  | Const bv, Num trueAddr, Var _ ->
    (fun (succ: Vertex<SSABBlock>) ->
      if BitVector.isTrue bv then
        succ.VData.PPoint.Address = BitVector.toUInt64 trueAddr
      else succ.VData.PPoint.Address <> BitVector.toUInt64 trueAddr)
    |> markSuccessorsConditionally cfg st blk
  | _ -> markAllSuccessors cfg st blk

let evalJmp cfg st blk = function
  | InterJmp expr -> evalInterJmp cfg st blk expr
  | _ -> markAllSuccessors cfg st blk

let evalStmt stackSt cfg st blk _ppoint = function
  | Def (v, e) -> evalDef stackSt st v e
  | Phi (v, ns) -> evalPhi cfg st blk v ns
  | Jmp jmpTy -> evalJmp cfg st blk jmpTy
  | LMark _ | SideEffect _ -> ()

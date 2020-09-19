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

module B2R2.MiddleEnd.DataFlow.TaintTransfer

open B2R2
open B2R2.BinIR
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinEssence
open B2R2.MiddleEnd.Lens
open B2R2.BinIR.SSA

let evalLoad st m rt addr =
  match addr with
  | StackValue.Const addr -> BitVector.toUInt64 addr |> CPState.findMem st m rt
  | _ -> Untainted

let evalReturn (st: CPState<TaintValue>) addr ret v =
  match v.Kind with
  | RegVar _ -> CPState.findReg st v
  | _ -> Utils.impossible ()

let rec evalExpr stackSt st = function
  | Num _ -> Untainted
  | Var v -> CPState.findReg st v
  | Nil -> Untainted
  | Load (m, rt, addr) ->
    StackTransfer.evalExpr stackSt addr |> evalLoad st m rt
  | UnOp _ -> Untainted
  | FuncName _ -> Untainted
  | BinOp _ -> Untainted
  | RelOp _ -> Untainted
  | Ite _ -> Untainted
  | Cast _ -> Untainted
  | Extract _ -> Untainted
  | Undefined _ -> Untainted
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
  elif TaintValue.goingUp st.RegState.[r] v then ()
  else
    st.RegState.[r] <- TaintValue.meet st.RegState.[r] v
    st.SSAWorkList.Push r

let evalDef stackSt st v e =
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
      |> Array.reduce TaintValue.meet
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

let evalInterJmp cfg st blk = function
  | Num addr ->
    (fun (succ: Vertex<SSABBlock>) ->
      DiGraph.findEdgeData cfg blk succ <> CallFallThroughEdge)
    |> markSuccessorsConditionally cfg st blk
  | _ ->
    let insInfos = blk.VData.InsInfos
    if insInfos.[Array.length insInfos - 1].Instruction.IsCall () then
      (fun (succ: Vertex<SSABBlock>) ->
        succ.VData.PPoint |> ProgramPoint.IsFake)
      |> markSuccessorsConditionally cfg st blk
    else markAllSuccessors cfg st blk

let evalJmp cfg st blk = function
  | InterJmp expr -> evalInterJmp cfg st blk expr
  | _ -> markAllSuccessors cfg st blk

let evalStmt stackSt cfg st blk ppoint = function
  | Def (v, e) -> evalDef stackSt st v e
  | Phi (v, ns) -> evalPhi cfg st blk v ns
  | Jmp jmpTy -> evalJmp cfg st blk jmpTy
  | LMark _ | SideEffect _ -> ()

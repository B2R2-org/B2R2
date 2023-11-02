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

module B2R2.MiddleEnd.DataFlow.SPTransfer

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.BinIR.SSA

let evalBinOp op c1 c2 =
  match op with
  | BinOpType.ADD -> SPValue.add c1 c2
  | BinOpType.SUB -> SPValue.sub c1 c2
  | BinOpType.AND -> SPValue.``and`` c1 c2
  | _ -> NotAConst

let isStackRelatedRegister (st: CPState<SPValue>) regid =
  st.BinHandle.RegisterFactory.IsStackPointer regid
  || st.BinHandle.RegisterFactory.IsFramePointer regid

let evalReturn (st: CPState<SPValue>) (blk: SSAVertex) var =
  match var.Kind with
  | RegVar (rt, rid, _) ->
    let hdl = st.BinHandle
    if isStackRelatedRegister st rid then
      if hdl.RegisterFactory.IsStackPointer rid then
        let value = CPState.findReg st var
        let shiftAmount = Const (Utils.computeStackShift rt blk)
        evalBinOp BinOpType.ADD value shiftAmount
      else CPState.findReg st var
    else NotAConst
  | _ -> Utils.impossible ()

let rec evalExpr st blk = function
  | Num bv -> Const bv
  | Var v -> CPState.findReg st v
  | Nil -> NotAConst
  | Load _ -> NotAConst
  | UnOp _ -> NotAConst
  | FuncName _ -> NotAConst
  | BinOp (op, _, e1, e2) ->
    let c1 = evalExpr st blk e1
    let c2 = evalExpr st blk e2
    evalBinOp op c1 c2
  | RelOp _ -> NotAConst
  | Ite _ -> NotAConst
  | Cast _ -> NotAConst
  | Extract _ -> NotAConst
  | Undefined _ -> NotAConst
  | ReturnVal (addr, _, v) -> evalReturn st blk v
  | _ -> Utils.impossible ()

let evalDef (st: CPState<SPValue>) blk v e =
  match v.Kind with
  | RegVar (_, regid, _) when isStackRelatedRegister st regid ->
    evalExpr st blk e |> CPState.updateConst st v
  | RegVar _ -> CPState.updateConst st v NotAConst
  | TempVar _ -> evalExpr st blk e |> CPState.updateConst st v
  | _ -> ()

let evalPhi st cfg blk dst srcIDs =
  match CPState.getExecutableSources st cfg blk srcIDs with
  | [||] -> ()
  | executableSrcIDs ->
    match dst.Kind with
    | RegVar _ | TempVar _ ->
      executableSrcIDs
      |> Array.choose (fun i ->
        { dst with Identifier = i } |> CPState.tryFindReg st true)
      |> Array.reduce st.CPCore.Meet
      |> fun merged -> CPState.updateConst st dst merged
    | _ -> ()

let evalJmp st cfg blk = function
  | InterJmp _ -> CPState.markExceptCallFallThrough st cfg blk
  | _ -> CPState.markAllSuccessors st cfg blk

let evalStmt st cfg blk = function
  | Def (v, e) -> evalDef st blk v e
  | Phi (v, ns) -> evalPhi st cfg blk v ns
  | Jmp jmpTy -> evalJmp st cfg blk jmpTy
  | LMark _ | ExternalCall _ | SideEffect _ -> ()

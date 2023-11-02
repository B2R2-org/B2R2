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

module B2R2.MiddleEnd.DataFlow.SCPTransfer

open B2R2
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowGraph

let private updateReadOnlyMem st mDst rt addr c =
  let align = RegType.toByteWidth rt |> uint64
  let dstid = mDst.Identifier
  let mem, updated = st.MemState[dstid]
  if (rt = st.DefaultWordSize) && (addr % align = 0UL) then
    let mem = Map.add addr c mem
    st.MemState[dstid] <- (mem, updated)
  else ()

let evalLoad st m rt addr =
  match addr with
  | Const addr ->
    let addr = BitVector.ToUInt64 addr
    match CPState.tryFindMem st m rt addr with
    | Some v -> v
    | None ->
      match st.CPCore.MemoryRead addr rt with
      | Some v ->
        let v = Const v (* Found a read-only memory contents, so update it. *)
        updateReadOnlyMem st m rt addr v
        v
      | None -> CPState.updateUninitialized st m addr
  | _ -> NotAConst

let evalUnOp op c =
  match op with
  | UnOpType.NEG -> SCPValue.neg c
  | UnOpType.NOT -> SCPValue.not c
  | _ -> NotAConst

let evalBinOp op c1 c2 =
  match op with
  | BinOpType.ADD -> SCPValue.add c1 c2
  | BinOpType.SUB -> SCPValue.sub c1 c2
  | BinOpType.MUL -> SCPValue.mul c1 c2
  | BinOpType.DIV -> SCPValue.div c1 c2
  | BinOpType.SDIV -> SCPValue.sdiv c1 c2
  | BinOpType.MOD -> SCPValue.``mod`` c1 c2
  | BinOpType.SMOD -> SCPValue.smod c1 c2
  | BinOpType.SHL -> SCPValue.shl c1 c2
  | BinOpType.SHR -> SCPValue.shr c1 c2
  | BinOpType.SAR -> SCPValue.sar c1 c2
  | BinOpType.AND -> SCPValue.``and`` c1 c2
  | BinOpType.OR -> SCPValue.``or`` c1 c2
  | BinOpType.XOR -> SCPValue.xor c1 c2
  | BinOpType.CONCAT -> SCPValue.concat c1 c2
  | _ -> NotAConst

let evalRelOp op c1 c2 =
  match op with
  | RelOpType.EQ -> SCPValue.eq c1 c2
  | RelOpType.NEQ -> SCPValue.neq c1 c2
  | RelOpType.GT -> SCPValue.gt c1 c2
  | RelOpType.GE -> SCPValue.ge c1 c2
  | RelOpType.SGT -> SCPValue.sgt c1 c2
  | RelOpType.SGE -> SCPValue.sge c1 c2
  | RelOpType.LT -> SCPValue.lt c1 c2
  | RelOpType.LE -> SCPValue.le c1 c2
  | RelOpType.SLT -> SCPValue.slt c1 c2
  | RelOpType.SLE -> SCPValue.sle c1 c2
  | _ -> NotAConst

let evalCast op rt c =
  match op with
  | CastKind.SignExt -> SCPValue.signExt rt c
  | CastKind.ZeroExt -> SCPValue.zeroExt rt c
  | _ -> NotAConst

let evalReturn st (blk: SSAVertex) ret var =
  match var.Kind with
  | RegVar (rt, rid, _) ->
    let hdl = st.BinHandle
    let fakeBlockInfo = blk.VData.FakeBlockInfo
    if hdl.RegisterFactory.IsStackPointer rid then
      let value = CPState.findReg st var
      let shiftAmount = Const (Utils.computeStackShift rt blk)
      evalBinOp BinOpType.ADD value shiftAmount
    elif GetPCThunkInfo.isGetPCThunk fakeBlockInfo.GetPCThunkInfo then
      Thunk (BitVector.OfUInt64 ret rt)
    elif CallingConvention.isNonVolatile hdl OS.Linux rid then
      CPState.findReg st var
    else NotAConst
  | _ -> Utils.impossible ()

let rec evalExpr st blk = function
  | Num bv -> Const bv
  | Var v -> CPState.findReg st v
  | Load (m, rt, addr) -> evalExpr st blk addr |> evalLoad st m rt
  | UnOp (op, _, e) -> evalExpr st blk e |> evalUnOp op
  | BinOp (op, _, e1, e2) ->
    let c1 = evalExpr st blk e1
    let c2 = evalExpr st blk e2
    evalBinOp op c1 c2
  | RelOp (op, _, e1, e2) ->
    let c1 = evalExpr st blk e1
    let c2 = evalExpr st blk e2
    evalRelOp op c1 c2
  | Ite (e1, _, e2, e3) ->
    let c1 = evalExpr st blk e1
    let c2 = evalExpr st blk e2
    let c3 = evalExpr st blk e3
    SCPValue.ite c1 c2 c3
  | Cast (op, rt, e) ->
    let c = evalExpr st blk e
    evalCast op rt c
  | Extract (e, rt, pos) ->
    let c = evalExpr st blk e
    SCPValue.extract c rt pos
  | ReturnVal (_addr, ret, v) ->
    evalReturn st blk ret v
  | FuncName _
  | Nil
  | Undefined _ -> NotAConst
  | _ -> Utils.impossible ()

let evalDef (st: CPState<SCPValue>) blk v e =
  match v.Kind with
  | MemVar -> ()
  | _ -> evalExpr st blk e |> CPState.updateConst st v

let evalPhi st cfg blk dst srcIDs =
  match CPState.getExecutableSources st cfg blk srcIDs with
  | [||] -> ()
  | executableSrcIDs ->
    match dst.Kind with
    | MemVar -> ()
    | _ ->
      executableSrcIDs
      |> Array.choose (fun i ->
        { dst with Identifier = i } |> CPState.tryFindReg st true)
      |> Array.reduce SCPValue.meet
      |> fun merged -> CPState.updateConst st dst merged

let evalJmp st cfg blk = function
  | InterJmp _ -> CPState.markExceptCallFallThrough st cfg blk
  | _ -> CPState.markAllSuccessors st cfg blk

let evalStmt st cfg blk = function
  | Def (v, e) -> evalDef st blk v e
  | Phi (v, ns) -> evalPhi st cfg blk v ns
  | Jmp jmpTy -> evalJmp st cfg blk jmpTy
  | LMark _ | ExternalCall _ | SideEffect _ -> ()

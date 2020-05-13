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

module B2R2.DataFlow.ConstantPropagation.Transfer

open B2R2
open B2R2.FrontEnd
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.BinGraph

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
  match hdl.FileInfo.TryFindFunctionSymbolName addr |> Utils.tupleToOpt with
  | Some name -> name.StartsWith "__x86.get_pc_thunk"
  | None -> BinHandler.ReadUInt (hdl, addr, 4) |> isGetPCThunkCode

/// This function should be used only with basic blocks representing a function
/// call. In that case, we only have one predecessor.
let getPredVertex (v: Vertex<SSABBlock>) =
  match v.Preds with
  | [ p ] -> p
  | _ -> Utils.impossible ()

let rec evalExpr hdl bbl st = function
  | Num bv -> Const bv, st
  | Var v -> CPState.loadReg v st, st
  | Load (m, rt, addr) ->
    let addr, st = evalExpr hdl bbl st addr
    evalLoad st m rt addr
  | UnOp (op, _, e) ->
    let c, st = evalExpr hdl bbl st e
    evalUnOp op c, st
  | BinOp (op, _, e1, e2) ->
    let c1, st = evalExpr hdl bbl st e1
    let c2, st = evalExpr hdl bbl st e2
    evalBinOp op c1 c2, st
  | RelOp (op, _, e1, e2) ->
    let c1, st = evalExpr hdl bbl st e1
    let c2, st = evalExpr hdl bbl st e2
    evalRelOp op c1 c2, st
  | Ite (e1, _, e2, e3) ->
    let c1, st = evalExpr hdl bbl st e1
    let c2, st = evalExpr hdl bbl st e2
    let c3, st = evalExpr hdl bbl st e3
    Constant.ite c1 c2 c3, st
  | Cast (op, rt, e) ->
    let c, st = evalExpr hdl bbl st e
    evalCast op rt c, st
  | Extract (e, rt, pos) ->
    let c, st = evalExpr hdl bbl st e
    Constant.extract c rt pos, st
  | Undefined _ -> Undef, st
  | Return (addr, v) -> evalReturn hdl bbl st addr v, st
  | _ -> Utils.impossible ()

and evalLoad st m rt addr =
  match addr with
  | Const addr ->
    let addr = BitVector.toUInt64 addr
    CPState.loadMem m rt addr st
  | _ -> NotAConst, st

and evalUnOp op c =
  match op with
  | UnOpType.NEG -> Constant.neg c
  | UnOpType.NOT -> Constant.not c
  | _ -> NotAConst

and evalBinOp op c1 c2 =
  match op with
  | BinOpType.ADD -> Constant.add c1 c2
  | BinOpType.SUB -> Constant.sub c1 c2
  | BinOpType.MUL -> Constant.mul c1 c2
  | BinOpType.DIV -> Constant.div c1 c2
  | BinOpType.SDIV -> Constant.sdiv c1 c2
  | BinOpType.MOD -> Constant.``mod`` c1 c2
  | BinOpType.SMOD -> Constant.smod c1 c2
  | BinOpType.SHL -> Constant.shl c1 c2
  | BinOpType.SHR -> Constant.shr c1 c2
  | BinOpType.SAR -> Constant.sar c1 c2
  | BinOpType.AND -> Constant.``and`` c1 c2
  | BinOpType.OR -> Constant.``or`` c1 c2
  | BinOpType.XOR -> Constant.xor c1 c2
  | BinOpType.CONCAT -> Constant.concat c1 c2
  | _ -> NotAConst

and evalRelOp op c1 c2 =
  match op with
  | RelOpType.EQ -> Constant.eq c1 c2
  | RelOpType.NEQ -> Constant.neq c1 c2
  | RelOpType.GT -> Constant.gt c1 c2
  | RelOpType.GE -> Constant.ge c1 c2
  | RelOpType.SGT -> Constant.sgt c1 c2
  | RelOpType.SGE -> Constant.sge c1 c2
  | RelOpType.LT -> Constant.lt c1 c2
  | RelOpType.LE -> Constant.le c1 c2
  | RelOpType.SLT -> Constant.slt c1 c2
  | RelOpType.SLE -> Constant.sle c1 c2
  | _ -> NotAConst

and evalCast op rt c =
  match op with
  | CastKind.SignExt -> Constant.signExt rt c
  | CastKind.ZeroExt -> Constant.zeroExt rt c
  | _ -> NotAConst

and evalReturn hdl bbl st addr v =
  match v.Kind with
  | RegVar (rt, rid, _) ->
    if hdl.RegisterBay.IsStackPointer rid then
      let c = CPState.loadReg v st
      let wordSize = Const (BitVector.ofUInt64 4UL rt)
      evalBinOp BinOpType.ADD c wordSize
    elif isGetPCThunk hdl addr then
      let p = getPredVertex bbl
      Const (BitVector.ofUInt64 p.VData.Range.Max rt)
    elif CallingConvention.isNonVolatile hdl rid then
      CPState.loadReg v st
    else NotAConst
  | _ -> Utils.impossible ()

let evalRegDef hdl bbl st v e =
  let c, st = evalExpr hdl bbl st e
  CPState.storeReg v c st

let evalMemDef hdl bbl st mDst e =
  match e with
  | Store (mSrc, rt, addr, e) ->
    let c, st = evalExpr hdl bbl st e
    let addr, st = evalExpr hdl bbl st addr
    let st = CPState.copyMem mDst mSrc st
    match addr with
    | Const addr ->
      let addr = BitVector.toUInt64 addr
      CPState.storeMem mDst mSrc rt addr c st |> snd
    | _ -> st
  | Return (_, mSrc) -> CPState.copyMem mDst mSrc st
  | _ ->  Utils.impossible ()

let evalDef hdl bbl st v e =
  match v.Kind with
  | RegVar _ | TempVar _ -> evalRegDef hdl bbl st v e
  | MemVar -> evalMemDef hdl bbl st v e
  | PCVar _ -> st

let evalPhi st v ns =
  match v.Kind with
  | RegVar _ | TempVar _ ->
    let c =
      ns
      |> Array.map (fun n -> { v with Identifier = n })
      |> Array.choose (fun v -> CPState.tryFindReg v st)
      |> Array.reduce Constant.meet
    CPState.storeReg v c st
  | MemVar -> CPState.mergeMem v.Identifier ns st
  | PCVar _ -> st

let evalStmt hdl bbl st = function
  | LMark _ -> st
  | Def (v, e) -> evalDef hdl bbl st v e
  | Phi (v, ns) -> evalPhi st v ns
  | Jmp _ -> st
  | SideEffect _ -> st

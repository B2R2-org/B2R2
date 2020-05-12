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

module B2R2.DataFlow.ConstantPropagationHelper

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

let rec evalExpr st = function
  | Num bv -> Const bv, st
  | Var (_, rid, _, _) -> Map.find (Regular rid) st, st
  | TempVar (_, n) -> Map.find (Temporary n) st, st
  | UnOp (op, e, _, _) ->
    let c, st = evalExpr st e
    evalUnOp op c, st
  | BinOp (op, _, e1, e2, _, _) ->
    let c1, st = evalExpr st e1
    let c2, st = evalExpr st e2
    evalBinOp op c1 c2, st
  | RelOp (op, e1, e2, _, _) ->
    let c1, st = evalExpr st e1
    let c2, st = evalExpr st e2
    evalRelOp op c1 c2, st
  | Load (_, _, addr, _, _) ->
    let addr, st = evalExpr st addr
    evalLoad st addr
  | Ite (e1, e2, e3, _, _) ->
    let c1, st = evalExpr st e1
    let c2, st = evalExpr st e2
    let c3, st = evalExpr st e3
    Constant.ite c1 c2 c3, st
  | Cast (op, rt, e, _, _) ->
    let c, st = evalExpr st e
    evalCast op rt c, st
  | Extract (e, rt, pos, _, _) ->
    let c, st = evalExpr st e
    Constant.extract c rt pos, st
  | Undefined _ -> Undef, st
  | _ -> Utils.impossible ()

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

and evalLoad st addr =
  match addr with
  | Const addr ->
    let addr = BitVector.toUInt64 addr
    match Map.tryFind (Memory addr) st with
    | Some c -> c, st
    | None ->
      let st = Map.add (Memory addr) NotAConst st
      NotAConst, st
  | _ -> NotAConst, st

and evalCast op rt c =
  match op with
  | CastKind.SignExt -> Constant.signExt rt c
  | CastKind.ZeroExt -> Constant.zeroExt rt c
  | _ -> NotAConst

let evalStmt (ppoint, st) = function
  | ISMark (addr, _) -> ProgramPoint (addr, 1), st
  | IEMark addr -> ProgramPoint (addr, 0), st
  | LMark _ -> ProgramPoint.Next ppoint, st
  | Put (Var (_, rid, _, _), e) ->
    let c, st = evalExpr st e
    let st = Map.add (Regular rid) c st
    ProgramPoint.Next ppoint, st
  | Put (TempVar (_, n), e) ->
    let c, st = evalExpr st e
    let st = Map.add (Temporary n) c st
    ProgramPoint.Next ppoint, st
  | Put _ -> ProgramPoint.Next ppoint, st
  | Store (_, addr, e) ->
    match evalExpr st addr with
    | Const bv, st ->
      let addr = BitVector.toUInt64 bv
      let c, st = evalExpr st e
      let st = Map.add (Memory addr) c st
      ProgramPoint.Next ppoint, st
    | _, st -> ProgramPoint.Next ppoint, st
  | Jmp _ -> ProgramPoint.Next ppoint, st
  | CJmp _ -> ProgramPoint.Next ppoint, st
  | InterJmp _ -> ProgramPoint.Next ppoint, st
  | InterCJmp _ -> ProgramPoint.Next ppoint, st
  | SideEffect _ -> ProgramPoint.Next ppoint, st

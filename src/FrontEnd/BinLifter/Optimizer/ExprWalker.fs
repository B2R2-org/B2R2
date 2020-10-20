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

namespace B2R2.FrontEnd.BinLifter

open System.Runtime.InteropServices

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

type internal ConstPropContext = {
  VarMap     : Map<RegisterID, Expr>
  TempVarMap : Map<int, Expr>
}

type internal ExprWalker =
  static member ConcretizeUnOp t bv =
    match t with
    | UnOpType.NEG -> BitVector.neg bv
    | UnOpType.NOT -> BitVector.bnot bv
    | UnOpType.FSQRT -> BitVector.fsqrt bv
    | UnOpType.FCOS -> BitVector.fcos bv
    | UnOpType.FSIN -> BitVector.fsin bv
    | UnOpType.FTAN -> BitVector.ftan bv
    | UnOpType.FATAN -> BitVector.fatan bv
    | _ -> Utils.impossible ()

  static member ConcretizeBinOp t bv1 bv2 =
    match t with
    | BinOpType.ADD -> BitVector.add bv1 bv2
    | BinOpType.SUB -> BitVector.sub bv1 bv2
    | BinOpType.MUL -> BitVector.mul bv1 bv2
    | BinOpType.DIV -> BitVector.div bv1 bv2
    | BinOpType.SDIV -> BitVector.sdiv bv1 bv2
    | BinOpType.MOD -> BitVector.modulo bv1 bv2
    | BinOpType.SMOD -> BitVector.smodulo bv1 bv2
    | BinOpType.SHL -> BitVector.shl bv1 bv2
    | BinOpType.SHR -> BitVector.shr bv1 bv2
    | BinOpType.SAR -> BitVector.sar bv1 bv2
    | BinOpType.AND -> BitVector.band bv1 bv2
    | BinOpType.OR -> BitVector.bor bv1 bv2
    | BinOpType.XOR -> BitVector.bxor bv1 bv2
    | BinOpType.CONCAT -> BitVector.concat bv1 bv2
    | BinOpType.FADD -> BitVector.fadd bv1 bv2
    | BinOpType.FSUB -> BitVector.fsub bv1 bv2
    | BinOpType.FMUL -> BitVector.fmul bv1 bv2
    | BinOpType.FDIV -> BitVector.fdiv bv1 bv2
    | BinOpType.FPOW -> BitVector.fpow bv1 bv2
    | BinOpType.FLOG -> BitVector.flog bv1 bv2
    | _ -> Utils.impossible ()

  static member ConcretizeRelOp t bv1 bv2 =
    match t with
    | RelOpType.EQ -> BitVector.eq bv1 bv2
    | RelOpType.NEQ -> BitVector.neq bv1 bv2
    | RelOpType.GT -> BitVector.gt bv1 bv2
    | RelOpType.GE -> BitVector.ge bv1 bv2
    | RelOpType.SGT -> BitVector.sgt bv1 bv2
    | RelOpType.SGE -> BitVector.sge bv1 bv2
    | RelOpType.LT -> BitVector.lt bv1 bv2
    | RelOpType.LE -> BitVector.le bv1 bv2
    | RelOpType.SLT -> BitVector.slt bv1 bv2
    | RelOpType.SLE -> BitVector.sle bv1 bv2
    | RelOpType.FGT -> BitVector.fgt bv1 bv2
    | RelOpType.FGE -> BitVector.fge bv1 bv2
    | RelOpType.FLT -> BitVector.flt bv1 bv2
    | RelOpType.FLE -> BitVector.fle bv1 bv2
    | _ -> Utils.impossible ()

  static member ConcretizeCast t rt bv =
    match t with
    | CastKind.SignExt -> BitVector.sext bv rt
    | CastKind.ZeroExt -> BitVector.zext bv rt
    | CastKind.IntToFloat -> BitVector.itof bv rt
    | CastKind.FtoIRound -> BitVector.ftoiround bv rt
    | CastKind.FtoICeil -> BitVector.ftoiceil bv rt
    | CastKind.FtoIFloor -> BitVector.ftoifloor bv rt
    | CastKind.FtoITrunc -> BitVector.ftoitrunc bv rt
    | CastKind.FloatExt -> BitVector.fext bv rt
    | _ -> Utils.impossible ()

  static member Replace (cpc, e, [<Out>] out: byref<Expr>) =
    match e with
    | Var (_, n, _, _) -> match cpc.VarMap.TryGetValue n with
                          | (true, e) -> out <- e; true
                          | _  -> false
    | TempVar (_, n) -> match cpc.TempVarMap.TryGetValue n with
                        | (true, e) -> out <- e; true
                        | _  -> false
    | UnOp (t, _e, _, _) ->
      let (trans, o) = ExprWalker.Replace (cpc, _e)
      if trans then
        match o with
        | Num bv -> out <- AST.num <| ExprWalker.ConcretizeUnOp t bv
        | _ -> out <- AST.unop t o
        true
      else false
    | BinOp (BinOpType.ADD, _, e, Num bv, _, _)
    | BinOp (BinOpType.ADD, _, Num bv, e, _, _) when BitVector.isZero bv ->
      let (trans, o) = ExprWalker.Replace (cpc, e)
      if trans then out <- o; true else out <- e; true
    | BinOp (BinOpType.MUL, _, e, Num bv, _, _)
    | BinOp (BinOpType.MUL, _, Num bv, e, _, _) when BitVector.isOne bv ->
      let (trans, o) = ExprWalker.Replace (cpc, e)
      if trans then out <- o; true else out <- e; true
    | BinOp (t, _, e1, e2, _, _) ->
      let (trans, e1') = ExprWalker.Replace (cpc, e1)
      let (trans1, e2') = ExprWalker.Replace (cpc, e2)
      if trans || trans1 then
        let e1 = if trans then e1' else e1
        let e2 = if trans1 then e2' else e2
        match e1, e2 with
        | Num bv1, Num bv2 ->
          out <- AST.num <| ExprWalker.ConcretizeBinOp t bv1 bv2
        | _ -> out <- AST.binop t e1 e2
        true
      else false
    | RelOp (t, e1, e2, _, _) ->
      let (trans, e1') = ExprWalker.Replace (cpc, e1)
      let (trans1, e2') = ExprWalker.Replace (cpc, e2)
      if trans || trans1 then
        let e1 = if trans then e1' else e1
        let e2 = if trans1 then e2' else e2
        match e1, e2 with
        | Num bv1, Num bv2 ->
          out <- AST.num <| ExprWalker.ConcretizeRelOp t bv1 bv2
        | _ -> out <- AST.relop t e1 e2
        true
      else false
    | Load (endian, rt, _e, _, _) ->
      let (trans, o) = ExprWalker.Replace (cpc, _e)
      if trans then out <- AST.load endian rt o; true else false
    | Ite (cond, e1, e2, _, _) ->
      let (trans, cond') = ExprWalker.Replace (cpc, cond)
      let (trans1, e1') = ExprWalker.Replace (cpc, e1)
      let (trans2, e2') = ExprWalker.Replace (cpc, e2)
      if trans || trans1 || trans2 then
        let c = if trans then cond' else cond
        let e1 = if trans1 then e1' else e1
        let e2 = if trans2 then e2' else e2
        match c with
        | Num bv -> if BitVector.isTrue bv then out <- e1 else out <- e2
        | _ -> out <- AST.ite c e1 e2
        true
      else false
    | Cast (t, rt, _e, _, _) ->
      let (trans, o) = ExprWalker.Replace (cpc, _e)
      if trans then
        match o with
        | Num bv -> out <- AST.num <| ExprWalker.ConcretizeCast t rt bv
        | _ -> out <- AST.cast t rt o
        true
      else false
    | Extract (e, rt, pos, _, _) ->
      let (trans, o) = ExprWalker.Replace (cpc, e)
      if trans then
        match o with
        | Num bv -> out <- AST.num <| BitVector.extract bv rt pos
        | _ -> out <- AST.extract o rt pos
        true
      else false
    | _ -> false

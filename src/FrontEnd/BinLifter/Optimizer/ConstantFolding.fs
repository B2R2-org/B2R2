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

[<RequireQualifiedAccess>]
module B2R2.FrontEnd.BinLifter.ConstantFolding

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

type Context = {
  VarMap: Dictionary<RegisterID, Expr>
  TempVarMap: Dictionary<int, Expr>
}

let private concretizeUnOp unopType bv =
  match unopType with
  | UnOpType.NEG -> BitVector.neg bv
  | UnOpType.NOT -> BitVector.bnot bv
  | UnOpType.FSQRT -> BitVector.fsqrt bv
  | UnOpType.FCOS -> BitVector.fcos bv
  | UnOpType.FSIN -> BitVector.fsin bv
  | UnOpType.FTAN -> BitVector.ftan bv
  | UnOpType.FATAN -> BitVector.fatan bv
  | _ -> Utils.impossible ()

let private concretizeBinOp binopType bv1 bv2 =
  match binopType with
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

let private concretizeRelOp relopType bv1 bv2 =
  match relopType with
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

let private concretizeCast castType rt bv =
  match castType with
  | CastKind.SignExt -> BitVector.sext bv rt
  | CastKind.ZeroExt -> BitVector.zext bv rt
  | CastKind.IntToFloat -> BitVector.itof bv rt
  | CastKind.FtoIRound -> BitVector.ftoiround bv rt
  | CastKind.FtoICeil -> BitVector.ftoiceil bv rt
  | CastKind.FtoIFloor -> BitVector.ftoifloor bv rt
  | CastKind.FtoITrunc -> BitVector.ftoitrunc bv rt
  | CastKind.FloatCast -> BitVector.fcast bv rt
  | _ -> Utils.impossible ()

let rec replace ctxt expr =
  match expr.E with
  | Var (_, name, _, _) ->
    match ctxt.VarMap.TryGetValue name with
    | true, e -> struct (true, e)
    | _  -> struct (false, expr)
  | TempVar (_, name) ->
    match ctxt.TempVarMap.TryGetValue name with
    | (true, e) -> struct (true, e)
    | _  -> struct (false, expr)
  | UnOp (t, e, _) ->
    let struct (changed, e) = replace ctxt e
    if changed then
      match e.E with
      | Num bv -> struct (true, AST.num <| concretizeUnOp t bv)
      | _ -> struct (true, AST.unop t e)
    else struct (false, expr)
  | BinOp (BinOpType.ADD, _, e, { E = Num bv }, _)
  | BinOp (BinOpType.ADD, _, { E = Num bv }, e, _)
    when BitVector.isZero bv ->
    let struct (changed, e') = replace ctxt e
    if changed then struct (true, e') else struct (true, e)
  | BinOp (BinOpType.MUL, _, e, { E = Num bv }, _)
  | BinOp (BinOpType.MUL, _, { E = Num bv }, e, _)
    when BitVector.isOne bv ->
    let struct (changed, e') = replace ctxt e
    if changed then struct (true, e') else struct (true, e)
  | BinOp (t, _, e1, e2, _) ->
    let struct (changed1, e1) = replace ctxt e1
    let struct (changed2, e2) = replace ctxt e2
    match e1.E, e2.E with
    | Num bv1, Num bv2 -> struct (true, AST.num <| concretizeBinOp t bv1 bv2)
    | _ ->
      if changed1 || changed2 then struct (true, AST.binop t e1 e2)
      else struct (false, expr)
  | RelOp (t, e1, e2, _) ->
    let struct (changed1, e1) = replace ctxt e1
    let struct (changed2, e2) = replace ctxt e2
    match e1.E, e2.E with
    | Num bv1, Num bv2 -> struct (true, AST.num <| concretizeRelOp t bv1 bv2)
    | _ ->
      if changed1 || changed2 then struct (true, AST.relop t e1 e2)
      else struct (false, expr)
  | Load (endian, rt, e, _) ->
    let struct (changed, e') = replace ctxt e
    if changed then struct (true, AST.load endian rt e')
    else struct (false, expr)
  | Ite (cond, e1, e2, _) ->
    let struct (changed0, cond) = replace ctxt cond
    let struct (changed1, e1) = replace ctxt e1
    let struct (changed2, e2) = replace ctxt e2
    if changed0 || changed1 || changed2 then
      match cond.E with
      | Num bv ->
        if BitVector.isTrue bv then struct (true, e1)
        else struct (false, e2)
      | _ -> struct (true, AST.ite cond e1 e2)
    else struct (false, expr)
  | Cast (kind, rt, e, _) ->
    let struct (changed, e) = replace ctxt e
    if changed then
      match e.E with
      | Num bv -> struct (true, AST.num <| concretizeCast kind rt bv)
      | _ -> struct (true, AST.cast kind rt e)
    else struct (false, expr)
  | Extract (e, rt, pos, _) ->
    let struct (changed, e) = replace ctxt e
    if changed then
      match e.E with
      | Num bv -> struct (true, AST.num <| BitVector.extract bv rt pos)
      | _ -> struct (true, AST.extract e rt pos)
    else struct (false, expr)
  | _ -> struct (false, expr)

let updateContextAtDef ctxt dst src =
  match dst.E, src.E with
  | Var (_, r, _, _), Num _ -> ctxt.VarMap.TryAdd (r, src) |> ignore
  | Var (_, r, _, _), _ -> ctxt.VarMap.Remove (r) |> ignore
  | TempVar (_, n), Num _ -> ctxt.TempVarMap.TryAdd (n, src) |> ignore
  | TempVar (_, n), _ -> ctxt.TempVarMap.Remove (n) |> ignore
  | _ -> ()

let rec optimizeLoop (stmts: Stmt []) idx ctxt =
  if Array.length stmts > idx then
    match stmts.[idx].S with
    | Store (endian, e1, e2) ->
      let struct (c1, e1) = replace ctxt e1
      let struct (c2, e2) = replace ctxt e2
      if c1 || c2 then stmts.[idx] <- AST.store endian e1 e2 else ()
      optimizeLoop stmts (idx + 1) ctxt
    | InterJmp (e, t) ->
      let struct (changed, e) = replace ctxt e
      if changed then stmts.[idx] <- AST.interjmp e t else ()
      optimizeLoop stmts (idx + 1) ctxt
    | InterCJmp (cond, e1, e2) ->
      let struct (c0, cond) = replace ctxt cond
      let struct (c1, e1) = replace ctxt e1
      let struct (c2, e2) = replace ctxt e2
      if c0 || c1 || c2 then
        stmts.[idx] <-
          match cond.E with
          | Num n when BitVector.isOne n -> AST.interjmp e1 InterJmpKind.Base
          | Num _ -> AST.interjmp e2 InterJmpKind.Base
          | _ -> AST.intercjmp cond e1 e2
      else ()
      optimizeLoop stmts (idx + 1) ctxt
    | Jmp (e) ->
      let struct (changed, e) = replace ctxt e
      if changed then stmts.[idx] <- AST.jmp e else ()
      optimizeLoop stmts (idx + 1) ctxt
    | CJmp (cond, e1, e2) ->
      let struct (c0, cond) = replace ctxt cond
      let struct (c1, e1) = replace ctxt e1
      let struct (c2, e2) = replace ctxt e2
      if c0 || c1 || c2 then
        stmts.[idx] <-
          match cond.E with
          | Num (n) when BitVector.isOne n -> AST.jmp e1
          | Num (_) -> AST.jmp e2
          | _ -> AST.cjmp cond e1 e2
      else ()
      optimizeLoop stmts (idx + 1) ctxt
    | LMark _ -> optimizeLoop stmts (idx + 1) ctxt
    | Put (lhs, rhs) ->
      let rhs = match replace ctxt rhs with
                | true, rhs -> stmts.[idx] <- AST.put lhs rhs; rhs
                | _ -> rhs
      updateContextAtDef ctxt lhs rhs
      optimizeLoop stmts (idx + 1) ctxt
    | ISMark _ | IEMark _ | SideEffect _ ->
      optimizeLoop stmts (idx + 1) ctxt
  else stmts

/// Assuming that the stmts are localized, i.e., those stmts represent a basic
/// block, perform local constant folding.
let optimize (stmts: Stmt []) =
  let stmts = Array.copy stmts
  optimizeLoop stmts 0 { VarMap = Dictionary (); TempVarMap = Dictionary () }

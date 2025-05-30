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

/// Provides a function that performs a constant folding optimization for the
/// lifted IR statements. This function assumes that the statements are
/// localized, i.e., they represent a basic block.
[<RequireQualifiedAccess>]
module B2R2.FrontEnd.BinLifter.ConstantFolding

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

type private VarMaps = {
  VarMap: Dictionary<RegisterID, Expr>
  TempVarMap: Dictionary<int, Expr>
}

let private concretizeUnOp unopType bv =
  match unopType with
  | UnOpType.NEG -> BitVector.Neg bv
  | UnOpType.NOT -> BitVector.BNot bv
  | UnOpType.FSQRT -> BitVector.FSqrt bv
  | UnOpType.FCOS -> BitVector.FCos bv
  | UnOpType.FSIN -> BitVector.FSin bv
  | UnOpType.FTAN -> BitVector.FTan bv
  | UnOpType.FATAN -> BitVector.FAtan bv
  | _ -> Terminator.impossible ()

let private concretizeBinOp binopType bv1 bv2 =
  match binopType with
  | BinOpType.ADD -> BitVector.Add (bv1, bv2)
  | BinOpType.SUB -> BitVector.Sub (bv1, bv2)
  | BinOpType.MUL -> BitVector.Mul (bv1, bv2)
  | BinOpType.DIV -> BitVector.Div (bv1, bv2)
  | BinOpType.SDIV -> BitVector.SDiv (bv1, bv2)
  | BinOpType.MOD -> BitVector.Modulo (bv1, bv2)
  | BinOpType.SMOD -> BitVector.SModulo (bv1, bv2)
  | BinOpType.SHL -> BitVector.Shl (bv1, bv2)
  | BinOpType.SHR -> BitVector.Shr (bv1, bv2)
  | BinOpType.SAR -> BitVector.Sar (bv1, bv2)
  | BinOpType.AND -> BitVector.BAnd (bv1, bv2)
  | BinOpType.OR -> BitVector.BOr (bv1, bv2)
  | BinOpType.XOR -> BitVector.BXor (bv1, bv2)
  | BinOpType.CONCAT -> BitVector.Concat (bv1, bv2)
  | BinOpType.FADD -> BitVector.FAdd (bv1, bv2)
  | BinOpType.FSUB -> BitVector.FSub (bv1, bv2)
  | BinOpType.FMUL -> BitVector.FMul (bv1, bv2)
  | BinOpType.FDIV -> BitVector.FDiv (bv1, bv2)
  | BinOpType.FPOW -> BitVector.FPow (bv1, bv2)
  | BinOpType.FLOG -> BitVector.FLog (bv1, bv2)
  | _ -> Terminator.impossible ()

let private concretizeRelOp relopType bv1 bv2 =
  match relopType with
  | RelOpType.EQ -> BitVector.Eq (bv1, bv2)
  | RelOpType.NEQ -> BitVector.Neq (bv1, bv2)
  | RelOpType.GT -> BitVector.Gt (bv1, bv2)
  | RelOpType.GE -> BitVector.Ge (bv1, bv2)
  | RelOpType.SGT -> BitVector.SGt (bv1, bv2)
  | RelOpType.SGE -> BitVector.SGe (bv1, bv2)
  | RelOpType.LT -> BitVector.Lt (bv1, bv2)
  | RelOpType.LE -> BitVector.Le (bv1, bv2)
  | RelOpType.SLT -> BitVector.SLt (bv1, bv2)
  | RelOpType.SLE -> BitVector.SLe (bv1, bv2)
  | RelOpType.FGT -> BitVector.FGt (bv1, bv2)
  | RelOpType.FGE -> BitVector.FGe (bv1, bv2)
  | RelOpType.FLT -> BitVector.FLt (bv1, bv2)
  | RelOpType.FLE -> BitVector.FLe (bv1, bv2)
  | _ -> Terminator.impossible ()

let private concretizeCast castType rt bv =
  match castType with
  | CastKind.SignExt -> BitVector.SExt (bv, rt)
  | CastKind.ZeroExt -> BitVector.ZExt (bv, rt)
  | CastKind.SIntToFloat -> BitVector.Itof (bv, rt, true)
  | CastKind.UIntToFloat -> BitVector.Itof (bv, rt, false)
  | CastKind.FtoIRound -> BitVector.FtoiRound (bv, rt)
  | CastKind.FtoICeil -> BitVector.FtoiCeil (bv, rt)
  | CastKind.FtoIFloor -> BitVector.FtoiFloor (bv, rt)
  | CastKind.FtoITrunc -> BitVector.FtoiTrunc (bv, rt)
  | CastKind.FloatCast -> BitVector.FCast (bv, rt)
  | _ -> Terminator.impossible ()

let rec private replace maps expr =
  match expr with
  | Var (_, name, _, _) ->
    match maps.VarMap.TryGetValue name with
    | true, e -> struct (true, e)
    | _  -> struct (false, expr)
  | TempVar (_, name, _) ->
    match maps.TempVarMap.TryGetValue name with
    | (true, e) -> struct (true, e)
    | _  -> struct (false, expr)
  | UnOp (t, e, _) ->
    let struct (changed, e) = replace maps e
    if changed then
      match e with
      | Num (bv, _) -> struct (true, AST.num <| concretizeUnOp t bv)
      | _ -> struct (true, AST.unop t e)
    else struct (false, expr)
  | BinOp (BinOpType.ADD, _, e, Num (bv, _), _)
  | BinOp (BinOpType.ADD, _, Num (bv, _), e, _) when BitVector.IsZero bv ->
    let struct (changed, e') = replace maps e
    if changed then struct (true, e') else struct (true, e)
  | BinOp (BinOpType.MUL, _, e, Num (bv, _), _)
  | BinOp (BinOpType.MUL, _, Num (bv, _), e, _) when BitVector.IsOne bv ->
    let struct (changed, e') = replace maps e
    if changed then struct (true, e') else struct (true, e)
  | BinOp (t, _, e1, e2, _) ->
    let struct (changed1, e1) = replace maps e1
    let struct (changed2, e2) = replace maps e2
    match e1, e2 with
    | Num (bv1, _), Num (bv2, _) ->
      struct (true, AST.num <| concretizeBinOp t bv1 bv2)
    | _ ->
      if changed1 || changed2 then struct (true, AST.binop t e1 e2)
      else struct (false, expr)
  | RelOp (t, e1, e2, _) ->
    let struct (changed1, e1) = replace maps e1
    let struct (changed2, e2) = replace maps e2
    match e1, e2 with
    | Num (bv1, _), Num (bv2, _) ->
      struct (true, AST.num <| concretizeRelOp t bv1 bv2)
    | _ ->
      if changed1 || changed2 then struct (true, AST.relop t e1 e2)
      else struct (false, expr)
  | Load (endian, rt, e, _) ->
    let struct (changed, e') = replace maps e
    if changed then struct (true, AST.load endian rt e')
    else struct (false, expr)
  | Ite (cond, e1, e2, _) ->
    let struct (changed0, cond) = replace maps cond
    let struct (changed1, e1) = replace maps e1
    let struct (changed2, e2) = replace maps e2
    if changed0 || changed1 || changed2 then
      match cond with
      | Num (bv, _) ->
        if BitVector.IsTrue bv then struct (true, e1)
        else struct (false, e2)
      | _ -> struct (true, AST.ite cond e1 e2)
    else struct (false, expr)
  | Cast (kind, rt, e, _) ->
    let struct (changed, e) = replace maps e
    if changed then
      match e with
      | Num (bv, _) -> struct (true, AST.num <| concretizeCast kind rt bv)
      | _ -> struct (true, AST.cast kind rt e)
    else struct (false, expr)
  | Extract (e, rt, pos, _) ->
    let struct (changed, e) = replace maps e
    if changed then
      match e with
      | Num (bv, _) -> struct (true, AST.num <| BitVector.Extract (bv, rt, pos))
      | _ -> struct (true, AST.extract e rt pos)
    else struct (false, expr)
  | _ -> struct (false, expr)

let private updateMapsAtDef maps dst src =
  match dst, src with
  | Var (_, r, _, _), Num _ -> maps.VarMap.TryAdd (r, src) |> ignore
  | Var (_, r, _, _), _ -> maps.VarMap.Remove (r) |> ignore
  | TempVar (_, n, _), Num _ -> maps.TempVarMap.TryAdd (n, src) |> ignore
  | TempVar (_, n, _), _ -> maps.TempVarMap.Remove (n) |> ignore
  | _ -> ()

let rec private optimizeLoop (stmts: Stmt []) idx maps =
  if Array.length stmts > idx then
    match stmts[idx] with
    | Store (endian, e1, e2, _) ->
      let struct (c1, e1) = replace maps e1
      let struct (c2, e2) = replace maps e2
      if c1 || c2 then stmts[idx] <- AST.store endian e1 e2 else ()
      optimizeLoop stmts (idx + 1) maps
    | InterJmp (e, t, _) ->
      let struct (changed, e) = replace maps e
      if changed then stmts[idx] <- AST.interjmp e t else ()
      optimizeLoop stmts (idx + 1) maps
    | InterCJmp (cond, e1, e2, _) ->
      let struct (c0, cond) = replace maps cond
      let struct (c1, e1) = replace maps e1
      let struct (c2, e2) = replace maps e2
      if c0 || c1 || c2 then
        stmts[idx] <-
          match cond with
          | Num (n, _) when BitVector.IsOne n ->
            AST.interjmp e1 InterJmpKind.Base
          | Num _ -> AST.interjmp e2 InterJmpKind.Base
          | _ -> AST.intercjmp cond e1 e2
      else ()
      optimizeLoop stmts (idx + 1) maps
    | Jmp (e, _) ->
      let struct (changed, e) = replace maps e
      if changed then stmts[idx] <- AST.jmp e else ()
      optimizeLoop stmts (idx + 1) maps
    | CJmp (cond, e1, e2, _) ->
      let struct (c0, cond) = replace maps cond
      let struct (c1, e1) = replace maps e1
      let struct (c2, e2) = replace maps e2
      if c0 || c1 || c2 then
        stmts[idx] <-
          match cond with
          | Num (n, _) when BitVector.IsOne n -> AST.jmp e1
          | Num (_) -> AST.jmp e2
          | _ -> AST.cjmp cond e1 e2
      else ()
      optimizeLoop stmts (idx + 1) maps
    | LMark _ -> optimizeLoop stmts (idx + 1) maps
    | Put (lhs, rhs, _) ->
      let rhs = match replace maps rhs with
                | true, rhs -> stmts[idx] <- AST.put lhs rhs; rhs
                | _ -> rhs
      updateMapsAtDef maps lhs rhs
      optimizeLoop stmts (idx + 1) maps
    | ISMark _ | IEMark _ | ExternalCall _ | SideEffect _ ->
      optimizeLoop stmts (idx + 1) maps
  else stmts

/// Assuming that the stmts are localized, i.e., those stmts represent a basic
/// block, perform local constant folding.
let optimize (stmts: Stmt []) =
  let stmts = Array.copy stmts
  optimizeLoop stmts 0 { VarMap = Dictionary (); TempVarMap = Dictionary () }

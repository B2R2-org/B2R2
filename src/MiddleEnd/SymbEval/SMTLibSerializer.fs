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

namespace B2R2.MiddleEnd.SymbEval

open System.Collections.Generic
open System.Text
open B2R2
open B2R2.BinIR

/// Serializes symbolic expressions and path conditions into SMT-LIB.
[<RequireQualifiedAccess>]
module SMTLibSerializer =
  let private bvSort (typ: RegType) = $"(_ BitVec {RegType.toBitWidth typ})"

  let private bvConst (bv: BitVector) =
    $"(_ bv{bv.ToBigInt()} {RegType.toBitWidth bv.Length})"

  let private symbol (name: string) =
    // FIXME: This escaping is not bijective. It is acceptable for generated
    // SymbEval variable names, but user-provided names may collide.
    let name = name.Replace("\\", "_").Replace("|", "_")
    $"|{name}|"

  let private unsupported name =
    invalidOp $"Unsupported SMT-LIB serialization: {name}"

  let private unaryOp = function
    | UnOpType.NEG -> "bvneg"
    | UnOpType.NOT -> "bvnot"
    | op -> UnOpType.toString op |> unsupported

  let private binaryOp = function
    | BinOpType.ADD -> "bvadd"
    | BinOpType.SUB -> "bvsub"
    | BinOpType.MUL -> "bvmul"
    | BinOpType.DIV -> "bvudiv"
    | BinOpType.SDIV -> "bvsdiv"
    | BinOpType.MOD -> "bvurem"
    | BinOpType.SMOD -> "bvsmod"
    | BinOpType.SHL -> "bvshl"
    | BinOpType.SHR -> "bvlshr"
    | BinOpType.SAR -> "bvashr"
    | BinOpType.AND -> "bvand"
    | BinOpType.OR -> "bvor"
    | BinOpType.XOR -> "bvxor"
    | op -> BinOpType.toString op |> unsupported

  let private relOp = function
    | RelOpType.EQ -> "="
    | RelOpType.GT -> "bvugt"
    | RelOpType.GE -> "bvuge"
    | RelOpType.SGT -> "bvsgt"
    | RelOpType.SGE -> "bvsge"
    | RelOpType.LT -> "bvult"
    | RelOpType.LE -> "bvule"
    | RelOpType.SLT -> "bvslt"
    | RelOpType.SLE -> "bvsle"
    | op -> RelOpType.toString op |> unsupported

  let private collectVar (decls: Dictionary<string, RegType>) name typ =
    let name = symbol name
    match decls.TryGetValue name with
    | true, oldTyp when oldTyp <> typ ->
      invalidOp $"Conflicting SMT-LIB variable type: {name}"
    | true, _ -> ()
    | false, _ -> decls[name] <- typ

  let rec private collectVars decls = function
    | Const _ -> ()
    | Var(name, typ) -> collectVar decls name typ
    | UnOp(_, expr) -> collectVars decls expr
    | BinOp(_, _, lhs, rhs)
    | RelOp(_, lhs, rhs) ->
      collectVars decls lhs
      collectVars decls rhs
    | Load(_, _, addr) -> collectVars decls addr
    | Ite(cond, thenExpr, elseExpr) ->
      collectVars decls cond
      collectVars decls thenExpr
      collectVars decls elseExpr
    | Cast(_, _, expr)
    | Extract(expr, _, _) -> collectVars decls expr
    | FuncApp(_, _, args) -> args |> List.iter (collectVars decls)
    | Undef _ -> ()

  let rec private serializeBool expr =
    match expr with
    | Const bv when bv.IsTrue -> "true"
    | Const bv when bv.IsFalse -> "false"
    | RelOp(RelOpType.NEQ, lhs, rhs) ->
      $"(not (= {serializeExpr lhs} {serializeExpr rhs}))"
    | RelOp(op, lhs, rhs) ->
      $"({relOp op} {serializeExpr lhs} {serializeExpr rhs})"
    | expr when SymbExpr.isCondition expr ->
      $"(= {serializeExpr expr} {bvConst BitVector.T})"
    | expr ->
      invalidOp $"Invalid SMT-LIB boolean expression type: {expr.Type}"

  and private serializeRelAsBitVec op lhs rhs =
    $"(ite {serializeBool (RelOp(op, lhs, rhs))} {bvConst BitVector.T} "
    + $"{bvConst BitVector.F})"

  and serializeExpr expr =
    match expr with
    | Const bv -> bvConst bv
    | Var(name, _) -> symbol name
    | UnOp(op, expr) -> $"({unaryOp op} {serializeExpr expr})"
    | BinOp(BinOpType.CONCAT, _, lhs, rhs) ->
      $"(concat {serializeExpr lhs} {serializeExpr rhs})"
    | BinOp(op, _, lhs, rhs) ->
      $"({binaryOp op} {serializeExpr lhs} {serializeExpr rhs})"
    | RelOp(op, lhs, rhs) -> serializeRelAsBitVec op lhs rhs
    | Load _ -> unsupported "symbolic load"
    | Ite(cond, thenExpr, elseExpr) ->
      $"(ite {serializeBool cond} {serializeExpr thenExpr} "
      + $"{serializeExpr elseExpr})"
    | Cast(kind, typ, expr) ->
      let amount = RegType.toBitWidth typ - RegType.toBitWidth expr.Type
      if amount < 0 then invalidOp $"Invalid SMT-LIB cast width: {expr.Type}"
      elif amount = 0 then serializeExpr expr
      else
        match kind with
        | CastKind.SignExt ->
          $"((_ sign_extend {amount}) {serializeExpr expr})"
        | CastKind.ZeroExt ->
          $"((_ zero_extend {amount}) {serializeExpr expr})"
        | kind -> CastKind.toString kind |> unsupported
    | Extract(expr, typ, startPos) ->
      let hi = startPos + RegType.toBitWidth typ - 1
      $"((_ extract {hi} {startPos}) {serializeExpr expr})"
    | FuncApp _ -> unsupported "function application"
    | Undef(_, reason) -> unsupported $"undefined value ({reason})"

  let private serializeScriptPrefix pathCondition additionalDeclExprs =
    let decls = Dictionary<string, RegType>()
    pathCondition |> List.iter (collectVars decls)
    additionalDeclExprs |> List.iter (collectVars decls)
    let sb = StringBuilder()
    sb.AppendLine("(set-logic QF_BV)") |> ignore
    decls
    |> Seq.sortBy (fun (KeyValue(name, _)) -> name)
    |> Seq.iter (fun (KeyValue(name, typ)) ->
      sb.AppendLine($"(declare-fun {name} () {bvSort typ})") |> ignore)
    pathCondition
    |> List.iter (fun expr ->
      sb.AppendLine($"(assert {serializeBool expr})") |> ignore)
    sb

  let serializeAssertions pathCondition additionalDeclExprs =
    serializeScriptPrefix pathCondition additionalDeclExprs
    |> fun sb -> sb.ToString()

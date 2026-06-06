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

open B2R2
open B2R2.BinIR

/// Represents a symbolic bit-vector value.
///
/// SymbEval keeps LowUIR condition values as 1-bit bit-vectors. Path
/// conditions contain expressions that are interpreted as the 1-bit true value.
type SymbExpr =
  /// A concrete bit-vector constant.
  | Const of BitVector
  /// A named symbolic bit-vector variable.
  | Var of name: string * typ: RegType
  /// A unary operation over a symbolic expression.
  | UnOp of UnOpType * SymbExpr
  /// A binary operation over symbolic expressions.
  | BinOp of BinOpType * typ: RegType * SymbExpr * SymbExpr
  /// A relational operation over symbolic expressions.
  | RelOp of RelOpType * SymbExpr * SymbExpr
  /// A symbolic memory load.
  | Load of Endian * typ: RegType * addr: SymbExpr
  /// An if-then-else expression.
  | Ite of cond: SymbExpr * thenExpr: SymbExpr * elseExpr: SymbExpr
  /// A type conversion.
  | Cast of CastKind * typ: RegType * SymbExpr
  /// A bit extraction.
  | Extract of SymbExpr * typ: RegType * startPos: int
  /// An uninterpreted function application.
  | FuncApp of name: string * typ: RegType * args: SymbExpr list
  /// A value that exists in the source IR but has undefined semantics.
  | Undef of typ: RegType * reason: string
with
  /// Return the bit width of the expression.
  member this.Type =
    match this with
    | Const bv -> bv.Length
    | Var(_, typ) -> typ
    | UnOp(_, expr) -> expr.Type
    | BinOp(_, typ, _, _) -> typ
    | RelOp _ -> 1<rt>
    | Load(_, typ, _) -> typ
    | Ite(_, thenExpr, _) -> thenExpr.Type
    | Cast(_, typ, _) -> typ
    | Extract(_, typ, _) -> typ
    | FuncApp(_, typ, _) -> typ
    | Undef(typ, _) -> typ

  override this.ToString() =
    match this with
    | Const bv -> bv.ToString()
    | Var(name, typ) -> $"{name}:{RegType.toString typ}"
    | UnOp(op, expr) -> $"({UnOpType.toString op} {expr})"
    | BinOp(op, typ, lhs, rhs) ->
      $"({lhs} {BinOpType.toString op} {rhs}):{RegType.toString typ}"
    | RelOp(op, lhs, rhs) -> $"({lhs} {RelOpType.toString op} {rhs})"
    | Load(_endian, typ, addr) -> $"[{addr}]:{RegType.toString typ}"
    | Ite(cond, thenExpr, elseExpr) ->
      $"(({cond}) ? ({thenExpr}) : ({elseExpr}))"
    | Cast(kind, typ, expr) ->
      $"{CastKind.toString kind}:{RegType.toString typ}({expr})"
    | Extract(expr, typ, startPos) ->
      let lastPos = int typ + startPos - 1
      $"({expr}[{lastPos}:{startPos}])"
    | FuncApp(name, typ, args) ->
      let args = args |> List.map string |> String.concat ", "
      $"{name}({args}):{RegType.toString typ}"
    | Undef(_, reason) -> $"?? ({reason})"

/// Represents an error encountered while communicating with an SMT solver.
type SolverFailure =
  | SolverCommunicationFailure of message: string
  | SolverOutputParseFailure of message: string * stdout: string
  | SolverSerializationFailure of message: string
  | SolverReturnedUnknown

/// Represents an error encountered during symbolic evaluation.
type SymbEvalError =
  | UnsupportedExpression of string
  | UnsupportedStatement of string
  | UnsupportedOperation of string
  | UnsupportedSymbolicAddress of SymbExpr
  | InvalidMemoryRead of Addr
  | UninitializedRegister of RegisterID
  | UninitializedTemporary of int
  | SolverFailure of SolverFailure

/// Represents values that can be requested from a solver model.
type IQueryExpr =
  /// Symbolic expressions to include in solver value extraction.
  abstract QueryValues: SymbExpr list

/// Represents one or more solver-model query expressions.
type QueryExpr =
  /// Request no values.
  | Empty
  /// Request one symbolic expression value.
  | Value of SymbExpr
  /// Request a nested sequence of query expressions.
  | Values of IQueryExpr list
with
  interface IQueryExpr with
    member this.QueryValues =
      match this with
      | Empty -> []
      | Value expr -> [ expr ]
      | Values exprs ->
        exprs |> List.collect (fun expr -> expr.QueryValues)

/// Symbolic expression helpers.
[<RequireQualifiedAccess>]
module SymbExpr =
  let zero typ = Const(BitVector.Zero typ)

  let one typ = Const(BitVector.One typ)

  /// The 1-bit bit-vector true value used for LowUIR conditions.
  let trueExpr = Const BitVector.T

  /// The 1-bit bit-vector false value used for LowUIR conditions.
  let falseExpr = Const BitVector.F

  /// Returns true when the expression has the 1-bit condition type.
  let isCondition (expr: SymbExpr) = expr.Type = 1<rt>

  let undef typ reason = Undef(typ, reason)

  let unop op expr = UnOp(op, expr)

  let binop op typ lhs rhs = BinOp(op, typ, lhs, rhs)

  let relop op lhs rhs = RelOp(op, lhs, rhs)

  let load endian typ addr = Load(endian, typ, addr)

  let ite cond thenExpr elseExpr = Ite(cond, thenExpr, elseExpr)

  let cast kind typ expr = Cast(kind, typ, expr)

  let extract expr typ startPos = Extract(expr, typ, startPos)

  let funcApp name typ args = FuncApp(name, typ, args)

  let tryGetConcrete = function
    | Const bv -> Some bv
    | _ -> None

  let tryGetConcreteAddr expr =
    tryGetConcrete expr |> Option.map (fun bv -> bv.ToUInt64())

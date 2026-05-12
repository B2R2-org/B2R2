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

namespace B2R2.MiddleEnd.SymEval

open B2R2

/// Represents a symbolic bit-vector value.
type SymExpr =
  /// A concrete bit-vector constant.
  | Const of BitVector
  /// A named symbolic bit-vector variable.
  | Var of name: string * typ: RegType
  /// A value that exists in the source IR but has undefined semantics.
  | Undef of typ: RegType * reason: string
with
  /// Return the bit width of the expression.
  member this.Type =
    match this with
    | Const bv -> bv.Length
    | Var(_, typ) -> typ
    | Undef(typ, _) -> typ

/// Represents an error encountered during symbolic evaluation.
type SymEvalError =
  | UnsupportedExpression of string
  | UnsupportedStatement of string
  | UnsupportedOperation of string
  | UnsupportedSymbolicAddress of SymExpr
  | UninitializedRegister of RegisterID
  | UninitializedTemporary of int
  | SolverFailure of string

/// Symbolic expression helpers.
[<RequireQualifiedAccess>]
module SymExpr =
  let zero typ = Const(BitVector.Zero typ)

  let one typ = Const(BitVector.One typ)

  let trueExpr = Const BitVector.T

  let falseExpr = Const BitVector.F

  let tryGetConcrete = function
    | Const bv -> Some bv
    | _ -> None

  let tryGetConcreteAddr expr =
    tryGetConcrete expr |> Option.map BitVector.ToUInt64

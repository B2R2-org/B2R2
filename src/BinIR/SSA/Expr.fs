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

namespace B2R2.BinIR.SSA

open B2R2
open B2R2.BinIR

/// Represents the SSA IR (Static Single Assignment IR) expressions, which are
/// mostly similar to LowUIR expressions.
type Expr =
  /// A number. For example, (0x42:I32) is a 32-bit number 0x42
  | Num of BitVector

  /// A variable.
  | Var of Variable

  /// List of expressions.
  | ExprList of Expr list

  /// Memory lookup such as [T_1]:I32
  | Load of Variable * RegType * Expr

  /// Memory update such as [T_1] <- T_2. The second argument is a type of
  /// stored value.
  | Store of Variable * RegType * Expr * Expr

  /// Name of uninterpreted function.
  | FuncName of string

  /// Unary operation such as negation. The second argument is a result type.
  | UnOp of UnOpType * RegType * Expr

  /// Binary operation such as add, sub, etc. The second argument is a result
  /// type after applying BinOp.
  | BinOp of BinOpType * RegType * Expr * Expr

  /// Relative operation such as eq, lt, etc. The second argument is a result
  /// type.
  | RelOp of RelOpType * RegType * Expr * Expr

  /// If-then-else expression. The first expression is a condition, second
  /// argument is a result type, and the third and the fourth are true and
  /// false expression respectively.
  | Ite of Expr * RegType * Expr * Expr

  /// Type casting expression. The first argument is a casting type, and the
  /// second argument is a result type.
  | Cast of CastKind * RegType * Expr

  /// Extraction expression. The first argument is target expression, and the
  /// second argument is the number of bits for extraction, and the third is
  /// the start position.
  | Extract of Expr * RegType * startPos: int

  /// Undefined expression. It is a fatal error when we encounter this
  /// expression while evaluating a program. This expression is useful when we
  /// encode a label that should not really jump to (e.g., divide-by-zero
  /// case).
  | Undefined of RegType * string
with
  /// Returns the type of an SSA expression.
  static member TypeOf expr =
    match expr with
    | Num bv -> BitVector.GetType bv
    | Var { Kind = RegVar (rt, _, _) }
    | Var { Kind = PCVar rt }
    | Var { Kind = TempVar (rt, _) }
    | Var { Kind = StackVar (rt, _) }
    | Var { Kind = GlobalVar (rt, _) } -> rt
    | Load (_, rt, _) -> rt
    | Store (_, rt, _, _) -> rt
    | UnOp (_, rt, _) -> rt
    | BinOp (_, rt, _, _) -> rt
    | RelOp (_, rt, _, _) -> rt
    | Ite (_, rt, _, _) -> rt
    | Cast (_, rt, _) -> rt
    | Extract (_, rt, _) -> rt
    | Undefined (rt, _) -> rt
    | _ -> raise InvalidExprException

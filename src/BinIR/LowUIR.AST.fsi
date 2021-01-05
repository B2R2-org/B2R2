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

namespace B2R2.BinIR.LowUIR

open B2R2
open B2R2.BinIR

/// This module defines functions for handling the AST of LowUIR.
[<RequireQualifiedAccess>]
module AST = begin
  /// Get Expression Information
  val getExprInfo: Expr -> ExprInfo

  /// Construct a number (Num).
  val num: BitVector -> Expr

  /// Construct a variable (Var).
  val var: RegType -> RegisterID -> string -> RegisterSet -> Expr

  /// Construct a pc variable (PCVar).
  val pcvar: RegType -> string -> Expr

  /// Construct a temporary variable (TempVar).
  val tmpvar: RegType -> Expr

  /// Construct a symbol (for a label) from a string.
  val symbol: string -> Symbol

  /// Construct an unary operator (UnOp).
  val unop: UnOpType -> Expr -> Expr

  /// Construct a binary operator (BinOp).
  val binop: BinOpType -> Expr -> Expr -> Expr

  /// Consing two expr
  val cons: Expr -> Expr -> Expr

  /// Construct a app
  val app: string -> Expr list -> RegType -> Expr

  /// Construct a relative operator (RelOp).
  val relop: RelOpType -> Expr -> Expr -> Expr

  /// Construct a load expression (Load).
  val load: Endian -> RegType -> Expr -> Expr

  /// Construct an ITE (if-then-else) expression (Ite).
  val ite: Expr -> Expr -> Expr -> Expr

  /// Construct a cast expression (Cast).
  val cast: CastKind -> RegType -> Expr -> Expr

  /// Construct a extract expression (Extract).
  val extract: Expr -> RegType -> StartPos -> Expr

  /// Undefined expression.
  val undef: RegType -> string -> Expr

  /// Construct a (Num 0) of size t.
  val num0: t: RegType -> Expr

  /// Construct a (Num 1) of size t.
  val num1: t: RegType -> Expr

  /// Num expression for a one-bit number zero.
  val b0: Expr

  /// Num expression for a one-bit number one.
  val b1: Expr

  /// Nil.
  val nil: Expr

  /// An assignment statement.
  val assign: Expr -> Expr -> Stmt

  /// Add two expressions.
  val add: Expr -> Expr -> Expr

  /// Subtract two expressions.
  val sub: Expr -> Expr -> Expr

  /// Multiplication.
  val mul: Expr -> Expr -> Expr

  /// Unsigned division.
  val div: Expr -> Expr -> Expr

  /// Signed division.
  val sdiv: Expr -> Expr -> Expr

  /// Unsigned modulus.
  val ``mod``: Expr -> Expr -> Expr

  /// Signed modulus.
  val smod: Expr -> Expr -> Expr

  /// Equal.
  val eq: Expr -> Expr -> Expr

  /// Not equal.
  val neq: Expr -> Expr -> Expr

  /// Unsigned greater than.
  val gt: Expr -> Expr -> Expr

  /// Unsigned greater than or equal.
  val ge: Expr -> Expr -> Expr

  /// Signed greater than.
  val sgt: Expr -> Expr -> Expr

  /// Signed greater than or equal.
  val sge: Expr -> Expr -> Expr

  /// Unsigned less than.
  val lt: Expr -> Expr -> Expr

  /// Unsigned less than or equal.
  val le: Expr -> Expr -> Expr

  /// Signed less than.
  val slt: Expr -> Expr -> Expr

  /// Signed less than or equal.
  val sle: Expr -> Expr -> Expr

  /// Bitwise AND.
  val ``and``: Expr -> Expr -> Expr

  /// Bitwise OR.
  val ``or``: Expr -> Expr -> Expr

  /// Bitwise XOR.
  val xor: Expr -> Expr -> Expr

  /// Shift arithmetic right.
  val sar: Expr -> Expr -> Expr

  /// Shift logical right.
  val shr: Expr -> Expr -> Expr

  /// Shift logical left.
  val shl: Expr -> Expr -> Expr

  /// Negation (Two's complement).
  val neg: Expr -> Expr

  /// Logical not.
  val not: Expr -> Expr

  /// Floating point add two expressions.
  val fadd: Expr -> Expr -> Expr

  /// Floating point subtract two expressions.
  val fsub: Expr -> Expr -> Expr

  /// Floating point multiplication.
  val fmul: Expr -> Expr -> Expr

  /// Floating point division.
  val fdiv: Expr -> Expr -> Expr

  /// Floating point greater than.
  val fgt: Expr -> Expr -> Expr

  /// Floating point greater than or equal.
  val fge: Expr -> Expr -> Expr

  /// Floating point less than.
  val flt: Expr -> Expr -> Expr

  /// Floating point less than or equal.
  val fle: Expr -> Expr -> Expr

  /// Floating point power.
  val fpow: Expr -> Expr -> Expr

  /// Floating point logarithm.
  val flog: Expr -> Expr -> Expr

  /// Floating point square root.
  val fsqrt: Expr -> Expr

  /// Floating point cosine.
  val fcos: Expr -> Expr

  /// Floating point sine.
  val fsin: Expr -> Expr

  /// Floating point tangent.
  val ftan: Expr -> Expr

  /// Floating point arc tangent.
  val fatan: Expr -> Expr

  /// Concatenation.
  val concat: Expr -> Expr -> Expr

  /// Concatenate an array of expressions.
  val concatArr: Expr[] -> Expr

  /// Unwrap (casted) expression.
  val unwrap: Expr -> Expr

  /// Zero-extend an expression.
  val zext: RegType -> Expr -> Expr

  /// Sign-extend an expression.
  val sext: RegType -> Expr -> Expr

  /// Take the low half bits of an expression.
  val xtlo: RegType -> Expr -> Expr

  /// Take the high half bits of an expression.
  val xthi: RegType -> Expr -> Expr

  /// Load expression in little-endian.
  val loadLE: RegType -> Expr -> Expr

  /// Load expression in big-endian.
  val loadBE: RegType -> Expr -> Expr

  /// Get the type of an expression.
  val typeOf: Expr -> RegType

  /// Return true if the given statement type checks.
  val typeCheck: Stmt -> bool

  /// Infix operator for LowUIR.
  module InfixOp = begin
    /// An assignment statement.
    val (:=): Expr -> Expr -> Stmt

    /// Add two expressions.
    val (.+): Expr -> Expr -> Expr

    /// Subtract two expressions.
    val (.-): Expr -> Expr -> Expr

    /// Multiplication.
    val (.*): Expr -> Expr -> Expr

    /// Unsigned division.
    val (./): Expr -> Expr -> Expr

    /// Signed division.
    val (?/): Expr -> Expr -> Expr

    /// Unsigned modulus.
    val (.%): Expr -> Expr -> Expr

    /// Signed modulus.
    val (?%): Expr -> Expr -> Expr

    /// Equal.
    val (==): Expr -> Expr -> Expr

    /// Not equal.
    val (!=): Expr -> Expr -> Expr

    /// Unsigned greater than.
    val (.>): Expr -> Expr -> Expr

    /// Unsigned greater than or equal.
    val (.>=): Expr -> Expr -> Expr

    /// Signed greater than.
    val (?>): Expr -> Expr -> Expr

    /// Signed greater than or equal.
    val (?>=): Expr -> Expr -> Expr

    /// Unsigned less than.
    val (.<): Expr -> Expr -> Expr

    /// Unsigned less than or equal.
    val (.<=): Expr -> Expr -> Expr

    /// Signed less than.
    val (?<): Expr -> Expr -> Expr

    /// Signed less than or equal.
    val (?<=): Expr -> Expr -> Expr

    /// Bitwise AND.
    val (.&): Expr -> Expr -> Expr

    /// Bitwise OR.
    val (.|): Expr -> Expr -> Expr

    /// Bitwise XOR.
    val (<+>): Expr -> Expr -> Expr

    /// Shift arithmetic right.
    val (?>>): Expr -> Expr -> Expr

    /// Shift logical right.
    val (>>): Expr -> Expr -> Expr

    /// Shift logical left.
    val (<<): Expr -> Expr -> Expr
  end

end

module HashCons = begin

  exception ConsistencyFailException of string
  exception TagNotExistException

  /// Return true if the given expression is hash-consable.
  val isHashConsable: Expr -> bool

  /// Return true if the given expression is hash-consed.
  val isHashConsed: Expr -> bool

  /// Return the tag of hash-consed expression.
  val getTag: Expr -> int64

  /// Hash-consed UnOp constructor.
  val unop: UnOpType -> Expr -> Expr

  /// Hash-consed BinOp constructor.
  val binop: BinOpType -> Expr -> Expr -> Expr

  /// Hash-consed App constructor.
  val app: string -> Expr list -> RegType -> Expr

  /// Hash-consed RelOp constructor.
  val relop: RelOpType -> Expr -> Expr -> Expr

  /// Hash-consed Load constructor.
  val load: Endian -> RegType -> Expr -> Expr

  /// Hash-consed Ite constructor.
  val ite: Expr -> Expr -> Expr -> Expr

  /// Hash-consed Cast constructor. N.B. Type checking is not performed.
  val cast: CastKind -> RegType -> Expr -> Expr

  /// Hash-consed Extract constructor.
  val extract: Expr -> RegType -> StartPos -> Expr

end

// vim: set tw=80 sts=2 sw=2:

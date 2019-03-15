(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

/// Type representing destination of assignment.
type Destination =
  | RegVar of RegType * RegisterID * string * int
  | PCVar of RegType * int
  | TempVar of RegType * int
  | MemVar of int
  (* XXX: Another candidate of MemVar definition *)
  (* In this way, we treat memory like variables *)
  // | MemVar of Expr * int

/// IR Expressions.
type Expr =
    /// A number. For example, (0x42:I32) is a 32-bit number 0x42
  | Num of BitVector

    /// A variable.
  | Var of Destination

    /// Memory lookup such as [T_1]:I32
  | Load of Destination * RegType * Expr

    /// Memory updating such as [T_1] <- T_2
  | Store of Destination * Expr * Expr

    /// Name of uninterpreted function.
  | FuncName of string

    /// Unary operation such as negation.
  | UnOp of UnOpType * Expr

    /// Binary operation such as add, sub, etc. The second argument is a result
    /// type after applying BinOp.
  | BinOp of BinOpType * RegType * Expr * Expr

    /// Relative operation such as eq, lt, etc.
  | RelOp of RelOpType * Expr * Expr

    /// If-then-else expression. The first expression is a condition, and the
    /// second and the third are true and false expression respectively.
  | Ite of Expr * Expr * Expr

    /// Type casting expression. The first argument is a casting type, and the
    /// second argument is a result type.
  | Cast of CastKind * RegType * Expr

    /// Extraction expression. The first argument is target expression, and the
    /// second argument is the number of bits for extraction, and the third is
    /// the start position.
  | Extract of Expr * RegType * StartPos

    /// Undefined expression. It is a fatal error when we encounter this
    /// expression while evaluating a program. This expression is useful when we
    /// encode a label that should not really jump to (e.g., divide-by-zero
    /// case).
  | Undefined of RegType * string

/// IR Label. Since we don't distinguish instruction boundary in SSA level, we
/// need to specify where the label comes from.
type Label = Addr * Symbol

type JmpType =
  (* We directly show jump destination label instread of wrapping with Expr *)
  | IntraJmp of Label
  | IntraCJmp of Expr * Label * Label
  | InterJmp of Destination * Expr
  | InterCJmp of Expr * Destination * Expr * Expr

/// IR Statements.
type Stmt =
    /// ConsInfo data representing a label (as in an assembly language). LMark is
    /// only valid within a machine instruction.
  | LMark of Label

    /// Assignment in SSA.
  | Def of Destination * Expr

  | Phi of Destination * int []

  | Jmp of JmpType

    /// This represents an instruction with side effects such as a system call.
  | SideEffect of SideEffect

/// A program is a list of statements.
type Prog = Stmt list list

// vim: set tw=80 sts=2 sw=2:

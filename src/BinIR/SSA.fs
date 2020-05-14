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

/// Type representing destination of an assignment.
type VariableKind =
  | RegVar of RegType * RegisterID * string
  | PCVar of RegType
  | TempVar of RegType * int
  | MemVar
with
  static member toString = function
    | RegVar (_, _, n) -> n
    | PCVar (_) -> "PC"
    | TempVar (_, n) -> "T_" + n.ToString()
    | MemVar -> "MEM"

/// SSA variables always have their own identifier.
type Variable = {
  Kind: VariableKind
  mutable Identifier: int
}
with
  static member toString ({ Kind = k; Identifier = i }) =
    VariableKind.toString k + "_" + i.ToString ()

  static member IsPC ({ Kind = k }) =
    match k with
    | PCVar (_) -> true
    | _ -> false

/// Basic expressions similar to LowUIR.Expr.
type Expr =
  /// A number. For example, (0x42:I32) is a 32-bit number 0x42
  | Num of BitVector

  /// A variable.
  | Var of Variable

  /// Nil value for cons cells.
  | Nil

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
  | Extract of Expr * RegType * StartPos

  /// Undefined expression. It is a fatal error when we encounter this
  /// expression while evaluating a program. This expression is useful when we
  /// encode a label that should not really jump to (e.g., divide-by-zero
  /// case).
  | Undefined of RegType * string

  /// Value returned from a function located at the address. The second argument
  /// indicates the return address, and the third argument indicates the live
  /// definition of previously defined variable.
  | ReturnVal of Addr * Addr * Variable

/// IR Label. Since we don't distinguish instruction boundary in SSA level, we
/// want to specify where the label comes from.
type Label = Addr * Symbol

type JmpType =
  /// Jump to a label.
  | IntraJmp of Label
  /// Conditional jump to a label.
  | IntraCJmp of Expr * Label * Label
  /// Jump to another instruction. The Expr is the jump address.
  | InterJmp of Expr
  /// Conditional jump. The first Expr is the condition, and the second and the
  /// third Expr refer to true and false branch addresses, respectively.
  | InterCJmp of Expr * Expr * Expr

/// IR Statements.
type Stmt =
  /// A label (as in an assembly language). LMark is only valid within a
  /// machine instruction.
  | LMark of Label

  /// Assignment in SSA.
  | Def of Variable * Expr

  /// Phi function.
  | Phi of Variable * int []

  /// Branch statement.
  | Jmp of JmpType

  /// This represents an instruction with side effects such as a system call.
  | SideEffect of SideEffect

/// A program is a list of statements.
type Prog = Stmt list list

// vim: set tw=80 sts=2 sw=2:

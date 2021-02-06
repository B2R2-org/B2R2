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

open System
open B2R2
open B2R2.BinIR
open B2R2.Utils

type [<Flags>] InterJmpInfo =
  | Base = 0
  | IsCall = 1
  | IsRet = 2
  | IsExit = 4
  | SwitchToARM = 8
  | SwitchToThumb = 16

[<Struct>]
type ConsInfo = {
  Tag: int64
  Hash: int
}

/// ExprInfo summarizes several abstract information about the Expr. This is
/// useful for writing an efficient post analyses.
type ExprInfo = {
  /// Is this expression contains memory load(s).
  HasLoad: bool
  /// A set of registers (their regids) used in this expression.
  VarsUsed: RegisterSet
  /// A set of temp variables (their IDs) used in this expression.
  TempVarsUsed: Set<int>
}

/// IR Expressions.
/// NOTE: You SHOULD NOT create Expr without using functions in
///       B2R2.BinIR.LowUIR.HashCons or B2R2.BinIR.LowUIR.AST.
[<CustomEquality; NoComparison>]
type Expr =
  /// A number. For example, (0x42:I32) is a 32-bit number 0x42
  | Num of BitVector

  /// A variable that represents a register of a CPU. Var (t, r, n) indicates
  /// a variable of type (t) that has RegisterID r and name (n).
  /// For example, (EAX:I32) represents the EAX register (of type I32).
  /// Note that name (n) is additional information that doesn't be used
  /// internally.
  | Var of RegType * RegisterID * string * RegisterSet

  /// Nil to represent cons cells. This should only be used with BinOpType.CONS.
  | Nil

  /// A variable that represents a Program Counter (PC) of a CPU.
  | PCVar of RegType * string

  /// A temporary variable represents an internal (imaginary) register. Names
  /// of temporary variables should always be affixed by an underscore (_) and
  /// a number. This is to make sure that any temporary variable is unique in
  /// a CFG. For example, a temporary variable T can be represented as
  /// (T_2:I32), where 2 is a unique number assigned to the variable.
  | TempVar of RegType * int

  /// Unary operation such as negation.
  | UnOp of UnOpType * Expr * ExprInfo * ConsInfo option

  /// Symbolic constant for labels.
  | Name of Symbol

  /// Name of uninterpreted function.
  | FuncName of string

  /// Binary operation such as add, sub, etc. The second argument is a result
  /// type after applying BinOp.
  | BinOp of BinOpType * RegType * Expr * Expr * ExprInfo * ConsInfo option

  /// Relative operation such as eq, lt, etc.
  | RelOp of RelOpType * Expr * Expr * ExprInfo * ConsInfo option

  /// Memory loading such as LE:[T_1:I32]
  | Load of Endian * RegType * Expr * ExprInfo * ConsInfo option

  /// If-then-else expression. The first expression is a condition, and the
  /// second and the third are true and false expression respectively.
  | Ite of Expr * Expr * Expr * ExprInfo * ConsInfo option

  /// Type casting expression. The first argument is a casting type, and the
  /// second argument is a result type.
  | Cast of CastKind * RegType * Expr * ExprInfo * ConsInfo option

  /// Extraction expression. The first argument is target expression, and the
  /// second argument is the number of bits for extraction, and the third is
  /// the start position.
  | Extract of Expr * RegType * StartPos * ExprInfo * ConsInfo option

  /// Undefined expression. This is rarely used, and it is a fatal error when we
  /// encounter this expression while evaluating a program. Some CPU manuals
  /// explicitly say that a register value is undefined after a certain
  /// operation. We model such cases with this expression.
  | Undefined of RegType * string

  member inline private __.DoHash v phash = (phash * 16777619) ^^^ v

  member inline private __.Hash2 h1 h2 =
    __.DoHash h1 -2128831035 |> __.DoHash h2

  member inline private __.Hash3 h1 h2 h3 =
    __.Hash2 h1 h2 |> __.DoHash h3

  member inline private __.Hash4 h1 h2 h3 h4 =
    __.Hash3 h1 h2 h3 |> __.DoHash h4

  override __.Equals rhs =
    match rhs with
    | :? Expr as x ->
      match __, x with
      (* Primitive comparison. *)
      | Num n1, Num n2 -> n1 = n2
      | Name s1, Name s2 -> s1 = s2
      | FuncName s1, FuncName s2 -> s1 = s2
      | Var (typ1, r1, _, _), Var (typ2, r2, _, _) -> typ1 = typ2 && r1 = r2
      | TempVar (typ1, n1), TempVar (typ2, n2) -> typ1 = typ2 && n1 = n2
      | PCVar (typ1, n1), PCVar (typ2, n2)
      | Undefined (typ1, n1), Undefined (typ2, n2) -> typ1 = typ2 && n1 = n2
      (* Non-Primitive Comparison.
         If both of arguments are hash-consed, use physical equality. *)
      | UnOp (_, _, _, Some _), UnOp (_, _, _, Some _)
      | BinOp (_, _, _, _, _, Some _), BinOp (_, _, _, _, _, Some _)
      | RelOp (_, _, _, _, Some _), RelOp (_, _, _, _, Some _)
      | Load (_, _, _, _, Some _), Load (_, _, _, _, Some _)
      | Ite (_, _, _, _, Some _), Ite (_, _, _, _, Some _)
      | Cast (_, _, _, _, Some _), Cast (_, _, _, _, Some _)
      | Extract (_, _, _, _, Some _), Extract (_, _, _, _, Some _) ->
        __ === x
      (* Otherwise, use structure equality *)
      | UnOp (op1, e1, _, _), UnOp (op2, e2, _, _) -> op1 = op2 && e1 = e2
      | BinOp (op1, typ1, e11, e12, _, _), BinOp (op2, typ2, e21, e22, _, _) ->
        op1 = op2 && typ1 = typ2 && e11 = e21 && e12 = e22
      | RelOp (op1, e11, e12, _, _), RelOp (op2, e21, e22, _, _) ->
        op1 = op2 && e11 = e21 && e12 = e22
      | Load (_endian1, typ1, e1, _, _), Load (_endian2, typ2, e2, _, _) ->
        _endian1 = _endian2 && typ1 = typ2 && e1 = e2
      | Ite (cond1, e11, e12, _, _), Ite (cond2, e21, e22, _, _) ->
        cond1 = cond2 && e11 = e21  && e12 = e22
      | Cast (cast1, typ1, e1, _, _), Cast (cast2, typ2, e2, _, _) ->
        cast1 = cast2 && typ1 = typ2 && e1 = e2
      | Extract (e1, typ1, p1, _, _), Extract (e2, typ2, p2, _, _) ->
        e1 = e2 && typ1 = typ2 && p1 = p2
      | _ -> false
    | _ -> false

  /// If cached hash exists, then take it. Otherwise, calculate it.
  override __.GetHashCode () =
    match __ with
    | Num n -> n.GetHashCode ()
    | Var (_typ, n, _, _) -> n.GetHashCode ()
    | Nil -> 0
    | PCVar (_typ, n) -> __.Hash2 (_typ.GetHashCode ()) (n.GetHashCode ())
    | TempVar (_typ, n) -> __.Hash2 (_typ.GetHashCode ()) (n.GetHashCode ())
    | UnOp (_, _, _, Some x) -> x.Hash
    | UnOp (op, e, _, None) -> __.Hash2 (op.GetHashCode ()) (e.GetHashCode ())
    | Name s -> s.GetHashCode ()
    | FuncName s -> s.GetHashCode ()
    | BinOp (_, _, _, _, _, Some x) -> x.Hash
    | BinOp (op, typ, e1, e2, _, None) ->
      __.Hash4 (op.GetHashCode ()) (typ.GetHashCode ())
               (e1.GetHashCode ()) (e2.GetHashCode ())
    | RelOp (_, _, _, _, Some x) -> x.Hash
    | RelOp (op, e1, e2, _, None) ->
      __.Hash3 (op.GetHashCode ()) (e1.GetHashCode ()) (e2.GetHashCode ())
    | Load (_endian, _, _, _, Some x) -> x.Hash
    | Load (_endian, typ, e, _, None) ->
      __.Hash3 (_endian.GetHashCode ()) (typ.GetHashCode ()) (e.GetHashCode ())
    | Ite (_, _, _, _, Some x) -> x.Hash
    | Ite (cond, e1, e2, _, None) ->
      __.Hash3 (cond.GetHashCode ()) (e1.GetHashCode ()) (e2.GetHashCode ())
    | Cast (_, _, _, _, Some x) -> x.Hash
    | Cast (cast, typ, e, _, None) ->
      __.Hash3 (cast.GetHashCode ()) (typ.GetHashCode ()) (e.GetHashCode ())
    | Extract (_, _, _, _, Some x) -> x.Hash
    | Extract (e, typ, pos, _, None) ->
      __.Hash3 (e.GetHashCode ()) (typ.GetHashCode ()) (pos.GetHashCode ())
    | Undefined (typ, r) -> __.Hash2 (typ.GetHashCode ()) (r.GetHashCode ())

/// IL Statements.
type Stmt =
  /// Metadata representing the start of a machine instruction. More
  /// specifically, it contains the length of the instruction. There must be a
  /// single IMark per a machine instruction.
  | ISMark of uint32

  /// Metadata representing the end of a machine instruction. It contains the
  /// length of the current instruction.
  | IEMark of uint32

  /// Metadata representing a label (as in an assembly language). LMark is only
  /// valid within a machine instruction.
  | LMark of Symbol

  /// This statement puts a value into a register. The first argument is a
  /// destination operand, and the second argument is a source operand. The
  /// destination operand should have either a Var or a TempVar.
  ///
  /// Example: [Put(T_1:I32, Load(LE, T_2:I32))]
  /// loads a 32-bit value from the address T2, and store the value to the
  /// temporary register T1.
  | Put of Expr * Expr

  /// This statement stores a value into a memory. The first argument
  /// represents the endianness, the second argument is a destination operand,
  /// and the third argument is a value to store.
  ///
  /// Example: Store(LE, T_1:I32, T_2:I32)
  /// stores a 32-bit value T_2 into the address T_1
  | Store of Endian * Expr * Expr

  /// This statement represents a jump (unconditional) to an LMark. The first
  /// argument specifies the target address.
  | Jmp of Expr

  /// This statement represents a conditional jump to an LMark. The first
  /// argument specifies a jump condition. If the condition is true, jump to
  /// the address specified by the second argument. Otherwise, jump to the
  /// address specified by the third argument.
  | CJmp of Expr * Expr * Expr

  /// This is an unconditional jump instruction to another instruction. This is
  /// an inter-instruction jump unlike Jmp statement. The first argument is the
  /// jump target address.
  | InterJmp of Expr * InterJmpInfo

  /// This is a conditional jump instruction to another instruction. The first
  /// argument specifies a jump condition. If the condition is true, change the
  /// program counter to jump to the address specified by the second argument.
  /// Otherwise, jump to the address specified by the third argument.
  | InterCJmp of Expr * Expr * Expr

  /// This represents an instruction with side effects such as a system call.
  | SideEffect of SideEffect

// vim: set tw=80 sts=2 sw=2:

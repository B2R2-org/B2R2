(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Minkyu Jung <hestati@kaist.ac.kr>
          Seung Il Jung <sijung@kaist.ac.kr>

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
open B2R2.Utils
open System

type [<System.Flags>] InterJmpInfo =
  | Base = 0
  | IsCall = 1
  | IsRet = 2
  | IsExit = 4

[<Struct>]
type ConsInfo = {
  Tag  : int64
  Hash : int
}

type ExprInfo = {
  HasLoad     : bool
  VarInfo     : RegisterSet
  TempVarInfo : Set<int>
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

    /// Undefined expression. It is a fatal error when we encounter this
    /// expression while evaluating a program. This expression is useful when we
    /// encode a label that should not really jump to (e.g., divide-by-zero
    /// case).
  | Undefined of RegType * string

  member inline private __.DoHash v phash = (phash * 16777619) ^^^ v

  member inline private __.Hash2 h1 h2 =
    __.DoHash h1 -2128831035 |> __.DoHash h2

  member inline private __.Hash3 h1 h2 h3 =
    __.Hash2 h1 h2 |> __.DoHash h3

  member inline private __.Hash4 h1 h2 h3 h4 =
    __.Hash3 h1 h2 h3 |> __.DoHash h4

  override __.Equals lhs =
    match lhs with
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
    /// ConsInfo data representing the start of a machine instruction. More
    /// specifically, it contains the address and the length of the instruction.
    /// There is a single IMark per machine instruction.
    ///
    /// Example: [IMark(<Addr>, <Len>)]
    /// represents a machine instruction of <Len> bytes located at <Addr>
  | ISMark of Addr * uint32

    /// ConsInfo data representing the end of a machine instruction. It contains the
    /// next fall-through address.
  | IEMark of Addr

    /// ConsInfo data representing a label (as in an assembly language). LMark is
    /// only valid within a machine instruction.
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

    /// This is an unconditional jump instruction to another instruction. This
    /// is an inter-instruction jump unlike Jmp statement. The first argument
    /// represents the program counter, and the second is the target address.
  | InterJmp of Expr * Expr * InterJmpInfo

    /// This is a conditional jump instruction to another instruction. The first
    /// argument specifies a jump condition, and the second argument represents
    /// the program counter. If the condition is true, change the program
    /// counter to jump to the address specified by the third argument.
    /// Otherwise, jump to the address specified by the fourth argument.
  | InterCJmp of Expr * Expr * Expr * Expr

    /// This represents an instruction with side effects such as a system call.
  | SideEffect of SideEffect

/// Pretty printer for LowUIR.
module Pp =
  open System.Text

  let unopToString = function
    | UnOpType.NEG -> "-"
    | UnOpType.NOT -> "~"
    | _ -> raise IllegalASTTypeException

  let binopToString = function
    | BinOpType.ADD -> "+"
    | BinOpType.SUB -> "-"
    | BinOpType.MUL -> "*"
    | BinOpType.DIV -> "/"
    | BinOpType.SDIV -> "?/"
    | BinOpType.MOD -> "%"
    | BinOpType.SMOD -> "?%"
    | BinOpType.SHL -> "<<"
    | BinOpType.SHR -> ">>"
    | BinOpType.SAR -> "?>>"
    | BinOpType.AND -> "&"
    | BinOpType.OR -> "|"
    | BinOpType.XOR -> "^"
    | BinOpType.CONCAT -> "++"
    | BinOpType.APP -> "-|"
    | BinOpType.CONS -> "::"
    | _ -> raise IllegalASTTypeException

  let relopToString = function
    | RelOpType.EQ -> "="
    | RelOpType.NEQ -> "!="
    | RelOpType.GT -> ">"
    | RelOpType.GE -> ">="
    | RelOpType.SGT -> "?>"
    | RelOpType.SGE -> "?>="
    | RelOpType.LT -> "<"
    | RelOpType.LE -> "<="
    | RelOpType.SLT -> "?<"
    | RelOpType.SLE -> "?<="
    | _ -> raise IllegalASTTypeException

  let castTypeToString = function
    | CastKind.SignExt -> "sext"
    | CastKind.ZeroExt -> "zext"
    | _ -> raise IllegalASTTypeException

  let sideEffectToString = function
    | ClockCounter -> "CLK"
    | Fence -> "Fence"
    | Halt -> "Halt"
    | Interrupt (n) -> "Int " + n.ToString ()
    | Lock -> "Lock"
    | Pause -> "Pause"
    | ProcessorID -> "PID"
    | SysCall -> "SysCall"
    | UndefinedInstr -> "Undef"
    | UnsupportedFP -> "FP"
    | UnsupportedPrivInstr -> "PrivInstr"
    | UnsupportedFAR -> "FAR"
    | UnsupportedExtension -> "CPU extension"

  let rec private _expToString expr (sb: StringBuilder) =
    match expr with
    | Num n -> sb.Append (BitVector.toString n) |> ignore
    | Var (_typ, _, n, _) -> sb.Append (n) |> ignore
    | PCVar (_typ, n) -> sb.Append (n) |> ignore
    | TempVar (typ, n) ->
      sb.Append ("T_") |> ignore
      sb.Append (n) |> ignore
      sb.Append (":") |> ignore
      sb.Append (RegType.toString typ) |> ignore
    | Name (n) -> sb.Append (Symbol.getName n) |> ignore
    | FuncName (n) -> sb.Append (n) |> ignore
    | UnOp (op, e, _, _) ->
      sb.Append ("(") |> ignore
      sb.Append (unopToString op) |> ignore
      sb.Append (" ") |> ignore
      _expToString e sb
      sb.Append (")") |> ignore
    | BinOp (op, _typ, e1, e2, _, _) ->
      sb.Append ("(") |> ignore
      _expToString e1 sb
      sb.Append (" ") |> ignore
      sb.Append (binopToString op) |> ignore
      sb.Append (" ") |> ignore
      _expToString e2 sb
      sb.Append (")") |> ignore
    | RelOp (op, e1, e2, _, _) ->
      sb.Append ("(") |> ignore
      _expToString e1 sb
      sb.Append (" ") |> ignore
      sb.Append (relopToString op) |> ignore
      sb.Append (" ") |> ignore
      _expToString e2 sb
      sb.Append (")") |> ignore
    | Load (_endian, typ, e, _, _) ->
      sb.Append ("[") |> ignore
      _expToString e sb
      sb.Append ("]:") |> ignore
      sb.Append (RegType.toString typ) |> ignore
    | Ite (cond, e1, e2, _, _) ->
      sb.Append ("(ite (") |> ignore
      _expToString cond sb
      sb.Append (") (") |> ignore
      _expToString e1 sb
      sb.Append (") (") |> ignore
      _expToString e2 sb
      sb.Append ("))") |> ignore
    | Cast (cast, typ, e, _, _) ->
      sb.Append (castTypeToString cast) |> ignore
      sb.Append (":") |> ignore
      sb.Append (RegType.toString typ) |> ignore
      sb.Append ("(") |> ignore
      _expToString e sb
      sb.Append (")") |> ignore
    | Extract (e, typ, p, _, _) ->
      sb.Append ("(") |> ignore
      _expToString e sb
      sb.Append ("[") |> ignore
      sb.Append ((int typ + p - 1).ToString () + ":" + p.ToString ())|> ignore
      sb.Append ("]") |> ignore
      sb.Append (")") |> ignore
    | Undefined (_, reason) ->
      sb.Append ("Undefined expression (") |> ignore
      sb.Append (reason) |> ignore
      sb.Append (")") |> ignore

  let private _stmtToString stmt (sb: StringBuilder) =
    match stmt with
    | ISMark (addr, len) ->
      sb.Append ("=== ISMark (") |> ignore
      sb.Append (addr.ToString("X")) |> ignore
      sb.Append (")") |> ignore
    | IEMark (addr) ->
      sb.Append ("=== IEMark (pc := ") |> ignore
      sb.Append (addr.ToString("X")) |> ignore
      sb.Append (")") |> ignore
    | LMark lbl ->
      sb.Append ("=== LMark (") |> ignore
      sb.Append (Symbol.getName lbl) |> ignore
      sb.Append (")") |> ignore
    | Put (exp1, exp2) ->
      _expToString exp1 sb
      sb.Append (" := ") |> ignore
      _expToString exp2 sb
    | Jmp exp ->
      sb.Append ("JmpLbl ") |> ignore
      _expToString exp sb
    | InterJmp (_pc, exp, _) ->
      sb.Append ("Jmp ") |> ignore
      _expToString exp sb
    | Store (_endian, exp1, exp2) ->
      sb.Append ("[") |> ignore
      _expToString exp1 sb
      sb.Append ("] := ") |> ignore
      _expToString exp2 sb
    | CJmp (cond, t, f) ->
      sb.Append ("if ") |> ignore
      _expToString cond sb
      sb.Append (" then JmpLbl ") |> ignore
      _expToString t sb
      sb.Append (" else JmpLbl ") |> ignore
      _expToString f sb
    | InterCJmp (cond, _pc, t, f) ->
      sb.Append ("if ") |> ignore
      _expToString cond sb
      sb.Append (" then Jmp ") |> ignore
      _expToString t sb
      sb.Append (" else Jmp ") |> ignore
      _expToString f sb
    | SideEffect eff ->
      sb.Append ("SideEffect " + sideEffectToString eff) |> ignore

  let expToString expr =
    let sb = new StringBuilder ()
    _expToString expr sb
    sb.ToString ()

  let stmtToString expr =
    let sb = new StringBuilder ()
    _stmtToString expr sb
    sb.ToString ()

  let stmtsToString stmts =
    let sb = new StringBuilder()
    Array.iter (fun stmt -> _stmtToString stmt sb
                            sb.Append (Environment.NewLine) |> ignore) stmts
    sb.ToString ()

// vim: set tw=80 sts=2 sw=2:

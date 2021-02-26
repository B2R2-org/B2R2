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
open LanguagePrimitives
open B2R2
open B2R2.BinIR

/// The kind of an InterJmp. Multiple kinds can present for a jump instruction.
[<Flags>]
type InterJmpKind =
  /// The base case, i.e., a simple jump instruction.
  | Base = 0
  /// A call to a function.
  | IsCall = 1
  /// A return from a function.
  | IsRet = 2
  /// An exit, which will terminate the process.
  | IsExit = 4
  /// A branch instructino that modifies the operation mode from Thumb to ARM.
  | SwitchToARM = 8
  /// A branch instructino that modifies the operation mode from ARM to Thumb.
  | SwitchToThumb = 16

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
/// NOTE: You MUST create Expr/Stmt through the AST module. *NEVER* directly
/// construct Expr nor Stmt.
#if ! HASHCONS
#else
[<CustomEquality; NoComparison>]
#endif
type E =
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
  | UnOp of UnOpType * Expr * ExprInfo

  /// Symbolic constant for labels.
  | Name of Symbol

  /// Name of uninterpreted function.
  | FuncName of string

  /// Binary operation such as add, sub, etc. The second argument is a result
  /// type after applying BinOp.
  | BinOp of BinOpType * RegType * Expr * Expr * ExprInfo

  /// Relative operation such as eq, lt, etc.
  | RelOp of RelOpType * Expr * Expr * ExprInfo

  /// Memory loading such as LE:[T_1:I32]
  | Load of Endian * RegType * Expr * ExprInfo

  /// If-then-else expression. The first expression is a condition, and the
  /// second and the third are true and false expression respectively.
  | Ite of Expr * Expr * Expr * ExprInfo

  /// Type casting expression. The first argument is a casting type, and the
  /// second argument is a result type.
  | Cast of CastKind * RegType * Expr * ExprInfo

  /// Extraction expression. The first argument is target expression, and the
  /// second argument is the number of bits for extraction, and the third is
  /// the start position.
  | Extract of Expr * RegType * StartPos * ExprInfo

  /// Undefined expression. This is rarely used, and it is a fatal error when we
  /// encounter this expression while evaluating a program. Some CPU manuals
  /// explicitly say that a register value is undefined after a certain
  /// operation. We model such cases with this expression.
  | Undefined of RegType * string
#if ! HASHCONS
#else
with
  override __.Equals rhs =
    match rhs with
    | :? E as rhs ->
      match __, rhs with
      | Num (n1), Num (n2) -> n1 = n2
      | Var (t1, r1, _, _), Var (t2, r2, _, _) -> t1 = t2 && r1 = r2
      | Nil, Nil -> true
      | PCVar (t1, _), PCVar (t2, _) -> t1 = t2
      | TempVar (t1, n1), TempVar (t2, n2) -> t1 = t2 && n1 = n2
      | UnOp (t1, e1, _), UnOp (t2, e2, _) -> t1 = t2 && PhysicalEquality e1 e2
      | Name (s1), Name (s2) -> s1 = s2
      | FuncName (n1), FuncName (n2) -> n1 = n2
      | BinOp (o1, t1, lhs1, rhs1, _), BinOp (o2, t2, lhs2, rhs2, _) ->
        o1 = o2 && t1 = t2 &&
          PhysicalEquality lhs1 lhs2 && PhysicalEquality rhs1 rhs2
      | RelOp (o1, lhs1, rhs1, _), RelOp (o2, lhs2, rhs2, _) ->
        o1 = o2 && PhysicalEquality lhs1 lhs2 && PhysicalEquality rhs1 rhs2
      | Load (n1, t1, e1, _), Load (n2, t2, e2, _) ->
        n1 = n2 && t1 = t2 && PhysicalEquality e1 e2
      | Ite (c1, t1, f1, _), Ite (c2, t2, f2, _) ->
        PhysicalEquality c1 c2 &&
          PhysicalEquality t1 t2 && PhysicalEquality f1 f2
      | Cast (k1, t1, e1, _), Cast (k2, t2, e2, _) ->
        k1 = k2 && t1 = t2 && PhysicalEquality e1 e2
      | Extract (e1, t1, p1, _), Extract (e2, t2, p2, _) ->
        PhysicalEquality e1 e2 && t1 = t2 && p1 = p2
      | Undefined (t1, s1), Undefined (t2, s2) -> t1 = t2 && s1 = s2
      | _ -> false
    | _ -> false

  static member inline HashVar (rt: RegType) (rid: RegisterID) =
    19 * (19 * int rt + int rid) + 1

  static member inline HashPCVar (rt: RegType) =
    19 * int rt + 2

  static member inline HashTempVar (rt: RegType) n =
    19 * (19 * int rt + n) + 3

  static member inline HashUnOp (op: UnOpType) e =
    19 * (19 * int op + e.HashKey) + 4

  static member inline HashName ((s, n): Symbol) =
    19 * (19 * s.GetHashCode () + n) + 5

  static member inline HashFuncName (s: string) =
    (19 * s.GetHashCode ()) + 6

  static member inline HashBinOp (op: BinOpType) (rt: RegType) e1 e2 =
    19 * (19 * (19 * (19 * int op + int rt) + e1.HashKey) + e2.HashKey) + 7

  static member inline HashRelOp (op: RelOpType) e1 e2 =
    19 * (19 * (19 * int op + e1.HashKey) + e2.HashKey) + 8

  static member inline HashLoad (endian: Endian) (rt: RegType) e =
    19 * (19 * (19 * int endian + int rt) + e.HashKey) + 9

  static member inline HashIte cond t f =
    19 * (19 * (19 * cond.HashKey + t.HashKey) + f.HashKey) + 10

  static member inline HashCast (kind: CastKind) (rt: RegType) e =
    19 * (19 * (19 * int kind + int rt) + e.HashKey) + 11

  static member inline HashExtract e (rt: RegType) pos =
    19 * (19 * (19 * e.HashKey + int rt) + pos) + 12

  static member inline HashUndef (rt: RegType) (s: string) =
    19 * (19 * int rt + s.GetHashCode ()) + 13

  override __.GetHashCode () =
    match __ with
    | Num n -> n.GetHashCode ()
    | Var (rt, rid, _, _) -> E.HashVar rt rid
    | Nil -> 0
    | PCVar (rt, _) -> E.HashPCVar rt
    | TempVar (rt, n) -> E.HashTempVar rt n
    | UnOp (op, e, _) -> E.HashUnOp op e
    | Name (s) -> E.HashName s
    | FuncName (s) -> E.HashFuncName s
    | BinOp (op, rt, e1, e2, _) -> E.HashBinOp op rt e1 e2
    | RelOp (op, e1, e2, _) -> E.HashRelOp op e1 e2
    | Load (endian, rt, e, _) -> E.HashLoad endian rt e
    | Ite (cond, t, f, _) -> E.HashIte cond t f
    | Cast (k, rt, e, _) -> E.HashCast k rt e
    | Extract (e, rt, pos, _) -> E.HashExtract e rt pos
    | Undefined (rt, s) -> E.HashUndef rt s
#endif

#if ! HASHCONS
/// When hash-consing is not used, we simply create a wrapper for an AST node.
and [<Struct>] Expr = {
  /// The actual AST node.
  E: E
}
#else
/// Hash-consed Expr.
and [<CustomEquality; CustomComparison>] Expr = {
  /// The actual AST node.
  E: E
  /// Unique id.
  Tag: uint32
  /// Hash cache.
  HashKey: int
}
with
  override __.Equals rhs =
    match rhs with
    | :? Expr as rhs -> __.Tag = rhs.Tag
    | _ -> false

  override __.GetHashCode () = __.HashKey

  interface IComparable with
    member __.CompareTo rhs =
      match rhs with
      | :? Expr as rhs -> __.Tag.CompareTo rhs.Tag
      | _ -> 1
#endif

/// IL Statements.
/// NOTE: You MUST create Expr/Stmt through the AST module. *NEVER* directly
/// construct Expr nor Stmt.
#if ! HASHCONS
#else
[<CustomEquality; NoComparison>]
#endif
type S =
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
  | InterJmp of Expr * InterJmpKind

  /// This is a conditional jump instruction to another instruction. The first
  /// argument specifies a jump condition. If the condition is true, change the
  /// program counter to jump to the address specified by the second argument.
  /// Otherwise, jump to the address specified by the third argument.
  | InterCJmp of Expr * Expr * Expr

  /// This represents an instruction with side effects such as a system call.
  | SideEffect of SideEffect
#if ! HASHCONS
#else
with
  override __.Equals rhs =
    match rhs with
    | :? S as rhs ->
      match __, rhs with
      | ISMark len1, ISMark len2 -> len1 = len2
      | IEMark len1, IEMark len2 -> len1 = len2
      | LMark s1, LMark s2 -> s1 = s2
      | Put (dst1, src1), Put (dst2, src2) ->
        dst1.Tag = dst2.Tag && src1.Tag = src2.Tag
      | Store (n1, addr1, e1), Store (n2, addr2, e2) ->
        n1 = n2 && addr1 = addr2 && e1.Tag = e2.Tag
      | Jmp (e1), Jmp (e2) -> e1.Tag = e2.Tag
      | CJmp (c1, t1, f1), CJmp (c2, t2, f2) ->
        c1.Tag = c2.Tag && t1.Tag = t2.Tag && f1.Tag = f2.Tag
      | InterJmp (e1, k1), InterJmp (e2, k2) -> e1.Tag = e2.Tag && k1 = k2
      | InterCJmp (c1, t1, f1), InterCJmp (c2, t2, f2) ->
        c1.Tag = c2.Tag && t1.Tag = t2.Tag && f1.Tag = f2.Tag
      | SideEffect e1, SideEffect e2 -> e1 = e2
      | _ -> false
    | _ -> false

  static member inline HashISMark (len: uint32) = len.GetHashCode () + 1

  static member inline HashIEMark (len: uint32) = 19 * len.GetHashCode () + 2

  static member inline HashLMark ((s, n): Symbol) =
    19 * (19 * s.GetHashCode () + n) + 3

  static member inline HashPut (dst: Expr) (src: Expr) =
    19 * (19 * dst.HashKey + src.HashKey) + 4

  static member inline HashStore (n: Endian) (addr: Expr) (e: Expr) =
    19 * (19 * (19 * int n + addr.HashKey) + e.HashKey) + 5

  static member inline HashJmp (e: Expr) =
    19 * (19 * e.HashKey + 1) + 6

  static member inline HashCJmp (cond: Expr) (t: Expr) (f: Expr) =
    19 * (19 * (19 * cond.HashKey + t.HashKey) + f.HashKey) + 7

  static member inline HashInterJmp (e: Expr) (k: InterJmpKind) =
    19 * (19 * e.HashKey + int k) + 8

  static member inline HashInterCJmp (cond: Expr) (t: Expr) (f: Expr) =
    19 * (19 * (19 * cond.HashKey + t.HashKey) + f.HashKey) + 9

  static member inline HashSideEffect (e: SideEffect) =
    (19 * hash e) + 10

  override __.GetHashCode () =
    match __ with
    | ISMark len -> S.HashISMark len
    | IEMark len -> S.HashIEMark len
    | LMark s -> S.HashLMark s
    | Put (dst, src) -> S.HashPut dst src
    | Store (n, addr, e) -> S.HashStore n addr e
    | Jmp (e) -> S.HashJmp e
    | CJmp (cond, t, f) -> S.HashCJmp cond t f
    | InterJmp (e, k) -> S.HashInterJmp e k
    | InterCJmp (cond, t, f) -> S.HashInterCJmp cond t f
    | SideEffect (e) -> S.HashSideEffect e
#endif

#if ! HASHCONS
/// When hash-consing is not used, we simply create a wrapper for an AST node.
and [<Struct>] Stmt = {
  /// The actual AST node.
  S: S
}
#else
/// Hash-consed Stmt.
and [<CustomEquality; NoComparison>] Stmt = {
  /// The actual AST node.
  S: S
  /// Unique id.
  Tag: uint32
  /// Hash cache.
  HashKey: int
}
with
  override __.Equals rhs =
    match rhs with
    | :? Stmt as rhs -> __.Tag = rhs.Tag
    | _ -> false

  override __.GetHashCode () = __.HashKey
#endif

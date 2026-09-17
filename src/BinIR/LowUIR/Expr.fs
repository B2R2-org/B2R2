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

open System.Text
open B2R2
open B2R2.BinIR

/// <namespacedoc>
///   <summary>
///   Contains the definition of the LowUIR intermediate representation (IR)
///   used in B2R2, which is the main IR used to represent the semantics of
///   instructions in a platform-agnostic way.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents a LowUIR expression.
/// <remarks>
/// You <i>must</i> create Expr/Stmt through the AST module. <b>NEVER</b>
/// directly construct Expr nor Stmt unless you know what you are doing.
/// </remarks>
/// </summary>
#if HASHCONS
[<CustomComparison; CustomEquality>]
#endif
type Expr =
  /// A number. For example, (0x42:I32) is a 32-bit number 0x42
  | Num of Value: BitVector
#if HASHCONS
         * HashCons: HashConsingInfo
#endif

  /// A variable that represents a register of a CPU. Var (t, r, n) indicates
  /// a variable of type (t) that has RegisterID r and name (n).
  /// For example, (EAX:I32) represents the EAX register (of type I32).
  /// Note that name (n) is additional information that doesn't be used
  /// internally.
  | Var of Type: RegType * RegisterID: RegisterID * Name: string
#if HASHCONS
         * HashCons: HashConsingInfo
#endif

  /// A variable that represents a Program Counter (PC) of a CPU.
  | PCVar of Type: RegType * Name: string
#if HASHCONS
           * HashCons: HashConsingInfo
#endif

  /// A temporary variable represents an internal (imaginary) register. Names
  /// of temporary variables should always be affixed by an underscore (_) and
  /// a number. This is to make sure that any temporary variable is unique in
  /// a CFG. For example, a temporary variable T can be represented as
  /// (T_2:I32), where 2 is a unique number assigned to the variable.
  | TempVar of Type: RegType * Index: int
#if HASHCONS
             * HashCons: HashConsingInfo
#endif

  /// List of expressions. We use this to represent function arguments.
  | ExprList of Elements: Expr list
#if HASHCONS
              * HashCons: HashConsingInfo
#endif

  /// Unary operation such as negation.
  | UnOp of Op: UnOpType * Operand: Expr
#if HASHCONS
          * HashCons: HashConsingInfo
#endif

  /// Jump destination of a Jmp or CJmp statement.
  | JmpDest of Target: Label
#if HASHCONS
             * HashCons: HashConsingInfo
#endif

  /// Name of uninterpreted function.
  | FuncName of Name: string
#if HASHCONS
              * HashCons: HashConsingInfo
#endif

  /// Binary operation such as add, sub, etc. The second argument is a result
  /// type after applying BinOp.
  | BinOp of Op: BinOpType * Type: RegType * Left: Expr * Right: Expr
#if HASHCONS
           * HashCons: HashConsingInfo
#endif

  /// Relative operation such as eq, lt, etc.
  | RelOp of Op: RelOpType * Left: Expr * Right: Expr
#if HASHCONS
           * HashCons: HashConsingInfo
#endif

  /// Memory loading such as LE:[T_1:I32]
  | Load of Endian: Endian * Type: RegType * Addr: Expr
#if HASHCONS
          * HashCons: HashConsingInfo
#endif

  /// If-then-else expression. The first expression is a condition, and the
  /// second and the third are true and false expression respectively.
  | Ite of Cond: Expr * TrueExpr: Expr * FalseExpr: Expr
#if HASHCONS
         * HashCons: HashConsingInfo
#endif

  /// Type casting expression. The first argument is a casting type, and the
  /// second argument is a result type.
  | Cast of Kind: CastKind * Type: RegType * Operand: Expr
#if HASHCONS
          * HashCons: HashConsingInfo
#endif

  /// <summary>
  /// The body evaluated with the given rounding direction in force.
  /// </summary>
  /// <remarks>
  /// This names a direction; it does not itself round. What rounds is the
  /// body, and most of what the IR does to a float rounds: the arithmetic
  /// (FADD, FSUB, FMUL, FDIV, FSQRT), every conversion that can lose
  /// something (FloatToSInt, RoundToIntegral, a FloatCast that narrows, an
  /// SIntToFloat or UIntToFloat whose integer is wider than the significand),
  /// and a named call answered by an operation that takes a direction. An
  /// FADD under one is still an add, which is what separates this from
  /// <c>CastKind.RoundToIntegral</c>, the operation that takes a float to a
  /// whole number.
  ///
  /// It comes to nothing only where the body has nothing to round: integer
  /// arithmetic, or a FloatCast that widens, which is exact for every value
  /// there is.
  ///
  /// The mode is an 8-bit expression in the
  /// <see cref='T:B2R2.BinIR.RoundingMode'/> encoding, an expression rather
  /// than a constant so that a direction known only at run time can name the
  /// register it comes from. A nested RoundCtrl wins over the one enclosing
  /// it.
  /// </remarks>
  | RoundCtrl of Mode: Expr * Body: Expr
#if HASHCONS
               * HashCons: HashConsingInfo
#endif

  /// Extraction expression. The first argument is target expression, and the
  /// second argument is the number of bits for extraction, and the third is
  /// the start position.
  | Extract of Operand: Expr * Type: RegType * StartPos: int
#if HASHCONS
             * HashCons: HashConsingInfo
#endif

  /// Undefined expression. This is rarely used, and it is a fatal error when we
  /// encounter this expression while evaluating a program. Some CPU manuals
  /// explicitly say that a register value is undefined after a certain
  /// operation. We model such cases with this expression.
  | Undefined of Type: RegType * Reason: string
#if HASHCONS
               * HashCons: HashConsingInfo
#endif
with
#if HASHCONS
  /// <summary>
  /// Retrieves the unique ID of the hash-consed expression.
  /// </summary>
  member inline this.ID with get() =
    match this with
    | Num(_, hc)
    | Var(_, _, _, hc)
    | PCVar(_, _, hc)
    | TempVar(_, _, hc)
    | ExprList(_, hc)
    | UnOp(_, _, hc)
    | JmpDest(_, hc)
    | FuncName(_, hc)
    | BinOp(_, _, _, _, hc)
    | RelOp(_, _, _, hc)
    | Load(_, _, _, hc)
    | Ite(_, _, _, hc)
    | Cast(_, _, _, hc)
    | RoundCtrl(_, _, hc)
    | Extract(_, _, _, hc)
    | Undefined(_, _, hc) -> hc.ID

  /// <summary>
  /// Retrieves the cached hash value of the hash-consed expression.
  /// </summary>
  member inline this.Hash with get() =
    match this with
    | Num(_, hc)
    | Var(_, _, _, hc)
    | PCVar(_, _, hc)
    | TempVar(_, _, hc)
    | ExprList(_, hc)
    | UnOp(_, _, hc)
    | JmpDest(_, hc)
    | FuncName(_, hc)
    | BinOp(_, _, _, _, hc)
    | RelOp(_, _, _, hc)
    | Load(_, _, _, hc)
    | Ite(_, _, _, hc)
    | Cast(_, _, _, hc)
    | RoundCtrl(_, _, hc)
    | Extract(_, _, _, hc)
    | Undefined(_, _, hc) -> hc.Hash

  static member inline HashVar(rt: RegType, rid: RegisterID) =
    19 * (19 * int rt + int rid) + 1

  static member inline HashPCVar(rt: RegType) = 19 * int rt + 2

  static member inline HashTempVar(rt: RegType, n) = 19 * (19 * int rt + n) + 3

  static member inline HashExprList(exprs: Expr list) =
    exprs
    |> List.fold (fun acc expr ->
      19 * acc + expr.Hash) 0

  static member inline HashUnOp(op: UnOpType, e: Expr) =
    19 * (19 * int op + e.Hash) + 4

  static member inline HashJmpDest(lbl: Label) = (19 * lbl.GetHashCode()) + 5

  static member inline HashFuncName(s: string) = (19 * s.GetHashCode()) + 6

  static member inline HashBinOp(op, rt, e1: Expr, e2: Expr) =
    19 * (19 * (19 * (19 * int op + int rt) + e1.Hash) + e2.Hash) + 7

  static member inline HashRelOp(op, e1: Expr, e2: Expr) =
    19 * (19 * (19 * int op + e1.Hash) + e2.Hash) + 8

  static member inline HashLoad(endian, rt: RegType, e: Expr) =
    19 * (19 * (19 * int endian + int rt) + e.Hash) + 9

  static member inline HashIte(cond: Expr, t: Expr, f: Expr) =
    19 * (19 * (19 * cond.Hash + t.Hash) + f.Hash) + 10

  static member inline HashCast(kind, rt: RegType, e: Expr) =
    19 * (19 * (19 * int kind + int rt) + e.Hash) + 11

  static member inline HashRoundCtrl(mode: Expr, body: Expr) =
    19 * (19 * mode.Hash + body.Hash) + 14

  static member inline HashExtract(e: Expr, rt: RegType, pos) =
    19 * (19 * (19 * e.Hash + int rt) + pos) + 12

  static member inline HashUndef(rt: RegType, s: string) =
    19 * (19 * int rt + s.GetHashCode()) + 13

  static member private ExprListEquals(lhs: Expr list, rhs: Expr list) =
    match lhs, rhs with
    | [], [] -> true
    | e1 :: lhs, e2 :: rhs -> e1.ID = e2.ID && Expr.ExprListEquals(lhs, rhs)
    | _ -> false

  interface System.IComparable with
    member this.CompareTo rhs =
      match rhs with
      | :? Expr as rhs -> this.ID.CompareTo rhs.ID
      | _ -> Terminator.impossible ()

  override this.GetHashCode() =
    match this with
    | Num(n, _) -> n.GetHashCode()
    | Var(rt, rid, _, _) -> Expr.HashVar(rt, rid)
    | PCVar(rt, _, _) -> Expr.HashPCVar rt
    | TempVar(rt, n, _) -> Expr.HashTempVar(rt, n)
    | ExprList(exprs, _) -> Expr.HashExprList exprs
    | UnOp(op, e, _) -> Expr.HashUnOp(op, e)
    | JmpDest(s, _) -> Expr.HashJmpDest s
    | FuncName(s, _) -> Expr.HashFuncName s
    | BinOp(op, rt, e1, e2, _) -> Expr.HashBinOp(op, rt, e1, e2)
    | RelOp(op, e1, e2, _) -> Expr.HashRelOp(op, e1, e2)
    | Load(endian, rt, e, _) -> Expr.HashLoad(endian, rt, e)
    | Ite(cond, t, f, _) -> Expr.HashIte(cond, t, f)
    | Cast(k, rt, e, _) -> Expr.HashCast(k, rt, e)
    | RoundCtrl(mode, body, _) -> Expr.HashRoundCtrl(mode, body)
    | Extract(e, rt, pos, _) -> Expr.HashExtract(e, rt, pos)
    | Undefined(rt, s, _) -> Expr.HashUndef(rt, s)

  override this.Equals rhs =
    match rhs with
    | :? Expr as rhs ->
      match this, rhs with
      | Num(n1, _), Num(n2, _) ->
        n1 = n2
      | Var(t1, r1, _, _), Var(t2, r2, _, _) ->
        t1 = t2 && r1 = r2
      | PCVar(t1, _, _), PCVar(t2, _, _) ->
        t1 = t2
      | TempVar(t1, n1, _), TempVar(t2, n2, _) ->
        t1 = t2 && n1 = n2
      | ExprList(lhs, _), ExprList(rhs, _) ->
        Expr.ExprListEquals(lhs, rhs)
      | UnOp(t1, e1, _), UnOp(t2, e2, _) ->
        t1 = t2 && e1 === e2
      | JmpDest(s1, _), JmpDest(s2, _) ->
        s1 = s2
      | FuncName(n1, _), FuncName(n2, _) ->
        n1 = n2
      | BinOp(o1, t1, lhs1, rhs1, _), BinOp(o2, t2, lhs2, rhs2, _) ->
        o1 = o2 && t1 = t2 && lhs1 === lhs2 && rhs1 === rhs2
      | RelOp(o1, lhs1, rhs1, _), RelOp(o2, lhs2, rhs2, _) ->
        o1 = o2 && lhs1 === lhs2 && rhs1 === rhs2
      | Load(n1, t1, e1, _), Load(n2, t2, e2, _) ->
        n1 = n2 && t1 = t2 && e1 === e2
      | Ite(c1, t1, f1, _), Ite(c2, t2, f2, _) ->
        c1 === c2 && t1 === t2 && f1 === f2
      | Cast(k1, t1, e1, _), Cast(k2, t2, e2, _) ->
        k1 = k2 && t1 = t2 && e1 === e2
      | RoundCtrl(m1, b1, _), RoundCtrl(m2, b2, _) ->
        m1 === m2 && b1 === b2
      | Extract(e1, t1, p1, _), Extract(e2, t2, p2, _) ->
        e1 === e2 && t1 = t2 && p1 = p2
      | Undefined(t1, s1, _), Undefined(t2, s2, _) ->
        t1 = t2 && s1 = s2
      | _ ->
        false
    | _ ->
      false
#endif

  static member internal AppendToString(expr, sb: StringBuilder) =
    match expr with
    | Num(Value = n) ->
      sb.Append(n.ToString()) |> ignore
    | Var(Type = _typ; Name = n) ->
      sb.Append n |> ignore
    | PCVar(Type = _typ; Name = n) ->
      sb.Append n |> ignore
    | TempVar(Type = typ; Index = n) ->
      sb.Append "T_" |> ignore
      sb.Append n |> ignore
      sb.Append ":" |> ignore
      sb.Append(RegType.toString typ) |> ignore
    | ExprList(Elements = exprs) ->
      exprs |> List.iteri (fun i e ->
        if i > 0 then sb.Append ", " |> ignore else ()
        Expr.AppendToString(e, sb))
    | JmpDest(Target = lbl) ->
      sb.Append lbl.Name |> ignore
    | FuncName(Name = n) ->
      sb.Append n |> ignore
    | UnOp(Op = op; Operand = e) ->
      sb.Append "(" |> ignore
      sb.Append(UnOpType.toString op) |> ignore
      sb.Append " " |> ignore
      Expr.AppendToString(e, sb)
      sb.Append ")" |> ignore
    (* The only prefix operator *)
    | BinOp(Op = BinOpType.FLOG; Left = e1; Right = e2) ->
      sb.Append "(lg (" |> ignore
      Expr.AppendToString(e1, sb)
      sb.Append ", " |> ignore
      Expr.AppendToString(e2, sb)
      sb.Append "))" |> ignore
    | BinOp(Op = BinOpType.APP; Type = typ; Left = e1; Right = e2) ->
      Expr.AppendToString(e1, sb)
      sb.Append "(" |> ignore
      Expr.AppendToString(e2, sb)
      sb.Append "):" |> ignore
      sb.Append(RegType.toString typ) |> ignore
    | BinOp(Op = op; Type = _typ; Left = e1; Right = e2) ->
      sb.Append "(" |> ignore
      Expr.AppendToString(e1, sb)
      sb.Append " " |> ignore
      sb.Append(BinOpType.toString op) |> ignore
      sb.Append " " |> ignore
      Expr.AppendToString(e2, sb)
      sb.Append ")" |> ignore
    | RelOp(Op = op; Left = e1; Right = e2) ->
      sb.Append "(" |> ignore
      Expr.AppendToString(e1, sb)
      sb.Append " " |> ignore
      sb.Append(RelOpType.toString op) |> ignore
      sb.Append " " |> ignore
      Expr.AppendToString(e2, sb)
      sb.Append ")" |> ignore
    | Load(Endian = _endian; Type = typ; Addr = e) ->
      sb.Append "[" |> ignore
      Expr.AppendToString(e, sb)
      sb.Append "]:" |> ignore
      sb.Append(RegType.toString typ) |> ignore
    | Ite(Cond = cond; TrueExpr = e1; FalseExpr = e2) ->
      sb.Append "((" |> ignore
      Expr.AppendToString(cond, sb)
      sb.Append ") ? (" |> ignore
      Expr.AppendToString(e1, sb)
      sb.Append ") : (" |> ignore
      Expr.AppendToString(e2, sb)
      sb.Append "))" |> ignore
    | Cast(Kind = cast; Type = typ; Operand = e) ->
      sb.Append(CastKind.toString cast) |> ignore
      sb.Append ":" |> ignore
      sb.Append(RegType.toString typ) |> ignore
      sb.Append "(" |> ignore
      Expr.AppendToString(e, sb)
      sb.Append ")" |> ignore
    | RoundCtrl(Mode = mode; Body = body) ->
      sb.Append "rnd(" |> ignore
      Expr.AppendToString(mode, sb)
      sb.Append ", " |> ignore
      Expr.AppendToString(body, sb)
      sb.Append ")" |> ignore
    | Extract(Operand = e; Type = typ; StartPos = p) ->
      sb.Append "(" |> ignore
      Expr.AppendToString(e, sb)
      sb.Append "[" |> ignore
      sb.Append((int typ + p - 1).ToString() + ":" + p.ToString()) |> ignore
      sb.Append "]" |> ignore
      sb.Append ")" |> ignore
    | Undefined(Reason = reason) ->
      sb.Append "?? (" |> ignore
      sb.Append(reason) |> ignore
      sb.Append ")" |> ignore

  override this.ToString() =
    let sb = StringBuilder()
    Expr.AppendToString(this, sb)
    sb.ToString()

/// Provides utility functions for expressions.
[<RequireQualifiedAccess>]
module Expr =
  /// Converts an expression to a string.
  [<CompiledName "ToString">]
  let toString (expr: Expr) = expr.ToString()

  /// Gets the type of an expression.
  [<CompiledName "TypeOf">]
  let rec typeOf expr =
    match expr with
    | Num(Value = n) -> n.Length
    | Var(Type = t)
    | PCVar(Type = t)
    | TempVar(Type = t) -> t
    | UnOp(Operand = e) -> typeOf e
    | BinOp(Type = t) -> t
    | RelOp _ -> 1<rt>
    | Load(Type = t) -> t
    | Ite(TrueExpr = e1) -> typeOf e1
    | Cast(Type = t) -> t
    | RoundCtrl(Body = body) -> typeOf body
    | Extract(Type = t) -> t
    | Undefined(Type = t) -> t
    | FuncName _ | JmpDest _ | ExprList _ -> raise InvalidExprException

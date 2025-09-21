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
[<CustomComparison; CustomEquality>]
type Expr =
  /// A number. For example, (0x42:I32) is a 32-bit number 0x42
  | Num of BitVector * HashConsingInfo

  /// A variable that represents a register of a CPU. Var (t, r, n) indicates
  /// a variable of type (t) that has RegisterID r and name (n).
  /// For example, (EAX:I32) represents the EAX register (of type I32).
  /// Note that name (n) is additional information that doesn't be used
  /// internally.
  | Var of RegType * RegisterID * string * HashConsingInfo

  /// A variable that represents a Program Counter (PC) of a CPU.
  | PCVar of RegType * string * HashConsingInfo

  /// A temporary variable represents an internal (imaginary) register. Names
  /// of temporary variables should always be affixed by an underscore (_) and
  /// a number. This is to make sure that any temporary variable is unique in
  /// a CFG. For example, a temporary variable T can be represented as
  /// (T_2:I32), where 2 is a unique number assigned to the variable.
  | TempVar of RegType * int * HashConsingInfo

  /// List of expressions. We use this to represent function arguments.
  | ExprList of Expr list * HashConsingInfo

  /// Unary operation such as negation.
  | UnOp of UnOpType * Expr * HashConsingInfo

  /// Jump destination of a Jmp or CJmp statement.
  | JmpDest of Label * HashConsingInfo

  /// Name of uninterpreted function.
  | FuncName of string * HashConsingInfo

  /// Binary operation such as add, sub, etc. The second argument is a result
  /// type after applying BinOp.
  | BinOp of BinOpType * RegType * Expr * Expr * HashConsingInfo

  /// Relative operation such as eq, lt, etc.
  | RelOp of RelOpType * Expr * Expr * HashConsingInfo

  /// Memory loading such as LE:[T_1:I32]
  | Load of Endian * RegType * Expr * HashConsingInfo

  /// If-then-else expression. The first expression is a condition, and the
  /// second and the third are true and false expression respectively.
  | Ite of Expr * Expr * Expr * HashConsingInfo

  /// Type casting expression. The first argument is a casting type, and the
  /// second argument is a result type.
  | Cast of CastKind * RegType * Expr * HashConsingInfo

  /// Extraction expression. The first argument is target expression, and the
  /// second argument is the number of bits for extraction, and the third is
  /// the start position.
  | Extract of Expr * RegType * startPos: int * HashConsingInfo

  /// Undefined expression. This is rarely used, and it is a fatal error when we
  /// encounter this expression while evaluating a program. Some CPU manuals
  /// explicitly say that a register value is undefined after a certain
  /// operation. We model such cases with this expression.
  | Undefined of RegType * string * HashConsingInfo
with
  /// <summary>
  /// Retrives the unique ID of the expression. If hash consing is not used,
  /// this will raise an exception.
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
    | Extract(_, _, _, hc)
    | Undefined(_, _, hc) -> hc.ID

  /// <summary>
  /// Retrives the hash value of the expression. If hash consing is not used,
  /// this will raise an exception.
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
    | Extract(_, _, _, hc)
    | Undefined(_, _, hc) -> hc.Hash

  static member inline HashVar(rt: RegType, rid: RegisterID) =
    19 * (19 * int rt + int rid) + 1

  static member inline HashPCVar(rt: RegType) =
    19 * int rt + 2

  static member inline HashTempVar(rt: RegType, n) =
    19 * (19 * int rt + n) + 3

  static member inline HashExprList(exprs: Expr list, hasCache) =
    exprs
    |> List.fold (fun acc expr ->
      let hash = if hasCache then expr.Hash else expr.GetHashCode()
      19 * acc + hash) 0

  static member inline HashUnOp(op: UnOpType, e: Expr, hasCache) =
    if hasCache then 19 * (19 * int op + e.Hash) + 4
    else 19 * (19 * int op + e.GetHashCode()) + 4

  static member inline HashJmpDest(lbl: Label) =
    19 * (19 * lbl.GetHashCode()) + 5

  static member inline HashFuncName(s: string) =
    (19 * s.GetHashCode()) + 6

  static member inline HashBinOp(op, rt, e1: Expr, e2: Expr, hasCache) =
    if hasCache then
      19 * (19 * (19 * (19 * int op + int rt) + e1.Hash) + e2.Hash) + 7
    else
      19 * (19 * (19 * (19 * int op + int rt) + e1.GetHashCode())
            + e2.GetHashCode()) + 7

  static member inline HashRelOp(op, e1: Expr, e2: Expr, hasCache) =
    if hasCache then 19 * (19 * (19 * int op + e1.Hash) + e2.Hash) + 8
    else 19 * (19 * (19 * int op + e1.GetHashCode()) + e2.GetHashCode()) + 8

  static member inline HashLoad(endian, rt: RegType, e: Expr, hasCache) =
    if hasCache then 19 * (19 * (19 * int endian + int rt) + e.Hash) + 9
    else 19 * (19 * (19 * int endian + int rt) + e.GetHashCode()) + 9

  static member inline HashIte(cond: Expr, t: Expr, f: Expr, hasCache) =
    if hasCache then
      19 * (19 * (19 * cond.Hash + t.Hash) + f.Hash) + 10
    else
      19 * (19 * (19 * cond.GetHashCode() + t.GetHashCode())
            + f.GetHashCode()) + 10

  static member inline HashCast(kind, rt: RegType, e: Expr, hasCache) =
    if hasCache then 19 * (19 * (19 * int kind + int rt) + e.Hash) + 11
    else 19 * (19 * (19 * int kind + int rt) + e.GetHashCode()) + 11

  static member inline HashExtract(e: Expr, rt: RegType, pos, hasCache) =
    if hasCache then 19 * (19 * (19 * e.Hash + int rt) + pos) + 12
    else 19 * (19 * (19 * e.GetHashCode() + int rt) + pos) + 12

  static member inline HashUndef(rt: RegType, s: string) =
    19 * (19 * int rt + s.GetHashCode()) + 13

  static member internal AppendToString(expr, sb: StringBuilder) =
    match expr with
    | Num(n, _) -> sb.Append(BitVector.ToString n) |> ignore
    | Var(_typ, _, n, _) -> sb.Append(n) |> ignore
    | PCVar(_typ, n, _) -> sb.Append(n) |> ignore
    | TempVar(typ, n, _) ->
      sb.Append("T_") |> ignore
      sb.Append(n) |> ignore
      sb.Append(":") |> ignore
      sb.Append(RegType.toString typ) |> ignore
    | ExprList([], _) -> ()
    | ExprList(e :: [], _) -> Expr.AppendToString(e, sb)
    | ExprList(e :: more, hc) ->
      Expr.AppendToString(e, sb) |> ignore
      sb.Append(", ") |> ignore
      Expr.AppendToString(ExprList(more, hc), sb)
    | JmpDest(lbl, _) -> sb.Append lbl.Name |> ignore
    | FuncName(n, _) -> sb.Append n |> ignore
    | UnOp(op, e, _) ->
      sb.Append("(") |> ignore
      sb.Append(UnOpType.toString op) |> ignore
      sb.Append(" ") |> ignore
      Expr.AppendToString(e, sb)
      sb.Append(")") |> ignore
    | BinOp(BinOpType.FLOG, _typ, e1, e2, _) -> (* The only prefix operator *)
      sb.Append("(lg (") |> ignore
      Expr.AppendToString(e1, sb)
      sb.Append(", ") |> ignore
      Expr.AppendToString(e2, sb)
      sb.Append("))") |> ignore
    | BinOp(BinOpType.APP, typ, e1, e2, _) ->
      Expr.AppendToString(e1, sb)
      sb.Append("(") |> ignore
      Expr.AppendToString(e2, sb)
      sb.Append("):") |> ignore
      sb.Append(RegType.toString typ) |> ignore
    | BinOp(op, _typ, e1, e2, _) ->
      sb.Append("(") |> ignore
      Expr.AppendToString(e1, sb)
      sb.Append(" ") |> ignore
      sb.Append(BinOpType.toString op) |> ignore
      sb.Append(" ") |> ignore
      Expr.AppendToString(e2, sb)
      sb.Append(")") |> ignore
    | RelOp(op, e1, e2, _) ->
      sb.Append("(") |> ignore
      Expr.AppendToString(e1, sb)
      sb.Append(" ") |> ignore
      sb.Append(RelOpType.toString op) |> ignore
      sb.Append(" ") |> ignore
      Expr.AppendToString(e2, sb)
      sb.Append(")") |> ignore
    | Load(_endian, typ, e, _) ->
      sb.Append("[") |> ignore
      Expr.AppendToString(e, sb)
      sb.Append("]:") |> ignore
      sb.Append(RegType.toString typ) |> ignore
    | Ite(cond, e1, e2, _) ->
      sb.Append("((") |> ignore
      Expr.AppendToString(cond, sb)
      sb.Append(") ? (") |> ignore
      Expr.AppendToString(e1, sb)
      sb.Append(") : (") |> ignore
      Expr.AppendToString(e2, sb)
      sb.Append("))") |> ignore
    | Cast(cast, typ, e, _) ->
      sb.Append(CastKind.toString cast) |> ignore
      sb.Append(":") |> ignore
      sb.Append(RegType.toString typ) |> ignore
      sb.Append("(") |> ignore
      Expr.AppendToString(e, sb)
      sb.Append(")") |> ignore
    | Extract(e, typ, p, _) ->
      sb.Append("(") |> ignore
      Expr.AppendToString(e, sb)
      sb.Append("[") |> ignore
      sb.Append((int typ + p - 1).ToString() + ":" + p.ToString()) |> ignore
      sb.Append("]") |> ignore
      sb.Append(")") |> ignore
    | Undefined(_, reason, _) ->
      sb.Append("?? (") |> ignore
      sb.Append(reason) |> ignore
      sb.Append(")") |> ignore

  static member ToString expr =
    let sb = StringBuilder()
    Expr.AppendToString(expr, sb)
    sb.ToString()

  /// Gets the type of an expression.
  static member TypeOf expr =
    match expr with
    | Num(n, _) -> n.Length
    | Var(t, _, _, _)
    | PCVar(t, _, _)
    | TempVar(t, _, _) -> t
    | UnOp(_, e, _) -> Expr.TypeOf e
    | BinOp(_, t, _, _, _) -> t
    | RelOp _ -> 1<rt>
    | Load(_, t, _, _) -> t
    | Ite(_, e1, _, _) -> Expr.TypeOf e1
    | Cast(_, t, _, _) -> t
    | Extract(_, t, _, _) -> t
    | Undefined(t, _, _) -> t
    | FuncName _ | JmpDest _ | ExprList _ -> raise InvalidExprException

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
    | ExprList(exprs, null) -> Expr.HashExprList(exprs, false)
    | ExprList(exprs, _) -> Expr.HashExprList(exprs, true)
    | UnOp(op, e, null) -> Expr.HashUnOp(op, e, false)
    | UnOp(op, e, _) -> Expr.HashUnOp(op, e, true)
    | JmpDest(s, _) -> Expr.HashJmpDest s
    | FuncName(s, _) -> Expr.HashFuncName s
    | BinOp(op, rt, e1, e2, null) -> Expr.HashBinOp(op, rt, e1, e2, false)
    | BinOp(op, rt, e1, e2, _) -> Expr.HashBinOp(op, rt, e1, e2, true)
    | RelOp(op, e1, e2, null) -> Expr.HashRelOp(op, e1, e2, false)
    | RelOp(op, e1, e2, _) -> Expr.HashRelOp(op, e1, e2, true)
    | Load(endian, rt, e, null) -> Expr.HashLoad(endian, rt, e, false)
    | Load(endian, rt, e, _) -> Expr.HashLoad(endian, rt, e, true)
    | Ite(cond, t, f, null) -> Expr.HashIte(cond, t, f, false)
    | Ite(cond, t, f, _) -> Expr.HashIte(cond, t, f, true)
    | Cast(k, rt, e, null) -> Expr.HashCast(k, rt, e, false)
    | Cast(k, rt, e, _) -> Expr.HashCast(k, rt, e, true)
    | Extract(e, rt, pos, null) -> Expr.HashExtract(e, rt, pos, false)
    | Extract(e, rt, pos, _) -> Expr.HashExtract(e, rt, pos, true)
    | Undefined(rt, s, _) -> Expr.HashUndef(rt, s)

  override this.Equals rhs =
    match rhs with
    | :? Expr as rhs ->
      match this, rhs with
      | Num(n1, _), Num(n2, _) -> n1 = n2
      | Var(t1, r1, _, _), Var(t2, r2, _, _) -> t1 = t2 && r1 = r2
      | PCVar(t1, _, _), PCVar(t2, _, _) -> t1 = t2
      | TempVar(t1, n1, _), TempVar(t2, n2, _) -> t1 = t2 && n1 = n2
      | ExprList(lhs, null), ExprList(rhs, null) ->
        List.forall2 (fun e1 e2 -> e1.Equals e2) lhs rhs
      | ExprList(lhs, _), ExprList(rhs, _) -> lhs === rhs
      | UnOp(t1, e1, null), UnOp(t2, e2, null) -> t1 = t2 && e1.Equals e2
      | UnOp(t1, e1, _), UnOp(t2, e2, _) -> t1 = t2 && e1 === e2
      | JmpDest(s1, _), JmpDest(s2, _) -> s1 = s2
      | FuncName(n1, _), FuncName(n2, _) -> n1 = n2
      | BinOp(o1, t1, lhs1, rhs1, null), BinOp(o2, t2, lhs2, rhs2, null) ->
        o1 = o2 && t1 = t2 && lhs1.Equals lhs2 && rhs1.Equals rhs2
      | BinOp(o1, t1, lhs1, rhs1, _), BinOp(o2, t2, lhs2, rhs2, _) ->
        o1 = o2 && t1 = t2 && lhs1 === lhs2 && rhs1 === rhs2
      | RelOp(o1, lhs1, rhs1, null), RelOp(o2, lhs2, rhs2, null) ->
        o1 = o2 && lhs1.Equals lhs2 && rhs1.Equals rhs2
      | RelOp(o1, lhs1, rhs1, _), RelOp(o2, lhs2, rhs2, _) ->
        o1 = o2 && lhs1 === lhs2 && rhs1 === rhs2
      | Load(n1, t1, e1, null), Load(n2, t2, e2, null) ->
        n1 = n2 && t1 = t2 && e1.Equals e2
      | Load(n1, t1, e1, _), Load(n2, t2, e2, _) ->
        n1 = n2 && t1 = t2 && e1 === e2
      | Ite(c1, t1, f1, null), Ite(c2, t2, f2, null) ->
        c1.Equals c2 && t1.Equals t2 && f1.Equals f2
      | Ite(c1, t1, f1, _), Ite(c2, t2, f2, _) ->
        c1 === c2 && t1 === t2 && f1 === f2
      | Cast(k1, t1, e1, null), Cast(k2, t2, e2, null) ->
        k1 = k2 && t1 = t2 && e1.Equals e2
      | Cast(k1, t1, e1, _), Cast(k2, t2, e2, _) ->
        k1 = k2 && t1 = t2 && e1 === e2
      | Extract(e1, t1, p1, null), Extract(e2, t2, p2, null) ->
        e1.Equals e2 && t1 = t2 && p1 = p2
      | Extract(e1, t1, p1, _), Extract(e2, t2, p2, _) ->
        e1 === e2 && t1 = t2 && p1 = p2
      | Undefined(t1, s1, _), Undefined(t2, s2, _) -> t1 = t2 && s1 = s2
      | _ -> false
    | _ -> false

  override this.ToString() = Expr.ToString this

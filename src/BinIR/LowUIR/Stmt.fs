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

/// <summary>
/// Represents a LowUIR statement.
/// <remarks>
/// You <i>must</i> create Expr/Stmt through the AST module. <b>NEVER</b>
/// directly construct Expr nor Stmt unless you know what you are doing.
/// </remarks>
/// </summary>
[<CustomEquality; NoComparison>]
type Stmt =
  /// Metadata representing the start of a machine instruction. More
  /// specifically, it contains the length of the instruction. There must be a
  /// single IMark per a machine instruction.
  | ISMark of uint32 * HashConsingInfo

  /// Metadata representing the end of a machine instruction. It contains the
  /// length of the current instruction.
  | IEMark of uint32 * HashConsingInfo

  /// Metadata representing a label (as in an assembly language). LMark is only
  /// valid within a machine instruction.
  | LMark of Label * HashConsingInfo

  /// This statement puts a value into a register. The first argument is a
  /// destination operand, and the second argument is a source operand. The
  /// destination operand should have either a Var or a TempVar.
  ///
  /// Example: [Put(T_1:I32, Load(LE, T_2:I32))]
  /// loads a 32-bit value from the address T2, and store the value to the
  /// temporary register T1.
  | Put of Expr * Expr * HashConsingInfo

  /// This statement stores a value into a memory. The first argument
  /// represents the endianness, the second argument is a destination operand,
  /// and the third argument is a value to store.
  ///
  /// Example: Store(LE, T_1:I32, T_2:I32)
  /// stores a 32-bit value T_2 into the address T_1
  | Store of Endian * Expr * Expr * HashConsingInfo

  /// This statement represents a jump (unconditional) to an LMark. The first
  /// argument specifies the target address.
  | Jmp of Expr * HashConsingInfo

  /// This statement represents a conditional jump to an LMark. The first
  /// argument specifies a jump condition. If the condition is true, jump to
  /// the address specified by the second argument. Otherwise, jump to the
  /// address specified by the third argument.
  | CJmp of Expr * Expr * Expr * HashConsingInfo

  /// This is an unconditional jump instruction to another instruction. This is
  /// an inter-instruction jump unlike Jmp statement. The first argument is the
  /// jump target address.
  | InterJmp of Expr * InterJmpKind * HashConsingInfo

  /// This is a conditional jump instruction to another instruction. The first
  /// argument specifies a jump condition. If the condition is true, change the
  /// program counter to jump to the address specified by the second argument.
  /// Otherwise, jump to the address specified by the third argument.
  | InterCJmp of Expr * Expr * Expr * HashConsingInfo

  /// External function call. This statement represents a uninterpreted function
  /// call. The argument expression is in a curried form.
  | ExternalCall of Expr * HashConsingInfo

  /// This represents an instruction with side effects such as a system call.
  | SideEffect of SideEffect * HashConsingInfo
with
  /// Unique ID of the hash consed statement.
  member inline this.ID with get() =
    match this with
    | ISMark(_, hc)
    | IEMark(_, hc)
    | LMark(_, hc)
    | Put(_, _, hc)
    | Store(_, _, _, hc)
    | Jmp(_, hc)
    | CJmp(_, _, _, hc)
    | InterJmp(_, _, hc)
    | InterCJmp(_, _, _, hc)
    | ExternalCall(_, hc)
    | SideEffect(_, hc) -> hc.ID

  /// Precomputed hash value of the statement.
  member inline this.Hash with get() =
    match this with
    | ISMark(_, hc)
    | IEMark(_, hc)
    | LMark(_, hc)
    | Put(_, _, hc)
    | Store(_, _, _, hc)
    | Jmp(_, hc)
    | CJmp(_, _, _, hc)
    | InterJmp(_, _, hc)
    | InterCJmp(_, _, _, hc)
    | ExternalCall(_, hc)
    | SideEffect(_, hc) -> hc.Hash

  static member inline HashISMark(len: uint32) = len.GetHashCode() + 1

  static member inline HashIEMark(len: uint32) = 19 * len.GetHashCode() + 2

  static member inline HashLMark(label: Label) =
    19 * (19 * label.GetHashCode()) + 3

  static member inline HashPut(dst: Expr, src: Expr) =
    19 * (19 * dst.Hash + src.Hash) + 4

  static member inline HashStore(n: Endian, addr: Expr, e: Expr) =
    19 * (19 * (19 * int n + addr.Hash) + e.Hash) + 5

  static member inline HashJmp(e: Expr) =
    19 * (19 * e.Hash + 1) + 6

  static member inline HashCJmp(cond: Expr, t: Expr, f: Expr) =
    19 * (19 * (19 * cond.Hash + t.Hash) + f.Hash) + 7

  static member inline HashInterJmp(e: Expr, k: InterJmpKind) =
    19 * (19 * e.Hash + int k) + 8

  static member inline HashInterCJmp(cond: Expr, t: Expr, f: Expr) =
    19 * (19 * (19 * cond.Hash + t.Hash) + f.Hash) + 9

  static member inline HashExtCall(e: Expr) =
    (19 * e.Hash) + 10

  static member inline HashSideEffect(e: SideEffect) =
    (19 * hash e) + 11

  static member AppendToString(stmt, sb: StringBuilder) =
    match stmt with
    | ISMark(len, _) ->
      sb.Append("(") |> ignore
      sb.Append(len.ToString()) |> ignore
      sb.Append(") {") |> ignore
    | IEMark(len, _) ->
      sb.Append("} // ") |> ignore
      sb.Append(len.ToString()) |> ignore
    | LMark(lbl, _) ->
      sb.Append(":") |> ignore
      sb.Append lbl.Name |> ignore
    | Put(exp1, exp2, _) ->
      Expr.AppendToString(exp1, sb)
      sb.Append(" := ") |> ignore
      Expr.AppendToString(exp2, sb)
    | Jmp(exp, _) ->
      sb.Append("jmp ") |> ignore
      Expr.AppendToString(exp, sb)
    | InterJmp(exp, _, _) ->
      sb.Append("ijmp ") |> ignore
      Expr.AppendToString(exp, sb)
    | Store(_endian, exp1, exp2, _) ->
      sb.Append("[") |> ignore
      Expr.AppendToString(exp1, sb)
      sb.Append("] := ") |> ignore
      Expr.AppendToString(exp2, sb)
    | CJmp(cond, t, f, _) ->
      sb.Append("if ") |> ignore
      Expr.AppendToString(cond, sb)
      sb.Append(" then jmp ") |> ignore
      Expr.AppendToString(t, sb)
      sb.Append(" else jmp ") |> ignore
      Expr.AppendToString(f, sb)
    | InterCJmp(cond, t, f, _) ->
      sb.Append("if ") |> ignore
      Expr.AppendToString(cond, sb)
      sb.Append(" then ijmp ") |> ignore
      Expr.AppendToString(t, sb)
      sb.Append(" else ijmp ") |> ignore
      Expr.AppendToString(f, sb)
    | ExternalCall(args, _) ->
      sb.Append("call ") |> ignore
      Expr.AppendToString(args, sb)
    | SideEffect(eff, _) ->
      sb.Append("!!" + SideEffect.ToString eff) |> ignore

  static member ToString stmt =
    let sb = StringBuilder()
    Stmt.AppendToString(stmt, sb)
    sb.ToString()

  override this.GetHashCode() =
    match this with
    | ISMark(len, _) -> Stmt.HashISMark len
    | IEMark(len, _) -> Stmt.HashIEMark len
    | LMark(s, _) -> Stmt.HashLMark s
    | Put(dst, src, _) -> Stmt.HashPut(dst, src)
    | Store(n, addr, e, _) -> Stmt.HashStore(n, addr, e)
    | Jmp(e, _) -> Stmt.HashJmp e
    | CJmp(cond, t, f, _) -> Stmt.HashCJmp(cond, t, f)
    | InterJmp(e, k, _) -> Stmt.HashInterJmp(e, k)
    | InterCJmp(cond, t, f, _) -> Stmt.HashInterCJmp(cond, t, f)
    | ExternalCall(e, _) -> Stmt.HashExtCall e
    | SideEffect(e, _) -> Stmt.HashSideEffect e

  override this.Equals rhs =
    match rhs with
    | :? Stmt as rhs ->
      match this, rhs with
      | ISMark(len1, _), ISMark(len2, _) -> len1 = len2
      | IEMark(len1, _), IEMark(len2, _) -> len1 = len2
      | LMark(lbl1, _), LMark(lbl2, _) -> lbl1 = lbl2
      | Put(dst1, src1, null), Put(dst2, src2, null) ->
        dst1 = dst2 && src1 = src2
      | Put(dst1, src1, _), Put(dst2, src2, _) ->
        dst1.ID = dst2.ID && src1.ID = src2.ID
      | Store(n1, addr1, e1, null), Store(n2, addr2, e2, null) ->
        n1 = n2 && addr1 = addr2 && e1 = e2
      | Store(n1, addr1, e1, _), Store(n2, addr2, e2, _) ->
        n1 = n2 && addr1 = addr2 && e1.ID = e2.ID
      | Jmp(e1, null), Jmp(e2, null) -> e1 = e2
      | Jmp(e1, _), Jmp(e2, _) -> e1.ID = e2.ID
      | CJmp(c1, t1, f1, null), CJmp(c2, t2, f2, null) ->
        c1 = c2 && t1 = t2 && f1 = f2
      | CJmp(c1, t1, f1, _), CJmp(c2, t2, f2, _) ->
        c1.ID = c2.ID && t1.ID = t2.ID && f1.ID = f2.ID
      | InterJmp(e1, k1, null), InterJmp(e2, k2, null) -> e1 = e2 && k1 = k2
      | InterJmp(e1, k1, _), InterJmp(e2, k2, _) -> e1.ID = e2.ID && k1 = k2
      | InterCJmp(c1, t1, f1, null), InterCJmp(c2, t2, f2, null) ->
        c1 = c2 && t1 = t2 && f1 = f2
      | InterCJmp(c1, t1, f1, _), InterCJmp(c2, t2, f2, _) ->
        c1.ID = c2.ID && t1.ID = t2.ID && f1.ID = f2.ID
      | SideEffect(e1, _), SideEffect(e2, _) -> e1 = e2
      | _ -> false
    | _ -> false

  override this.ToString() = Stmt.ToString this

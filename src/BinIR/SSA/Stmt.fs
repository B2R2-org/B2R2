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

open System.Text
open B2R2.BinIR

/// Represents an SSA statement.
type Stmt =
  /// A label (as in an assembly language). LMark is only valid within a
  /// machine instruction.
  | LMark of Label

  /// Assignment in SSA.
  | Def of Variable * Expr

  /// Phi function.
  | Phi of Variable * int[]

  /// Branch statement.
  | Jmp of JmpType

  /// External call.
  | ExternalCall of Expr * inVars: Variable list * outVars: Variable list

  /// This represents an instruction with side effects such as a system call.
  | SideEffect of SideEffect
with
  static member private LabelToString(lbl: Label, sb: StringBuilder) =
    sb.Append $"{lbl.Name} @ {lbl.Address:x}" |> ignore

  static member private VariablesToString(kind, vars, sb: StringBuilder) =
    sb.Append(" ") |> ignore
    sb.Append(kind: string) |> ignore
    sb.Append("(") |> ignore
    vars |> List.iter (fun v ->
      sb.Append(Variable.ToString v) |> ignore
      sb.Append(";") |> ignore)
    sb.Append(")") |> ignore

  static member internal AppendToString(stmt: Stmt, sb: StringBuilder) =
    match stmt with
    | LMark lbl ->
      sb.Append("=== LMark (") |> ignore
      Stmt.LabelToString(lbl, sb)
      sb.Append(")") |> ignore
    | Def(v, e) ->
      sb.Append(Variable.ToString v) |> ignore
      sb.Append(" := ") |> ignore
      Expr.AppendToString(e, sb)
    | Jmp(IntraJmp(lbl)) ->
      sb.Append("JmpLbl ") |> ignore
      Stmt.LabelToString(lbl, sb)
    | Jmp(IntraCJmp(cond, lbl1, lbl2)) ->
      sb.Append("if ") |> ignore
      Expr.AppendToString(cond, sb)
      sb.Append(" then JmpLbl ") |> ignore
      Stmt.LabelToString(lbl1, sb)
      sb.Append(" else JmpLbl ") |> ignore
      Stmt.LabelToString(lbl2, sb)
    | Jmp(InterJmp(dst)) ->
      sb.Append("Jmp ") |> ignore
      Expr.AppendToString(dst, sb)
    | Jmp(InterCJmp(cond, dst1, dst2)) ->
      sb.Append("if ") |> ignore
      Expr.AppendToString(cond, sb)
      sb.Append(" then Jmp ") |> ignore
      Expr.AppendToString(dst1, sb)
      sb.Append(" else Jmp ") |> ignore
      Expr.AppendToString(dst2, sb)
    | Phi(def, indices) ->
      sb.Append(Variable.ToString def) |> ignore
      sb.Append(" := phi(") |> ignore
      indices |> Array.iter (fun i ->
        sb.Append(i.ToString()) |> ignore
        sb.Append(";") |> ignore)
      sb.Append(")") |> ignore
    | ExternalCall(args, inVars, outVars) ->
      sb.Append("call ") |> ignore
      Expr.AppendToString(args, sb)
      Stmt.VariablesToString("OutVars", outVars, sb)
      Stmt.VariablesToString("InVars", inVars, sb)
    | SideEffect eff ->
      sb.Append("SideEffect " + SideEffect.ToString eff) |> ignore

  /// Pretty-prints an SSA statement to a string.
  static member ToString stmt =
    let sb = StringBuilder()
    Stmt.AppendToString(stmt, sb)
    sb.ToString()

/// Represents a jump kind of SSA's Jmp statement.
and JmpType =
  /// Jump to a label.
  | IntraJmp of Label
  /// Conditional jump to a label.
  | IntraCJmp of Expr * Label * Label
  /// Jump to another instruction. The Expr is the jump address.
  | InterJmp of Expr
  /// Conditional jump. The first Expr is the condition, and the second and the
  /// third Expr refer to true and false branch addresses, respectively.
  | InterCJmp of Expr * Expr * Expr


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

/// Provides the functionality to pretty-print SSA expressions and statements.
module B2R2.BinIR.SSA.Pp

open System
open System.Text
open B2R2
open B2R2.BinIR

let rec private expToStringAux expr (sb: StringBuilder) =
  match expr with
  | Num n -> sb.Append(BitVector.ToString n) |> ignore
  | Var(v) -> sb.Append(Variable.ToString v) |> ignore
  | Nil -> sb.Append "nil" |> ignore
  | FuncName(n) -> sb.Append n |> ignore
  | UnOp(op, _, e) ->
    sb.Append "(" |> ignore
    sb.Append(UnOpType.toString op) |> ignore
    sb.Append " " |> ignore
    expToStringAux e sb
    sb.Append ")" |> ignore
  | BinOp(op, _, e1, e2) ->
    sb.Append "(" |> ignore
    expToStringAux e1 sb
    sb.Append " " |> ignore
    sb.Append(BinOpType.toString op) |> ignore
    sb.Append " " |> ignore
    expToStringAux e2 sb
    sb.Append ")" |> ignore
  | RelOp(op, _, e1, e2) ->
    sb.Append "(" |> ignore
    expToStringAux e1 sb
    sb.Append " " |> ignore
    sb.Append(RelOpType.toString op) |> ignore
    sb.Append " " |> ignore
    expToStringAux e2 sb
    sb.Append ")" |> ignore
  | Load(v, typ, e) ->
    sb.Append(Variable.ToString v) |> ignore
    sb.Append "[" |> ignore
    expToStringAux e sb
    sb.Append "]:" |> ignore
    sb.Append(RegType.toString typ) |> ignore
  | Store(v, _, addr, e) ->
    sb.Append(Variable.ToString v) |> ignore
    sb.Append "[" |> ignore
    expToStringAux addr sb
    sb.Append " <- " |> ignore
    expToStringAux e sb
    sb.Append "]" |> ignore
  | Ite(cond, _, e1, e2) ->
    sb.Append "(ite (" |> ignore
    expToStringAux cond sb
    sb.Append ") (" |> ignore
    expToStringAux e1 sb
    sb.Append ") (" |> ignore
    expToStringAux e2 sb
    sb.Append "))" |> ignore
  | Cast(cast, typ, e) ->
    sb.Append(CastKind.toString cast) |> ignore
    sb.Append ":" |> ignore
    sb.Append(RegType.toString typ) |> ignore
    sb.Append "(" |> ignore
    expToStringAux e sb
    sb.Append ")" |> ignore
  | Extract(e, typ, p) ->
    sb.Append "(" |> ignore
    expToStringAux e sb
    sb.Append "[" |> ignore
    sb.Append((int typ + p - 1).ToString() + ":" + p.ToString()) |> ignore
    sb.Append "]" |> ignore
    sb.Append ")" |> ignore
  | Undefined(_, reason) ->
    sb.Append("Undefined expression (") |> ignore
    sb.Append reason |> ignore
    sb.Append ")" |> ignore

let private labelToString (lbl: Label) (sb: StringBuilder) =
  sb.Append $"{lbl.Name} @ {lbl.Address:x}" |> ignore

let private variablesToString (kind: string) vars (sb: StringBuilder) =
  sb.Append(" ") |> ignore
  sb.Append(kind) |> ignore
  sb.Append("(") |> ignore
  vars |> List.iter (fun v ->
    sb.Append(Variable.ToString v) |> ignore
    sb.Append(";") |> ignore)
  sb.Append(")") |> ignore

let private stmtToStringAux stmt (sb: StringBuilder) =
  match stmt with
  | LMark lbl ->
    sb.Append("=== LMark (") |> ignore
    labelToString lbl sb
    sb.Append(")") |> ignore
  | Def(v, e) ->
    sb.Append(Variable.ToString v) |> ignore
    sb.Append(" := ") |> ignore
    expToStringAux e sb
  | Jmp(IntraJmp(lbl))->
    sb.Append("JmpLbl ") |> ignore
    labelToString lbl sb
  | Jmp(IntraCJmp(cond, lbl1, lbl2)) ->
    sb.Append("if ") |> ignore
    expToStringAux cond sb
    sb.Append(" then JmpLbl ") |> ignore
    labelToString lbl1 sb
    sb.Append(" else JmpLbl ") |> ignore
    labelToString lbl2 sb
  | Jmp(InterJmp(dst)) ->
    sb.Append("Jmp ") |> ignore
    expToStringAux dst sb
  | Jmp(InterCJmp(cond, dst1, dst2)) ->
    sb.Append("if ") |> ignore
    expToStringAux cond sb
    sb.Append(" then Jmp ") |> ignore
    expToStringAux dst1 sb
    sb.Append(" else Jmp ") |> ignore
    expToStringAux dst2 sb
  | Phi(def, indices) ->
    sb.Append(Variable.ToString def) |> ignore
    sb.Append(" := phi(") |> ignore
    indices |> Array.iter (fun i ->
      sb.Append(i.ToString()) |> ignore
      sb.Append(";") |> ignore)
    sb.Append(")") |> ignore
  | ExternalCall(args, inVars, outVars) ->
    sb.Append("call ") |> ignore
    expToStringAux args sb
    variablesToString "OutVars" outVars sb
    variablesToString "InVars" inVars sb
  | SideEffect eff ->
    sb.Append("SideEffect " + SideEffect.ToString eff) |> ignore

/// Pretty-prints an SSA expression to a string.
let expToString expr =
  let sb = StringBuilder()
  expToStringAux expr sb
  sb.ToString()

/// Pretty-prints an SSA statement to a string.
let stmtToString expr =
  let sb = StringBuilder()
  stmtToStringAux expr sb
  sb.ToString()

/// Pretty-prints an array of SSA statements to a string.
let stmtsToString stmts =
  let sb = StringBuilder()
  Array.iter (fun stmt -> stmtToStringAux stmt sb
                          sb.Append(Environment.NewLine) |> ignore) stmts
  sb.ToString()

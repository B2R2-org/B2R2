(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

/// Pretty printer for LowUIR.
module B2R2.BinIR.LowUIR.Pp

open System
open System.Text
open B2R2
open B2R2.BinIR

let rec private expToStringAux expr (sb: StringBuilder) =
  match expr with
  | Num n -> sb.Append (BitVector.toString n) |> ignore
  | Var (_typ, _, n, _) -> sb.Append (n) |> ignore
  | Nil -> sb.Append ("nil") |> ignore
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
    sb.Append (UnOpType.toString op) |> ignore
    sb.Append (" ") |> ignore
    expToStringAux e sb
    sb.Append (")") |> ignore
  | BinOp (op, _typ, e1, e2, _, _) ->
    sb.Append ("(") |> ignore
    expToStringAux e1 sb
    sb.Append (" ") |> ignore
    sb.Append (BinOpType.toString op) |> ignore
    sb.Append (" ") |> ignore
    expToStringAux e2 sb
    sb.Append (")") |> ignore
  | RelOp (op, e1, e2, _, _) ->
    sb.Append ("(") |> ignore
    expToStringAux e1 sb
    sb.Append (" ") |> ignore
    sb.Append (RelOpType.toString op) |> ignore
    sb.Append (" ") |> ignore
    expToStringAux e2 sb
    sb.Append (")") |> ignore
  | Load (_endian, typ, e, _, _) ->
    sb.Append ("[") |> ignore
    expToStringAux e sb
    sb.Append ("]:") |> ignore
    sb.Append (RegType.toString typ) |> ignore
  | Ite (cond, e1, e2, _, _) ->
    sb.Append ("(ite (") |> ignore
    expToStringAux cond sb
    sb.Append (") (") |> ignore
    expToStringAux e1 sb
    sb.Append (") (") |> ignore
    expToStringAux e2 sb
    sb.Append ("))") |> ignore
  | Cast (cast, typ, e, _, _) ->
    sb.Append (CastKind.toString cast) |> ignore
    sb.Append (":") |> ignore
    sb.Append (RegType.toString typ) |> ignore
    sb.Append ("(") |> ignore
    expToStringAux e sb
    sb.Append (")") |> ignore
  | Extract (e, typ, p, _, _) ->
    sb.Append ("(") |> ignore
    expToStringAux e sb
    sb.Append ("[") |> ignore
    sb.Append ((int typ + p - 1).ToString () + ":" + p.ToString ())|> ignore
    sb.Append ("]") |> ignore
    sb.Append (")") |> ignore
  | Undefined (_, reason) ->
    sb.Append ("Undefined expression (") |> ignore
    sb.Append (reason) |> ignore
    sb.Append (")") |> ignore

let private stmtToStringAux stmt (sb: StringBuilder) =
  match stmt with
  | ISMark (addr, _) ->
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
    expToStringAux exp1 sb
    sb.Append (" := ") |> ignore
    expToStringAux exp2 sb
  | Jmp exp ->
    sb.Append ("JmpLbl ") |> ignore
    expToStringAux exp sb
  | InterJmp (_pc, exp, _) ->
    sb.Append ("Jmp ") |> ignore
    expToStringAux exp sb
  | Store (_endian, exp1, exp2) ->
    sb.Append ("[") |> ignore
    expToStringAux exp1 sb
    sb.Append ("] := ") |> ignore
    expToStringAux exp2 sb
  | CJmp (cond, t, f) ->
    sb.Append ("if ") |> ignore
    expToStringAux cond sb
    sb.Append (" then JmpLbl ") |> ignore
    expToStringAux t sb
    sb.Append (" else JmpLbl ") |> ignore
    expToStringAux f sb
  | InterCJmp (cond, _pc, t, f) ->
    sb.Append ("if ") |> ignore
    expToStringAux cond sb
    sb.Append (" then Jmp ") |> ignore
    expToStringAux t sb
    sb.Append (" else Jmp ") |> ignore
    expToStringAux f sb
  | SideEffect eff ->
    sb.Append ("SideEffect " + SideEffect.toString eff) |> ignore

let expToString expr =
  let sb = new StringBuilder ()
  expToStringAux expr sb
  sb.ToString ()

let stmtToString expr =
  let sb = new StringBuilder ()
  stmtToStringAux expr sb
  sb.ToString ()

let stmtsToString stmts =
  let sb = StringBuilder()
  Array.iter (fun stmt -> stmtToStringAux stmt sb
                          sb.Append (Environment.NewLine) |> ignore) stmts
  sb.ToString ()


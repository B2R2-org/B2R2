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

/// Pretty printer for SSA.
module B2R2.BinIR.SSA.Pp

open System
open System.Text
open B2R2
open B2R2.BinIR

let rec private expToStringAux expr (sb: StringBuilder) =
  match expr with
  | Num n -> sb.Append (BitVector.toString n) |> ignore
  | Var (v) -> sb.Append (Variable.toString v) |> ignore
  | FuncName (n) -> sb.Append (n) |> ignore
  | UnOp (op, e) ->
    sb.Append ("(") |> ignore
    sb.Append (UnOpType.toString op) |> ignore
    sb.Append (" ") |> ignore
    expToStringAux e sb
    sb.Append (")") |> ignore
  | BinOp (op, _, e1, e2) ->
    sb.Append ("(") |> ignore
    expToStringAux e1 sb
    sb.Append (" ") |> ignore
    sb.Append (BinOpType.toString op) |> ignore
    sb.Append (" ") |> ignore
    expToStringAux e2 sb
    sb.Append (")") |> ignore
  | RelOp (op, e1, e2) ->
    sb.Append ("(") |> ignore
    expToStringAux e1 sb
    sb.Append (" ") |> ignore
    sb.Append (RelOpType.toString op) |> ignore
    sb.Append (" ") |> ignore
    expToStringAux e2 sb
    sb.Append (")") |> ignore
  | Load (_endian, typ, e) ->
    sb.Append ("[") |> ignore
    expToStringAux e sb
    sb.Append ("]:") |> ignore
    sb.Append (RegType.toString typ) |> ignore
  | Store (_, addr, e) ->
    sb.Append ("[") |> ignore
    expToStringAux addr sb
    sb.Append (" <- ") |> ignore
    expToStringAux e sb
    sb.Append ("]") |> ignore
  | Ite (cond, e1, e2) ->
    sb.Append ("(ite (") |> ignore
    expToStringAux cond sb
    sb.Append (") (") |> ignore
    expToStringAux e1 sb
    sb.Append (") (") |> ignore
    expToStringAux e2 sb
    sb.Append ("))") |> ignore
  | Cast (cast, typ, e) ->
    sb.Append (CastKind.toString cast) |> ignore
    sb.Append (":") |> ignore
    sb.Append (RegType.toString typ) |> ignore
    sb.Append ("(") |> ignore
    expToStringAux e sb
    sb.Append (")") |> ignore
  | Extract (e, typ, p) ->
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
  | Return (addr) ->
    sb.Append ("RetFromFunc(") |> ignore
    sb.Append (addr.ToString ("X")) |> ignore
    sb.Append (")") |> ignore

let private labelToString (addr: Addr, symb) (sb: StringBuilder) =
  sb.Append (Symbol.getName symb) |> ignore
  sb.Append (" @ ") |> ignore
  sb.Append (addr.ToString ("X")) |> ignore

let private stmtToStringAux stmt (sb: StringBuilder) =
  match stmt with
  | LMark lbl ->
    sb.Append ("=== LMark (") |> ignore
    labelToString lbl sb
    sb.Append (")") |> ignore
  | Def (v, e) ->
    sb.Append (Variable.toString v) |> ignore
    sb.Append (" := ") |> ignore
    expToStringAux e sb
  | Jmp (IntraJmp (lbl))->
    sb.Append ("JmpLbl ") |> ignore
    labelToString lbl sb
  | Jmp (IntraCJmp (cond, lbl1, lbl2)) ->
    sb.Append ("if ") |> ignore
    expToStringAux cond sb
    sb.Append (" then JmpLbl ") |> ignore
    labelToString lbl1 sb
    sb.Append (" else JmpLbl ") |> ignore
    labelToString lbl2 sb
  | Jmp (InterJmp (_, dst)) ->
    sb.Append ("Jmp ") |> ignore
    expToStringAux dst sb
  | Jmp (InterCJmp (cond, _, dst1, dst2)) ->
    sb.Append ("if ") |> ignore
    expToStringAux cond sb
    sb.Append (" then Jmp ") |> ignore
    expToStringAux dst1 sb
    sb.Append (" else Jmp ") |> ignore
    expToStringAux dst2 sb
  | Phi (def, indices) ->
    sb.Append (Variable.toString def) |> ignore
    sb.Append (" := phi(") |> ignore
    indices |> Array.iter (fun i ->
      sb.Append (i.ToString ()) |> ignore
      sb.Append (";") |> ignore)
    sb.Append (")") |> ignore
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

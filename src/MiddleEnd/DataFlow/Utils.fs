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

module B2R2.MiddleEnd.DataFlow.Utils

open B2R2.BinIR.LowUIR

let rec private extractUseFromExpr = function
  | Var (_, id, _, _) -> [ Regular id ]
  | TempVar (_, n) -> [ Temporary n ]
  | UnOp (_, e, _) -> extractUseFromExpr e
  | BinOp (_, _, e1, e2, _) -> extractUseFromExpr e1 @ extractUseFromExpr e2
  | RelOp (_, e1, e2, _) -> extractUseFromExpr e1 @ extractUseFromExpr e2
  | Load (_, _, e, _) -> extractUseFromExpr e
  | Ite (c, e1, e2, _) ->
    extractUseFromExpr c @ extractUseFromExpr e1 @ extractUseFromExpr e2
  | Cast (_, _, e, _) -> extractUseFromExpr e
  | Extract (e, _, _, _) -> extractUseFromExpr e
  | _ -> []

let private extractUseFromStmt = function
  | Put (_, e)
  | Store (_, _, e)
  | Jmp (e)
  | CJmp (e, _, _)
  | InterJmp (e, _) -> extractUseFromExpr e
  | InterCJmp (c, e1, e2) ->
    extractUseFromExpr c @ extractUseFromExpr e1 @ extractUseFromExpr e2
  | _ -> []

let extractUses stmt =
  extractUseFromStmt stmt
  |> Set.ofList

let filterRegularVars vars =
  vars |> Set.filter (function
    | Regular _ -> true
    | _ -> false)

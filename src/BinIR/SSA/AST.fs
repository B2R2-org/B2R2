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

/// <summary>
/// Provides a set of functions for constructing SSA expressions and statements.
/// <remarks>
/// Any SSA AST construction must be done through the functions in this module.
/// </remarks>
/// </summary>
[<RequireQualifiedAccess>]
module B2R2.BinIR.SSA.AST

open B2R2
open B2R2.BinIR

let rec private translateDest = function
  | LowUIR.Var(Type = ty; RegisterID = r; Name = n) ->
    { Kind = RegVar(ty, r, n); Identifier = -1 }
  | LowUIR.PCVar(Type = ty) ->
    { Kind = PCVar(ty); Identifier = -1 }
  | LowUIR.TempVar(Type = ty; Index = n) ->
    { Kind = TempVar(ty, n); Identifier = -1 }
  | _ ->
    raise InvalidExprException

let private translateLabel addr = function
  | LowUIR.JmpDest(Target = lbl) -> lbl
  | LowUIR.Undefined(Reason = s) -> Label(s, -1, addr)
  | _ -> raise InvalidExprException

let rec translateExpr (e: LowUIR.Expr) =
  match e with
  | LowUIR.Num(Value = bv) ->
    Num bv
  | (LowUIR.Var _ as e)
  | (LowUIR.PCVar _ as e)
  | (LowUIR.TempVar _ as e) ->
    Var <| translateDest e
  | LowUIR.ExprList(Elements = exprs) ->
    ExprList(List.map translateExpr exprs)
  | LowUIR.UnOp(Op = op; Operand = e) ->
    let ty = LowUIR.Expr.typeOf e
    UnOp(op, ty, translateExpr e)
  | LowUIR.FuncName(Name = s) ->
    FuncName s
  | LowUIR.BinOp(Op = op; Type = ty; Left = e1; Right = e2) ->
    BinOp(op, ty, translateExpr e1, translateExpr e2)
  | LowUIR.RelOp(Op = op; Left = e1; Right = e2) ->
    RelOp(op, 1<rt>, translateExpr e1, translateExpr e2)
  | LowUIR.Load(Type = ty; Addr = e) ->
    Load({ Kind = MemVar; Identifier = -1 }, ty, translateExpr e)
  | LowUIR.Ite(Cond = e1; TrueExpr = e2; FalseExpr = e3) ->
    let ty = LowUIR.Expr.typeOf e2
    Ite(translateExpr e1, ty, translateExpr e2, translateExpr e3)
  | LowUIR.Cast(Kind = op; Type = ty; Operand = e) ->
    Cast(op, ty, translateExpr e)
  | LowUIR.RoundCtrl(Mode = mode; Body = body) ->
    let ty = LowUIR.Expr.typeOf body
    RoundCtrl(translateExpr mode, ty, translateExpr body)
  | LowUIR.Extract(Operand = e; Type = ty; StartPos = pos) ->
    Extract(translateExpr e, ty, pos)
  | LowUIR.Undefined(Type = ty; Reason = s) ->
    Undefined(ty, s)
  | _ ->
    raise InvalidExprException (* Name *)

let rec private translateStmtAux defaultRegType addr (s: LowUIR.Stmt) =
  match s with
  | LowUIR.ISMark _ ->
    let pc = { Kind = PCVar(defaultRegType); Identifier = -1 }
    let n = Num <| BitVector(u64 = addr, bitLen = defaultRegType)
    Def(pc, n) |> Some
  | LowUIR.IEMark _ ->
    None
  | LowUIR.LMark(Label = lbl) ->
    LMark lbl |> Some
  | LowUIR.Put(Dst = var; Src = expr) ->
    let dest = translateDest var
    let expr = translateExpr expr
    Def(dest, expr) |> Some
  | LowUIR.Store(Addr = addr; Value = expr) ->
    let ty = LowUIR.Expr.typeOf expr
    let addr = translateExpr addr
    let expr = translateExpr expr
    let srcMem = { Kind = MemVar; Identifier = -1 }
    let dstMem = { Kind = MemVar; Identifier = -1 }
    let store = Store(srcMem, ty, addr, expr)
    Def(dstMem, store) |> Some
  | LowUIR.Jmp(Target = expr) ->
    let label = translateLabel addr expr
    let jmp = IntraJmp label
    Jmp jmp |> Some
  | LowUIR.CJmp(Cond = expr; TrueTarget = label1; FalseTarget = label2) ->
    let expr = translateExpr expr
    let label1 = translateLabel addr label1
    let label2 = translateLabel addr label2
    let jmp = IntraCJmp(expr, label1, label2)
    Jmp jmp |> Some
  | LowUIR.InterJmp(Target = expr) ->
    let expr = translateExpr expr
    let jmp = InterJmp(expr)
    Jmp jmp |> Some
  | LowUIR.InterCJmp(Cond = expr1; TrueTarget = expr2; FalseTarget = expr3) ->
    let expr1 = translateExpr expr1
    let expr2 = translateExpr expr2
    let expr3 = translateExpr expr3
    let jmp = InterCJmp(expr1, expr2, expr3)
    Jmp jmp |> Some
  | LowUIR.ExternalCall(Call = args) ->
    let e = args |> translateExpr
    ExternalCall(e, [], []) |> Some
  | LowUIR.SideEffect(Effect = s) ->
    SideEffect s |> Some

let translateStmts defaultRegType addr (postProc: IStmtPostProcessor) stmts =
  stmts
  |> Array.choose (fun stmt ->
    translateStmtAux defaultRegType addr stmt
    |> Option.map postProc.PostProcess)

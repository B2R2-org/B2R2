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

/// Provides a function that performs a constant folding optimization for the
/// lifted IR statements. This function assumes that the statements are
/// localized, i.e., they represent a basic block.
[<RequireQualifiedAccess>]
module B2R2.FrontEnd.BinLifter.ConstantFolding

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

type private VarMaps =
  { VarMap: Dictionary<RegisterID, Expr>
    TempVarMap: Dictionary<int, Expr> }

(* Folding a concrete operand is left to the AST constructors, which already
   do it and already screen out the operations whose result a rounding
   direction would decide. *)
let rec private replace maps expr =
  match expr with
  | Var(RegisterID = name) ->
    match maps.VarMap.TryGetValue name with
    | true, e -> struct (true, e)
    | _ -> struct (false, expr)
  | TempVar(Index = name) ->
    match maps.TempVarMap.TryGetValue name with
    | (true, e) -> struct (true, e)
    | _ -> struct (false, expr)
  | UnOp(Op = t; Operand = e) ->
    let struct (changed, e) = replace maps e
    if changed then struct (true, AST.unop t e) else struct (false, expr)
  | BinOp(Op = BinOpType.ADD; Left = e; Right = Num(Value = bv))
  | BinOp(Op = BinOpType.ADD; Left = Num(Value = bv); Right = e)
    when bv.IsZero ->
    let struct (changed, e') = replace maps e
    if changed then struct (true, e') else struct (true, e)
  | BinOp(Op = BinOpType.MUL; Left = e; Right = Num(Value = bv))
  | BinOp(Op = BinOpType.MUL; Left = Num(Value = bv); Right = e)
    when bv.IsOne ->
    let struct (changed, e') = replace maps e
    if changed then struct (true, e') else struct (true, e)
  | BinOp(Op = t; Left = e1; Right = e2) ->
    let struct (changed1, e1) = replace maps e1
    let struct (changed2, e2) = replace maps e2
    if changed1 || changed2 then struct (true, AST.binop t e1 e2)
    else struct (false, expr)
  | RelOp(Op = t; Left = e1; Right = e2) ->
    let struct (changed1, e1) = replace maps e1
    let struct (changed2, e2) = replace maps e2
    if changed1 || changed2 then struct (true, AST.relop t e1 e2)
    else struct (false, expr)
  | Load(Endian = endian; Type = rt; Addr = e) ->
    let struct (changed, e') = replace maps e
    if changed then struct (true, AST.load endian rt e')
    else struct (false, expr)
  | Ite(Cond = cond; TrueExpr = e1; FalseExpr = e2) ->
    let struct (changed0, cond) = replace maps cond
    let struct (changed1, e1) = replace maps e1
    let struct (changed2, e2) = replace maps e2
    if changed0 || changed1 || changed2 then
      struct (true, AST.ite cond e1 e2)
    else
      struct (false, expr)
  | RoundCtrl(Mode = mode; Body = body) ->
    let struct (modeChanged, mode) = replace maps mode
    let struct (bodyChanged, body) = replace maps body
    if modeChanged || bodyChanged then
      struct (true, AST.roundCtrl mode body)
    else
      struct (false, expr)
  | Cast(Kind = kind; Type = rt; Operand = e) ->
    let struct (changed, e) = replace maps e
    if changed then struct (true, AST.cast kind rt e)
    else struct (false, expr)
  | Extract(Operand = e; Type = rt; StartPos = pos) ->
    let struct (changed, e) = replace maps e
    if changed then struct (true, AST.extract e rt pos)
    else struct (false, expr)
  | _ ->
    struct (false, expr)

let private updateMapsAtDef maps dst src =
  match dst, src with
  | Var(RegisterID = r), Num _ -> maps.VarMap[r] <- src
  | Var(RegisterID = r), _ -> maps.VarMap.Remove(r) |> ignore
  | TempVar(Index = n), Num _ -> maps.TempVarMap[n] <- src
  | TempVar(Index = n), _ -> maps.TempVarMap.Remove(n) |> ignore
  | _ -> ()

let rec private optimizeLoop (stmts: Stmt[]) idx maps =
  if Array.length stmts > idx then
    match stmts[idx] with
    | Store(Endian = endian; Addr = e1; Value = e2) ->
      let struct (c1, e1) = replace maps e1
      let struct (c2, e2) = replace maps e2
      if c1 || c2 then stmts[idx] <- AST.store endian e1 e2 else ()
      optimizeLoop stmts (idx + 1) maps
    | InterJmp(Target = e; Kind = t) ->
      let struct (changed, e) = replace maps e
      if changed then stmts[idx] <- AST.interjmp e t else ()
      optimizeLoop stmts (idx + 1) maps
    | InterCJmp(Cond = cond; TrueTarget = e1; FalseTarget = e2) ->
      let struct (c0, cond) = replace maps cond
      let struct (c1, e1) = replace maps e1
      let struct (c2, e2) = replace maps e2
      if c0 || c1 || c2 then
        stmts[idx] <-
          match cond with
          | Num(Value = n) when n.IsOne ->
            AST.interjmp e1 InterJmpKind.Base
          | Num _ -> AST.interjmp e2 InterJmpKind.Base
          | _ -> AST.intercjmp cond e1 e2
      else
        ()
      optimizeLoop stmts (idx + 1) maps
    | Jmp(Target = e) ->
      let struct (changed, e) = replace maps e
      if changed then stmts[idx] <- AST.jmp e else ()
      optimizeLoop stmts (idx + 1) maps
    | CJmp(Cond = cond; TrueTarget = e1; FalseTarget = e2) ->
      let struct (c0, cond) = replace maps cond
      let struct (c1, e1) = replace maps e1
      let struct (c2, e2) = replace maps e2
      if c0 || c1 || c2 then
        stmts[idx] <-
          match cond with
          | Num(Value = n) when n.IsOne -> AST.jmp e1
          | Num(_) -> AST.jmp e2
          | _ -> AST.cjmp cond e1 e2
      else
        ()
      optimizeLoop stmts (idx + 1) maps
    | LMark _ ->
      optimizeLoop stmts (idx + 1) maps
    | Put(Dst = lhs; Src = rhs) ->
      let rhs = match replace maps rhs with
                | true, rhs -> stmts[idx] <- AST.put lhs rhs; rhs
                | _ -> rhs
      updateMapsAtDef maps lhs rhs
      optimizeLoop stmts (idx + 1) maps
    | ISMark _ | IEMark _ | ExternalCall _ | SideEffect _ ->
      optimizeLoop stmts (idx + 1) maps
  else
    stmts

/// Assuming that the stmts are localized, i.e., those stmts represent a basic
/// block, perform local constant folding.
let optimize (stmts: Stmt[]) =
  let stmts = Array.copy stmts
  optimizeLoop stmts 0 { VarMap = Dictionary(); TempVarMap = Dictionary() }

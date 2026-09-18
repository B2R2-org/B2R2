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

/// Provides a function that performs a copy propagation optimization for the
/// lifted IR statements. This function assumes that the statements are
/// localized, i.e., they represent a basic block.
[<RequireQualifiedAccess>]
module B2R2.FrontEnd.BinLifter.CopyPropagation

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

/// <summary>
/// What a block has been read to know so far: <c>Map</c> holds the expression
/// each variable may be replaced with, and <c>Deps</c> answers the question
/// the replacement raises, namely which of those expressions a given variable
/// is read by, so that redefining it drops them all.
/// </summary>
type private Maps =
  { Map: Dictionary<Key, Expr>
    Deps: Dictionary<Key, List<Key>> }

/// Names a variable an expression may be stored under.
and [<Struct>] private Key =
  | Reg of reg: RegisterID
  | Tmp of tmp: int

let private keyOf expr =
  match expr with
  | Var(RegisterID = r) -> ValueSome(Reg r)
  | TempVar(Index = n) -> ValueSome(Tmp n)
  | _ -> ValueNone

/// <summary>
/// Returns the one variable a propagatable expression reads, or
/// <c>ValueNone</c> when the expression is not one this pass propagates. Every
/// form admitted here is at most three nodes deep, reads exactly one variable
/// and loads nothing, which is what bounds the growth a replacement can cause
/// and what leaves memory writes unable to invalidate anything.
/// </summary>
let private tryFindSource expr =
  match expr with
  | Var _ | TempVar _ -> keyOf expr
  | UnOp(Operand = e) | Cast(Operand = e) | Extract(Operand = e) -> keyOf e
  | BinOp(Left = Num _; Right = e) | BinOp(Left = e; Right = Num _)
  | RelOp(Left = Num _; Right = e) | RelOp(Left = e; Right = Num _) -> keyOf e
  | _ -> ValueNone

let private lookup maps key expr =
  match (maps: Maps).Map.TryGetValue key with
  | true, e -> struct (true, e)
  | _ -> struct (false, expr)

let rec private replace maps expr =
  match expr with
  | Var(RegisterID = r) ->
    lookup maps (Reg r) expr
  | TempVar(Index = n) ->
    lookup maps (Tmp n) expr
  | UnOp(Op = t; Operand = e) ->
    let struct (changed, e) = replace maps e
    if changed then struct (true, AST.unop t e) else struct (false, expr)
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
    let struct (changed, e) = replace maps e
    if changed then struct (true, AST.load endian rt e)
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

/// Drops what redefining the given variable has made stale: its own entry, and
/// every entry that reads it.
let private kill maps key =
  (maps: Maps).Map.Remove key |> ignore
  match maps.Deps.TryGetValue key with
  | true, dependents ->
    for dependent in dependents do maps.Map.Remove dependent |> ignore done
    maps.Deps.Remove key |> ignore
  | _ ->
    ()

/// Records that the destination may be replaced with the source expression.
/// A source reading the destination itself is refused, as the entry would
/// then speak of the value the definition has just overwritten.
let private define maps dst src =
  kill maps dst
  match tryFindSource src with
  | ValueSome source when source <> dst ->
    (maps: Maps).Map[dst] <- src
    match maps.Deps.TryGetValue source with
    | true, dependents -> dependents.Add dst
    | _ -> maps.Deps[source] <- List [ dst ]
  | _ ->
    ()

let private updateMapsAtDef maps dst src =
  match keyOf dst with
  | ValueSome key -> define maps key src
  | ValueNone -> ()

let private clear maps =
  (maps: Maps).Map.Clear()
  maps.Deps.Clear()

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
      if c0 || c1 || c2 then stmts[idx] <- AST.intercjmp cond e1 e2 else ()
      optimizeLoop stmts (idx + 1) maps
    | Jmp(Target = e) ->
      let struct (changed, e) = replace maps e
      if changed then stmts[idx] <- AST.jmp e else ()
      optimizeLoop stmts (idx + 1) maps
    | CJmp(Cond = cond; TrueTarget = e1; FalseTarget = e2) ->
      let struct (c0, cond) = replace maps cond
      let struct (c1, e1) = replace maps e1
      let struct (c2, e2) = replace maps e2
      if c0 || c1 || c2 then stmts[idx] <- AST.cjmp cond e1 e2 else ()
      optimizeLoop stmts (idx + 1) maps
    | Put(Dst = lhs; Src = rhs) ->
      let rhs = match replace maps rhs with
                | true, rhs -> stmts[idx] <- AST.put lhs rhs; rhs
                | _ -> rhs
      updateMapsAtDef maps lhs rhs
      optimizeLoop stmts (idx + 1) maps
    | ExternalCall _ ->
      (* Nothing says what the call leaves the registers holding. *)
      clear maps
      optimizeLoop stmts (idx + 1) maps
    | SideEffect(Effect = eff) ->
      if SideEffect.mayClobberRegisters eff then clear maps else ()
      optimizeLoop stmts (idx + 1) maps
    | ISMark _ | IEMark _ | LMark _ ->
      optimizeLoop stmts (idx + 1) maps
  else
    stmts

/// Assuming that the stmts are localized, i.e., those stmts represent a basic
/// block, perform local copy propagation.
let optimize (stmts: Stmt[]) =
  let stmts = Array.copy stmts
  optimizeLoop stmts 0 { Map = Dictionary(); Deps = Dictionary() }

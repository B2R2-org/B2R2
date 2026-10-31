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


/// Provides a way to evaluate an SSA expression while one variable, the root,
/// holds a given value, following the definitions of the other variables it
/// reads. A temporary or a stack slot of the IR data flow carries no width, so
/// such a variable takes the width of the expression that reads it.
module B2R2.MiddleEnd.DataFlow.SSAExprEvaluator

open B2R2
open B2R2.BinIR
open B2R2.BinIR.SSA

/// Finds the width of the given expression, which is zero for a variable that
/// carries none.
let private widthOf e =
  match e with
  | Var { Kind = MemVar } -> 0<rt>
  | Num _ | Var _ | Load _ | UnOp _ | BinOp _ | RelOp _ | Ite _ | Cast _
  | Extract _ -> Expr.typeOf e
  | _ -> 0<rt>

/// Finds the width at which a reader of rt bits reads the given expression,
/// which is its own unless it carries none.
let private widthAt rt e =
  let w = widthOf e
  if w = 0<rt> then rt else w

/// Keeps the given value if it is not a constant, or if its width satisfies the
/// given condition. A variable that carries no width takes the width of its
/// definition, which can differ from the width at which it is read, as when a
/// stack slot is read back in part; such a read is not a constant.
let private keepIf isFitting c =
  match c with
  | ConstantDomain.Const(bv: BitVector) when not (isFitting bv.Length) ->
    ConstantDomain.NotAConst
  | _ ->
    c

/// Evaluates the given expression, whose width is rt unless rt is zero.
let rec private evalAt findDef root (value: int64 option) depth rt e =
  let eval = evalAt findDef root value depth
  match e with
  | Num bv ->
    ConstantDomain.Const bv
  | Var v when v = root ->
    match widthAt rt e, value with
    | w, Some n when w > 0<rt> -> ConstantDomain.Const(BitVector(n, w))
    | _ -> ConstantDomain.NotAConst
  | Var v when depth > 0 ->
    match findDef v with
    | Some(Def(_, d)) ->
      let w = widthAt rt e
      evalAt findDef root value (depth - 1) (widthAt w d) d
      |> keepIf (fun dw -> w = 0<rt> || dw = w)
    | _ ->
      ConstantDomain.NotAConst
  | BinOp(BinOpType.CONCAT, _, e1, e2) ->
    ConstantDomain.concat (eval (widthOf e1) e1) (eval (widthOf e2) e2)
  | BinOp(op, t, e1, e2) ->
    ConstantDomain.evalBinOp op (eval t e1) (eval t e2)
  | RelOp(op, _, e1, e2) ->
    match max (widthOf e1) (widthOf e2) with
    | t when t > 0<rt> -> ConstantDomain.evalRelOp op (eval t e1) (eval t e2)
    | _ -> ConstantDomain.NotAConst
  | UnOp(op, t, e) ->
    ConstantDomain.evalUnOp op (eval t e)
  | Cast(kind, t, e) ->
    eval (widthOf e) e
    |> keepIf (fun w -> widthOf e > 0<rt> || w < t)
    |> ConstantDomain.evalCast kind t
  | Extract(e, t, pos) ->
    let c = eval (widthOf e) e |> keepIf (fun w -> int w >= int t + pos)
    ConstantDomain.extract c t pos
  | Ite(cond, t, e1, e2) ->
    ConstantDomain.ite (eval 1<rt> cond) (eval t e1) (eval t e2)
  | _ ->
    ConstantDomain.NotAConst

/// Evaluates the given expression with the root holding the given value, if
/// any, following the definitions of the other variables it reads, as findDef
/// gives them, up to the given depth. The result is not a constant if it
/// depends on anything else, or on the root while the root holds no value.
let evaluate findDef root value depth e =
  evalAt findDef root value depth (widthOf e) e

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

module B2R2.MiddleEnd.ControlFlowAnalysis.IRHelper

open B2R2
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.MiddleEnd.DataFlow

let private varToBV cpState var id =
  let v = { var with Identifier = id }
  match CPState.findReg cpState v with
  | Const bv -> Some bv
  | _ -> None

let private expandPhi cpState var ids e =
  let bvs = ids |> Array.toList |> List.map (fun id -> varToBV cpState var id)
  match bvs[0] with
  | Some hd ->
    if bvs.Tail |> List.forall (function Some bv -> bv = hd | None -> false)
    then Num hd
    else e
  | None -> e

/// Recursively expand vars until we meet a Load expr.
let rec symbolicExpand cpState = function
  | Num _ as e -> e
  | Var v as e ->
    match Map.tryFind v cpState.SSAEdges.Defs with
    | Some (Def (_, e)) -> symbolicExpand cpState e
    | Some (Phi (_, ids)) -> expandPhi cpState v ids e
    | _ -> e
  | Load _ as e -> e
  | UnOp (_, _, Load _) as e -> e
  | UnOp (op, rt, e) ->
    let e = symbolicExpand cpState e
    UnOp (op, rt, e)
  | BinOp (_, _, Load _, _)
  | BinOp (_, _, _, Load _) as e -> e
  | BinOp (op, rt, e1, e2) ->
    let e1 = symbolicExpand cpState e1
    let e2 = symbolicExpand cpState e2
    BinOp (op, rt, e1, e2)
  | RelOp (_, _, Load _, _)
  | RelOp (_, _, _, Load _) as e -> e
  | RelOp (op, rt, e1, e2) ->
    let e1 = symbolicExpand cpState e1
    let e2 = symbolicExpand cpState e2
    RelOp (op, rt, e1, e2)
  | Ite (Load _, _, _, _)
  | Ite (_, _, Load _, _)
  | Ite (_, _, _, Load _) as e -> e
  | Ite (e1, rt, e2, e3) ->
    let e1 = symbolicExpand cpState e1
    let e2 = symbolicExpand cpState e2
    let e3 = symbolicExpand cpState e3
    Ite (e1, rt, e2, e3)
  | Cast (_, _, Load _) as e -> e
  | Cast (op, rt, e) ->
    let e = symbolicExpand cpState e
    Cast (op, rt, e)
  | Extract (Load _, _, _) as e -> e
  | Extract (e, rt, pos) ->
    let e = symbolicExpand cpState e
    Extract (e, rt, pos)
  | e -> e

let rec simplify = function
  | Load (v, rt, e) -> Load (v, rt, simplify e)
  | Store (v, rt, e1, e2) -> Store (v, rt, simplify e1, simplify e2)
  | BinOp (BinOpType.ADD, rt, BinOp (BinOpType.ADD, _, Num v1, e), Num v2)
  | BinOp (BinOpType.ADD, rt, BinOp (BinOpType.ADD, _, e, Num v1), Num v2)
  | BinOp (BinOpType.ADD, rt, Num v1, BinOp (BinOpType.ADD, _, e, Num v2))
  | BinOp (BinOpType.ADD, rt, Num v1, BinOp (BinOpType.ADD, _, Num v2, e)) ->
    BinOp (BinOpType.ADD, rt, e, Num (BitVector.Add (v1, v2)))
  | BinOp (BinOpType.ADD, _, Num v1, Num v2) -> Num (BitVector.Add (v1, v2))
  | BinOp (BinOpType.SUB, _, Num v1, Num v2) -> Num (BitVector.Sub (v1, v2))
  | BinOp (BinOpType.MUL, _, Num v1, Num v2) -> Num (BitVector.Mul (v1, v2))
  | BinOp (BinOpType.DIV, _, Num v1, Num v2) -> Num (BitVector.Div (v1, v2))
  | BinOp (BinOpType.AND, _, Num v1, Num v2) -> Num (BitVector.BAnd (v1, v2))
  | BinOp (BinOpType.OR, _, Num v1, Num v2) -> Num (BitVector.BOr (v1, v2))
  | BinOp (BinOpType.SHR, _, Num v1, Num v2) -> Num (BitVector.Shr (v1, v2))
  | BinOp (BinOpType.SHL, _, Num v1, Num v2) -> Num (BitVector.Shl (v1, v2))
  | BinOp (op, rt, e1, e2) -> BinOp (op, rt, simplify e1, simplify e2)
  | UnOp (op, rt, e) -> UnOp (op, rt, simplify e)
  | RelOp (op, rt, e1, e2) -> RelOp (op, rt, simplify e1, simplify e2)
  | Ite (c, rt, e1, e2) -> Ite (simplify c, rt, simplify e1, simplify e2)
  | Cast (k, rt, e) -> Cast (k, rt, simplify e)
  | Extract (Cast (CastKind.ZeroExt, _, e), rt, 0) when AST.typeOf e = rt -> e
  | Extract (Cast (CastKind.SignExt, _, e), rt, 0) when AST.typeOf e = rt -> e
  | Extract (e, rt, pos) -> Extract (simplify e, rt, pos)
  | expr -> expr

let rec foldWithConstant cpState = function
  | Var v as e ->
    match CPState.findReg cpState v with
    | Const bv -> Num bv
    | _ ->
      match Map.tryFind v cpState.SSAEdges.Defs with
      | Some (Def (_, e)) -> foldWithConstant cpState e
      | _ -> e
  | Load (m, rt, addr) as e ->
    match foldWithConstant cpState addr with
    | Num addr ->
      let addr = BitVector.ToUInt64 addr
      match CPState.tryFindMem cpState m rt addr with
      | Some (Const bv) -> Num bv
      | _ -> e
    | _ -> e
  | UnOp (op, rt, e) -> UnOp (op, rt, foldWithConstant cpState e)
  | BinOp (op, rt, e1, e2) ->
    let e1 = foldWithConstant cpState e1
    let e2 = foldWithConstant cpState e2
    BinOp (op, rt, e1, e2) |> simplify
  | RelOp (op, rt, e1, e2) ->
    let e1 = foldWithConstant cpState e1
    let e2 = foldWithConstant cpState e2
    RelOp (op, rt, e1, e2)
  | Ite (e1, rt, e2, e3) ->
    let e1 = foldWithConstant cpState e1
    let e2 = foldWithConstant cpState e2
    let e3 = foldWithConstant cpState e3
    Ite (e1, rt, e2, e3)
  | Cast (op, rt, e) -> Cast (op, rt, foldWithConstant cpState e)
  | Extract (e, rt, pos) -> Extract (foldWithConstant cpState e, rt, pos)
  | e -> e

let resolveExpr cpState needConstFolding expr =
  expr
  |> symbolicExpand cpState
  |> fun expr ->
    if needConstFolding then foldWithConstant cpState expr else expr
  |> simplify

let tryResolveExprToBV cpState expr =
  match resolveExpr cpState true expr with
  | Num addr -> Some addr
  | _ -> None

let tryConvertBVToUInt32 bv =
  let bv = BitVector.Cast (bv, 256<rt>)
  let maxVal = BitVector.Cast (BitVector.MaxUInt32, 256<rt>)
  let isConvertible = BitVector.Le (bv, maxVal) |> BitVector.IsTrue
  if isConvertible then bv |> BitVector.ToUInt32 |> Some
  else None

let tryConvertBVToUInt64 bv =
  let bv = BitVector.Cast (bv, 256<rt>)
  let maxVal = BitVector.Cast (BitVector.MaxUInt64, 256<rt>)
  let isConvertible = BitVector.Le (bv, maxVal) |> BitVector.IsTrue
  if isConvertible then bv |> BitVector.ToUInt64 |> Some
  else None

let tryResolveExprToUInt32 cpState expr =
  match tryResolveExprToBV cpState expr with
  | Some addr -> addr |> tryConvertBVToUInt32
  | _ -> None

let tryResolveExprToUInt64 cpState expr =
  match tryResolveExprToBV cpState expr with
  | Some addr -> addr |> tryConvertBVToUInt64
  | _ -> None

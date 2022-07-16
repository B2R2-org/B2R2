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

module B2R2.RearEnd.ROP.Simplify

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR

let inline negNum x = BitVector.Neg x |> AST.num

let inline zeroNum ty = BitVector.Zero ty |> AST.num

let inline maxNum ty =
  match ty with
  | 8<rt>  -> BitVector.MaxUInt8  |> AST.num
  | 16<rt> -> BitVector.MaxUInt16 |> AST.num
  | 32<rt> -> BitVector.MaxUInt32 |> AST.num
  | 64<rt> -> BitVector.MaxUInt64 |> AST.num
  | _ -> failwith "maxNum fail"

let inline isZero e =
  match e.E with
  | Num n -> (BitVector.GetValue n).IsZero
  | _ -> false

let inline isOne e =
  match e.E with
  | Num n -> (BitVector.GetValue n).IsOne
  | _ -> false

let isFlippable x = (BitVector.IsNegative x) && not (BitVector.IsSignedMin x)

let inline isMax ty e =
  match e.E with
  | Num n -> (BitVector.Add (n, BitVector.One ty) |> BitVector.GetValue).IsZero
  | _ -> false

let inline binADD e1 e2 = AST.binop BinOpType.ADD e1 e2

let inline binSUB e1 e2 = AST.binop BinOpType.SUB e1 e2

let inline subNum n1 n2 = BitVector.Sub (n1, n2) |> AST.num

let inline addNum n1 n2 = BitVector.Add (n1, n2) |> AST.num

let rec simplify expr =
  match expr.E with
  | UnOp (op, e1, _) -> AST.unop op <| simplify e1
  | BinOp (op, ty, e1, e2, _) -> simplifyBinOp op ty e1 e2
  | RelOp (op, e1, e2, _) -> AST.relop op (simplify e1) (simplify e2)
  | Load (endian, ty, e1, _) -> AST.load endian ty <| simplify e1
  | Ite (e1, e2, e3, _) -> AST.ite (simplify e1) (simplify e2) (simplify e3)
  | Cast (kind, ty, e1, _) -> simplifyCast kind ty e1
  | _ -> expr (* Var, TempVar, Num, Name, PCVar *)

and simplifyBinOp op ty e1 e2  =
  match op, e1.E, e2.E with
  | BinOpType.XOR, _, _ when e1 = e2 -> zeroNum ty
  | BinOpType.XOR, _, _ when isZero e1 -> simplify e2
  | BinOpType.XOR, _, _ when isZero e2 -> simplify e1
  | BinOpType.AND, _, _ when e1 = e2 -> simplify e1
  | BinOpType.AND, _, _ when isMax ty e1 -> simplify e2
  | BinOpType.AND, _, _ when isMax ty e2 -> simplify e1
  | BinOpType.AND, _, _ when isZero e1 || isZero e2 -> zeroNum ty
  | BinOpType.OR, _, _ when e1 = e2 -> simplify e1
  | BinOpType.OR, _, _ when isZero e1 -> simplify e2
  | BinOpType.OR, _, _ when isZero e2 -> simplify e1
  | BinOpType.OR, _, _ when isMax ty e1 || isMax ty e2 -> maxNum ty
  | op, _, _ when isZero e1 && (op = BinOpType.ADD || op = BinOpType.SUB) ->
    simplify e2
  | op, _, _ when isZero e2 && (op = BinOpType.ADD || op = BinOpType.SUB) ->
    simplify e1
  | BinOpType.ADD, Num (n1), _ when isFlippable n1 ->
    simplify (binSUB e2 (negNum n1))
  | BinOpType.ADD, _, Num (n1) when isFlippable n1 ->
    simplify (binSUB e2 (negNum n1))
  | BinOpType.SUB, _, Num (n2) when isFlippable n2 ->
    simplify (binADD e1 (negNum n2))
  | BinOpType.SUB, Num (n1), _ when isFlippable n1 ->
    simplify (binSUB e2 (negNum n1))
  (* ADD + ADD *)
  | BinOpType.ADD, BinOp (BinOpType.ADD, _, { E = Num (n1) }, e2, _),
                   BinOp (BinOpType.ADD, _, { E = Num (n3) }, e4, _)
  | BinOpType.ADD, BinOp (BinOpType.ADD, _, { E = Num (n1) }, e2, _),
                   BinOp (BinOpType.ADD, _, e4, { E = Num (n3) }, _)
  | BinOpType.ADD, BinOp (BinOpType.ADD, _, e2, { E = Num (n1) }, _),
                   BinOp (BinOpType.ADD, _, { E = Num (n3) }, e4, _)
  | BinOpType.ADD, BinOp (BinOpType.ADD, _, e2, { E = Num (n1) }, _),
                   BinOp (BinOpType.ADD, _, e4, { E = Num (n3) }, _) ->
    simplify (binADD (binADD e2 e4) (addNum n1 n3))
  (* SUB + SUB *)
  | BinOpType.ADD, BinOp (BinOpType.SUB, _, { E = Num (n1) }, e2, _),
                   BinOp (BinOpType.SUB, _, { E = Num (n3) }, e4, _) ->
    simplify (binSUB (addNum n1 n3) (binADD e2 e4))
  | BinOpType.ADD, BinOp (BinOpType.SUB, _, { E = Num (n1) }, e2, _),
                   BinOp (BinOpType.SUB, _, e3, { E = Num (n4) }, _) ->
    simplify (binADD (subNum n1 n4) (binSUB e3 e2))
  | BinOpType.ADD, BinOp (BinOpType.SUB, _, e2, { E = Num (n1) }, _),
                   BinOp (BinOpType.SUB, _, { E = Num (n3) }, e4, _) ->
    simplify (binADD (subNum n3 n1) (binSUB e2 e4))
  | BinOpType.ADD, BinOp (BinOpType.SUB, _, e2, { E = Num (n1) }, _),
                   BinOp (BinOpType.SUB, _, e4, { E = Num (n3) }, _) ->
    simplify (binSUB (binADD e2 e4) (addNum n1 n3))
  (* Num + Num *)
  | BinOpType.ADD, Num (n1), Num (n2) -> addNum n1 n2
  (* ADD + Num, Num + ADD *)
  | BinOpType.ADD, Num (n1), BinOp (BinOpType.ADD, _, { E = Num (n2) }, e3, _)
  | BinOpType.ADD, Num (n1), BinOp (BinOpType.ADD, _, e3, { E = Num (n2) }, _)
  | BinOpType.ADD, BinOp (BinOpType.ADD, _, { E = Num (n2) }, e3, _), Num (n1)
  | BinOpType.ADD, BinOp (BinOpType.ADD, _, e3, { E = Num (n2) }, _), Num (n1)
    ->
    simplify (binADD e3 (addNum n1 n2))
  (* Num + SUB, SUB + Num *)
  | BinOpType.ADD, Num (n1), BinOp (BinOpType.SUB, _, { E = Num (n2) }, e3, _)
  | BinOpType.ADD, BinOp (BinOpType.SUB, _, { E = Num (n2) }, e3, _), Num (n1)
    ->
    simplify (binSUB (addNum n1 n2) e3)
  | BinOpType.ADD, Num (n1), BinOp (BinOpType.SUB, _, e2, { E = Num (n3) }, _)
  | BinOpType.ADD, BinOp (BinOpType.SUB, _, e2, { E = Num (n3) }, _), Num (n1)
    ->
    simplify (binADD e2 (subNum n1 n3))
  (* SUB + ADD, ADD + SUB *)
  | BinOpType.ADD, BinOp (BinOpType.SUB, _, { E = Num (n1) }, e2, _),
                   BinOp (BinOpType.ADD, _, { E = Num (n3) }, e4, _)
  | BinOpType.ADD, BinOp (BinOpType.ADD, _, { E = Num (n3) }, e4, _),
                   BinOp (BinOpType.SUB, _, { E = Num (n1) }, e2, _)
  | BinOpType.ADD, BinOp (BinOpType.SUB, _, { E = Num (n1) }, e2, _),
                   BinOp (BinOpType.ADD, _, e4, { E = Num (n3) }, _)
  | BinOpType.ADD, BinOp (BinOpType.ADD, _, e4, { E = Num (n3) }, _),
                   BinOp (BinOpType.SUB, _, { E = Num (n1) }, e2, _) ->
    simplify (binADD (addNum n1 n3) (binSUB e4 e2))
  | BinOpType.ADD, BinOp (BinOpType.SUB, _, e1, { E = Num (n2) }, _),
                   BinOp (BinOpType.ADD, _, { E = Num (n3) }, e4, _)
  | BinOpType.ADD, BinOp (BinOpType.ADD, _, { E = Num (n3) }, e4, _),
                   BinOp (BinOpType.SUB, _, e1, { E = Num (n2) }, _)
  | BinOpType.ADD, BinOp (BinOpType.ADD, _, e4, { E = Num (n3) }, _),
                   BinOp (BinOpType.SUB, _, e1, { E = Num (n2) }, _)
  | BinOpType.ADD, BinOp (BinOpType.SUB, _, e1, { E = Num (n2) }, _),
                   BinOp (BinOpType.ADD, _, e4, { E = Num (n3) }, _) ->
    simplify (binADD (subNum n3 n2) (binADD e1 e4))
  (* ADD - ADD *)
  | BinOpType.SUB, BinOp (BinOpType.ADD, _, { E = Num (n1) }, e2, _),
                   BinOp (BinOpType.ADD, _, { E = Num (n3) }, e4, _)
  | BinOpType.SUB, BinOp (BinOpType.ADD, _, { E = Num (n1) }, e2, _),
                   BinOp (BinOpType.ADD, _, e4, { E = Num (n3) }, _)
  | BinOpType.SUB, BinOp (BinOpType.ADD, _, e2, { E = Num (n1) }, _),
                   BinOp (BinOpType.ADD, _, { E = Num (n3) }, e4, _)
  | BinOpType.SUB, BinOp (BinOpType.ADD, _, e2, { E = Num (n1) }, _),
                   BinOp (BinOpType.ADD, _, e4, { E = Num (n3) }, _) ->
    simplify (binADD (binSUB e2 e4) (subNum n1 n3))
  (* SUB - SUB *)
  | BinOpType.SUB, BinOp (BinOpType.SUB, _, { E = Num (n1) }, e2, _),
                   BinOp (BinOpType.SUB, _, { E = Num (n3) }, e4, _) ->
    simplify (binSUB (subNum n1 n3) (binSUB e2 e4))
  | BinOpType.SUB, BinOp (BinOpType.SUB, _, { E = Num (n1) }, e2, _),
                   BinOp (BinOpType.SUB, _, e3, { E = Num (n4) }, _) ->
    simplify (binSUB (addNum n1 n4) (binADD e2 e3))
  | BinOpType.SUB, BinOp (BinOpType.SUB, _, e2, { E = Num (n1) }, _),
                   BinOp (BinOpType.SUB, _, { E = Num (n3) }, e4, _) ->
    simplify (binSUB (binADD e2 e4) (addNum n1 n3))
  | BinOpType.SUB, BinOp (BinOpType.SUB, _, e2, { E = Num (n1) }, _),
                   BinOp (BinOpType.SUB, _, e4, { E = Num (n3) }, _) ->
    simplify (binSUB (binSUB e2 e4) (subNum n1 n3))
  (* Num - Num *)
  | BinOpType.SUB, Num (n1), Num (n2) -> subNum n1 n2
  (* ADD - Num, Num - ADD *)
  | BinOpType.SUB, BinOp (BinOpType.ADD, _, { E = Num (n1) }, e2, _), Num (n3)
  | BinOpType.SUB, BinOp (BinOpType.ADD, _, e2, { E = Num (n1) }, _), Num (n3)
    -> simplify (binADD (subNum n1 n3) e2)
  | BinOpType.SUB, Num (n1), BinOp (BinOpType.ADD, _, { E = Num (n2) }, e3, _)
  | BinOpType.SUB, Num (n1), BinOp (BinOpType.ADD, _, e3, { E = Num (n2) }, _)
    -> simplify (binSUB (subNum n1 n2) e3)
  (* SUB - Num, Num - SUB *)
  | BinOpType.SUB, BinOp (BinOpType.SUB, _, { E = Num (n1) }, e2, _), Num (n3)
    -> simplify (binSUB (subNum n1 n3) e2)
  | BinOpType.SUB, BinOp (BinOpType.SUB, _, e1, { E = Num (n2) }, _), Num (n3)
    -> simplify (binSUB e1 (addNum n2 n3))
  | BinOpType.SUB, Num (n1), BinOp (BinOpType.SUB, _, { E = Num (n2) }, e3, _)
    -> simplify (binADD e3 (subNum n1 n2))
  | BinOpType.SUB, Num (n1), BinOp (BinOpType.SUB, _, e2, { E = Num (n3) }, _)
    -> simplify (binSUB (addNum n1 n3) e2)
  (* ADD - SUB, SUB - ADD *)
  | BinOpType.SUB, BinOp (BinOpType.ADD, _, { E = Num (n1) }, e2, _),
                   BinOp (BinOpType.SUB, _, { E = Num (n3) }, e4, _)
  | BinOpType.SUB, BinOp (BinOpType.ADD, _, e2, { E = Num (n1) }, _),
                   BinOp (BinOpType.SUB, _, { E = Num (n3) }, e4, _) ->
    simplify (binADD (subNum n1 n3) (binSUB e2 e4))
  | BinOpType.SUB, BinOp (BinOpType.ADD, _, { E = Num (n1) }, e2, _),
                   BinOp (BinOpType.SUB, _, e3, { E = Num (n4) }, _)
  | BinOpType.SUB, BinOp (BinOpType.ADD, _, e2, { E = Num (n1) }, _),
                   BinOp (BinOpType.SUB, _, e3, { E = Num (n4) }, _) ->
    simplify (binADD (addNum n1 n4) (binSUB e2 e3))
  | BinOpType.SUB, BinOp (BinOpType.SUB, _, e1, { E = Num (n2) }, _),
                   BinOp (BinOpType.ADD, _, { E = Num (n3) }, e4, _)
  | BinOpType.SUB, BinOp (BinOpType.SUB, _, e1, { E = Num (n2) }, _),
                   BinOp (BinOpType.ADD, _, e4, { E = Num (n3) }, _) ->
    simplify (binSUB (binSUB e1 e4) (addNum n2 n3))
  | BinOpType.SUB, BinOp (BinOpType.SUB, _, { E = Num (n1) }, e2, _),
                   BinOp (BinOpType.ADD, _, { E = Num (n3) }, e4, _)
  | BinOpType.SUB, BinOp (BinOpType.SUB, _, { E = Num (n1) }, e2, _),
                   BinOp (BinOpType.ADD, _, e4, { E = Num (n3) }, _) ->
    simplify (binSUB (subNum n1 n3) (binADD e2 e4))
  | BinOpType.SUB, _, _ when e1 = e2 -> zeroNum ty
  | BinOpType.MUL, _, _ when isOne e1 -> simplify e2
  | BinOpType.MUL, _, _ when isOne e2 -> simplify e1
  | BinOpType.MUL, _, _ when isZero e1 || isZero e2 -> zeroNum ty
  | _, _, _ -> AST.binop op (simplify e1) (simplify e2)

and simplifyCast kind ty e1 =
  match kind, e1.E with
  | CastKind.ZeroExt, Num n -> BitVector.ZExt (n, ty) |> AST.num
  | _, _ -> AST.cast kind ty <| simplify e1

(*
    B2R2 - the Next-Generation Reversing Platform

    Author: HyungSeok Han <hyungseok.han@kaist.ac.kr>

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

module B2R2.ROP.Simplify

open B2R2
open B2R2.BinIR.LowUIR

let inline negNum x = BitVector.neg x |> Num

let inline zeroNum ty = Num (BitVector.zero ty)

let inline maxNum ty =
    match ty with
    | 8<rt>  -> BitVector.maxNum8  |> Num
    | 16<rt> -> BitVector.maxNum16 |> Num
    | 32<rt> -> BitVector.maxNum32 |> Num
    | 64<rt> -> BitVector.maxNum64 |> Num
    | _ -> failwith "maxNum fail"

let inline isZero x =
    match x with
    | Num n -> (BitVector.getValue n).IsZero
    | _ -> false

let inline isOne x =
    match x with
    | Num n -> (BitVector.getValue n).IsOne
    | _ -> false

let isFlippable x = (BitVector.isNegative x) && not (BitVector.isSignedMin x)

let inline isMax ty e =
    match e with
    | Num n -> (BitVector.one ty |> BitVector.add n |> BitVector.getValue).IsZero
    | _ -> false

let inline binADD ty e1 e2 = AST.binop BinOpType.ADD e1 e2

let inline binSUB ty e1 e2 = AST.binop BinOpType.SUB e1 e2

let inline subNum n1 n2 = BitVector.sub n1 n2 |> Num

let inline addNum n1 n2 = BitVector.add n1 n2 |> Num

let rec simplify expr =
    match expr with
    | UnOp (op, e1, _, _) -> AST.unop op <| simplify e1
    | BinOp (op, ty, e1, e2, _, _) -> simplifyBinOp op ty e1 e2
    | RelOp (op, e1, e2, _, _) -> AST.relop op (simplify e1) (simplify e2)
    | Load (endian, ty, e1, _, _) -> AST.load endian ty <| simplify e1
    | Ite (e1, e2, e3, _, _) -> AST.ite (simplify e1) (simplify e2) (simplify e3)
    | Cast (kind, ty, e1, _, _) -> simplifyCast kind ty e1
    | expr -> expr (* Var, TempVar, Num, Name, PCVar *)

and simplifyBinOp op ty e1 e2  =
    match op, e1, e2 with
    | BinOpType.XOR, e1, e2 when e1 = e2 -> zeroNum ty
    | BinOpType.XOR, e1, e2 when isZero e1 -> simplify e2
    | BinOpType.XOR, e1, e2 when isZero e2 -> simplify e1
    | BinOpType.AND, e1, e2 when e1 = e2 -> simplify e1
    | BinOpType.AND, e1, e2 when isMax ty e1 -> simplify e2
    | BinOpType.AND, e1, e2 when isMax ty e2 -> simplify e1
    | BinOpType.AND, e1, e2 when isZero e1 || isZero e2 -> zeroNum ty
    | BinOpType.OR, e1, e2 when e1 = e2 -> simplify e1
    | BinOpType.OR, e1, e2 when isZero e1 -> simplify e2
    | BinOpType.OR, e1, e2 when isZero e2 -> simplify e1
    | BinOpType.OR, e1, e2 when isMax ty e1 || isMax ty e2 -> maxNum ty
    | op, e1, e2 when isZero e1 && (op = BinOpType.ADD || op = BinOpType.SUB) ->
        simplify e2
    | op, e1, e2 when isZero e2 && (op = BinOpType.ADD || op = BinOpType.SUB) ->
        simplify e1
    | BinOpType.ADD, Num (n1), e2 when isFlippable n1 ->
        simplify (binSUB ty e2 (negNum n1))
    | BinOpType.ADD, e2, Num (n1) when isFlippable n1 ->
        simplify (binSUB ty e2 (negNum n1))
    | BinOpType.SUB, e1, Num (n2) when isFlippable n2 ->
        simplify (binADD ty e1 (negNum n2))
    | BinOpType.SUB, Num (n1), e2 when isFlippable n1 ->
        simplify (binSUB ty e2 (negNum n1))
    (* ADD + ADD *)
    | BinOpType.ADD, BinOp (BinOpType.ADD, _, Num (n1), e2, _, _),
                                      BinOp (BinOpType.ADD, _, Num (n3), e4, _, _)
    | BinOpType.ADD, BinOp (BinOpType.ADD, _, Num (n1), e2, _, _),
                                      BinOp (BinOpType.ADD, _, e4, Num (n3), _, _)
    | BinOpType.ADD, BinOp (BinOpType.ADD, _, e2, Num (n1), _, _),
                                      BinOp (BinOpType.ADD, _, Num (n3), e4, _, _)
    | BinOpType.ADD, BinOp (BinOpType.ADD, _, e2, Num (n1), _, _),
                                      BinOp (BinOpType.ADD, _, e4, Num (n3), _, _) ->
        simplify (binADD ty (binADD ty e2 e4) (addNum n1 n3))
    (* SUB + SUB *)
    | BinOpType.ADD, BinOp (BinOpType.SUB, _, Num (n1), e2, _, _),
                                      BinOp (BinOpType.SUB, _, Num (n3), e4, _, _) ->
        simplify (binSUB ty (addNum n1 n3) (binADD ty e2 e4))
    | BinOpType.ADD, BinOp (BinOpType.SUB, _, Num (n1), e2, _, _),
                                      BinOp (BinOpType.SUB, _, e3, Num (n4), _, _) ->
        simplify (binADD ty (subNum n1 n4) (binSUB ty e3 e2))
    | BinOpType.ADD, BinOp (BinOpType.SUB, _, e2, Num (n1), _, _),
                                      BinOp (BinOpType.SUB, _, Num (n3), e4, _, _) ->
        simplify (binADD ty (subNum n3 n1) (binSUB ty e2 e4))
    | BinOpType.ADD, BinOp (BinOpType.SUB, _, e2, Num (n1), _, _),
                                      BinOp (BinOpType.SUB, _, e4, Num (n3), _, _) ->
        simplify (binSUB ty (binADD ty e2 e4) (addNum n1 n3))
    (* Num + Num *)
    | BinOpType.ADD, Num (n1), Num (n2) -> addNum n1 n2
    (* ADD + Num, Num + ADD *)
    | BinOpType.ADD, Num (n1), BinOp (BinOpType.ADD, _, Num (n2), e3, _, _)
    | BinOpType.ADD, Num (n1), BinOp (BinOpType.ADD, _, e3, Num (n2), _, _)
    | BinOpType.ADD, BinOp (BinOpType.ADD, _, Num (n2), e3, _, _), Num (n1)
    | BinOpType.ADD, BinOp (BinOpType.ADD, _, e3, Num (n2), _, _), Num (n1) ->
        simplify (binADD ty e3 (addNum n1 n2))
    (* Num + SUB, SUB + Num *)
    | BinOpType.ADD, Num (n1), BinOp (BinOpType.SUB, _, Num (n2), e3, _, _)
    | BinOpType.ADD, BinOp (BinOpType.SUB, _, Num (n2), e3, _, _), Num (n1) ->
        simplify (binSUB ty (addNum n1 n2) e3)
    | BinOpType.ADD, Num (n1), BinOp (BinOpType.SUB, _, e2, Num (n3), _, _)
    | BinOpType.ADD, BinOp (BinOpType.SUB, _, e2, Num (n3), _, _), Num (n1) ->
        simplify (binADD ty e2 (subNum n1 n3))
    (* SUB + ADD, ADD + SUB *)
    | BinOpType.ADD, BinOp (BinOpType.SUB, _, Num (n1), e2, _, _),
                                      BinOp (BinOpType.ADD, _, Num (n3), e4, _, _)
    | BinOpType.ADD, BinOp (BinOpType.ADD, _, Num (n3), e4, _, _),
                                      BinOp (BinOpType.SUB, _, Num (n1), e2, _, _)
    | BinOpType.ADD, BinOp (BinOpType.SUB, _, Num (n1), e2, _, _),
                                      BinOp (BinOpType.ADD, _, e4, Num (n3), _, _)
    | BinOpType.ADD, BinOp (BinOpType.ADD, _, e4, Num (n3), _, _),
                                      BinOp (BinOpType.SUB, _, Num (n1), e2, _, _) ->
        simplify (binADD ty (addNum n1 n3) (binSUB ty e4 e2))
    | BinOpType.ADD, BinOp (BinOpType.SUB, _, e1, Num (n2), _, _),
                                      BinOp (BinOpType.ADD, _, Num (n3), e4, _, _)
    | BinOpType.ADD, BinOp (BinOpType.ADD, _, Num (n3), e4, _, _),
                                      BinOp (BinOpType.SUB, _, e1, Num (n2), _, _)
    | BinOpType.ADD, BinOp (BinOpType.ADD, _, e4, Num (n3), _, _),
                                      BinOp (BinOpType.SUB, _, e1, Num (n2), _, _)
    | BinOpType.ADD, BinOp (BinOpType.SUB, _, e1, Num (n2), _, _),
                                      BinOp (BinOpType.ADD, _, e4, Num (n3), _, _) ->
        simplify (binADD ty (subNum n3 n2) (binADD ty e1 e4))
    (* ADD - ADD *)
    | BinOpType.SUB, BinOp (BinOpType.ADD, _, Num (n1), e2, _, _),
                                      BinOp (BinOpType.ADD, _, Num (n3), e4, _, _)
    | BinOpType.SUB, BinOp (BinOpType.ADD, _, Num (n1), e2, _, _),
                                      BinOp (BinOpType.ADD, _, e4, Num (n3), _, _)
    | BinOpType.SUB, BinOp (BinOpType.ADD, _, e2, Num (n1), _, _),
                                      BinOp (BinOpType.ADD, _, Num (n3), e4, _, _)
    | BinOpType.SUB, BinOp (BinOpType.ADD, _, e2, Num (n1), _, _),
                                      BinOp (BinOpType.ADD, _, e4, Num (n3), _, _) ->
        simplify (binADD ty (binSUB ty e2 e4) (subNum n1 n3))
    (* SUB - SUB *)
    | BinOpType.SUB, BinOp (BinOpType.SUB, _, Num (n1), e2, _, _),
                                      BinOp (BinOpType.SUB, _, Num (n3), e4, _, _) ->
        simplify (binSUB ty (subNum n1 n3) (binSUB ty e2 e4))
    | BinOpType.SUB, BinOp (BinOpType.SUB, _, Num (n1), e2, _, _),
                                      BinOp (BinOpType.SUB, _, e3, Num (n4), _, _) ->
        simplify (binSUB ty (addNum n1 n4) (binADD ty e2 e3))
    | BinOpType.SUB, BinOp (BinOpType.SUB, _, e2, Num (n1), _, _),
                                      BinOp (BinOpType.SUB, _, Num (n3), e4, _, _) ->
        simplify (binSUB ty (binADD ty e2 e4) (addNum n1 n3))
    | BinOpType.SUB, BinOp (BinOpType.SUB, _, e2, Num (n1), _, _),
                                      BinOp (BinOpType.SUB, _, e4, Num (n3), _, _) ->
        simplify (binSUB ty (binSUB ty e2 e4) (subNum n1 n3))
    (* Num - Num *)
    | BinOpType.SUB, Num (n1), Num (n2) -> subNum n1 n2
    (* ADD - Num, Num - ADD *)
    | BinOpType.SUB, BinOp (BinOpType.ADD, _, Num (n1), e2, _, _), Num (n3)
    | BinOpType.SUB, BinOp (BinOpType.ADD, _, e2, Num (n1), _, _), Num (n3) ->
        simplify (binADD ty (subNum n1 n3) e2)
    | BinOpType.SUB, Num (n1), BinOp (BinOpType.ADD, _, Num (n2), e3, _, _)
    | BinOpType.SUB, Num (n1), BinOp (BinOpType.ADD, _, e3, Num (n2), _, _) ->
        simplify (binSUB ty (subNum n1 n2) e3)
    (* SUB - Num, Num - SUB *)
    | BinOpType.SUB, BinOp (BinOpType.SUB, _, Num (n1), e2, _, _), Num (n3) ->
        simplify (binSUB ty (subNum n1 n3) e2)
    | BinOpType.SUB, BinOp (BinOpType.SUB, _, e1, Num (n2), _, _), Num (n3) ->
        simplify (binSUB ty e1 (addNum n2 n3))
    | BinOpType.SUB, Num (n1), BinOp (BinOpType.SUB, _, Num (n2), e3, _, _) ->
        simplify (binADD ty e3 (subNum n1 n2))
    | BinOpType.SUB, Num (n1), BinOp (BinOpType.SUB, _, e2, Num (n3), _, _) ->
        simplify (binSUB ty (addNum n1 n3) e2)
    (* ADD - SUB, SUB - ADD *)
    | BinOpType.SUB, BinOp (BinOpType.ADD, _, Num (n1), e2, _, _),
                                      BinOp (BinOpType.SUB, _, Num (n3), e4, _, _)
    | BinOpType.SUB, BinOp (BinOpType.ADD, _, e2, Num (n1), _, _),
                                      BinOp (BinOpType.SUB, _, Num (n3), e4, _, _) ->
        simplify (binADD ty (subNum n1 n3) (binSUB ty e2 e4))
    | BinOpType.SUB, BinOp (BinOpType.ADD, _, Num (n1), e2, _, _),
                                      BinOp (BinOpType.SUB, _, e3, Num (n4), _, _)
    | BinOpType.SUB, BinOp (BinOpType.ADD, _, e2, Num (n1), _, _),
                                      BinOp (BinOpType.SUB, _, e3, Num (n4), _, _) ->
        simplify (binADD ty (addNum n1 n4) (binSUB ty e2 e3))
    | BinOpType.SUB, BinOp (BinOpType.SUB, _, e1, Num (n2), _, _),
                                      BinOp (BinOpType.ADD, _, Num (n3), e4, _, _)
    | BinOpType.SUB, BinOp (BinOpType.SUB, _, e1, Num (n2), _, _),
                                      BinOp (BinOpType.ADD, _, e4, Num (n3), _, _) ->
        simplify (binSUB ty (binSUB ty e1 e4) (addNum n2 n3))
    | BinOpType.SUB, BinOp (BinOpType.SUB, _, Num (n1), e2, _, _),
                                      BinOp (BinOpType.ADD, _, Num (n3), e4, _, _)
    | BinOpType.SUB, BinOp (BinOpType.SUB, _, Num (n1), e2, _, _),
                                      BinOp (BinOpType.ADD, _, e4, Num (n3), _, _) ->
        simplify (binSUB ty (subNum n1 n3) (binADD ty e2 e4))
    | BinOpType.SUB, e1, e2 when e1 = e2 -> zeroNum ty
    | BinOpType.MUL, e1, e2 when isOne e1 -> simplify e2
    | BinOpType.MUL, e1, e2 when isOne e2 -> simplify e1
    | BinOpType.MUL, e1, e2 when isZero e1 || isZero e2 -> zeroNum ty
    | _, _, _ -> AST.binop op (simplify e1) (simplify e2)

and simplifyCast kind ty e1 =
    match kind, e1 with
    | CastKind.ZeroExt, Num n -> BitVector.zext n ty |> Num
    | _, _ -> AST.cast kind ty <| simplify e1

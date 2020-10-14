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

namespace B2R2.MiddleEnd.DataFlow

open B2R2

type SCCPValue =
  | NotAConst
  | Const of BitVector
  | Pointer of BitVector
  | Undef

module SCCPValue =

  let meet c1 c2 =
    match c1, c2 with
    | Undef, c | c, Undef -> c
    | Const bv1, Const bv2 -> if bv1 = bv2 then c1 else NotAConst
    | Pointer bv1, Pointer bv2 -> if bv1 = bv2 then c1 else NotAConst
    | _ -> NotAConst

  let unOp op = function
    | Const bv -> Const (op bv)
    | Pointer bv -> Const (op bv)
    | c -> c

  let neg c = unOp BitVector.neg c

  let not c = unOp BitVector.bnot c

  let binOp op c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef -> Undef
    | Pointer bv1, Pointer bv2
    | Pointer bv1, Const bv2
    | Const bv1, Pointer bv2
    | Const bv1, Const bv2 -> Const (op bv1 bv2)
    | _ -> NotAConst

  let add c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef -> Undef
    | Pointer bv1, Const bv2
    | Const bv1, Pointer bv2 -> Pointer (BitVector.add bv1 bv2)
    | Pointer bv1, Pointer bv2
    | Const bv1, Const bv2 -> Const (BitVector.add bv1 bv2)
    | _ -> NotAConst

  let sub c1 c2 = binOp BitVector.sub c1 c2

  let mul c1 c2 = binOp BitVector.mul c1 c2

  let divAux divop c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef -> Undef
    | Pointer bv1, Pointer bv2
    | Pointer bv1, Const bv2
    | Const bv1, Pointer bv2
    | Const bv1, Const bv2 ->
      if BitVector.isZero bv2 then NotAConst
      else Const (divop bv1 bv2)
    | _ -> NotAConst

  let div c1 c2 = divAux BitVector.div c1 c2

  let sdiv c1 c2 = divAux BitVector.sdiv c1 c2

  let ``mod`` c1 c2 = binOp BitVector.modulo c1 c2

  let smod c1 c2 = binOp BitVector.smodulo c1 c2

  let shl c1 c2 = binOp BitVector.shl c1 c2

  let shr c1 c2 = binOp BitVector.shr c1 c2

  let sar c1 c2 = binOp BitVector.sar c1 c2

  let ``and`` c1 c2 = binOp BitVector.band c1 c2

  let ``or`` c1 c2 = binOp BitVector.bor c1 c2

  let xor c1 c2 = binOp BitVector.bxor c1 c2

  let concat c1 c2 = binOp BitVector.concat c1 c2

  let relOp op c1 c2 = binOp op c1 c2

  let eq c1 c2 = relOp BitVector.eq c1 c2

  let neq c1 c2 = relOp BitVector.neq c1 c2

  let gt c1 c2 = relOp BitVector.gt c1 c2

  let ge c1 c2 = relOp BitVector.ge c1 c2

  let sgt c1 c2 = relOp BitVector.sgt c1 c2

  let sge c1 c2 = relOp BitVector.sge c1 c2

  let lt c1 c2 = relOp BitVector.lt c1 c2

  let le c1 c2 = relOp BitVector.le c1 c2

  let slt c1 c2 = relOp BitVector.slt c1 c2

  let sle c1 c2 = relOp BitVector.sle c1 c2

  let ite cond c1 c2 =
    match cond with
    | Undef -> Undef
    | Pointer bv
    | Const bv -> if BitVector.isZero bv then c2 else c1
    | NotAConst -> meet c1 c2

  let cast op rt c =
    unOp (fun bv -> op bv rt) c

  let signExt rt c = cast BitVector.sext rt c

  let zeroExt rt c = cast BitVector.zext rt c

  let extract c rt pos =
    unOp (fun bv -> BitVector.extract bv rt pos) c

  let goingUp a b =
    match a, b with
    | Const _, Undef
    | Pointer _, Undef
    | NotAConst, Undef
    | NotAConst, Const _
    | NotAConst, Pointer _ -> true
    | _ -> false

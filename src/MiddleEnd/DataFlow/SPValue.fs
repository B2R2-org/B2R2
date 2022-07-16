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

/// StackPointerPropagation values.
type SPValue =
  | NotAConst
  | Const of BitVector
  | Undef

module SPValue =

  let goingUp fromV toV =
    match fromV, toV with
    | Const _, Undef
    | NotAConst, Undef
    | NotAConst, Const _ -> true
    | _ -> false

  let meet c1 c2 =
    match c1, c2 with
    | Undef, c | c, Undef -> c
    | Const bv1, Const bv2 -> if bv1 = bv2 then c1 else NotAConst
    | _ -> NotAConst

  let add c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef -> Undef
    | Const bv1, Const bv2 -> Const (BitVector.Add (bv1, bv2))
    | _ -> NotAConst

  let sub c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef -> Undef
    | Const bv1, Const bv2 -> Const (BitVector.Sub (bv1, bv2))
    | _ -> NotAConst

  let ``and`` c1 c2 =
    match c1, c2 with
    | Undef, _ | _, Undef -> Undef
    | Const bv1, Const bv2 -> Const (BitVector.BAnd (bv1, bv2))
    | _ -> NotAConst

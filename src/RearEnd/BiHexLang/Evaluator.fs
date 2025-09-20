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

namespace B2R2.RearEnd.BiHexLang

open System

/// Represents an evaluator for BiHexLang expressions.
type Evaluator() =
  let unifyType ltyp rtyp =
    match ltyp, rtyp with
    | Hex, Hex -> Hex
    | Dec, Dec -> Dec
    | Oct, Oct -> Oct
    | Bin, Bin -> Bin
    | Hex, _ | _, Hex -> Hex
    | Dec, _ | _, Dec -> Dec
    | Oct, _ | _, Oct -> Oct

  let unifyByteCount lcnt rcnt =
    if lcnt > rcnt then lcnt else rcnt

  let bigintToSignExtendedBytes (n: bigint) cnt =
    let bs = n.ToByteArray()
    let pad = if n >= 0I then 0uy else 0xFFuy
    if bs.Length >= cnt then bs[..cnt - 1]
    else Array.append bs (Array.create (cnt - bs.Length) pad)

  let bigintToZeroPaddedBytes (n: bigint) cnt =
    let bs = n.ToByteArray()
    if bs.Length >= cnt then bs
    else Array.append bs (Array.create (cnt - bs.Length) 0uy)

  let rec eval expr =
    match expr with
    | Number(typ, bs) ->
      bigint [| yield! bs; 0uy |], typ, bs.Length
    | Str(s) ->
      let bs = Text.ASCIIEncoding.ASCII.GetBytes s |> Array.rev
      bigint bs, Hex, max 1 s.Length
    | Add(lhs, rhs) ->
      binop (+) lhs rhs
    | Sub(lhs, rhs) ->
      binop (-) lhs rhs
    | Mul(Str(s), Number(_, bs))
    | Mul(Number(_, bs), Str(s)) ->
      let n = bigint [| yield! bs; 0uy |] |> int
      let bs = String.replicate n s |> Text.ASCIIEncoding.ASCII.GetBytes
      bigint (Array.rev bs), Hex, max 1 bs.Length
    | Mul(lhs, rhs) ->
      binop (*) lhs rhs
    | Div(lhs, rhs) ->
      binop (/) lhs rhs
    | Mod(lhs, rhs) ->
      binop (%) lhs rhs
    | And(lhs, rhs) ->
      binop (&&&) lhs rhs
    | Or(lhs, rhs) ->
      binop (|||) lhs rhs
    | Xor(lhs, rhs) ->
      binop (^^^) lhs rhs
    | Shl(lhs, rhs) ->
      let lhs, ltyp, lcnt = eval lhs
      let rhs, rtyp, rcnt = eval rhs
      let mask = "0" + String.replicate lcnt "FF"
      let mask = bigint.Parse(mask, Globalization.NumberStyles.HexNumber)
      if lcnt = rcnt then
        let r = (lhs <<< int rhs) &&& mask
        let r = r.ToByteArray()[..lcnt - 1] |> bigint
        r, unifyType ltyp rtyp, lcnt
      else
        let lhs = bigintToZeroPaddedBytes lhs (max lcnt rcnt) |> bigint
        let rhs = bigintToZeroPaddedBytes rhs (max lcnt rcnt) |> bigint
        let r = (lhs <<< int rhs) &&& mask
        let r = r.ToByteArray()[..lcnt - 1] |> bigint
        r, unifyType ltyp rtyp, lcnt
    | Shr(lhs, rhs) ->
      binop (fun l r -> l >>> int r) lhs rhs
    | Neg e ->
      let e, typ, cnt = eval e
      - e, typ, cnt
    | Not e ->
      let e, typ, cnt = eval e
      Numerics.BigInteger.op_OnesComplement e, typ, cnt
    | Cast(typ, e) ->
      let e, _, cnt = eval e
      e, typ, cnt
    | Concat(lhs, rhs) ->
      let lhs, ltyp, lcnt = eval lhs
      let rhs, rtyp, rcnt = eval rhs
      let lhs = (bigintToZeroPaddedBytes lhs lcnt)[..lcnt - 1]
      let rhs = (bigintToZeroPaddedBytes rhs rcnt)[..rcnt - 1]
      bigint [| yield! rhs; yield! lhs; 0uy |], unifyType ltyp rtyp, lcnt + rcnt

  and binop op lhs rhs =
    let lhs, ltyp, lcnt = eval lhs
    let rhs, rtyp, rcnt = eval rhs
    if lcnt = rcnt then
      op lhs rhs, unifyType ltyp rtyp, unifyByteCount lcnt rcnt
    else
      let lhs = bigintToZeroPaddedBytes lhs (max lcnt rcnt) |> bigint
      let rhs = bigintToZeroPaddedBytes rhs (max lcnt rcnt) |> bigint
      op lhs rhs, unifyType ltyp rtyp, unifyByteCount lcnt rcnt

  /// Evaluates the given expression and returns the result as a string.
  member _.EvalExprToString expr =
    let n, typ, cnt = eval expr
    let bs = bigintToSignExtendedBytes n cnt
    Expr.ToString(Number(typ, bs))

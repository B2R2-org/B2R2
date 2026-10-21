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
/// Lifts the Matrix-Multiply Assist forms: the accumulator moves and the
/// rank-k updates (the "ger" forms). Accumulator n is no state of its own:
/// the manual has VSR 4n to 4n + 3 and ACC[n] hold the same data, so row i
/// of the accumulator is VSR 4n + i, the moves between the two are no-ops,
/// and an update writes those registers. A source never overlaps the
/// accumulator it updates (the decoder refuses that form), so each row is
/// written as soon as it is computed.
/// </summary>
module internal B2R2.FrontEnd.PPC.VSXMatrix

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.OperandHelper
open B2R2.FrontEnd.PPC.VSXLifter

/// The rows of the accumulator an operand names: the halves of VSR 4n to
/// 4n + 3.
let private rowsOf bld opr =
  match opr with
  | OprReg reg when reg >= Register.ACC0 && reg <= Register.ACC7 ->
    let n = int reg - int Register.ACC0
    Array.init 4 (fun i ->
      vsrOf bld (OprReg(getVsxRegister (uint32 (4 * n + i)))))
  | _ ->
    raise InvalidOperandException

/// Clears a row.
let private clearRow bld (struct (h: Expr, l: Expr)) =
  append bld {
    h := AST.num0 64<rt>
    l := AST.num0 64<rt>
  }

/// xxsetaccz: every row of the accumulator cleared.
let setAccumulatorZero ins bld =
  lift bld ins {
    rowsOf bld (getOneOpr ins) |> Array.iter (clearRow bld)
  }

/// <summary>
/// A rank-k update over words: element j of row i computed by f from word i
/// of xA, word j of xB and the element itself, each row written through
/// temporaries once its four words are computed.
/// </summary>
let private updateWords (ins: Instruction) bld f =
  let struct (o1, o2, o3) = getThreeOprs ins
  let struct (ah, al) = vsrOf bld o2
  let struct (bh, bl) = vsrOf bld o3
  let xs = VSXFloat.lanesOf 32<rt> ah al
  let ys = VSXFloat.lanesOf 32<rt> bh bl
  rowsOf bld o1
  |> Array.iteri (fun i (struct (h, l)) ->
    let accs = VSXFloat.lanesOf 32<rt> h l
    let results = Array.init 4 (fun j -> f xs[i] ys[j] accs[j])
    VSXFloat.writeLanes bld 32<rt> h l results)

/// A rank-k update over words, as one instruction.
let private wordUpdate ins bld f =
  lift bld ins {
    updateWords ins bld f
  }

/// <summary>
/// One element of a single- or double-precision update: the product (kind
/// 0) or the fused multiply-add of the four accumulating kinds -- 1 adds
/// the element, 2 subtracts it, 3 subtracts it and negates the rounded
/// result, 4 adds it and negates -- through the calls the other vector
/// multiply-adds make, NaNs in POWER's order.
/// </summary>
let private fusedElement bld lane kind x y acc =
  if kind = 0 then
    VSXFloat.arith AST.fmul lane [ x; y ]
  else
    let subtract = kind = 2 || kind = 3
    VSXFloat.mulAddLane bld lane false subtract (kind >= 3) x y acc

/// The register an operand names.
let private regOf = function
  | OprReg reg -> reg
  | _ -> raise InvalidOperandException

/// xvf32ger and its accumulating forms.
let singleUpdate ins bld kind =
  wordUpdate ins bld (fusedElement bld VSXFloat.single kind)

/// <summary>
/// xvf64ger and its accumulating forms: the four doubles of the pair
/// starting at xA by the two of xB, each row of the accumulator two
/// doublewords.
/// </summary>
let doubleUpdate (ins: Instruction) bld kind =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (a0, a1) = vsrOf bld o2
    let struct (a2, a3) = vsrOf bld (OprReg(secondOfPair (regOf o2)))
    let struct (y0, y1) = vsrOf bld o3
    let xs = [| a0; a1; a2; a3 |]
    let f x y acc = fusedElement bld VSXFloat.double kind x y acc
    rowsOf bld o1
    |> Array.iteri (fun i (struct (h, l)) ->
      VSXFloat.writeLanes bld 64<rt> h l [| f xs[i] y0 h; f xs[i] y1 l |])
  }

/// The 16-bit value in halfword k (0 the high one) of a word.
let private halfword (w: Expr) k =
  if k = 0 then AST.xthi 16<rt> w else AST.xtlo 16<rt> w

/// A bfloat16 as the single it is, a NaN quieted.
let private widenBF16 (h: Expr) =
  let s = AST.zext 32<rt> h << numI32 16 32<rt>
  let lane = VSXFloat.single
  AST.ite (VSXFloat.isNaNOf lane s) (VSXFloat.quietOf lane s) s

/// The first NaN of a stage, quieted, or the stage's computed fallback.
let private nanChoice candidates fallback =
  let lane = VSXFloat.single
  List.foldBack (fun c rest ->
    AST.ite (VSXFloat.isNaNOf lane c) (VSXFloat.quietOf lane c) rest)
    candidates fallback

/// A single-precision infinity, with either sign.
let private isInfinity value =
  (value .& numU32 0x7fffffffu 32<rt>) == numU32 0x7f800000u 32<rt>

/// Infinity times zero creates a default NaN before later NaNs are selected.
let private invalidProduct x y =
  let lane = VSXFloat.single
  (isInfinity x .& VSXFloat.isZeroOf lane y)
  .| (VSXFloat.isZeroOf lane x .& isInfinity y)

/// A NaN generated by a stage, or a non-NaN placeholder for a regular result.
let private generatedNaN invalid =
  AST.ite invalid (VSXFloat.defaultNaNOf VSXFloat.single) (AST.num0 32<rt>)

/// Preserve the staged multiply, fused sum and accumulator NaN priorities.
let settleDot widen kind x y acc res =
  let lane = VSXFloat.single
  let x0, x1 = widen (halfword x 0), widen (halfword x 1)
  let y0, y1 = widen (halfword y 0), widen (halfword y 1)
  let product =
    nanChoice [ x0; y0 ] (generatedNaN (invalidProduct x0 y0))
  let inf0 = isInfinity x0 .| isInfinity y0
  let inf1 = isInfinity x1 .| isInfinity y1
  let sign0 = AST.xthi 1<rt> (x0 <+> y0)
  let sign1 = AST.xthi 1<rt> (x1 <+> y1)
  let invalidSum = invalidProduct x1 y1 .| (inf0 .& inf1 .& (sign0 != sign1))
  let sum = nanChoice [ x1; product; y1 ] (generatedNaN invalidSum)
  let candidates = if kind = 0 then [ sum ] else [ sum; acc ]
  let fallback =
    AST.ite (VSXFloat.isNaNOf lane res) (VSXFloat.defaultNaNOf lane) res
  nanChoice candidates fallback

/// <summary>
/// xvf16ger2 and xvbf16ger2 and their accumulating forms: each element the
/// named call FGER2HALF or FGER2BF16 (lanes/X.md) of the two words and the
/// element, in the direction FPSCR[RN] names, its NaN settled here.
/// </summary>
let dotUpdate ins bld isBF16 kind =
  let name = if isBF16 then "FGER2BF16" else "FGER2HALF"
  let widen = if isBF16 then widenBF16 else VSXConvert.widenHalf VSXFloat.single
  let fpscr = regVar bld Register.FPSCR
  let mode = AST.zext 8<rt> (AST.extract fpscr 2<rt> 0)
  let element x y acc =
    let args = [ x; y; acc; numI32 kind 8<rt>; mode ]
    settleDot widen kind x y acc (AST.app name args 32<rt>)
  wordUpdate ins bld element

/// The fields of a word, most significant first, each width bits wide.
let private fieldsOf (w: Expr) width =
  Array.init (32 / width) (fun k ->
    AST.extract w (width * 1<rt>) (32 - width * (k + 1)))

/// <summary>
/// The sum of the products of matching fields of two words, at a width:
/// xA's fields signed, xB's signed or not.
/// </summary>
let private dotOf rt width ySigned (x: Expr) (y: Expr) =
  let ext signed v = if signed then AST.sext rt v else AST.zext rt v
  Array.map2 (fun a b -> ext true a .* ext ySigned b)
    (fieldsOf x width) (fieldsOf y width)
  |> Array.reduce (.+)

/// xvi4ger8, xvi8ger4, xvi16ger2 and their "pp" forms: the sum of products,
/// plus the element where the form accumulates, modulo two to the 32.
let integerUpdate ins bld width ySigned accumulate =
  let element x y acc =
    let sum = dotOf 32<rt> width ySigned x y
    if accumulate then sum .+ acc else sum
  wordUpdate ins bld element

/// The bounds of a signed word, at 64 bits.
let private wordMin = numI64 (-2147483648L) 64<rt>

let private wordMax = numI64 2147483647L 64<rt>

/// One saturated element: the sum (plus the element where the form
/// accumulates) clamped to a signed word, sat set where it was clamped.
let private saturated bld sat width ySigned accumulate x y acc =
  let sum = dotOf 64<rt> width ySigned x y
  let total = tmpVar bld 64<rt>
  let low = total ?< wordMin
  let high = total ?> wordMax
  append bld {
    total := if accumulate then sum .+ AST.sext 64<rt> acc else sum
    sat := sat .| low .| high
  }
  AST.xtlo 32<rt> (AST.ite low wordMin (AST.ite high wordMax total))

/// <summary>
/// xvi8ger4spp, xvi16ger2s and xvi16ger2spp: the sum of products, plus the
/// element where the form accumulates, saturated to a signed word; a
/// saturated element sets VSCR's sticky SAT bit.
/// </summary>
let saturatingUpdate ins bld width ySigned accumulate =
  lift bld ins {
    let sat = tmpVar bld 1<rt>
    let vscr = regVar bld Register.VSCR
    sat := AST.b0
    updateWords ins bld (saturated bld sat width ySigned accumulate)
    vscr := vscr .| AST.zext 32<rt> sat
  }

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
/// The bfloat16 instructions Armv8.6 added to AArch32 (DDI0487F.c F6.1.57,
/// F6.1.68, F6.1.77, F6.1.79, F6.1.80, F6.1.87, F6.1.88 and F6.1.131): VDOT
/// and VMMLA, which round to odd, flush denormals and answer the default NaN
/// whatever FPSCR says, raising nothing; VFMAB and VFMAT, an FPMulAdd of
/// widened bfloat16s on the standard value; and the conversions from a
/// single, VCVT on the standard value and VCVTB and VCVTT on FPSCR.
/// </summary>
module internal B2R2.FrontEnd.ARM32.BF16Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM32
open B2R2.FrontEnd.ARM32.LiftingUtils
open B2R2.FrontEnd.ARM32.FloatingPoint
open B2R2.FrontEnd.ARM32.FPLifter

/// A bfloat16 as the single it is the top half of.
let private widen e = AST.concat e (AST.num0 16<rt>)

/// A single as BFUnpack reads it: a denormal is a zero of its sign, the
/// flushing the bfloat16 arithmetic does whatever FPSCR says.
let private bfFlush e =
  let exponent = e .& numU32 0x7f800000u 32<rt>
  AST.ite (exponent == AST.num0 32<rt>) (e .& numU32 0x80000000u 32<rt>) e

/// Whether an expression loses nothing to rounding: rounded up and down it
/// gives the same number exactly where it is representable.
let private isExact e =
  let up = AST.roundCtrl (AST.roundingMode RoundingMode.TowardPositive) e
  let down = AST.roundCtrl (AST.roundingMode RoundingMode.TowardNegative) e
  AST.feq up down

/// <summary>
/// BFRound of an arithmetic's exact answer: rounded to ODD -- truncated, and
/// the last bit set if anything was lost -- a zero of its sign below the
/// smallest normal, and an infinity from two to the 128th on, which is asked
/// of the answer halved, where it still fits.
/// </summary>
let private bfRound arith halved =
  let truncated e = AST.roundCtrl (AST.roundingMode RoundingMode.TowardZero) e
  let magnitude e = e .& numU32 0x7fffffffu 32<rt>
  let t = truncated arith
  let sign = t .& numU32 0x80000000u 32<rt>
  let odd = AST.ite (isExact arith) t (t .| AST.num1 32<rt>)
  let tiny = magnitude t .< numU32 0x00800000u 32<rt>
  let beyond = magnitude (truncated halved) .>= numU32 0x7f000000u 32<rt>
  let infinity = sign .| numU32 0x7f800000u 32<rt>
  AST.ite beyond infinity (AST.ite tiny sign odd)

/// <summary>
/// BFMul: two bfloat16s multiplied into a single. A NaN, or an infinity times
/// a zero, makes the default NaN; an infinity or a zero otherwise carries the
/// two signs' exclusive or; the rest rounds by bfRound, which changes an
/// answer only at the ends of the range.
/// </summary>
let private bfMul bld a b =
  let struct (x, y, r) = tmpVars3 bld 32<rt>
  append bld {
    x := bfFlush (widen a)
    y := bfFlush (widen b)
  }
  let half = numU32 0x3f000000u 32<rt>
  let rounded = bfRound (AST.fmul x y) (AST.fmul (AST.fmul x half) y)
  let sign = (x <+> y) .& numU32 0x80000000u 32<rt>
  let infX = isInfinity 32<rt> x
  let infY = isInfinity 32<rt> y
  let zeroX = isZero 32<rt> x
  let zeroY = isZero 32<rt> y
  let invalid =
    isNaN 32<rt> x .| isNaN 32<rt> y .| (infX .& zeroY) .| (zeroX .& infY)
  let special =
    AST.ite (infX .| infY) (sign .| numU32 0x7f800000u 32<rt>) sign
  let ordinary = AST.ite (infX .| infY .| zeroX .| zeroY) special rounded
  append bld { r := AST.ite invalid (fpDefaultNaN 32<rt>) ordinary }
  r

/// <summary>
/// BFAdd: two singles added, each read as BFUnpack reads it. A NaN, or
/// infinities of opposite signs, make the default NaN; an infinity otherwise
/// wins; two zeros of one sign keep it; the rest rounds by bfRound, a sum
/// that cancels exactly coming out a positive zero.
/// </summary>
let private bfAdd bld a b =
  let struct (x, y, r) = tmpVars3 bld 32<rt>
  append bld {
    x := bfFlush a
    y := bfFlush b
  }
  let half e = AST.fmul e (numU32 0x3f000000u 32<rt>)
  let rounded = bfRound (AST.fadd x y) (AST.fadd (half x) (half y))
  let infX = isInfinity 32<rt> x
  let infY = isInfinity 32<rt> y
  let opposite = AST.xthi 1<rt> x <+> AST.xthi 1<rt> y
  let invalid = isNaN 32<rt> x .| isNaN 32<rt> y .| (infX .& infY .& opposite)
  let zeros = isZero 32<rt> x .& isZero 32<rt> y .& AST.not opposite
  let ordinary = AST.ite infX x (AST.ite (infY .| zeros) y rounded)
  append bld { r := AST.ite invalid (fpDefaultNaN 32<rt>) ordinary }
  r

/// The bfloat16s of a doubleword a scalar names, all of them.
let private scalarHalves bld r = readLanes bld 16 (OprSIMD(SFReg(Vector r)))

/// <summary>
/// VDOT, by vector and by element: every word of Dd or Qd accumulates two
/// products of bfloat16s, a pair of Dn or Qn against a pair of Dm or Qm --
/// the one pair the index names, by element -- by BFMul and BFAdd.
/// </summary>
let vdot (ins: Instruction) bld =
  conditional ins bld (fun () ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let acc = readLanes bld 32 dst
    let a = readLanes bld 16 src1
    let pairOf =
      match src2 with
      | OprSIMD(SFReg(Scalar(r, Some idx))) ->
        let b = scalarHalves bld r
        fun _ -> b[int idx * 2], b[int idx * 2 + 1]
      | _ ->
        let b = readLanes bld 16 src2
        fun e -> b[2 * e], b[2 * e + 1]
    Array.init acc.Length (fun e ->
      let b0, b1 = pairOf e
      let sum = bfAdd bld (bfMul bld a[2 * e] b0) (bfMul bld a[2 * e + 1] b1)
      bfAdd bld acc[e] sum)
    |> writeLanes bld dst)

/// <summary>
/// VMMLA: the 2x4 by 4x2 bfloat16 matrix product accumulated into a 2x2 of
/// words. BFMatMulAdd adds two pairs of products to each word in turn, every
/// step rounding as VDOT's do.
/// </summary>
let vmmla (ins: Instruction) bld =
  conditional ins bld (fun () ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let acc = readLanes bld 32 dst
    let a = readLanes bld 16 src1
    let b = readLanes bld 16 src2
    Array.init 4 (fun n ->
      let i, j = n / 2, n % 2
      let step sum k =
        let p0 = bfMul bld a[4 * i + 2 * k] b[4 * j + 2 * k]
        let p1 = bfMul bld a[4 * i + 2 * k + 1] b[4 * j + 2 * k + 1]
        bfAdd bld sum (bfAdd bld p0 p1)
      step (step acc[n] 0) 1)
    |> writeLanes bld dst)

/// <summary>
/// VFMAB and VFMAT, by vector and by scalar: the bottom or the top bfloat16
/// of each word of Qn, widened, times Qm's in the same place -- or the one
/// the index names -- added to the word of Qd by FPMulAdd on the standard
/// value.
/// </summary>
let vfmaLong (ins: Instruction) bld isTop =
  conditional ins bld (fun () ->
    let struct (dst, src1, src2) = getThreeOprs ins
    let acc = readLanes bld 32 dst
    let a = readLanes bld 16 src1
    let sel = if isTop then 1 else 0
    let second =
      match src2 with
      | OprSIMD(SFReg(Scalar(r, Some idx))) ->
        let b = scalarHalves bld r
        Array.create acc.Length b[int idx]
      | _ ->
        let b = readLanes bld 16 src2
        Array.init acc.Length (fun e -> b[2 * e + sel])
    Array.init acc.Length (fun e ->
      let x = tmpVar bld 32<rt>
      let y = tmpVar bld 32<rt>
      append bld { x := widen a[2 * e + sel] }
      append bld { y := widen second[e] }
      fpMulAdd bld StandardValue 32<rt> acc[e] x y)
    |> writeLanes bld dst)

/// <summary>
/// Whether a single's top sixteen bits round up to make its bfloat16, in the
/// direction the two bits of the mode name: to nearest on the bits dropped, a
/// tie going to an even result; away from zero toward the value's own
/// infinity; never toward zero.
/// </summary>
let private bfRoundsUp mode src =
  let low = src .& numU32 0xffffu 32<rt>
  let lost = low != AST.num0 32<rt>
  let negative = AST.xthi 1<rt> src
  let tie = low == numU32 0x8000u 32<rt>
  let odd = AST.extract src 1<rt> 16
  let nearest = (low .> numU32 0x8000u 32<rt>) .| (tie .& odd)
  let towardPlus = lost .& AST.not negative
  let directed = AST.ite (mode == numI32 1 2<rt>) towardPlus (lost .& negative)
  let otherwise = AST.ite (mode == numI32 3 2<rt>) AST.b0 directed
  AST.ite (mode == AST.num0 2<rt>) nearest otherwise

/// <summary>
/// FPConvertBF: the bfloat16 a single rounds to, its top sixteen bits rounded
/// in the direction the controls name; on a magnitude's bits that is an
/// increment or nothing, and the carry walks into the exponent and out of the
/// top of the range into an infinity. A NaN is the default NaN under DN, and
/// otherwise its own top sixteen bits made quiet. The operand is unpacked,
/// so FZ flushes a denormal one, raising Input Denormal.
/// </summary>
let private toBFloat bld ctl src =
  let src = fpFlushIn bld ctl 32<rt> src
  let rounded = tmpVar bld 16<rt>
  let up = bfRoundsUp (roundingMode bld ctl) src
  append bld { rounded := AST.xthi 16<rt> src .+ AST.zext 16<rt> up }
  let quieted = AST.xthi 16<rt> src .| numU32 0x40u 16<rt>
  let dn = defaultNaNMode bld ctl
  let nan = AST.ite dn (numU32 0x7fc0u 16<rt>) quieted
  let finite = AST.not (isNaN 32<rt> src .| isInfinity 32<rt> src)
  let inexact = finite .& ((src .& numU32 0xffffu 32<rt>) != AST.num0 32<rt>)
  let magnitude = rounded .& numU32 0x7fffu 16<rt>
  let overflow = finite .& (magnitude == numU32 0x7f80u 16<rt>)
  let tiny = (src .& numU32 0x7f800000u 32<rt>) == AST.num0 32<rt>
  fpBits (isSNaN 32<rt> src) fpNone overflow (tiny .& inexact) inexact
  |> fpRecord bld
  AST.ite (isNaN 32<rt> src) nan rounded

/// VCVT from singles to bfloat16s: Qm's four into Dd, on the standard value.
let vcvt (ins: Instruction) bld =
  conditional ins bld (fun () ->
    let struct (dst, src) = getTwoOprs ins
    readLanes bld 32 src
    |> Array.map (toBFloat bld StandardValue)
    |> writeLanes bld dst)

/// Whether an instruction converts singles to bfloat16s.
let converts (ins: Instruction) =
  match ins.SIMDTyp with
  | Some(TwoDT(BF16, SIMDTypF32)) -> true
  | _ -> false

/// VCVTB and VCVTT from a single to a bfloat16, on FPSCR, into the bottom or
/// the top half of Sd, the other half left as it was.
let vcvtHalf (ins: Instruction) bld isTop =
  conditional ins bld (fun () ->
    let struct (d, s) = transTwoOprs ins bld
    let h = toBFloat bld FPSCRValue s
    let mask = numU32 (if isTop then 0xffffu else 0xffff0000u) 32<rt>
    let shift = numI32 (if isTop then 16 else 0) 32<rt>
    append bld { d := (d .& mask) .| (AST.zext 32<rt> h << shift) })

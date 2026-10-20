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
/// The vector facility's floating-point instructions, on four singles at a
/// time. They round to nearest whatever FPSCR[RN] holds, so each rounding
/// operation is enclosed in a RoundCtrl naming that direction; they set no
/// FPSCR bit at all. A NaN answer follows the ISA's order -- the first NaN
/// operand, quieted, or else the standard QNaN 0x7FC00000 for an invalid
/// operation -- rather than whatever the host's arithmetic hands back. With
/// VSCR[NJ] set, a denormal operand is read as a zero of its sign and a
/// denormal result written as one.
/// </summary>
module internal B2R2.FrontEnd.PPC.VectorFloatLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.VectorElements
open B2R2.FrontEnd.PPC.VectorIntegerLifter

/// VSCR[NJ], the non-Java mode bit, bit 16 of VSCR as it is kept here.
let private nonJava bld = AST.extract (regVar bld Register.VSCR) 1<rt> 16

/// Whether a single is a denormal: its exponent zero and its fraction not.
let private isDenormal x =
  let exponent = x .& numU32 0x7f800000u 32<rt>
  let fraction = x .& numU32 0x007fffffu 32<rt>
  (exponent == AST.num0 32<rt>) .& (fraction != AST.num0 32<rt>)

/// A single with a denormal replaced by a zero of its sign where NJ is set.
let private flush nj x =
  AST.ite (nj .& isDenormal x) (x .& numU32 0x80000000u 32<rt>) x

/// The standard QNaN of the vector facility.
let private standardQNaN = numU32 0x7fc00000u 32<rt>

/// An answer settled by the ISA's NaN rules: the first operand that is a
/// NaN, in the order given, quieted; else a NaN the operation itself made is
/// the standard QNaN.
let private settleNaN operands r =
  let quiet x = x .| numU32 0x00400000u 32<rt>
  let made = AST.ite (IEEE754Single.isNaN r) standardQNaN r
  List.foldBack (fun x acc ->
    AST.ite (IEEE754Single.isNaN x) (quiet x) acc) operands made

/// An expression rounded to nearest, ties to even, whatever FPSCR[RN] says.
let private nearest e =
  AST.roundCtrl (AST.roundingMode RoundingMode.ToNearestEven) e

/// The singles of a vector register, flushed as NJ says.
let private singlesOf bld nj opr =
  elementsOf bld 32<rt> opr |> Array.map (flush nj)

/// The NJ bit, held for an instruction that reads it more than once.
let private heldNonJava bld =
  let nj = tmpVar bld 1<rt>
  append bld { nj := nonJava bld }
  nj

/// vaddfp/vsubfp: the sum or difference of each pair of singles.
let vecFloatBinary ins bld op =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let nj = heldNonJava bld
    let a = singlesOf bld nj o2
    let b = singlesOf bld nj o3
    Array.map2 (fun x y -> flush nj (settleNaN [ x; y ] (nearest (op x y)))) a b
    |> putElements bld o1
  }

/// vmaddfp/vnmsubfp vD, vA, vC, vB: vA times vC plus vB -- or the negation of
/// vA times vC minus vB -- as one fused operation rounded once; the NaN taken
/// is vA's, then vB's, then vC's. The negation of a NaN is left alone.
let vecFloatMultiplyAdd ins bld negate =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let nj = heldNonJava bld
    let a = singlesOf bld nj o2
    let c = singlesOf bld nj o3
    let b = singlesOf bld nj o4
    let flags = numI32 (if negate then 2 else 0) 8<rt>
    let signBit = numU32 0x80000000u 32<rt>
    Array.init 4 (fun i ->
      let fused = nearest (AST.app "FMA32" [ a[i]; c[i]; b[i]; flags ] 32<rt>)
      let r = settleNaN [ a[i]; b[i]; c[i] ] fused
      let negated = AST.ite (IEEE754Single.isNaN r) r (r <+> signBit)
      flush nj (if negate then negated else r))
    |> putElements bld o1
  }

/// vmaxfp/vminfp: the larger (or smaller) of each pair of singles, +0 being
/// the larger of the two zeros, a NaN operand giving a QNaN.
let vecFloatMaxMin ins bld isMax =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let nj = heldNonJava bld
    let a = singlesOf bld nj o2
    let b = singlesOf bld nj o3
    Array.map2 (fun x y ->
      let pick, tie = if isMax then AST.fgt x y, x .& y else AST.flt x y, x .| y
      let r = AST.ite pick x (AST.ite (AST.feq x y) tie y)
      flush nj (settleNaN [ x; y ] r)) a b
    |> putElements bld o1
  }

/// vrefp/vrsqrtefp: the reciprocal, or the reciprocal square root, of each
/// single, computed exactly and rounded once for each operation it takes.
let vecFloatReciprocal ins bld root =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let nj = heldNonJava bld
    let one = numU32 0x3f800000u 32<rt>
    singlesOf bld nj o2
    |> Array.map (fun x ->
      let d = if root then nearest (AST.fsqrt x) else x
      flush nj (settleNaN [ x ] (nearest (AST.fdiv one d))))
    |> putElements bld o1
  }

/// vexptefp/vlogefp: 2 raised to each single, or the base-2 logarithm of it.
let vecFloatExpLog ins bld isExp =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let nj = heldNonJava bld
    let two = numU32 0x40000000u 32<rt>
    singlesOf bld nj o2
    |> Array.map (fun x ->
      let r = if isExp then AST.fpow two x else AST.flog two x
      flush nj (settleNaN [ x ] (nearest r)))
    |> putElements bld o1
  }

/// vrfin/vrfiz/vrfip/vrfim: each single rounded to an integral value in the
/// direction the instruction names.
let vecFloatRound ins bld mode =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let nj = heldNonJava bld
    singlesOf bld nj o2
    |> Array.map (fun x ->
      settleNaN [ x ] (AST.roundToIntegral mode 32<rt> x))
    |> putElements bld o1
  }

/// vcfsx/vcfux vD, vB, UIM: each signed or unsigned word converted to the
/// nearest single and divided by 2^UIM, which a nonzero result takes exactly
/// as a smaller exponent.
let vecFloatFromInt ins bld signed =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let scale = numU32 (getImmValue o3 <<< 23) 32<rt>
    let kind = if signed then CastKind.SIntToFloat else CastKind.UIntToFloat
    elementsOf bld 32<rt> o2
    |> Array.map (fun w ->
      let r = nearest (AST.cast kind 32<rt> w)
      AST.ite (w == AST.num0 32<rt>) (AST.num0 32<rt>) (r .- scale))
    |> putElements bld o1
  }

/// The word a single converts to under VSCR's saturating rules, the
/// conversion made exactly on the single's bits: UIM added to its exponent,
/// the fraction shifted into place and truncated toward zero. A NaN gives 0;
/// a value past the word's range, an infinity included, gives the nearer end
/// and saturates; a negative value an unsigned word cannot hold gives 0 and
/// saturates, unless it lies between -1 and 0 and so truncates to 0 anyway.
let private floatToWord signed uim (x: Expr) =
  let exponent = AST.zext 32<rt> (AST.extract x 8<rt> 23)
  let e = exponent .+ numI32 (int uim - 127) 32<rt>
  let negative = AST.xthi 1<rt> x
  let nan = IEEE754Single.isNaN x
  let significand = (x .& numU32 0x007fffffu 32<rt>) .| numU32 0x800000u 32<rt>
  let wide = AST.zext 64<rt> significand << numI32 32 64<rt>
  let magnitude =
    AST.xtlo 32<rt> (wide >> AST.zext 64<rt> (numI32 55 32<rt> .- e))
  let limit = if signed then 30 else 31
  let large = (e ?> numI32 limit 32<rt>) .| IEEE754Single.isInfinity x
  let small = e ?< AST.num0 32<rt>
  let zero = AST.num0 32<rt>
  if signed then
    let minWord = numU32 0x80000000u 32<rt>
    let top = AST.ite negative minWord (numU32 0x7fffffffu 32<rt>)
    let value = AST.ite negative (AST.neg magnitude) magnitude
    let inRange = AST.ite small zero value
    let r = AST.ite nan zero (AST.ite large top inRange)
    struct (r, AST.not nan .& large)
  else
    let top = AST.ite negative zero (numU32 0xffffffffu 32<rt>)
    let negativeSat = AST.not small .& negative
    let inRange = AST.ite (small .| negative) zero magnitude
    let r = AST.ite nan zero (AST.ite large top inRange)
    struct (r, AST.not nan .& (large .| negativeSat))

/// vctsxs/vctuxs vD, vB, UIM: each single times 2^UIM converted to a signed
/// or unsigned word toward zero, saturating and setting VSCR[SAT] where it
/// does.
let vecFloatToInt ins bld signed =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let uim = getImmValue o3
    elementsOf bld 32<rt> o2
    |> Array.map (floatToWord signed uim)
    |> putSaturated bld o1
  }

/// vcmpeqfp/vcmpgefp/vcmpgtfp: each pair of singles compared, a NaN making
/// the compare false.
let vecFloatCompare ins bld rel record =
  let nj = nonJava bld
  let flushed a b = rel (flush nj a) (flush nj b)
  vecCompareElements ins bld 32<rt> flushed record

/// vcmpbfp[.]: whether each single of vA lies within the bounds -vB .. vB,
/// as two bits at the top of its word: the first set where it is not at most
/// vB, the second where it is not at least -vB, both where either is a NaN.
/// The record form sets CR6 to 0b0010 where every single is within bounds.
let vcmpbfp ins bld record =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let nj = heldNonJava bld
    let a = singlesOf bld nj o2
    let b = singlesOf bld nj o3
    let signBit = numU32 0x80000000u 32<rt>
    let words =
      Array.map2 (fun x y ->
        let above = AST.not (AST.fle x y)
        let below = AST.not (AST.fge x (y <+> signBit))
        AST.concat (AST.concat above below) (AST.num0 30<rt>)) a b
    let held = Array.init 4 (fun _ -> tmpVar bld 32<rt>)
    for i in 0 .. 3 do held[i] := words[i]
    putElements bld o1 held
    if record then
      let zero = AST.num0 32<rt>
      regVar bld Register.CR6_0 := AST.b0
      regVar bld Register.CR6_1 := AST.b0
      regVar bld Register.CR6_2 :=
        Array.map (fun w -> w == zero) held |> Array.reduce (.&)
      regVar bld Register.CR6_3 := AST.b0
    else
      ()
  }

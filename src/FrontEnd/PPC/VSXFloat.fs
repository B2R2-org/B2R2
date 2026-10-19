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
/// Lifts the VSX floating-point arithmetic ISA 2.07 to 3.1 added beyond what
/// VectorLifter does: the vector single-precision forms and the double ones
/// that were missing, the multiply-adds, the estimates, the roundings to an
/// integral value, maximum and minimum, and the sign operations.
///
/// The arithmetic follows the host-op pattern the PPC lifter uses: the
/// operation is the IR's own floating-point operation at the lane's width,
/// which the evaluator rounds once in the direction FPSCR[RN] names, and what
/// the host makes of a NaN is settled afterwards. FPSCR's exception bits are
/// not written, as they are not by the rest of the PPC lifter; FPRF is, by
/// the scalar forms that set it.
/// </summary>
module internal B2R2.FrontEnd.PPC.VSXFloat

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.VSXLifter

/// The fields of a binary floating-point lane: its width, and how many bits
/// its exponent and its fraction take.
type Lane =
  { Width: RegType
    ExpBits: int
    FracBits: int }

/// A single-precision lane.
let single = { Width = 32<rt>; ExpBits = 8; FracBits = 23 }

/// A double-precision lane.
let double = { Width = 64<rt>; ExpBits = 11; FracBits = 52 }

/// A constant of a lane's width.
let private bits lane (v: uint64) = numU64 v lane.Width

/// The sign bit of a lane.
let signOf lane = bits lane (1UL <<< (int lane.Width - 1))

/// The exponent field of a lane, in place.
let private expMask lane =
  bits lane (((1UL <<< lane.ExpBits) - 1UL) <<< lane.FracBits)

/// The fraction field of a lane, in place.
let private fracMask lane = bits lane ((1UL <<< lane.FracBits) - 1UL)

/// The bit that tells a quiet NaN from a signalling one.
let private quietBit lane = bits lane (1UL <<< (lane.FracBits - 1))

/// Whether a lane holds a NaN.
let isNaNOf lane x =
  ((x .& expMask lane) == expMask lane)
  .& ((x .& fracMask lane) != AST.num0 lane.Width)

/// Whether a lane holds a signalling NaN.
let isSNaNOf lane x =
  isNaNOf lane x .& ((x .& quietBit lane) == AST.num0 lane.Width)

/// Whether a lane holds a quiet NaN.
let isQNaNOf lane x =
  isNaNOf lane x .& ((x .& quietBit lane) != AST.num0 lane.Width)

/// Whether a lane holds a zero of either sign.
let isZeroOf lane x =
  (x .& AST.not (signOf lane)) == AST.num0 lane.Width

/// A NaN made quiet, its payload kept.
let quietOf lane x = x .| quietBit lane

/// The positive default quiet NaN of a lane.
let defaultNaNOf lane = expMask lane .| quietBit lane

/// The lane format of an element size.
let laneOf (esize: RegType) = if esize = 32<rt> then single else double

/// The lanes of a register held as two halves, element 0 first: two
/// doublewords or four words.
let lanesOf (esize: RegType) (h: Expr) (l: Expr) =
  if esize = 64<rt> then
    [| h; l |]
  else
    [| AST.xthi 32<rt> h
       AST.xtlo 32<rt> h
       AST.xthi 32<rt> l
       AST.xtlo 32<rt> l |]

/// Writes lanes, element 0 first, into a register's halves through
/// temporaries, so a source that is also the target is read whole first.
let writeLanes bld (esize: RegType) (dh: Expr) (dl: Expr) (r: Expr[]) =
  let struct (th, tl) = tmpVars2 bld 64<rt>
  if esize = 64<rt> then
    append bld {
      th := r[0]
      tl := r[1]
    }
  else
    append bld {
      th := AST.concat r[0] r[1]
      tl := AST.concat r[2] r[3]
    }
  append bld {
    dh := th
    dl := tl
  }

/// The registers an operation reads, after the one it writes.
let private sourcesOf (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) -> o1, [ o2; o3 ]
  | TwoOperands(o1, o2) -> o1, [ o2 ]
  | _ -> raise InvalidOperandException

/// An element-wise vector operation, "xT, xA, xB" or "xT, xB": each lane of
/// xT computed by f from the matching lanes of the sources, in order.
let vectorMap ins bld esize f =
  lift bld ins {
    let dst, srcs = sourcesOf ins
    let struct (dh, dl) = vsrOf bld dst
    let lanes =
      srcs
      |> List.map (fun o ->
        let struct (h, l) = vsrOf bld o
        lanesOf esize h l)
    let n = if esize = 64<rt> then 2 else 4
    let lane = laneOf esize
    let results =
      Array.init n (fun i -> f lane (lanes |> List.map (fun ls -> ls[i])))
    writeLanes bld esize dh dl results
  }

/// A scalar double operation, "xT, xA, xB" or "xT, xB": doubleword 0 of xT
/// from doubleword 0 of the sources, doubleword 1 cleared, and FPRF set
/// where the instruction sets it.
let scalarMap ins bld setsFPRF f =
  lift bld ins {
    let dst, srcs = sourcesOf ins
    let struct (dh, dl) = vsrOf bld dst
    let xs =
      srcs
      |> List.map (fun o ->
        let struct (h, _) = vsrOf bld o
        h)
    let res = tmpVar bld 64<rt>
    res := f double xs
    dh := res
    dl := AST.num0 64<rt>
    if setsFPRF then setFPRF bld dh else ()
  }

/// An answer settled by the architecture's NaN rules, not by what the host
/// makes of a NaN: the first operand that is a NaN, quieted, or else -- an
/// invalid operation -- the positive default quiet NaN.
let private settleNaN lane (operands: Expr list) res =
  let made = AST.ite (isNaNOf lane res) (defaultNaNOf lane) res
  List.foldBack (fun x acc ->
    AST.ite (isNaNOf lane x) (quietOf lane x) acc) operands made

/// The operand list of a binary operation.
let private two = function
  | [ a; b ] -> struct (a, b)
  | _ -> raise InvalidOperandException

/// The operand of a unary operation.
let private one = function
  | [ b ] -> b
  | _ -> raise InvalidOperandException

/// A binary arithmetic lane: the host operation, the NaN settled after.
/// The first NaN operand comes back quieted, as POWER does.
let arith op lane xs =
  let struct (a, b) = two xs
  settleNaN lane xs (op a b)

/// The square root of a lane.
let squareRoot lane xs = settleNaN lane xs (AST.fsqrt (one xs))

/// The value 1.0 in a lane.
let private oneOf lane =
  if lane.Width = 32<rt> then bits lane 0x3f800000UL
  else bits lane 0x3ff0000000000000UL

/// The reciprocal (isSqrt: of the square root) estimate of a lane. The
/// architecture lets an estimate stray by a part in 16384, which no analysis
/// can usefully model, so the exact answer stands in, as it does for fres.
let estimate isSqrt lane xs =
  let b = one xs
  settleNaN lane xs (AST.fdiv (oneOf lane) (if isSqrt then AST.fsqrt b else b))

/// A NaN quieted, and anything else rounded by the given rounding: a host's
/// rounding to an integral value need not quiet a signalling NaN, which the
/// architecture does.
let private unlessNaN lane round xs =
  let b = one xs
  AST.ite (isNaNOf lane b) (quietOf lane b) (round b)

/// A lane rounded to an integral value in a direction.
let private roundIn mode lane xs =
  unlessNaN lane (AST.roundToIntegral mode lane.Width) xs

/// Rounded to the nearest integral value, ties away from zero.
let awayFromZero lane xs = roundIn RoundingMode.ToNearestAway lane xs

/// Rounded toward -Inf.
let downward lane xs = roundIn RoundingMode.TowardNegative lane xs

/// Rounded toward +Inf.
let upward lane xs = roundIn RoundingMode.TowardPositive lane xs

/// Rounded toward zero.
let towardZero lane xs = roundIn RoundingMode.TowardZero lane xs

/// Rounded in the direction FPSCR[RN] names, which a rounding no RoundCtrl
/// encloses takes.
let byFPSCR lane xs =
  unlessNaN lane (AST.cast CastKind.RoundToIntegral lane.Width) xs

/// The sign operations, which touch only the sign bit, so a NaN is no
/// exception and nothing is raised: 0 clears it, 1 sets it, 2 flips it.
let signOp kind lane xs =
  let b = one xs
  match kind with
  | 0 -> b .& AST.not (signOf lane)
  | 1 -> b .| signOf lane
  | _ -> b <+> signOf lane

/// xvcpsgndp and xvcpsgnsp: the sign of xA on the magnitude of xB.
let copySignOf lane xs =
  let struct (a, b) = two xs
  (a .& signOf lane) .| (b .& AST.not (signOf lane))

/// <summary>
/// bfp_MAXIMUM and bfp_MINIMUM (Book I 7.3.2): a quiet NaN loses to a
/// number, a signalling one wins and comes back quiet, x being preferred
/// where both are NaNs; otherwise the greater (or lesser), +0 counting as
/// greater than -0, which for two zeroes is the bitwise and (or or) of them.
/// </summary>
let maxMin isMax lane xs =
  let struct (x, y) = two xs
  let ordered = if isMax then AST.fgt x y else AST.flt x y
  let zeroes = isZeroOf lane x .& isZeroOf lane y
  let both = if isMax then x .& y else x .| y
  let pick = AST.ite zeroes both (AST.ite ordered x y)
  let fromSNaNY = AST.ite (isSNaNOf lane y) (quietOf lane y) pick
  let fromY = AST.ite (isQNaNOf lane y) x fromSNaNY
  let fromX = AST.ite (isSNaNOf lane x) (quietOf lane x) fromY
  let afterQuietX = AST.ite (isNaNOf lane y) x y
  AST.ite (isQNaNOf lane x) afterQuietX fromX

/// bfp_MAXIMUM_TYPE_C and bfp_MINIMUM_TYPE_C: y whenever either operand is
/// a NaN, or on a tie; otherwise the greater (or lesser). An ordered
/// comparison with a NaN is false, which is what picks y then.
let maxMinC isMax (_: Lane) xs =
  let struct (x, y) = two xs
  AST.ite (if isMax then AST.fgt x y else AST.flt x y) x y

/// bfp_MAXIMUM_TYPE_J and bfp_MINIMUM_TYPE_J: a NaN in x, then one in y,
/// passes as it is; two zeroes give +0 (or -0) if either is; otherwise the
/// greater (or lesser), y on a tie.
let maxMinJ isMax lane xs =
  let struct (x, y) = two xs
  let ordered = if isMax then AST.fgt x y else AST.flt x y
  let zeroes = isZeroOf lane x .& isZeroOf lane y
  let both = if isMax then x .& y else x .| y
  let pick = AST.ite zeroes both (AST.ite ordered x y)
  AST.ite (isNaNOf lane x) x (AST.ite (isNaNOf lane y) y pick)

/// The fused multiply-add of one lane, through the call the scalar forms
/// make: bit 1 of the flags negates the addend.
let private fused lane x y z subtract =
  let f = numU64 (if subtract then 2UL else 0UL) 8<rt>
  let name = if lane.Width = 32<rt> then "FMA32" else "FMA64"
  AST.app name [ x; y; z; f ] lane.Width

/// <summary>
/// One lane of a vector multiply-add. The "a" forms multiply xA by xB and
/// add xT; the "m" forms multiply xA by xT and add xB. Which NaN comes back
/// follows POWER's order -- xA, then the addend, then the other factor --
/// quieted; an invalid operation answers with the default quiet NaN; the
/// negating forms flip the sign of the rounded result, a NaN excepted.
/// </summary>
let private mulAddLane bld lane targetIsFactor subtract negate a b t =
  let res = tmpVar bld lane.Width
  let x, y, z = if targetIsFactor then a, t, b else a, b, t
  let addend, other = if targetIsFactor then b, t else t, b
  let quietIfNaN v orElse = AST.ite (isNaNOf lane v) (quietOf lane v) orElse
  let chosen = quietIfNaN a (quietIfNaN addend (quietOf lane other))
  let noNaN = AST.not (isNaNOf lane a .| isNaNOf lane b .| isNaNOf lane t)
  append bld {
    res := fused lane x y z subtract
    res := AST.ite (isNaNOf lane res) (defaultNaNOf lane) res
    res := AST.ite noNaN res chosen
  }
  if negate then AST.ite (isNaNOf lane res) res (res <+> signOf lane)
  else res

/// The vector multiply-adds, over lanes of the given size.
let vectorMulAdd ins bld esize targetIsFactor subtract negate =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (th, tl) = vsrOf bld o1
    let struct (ah, al) = vsrOf bld o2
    let struct (bh, bl) = vsrOf bld o3
    let lane = laneOf esize
    let ts = lanesOf esize th tl
    let xs = lanesOf esize ah al
    let ys = lanesOf esize bh bl
    let results =
      Array.init ts.Length (fun i ->
        mulAddLane bld lane targetIsFactor subtract negate xs[i] ys[i] ts[i])
    writeLanes bld esize th tl results
  }

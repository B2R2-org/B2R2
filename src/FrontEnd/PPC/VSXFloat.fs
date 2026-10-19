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

/// The all-ones or all-zeroes a compare writes into a lane.
let private maskOf lane cond =
  AST.ite cond (AST.not (AST.num0 lane.Width)) (AST.num0 lane.Width)

/// <summary>
/// The vector compares, "xT, xA, xB": each lane all ones where the matching
/// lanes compare true and all zeroes where not, a NaN comparing false. The
/// record forms also say in CR6 whether every lane compared true (bit 0) or
/// none did (bit 2).
/// </summary>
let vectorCompare ins bld esize rel record =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let struct (ah, al) = vsrOf bld o2
    let struct (bh, bl) = vsrOf bld o3
    let lane = laneOf esize
    let xs = lanesOf esize ah al
    let ys = lanesOf esize bh bl
    let conds = Array.init xs.Length (fun i -> tmpVar bld 1<rt>)
    for i in 0 .. xs.Length - 1 do
      conds[i] := rel xs[i] ys[i]
    writeLanes bld esize dh dl (Array.map (maskOf lane) conds)
    if record then
      let all = Array.reduce (.&) conds
      let none = Array.reduce (.&) (Array.map AST.not conds)
      regVar bld Register.CR6_0 := all
      regVar bld Register.CR6_1 := AST.b0
      regVar bld Register.CR6_2 := none
      regVar bld Register.CR6_3 := AST.b0
    else
      ()
  }

/// xscmpeqdp, xscmpgtdp and xscmpgedp: doubleword 0 of xT all ones where the
/// doubles in doubleword 0 of xA and xB compare true, doubleword 1 cleared.
let scalarCompare ins bld rel =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let struct (ah, _) = vsrOf bld o2
    let struct (bh, _) = vsrOf bld o3
    dh := maskOf double (rel ah bh)
    dl := AST.num0 64<rt>
  }

/// The four bits of the CR field an operand names, and FPSCR's FPCC.
let private crAndFPCC bld opr =
  let lt, gt, eq, un =
    match opr with
    | OprReg reg -> transCRxToExpr bld reg
    | _ -> raise InvalidOperandException
  let fpscr = regVar bld Register.FPSCR
  let fpcc = [| for pos in [ 15; 14; 13; 12 ] -> AST.extract fpscr 1<rt> pos |]
  struct ([| lt; gt; eq; un |], fpcc)

/// Writes four bits to a CR field and, where asked, to FPCC.
let private writeField bld opr withFPCC (bits: Expr[]) =
  let struct (cr, fpcc) = crAndFPCC bld opr
  let vals = Array.init 4 (fun _ -> tmpVar bld 1<rt>)
  append bld {
    for i in 0 .. 3 do
      vals[i] := bits[i]
    for i in 0 .. 3 do
      cr[i] := vals[i]
  }
  if withFPCC then
    append bld {
      for i in 0 .. 3 do
        fpcc[i] := vals[i]
    }
  else
    ()

/// <summary>
/// xscmpodp: the ordered compare of the doubles in doubleword 0 of xA and
/// xB into a CR field and FPCC, as xscmpudp does. A signalling NaN sets
/// VXSNAN, and VXVC with it unless VE is set; a quiet one sets VXVC.
/// </summary>
let xscmpodp ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (a, _) = vsrOf bld o2
    let struct (b, _) = vsrOf bld o3
    let un = isNaNOf double a .| isNaNOf double b
    let snan = isSNaNOf double a .| isSNaNOf double b
    let fpscr = regVar bld Register.FPSCR
    let ve = AST.extract fpscr 1<rt> 7
    let vxsnan = AST.extract fpscr 1<rt> 24
    let vxvc = AST.extract fpscr 1<rt> 19
    let lt = AST.not un .& AST.flt a b
    let gt = AST.not un .& AST.fgt a b
    let eq = AST.not un .& AST.not (AST.flt a b) .& AST.not (AST.fgt a b)
    writeField bld o1 true [| lt; gt; eq; un |]
    vxsnan := vxsnan .| snan
    vxvc := vxvc .| AST.ite snan (AST.not ve) un
  }

/// xscmpexpdp: the exponent fields of the doubles in doubleword 0 of xA and
/// xB compared as unsigned numbers into a CR field and FPCC, unordered where
/// either is a NaN.
let xscmpexpdp ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (a, _) = vsrOf bld o2
    let struct (b, _) = vsrOf bld o3
    let ea = AST.extract a 11<rt> 52
    let eb = AST.extract b 11<rt> 52
    let un = isNaNOf double a .| isNaNOf double b
    let lt = AST.not un .& (ea .< eb)
    let gt = AST.not un .& (ea .> eb)
    let eq = AST.not un .& (ea == eb)
    writeField bld o1 true [| lt; gt; eq; un |]
  }

/// The exponent fields of a lane's format: how wide, and the bias.
let private expWidth lane = regTypeOf lane.ExpBits

let private bias lane = (1 <<< (lane.ExpBits - 1)) - 1

/// The unbiased exponent of a lane, as a signed 16-bit number: the biased
/// field less the bias, so a zero or a denormal reads as -bias.
let private unbiased lane x =
  let e = AST.extract x (expWidth lane) lane.FracBits
  AST.zext 16<rt> e .- numI32 (bias lane) 16<rt>

/// Whether a lane holds an infinity.
let private isInfOf lane x =
  AST.extract x (expWidth lane) lane.FracBits
  == AST.not (AST.num0 (expWidth lane))
  .& (AST.extract x (regTypeOf lane.FracBits) 0
      == AST.num0 (regTypeOf lane.FracBits))

/// Whether a lane holds a denormal.
let private isDenOf lane x =
  (AST.extract x (expWidth lane) lane.FracBits == AST.num0 (expWidth lane))
  .& AST.not (isZeroOf lane x)

/// A signed 16-bit constant.
let private s16 v = numI32 v 16<rt>

/// <summary>
/// The software-divide test of one pair of lanes (xstdivdp, xvtdivdp,
/// xvtdivsp): fe where the quotient needs a software fix-up -- an operand
/// that is a NaN or an infinity, a zero divisor, exponents so far apart or
/// so extreme that the estimate-and-refine sequence would over- or
/// underflow -- and fg where an operand is an infinity or the divisor a
/// zero or a denormal. The thresholds are the format's.
/// </summary>
let private divideTest lane a b =
  let ea = unbiased lane a
  let eb = unbiased lane b
  let isDouble = lane.Width = 64<rt>
  let lo, hi = if isDouble then -1022, 1021 else -126, 125
  let far, near, tiny = if isDouble then 1023, -1021, -970 else 127, -125, -103
  let live = AST.not (isZeroOf lane a)
  let fe =
    isNaNOf lane a .| isInfOf lane a .| isNaNOf lane b .| isInfOf lane b
    .| isZeroOf lane b .| (eb ?<= s16 lo) .| (eb ?>= s16 hi)
    .| (live .& ((ea .- eb) ?>= s16 far))
    .| (live .& ((ea .- eb) ?<= s16 near))
    .| (live .& (ea ?<= s16 tiny))
  let fg =
    isInfOf lane a .| isInfOf lane b .| isZeroOf lane b .| isDenOf lane b
  struct (fe, fg)

/// The software-square-root test of one lane (xstsqrtdp, xvtsqrtdp,
/// xvtsqrtsp): fe for a zero, a NaN, an infinity, a negative number or an
/// exponent too small, fg for a zero, an infinity or a denormal.
let private sqrtTest lane b =
  let eb = unbiased lane b
  let tiny = if lane.Width = 64<rt> then -970 else -103
  let negative = AST.extract b 1<rt> (int lane.Width - 1)
  let fe =
    isNaNOf lane b .| isInfOf lane b .| isZeroOf lane b .| negative
    .| (eb ?<= s16 tiny)
  let fg = isInfOf lane b .| isZeroOf lane b .| isDenOf lane b
  struct (fe, fg)

/// The lanes a test reads: element 0 alone for the scalar forms.
let private testLanes esize scalar (h: Expr) l =
  if scalar then [| h |] else lanesOf esize h l

/// <summary>
/// The software divide and square-root tests, "BF, xA, xB" and "BF, xB":
/// CR field BF set to 0b1 || fg || fe || 0b0, fe and fg gathered over every
/// lane tested.
/// </summary>
let softwareTest (ins: Instruction) bld esize scalar isDivide =
  lift bld ins {
    let lane = laneOf esize
    let field, flags =
      match ins.Operands with
      | ThreeOperands(f, o2, o3) when isDivide ->
        let struct (ah, al) = vsrOf bld o2
        let struct (bh, bl) = vsrOf bld o3
        let xs = testLanes esize scalar ah al
        let ys = testLanes esize scalar bh bl
        f, Array.map2 (divideTest lane) xs ys
      | TwoOperands(f, o2) ->
        let struct (bh, bl) = vsrOf bld o2
        f, Array.map (sqrtTest lane) (testLanes esize scalar bh bl)
      | _ ->
        raise InvalidOperandException
    let fe = flags |> Array.map (fun struct (e, _) -> e) |> Array.reduce (.|)
    let fg = flags |> Array.map (fun struct (_, g) -> g) |> Array.reduce (.|)
    writeField bld field false [| AST.b1; fg; fe; AST.b0 |]
  }

/// The classes a data-class mask names, bit 0 (the mask's highest) first:
/// NaN, +Inf, -Inf, +0, -0, +denormal, -denormal; given the class tests of
/// a value, whether it is in any class the mask selects.
let private classMatch dcmx sign nan inf zero den =
  let positive = AST.not sign
  [| nan
     inf .& positive
     inf .& sign
     zero .& positive
     zero .& sign
     den .& positive
     den .& sign |]
  |> Array.indexed
  |> Array.filter (fun (k, _) -> (dcmx >>> (6 - k)) &&& 1 = 1)
  |> Array.map snd
  |> Array.fold (.|) AST.b0

/// Whether a lane is in a class the mask selects.
let private laneMatch lane dcmx x =
  let sign = AST.extract x 1<rt> (int lane.Width - 1)
  let nan, inf = isNaNOf lane x, isInfOf lane x
  let zero, den = isZeroOf lane x, isDenOf lane x
  classMatch dcmx sign nan inf zero den

/// The immediate operand at the end of an instruction, as an int.
let private immOf = function
  | OprImm n -> int n
  | _ -> raise InvalidOperandException

/// <summary>
/// xvtstdcdp and xvtstdcsp, "xT, xB, DCMX": each lane of xT all ones where
/// the matching lane of xB is in a class DCMX selects, all zeroes where not.
/// </summary>
let vectorTestClass ins bld esize =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let struct (bh, bl) = vsrOf bld o2
    let lane = laneOf esize
    let dcmx = immOf o3
    let results =
      lanesOf esize bh bl
      |> Array.map (fun x -> maskOf lane (laneMatch lane dcmx x))
    writeLanes bld esize dh dl results
  }

/// <summary>
/// xststdcdp and xststdcsp, "BF, xB, DCMX": the sign of the double in
/// doubleword 0 of xB, whether it is in a class DCMX selects, and -- for
/// xststdcsp -- whether no single represents it, into a CR field and FPCC.
/// xststdcsp reads the classes as the value would be in single precision:
/// an exponent below the single range is a denormal there.
/// </summary>
let scalarTestClass ins bld isSingle =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (b, _) = vsrOf bld o2
    let dcmx = immOf o3
    let sign = AST.extract b 1<rt> 63
    let exp = AST.extract b 11<rt> 52
    let tinyForSingle =
      (exp != AST.num0 11<rt>) .& (exp .< numI32 0x381 11<rt>)
    let den =
      if isSingle then isDenOf double b .| tinyForSingle else isDenOf double b
    let nan, inf, zero = isNaNOf double b, isInfOf double b, isZeroOf double b
    let matched = classMatch dcmx sign nan inf zero den
    let narrowed = AST.cast CastKind.FloatCast 32<rt> b
    let back = AST.cast CastKind.FloatCast 64<rt> narrowed
    let payloadLost =
      AST.extract b 29<rt> 0 != AST.num0 29<rt>
    let notSingle =
      if isSingle then AST.ite (isNaNOf double b) payloadLost (back != b)
      else AST.b0
    writeField bld o1 true [| sign; AST.b0; matched; notSingle |]
  }

/// xsiexpdp, "xT, rA, rB": the sign and fraction of rA with the low eleven
/// bits of rB as the exponent, in doubleword 0; doubleword 1 cleared.
let xsiexpdp ins (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vsrOf bld o1
    let ra = AST.zext 64<rt> (transOpr bld o2)
    let rb = AST.zext 64<rt> (transOpr bld o3)
    let keep = numU64 0x800fffffffffffffUL 64<rt>
    let exp = (rb .& numU64 0x7ffUL 64<rt>) << numI32 52 64<rt>
    dh := (ra .& keep) .| exp
    dl := AST.num0 64<rt>
  }

/// xsxexpdp and xsxsigdp, "rT, xB": the exponent field, or the significand
/// with its implicit bit where the value is normal, of the double in
/// doubleword 0 of xB, into a general register.
let scalarExtract ins (bld: ILowUIRBuilder) significand =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let rt = transOpr bld o1
    let struct (b, _) = vsrOf bld o2
    let exp = AST.extract b 11<rt> 52
    let normal = (exp != AST.num0 11<rt>) .& (exp != numI32 0x7ff 11<rt>)
    let fraction = b .& numU64 0xfffffffffffffUL 64<rt>
    let implicit = numU64 (1UL <<< 52) 64<rt>
    let withImplicit = AST.ite normal (fraction .| implicit) fraction
    let value = if significand then withImplicit else AST.zext 64<rt> exp
    rt := AST.xtlo bld.RegType value
  }

/// <summary>
/// xviexpdp and xviexpsp, "xT, xA, xB": each lane the sign and fraction of
/// xA's with the low exponent-width bits of xB's as the exponent.
/// </summary>
let insertExponent lane xs =
  let struct (a, b) = two xs
  let field = (AST.num1 lane.Width << numI32 lane.ExpBits lane.Width)
              .- AST.num1 lane.Width
  let exp = (b .& field) << numI32 lane.FracBits lane.Width
  (a .& AST.not (field << numI32 lane.FracBits lane.Width)) .| exp

/// xvxexpdp and xvxexpsp: each lane's exponent field, zero-extended.
let extractExponent lane xs =
  let b = one xs
  AST.zext lane.Width (AST.extract b (expWidth lane) lane.FracBits)

/// xvxsigdp and xvxsigsp: each lane's fraction with the implicit bit where
/// the value is normal.
let extractSignificand lane xs =
  let b = one xs
  let exp = AST.extract b (expWidth lane) lane.FracBits
  let normal =
    (exp != AST.num0 (expWidth lane))
    .& (exp != AST.not (AST.num0 (expWidth lane)))
  let fraction = AST.zext lane.Width (AST.extract b (regTypeOf lane.FracBits) 0)
  let implicit = AST.num1 lane.Width << numI32 lane.FracBits lane.Width
  AST.ite normal (fraction .| implicit) fraction

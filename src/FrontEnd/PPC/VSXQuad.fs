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
/// Lifts the quad-precision forms of primary opcode 60's neighbour 63: the
/// arithmetic, the compares, the conversions and the operations on a quad's
/// fields. A quad is the whole of a vector register, VSR 32 to 63, read
/// here as one 128-bit value whose high half is doubleword 0.
///
/// LowUIR has no 128-bit floating-point type, so every operation that
/// rounds a quad goes out as a named call -- FADD128, FSUB128, FMUL128,
/// FDIV128, FSQRT128, FMA128, FRINT128, FRND80, FCVT128TO64 and FCVTINT128,
/// specified in lanes/X.md -- with the rounding direction passed in. What
/// does not round is spelt out in the IR: the signs, the fields, the
/// compares, the conversions to an integer, and the exact conversions from
/// a double and from a doubleword. Which NaN an operation answers with is
/// settled in the IR too, in POWER's order, so a named call's own NaN
/// does not matter.
/// </summary>
module internal B2R2.FrontEnd.PPC.VSXQuad

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.VSXLifter

/// A 128-bit constant from its two halves.
let private q128 (hi: uint64) (lo: uint64) =
  let v = (bigint hi <<< 64) ||| bigint lo
  AST.num (BitVector(v, 128<rt>))

/// The sign bit of a quad.
let private signBit = q128 0x8000000000000000UL 0UL

/// The exponent field of a quad, in place.
let private expMask = q128 0x7fff000000000000UL 0UL

/// The fraction field of a quad, in place.
let private fracMask = q128 0x0000ffffffffffffUL 0xffffffffffffffffUL

/// The bit that makes a NaN quiet.
let private quietBit = q128 0x0000800000000000UL 0UL

/// The positive default quiet NaN.
let private defaultNaN = q128 0x7fff800000000000UL 0UL

let private zero128 = AST.num0 128<rt>

let isNaN q = ((q .& expMask) == expMask) .& ((q .& fracMask) != zero128)

let isSNaN q = isNaN q .& ((q .& quietBit) == zero128)

let isQNaN q = isNaN q .& ((q .& quietBit) != zero128)

let isInf q = ((q .& expMask) == expMask) .& ((q .& fracMask) == zero128)

let isZero q = (q .& AST.not signBit) == zero128

let isDenormal q = ((q .& expMask) == zero128) .& AST.not (isZero q)

let private quieted q = q .| quietBit

let private negative q = AST.xthi 1<rt> q

/// The quad in the vector register an operand names.
let quadOf bld opr =
  let struct (h, l) = vsrOf bld opr
  AST.concat h l

/// Writes a quad into the vector register an operand names, through a
/// temporary so a source that is also the target is read first.
let private writeQuad bld opr (q: Expr) =
  let struct (h, l) = vsrOf bld opr
  let t = tmpVar bld 128<rt>
  append bld {
    t := q
    h := AST.xthi 64<rt> t
    l := AST.xtlo 64<rt> t
  }
  t

/// FPRF set to the class and sign of a quad.
let private setFPRF128 bld q =
  let fpscr = regVar bld Register.FPSCR
  let nan = isNaN q
  let zero = isZero q
  let sign = negative q
  let finiteOrInf = AST.not nan .& AST.not zero
  append bld {
    AST.extract fpscr 1<rt> 16 := nan .| isDenormal q .| (zero .& sign)
    AST.extract fpscr 1<rt> 15 := finiteOrInf .& sign
    AST.extract fpscr 1<rt> 14 := finiteOrInf .& AST.not sign
    AST.extract fpscr 1<rt> 13 := zero
    AST.extract fpscr 1<rt> 12 := nan .| isInf q
  }

/// The rounding direction FPSCR[RN] names, as the named calls take it.
let private byFPSCR bld =
  AST.zext 8<rt> (AST.extract (regVar bld Register.FPSCR) 2<rt> 0)

/// The direction an "o" form or a plain one rounds in: to odd (4), or the
/// one FPSCR[RN] names.
let private directionOf bld toOdd =
  if toOdd then numI32 4 8<rt> else byFPSCR bld

/// The first NaN of the operands in the order given, quieted, or the
/// default NaN where none is a NaN but the answer is.
let private settleNaN operands (res: Expr) =
  let rec firstNaN = function
    | [] -> AST.ite (isNaN res) defaultNaN res
    | x :: rest -> AST.ite (isNaN x) (quieted x) (firstNaN rest)
  firstNaN operands

/// The operands of a "vRT, vRA, vRB".
let private three (ins: Instruction) bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  struct (o1, quadOf bld o2, quadOf bld o3)

/// <summary>
/// xsaddqp, xssubqp, xsmulqp and xsdivqp (and their round-to-odd "o"
/// forms): the named call, its NaN settled in POWER's order (vRA, then
/// vRB), the result in vRT and its class in FPRF.
/// </summary>
let arith ins bld name toOdd =
  lift bld ins {
    let struct (dst, a, b) = three ins bld
    let mode = directionOf bld toOdd
    let res = AST.app name [ a; b; mode ] 128<rt>
    let t = writeQuad bld dst (settleNaN [ a; b ] res)
    setFPRF128 bld t
  }

/// xssqrtqp[o]: the square root of vRB, a negative operand being invalid.
let squareRoot ins bld toOdd =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let b = quadOf bld o2
    let mode = directionOf bld toOdd
    let res = AST.app "FSQRT128" [ b; mode ] 128<rt>
    let t = writeQuad bld o1 (settleNaN [ b ] res)
    setFPRF128 bld t
  }

/// <summary>
/// The quad multiply-adds: vRA times vRB plus (or minus) vRT, fused, the
/// negating forms flipping the rounded result's sign, a NaN excepted. A NaN
/// comes back in POWER's order: vRA, then the addend vRT, then vRB.
/// </summary>
let mulAdd ins bld subtract negate toOdd =
  lift bld ins {
    let struct (dst, a, b) = three ins bld
    let t = quadOf bld dst
    let old = tmpVar bld 128<rt>
    let res = tmpVar bld 128<rt>
    let flags = numI32 (if subtract then 2 else 0) 8<rt>
    let mode = directionOf bld toOdd
    old := t
    res := AST.app "FMA128" [ a; b; old; flags; mode ] 128<rt>
    res := settleNaN [ a; old; b ] res
    let flipped = AST.ite (isNaN res) res (res <+> signBit)
    let written = writeQuad bld dst (if negate then flipped else res)
    setFPRF128 bld written
  }

/// xsabsqp, xsnabsqp and xsnegqp: the sign bit cleared (0), set (1) or
/// flipped (2), nothing else touched, NaNs included.
let signOp ins bld kind =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let b = quadOf bld o2
    let res =
      match kind with
      | 0 -> b .& AST.not signBit
      | 1 -> b .| signBit
      | _ -> b <+> signBit
    writeQuad bld o1 res |> ignore
  }

/// xscpsgnqp: the sign of vRA on the rest of vRB.
let copySign ins bld =
  lift bld ins {
    let struct (dst, a, b) = three ins bld
    let res = (a .& signBit) .| (b .& AST.not signBit)
    writeQuad bld dst res |> ignore
  }

/// Whether a is less than b, neither a NaN: two zeroes are equal whatever
/// their signs; otherwise a sign-magnitude comparison.
let private lessThan a b =
  let ma = a .& AST.not signBit
  let mb = b .& AST.not signBit
  let sa = negative a
  let sb = negative b
  let bothZero = (ma == zero128) .& (mb == zero128)
  let bySign = AST.ite (sa != sb) sa (AST.ite sa (ma .> mb) (ma .< mb))
  AST.not bothZero .& bySign

/// Whether a equals b, neither a NaN.
let private equalTo a b = (a == b) .| (isZero a .& isZero b)

/// The all-ones or all-zeroes of a 128-bit mask.
let private maskOf cond = AST.ite cond (AST.not zero128) zero128

/// xscmpeqqp, xscmpgtqp and xscmpgeqp: vRT all ones where the compare is
/// true, a NaN comparing false.
let compareMask ins bld kind =
  lift bld ins {
    let struct (dst, a, b) = three ins bld
    let ordered = AST.not (isNaN a .| isNaN b)
    let cond =
      match kind with
      | 0 -> equalTo a b
      | 1 -> lessThan b a
      | _ -> lessThan b a .| equalTo a b
    writeQuad bld dst (maskOf (ordered .& cond)) |> ignore
  }

/// <summary>
/// The invalid-operation bits a quad compare into a CR field sets: VXSNAN
/// for a signalling NaN; for the ordered compare also VXVC for any NaN,
/// except a signalling one when VE is set.
/// </summary>
let private compareFlags bld ordered a b =
  let fpscr = regVar bld Register.FPSCR
  let vxsnan = AST.extract fpscr 1<rt> 24
  let snan = isSNaN a .| isSNaN b
  append bld { vxsnan := vxsnan .| snan }
  if ordered then
    let vxvc = AST.extract fpscr 1<rt> 19
    let ve = AST.extract fpscr 1<rt> 7
    let un = isNaN a .| isNaN b
    append bld { vxvc := vxvc .| AST.ite snan (AST.not ve) un }
  else
    ()

/// xscmpuqp and xscmpoqp: less-than, greater-than, equal or unordered into a
/// CR field and FPCC.
let compareField ins bld ordered =
  lift bld ins {
    let struct (f, a, b) = three ins bld
    let un = isNaN a .| isNaN b
    let lt = AST.not un .& lessThan a b
    let gt = AST.not un .& lessThan b a
    let eq = AST.not un .& equalTo a b
    VSXFloat.writeField bld f true [| lt; gt; eq; un |]
    compareFlags bld ordered a b
  }

/// xscmpexpqp: the exponent fields compared as unsigned numbers, unordered
/// where either quad is a NaN.
let compareExponents ins bld =
  lift bld ins {
    let struct (f, a, b) = three ins bld
    let ea = AST.extract a 15<rt> 112
    let eb = AST.extract b 15<rt> 112
    let un = isNaN a .| isNaN b
    let lt = AST.not un .& (ea .< eb)
    let gt = AST.not un .& (ea .> eb)
    let eq = AST.not un .& (ea == eb)
    VSXFloat.writeField bld f true [| lt; gt; eq; un |]
  }

/// xsmaxcqp and xsmincqp: vRB where either is a NaN or on a tie, otherwise
/// the greater (or lesser).
let maxMinC ins bld isMax =
  lift bld ins {
    let struct (dst, a, b) = three ins bld
    let picked = if isMax then lessThan b a else lessThan a b
    let ordered = AST.not (isNaN a .| isNaN b)
    writeQuad bld dst (AST.ite (ordered .& picked) a b) |> ignore
  }

/// The immediate operand an instruction carries, as an int.
let private immOf = function
  | OprImm n -> int n
  | _ -> raise InvalidOperandException

/// <summary>
/// xststdcqp, "BF, vRB, DCMX": the sign of the quad in vRB, 0, whether it
/// is in a class DCMX selects (bit 0 the highest: NaN, +Inf, -Inf, +0, -0,
/// +denormal, -denormal), and 0, into a CR field and FPCC.
/// </summary>
let testClass ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let b = quadOf bld o2
    let dcmx = immOf o3
    let sign = negative b
    let positive = AST.not sign
    let classes =
      [| isNaN b
         isInf b .& positive
         isInf b .& sign
         isZero b .& positive
         isZero b .& sign
         isDenormal b .& positive
         isDenormal b .& sign |]
    let matched =
      classes
      |> Array.indexed
      |> Array.filter (fun (k, _) -> (dcmx >>> (6 - k)) &&& 1 = 1)
      |> Array.map snd
      |> Array.fold (.|) AST.b0
    VSXFloat.writeField bld o1 true [| sign; AST.b0; matched; AST.b0 |]
  }

/// A doubleword moved into a quad's doubleword 0, doubleword 1 cleared.
let private inDoubleword0 (d: Expr) = AST.zext 128<rt> d << numI32 64 128<rt>

/// xsxexpqp: the exponent field of vRB, zero-extended into doubleword 0.
let extractExponent ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let b = quadOf bld o2
    let exp = AST.zext 64<rt> (AST.extract b 15<rt> 112)
    writeQuad bld o1 (inDoubleword0 exp) |> ignore
  }

/// The implicit bit of a quad's significand.
let private implicitBit = q128 0x0001000000000000UL 0UL

/// Whether a quad is normal: its exponent field neither zero nor all ones.
let private isNormal q =
  ((q .& expMask) != zero128) .& ((q .& expMask) != expMask)

/// xsxsigqp: the fraction of vRB with the implicit bit where it is normal.
let extractSignificand ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let b = quadOf bld o2
    let frac = b .& fracMask
    let res = AST.ite (isNormal b) (frac .| implicitBit) frac
    writeQuad bld o1 res |> ignore
  }

/// xsiexpqp: the sign and fraction of vRA with the low 15 bits of vRB's
/// doubleword 0 as the exponent field.
let insertExponent ins bld =
  lift bld ins {
    let struct (dst, a, b) = three ins bld
    let exp = AST.zext 128<rt> (AST.extract b 15<rt> 64)
    let res = (a .& AST.not expMask) .| (exp << numI32 112 128<rt>)
    writeQuad bld dst res |> ignore
  }

/// <summary>
/// A 64-bit magnitude, nonzero, as a quad's exponent field and fraction: it
/// is normalized by its leading zeroes, the leading one becoming the
/// implicit bit (shifted to bit 112 and masked off), so the conversion is
/// exact. top is the exponent the magnitude's bit 63 stands for.
/// </summary>
let private normalized (mag: Expr) top =
  let lz = VectorLifter.countLeadingZerosOf 64<rt> mag
  let shift = AST.zext 128<rt> lz .+ numI32 49 128<rt>
  let frac = (AST.zext 128<rt> mag << shift) .& fracMask
  let biased = numI32 (16383 + top) 64<rt> .- lz
  (AST.zext 128<rt> biased << numI32 112 128<rt>) .| frac

/// <summary>
/// xscvdpqp: the double in doubleword 0 of vRB, exactly as a quad: a normal
/// one by its fields, a denormal one normalized, a signalling NaN quieted.
/// FPRF is set.
/// </summary>
let fromDouble ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let d = AST.xthi 64<rt> (quadOf bld o2)
    let sign = AST.zext 128<rt> (AST.xthi 1<rt> d) << numI32 127 128<rt>
    let exp = AST.extract d 11<rt> 52
    let frac = d .& numU64 0xfffffffffffffUL 64<rt>
    let moved = AST.zext 128<rt> frac << numI32 60 128<rt>
    let rebiased = AST.zext 128<rt> exp .+ numI32 (16383 - 1023) 128<rt>
    let normal = (rebiased << numI32 112 128<rt>) .| moved
    let inf = expMask .| moved
    let noFraction = frac == AST.num0 64<rt>
    let special = AST.ite noFraction inf (inf .| quietBit)
    let tiny = AST.ite noFraction zero128 (normalized frac (-1011))
    let byExp = AST.ite (exp == AST.num0 11<rt>) tiny normal
    let res = sign .| AST.ite (exp == numI32 0x7ff 11<rt>) special byExp
    let t = writeQuad bld o1 res
    setFPRF128 bld t
  }

/// xscvsdqp and xscvudqp: the doubleword integer in doubleword 0 of vRB,
/// exactly as a quad. FPRF is set.
let fromLong ins bld isSigned =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let x = AST.xthi 64<rt> (quadOf bld o2)
    let neg = if isSigned then AST.xthi 1<rt> x else AST.b0
    let mag = AST.ite neg (AST.neg x) x
    let sign = AST.zext 128<rt> neg << numI32 127 128<rt>
    let value = sign .| normalized mag 63
    let res = AST.ite (mag == AST.num0 64<rt>) zero128 value
    let t = writeQuad bld o1 res
    setFPRF128 bld t
  }

/// xscvsqqp and xscvuqqp: the quadword integer in vRB rounded to a quad in
/// the direction FPSCR[RN] names, through the named call. FPRF is set.
let fromQuadword ins bld isSigned =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let x = quadOf bld o2
    let signed = numI32 (if isSigned then 1 else 0) 8<rt>
    let args = [ x; signed; byFPSCR bld ]
    let t = writeQuad bld o1 (AST.app "FCVTINT128" args 128<rt>)
    setFPRF128 bld t
  }

/// <summary>
/// xscvqpdp and xscvqpdpo: vRB rounded to a double in doubleword 0, in the
/// direction FPSCR[RN] names or to odd, through the named call; a NaN keeps
/// the top of its fraction and comes back quiet. Doubleword 1 is cleared
/// and FPRF set.
/// </summary>
let toDouble ins bld toOdd =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let b = quadOf bld o2
    let struct (dh, dl) = vsrOf bld o1
    let sign = AST.xthi 64<rt> b .& numU64 0x8000000000000000UL 64<rt>
    let top = AST.xtlo 64<rt> ((b .& fracMask) >> numI32 60 128<rt>)
    let nan = sign .| numU64 0x7ff8000000000000UL 64<rt> .| top
    let rounded = AST.app "FCVT128TO64" [ b; directionOf bld toOdd ] 64<rt>
    dh := AST.ite (isNaN b) nan rounded
    dl := AST.num0 64<rt>
    setFPRF bld dh
  }

/// 2 to the n as a 128-bit integer.
let private pow2 n = AST.num1 128<rt> << numI32 n 128<rt>

/// <summary>
/// A quad truncated toward zero to an integer of the given width, as a
/// 128-bit magnitude: the significand shifted by the unbiased exponent. A
/// magnitude too big for the width is caught by the caller; anything below
/// one is zero.
/// </summary>
let private truncatedMagnitude q =
  let biased = AST.zext 16<rt> (AST.extract q 15<rt> 112)
  let unbiased = biased .- numI32 16383 16<rt>
  let mant = (q .& fracMask) .| implicitBit
  let right = AST.zext 128<rt> (numI32 112 16<rt> .- unbiased)
  let left = AST.zext 128<rt> (unbiased .- numI32 112 16<rt>)
  let shifted =
    AST.ite (unbiased ?<= numI32 112 16<rt>) (mant >> right) (mant << left)
  struct (unbiased, AST.ite (unbiased ?< AST.num0 16<rt>) zero128 shifted)

/// <summary>
/// A quad converted to a signed or unsigned integer of a width (32, 64 or
/// 128), truncated toward zero and saturated, as the ISA's convert tables
/// say: a NaN gives the smallest signed value or zero; a value past either
/// end gives that end; a negative value gives zero to an unsigned one. The
/// result is the width's bits, at 128.
/// </summary>
let private toIntegerOf width isSigned q =
  let struct (unbiased, t) = truncatedMagnitude q
  let huge = unbiased ?>= numI32 width 16<rt>
  let neg = negative q
  let mask =
    if width = 128 then AST.not zero128 else pow2 width .- AST.num1 128<rt>
  if isSigned then
    let half = pow2 (width - 1)
    let maxValue = half .- AST.num1 128<rt>
    let minValue = half
    let posOver = huge .| (t .> maxValue)
    let negOver = huge .| (t .> half)
    let positive = AST.ite posOver maxValue t
    let negated = AST.ite negOver minValue (AST.neg t .& mask)
    AST.ite (isNaN q) minValue (AST.ite neg negated positive)
  else
    let over = huge .| (t .> mask)
    let positive = AST.ite over mask t
    AST.ite (isNaN q .| neg) zero128 positive

/// <summary>
/// xscvqp[su][dwq]z: vRB converted to an integer of the given width,
/// truncated and saturated. A word is extended to a doubleword as its
/// signedness says; a word or a doubleword goes in doubleword 0 with
/// doubleword 1 cleared. FPRF is left alone (the ISA leaves it undefined).
/// </summary>
let toInteger ins bld width isSigned =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let b = quadOf bld o2
    let bits = toIntegerOf width isSigned b
    let res =
      match width with
      | 128 ->
        bits
      | 64 ->
        inDoubleword0 (AST.xtlo 64<rt> bits)
      | _ ->
        let w = AST.xtlo 32<rt> bits
        let ext = if isSigned then AST.sext 64<rt> w else AST.zext 64<rt> w
        inDoubleword0 ext
    writeQuad bld o1 res |> ignore
  }

/// <summary>
/// The rounding direction a Z23-form's R and RMC name, as the named calls
/// take it: R = 0 with RMC = 0 rounds to nearest with ties away from zero
/// (5), R = 0 with RMC = 3 in the direction FPSCR[RN] names, and R = 1 in
/// the direction RMC names (0 to nearest, 1 toward zero, 2 toward +Inf, 3
/// toward -Inf).
/// </summary>
let private directionOfRMC bld r rmc =
  match r, rmc with
  | 0, 0 -> numI32 5 8<rt>
  | 0, _ -> byFPSCR bld
  | _ -> numI32 rmc 8<rt>

/// The operands of a Z23-form: "R, vRT, vRB, RMC".
let private z23 (ins: Instruction) =
  match ins.Operands with
  | FourOperands(OprImm r, t, b, OprImm rmc) -> struct (int r, t, b, int rmc)
  | _ -> raise InvalidOperandException

/// <summary>
/// xsrqpi and xsrqpix: vRB rounded to an integral value in the direction R
/// and RMC name, through the named call; a NaN comes back quiet, an
/// infinity or a zero as it is. FPRF is set.
/// </summary>
let roundToIntegral ins bld =
  lift bld ins {
    let struct (r, o1, o2, rmc) = z23 ins
    let b = quadOf bld o2
    let mode = directionOfRMC bld r rmc
    let rounded = AST.app "FRINT128" [ b; mode ] 128<rt>
    let t = writeQuad bld o1 (AST.ite (isNaN b) (quieted b) rounded)
    setFPRF128 bld t
  }

/// The low 49 bits of a quad's fraction, which double-extended precision's
/// 64-bit significand does not hold.
let private beyondX80 = q128 0UL 0x0001ffffffffffffUL

/// <summary>
/// xsrqpxp: vRB rounded to double-extended precision -- the quad's exponent
/// range, a 64-bit significand -- in the direction R and RMC name, through
/// the named call; a NaN comes back quiet with its fraction cut to that
/// precision. FPRF is set.
/// </summary>
let roundToX80 ins bld =
  lift bld ins {
    let struct (r, o1, o2, rmc) = z23 ins
    let b = quadOf bld o2
    let mode = directionOfRMC bld r rmc
    let rounded = AST.app "FRND80" [ b; mode ] 128<rt>
    let nan = quieted b .& AST.not beyondX80
    let t = writeQuad bld o1 (AST.ite (isNaN b) nan rounded)
    setFPRF128 bld t
  }

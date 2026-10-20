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
/// The vector facility's decimal integer instructions. A signed packed decimal
/// value is 31 four-bit digits, the most significant first, and a four-bit
/// sign code; it is read into the binary number it stands for, the arithmetic
/// is done in binary, and the answer is written back as digits. Every value
/// 31 digits hold is below 2^104, so a 128-bit number holds it with room for
/// a sum and a sign.
/// </summary>
module internal B2R2.FrontEnd.PPC.VectorDecimalLifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.VectorElements

/// Ten to a power, as a 128-bit number.
let private pow10 (n: int) = AST.num (BitVector(bigint.Pow(10I, n), 128<rt>))

/// The 31 digits of a packed decimal value, the most significant first.
let private digitsOf (q: Expr) =
  Array.init 31 (fun k -> AST.extract q 4<rt> (124 - 4 * k))

/// Whether a signed packed decimal value is a valid encoding: every digit at
/// most 9 and a sign code of 10 or more.
let private isValidSigned q =
  let digitsValid =
    digitsOf q
    |> Array.map (fun d -> d .<= numI32 9 4<rt>)
    |> Array.reduce (.&)
  digitsValid .& (AST.xtlo 4<rt> q .>= numI32 10 4<rt>)

/// The magnitude a packed decimal value's digits stand for.
let private magnitudeOf q =
  digitsOf q
  |> Array.mapi (fun k d -> AST.zext 128<rt> d .* pow10 (30 - k))
  |> Array.reduce (.+)

/// Whether a sign code says negative, which 0b1011 and 0b1101 do.
let private isMinus (q: Expr) =
  let sign = AST.xtlo 4<rt> q
  (sign == numI32 0xb 4<rt>) .| (sign == numI32 0xd 4<rt>)

/// The signed number a signed packed decimal value stands for.
let private signedValueOf q =
  let m = magnitudeOf q
  AST.ite (isMinus q) (AST.neg m) m

/// The low 31 decimal digits of a binary magnitude, packed, followed by a
/// sign code.
let private packedOf (m: Expr) sign =
  let digits =
    Array.init 31 (fun k ->
      AST.xtlo 4<rt> ((m ./ pow10 (30 - k)) .% numI32 10 128<rt>))
  concatElements (Array.append digits [| sign |])

/// The sign code of a result that is not negative: 0b1100, or 0b1111 where the
/// preferred-sign operand PS says so.
let private plusSign ps = numI32 (if ps then 0xf else 0xc) 4<rt>

/// Sets CR6 from a decimal result: less than, greater than and equal to zero
/// and the overflow bit, where both operands are valid; 0b0001 where either
/// is not.
let private setDecimalCR6 (bld: ILowUIRBuilder) valid (r: Expr) overflow =
  append bld {
    regVar bld Register.CR6_0 := valid .& (r ?< AST.num0 128<rt>)
    regVar bld Register.CR6_1 := valid .& (r ?> AST.num0 128<rt>)
    regVar bld Register.CR6_2 := valid .& (r == AST.num0 128<rt>)
    regVar bld Register.CR6_3 := AST.not valid .| overflow
  }

/// bcdadd./bcdsub.: the sum or the difference of two signed packed decimal
/// values, its low 31 digits written with a sign code saying negative (0b1101)
/// or not, and CR6 saying how it compares with zero and whether it overflowed
/// 31 digits. The ISA leaves the result undefined where an operand is not a
/// valid encoding; it is written as all ones there, as QEMU writes it.
let bcdAddSub ins bld subtract =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let ps = getImmValue o4 = 1u
    let struct (a, b) = tmpVars2 bld 128<rt>
    let struct (r, m) = tmpVars2 bld 128<rt>
    let valid = tmpVar bld 1<rt>
    a := quadOf bld o2
    b := quadOf bld o3
    valid := isValidSigned a .& isValidSigned b
    let combine = if subtract then (.-) else (.+)
    r := combine (signedValueOf a) (signedValueOf b)
    m := AST.ite (r ?< AST.num0 128<rt>) (AST.neg r) r
    let sign = AST.ite (r ?< AST.num0 128<rt>) (numI32 0xd 4<rt>) (plusSign ps)
    let ones = AST.not (AST.num0 128<rt>)
    putElements bld o1 [| AST.ite valid (packedOf m sign) ones |]
    setDecimalCR6 bld valid r (m .>= pow10 31)
  }

/// Sets CR6 from a decimal instruction's flags: less than, greater than and
/// equal to zero where the operands are valid, and the last bit where either
/// one is invalid or the result overflowed.
let private setDecimalFlags (bld: ILowUIRBuilder) invalid lt gt eq overflow =
  let valid = AST.not invalid
  append bld {
    regVar bld Register.CR6_0 := valid .& lt
    regVar bld Register.CR6_1 := valid .& gt
    regVar bld Register.CR6_2 := valid .& eq
    regVar bld Register.CR6_3 := invalid .| overflow
  }

/// The 31 digits of a signed packed decimal value as one 124-bit field, kept
/// in the low bits of a 128-bit number.
let private digitField (q: Expr) = q >> numI32 4 128<rt>

/// What a decimal instruction writes where an operand is invalid, which the
/// ISA leaves undefined: the target as it was, or the result computed as if
/// the operand were valid -- the choice QEMU makes for each.
type private OnInvalid =
  | KeepTarget
  | WriteResult

/// Writes a decimal result and sets CR6 from whether the value reported on is
/// negative or zero.
let private finishDecimal bld opr onInvalid invalid minus zero overflow result =
  let nonzero = AST.not zero
  let lt = nonzero .& minus
  let gt = nonzero .& AST.not minus
  let written =
    match onInvalid with
    | KeepTarget -> AST.ite invalid (quadOf bld opr) result
    | WriteResult -> result
  putElements bld opr [| written |]
  setDecimalFlags bld invalid lt gt zero overflow

/// Whether a signed packed decimal operand is invalid, negative, and zero.
let private signedFlags q =
  let zero = digitField q == AST.num0 128<rt>
  struct (AST.not (isValidSigned q), isMinus q, zero)

/// The sign code a result takes: 0b1101 when negative, else 0b1100, or
/// 0b1111 where PS is 1.
let private signCode minus ps = AST.ite minus (numI32 0xd 4<rt>) (plusSign ps)

/// A 128-bit value with its sign code replaced.
let private withSign (q: Expr) sign =
  (q .& AST.not (numI32 0xf 128<rt>)) .| AST.zext 128<rt> sign

/// The PS operand of a decimal instruction.
let private psOf opr = getImmValue opr = 1u

/// A vector operand held in a temporary.
let private heldQuad bld opr =
  let q = tmpVar bld 128<rt>
  append bld { q := quadOf bld opr }
  q

/// bcdcpsgn. vD, vA, vB: vA's digits with vB's sign code.
let bcdcpsgn ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = heldQuad bld o2
    let b = heldQuad bld o3
    let struct (badA, _, zero) = signedFlags a
    let struct (badB, minus, _) = signedFlags b
    let result = withSign a (AST.xtlo 4<rt> b)
    finishDecimal bld o1 KeepTarget (badA .| badB) minus zero AST.b0 result
  }

/// bcdsetsgn. vD, vB, PS: vB with the preferred sign code for its sign.
let bcdsetsgn ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let b = heldQuad bld o2
    let struct (bad, minus, zero) = signedFlags b
    let result = withSign b (signCode minus (psOf o3))
    finishDecimal bld o1 WriteResult bad minus zero AST.b0 result
  }

/// bcdcfsq. vD, vB, PS: the signed quadword vB as a signed packed decimal;
/// one past 31 digits overflows and leaves vD undefined, kept as it was.
let bcdcfsq ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let v = heldQuad bld o2
    let minus = v ?< AST.num0 128<rt>
    let m = AST.ite minus (AST.neg v) v
    let overflow = tmpVar bld 1<rt>
    overflow := m .>= pow10 31
    let zero = v == AST.num0 128<rt>
    let result = packedOf m (signCode minus (psOf o3))
    putElements bld o1 [| AST.ite overflow (quadOf bld o1) result |]
    let positive = AST.not minus .& AST.not zero
    setDecimalFlags bld AST.b0 minus positive zero overflow
  }

/// bcdctsq. vD, vB: the signed packed decimal vB as a signed quadword.
let bcdctsq ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let b = heldQuad bld o2
    let struct (bad, minus, zero) = signedFlags b
    finishDecimal bld o1 WriteResult bad minus zero AST.b0 (signedValueOf b)
  }

/// The digit shift count of bcds., bcdus. and bcdsr.: the signed byte 7 of
/// vA, positive for a left shift, clamped to the number of digits.
let private shiftCount bld opr digits =
  let struct (ah, _) = halvesOf bld opr
  let n = tmpVar bld 8<rt>
  let limit = numI32 digits 8<rt>
  append bld { n := AST.xtlo 8<rt> ah }
  let left = n ?> AST.num0 8<rt>
  let back = AST.neg n
  let count = AST.ite left n back
  let clamped = AST.ite (count .> limit) limit count
  struct (left, AST.zext 128<rt> clamped .* numI32 4 128<rt>)

/// A digit field of `digits` digits shifted left or right by `bits` (four per
/// digit), and whether a nonzero digit went out on the left.
let private shiftDigits (field: Expr) digits left (bits: Expr) =
  let width = numI32 (4 * digits) 128<rt>
  let mask = AST.not (AST.not (AST.num0 128<rt>) << width)
  let shifted = AST.ite left ((field << bits) .& mask) (field >> bits)
  let out = field >> (width .- bits)
  let lost = bits != AST.num0 128<rt> .& (out != AST.num0 128<rt>)
  struct (shifted, left .& lost)

/// bcds. vD, vA, vB, PS: the digits of vB shifted left or right by byte 7 of
/// vA, a nonzero digit shifted out on the left overflowing.
let bcds ins bld =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let b = heldQuad bld o3
    let struct (bad, minus, zero) = signedFlags b
    let struct (left, bits) = shiftCount bld o2 31
    let struct (shifted, overflow) = shiftDigits (digitField b) 31 left bits
    let sign = AST.zext 128<rt> (signCode minus (psOf o4))
    let result = (shifted << numI32 4 128<rt>) .| sign
    finishDecimal bld o1 KeepTarget bad minus zero overflow result
  }

/// Whether an unsigned packed decimal value is valid: every nibble a digit.
let private isValidUnsigned (q: Expr) =
  Array.init 32 (fun k -> AST.extract q 4<rt> (4 * k) .<= numI32 9 4<rt>)
  |> Array.reduce (.&)

/// bcdus. vD, vA, vB: the 32 unsigned digits of vB shifted as bcds. shifts.
let bcdus ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let b = heldQuad bld o3
    let bad = AST.not (isValidUnsigned b)
    let zero = b == AST.num0 128<rt>
    let struct (left, bits) = shiftCount bld o2 32
    let struct (shifted, overflow) = shiftDigits b 32 left bits
    finishDecimal bld o1 KeepTarget bad AST.b0 zero overflow shifted
  }

/// bcdsr. vD, vA, vB, PS: bcds. that rounds a right shift, the magnitude
/// incremented where the last digit shifted out is 5 or more.
let bcdsr ins bld =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let b = heldQuad bld o3
    let struct (bad, minus, zero) = signedFlags b
    let struct (left, bits) = shiftCount bld o2 31
    let field = digitField b
    let struct (shifted, overflow) = shiftDigits field 31 left bits
    let four = numI32 4 128<rt>
    let last = AST.xtlo 4<rt> (field >> (bits .- four))
    let up = AST.not left .& (bits != AST.num0 128<rt>)
    let round = up .& (last .>= numI32 5 4<rt>)
    let shiftedQ = tmpVar bld 128<rt>
    shiftedQ := (shifted << four) .| numI32 0xc 128<rt>
    let rounded = magnitudeOf shiftedQ .+ AST.zext 128<rt> round
    let result = packedOf rounded (signCode minus (psOf o4))
    finishDecimal bld o1 KeepTarget bad minus zero overflow result
  }

/// The digits of a field kept to its rightmost `length` ones, where `length`
/// is below the number it has, and whether a nonzero digit was cut off.
let private truncateDigits (field: Expr) digits (length: Expr) =
  let bits = AST.zext 128<rt> length .* numI32 4 128<rt>
  let short = length .< numI32 digits 16<rt>
  let kept = field .& AST.not (AST.not (AST.num0 128<rt>) << bits)
  let lost = short .& ((field >> bits) != AST.num0 128<rt>)
  struct (AST.ite short kept field, lost)

/// The digit count of bcdtrunc. and bcdutrunc.: bits 48:63 of vA.
let private truncateLength bld opr =
  let struct (ah, _) = halvesOf bld opr
  let length = tmpVar bld 16<rt>
  append bld { length := AST.xtlo 16<rt> ah }
  length

/// bcdtrunc. vD, vA, vB, PS: vB kept to its rightmost N digits, N being bits
/// 48:63 of vA, a nonzero digit cut off overflowing.
let bcdtrunc ins bld =
  lift bld ins {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let b = heldQuad bld o3
    let struct (bad, minus, zero) = signedFlags b
    let length = truncateLength bld o2
    let struct (kept, overflow) = truncateDigits (digitField b) 31 length
    let sign = AST.zext 128<rt> (signCode minus (psOf o4))
    let result = (kept << numI32 4 128<rt>) .| sign
    finishDecimal bld o1 KeepTarget bad minus zero overflow result
  }

/// bcdutrunc. vD, vA, vB: the 32 unsigned digits of vB kept as bcdtrunc.
/// keeps them.
let bcdutrunc ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let b = heldQuad bld o3
    let bad = AST.not (isValidUnsigned b)
    let zero = b == AST.num0 128<rt>
    let length = truncateLength bld o2
    let struct (kept, overflow) = truncateDigits b 32 length
    finishDecimal bld o1 KeepTarget bad AST.b0 zero overflow kept
  }

/// bcdcfn. vD, vB, PS: the national decimal vB -- seven halfwords 0x0030 to
/// 0x0039 and a sign halfword 0x002B or 0x002D -- as a signed packed decimal.
let bcdcfn ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let b = heldQuad bld o2
    let h = elementsOfHalves 16<rt> (AST.xthi 64<rt> b) (AST.xtlo 64<rt> b)
    let digit x = (x .>= numI32 0x30 16<rt>) .& (x .<= numI32 0x39 16<rt>)
    let plus = h[7] == numI32 0x2b 16<rt>
    let minus = AST.not plus
    let signOk = plus .| (h[7] == numI32 0x2d 16<rt>)
    let digitsOk = h[..6] |> Array.map digit |> Array.reduce (.&)
    let isZero x = x == numI32 0x30 16<rt>
    let zero = h[..6] |> Array.map isZero |> Array.reduce (.&)
    let digits = h[..6] |> Array.map (AST.xtlo 4<rt>)
    let result =
      Array.append digits [| signCode minus (psOf o3) |]
      |> concatElements
      |> AST.zext 128<rt>
    let bad = AST.not (signOk .& digitsOk)
    finishDecimal bld o1 WriteResult bad minus zero AST.b0 result
  }

/// bcdctn. vD, vB: the low seven digits of the signed packed decimal vB as a
/// national decimal, more digits than that overflowing.
let bcdctn ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let b = heldQuad bld o2
    let struct (bad, minus, zero) = signedFlags b
    let overflow = (b >> numI32 32 128<rt>) != AST.num0 128<rt>
    let digits =
      Array.init 7 (fun i ->
        AST.zext 16<rt> (AST.extract b 4<rt> (28 - 4 * i))
        .| numI32 0x30 16<rt>)
    let sign = AST.ite minus (numI32 0x2d 16<rt>) (numI32 0x2b 16<rt>)
    let result = concatElements (Array.append digits [| sign |])
    finishDecimal bld o1 WriteResult bad minus zero overflow result
  }

/// bcdcfz. vD, vB, PS: the zoned decimal vB -- a digit in the low nibble of
/// each byte, a zone of 0x3 (PS 0) or 0xF (PS 1) above the first fifteen and
/// the sign above the last -- as a signed packed decimal.
let bcdcfz ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let ps = psOf o3
    let b = heldQuad bld o2
    let bytes = elementsOfHalves 8<rt> (AST.xthi 64<rt> b) (AST.xtlo 64<rt> b)
    let zone = numI32 (if ps then 0xf else 0x3) 4<rt>
    let zonedOk x =
      (AST.xthi 4<rt> x == zone) .& (AST.xtlo 4<rt> x .<= numI32 9 4<rt>)
    let signZone = AST.xthi 4<rt> bytes[15]
    let lastOk = AST.xtlo 4<rt> bytes[15] .<= numI32 9 4<rt>
    let signOk = if ps then signZone .>= numI32 0xa 4<rt> else AST.b1
    let digitsOk = bytes[..14] |> Array.map zonedOk |> Array.reduce (.&)
    let minusSign =
      (signZone == numI32 0xb 4<rt>) .| (signZone == numI32 0xd 4<rt>)
    let minus = if ps then minusSign else AST.extract signZone 1<rt> 2
    let digits = bytes |> Array.map (AST.xtlo 4<rt>)
    let zero =
      digits |> Array.map (fun d -> d == AST.num0 4<rt>) |> Array.reduce (.&)
    let result =
      Array.append digits [| signCode minus false |]
      |> concatElements
      |> AST.zext 128<rt>
    let bad = AST.not (signOk .& lastOk .& digitsOk)
    finishDecimal bld o1 WriteResult bad minus zero AST.b0 result
  }

/// bcdctz. vD, vB, PS: the low sixteen digits of the signed packed decimal vB
/// as a zoned decimal, more digits than that overflowing. The pseudocode
/// tests nibbles 0 to 15 for the overflow, one more than the sixteen digits
/// leave out and than its own text says; the text is followed, as QEMU does.
let bcdctz ins bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let ps = psOf o3
    let b = heldQuad bld o2
    let struct (bad, minus, zero) = signedFlags b
    let overflow = (b >> numI32 68 128<rt>) != AST.num0 128<rt>
    let zone = numI32 (if ps then 0xf else 0x3) 4<rt>
    let digit i = AST.extract b 4<rt> (64 - 4 * i)
    let sign =
      if ps then AST.ite minus (numI32 0xd 4<rt>) (numI32 0xc 4<rt>)
      else AST.ite minus (numI32 0x7 4<rt>) (numI32 0x3 4<rt>)
    let bytes =
      Array.init 16 (fun i ->
        AST.concat (if i = 15 then sign else zone) (digit i))
    let result = concatElements bytes
    finishDecimal bld o1 WriteResult bad minus zero overflow result
  }

/// vmul10uq/vmul10cuq/vmul10euq/vmul10ecuq: vA times ten, plus the digit in
/// the low nibble of vB for the extended forms, as a 128-bit number -- or the
/// part of it above 128 bits, for the carry forms.
let vecMultiplyByTen (ins: Instruction) bld extended carry =
  lift bld ins {
    let o1, o2 =
      match ins.Operands with
      | TwoOperands(o1, o2) | ThreeOperands(o1, o2, _) -> o1, o2
      | _ -> raise InvalidOperandException
    let cin =
      match ins.Operands with
      | ThreeOperands(_, _, o3) when extended ->
        let struct (_, bl) = halvesOf bld o3
        AST.zext 256<rt> (AST.xtlo 4<rt> bl)
      | _ ->
        AST.num0 256<rt>
    let ten = numI32 10 256<rt>
    let product = (AST.zext 256<rt> (quadOf bld o2) .* ten) .+ cin
    let pick = if carry then AST.xthi 128<rt> else AST.xtlo 128<rt>
    putElements bld o1 [| pick product |]
  }

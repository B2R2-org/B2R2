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
/// Lifts the m68k floating-point instructions. The unit works in
/// extended precision, which is eighty bits: a sign, fifteen bits of exponent,
/// and a mantissa of sixty-four that carries its leading one explicitly rather
/// than implying it as the IEEE formats do. No register file holds a value
/// that wide, so a register is kept as the two that together are exactly it,
/// and every operation is carried out in double precision and converted back.
/// The results therefore agree with hardware wherever a program stays within
/// what a double can hold, which is everything short of arithmetic that means
/// to use the extended format's extra range.
/// </summary>
module internal B2R2.FrontEnd.M68K.FloatLifter

open System
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.M68K.LiftHelper

/// How wide a floating-point value is in memory in the extended-precision
/// format: the sign and the exponent in the first word, a word of nothing, and
/// the mantissa in the two long words after it.
let [<Literal>] private ExtendedBytes = 12

/// How much wider the bias of an extended-precision exponent is than that of a
/// double-precision one, which is what converting between the two moves it by.
let [<Literal>] private BiasDiff = 0x3c00UL

/// A sixty-four-bit constant.
let inline private num64 (n: uint64) = numU64 n 64<rt>

/// The exponent and mantissa of a double-precision infinity, which is what
/// every exponent too wide for the format becomes.
let [<Literal>] private DoubleInf = 0x7ff0000000000000UL

/// The smallest extended exponent that a double can still carry as a denormal.
/// A double denormal is a value below 2 raised to the minus 1022, and extended
/// precision holds every one of them as an ordinary normalised number, so their
/// exponents are the ones at or below BiasDiff -- down to BiasDiff minus 51,
/// which is the smallest denormal of all. Anything below that a double has no
/// room for and rounds away to zero.
let [<Literal>] private MinDenormExp = BiasDiff - 51UL

/// Returns the double-precision value that an extended-precision one holds,
/// given the word carrying its sign and exponent and the long word pair
/// carrying its mantissa. An exponent of nothing is a zero and one of all ones
/// an infinity or a NaN, each of which keeps its meaning across; an exponent
/// too wide for a double to carry becomes an infinity, and one too narrow
/// becomes a denormal and then a zero.
///
/// The denormal arm is not a nicety. Without it every value below 2 to the
/// minus 1022 arrived as a zero, which FABS and even FMOVE.X -- a sign-bit
/// clear and a copy -- turned the smallest numbers a guest can hold into
/// nothing at all. The shift is arithmetic rather than a search: an extended
/// exponent fixes how far the mantissa has to come down to sit under a fixed
/// double exponent of zero, and that distance is BiasDiff plus twelve less the
/// exponent, which runs from twelve at the largest denormal to sixty-three at
/// the smallest.
let private extendedToDouble b a =
  let b = AST.zext 64<rt> b
  let sign = (b .& num64 0x8000UL) << numI32 48 64<rt>
  let expE = b .& num64 0x7fffUL
  let frac = (a >> numI32 11 64<rt>) .& num64 0xfffffffffffffUL
  let expD = (expE .- num64 BiasDiff) << numI32 52 64<rt>
  let denorm = a >> (num64 (BiasDiff + 12UL) .- expE)
  AST.ite (expE == num64 0x7fffUL)
    (sign .| num64 DoubleInf .| frac)
    (AST.ite (expE .< num64 MinDenormExp)
       sign
       (AST.ite (expE .<= num64 BiasDiff)
          (sign .| denorm)
          (AST.ite (expE .>= num64 (BiasDiff + 0x7ffUL))
             (sign .| num64 DoubleInf)
             (sign .| expD .| frac))))

/// One step of the search for a denormal fraction's leading one: if the top
/// `k` bits of the mantissa are empty, shift it up by `k` and charge `k` to the
/// count. Six steps, from thirty-two down to one, normalise any nonzero word.
/// The count is written before the mantissa, so that both statements test the
/// mantissa as it stood on entry.
let private normalizeStep bld m sh k =
  let empty = (m >> numI32 (64 - k) 64<rt>) == AST.num0 64<rt>
  append bld {
    sh := AST.ite empty (sh .+ numI32 k 64<rt>) sh
    m := AST.ite empty (m << numI32 k 64<rt>) m
  }

/// Returns the extended-precision halves of a double-precision value: the word
/// holding its sign and exponent, and its mantissa with the leading one that a
/// double only implies made explicit.
///
/// A double denormal has no leading one to make explicit and no exponent to
/// carry over, so it is normalised instead: its fraction is brought to the top
/// of the word, the leading one is searched for, and the distance it travelled
/// is taken off the exponent. Extended precision has room for every one of
/// them, which is why they can be kept exactly rather than flushed -- and
/// keeping them is what makes the round trip back through extendedToDouble
/// exact.
let private doubleToExtended bld t =
  let expD = tmpVar bld 64<rt>
  let frac = tmpVar bld 64<rt>
  let m = tmpVar bld 64<rt>
  let sh = tmpVar bld 64<rt>
  let hi = tmpVar bld 16<rt>
  let lo = tmpVar bld 64<rt>
  append bld {
    expD := (t >> numI32 52 64<rt>) .& num64 0x7ffUL
    frac := t .& num64 0xfffffffffffffUL
    (* The fraction with its own highest bit at the top of the word, which is
       where the search below starts from. *)
    m := frac << numI32 12 64<rt>
    sh := AST.num0 64<rt>
  }
  normalizeStep bld m sh 32
  normalizeStep bld m sh 16
  normalizeStep bld m sh 8
  normalizeStep bld m sh 4
  normalizeStep bld m sh 2
  normalizeStep bld m sh 1
  append bld {
    hi :=
      (AST.xtlo 16<rt> (t >> numI32 48 64<rt>) .& numI32 0x8000 16<rt>)
      .| AST.ite (expD == AST.num0 64<rt>)
           (AST.ite (frac == AST.num0 64<rt>)
              (AST.num0 16<rt>)
              (AST.xtlo 16<rt> (num64 BiasDiff .- sh)))
           (AST.ite (expD == num64 0x7ffUL)
              (numI32 0x7fff 16<rt>)
              (AST.xtlo 16<rt> expD .+ numI32 0x3c00 16<rt>))
    lo :=
      AST.ite (expD == AST.num0 64<rt>)
        (AST.ite (frac == AST.num0 64<rt>) (AST.num0 64<rt>) m)
        (num64 0x8000000000000000UL .| (frac << numI32 11 64<rt>))
  }
  struct (hi, lo)

/// Returns the double-precision value that a floating-point data register
/// holds.
let private readFloat bld reg =
  let struct (lo, hi) = RegisterHelper.toFloatParts reg
  extendedToDouble (regVar bld hi) (regVar bld lo)

/// Writes a double-precision value into a floating-point data register, which
/// keeps it in the extended precision the unit works in.
let private writeFloat bld reg v =
  let struct (rlo, rhi) = RegisterHelper.toFloatParts reg
  let struct (hi, lo) = doubleToExtended bld v
  append bld {
    regVar bld rhi := hi
    regVar bld rlo := lo
  }

/// Reads an extended-precision value out of the twelve bytes of memory that
/// carry it, dropping the word of padding the register does not keep.
let private loadExtended bld addr =
  AST.concat (loadNative bld 16<rt> addr)
             (loadNative bld 64<rt> (addr .+ num32 4))

/// Writes the two halves of an extended-precision value out over the twelve
/// bytes that carry it, filling in the word of padding.
let private storeExtended bld addr hi lo =
  append bld {
    storeNative bld addr hi
    storeNative bld (addr .+ num32 2) (AST.num0 16<rt>)
    storeNative bld (addr .+ num32 4) lo
  }

/// Returns the big-endian value that a run of bytes of a floating-point
/// immediate holds.
let private beValue (bytes: byte[]) off len =
  Array.sub bytes off len
  |> Array.fold (fun acc b -> (acc <<< 8) ||| uint64 b) 0UL

/// Returns the double-precision bits of an extended-precision value given the
/// word holding its sign and exponent and the long word pair holding its
/// mantissa. This is what extendedToDouble does, for the one case where both
/// are known while the instruction is being lifted.
let private extendedBitsToDouble se man =
  let sign = (se &&& 0x8000UL) <<< 48
  let expE = se &&& 0x7fffUL
  let frac = (man >>> 11) &&& 0xfffffffffffffUL
  if expE = 0x7fffUL then sign ||| DoubleInf ||| frac
  elif expE <= BiasDiff then sign
  elif expE >= BiasDiff + 0x7ffUL then sign ||| DoubleInf
  else sign ||| ((expE - BiasDiff) <<< 52) ||| frac

/// Returns the double-precision bits of a floating-point immediate, which the
/// parser keeps as the bytes it read because no integer is wide enough to hold
/// the widest of the formats.
let private immDouble (bytes: byte[]) =
  match bytes.Length with
  | 4 ->
    BitConverter.Int32BitsToSingle(int (uint32 (beValue bytes 0 4)))
    |> float
    |> BitConverter.DoubleToUInt64Bits
  | 8 ->
    beValue bytes 0 8
  | _ ->
    extendedBitsToDouble (beValue bytes 0 2) (beValue bytes 4 8)

/// Returns whether a register is one of the floating-point data registers,
/// which is what tells an FMOVE that loads one from an FMOVE that stores one.
let isFloatReg reg =
  match reg with
  | R.FP0 | R.FP1 | R.FP2 | R.FP3
  | R.FP4 | R.FP5 | R.FP6 | R.FP7 -> true
  | _ -> false

/// Returns the floating-point register an operand names.
let private floatRegOf opr =
  match opr with
  | OpReg r when isFloatReg r -> r
  | _ -> raise InvalidOperandException

/// Returns the address a floating-point memory operand names.
let private floatAddrOf bld ins size opr =
  match transOpr bld ins size opr with
  | LMem addr -> addr
  | _ -> raise InvalidOperandException

/// Returns the double-precision value that a floating-point source operand
/// holds, whichever of the formats the instruction reads it in.
let private readFloatOpr bld ins size opr =
  match opr, size with
  | OpFImm bytes, _ ->
    num64 (immDouble bytes)
  | OpReg r, _ when isFloatReg r ->
    readFloat bld r
  | _, Sz.Extended ->
    let addr = floatAddrOf bld ins Sz.Extended opr
    extendedToDouble (loadNative bld 16<rt> addr)
                     (loadNative bld 64<rt> (addr .+ num32 4))
  | _, (Sz.Byte | Sz.Word | Sz.Long) ->
    let v = readLoc bld size (transOpr bld ins size opr)
    AST.cast CastKind.SIntToFloat 64<rt> v
  | _, Sz.Single ->
    let v = readLoc bld Sz.Single (transOpr bld ins Sz.Single opr)
    AST.cast CastKind.FloatCast 64<rt> v
  | _, Sz.Double ->
    readLoc bld Sz.Double (transOpr bld ins Sz.Double opr)
  | _ ->
    raise InvalidOperandSizeException

/// Writes a double-precision value out to a floating-point destination in
/// whichever of the formats the instruction names.
let private writeFloatOpr bld ins size opr v =
  match opr, size with
  | OpReg r, _ when isFloatReg r ->
    writeFloat bld r v
  | _, Sz.Extended ->
    let addr = floatAddrOf bld ins Sz.Extended opr
    let struct (hi, lo) = doubleToExtended bld v
    storeExtended bld addr hi lo
  | _, (Sz.Byte | Sz.Word | Sz.Long) ->
    let dst = transOpr bld ins size opr
    let rt = regTypeOf size
    append bld {
      writeLoc bld size dst (AST.cast CastKind.FtoIRound rt v)
    }
  | _, Sz.Single ->
    let dst = transOpr bld ins Sz.Single opr
    append bld {
      writeLoc bld Sz.Single dst (AST.cast CastKind.FloatCast 32<rt> v)
    }
  | _, Sz.Double ->
    append bld {
      writeLoc bld Sz.Double (transOpr bld ins Sz.Double opr) v
    }
  | _ ->
    raise InvalidOperandSizeException

/// Sets the four condition codes that the floating-point status register keeps
/// in its bits 27 to 24 -- negative, zero, infinity, and not-a-number -- from
/// a result.
let private setFpuFlags bld r =
  let fpsr = regVar bld R.FPSR
  let mag = tmpVar bld 64<rt>
  let at b n = AST.zext 32<rt> b << numI32 n 32<rt>
  append bld {
    mag := r .& num64 0x7fffffffffffffffUL
    fpsr :=
      (fpsr .& numU32 0xf0ffffffu 32<rt>)
      .| at (AST.xthi 1<rt> r) 27
      .| at (mag == AST.num0 64<rt>) 26
      .| at (mag == num64 DoubleInf) 25
      .| at (mag .> num64 DoubleInf) 24
  }

/// Sets the condition codes a comparison leaves. A subtraction would report
/// two infinities of one sign as a NaN rather than as the equals they are, so
/// this asks the comparison itself: two values that are neither ordered one
/// way nor the other are the unordered pair a NaN makes.
let private setFpuCmpFlags bld d s =
  let fpsr = regVar bld R.FPSR
  let at b n = AST.zext 32<rt> b << numI32 n 32<rt>
  let unordered = AST.not (AST.fle d s) .& AST.not (AST.fgt d s)
  append bld {
    fpsr :=
      (fpsr .& numU32 0xf0ffffffu 32<rt>)
      .| at (AST.flt d s) 27
      .| at (AST.feq d s) 26
      .| at unordered 24
  }

/// Lifts a floating-point operation of two operands, which combines the source
/// into the register that the destination names.
let private dyadic (ins: Instruction) bld op =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let dstReg = floatRegOf o2
    let s = tmpVar bld 64<rt>
    let d = tmpVar bld 64<rt>
    let r = tmpVar bld 64<rt>
    s := readFloatOpr bld ins ins.Size o1
    d := readFloat bld dstReg
    r := op d s
    setFpuFlags bld r
    writeFloat bld dstReg r
  }

/// Lifts a floating-point operation of one operand, which the assembler writes
/// with one register where the source and the destination are the same.
let private monadic (ins: Instruction) bld op =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let dstReg = floatRegOf o2
    let s = tmpVar bld 64<rt>
    let r = tmpVar bld 64<rt>
    s := readFloatOpr bld ins ins.Size o1
    r := op s
    setFpuFlags bld r
    writeFloat bld dstReg r
  }

/// Rounds a value to single precision, which is the precision the two
/// single-precision operations work in throughout.
let private toSingle v =
  AST.cast CastKind.FloatCast 64<rt> (AST.cast CastKind.FloatCast 32<rt> v)

/// Lifts an FADD.
let fadd ins bld = dyadic ins bld AST.fadd

/// Lifts an FSUB.
let fsub ins bld = dyadic ins bld AST.fsub

/// Lifts an FMUL.
let fmul ins bld = dyadic ins bld AST.fmul

/// Lifts an FDIV.
let fdiv ins bld = dyadic ins bld AST.fdiv

/// Lifts an FSGLMUL, which multiplies in single precision.
let fsglmul ins bld =
  dyadic ins bld (fun d s -> toSingle (AST.fmul (toSingle d) (toSingle s)))

/// Lifts an FSGLDIV, which divides in single precision.
let fsgldiv ins bld =
  dyadic ins bld (fun d s -> toSingle (AST.fdiv (toSingle d) (toSingle s)))

/// Lifts an FMOVE that moves a real number rather than a control register.
let private fmoveData ins bld = monadic ins bld id

/// Lifts an FNEG, which turns the sign bit over and leaves everything else,
/// so that a zero and a NaN keep what they are.
let fneg ins bld =
  monadic ins bld (fun s -> s <+> num64 0x8000000000000000UL)

/// Lifts an FABS, which clears the sign bit.
let fabs ins bld =
  monadic ins bld (fun s -> s .& num64 0x7fffffffffffffffUL)

/// Lifts an FSQRT.
let fsqrt ins bld = monadic ins bld AST.fsqrt

/// Lifts an FINT, which rounds to a whole number.
let fint ins bld =
  monadic ins bld (AST.cast CastKind.FtoFRound 64<rt>)

/// Lifts an FINTRZ, which rounds to a whole number toward zero whatever the
/// rounding mode says.
let fintrz ins bld =
  monadic ins bld (AST.cast CastKind.FtoFTrunc 64<rt>)

/// Lifts an FGETEXP, which gives the exponent of its source as a whole number,
/// counted from the bias rather than as the format stores it. A zero has no
/// exponent to give and answers zero.
let fgetexp ins bld =
  monadic ins bld (fun s ->
    let mag = s .& num64 0x7fffffffffffffffUL
    let e = AST.xtlo 32<rt> ((s >> numI32 52 64<rt>) .& num64 0x7ffUL)
    AST.ite (mag == AST.num0 64<rt>)
      (AST.num0 64<rt>)
      (AST.cast CastKind.SIntToFloat 64<rt> (e .- numI32 1023 32<rt>)))

/// Lifts an FSCALE, which multiplies by the power of two that its source
/// names, the source being a whole number rather than a real one.
let fscale ins bld =
  dyadic ins bld (fun d s ->
    let k = AST.cast CastKind.FtoITrunc 64<rt> s
    let e = (k .+ num64 1023UL) << numI32 52 64<rt>
    AST.fmul d e)

/// A double-precision constant.
let private numFloat (v: float) = num64 (BitConverter.DoubleToUInt64Bits v)

/// Lifts an FMOD, which is the remainder of a division whose quotient is
/// rounded toward zero.
let fmod ins bld =
  dyadic ins bld (fun d s ->
    let q = AST.cast CastKind.FtoFTrunc 64<rt> (AST.fdiv d s)
    AST.fsub d (AST.fmul s q))

/// Lifts an FREM, which is the remainder of a division whose quotient is
/// rounded to the nearest whole number.
let frem ins bld =
  dyadic ins bld (fun d s ->
    let q = AST.cast CastKind.FtoFRound 64<rt> (AST.fdiv d s)
    AST.fsub d (AST.fmul s q))

/// The magnitude of a value, which is its sign bit cleared.
let private fmagnitude s = s .& num64 0x7fffffffffffffffUL

/// Returns e raised to the power of a value.
///
/// Not FPOW. Raising Math.E to a power amplifies the error in Math.E ITSELF by
/// the exponent: e is not exactly representable, and pow has no way to know
/// what the base was meant to be, so the relative error of the answer grows
/// with the argument. Measured against QEMU over operands up to 2^12, pow(e, x)
/// was 291 ulp out on the worst of them and outside two ulp on 429 of 6000.
///
/// cosh and sinh carry no such constant, and cosh(x) + sinh(x) is e^x
/// identically, so the sum of the two holds to two ulp. It is computed at the
/// magnitude and reciprocated for a negative argument, because for x below zero
/// cosh(x) and sinh(x) are equal and opposite and their sum would cancel away
/// everything it was meant to carry.
///
/// The one place this is weaker than the FPU is an argument below about -709,
/// where e^x is a denormal and the reciprocal of an overflowed cosh is zero.
/// Nothing observable follows: the register model keeps a double and loses a
/// denormal in the conversion anyway.
let private expOf s =
  let m = fmagnitude s
  let p = AST.fadd (AST.fcosh m) (AST.fsinh m)
  AST.ite (AST.xthi 1<rt> s) (AST.fdiv (numFloat 1.0) p) p

/// Lifts an FETOX, which raises e to the power of its source.
let fetox ins bld = monadic ins bld expOf

/// Lifts an FETOXM1, which is one less than that.
///
/// Subtracting the one is what this instruction exists to avoid. For a small
/// argument the answer is very nearly the argument itself, and taking one from
/// a sum that is very nearly one throws away every bit of it: measured against
/// QEMU over [-1, 1], the subtraction form was 1.07e12 ulp out at worst and got
/// the sign or the class of the answer wrong on 401 of 6000 operands.
///
/// sinh(x) + 2 sinh(x/2)^2 is the same quantity with nothing left to cancel.
/// Near zero the first term is the argument and the second is its square over
/// two, each computed to its own relative precision, and the halving is exact;
/// that holds to two ulp. Away from zero there is no cancellation to avoid and
/// the subtraction is the accurate form -- and the only one of the two that
/// survives an argument large enough for sinh to overflow, since the identity
/// would then add an infinity to an infinity. The two divide the domain at a
/// half.
///
/// A zero answers itself. The identity would not: the sum of a negative zero
/// and a positive one is positive, and expm1 of a negative zero is a negative
/// zero.
let fetoxm1 ins bld =
  monadic ins bld (fun s ->
    let mag = fmagnitude s
    let half = AST.fmul s (numFloat 0.5)
    let sh = AST.fsinh half
    let near =
      AST.fadd (AST.fsinh s) (AST.fmul (numFloat 2.0) (AST.fmul sh sh))
    let far = AST.fsub (expOf s) (numFloat 1.0)
    AST.ite (mag == AST.num0 64<rt>)
      s
      (AST.ite (AST.flt mag (numFloat 0.5)) near far))

/// Lifts an FTWOTOX, which raises two to the power of its source.
let ftwotox ins bld = monadic ins bld (AST.fpow (numFloat 2.0))

/// Lifts an FTENTOX, which raises ten to the power of its source.
let ftentox ins bld = monadic ins bld (AST.fpow (numFloat 10.0))

/// Lifts an FLOGN, the natural logarithm.
let flogn ins bld = monadic ins bld (AST.flog (numFloat Math.E))

/// Lifts an FLOGNP1, the natural logarithm of one more than its source.
///
/// Forming the sum is what this instruction exists to avoid, for the mirror
/// image of FETOXM1's reason: for a small argument the sum loses the low bits
/// of it before the logarithm ever sees them, which measured 1.07e12 ulp out
/// against QEMU over [-1, 1].
///
/// 2 atanh(x / (x + 2)) is the same quantity and never forms the sum. atanh(z)
/// is half the logarithm of (1 + z) / (1 - z), and z = x / (x + 2) makes that
/// ratio exactly 1 + x, so the identity is exact and near zero the division is
/// well conditioned; that holds to two ulp. It fails the other way for a large
/// argument, where x / (x + 2) rounds to one and the answer to an infinity, and
/// for one near minus one, where the division loses what the logarithm needs.
/// Both are places where the sum has nothing left to cancel, so the two divide
/// the domain at a half.
let flognp1 ins bld =
  monadic ins bld (fun s ->
    let near =
      AST.fmul (numFloat 2.0)
        (AST.fatanh (AST.fdiv s (AST.fadd s (numFloat 2.0))))
    let far = AST.flog (numFloat Math.E) (AST.fadd s (numFloat 1.0))
    AST.ite (AST.flt (fmagnitude s) (numFloat 0.5)) near far)

/// Lifts an FLOG2.
let flog2 ins bld = monadic ins bld (AST.flog (numFloat 2.0))

/// Lifts an FLOG10.
let flog10 ins bld = monadic ins bld (AST.flog (numFloat 10.0))

/// Lifts an FSIN.
let fsin ins bld = monadic ins bld AST.fsin

/// Lifts an FCOS.
let fcos ins bld = monadic ins bld AST.fcos

/// Lifts an FTAN.
let ftan ins bld = monadic ins bld AST.ftan

/// Lifts an FASIN.
let fasin ins bld = monadic ins bld AST.fasin

/// Lifts an FACOS.
let facos ins bld = monadic ins bld AST.facos

/// Lifts an FATAN.
let fatan ins bld = monadic ins bld AST.fatan

/// Lifts an FSINH.
let fsinh ins bld = monadic ins bld AST.fsinh

/// Lifts an FCOSH.
let fcosh ins bld = monadic ins bld AST.fcosh

/// Lifts an FTANH.
let ftanh ins bld = monadic ins bld AST.ftanh

/// Lifts an FATANH.
let fatanh ins bld = monadic ins bld AST.fatanh

/// Lifts an FSINCOS, the one FPU instruction with two destinations: the sine
/// goes to the register the opcode word names in bits 9 to 7 and the cosine to
/// the one it names in bits 2 to 0, which the parser hands over as the third
/// and the second operand. The cosine is stored first, so that an encoding
/// naming the same register twice keeps the sine, as the manual says it does,
/// and the condition codes are the sine's.
let fsincos (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let cosReg = floatRegOf o2
    let sinReg = floatRegOf o3
    let s = tmpVar bld 64<rt>
    let c = tmpVar bld 64<rt>
    let r = tmpVar bld 64<rt>
    s := readFloatOpr bld ins ins.Size o1
    c := AST.fcos s
    r := AST.fsin s
    writeFloat bld cosReg c
    setFpuFlags bld r
    writeFloat bld sinReg r
  }

/// Lifts an FGETMAN, which gives the mantissa of its source as a number of at
/// least one and less than two, keeping the sign. A zero has no mantissa to
/// give and answers itself.
let fgetman ins bld =
  monadic ins bld (fun s ->
    let mag = s .& num64 0x7fffffffffffffffUL
    AST.ite (mag == AST.num0 64<rt>)
      s
      ((s .& num64 0x800fffffffffffffUL) .| num64 0x3ff0000000000000UL))

/// Lifts an FCMP, which reports how its destination stands against its source
/// and keeps nothing.
let fcmp (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let s = tmpVar bld 64<rt>
    let d = tmpVar bld 64<rt>
    s := readFloatOpr bld ins ins.Size o1
    d := readFloat bld (floatRegOf o2)
    setFpuCmpFlags bld d s
  }

/// Lifts an FTST, which reports what its one operand is.
let ftst (ins: Instruction) bld =
  lift bld ins {
    let s = tmpVar bld 64<rt>
    s := readFloatOpr bld ins ins.Size (getOneOpr ins)
    setFpuFlags bld s
  }

/// Returns the constant that an FMOVECR offset names, as the bits of the
/// double it comes to. The unit keeps these to extended precision and the
/// largest powers of ten it holds are far past what a double can carry, so
/// those come back as infinities; every offset the manual leaves undefined
/// answers zero, which is what the hardware is documented to give.
let private moveCrValue (offset: int64) =
  let bits (v: float) = BitConverter.DoubleToUInt64Bits v
  match offset with
  | 0x00L ->
    bits Math.PI
  | 0x0BL ->
    bits (Math.Log10 2.0)
  | 0x0CL ->
    bits Math.E
  | 0x0DL ->
    bits (1.0 / Math.Log 2.0)
  | 0x0EL ->
    bits (Math.Log10 Math.E)
  | 0x30L ->
    bits (Math.Log 2.0)
  | 0x31L ->
    bits (Math.Log 10.0)
  | 0x32L ->
    bits 1.0
  | n when n >= 0x33L && n <= 0x3fL ->
    bits (Math.Pow(10.0, float (1 <<< int (n - 0x33L))))
  | _ ->
    bits 0.0

/// Lifts an FMOVECR, which loads one of the constants the unit keeps in a
/// table of its own.
let fmovecr (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let offset =
      match o1 with
      | OpImm v -> v
      | _ -> raise InvalidOperandException
    let r = tmpVar bld 64<rt>
    r := num64 (moveCrValue offset)
    setFpuFlags bld r
    writeFloat bld (floatRegOf o2) r
  }

/// Lifts an FMOVE of one floating-point control register, which is the form an
/// FMOVEM of a single register takes.
let private fmoveControl (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    match o1, o2 with
    | OpReg((R.FPCR | R.FPSR | R.FPIAR) as r), dstOpr ->
      let dst = transOpr bld ins Sz.Long dstOpr
      writeLoc bld Sz.Long dst (regVar bld r)
    | srcOpr, OpReg((R.FPCR | R.FPSR | R.FPIAR) as r) ->
      let src = transOpr bld ins Sz.Long srcOpr
      regVar bld r := readLoc bld Sz.Long src
    | _ ->
      raise InvalidOperandException
  }

/// Lifts an FMOVE, whose two shapes -- moving a real number and moving a
/// control register -- share one mnemonic.
let fmove (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OpReg(R.FPCR | R.FPSR | R.FPIAR), _)
  | TwoOperands(_, OpReg(R.FPCR | R.FPSR | R.FPIAR)) ->
    fmoveControl ins bld
  | TwoOperands(_, OpReg r) when isFloatReg r ->
    fmoveData ins bld
  | TwoOperands(OpReg r, dstOpr) when isFloatReg r ->
    lift bld ins {
      let v = tmpVar bld 64<rt>
      v := readFloat bld r
      setFpuFlags bld v
      writeFloatOpr bld ins ins.Size dstOpr v
    }
  | _ ->
    (* An FMOVE to a packed-decimal destination, which this lifter does not
       model: the format has no counterpart in the intermediate language. *)
    lift bld ins { AST.sideEffect UnsupportedInstruction }

/// Writes a floating-point data register out in the extended-precision format,
/// which is the format an FMOVEM moves one in.
let private storeFloatReg bld addr reg =
  let struct (lo, hi) = RegisterHelper.toFloatParts reg
  storeExtended bld addr (regVar bld hi) (regVar bld lo)

/// Reads a floating-point data register back in from that same format.
let private loadFloatReg bld addr reg =
  let struct (lo, hi) = RegisterHelper.toFloatParts reg
  append bld {
    regVar bld hi := loadNative bld 16<rt> addr
    regVar bld lo := loadNative bld 64<rt> (addr .+ num32 4)
  }

/// Lifts an FMOVEM of the floating-point data registers, which moves each of
/// them to or from twelve bytes of memory. A predecrementing store fills
/// memory downwards from the last register of the bank, as an integer MOVEM
/// does; every other mode runs from the first register upwards.
let private fmovemData (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    match o1, o2 with
    | OpRegList regs, OpMem(PreDec an) ->
      let ar = regVar bld an
      let t = tmpVar bld 32<rt>
      t := ar
      for r in Array.rev regs do
        t := t .- num32 ExtendedBytes
        storeFloatReg bld t r
      ar := t
    | OpRegList regs, dstOpr ->
      let addr = tmpVar bld 32<rt>
      addr := floatAddrOf bld ins Sz.Extended dstOpr
      for i in 0 .. regs.Length - 1 do
        storeFloatReg bld (addr .+ num32 (i * ExtendedBytes)) regs[i]
    | OpMem(PostInc an), OpRegList regs ->
      let ar = regVar bld an
      let t = tmpVar bld 32<rt>
      t := ar
      for r in regs do
        loadFloatReg bld t r
        t := t .+ num32 ExtendedBytes
      ar := t
    | srcOpr, OpRegList regs ->
      let addr = tmpVar bld 32<rt>
      addr := floatAddrOf bld ins Sz.Extended srcOpr
      for i in 0 .. regs.Length - 1 do
        loadFloatReg bld (addr .+ num32 (i * ExtendedBytes)) regs[i]
    | _ ->
      raise InvalidOperandException
  }

/// Lifts an FMOVEM of the floating-point control registers, each of which is
/// one long word wherever it goes.
let private fmovemControl (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    match o1, o2 with
    | OpRegList regs, OpMem(PreDec an) ->
      let ar = regVar bld an
      let t = tmpVar bld 32<rt>
      t := ar
      for r in Array.rev regs do
        t := t .- num32 4
        storeNative bld t (regVar bld r)
      ar := t
    | OpRegList regs, dstOpr ->
      let addr = tmpVar bld 32<rt>
      addr := floatAddrOf bld ins Sz.Long dstOpr
      for i in 0 .. regs.Length - 1 do
        storeNative bld (addr .+ num32 (i * 4)) (regVar bld regs[i])
    | OpMem(PostInc an), OpRegList regs ->
      let ar = regVar bld an
      let t = tmpVar bld 32<rt>
      t := ar
      for r in regs do
        regVar bld r := loadNative bld 32<rt> t
        t := t .+ num32 4
      ar := t
    | srcOpr, OpRegList regs ->
      let addr = tmpVar bld 32<rt>
      addr := floatAddrOf bld ins Sz.Long srcOpr
      for i in 0 .. regs.Length - 1 do
        regVar bld regs[i] := loadNative bld 32<rt> (addr .+ num32 (i * 4))
    | _ ->
      raise InvalidOperandException
  }

/// Lifts an FMOVEM, whose list is of the data registers or of the control
/// ones, the size of the operation telling which.
let fmovem (ins: Instruction) bld =
  if ins.Size = Sz.Extended then fmovemData ins bld
  else fmovemControl ins bld

/// Returns the condition that a floating-point conditional opcode names, in
/// the numbering of the manual's conditional-test table. The signalling half
/// of that table tests the very same conditions as the ordinary half, so what
/// tells them apart -- whether a NaN raises -- costs nothing here.
let private fpCcIndex opcode =
  match opcode with
  | Op.FBF | Op.FSF | Op.FDBF | Op.FTRAPF -> 0
  | Op.FBEQ | Op.FSEQ | Op.FDBEQ | Op.FTRAPEQ -> 1
  | Op.FBOGT | Op.FSOGT | Op.FDBOGT | Op.FTRAPOGT -> 2
  | Op.FBOGE | Op.FSOGE | Op.FDBOGE | Op.FTRAPOGE -> 3
  | Op.FBOLT | Op.FSOLT | Op.FDBOLT | Op.FTRAPOLT -> 4
  | Op.FBOLE | Op.FSOLE | Op.FDBOLE | Op.FTRAPOLE -> 5
  | Op.FBOGL | Op.FSOGL | Op.FDBOGL | Op.FTRAPOGL -> 6
  | Op.FBOR | Op.FSOR | Op.FDBOR | Op.FTRAPOR -> 7
  | Op.FBUN | Op.FSUN | Op.FDBUN | Op.FTRAPUN -> 8
  | Op.FBUEQ | Op.FSUEQ | Op.FDBUEQ | Op.FTRAPUEQ -> 9
  | Op.FBUGT | Op.FSUGT | Op.FDBUGT | Op.FTRAPUGT -> 10
  | Op.FBUGE | Op.FSUGE | Op.FDBUGE | Op.FTRAPUGE -> 11
  | Op.FBULT | Op.FSULT | Op.FDBULT | Op.FTRAPULT -> 12
  | Op.FBULE | Op.FSULE | Op.FDBULE | Op.FTRAPULE -> 13
  | Op.FBNE | Op.FSNE | Op.FDBNE | Op.FTRAPNE -> 14
  | Op.FBT | Op.FST | Op.FDBT | Op.FTRAPT -> 15
  | Op.FBSF | Op.FSSF | Op.FDBSF | Op.FTRAPSF -> 16
  | Op.FBSEQ | Op.FSSEQ | Op.FDBSEQ | Op.FTRAPSEQ -> 17
  | Op.FBGT | Op.FSGT | Op.FDBGT | Op.FTRAPGT -> 18
  | Op.FBGE | Op.FSGE | Op.FDBGE | Op.FTRAPGE -> 19
  | Op.FBLT | Op.FSLT | Op.FDBLT | Op.FTRAPLT -> 20
  | Op.FBLE | Op.FSLE | Op.FDBLE | Op.FTRAPLE -> 21
  | Op.FBGL | Op.FSGL | Op.FDBGL | Op.FTRAPGL -> 22
  | Op.FBGLE | Op.FSGLE | Op.FDBGLE | Op.FTRAPGLE -> 23
  | Op.FBNGLE | Op.FSNGLE | Op.FDBNGLE | Op.FTRAPNGLE -> 24
  | Op.FBNGL | Op.FSNGL | Op.FDBNGL | Op.FTRAPNGL -> 25
  | Op.FBNLE | Op.FSNLE | Op.FDBNLE | Op.FTRAPNLE -> 26
  | Op.FBNLT | Op.FSNLT | Op.FDBNLT | Op.FTRAPNLT -> 27
  | Op.FBNGE | Op.FSNGE | Op.FDBNGE | Op.FTRAPNGE -> 28
  | Op.FBNGT | Op.FSNGT | Op.FDBNGT | Op.FTRAPNGT -> 29
  | Op.FBSNE | Op.FSSNE | Op.FDBSNE | Op.FTRAPSNE -> 30
  | Op.FBST | Op.FSST | Op.FDBST | Op.FTRAPST -> 31
  | _ -> raise InvalidOpcodeException

/// Returns the expression a floating-point conditional opcode tests. Only the
/// negative, the zero, and the not-a-number bits appear in the table; the
/// infinity bit the unit also keeps is never one of them.
let private fpCondExpr bld opcode =
  let fpsr = regVar bld R.FPSR
  let n = AST.extract fpsr 1<rt> 27
  let z = AST.extract fpsr 1<rt> 26
  let nan = AST.extract fpsr 1<rt> 24
  match fpCcIndex opcode % 16 with
  | 0 -> AST.b0
  | 1 -> z
  | 2 -> AST.not (nan .| z .| n)
  | 3 -> z .| AST.not (nan .| n)
  | 4 -> n .& AST.not (nan .| z)
  | 5 -> z .| (n .& AST.not nan)
  | 6 -> AST.not (nan .| z)
  | 7 -> AST.not nan
  | 8 -> nan
  | 9 -> nan .| z
  | 10 -> nan .| AST.not (n .| z)
  | 11 -> nan .| z .| AST.not n
  | 12 -> nan .| (n .& AST.not z)
  | 13 -> nan .| z .| n
  | 14 -> AST.not z
  | _ -> AST.b1

/// Lifts an FBcc.
let fbcc (ins: Instruction) bld =
  lift bld ins {
    AST.intercjmp (fpCondExpr bld ins.Opcode)
                  (branchTarget ins)
                  (fallThrough ins)
    return NoEndMark
  }

/// Lifts an FScc, which fills a byte with ones where its condition holds and
/// with zeroes where it does not.
let fscc (ins: Instruction) bld =
  lift bld ins {
    let dst = transOpr bld ins Sz.Byte (getOneOpr ins)
    writeLoc bld Sz.Byte dst
      (AST.ite (fpCondExpr bld ins.Opcode)
               (AST.not (AST.num0 8<rt>))
               (AST.num0 8<rt>))
  }

/// Lifts an FDBcc, which branches only where its condition fails and the
/// counter it decrements has not yet run past zero.
let fdbcc (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, _) = getTwoOprs ins
    let counter = AST.xtlo 16<rt> (regOf bld o1)
    let fall = fallThrough ins
    _if bld "FdbccTaken" (fpCondExpr bld ins.Opcode)
      (block { AST.interjmp fall InterJmpKind.Base })
      (block {
        counter := counter .- AST.num1 16<rt>
        AST.intercjmp (counter != AST.not (AST.num0 16<rt>))
                      (branchTarget ins)
                      fall
      })
    return NoEndMark
  }

/// Lifts an FTRAPcc, which traps where its condition holds.
let ftrapcc (ins: Instruction) bld =
  lift bld ins {
    _when bld "Ftrapcc" (fpCondExpr bld ins.Opcode)
      (block {
        AST.sideEffect (Exception FloatingPointException)
      })
  }


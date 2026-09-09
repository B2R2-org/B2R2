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
/// Translates the Alpha floating-point instructions.
///
/// Every floating-point register is a quadword holding a T_floating number,
/// the ones an S_floating instruction works on included: the architecture
/// keeps a single-precision number in the double-precision layout and does the
/// reordering on the way to and from memory, so a load or a store is where the
/// two formats meet and everything between them is one width.
/// </summary>
module internal B2R2.FrontEnd.Alpha.FloatLifter

open System
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Alpha.LiftHelper

/// The bit every floating-point number keeps its sign in.
let [<Literal>] private SignBit = 0x8000000000000000UL

/// <summary>
/// The T_floating number an S_floating one in memory stands for.
///
/// The exponent widens from eight bits to eleven, and the architecture names
/// the mapping MAP_S: an exponent of all ones or of all zeros is carried
/// across as it is, so that an exceptional value stays the same kind of
/// exceptional value, and anything between is rebiased. That last is what an
/// ordinary widening conversion would do; the two ends are what it would not,
/// which is why this is built out of bits rather than out of a cast.
/// </summary>
let private mapS (word: Expr) =
  let sign = AST.zext 64<rt> (AST.extract word 1<rt> 31) << num64 63
  let expo = AST.zext 64<rt> (AST.extract word 8<rt> 23)
  let frac = AST.zext 64<rt> (AST.extract word 23<rt> 0) << num64 29
  let allOnes = expo == num64 0xff
  let allZeros = expo == AST.num0 64<rt>
  let rebiased = expo .+ num64 0x380
  let mapped = AST.ite allOnes (num64 0x7ff) (AST.ite allZeros expo rebiased)
  sign .| (mapped << num64 52) .| frac

/// <summary>
/// The S_floating number in memory that a T_floating register stands for,
/// which is the reverse of the mapping above.
///
/// The architecture takes the sign and the low bit of the exponent's high half
/// and then the thirty bits below the three it ignores, and checks nothing:
/// whatever produced the register was to have produced a single already.
/// </summary>
let private unmapS (reg: Expr) =
  AST.concat (AST.extract reg 2<rt> 62) (AST.extract reg 30<rt> 29)

/// The plain floating-point loads and stores of a whole quadword, which is
/// what a T_floating number is in memory as well as in a register.
let ldt ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = tmpVar bld 64<rt>
    ea := transOpr bld o2
    regWrite bld (getReg o1) (loadNative bld 64<rt> ea)
  }

let stt ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = tmpVar bld 64<rt>
    ea := transOpr bld o2
    storeNative bld ea (transOpr bld o1)
  }

/// lds: a longword read from memory and spread into the register layout.
let lds ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = tmpVar bld 64<rt>
    let word = tmpVar bld 32<rt>
    ea := transOpr bld o2
    word := loadNative bld 32<rt> ea
    regWrite bld (getReg o1) (mapS word)
  }

/// sts: the register gathered back into the longword it stands for.
let sts ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = tmpVar bld 64<rt>
    ea := transOpr bld o2
    storeNative bld ea (unmapS (transOpr bld o1))
  }

/// <summary>
/// The value a register holds read at single precision, which is exact: what
/// the register holds is a single already, kept in the wider layout.
/// </summary>
let private toSingle e = AST.cast CastKind.FloatCast 32<rt> e

/// The same value put back in the layout a register keeps, which is what every
/// single-precision instruction leaves behind.
let private toDouble e = AST.cast CastKind.FloatCast 64<rt> e

/// <summary>
/// The arithmetic of two registers, done at the width the instruction names.
///
/// A single-precision instruction is the interesting half: its operands come
/// down to singles first, so that the one rounding is the rounding of a single
/// addition rather than a double one narrowed afterward, which is where a
/// doubly-rounded result would differ in its last bit.
/// </summary>
let private arith ins bld isSingle op =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = transOpr bld o1
    let b = transOpr bld o2
    let v =
      if isSingle then toDouble (op (toSingle a) (toSingle b))
      else op a b
    regWrite bld (getReg o3) v
  }

let adds ins bld = arith ins bld true AST.fadd

let subs ins bld = arith ins bld true AST.fsub

let muls ins bld = arith ins bld true AST.fmul

let divs ins bld = arith ins bld true AST.fdiv

let addt ins bld = arith ins bld false AST.fadd

let subt ins bld = arith ins bld false AST.fsub

let mult ins bld = arith ins bld false AST.fmul

let divt ins bld = arith ins bld false AST.fdiv

/// The square roots, at the two widths the IEEE instructions come in.
let private sqrt ins bld isSingle =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let v = transOpr bld o1
    let r =
      if isSingle then toDouble (AST.fsqrt (toSingle v))
      else AST.fsqrt v
    regWrite bld (getReg o2) r
  }

let sqrts ins bld = sqrt ins bld true

let sqrtt ins bld = sqrt ins bld false

/// <summary>
/// The comparisons, which leave a floating-point value in a register rather
/// than a bit: two, which is the nearest thing to a truth the format has, or a
/// true zero.
///
/// A branch on the result then reads it as any other floating-point register,
/// which is why the answer is a number and not a one.
/// </summary>
let private compare ins bld rel =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = transOpr bld o1
    let b = transOpr bld o2
    let two = numU64 0x4000000000000000UL 64<rt>
    regWrite bld (getReg o3) (AST.ite (rel a b) two (AST.num0 64<rt>))
  }

let cmpteq ins bld = compare ins bld AST.feq

let cmptlt ins bld = compare ins bld AST.flt

let cmptle ins bld = compare ins bld AST.fle

/// cmptun: true where the two cannot be ordered at all, which is to say where
/// either of them is not a number.
let cmptun ins bld =
  let unordered a b = IEEE754Double.isNaN a .| IEEE754Double.isNaN b
  compare ins bld unordered

/// <summary>
/// How an instruction rounds, which its qualifier names by its last letter:
/// chopped toward zero, toward minus infinity, or the mode the floating-point
/// control register holds.
///
/// Nothing else in the qualifier bears on what is computed -- the rest says
/// what to trap on, and a trap is not something this models -- so this is the
/// whole of what the qualifier is read for.
/// </summary>
type private Rounding =
  /// Toward zero.
  | Chopped
  /// Toward minus infinity.
  | MinusInfinity
  /// To the nearest, ties to even, which is how the machine rounds when the
  /// qualifier names no mode at all.
  | Nearest

/// Returns how the given qualifier rounds.
let private roundingOf qualifier =
  match qualifier with
  | Qualifier.C | Qualifier.UC | Qualifier.SUC | Qualifier.SUIC
  | Qualifier.SC | Qualifier.VC | Qualifier.SVC | Qualifier.SVIC ->
    Chopped
  | Qualifier.M | Qualifier.UM | Qualifier.SUM | Qualifier.SUIM
  | Qualifier.VM | Qualifier.SVM | Qualifier.SVIM ->
    MinusInfinity
  | _ ->
    Nearest

/// <summary>
/// cvttq: a floating-point number turned into the two's-complement one it
/// stands for, rounded the way the qualifier says.
///
/// A dynamic qualifier names the mode the control register holds, which this
/// reads as the nearest: what the register holds is not known while lifting,
/// and every mode a compiler emits it for is named outright instead.
/// </summary>
let cvttq (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let kind =
      match roundingOf ins.Qualifier with
      | Chopped -> CastKind.FtoITrunc
      | MinusInfinity -> CastKind.FtoIFloor
      | Nearest -> CastKind.FtoIRound
    regWrite bld (getReg o2) (AST.cast kind 64<rt> (transOpr bld o1))
  }

/// The integer conversions the other way, which read a whole quadword and
/// leave a number of the width the instruction names.
let private intToFloat ins bld isSingle =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let v = AST.cast CastKind.SIntToFloat 64<rt> (transOpr bld o1)
    regWrite bld (getReg o2) (if isSingle then toDouble (toSingle v) else v)
  }

let cvtqs ins bld = intToFloat ins bld true

let cvtqt ins bld = intToFloat ins bld false

/// cvtts: a double narrowed to a single, which is the one conversion of the
/// pair that rounds.
let cvtts ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    regWrite bld (getReg o2) (toDouble (toSingle (transOpr bld o1)))
  }

/// <summary>
/// cvtst: a single widened to a double, which the architecture calls the
/// identity transformation for a finite value and which is a move here.
///
/// That it is a move is the whole point of keeping a single in the double
/// layout: the widening has already happened, on the way in from memory.
/// </summary>
let cvtst ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    regWrite bld (getReg o2) (transOpr bld o1)
  }

/// cvtlq: the longword a register holds in the layout the architecture spreads
/// one across, gathered back into the low half of a quadword.
let cvtlq ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    regWrite bld (getReg o2) (AST.sext 64<rt> (unmapS (transOpr bld o1)))
  }

/// cvtql: a longword spread back out into that layout, which is where a
/// floating-point register keeps one.
let cvtql ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let v = transOpr bld o1
    let hi = AST.zext 64<rt> (AST.extract v 2<rt> 30) << num64 62
    let lo = AST.zext 64<rt> (AST.extract v 30<rt> 0) << num64 29
    regWrite bld (getReg o2) (hi .| lo)
  }

/// <summary>
/// The copy instructions, which take some high part of one register and the
/// rest of another.
///
/// Between them they are how a program negates a number, takes its absolute
/// value, or moves one at all: the architecture spends no opcode on any of
/// those, because taking the sign from one register and the magnitude from
/// another says all three.
/// </summary>
let private copy ins bld split negate =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = transOpr bld o1
    let b = transOpr bld o2
    let hi = numU64 (UInt64.MaxValue <<< (64 - split)) 64<rt>
    let taken = a .& hi
    let taken = if negate then taken <+> numU64 SignBit 64<rt> else taken
    regWrite bld (getReg o3) (taken .| (b .& AST.not hi))
  }

let cpys ins bld = copy ins bld 1 false

let cpysn ins bld = copy ins bld 1 true

let cpyse ins bld = copy ins bld 12 false

/// <summary>
/// Whether a floating-point register compares the given way against zero.
///
/// A number in this format read as a two's-complement integer orders the same
/// way it does as a number, which is what lets the tests below be integer
/// comparisons -- except for a negative zero, which reads as the smallest
/// integer of all and has to be folded onto a positive one wherever the sense
/// of the test would tell the two apart.
/// </summary>
module private FloatZero =
  /// The magnitude alone, which is what a test for being zero reads: it is the
  /// one test both zeros answer the same way.
  let magnitude v = v .& numU64 (SignBit - 1UL) 64<rt>

  /// The value with a negative zero folded onto a positive one, for the tests
  /// that would otherwise call it the smallest number there is.
  let folded v =
    AST.ite (v == numU64 SignBit 64<rt>) (AST.num0 64<rt>) v

  let isEqual v = magnitude v == AST.num0 64<rt>

  let isNotEqual v = magnitude v != AST.num0 64<rt>

  let isLess v = folded v ?< AST.num0 64<rt>

  let isGreaterOrEqual v = folded v ?>= AST.num0 64<rt>

  let isLessOrEqual v = v ?<= AST.num0 64<rt>

  let isGreater v = v ?> AST.num0 64<rt>

/// The floating-point branches, which test the register they name against
/// zero and go where their displacement points.
let private branchCond ins bld cond =
  lift bld ins {
    let struct (o1, _) = getTwoOprs ins
    AST.intercjmp (cond (transOpr bld o1))
                  (numU64 (branchTarget ins) 64<rt>)
                  (numU64 (nextAddr ins) 64<rt>)
    return NoEndMark
  }

let fbeq ins bld = branchCond ins bld FloatZero.isEqual

let fbne ins bld = branchCond ins bld FloatZero.isNotEqual

let fblt ins bld = branchCond ins bld FloatZero.isLess

let fble ins bld = branchCond ins bld FloatZero.isLessOrEqual

let fbgt ins bld = branchCond ins bld FloatZero.isGreater

let fbge ins bld = branchCond ins bld FloatZero.isGreaterOrEqual

/// The floating-point conditional moves, on the same tests against zero.
let private fcmov ins bld cond =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let dst = getReg o3
    let a = transOpr bld o1
    let b = transOpr bld o2
    regWrite bld dst (AST.ite (cond a) b (regRead bld dst))
  }

let fcmoveq ins bld = fcmov ins bld FloatZero.isEqual

let fcmovne ins bld = fcmov ins bld FloatZero.isNotEqual

let fcmovlt ins bld = fcmov ins bld FloatZero.isLess

let fcmovle ins bld = fcmov ins bld FloatZero.isLessOrEqual

let fcmovgt ins bld = fcmov ins bld FloatZero.isGreater

let fcmovge ins bld = fcmov ins bld FloatZero.isGreaterOrEqual

/// mt_fpcr/mf_fpcr: the floating-point control register, which an instruction
/// reaches only through a floating-point register.
let mtFpcr ins bld =
  lift bld ins {
    regVar bld Register.FPCR := transOpr bld (getOneOpr ins)
  }

let mfFpcr ins bld =
  lift bld ins {
    regWrite bld (getReg (getOneOpr ins)) (regVar bld Register.FPCR)
  }

/// ftoit/itoft: a whole quadword moved between the two register files, which
/// is how a program gets at the bits of a number without going through memory.
let ftoit ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    regWrite bld (getReg o2) (transOpr bld o1)
  }

let itoft ins bld = ftoit ins bld

/// ftois: the longword a floating-point register holds, gathered and widened
/// with its sign, which is the same reordering a store of one would do.
let ftois ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    regWrite bld (getReg o2) (AST.sext 64<rt> (unmapS (transOpr bld o1)))
  }

/// itofs: a longword spread into the layout a register keeps one in, which is
/// the same reordering a load of one would do.
let itofs ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    regWrite bld (getReg o2) (mapS (AST.xtlo 32<rt> (transOpr bld o1)))
  }

/// <summary>
/// The eleven-bit register exponent an eight-bit F_floating memory exponent
/// stands for, which the architecture names MAP_F.
///
/// Unlike the mapping S_floating needs, this one is a plain rebias with only
/// zero carried across as itself: an exponent of all ones is an ordinary
/// F_floating number rather than an infinity, F having neither infinities nor
/// NaNs to preserve. That difference between the two mappings is the whole of
/// why they are separate functions.
/// </summary>
let private mapF (expo: Expr) =
  AST.ite (expo == AST.num0 64<rt>) expo (expo .+ num64 0x380)

/// <summary>
/// The eight-bit memory exponent an eleven-bit register exponent stands for,
/// which is the reverse of the mapping above read off the bits rather than
/// subtracted: the high bit of the memory exponent is register bit 62 and its
/// low seven are register bits 58 through 52, the three between being the ones
/// a store ignores.
/// </summary>
let private unmapFExpo (reg: Expr) =
  AST.concat (AST.extract reg 1<rt> 62) (AST.extract reg 7<rt> 52)

/// <summary>
/// The four sixteen-bit words of a quadword in the reverse order.
///
/// This is the whole of what a G_floating load or a store does: what VAX put
/// in memory has its words the other way round from the register layout, and
/// the register layout is otherwise the same as a T_floating number's -- sign
/// at the top, then eleven bits of exponent, then the fraction. Being its own
/// inverse, the same function serves the load and the store.
/// </summary>
let private swapWords (v: Expr) =
  let w i = AST.extract v 16<rt> (i * 16)
  AST.concat (AST.concat (w 0) (w 1)) (AST.concat (w 2) (w 3))

/// <summary>
/// The T_floating number a G_floating one in a register stands for.
///
/// Both formats put the sign, an eleven-bit exponent and a fifty-two-bit
/// fraction in the same places, and both leave the leading fraction bit
/// implied -- but G reads its exponent as one greater than two would have it,
/// its value being the fraction taken as less than one rather than as at
/// least one. So the conversion either way is a rebias by two and nothing
/// else, which is what makes VAX arithmetic reachable at all: the IR has no
/// G_floating operator, and needs none.
///
/// A G_floating exponent of zero is a true zero where the sign is clear and a
/// reserved operand where it is set. The reserved operand takes an arithmetic
/// exception, which is not something this models, so both read as zero here.
/// </summary>
let private rebias (delta: int) (v: Expr) =
  let expo = AST.zext 64<rt> (AST.extract v 11<rt> 52)
  let sign = v .& numU64 SignBit 64<rt>
  let frac = v .& numU64 0xfffffffffffffUL 64<rt>
  let moved = ((expo .+ num64 delta) .& num64 0x7ff) << num64 52
  AST.ite (expo == AST.num0 64<rt>) (AST.num0 64<rt>) (sign .| moved .| frac)

/// The T_floating number a G_floating register holds.
let private ofG v = rebias -2 v

/// The G_floating number a T_floating value stands for.
let private toG v = rebias 2 v

/// ldf: an F_floating longword read from memory and spread into the register,
/// which holds it as the G_floating number it is worth.
let ldf ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = tmpVar bld 64<rt>
    let w = tmpVar bld 32<rt>
    ea := transOpr bld o2
    w := loadNative bld 32<rt> ea
    let sign = AST.zext 64<rt> (AST.extract w 1<rt> 15) << num64 63
    let expo = mapF (AST.zext 64<rt> (AST.extract w 8<rt> 7)) << num64 52
    let hi = AST.zext 64<rt> (AST.extract w 7<rt> 0) << num64 45
    let lo = AST.zext 64<rt> (AST.extract w 16<rt> 16) << num64 29
    regWrite bld (getReg o1) (sign .| expo .| hi .| lo)
  }

/// <summary>
/// stf: the register gathered back into the longword VAX put in memory.
///
/// The sign, the exponent and the top seven fraction bits go in the LOW half
/// of the longword and the rest of the fraction in the high one, which is the
/// order VAX wrote and the reverse of where a reader expects them: the
/// handbook puts the sign at bit 15 of the datum, not at bit 31.
/// </summary>
let stf ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = tmpVar bld 64<rt>
    let v = tmpVar bld 64<rt>
    ea := transOpr bld o2
    v := transOpr bld o1
    let low =
      AST.concat (AST.concat (AST.extract v 1<rt> 63) (unmapFExpo v))
                 (AST.extract v 7<rt> 45)
    storeNative bld ea (AST.concat (AST.extract v 16<rt> 29) low)
  }

/// ldg/stg: a G_floating quadword, which differs from the register layout only
/// in the order of its four words. A D_floating datum is moved by the same
/// pair, the reordering being the same.
let ldg ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = tmpVar bld 64<rt>
    ea := transOpr bld o2
    regWrite bld (getReg o1) (swapWords (loadNative bld 64<rt> ea))
  }

let stg ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let ea = tmpVar bld 64<rt>
    ea := transOpr bld o2
    storeNative bld ea (swapWords (transOpr bld o1))
  }

/// <summary>
/// The VAX arithmetic, done by converting each operand to the T_floating
/// number it is worth, operating there, and converting the result back.
///
/// The F_floating forms round to twenty-four bits of fraction on the way out,
/// which is F's precision and also a single's -- so the same narrowing that
/// the S_floating instructions use serves here, the difference between the two
/// formats being in the exponent rather than in the fraction.
/// </summary>
let private vaxArith ins bld isF op =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = ofG (transOpr bld o1)
    let b = ofG (transOpr bld o2)
    let r = op a b
    let r = if isF then toDouble (toSingle r) else r
    regWrite bld (getReg o3) (toG r)
  }

let addf ins bld = vaxArith ins bld true AST.fadd

let subf ins bld = vaxArith ins bld true AST.fsub

let mulf ins bld = vaxArith ins bld true AST.fmul

let divf ins bld = vaxArith ins bld true AST.fdiv

let addg ins bld = vaxArith ins bld false AST.fadd

let subg ins bld = vaxArith ins bld false AST.fsub

let mulg ins bld = vaxArith ins bld false AST.fmul

let divg ins bld = vaxArith ins bld false AST.fdiv

/// The square roots, at the two VAX widths.
let private vaxSqrt ins bld isF =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let r = AST.fsqrt (ofG (transOpr bld o1))
    let r = if isF then toDouble (toSingle r) else r
    regWrite bld (getReg o2) (toG r)
  }

let sqrtf ins bld = vaxSqrt ins bld true

let sqrtg ins bld = vaxSqrt ins bld false

/// <summary>
/// The G_floating comparisons, which leave a floating-point value rather than
/// a bit, as the IEEE ones do: the same pattern, which is two read as a
/// T_floating number and a half read as a G_floating one.
/// </summary>
let private vaxCompare ins bld rel =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let a = ofG (transOpr bld o1)
    let b = ofG (transOpr bld o2)
    let half = numU64 0x4000000000000000UL 64<rt>
    regWrite bld (getReg o3) (AST.ite (rel a b) half (AST.num0 64<rt>))
  }

let cmpgeq ins bld = vaxCompare ins bld AST.feq

let cmpglt ins bld = vaxCompare ins bld AST.flt

let cmpgle ins bld = vaxCompare ins bld AST.fle

/// cvtgf: a G_floating number narrowed to F's precision, which leaves it in
/// the same register layout: what an F_floating register holds is the
/// G_floating number it is worth.
let cvtgf ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let v = ofG (transOpr bld o1)
    regWrite bld (getReg o2) (toG (toDouble (toSingle v)))
  }

/// cvtgq: a G_floating number turned into the two's-complement one it stands
/// for, rounded the way the qualifier says.
let cvtgq (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let kind =
      match roundingOf ins.Qualifier with
      | Chopped -> CastKind.FtoITrunc
      | MinusInfinity -> CastKind.FtoIFloor
      | Nearest -> CastKind.FtoIRound
    regWrite bld (getReg o2) (AST.cast kind 64<rt> (ofG (transOpr bld o1)))
  }

/// cvtqf/cvtqg: a whole quadword turned into a VAX number of either width.
let private intToVax ins bld isF =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let v = AST.cast CastKind.SIntToFloat 64<rt> (transOpr bld o1)
    let v = if isF then toDouble (toSingle v) else v
    regWrite bld (getReg o2) (toG v)
  }

let cvtqf ins bld = intToVax ins bld true

let cvtqg ins bld = intToVax ins bld false

/// <summary>
/// cvtdg: a D_floating number turned into the G_floating one that carries as
/// much of it as G can hold.
///
/// D keeps F's eight-bit exponent and spends the rest of the quadword on
/// fraction, so it has fifty-five fraction bits where G has fifty-two: the
/// exponent widens by the same mapping an F_floating load uses, and the low
/// three fraction bits are dropped. That loss is the architecture's -- D has no
/// arithmetic of its own, and the handbook's own advice is to reach it by
/// converting to G, operating, and converting back.
/// </summary>
let cvtdg ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let v = tmpVar bld 64<rt>
    v := transOpr bld o1
    let sign = v .& numU64 SignBit 64<rt>
    let expo = mapF (AST.zext 64<rt> (AST.extract v 8<rt> 55)) << num64 52
    let frac = AST.zext 64<rt> (AST.extract v 52<rt> 3)
    regWrite bld (getReg o2) (sign .| expo .| frac)
  }

/// cvtgd: the reverse, which spreads the fraction back out and narrows the
/// exponent by picking its bits the way a store does.
let cvtgd ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let v = tmpVar bld 64<rt>
    v := transOpr bld o1
    let sign = v .& numU64 SignBit 64<rt>
    let expo = AST.zext 64<rt> (unmapFExpo v) << num64 55
    let frac = AST.zext 64<rt> (AST.extract v 52<rt> 0) << num64 3
    regWrite bld (getReg o2) (sign .| expo .| frac)
  }

/// <summary>
/// itoff: a longword moved from a general register into the layout an
/// F_floating register keeps one in.
///
/// It is the load's rearrangement without the load's word swapping, which the
/// handbook states outright: what an integer register holds is already in the
/// order the register wants, so only the exponent is widened.
/// </summary>
let itoff ins bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let v = tmpVar bld 64<rt>
    v := transOpr bld o1
    let sign = AST.zext 64<rt> (AST.extract v 1<rt> 31) << num64 63
    let expo = mapF (AST.zext 64<rt> (AST.extract v 8<rt> 23)) << num64 52
    let frac = AST.zext 64<rt> (AST.extract v 23<rt> 0) << num64 29
    regWrite bld (getReg o2) (sign .| expo .| frac)
  }

// vim: set tw=80 sts=2 sw=2:

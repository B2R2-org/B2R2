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

module internal B2R2.FrontEnd.Intel.X87Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.Intel
open B2R2.FrontEnd.Intel.LiftingUtils

#if !EMULATION
let private undefC0 = AST.undef 1<rt> "C0 is undefined."

let private undefC1 = AST.undef 1<rt> "C1 is undefined."

let private undefC2 = AST.undef 1<rt> "C2 is undefined."

let private undefC3 = AST.undef 1<rt> "C3 is undefined."

let private allCFlagsUndefined bld =
  append bld {
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC1) := undefC1
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
  }

let private cflagsUndefined023 bld =
  append bld {
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
  }
#endif

let inline private getFPUPseudoRegVars bld r =
  struct (pseudoRegVar bld r 2, pseudoRegVar bld r 1)

let private updateC1OnLoad bld =
  append bld {
    let top = regVar bld R.FTOP
    let c1Flag = regVar bld R.FSWC1
    (* Top value has been wrapped around, which means stack overflow in B2R2. *)
    direct c1Flag := (top == AST.num0 8<rt>)
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

let private updateC1OnStore bld =
  append bld {
    let top = regVar bld R.FTOP
    let c1Flag = regVar bld R.FSWC1
    (* Top value has been wrapped around, which means stack underflow in
       B2R2. *)
    direct c1Flag := (top != numI32 7 8<rt>)
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

/// The stack registers, from the top of the stack down.
let private stackRegs =
  [ R.ST0; R.ST1; R.ST2; R.ST3; R.ST4; R.ST5; R.ST6; R.ST7 ]

/// A sixty-four-bit constant.
let inline private num64 (n: uint64) = numU64 n 64<rt>

/// How much wider the bias of an extended-precision exponent is than that of a
/// double-precision one: 16383 against 1023.
let [<Literal>] private BiasDiff = 0x3c00UL

/// The fraction of a double, below its exponent.
let [<Literal>] private FracMask = 0xfffffffffffffUL

/// A double-precision infinity, which is what every value too large for a
/// double becomes.
let [<Literal>] private DoubleInf = 0x7ff0000000000000UL

/// The bit that makes a double-precision NaN quiet.
let [<Literal>] private QuietBit = 0x0008000000000000UL

/// The real indefinite: the quiet NaN the FPU answers an invalid operation
/// with, such as an infinity less an infinity.
let [<Literal>] private Indefinite = 0xfff8000000000000UL

/// A negative double-precision infinity.
let [<Literal>] private NegInf = 0xfff0000000000000UL

/// The sign bit of a double, which is also where the integer bit of an
/// extended-precision mantissa sits.
let [<Literal>] private TopBit = 0x8000000000000000UL

#if !EMULATION
/// The bit that makes an extended-precision NaN quiet.
let [<Literal>] private ExtQuietBit = 0x4000000000000000UL
#endif

/// A shift count kept within a word, so that an operand computed for a case
/// that does not hold still shifts by something a word allows.
let inline private inWord n = n .& numI32 63 64<rt>

/// Rounds `a` shifted down by `s` to the nearest whole number, ties to the
/// even one: what the shift drops decides, against half of the last place
/// kept.
let private roundShifted a s =
  let one = AST.num1 64<rt>
  let kept = a >> s
  let dropped = a .& ((one << s) .- one)
  let half = one << inWord (s .- one)
  let up = (dropped .> half) .| ((dropped == half) .& AST.xtlo 1<rt> kept)
  kept .+ AST.zext 64<rt> up

/// The finite double nearest an extended-precision value of biased exponent
/// `e` and mantissa `a`, for an `e` from BiasDiff - 51 to BiasDiff + 0x7fe:
/// a normal double, which keeps fifty-three bits of the sixty-four, or a
/// denormal, which keeps fewer the further below BiasDiff the exponent is --
/// fifty-two at it, down to one. Rounding up may carry the mantissa into the
/// exponent, out of the largest denormal into the smallest normal or out of
/// the largest normal into infinity, and each is the right answer.
let private finiteToDouble e a =
  let normal = e .> num64 BiasDiff
  let shift = AST.ite normal (numI32 11 64<rt>) (num64 (BiasDiff + 12UL) .- e)
  let exp = (e .- num64 (BiasDiff + 1UL)) << numI32 52 64<rt>
  AST.ite normal exp (AST.num0 64<rt>) .+ roundShifted a (inWord shift)

/// The double an extended-precision infinity or NaN becomes. An infinity stays
/// one, and a NaN keeps as much of its payload as a double has room for, its
/// quiet bit with it; one whose payload all lies below that room would come
/// out an infinity, so it is quieted instead.
let private specialToDouble a =
  let payload = (a >> numI32 11 64<rt>) .& num64 FracMask
  let nan = AST.ite (payload == AST.num0 64<rt>) (num64 QuietBit) payload
  let isInf = (a << AST.num1 64<rt>) == AST.num0 64<rt>
  num64 DoubleInf .| AST.ite isInf (AST.num0 64<rt>) nan

/// Returns, in a temporary, the double nearest the extended-precision value
/// whose sign and exponent are `b` and whose mantissa is `a`, ties to even,
/// which is what storing the value as a double does: an exponent too large for
/// a double gives an infinity, and one too small a denormal or a zero. Half
/// the smallest denormal sits one exponent below where finiteToDouble stops,
/// and rounds up from anything above it.
let private extendedToDouble bld b a =
  let e = tmpVar bld 64<rt>
  let d = tmpVar bld 64<rt>
  let sign = (AST.zext 64<rt> b .& num64 0x8000UL) << numI32 48 64<rt>
  let aboveHalf = AST.zext 64<rt> (a .> num64 TopBit)
  let tiny =
    AST.ite (e == num64 (BiasDiff - 52UL)) aboveHalf (AST.num0 64<rt>)
  let finite =
    AST.ite (e .>= num64 (BiasDiff - 51UL)) (finiteToDouble e a) tiny
  let ordinary =
    AST.ite (e .>= num64 (BiasDiff + 0x7ffUL)) (num64 DoubleInf) finite
  append bld {
    direct e := AST.zext 64<rt> b .& num64 0x7fffUL
    direct d := AST.ite (e == num64 0x7fffUL) (specialToDouble a) ordinary
    direct d := sign .| d
  }
  d

/// One step of the search for a denormal fraction's leading one: if the top
/// `k` bits of `m` are empty, shift it up by `k` and count `k` in `sh`. Six
/// steps, from thirty-two down to one, bring any nonzero word's leading one to
/// the top. The count is written before the mantissa, so that both statements
/// test the mantissa as it stood before the step.
let private normalizeStep bld m sh k =
  let empty = (m >> numI32 (64 - k) 64<rt>) == AST.num0 64<rt>
  append bld {
    direct sh := AST.ite empty (sh .+ numI32 k 64<rt>) sh
    direct m := AST.ite empty (m << numI32 k 64<rt>) m
  }

/// Brings the leading one of a nonzero word `v` to its top, returning the word
/// and how far it moved, in temporaries.
let private normalized bld v =
  let struct (m, sh) = tmpVars2 bld 64<rt>
  append bld {
    direct m := v
    direct sh := AST.num0 64<rt>
  }
  for k in [ 32; 16; 8; 4; 2; 1 ] do normalizeStep bld m sh k
  struct (m, sh)

/// The word with the sign and the exponent that doubleToExtended gives the
/// double whose sign is in `t` and whose exponent and fraction are `expD` and
/// `frac`, where a denormal's leading one sat `sh` places below the top.
let private extendedHi t expD frac sh =
  let sign = AST.xtlo 16<rt> (t >> numI32 48 64<rt>) .& numI32 0x8000 16<rt>
  let denormal =
    AST.ite (frac == AST.num0 64<rt>)
      (AST.num0 16<rt>)
      (AST.xtlo 16<rt> (num64 BiasDiff .- sh))
  let normal =
    AST.ite (expD == num64 0x7ffUL)
      (numI32 0x7fff 16<rt>)
      (AST.xtlo 16<rt> expD .+ numI32 0x3c00 16<rt>)
  sign .| AST.ite (expD == AST.num0 64<rt>) denormal normal

/// Returns the extended-precision halves of the double `v`, exactly: the word
/// with its sign and exponent, and its mantissa with the leading one a double
/// only implies made explicit. A denormal has no leading one to make explicit,
/// so it is normalised instead -- its leading one brought to the top, and the
/// distance it travelled taken off the exponent. Extended precision has room
/// for every one of them, which keeps the way back through extendedToDouble
/// exact.
let private doubleToExtended bld v =
  let struct (t, expD, frac) = tmpVars3 bld 64<rt>
  let lo = tmpVar bld 64<rt>
  let hi = tmpVar bld 16<rt>
  append bld {
    direct t := v
    direct expD := (t >> numI32 52 64<rt>) .& num64 0x7ffUL
    direct frac := t .& num64 FracMask
  }
  let struct (m, sh) = normalized bld (frac << numI32 12 64<rt>)
  append bld {
    direct hi := extendedHi t expD frac sh
    direct lo :=
      AST.ite (expD == AST.num0 64<rt>)
        (AST.ite (frac == AST.num0 64<rt>) (AST.num0 64<rt>) m)
        (num64 TopBit .| (frac << numI32 11 64<rt>))
  }
  struct (hi, lo)

/// The magnitude of a double: the double with its sign cleared.
let private magnitudeOf v = v .& num64 0x7fffffffffffffffUL

/// Whether a double is a NaN: its magnitude lies above an infinity's.
let private isNaND v = magnitudeOf v .> num64 DoubleInf

/// Whether a double is a NaN or an infinity.
let private isNonFinite v = magnitudeOf v .>= num64 DoubleInf

/// A double with its quiet bit set if it is a NaN, which is what the FPU makes
/// of a signalling NaN it loads from or stores to a double.
let private quietIfNaN v = AST.ite (isNaND v) (v .| num64 QuietBit) v

/// Of two doubles, at least one a NaN, the one the FPU hands back, quieted
/// (Intel SDM vol. 1, table 4-7): the NaN, or of two NaNs the one with the
/// larger significand, and of two with the same significand the positive one.
/// The quiet bit belongs to the significand, so a quiet NaN wins over a
/// signalling one, which is the table's first rule.
let private nanOf a b =
  let fa = a .& num64 FracMask
  let fb = b .& num64 FracMask
  let larger = AST.ite (fa == fb) (AST.not (AST.xthi 1<rt> a)) (fa .> fb)
  let first = isNaND a .& (AST.not (isNaND b) .| larger)
  AST.ite first a b .| num64 QuietBit

/// The result `r` of an operation on `a` and `b`, unless either is a NaN: then
/// the NaN nanOf picks. IEEE arithmetic gives back a NaN too, but leaves open
/// which of two, and a function the IR computes may give back another.
let private orNaNOf a b r = AST.ite (isNaND a .| isNaND b) (nanOf a b) r

#if EMULATION
(* An emulator keeps a stack register as the double its value is computed in,
   in the register's mantissa half, and leaves the other half alone. Every
   operation computes in double precision anyway, and converting to and from
   the extended form around each one was most of what an x87 instruction cost
   to run. Only a load or store of the extended format itself converts, which
   is where a value no double can hold is rounded to one. *)

/// The double a stack register holds, as an expression to use at once. It is
/// the register itself, so it names what the register holds when the
/// statement using it runs.
let private readST bld reg = pseudoRegVar bld reg 1
#else
/// The double a stack register holds, in a temporary: the register keeps its
/// value in extended precision, which every operation computes from as a
/// double.
let private readST bld reg =
  let struct (b, a) = getFPUPseudoRegVars bld reg
  extendedToDouble bld b a
#endif

/// The double a stack register holds now, kept in a temporary that a write to
/// the register, or a push or a pop moving it, leaves alone.
let private takeST bld reg =
#if EMULATION
  let t = tmpVar bld 64<rt>
  append bld {
    direct t := readST bld reg
  }
  t
#else
  readST bld reg
#endif

/// Writes a double to a stack register.
let private writeST bld reg v =
#if EMULATION
  append bld {
    direct (pseudoRegVar bld reg 1) := v
  }
#else
  let struct (hi, lo) = doubleToExtended bld v
  let struct (b, a) = getFPUPseudoRegVars bld reg
  append bld {
    direct b := hi
    direct a := lo
  }
#endif

/// Copies one stack register into another.
let private copyST bld dst src =
#if EMULATION
  append bld {
    direct (pseudoRegVar bld dst 1) := pseudoRegVar bld src 1
  }
#else
  let struct (dstB, dstA) = getFPUPseudoRegVars bld dst
  let struct (srcB, srcA) = getFPUPseudoRegVars bld src
  append bld {
    direct dstA := srcA
    direct dstB := srcB
  }
#endif

/// Empties a stack register to a zero.
let private clearST bld reg =
#if EMULATION
  append bld {
    direct (pseudoRegVar bld reg 1) := AST.num0 64<rt>
  }
#else
  let struct (b, a) = getFPUPseudoRegVars bld reg
  append bld {
    direct b := AST.num0 16<rt>
    direct a := AST.num0 64<rt>
  }
#endif

/// Copies `src` into a stack register where `cond` holds.
let private selectST bld cond dst src =
#if EMULATION
  let d = pseudoRegVar bld dst 1
  append bld {
    direct d := AST.ite cond (pseudoRegVar bld src 1) d
  }
#else
  let struct (srcB, srcA) = getFPUPseudoRegVars bld src
  let struct (dstB, dstA) = getFPUPseudoRegVars bld dst
  append bld {
    direct dstB := AST.ite cond srcB dstB
    direct dstA := AST.ite cond srcA dstA
  }
#endif

/// Sets a stack register's value aside, as it is kept, for unstashST to put
/// back into a stack register: a rotation, an exchange or a push moves the
/// register it came from first.
let private stashST bld reg =
#if EMULATION
  takeST bld reg
#else
  let struct (b, a) = getFPUPseudoRegVars bld reg
  let tmpB = tmpVar bld 16<rt>
  let tmpA = tmpVar bld 64<rt>
  append bld {
    direct tmpB := b
    direct tmpA := a
  }
  struct (tmpB, tmpA)
#endif

/// Puts a value stashST or stashDouble set aside into a stack register.
let private unstashST bld reg stash =
#if EMULATION
  writeST bld reg stash
#else
  let struct (tmpB, tmpA) = stash
  let struct (b, a) = getFPUPseudoRegVars bld reg
  append bld {
    direct b := tmpB
    direct a := tmpA
  }
#endif

/// Sets a double aside as a stack register keeps it, for unstashST.
let private stashDouble bld v =
#if EMULATION
  let t = tmpVar bld 64<rt>
  append bld {
    direct t := v
  }
  t
#else
  doubleToExtended bld v
#endif

/// Reads the extended-precision value whose mantissa is at `lo` and whose sign
/// and exponent are at `hi`, setting it aside as a stack register keeps it, for
/// unstashST.
let private loadExtended bld lo hi =
  let tmpB = tmpVar bld 16<rt>
  let tmpA = tmpVar bld 64<rt>
  append bld {
    direct tmpB := AST.loadLE 16<rt> hi
    direct tmpA := AST.loadLE 64<rt> lo
  }
#if EMULATION
  extendedToDouble bld tmpB tmpA
#else
  struct (tmpB, tmpA)
#endif

/// Writes a stack register out in extended precision: its mantissa at `lo`, and
/// its sign and exponent at `hi`.
let private storeExtended bld lo hi reg =
#if EMULATION
  let struct (hiWord, mantissa) = doubleToExtended bld (readST bld reg)
#else
  let struct (hiWord, mantissa) = getFPUPseudoRegVars bld reg
#endif
  append bld {
    AST.store Endian.Little lo mantissa
    AST.store Endian.Little hi hiWord
  }

/// The sign bit of a stack register.
let private signOfST bld reg =
#if EMULATION
  AST.xthi 1<rt> (pseudoRegVar bld reg 1)
#else
  AST.xthi 1<rt> (pseudoRegVar bld reg 2)
#endif

let private pushFPUStack bld =
  let top = regVar bld R.FTOP
  (* We increment TOP here (which is the opposite way of what the manual says),
     because it is more intuitive to consider it as a counter. *)
  append bld {
    extractDstAssign top (top .+ AST.num1 8<rt>)
  }
  copyST bld R.ST7 R.ST6
  copyST bld R.ST6 R.ST5
  copyST bld R.ST5 R.ST4
  copyST bld R.ST4 R.ST3
  copyST bld R.ST3 R.ST2
  copyST bld R.ST2 R.ST1
  copyST bld R.ST1 R.ST0

let private popFPUStack bld =
  let top = regVar bld R.FTOP
  (* We decrement TOP here (the opposite way compared to the manual) because it
     is more intuitive, because it is more intuitive to consider it as a
     counter. *)
  append bld {
    extractDstAssign top (top .- AST.num1 8<rt>)
  }
  copyST bld R.ST0 R.ST1
  copyST bld R.ST1 R.ST2
  copyST bld R.ST2 R.ST3
  copyST bld R.ST3 R.ST4
  copyST bld R.ST4 R.ST5
  copyST bld R.ST5 R.ST6
  copyST bld R.ST6 R.ST7
  clearST bld R.ST7

let inline private getLoadAddressExpr (src: Expr) =
  match src with
  | Load(Addr = addr) -> struct (addr, Expr.typeOf addr)
  | _ -> Terminator.impossible ()

/// A floating-point operand from memory as a double: a single widened, which
/// is exact, or a double as it is.
let private asDouble (opr: Expr) =
  if Expr.typeOf opr = 64<rt> then opr
  else AST.cast CastKind.FloatCast 64<rt> opr

/// Pushes a double onto the stack.
let private pushDouble bld v =
  let stash = stashDouble bld v
  pushFPUStack bld
  unstashST bld R.ST0 stash
  updateC1OnLoad bld

let private fpuLoad (ins: Instruction) bld v =
  lift bld ins {
    pushDouble bld v
  }

/// The value FLD pushes, set aside before the push moves the stack: an
/// extended value from memory or a stack register as it stands, a single or a
/// double from memory as a double, a signalling NaN quieted.
let private stashOperand bld (opr: Expr) =
  match opr with
  | Load(Addr = addr) when Expr.typeOf opr = 80<rt> ->
    let hi = addr .+ numI32 8 (Expr.typeOf addr)
    loadExtended bld addr hi
  | BinOp(Left = Var(RegisterID = r); Right = Var _) ->
    stashST bld (RegisterHelper.pseudoRegToReg (Register.ofRegID r))
  | _ ->
    let t = tmpVar bld 64<rt>
    append bld {
      direct t := asDouble opr
    }
    stashDouble bld (quietIfNaN t)

let fld (ins: Instruction) bld =
  lift bld ins {
    let stash = stashOperand bld (transOneOpr ins bld)
    pushFPUStack bld
    unstashST bld R.ST0 stash
    updateC1OnLoad bld
  }

/// Stores ST(0) in the format the memory operand names: as a single or a
/// double, rounded to it and a signalling NaN quieted, or as it stands in
/// extended precision.
let private storeOperand bld (dst: Expr) =
  match Expr.typeOf dst with
  | 80<rt> ->
    let struct (addr, addrSize) = getLoadAddressExpr dst
    storeExtended bld addr (addr .+ numI32 8 addrSize) R.ST0
  | 64<rt> ->
    append bld {
      direct dst := quietIfNaN (readST bld R.ST0)
    }
  | _ ->
    append bld {
      direct dst := AST.cast CastKind.FloatCast 32<rt> (readST bld R.ST0)
    }

let ffst (ins: Instruction) bld doPop =
  lift bld ins {
    match ins.Operands with
    | OneOperand(OprReg r) ->
      copyST bld r R.ST0
    | OneOperand(opr) ->
      storeOperand bld (transOpr ins bld false opr)
    | _ ->
      raise InvalidOperandException
    if doPop then popFPUStack bld else ()
    updateC1OnStore bld
  }

let fild (ins: Instruction) bld =
  lift bld ins {
    let oprExpr = transOneOpr ins bld
    pushDouble bld (AST.cast CastKind.SIntToFloat 64<rt> oprExpr)
  }

let fist (ins: Instruction) bld doPop =
  lift bld ins {
    let oprExpr = transOneOpr ins bld
    let oprSize = Expr.typeOf oprExpr
    (* The stack value is brought down to a double and converted from there,
       whatever width the destination is. Bringing it down to the destination's
       own width first -- a half for a word destination -- is a second rounding
       the instruction does not perform, and leaves a format the conversion
       cannot read. FISTTP does the same. *)
    (* FCW bits 11:10 are the rounding control, in the encoding the IR's own
       rounding mode uses. *)
    let rc = AST.zext 8<rt> (AST.extract (regVar bld R.FCW) 2<rt> 10)
    let body = AST.cast CastKind.FloatToSInt oprSize (readST bld R.ST0)
    direct oprExpr := AST.roundCtrl rc body
    if doPop then popFPUStack bld else ()
    updateC1OnStore bld
  }

let fisttp (ins: Instruction) bld =
  lift bld ins {
    let oprExpr = transOneOpr ins bld
    let oprSize = Expr.typeOf oprExpr
    let v = readST bld R.ST0
    direct oprExpr := AST.floatToSInt RoundingMode.TowardZero oprSize v
    popFPUStack bld
    direct (regVar bld R.FSWC1) := AST.b0
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

let private getTwoBCDDigits addrExpr addrSize startPos =
  let byteValue = AST.loadLE 8<rt> (addrExpr .+ numI32 startPos addrSize)
  let d1 =
    let msb = AST.extract byteValue 1<rt> 3
    (byteValue .& (AST.sext 8<rt> msb .| numI32 0xF0 8<rt>)) |> AST.sext 64<rt>
  let d2 =
    let msb = AST.extract byteValue 1<rt> 7
    ((byteValue >> numI32 4 8<rt>) .& (AST.sext 8<rt> msb .| numI32 0xF0 8<rt>))
    |> AST.sext 64<rt>
  struct (d1, d2)

let private bcdToInt intgr addrExpr addrSize bld =
  append bld {
    let struct (d1, d2) = getTwoBCDDigits addrExpr addrSize 0
    let struct (d3, d4) = getTwoBCDDigits addrExpr addrSize 1
    let struct (d5, d6) = getTwoBCDDigits addrExpr addrSize 2
    let struct (d7, d8) = getTwoBCDDigits addrExpr addrSize 3
    let struct (d9, d10) = getTwoBCDDigits addrExpr addrSize 4
    let struct (d11, d12) = getTwoBCDDigits addrExpr addrSize 5
    let struct (d13, d14) = getTwoBCDDigits addrExpr addrSize 6
    let struct (d15, d16) = getTwoBCDDigits addrExpr addrSize 7
    let struct (d17, d18) = getTwoBCDDigits addrExpr addrSize 8
    let signByte = AST.loadLE 8<rt> (addrExpr .+ numI32 9 addrSize)
    let signBit = AST.xthi 1<rt> signByte
    direct intgr := d1
    direct intgr := intgr .+ d2 .* numI64 10L 64<rt>
    direct intgr := intgr .+ d3 .* numI64 100L 64<rt>
    direct intgr := intgr .+ d4 .* numI64 1000L 64<rt>
    direct intgr := intgr .+ d5 .* numI64 10000L 64<rt>
    direct intgr := intgr .+ d6 .* numI64 100000L 64<rt>
    direct intgr := intgr .+ d7 .* numI64 1000000L 64<rt>
    direct intgr := intgr .+ d8 .* numI64 10000000L 64<rt>
    direct intgr := intgr .+ d9 .* numI64 100000000L 64<rt>
    direct intgr := intgr .+ d10 .* numI64 1000000000L 64<rt>
    direct intgr := intgr .+ d11 .* numI64 10000000000L 64<rt>
    direct intgr := intgr .+ d12 .* numI64 100000000000L 64<rt>
    direct intgr := intgr .+ d13 .* numI64 1000000000000L 64<rt>
    direct intgr := intgr .+ d14 .* numI64 10000000000000L 64<rt>
    direct intgr := intgr .+ d15 .* numI64 100000000000000L 64<rt>
    direct intgr := intgr .+ d16 .* numI64 1000000000000000L 64<rt>
    direct intgr := intgr .+ d17 .* numI64 10000000000000000L 64<rt>
    direct intgr := intgr .+ d18 .* numI64 100000000000000000L 64<rt>
    direct (AST.xthi 1<rt> intgr) := signBit
  }

let fbld (ins: Instruction) bld =
  lift bld ins {
    let src = transOneOpr ins bld
    let struct (addrExpr, addrSize) = getLoadAddressExpr src
    let intgr = tmpVar bld 64<rt>
    bcdToInt intgr addrExpr addrSize bld
    pushDouble bld (AST.cast CastKind.SIntToFloat 64<rt> intgr)
  }

let private storeTwoDigitBCD n10 addrExpr addrSize intgr pos bld =
  append bld {
    let d1 = (AST.xtlo 8<rt> (intgr .% n10)) .& (numI32 0xF 8<rt>)
    let d2 = (AST.xtlo 8<rt> ((intgr ./ n10) .% n10)) .& (numI32 0xF 8<rt>)
    let ds = (d2 << (numI32 4 8<rt>)) .| d1
    AST.store Endian.Little (addrExpr .+ numI32 pos addrSize) ds
  }

let private storeBCD addrExpr addrSize intgr bld =
  append bld {
    let n10 = numI32 10 64<rt>
    let n100 = numI32 100 64<rt>
    let sign = tmpVar bld 1<rt>
    let signByte = (AST.zext 8<rt> sign) << numI32 7 8<rt>
    direct sign := AST.xthi 1<rt> intgr
    storeTwoDigitBCD n10 addrExpr addrSize intgr 0 bld
    direct intgr := intgr ./ n100
    storeTwoDigitBCD n10 addrExpr addrSize intgr 1 bld
    direct intgr := intgr ./ n100
    storeTwoDigitBCD n10 addrExpr addrSize intgr 2 bld
    direct intgr := intgr ./ n100
    storeTwoDigitBCD n10 addrExpr addrSize intgr 3 bld
    direct intgr := intgr ./ n100
    storeTwoDigitBCD n10 addrExpr addrSize intgr 4 bld
    direct intgr := intgr ./ n100
    storeTwoDigitBCD n10 addrExpr addrSize intgr 5 bld
    direct intgr := intgr ./ n100
    storeTwoDigitBCD n10 addrExpr addrSize intgr 6 bld
    direct intgr := intgr ./ n100
    storeTwoDigitBCD n10 addrExpr addrSize intgr 7 bld
    direct intgr := intgr ./ n100
    storeTwoDigitBCD n10 addrExpr addrSize intgr 8 bld
    AST.store Endian.Little (addrExpr .+ numI32 9 addrSize) signByte
  }

let fbstp (ins: Instruction) bld =
  lift bld ins {
    let dst = transOneOpr ins bld
    let struct (addrExpr, addrSize) = getLoadAddressExpr dst
    let intgr = tmpVar bld 64<rt>
    let v = readST bld R.ST0
    direct intgr := AST.floatToSInt RoundingMode.ToNearestEven 64<rt> v
    storeBCD addrExpr addrSize intgr bld
    popFPUStack bld
    updateC1OnStore bld
  }

let fxch (ins: Instruction) bld =
  lift bld ins {
    let other =
      match ins.Operands with
      | OneOperand(OprReg reg) -> reg
      | NoOperand -> R.ST1
      | _ -> raise InvalidOperandException
    let stash = stashST bld R.ST0
    copyST bld R.ST0 other
    unstashST bld other stash
    direct (regVar bld R.FSWC1) := AST.b0
#if !EMULATION
    cflagsUndefined023 bld
#endif
  }

let private fcmov (ins: Instruction) bld cond =
  let srcReg =
    match ins.Operands with
    | TwoOperands(_, OprReg reg) -> reg
    | _ -> raise InvalidOperandException
  selectST bld cond R.ST0 srcReg
#if !EMULATION
  append bld {
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
  }
#endif

let fcmove (ins: Instruction) bld =
  lift bld ins {
#if EMULATION
    getZFLazy bld |> fcmov ins bld
#else
    regVar bld R.ZF |> fcmov ins bld
#endif
  }

let fcmovne (ins: Instruction) bld =
  lift bld ins {
#if EMULATION
    getZFLazy bld |> AST.not |> fcmov ins bld
#else
    regVar bld R.ZF |> AST.not |> fcmov ins bld
#endif
  }

let fcmovb (ins: Instruction) bld =
  lift bld ins {
#if EMULATION
    getCFLazy bld |> fcmov ins bld
#else
    regVar bld R.CF |> fcmov ins bld
#endif
  }

let fcmovbe (ins: Instruction) bld =
  lift bld ins {
#if EMULATION
    (getCFLazy bld .| getZFLazy bld) |> fcmov ins bld
#else
    (regVar bld R.CF .| regVar bld R.ZF) |> fcmov ins bld
#endif
  }

let fcmovnb (ins: Instruction) bld =
  lift bld ins {
#if EMULATION
    getCFLazy bld |> AST.not |> fcmov ins bld
#else
    regVar bld R.CF |> AST.not |> fcmov ins bld
#endif
  }

let fcmovnbe (ins: Instruction) bld =
  lift bld ins {
#if EMULATION
    let cond1 = getCFLazy bld |> AST.not
    let cond2 = getZFLazy bld |> AST.not
#else
    let cond1 = regVar bld R.CF |> AST.not
    let cond2 = regVar bld R.ZF |> AST.not
#endif
    cond1 .& cond2 |> fcmov ins bld
  }

let fcmovu (ins: Instruction) bld =
  lift bld ins {
#if EMULATION
    getPFLazy bld |> fcmov ins bld
#else
    regVar bld R.PF |> fcmov ins bld
#endif
  }

let fcmovnu (ins: Instruction) bld =
  lift bld ins {
#if EMULATION
    getPFLazy bld |> AST.not |> fcmov ins bld
#else
    regVar bld R.PF |> AST.not |> fcmov ins bld
#endif
  }

/// A single widened to a double the way the FPU widens an operand, which
/// leaves a signalling NaN signalling where a conversion may quiet it: which of
/// two NaNs an operation gives back turns on it.
let private widenSingle s =
  let w = AST.zext 64<rt> s
  let sign = (w .& num64 0x80000000UL) << numI32 32 64<rt>
  let payload = (w .& num64 0x7fffffUL) << numI32 29 64<rt>
  let isNaN = (s .& numI32 0x7fffffff 32<rt>) .> numI32 0x7f800000 32<rt>
  let nan = sign .| num64 DoubleInf .| payload
  AST.ite isNaN nan (AST.cast CastKind.FloatCast 64<rt> s)

/// An arithmetic operand from memory, read into a temporary as a double: a
/// double as it is, or a single widened by widenSingle.
let private loadOperand bld (opr: Expr) =
  let t = tmpVar bld 64<rt>
  if Expr.typeOf opr = 64<rt> then
    append bld {
      direct t := opr
    }
  else
    let s = tmpVar bld 32<rt>
    append bld {
      direct s := opr
      direct t := widenSingle s
    }
  t

/// An arithmetic instruction on two floating-point operands, a NaN among them
/// answered by nanOf. A zero divisor gives an infinity, or the indefinite for
/// a zero dividend, which is what the FPU gives with the exception masked.
let private fpuFBinOp (ins: Instruction) bld binOp doPop leftToRight =
  let apply x y =
    orNaNOf x y (if leftToRight then binOp x y else binOp y x)
  lift bld ins {
    match ins.Operands with
    | NoOperand ->
      writeST bld R.ST1 (apply (readST bld R.ST0) (readST bld R.ST1))
    | OneOperand _ ->
      let opr = loadOperand bld (transOneOpr ins bld)
      writeST bld R.ST0 (apply (readST bld R.ST0) opr)
    | TwoOperands(OprReg reg0, OprReg reg1) ->
      writeST bld reg0 (apply (readST bld reg0) (readST bld reg1))
    | _ ->
      raise InvalidOperandException
    if doPop then popFPUStack bld else ()
    updateC1OnStore bld
  }

let private fpuIntOp (ins: Instruction) bld binOp leftToRight =
  let apply x y = if leftToRight then binOp x y else binOp y x
  lift bld ins {
    let oprExpr = transOneOpr ins bld
    let opr = AST.cast CastKind.SIntToFloat 64<rt> oprExpr
    writeST bld R.ST0 (apply (readST bld R.ST0) opr)
  }

let fpuadd ins bld doPop = fpuFBinOp ins bld AST.fadd doPop true

let fiadd ins bld = fpuIntOp ins bld AST.fadd true

let fpusub ins bld doPop = fpuFBinOp ins bld AST.fsub doPop true

let fisub ins bld = fpuIntOp ins bld AST.fsub true

let fsubr ins bld doPop = fpuFBinOp ins bld AST.fsub doPop false

let fisubr ins bld = fpuIntOp ins bld AST.fsub false

let fpumul ins bld doPop = fpuFBinOp ins bld AST.fmul doPop true

let fimul ins bld = fpuIntOp ins bld AST.fmul true

let fpudiv ins bld doPop = fpuFBinOp ins bld AST.fdiv doPop true

let fidiv ins bld = fpuIntOp ins bld AST.fdiv true

let fdivr ins bld doPop = fpuFBinOp ins bld AST.fdiv doPop false

let fidivr ins bld = fpuIntOp ins bld AST.fdiv false

let inline private castToF64 intexp =
  AST.cast CastKind.SIntToFloat 64<rt> intexp

let getExponent isDouble src =
  if isDouble then
    let numMantissa = numI32 52 64<rt>
    let mask = numI32 0x7FF 64<rt>
    AST.xtlo 32<rt> ((src >> numMantissa) .& mask)
  else
    let numMantissa = numI32 23 32<rt>
    let mask = numI32 0xff 32<rt>
    (src >> numMantissa) .& mask

let getMantissa isDouble src =
  let mask =
    if isDouble then numU64 0xfffff_ffffffffUL 64<rt>
    else numU64 0x7fffffUL 32<rt>
  src .& mask

let isNan isDouble expr =
  let exponent = getExponent isDouble expr
  let mantissa = getMantissa isDouble expr
  let e = if isDouble then numI32 0x7ff 32<rt> else numI32 0xff 32<rt>
  let zero = if isDouble then AST.num0 64<rt> else AST.num0 32<rt>
  (exponent == e) .& (mantissa != zero)

/// What FPREM and FPREM1 leave for a dividend `a` and a divisor `b` where
/// either is a NaN or an infinity, or the divisor a zero: the NaN nanOf picks;
/// the indefinite for an infinite dividend or a zero divisor, which leave no
/// remainder to take; and otherwise the dividend, which an infinite divisor
/// goes into no times.
let private specialRemainder a b =
  let invalid =
    (magnitudeOf a == num64 DoubleInf) .| (magnitudeOf b == AST.num0 64<rt>)
  orNaNOf a b (AST.ite invalid (num64 Indefinite) a)

/// The integer significand of a finite double, in a temporary, and in another
/// the biased exponent that scales it: a normal double's leading one made
/// explicit, and a denormal's exponent taken for the least, one, which is the
/// scale of its significand too.
let private significandOf bld v =
  let struct (m, e) = tmpVars2 bld 64<rt>
  let field = (v >> numI32 52 64<rt>) .& num64 0x7ffUL
  let normal = field != AST.num0 64<rt>
  let lead = AST.ite normal (num64 0x10000000000000UL) (AST.num0 64<rt>)
  append bld {
    direct m := (v .& num64 FracMask) .| lead
    direct e := AST.ite normal field (AST.num1 64<rt>)
  }
  struct (m, e)

/// How far up the dividend's significand goes for the division, given `d`, the
/// dividend's exponent less the divisor's: `d` places, but sixty-one where `d`
/// is sixty-four or more, for which the FPU too stops at a partial remainder,
/// and none for a dividend below the divisor.
let private dividendShift d =
  let full = AST.ite (d ?>= numI32 64 64<rt>) (numI32 61 64<rt>) d
  AST.ite (d ?< AST.num0 64<rt>) (AST.num0 64<rt>) full

/// How far up the divisor's significand goes for a dividend below it: one
/// place for a dividend an exponent below, which lines the two up, and two for
/// one further below, which leaves the quotient a zero and the remainder short
/// of half the divisor, all that FPREM1 needs to see.
let private divisorShift d =
  let one = AST.num1 64<rt>
  let below = AST.ite (d == numI64 -1L 64<rt>) one (numI32 2 64<rt>)
  AST.ite (d ?< AST.num0 64<rt>) below (AST.num0 64<rt>)

/// Whether FPREM1 takes off one divisor `m` more than the division did, its
/// quotient `q` rounding to nearest: for a remainder past half the divisor,
/// and for one of exactly half, to an even quotient. A partial reduction
/// rounds nothing, nor does FPREM.
let private roundsUp round d rem m q =
  if round then
    let twice = rem << AST.num1 64<rt>
    let tie = (twice == m) .& AST.xtlo 1<rt> q
    (d ?< numI32 64 64<rt>) .& ((twice .> m) .| tie)
  else
    AST.b0

/// Two to the power `k`, for a `k` from -1022 to 1023: a normal double, built
/// from its exponent alone.
let private pow2 k = (k .+ num64 1023UL) << numI32 52 64<rt>

/// `k` brought within the powers pow2 builds.
let private clampPow2 k =
  let lo = numI64 -1022L 64<rt>
  let hi = num64 1023UL
  AST.ite (k ?< lo) lo (AST.ite (k ?> hi) hi k)

/// `v` scaled by two to the power `n`, a whole number of at most 2200 in
/// magnitude, in three steps each of a power pow2 builds. Scaling up is exact
/// until it overflows. Scaling down rounds in its last step alone: should a
/// step before it round, what is left is too small for the last to give
/// anything but a zero, which the value scaled at once would be as well.
let private scaleBy bld v n =
  let struct (n1, n2, n3) = tmpVars3 bld 64<rt>
  append bld {
    direct n3 := clampPow2 n
    direct n2 := clampPow2 (n .- n3)
    direct n1 := n .- n3 .- n2
  }
  AST.fmul (AST.fmul (AST.fmul v (pow2 n1)) (pow2 n2)) (pow2 n3)

/// Sets C2 to say whether a reduction is `partial`, and C1, C3 and C0 to the
/// low three bits of the quotient `q` of a complete one, leaving them as they
/// were for a partial one.
let private writeQuotientBits bld partial q =
  let keep flag bit =
    AST.ite partial (regVar bld flag) (AST.extract q 1<rt> bit)
  append bld {
    direct (regVar bld R.FSWC2) := partial
    direct (regVar bld R.FSWC1) := keep R.FSWC1 0
    direct (regVar bld R.FSWC3) := keep R.FSWC3 1
    direct (regVar bld R.FSWC0) := keep R.FSWC0 2
  }

/// Writes the remainder of FPREM or FPREM1 for two finite doubles, the divisor
/// not a zero. It is worked out exactly, on their integer significands: the
/// doubles' own arithmetic rounds the divisor times any quotient of more than
/// a few bits, and the quotient runs to sixty-four. The remainder takes the
/// dividend's sign, which FPREM1 turns where its quotient rounds up. Exponents
/// sixty-four or more apart leave a partial remainder, with C2 set and the
/// quotient bits as they were, for the instruction to be run again.
let private remainderOf bld round a b =
  let struct (ma, ea) = significandOf bld a
  let struct (mb, eb) = significandOf bld b
  let struct (d, shift, sign) = tmpVars3 bld 64<rt>
  let struct (n, m, q) = tmpVars3 bld 128<rt>
  let rem = tmpVar bld 64<rt>
  let up = tmpVar bld 1<rt>
  let m64 = AST.xtlo 64<rt> m
  let q64 = AST.xtlo 64<rt> q
  let turn = AST.ite up (num64 TopBit) (AST.num0 64<rt>)
  append bld {
    direct d := ea .- eb
    direct shift := dividendShift d
    direct n := AST.zext 128<rt> ma << AST.zext 128<rt> shift
    direct m := AST.zext 128<rt> mb << AST.zext 128<rt> (divisorShift d)
    direct q := n ./ m
    direct rem := AST.xtlo 64<rt> (n .% m)
    direct up := roundsUp round d rem m64 q64
    direct rem := AST.ite up (m64 .- rem) rem
    direct sign := (a .& num64 TopBit) <+> turn
  }
  let exp = ea .- shift .- num64 1075UL
  writeST bld R.ST0 (sign .| scaleBy bld (castToF64 rem) exp)
  writeQuotientBits bld (d ?>= numI32 64 64<rt>) (q64 .+ AST.zext 64<rt> up)

let fprem (ins: Instruction) bld round =
  lift bld ins {
    let lblSpecial = label bld "Special"
    let lblOrdered = label bld "Ordered"
    let lblExit = label bld "Exit"
    let tmp0 = takeST bld R.ST0
    let tmp1 = takeST bld R.ST1
    let zeroDivisor = magnitudeOf tmp1 == AST.num0 64<rt>
    AST.cjmp
      (isNonFinite tmp0 .| isNonFinite tmp1 .| zeroDivisor)
      (AST.jmpDest lblSpecial)
      (AST.jmpDest lblOrdered)
    AST.lmark lblSpecial
    writeST bld R.ST0 (specialRemainder tmp0 tmp1)
    direct (regVar bld R.FSWC2) := AST.b0
    AST.jmp (AST.jmpDest lblExit)
    AST.lmark lblOrdered
    remainderOf bld round tmp0 tmp1
    AST.lmark lblExit
  }

let fabs (ins: Instruction) bld =
  lift bld ins {
    direct (signOfST bld R.ST0) := AST.b0
    direct (regVar bld R.FSWC1) := AST.b0
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

let fchs (ins: Instruction) bld =
  lift bld ins {
    let sign = signOfST bld R.ST0
    let tmp = tmpVar bld 1<rt>
    direct tmp := sign
    direct sign := AST.not tmp
    direct (regVar bld R.FSWC1) := AST.b0
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

/// Sets the quiet bit of a stack register holding a NaN, as an instruction
/// handing back the NaN it was given does.
let private quietST bld reg =
#if EMULATION
  let v = pseudoRegVar bld reg 1
  append bld {
    direct v := quietIfNaN v
  }
#else
  let struct (b, a) = getFPUPseudoRegVars bld reg
  let special = (b .& numI32 0x7fff 16<rt>) == numI32 0x7fff 16<rt>
  let isNaN = special .& ((a << AST.num1 64<rt>) != AST.num0 64<rt>)
  append bld {
    direct a := AST.ite isNaN (a .| num64 ExtQuietBit) a
  }
#endif

let frndint (ins: Instruction) bld =
  lift bld ins {
    let lblSpecial = label bld "Special"
    let lblOrdered = label bld "Ordered"
    let lblExit = label bld "Exit"
    (* FCW bits 11:10 are the rounding control, in the encoding the IR's own
       rounding mode uses. *)
    let rc = AST.zext 8<rt> (AST.extract (regVar bld R.FCW) 2<rt> 10)
    let tmp0 = takeST bld R.ST0
    AST.cjmp
      (isNonFinite tmp0) (AST.jmpDest lblSpecial) (AST.jmpDest lblOrdered)
    AST.lmark lblSpecial
    quietST bld R.ST0
    AST.jmp (AST.jmpDest lblExit)
    AST.lmark lblOrdered
    (* The result stays a number: rounding through an integer answers a value
       no integer can hold -- which FRNDINT rounds like any other -- with the
       integer indefinite instead. *)
    direct tmp0 :=
      AST.roundCtrl rc (AST.cast CastKind.RoundToIntegral 64<rt> tmp0)
    writeST bld R.ST0 tmp0
    AST.lmark lblExit
    updateC1OnStore bld
  }

/// The double 2200.0. Scaled by two to the 2200th power, every finite double
/// but a zero overflows, and scaled by its inverse, vanishes.
let [<Literal>] private ScaleLimit = 0x40a1300000000000UL

/// The scale FSCALE reads from a double `s`, kept within ScaleLimit: beyond it
/// every scale gives the same result, an infinity among them.
let private limitScale s =
  let limit = num64 ScaleLimit
  AST.ite (magnitudeOf s .> limit) ((s .& num64 TopBit) .| limit) s

/// Whether FSCALE has no result for `v` and the scale `s`: a zero and a scale
/// of infinity, or an infinity and a scale of minus infinity, each a zero
/// times an infinity.
let private isInvalidScale v s =
  let zeroUp = (s == num64 DoubleInf) .& (magnitudeOf v == AST.num0 64<rt>)
  let infDown = (s == num64 NegInf) .& (magnitudeOf v == num64 DoubleInf)
  zeroUp .| infDown

let fscale (ins: Instruction) bld =
  lift bld ins {
    let n = tmpVar bld 64<rt>
    let tmp0 = takeST bld R.ST0
    let tmp1 = takeST bld R.ST1
    let toward = RoundingMode.TowardZero
    direct n := AST.floatToSInt toward 64<rt> (limitScale tmp1)
    let scaled = scaleBy bld tmp0 n
    let v = AST.ite (isInvalidScale tmp0 tmp1) (num64 Indefinite) scaled
    writeST bld R.ST0 (orNaNOf tmp0 tmp1 v)
    updateC1OnStore bld
  }

let fsqrt (ins: Instruction) bld =
  lift bld ins {
    writeST bld R.ST0 (AST.unop UnOpType.FSQRT (readST bld R.ST0))
    updateC1OnStore bld
  }

#if EMULATION
/// The two parts FXTRACT splits a stack register into, each set aside for
/// unstashST: its unbiased exponent, as a double, and its significand -- the
/// value with that exponent taken out, which leaves it from one up to two. A
/// denormal is normalised first, which doubleToExtended does. A zero splits
/// into a negative infinity and itself, an infinity into a positive one and
/// itself, and a NaN into itself twice, quieted.
let private splitST bld reg =
  let v = takeST bld reg
  let struct (hi, lo) = doubleToExtended bld v
  let e = AST.zext 64<rt> (hi .& numI32 0x7fff 16<rt>)
  let isZero = magnitudeOf v == AST.num0 64<rt>
  let special = isZero .| isNonFinite v
  let fraction = (lo >> numI32 11 64<rt>) .& num64 FracMask
  let significand =
    (v .& num64 TopBit) .| num64 0x3ff0000000000000UL .| fraction
  let infinite = AST.ite isZero (num64 NegInf) (num64 DoubleInf)
  let unbiased = castToF64 (e .- num64 0x3fffUL)
  let quieted = quietIfNaN v
  let exponent = AST.ite (isNaND v) quieted (AST.ite special infinite unbiased)
  struct (exponent, AST.ite special quieted significand)
#else
/// The exponent part of what FXTRACT splits the extended-precision value `hi`
/// and `m` into, set aside for unstashST, where `m` is the value's mantissa
/// normalised by `sh` places: a negative infinity for a zero, a positive one
/// for an infinity, the NaN quieted for a NaN, and the unbiased exponent
/// otherwise, of which a denormal's is its least less the normalising shift.
let private exponentPart bld hi m sh =
  let e = AST.zext 64<rt> (hi .& numI32 0x7fff 16<rt>)
  let isZero = (e == AST.num0 64<rt>) .& (m == AST.num0 64<rt>)
  let special = e == num64 0x7fffUL
  let isNaN = special .& ((m << AST.num1 64<rt>) != AST.num0 64<rt>)
  let least = AST.ite (e == AST.num0 64<rt>) (AST.num1 64<rt>) e
  let unbiased = castToF64 (least .- num64 0x3fffUL .- sh)
  let struct (expHi, expLo) = doubleToExtended bld unbiased
  let infHi = AST.ite isZero (numI32 0xffff 16<rt>) (numI32 0x7fff 16<rt>)
  let infinite = isZero .| special
  let outHi = AST.ite isNaN hi (AST.ite infinite infHi expHi)
  let quieted = m .| num64 ExtQuietBit
  struct (outHi, AST.ite isNaN quieted (AST.ite infinite (num64 TopBit) expLo))

/// The two parts FXTRACT splits a stack register into, each set aside for
/// unstashST: its unbiased exponent, as a double (see exponentPart), and its
/// significand -- the value with that exponent taken out, which leaves it from
/// one up to two. A zero or an infinity is its own significand, and a NaN is
/// its own quieted.
let private splitST bld reg =
  let struct (b, a) = getFPUPseudoRegVars bld reg
  let hi = tmpVar bld 16<rt>
  append bld {
    direct hi := b
  }
  let struct (m, sh) = normalized bld a
  let special = (hi .& numI32 0x7fff 16<rt>) == numI32 0x7fff 16<rt>
  let keep = special .| (m == AST.num0 64<rt>)
  let isNaN = special .& ((m << AST.num1 64<rt>) != AST.num0 64<rt>)
  let sigHi = (hi .& numI32 0x8000 16<rt>) .| numI32 0x3fff 16<rt>
  let sigLo = AST.ite isNaN (m .| num64 ExtQuietBit) m
  struct (exponentPart bld hi m sh, struct (AST.ite keep hi sigHi, sigLo))
#endif

let fxtract (ins: Instruction) bld =
  lift bld ins {
    let struct (exponent, significand) = splitST bld R.ST0
    unstashST bld R.ST0 exponent
    pushFPUStack bld
    unstashST bld R.ST0 significand
  }

/// The two doubles a compare weighs, as they stand before anything the compare
/// pops moves the stack.
let private prepareTwoOprsForComparison (ins: Instruction) bld =
  match ins.Operands with
  | NoOperand ->
    struct (readST bld R.ST0, readST bld R.ST1)
  | OneOperand(OprReg r) ->
    struct (readST bld R.ST0, readST bld r)
  | OneOperand(opr) ->
    let tmp1 = tmpVar bld 64<rt>
    let oprExpr = transOpr ins bld false opr
    append bld {
      direct tmp1 := AST.cast CastKind.FloatCast 64<rt> oprExpr
    }
    struct (readST bld R.ST0, tmp1)
  | TwoOperands(OprReg r1, OprReg r2) ->
    struct (readST bld r1, readST bld r2)
  | _ ->
    raise InvalidOperandException

let fcom (ins: Instruction) bld nPop unordered =
  lift bld ins {
    let c0 = regVar bld R.FSWC0
    let c2 = regVar bld R.FSWC2
    let c3 = regVar bld R.FSWC3
    let struct (tmp0, tmp1) = prepareTwoOprsForComparison ins bld
    let isNan = isNan true tmp0 .| isNan true tmp1
    direct c0 := isNan .| AST.flt tmp0 tmp1
    direct c2 := isNan .| AST.b0
    direct c3 := isNan .| AST.feq tmp0 tmp1
    direct (regVar bld R.FSWC1) := AST.b0
    if nPop > 0 then popFPUStack bld else ()
    if nPop = 2 then popFPUStack bld else ()
  }

let ficom (ins: Instruction) bld doPop =
  lift bld ins {
    let oprExpr = transOneOpr ins bld
    let tmp1 = tmpVar bld 64<rt>
    let tmp0 = readST bld R.ST0
    direct tmp1 := AST.cast CastKind.SIntToFloat 64<rt> oprExpr
    let isNan = isNan true tmp0 .| isNan true tmp1
    direct (regVar bld R.FSWC0) := isNan .| AST.flt tmp0 tmp1
    direct (regVar bld R.FSWC2) := isNan .| AST.b0
    direct (regVar bld R.FSWC3) := isNan .| AST.feq tmp0 tmp1
    direct (regVar bld R.FSWC1) := AST.b0
    if doPop then popFPUStack bld else ()
  }

let fcomi (ins: Instruction) bld doPop =
  lift bld ins {
    let zf = regVar bld R.ZF
    let pf = regVar bld R.PF
    let cf = regVar bld R.CF
    let struct (tmp0, tmp1) = prepareTwoOprsForComparison ins bld
    let isNan = isNan true tmp0 .| isNan true tmp1
    direct cf := isNan .| AST.flt tmp0 tmp1
    direct pf := isNan .| AST.b0
    direct zf := isNan .| AST.feq tmp0 tmp1
    (* Unlike the FCOM family, which reports in the status word and leaves
       EFLAGS alone, FCOMI clears the three flags it does not use. *)
    direct (regVar bld R.OF) := AST.b0
    direct (regVar bld R.SF) := AST.b0
    direct (regVar bld R.AF) := AST.b0
    direct (regVar bld R.FSWC1) := AST.b0
    if doPop then popFPUStack bld else ()
#if EMULATION
    bld.ConditionCodeOp <- ConditionCodeOp.EFlags
#endif
  }

let ftst (ins: Instruction) bld =
  lift bld ins {
    let num0V = AST.num0 64<rt>
    let c0 = regVar bld R.FSWC0
    let c2 = regVar bld R.FSWC2
    let c3 = regVar bld R.FSWC3
    let tmp = readST bld R.ST0
    (* A NaN is unordered against zero as against anything else, which is all
       three condition codes set, not the "greater than" that falls out of a
       comparison that answers false twice. *)
    let unordered = isNan true tmp
    direct c0 := unordered .| AST.flt tmp num0V
    direct c2 := unordered .| AST.b0
    direct c3 := unordered .| AST.feq tmp num0V
    direct (regVar bld R.FSWC1) := AST.b0
  }

/// What FXAM tells of a stack register: whether it holds a NaN, an infinity or
/// a zero, and its sign.
let private classifyST bld reg =
#if EMULATION
  let v = pseudoRegVar bld reg 1
  let exponent = (v >> numI32 52 64<rt>) .& num64 0x7ffUL
  let frac = v .& num64 FracMask
  let special = exponent == num64 0x7ffUL
  let isNaN = special .& (frac != AST.num0 64<rt>)
  let isInf = special .& (frac == AST.num0 64<rt>)
  let isZero = (v << AST.num1 64<rt>) == AST.num0 64<rt>
  struct (isNaN, isInf, isZero, AST.xthi 1<rt> v)
#else
  let struct (b, a) = getFPUPseudoRegVars bld reg
  let n7fff = numI32 0x7fff 16<rt>
  let exponent = b .& n7fff
  let num = numI64 0x7FFFFFFF_FFFFFFFFL 64<rt>
  let isNaN = (exponent == n7fff) .& ((a .& num) != AST.num0 64<rt>)
  let isInf = (exponent == n7fff) .& ((a .& num) == AST.num0 64<rt>)
  let isZero = (a == AST.num0 64<rt>) .& (exponent == AST.num0 16<rt>)
  struct (isNaN, isInf, isZero, AST.xthi 1<rt> b)
#endif

let fxam (ins: Instruction) bld =
  lift bld ins {
    let top = regVar bld R.FTOP
    let struct (isNaN, isInf, isZero, sign) = classifyST bld R.ST0
    let isEmpty = top == numI32 0 8<rt>
    let c3Cond = isZero .| isEmpty
    let c2Cond = AST.not (isNaN .| isZero .| isEmpty)
    let c0Cond = isNaN .| isInf .| isEmpty
    direct (regVar bld R.FSWC1) := sign
    direct (regVar bld R.FSWC3) := c3Cond
    direct (regVar bld R.FSWC2) := c2Cond
    direct (regVar bld R.FSWC0) := c0Cond
  }

/// Jumps to `lin` unless the operand `v` of a trigonometric instruction is out
/// of its range, a finite value of 2^63 or more in magnitude, which the
/// instruction leaves as it is. A NaN or an infinity is in range (see
/// trigResult).
let private checkForTrigFunction v lin lout bld =
  let mag = magnitudeOf v
  let limit = num64 0x43e0000000000000UL (* 2^63 *)
  let outOfRange = (mag .>= limit) .& (mag .< num64 DoubleInf)
  append bld {
    AST.cjmp outOfRange (AST.jmpDest lout) (AST.jmpDest lin)
  }

/// What a trigonometric instruction gives for its operand `v`: `r`, unless `v`
/// is a NaN, which comes back quieted, or an infinity, which has no sine,
/// cosine or tangent and gives the indefinite.
let private trigResult v r =
  let special = AST.ite (isNaND v) (v .| num64 QuietBit) (num64 Indefinite)
  AST.ite (isNonFinite v) special r

let private ftrig (ins: Instruction) bld trigFunc =
  lift bld ins {
    let c0 = regVar bld R.FSWC0
    let c1 = regVar bld R.FSWC1
    let c2 = regVar bld R.FSWC2
    let c3 = regVar bld R.FSWC3
    let lin = label bld "IsInRange"
    let lout = label bld "IsOutOfRange"
    let lexit = label bld "Exit"
    let tmp = tmpVar bld 64<rt>
    let signed = takeST bld R.ST0
    checkForTrigFunction signed lin lout bld
    AST.lmark lin
    direct tmp := trigResult signed (trigFunc signed)
    writeST bld R.ST0 tmp
    direct c2 := AST.b0
    AST.jmp (AST.jmpDest lexit)
    AST.lmark lout
    direct c2 := AST.b1
    AST.lmark lexit
#if !EMULATION
    direct c0 := undefC0
    direct c3 := undefC3
#endif
    direct c1 := AST.b0
  }

let fsin ins bld = ftrig ins bld AST.fsin

let fcos ins bld = ftrig ins bld AST.fcos

let fsincos (ins: Instruction) bld =
  lift bld ins {
    let c0 = regVar bld R.FSWC0
    let c2 = regVar bld R.FSWC2
    let c3 = regVar bld R.FSWC3
    let lin = label bld "IsInRange"
    let lout = label bld "IsOutOfRange"
    let lexit = label bld "Exit"
    let struct (tmpsin, tmpcos) = tmpVars2 bld 64<rt>
    let signed = takeST bld R.ST0
    checkForTrigFunction signed lin lout bld
    AST.lmark lin
    direct tmpcos := trigResult signed (AST.fcos signed)
    direct tmpsin := trigResult signed (AST.fsin signed)
    writeST bld R.ST0 tmpsin
    pushFPUStack bld
    writeST bld R.ST0 tmpcos
    direct c2 := AST.b0
    AST.jmp (AST.jmpDest lexit)
    AST.lmark lout
    direct c2 := AST.b1
    AST.lmark lexit
#if !EMULATION
    direct c0 := undefC0
    direct c3 := undefC3
#endif
    updateC1OnLoad bld
  }

let fptan (ins: Instruction) bld =
  lift bld ins {
    let c0 = regVar bld R.FSWC0
    let c2 = regVar bld R.FSWC2
    let c3 = regVar bld R.FSWC3
    let lin = label bld "IsInRange"
    let lout = label bld "IsOutOfRange"
    let lexit = label bld "Exit"
    let fone = numI64 0x3ff0000000000000L 64<rt> (* 1.0 *)
    let tmp = tmpVar bld 64<rt>
    let signed = takeST bld R.ST0
    checkForTrigFunction signed lin lout bld
    AST.lmark lin
    direct tmp := trigResult signed (AST.ftan signed)
    writeST bld R.ST0 tmp
    direct c2 := AST.b0
    pushFPUStack bld
    writeST bld R.ST0 (trigResult signed fone)
    direct c2 := AST.b0
    AST.jmp (AST.jmpDest lexit)
    AST.lmark lout
    direct c2 := AST.b1
    AST.lmark lexit
#if !EMULATION
    direct c0 := undefC0
    direct c3 := undefC3
#endif
    updateC1OnLoad bld
  }

/// FPATAN is atan2(ST(1), ST(0)), not atan of their quotient: the quotient
/// alone loses which quadrant the point is in, and turns the two corners where
/// both operands are zero or both are infinite into a NaN. The angle of the
/// quotient is therefore corrected by the signs of the two operands.
let fpatan (ins: Instruction) bld =
  lift bld ins {
    let res = tmpVar bld 64<rt>
    let quot = tmpVar bld 64<rt>
    let signMask = numI64 0x8000000000000000L 64<rt>
    let absMask = numI64 0x7FFFFFFFFFFFFFFFL 64<rt>
    let inf = numI64 0x7FF0000000000000L 64<rt>
    let pi = numI64 0x400921FB54442D18L 64<rt> (* pi *)
    let piOver4 = numI64 0x3FE921FB54442D18L 64<rt> (* pi / 4 *)
    let zero = AST.num0 64<rt>
    let tmp0 = takeST bld R.ST0
    let tmp1 = takeST bld R.ST1
    (* The two corners stand in for the quotient the division cannot form, so
       they carry the sign that quotient would have had: the two operands'
       signs combined. The correction below carries ST(1)'s own sign instead,
       which is the side of the x axis the angle comes back on. *)
    let signY = tmp1 .& signMask
    let signQuot = (tmp0 <+> tmp1) .& signMask
    let absX = tmp0 .& absMask
    let absY = tmp1 .& absMask
    let bothZero = (absX == zero) .& (absY == zero)
    let bothInf = (absX == inf) .& (absY == inf)
    let angle = AST.fatan (AST.fdiv tmp1 tmp0)
    direct quot :=
      AST.ite bothZero (zero .| signQuot)
                       (AST.ite bothInf (piOver4 .| signQuot) angle)
    (* A negative ST(0) -- including -0.0, hence the sign bit rather than a
       comparison -- moves the angle into the second or the third quadrant. *)
    direct res :=
      AST.ite (AST.xthi 1<rt> tmp0) (AST.fadd quot (pi .| signY)) quot
    writeST bld R.ST1 (orNaNOf tmp0 tmp1 res)
    popFPUStack bld
    updateC1OnStore bld
#if !EMULATION
    cflagsUndefined023 bld
#endif
  }

let f2xm1 (ins: Instruction) bld =
  lift bld ins {
    let f1 = numI32 1 64<rt> |> castToF64
    let f2 = numI32 2 64<rt> |> castToF64
    let c1 = regVar bld R.FSWC1
    let v = readST bld R.ST0
    (* A zero is its own result, with a sign the subtraction would lose, and a
       NaN is its own quieted. *)
    let keep = (magnitudeOf v == AST.num0 64<rt>) .| isNaND v
    let r = AST.fsub (AST.fpow f2 v) f1
    writeST bld R.ST0 (AST.ite keep (quietIfNaN v) r)
    direct c1 := AST.b0
#if !EMULATION
    cflagsUndefined023 bld
#endif
  }

let fyl2x (ins: Instruction) bld =
  lift bld ins {
    let f2 = numI32 2 64<rt> |> castToF64
    let x = readST bld R.ST0
    let y = readST bld R.ST1
    (* A value below zero has no logarithm, and the FPU answers it with the
       indefinite, where the IR's logarithm may give any NaN. *)
    let negative = AST.xthi 1<rt> x .& (magnitudeOf x != AST.num0 64<rt>)
    let r = AST.ite negative (num64 Indefinite) (AST.fmul y (AST.flog f2 x))
    writeST bld R.ST1 (orNaNOf x y r)
    popFPUStack bld
    updateC1OnStore bld
#if !EMULATION
    cflagsUndefined023 bld
#endif
  }

let fyl2xp1 (ins: Instruction) bld =
  lift bld ins {
    let f1 = numI32 1 64<rt> |> castToF64
    let f2 = numI32 2 64<rt> |> castToF64
    let x = readST bld R.ST0
    let y = readST bld R.ST1
    (* The logarithm of one plus a zero is that zero, with a sign the sum would
       lose. *)
    let isZero = magnitudeOf x == AST.num0 64<rt>
    let log = AST.ite isZero x (AST.flog f2 (AST.fadd x f1))
    writeST bld R.ST1 (orNaNOf x y (AST.fmul y log))
    popFPUStack bld
    updateC1OnStore bld
#if !EMULATION
    cflagsUndefined023 bld
#endif
  }

let fld1 ins bld =
  let oprExpr = numU64 0x3FF0000000000000UL 64<rt>
  fpuLoad ins bld oprExpr

let fldz (ins: Instruction) bld =
  lift bld ins {
    pushFPUStack bld
    clearST bld R.ST0
    updateC1OnLoad bld
  }

let fldpi ins bld =
  let oprExpr = numU64 4614256656552045848UL 64<rt>
  fpuLoad ins bld oprExpr

let fldl2e ins bld =
  let oprExpr = numU64 4609176140021203710UL 64<rt>
  fpuLoad ins bld oprExpr

let fldln2 ins bld =
  let oprExpr = numU64 4604418534313441775UL 64<rt>
  fpuLoad ins bld oprExpr

let fldl2t ins bld =
  let oprExpr = numU64 4614662735865160561UL 64<rt>
  fpuLoad ins bld oprExpr

let fldlg2 ins bld =
  let oprExpr = numU64 4599094494223104511UL 64<rt>
  fpuLoad ins bld oprExpr

let fincstp (ins: Instruction) bld =
  lift bld ins {
    let top = regVar bld R.FTOP
    (* TOP in B2R2 is really a counter, so we decrement TOP here (same as
       pop). *)
    let cond = top == numI32 0 8<rt>
    let updatedTOP = AST.ite cond (numI32 7 8<rt>) (top .- AST.num1 8<rt>)
    extractDstAssign top updatedTOP
    let stash = stashST bld R.ST0
    copyST bld R.ST0 R.ST1
    copyST bld R.ST1 R.ST2
    copyST bld R.ST2 R.ST3
    copyST bld R.ST3 R.ST4
    copyST bld R.ST4 R.ST5
    copyST bld R.ST5 R.ST6
    copyST bld R.ST6 R.ST7
    unstashST bld R.ST7 stash
    direct (regVar bld R.FSWC1) := AST.b0
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

let fdecstp (ins: Instruction) bld =
  lift bld ins {
    let top = regVar bld R.FTOP
    (* TOP in B2R2 is really a counter, so we increment TOP here. *)
    let cond = top == numI32 7 8<rt>
    let updatedTOP = AST.ite cond (AST.num0 8<rt>) (top .+ AST.num1 8<rt>)
    extractDstAssign top updatedTOP
    let stash = stashST bld R.ST7
    copyST bld R.ST7 R.ST6
    copyST bld R.ST6 R.ST5
    copyST bld R.ST5 R.ST4
    copyST bld R.ST4 R.ST3
    copyST bld R.ST3 R.ST2
    copyST bld R.ST2 R.ST1
    copyST bld R.ST1 R.ST0
    unstashST bld R.ST0 stash
    direct (regVar bld R.FSWC1) := AST.b0
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

let ffree (ins: Instruction) bld =
  lift bld ins {
    let top = regVar bld R.FTOP
    let tagWord = regVar bld R.FTW
    let struct (top16, shifter, tagValue) = tmpVars3 bld 16<rt>
    let value3 = numI32 3 16<rt>
    let offset =
      match ins.Operands with
      | OneOperand(OprReg R.ST0) -> numI32 0 16<rt>
      | OneOperand(OprReg R.ST1) -> numI32 1 16<rt>
      | OneOperand(OprReg R.ST2) -> numI32 2 16<rt>
      | OneOperand(OprReg R.ST3) -> numI32 3 16<rt>
      | OneOperand(OprReg R.ST4) -> numI32 4 16<rt>
      | OneOperand(OprReg R.ST5) -> numI32 5 16<rt>
      | OneOperand(OprReg R.ST6) -> numI32 6 16<rt>
      | OneOperand(OprReg R.ST7) -> numI32 7 16<rt>
      | _ -> raise InvalidOperandException
    direct top16 := AST.cast CastKind.ZeroExt 16<rt> top
    direct top16 := top16 .+ offset
    direct shifter := (numI32 2 16<rt>) .* top16
    direct tagValue := (value3 << shifter)
    direct tagWord := tagWord .| tagValue
  }

(* FIXME: check all unmasked pending floating point exceptions. *)
let private checkFPUExceptions bld = ()

let private clearFPU bld =
  append bld {
    let cw = numI32 895 16<rt>
    let tw = BitVector.MaxUInt16 |> AST.num
    direct (regVar bld R.FCW) := cw
    direct (regVar bld R.FSW) := AST.num0 16<rt>
    direct (regVar bld R.FTW) := tw
  }

let finit (ins: Instruction) bld =
  lift bld ins {
    checkFPUExceptions bld
    clearFPU bld
  }

let fninit (ins: Instruction) bld =
  lift bld ins {
    clearFPU bld
  }

let fclex (ins: Instruction) bld =
  lift bld ins {
    let stsWrd = regVar bld R.FSW
    direct stsWrd := stsWrd .& (numI32 0xFF80 16<rt>)
    direct (AST.xthi 1<rt> stsWrd) := AST.b0
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC1) := undefC1
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

let fstcw (ins: Instruction) bld =
  lift bld ins {
    let oprExpr = transOneOpr ins bld
    checkFPUExceptions bld
    direct oprExpr := regVar bld R.FCW
#if !EMULATION
    allCFlagsUndefined bld
#endif
  }

let fnstcw (ins: Instruction) bld =
  lift bld ins {
    let oprExpr = transOneOpr ins bld
    direct oprExpr := regVar bld R.FCW
#if !EMULATION
    allCFlagsUndefined bld
#endif
  }

let fldcw (ins: Instruction) bld =
  lift bld ins {
    let oprExpr = transOneOpr ins bld
    direct (regVar bld R.FCW) := oprExpr
#if !EMULATION
    direct (regVar bld R.FSWC0) := undefC0
    direct (regVar bld R.FSWC1) := undefC1
    direct (regVar bld R.FSWC2) := undefC2
    direct (regVar bld R.FSWC3) := undefC3
#endif
  }

let inline private storeLE addr v = AST.store Endian.Little addr v

let private m14fstenv dstAddr addrSize bld =
  append bld {
    let fiplo = AST.xtlo 16<rt> (regVar bld R.FIP)
    let fdplo = AST.xtlo 16<rt> (regVar bld R.FDP)
    storeLE (dstAddr) (regVar bld R.FCW)
    storeLE (dstAddr .+ numI32 2 addrSize) (regVar bld R.FSW)
    storeLE (dstAddr .+ numI32 4 addrSize) (regVar bld R.FTW)
    storeLE (dstAddr .+ numI32 6 addrSize) fiplo
    storeLE (dstAddr .+ numI32 8 addrSize) (regVar bld R.FCS)
    storeLE (dstAddr .+ numI32 10 addrSize) fdplo
    storeLE (dstAddr .+ numI32 12 addrSize) (regVar bld R.FDS)
  }

let private m28fstenv dstAddr addrSize bld =
  append bld {
    let n0 = numI32 0 16<rt>
    storeLE (dstAddr) (regVar bld R.FCW)
    storeLE (dstAddr .+ numI32 2 addrSize) n0
    storeLE (dstAddr .+ numI32 4 addrSize) (regVar bld R.FSW)
    storeLE (dstAddr .+ numI32 6 addrSize) n0
    storeLE (dstAddr .+ numI32 8 addrSize) (regVar bld R.FTW)
    storeLE (dstAddr .+ numI32 10 addrSize) n0
    storeLE (dstAddr .+ numI32 12 addrSize) (regVar bld R.FIP)
    storeLE (dstAddr .+ numI32 20 addrSize) (regVar bld R.FDP)
  }

let fnstenv (ins: Instruction) bld =
  lift bld ins {
    let dst = transOneOpr ins bld
    let struct (addrExpr, addrSize) = getLoadAddressExpr dst
    match Expr.typeOf dst with
    | 112<rt> -> m14fstenv addrExpr addrSize bld
    | 224<rt> -> m28fstenv addrExpr addrSize bld
    | _ -> raise InvalidOperandSizeException
  }

/// Neither summary bit of the status word holds state of its own: ES (bit 7)
/// says an exception is flagged that the control word does not mask, and B
/// (bit 15) has followed ES on every FPU since the 387. An environment can be
/// loaded with the three out of step -- flags masked but ES set, say -- and the
/// FPU answers the next read with the summary its flags and masks imply, not
/// the one it was handed. Loading is the only place they can disagree here,
/// nothing in this lifter raising an exception of its own.
let private syncSummaryBits bld =
  append bld {
    let stsWrd = regVar bld R.FSW
    let excMask = numI32 0x3F 16<rt>
    let masked = regVar bld R.FCW .& excMask
    let pending = (stsWrd .& excMask) .& AST.not masked
    let quiet = pending == AST.num0 16<rt>
    let summary = AST.ite quiet (AST.num0 16<rt>) (numI32 0x8080 16<rt>)
    direct stsWrd := (stsWrd .& numI32 0x7F7F 16<rt>) .| summary
  }

let private m14fldenv srcAddr addrSize bld =
  append bld {
    direct (regVar bld R.FCW) := AST.loadLE 16<rt> (srcAddr)
    direct (regVar bld R.FSW) :=
      AST.loadLE 16<rt> (srcAddr .+ numI32 2 addrSize)
    direct (regVar bld R.FTW) :=
      AST.loadLE 16<rt> (srcAddr .+ numI32 4 addrSize)
    direct (AST.xtlo 16<rt> (regVar bld R.FIP)) :=
      AST.loadLE 16<rt> (srcAddr .+ numI32 6 addrSize)
    direct (regVar bld R.FCS) :=
      AST.loadLE 16<rt> (srcAddr .+ numI32 8 addrSize)
    direct (AST.xtlo 16<rt> (regVar bld R.FDP)) :=
      AST.loadLE 16<rt> (srcAddr .+ numI32 10 addrSize)
    direct (regVar bld R.FDS) :=
      AST.loadLE 16<rt> (srcAddr .+ numI32 12 addrSize)
    syncSummaryBits bld
  }

let private m28fldenv srcAddr addrSize bld =
  append bld {
    direct (regVar bld R.FCW) := AST.loadLE 16<rt> (srcAddr)
    direct (regVar bld R.FSW) :=
      AST.loadLE 16<rt> (srcAddr .+ numI32 4 addrSize)
    direct (regVar bld R.FTW) :=
      AST.loadLE 16<rt> (srcAddr .+ numI32 8 addrSize)
    direct (regVar bld R.FIP) :=
      AST.loadLE 64<rt> (srcAddr .+ numI32 12 addrSize)
    direct (regVar bld R.FDP) :=
      AST.loadLE 64<rt> (srcAddr .+ numI32 20 addrSize)
    syncSummaryBits bld
  }

let fldenv (ins: Instruction) bld =
  lift bld ins {
    let src = transOneOpr ins bld
    let struct (addrExpr, addrSize) = getLoadAddressExpr src
    match Expr.typeOf src with
    | 112<rt> -> m14fldenv addrExpr addrSize bld
    | 224<rt> -> m28fldenv addrExpr addrSize bld
    | _ -> raise InvalidOperandSizeException
  }

/// Writes the stack registers out as FSAVE lays them out: ten bytes each, from
/// `offset` bytes in, mantissa first.
let private stSts dstAddr addrSize offset bld =
  for i, st in List.indexed stackRegs do
    let at off = dstAddr .+ numI32 (offset + 10 * i + off) addrSize
    storeExtended bld (at 0) (at 8) st

let fnsave (ins: Instruction) bld =
  lift bld ins {
    let dst = transOneOpr ins bld
    let struct (addrExpr, addrSize) = getLoadAddressExpr dst
    match Expr.typeOf dst with
    | 752<rt> ->
      m14fstenv addrExpr addrSize bld
      stSts addrExpr addrSize 14 bld
    | 864<rt> ->
      m28fstenv addrExpr addrSize bld
      stSts addrExpr addrSize 28 bld
    | _ ->
      raise InvalidOperandSizeException
    direct (regVar bld R.FCW) := numI32 0x037F 16<rt>
    direct (regVar bld R.FSW) := AST.num0 16<rt>
    direct (regVar bld R.FTW) := numI32 0xFFFF 16<rt>
    direct (regVar bld R.FDP) := AST.num0 64<rt>
    direct (regVar bld R.FIP) := AST.num0 64<rt>
    direct (regVar bld R.FOP) := AST.num0 16<rt>
  }

/// Reads the stack registers back in from where stSts lays them out, as they
/// were saved.
let private ldSts srcAddr addrSize offset bld =
  for i, st in List.indexed stackRegs do
    let at off = srcAddr .+ numI32 (offset + 10 * i + off) addrSize
    unstashST bld st (loadExtended bld (at 0) (at 8))

let frstor (ins: Instruction) bld =
  lift bld ins {
    let src = transOneOpr ins bld
    let struct (addrExpr, addrSize) = getLoadAddressExpr src
    match Expr.typeOf src with
    | 752<rt> ->
      m14fldenv addrExpr addrSize bld
      ldSts addrExpr addrSize 14 bld
    | 864<rt> ->
      m28fldenv addrExpr addrSize bld
      ldSts addrExpr addrSize 28 bld
    | _ ->
      raise InvalidOperandSizeException
  }

let fnstsw (ins: Instruction) bld =
  lift bld ins {
    let oprExpr = transOneOpr ins bld
    direct oprExpr := regVar bld R.FSW
#if !EMULATION
    allCFlagsUndefined bld
#endif
  }

let wait (ins: Instruction) bld =
  lift bld ins {
    checkFPUExceptions bld
  }

let fnop (ins: Instruction) bld =
  lift bld ins {
#if !EMULATION
    allCFlagsUndefined bld
#endif
  }

/// The SSE registers FXSAVE always lays out, on the same stride from one
/// hundred and sixty bytes in.
let private fxsaveXmmRegs =
  [ R.XMM0; R.XMM1; R.XMM2; R.XMM3; R.XMM4; R.XMM5; R.XMM6; R.XMM7 ]

/// The eight more it lays out in 64-bit mode, carrying on from there.
let private fxsaveXmmRegs64 =
  [ R.XMM8; R.XMM9; R.XMM10; R.XMM11; R.XMM12; R.XMM13; R.XMM14; R.XMM15 ]

/// The XMM registers a save area holds in the given mode.
let private xmmRegsOf is64bit =
  if is64bit then fxsaveXmmRegs @ fxsaveXmmRegs64 else fxsaveXmmRegs

/// Addresses one field of a save area: the area's own address for the field at
/// zero, and a displacement from it for every other one.
let private fieldAt baseAddr addrSize off =
  if off = 0 then baseAddr else baseAddr .+ numI32 off addrSize

/// The x87 half of an FXSAVE-format image: the control, status and tag words,
/// the opcode and the last instruction and data pointers, and the eight stack
/// registers, eighty bits each on a sixteen-byte stride from thirty-two bytes
/// in.
let private storeX87Area bld baseAddr addrSize =
  let at off = fieldAt baseAddr addrSize off
  let words =
    block {
      yield storeLE (at 0) (regVar bld R.FCW)
      yield storeLE (at 2) (regVar bld R.FSW)
      yield storeLE (at 4) (regVar bld R.FTW)
      yield storeLE (at 6) (regVar bld R.FOP)
      yield storeLE (at 8) (regVar bld R.FIP)
      yield storeLE (at 16) (regVar bld R.FDP)
    }
  fun b ->
    words b
    for i, st in List.indexed stackRegs do
      storeExtended b (at (32 + 16 * i)) (at (40 + 16 * i)) st

/// The SSE half of an FXSAVE-format image: MXCSR beside the mask of the bits
/// it accepts, and the XMM registers.
let private storeSseArea bld baseAddr addrSize is64bit =
  let at off = fieldAt baseAddr addrSize off
  block {
    yield storeLE (at 24) (regVar bld R.MXCSR)
    yield storeLE (at 28) (regVar bld R.MXCSRMASK)
    for i, xmm in List.indexed (xmmRegsOf is64bit) do
      let struct (xmmb, xmma) = pseudoRegVar128 bld xmm
      yield storeLE (at (160 + 16 * i)) xmma
      yield storeLE (at (168 + 16 * i)) xmmb
  }

/// Reads the x87 half of an FXSAVE-format image back into the registers.
let private loadX87Area bld baseAddr addrSize =
  let at off = fieldAt baseAddr addrSize off
  let words =
    block {
      direct (regVar bld R.FCW) := AST.loadLE 16<rt> (at 0)
      direct (regVar bld R.FSW) := AST.loadLE 16<rt> (at 2)
      direct (regVar bld R.FTW) := AST.loadLE 16<rt> (at 4)
      direct (regVar bld R.FOP) := AST.loadLE 16<rt> (at 6)
      direct (regVar bld R.FIP) := AST.loadLE 64<rt> (at 8)
      direct (regVar bld R.FDP) := AST.loadLE 64<rt> (at 16)
    }
  fun b ->
    words b
    for i, st in List.indexed stackRegs do
      let stash = loadExtended b (at (32 + 16 * i)) (at (40 + 16 * i))
      unstashST b st stash

/// Reads the XMM registers back out of an FXSAVE-format image. MXCSR is not
/// among them: XRSTOR loads it under a rule of its own, and FXRSTOR pairs this
/// with `loadMxcsrArea` to get the whole SSE half.
let private loadXmmArea bld baseAddr addrSize is64bit =
  let at off = fieldAt baseAddr addrSize off
  block {
    for i, xmm in List.indexed (xmmRegsOf is64bit) do
      let struct (xmmb, xmma) = pseudoRegVar128 bld xmm
      direct xmma := AST.loadLE 64<rt> (at (160 + 16 * i))
      direct xmmb := AST.loadLE 64<rt> (at (168 + 16 * i))
  }

/// Reads MXCSR, and the mask beside it, back out of an FXSAVE-format image.
let private loadMxcsrArea bld baseAddr addrSize =
  let at off = fieldAt baseAddr addrSize off
  block {
    direct (regVar bld R.MXCSR) := AST.loadLE 32<rt> (at 24)
    direct (regVar bld R.MXCSRMASK) := AST.loadLE 32<rt> (at 28)
  }

/// Reads MXCSR alone, which is what XRSTOR loads: the mask beside it reports
/// what the silicon will accept, so no value from memory belongs there.
let private loadMxcsrOnly bld baseAddr addrSize =
  let at off = fieldAt baseAddr addrSize off
  block {
    direct (regVar bld R.MXCSR) := AST.loadLE 32<rt> (at 24)
  }

let private fxsaveInternal bld dstAddr addrSize is64bit =
  storeX87Area bld dstAddr addrSize bld
  storeSseArea bld dstAddr addrSize is64bit bld

let fxsave (ins: Instruction) bld =
  lift bld ins {
    let dst = transOneOpr ins bld
    let struct (addrExpr, addrSize) = getLoadAddressExpr dst
    fxsaveInternal bld addrExpr addrSize (bld.RegType = 64<rt>)
  }

let private fxrstoreInternal bld srcAddr addrSz is64bit =
  loadX87Area bld srcAddr addrSz bld
  loadMxcsrArea bld srcAddr addrSz bld
  loadXmmArea bld srcAddr addrSz is64bit bld

let fxrstor (ins: Instruction) bld =
  lift bld ins {
    let src = transOneOpr ins bld
    let struct (addrExpr, addrSize) = getLoadAddressExpr src
    fxrstoreInternal bld addrExpr addrSize (bld.RegType = 64<rt>)
  }

/// The XSAVE header follows the 512-byte legacy region. Its first eight bytes
/// name the components the image holds.
let [<Literal>] private XStateBvOff = 512

/// Its next eight name the layout a compacted image was written in.
let [<Literal>] private XCompBvOff = 520

/// Bit 63 of XCOMP_BV, the one that says the image is compacted.
let [<Literal>] private CompactedFormat = 0x8000000000000000UL

/// The components an XSAVE-family instruction acts on: the ones EDX:EAX names,
/// narrowed to those XCR0 says this processor manages. Only x87 (bit 0) and
/// SSE (bit 1) are modeled, and those are the only bits the emulator ever puts
/// in XCR0, so the mask can name nothing that goes unsaved. Widening XCR0
/// without widening these two means promising a component nothing writes.
let private xsaveRfbm bld =
  AST.concat (regVar bld R.EDX) (regVar bld R.EAX) .& regVar bld R.XCR0

/// The bit of a component bitmap belonging to the x87 state.
let private x87Bit bv = AST.xtlo 1<rt> bv

/// The bit of a component bitmap belonging to the SSE state.
let private sseBit bv = AST.extract bv 1<rt> 1

/// Writes the components the mask names into the legacy region, which is where
/// every format of the XSAVE area keeps x87 and SSE state: the standard and
/// the compacted layout differ in the header and in where they put the
/// components above these two, not in these.
let private xsaveComponents bld rfbm dstAddr addrSize is64bit =
  let x87 = storeX87Area bld dstAddr addrSize
  let sse = storeSseArea bld dstAddr addrSize is64bit
  _when bld "XsaveX87" (x87Bit rfbm) x87
  _when bld "XsaveSse" (sseBit rfbm) sse

/// XSAVE and XSAVEOPT: save the components EDX:EAX and XCR0 agree on, then add
/// them to the ones the header already claims. XSAVEOPT is allowed to skip a
/// component the processor knows is unchanged since it was last saved, and
/// writing it anyway is always a correct answer, so the two share this.
///
/// XINUSE is modeled as all ones -- the architecture lets a processor call a
/// component in use when it is really in its initial configuration -- so the
/// header ends up naming every component the mask asked for. Nothing else in
/// the header is touched, which is what leaves XCOMP_BV zero for the standard
/// format.
let private xsaveInternal bld dstAddr addrSize is64bit =
  let rfbm = tmpVar bld 64<rt>
  let bvAddr = fieldAt dstAddr addrSize XStateBvOff
  append bld {
    direct rfbm := xsaveRfbm bld
  }
  xsaveComponents bld rfbm dstAddr addrSize is64bit
  append bld {
    storeLE bvAddr (AST.loadLE 64<rt> bvAddr .| rfbm)
  }

let xsave (ins: Instruction) bld =
  lift bld ins {
    let dst = transOneOpr ins bld
    let struct (addrExpr, addrSize) = getLoadAddressExpr dst
    xsaveInternal bld addrExpr addrSize (bld.RegType = 64<rt>)
  }

/// XSAVEC: the same components, in the compacted format. The header names the
/// layout as well as the contents, and it replaces what was there rather than
/// adding to it -- XCOMP_BV describes the whole image, so a component left out
/// of the mask is left out of the image.
let private xsavecInternal bld dstAddr addrSize is64bit =
  let rfbm = tmpVar bld 64<rt>
  append bld {
    direct rfbm := xsaveRfbm bld
  }
  xsaveComponents bld rfbm dstAddr addrSize is64bit
  append bld {
    storeLE (fieldAt dstAddr addrSize XStateBvOff) rfbm
    storeLE (fieldAt dstAddr addrSize XCompBvOff)
      (rfbm .| numU64 CompactedFormat 64<rt>)
  }

let xsavec (ins: Instruction) bld =
  lift bld ins {
    let dst = transOneOpr ins bld
    let struct (addrExpr, addrSize) = getLoadAddressExpr dst
    xsavecInternal bld addrExpr addrSize (bld.RegType = 64<rt>)
  }

/// The x87 state as XRSTOR defines its initial configuration: the default
/// control word, a clear status word, every stack slot tagged empty, and no
/// opcode, pointer or datum left over from before.
let private initX87Area bld =
  let words =
    block {
      direct (regVar bld R.FCW) := numI32 0x037F 16<rt>
      direct (regVar bld R.FSW) := AST.num0 16<rt>
      direct (regVar bld R.FTW) := numI32 0xFFFF 16<rt>
      direct (regVar bld R.FOP) := AST.num0 16<rt>
      direct (regVar bld R.FIP) := AST.num0 64<rt>
      direct (regVar bld R.FDP) := AST.num0 64<rt>
    }
  fun b ->
    words b
    for st in stackRegs do clearST b st

/// The SSE state as XRSTOR defines its initial configuration. MXCSR is not
/// part of it: XRSTOR loads that from memory whether or not the header claims
/// the component.
let private initXmmArea bld is64bit =
  block {
    for xmm in xmmRegsOf is64bit do
      let struct (xmmb, xmma) = pseudoRegVar128 bld xmm
      direct xmma := AST.num0 64<rt>
      direct xmmb := AST.num0 64<rt>
  }

/// XRSTOR: for every component the mask names, load it from the image when the
/// header says the image holds it, and put it back to its initial
/// configuration when the header says it does not. MXCSR is the exception the
/// architecture carves out -- naming the SSE component in the mask loads it
/// either way.
///
/// The compacted format needs no case of its own here. It moves only the
/// components above SSE, and those are the ones this does not model, so x87
/// and SSE sit at the same offsets in an image of either format.
let private xrstorInternal bld srcAddr addrSize is64bit =
  let rfbm = tmpVar bld 64<rt>
  let bv = tmpVar bld 64<rt>
  append bld {
    direct rfbm := xsaveRfbm bld
    direct bv := AST.loadLE 64<rt> (fieldAt srcAddr addrSize XStateBvOff)
  }
  let loadX87 = loadX87Area bld srcAddr addrSize
  let initX87 = initX87Area bld
  let loadXmm = loadXmmArea bld srcAddr addrSize is64bit
  let initXmm = initXmmArea bld is64bit
  let loadMxcsr = loadMxcsrOnly bld srcAddr addrSize
  _when bld "RstorX87" (x87Bit rfbm .& x87Bit bv) loadX87
  _when bld "InitX87" (x87Bit rfbm .& AST.not (x87Bit bv)) initX87
  _when bld "RstorXmm" (sseBit rfbm .& sseBit bv) loadXmm
  _when bld "InitXmm" (sseBit rfbm .& AST.not (sseBit bv)) initXmm
  _when bld "RstorMxcsr" (sseBit rfbm) loadMxcsr

let xrstor (ins: Instruction) bld =
  lift bld ins {
    let src = transOneOpr ins bld
    let struct (addrExpr, addrSize) = getLoadAddressExpr src
    xrstorInternal bld addrExpr addrSize (bld.RegType = 64<rt>)
  }

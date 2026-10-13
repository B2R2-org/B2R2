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
/// Lifts the m68k floating-point instructions. The unit works in extended
/// precision, which is eighty bits: a sign, fifteen bits of exponent, and a
/// mantissa of sixty-four that carries its leading one explicitly rather than
/// implying it as the IEEE formats do. No register file holds a value that
/// wide, so a register is kept as the two that together are exactly it: the
/// sign and exponent word, and the mantissa.
///
/// The emulator computes in that format, exactly, through BRemu's M68KFloat
/// (the EMULATION build below): every arithmetic instruction is a call that
/// rounds once, to FPCR's precision and in its direction, as the unit does.
/// The static build carries every operation out in double precision and
/// converts back, which agrees with hardware wherever a program stays within
/// what a double can hold.
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

/// A sixty-four-bit constant.
let inline private num64 (n: uint64) = numU64 n 64<rt>

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

#if EMULATION
(* The emulator computes in the extended format itself, through BRemu's
   M68KFloat: a register keeps its sign and exponent word and its
   significand, every arithmetic instruction is one call that answers with
   the result and the condition codes it sets, and only the transcendental
   instructions still go through a double. *)

/// Calls an M68KFloat operation, the 128-bit word it gives back held in a
/// temporary: the significand in its low 64 bits, the sign and exponent in
/// bits 79:64, and in bits 127:96 the FPSR bits the operation sets.
let private m68kCall bld name args =
  let t = tmpVar bld 128<rt>
  append bld {
    t := AST.app name args 128<rt>
  }
  t

/// The sign and exponent word of an M68KFloat result.
let private seOf t = AST.extract t 16<rt> 64

/// The significand of an M68KFloat result.
let private sigOf t = AST.xtlo 64<rt> t

/// The FPSR bits an M68KFloat result sets, in FPSR's own places.
let private fpsrBitsOf t = AST.extract t 32<rt> 96

/// FPCR as the control an operation takes: its rounding mode in bits 5:4
/// and its precision in bits 7:6.
let private fpcrCtl bld = AST.zext 64<rt> (regVar bld R.FPCR)

/// The control of an instruction whose mnemonic names its precision, as the
/// 68040's FSADD and FDADD do: FPCR's mode at that precision, 1 for single
/// and 2 for double.
let private precCtl bld (prec: uint64) =
  (fpcrCtl bld .& num64 0x30UL) .| num64 (prec <<< 6)

/// The control an arithmetic instruction rounds by.
let private ctlOf bld (ins: Instruction) =
  match ins.Opcode with
  | Op.FSADD | Op.FSSUB | Op.FSMUL | Op.FSDIV | Op.FSSQRT
  | Op.FSMOVE | Op.FSABS | Op.FSNEG ->
    precCtl bld 1UL
  | Op.FDADD | Op.FDSUB | Op.FDMUL | Op.FDDIV | Op.FDSQRT
  | Op.FDMOVE | Op.FDABS | Op.FDNEG ->
    precCtl bld 2UL
  | _ ->
    fpcrCtl bld

/// A floating-point data register as M68KFloat takes an operand: its sign and
/// exponent word and its significand.
let private regOperand bld reg =
  let struct (lo, hi) = RegisterHelper.toFloatParts reg
  struct (regVar bld hi, regVar bld lo)

/// A value M68KFloat has widened into the extended format, as an operand.
let private widened bld name v =
  let t = m68kCall bld name [ v ]
  struct (seOf t, sigOf t)

/// The extended value an immediate in a binary format widens to, worked out
/// while lifting for a normal value or a zero, which is what a program
/// writes as a constant: `fracBits` and `biasDiff` say which format, as the
/// bits of its fraction and how far its bias sits below the extended one.
/// Anything else is left to M68KFloat.
let private widenedConst (bits: uint64) fracBits biasDiff =
  let top = fracBits + (if fracBits = 52 then 11 else 8)
  let sign = (bits >>> (top - 15)) &&& 0x8000UL
  let e = (bits >>> fracBits) &&& ((1UL <<< (top - fracBits)) - 1UL)
  let frac = bits &&& ((1UL <<< fracBits) - 1UL)
  let maxE = (1UL <<< (top - fracBits)) - 1UL
  if e - 1UL < maxE - 1UL then
    let m = 0x8000000000000000UL ||| (frac <<< (63 - fracBits))
    ValueSome(struct (sign ||| (e + biasDiff), m))
  elif e = 0UL && frac = 0UL then
    ValueSome(struct (sign, 0UL))
  else
    ValueNone

/// A single or a double immediate as an operand, widened while lifting where
/// widenedConst can, and by M68KFloat where it cannot.
let private immWidened bld name bits fracBits biasDiff =
  match widenedConst bits fracBits biasDiff with
  | ValueSome(struct (se, m)) -> struct (numU64 se 16<rt>, num64 m)
  | ValueNone -> widened bld name (num64 bits)

/// A floating-point immediate as an operand: an extended one as it is, a
/// single or a double one widened.
let private immOperand bld (bytes: byte[]) =
  match bytes.Length with
  | 4 -> immWidened bld "M68KOFF32" (beValue bytes 0 4) 23 0x3f80UL
  | 8 -> immWidened bld "M68KOFF64" (beValue bytes 0 8) 52 0x3c00UL
  | _ -> struct (numU64 (beValue bytes 0 2) 16<rt>, num64 (beValue bytes 4 8))

/// A floating-point source operand as M68KFloat takes it, widened exactly
/// from whichever format the instruction reads it in.
let private srcOperand bld ins size opr =
  match opr, size with
  | OpFImm bytes, _ ->
    immOperand bld bytes
  | OpReg r, _ when isFloatReg r ->
    regOperand bld r
  | _, Sz.Extended ->
    let addr = floatAddrOf bld ins Sz.Extended opr
    struct (loadNative bld 16<rt> addr, loadNative bld 64<rt> (addr .+ num32 4))
  | _, (Sz.Byte | Sz.Word | Sz.Long) ->
    let v = readLoc bld size (transOpr bld ins size opr)
    widened bld "M68KOFINT" (AST.sext 64<rt> v)
  | _, Sz.Single ->
    let v = readLoc bld Sz.Single (transOpr bld ins Sz.Single opr)
    widened bld "M68KOFF32" (AST.zext 64<rt> v)
  | _, Sz.Double ->
    let v = readLoc bld Sz.Double (transOpr bld ins Sz.Double opr)
    widened bld "M68KOFF64" v
  | _ ->
    raise InvalidOperandSizeException

/// Writes an M68KFloat result to a floating-point data register.
let private writeResult bld reg t =
  let struct (rlo, rhi) = RegisterHelper.toFloatParts reg
  append bld {
    regVar bld rhi := seOf t
    regVar bld rlo := sigOf t
  }

/// Puts into FPSR the bits of `bits` that `mask` covers.
let private mergeFpsr bld bits (mask: uint32) =
  let fpsr = regVar bld R.FPSR
  append bld {
    fpsr := (fpsr .& numU32 (~~~mask) 32<rt>) .| (bits .& numU32 mask 32<rt>)
  }

/// Sets FPSR's condition codes from an M68KFloat result.
let private setCondition bld t = mergeFpsr bld (fpsrBitsOf t) 0x0f000000u

/// FPSR's condition codes for a value as it stands, as FTST and FMOVE report
/// them: the sign, and whether it is a zero, an infinity or a NaN. They are
/// worked out here rather than called for, as FMOVE is the commonest FPU
/// instruction there is.
let private conditionOf se m =
  let e = AST.zext 32<rt> se .& numI32 0x7fff 32<rt>
  let top = e == numI32 0x7fff 32<rt>
  let frac = (m << AST.num1 64<rt>) != AST.num0 64<rt>
  let at b n = AST.zext 32<rt> b << numI32 n 32<rt>
  at (AST.xthi 1<rt> se) 27
  .| at ((e == AST.num0 32<rt>) .& (m == AST.num0 64<rt>)) 26
  .| at (top .& AST.not frac) 25
  .| at (top .& frac) 24

/// Sets FPSR's condition codes from a value as it stands.
let private setConditionOf bld se m =
  mergeFpsr bld (conditionOf se m) 0x0f000000u

/// Lifts an instruction of one operand that M68KFloat works out from the
/// arguments `argsOf` makes of the source, into the destination register.
let private unary (ins: Instruction) bld name argsOf =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let dstReg = floatRegOf o2
    let struct (se, m) = srcOperand bld ins ins.Size o1
    let t = m68kCall bld name (argsOf se m)
    writeResult bld dstReg t
    setCondition bld t
  }

/// Lifts an instruction of one operand under a control, the source handed
/// over as `adjust` makes it.
let private monadic ins bld name ctl adjust =
  unary ins bld name (fun se m -> [ ctl; adjust se; m ])

/// Lifts an instruction of two operands that M68KFloat works out, combining
/// the source into the destination register.
let private dyadic (ins: Instruction) bld name ctl =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let dstReg = floatRegOf o2
    let struct (sse, sm) = srcOperand bld ins ins.Size o1
    let struct (dse, dm) = regOperand bld dstReg
    let t = m68kCall bld name [ ctl; dse; dm; sse; sm ]
    writeResult bld dstReg t
    setCondition bld t
  }

/// Lifts an FADD, an FSADD or an FDADD.
let fadd (ins: Instruction) bld = dyadic ins bld "M68KADD" (ctlOf bld ins)

/// Lifts an FSUB, an FSSUB or an FDSUB.
let fsub (ins: Instruction) bld = dyadic ins bld "M68KSUB" (ctlOf bld ins)

/// Lifts an FMUL, an FSMUL or an FDMUL.
let fmul (ins: Instruction) bld = dyadic ins bld "M68KMUL" (ctlOf bld ins)

/// Lifts an FDIV, an FSDIV or an FDDIV.
let fdiv (ins: Instruction) bld = dyadic ins bld "M68KDIV" (ctlOf bld ins)

/// Lifts an FSGLMUL, which multiplies in single precision.
let fsglmul ins bld = dyadic ins bld "M68KSGLMUL" (fpcrCtl bld)

/// Lifts an FSGLDIV, which divides in single precision.
let fsgldiv ins bld = dyadic ins bld "M68KSGLDIV" (fpcrCtl bld)

/// Lifts an FMOVE, an FSMOVE or an FDMOVE into a floating-point data
/// register. FMOVE copies an extended source as it is and widens any other
/// exactly, rounding neither, as QEMU does; FSMOVE and FDMOVE round.
let private fmoveData (ins: Instruction) bld =
  match ins.Opcode with
  | Op.FSMOVE | Op.FDMOVE ->
    monadic ins bld "M68KROUND" (ctlOf bld ins) id
  | _ ->
    lift bld ins {
      let struct (o1, o2) = getTwoOprs ins
      let struct (rlo, rhi) = RegisterHelper.toFloatParts (floatRegOf o2)
      let struct (se, m) = srcOperand bld ins ins.Size o1
      let tse = tmpVar bld 16<rt>
      let tm = tmpVar bld 64<rt>
      tse := se
      tm := m
      regVar bld rhi := tse
      regVar bld rlo := tm
      setConditionOf bld tse tm
    }

/// The value of a floating-point data register as an FMOVE writes it out in
/// the format `size` names, rounded in the direction FPCR names.
let private outValue bld size se m =
  let ctl = fpcrCtl bld
  match size with
  | Sz.Double -> AST.app "M68KTOF64" [ ctl; se; m ] 64<rt>
  | Sz.Single -> AST.xtlo 32<rt> (AST.app "M68KTOF32" [ ctl; se; m ] 64<rt>)
  | _ -> AST.xtlo (regTypeOf size) (AST.app "M68KTOINT" [ ctl; se; m ] 64<rt>)

/// Writes a floating-point data register out in the format `size` names.
let private writeOut bld ins size dstOpr se m =
  match size with
  | Sz.Extended ->
    storeExtended bld (floatAddrOf bld ins Sz.Extended dstOpr) se m
  | Sz.Packed ->
    raise InvalidOperandSizeException
  | _ ->
    let dst = transOpr bld ins size dstOpr
    append bld {
      writeLoc bld size dst (outValue bld size se m)
    }

/// Lifts an FMOVE out of a floating-point data register. The condition codes
/// are the register's, which is what QEMU sets them from.
let private fmoveOut (ins: Instruction) bld reg dstOpr =
  lift bld ins {
    let struct (se, m) = regOperand bld reg
    writeOut bld ins ins.Size dstOpr se m
    setConditionOf bld se m
  }

/// Lifts an FNEG, an FSNEG or an FDNEG: the sign turned over, the value then
/// rounded to the precision, as QEMU does.
let fneg (ins: Instruction) bld =
  let flip se = se <+> numI32 0x8000 16<rt>
  monadic ins bld "M68KROUND" (ctlOf bld ins) flip

/// Lifts an FABS, an FSABS or an FDABS: the sign cleared, the value then
/// rounded to the precision.
let fabs (ins: Instruction) bld =
  let clear se = se .& numI32 0x7fff 16<rt>
  monadic ins bld "M68KROUND" (ctlOf bld ins) clear

/// Lifts an FSQRT, an FSSQRT or an FDSQRT.
let fsqrt (ins: Instruction) bld =
  monadic ins bld "M68KSQRT" (ctlOf bld ins) id

/// Lifts an FINT, which rounds to a whole number in whichever direction
/// FPCR.RND names.
let fint ins bld = monadic ins bld "M68KINT" (fpcrCtl bld) id

/// Lifts an FINTRZ, which rounds to a whole number toward zero whatever the
/// rounding mode says: FPCR with its mode replaced by mode 1.
let fintrz ins bld =
  let ctl = (fpcrCtl bld .& num64 (~~~0x30UL)) .| num64 0x10UL
  monadic ins bld "M68KINT" ctl id

/// Lifts an FGETEXP, which gives the exponent of its source as a value.
let fgetexp ins bld = unary ins bld "M68KGETEXP" (fun se m -> [ se; m ])

/// Lifts an FGETMAN, which gives its source with the exponent taken out.
let fgetman ins bld = monadic ins bld "M68KGETMAN" (fpcrCtl bld) id

/// Lifts an FSCALE, which multiplies by the power of two its source names.
let fscale ins bld = dyadic ins bld "M68KSCALE" (fpcrCtl bld)

/// Lifts an FMOD, or an FREM where `isRem` is set, which also leave the
/// quotient's sign and low seven bits in FPSR's quotient byte -- unless the
/// answer is a NaN, which leaves that byte alone.
let private modRem (ins: Instruction) bld (isRem: uint64) =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let dstReg = floatRegOf o2
    let struct (sse, sm) = srcOperand bld ins ins.Size o1
    let struct (dse, dm) = regOperand bld dstReg
    let args = [ fpcrCtl bld; num64 isRem; dse; dm; sse; sm ]
    let t = m68kCall bld "M68KMODREM" args
    let both = numU32 0x0fff0000u 32<rt>
    let ccOnly = numU32 0x0f000000u 32<rt>
    let mask = AST.ite (AST.extract t 1<rt> 80) both ccOnly
    let fpsr = regVar bld R.FPSR
    writeResult bld dstReg t
    fpsr := (fpsr .& AST.not mask) .| (fpsrBitsOf t .& mask)
  }

/// Lifts an FMOD, whose quotient is rounded toward zero.
let fmod ins bld = modRem ins bld 0UL

/// Lifts an FREM, whose quotient is rounded to the nearest whole number.
let frem ins bld = modRem ins bld 1UL

/// Lifts an FCMP, which reports how its destination stands against its source
/// and keeps nothing.
let fcmp (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let struct (sse, sm) = srcOperand bld ins ins.Size o1
    let struct (dse, dm) = regOperand bld (floatRegOf o2)
    let cc = AST.app "M68KCMP" [ dse; dm; sse; sm ] 64<rt>
    mergeFpsr bld (AST.xtlo 32<rt> cc) 0x0f000000u
  }

/// Lifts an FTST, which reports what its one operand is.
let ftst (ins: Instruction) bld =
  lift bld ins {
    let struct (se, m) = srcOperand bld ins ins.Size (getOneOpr ins)
    setConditionOf bld se m
  }

/// Returns the constant an FMOVECR offset names, as the unit's ROM holds it
/// in the extended format: its sign and exponent word and its significand.
/// Every offset the manual leaves undefined answers zero, as the 68040's
/// does.
let private moveCrConstant (offset: int64) =
  match offset with
  | 0x00L -> struct (0x4000UL, 0xc90fdaa22168c235UL)
  | 0x0BL -> struct (0x3ffdUL, 0x9a209a84fbcff798UL)
  | 0x0CL -> struct (0x4000UL, 0xadf85458a2bb4a9aUL)
  | 0x0DL -> struct (0x3fffUL, 0xb8aa3b295c17f0bcUL)
  | 0x0EL -> struct (0x3ffdUL, 0xde5bd8a937287195UL)
  | 0x30L -> struct (0x3ffeUL, 0xb17217f7d1cf79acUL)
  | 0x31L -> struct (0x4000UL, 0x935d8dddaaa8ac17UL)
  | 0x32L -> struct (0x3fffUL, 0x8000000000000000UL)
  | 0x33L -> struct (0x4002UL, 0xa000000000000000UL)
  | 0x34L -> struct (0x4005UL, 0xc800000000000000UL)
  | 0x35L -> struct (0x400cUL, 0x9c40000000000000UL)
  | 0x36L -> struct (0x4019UL, 0xbebc200000000000UL)
  | 0x37L -> struct (0x4034UL, 0x8e1bc9bf04000000UL)
  | 0x38L -> struct (0x4069UL, 0x9dc5ada82b70b59eUL)
  | 0x39L -> struct (0x40d3UL, 0xc2781f49ffcfa6d5UL)
  | 0x3aL -> struct (0x41a8UL, 0x93ba47c980e98ce0UL)
  | 0x3bL -> struct (0x4351UL, 0xaa7eebfb9df9de8eUL)
  | 0x3cL -> struct (0x46a3UL, 0xe319a0aea60e91c7UL)
  | 0x3dL -> struct (0x4d48UL, 0xc976758681750c17UL)
  | 0x3eL -> struct (0x5a92UL, 0x9e8b3b5dc53d5de5UL)
  | 0x3fL -> struct (0x7525UL, 0xc46052028a20979bUL)
  | _ -> struct (0UL, 0UL)

/// Lifts an FMOVECR, which loads one of the constants the unit keeps in a
/// table of its own.
let fmovecr (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let offset =
      match o1 with
      | OpImm v -> v
      | _ -> raise InvalidOperandException
    let struct (se, m) = moveCrConstant offset
    let struct (rlo, rhi) = RegisterHelper.toFloatParts (floatRegOf o2)
    let seV = numU64 se 16<rt>
    let mV = num64 m
    regVar bld rhi := seV
    regVar bld rlo := mV
    setConditionOf bld seV mV
  }

/// Lifts an instruction that still computes in double precision: the source
/// as the double nearest it, `op` applied there, and the answer widened back.
let private transcendental (ins: Instruction) bld op =
  lift bld ins {
    let struct (o1, o2) = getTwoOprs ins
    let dstReg = floatRegOf o2
    let struct (se, m) = srcOperand bld ins ins.Size o1
    let s = tmpVar bld 64<rt>
    s := AST.app "M68KVIEWF64" [ se; m ] 64<rt>
    let t = m68kCall bld "M68KOFF64" [ op s ]
    writeResult bld dstReg t
    setCondition bld t
  }

/// Lifts an FSINCOS, the one FPU instruction with two destinations: the sine
/// goes to the register the opcode word names in bits 9 to 7 and the cosine to
/// the one it names in bits 2 to 0, which the parser hands over as the third
/// and the second operand. The cosine is stored first, so that an encoding
/// naming the same register twice keeps the sine, as the manual says it does,
/// and the condition codes are the sine's.
let fsincos (ins: Instruction) bld =
  lift bld ins {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (se, m) = srcOperand bld ins ins.Size o1
    let s = tmpVar bld 64<rt>
    s := AST.app "M68KVIEWF64" [ se; m ] 64<rt>
    let c = m68kCall bld "M68KOFF64" [ AST.fcos s ]
    let r = m68kCall bld "M68KOFF64" [ AST.fsin s ]
    writeResult bld (floatRegOf o2) c
    writeResult bld (floatRegOf o3) r
    setCondition bld r
  }
#else
/// How much wider the bias of an extended-precision exponent is than that of a
/// double-precision one, which is what converting between the two moves it by.
let [<Literal>] private BiasDiff = 0x3c00UL

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
    (* The conversion is left bare, which is to say rounded in whichever
       direction FPCR.RND names: that is what the instruction does, and what an
       expression no RoundCtrl encloses means. *)
    let dst = transOpr bld ins size opr
    let rt = regTypeOf size
    append bld {
      writeLoc bld size dst (AST.cast CastKind.FloatToSInt rt v)
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

/// Lifts an FINT, which rounds to a whole number in whichever direction
/// FPCR.RND names -- a bare rounding, as against FINTRZ below, which names one
/// of its own.
let fint ins bld =
  monadic ins bld (AST.cast CastKind.RoundToIntegral 64<rt>)

/// Lifts an FINTRZ, which rounds to a whole number toward zero whatever the
/// rounding mode says.
let fintrz ins bld =
  monadic ins bld (AST.roundToIntegral RoundingMode.TowardZero 64<rt>)

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
    let k = AST.floatToSInt RoundingMode.TowardZero 64<rt> s
    let e = (k .+ num64 1023UL) << numI32 52 64<rt>
    AST.fmul d e)

/// Lifts an FMOD, which is the remainder of a division whose quotient is
/// rounded toward zero.
let fmod ins bld =
  dyadic ins bld (fun d s ->
    let q = AST.roundToIntegral RoundingMode.TowardZero 64<rt> (AST.fdiv d s)
    AST.fsub d (AST.fmul s q))

/// Lifts an FREM, which is the remainder of a division whose quotient is
/// rounded to the nearest whole number.
let frem ins bld =
  dyadic ins bld (fun d s ->
    let q = AST.roundToIntegral RoundingMode.ToNearestEven 64<rt> (AST.fdiv d s)
    AST.fsub d (AST.fmul s q))

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

/// Lifts an FMOVE out of a floating-point data register.
let private fmoveOut (ins: Instruction) bld reg dstOpr =
  lift bld ins {
    let v = tmpVar bld 64<rt>
    v := readFloat bld reg
    setFpuFlags bld v
    writeFloatOpr bld ins ins.Size dstOpr v
  }

/// Lifts an instruction computed in double precision.
let private transcendental ins bld op = monadic ins bld op
#endif

/// A double-precision constant.
let private numFloat (v: float) = num64 (BitConverter.DoubleToUInt64Bits v)

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
let fetox ins bld = transcendental ins bld expOf

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
  transcendental ins bld (fun s ->
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
let ftwotox ins bld = transcendental ins bld (AST.fpow (numFloat 2.0))

/// Lifts an FTENTOX, which raises ten to the power of its source.
let ftentox ins bld = transcendental ins bld (AST.fpow (numFloat 10.0))

/// Lifts an FLOGN, the natural logarithm.
let flogn ins bld = transcendental ins bld (AST.flog (numFloat Math.E))

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
  transcendental ins bld (fun s ->
    let near =
      AST.fmul (numFloat 2.0)
        (AST.fatanh (AST.fdiv s (AST.fadd s (numFloat 2.0))))
    let far = AST.flog (numFloat Math.E) (AST.fadd s (numFloat 1.0))
    AST.ite (AST.flt (fmagnitude s) (numFloat 0.5)) near far)

/// Lifts an FLOG2.
let flog2 ins bld = transcendental ins bld (AST.flog (numFloat 2.0))

/// Lifts an FLOG10.
let flog10 ins bld = transcendental ins bld (AST.flog (numFloat 10.0))

/// Lifts an FSIN.
let fsin ins bld = transcendental ins bld AST.fsin

/// Lifts an FCOS.
let fcos ins bld = transcendental ins bld AST.fcos

/// Lifts an FTAN.
let ftan ins bld = transcendental ins bld AST.ftan

/// Lifts an FASIN.
let fasin ins bld = transcendental ins bld AST.fasin

/// Lifts an FACOS.
let facos ins bld = transcendental ins bld AST.facos

/// Lifts an FATAN.
let fatan ins bld = transcendental ins bld AST.fatan

/// Lifts an FSINH.
let fsinh ins bld = transcendental ins bld AST.fsinh

/// Lifts an FCOSH.
let fcosh ins bld = transcendental ins bld AST.fcosh

/// Lifts an FTANH.
let ftanh ins bld = transcendental ins bld AST.ftanh

/// Lifts an FATANH.
let fatanh ins bld = transcendental ins bld AST.fatanh

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
    fmoveOut ins bld r dstOpr
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

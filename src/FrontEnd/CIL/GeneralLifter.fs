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
/// Translates the CIL instructions that compute: the constants, the variables,
/// the arithmetic, the conversions, the comparisons, the branches, and the
/// loads and stores through a pointer. What each one does is a function of
/// the slots it pops and nothing else, so everything here is spelled out in
/// LowUIR and needs no runtime behind it.
module internal B2R2.FrontEnd.CIL.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.CIL.LiftHelper

/// An instruction whose whole effect is to leave the machine as it was: nop,
/// and the prefixes that promise something about the instruction after them
/// which this model needs no promise of.
let nop (ins: Instruction) bld =
  lift bld ins { () }

/// An instruction this lifter has no model for, which the emulator is left to
/// refuse rather than to run as something it is not.
let unsupported (ins: Instruction) bld =
  lift bld ins { AST.sideEffect UnsupportedInstruction }

/// break: a trap into whatever debugger is attached.
let breakpoint (ins: Instruction) bld =
  lift bld ins { AST.sideEffect Breakpoint }

let private pushConst (ins: Instruction) bld v t =
  lift bld ins { push bld v t }

/// ldc.i4 and ldc.i4.s, whose constant the parser has already widened.
let ldcI4 ins bld =
  pushConst ins bld (numI32 (getI4 ins) 64<rt>) (tag SlotType.I4)

/// ldc.i4.0 to ldc.i4.8 and ldc.i4.m1, whose constant is in the opcode.
let ldcI4N ins bld n = pushConst ins bld (num64 n) (tag SlotType.I4)

let ldcI8 ins bld =
  pushConst ins bld (numI64 (getI8 ins) 64<rt>) (tag SlotType.I8)

/// ldc.r4: a single, as its bits.
let ldcR4 ins bld =
  let bits = System.BitConverter.SingleToUInt32Bits(getR4 ins)
  pushConst ins bld (numU64 (uint64 bits) 64<rt>) (tag SlotType.F4)

let ldcR8 ins bld = pushConst ins bld (numF64 (getR8 ins)) (tag SlotType.F8)

let ldnull ins bld = pushConst ins bld (AST.num0 64<rt>) (tag SlotType.O)

/// <summary>
/// The value a variable holds, widened to what the stack keeps of its type: an
/// int32 sign-extended, a small integer sign- or zero-extended as its type
/// says, a float32 as its own bits, and everything else as it is.
///
/// The widening is done on the load rather than the store because a store
/// through the variable's address (ldloca followed by stind) bypasses the
/// store and leaves whatever it wrote in the low bytes.
/// </summary>
let private widenVar v d =
  let r4 = AST.ite (d == tag SlotType.R4) (zext32 v) v
  let u2 = AST.ite (d == tag SlotType.U2) (zext16 v) r4
  let i2 = AST.ite (d == tag SlotType.I2) (sext16 v) u2
  let u1 = AST.ite (d == tag SlotType.U1) (zext8 v) i2
  let i1 = AST.ite (d == tag SlotType.I1) (sext8 v) u1
  AST.ite (d == tag SlotType.I4) (sext32 v) i1

/// The tag a loaded variable gets: every small integer type loads as an
/// int32, a float32 as a single-precision F, and the rest as themselves.
let private stackTagOf d =
  let isSmall = (d .>= tag SlotType.I1) .& (d .<= tag SlotType.U2)
  let r4 = AST.ite (d == tag SlotType.R4) (tag SlotType.F4) d
  AST.ite isSmall (tag SlotType.I4) r4

let private loadVar (ins: Instruction) bld addr =
  lift bld ins {
    let struct (v, d) = readSlot bld addr
    push bld (widenVar v d) (stackTagOf d)
  }

let ldloc ins bld = loadVar ins bld (varAddr (fp bld) (getVar ins))

let ldlocN ins bld n = loadVar ins bld (varAddr (fp bld) n)

let ldarg ins bld = loadVar ins bld (varAddr (ap bld) (getVar ins))

let ldargN ins bld n = loadVar ins bld (varAddr (ap bld) n)

/// <summary>
/// Stores the top of the stack into a variable, converting to the variable's
/// type where the representation differs: a float32 variable takes the single
/// a double rounds to, and a float64 variable the double a single widens to.
/// Everything else is written as it is, the variable's type living in its low
/// bytes and its load doing the narrowing.
///
/// The tag word is the variable's declared type and is left alone.
/// </summary>
let private storeVar (ins: Instruction) bld addr =
  lift bld ins {
    let struct (v, t) = peek bld 0
    let d = tmpVar bld 64<rt>
    d := loadTag addr
    let single = AST.zext 64<rt> (narrowF t v)
    let dbl = AST.ite (d == tag SlotType.F8) (asDouble t v) v
    AST.store Endian.Little addr (AST.ite (d == tag SlotType.R4) single dbl)
    drop bld 1
  }

let stloc ins bld = storeVar ins bld (varAddr (fp bld) (getVar ins))

let stlocN ins bld n = storeVar ins bld (varAddr (fp bld) n)

let starg ins bld = storeVar ins bld (varAddr (ap bld) (getVar ins))

/// ldloca/ldarga: the address of a variable's slot, whose value word is where
/// a load or store through it finds the variable in its own representation.
let private addressOfVar (ins: Instruction) bld addr =
  lift bld ins { push bld addr (tag SlotType.Ref) }

let ldloca ins bld = addressOfVar ins bld (varAddr (fp bld) (getVar ins))

let ldarga ins bld = addressOfVar ins bld (varAddr (ap bld) (getVar ins))

let dup (ins: Instruction) bld =
  lift bld ins {
    let struct (v, t) = peek bld 0
    push bld v t
  }

let pop (ins: Instruction) bld =
  lift bld ins { drop bld 1 }

/// The two operands of a binary instruction, the first pushed first, with
/// their tags, and the tag of its result computed into a temporary.
let private binaryOperands bld =
  let struct (b, tb) = peek bld 0
  let struct (a, ta) = peek bld 1
  let t = tmpVar bld 64<rt>
  append bld { t := maxTag ta tb }
  struct (a, ta, b, tb, t)

/// The floating-point result of a binary instruction: the operands as doubles,
/// the operation in double precision, and the result in the precision the
/// result's tag says.
let private floatOp fop a ta b tb t =
  floatResult t (fop (asDouble ta a) (asDouble tb b))

/// <summary>
/// add, sub and mul, whose low bits depend on the low bits of the operands
/// alone, so that the 32-bit result is the 64-bit one narrowed and widened
/// back.
/// </summary>
let private arith (ins: Instruction) bld iop fop =
  lift bld ins {
    let struct (a, ta, b, tb, t) = binaryOperands bld
    let i = iop a b
    let f = floatOp fop a ta b tb t
    replace bld 2 (AST.ite (isF t) f (AST.ite (is32 t) (sext32 i) i)) t
  }

let add ins bld = arith ins bld AST.add AST.fadd

let sub ins bld = arith ins bld AST.sub AST.fsub

let mul ins bld = arith ins bld AST.mul AST.fmul

/// and, or and xor: the canonical form is closed under them, so there is no
/// width to speak of.
let private logic (ins: Instruction) bld op =
  lift bld ins {
    let struct (a, _, b, _, t) = binaryOperands bld
    replace bld 2 (op a b) t
  }

let logicAnd ins bld = logic ins bld (fun a b -> a .& b)

let logicOr ins bld = logic ins bld (fun a b -> a .| b)

let logicXor ins bld = logic ins bld AST.xor

/// neg: a floating-point negation flips the sign bit, of a NaN too, which is
/// what the runtime's xor with a sign mask does.
let neg (ins: Instruction) bld =
  lift bld ins {
    let struct (v, t) = peek bld 0
    let i = AST.neg v
    let f8 = v <+> numU64 0x8000000000000000UL 64<rt>
    let f = AST.ite (isF4 t) (v <+> numU64 0x80000000UL 64<rt>) f8
    let r = AST.ite (isF t) f (AST.ite (is32 t) (sext32 i) i)
    writeSlot bld (slotAddr bld 0) r t
  }

/// not: the canonical form is closed under a complement.
let logicNot (ins: Instruction) bld =
  lift bld ins {
    let struct (v, t) = peek bld 0
    writeSlot bld (slotAddr bld 0) (AST.not v) t
  }

/// The most negative value of the width the operands compute in, which is the
/// one dividend whose division by minus one overflows.
let private minValue t =
  let min32 = numI64 -2147483648L 64<rt>
  AST.ite (is32 t) min32 (numI64 System.Int64.MinValue 64<rt>)

/// <summary>
/// div and rem, which raise on a zero divisor and on the one overflowing
/// quotient rather than compute either.
///
/// The division is never handed a divisor of zero or minus one: the first is
/// replaced by one behind the raise, and the second is a case of its own, a
/// negation for div and zero for rem, so that neither the evaluator nor a host
/// evaluating both arms of a choice can trap where the guest would not.
/// </summary>
let private divide (ins: Instruction) bld op byMinusOne fop =
  lift bld ins {
    let struct (a, ta, b, tb, t) = binaryOperands bld
    let isInt = AST.not (isF t)
    let zero = b == AST.num0 64<rt>
    let minusOne = b == num64 -1
    let ovf = minusOne .& (a == minValue t)
    raiseWhen bld "DivideByZero" (isInt .& zero) CILException.DivideByZero
    raiseWhen bld "DivideOverflow" (isInt .& ovf) CILException.Overflow
    let safe = AST.ite (zero .| minusOne) (num64 1) b
    let q32 = sext32 (op (lo32 a) (lo32 safe))
    let i32 = AST.ite minusOne (sext32 (byMinusOne a)) q32
    let i64 = AST.ite minusOne (byMinusOne a) (op a safe)
    let f = floatOp fop a ta b tb t
    replace bld 2 (AST.ite (isF t) f (AST.ite (is32 t) i32 i64)) t
  }

let div ins bld = divide ins bld AST.sdiv AST.neg AST.fdiv

/// rem: the floating-point remainder is the exact one fmod computes, which no
/// composition of rounded operations gives, so it is named for the evaluator.
let rem ins bld =
  let fmod a b = AST.app "FMOD64" [ a; b ] 64<rt>
  divide ins bld AST.smod (fun _ -> AST.num0 64<rt>) fmod

/// div.un and rem.un, which raise on a zero divisor alone.
let private divideUnsigned (ins: Instruction) bld op =
  lift bld ins {
    let struct (a, _, b, _, t) = binaryOperands bld
    let zero = b == AST.num0 64<rt>
    raiseWhen bld "DivideByZero" zero CILException.DivideByZero
    let safe = AST.ite zero (num64 1) b
    let i32 = sext32 (op (lo32 a) (lo32 safe))
    replace bld 2 (AST.ite (is32 t) i32 (op a safe)) t
  }

let divUn ins bld = divideUnsigned ins bld AST.div

let remUn ins bld = divideUnsigned ins bld (fun a b -> a .% b)

/// <summary>
/// The shifts, whose count is masked to the width as the runtime's host does;
/// ECMA-335 leaves a count at or past the width unspecified.
///
/// The result keeps the type of the value shifted, and an arithmetic right
/// shift of the canonical form is itself canonical, so only the left shift and
/// the logical right shift have to be narrowed.
/// </summary>
let private shift (ins: Instruction) bld op32 op64 =
  lift bld ins {
    let struct (n, _) = peek bld 0
    let struct (v, t) = peek bld 1
    let r32 = sext32 (op32 v (n .& num64 31))
    replace bld 2 (AST.ite (is32 t) r32 (op64 v (n .& num64 63))) t
  }

let shl ins bld = shift ins bld (fun v c -> v << c) (fun v c -> v << c)

let shr ins bld = shift ins bld (fun v c -> v ?>> c) (fun v c -> v ?>> c)

let shrUn ins bld = shift ins bld (fun v c -> zext32 v >> c) (fun v c -> v >> c)

/// <summary>
/// The checked add, sub and mul, which raise on an overflow rather than wrap.
///
/// The 32-bit case is checked by computing in 64 bits and asking whether the
/// result is its own canonical form; the 64-bit case by the test the operation
/// has for it.
/// </summary>
let private checkedArith (ins: Instruction) bld op32 op64 =
  lift bld ins {
    let struct (a, _, b, _, t) = binaryOperands bld
    let struct (r32, ovf32) = op32 a b
    let struct (r64, ovf64) = op64 a b
    let ovf = AST.ite (is32 t) ovf32 ovf64
    raiseWhen bld "Overflow" ovf CILException.Overflow
    replace bld 2 (AST.ite (is32 t) r32 r64) t
  }

/// A 64-bit operation on two canonical int32 values, whose exact result fits,
/// overflows int32 when it is not its own canonical form.
let private via64 op a b =
  let r = op a b
  struct (sext32 r, r != sext32 r)

/// The 32-bit halves of two canonical int32 values, as unsigned 64-bit values.
let private unsigned32 op a b =
  let r = op (zext32 a) (zext32 b)
  struct (sext32 r, (r >> num64 32) != AST.num0 64<rt>)

let private signBit v = AST.xthi 1<rt> v

let addOvf ins bld =
  let add64 a b =
    let r = a .+ b
    struct (r, signBit ((a <+> r) .& (b <+> r)))
  checkedArith ins bld (via64 AST.add) add64

let addOvfUn ins bld =
  let add64 a b =
    let r = a .+ b
    struct (r, r .< a)
  checkedArith ins bld (unsigned32 AST.add) add64

let subOvf ins bld =
  let sub64 a b =
    let r = a .- b
    struct (r, signBit ((a <+> b) .& (a <+> r)))
  checkedArith ins bld (via64 AST.sub) sub64

let subOvfUn ins bld =
  let sub32 a b = struct (sext32 (a .- b), lo32 a .< lo32 b)
  let sub64 a b = struct (a .- b, a .< b)
  checkedArith ins bld sub32 sub64

/// The 128-bit product of two 64-bit values, which is what says whether the
/// 64-bit one lost anything.
let private wide ext a b =
  let p = (ext 128<rt> a) .* (ext 128<rt> b)
  let low = AST.xtlo 64<rt> p
  struct (p, low)

let mulOvf ins bld =
  let mul64 a b =
    let struct (p, low) = wide AST.sext a b
    struct (low, p != AST.sext 128<rt> low)
  checkedArith ins bld (via64 AST.mul) mul64

let mulOvfUn ins bld =
  let mul64 a b =
    let struct (p, low) = wide AST.zext a b
    struct (low, AST.xthi 64<rt> p != AST.num0 64<rt>)
  checkedArith ins bld (unsigned32 AST.mul) mul64

/// <summary>
/// The unchecked conversions: what the top of the stack becomes is a function
/// of whether it is a floating-point number, and for the widenings of whether
/// it is an int32, which is the one integer whose unsigned reading is not its
/// slot word.
/// </summary>
let private conv (ins: Instruction) bld outTag ofInt ofFloat =
  lift bld ins {
    let struct (v, t) = peek bld 0
    let r = AST.ite (isF t) (ofFloat (asDouble t v)) (ofInt v (is32 t))
    writeSlot bld (slotAddr bld 0) r (tag outTag)
  }

/// The unsigned reading of an integer slot: the low 32 bits of an int32, the
/// whole word of anything wider.
let private asUnsigned v is32 = AST.ite is32 (zext32 v) v

let convI1 ins bld =
  conv ins bld SlotType.I4 (fun v _ -> sext8 v) (fun x -> sext8 (toI32 x))

let convU1 ins bld =
  conv ins bld SlotType.I4 (fun v _ -> zext8 v) (fun x -> zext8 (toI32 x))

let convI2 ins bld =
  conv ins bld SlotType.I4 (fun v _ -> sext16 v) (fun x -> sext16 (toI32 x))

let convU2 ins bld =
  conv ins bld SlotType.I4 (fun v _ -> zext16 v) (fun x -> zext16 (toI32 x))

let convI4 ins bld = conv ins bld SlotType.I4 (fun v _ -> sext32 v) toI32

/// conv.u4: the same bits as conv.i4 from an integer, the stack holding an
/// int32 either way.
let convU4 ins bld =
  conv ins bld SlotType.I4 (fun v _ -> sext32 v) (fun x -> sext32 (toU32 x))

/// conv.i8 and conv.i: the canonical int32 is its own sign-extension.
let private convSigned64 ins bld outTag =
  conv ins bld outTag (fun v _ -> v) toI64

let convI8 ins bld = convSigned64 ins bld SlotType.I8

let convI ins bld = convSigned64 ins bld SlotType.I

let private convUnsigned64 ins bld outTag =
  conv ins bld outTag asUnsigned toU64

let convU8 ins bld = convUnsigned64 ins bld SlotType.I8

let convU ins bld = convUnsigned64 ins bld SlotType.I

/// conv.r4: an integer is converted to a single directly, which rounds once;
/// a double is rounded to a single, and a single is left as it is -- the
/// conversion of it to a double and back would quiet a signaling NaN, which
/// the runtime's no-op does not.
let convR4 (ins: Instruction) bld =
  lift bld ins {
    let struct (v, t) = peek bld 0
    let ofInt = AST.zext 64<rt> (AST.cast CastKind.SIntToFloat 32<rt> v)
    let ofFloat = AST.zext 64<rt> (narrowF t v)
    let r = AST.ite (isF t) ofFloat ofInt
    writeSlot bld (slotAddr bld 0) r (tag SlotType.F4)
  }

let convR8 ins bld =
  let ofInt v _ = AST.cast CastKind.SIntToFloat 64<rt> v
  conv ins bld SlotType.F8 ofInt id

/// conv.r.un: the integer read as unsigned, to a double.
let convRUn ins bld =
  let ofInt v is32 = AST.cast CastKind.UIntToFloat 64<rt> (asUnsigned v is32)
  conv ins bld SlotType.F8 ofInt id

/// <summary>
/// The checked conversions, which raise where the value does not fit the type
/// converted to and otherwise convert as the unchecked ones do.
///
/// An integer's fit is a comparison against the bounds of the type, of the
/// slot word read as the source's signedness says. A double's fit is a
/// comparison against the bounds as doubles, open at both ends so that a value
/// truncating to the bound passes, a NaN failing every comparison.
/// </summary>
let private convOvf (ins: Instruction) bld outTag intOvf ofInt floatOvf ofF =
  lift bld ins {
    let struct (v, t) = peek bld 0
    let d = asDouble t v
    let ovf = AST.ite (isF t) (floatOvf d) (intOvf v (is32 t))
    raiseWhen bld "ConvOverflow" ovf CILException.Overflow
    let r = AST.ite (isF t) (ofF d) (ofInt v (is32 t))
    writeSlot bld (slotAddr bld 0) r (tag outTag)
  }

/// Whether a signed integer lies outside the given bounds.
let private outside lo hi v = (v ?< numI64 lo 64<rt>) .| (v ?> numI64 hi 64<rt>)

/// The overflow test of a signed integer source against the given bounds,
/// which is the same whatever the source's width.
let private intRange lo hi v _ = outside lo hi v

/// An integer converted as it is, which every checked conversion whose result
/// is as wide as the canonical form does.
let private keep v _ = v

/// An integer narrowed to a canonical int32.
let private narrow32 v _ = sext32 v

/// A double converted to a uint32 and put in canonical form.
let private toU32Canonical x = sext32 (toU32 x)

/// Whether a double is NaN or lies at or beyond either of the given bounds,
/// which are one past the range so that truncation to the range passes.
let private outsideF lo hi x =
  IEEE754Double.isNaN x .| AST.fle x (numF64 lo) .| AST.fge x (numF64 hi)

let convOvfI1 ins bld =
  let ovf = outsideF -129.0 128.0
  convOvf ins bld SlotType.I4 (intRange -128L 127L) keep ovf toI32

let convOvfU1 ins bld =
  let ovf = outsideF -1.0 256.0
  convOvf ins bld SlotType.I4 (intRange 0L 255L) keep ovf toI32

let convOvfI2 ins bld =
  let ovf = outsideF -32769.0 32768.0
  convOvf ins bld SlotType.I4 (intRange -32768L 32767L) keep ovf toI32

let convOvfU2 ins bld =
  let ovf = outsideF -1.0 65536.0
  convOvf ins bld SlotType.I4 (intRange 0L 65535L) keep ovf toI32

let convOvfI4 ins bld =
  let range = intRange -2147483648L 2147483647L
  let ovf = outsideF -2147483649.0 2147483648.0
  convOvf ins bld SlotType.I4 range narrow32 ovf toI32

let convOvfU4 ins bld =
  let range = intRange 0L 4294967295L
  let ovf = outsideF -1.0 4294967296.0
  convOvf ins bld SlotType.I4 range narrow32 ovf toU32Canonical

/// A signed 64-bit integer from a signed source never overflows; a double
/// does when it is at or past 2^63 in magnitude, the low bound being exact.
let private convOvfSigned64 ins bld outTag =
  let floatOvf x =
    IEEE754Double.isNaN x
    .| AST.flt x (numF64 -9223372036854775808.0)
    .| AST.fge x (numF64 9223372036854775808.0)
  convOvf ins bld outTag (fun _ _ -> AST.b0) (fun v _ -> v) floatOvf toI64

let convOvfI8 ins bld = convOvfSigned64 ins bld SlotType.I8

let convOvfI ins bld = convOvfSigned64 ins bld SlotType.I

let private convOvfUnsigned64 ins bld outTag =
  let negative v _ = v ?< AST.num0 64<rt>
  let ovf = outsideF -1.0 18446744073709551616.0
  convOvf ins bld outTag negative keep ovf toU64

let convOvfU8 ins bld = convOvfUnsigned64 ins bld SlotType.I8

let convOvfU ins bld = convOvfUnsigned64 ins bld SlotType.I

/// The .un forms, whose integer source is read as unsigned: it overflows when
/// it is above the type's maximum, and is otherwise already the result.
let private convOvfUn ins bld outTag (max: uint64) floatOvf ofF =
  let intOvf v is32 = asUnsigned v is32 .> numU64 max 64<rt>
  convOvf ins bld outTag intOvf asUnsigned floatOvf ofF

let convOvfI1Un ins bld =
  convOvfUn ins bld SlotType.I4 127UL (outsideF -129.0 128.0) toI32

let convOvfU1Un ins bld =
  convOvfUn ins bld SlotType.I4 255UL (outsideF -1.0 256.0) toI32

let convOvfI2Un ins bld =
  convOvfUn ins bld SlotType.I4 32767UL (outsideF -32769.0 32768.0) toI32

let convOvfU2Un ins bld =
  convOvfUn ins bld SlotType.I4 65535UL (outsideF -1.0 65536.0) toI32

let convOvfI4Un ins bld =
  let ovf = outsideF -2147483649.0 2147483648.0
  convOvfUn ins bld SlotType.I4 2147483647UL ovf toI32

/// conv.ovf.u4.un: the result is an int32 on the stack, so the unsigned value
/// that fits is put in canonical form.
let convOvfU4Un ins bld =
  let intOvf v is32 = asUnsigned v is32 .> numU64 4294967295UL 64<rt>
  let ofInt v is32 = sext32 (asUnsigned v is32)
  let ovf = outsideF -1.0 4294967296.0
  convOvf ins bld SlotType.I4 intOvf ofInt ovf toU32Canonical

let private convOvfSigned64Un ins bld outTag =
  let floatOvf x =
    IEEE754Double.isNaN x
    .| AST.flt x (numF64 -9223372036854775808.0)
    .| AST.fge x (numF64 9223372036854775808.0)
  convOvfUn ins bld outTag 0x7fffffffffffffffUL floatOvf toI64

let convOvfI8Un ins bld = convOvfSigned64Un ins bld SlotType.I8

let convOvfIUn ins bld = convOvfSigned64Un ins bld SlotType.I

let private convOvfUnsigned64Un ins bld outTag =
  let ovf = outsideF -1.0 18446744073709551616.0
  convOvfUn ins bld outTag System.UInt64.MaxValue ovf toU64

let convOvfU8Un ins bld = convOvfUnsigned64Un ins bld SlotType.I8

let convOvfUUn ins bld = convOvfUnsigned64Un ins bld SlotType.I

/// ckfinite: raises on a NaN or an infinity and otherwise leaves the value.
let ckfinite (ins: Instruction) bld =
  lift bld ins {
    let struct (v, t) = peek bld 0
    let d = asDouble t v
    let bad = IEEE754Double.isNaN d .| IEEE754Double.isInfinity d
    raiseWhen bld "NotFinite" bad CILException.Arithmetic
  }

/// <summary>
/// The comparisons and the conditional branches, which compare two slots as
/// floating-point numbers when they are that and as integers otherwise.
///
/// An integer comparison is done on the slot words, in 64 bits, whatever the
/// width of the operands: the canonical form of an int32 keeps both its signed
/// and its unsigned order, so a comparison of two of them comes out as the
/// 32-bit one would. The unordered forms of the floating-point comparisons are
/// the negations of the ordered ones they are named against: cgt.un holds
/// where a <= b does not, which is where a > b or either is a NaN.
/// </summary>
let private condition bld fcmp icmp =
  let struct (b, tb) = peek bld 0
  let struct (a, ta) = peek bld 1
  AST.ite (isF tb) (fcmp (asDouble ta a) (asDouble tb b)) (icmp a b)

let private compare (ins: Instruction) bld fcmp icmp =
  lift bld ins {
    let c = condition bld fcmp icmp
    replace bld 2 (AST.zext 64<rt> c) (tag SlotType.I4)
  }

let ceq ins bld = compare ins bld AST.feq AST.eq

let cgt ins bld = compare ins bld AST.fgt AST.sgt

let cgtUn ins bld = compare ins bld (fun a b -> AST.not (AST.fle a b)) AST.gt

let clt ins bld = compare ins bld AST.flt AST.slt

let cltUn ins bld = compare ins bld (fun a b -> AST.not (AST.fge a b)) AST.lt

/// Jumps to the instruction's target when the condition holds and to the
/// instruction after it otherwise.
let private jumpWhen ins bld cond =
  let target = numU64 (getTarget ins) 64<rt>
  let next = numU64 (nextAddr ins) 64<rt>
  append bld { AST.intercjmp cond target next }

let br (ins: Instruction) bld =
  lift bld ins {
    AST.interjmp (numU64 (getTarget ins) 64<rt>) InterJmpKind.Base
    return NoEndMark
  }

/// brtrue and brfalse, which test one slot: a non-zero integer, or a non-null
/// reference, is true.
let private branchOn (ins: Instruction) bld test =
  lift bld ins {
    let struct (v, _) = peek bld 0
    let c = tmpVar bld 1<rt>
    c := test v
    drop bld 1
    jumpWhen ins bld c
    return NoEndMark
  }

let brtrue ins bld = branchOn ins bld (fun v -> v != AST.num0 64<rt>)

let brfalse ins bld = branchOn ins bld (fun v -> v == AST.num0 64<rt>)

let private branchCmp (ins: Instruction) bld fcmp icmp =
  lift bld ins {
    let c = tmpVar bld 1<rt>
    c := condition bld fcmp icmp
    drop bld 2
    jumpWhen ins bld c
    return NoEndMark
  }

let beq ins bld = branchCmp ins bld AST.feq AST.eq

let bge ins bld = branchCmp ins bld AST.fge AST.sge

let bgt ins bld = branchCmp ins bld AST.fgt AST.sgt

let ble ins bld = branchCmp ins bld AST.fle AST.sle

let blt ins bld = branchCmp ins bld AST.flt AST.slt

let bneUn ins bld =
  branchCmp ins bld (fun a b -> AST.not (AST.feq a b)) AST.neq

let bgeUn ins bld =
  branchCmp ins bld (fun a b -> AST.not (AST.flt a b)) AST.ge

let bgtUn ins bld =
  branchCmp ins bld (fun a b -> AST.not (AST.fle a b)) AST.gt

let bleUn ins bld =
  branchCmp ins bld (fun a b -> AST.not (AST.fgt a b)) AST.le

let bltUn ins bld =
  branchCmp ins bld (fun a b -> AST.not (AST.fge a b)) AST.lt

/// <summary>
/// switch: the value is read as an unsigned 32-bit index into the table, and
/// an index at or past the end falls through to the next instruction.
///
/// Each entry is a test and a jump of its own, the jump ending the trace when
/// it is taken; the instruction ends the ordinary way where none is.
/// </summary>
let switch (ins: Instruction) bld =
  lift bld ins {
    let struct (v, _) = peek bld 0
    let idx = tmpVar bld 32<rt>
    idx := lo32 v
    drop bld 1
    getTargets ins
    |> List.iteri (fun i target ->
      let taken = numU64 target 64<rt>
      _when bld "Case" (idx == numI32 i 32<rt>) (block {
        AST.interjmp taken InterJmpKind.Base
      }))
  }

/// The loads through a pointer, which widen what they read to the kind the
/// stack keeps of the type in the opcode and replace the pointer with it.
let private ldind (ins: Instruction) bld size widen outTag =
  lift bld ins {
    let struct (addr, _) = peek bld 0
    let v = widen (AST.loadLE size addr)
    writeSlot bld (slotAddr bld 0) v (tag outTag)
  }

let ldindI1 ins bld = ldind ins bld 8<rt> (AST.sext 64<rt>) SlotType.I4

let ldindU1 ins bld = ldind ins bld 8<rt> (AST.zext 64<rt>) SlotType.I4

let ldindI2 ins bld = ldind ins bld 16<rt> (AST.sext 64<rt>) SlotType.I4

let ldindU2 ins bld = ldind ins bld 16<rt> (AST.zext 64<rt>) SlotType.I4

/// ldind.i4 and ldind.u4 read the same bits, the stack holding an int32
/// either way.
let ldindI4 ins bld = ldind ins bld 32<rt> (AST.sext 64<rt>) SlotType.I4

let ldindI8 ins bld = ldind ins bld 64<rt> id SlotType.I8

let ldindI ins bld = ldind ins bld 64<rt> id SlotType.I

let ldindR4 ins bld = ldind ins bld 32<rt> (AST.zext 64<rt>) SlotType.F4

let ldindR8 ins bld = ldind ins bld 64<rt> id SlotType.F8

let ldindRef ins bld = ldind ins bld 64<rt> id SlotType.O

/// The stores through a pointer, which narrow the value to the type in the
/// opcode, given the value and its tag. The stack is popped after the store,
/// so that a store which faults leaves the instruction ready to run again.
let private stind (ins: Instruction) bld narrow =
  lift bld ins {
    let struct (v, t) = peek bld 0
    let struct (addr, _) = peek bld 1
    AST.store Endian.Little addr (narrow v t)
    drop bld 2
  }

let stindI1 ins bld = stind ins bld (fun v _ -> lo8 v)

let stindI2 ins bld = stind ins bld (fun v _ -> lo16 v)

let stindI4 ins bld = stind ins bld (fun v _ -> lo32 v)

let stindI8 ins bld = stind ins bld (fun v _ -> v)

let stindI ins bld = stind ins bld (fun v _ -> v)

let stindRef ins bld = stind ins bld (fun v _ -> v)

/// stind.r4: a single as it is, a double as the single it rounds to.
let stindR4 ins bld = stind ins bld (fun v t -> narrowF t v)

/// stind.r8: a double as it is, a single as the double it widens to.
let stindR8 ins bld = stind ins bld (fun v t -> asDouble t v)

/// A byte count from the stack, which the block instructions take as an
/// unsigned 32-bit integer or a native unsigned int.
let private count bld =
  let struct (n, t) = peek bld 0
  let c = tmpVar bld 64<rt>
  append bld { c := AST.ite (is32 t) (zext32 n) n }
  c

/// cpblk: copies count bytes from the second pointer to the first, one byte at
/// a time, upwards; the blocks are not to overlap.
let cpblk (ins: Instruction) bld =
  lift bld ins {
    let n = count bld
    let struct (src, _) = peek bld 1
    let struct (dst, _) = peek bld 2
    let i = tmpVar bld 64<rt>
    i := AST.num0 64<rt>
    _while bld "Cpblk" (i .< n) (block {
      AST.store Endian.Little (dst .+ i) (AST.loadLE 8<rt> (src .+ i))
      i := i .+ num64 1
    })
    drop bld 3
  }

/// initblk: fills count bytes at the pointer with the low byte of the value.
let initblk (ins: Instruction) bld =
  lift bld ins {
    let n = count bld
    let struct (v, _) = peek bld 1
    let struct (dst, _) = peek bld 2
    let i = tmpVar bld 64<rt>
    i := AST.num0 64<rt>
    _while bld "Initblk" (i .< n) (block {
      AST.store Endian.Little (dst .+ i) (lo8 v)
      i := i .+ num64 1
    })
    drop bld 3
  }

/// <summary>
/// localloc: a block of the given size, zeroed as a method with its locals
/// initialized has it, whose address replaces the size on the stack.
///
/// The block is carved out of the evaluation stack, which the instruction is
/// specified to find empty apart from the size: it goes below the slot the
/// size was in, rounded up to whole slots, and the address goes into a slot
/// below it, so that everything pushed afterwards lands under the block and
/// nothing popped ever reaches it. The runtime reclaims it with the frame.
/// </summary>
let localloc (ins: Instruction) bld =
  lift bld ins {
    let n = count bld
    let size = tmpVar bld 64<rt>
    size := (n .+ num64 (Slot.Size - 1)) .& num64 -Slot.Size
    let top = tmpVar bld 64<rt>
    top := sp bld .- size
    let i = tmpVar bld 64<rt>
    i := top
    _while bld "Localloc" (i .< sp bld) (block {
      AST.store Endian.Little i (AST.num0 64<rt>)
      i := i .+ num64 8
    })
    let s = tmpVar bld 64<rt>
    s := top .- num64 Slot.Size
    writeSlot bld s top (tag SlotType.I)
    sp bld := s
  }

// vim: set tw=80 sts=2 sw=2:

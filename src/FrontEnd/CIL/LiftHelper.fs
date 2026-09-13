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
/// Provides the pieces every CIL lifter shares: the slots the evaluation stack,
/// the arguments and the local variables are kept in, the tags that say what
/// a slot holds, and the conversions the machine defines between its types.
module internal B2R2.FrontEnd.CIL.LiftHelper

open System
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils

/// A quadword constant, which is the width of every slot word and register.
let inline num64 (n: int) = numI32 n 64<rt>

/// The bits of a double, as a quadword constant.
let numF64 (v: float) = numU64 (BitConverter.DoubleToUInt64Bits v) 64<rt>

/// A slot type, as the tag word a slot carries.
let tag (t: SlotType) = num64 (int t)

/// Returns the one operand of an instruction that has one.
let getOneOpr (ins: Instruction) =
  match ins.Operands with
  | OneOperand o -> o
  | _ -> raise InvalidOperandException

/// Returns the variable index an instruction carries.
let getVar ins =
  match getOneOpr ins with
  | OprVar i -> int i
  | _ -> raise InvalidOperandException

/// Returns the 32-bit constant an instruction carries.
let getI4 ins =
  match getOneOpr ins with
  | OprI4 v -> v
  | _ -> raise InvalidOperandException

/// Returns the 64-bit constant an instruction carries.
let getI8 ins =
  match getOneOpr ins with
  | OprI8 v -> v
  | _ -> raise InvalidOperandException

/// Returns the single-precision constant an instruction carries.
let getR4 ins =
  match getOneOpr ins with
  | OprR4 v -> v
  | _ -> raise InvalidOperandException

/// Returns the double-precision constant an instruction carries.
let getR8 ins =
  match getOneOpr ins with
  | OprR8 v -> v
  | _ -> raise InvalidOperandException

/// Returns the address a branch reaches.
let getTarget ins =
  match getOneOpr ins with
  | OprTarget t -> t
  | _ -> raise InvalidOperandException

/// Returns the addresses a switch may reach.
let getTargets ins =
  match getOneOpr ins with
  | OprTargets ts -> ts
  | _ -> raise InvalidOperandException

/// Returns the metadata token an instruction carries.
let getToken ins =
  match getOneOpr ins with
  | OprToken t -> t
  | _ -> raise InvalidOperandException

/// The address of the instruction after this one, which is where a branch not
/// taken goes and what a call comes back to.
let nextAddr (ins: Instruction) = ins.Address + uint64 ins.Length

/// The stack pointer: the address of the slot on top of the evaluation stack.
let sp bld = regVar bld Register.SP

/// The frame pointer: the address of the slot of local variable 0.
let fp bld = regVar bld Register.FP

/// The argument pointer: the address of the slot of argument 0.
let ap bld = regVar bld Register.AP

/// The address of the slot n below the top of the evaluation stack; n = 0 is
/// the top itself.
let slotAddr bld n = sp bld .+ num64 (n * Slot.Size)

/// The address of the slot of variable n, counted down from the slot of
/// variable 0 at the given origin.
let varAddr origin n = origin .- num64 (n * Slot.Size)

/// The value word of the slot at the given address.
let loadValue addr = AST.loadLE 64<rt> addr

/// The tag word of the slot at the given address.
let loadTag addr = AST.loadLE 64<rt> (addr .+ num64 Slot.TagOffset)

/// Reads the slot at the given address into two temporaries: the value and the
/// tag.
let readSlot bld addr =
  let struct (v, t) = tmpVars2 bld 64<rt>
  append bld {
    v := loadValue addr
    t := loadTag addr
  }
  struct (v, t)

/// Reads the slot n below the top of the evaluation stack into temporaries,
/// leaving the stack as it is.
let peek bld n = readSlot bld (slotAddr bld n)

/// Writes the slot at the given address.
let writeSlot bld addr v t =
  append bld {
    AST.store Endian.Little addr v
    AST.store Endian.Little (addr .+ num64 Slot.TagOffset) t
  }

/// Drops n slots from the evaluation stack.
let drop bld n =
  if n > 0 then append bld { sp bld := sp bld .+ num64 (n * Slot.Size) }
  else ()

/// <summary>
/// Pushes a slot onto the evaluation stack.
///
/// The stack pointer is written last, after both stores, so that a store that
/// faults leaves the stack as the instruction found it and the instruction can
/// be run again from its start.
/// </summary>
let push bld v t =
  let s = tmpVar bld 64<rt>
  append bld { s := sp bld .- num64 Slot.Size }
  writeSlot bld s v t
  append bld { sp bld := s }

/// <summary>
/// Pops n slots from the evaluation stack and pushes one, which is what nearly
/// every computing instruction does.
///
/// The pushed slot takes the place of the deepest of those popped, so nothing
/// moves and the stack pointer is written once, after the stores.
/// </summary>
let replace bld n v t =
  if n = 0 then
    push bld v t
  else
    writeSlot bld (slotAddr bld (n - 1)) v t
    drop bld (n - 1)

/// Whether a tag says a slot holds a floating-point number.
let isF t = (t == tag SlotType.F4) .| (t == tag SlotType.F8)

/// Whether a tag says a slot holds a floating-point number of single
/// precision.
let isF4 t = t == tag SlotType.F4

/// Whether a tag says a slot holds a 32-bit integer.
let is32 t = t == tag SlotType.I4

/// <summary>
/// The tag of the result of a binary numeric instruction, given the tags of
/// its two operands (ECMA-335 III.1.5, tables 2 to 5).
///
/// It is the greater of the two: an int32 with a native int is a native int, a
/// managed pointer with either is a managed pointer, and a single with a
/// double is a double. Every pair the tables allow works out this way, which is
/// what the order of the SlotType values was chosen for.
/// </summary>
let maxTag a b = AST.ite (a .> b) a b

let lo8 v = AST.xtlo 8<rt> v

let lo16 v = AST.xtlo 16<rt> v

let lo32 v = AST.xtlo 32<rt> v

let sext8 v = AST.sext 64<rt> (lo8 v)

let zext8 v = AST.zext 64<rt> (lo8 v)

let sext16 v = AST.sext 64<rt> (lo16 v)

let zext16 v = AST.zext 64<rt> (lo16 v)

/// The canonical form of an int32 on the stack: its low 32 bits, sign-extended
/// to the slot word.
let sext32 v = AST.sext 64<rt> (lo32 v)

let zext32 v = AST.zext 64<rt> (lo32 v)

/// The single-precision bits of a double, rounded to nearest.
let toSingle v = AST.cast CastKind.FloatCast 32<rt> v

/// The double a single's bits stand for, which is exact.
let ofSingle e = AST.cast CastKind.FloatCast 64<rt> e

/// The double a floating-point slot holds: an F8 as it is, an F4 widened
/// from the single bits in its low half.
let asDouble t v = AST.ite (isF4 t) (ofSingle (lo32 v)) v

/// The single bits a floating-point slot narrows to: an F4's own, an F8
/// rounded to nearest.
let narrowF t v = AST.ite (isF4 t) (lo32 v) (toSingle v)

/// <summary>
/// The result of a floating-point instruction computed in double precision,
/// given the tag of the result.
///
/// Two singles compute in single precision, which the runtime does with a
/// single-precision instruction and this does by rounding the double result:
/// a double holds more than twice the bits of a single, so rounding the exact
/// sum, difference, product or quotient of two singles to a double and then to
/// a single lands where rounding it to a single once would have.
/// </summary>
let floatResult t r = AST.ite (isF4 t) (AST.zext 64<rt> (toSingle r)) r

/// Raises an exception of the machine's own, by naming it to the runtime.
let raiseException bld (e: CILException) =
  append bld { AST.extCall (AST.app "raise" [ num64 (int e) ] 64<rt>) }

/// Raises an exception of the machine's own when the condition holds.
let raiseWhen bld name cond (e: CILException) =
  _when bld name cond (block {
    AST.extCall (AST.app "raise" [ num64 (int e) ] 64<rt>)
  })

/// <summary>
/// Saturates a conversion of a double to an integer: NaN to zero, and anything
/// at or past a bound to the bound's value. This is what the runtime has done
/// on every platform since .NET 9, and what the C-like "unspecified" of
/// ECMA-335 III.3.27 leaves room for.
/// </summary>
let private saturate x lo loValue hi hiValue conv =
  let inRange = AST.ite (AST.fle x lo) loValue conv
  let bounded = AST.ite (AST.fge x hi) hiValue inRange
  AST.ite (IEEE754Double.isNaN x) (AST.num0 64<rt>) bounded

/// A double truncated toward zero to a 64-bit integer, whose value is known to
/// fit.
let private trunc64 x = AST.cast CastKind.FtoITrunc 64<rt> x

/// A double converted to an int32, saturating, in canonical form.
let toI32 x =
  let lo = numF64 -2147483648.0
  let hi = numF64 2147483648.0
  let conv = AST.sext 64<rt> (AST.cast CastKind.FtoITrunc 32<rt> x)
  saturate x lo (numI64 -2147483648L 64<rt>) hi (num64 0x7fffffff) conv

/// A double converted to a uint32, saturating, in canonical form.
let toU32 x =
  let hi = numF64 4294967296.0
  let conv = sext32 (trunc64 x)
  saturate x (numF64 0.0) (AST.num0 64<rt>) hi (numI64 -1L 64<rt>) conv

/// A double converted to an int64, saturating.
let toI64 x =
  let lo = numF64 -9223372036854775808.0
  let hi = numF64 9223372036854775808.0
  let minValue = numI64 Int64.MinValue 64<rt>
  saturate x lo minValue hi (numI64 Int64.MaxValue 64<rt>) (trunc64 x)

/// <summary>
/// A double converted to a uint64, saturating.
///
/// The truncating cast is a signed one, so a value from 2^63 up is brought
/// below that first and the difference is added back afterwards, which is
/// exact: both are doubles between 2^63 and 2^64, so their difference is.
/// </summary>
let toU64 x =
  let two63 = numF64 9223372036854775808.0
  let high = trunc64 (AST.fsub x two63) .+ numU64 (1UL <<< 63) 64<rt>
  let hi = numF64 18446744073709551616.0
  let conv = AST.ite (AST.fge x two63) high (trunc64 x)
  saturate x (numF64 0.0) (AST.num0 64<rt>) hi (numI64 -1L 64<rt>) conv

// vim: set tw=80 sts=2 sw=2:

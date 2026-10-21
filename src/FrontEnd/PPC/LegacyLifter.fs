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
/// Lifts the instructions of the Power ISA 2.07B categories that 3.1 no
/// longer has. Lifter hands this module every opcode it says it lifts.
/// </summary>
module internal B2R2.FrontEnd.PPC.LegacyLifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils

/// Which halfwords of rA and rB a legacy multiply takes: bits 48:63 of rA
/// and 32:47 of rB (cross), 32:47 of both (high), or 48:63 of both (low).
type private Halves =
  | Cross
  | High
  | Low

/// What a legacy multiply does with the product of the two halfwords.
type private Product =
  /// Writes it to rT, the halfwords read as signed or as unsigned numbers.
  | Multiply of signed: bool
  /// Adds it to rT's low word, the sum wrapping at 32 bits. The signedness
  /// says how the halfwords and the word are read, and so what counts as an
  /// overflow.
  | Accumulate of signed: bool
  /// The same, a sum that does not fit pinned to the nearest value that does.
  | AccumulateSaturate of signed: bool
  /// Subtracts it from rT's low word, everything signed.
  | Subtract
  /// The same, a difference that does not fit pinned as above.
  | SubtractSaturate

/// <summary>
/// The Legacy Integer Multiply-Accumulate instructions, each as the
/// halfwords it takes, what it does with their product, whether it records
/// an overflow in OV and SO (OE), and whether it records CR0 (Rc).
/// </summary>
let private multiplyOf = function
  | Op.MACCHW -> ValueSome(Cross, Accumulate true, false, false)
  | Op.MACCHWdot -> ValueSome(Cross, Accumulate true, false, true)
  | Op.MACCHWO -> ValueSome(Cross, Accumulate true, true, false)
  | Op.MACCHWOdot -> ValueSome(Cross, Accumulate true, true, true)
  | Op.MACCHWS -> ValueSome(Cross, AccumulateSaturate true, false, false)
  | Op.MACCHWSdot -> ValueSome(Cross, AccumulateSaturate true, false, true)
  | Op.MACCHWSO -> ValueSome(Cross, AccumulateSaturate true, true, false)
  | Op.MACCHWSOdot -> ValueSome(Cross, AccumulateSaturate true, true, true)
  | Op.MACCHWSU -> ValueSome(Cross, AccumulateSaturate false, false, false)
  | Op.MACCHWSUdot -> ValueSome(Cross, AccumulateSaturate false, false, true)
  | Op.MACCHWSUO -> ValueSome(Cross, AccumulateSaturate false, true, false)
  | Op.MACCHWSUOdot -> ValueSome(Cross, AccumulateSaturate false, true, true)
  | Op.MACCHWU -> ValueSome(Cross, Accumulate false, false, false)
  | Op.MACCHWUdot -> ValueSome(Cross, Accumulate false, false, true)
  | Op.MACCHWUO -> ValueSome(Cross, Accumulate false, true, false)
  | Op.MACCHWUOdot -> ValueSome(Cross, Accumulate false, true, true)
  | Op.NMACCHW -> ValueSome(Cross, Subtract, false, false)
  | Op.NMACCHWdot -> ValueSome(Cross, Subtract, false, true)
  | Op.NMACCHWO -> ValueSome(Cross, Subtract, true, false)
  | Op.NMACCHWOdot -> ValueSome(Cross, Subtract, true, true)
  | Op.NMACCHWS -> ValueSome(Cross, SubtractSaturate, false, false)
  | Op.NMACCHWSdot -> ValueSome(Cross, SubtractSaturate, false, true)
  | Op.NMACCHWSO -> ValueSome(Cross, SubtractSaturate, true, false)
  | Op.NMACCHWSOdot -> ValueSome(Cross, SubtractSaturate, true, true)
  | Op.MULCHW -> ValueSome(Cross, Multiply true, false, false)
  | Op.MULCHWdot -> ValueSome(Cross, Multiply true, false, true)
  | Op.MULCHWU -> ValueSome(Cross, Multiply false, false, false)
  | Op.MULCHWUdot -> ValueSome(Cross, Multiply false, false, true)
  | Op.MACHHW -> ValueSome(High, Accumulate true, false, false)
  | Op.MACHHWdot -> ValueSome(High, Accumulate true, false, true)
  | Op.MACHHWO -> ValueSome(High, Accumulate true, true, false)
  | Op.MACHHWOdot -> ValueSome(High, Accumulate true, true, true)
  | Op.MACHHWS -> ValueSome(High, AccumulateSaturate true, false, false)
  | Op.MACHHWSdot -> ValueSome(High, AccumulateSaturate true, false, true)
  | Op.MACHHWSO -> ValueSome(High, AccumulateSaturate true, true, false)
  | Op.MACHHWSOdot -> ValueSome(High, AccumulateSaturate true, true, true)
  | Op.MACHHWSU -> ValueSome(High, AccumulateSaturate false, false, false)
  | Op.MACHHWSUdot -> ValueSome(High, AccumulateSaturate false, false, true)
  | Op.MACHHWSUO -> ValueSome(High, AccumulateSaturate false, true, false)
  | Op.MACHHWSUOdot -> ValueSome(High, AccumulateSaturate false, true, true)
  | Op.MACHHWU -> ValueSome(High, Accumulate false, false, false)
  | Op.MACHHWUdot -> ValueSome(High, Accumulate false, false, true)
  | Op.MACHHWUO -> ValueSome(High, Accumulate false, true, false)
  | Op.MACHHWUOdot -> ValueSome(High, Accumulate false, true, true)
  | Op.NMACHHW -> ValueSome(High, Subtract, false, false)
  | Op.NMACHHWdot -> ValueSome(High, Subtract, false, true)
  | Op.NMACHHWO -> ValueSome(High, Subtract, true, false)
  | Op.NMACHHWOdot -> ValueSome(High, Subtract, true, true)
  | Op.NMACHHWS -> ValueSome(High, SubtractSaturate, false, false)
  | Op.NMACHHWSdot -> ValueSome(High, SubtractSaturate, false, true)
  | Op.NMACHHWSO -> ValueSome(High, SubtractSaturate, true, false)
  | Op.NMACHHWSOdot -> ValueSome(High, SubtractSaturate, true, true)
  | Op.MULHHW -> ValueSome(High, Multiply true, false, false)
  | Op.MULHHWdot -> ValueSome(High, Multiply true, false, true)
  | Op.MULHHWU -> ValueSome(High, Multiply false, false, false)
  | Op.MULHHWUdot -> ValueSome(High, Multiply false, false, true)
  | Op.MACLHW -> ValueSome(Low, Accumulate true, false, false)
  | Op.MACLHWdot -> ValueSome(Low, Accumulate true, false, true)
  | Op.MACLHWO -> ValueSome(Low, Accumulate true, true, false)
  | Op.MACLHWOdot -> ValueSome(Low, Accumulate true, true, true)
  | Op.MACLHWS -> ValueSome(Low, AccumulateSaturate true, false, false)
  | Op.MACLHWSdot -> ValueSome(Low, AccumulateSaturate true, false, true)
  | Op.MACLHWSO -> ValueSome(Low, AccumulateSaturate true, true, false)
  | Op.MACLHWSOdot -> ValueSome(Low, AccumulateSaturate true, true, true)
  | Op.MACLHWSU -> ValueSome(Low, AccumulateSaturate false, false, false)
  | Op.MACLHWSUdot -> ValueSome(Low, AccumulateSaturate false, false, true)
  | Op.MACLHWSUO -> ValueSome(Low, AccumulateSaturate false, true, false)
  | Op.MACLHWSUOdot -> ValueSome(Low, AccumulateSaturate false, true, true)
  | Op.MACLHWU -> ValueSome(Low, Accumulate false, false, false)
  | Op.MACLHWUdot -> ValueSome(Low, Accumulate false, false, true)
  | Op.MACLHWUO -> ValueSome(Low, Accumulate false, true, false)
  | Op.MACLHWUOdot -> ValueSome(Low, Accumulate false, true, true)
  | Op.NMACLHW -> ValueSome(Low, Subtract, false, false)
  | Op.NMACLHWdot -> ValueSome(Low, Subtract, false, true)
  | Op.NMACLHWO -> ValueSome(Low, Subtract, true, false)
  | Op.NMACLHWOdot -> ValueSome(Low, Subtract, true, true)
  | Op.NMACLHWS -> ValueSome(Low, SubtractSaturate, false, false)
  | Op.NMACLHWSdot -> ValueSome(Low, SubtractSaturate, false, true)
  | Op.NMACLHWSO -> ValueSome(Low, SubtractSaturate, true, false)
  | Op.NMACLHWSOdot -> ValueSome(Low, SubtractSaturate, true, true)
  | Op.MULLHW -> ValueSome(Low, Multiply true, false, false)
  | Op.MULLHWdot -> ValueSome(Low, Multiply true, false, true)
  | Op.MULLHWU -> ValueSome(Low, Multiply false, false, false)
  | Op.MULLHWUdot -> ValueSome(Low, Multiply false, false, true)
  | _ -> ValueNone

/// A halfword of a register, bits 32:47 when high and 48:63 otherwise,
/// widened to 64 bits as a signed or an unsigned number.
let private halfword signed high reg =
  let half = AST.extract reg 16<rt> (if high then 16 else 0)
  if signed then AST.sext 64<rt> half else AST.zext 64<rt> half

/// The two halfwords a legacy multiply takes from rA and rB.
let private factors halves signed ra rb =
  match halves with
  | Cross -> halfword signed false ra, halfword signed true rb
  | High -> halfword signed true ra, halfword signed true rb
  | Low -> halfword signed false ra, halfword signed false rb

/// Whether a product reads its halfwords as signed numbers.
let private isSigned = function
  | Multiply signed | Accumulate signed | AccumulateSaturate signed -> signed
  | Subtract | SubtractSaturate -> true

/// rT's low word widened to 64 bits, plus or minus the product.
let private accumulated product signed (rt: Expr) prod =
  let word = AST.xtlo 32<rt> rt
  let acc = if signed then AST.sext 64<rt> word else AST.zext 64<rt> word
  match product with
  | Subtract | SubtractSaturate -> acc .- prod
  | Multiply _ | Accumulate _ | AccumulateSaturate _ -> acc .+ prod

/// Whether a 64-bit sum does not fit a word read as signed or unsigned.
let private overflows signed sum =
  if signed then sum != AST.sext 64<rt> (AST.xtlo 32<rt> sum)
  else AST.xthi 32<rt> sum != AST.num0 32<rt>

/// The word a saturating sum that does not fit is pinned to: the signed
/// limit on the side the sum fell, or the unsigned maximum.
let private saturated signed sum =
  if signed then
    let least = numU32 0x80000000u 32<rt>
    let greatest = numU32 0x7fffffffu 32<rt>
    AST.ite (sum ?< AST.num0 64<rt>) least greatest
  else
    numU32 0xffffffffu 32<rt>

/// The word a legacy multiply writes into rT's low word, and whether its sum
/// overflowed (never, for a plain multiply).
let private result bld product signed rt prod =
  match product with
  | Multiply _ ->
    AST.xtlo 32<rt> prod, AST.b0
  | Accumulate _ | Subtract ->
    let sum = tmpVar bld 64<rt>
    append bld { sum := accumulated product signed rt prod }
    AST.xtlo 32<rt> sum, overflows signed sum
  | AccumulateSaturate _ | SubtractSaturate ->
    let sum = tmpVar bld 64<rt>
    append bld { sum := accumulated product signed rt prod }
    let over = overflows signed sum
    AST.ite over (saturated signed sum) (AST.xtlo 32<rt> sum), over

/// Records an overflow in XER: OV says whether there was one, and SO keeps
/// it once there has been.
let private recordOverflow bld over =
  append bld {
    let xer = regVar bld Register.XER
    AST.extract xer 1<rt> 30 := over
    AST.extract xer 1<rt> 31 := over .| AST.extract xer 1<rt> 31
  }

/// <summary>
/// Lifts a legacy multiply. The word it computes goes into bits 32:63 of
/// rT; the manual leaves bits 0:31 undefined, and the word is sign-extended
/// into them, so that CR0, which the manual sets from the 32-bit result, is
/// what comparing the whole register with zero gives on either word size.
/// </summary>
let private multiply (ins: Instruction) bld (halves, product, oe, rc) =
  lift bld ins {
    let struct (rt, ra, rb) = transThreeOprs ins bld
    let signed = isSigned product
    let a, b = factors halves signed ra rb
    let prod = tmpVar bld 64<rt>
    let word = tmpVar bld 32<rt>
    let over = tmpVar bld 1<rt>
    prod := a .* b
    let value, overflow = result bld product signed rt prod
    word := value
    over := overflow
    rt := AST.sext bld.RegType word
    if oe then recordOverflow bld over else ()
    if rc then setCR0Reg bld rt else ()
  }

/// Whether this module lifts the opcode.
let lifts op = (multiplyOf op).IsSome

/// Lifts an instruction whose opcode this module lifts.
let translate (ins: Instruction) bld =
  match multiplyOf ins.Opcode with
  | ValueSome spec -> multiply ins bld spec
  | ValueNone -> raise InvalidOpcodeException

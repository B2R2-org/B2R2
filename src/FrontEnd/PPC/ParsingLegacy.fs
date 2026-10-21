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
/// Decodes the instructions of the Power ISA 2.07B categories that 3.1 no
/// longer has, and the encodings whose reading the categories of a processor
/// decide (see Category). ParsingMain hands a word here first; a word this
/// module does not take goes on to ParsingMain's own decoder.
/// </summary>
module internal B2R2.FrontEnd.PPC.ParsingLegacy

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils
open B2R2.FrontEnd.PPC.OperandHelper

/// The three general registers of an X- or XO-form, in the order the fields
/// hold them: rT (or rS), rA, rB.
let private threeRegisters bin =
  let rt = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  ThreeOperands(rt, ra, rb)

/// The halfword multiplies, by the ten-bit extended opcode of their X-form,
/// each with the name that records CR0 after the one that does not.
let private multiplies = function
  | 8u -> ValueSome [| Op.MULHHWU; Op.MULHHWUdot |]
  | 40u -> ValueSome [| Op.MULHHW; Op.MULHHWdot |]
  | 136u -> ValueSome [| Op.MULCHWU; Op.MULCHWUdot |]
  | 168u -> ValueSome [| Op.MULCHW; Op.MULCHWdot |]
  | 392u -> ValueSome [| Op.MULLHWU; Op.MULLHWUdot |]
  | 424u -> ValueSome [| Op.MULLHW; Op.MULLHWdot |]
  | _ -> ValueNone

/// The multiply-accumulates, by the nine-bit extended opcode their XO-form
/// keeps below OE, each as its four names: plain, recording CR0, recording
/// OV, and recording both.
let private accumulates = function
  | 12u ->
    [| Op.MACHHWU; Op.MACHHWUdot; Op.MACHHWUO; Op.MACHHWUOdot |]
  | 44u ->
    [| Op.MACHHW; Op.MACHHWdot; Op.MACHHWO; Op.MACHHWOdot |]
  | 46u ->
    [| Op.NMACHHW; Op.NMACHHWdot; Op.NMACHHWO; Op.NMACHHWOdot |]
  | 76u ->
    [| Op.MACHHWSU; Op.MACHHWSUdot; Op.MACHHWSUO; Op.MACHHWSUOdot |]
  | 108u ->
    [| Op.MACHHWS; Op.MACHHWSdot; Op.MACHHWSO; Op.MACHHWSOdot |]
  | 110u ->
    [| Op.NMACHHWS; Op.NMACHHWSdot; Op.NMACHHWSO; Op.NMACHHWSOdot |]
  | 140u ->
    [| Op.MACCHWU; Op.MACCHWUdot; Op.MACCHWUO; Op.MACCHWUOdot |]
  | 172u ->
    [| Op.MACCHW; Op.MACCHWdot; Op.MACCHWO; Op.MACCHWOdot |]
  | 174u ->
    [| Op.NMACCHW; Op.NMACCHWdot; Op.NMACCHWO; Op.NMACCHWOdot |]
  | 204u ->
    [| Op.MACCHWSU; Op.MACCHWSUdot; Op.MACCHWSUO; Op.MACCHWSUOdot |]
  | 236u ->
    [| Op.MACCHWS; Op.MACCHWSdot; Op.MACCHWSO; Op.MACCHWSOdot |]
  | 238u ->
    [| Op.NMACCHWS; Op.NMACCHWSdot; Op.NMACCHWSO; Op.NMACCHWSOdot |]
  | 396u ->
    [| Op.MACLHWU; Op.MACLHWUdot; Op.MACLHWUO; Op.MACLHWUOdot |]
  | 428u ->
    [| Op.MACLHW; Op.MACLHWdot; Op.MACLHWO; Op.MACLHWOdot |]
  | 430u ->
    [| Op.NMACLHW; Op.NMACLHWdot; Op.NMACLHWO; Op.NMACLHWOdot |]
  | 460u ->
    [| Op.MACLHWSU; Op.MACLHWSUdot; Op.MACLHWSUO; Op.MACLHWSUOdot |]
  | 492u ->
    [| Op.MACLHWS; Op.MACLHWSdot; Op.MACLHWSO; Op.MACLHWSOdot |]
  | 494u ->
    [| Op.NMACLHWS; Op.NMACLHWSdot; Op.NMACLHWSO; Op.NMACLHWSOdot |]
  | _ ->
    raise ParsingFailureException

/// <summary>
/// Primary opcode 4 on a processor with the Legacy Integer
/// Multiply-Accumulate category, which has no vector facility to share it
/// with. A multiply is an X-form whose bit 21 is part of its extended opcode;
/// a multiply-accumulate is an XO-form whose bit 21 is OE.
/// </summary>
let private parseLegacyMultiply bin =
  match multiplies (Bits.extract bin 10u 1u) with
  | ValueSome ops ->
    struct (ops[int (Bits.pick bin 0u)], threeRegisters bin)
  | ValueNone ->
    let ops = accumulates (Bits.extract bin 9u 1u)
    let form = Bits.pick bin 10u * 2u + Bits.pick bin 0u
    struct (ops[int form], threeRegisters bin)

/// Whether the categories give primary opcode 4 to the Legacy Integer
/// Multiply-Accumulate instructions.
let private hasLegacyMultiply category =
  Category.includes Category.LegacyIntegerMultiplyAccumulate category

/// The instruction a word is, if it is one this module takes on a processor
/// implementing the categories given.
let tryParse category bin =
  match bin >>> 26 with
  | 4u when hasLegacyMultiply category ->
    ValueSome(parseLegacyMultiply bin)
  | _ ->
    ValueNone

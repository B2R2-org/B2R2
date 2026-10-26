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
/// Encodes the instructions of the Power ISA 2.07B categories that 3.1 no
/// longer has. Several of them share an encoding with an instruction of
/// another category, which only the decoder has to tell apart: an encoder is
/// found by its opcode, and no two opcodes share one.
/// </summary>
module internal B2R2.Assembly.PPC.AsmLegacy

open B2R2.FrontEnd.PPC
open B2R2.Assembly.PPC.ParserHelper
open B2R2.Assembly.PPC.AsmField

/// An "rT, rA, rB" in primary opcode 4, its eleven low bits given whole.
let private rtab rest ins =
  match ins.Operands with
  | [ Rg t; Rg a; Rg b ] -> word 4u (gpr t) (gpr a) (gpr b) rest
  | _ -> wrongOperands ins

/// The two names of a halfword multiply, an X-form whose ten-bit extended
/// opcode is given.
let private multiply xo plain dot =
  [ plain, rtab (xo <<< 1); dot, rtab ((xo <<< 1) ||| 1u) ]

/// The four names of a multiply-accumulate, an XO-form whose nine-bit
/// extended opcode is given: OE sits above it and Rc below.
let private accumulate xo (plain, dot) (ovf, ovfDot) =
  [ plain, rtab (xo <<< 1)
    dot, rtab ((xo <<< 1) ||| 1u)
    ovf, rtab (0x400u ||| (xo <<< 1))
    ovfDot, rtab (0x400u ||| (xo <<< 1) ||| 1u) ]

/// The Legacy Integer Multiply-Accumulate instructions.
let private multiplyAccumulateEncoders () =
  List.concat
    [ multiply 8u Op.MULHHWU Op.MULHHWUdot
      multiply 40u Op.MULHHW Op.MULHHWdot
      multiply 136u Op.MULCHWU Op.MULCHWUdot
      multiply 168u Op.MULCHW Op.MULCHWdot
      multiply 392u Op.MULLHWU Op.MULLHWUdot
      multiply 424u Op.MULLHW Op.MULLHWdot
      accumulate 12u (Op.MACHHWU, Op.MACHHWUdot) (Op.MACHHWUO, Op.MACHHWUOdot)
      accumulate 44u (Op.MACHHW, Op.MACHHWdot) (Op.MACHHWO, Op.MACHHWOdot)
      accumulate 46u (Op.NMACHHW, Op.NMACHHWdot) (Op.NMACHHWO, Op.NMACHHWOdot)
      accumulate 76u
        (Op.MACHHWSU, Op.MACHHWSUdot) (Op.MACHHWSUO, Op.MACHHWSUOdot)
      accumulate 108u
        (Op.MACHHWS, Op.MACHHWSdot) (Op.MACHHWSO, Op.MACHHWSOdot)
      accumulate 110u
        (Op.NMACHHWS, Op.NMACHHWSdot) (Op.NMACHHWSO, Op.NMACHHWSOdot)
      accumulate 140u
        (Op.MACCHWU, Op.MACCHWUdot) (Op.MACCHWUO, Op.MACCHWUOdot)
      accumulate 172u (Op.MACCHW, Op.MACCHWdot) (Op.MACCHWO, Op.MACCHWOdot)
      accumulate 174u
        (Op.NMACCHW, Op.NMACCHWdot) (Op.NMACCHWO, Op.NMACCHWOdot)
      accumulate 204u
        (Op.MACCHWSU, Op.MACCHWSUdot) (Op.MACCHWSUO, Op.MACCHWSUOdot)
      accumulate 236u
        (Op.MACCHWS, Op.MACCHWSdot) (Op.MACCHWSO, Op.MACCHWSOdot)
      accumulate 238u
        (Op.NMACCHWS, Op.NMACCHWSdot) (Op.NMACCHWSO, Op.NMACCHWSOdot)
      accumulate 396u
        (Op.MACLHWU, Op.MACLHWUdot) (Op.MACLHWUO, Op.MACLHWUOdot)
      accumulate 428u (Op.MACLHW, Op.MACLHWdot) (Op.MACLHWO, Op.MACLHWOdot)
      accumulate 430u
        (Op.NMACLHW, Op.NMACLHWdot) (Op.NMACLHWO, Op.NMACLHWOdot)
      accumulate 460u
        (Op.MACLHWSU, Op.MACLHWSUdot) (Op.MACLHWSUO, Op.MACLHWSUOdot)
      accumulate 492u
        (Op.MACLHWS, Op.MACLHWSdot) (Op.MACLHWSO, Op.MACLHWSOdot)
      accumulate 494u
        (Op.NMACLHWS, Op.NMACLHWSdot) (Op.NMACLHWSO, Op.NMACLHWSOdot) ]

/// An "rA, rS, rB" in primary opcode 31, its eleven low bits given whole.
let private rasb rest ins =
  match ins.Operands with
  | [ Rg a; Rg s; Rg b ] -> word 31u (gpr s) (gpr a) (gpr b) rest
  | _ -> wrongOperands ins

/// The Legacy Move Assist instructions.
let private moveAssistEncoders () =
  [ Op.DLMZB, rasb (78u <<< 1)
    Op.DLMZBdot, rasb ((78u <<< 1) ||| 1u) ]

/// Every instruction of the categories Power ISA 3.1 dropped.
let legacyEncoders () =
  multiplyAccumulateEncoders () @ moveAssistEncoders ()

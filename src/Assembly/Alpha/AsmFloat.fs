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
/// Encodes the floating-point instructions.
///
/// The names these go under and the function codes they are written with both
/// come from <see cref='T:B2R2.FrontEnd.Alpha.FloatFunction'/>, which is what
/// the decoder reads them out of as well, so a word this encodes and the text
/// the disassembler writes for it cannot disagree about which combination of
/// trapping and rounding is written which way. What is left for this file to
/// say is only what each instruction works on.
/// </summary>
module internal B2R2.Assembly.Alpha.AsmFloat

open B2R2.FrontEnd.Alpha
open B2R2.Assembly.Alpha.ParserHelper
open B2R2.Assembly.Alpha.AsmField

/// An instruction computing from two floating-point registers into a third.
let private arithmetic op func ins =
  match ins.Operands with
  | [ Rg fa; Rg fb; Rg fc ] -> fltWord op func (fpr fa) (fpr fb) (fpr fc)
  | _ -> wrongOperands ins

/// An instruction reading one floating-point register, which leaves the field
/// naming the first one unused.
let private convert op func ins =
  match ins.Operands with
  | [ Rg fb; Rg fc ] -> fltWord op func Unused (fpr fb) (fpr fc)
  | _ -> wrongOperands ins

/// An instruction moving what a general register holds into a floating-point
/// one, which names the general register where a first one would be.
let private intToFloat op func ins =
  match ins.Operands with
  | [ Rg ra; Rg fc ] -> fltWord op func (gpr ra) Unused (fpr fc)
  | _ -> wrongOperands ins

/// <summary>
/// An instruction reading or writing the control register.
///
/// It names one floating-point register, and the architecture asks that all
/// three of its register fields hold that same one, so it is written into each.
/// </summary>
let private controlRegister op func ins =
  match ins.Operands with
  | [ Rg fa ] -> fltWord op func (fpr fa) (fpr fa) (fpr fa)
  | _ -> wrongOperands ins

/// <summary>
/// What one floating-point instruction works on, given the major opcode and
/// the function code the instruction and its qualifier are written with.
///
/// Which shape each instruction takes is said here and in the parser both, and
/// the round-trip sweep is what holds the two to the same answer.
/// </summary>
let private encoderFor op major func =
  match op with
  | Opcode.ITOFS | Opcode.ITOFF | Opcode.ITOFT -> intToFloat major func
  | Opcode.MT_FPCR | Opcode.MF_FPCR -> controlRegister major func
  | Opcode.SQRTF | Opcode.SQRTG | Opcode.SQRTS | Opcode.SQRTT
  | Opcode.CVTDG | Opcode.CVTGF | Opcode.CVTGD | Opcode.CVTGQ
  | Opcode.CVTQF | Opcode.CVTQG | Opcode.CVTTS | Opcode.CVTST
  | Opcode.CVTTQ | Opcode.CVTQS | Opcode.CVTQT | Opcode.CVTLQ
  | Opcode.CVTQL -> convert major func
  | _ -> arithmetic major func

/// Every floating-point instruction, each under the name it is written by --
/// the qualifier it carries included, because that is part of the name -- and
/// paired with the encoder for it.
let floatEncoders () =
  [ for op, qualifier, major, func in FloatFunction.all ->
      Qualifier.mnemonicOf op qualifier, encoderFor op major func ]

// vim: set tw=80 sts=2 sw=2:

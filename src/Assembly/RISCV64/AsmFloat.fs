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
/// Encodes the instructions that work on the floating-point registers, in both
/// the width of a single number and the width of a double one.
///
/// Which of the two widths an instruction works in is written into its name and
/// held in the lowest bit of the field above its registers, so the two sets are
/// the same set twice over. What an instruction rounds by is written last where
/// it is written at all, and is left out where the instruction takes it from
/// the rounding-mode register instead.
/// </summary>
module internal B2R2.Assembly.RISCV64.AsmFloat

open B2R2.FrontEnd.RISCV64
open B2R2.Assembly.RISCV64.ParserHelper
open B2R2.Assembly.RISCV64.AsmField

/// A load into a floating-point register, which names where it reads the way a
/// load into a general register does.
let private loadForm funct3 ins =
  match ins.Operands with
  | [ Rg d; Mem(offset, b) ] ->
    iType OpLoadFp funct3 (fpr d) (gpr b) (immediate12 offset)
  | _ ->
    wrongOperands ins

/// A store out of a floating-point register.
let private storeForm funct3 ins =
  match ins.Operands with
  | [ Rg s; Mem(offset, b) ] ->
    sType OpStoreFp funct3 (gpr b) (fpr s) (immediate12 offset)
  | _ ->
    wrongOperands ins

/// <summary>
/// A multiply whose product is added to a third register before it is rounded.
///
/// This is the one thing a whole opcode of its own says, because a fourth
/// register leaves no room for the field that would otherwise say it; what is
/// left of that field says which of the two widths the instruction works in.
/// </summary>
let private fusedForm opcode fmt ins =
  match ins.Operands with
  | Rg d :: Rg s1 :: Rg s2 :: Rg s3 :: rest ->
    let funct7 = (fpr s3 <<< 2) ||| fmt
    rType opcode (roundingOf rest) funct7 (fpr d) (fpr s1) (fpr s2)
  | _ ->
    wrongOperands ins

/// An instruction computing from two floating-point registers into a third and
/// rounding what it computed.
let private roundedForm funct7 ins =
  match ins.Operands with
  | Rg d :: Rg s1 :: Rg s2 :: rest ->
    rType OpFloat (roundingOf rest) funct7 (fpr d) (fpr s1) (fpr s2)
  | _ ->
    wrongOperands ins

/// The same from one register rather than two, where what would name the second
/// says which instruction it is instead.
let private unaryForm funct7 rs2 ins =
  match ins.Operands with
  | Rg d :: Rg s :: rest ->
    rType OpFloat (roundingOf rest) funct7 (fpr d) (fpr s) rs2
  | _ ->
    wrongOperands ins

/// An instruction on two floating-point registers that rounds nothing, so that
/// the field a rounding mode would fill says which instruction it is.
let private exactForm funct3 funct7 ins =
  match ins.Operands with
  | [ Rg d; Rg s1; Rg s2 ] ->
    rType OpFloat funct3 funct7 (fpr d) (fpr s1) (fpr s2)
  | _ ->
    wrongOperands ins

/// A comparison, which answers into a general register.
let private compareForm funct3 funct7 ins =
  match ins.Operands with
  | [ Rg d; Rg s1; Rg s2 ] ->
    rType OpFloat funct3 funct7 (gpr d) (fpr s1) (fpr s2)
  | _ ->
    wrongOperands ins

/// An instruction reading a floating-point register and writing a general one.
let private fromFloatForm funct7 rs2 ins =
  match ins.Operands with
  | Rg d :: Rg s :: rest ->
    rType OpFloat (roundingOf rest) funct7 (gpr d) (fpr s) rs2
  | _ ->
    wrongOperands ins

/// An instruction reading a general register and writing a floating-point one.
let private toFloatForm funct7 rs2 ins =
  match ins.Operands with
  | Rg d :: Rg s :: rest ->
    rType OpFloat (roundingOf rest) funct7 (fpr d) (gpr s) rs2
  | _ ->
    wrongOperands ins

/// <summary>
/// An instruction writing a general register from a floating-point one and
/// rounding nothing, so that the field a rounding mode would fill says which
/// instruction it is.
///
/// Moving the bits of one register into the other rounds nothing because it
/// computes nothing, and neither does saying what kind of number a register
/// holds.
/// </summary>
let private fromFloatExactForm funct3 funct7 ins =
  match ins.Operands with
  | [ Rg d; Rg s ] -> rType OpFloat funct3 funct7 (gpr d) (fpr s) 0u
  | _ -> wrongOperands ins

/// <summary>
/// An instruction writing a floating-point register from a general one and
/// rounding nothing.
///
/// Besides moving the bits across, this is how a whole number narrower than the
/// significand of a double is widened: every such number is one a double holds
/// exactly, so there is nothing to round and no mode to write.
/// </summary>
let private toFloatExactForm funct7 rs2 ins =
  match ins.Operands with
  | [ Rg d; Rg s ] -> rType OpFloat 0u funct7 (fpr d) (gpr s) rs2
  | _ -> wrongOperands ins

/// The instructions that work on the floating-point registers.
let floatEncoders () =
  [ Op.FLW, loadForm 2u
    Op.FLD, loadForm 3u
    Op.FSW, storeForm 2u
    Op.FSD, storeForm 3u
    Op.FMADDdotS, fusedForm 0x43u 0u
    Op.FMSUBdotS, fusedForm 0x47u 0u
    Op.FNMSUBdotS, fusedForm 0x4Bu 0u
    Op.FNMADDdotS, fusedForm 0x4Fu 0u
    Op.FMADDdotD, fusedForm 0x43u 1u
    Op.FMSUBdotD, fusedForm 0x47u 1u
    Op.FNMSUBdotD, fusedForm 0x4Bu 1u
    Op.FNMADDdotD, fusedForm 0x4Fu 1u
    Op.FADDdotS, roundedForm 0x00u
    Op.FSUBdotS, roundedForm 0x04u
    Op.FMULdotS, roundedForm 0x08u
    Op.FDIVdotS, roundedForm 0x0Cu
    Op.FSQRTdotS, unaryForm 0x2Cu 0u
    Op.FSGNJdotS, exactForm 0u 0x10u
    Op.FSGNJNdotS, exactForm 1u 0x10u
    Op.FSGNJXdotS, exactForm 2u 0x10u
    Op.FMINdotS, exactForm 0u 0x14u
    Op.FMAXdotS, exactForm 1u 0x14u
    Op.FEQdotS, compareForm 2u 0x50u
    Op.FLTdotS, compareForm 1u 0x50u
    Op.FLEdotS, compareForm 0u 0x50u
    Op.FCVTdotWdotS, fromFloatForm 0x60u 0u
    Op.FCVTdotWUdotS, fromFloatForm 0x60u 1u
    Op.FCVTdotLdotS, fromFloatForm 0x60u 2u
    Op.FCVTdotLUdotS, fromFloatForm 0x60u 3u
    Op.FCVTdotSdotW, toFloatForm 0x68u 0u
    Op.FCVTdotSdotWU, toFloatForm 0x68u 1u
    Op.FCVTdotSdotL, toFloatForm 0x68u 2u
    Op.FCVTdotSdotLU, toFloatForm 0x68u 3u
    Op.FMVdotXdotW, fromFloatExactForm 0u 0x70u
    Op.FCLASSdotS, fromFloatExactForm 1u 0x70u
    Op.FMVdotWdotX, toFloatExactForm 0x78u 0u
    Op.FADDdotD, roundedForm 0x01u
    Op.FSUBdotD, roundedForm 0x05u
    Op.FMULdotD, roundedForm 0x09u
    Op.FDIVdotD, roundedForm 0x0Du
    Op.FSQRTdotD, unaryForm 0x2Du 0u
    Op.FSGNJdotD, exactForm 0u 0x11u
    Op.FSGNJNdotD, exactForm 1u 0x11u
    Op.FSGNJXdotD, exactForm 2u 0x11u
    Op.FMINdotD, exactForm 0u 0x15u
    Op.FMAXdotD, exactForm 1u 0x15u
    Op.FCVTdotSdotD, unaryForm 0x20u 1u
    Op.FCVTdotDdotS, unaryForm 0x21u 0u
    Op.FEQdotD, compareForm 2u 0x51u
    Op.FLTdotD, compareForm 1u 0x51u
    Op.FLEdotD, compareForm 0u 0x51u
    Op.FCVTdotWdotD, fromFloatForm 0x61u 0u
    Op.FCVTdotWUdotD, fromFloatForm 0x61u 1u
    Op.FCVTdotLdotD, fromFloatForm 0x61u 2u
    Op.FCVTdotLUdotD, fromFloatForm 0x61u 3u
    Op.FCVTdotDdotW, toFloatExactForm 0x69u 0u
    Op.FCVTdotDdotWU, toFloatExactForm 0x69u 1u
    Op.FCVTdotDdotL, toFloatForm 0x69u 2u
    Op.FCVTdotDdotLU, toFloatForm 0x69u 3u
    Op.FMVdotXdotD, fromFloatExactForm 0u 0x71u
    Op.FCLASSdotD, fromFloatExactForm 1u 0x71u
    Op.FMVdotDdotX, toFloatExactForm 0x79u 0u ]

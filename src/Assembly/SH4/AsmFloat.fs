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
/// Encodes the floating-point unit.
///
/// Which registers a floating-point instruction names is not written into it:
/// the same word reads two single-precision registers or one pair of them,
/// according to a bit a program sets at run time. What is encoded here is the
/// cleared state, which is the one B2R2's decoder reads a word in and the one a
/// userland program runs in until it sets the bit itself.
/// </summary>
module internal B2R2.Assembly.SH4.AsmFloat

open B2R2.FrontEnd.SH4
open B2R2.Assembly.SH4.ParserHelper
open B2R2.Assembly.SH4.AsmField

/// The family every floating-point instruction belongs to, which is the last
/// one there is.
let [<Literal>] private FamFloat = 0xFus

/// An instruction computing from one floating-point register into another.
let private fpuPair rest ins =
  match ins.Operands with
  | [ Rg m; Rg n ] -> nmWord FamFloat (fpr n) (fpr m) rest
  | _ -> wrongOperands ins

/// The instruction multiplying two registers and adding the first of the file
/// to what it made, which is the only one naming three registers.
let private multiplyAccumulate ins =
  match ins.Operands with
  | [ Rg Register.FR0; Rg m; Rg n ] ->
    nmWord FamFloat (fpr n) (fpr m) 0xEus
  | _ -> wrongOperands ins

/// A move between a floating-point register and memory, which takes the same
/// forms a move of a longword does and differs only in which file the register
/// it names comes out of.
let private moveSingle ins =
  match ins.Operands with
  | [ Idx m; Rg n ] -> nmWord FamFloat (fpr n) (gpr m) 0x6us
  | [ Rg m; Idx n ] -> nmWord FamFloat (gpr n) (fpr m) 0x7us
  | [ Ind m; Rg n ] -> nmWord FamFloat (fpr n) (gpr m) 0x8us
  | [ Post m; Rg n ] -> nmWord FamFloat (fpr n) (gpr m) 0x9us
  | [ Rg m; Ind n ] -> nmWord FamFloat (gpr n) (fpr m) 0xAus
  | [ Rg m; Pre n ] -> nmWord FamFloat (gpr n) (fpr m) 0xBus
  | _ -> wrongOperands ins

/// An instruction naming one floating-point register and nothing else, where
/// everything below the field naming it is spelt out.
let private oneFpr rest ins =
  match ins.Operands with
  | [ Rg n ] -> nWord FamFloat (fpr n) rest
  | _ -> wrongOperands ins

/// An instruction moving what the register standing between the two files
/// holds, in the direction the given order of the operands says.
let private throughFpul toFpul rest ins =
  match ins.Operands, toFpul with
  | [ Rg m; Rg Register.FPUL ], true -> nWord FamFloat (fpr m) rest
  | [ Rg Register.FPUL; Rg n ], false -> nWord FamFloat (fpr n) rest
  | _ -> wrongOperands ins

/// The same, where what is moved is a pair rather than a single register, so
/// that the field naming it is a bit narrower and sits a bit higher.
let private pairThroughFpul toFpul rest ins =
  match ins.Operands, toFpul with
  | [ Rg m; Rg Register.FPUL ], true -> nWord FamFloat (dpr m <<< 1) rest
  | [ Rg Register.FPUL; Rg n ], false -> nWord FamFloat (dpr n <<< 1) rest
  | _ -> wrongOperands ins

/// The instruction adding up what two vectors hold, which names each of them by
/// the two bits that are all four registers of one have in common.
let private innerProduct ins =
  match ins.Operands with
  | [ Rg m; Rg n ] -> nWord FamFloat ((fvr n <<< 2) ||| fvr m) 0xEDus
  | _ -> wrongOperands ins

/// The instruction multiplying a vector by the matrix the whole of the other
/// register file holds.
let private transform ins =
  match ins.Operands with
  | [ Rg Register.XMTRX; Rg n ] -> nWord FamFloat ((fvr n <<< 2) ||| 1us) 0xFDus
  | _ -> wrongOperands ins

/// An instruction naming nothing at all, which for this unit means one of the
/// two swapping a register file for the one behind it.
let private noOperand word ins =
  match ins.Operands with
  | [] -> word
  | _ -> wrongOperands ins

/// The whole of the floating-point unit at the width the decoder reads it in.
let floatEncoders () =
  [ "fadd", fpuPair 0x0us
    "fsub", fpuPair 0x1us
    "fmul", fpuPair 0x2us
    "fdiv", fpuPair 0x3us
    "fcmpeq", fpuPair 0x4us
    "fcmpgt", fpuPair 0x5us
    "fmov", fpuPair 0xCus
    "fmac", multiplyAccumulate
    "fmovs", moveSingle
    "fneg", oneFpr 0x4Dus
    "fabs", oneFpr 0x5Dus
    "fsqrt", oneFpr 0x6Dus
    "fldi0", oneFpr 0x8Dus
    "fldi1", oneFpr 0x9Dus
    "fsts", throughFpul false 0x0Dus
    "flds", throughFpul true 0x1Dus
    "float", throughFpul false 0x2Dus
    "ftrc", throughFpul true 0x3Dus
    "fcnvsd", pairThroughFpul false 0xADus
    "fcnvds", pairThroughFpul true 0xBDus
    "fipr", innerProduct
    "ftrv", transform
    "fschg", noOperand 0xF3FDus
    "frchg", noOperand 0xFBFDus ]

// vim: set tw=80 sts=2 sw=2:

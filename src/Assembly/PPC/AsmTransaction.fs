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
/// Encodes the instructions of the Transactional Memory category (Power ISA
/// 2.07B Book II chapter 5), all of primary opcode 31 and all but tcheck with
/// the record bit set.
/// </summary>
module internal B2R2.Assembly.PPC.AsmTransaction

open B2R2.FrontEnd.PPC
open B2R2.Assembly.PPC.ParserHelper
open B2R2.Assembly.PPC.AsmField

/// tbegin., "R": the bit 10, which is the lowest bit of the first register
/// field.
let private tbegin ins =
  match ins.Operands with
  | [ Im r ] ->
    xForm 31u (unsigned 1 r) 0u 0u 654u 1u
  | _ ->
    wrongOperands ins

/// tend., "A": the bit 6, which is the highest bit of the first register field.
let private tend ins =
  match ins.Operands with
  | [ Im a ] ->
    xForm 31u (unsigned 1 a <<< 4) 0u 0u 686u 1u
  | _ ->
    wrongOperands ins

/// tabort., "rA".
let private tabort ins =
  match ins.Operands with
  | [ Rg a ] ->
    xForm 31u 0u (gpr a) 0u 910u 1u
  | _ ->
    wrongOperands ins

/// A conditional abort against a register, "TO, rA, rB".
let private abortRegister xo ins =
  match ins.Operands with
  | [ Im ct; Rg a; Rg b ] ->
    xForm 31u (unsigned 5 ct) (gpr a) (gpr b) xo 1u
  | _ ->
    wrongOperands ins

/// A conditional abort against an immediate, "TO, rA, SI": SI is five bits of
/// the field a register would be in, a signed number.
let private abortImmediate bitLen xo ins =
  match ins.Operands with
  | [ Im ct; Rg a; Im si ] ->
    xForm 31u (unsigned 5 ct) (gpr a) (signed 5 (signedValue bitLen si)) xo 1u
  | _ ->
    wrongOperands ins

/// tcheck, "BF": the field is the three bits 6:8.
let private tcheck ins =
  match ins.Operands with
  | [ Rg bf ] ->
    xForm 31u (crf bf <<< 2) 0u 0u 718u 0u
  | _ ->
    wrongOperands ins

/// tsr., "L": the bit 10.
let private tsr ins =
  match ins.Operands with
  | [ Im l ] ->
    xForm 31u (unsigned 1 l) 0u 0u 750u 1u
  | _ ->
    wrongOperands ins

/// The transactional memory instructions, at the width a source is read at.
let transactionEncoders bitLen =
  [ Op.TABORTDCIdot, abortImmediate bitLen 878u
    Op.TABORTDCdot, abortRegister 814u
    Op.TABORTWCIdot, abortImmediate bitLen 846u
    Op.TABORTWCdot, abortRegister 782u
    Op.TABORTdot, tabort
    Op.TBEGINdot, tbegin
    Op.TCHECK, tcheck
    Op.TENDdot, tend
    Op.TSRdot, tsr ]

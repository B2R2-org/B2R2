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
/// Encodes the instructions of the Signal Processing Engine, the ones in
/// primary opcode 4 that a processor with the engine reads in place of the
/// vector facility.
/// </summary>
module internal B2R2.Assembly.PPC.AsmSPE

open B2R2.FrontEnd.PPC
open B2R2.Assembly.PPC.ParserHelper
open B2R2.Assembly.PPC.AsmField

/// An EVX-form "RT, RA, RB".
let private rrr xo ins =
  match ins.Operands with
  | [ Rg d; Rg a; Rg b ] -> word 4u (gpr d) (gpr a) (gpr b) xo
  | _ -> wrongOperands ins

/// An EVX-form "RT, RA" whose RB field no register fills.
let private rr xo ins =
  match ins.Operands with
  | [ Rg d; Rg a ] -> word 4u (gpr d) (gpr a) 0u xo
  | _ -> wrongOperands ins

/// An EVX-form "RT, RB" whose RA field no register fills.
let private rb xo ins =
  match ins.Operands with
  | [ Rg d; Rg b ] -> word 4u (gpr d) 0u (gpr b) xo
  | _ -> wrongOperands ins

/// An EVX-form "RT, RB, UI" whose number is in the RA field.
let private rbUi xo ins =
  match ins.Operands with
  | [ Rg d; Rg b; Im u ] -> word 4u (gpr d) (unsigned 5 u) (gpr b) xo
  | _ -> wrongOperands ins

/// An EVX-form "RT, UI, RB" whose number is in the RA field.
let private uiRb xo ins =
  match ins.Operands with
  | [ Rg d; Im u; Rg b ] -> word 4u (gpr d) (unsigned 5 u) (gpr b) xo
  | _ -> wrongOperands ins

/// An EVX-form "RT, RA, UI" whose number is in the RB field.
let private raUi xo ins =
  match ins.Operands with
  | [ Rg d; Rg a; Im u ] -> word 4u (gpr d) (gpr a) (unsigned 5 u) xo
  | _ -> wrongOperands ins

/// An EVX-form "RT, SI", whose signed number is in the RA field.
let private si xo ins =
  match ins.Operands with
  | [ Rg d; Im v ] -> word 4u (gpr d) (signed 5 (int64 v)) 0u xo
  | _ -> wrongOperands ins

/// An EVX-form "BF, RA, RB".
let private cmp xo ins =
  match ins.Operands with
  | [ Rg c; Rg a; Rg b ] -> word 4u (crf c <<< 2) (gpr a) (gpr b) xo
  | _ -> wrongOperands ins

/// An EVS-form "RT, RA, RB, BFA", the CR field in the low three bits.
let private sel xo ins =
  match ins.Operands with
  | [ Rg d; Rg a; Rg b; Rg c ] ->
    word 4u (gpr d) (gpr a) (gpr b) (xo ||| crf c)
  | _ ->
    wrongOperands ins

/// An EVX-form access "RT, D(RA)", whose distance is a whole number of the
/// accessed size, at most thirty-one of them.
let private disp size xo ins =
  match ins.Operands with
  | [ Rg d; Mem(dist, a) ] when dist >= 0 && dist % size = 0 ->
    word 4u (gpr d) (gpr a) (unsigned 5 (uint64 (dist / size))) xo
  | [ Rg _; Mem _ ] ->
    fail "this access reaches a whole number of its size"
  | _ ->
    wrongOperands ins

/// The encoders of the "logic" theme.
let private logicEncoders () =
  [ Op.EVADDIW, rbUi 514u
    Op.EVADDW, rrr 512u
    Op.EVAND, rrr 529u
    Op.EVANDC, rrr 530u
    Op.EVEQV, rrr 537u
    Op.EVNAND, rrr 542u
    Op.EVNOR, rrr 536u
    Op.EVOR, rrr 535u
    Op.EVORC, rrr 539u
    Op.EVSUBFW, rrr 516u
    Op.EVSUBIFW, uiRb 518u
    Op.EVXOR, rrr 534u ]

/// The encoders of the "shift" theme.
let private shiftEncoders () =
  [ Op.BRINC, rrr 527u
    Op.EVABS, rr 520u
    Op.EVCNTLSW, rr 526u
    Op.EVCNTLZW, rr 525u
    Op.EVEXTSB, rr 522u
    Op.EVEXTSH, rr 523u
    Op.EVMERGEHI, rrr 556u
    Op.EVMERGEHILO, rrr 558u
    Op.EVMERGELO, rrr 557u
    Op.EVMERGELOHI, rrr 559u
    Op.EVNEG, rr 521u
    Op.EVRLW, rrr 552u
    Op.EVRLWI, raUi 554u
    Op.EVRNDW, rr 524u
    Op.EVSLW, rrr 548u
    Op.EVSLWI, raUi 550u
    Op.EVSPLATFI, si 555u
    Op.EVSPLATI, si 553u
    Op.EVSRWIS, raUi 547u
    Op.EVSRWIU, raUi 546u
    Op.EVSRWS, rrr 545u
    Op.EVSRWU, rrr 544u ]

/// The encoders of the "compare" theme.
let private compareEncoders () =
  [ Op.EVCMPEQ, cmp 564u
    Op.EVCMPGTS, cmp 561u
    Op.EVCMPGTU, cmp 560u
    Op.EVCMPLTS, cmp 563u
    Op.EVCMPLTU, cmp 562u
    Op.EVSEL, sel 632u ]

/// The encoders of the Signal Processing Engine.
let signalProcessingEncoders () =
  List.concat
    [ logicEncoders ()
      shiftEncoders ()
      compareEncoders () ]

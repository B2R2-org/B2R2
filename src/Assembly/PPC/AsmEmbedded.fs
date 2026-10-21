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
/// Encodes the instructions the embedded environment adds to primary opcode 31
/// (Power ISA 2.07B Book II and Book III-E).
/// </summary>
module internal B2R2.Assembly.PPC.AsmEmbedded

open B2R2.FrontEnd.PPC
open B2R2.Assembly.PPC.ParserHelper
open B2R2.Assembly.PPC.AsmField

/// A cache-locking instruction, "CT, rA, rB", given its extended opcode and
/// its record bit: CT is the four bits 7:10.
let private cacheLock xo rc ins =
  match ins.Operands with
  | [ Im ct; Rg a; Rg b ] -> xForm 31u (unsigned 4 ct) (gpr a) (gpr b) xo rc
  | _ -> wrongOperands ins

/// The cache-locking instructions.
let private cacheLockEncoders () =
  [ Op.DCBLC, cacheLock 390u 0u
    Op.DCBLQdot, cacheLock 422u 1u
    Op.DCBTLS, cacheLock 166u 0u
    Op.DCBTSTLS, cacheLock 134u 0u
    Op.ICBLC, cacheLock 230u 0u
    Op.ICBLQdot, cacheLock 198u 1u
    Op.ICBTLS, cacheLock 486u 0u ]

/// mbar, "MO": the five bits 6:10.
let private mbar ins =
  match ins.Operands with
  | [ Im mo ] -> xForm 31u (unsigned 5 mo) 0u 0u 854u 0u
  | _ -> wrongOperands ins

/// dnh, "DUI, DUIS": five bits 6:10 and the ten bits 11:20.
let private dnh ins =
  match ins.Operands with
  | [ Im dui; Im duis ] ->
    let duis = unsigned 10 duis
    xForm 19u (unsigned 5 dui) (duis >>> 5) (duis &&& 0x1Fu) 198u 0u
  | _ ->
    wrongOperands ins

/// ehpriv, "OC": the fifteen bits 6:20.
let private ehpriv ins =
  match ins.Operands with
  | [ Im oc ] ->
    let oc = unsigned 15 oc
    xForm 31u (oc >>> 10) ((oc >>> 5) &&& 0x1Fu) (oc &&& 0x1Fu) 270u 0u
  | _ ->
    wrongOperands ins

/// mfpmr, "rT, PMRN": the number is written in the halves the encoding of a
/// special register keeps its number in.
let private mfpmr ins =
  match ins.Operands with
  | [ Rg t; Im pmrn ] ->
    word 31u (gpr t) 0u 0u (specialRegister pmrn ||| (334u <<< 1))
  | _ ->
    wrongOperands ins

/// mtpmr, "PMRN, rS".
let private mtpmr ins =
  match ins.Operands with
  | [ Im pmrn; Rg s ] ->
    word 31u (gpr s) 0u 0u (specialRegister pmrn ||| (462u <<< 1))
  | _ ->
    wrongOperands ins

/// mfdcrux, "rT, rA".
let private mfdcrux ins =
  match ins.Operands with
  | [ Rg t; Rg a ] -> xForm 31u (gpr t) (gpr a) 0u 291u 0u
  | _ -> wrongOperands ins

/// mtdcrux, "rA, rS" as objdump writes it.
let private mtdcrux ins =
  match ins.Operands with
  | [ Rg a; Rg s ] -> xForm 31u (gpr s) (gpr a) 0u 419u 0u
  | _ -> wrongOperands ins

/// xnop, the no-op whose word is xori 0, 0, 0.
let private xnop ins =
  match ins.Operands with
  | [] -> dForm 26u 0u 0u 0u
  | _ -> wrongOperands ins

/// The barrier, hint and move instructions of the embedded environment.
let private miscellaneousEncoders () =
  [ Op.DNH, dnh
    Op.EHPRIV, ehpriv
    Op.MBAR, mbar
    Op.MFDCRUX, mfdcrux
    Op.MFPMR, mfpmr
    Op.MTDCRUX, mtdcrux
    Op.MTPMR, mtpmr
    Op.XNOP, xnop ]

/// A decorated access, "rT, rA, rB", given its extended opcode and what names
/// rT.
let private decorated regField xo ins =
  match ins.Operands with
  | [ Rg t; Rg a; Rg b ] ->
    xForm 31u (regField t) (gpr a) (gpr b) xo 0u
  | _ ->
    wrongOperands ins

/// dsn, "rA, rB".
let private dsn ins =
  match ins.Operands with
  | [ Rg a; Rg b ] ->
    xForm 31u 0u (gpr a) (gpr b) 483u 0u
  | _ ->
    wrongOperands ins

/// The decorated loads and stores, and dsn.
let private decoratedStorageEncoders () =
  [ Op.DSN, dsn
    Op.LBDX, decorated gpr 515u
    Op.LDDX, decorated gpr 611u
    Op.LFDDX, decorated fpr 803u
    Op.LHDX, decorated gpr 547u
    Op.LWDX, decorated gpr 579u
    Op.STBDX, decorated gpr 643u
    Op.STDDX, decorated gpr 739u
    Op.STFDDX, decorated fpr 931u
    Op.STHDX, decorated gpr 675u
    Op.STWDX, decorated gpr 707u ]

/// Every instruction the embedded environment adds.
let embeddedEncoders () =
  cacheLockEncoders ()
  @ miscellaneousEncoders ()
  @ decoratedStorageEncoders ()

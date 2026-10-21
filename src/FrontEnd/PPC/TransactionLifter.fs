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
/// Lifts the instructions of the Transactional Memory category (Power ISA
/// 2.07B Book II chapter 5) for a processor that fails every transaction. The
/// architecture lets a transaction fail at any time, and a processor that never
/// lets one begin is one such: software is expected to count its retries and
/// fall back to a lock (the programming note to the failure persistent bit).
/// The transaction state, MSR[TS], therefore stays Non-transactional, which is
/// why every instruction but tbegin. only sets CR0 (or the field tcheck names)
/// to what the state gives it.
/// </summary>
module internal B2R2.FrontEnd.PPC.TransactionLifter

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils

/// What TEXASR holds once the outer transaction a tbegin. started has failed
/// at once. tbegin. sets it to 1 in the transaction level (bits 52:63) and to
/// the instruction's R in the rollback-only bit (38); the failure sets the
/// failure persistent bit (7) and the nesting overflow cause (9), which tell
/// software not to retry, the privilege bits (34:35) to the state of a user
/// program on a processor that is not virtualized (MSR[HV] and MSR[PR] both
/// set), the failure summary bit (36), and the bit that says TFIAR is exact
/// (37); recording a failure leaves the transaction level alone.
let private failedTexasr rollbackOnly =
  0x0140_0000_3c00_0001UL ||| (rollbackOnly <<< 25)

/// What the privilege state (MSR[HV] and MSR[PR]) puts in the low bits of
/// TFIAR.
let private privilege = 3UL

/// Sets CR0 to the four bits given, LT, GT, EQ and SO in the order they read.
let private setCR0 bld (lt, gt, eq, so) =
  append bld {
    regVar bld Register.CR0_0 := lt
    regVar bld Register.CR0_1 := gt
    regVar bld Register.CR0_2 := eq
    regVar bld Register.CR0_3 := so
  }

/// tbegin. R: the transaction fails as it begins. Failure recording puts the
/// cause in TEXASR, the address the handler is at in TFHAR (the instruction
/// after the tbegin., where control goes) and that of the instruction that
/// failed in TFIAR (the tbegin. itself); failure handling then sets CR0 to
/// 0b1010 and continues at TFHAR.
let private tbegin (ins: Instruction) bld =
  let rollbackOnly =
    match ins.Operands with
    | OneOperand(OprImm r) -> r
    | _ -> raise InvalidOperandException
  lift bld ins {
    regVar bld Register.TEXASR := numU64 (failedTexasr rollbackOnly) 64<rt>
    regVar bld Register.TFHAR := numU64 (ins.Address + 4UL) 64<rt>
    regVar bld Register.TFIAR := numU64 (ins.Address ||| privilege) 64<rt>
    setCR0 bld (AST.b1, AST.b0, AST.b1, AST.b0)
  }

/// The instructions that only set CR0, to 0 || MSR[TS] || 0, which is zero in
/// the Non-transactional state: tend., tabort. and the conditional aborts, and
/// tsr. All of them are no-ops there otherwise.
let private clearCR0 (ins: Instruction) bld =
  lift bld ins {
    setCR0 bld (AST.b0, AST.b0, AST.b0, AST.b0)
  }

/// tcheck BF: the field BF receives TDOOMED || MSR[TS] || 0. A processor that
/// fails every transaction has recorded a failure whenever it has begun one,
/// and that sets TDOOMED, so the field is 0b1000.
let private tcheck (ins: Instruction) bld =
  lift bld ins {
    let crd0, crd1, crd2, crd3 = transCondOneOpr ins bld
    crd0 := AST.b1
    crd1 := AST.b0
    crd2 := AST.b0
    crd3 := AST.b0
  }

/// The register a move names, and whether it is the upper word of TEXASR.
let private sprOf = function
  | Op.MFTFHAR | Op.MTTFHAR -> Register.TFHAR
  | Op.MFTFIAR | Op.MTTFIAR -> Register.TFIAR
  | _ -> Register.TEXASR

/// A move from a 64-bit register into one of the processor's width, which
/// keeps its low bits.
let private mfspr (ins: Instruction) bld =
  lift bld ins {
    let rt = transOneOpr ins bld
    let value = regVar bld (sprOf ins.Opcode)
    rt := AST.xtlo bld.RegType value
  }

/// mftexasru: TEXASRU, the upper word of TEXASR, zero-extended.
let private mftexasru (ins: Instruction) bld =
  lift bld ins {
    let rt = transOneOpr ins bld
    rt := AST.zext bld.RegType (AST.xthi 32<rt> (regVar bld Register.TEXASR))
  }

/// A move to a 64-bit register, zero-extended where the source is narrower.
let private mtspr (ins: Instruction) bld =
  lift bld ins {
    let rs = transOneOpr ins bld
    regVar bld (sprOf ins.Opcode) := AST.zext 64<rt> rs
  }

/// mttexasru: the low word of rS becomes the upper word of TEXASR.
let private mttexasru (ins: Instruction) bld =
  lift bld ins {
    let rs = transOneOpr ins bld
    let texasr = regVar bld Register.TEXASR
    let upper = AST.zext 64<rt> (AST.xtlo 32<rt> rs) << numI32 32 64<rt>
    texasr := (texasr .& numU64 0xffffffffUL 64<rt>) .| upper
  }

/// Whether this module lifts the opcode.
let lifts = function
  | Op.TABORTDCIdot | Op.TABORTDCdot | Op.TABORTWCIdot | Op.TABORTWCdot
  | Op.TABORTdot | Op.TBEGINdot | Op.TCHECK | Op.TENDdot | Op.TSRdot
  | Op.MFTEXASR | Op.MFTEXASRU | Op.MFTFHAR | Op.MFTFIAR | Op.MTTEXASR
  | Op.MTTEXASRU | Op.MTTFHAR | Op.MTTFIAR -> true
  | _ -> false

/// Lifts an instruction whose opcode this module lifts. The special registers
/// of the category may be written only outside a transaction, which is the
/// only state this machine has.
let translate (ins: Instruction) bld =
  match ins.Opcode with
  | Op.TBEGINdot ->
    tbegin ins bld
  | Op.TCHECK ->
    tcheck ins bld
  | Op.MFTFHAR | Op.MFTFIAR | Op.MFTEXASR ->
    mfspr ins bld
  | Op.MFTEXASRU ->
    mftexasru ins bld
  | Op.MTTFHAR | Op.MTTFIAR | Op.MTTEXASR ->
    mtspr ins bld
  | Op.MTTEXASRU ->
    mttexasru ins bld
  | _ ->
    clearCR0 ins bld

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

namespace B2R2.FrontEnd.BinLifter.SH4

open B2R2
open B2R2.FrontEnd

/// Shortcut for Register type.
type internal R = Register.SH4

/// This module exposes several useful functions to handle SH4 registers.
[<RequireQualifiedAccess>]
module Register =
  let toRegType = function
    | R.MD | R.RB | R.BL | R.FD | R.M | R.Q | R.IMASK | R.S | R.T
    | R.FPSCR_RM | R.FPSCR_FLAG | R.FPSCR_ENABLE | R.FPSCR_CAUSE | R.FPSCR_DN
    | R.FPSCR_PR | R.FPSCR_SZ | R.FPSCR_FR -> 1<rt>
    | R.R0 | R.R1 | R.R2 | R.R3 | R.R4 | R.R5 | R.R6 | R.R7 | R.R8 | R.R9
    | R.R10 | R.R11 | R.R12 | R.R13 | R.R14 | R.R15 | R.R0_BANK | R.R1_BANK
    | R.R2_BANK | R.R3_BANK | R.R4_BANK | R.R5_BANK | R.R6_BANK | R.R7_BANK
    | R.SR | R.GBR | R.SSR
    | R.SPC | R.SGR | R.DBR | R.VBR | R.MACH | R.MACL | R.PR | R.FPUL | R.PC
    | R.FPSCR | R.FPR0 | R.FPR1 | R.FPR2 | R.FPR3 | R.FPR4 | R.FPR5 | R.FPR6
    | R.FPR7 | R.FPR8 | R.FPR9 | R.FPR10 | R.FPR11 | R.FPR12 | R.FPR13
    | R.FPR14 | R.FPR15 | R.FR0 | R.FR1 | R.FR2 | R.FR3 | R.FR4 | R.FR5
    | R.FR6 | R.FR7 | R.FR8 | R.FR9 | R.FR10 | R.FR11 | R.FR12 | R.FR13
    | R.FR14 | R.FR15 | R.XF0 | R.XF1 | R.XF2 | R.XF3 | R.XF4 | R.XF5 | R.XF6
    | R.XF7 | R.XF8 | R.XF9 | R.XF10 | R.XF11 | R.XF12 | R.XF13 | R.XF14
    | R.XF15 | R.PTEH | R.PTEL | R.PTEA | R.TTB | R.TEA | R.MMUCR | R.CCR
    | R.QACR0 | R.QACR1 | R.TRA | R.EXPEVT | R.INTEVT -> 32<rt>
    | R.DR0 | R.DR2 | R.DR4 | R.DR6 | R.DR8 | R.DR10 | R.DR12 | R.DR14
    | R.XD0 | R.XD2 | R.XD4 | R.XD6 | R.XD8 | R.XD10 | R.XD12
    | R.XD14  -> 64<rt>
    | R.FV0 | R.FV4 | R.FV8 | R.FV12 -> 128<rt>
    | R.XMTRX -> 512<rt>
    | _ -> Utils.impossible()

type Const = int32

type AddressingMode =
  | Regdir of Register.SH4
  | RegIndir of Register.SH4
  | PostInc of Register.SH4
  | PreDec of Register.SH4
  | RegDisp of Const * Register.SH4
  | IdxIndir of Register.SH4 * Register.SH4
  | GbrDisp of Const * Register.SH4
  | IdxGbr of Register.SH4 * Register.SH4
  | PCrDisp of Const * Register.SH4
  | PCr of Const
  | Imm of Const

type Operand =
  | OpImm of Const
  | OpAddr of Const
  | OpReg of AddressingMode

type Operands =
  | NoOperand
  | OneOperand of Operand
  | TwoOperands of Operand * Operand
  | ThreeOperands of Operand * Operand * Operand

[<NoComparison; CustomEquality>]
type InsInfo = {
  // Address.
  Address: Addr
  // Instruction Length.
  NumBytes: uint32
  // Opcode.
  Opcode: Opcode
  // Operands.
  Operands: Operands
}
with
  override __.GetHashCode () =
    hash (__.Address,
          __.NumBytes,
          __.Opcode)
  override __.Equals (i) =
    match i with
    | :? InsInfo as i ->
      i.Address = __.Address
      && i.NumBytes = __.NumBytes
      && i.Opcode = __.Opcode
    | _ -> false

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

module internal B2R2.FrontEnd.PARISC.Lifter

open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.PARISC
open B2R2.FrontEnd.PARISC.GeneralLifter

/// Translate IR.
let translate (ins: Instruction) bld =
  match ins.Opcode with
  | Opcode.ADD ->
    add ins bld
  | Opcode.ADDB | Opcode.ADDIB ->
    addb ins bld
  | Opcode.ADDI ->
    addi ins bld
  | Opcode.ADDIL ->
    addil ins bld
  | Opcode.AND ->
    ``and`` ins bld
  | Opcode.ANDCM ->
    andcm ins bld
  | Opcode.B ->
    b ins bld
  | Opcode.BB ->
    bb ins bld
  | Opcode.BE ->
    be ins bld
  | Opcode.BLR ->
    blr ins bld
  | Opcode.BREAK ->
    ``break`` ins bld
  | Opcode.BV ->
    bv ins bld
  | Opcode.BVE ->
    bve ins bld
  | Opcode.CMPB | Opcode.CMPIB ->
    cmpb ins bld
  | Opcode.CMPCLR | Opcode.CMPICLR ->
    cmpclr ins bld
  | Opcode.DEPD | Opcode.DEPDI | Opcode.DEPW | Opcode.DEPWI ->
    dep ins bld
  | Opcode.DS ->
    ds ins bld
  | Opcode.EXTRD | Opcode.EXTRW ->
    extr ins bld
  | Opcode.FABS ->
    FloatLifter.fabs ins bld
  | Opcode.FADD ->
    FloatLifter.fadd ins bld
  | Opcode.FCMP ->
    FloatLifter.fcmp ins bld
  | Opcode.FCNV ->
    FloatLifter.fcnv ins bld
  | Opcode.FCPY ->
    FloatLifter.fcpy ins bld
  | Opcode.FDIV ->
    FloatLifter.fdiv ins bld
  | Opcode.FLDD | Opcode.FLDW ->
    FloatLifter.fpLoad ins bld
  | Opcode.FMPY ->
    FloatLifter.fmpy ins bld
  | Opcode.FMPYADD | Opcode.FMPYSUB ->
    FloatLifter.fmpyadd ins bld
  | Opcode.FMPYFADD | Opcode.FMPYNFADD ->
    FloatLifter.fmpyfadd ins bld
  | Opcode.FNEG ->
    FloatLifter.fneg ins bld
  | Opcode.FNEGABS ->
    FloatLifter.fnegabs ins bld
  | Opcode.FRND ->
    FloatLifter.frnd ins bld
  | Opcode.FSQRT ->
    FloatLifter.fsqrt ins bld
  | Opcode.FSTD | Opcode.FSTW ->
    FloatLifter.fpStore ins bld
  | Opcode.FTEST ->
    FloatLifter.ftest ins bld
  | Opcode.LDB | Opcode.LDD | Opcode.LDDA | Opcode.LDH | Opcode.LDW
  | Opcode.LDWA ->
    load ins bld
  | Opcode.LDCD | Opcode.LDCW ->
    ldcw ins bld
  | Opcode.LDIL ->
    ldil ins bld
  | Opcode.LDO ->
    ldo ins bld
  | Opcode.LDSID ->
    ldsid ins bld
  | Opcode.MFCTL | Opcode.MFIA ->
    mfctl ins bld
  | Opcode.MFSP | Opcode.MTSP ->
    movsp ins bld
  | Opcode.MOVB | Opcode.MOVIB ->
    movb ins bld
  | Opcode.MTCTL ->
    mtctl ins bld
  | Opcode.MTSARCM ->
    mtsarcm ins bld
  | Opcode.OR ->
    ``or`` ins bld
  | Opcode.SHLADD ->
    shladd ins bld
  | Opcode.SHRPD | Opcode.SHRPW ->
    shrp ins bld
  | Opcode.STB | Opcode.STD | Opcode.STDA | Opcode.STH | Opcode.STW
  | Opcode.STWA ->
    store ins bld
  | Opcode.STBY ->
    stby ins bld
  | Opcode.SUB ->
    sub ins bld
  | Opcode.SUBI ->
    subi ins bld
  | Opcode.SYNC | Opcode.SYNCDMA ->
    sync ins bld
  | Opcode.UADDCM ->
    uaddcm ins bld
  | Opcode.UXOR ->
    uxor ins bld
  | Opcode.XMPYU ->
    FloatLifter.xmpyu ins bld
  | Opcode.XOR ->
    xor ins bld
  (* The cache and translation-buffer maintenance, the performance monitor, the
     branch-target stack, the system-mask and interrupt-state instructions, and
     the identifying reads: none of them changes a register or a byte of memory
     that user code can observe, so an emulator of user code has nothing to do
     for them. *)
  | Opcode.DIAG | Opcode.FDC | Opcode.FDCE | Opcode.FIC | Opcode.FICE
  | Opcode.FID | Opcode.IDTLBT | Opcode.IITLBT | Opcode.MTSM | Opcode.PDC
  | Opcode.PDTLB | Opcode.PDTLBE | Opcode.PITLB | Opcode.PITLBE
  | Opcode.PMDIS | Opcode.PMENB | Opcode.PUSHBTS | Opcode.PUSHNOM
  | Opcode.POPBTS | Opcode.CLRBTS | Opcode.RFI | Opcode.RSM
  | Opcode.SSM ->
    nop ins bld
  | Opcode.PROBE | Opcode.PROBEI ->
    probe ins bld
  (* The privileged instructions user code can only reach to fault: the
     half-entry TLB inserts -- which is exactly what they are there for, since
     the atomic primitives put one after the test of their result so that a
     kernel error, which nullifies nothing, faults on the spot -- and the two
     that ask where in real memory an address lives. *)
  | Opcode.IITLBA | Opcode.IITLBP | Opcode.IDTLBA | Opcode.IDTLBP
  | Opcode.LCI | Opcode.LPA ->
    illegal ins bld
  (* Valid, but outside what this lifter models: the multimedia operations on
     packed halfwords, the decimal correction, and the coprocessor and
     special-function unit interfaces, which no unit BRemu provides answers. *)
  | Opcode.CLDD | Opcode.CLDW | Opcode.COPR | Opcode.CSTD | Opcode.CSTW
  | Opcode.DCOR | Opcode.HADD | Opcode.HAVG | Opcode.HSHL | Opcode.HSHLADD
  | Opcode.HSHR | Opcode.HSHRADD | Opcode.HSUB | Opcode.MIXH | Opcode.MIXW
  | Opcode.PERMH | Opcode.SPOP0 | Opcode.SPOP1 | Opcode.SPOP2 | Opcode.SPOP3
  | Opcode.STDBY ->
    unsupported ins bld
  | o ->
    raise (NotImplementedIRException(Disasm.opCodeToString o))

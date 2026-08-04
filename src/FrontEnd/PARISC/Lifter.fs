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
let translate (ins: Instruction) insLen bld =
  match ins.Opcode with
  | Opcode.ADD -> add ins insLen bld
  | Opcode.ADDB | Opcode.ADDIB -> addb ins insLen bld
  | Opcode.ADDI -> addi ins insLen bld
  | Opcode.ADDIL -> addil ins insLen bld
  | Opcode.AND -> ``and`` ins insLen bld
  | Opcode.ANDCM -> andcm ins insLen bld
  | Opcode.B -> b ins insLen bld
  | Opcode.BB -> bb ins insLen bld
  | Opcode.BE -> be ins insLen bld
  | Opcode.BLR -> blr ins insLen bld
  | Opcode.BREAK -> ``break`` ins insLen bld
  | Opcode.BV -> bv ins insLen bld
  | Opcode.BVE -> bve ins insLen bld
  | Opcode.CMPB | Opcode.CMPIB -> cmpb ins insLen bld
  | Opcode.CMPCLR | Opcode.CMPICLR -> cmpclr ins insLen bld
  | Opcode.DEPD | Opcode.DEPDI | Opcode.DEPW | Opcode.DEPWI ->
    dep ins insLen bld
  | Opcode.DS -> ds ins insLen bld
  | Opcode.EXTRD | Opcode.EXTRW -> extr ins insLen bld
  | Opcode.FABS -> FloatLifter.fabs ins insLen bld
  | Opcode.FADD -> FloatLifter.fadd ins insLen bld
  | Opcode.FCMP -> FloatLifter.fcmp ins insLen bld
  | Opcode.FCNV -> FloatLifter.fcnv ins insLen bld
  | Opcode.FCPY -> FloatLifter.fcpy ins insLen bld
  | Opcode.FDIV -> FloatLifter.fdiv ins insLen bld
  | Opcode.FLDD | Opcode.FLDW -> FloatLifter.fpLoad ins insLen bld
  | Opcode.FMPY -> FloatLifter.fmpy ins insLen bld
  | Opcode.FMPYADD | Opcode.FMPYSUB -> FloatLifter.fmpyadd ins insLen bld
  | Opcode.FMPYFADD | Opcode.FMPYNFADD -> FloatLifter.fmpyfadd ins insLen bld
  | Opcode.FNEG -> FloatLifter.fneg ins insLen bld
  | Opcode.FNEGABS -> FloatLifter.fnegabs ins insLen bld
  | Opcode.FRND -> FloatLifter.frnd ins insLen bld
  | Opcode.FSQRT -> FloatLifter.fsqrt ins insLen bld
  | Opcode.FSTD | Opcode.FSTW -> FloatLifter.fpStore ins insLen bld
  | Opcode.FTEST -> FloatLifter.ftest ins insLen bld
  | Opcode.LDB | Opcode.LDD | Opcode.LDDA | Opcode.LDH | Opcode.LDW
  | Opcode.LDWA -> load ins insLen bld
  | Opcode.LDCD | Opcode.LDCW -> ldcw ins insLen bld
  | Opcode.LDIL -> ldil ins insLen bld
  | Opcode.LDO -> ldo ins insLen bld
  | Opcode.LDSID -> ldsid ins insLen bld
  | Opcode.MFCTL | Opcode.MFIA -> mfctl ins insLen bld
  | Opcode.MFSP | Opcode.MTSP -> movsp ins insLen bld
  | Opcode.MOVB | Opcode.MOVIB -> movb ins insLen bld
  | Opcode.MTCTL -> mtctl ins insLen bld
  | Opcode.MTSARCM -> mtsarcm ins insLen bld
  | Opcode.OR -> ``or`` ins insLen bld
  | Opcode.SHLADD -> shladd ins insLen bld
  | Opcode.SHRPD | Opcode.SHRPW -> shrp ins insLen bld
  | Opcode.STB | Opcode.STD | Opcode.STDA | Opcode.STH | Opcode.STW
  | Opcode.STWA -> store ins insLen bld
  | Opcode.STBY -> stby ins insLen bld
  | Opcode.SUB -> sub ins insLen bld
  | Opcode.SUBI -> subi ins insLen bld
  | Opcode.SYNC | Opcode.SYNCDMA -> sync ins insLen bld
  | Opcode.UADDCM -> uaddcm ins insLen bld
  | Opcode.UXOR -> uxor ins insLen bld
  | Opcode.XMPYU -> FloatLifter.xmpyu ins insLen bld
  | Opcode.XOR -> xor ins insLen bld
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
  | Opcode.SSM -> nop ins insLen bld
  | Opcode.PROBE | Opcode.PROBEI -> probe ins insLen bld
  (* The privileged instructions user code can only reach to fault: the
     half-entry TLB inserts -- which is exactly what they are there for, since
     the atomic primitives put one after the test of their result so that a
     kernel error, which nullifies nothing, faults on the spot -- and the two
     that ask where in real memory an address lives. *)
  | Opcode.IITLBA | Opcode.IITLBP | Opcode.IDTLBA | Opcode.IDTLBP
  | Opcode.LCI | Opcode.LPA -> illegal ins insLen bld
  (* Valid, but outside what this lifter models: the multimedia operations on
     packed halfwords, the decimal correction, and the coprocessor and
     special-function unit interfaces, which no unit BRemu provides answers. *)
  | Opcode.CLDD | Opcode.CLDW | Opcode.COPR | Opcode.CSTD | Opcode.CSTW
  | Opcode.DCOR | Opcode.HADD | Opcode.HAVG | Opcode.HSHL | Opcode.HSHLADD
  | Opcode.HSHR | Opcode.HSHRADD | Opcode.HSUB | Opcode.MIXH | Opcode.MIXW
  | Opcode.PERMH | Opcode.SPOP0 | Opcode.SPOP1 | Opcode.SPOP2 | Opcode.SPOP3
  | Opcode.STDBY -> unsupported ins insLen bld
  | o -> raise (NotImplementedIRException(Disasm.opCodeToString o))

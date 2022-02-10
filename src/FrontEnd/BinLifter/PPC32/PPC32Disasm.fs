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

module B2R2.FrontEnd.BinLifter.PPC32.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter

let opCodeToString = function
  | Op.ADD -> "ADD"
  | Op.ADDdot -> "ADD."
  | Op.ADDO -> "ADDO"
  | Op.ADDOdot -> "ADDO."
  | Op.ADDC -> "ADDC"
  | Op.ADDCdot -> "ADDC."
  | Op.ADDCO -> "ADDCO"
  | Op.ADDCOdot -> "ADDCO."
  | Op.ADDE -> "ADDE"
  | Op.ADDEdot -> "ADDE."
  | Op.ADDEO -> "ADDEO"
  | Op.ADDEOdot -> "ADDEO."
  | Op.ADDME -> "ADDME"
  | Op.ADDMEdot -> "ADDME."
  | Op.ADDMEO -> "ADDMEO"
  | Op.ADDMEOdot -> "ADDMEO."
  | Op.ADDZE -> "ADDZE"
  | Op.ADDZEdot -> "ADDZE."
  | Op.ADDZEO -> "ADDZEO"
  | Op.ADDZEOdot -> "ADDZEO."
  | Op.DIVW -> "DIVW"
  | Op.DIVWdot -> "DIVW."
  | Op.DIVWO -> "DIVWO"
  | Op.DIVWOdot -> "DIVWO."
  | Op.DIVWU -> "DIVWU"
  | Op.DIVWUdot -> "DIVWU."
  | Op.DIVWUO -> "DIVWUO"
  | Op.DIVWUOdot -> "DIVWUO."
  | Op.MULLW -> "MULLW"
  | Op.MULLWdot -> "MULLW."
  | Op.MULLWO -> "MULLWO"
  | Op.MULLWOdot -> "MULLWO."
  | Op.NEG -> "NEG"
  | Op.NEGdot -> "NEG."
  | Op.NEGO -> "NEGO"
  | Op.NEGOdot -> "NEGO."
  | Op.SUBF -> "SUBF"
  | Op.SUBFdot -> "SUBF."
  | Op.SUBFO -> "SUBFO"
  | Op.SUBFOdot -> "SUBFO."
  | Op.SUBFC -> "SUBFC"
  | Op.SUBFCdot -> "SUBFC."
  | Op.SUBFCO -> "SUBFCO"
  | Op.SUBFCOdot -> "SUBFCO."
  | Op.SUBFE -> "SUBFE"
  | Op.SUBFEdot -> "SUBFE."
  | Op.SUBFEO -> "SUBFEO"
  | Op.SUBFEOdot -> "SUBFEO."
  | Op.SUBFME -> "SUBFME"
  | Op.SUBFMEdot -> "SUBFME."
  | Op.SUBFMEO -> "SUBFMEO"
  | Op.SUBFMEOdot -> "SUBFMEO."
  | Op.SUBFZE -> "SUBFZE"
  | Op.SUBFZEdot -> "SUBFZE."
  | Op.SUBFZEO -> "SUBFZEO"
  | Op.SUBFZEOdot -> "SUBFZEO."
  | Op.MULHW -> "MULHW"
  | Op.MULHWdot -> "MULHW."
  | Op.MULHWU -> "MULHWU"
  | Op.MULHWUdot -> "MULHWU."
  | Op.AND -> "AND"
  | Op.ANDdot -> "AND."
  | Op.ANDC -> "ANDC"
  | Op.ANDCdot -> "ANDC."
  | Op.CNTLZW -> "CNTLZW"
  | Op.CNTLZWdot -> "CNTLZW."
  | Op.DCBTST -> "DCBTST"
  | Op.DCBA -> "DCBA"
  | Op.DCBF -> "DCBF"
  | Op.DCBI -> "DCBI"
  | Op.ICBI -> "ICBI"
  | Op.DCBST -> "DCBST"
  | Op.DCBT -> "DCBT"
  | Op.DCBZ -> "DCBZ"
  | Op.ECIWX -> "ECIWX"
  | Op.ECOWX -> "ECOWX"
  | Op.EIEIO -> "EIEIO"
  | Op.EQV -> "EQV"
  | Op.EQVdot -> "EQV."
  | Op.EXTSB -> "EXTSB"
  | Op.EXTSBdot -> "EXTSB."
  | Op.EXTSH -> "EXTSH"
  | Op.EXTSHdot -> "EXTSH."
  | Op.LBZUX -> "LBZUX"
  | Op.LBZX -> "LBZX"
  | Op.LFDUX -> "LFDUX"
  | Op.LFDX -> "LFDX"
  | Op.LFSUX -> "LFSUX"
  | Op.LFSX -> "LFSX"
  | Op.LHAUX -> "LHAUX"
  | Op.LHAX -> "LHAX"
  | Op.LHBRX -> "LHBRX"
  | Op.LHZUX -> "LHZUX"
  | Op.LHZX -> "LHZX"
  | Op.LSWI -> "LSWI"
  | Op.LSWX -> "LSWX"
  | Op.LWARX -> "LWARX"
  | Op.LWBRX -> "LWBRX"
  | Op.LWZUX -> "LWZUX"
  | Op.LWZX -> "LWZX"
  | Op.CMP -> "CMP"
  | Op.CMPL ->"CMPL"
  | Op.MCRXR -> "MCRXR"
  | Op.MFCR -> "MFCR"
  | Op.MFMSR -> "MFMSR"
  | Op.MFSRIN -> "MFSRIN"
  | Op.MTMSR -> "MTMSR"
  | Op.MTSRIN -> "MTSRIN"
  | Op.NAND -> "NAND"
  | Op.NANDdot -> "NAND."
  | Op.NOR -> "NOR"
  | Op.NORdot -> "NOR."
  | Op.OR -> "OR"
  | Op.ORdot -> "OR."
  | Op.ORC -> "ORC"
  | Op.ORCdot -> "ORC."
  | Op.SLW -> "SLW"
  | Op.SLWdot -> "SLW."
  | Op.SRAW -> "SRAW"
  | Op.SRAWdot -> "SRAW."
  | Op.SRW -> "SRW"
  | Op.SRWdot -> "SRW."
  | Op.STBUX -> "STBUX"
  | Op.STBX -> "STBX"
  | Op.STFDUX -> "STFDUX"
  | Op.STFDX -> "STFDX"
  | Op.STFIWX -> "STFIWX"
  | Op.STWUX -> "STWUX"
  | Op.STFSUX -> "STFSUX"
  | Op.STWX -> "STWX"
  | Op.STFSX -> "STFSX"
  | Op.STHBRX -> "STHBRX"
  | Op.STHUX -> "STHUX"
  | Op.STHX -> "STHX"
  | Op.STWBRX -> "STWBRX"
  | Op.STWCXdot -> "STWCX."
  | Op.SYNC -> "SYNC"
  | Op.TLBIA -> "TLBIA"
  | Op.TLBIE -> "TLBIE"
  | Op.TLBSYNC -> "TLBSYNC"
  | Op.XOR -> "XOR"
  | Op.XORdot -> "XOR."
  | Op.STSWX -> "STSWX"
  | Op.CMPW -> "CMPW"
  | Op.CMPLW -> "CMPLW"
  | Op.TW -> "TW"
  | Op.TWEQ -> "TWEQ"
  | Op.TRAP -> "TRAP"
  | Op.MTCRF -> "MTCRF"
  | Op.MTSR -> "MTSR"
  | Op.MFSPR -> "MFSPR"
  | Op.MFXER -> "MFXER"
  | Op.MFLR -> "MFLR"
  | Op.MFCTR -> "MFCTR"
  | Op.MFTB -> "MFTB"
  | Op.MFTBU -> "MFTBU"
  | Op.MTSPR -> "MTSPR"
  | Op.MTXER -> "MTXER"
  | Op.MTLR -> "MTLR"
  | Op.MTCTR -> "MTCTR"
  | Op.MFSR -> "MFSR"
  | Op.STSWI -> "STSWI"
  | Op.SRAWI -> "SRAWI"
  | Op.SRAWIdot -> "SRAWI."
  | Op.FCMPU -> "FCMPU"
  | Op.FRSP -> "FRSP"
  | Op.FRSPdot -> "FRSP."
  | Op.FCTIW -> "FCTIW"
  | Op.FCTIWdot -> "FCTIW."
  | Op.FCTIWZ -> "FCTIWZ"
  | Op.FCTIWZdot -> "FCTIWZ."
  | Op.FDIV -> "FDIV"
  | Op.FDIVdot -> "FDIV."
  | Op.FSUB -> "FSUB"
  | Op.FSUBdot -> "FSUB."
  | Op.FADD -> "FADD"
  | Op.FADDdot -> "FADD."
  | Op.FSQRT -> "FSQRT"
  | Op.FSQRTdot -> "FSQRT."
  | Op.FSEL -> "FSEL"
  | Op.FSELdot -> "FSEL."
  | Op.FMUL -> "FMUL"
  | Op.FMULdot -> "FMUL."
  | Op.FRSQRTE -> "FRSQRTE"
  | Op.FRSQRTEdot -> "FRSQRTE."
  | Op.FMSUB -> "FMSUB"
  | Op.FMSUBdot -> "FMSUB."
  | Op.FMADD -> "FMADD"
  | Op.FMADDdot -> "FMADD."
  | Op.FNMSUB -> "FNMSUB"
  | Op.FNMSUBdot -> "FNMSUB."
  | Op.FNMADD -> "FNMADD"
  | Op.FNMADDdot -> "FNMADD."
  | Op.FCMPO -> "FCMPO"
  | Op.MTFSB1 -> "MTFSB1"
  | Op.MTFSB1dot -> "MTFSB1."
  | Op.FNEG -> "FNEG"
  | Op.FNEGdot -> "FNEG."
  | Op.MCRFS -> "MCRFS"
  | Op.MTFSB0 -> "MTFSB0"
  | Op.MTFSB0dot -> "MTFSB0."
  | Op.FMR -> "FMR"
  | Op.FMRdot -> "FMR."
  | Op.MTFSFI -> "MTFSFI"
  | Op.MTFSFIdot -> "MTFSFI."
  | Op.FNABS -> "FNABS"
  | Op.FNABSdot -> "FNABS."
  | Op.FABS -> "FABS"
  | Op.FABSdot -> "FABS."
  | Op.MFFS -> "MFFS"
  | Op.MFFSdot -> "MFFS."
  | Op.MTFSF -> "MTFSF"
  | Op.MTFSFdot -> "MTFSF."
  | _ -> Utils.impossible ()

let inline buildOpcode ins (builder: DisasmBuilder<_>) =
  let str = opCodeToString ins.Opcode
  builder.Accumulate AsmWordKind.Mnemonic str

let oprToString opr delim (builder: DisasmBuilder<_>) =
  match opr with
  | OpReg reg ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Variable (Register.toString reg)
  | Immediate imm ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (String.u64ToHex imm)

let buildOprs insInfo builder =
  match insInfo.Operands with
  | NoOperand -> ()
  | OneOperand opr ->
    oprToString opr " " builder
  | TwoOperands (opr1, opr2) ->
    oprToString opr1 " " builder
    oprToString opr2 ", " builder
  | ThreeOperands (opr1, opr2, opr3) ->
    oprToString opr1 " " builder
    oprToString opr2 ", " builder
    oprToString opr3 ", " builder
  | FourOperands (opr1, opr2, opr3, opr4) ->
    oprToString opr1 " " builder
    oprToString opr2 ", " builder
    oprToString opr3 ", " builder
    oprToString opr4 ", " builder

let disasm insInfo (builder: DisasmBuilder<_>) =
  if builder.ShowAddr then builder.AccumulateAddr () else ()
  buildOpcode insInfo builder
  buildOprs insInfo builder

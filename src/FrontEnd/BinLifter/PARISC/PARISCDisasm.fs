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

module B2R2.FrontEnd.BinLifter.PARISC.Disasm

// TODO Implement disasm logic

open B2R2
open B2R2.FrontEnd.Register
open B2R2.FrontEnd.BinLifter

let opCodeToString = function
  (* 3-Register Arithmetic & Logical Instructions *)
  | Op.ADD -> "add"
  | Op.ADDL -> "add,l"
  | Op.ADDC -> "add,c"
  | Op.SHLADD -> "shladd"
  | Op.SHLADDL -> "shladdl"
  | Op.SUB -> "sub"
  | Op.SUBB -> "sub,b"
  | Op.OR -> "or"
  | Op.XOR -> "xor"
  | Op.AND -> "and"
  | Op.ANDCM -> "andcm"
  | Op.UADDCM -> "uaddcm"
  | Op.UXOR -> "uxor"
  | Op.DS -> "ds"
  | Op.CMPCLR -> "cmpclr"
  | Op.DCOR -> "dcor"
  (* Immediate Arithmetic Instructions *)
  | Op.ADDI -> "addi"
  | Op.SUBI -> "subi"
  | Op.CMPICLR -> "cmpiclr"
  (* Shift Pair, Extract & Deposit Instructions *)
  | Op.SHRPD -> "shrpd"
  | Op.SHRPW -> "shrpw"
  | Op.EXTRD -> "extrd"
  | Op.EXTRW -> "extrw,u"
  | Op.DEPD -> "depd"
  | Op.DEPDI -> "depdi"
  | Op.DEPW -> "depw,z"
  | Op.DEPWI -> "depwi"
  (* Parallel Halfword Arithmetic Instructions *)
  | Op.HADD -> "hadd"
  | Op.HSUB -> "hsub"
  | Op.HAVG -> "havg"
  (* Parallel Halfword Shift Instructions *)
  | Op.HSHLADD -> "hshladd"
  | Op.HSHRADD -> "hshradd"
  | Op.HSHL -> "hshl"
  | Op.HSHR -> "hshr"
  (* Rearrangement Instructions *)
  | Op.PERMH -> "permh"
  | Op.MIXH -> "mixh"
  | Op.MIXW -> "mixw"
  (* Load/Store Instructions *)
  | Op.LDB -> "ldb"
  | Op.LDBS -> "ldbs"
  | Op.STB -> "stb"
  | Op.STBS -> "stbs"
  | Op.LDH -> "ldh"
  | Op.STH -> "sth"
  | Op.LDW -> "ldw"
  | Op.LDWS -> "ldws"
  | Op.STW -> "stw"
  | Op.STWS -> "sts"
  | Op.LDD -> "ldd"
  | Op.STD -> "std"
  (* Load/Store Absolute Instructions *)
  | Op.LDWA -> "ldwa"
  | Op.STWA -> "stwa"
  | Op.LDDA -> "ldda"
  | Op.STDA -> "stda"
  (* Load and Clear Instructions *)
  | Op.LDCW -> "ldcw"
  | Op.LDCD -> "ldcd"
  (* Store Bytes/DoubleWord Bytes Instructions *)
  | Op.STBY -> "stby"
  | Op.STDBY -> "stdby"
  (* Long Immediate Instructions *)
  | Op.LDO -> "ldo"
  | Op.LDIL -> "ldil"
  | Op.ADDIL -> "addil"
  (* Unconditional Local Branches *)
  | Op.BL -> "b,l"
  | Op.BLR -> "blr"
  | Op.BV -> "bv"
  (* Unconditional External Branches *)
  | Op.BE -> "be"
  | Op.BVE -> "bve"
  (* Conditional Local Branches *)
  | Op.ADDB -> "addb"
  | Op.ADDIB -> "addib"
  | Op.BB -> "bb"
  | Op.CMPB -> "cmpb"
  | Op.CMPIB -> "cmpib"
  | Op.MOVB -> "movb"
  | Op.MOVIB -> "movib"
  (* Special Register Move Instructions *)
  | Op.LDSID -> "ldsid"
  | Op.MTSP -> "mtsp"
  | Op.MFSP -> "mfsp"
  | Op.MTCTL -> "mtsar"
  | Op.MFCTL -> "mfctl"
  | Op.MTSARCM -> "mtsarcm"
  | Op.MFIA -> "mfia"
  (* System Mask Control Instructions *)
  | Op.SSM -> "ssm"
  | Op.RSM -> "rsm"
  | Op.MTSM -> "mtsm"
  (* Return From Interrupt & Break Instructions *)
  | Op.RFI -> "rfi"
  | Op.BREAK -> "break"
  (* Memory Management Instructions *)
  | Op.SYNC -> "sync"
  | Op.SYNCDMA -> "syncdma"
  | Op.PROBE -> "probe"
  | Op.PROBEI -> "probei"
  | Op.LPA -> "lpa"
  | Op.LCI -> "lci"
  | Op.PDTLB -> "pdtlb"
  | Op.PITLB -> "pitlb"
  | Op.PDTLBE -> "pdtlbe"
  | Op.PITLBE -> "pitlbe"
  | Op.IDTLBT -> "idtlbt"
  | Op.IITLBT -> "iitlbt"
  | Op.PDC -> "pdc"
  | Op.FDC -> "fdc"
  | Op.FIC -> "fic"
  | Op.FDCE -> "fdce"
  | Op.FICE -> "fice"
  | Op.PUSHBTS -> "pushbts"
  | Op.PUSHNOM -> "pushnom"
  (* Implementation-Dependent Instruction *)
  | Op.DIAG -> "diag"
  (* Special Function Instructions *)
  | Op.SPOP0 -> "spop0"
  | Op.SPOP1 -> "spop1"
  | Op.SPOP2 -> "spop2"
  | Op.SPOP3 -> "spop3"
  (* Coprocessor Instructions *)
  | Op.COPR -> "copr"
  | Op.CLDD -> "cldd"
  | Op.CLDW -> "cldw"
  | Op.CSTD -> "cstd"
  | Op.CSTW -> "cstw"
  (* Floating-Point Load and Store Instructions *)
  | Op.FLDW -> "fldw"
  | Op.FLDD -> "fldd"
  | Op.FSTW -> "fstw"
  | Op.FSTD -> "fstd"
  (* Floating-Point Multiply/Add Instructions *)
  | Op.FMPYADD -> "fmpyadd"
  | Op.FMPYSUB -> "fmpysub"
  (* Floating-Point Sub-op Multiply/Add Instructions *)
  | Op.FMPYFADD -> "fmpyfadd"
  | Op.FMPYNFADD -> "fmpynfadd"
  (* Floating-Point Conversion and Arithmetic Instructions *)
  | Op.FID -> "fid"
  | Op.FCPYDBL -> "fcpy,dbl"
  | Op.FCPYSGL -> "fcpy,sgl"
  | Op.FABS -> "fabs"
  | Op.FSQRT -> "fsqrt"
  | Op.FRND -> "frnd"
  | Op.FNEG -> "fneg"
  | Op.FNEGABS -> "fnegabs"
  (* Floating-Point Conversion Instructions *)
  | Op.FCNV -> "fcnv"
  (* Floating-Point Compare and Test Instructions *)
  | Op.FCMP -> "fcmp"
  | Op.FTEST -> "ftest"
  (* Floating-Point Arithmetic Instructions *)
  | Op.FADD -> "fadd"
  | Op.FSUB -> "fsub"
  | Op.FMPY -> "fmpy"
  | Op.FDIV -> "fdiv"
  (* Floating-Point interruptions and exceptions *)
  | Op.PMENB -> "pmenb"
  | Op.PMDIS -> "pmdis"
  (*  Default case for unknown opcodes  *)
  | _ -> failwith "Unknown opcode"

let roundModeToString = function
  | RoundMode.RN -> "rn"
  | RoundMode.RZ -> "rz"
  | RoundMode.RP -> "rp"
  | RoundMode.RM -> "rm"
  | _ -> failwith "Invalid rounding mode"

let condToString = function
  | PARISCCondition.NV -> ""
  | PARISCCondition.EQ -> "="
  | PARISCCondition.LT -> "<"
  | PARISCCondition.LTU -> "<<"
  | PARISCCondition.LTE -> "<="
  | PARISCCondition.LTEU -> "<<="
  | PARISCCondition.GT -> ">"
  | PARISCCondition.GTU -> ">>"
  | PARISCCondition.GTE -> ">="
  | PARISCCondition.GTEU -> ">>="
  | PARISCCondition.TR -> "tr"
  | PARISCCondition.NEQ -> "<>"
  | _ -> failwith "Invalid condition"

let shtostring = function
  | SHIFTST.SARSHFT -> "sar"
  | _ -> failwith "invalid sarshift"

let inline buildOpcode ins (builder: DisasmBuilder) =
  let str = opCodeToString ins.Opcode
  builder.Accumulate AsmWordKind.Mnemonic str

let inline relToString pc offset (builder: DisasmBuilder) =
  let targetAddr = pc + uint64 offset
  builder.Accumulate AsmWordKind.Value (HexString.ofUInt64 targetAddr)

let oprToString insInfo opr delim (builder: DisasmBuilder) =
  match opr with
  | OpReg reg ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Variable (PARISCRegister.String reg)
  | OpImm imm
  | OpShiftAmount imm ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (HexString.ofUInt64 imm)
  | OpMem (b, None, _) ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.String "("
    builder.Accumulate AsmWordKind.Variable (PARISCRegister.String b)
    builder.Accumulate AsmWordKind.String ")"
  | OpMem (b, Some (Imm off), _) ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (off.ToString ("D"))
    builder.Accumulate AsmWordKind.String "("
    builder.Accumulate AsmWordKind.Variable (PARISCRegister.String b)
    builder.Accumulate AsmWordKind.String ")"
  | OpMem (b, Some (Reg off), _) ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Variable (PARISCRegister.String off)
    builder.Accumulate AsmWordKind.String "("
    builder.Accumulate AsmWordKind.Variable (PARISCRegister.String b)
    builder.Accumulate AsmWordKind.String ")"
  | OpAddr (Relative offset) ->
    builder.Accumulate AsmWordKind.String delim
    relToString insInfo.Address offset builder
  | OpAddr (RelativeBase (b, off)) ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (off.ToString ("D"))
    builder.Accumulate AsmWordKind.String "("
    builder.Accumulate AsmWordKind.Variable (PARISCRegister.String b)
    builder.Accumulate AsmWordKind.String ")"
  | OpAtomMemOper (aq, rl) ->
    if aq then builder.Accumulate AsmWordKind.String "aq"
    if rl then builder.Accumulate AsmWordKind.String "rl"
  | OpRoundMode (rm) ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.String (roundModeToString rm)
  | OpCSR (csr) ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (HexString.ofUInt16 csr)
  | OpCond (cond) ->
    match cond with
    | PARISCCondition.NV ->
      builder.Accumulate AsmWordKind.String (condToString cond)
    | _ ->
      builder.Accumulate AsmWordKind.String ","
      builder.Accumulate AsmWordKind.String (condToString cond)
  | OpSARSHIFT (sarshiftstr) ->
    builder.Accumulate AsmWordKind.String ","
    builder.Accumulate AsmWordKind.String (shtostring sarshiftstr)

let buildOprs insInfo builder =
  match insInfo.Operands with
  | NoOperand -> ()
  | OneOperand opr ->
    oprToString insInfo opr " " builder
  | TwoOperands (opr1, opr2) ->
    oprToString insInfo opr1 " " builder
    oprToString insInfo opr2 ", " builder
  | ThreeOperands (opr1, opr2, opr3) ->
    oprToString insInfo opr1 " " builder
    oprToString insInfo opr2 ", " builder
    oprToString insInfo opr3 ", " builder
  | FourOperands (opr1, opr2, opr3, opr4) ->
    oprToString insInfo opr1 " " builder
    oprToString insInfo opr2 ", " builder
    oprToString insInfo opr3 ", " builder
    oprToString insInfo opr4 ", " builder
  | FiveOperands (opr1, opr2, opr3, opr4, opr5) ->
    oprToString insInfo opr1 " " builder
    oprToString insInfo opr2 ", " builder
    oprToString insInfo opr3 ", " builder
    oprToString insInfo opr4 ", " builder
    oprToString insInfo opr5 ", " builder

let disasm insInfo (builder: DisasmBuilder) =
  if builder.ShowAddr then builder.AccumulateAddr () else ()
  buildOpcode insInfo builder
  buildOprs insInfo builder

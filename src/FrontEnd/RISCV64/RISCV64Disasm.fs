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

module B2R2.FrontEnd.RISCV64.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.BitData

let opCodeToString = function
  | Op.LUI -> "lui"
  | Op.AUIPC -> "auipc"
  | Op.JAL -> "jal"
  | Op.JALR -> "jalr"
  | Op.BEQ -> "beq"
  | Op.BNE -> "bne"
  | Op.BLT -> "blt"
  | Op.BGE -> "bge"
  | Op.BLTU -> "bltu"
  | Op.BGEU -> "bgeu"
  | Op.LB -> "lb"
  | Op.LH -> "lh"
  | Op.LW -> "lw"
  | Op.LBU -> "lbu"
  | Op.LHU -> "lhu"
  | Op.SB -> "sb"
  | Op.SH -> "sh"
  | Op.SW -> "sw"
  | Op.ADDI -> "addi"
  | Op.SLTI -> "slti"
  | Op.SLTIU -> "sltiu"
  | Op.XORI -> "xori"
  | Op.ORI -> "ori"
  | Op.ANDI -> "andi"
  | Op.SLLI -> "slli"
  | Op.SRLI -> "srli"
  | Op.SRAI -> "srai"
  | Op.ADD -> "add"
  | Op.SUB -> "sub"
  | Op.SLL -> "sll"
  | Op.SLT -> "slt"
  | Op.SLTU -> "sltu"
  | Op.XOR -> "xor"
  | Op.SRL -> "srl"
  | Op.SRA -> "sra"
  | Op.OR -> "or"
  | Op.AND -> "and"
  | Op.FENCE -> "fence"
  | Op.FENCEdotI -> "fence.i"
  | Op.ECALL -> "ecall"
  | Op.EBREAK -> "ebreak"
  | Op.CSRRW -> "csrrw"
  | Op.CSRRS -> "csrrs"
  | Op.CSRRC -> "csrrc"
  | Op.CSRRWI -> "csrrwi"
  | Op.CSRRSI -> "csrrsi"
  | Op.CSRRCI -> "csrrci"
  (* RV64I Base Instruction Set *)
  | Op.LWU -> "lwu"
  | Op.LD -> "ld"
  | Op.SD -> "sd"
  | Op.ADDIW -> "addiw"
  | Op.SLLIW -> "slliw"
  | Op.SRLIW -> "srliw"
  | Op.SRAIW -> "sraiw"
  | Op.ADDW -> "addw"
  | Op.SUBW -> "subw"
  | Op.SLLW -> "sllw"
  | Op.SRLW -> "srlw"
  | Op.SRAW -> "sraw"
  (* RV32M Standard Extension *)
  | Op.MUL -> "mul"
  | Op.MULH -> "mulh"
  | Op.MULHSU -> "mulhsu"
  | Op.MULHU -> "mulhu"
  | Op.DIV -> "div"
  | Op.DIVU -> "divu"
  | Op.REM -> "rem"
  | Op.REMU -> "remu"
  (* RV64M Standard Extension *)
  | Op.MULW -> "mulw"
  | Op.DIVW -> "divw"
  | Op.DIVUW -> "divuw"
  | Op.REMW -> "remw"
  | Op.REMUW -> "remuw"
  (* RV32A Standard Extension *)
  | Op.LRdotW -> "lr.w"
  | Op.SCdotW -> "sc.w"
  | Op.AMOSWAPdotW -> "amoswap.w"
  | Op.AMOADDdotW -> "amoadd.w"
  | Op.AMOXORdotW -> "amoxor.w"
  | Op.AMOANDdotW -> "amoand.w"
  | Op.AMOORdotW -> "amoor.w"
  | Op.AMOMINdotW -> "amomin.w"
  | Op.AMOMAXdotW -> "amomax.w"
  | Op.AMOMINUdotW -> "amomin.w"
  | Op.AMOMAXUdotW -> "amomax.w"
  (* RV64A Standard Extension *)
  | Op.LRdotD -> "lr.d"
  | Op.SCdotD -> "sc.d"
  | Op.AMOSWAPdotD -> "amoswap.d"
  | Op.AMOADDdotD -> "amoadd.d"
  | Op.AMOXORdotD -> "amoxor.d"
  | Op.AMOANDdotD -> "amoand.d"
  | Op.AMOORdotD -> "amoor.d"
  | Op.AMOMINdotD -> "amomin.d"
  | Op.AMOMAXdotD -> "amomax.d"
  | Op.AMOMINUdotD -> "amominu.d"
  | Op.AMOMAXUdotD -> "amomaxu.d"
  (* RV32F Standard Extension *)
  | Op.FLW -> "flw"
  | Op.FSW -> "fsw"
  | Op.FMADDdotS -> "fmadd.s"
  | Op.FMSUBdotS -> "fmsub.s"
  | Op.FNMSUBdotS -> "fnmsub.s"
  | Op.FNMADDdotS -> "fnmadd.s"
  | Op.FADDdotS -> "fadd.s"
  | Op.FSUBdotS -> "fsub.s"
  | Op.FMULdotS -> "fmul.s"
  | Op.FDIVdotS -> "fdiv.s"
  | Op.FSQRTdotS -> "fsqrt.s"
  | Op.FSGNJdotS -> "fsgnj.s"
  | Op.FSGNJNdotS -> "fsgnjn.s"
  | Op.FSGNJXdotS -> "fsgnjx.s"
  | Op.FMINdotS -> "fmin.s"
  | Op.FMAXdotS -> "fmax.s"
  | Op.FCVTdotWdotS -> "fcvt.w.s"
  | Op.FCVTdotWUdotS -> "fcvt.wu.s"
  | Op.FMVdotXdotW -> "fmv.x.w"
  | Op.FEQdotS -> "feq.s"
  | Op.FLTdotS -> "flt.s"
  | Op.FLEdotS -> "fle.s"
  | Op.FCLASSdotS -> "fclass.s"
  | Op.FCVTdotSdotW -> "fcvt.w.s"
  | Op.FCVTdotSdotWU -> "fcvt.s.wu"
  | Op.FMVdotWdotX -> "fmv.w.x"
  (* RV64F Standard Extension *)
  | Op.FCVTdotLdotS -> "fcvt.l.s"
  | Op.FCVTdotLUdotS -> "fcvt.lu.s"
  | Op.FCVTdotSdotL -> "fcvt.s.l"
  | Op.FCVTdotSdotLU -> "fcvt.s.lu"
  (* RV32D Standard Extension *)
  | Op.FLD -> "fld"
  | Op.FSD -> "fsd"
  | Op.FMADDdotD -> "fmadd.d"
  | Op.FMSUBdotD -> "fmsub.d"
  | Op.FNMSUBdotD -> "fnmsub.d"
  | Op.FNMADDdotD -> "fnmadd.d"
  | Op.FADDdotD -> "fadd.d"
  | Op.FSUBdotD -> "fsub.d"
  | Op.FMULdotD -> "fmul.d"
  | Op.FDIVdotD -> "fdiv.d"
  | Op.FSQRTdotD -> "fsqrt.d"
  | Op.FSGNJdotD -> "fsgnj.d"
  | Op.FSGNJNdotD -> "fsgnjn.d"
  | Op.FSGNJXdotD -> "fsgnjx.d"
  | Op.FMINdotD -> "fmin.d"
  | Op.FMAXdotD -> "fmax.d"
  | Op.FCVTdotSdotD -> "fcvt.s.d"
  | Op.FCVTdotDdotS -> "fcvt.d.s"
  | Op.FEQdotD -> "feq.d"
  | Op.FLTdotD -> "flt.d"
  | Op.FLEdotD -> "fle.d"
  | Op.FCLASSdotD -> "fclass.d"
  | Op.FCVTdotWdotD -> "fcvt.w.d"
  | Op.FCVTdotWUdotD -> "fcvt.wu.d"
  | Op.FCVTdotDdotW -> "fcvt.d.w"
  | Op.FCVTdotDdotWU -> "fcvt.d.wu"
  (* RV64D Standard Extension *)
  | Op.FCVTdotLdotD -> "fcvt.l.d"
  | Op.FCVTdotLUdotD -> "fcvt.lu.d"
  | Op.FMVdotXdotD -> "fmv.x.d"
  | Op.FCVTdotDdotL -> "fcvt.d.l"
  | Op.FCVTdotDdotLU -> "fcvt.d.lu"
  | Op.FMVdotDdotX -> "fmv.d.x"
  | Op.FENCEdotTSO -> "fence.tso"
  | Op.CdotADDI4SPN -> "addi"
  | Op.CdotFLD -> "fld"
  | Op.CdotLW -> "lw"
  | Op.CdotLD -> "ld"
  | Op.CdotFSD -> "fsd"
  | Op.CdotSW -> "sw"
  | Op.CdotSD -> "sd"
  | Op.CdotNOP -> "nop"
  | Op.CdotADDI -> "addi"
  | Op.CdotADDIW -> "addiw"
  | Op.CdotLI -> "addi"
  | Op.CdotADDI16SP -> "addi"
  | Op.CdotLUI -> "lui"
  | Op.CdotSRLI -> "srli"
  | Op.CdotSRAI -> "srai"
  | Op.CdotANDI -> "andi"
  | Op.CdotSUB -> "sub"
  | Op.CdotXOR -> "xor"
  | Op.CdotOR -> "or"
  | Op.CdotAND -> "and"
  | Op.CdotSUBW -> "subw"
  | Op.CdotADDW -> "addw"
  | Op.CdotJ -> "jal"
  | Op.CdotBEQZ -> "beq"
  | Op.CdotBNEZ -> "bne"
  | Op.CdotSLLI -> "slli"
  | Op.CdotFLDSP -> "fld"
  | Op.CdotLWSP -> "lw"
  | Op.CdotLDSP -> "ld"
  | Op.CdotJR -> "jalr"
  | Op.CdotMV -> "add"
  | Op.CdotEBREAK -> "ebreak"
  | Op.CdotJALR -> "jalr"
  | Op.CdotADD -> "add"
  | Op.CdotFSDSP -> "fsd"
  | Op.CdotSWSP -> "sw"
  | Op.CdotSDSP -> "sd"
  | _ -> Terminator.impossible ()

let roundModeToString = function
  | RoundMode.RNE -> "rne"
  | RoundMode.RTZ -> "rtz"
  | RoundMode.RDN -> "rdn"
  | RoundMode.RUP -> "rup"
  | RoundMode.RMM -> "rmm"
  | RoundMode.DYN -> ""
  | _ -> Terminator.impossible ()

let fenceMaskToString x =
  let bin = x |> uint32
  let i = if pickBit bin 3u = 1u then "i" else ""
  let o = if pickBit bin 2u = 1u then "o" else ""
  let r = if pickBit bin 1u = 1u then "r" else ""
  let w = if pickBit bin 0u = 1u then "w" else ""
  i + o + r + w

let inline buildOpcode ins (builder: IDisasmBuilder) =
  let str = opCodeToString ins.Opcode
  builder.Accumulate AsmWordKind.Mnemonic str

let inline relToString pc offset (builder: IDisasmBuilder) =
  let targetAddr = pc + uint64 offset
  builder.Accumulate AsmWordKind.Value (HexString.ofUInt64 targetAddr)

let oprToString insInfo opr delim (builder: IDisasmBuilder) =
  match opr with
  | OpReg reg ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Variable (Register.toString reg)
  | OpImm imm
  | OpShiftAmount imm ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (HexString.ofUInt64 imm)
  | OpMem (b, None, _) ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.String "("
    builder.Accumulate AsmWordKind.Variable (Register.toString b)
    builder.Accumulate AsmWordKind.String ")"
  | OpMem (b, Some (Imm off), _) ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (off.ToString ("D"))
    builder.Accumulate AsmWordKind.String "("
    builder.Accumulate AsmWordKind.Variable (Register.toString b)
    builder.Accumulate AsmWordKind.String ")"
  | OpAddr (Relative offset) ->
    builder.Accumulate AsmWordKind.String delim
    relToString insInfo.Address offset builder
  | OpAddr (RelativeBase (b, off)) ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (off.ToString ("D"))
    builder.Accumulate AsmWordKind.String "("
    builder.Accumulate AsmWordKind.Variable (Register.toString b)
    builder.Accumulate AsmWordKind.String ")"
  | OpAtomMemOper (aq, rl) ->
    if aq then builder.Accumulate AsmWordKind.String "aq"
    if rl then builder.Accumulate AsmWordKind.String "rl"
  | OpFenceMask (pred, succ) ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.String (fenceMaskToString pred)
    builder.Accumulate AsmWordKind.String ","
    builder.Accumulate AsmWordKind.String (fenceMaskToString succ)
  | OpRoundMode (rm) ->
    if rm <> RoundMode.DYN then
      builder.Accumulate AsmWordKind.String delim
      builder.Accumulate AsmWordKind.String (roundModeToString rm)
    else ()
  | OpCSR (csr) ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (HexString.ofUInt16 csr)

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

let disasm insInfo (builder: IDisasmBuilder) =
  builder.AccumulateAddrMarker insInfo.Address
  buildOpcode insInfo builder
  buildOprs insInfo builder

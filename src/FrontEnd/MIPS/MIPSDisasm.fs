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

module internal B2R2.FrontEnd.MIPS.Disasm

open B2R2.FrontEnd

let condToString = function
  | Condition.F -> ".f"
  | Condition.UN -> ".un"
  | Condition.EQ -> ".eq"
  | Condition.GE -> ".ge"
  | Condition.LT -> ".lt"
  | Condition.LE -> ".le"
  | Condition.NE -> ".ne"
  | _ -> raise InvalidConditionException

let fmtToString = function
  | Fmt.S -> ".s"
  | Fmt.D -> ".d"
  | Fmt.W -> ".w"
  | Fmt.L -> ".l"
  | Fmt.PS -> ".ps"
  | Fmt.OB -> ".ob"
  | Fmt.QH -> ".qh"
  | Fmt.UNINTERPRETED_WORD -> ".uninterpreted_word"
  | Fmt.UNINTERPRETED_DOUBLEWORD -> ".uninterpreted_doubleword"
  | _ -> raise InvalidFmtException

let opCodeToString = function
  | Op.ADD -> "add"
  | Op.ADDIU -> "addiu"
  | Op.ADDU -> "addu"
  | Op.ALIGN -> "align"
  | Op.AND -> "and"
  | Op.ANDI -> "andi"
  | Op.AUI -> "aui"
  | Op.B -> "b"
  | Op.BAL -> "bal"
  | Op.BC1F -> "bc1f"
  | Op.BC1T -> "bc1t"
  | Op.BEQ -> "beq"
  | Op.BGEZAL -> "bgezal"
  | Op.BGEZ -> "bgez"
  | Op.BGTZ -> "bgtz"
  | Op.BITSWAP -> "bitswap"
  | Op.BLEZ -> "blez"
  | Op.BLTZ -> "bltz"
  | Op.BNE -> "bne"
  | Op.C -> "c"
  | Op.CFC1 -> "cfc1"
  | Op.CLZ -> "clz"
  | Op.CTC1 -> "ctc1"
  | Op.CVTD -> "cvt.d"
  | Op.CVTS -> "cvt.s"
  | Op.DADDIU -> "daddiu"
  | Op.DADDU -> "daddu"
  | Op.DALIGN -> "dalign"
  | Op.DBITSWAP -> "dbitswap"
  | Op.DCLZ -> "dclz"
  | Op.DDIVU -> "ddivu"
  | Op.DEXT -> "dext"
  | Op.DEXTM -> "dextm"
  | Op.DEXTU -> "dextu"
  | Op.DINS -> "dins"
  | Op.DINSM -> "dinsm"
  | Op.DINSU -> "dinsu"
  | Op.DIV -> "div"
  | Op.DIVU -> "divu"
  | Op.DMFC1 -> "dmfc1"
  | Op.DMTC1 -> "dmtc1"
  | Op.DMULT -> "dmult"
  | Op.DMULTU -> "dmultu"
  | Op.DROTR -> "drotr"
  | Op.DSLL -> "dsll"
  | Op.DSLL32 -> "dsll32"
  | Op.DSLLV -> "dsllv"
  | Op.DSRA -> "dsra"
  | Op.DSRA32 -> "dsra32"
  | Op.DSRL -> "dsrl"
  | Op.DSRL32 -> "dsrl32"
  | Op.DSRLV -> "dsrlv"
  | Op.DSUBU -> "dsubu"
  | Op.EHB -> "ehb"
  | Op.EXT -> "ext"
  | Op.INS -> "ins"
  | Op.JALR -> "jalr"
  | Op.JALRHB -> "jalr.hb"
  | Op.JR -> "jr"
  | Op.JRHB -> "jr.hb"
  | Op.LB -> "lb"
  | Op.LBU -> "lbu"
  | Op.LD -> "ld"
  | Op.LDC1 -> "ldc1"
  | Op.LH -> "lh"
  | Op.LHU -> "lhu"
  | Op.LUI -> "lui"
  | Op.LW -> "lw"
  | Op.LWC1 -> "lwc1"
  | Op.LWU -> "lwu"
  | Op.MADD -> "madd"
  | Op.MFC1 -> "mfc1"
  | Op.MFHI -> "mfhi"
  | Op.MFLO -> "mflo"
  | Op.MOV -> "mov"
  | Op.MOVN -> "movn"
  | Op.MOVZ -> "movz"
  | Op.MTC1 -> "mtc1"
  | Op.MUL -> "mul"
  | Op.MULT -> "mult"
  | Op.MULTU -> "multu"
  | Op.NOP -> "nop"
  | Op.NOR -> "nor"
  | Op.OR -> "or"
  | Op.ORI -> "ori"
  | Op.PAUSE -> "pause"
  | Op.ROTR -> "rotr"
  | Op.SB -> "sb"
  | Op.SD -> "sd"
  | Op.SDC1 -> "sdc1"
  | Op.SDL -> "sdl"
  | Op.SDR -> "sdr"
  | Op.SEB -> "seb"
  | Op.SEH -> "seh"
  | Op.SH -> "sh"
  | Op.SLL -> "sll"
  | Op.SLLV -> "sllv"
  | Op.SLT -> "slt"
  | Op.SLTI -> "slti"
  | Op.SLTIU -> "sltiu"
  | Op.SLTU -> "sltu"
  | Op.SRA -> "sra"
  | Op.SRL -> "srl"
  | Op.SRLV -> "srlv"
  | Op.SSNOP -> "ssnop"
  | Op.SUB -> "sub"
  | Op.SUBU -> "subu"
  | Op.SW -> "sw"
  | Op.SWC1 -> "swc1"
  | Op.SWL -> "swl"
  | Op.SWR -> "swr"
  | Op.TEQ -> "teq"
  | Op.TRUNCL -> "trunc.l"
  | Op.TRUNCW -> "trunc.w"
  | Op.WSBH -> "wsbh"
  | Op.XOR -> "xor"
  | Op.XORI -> "xori"
  | _ -> failwith "Unknown opcode encountered."

let inline appendCond insInfo opcode =
  match insInfo.Condition with
  | None -> opcode
  | Some c -> opcode + condToString c

let inline appendFmt insInfo opcode =
  match insInfo.Fmt with
  | None -> opcode
  | Some f -> opcode + fmtToString f

let inline buildOpcode ins builder acc =
  let str = opCodeToString ins.Opcode |> appendCond ins |> appendFmt ins
  builder AsmWordKind.Mnemonic str acc

let inline relToString pc offset builder acc =
  let targetAddr = pc + uint64 offset
  builder AsmWordKind.Value ("0x" + targetAddr.ToString("X")) acc

let oprToString insInfo opr delim builder acc =
  match opr with
  | OpReg reg ->
    builder AsmWordKind.String delim acc
    |> builder AsmWordKind.Variable (Register.toString reg)
  | Immediate imm
  | ShiftAmount imm ->
    builder AsmWordKind.String delim acc
    |> builder AsmWordKind.Value ("0x" + imm.ToString ("X"))
  | Memory (b, off, _) ->
    builder AsmWordKind.String delim acc
    |> builder AsmWordKind.Value (off.ToString ("D"))
    |> builder AsmWordKind.String "("
    |> builder AsmWordKind.Variable (Register.toString b)
    |> builder AsmWordKind.String ")"
  | Address (Relative offset) ->
    builder AsmWordKind.String delim acc
    |> relToString insInfo.Address offset builder
  // Never gets matched. Only used in intermediate stage mips assembly parser.
  | GoToLabel _ -> raise InvalidOperandException

let buildOprs insInfo builder acc =
  match insInfo.Operands with
  | NoOperand -> acc
  | OneOperand opr ->
    oprToString insInfo opr " " builder acc
  | TwoOperands (opr1, opr2) ->
    oprToString insInfo opr1 " " builder acc
    |> oprToString insInfo opr2 ", " builder
  | ThreeOperands (opr1, opr2, opr3) ->
    oprToString insInfo opr1 " " builder acc
    |> oprToString insInfo opr2 ", " builder
    |> oprToString insInfo opr3 ", " builder
  | FourOperands (opr1, opr2, opr3, opr4) ->
    oprToString insInfo opr1 " " builder acc
    |> oprToString insInfo opr2 ", " builder
    |> oprToString insInfo opr3 ", " builder
    |> oprToString insInfo opr4 ", " builder

let disasm showAddr wordSize insInfo builder acc =
  let pc = insInfo.Address
  DisasmBuilder.addr pc wordSize showAddr builder acc
  |> buildOpcode insInfo builder
  |> buildOprs insInfo builder

// vim: set tw=80 sts=2 sw=2:

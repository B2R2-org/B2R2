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

open B2R2
open B2R2.FrontEnd.BinLifter

let condToString = function
  | Condition.F -> ".f"
  | Condition.UN -> ".un"
  | Condition.EQ -> ".eq"
  | Condition.UEQ -> ".ueq"
  | Condition.OLT -> ".olt"
  | Condition.ULT -> ".ult"
  | Condition.OLE -> ".ole"
  | Condition.ULE -> ".ule"
  | Condition.SF -> ".sf"
  | Condition.NGLE -> ".ngle"
  | Condition.SEQ -> ".seq"
  | Condition.NGL -> ".ngl"
  | Condition.LT -> ".lt"
  | Condition.NGE -> ".nge"
  | Condition.LE -> ".le"
  | Condition.NGT -> ".ngt"
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
  | Op.ABS -> "abs"
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
  | Op.BC3F -> "bc3f"
  | Op.BC3FL -> "bc3fl"
  | Op.BC3T -> "bc3t"
  | Op.BC3TL -> "bc3tl"
  | Op.BEQ -> "beq"
  | Op.BEQL -> "beql"
  | Op.BGEZ -> "bgez"
  | Op.BGEZAL -> "bgezal"
  | Op.BGTZ -> "bgtz"
  | Op.BITSWAP -> "bitswap"
  | Op.BLEZ -> "blez"
  | Op.BLTZ -> "bltz"
  | Op.BLTZAL -> "bltzal"
  | Op.BNE -> "bne"
  | Op.BNEL -> "bnel"
  | Op.BREAK -> "break"
  | Op.C -> "c"
  | Op.CFC1 -> "cfc1"
  | Op.CLZ -> "clz"
  | Op.CTC1 -> "ctc1"
  | Op.CVTD -> "cvt.d"
  | Op.CVTS -> "cvt.s"
  | Op.CVTW -> "cvt.w"
  | Op.DADD -> "dadd"
  | Op.DADDIU -> "daddiu"
  | Op.DADDU -> "daddu"
  | Op.DALIGN -> "dalign"
  | Op.DBITSWAP -> "dbitswap"
  | Op.DCLZ -> "dclz"
  | Op.DDIV -> "ddiv"
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
  | Op.DROTR32 -> "drotr32 "
  | Op.DROTRV -> "drotrv"
  | Op.DSBH -> "dsbh"
  | Op.DSHD -> "dshd"
  | Op.DSLL -> "dsll"
  | Op.DSLL32 -> "dsll32"
  | Op.DSLLV -> "dsllv"
  | Op.DSRA -> "dsra"
  | Op.DSRA32 -> "dsra32"
  | Op.DSRAV -> "dsrav"
  | Op.DSRL -> "dsrl"
  | Op.DSRL32 -> "dsrl32"
  | Op.DSRLV -> "dsrlv"
  | Op.DSUBU -> "dsubu"
  | Op.EHB -> "ehb"
  | Op.EXT -> "ext"
  | Op.INS -> "ins"
  | Op.J -> "j"
  | Op.JAL -> "jal"
  | Op.JALR -> "jalr"
  | Op.JALRHB -> "jalr.hb"
  | Op.JR -> "jr"
  | Op.JRHB -> "jr.hb"
  | Op.LB -> "lb"
  | Op.LBU -> "lbu"
  | Op.LD -> "ld"
  | Op.LDC1 -> "ldc1"
  | Op.LDL -> "ldl"
  | Op.LDR -> "ldr"
  | Op.LDXC1 -> "ldxc1"
  | Op.LH -> "lh"
  | Op.LHU -> "lhu"
  | Op.LL -> "ll"
  | Op.LLD -> "lld"
  | Op.LUI -> "lui"
  | Op.LW -> "lw"
  | Op.LWC1 -> "lwc1"
  | Op.LWL -> "lwl"
  | Op.LWR -> "lwr"
  | Op.LWU -> "lwu"
  | Op.LWXC1 -> "lwxc1"
  | Op.MADD -> "madd"
  | Op.MADDU -> "maddu"
  | Op.MFC1 -> "mfc1"
  | Op.MFHC1 -> "mfhc1"
  | Op.MFHI -> "mfhi"
  | Op.MFLO -> "mflo"
  | Op.MOV -> "mov"
  | Op.MOVF -> "movf"
  | Op.MOVN -> "movn"
  | Op.MOVT -> "movt"
  | Op.MOVZ -> "movz"
  | Op.MSUB -> "msub"
  | Op.MSUBU -> "msubu"
  | Op.MTC1 -> "mtc1"
  | Op.MTHC1 -> "mthc1"
  | Op.MTHI -> "mthi"
  | Op.MTLO -> "mtlo"
  | Op.MUL -> "mul"
  | Op.MULT -> "mult"
  | Op.MULTU -> "multu"
  | Op.NEG -> "neg"
  | Op.NMADD -> "nmadd"
  | Op.NOP -> "nop"
  | Op.NOR -> "nor"
  | Op.OR -> "or"
  | Op.ORI -> "ori"
  | Op.PAUSE -> "pause"
  | Op.PREF -> "pref"
  | Op.PREFX -> "prefx"
  | Op.RDHWR -> "rdhwr"
  | Op.RECIP -> "recip"
  | Op.ROTR -> "rotr"
  | Op.ROTRV -> "rotrv"
  | Op.RSQRT -> "rsqrt"
  | Op.SB -> "sb"
  | Op.SC -> "sc"
  | Op.SCD -> "scd"
  | Op.SD -> "sd"
  | Op.SDC1 -> "sdc1"
  | Op.SDL -> "sdl"
  | Op.SDR -> "sdr"
  | Op.SDXC1 -> "sdxc1"
  | Op.SEB -> "seb"
  | Op.SEH -> "seh"
  | Op.SH -> "sh"
  | Op.SLL -> "sll"
  | Op.SLLV -> "sllv"
  | Op.SLT -> "slt"
  | Op.SLTI -> "slti"
  | Op.SLTIU -> "sltiu"
  | Op.SLTU -> "sltu"
  | Op.SQRT -> "sqrt"
  | Op.SRA -> "sra"
  | Op.SRAV -> "srav"
  | Op.SRL -> "srl"
  | Op.SRLV -> "srlv"
  | Op.SSNOP -> "ssnop"
  | Op.SUB -> "sub"
  | Op.SUBU -> "subu"
  | Op.SW -> "sw"
  | Op.SWC1 -> "swc1"
  | Op.SWL -> "swl"
  | Op.SWR -> "swr"
  | Op.SWXC1 -> "swxc1"
  | Op.SYNC -> "sync"
  | Op.SYSCALL -> "syscall"
  | Op.TEQ -> "teq"
  | Op.TEQI -> "teqi"
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

let inline buildOpcode ins (builder: DisasmBuilder) =
  let str = opCodeToString ins.Opcode |> appendCond ins |> appendFmt ins
  builder.Accumulate AsmWordKind.Mnemonic str

let inline relToString pc offset (builder: DisasmBuilder) =
  let targetAddr = pc + uint64 offset
  builder.Accumulate AsmWordKind.Value (HexString.ofUInt64 targetAddr)

let inline regToString ins reg =
  match ins.OperationSize with
  | 64<rt> -> Register.toString reg WordSize.Bit64
  | _ -> Register.toString reg WordSize.Bit32

let oprToString insInfo opr delim (builder: DisasmBuilder) =
  match opr with
  | OpReg reg ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Variable (regToString insInfo reg)
  | OpImm imm
  | OpShiftAmount imm ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (HexString.ofUInt64 imm)
  | OpMem (b, Imm off, _) ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Value (off.ToString ("D"))
    builder.Accumulate AsmWordKind.String "("
    builder.Accumulate AsmWordKind.Variable (regToString insInfo b)
    builder.Accumulate AsmWordKind.String ")"
  | OpMem (b, Reg off, _) ->
    builder.Accumulate AsmWordKind.String delim
    builder.Accumulate AsmWordKind.Variable (regToString insInfo off)
    builder.Accumulate AsmWordKind.String "("
    builder.Accumulate AsmWordKind.Variable (regToString insInfo b)
    builder.Accumulate AsmWordKind.String ")"
  | OpAddr (Relative offset) ->
    builder.Accumulate AsmWordKind.String delim
    relToString insInfo.Address offset builder
  // Never gets matched. Only used in intermediate stage mips assembly parser.
  | GoToLabel _ -> raise InvalidOperandException

let buildOprs insInfo (builder: DisasmBuilder) =
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

let disasm wordSize insInfo (builder: DisasmBuilder) =
  if builder.ShowAddr then builder.AccumulateAddr () else ()
  buildOpcode insInfo builder
  buildOprs insInfo builder

// vim: set tw=80 sts=2 sw=2:

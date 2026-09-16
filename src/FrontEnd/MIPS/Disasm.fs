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
  | _ -> raise ParsingFailureException

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
  | _ -> raise ParsingFailureException

let opCodeToString = function
  | Op.ABS -> "abs"
  | Op.ADD -> "add"
  | Op.ADDI -> "addi"
  | Op.ADDIU -> "addiu"
  | Op.ADDU -> "addu"
  | Op.ALIGN -> "align"
  | Op.ALNVPS -> "alnv.ps"
  | Op.AND -> "and"
  | Op.ANDI -> "andi"
  | Op.AUI -> "aui"
  | Op.B -> "b"
  | Op.BAL -> "bal"
  | Op.NAL -> "nal"
  | Op.BC1F -> "bc1f"
  | Op.BC1T -> "bc1t"
  | Op.BC3F -> "bc3f"
  | Op.BC3FL -> "bc3fl"
  | Op.BC3T -> "bc3t"
  | Op.BC3TL -> "bc3tl"
  | Op.BEQ -> "beq"
  | Op.BC1FL -> "bc1fl"
  | Op.BC1TL -> "bc1tl"
  | Op.BEQL -> "beql"
  | Op.BGEZALL -> "bgezall"
  | Op.BGEZL -> "bgezl"
  | Op.BGTZL -> "bgtzl"
  | Op.BLEZL -> "blezl"
  | Op.BLTZALL -> "bltzall"
  | Op.BLTZL -> "bltzl"
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
  | Op.CLO -> "clo"
  | Op.CLZ -> "clz"
  | Op.CTC1 -> "ctc1"
  | Op.CVTD -> "cvt.d"
  | Op.CVTS -> "cvt.s"
  | Op.CVTL -> "cvt.l"
  | Op.CVTW -> "cvt.w"
  | Op.CVTPSS -> "cvt.ps.s"
  | Op.CVTSPL -> "cvt.s.pl"
  | Op.CVTSPU -> "cvt.s.pu"
  | Op.DADD -> "dadd"
  | Op.DADDI -> "daddi"
  | Op.DADDIU -> "daddiu"
  | Op.BALC -> "balc"
  | Op.BC -> "bc"
  | Op.BEQC -> "beqc"
  | Op.BEQZALC -> "beqzalc"
  | Op.BEQZC -> "beqzc"
  | Op.BGEC -> "bgec"
  | Op.BGEUC -> "bgeuc"
  | Op.BGEZALC -> "bgezalc"
  | Op.BGEZC -> "bgezc"
  | Op.BGTZALC -> "bgtzalc"
  | Op.BGTZC -> "bgtzc"
  | Op.BLEZALC -> "blezalc"
  | Op.BLEZC -> "blezc"
  | Op.BLTC -> "bltc"
  | Op.BLTUC -> "bltuc"
  | Op.BLTZALC -> "bltzalc"
  | Op.BLTZC -> "bltzc"
  | Op.BNEC -> "bnec"
  | Op.BNEZALC -> "bnezalc"
  | Op.BNEZC -> "bnezc"
  | Op.BNVC -> "bnvc"
  | Op.BOVC -> "bovc"
  | Op.DLSA -> "dlsa"
  | Op.JIALC -> "jialc"
  | Op.ADDIUPC -> "addiupc"
  | Op.ALUIPC -> "aluipc"
  | Op.LWPC -> "lwpc"
  | Op.LWUPC -> "lwupc"
  | Op.LDPC -> "ldpc"
  | Op.LLDP -> "lldp"
  | Op.LLWP -> "llwp"
  | Op.SCDP -> "scdp"
  | Op.SCWP -> "scwp"
  | Op.BC1EQZ -> "bc1eqz"
  | Op.BC1NEZ -> "bc1nez"
  | Op.CLASS -> "class"
  | Op.MADDF -> "maddf"
  | Op.MSUBF -> "msubf"
  | Op.RINT -> "rint"
  | Op.CMP -> "cmp"
  | Op.MAX -> "max"
  | Op.MAXA -> "maxa"
  | Op.MIN -> "min"
  | Op.MINA -> "mina"
  | Op.SEL -> "sel"
  | Op.JIC -> "jic"
  | Op.SELEQZ -> "seleqz"
  | Op.SELNEZ -> "selnez"
  | Op.SELNEQZ -> "selneqz"
  | Op.DMOD -> "dmod"
  | Op.DMODU -> "dmodu"
  | Op.DMUH -> "dmuh"
  | Op.DMUHU -> "dmuhu"
  | Op.DMUL -> "dmul"
  | Op.DMULU -> "dmulu"
  | Op.LSA -> "lsa"
  | Op.MOD -> "mod"
  | Op.MODU -> "modu"
  | Op.MUH -> "muh"
  | Op.MUHU -> "muhu"
  | Op.MULU -> "mulu"
  | Op.DADDU -> "daddu"
  | Op.DAHI -> "dahi"
  | Op.DALIGN -> "dalign"
  | Op.DATI -> "dati"
  | Op.DAUI -> "daui"
  | Op.DBITSWAP -> "dbitswap"
  | Op.DCLO -> "dclo"
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
  | Op.DSUB -> "dsub"
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
  | Op.LUXC1 -> "luxc1"
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
  | Op.NMSUB -> "nmsub"
  | Op.NOP -> "nop"
  | Op.NOR -> "nor"
  | Op.OR -> "or"
  | Op.ORI -> "ori"
  | Op.PAUSE -> "pause"
  | Op.PLLPS -> "pll.ps"
  | Op.PLUPS -> "plu.ps"
  | Op.PREF -> "pref"
  | Op.PREFX -> "prefx"
  | Op.PULPS -> "pul.ps"
  | Op.PUUPS -> "puu.ps"
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
  | Op.SUXC1 -> "suxc1"
  | Op.SW -> "sw"
  | Op.SWC1 -> "swc1"
  | Op.SWL -> "swl"
  | Op.SWR -> "swr"
  | Op.SWXC1 -> "swxc1"
  | Op.SYNC -> "sync"
  | Op.SYSCALL -> "syscall"
  | Op.TEQ -> "teq"
  | Op.TEQI -> "teqi"
  | Op.CEILL -> "ceil.l"
  | Op.CEILW -> "ceil.w"
  | Op.FLOORL -> "floor.l"
  | Op.FLOORW -> "floor.w"
  | Op.ROUNDL -> "round.l"
  | Op.ROUNDW -> "round.w"
  | Op.TRUNCL -> "trunc.l"
  | Op.TRUNCW -> "trunc.w"
  | Op.WSBH -> "wsbh"
  | Op.XOR -> "xor"
  | Op.XORI -> "xori"
  (* The privileged instructions. They are grouped rather than spelled into
     the list above because they are one family: everything the COP0 major
     opcode holds, the EVA loads and stores that name the other address
     space, and the two cache-maintenance opcodes. *)
  | Op.MFC0 -> "mfc0"
  | Op.MTC0 -> "mtc0"
  | Op.DMFC0 -> "dmfc0"
  | Op.DMTC0 -> "dmtc0"
  | Op.MFHC0 -> "mfhc0"
  | Op.MTHC0 -> "mthc0"
  | Op.RDPGPR -> "rdpgpr"
  | Op.WRPGPR -> "wrpgpr"
  | Op.DI -> "di"
  | Op.EI -> "ei"
  | Op.DVP -> "dvp"
  | Op.EVP -> "evp"
  | Op.ERET -> "eret"
  | Op.ERETNC -> "eretnc"
  | Op.DERET -> "deret"
  | Op.TLBP -> "tlbp"
  | Op.TLBR -> "tlbr"
  | Op.TLBWI -> "tlbwi"
  | Op.TLBWR -> "tlbwr"
  | Op.TLBINV -> "tlbinv"
  | Op.TLBINVF -> "tlbinvf"
  | Op.CACHE -> "cache"
  | Op.CACHEE -> "cachee"
  | Op.GINVI -> "ginvi"
  | Op.GINVT -> "ginvt"
  | Op.WAIT -> "wait"
  | Op.LBE -> "lbe"
  | Op.LBUE -> "lbue"
  | Op.LHE -> "lhe"
  | Op.LHUE -> "lhue"
  | Op.LWE -> "lwe"
  | Op.LWLE -> "lwle"
  | Op.LWRE -> "lwre"
  | Op.LLE -> "lle"
  | Op.LLWPE -> "llwpe"
  | Op.SBE -> "sbe"
  | Op.SHE -> "she"
  | Op.SWE -> "swe"
  | Op.SWLE -> "swle"
  | Op.SWRE -> "swre"
  | Op.SCE -> "sce"
  | Op.SCWPE -> "scwpe"
  | Op.PREFE -> "prefe"
  (* The conditional traps beside TEQ and TEQI, and the two whose whole
     effect is to raise an exception of their own. *)
  | Op.TGE -> "tge"
  | Op.TGEU -> "tgeu"
  | Op.TGEI -> "tgei"
  | Op.TGEIU -> "tgeiu"
  | Op.TLT -> "tlt"
  | Op.TLTU -> "tltu"
  | Op.TLTI -> "tlti"
  | Op.TLTIU -> "tltiu"
  | Op.TNE -> "tne"
  | Op.TNEI -> "tnei"
  | Op.SDBBP -> "sdbbp"
  | Op.SIGRIE -> "sigrie"
  | Op.JRC -> "jrc"
  | Op.JALRS -> "jalrs"
  | Op.JALRC -> "jalrc"
  | Op.JRADDIUSP -> "jraddiusp"
  | Op.JRCADDIUSP -> "jrcaddiusp"
  | Op.LWM -> "lwm"
  | Op.SWM -> "swm"
  | Op.MOVEP -> "movep"
  | Op.JALS -> "jals"
  | Op.JALRSHB -> "jalrs.hb"
  | Op.BLTZALS -> "bltzals"
  | Op.BGEZALS -> "bgezals"
  | Op.LWP -> "lwp"
  | Op.SWP -> "swp"
  | Op.LDP -> "ldp"
  | Op.SDP -> "sdp"
  | Op.LDM -> "ldm"
  | Op.SDM -> "sdm"
  | Op.LWXS -> "lwxs"
  | Op.JALX -> "jalx"
  | Op.CRC32B -> "crc32b"
  | Op.CRC32H -> "crc32h"
  | Op.CRC32W -> "crc32w"
  | Op.CRC32D -> "crc32d"
  | Op.CRC32CB -> "crc32cb"
  | Op.CRC32CH -> "crc32ch"
  | Op.CRC32CW -> "crc32cw"
  | Op.CRC32CD -> "crc32cd"
  | _ -> raise InvalidOpcodeException

let inline appendCond (ins: Instruction) opcode =
  match ins.Condition with
  | None -> opcode
  | Some c -> opcode + condToString c

let inline appendFmt (ins: Instruction) opcode =
  match ins.Fmt with
  | None -> opcode
  | Some f -> opcode + fmtToString f

let inline buildOpcode (ins: Instruction) (builder: IDisasmBuilder) =
  let str = opCodeToString ins.Opcode |> appendCond ins |> appendFmt ins
  builder.Accumulate(AsmWordKind.Mnemonic, str)

let inline relToString pc offset (builder: IDisasmBuilder) =
  let targetAddr = pc + uint64 offset
  builder.Accumulate(AsmWordKind.Value, HexString.ofUInt64 targetAddr)

let inline regToString (ins: Instruction) reg =
  match ins.OperationSize with
  | 64<rt> -> Register.toString reg WordSize.Bit64
  | _ -> Register.toString reg WordSize.Bit32

let oprToString ins opr delim (builder: IDisasmBuilder) =
  match opr with
  | OpReg reg ->
    builder.Accumulate(AsmWordKind.String, delim)
    builder.Accumulate(AsmWordKind.Variable, regToString ins reg)
  | OpImm imm
  | OpShiftAmount imm ->
    builder.Accumulate(AsmWordKind.String, delim)
    builder.Accumulate(AsmWordKind.Value, HexString.ofUInt64 imm)
  | OpMem(b, Imm off, _) ->
    builder.Accumulate(AsmWordKind.String, delim)
    builder.Accumulate(AsmWordKind.Value, off.ToString("D"))
    builder.Accumulate(AsmWordKind.String, "(")
    builder.Accumulate(AsmWordKind.Variable, regToString ins b)
    builder.Accumulate(AsmWordKind.String, ")")
  | OpMem(b, Reg off, _) ->
    builder.Accumulate(AsmWordKind.String, delim)
    builder.Accumulate(AsmWordKind.Variable, regToString ins off)
    builder.Accumulate(AsmWordKind.String, "(")
    builder.Accumulate(AsmWordKind.Variable, regToString ins b)
    builder.Accumulate(AsmWordKind.String, ")")
  | OpAddr(Relative offset) ->
    builder.Accumulate(AsmWordKind.String, delim)
    relToString ins.Address offset builder
  | OpAddr(Region index) ->
    builder.Accumulate(AsmWordKind.String, delim)
    let target = JumpTarget.regionTarget ins.Address ins.WordSize index
    builder.Accumulate(AsmWordKind.Value, HexString.ofUInt64 target)
  | OpRegList regs ->
    builder.Accumulate(AsmWordKind.String, delim)
    regs |> List.iteri (fun i r ->
      if i > 0 then builder.Accumulate(AsmWordKind.String, ", ") else ()
      builder.Accumulate(AsmWordKind.Variable, regToString ins r)
    )
  // Never gets matched. Only used in intermediate stage mips assembly parser.
  | GoToLabel _ ->
    raise InvalidOperandException

let buildOprs (ins: Instruction) (builder: IDisasmBuilder) =
  match ins.Operands with
  | NoOperand ->
    ()
  | OneOperand opr ->
    oprToString ins opr " " builder
  | TwoOperands(opr1, opr2) ->
    oprToString ins opr1 " " builder
    oprToString ins opr2 ", " builder
  | ThreeOperands(opr1, opr2, opr3) ->
    oprToString ins opr1 " " builder
    oprToString ins opr2 ", " builder
    oprToString ins opr3 ", " builder
  | FourOperands(opr1, opr2, opr3, opr4) ->
    oprToString ins opr1 " " builder
    oprToString ins opr2 ", " builder
    oprToString ins opr3 ", " builder
    oprToString ins opr4 ", " builder

let disasm (ins: Instruction) (builder: IDisasmBuilder) =
  builder.AccumulateAddrMarker ins.Address
  buildOpcode ins builder
  buildOprs ins builder

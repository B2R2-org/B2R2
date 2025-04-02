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

module B2R2.FrontEnd.SH4.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter

let opCodeToString = function
  | Opcode.ADD -> "add"
  | Opcode.ADDC -> "addc"
  | Opcode.ADDV -> "addv"
  | Opcode.AND -> "and"
  | Opcode.ANDB -> "andb"
  | Opcode.BF -> "bf"
  | Opcode.BFS -> "bfs"
  | Opcode.BRA -> "bra"
  | Opcode.BRAF -> "braf"
  | Opcode.BSR -> "bsr"
  | Opcode.BSRF -> "bsrf"
  | Opcode.BT -> "bt"
  | Opcode.BTS -> "bts"
  | Opcode.CLRMAC -> "clrmac"
  | Opcode.CLRS -> "clrs"
  | Opcode.CLRT -> "clrt"
  | Opcode.CMPEQ -> "cmpeq"
  | Opcode.CMPGE -> "cmpge"
  | Opcode.CMPGT -> "cmpgt"
  | Opcode.CMPHI -> "cmphi"
  | Opcode.CMPHS -> "cmphs"
  | Opcode.CMPPL -> "cmppl"
  | Opcode.CMPPZ -> "cmppz"
  | Opcode.CMPSTR -> "cmpstr"
  | Opcode.DIV0S -> "div0s"
  | Opcode.DIV0U -> "div0u"
  | Opcode.DIV1 -> "div1"
  | Opcode.DMULSL -> "dmulsl"
  | Opcode.DMULUL -> "dmulul"
  | Opcode.DT -> "dt"
  | Opcode.EXTS -> "exts"
  | Opcode.EXTSB -> "extsb"
  | Opcode.EXTSW -> "extsw"
  | Opcode.EXTU -> "extu"
  | Opcode.EXTUB -> "extub"
  | Opcode.EXTUW -> "extuw"
  | Opcode.FABS -> "fabs"
  | Opcode.FADD -> "fadd"
  | Opcode.FCMP -> "fcmp"
  | Opcode.FCMPEQ -> "fcmpeq"
  | Opcode.FCMPGT -> "fcmpgt"
  | Opcode.FCNVDS -> "fcnvds"
  | Opcode.FCNVSD -> "fcnvsd"
  | Opcode.FDIV -> "fdiv"
  | Opcode.FIPR -> "fipr"
  | Opcode.FLDI0 -> "fldi0"
  | Opcode.FLDI1 -> "fldi1"
  | Opcode.FLDS -> "flds"
  | Opcode.FLOAT -> "float"
  | Opcode.FMAC -> "fmac"
  | Opcode.FMOV -> "fmov"
  | Opcode.FMUL -> "fmul"
  | Opcode.FNEG -> "fneg"
  | Opcode.FRCHG -> "frchg"
  | Opcode.FSCHG -> "fschg"
  | Opcode.FSQRT -> "fsqrt"
  | Opcode.FSTS -> "fsts"
  | Opcode.FSUB -> "fsub"
  | Opcode.FTRC -> "ftrc"
  | Opcode.FTRV -> "ftrv"
  | Opcode.JMP -> "jmp"
  | Opcode.JSR -> "jsr"
  | Opcode.LDC -> "ldc"
  | Opcode.LDCL -> "ldcl"
  | Opcode.LDS -> "lds"
  | Opcode.LDSL -> "ldsl"
  | Opcode.LDTLB -> "ldtlb"
  | Opcode.MACL -> "macl"
  | Opcode.MACW -> "macw"
  | Opcode.MOV -> "mov"
  | Opcode.MOVA -> "mova"
  | Opcode.MOVB -> "movb"
  | Opcode.MOVW -> "movw"
  | Opcode.MOVL -> "movl"
  | Opcode.MOVCAL -> "movcal"
  | Opcode.MOVT -> "movt"
  | Opcode.MULL -> "mull"
  | Opcode.MULSW -> "mulsw"
  | Opcode.MULUW -> "muluw"
  | Opcode.NEG -> "neg"
  | Opcode.NEGC -> "negc"
  | Opcode.NOP -> "nop"
  | Opcode.NOT -> "not"
  | Opcode.OCBI -> "ocbi"
  | Opcode.OCBP -> "ocbp"
  | Opcode.OCBWB -> "ocbwb"
  | Opcode.OR -> "or"
  | Opcode.ORB -> "orb"
  | Opcode.PREF -> "pref"
  | Opcode.ROTCL -> "rotcl"
  | Opcode.ROTCR -> "rotcr"
  | Opcode.ROTL -> "rotl"
  | Opcode.ROTR -> "rotr"
  | Opcode.RTE -> "rte"
  | Opcode.RTS -> "rts"
  | Opcode.SETS -> "sets"
  | Opcode.SETT -> "sett"
  | Opcode.SHAD -> "shad"
  | Opcode.SHAL -> "shal"
  | Opcode.SHAR -> "shar"
  | Opcode.SHLD -> "shld"
  | Opcode.SHLL -> "shll"
  | Opcode.SHLL2 -> "shll2"
  | Opcode.SHLL8 -> "shll8"
  | Opcode.SHLL16 -> "shll16"
  | Opcode.SHLR -> "shlr"
  | Opcode.SHLR2 -> "shlr2"
  | Opcode.SHLR8 -> "shlr8"
  | Opcode.SHLR16 -> "shlr16"
  | Opcode.SLEEP -> "sleep"
  | Opcode.STC -> "stc"
  | Opcode.STCL -> "stcl"
  | Opcode.STS -> "sts"
  | Opcode.STSL -> "stsl"
  | Opcode.SUB -> "sub"
  | Opcode.SUBC -> "subc"
  | Opcode.SUBV -> "subv"
  | Opcode.SWAP -> "swap"
  | Opcode.SWAPB -> "swapb"
  | Opcode.SWAPW -> "swapw"
  | Opcode.TAS -> "tas"
  | Opcode.TASB -> "tasb"
  | Opcode.TRAPA -> "trapa"
  | Opcode.TST -> "tst"
  | Opcode.TSTB -> "tstb"
  | Opcode.XOR -> "xor"
  | Opcode.XORB -> "xorb"
  | Opcode.XTRCT -> "xtrct"
  | Opcode.InvalidOp -> "(invalid)"
  | _ -> Utils.impossible()

let prepDelim delim (builder: DisasmBuilder) =
  match delim with
  | None -> ()
  | Some delimiter -> builder.Accumulate AsmWordKind.String delimiter

let immToStr imm (builder: DisasmBuilder) =
  builder.Accumulate AsmWordKind.Value (HexString.ofInt32 imm)

let addrToStr shift addr (builder: DisasmBuilder) =
  let relAddr = int(addr) + shift + 4
  if shift >= 0 then
    builder.Accumulate AsmWordKind.String ".+"
    builder.Accumulate AsmWordKind.Value (string shift)
    builder.Accumulate AsmWordKind.String "     ; "
    builder.Accumulate AsmWordKind.Value (HexString.ofInt32 relAddr)
  else
    builder.Accumulate AsmWordKind.String "."
    builder.Accumulate AsmWordKind.Value (string shift)
    builder.Accumulate AsmWordKind.String "     ; "
    builder.Accumulate AsmWordKind.Value (HexString.ofInt32 relAddr)

let memToStr addrMode (builder: DisasmBuilder) =
  match addrMode with
  | Regdir reg ->
    let reg = Register.toString reg
    builder.Accumulate AsmWordKind.Variable reg
  | RegIndir reg ->
    let reg = Register.toString reg
    builder.Accumulate AsmWordKind.String "@"
    builder.Accumulate AsmWordKind.Variable reg
  | PostInc reg ->
    let reg = Register.toString reg
    builder.Accumulate AsmWordKind.String "@"
    builder.Accumulate AsmWordKind.Variable reg
    builder.Accumulate AsmWordKind.String "+"
  | PreDec reg ->
    let reg = Register.toString reg
    builder.Accumulate AsmWordKind.String "@"
    builder.Accumulate AsmWordKind.String "-"
    builder.Accumulate AsmWordKind.Variable reg
  | RegDisp (imm, reg) ->
    let reg = Register.toString reg
    builder.Accumulate AsmWordKind.String "@"
    builder.Accumulate AsmWordKind.String "("
    builder.Accumulate AsmWordKind.Value (string imm)
    builder.Accumulate AsmWordKind.String ","
    builder.Accumulate AsmWordKind.Variable reg
    builder.Accumulate AsmWordKind.String ")"
  | IdxIndir (R.R0, reg2) ->
    let reg1 = Register.toString R.R0
    let reg2 = Register.toString reg2
    builder.Accumulate AsmWordKind.String "@"
    builder.Accumulate AsmWordKind.String "("
    builder.Accumulate AsmWordKind.Variable reg1
    builder.Accumulate AsmWordKind.String ","
    builder.Accumulate AsmWordKind.Variable reg2
    builder.Accumulate AsmWordKind.String ")"
  | GbrDisp (imm, R.GBR) ->
    let reg = Register.toString R.GBR
    builder.Accumulate AsmWordKind.String "@"
    builder.Accumulate AsmWordKind.String "("
    builder.Accumulate AsmWordKind.Value (string imm)
    builder.Accumulate AsmWordKind.String ","
    builder.Accumulate AsmWordKind.Variable reg
    builder.Accumulate AsmWordKind.String ")"
  | IdxGbr (R.R0, R.GBR) ->
    let reg1 = Register.toString R.R0
    let reg2 = Register.toString R.GBR
    builder.Accumulate AsmWordKind.String "@"
    builder.Accumulate AsmWordKind.String "("
    builder.Accumulate AsmWordKind.Variable reg1
    builder.Accumulate AsmWordKind.String ","
    builder.Accumulate AsmWordKind.Variable reg2
    builder.Accumulate AsmWordKind.String ")"
  | PCrDisp (imm, R.PC) ->
    let reg = Register.toString R.PC
    builder.Accumulate AsmWordKind.String "@"
    builder.Accumulate AsmWordKind.String "("
    builder.Accumulate AsmWordKind.Value (string imm)
    builder.Accumulate AsmWordKind.String ","
    builder.Accumulate AsmWordKind.Variable reg
    builder.Accumulate AsmWordKind.String ")"
  | PCr imm ->
    builder.Accumulate AsmWordKind.Value (string imm)
  | Imm imm ->
    builder.Accumulate AsmWordKind.String "#"
    builder.Accumulate AsmWordKind.Value (string imm)
  | _ -> raise InvalidOperandException

let buildReg ins reg (builder: DisasmBuilder) =
  let reg = Register.toString reg
  builder.Accumulate AsmWordKind.Variable reg

let opToStr ins addr op delim builder =
  match op with
  | OpReg addrMode ->
    prepDelim delim builder
    memToStr addrMode builder
  | OpImm n ->
    prepDelim delim builder
    immToStr n builder
  | OpAddr s ->
    prepDelim delim builder
    addrToStr s addr builder

let buildOp ins pc builder =
  match ins.Operands with
  | NoOperand -> ()
  | OneOperand opr ->
    opToStr ins pc opr (Some " ") builder
  | TwoOperands (opr1, opr2) ->
    opToStr ins pc opr1 (Some " ") builder
    opToStr ins pc opr2 (Some ",") builder
  | ThreeOperands (opr1, opr2, opr3) ->
    opToStr ins pc opr1 (Some " ") builder
    opToStr ins pc opr2 (Some ",") builder
    opToStr ins pc opr3 (Some ",") builder

let inline buildOpcode ins (builder: DisasmBuilder) =
  let str = opCodeToString ins.Opcode
  builder.Accumulate AsmWordKind.Mnemonic str
  if String.length str = 2 then builder.Accumulate AsmWordKind.String "      "
  elif String.length str = 3 then builder.Accumulate AsmWordKind.String "     "
  elif String.length str = 4 then builder.Accumulate AsmWordKind.String "    "
  elif String.length str = 5 then builder.Accumulate AsmWordKind.String "   "
  elif String.length str = 6 then builder.Accumulate AsmWordKind.String "  "
  else builder.Accumulate AsmWordKind.String ""

let disas insInfo (builder: DisasmBuilder) =
  let pc = insInfo.Address
  if builder.ShowAddr then builder.AccumulateAddr () else ()
  buildOpcode insInfo builder
  buildOp insInfo pc builder

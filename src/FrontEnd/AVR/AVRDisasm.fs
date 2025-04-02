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

module B2R2.FrontEnd.AVR.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter

let opCodeToString = function
  | Opcode.ADC -> "adc"
  | Opcode.ADD -> "add"
  | Opcode.ADIW -> "adiw"
  | Opcode.AND -> "and"
  | Opcode.ANDI -> "andi"
  | Opcode.ASR -> "asr"
  | Opcode.BCLR -> "bclr"
  | Opcode.BLD -> "bld"
  | Opcode.BRBC -> "brbc"
  | Opcode.BRBS -> "brbs"
  | Opcode.BRCC -> "brcc"
  | Opcode.BRCS -> "brcs"
  | Opcode.BREAK -> "break"
  | Opcode.BREQ -> "breq"
  | Opcode.BRGE -> "brge"
  | Opcode.BRHC -> "brhc"
  | Opcode.BRHS -> "brhs"
  | Opcode.BRID -> "brid"
  | Opcode.BRIE -> "brie"
  | Opcode.BRLAO -> "brlao"
  | Opcode.BRLT -> "brlt"
  | Opcode.BRMI -> "brmi"
  | Opcode.BRNE -> "brne"
  | Opcode.BRPL -> "brpl"
  | Opcode.BRSH -> "brsh"
  | Opcode.BRTC -> "brtc"
  | Opcode.BRTS -> "brts"
  | Opcode.BRVC -> "brvc"
  | Opcode.BRVS -> "brvs"
  | Opcode.BSET -> "bset"
  | Opcode.BST -> "bst"
  | Opcode.CALL -> "call"
  | Opcode.CBI -> "cbi"
  | Opcode.CBR -> "cbr"
  | Opcode.CLC -> "clc"
  | Opcode.CLH -> "clh"
  | Opcode.CLI -> "cli"
  | Opcode.CLN -> "cln"
  | Opcode.CLR -> "clr"
  | Opcode.CLS -> "cls"
  | Opcode.CLT -> "clt"
  | Opcode.CLV -> "clv"
  | Opcode.CLZ -> "clz"
  | Opcode.COM -> "com"
  | Opcode.CP -> "cp"
  | Opcode.CPC -> "cpc"
  | Opcode.CPI -> "cpi"
  | Opcode.CPSE -> "cpse"
  | Opcode.DEC -> "dec"
  | Opcode.DES -> "des"
  | Opcode.EICALL -> "eicall"
  | Opcode.EIJMP -> "eijmp"
  | Opcode.ELPM -> "elpm"
  | Opcode.EOR -> "eor"
  | Opcode.FMUL -> "fmul"
  | Opcode.FMULS -> "fmuls"
  | Opcode.FMULSU -> "fmulsu"
  | Opcode.ICALL -> "icall"
  | Opcode.IJMP -> "ijmp"
  | Opcode.IN -> "in"
  | Opcode.INC -> "inc"
  | Opcode.JMP -> "jmp"
  | Opcode.LAC -> "lac"
  | Opcode.LAS -> "las"
  | Opcode.LAT -> "lat"
  | Opcode.LD -> "ld"
  | Opcode.LDD -> "ldd"
  | Opcode.LDI -> "ldi"
  | Opcode.LDS -> "lds"
  | Opcode.LPM -> "lpm"
  | Opcode.LSL -> "lsl"
  | Opcode.LSR -> "lsr"
  | Opcode.MOV -> "mov"
  | Opcode.MOVW -> "movw"
  | Opcode.MUL -> "mul"
  | Opcode.MULS -> "muls"
  | Opcode.MULSU -> "mulsu"
  | Opcode.NEG -> "neg"
  | Opcode.NOP -> "nop"
  | Opcode.OR -> "or"
  | Opcode.ORI -> "ori"
  | Opcode.OUT -> "out"
  | Opcode.POP -> "pop"
  | Opcode.PUSH -> "push"
  | Opcode.RCALL -> "rcall"
  | Opcode.RET -> "ret"
  | Opcode.RETI -> "reti"
  | Opcode.RJMP -> "rjmp"
  | Opcode.ROL -> "rol"
  | Opcode.ROR -> "ror"
  | Opcode.SBC -> "sbc"
  | Opcode.SBCI -> "sbci"
  | Opcode.SBI -> "sbi"
  | Opcode.SBIC -> "sbic"
  | Opcode.SBIS -> "sbis"
  | Opcode.SBIW -> "sbiw"
  | Opcode.SBR -> "sbr"
  | Opcode.SBRC -> "sbrc"
  | Opcode.SBRS -> "sbrs"
  | Opcode.SEC -> "sec"
  | Opcode.SEH -> "seh"
  | Opcode.SEI -> "sei"
  | Opcode.SEN -> "sen"
  | Opcode.SER -> "ser"
  | Opcode.SES -> "ses"
  | Opcode.SET -> "set"
  | Opcode.SEV -> "sev"
  | Opcode.SEZ -> "sez"
  | Opcode.SLEEP -> "sleep"
  | Opcode.SPM -> "spm"
  | Opcode.STD -> "std"
  | Opcode.ST -> "st"
  | Opcode.STS -> "sts"
  | Opcode.SUB -> "sub"
  | Opcode.SUBI -> "subi"
  | Opcode.SWAP -> "swap"
  | Opcode.TST -> "tst"
  | Opcode.WDR -> "wdr"
  | Opcode.XCH -> "xch"
  | Opcode.InvalidOp -> "(invalid)"
  | _ -> Utils.impossible ()

let prependDelimiter delimiter (builder: DisasmBuilder) =
  match delimiter with
  | None -> ()
  | Some delim -> builder.Accumulate AsmWordKind.String delim

let immToString imm  (builder: DisasmBuilder) =
  builder.Accumulate AsmWordKind.Value (HexString.ofInt32 imm)

let addrToString shift addr (builder: DisasmBuilder) =
  let relAddr = int(addr) + shift + 2
  if shift>=0 then
    builder.Accumulate AsmWordKind.String ".+"
    builder.Accumulate AsmWordKind.Value (string shift)
    builder.Accumulate AsmWordKind.String "     ; "
    builder.Accumulate AsmWordKind.Value (HexString.ofInt32 relAddr)
    else
      builder.Accumulate AsmWordKind.String "."
      builder.Accumulate AsmWordKind.Value (string shift)
      builder.Accumulate AsmWordKind.String "     ; "
      builder.Accumulate AsmWordKind.Value (HexString.ofInt32 relAddr)

let memToString addrMode (builder: DisasmBuilder) =
  match addrMode with
  | DispMode (reg,c) ->
    let reg = Register.toString reg
    builder.Accumulate AsmWordKind.Variable reg
    builder.Accumulate AsmWordKind.String "+"
    builder.Accumulate AsmWordKind.Value (string c)
  | PreIdxMode reg ->
    let reg = Register.toString reg
    builder.Accumulate AsmWordKind.String "-"
    builder.Accumulate AsmWordKind.Variable reg
  | PostIdxMode reg ->
    let reg = Register.toString reg
    builder.Accumulate AsmWordKind.Variable reg
    builder.Accumulate AsmWordKind.String "+"
  | UnchMode reg ->
    let reg = Register.toString reg
    builder.Accumulate AsmWordKind.Variable reg

let buildReg ins reg (builder: DisasmBuilder) =
  let reg = Register.toString reg
  builder.Accumulate AsmWordKind.Variable reg

let oprToString ins addr operand delim builder =
  match operand with
  | OprReg reg ->
    prependDelimiter delim builder
    buildReg ins reg builder
  | OprImm k ->
    prependDelimiter delim builder
    immToString k builder
  | OprAddr shift ->
    prependDelimiter delim builder
    addrToString shift addr builder
  | OprMemory addrMode ->
    prependDelimiter delim builder
    memToString addrMode builder

let buildComment opr1 opr2 (builder: DisasmBuilder) =
  match opr1, opr2 with
  | OprImm imm, _ | _, OprImm imm ->
    builder.Accumulate AsmWordKind.String "     ; "
    builder.Accumulate AsmWordKind.Value (string imm)
  | OprMemory addrMode, _ | _, OprMemory addrMode ->
    match addrMode with
    | DispMode (reg, c) ->
      builder.Accumulate AsmWordKind.String "     ; "
      builder.Accumulate AsmWordKind.Value (HexString.ofInt32 c)
    | _ -> ()
  | _ -> ()

let buildOprs ins pc builder =
  match ins.Operands with
  | NoOperand -> ()
  | OneOperand opr ->
    oprToString ins pc opr (Some " ") builder
  | TwoOperands (opr1, opr2) ->
    oprToString ins pc opr1 (Some " ") builder
    oprToString ins pc opr2 (Some ", ") builder
    buildComment opr1 opr2 builder

let inline buildOpcode ins (builder: DisasmBuilder) =
  let str = opCodeToString ins.Opcode
  builder.Accumulate AsmWordKind.Mnemonic str

let disasm insInfo (builder: DisasmBuilder) =
  let pc = insInfo.Address
  if builder.ShowAddr then builder.AccumulateAddr () else ()
  buildOpcode insInfo builder
  buildOprs insInfo pc builder

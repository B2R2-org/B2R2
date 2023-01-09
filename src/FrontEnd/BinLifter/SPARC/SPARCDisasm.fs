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

module B2R2.FrontEnd.BinLifter.SPARC.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.SPARC

let opCodeToString = function
  | Opcode.ADD -> "add"
  | Opcode.ADDcc -> "addcc"
  | Opcode.ADDC -> "addc"
  | Opcode.ADDCcc -> "addccc"
  | Opcode.AND -> "and"
  | Opcode.ANDcc -> "andcc"
  | Opcode.ANDN -> "andn"
  | Opcode.ANDNcc -> "andncc"
  | Opcode.BPA -> "ba"
  | Opcode.BPN -> "bn"
  | Opcode.BPNE -> "bne"
  | Opcode.BPE -> "be"
  | Opcode.BPG -> "bg"
  | Opcode.BPLE -> "ble"
  | Opcode.BPGE -> "bge"
  | Opcode.BPL -> "bl"
  | Opcode.BPGU -> "bgu"
  | Opcode.BPLEU -> "bleu"
  | Opcode.BPCC -> "bcc"
  | Opcode.BPCS -> "bcs"
  | Opcode.BPPOS -> "bpos"
  | Opcode.BPNEG -> "bneg"
  | Opcode.BPVC -> "bvc"
  | Opcode.BPVS -> "bvs"
  | Opcode.BA -> "ba"
  | Opcode.BN -> "bn"
  | Opcode.BNE -> "bne"
  | Opcode.BE -> "be"
  | Opcode.BG -> "bg"
  | Opcode.BLE -> "ble"
  | Opcode.BGE -> "bge"
  | Opcode.BL -> "bl"
  | Opcode.BGU -> "bgu"
  | Opcode.BLEU -> "bleu"
  | Opcode.BCC -> "bcc"
  | Opcode.BCS -> "bcs"
  | Opcode.BPOS -> "bpos"
  | Opcode.BNEG -> "bneg"
  | Opcode.BVC -> "bvc"
  | Opcode.BRZ -> "brz"
  | Opcode.BRLEZ -> "brlez"
  | Opcode.BRLZ -> "brlz"
  | Opcode.BRNZ -> "brnz"
  | Opcode.BRGZ -> "brgz"
  | Opcode.BRGEZ -> "brgez"
  | Opcode.CALL -> "call"
  | Opcode.CASXA -> "casxa"
  | Opcode.DONE -> "done"
  | Opcode.FABSs -> "fabss"
  | Opcode.FABSd -> "fabsd"
  | Opcode.FABSq -> "fabsq"
  | Opcode.FADDs -> "fadds"
  | Opcode.FADDd -> "faddd"
  | Opcode.FADDq -> "faddq"
  | Opcode.FBA -> "fba"
  | Opcode.FBN -> "fbn"
  | Opcode.FBU -> "fbu"
  | Opcode.FBG -> "fbg"
  | Opcode.FBUG -> "fbug"
  | Opcode.FBL -> "fbl"
  | Opcode.FBUL -> "fbul"
  | Opcode.FBLG -> "fblg"
  | Opcode.FBNE -> "fbne"
  | Opcode.FBE -> "fbe"
  | Opcode.FBUE -> "fbue"
  | Opcode.FBGE -> "fbge"
  | Opcode.FBUGE -> "fbuge"
  | Opcode.FBLE -> "fble"
  | Opcode.FBULE -> "fbule"
  | Opcode.FBO -> "fbo"
  | Opcode.FBPA -> "fba"
  | Opcode.FBPN -> "fbn"
  | Opcode.FBPU -> "fbu"
  | Opcode.FBPG -> "fbg"
  | Opcode.FBPUG -> "fbug"
  | Opcode.FBPL -> "fbl"
  | Opcode.FBPUL -> "fbul"
  | Opcode.FBPLG -> "fblg"
  | Opcode.FBPNE -> "fbne"
  | Opcode.FBPE -> "fbe"
  | Opcode.FBPUE -> "fbue"
  | Opcode.FBPGE -> "fbge"
  | Opcode.FBPUGE -> "fbuge"
  | Opcode.FBPLE -> "fble"
  | Opcode.FBPULE -> "fbule"
  | Opcode.FBPO -> "fbo"
  | Opcode.FCMPs -> "fcmps"
  | Opcode.FCMPd -> "fcmpd"
  | Opcode.FCMPq -> "fcmpq"
  | Opcode.FCMPEs -> "fcmpes"
  | Opcode.FCMPEd -> "fcmped"
  | Opcode.FCMPEq -> "fcmpeq"
  | Opcode.FDIVs -> "fdivs"
  | Opcode.FDIVd -> "fdivd"
  | Opcode.FDIVq -> "fdivq"
  | Opcode.FiTOs -> "fitos"
  | Opcode.FiTOd -> "fitod"
  | Opcode.FiTOq -> "fitoq"
  | Opcode.FLUSH -> "flush"
  | Opcode.FLUSHW -> "flushw"
  | Opcode.FMOVs -> "fmovs"
  | Opcode.FMOVd -> "fmovd"
  | Opcode.FMOVq -> "fmovq"
  | Opcode.FMOVA -> "fmova"
  | Opcode.FMOVN -> "fmovn"
  | Opcode.FMOVNE -> "fmoven"
  | Opcode.FMOVE -> "fmove"
  | Opcode.FMOVG -> "fmovg"
  | Opcode.FMOVLE -> "fmovle"
  | Opcode.FMOVGE -> "fmovge"
  | Opcode.FMOVL -> "fmovl"
  | Opcode.FMOVGU -> "fmovgu"
  | Opcode.FMOVLEU -> "fmovleu"
  | Opcode.FMOVCC -> "fmovcc"
  | Opcode.FMOVCS -> "fmovcs"
  | Opcode.FMOVPOS -> "fmovpos"
  | Opcode.FMOVNEG -> "fmovneg"
  | Opcode.FMOVVC -> "fmovvc"
  | Opcode.FMOVVS -> "fmovvs"
  | Opcode.FMOVFA -> "fmovfa"
  | Opcode.FMOVFN -> "fmovfn"
  | Opcode.FMOVFU -> "fmovfu"
  | Opcode.FMOVFG -> "fmovfg"
  | Opcode.FMOVFUG -> "fmovfug"
  | Opcode.FMOVFL -> "fmovfl"
  | Opcode.FMOVFUL -> "fmovful"
  | Opcode.FMOVFLG -> "fmovflg"
  | Opcode.FMOVFNE -> "fmovfne"
  | Opcode.FMOVFE -> "fmovfe"
  | Opcode.FMOVFUE -> "fmovfue"
  | Opcode.FMOVFGE -> "fmovfge"
  | Opcode.FMOVFUGE -> "fmovfuge"
  | Opcode.FMOVFLE -> "fmovfle"
  | Opcode.FMOVFULE -> "fmovfule"
  | Opcode.FMOVFO -> "fmovfo"
  | Opcode.FMOVRZ -> "fmovre"
  | Opcode.FMOVRLEZ -> "fmovrlez"
  | Opcode.FMOVRLZ -> "fmovrlz"
  | Opcode.FMOVRNZ -> "fmovrne"
  | Opcode.FMOVRGZ -> "fmovrgz"
  | Opcode.FMOVRGEZ -> "fmovrgez"
  | Opcode.FMULs -> "fmuls"
  | Opcode.FMULd -> "fmuld"
  | Opcode.FMULq -> "fmulq"
  | Opcode.FNEGs -> "fnegs"
  | Opcode.FNEGd -> "fnegd"
  | Opcode.FNEGq -> "fnegq"
  | Opcode.FsMULd -> "fsmuld"
  | Opcode.FdMULq -> "fdmulq"
  | Opcode.FSQRTs -> "fsqrts"
  | Opcode.FSQRTd -> "fsqrtd"
  | Opcode.FSQRTq -> "fsqrtq"
  | Opcode.FsTOi -> "fstoi"
  | Opcode.FdTOi -> "fdtoi"
  | Opcode.FqTOi -> "fqtoi"
  | Opcode.FsTOd -> "fstod"
  | Opcode.FsTOq -> "fstoq"
  | Opcode.FdTOs -> "fdtos"
  | Opcode.FdTOq -> "fdtoq"
  | Opcode.FqTOs -> "fdtos"
  | Opcode.FqTOd -> "fqtod"
  | Opcode.FsTOx -> "fstox"
  | Opcode.FdTOx -> "fdtox"
  | Opcode.FqTOx -> "fqtox"
  | Opcode.FSUBs -> "fsubs"
  | Opcode.FSUBd -> "fsubd"
  | Opcode.FSUBq -> "fsubq"
  | Opcode.FxTOs -> "fxtos"
  | Opcode.FxTOd -> "fxtod"
  | Opcode.FxTOq -> "fxtoq"
  | Opcode.ILLTRAP -> "illtrap"
  | Opcode.IMPDEP1 -> "impdep1"
  | Opcode.IMPDEP2 -> "impdep2"
  | Opcode.JMPL -> "jmpl"
  | Opcode.LDD -> "ldd"
  | Opcode.LDDA -> "ldda"
  | Opcode.LDDF -> "ldd"
  | Opcode.LDDFA -> "ldda"
  | Opcode.LDF -> "ld"
  | Opcode.LDFA -> "lda"
  | Opcode.LDFSR -> "ld"
  | Opcode.LDQF -> "ldq"
  | Opcode.LDQFA -> "ldqa"
  | Opcode.LDSB -> "ldsb"
  | Opcode.LDSBA -> "ldsba"
  | Opcode.LDSH -> "ldsh"
  | Opcode.LDSHA -> "ldsha"
  | Opcode.LDSTUB -> "ldstub"
  | Opcode.LDSTUBA -> "ldstuba"
  | Opcode.LDSW -> "ldsw"
  | Opcode.LDSWA -> "ldswa"
  | Opcode.LDUB -> "ldub"
  | Opcode.LDUBA -> "lduba"
  | Opcode.LDUH -> "lduh"
  | Opcode.LDUHA -> "lduha"
  | Opcode.LDUW -> "lduw"
  | Opcode.LDUWA -> "lduwa"
  | Opcode.LDX -> "ldx"
  | Opcode.LDXA -> "ldxa"
  | Opcode.LDXFSR -> "ldx"
  | Opcode.MEMBAR -> "membar"
  | Opcode.MOVA -> "mova"
  | Opcode.MOVN -> "movn"
  | Opcode.MOVNE -> "movne"
  | Opcode.MOVE -> "move"
  | Opcode.MOVG -> "movg"
  | Opcode.MOVLE -> "movle"
  | Opcode.MOVGE -> "movge"
  | Opcode.MOVL -> "movl"
  | Opcode.MOVGU -> "movgu"
  | Opcode.MOVLEU -> "movleu"
  | Opcode.MOVCC -> "movcc"
  | Opcode.MOVCS -> "movcs"
  | Opcode.MOVPOS -> "movpos"
  | Opcode.MOVNEG -> "movneg"
  | Opcode.MOVVC -> "movvc"
  | Opcode.MOVVS -> "movvs"
  | Opcode.MOVFA -> "movfa"
  | Opcode.MOVFN -> "movfn"
  | Opcode.MOVFU -> "movfu"
  | Opcode.MOVFG -> "movfg"
  | Opcode.MOVFUG -> "movfug"
  | Opcode.MOVFL -> "movfll"
  | Opcode.MOVFUL -> "movful"
  | Opcode.MOVFLG -> "movflg"
  | Opcode.MOVFNE -> "movfne"
  | Opcode.MOVFE -> "movfe"
  | Opcode.MOVFUE -> "movfue"
  | Opcode.MOVFGE -> "movfge"
  | Opcode.MOVFUGE -> "movfuge"
  | Opcode.MOVFLE -> "movfle"
  | Opcode.MOVFULE -> "movfule"
  | Opcode.MOVFO -> "movfo"
  | Opcode.MOVRZ -> "movrz"
  | Opcode.MOVRLEZ -> "movrlez"
  | Opcode.MOVRLZ -> "movrlz"
  | Opcode.MOVRNZ -> "movrnz"
  | Opcode.MOVRGZ -> "movrgz"
  | Opcode.MOVRGEZ -> "movrgez"
  | Opcode.MULScc -> "mulscc"
  | Opcode.MULX -> "mulx"
  | Opcode.NOP -> "nop"
  | Opcode.OR -> "or"
  | Opcode.ORcc -> "orcc"
  | Opcode.ORN -> "opn"
  | Opcode.ORNcc -> "orncc"
  | Opcode.POPC -> "popc"
  | Opcode.PREFETCH -> "prefetch"
  | Opcode.PREFETCHA -> "prefetcha"
  | Opcode.RDASI -> "rd"
  | Opcode.RDASR -> "rd"
  | Opcode.RDCCR -> "rd"
  | Opcode.RDFPRS -> "rd"
  | Opcode.RDPC -> "rd"
  | Opcode.RDPR -> "rd"
  | Opcode.RDTICK -> "rd"
  | Opcode.RDY -> "rd"
  | Opcode.RESTORE -> "restore"
  | Opcode.RESTORED -> "restored"
  | Opcode.RETRY -> "retry"
  | Opcode.RETURN -> "return"
  | Opcode.SAVE -> "save"
  | Opcode.SAVED -> "saved"
  | Opcode.SDIV -> "sdiv"
  | Opcode.SDIVcc -> "sdivcc"
  | Opcode.SDIVX -> "sdivx"
  | Opcode.SETHI -> "sethi"
  | Opcode.SIR -> "sir"
  | Opcode.SLL -> "sll"
  | Opcode.SLLX -> "sllx"
  | Opcode.SMUL -> "smul"
  | Opcode.SMULcc -> "smulcc"
  | Opcode.SRA -> "sra"
  | Opcode.SRAX -> "srax"
  | Opcode.SRL -> "srl"
  | Opcode.SRLX -> "srlx"
  | Opcode.STB -> "stb"
  | Opcode.STBA -> "stba"
  | Opcode.STBAR -> "stbar"
  | Opcode.STD -> "std"
  | Opcode.STDA -> "stda"
  | Opcode.STDF -> "std"
  | Opcode.STDFA -> "stda"
  | Opcode.STF -> "st"
  | Opcode.STFA -> "sta"
  | Opcode.STFSR -> "st"
  | Opcode.STH -> "sth"
  | Opcode.STHA -> "stha"
  | Opcode.STQF -> "stqf"
  | Opcode.STQFA -> "stqa"
  | Opcode.STW -> "stw"
  | Opcode.STWA -> "stwa"
  | Opcode.STX -> "stx"
  | Opcode.STXA -> "stxa"
  | Opcode.STXFSR -> "stx"
  | Opcode.SUB -> "sub"
  | Opcode.SUBcc -> "subcc"
  | Opcode.SWAP -> "swap"
  | Opcode.SWAPA -> "swapa"
  | Opcode.TADDcc -> "taddcc"
  | Opcode.TADDccTV ->" taddcctv"
  | Opcode.Tcc -> "tcc"
  | Opcode.TA -> "ta"
  | Opcode.TN -> "tn"
  | Opcode.TNE -> "tne"
  | Opcode.TE -> "te"
  | Opcode.TG -> "tg"
  | Opcode.TLE -> "tle"
  | Opcode.TGE -> "tge"
  | Opcode.TL -> "tl"
  | Opcode.TGU -> "tgu"
  | Opcode.TLEU -> "tleu"
  | Opcode.TCC -> "tcc"
  | Opcode.TCS -> "tcs"
  | Opcode.TPOS -> "tpos"
  | Opcode.TNEG -> "tneg"
  | Opcode.TVC -> "tvc"
  | Opcode.TVS -> "tvs"
  | Opcode.TSUBcc -> "tsubcc"
  | Opcode.TSUBccTV -> " tsubcctv"
  | Opcode.UDIV -> "udiv"
  | Opcode.UDIVcc -> "udivcc"
  | Opcode.UDIVX -> "udivx"
  | Opcode.UMUL -> "umul"
  | Opcode.UMULcc -> "umulcc"
  | Opcode.WRASI -> "wr"
  | Opcode.WRASR -> "wr"
  | Opcode.WRCCR -> "wr"
  | Opcode.WRFPRS -> "wr"
  | Opcode.WRPR -> "wr"
  | Opcode.WRY -> "wr"
  | Opcode.WNOR -> "wnor"
  | Opcode.WNORcc -> "wnorcc"
  | Opcode.XOR -> "xor"
  | Opcode.XORcc -> "xorcc"
  | Opcode.XNOR -> "xnor"
  | Opcode.XNORcc -> "xnorcc"
  | Opcode.InvalidOp -> "(invalid)"
  | _ -> Utils.impossible ()

let prependDelimiter delimiter (builder: DisasmBuilder<_>) =
  match delimiter with
  | None -> ()
  | Some delim -> builder.Accumulate AsmWordKind.String delim

let immToString imm (builder: DisasmBuilder<_>) =
  builder.Accumulate AsmWordKind.Value (String.i32ToHex imm)

let immToStringNoPrefix imm (builder: DisasmBuilder<_>) =
  builder.Accumulate AsmWordKind.Value (String.i32ToHexNoPrefix imm)

let ccToString cc (builder: DisasmBuilder<_>) =
  let cc = ConditionCode.toString cc
  builder.Accumulate AsmWordKind.Variable cc

let buildReg ins reg (builder: DisasmBuilder<_>) =
  let reg = Register.toString reg
  builder.Accumulate AsmWordKind.Variable reg

let memToString addrMode (builder: DisasmBuilder<_>) =
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

let oprToString ins addr operand delim builder =
  match operand with
  | OprReg reg ->
    prependDelimiter delim builder
    buildReg ins reg builder
  | OprImm k ->
    prependDelimiter delim builder
    immToString k builder
  | OprCC cc ->
    prependDelimiter delim builder
    ccToString cc builder
  | OprPriReg k ->
    prependDelimiter delim builder (* FIXME *)
  | OprAddr k ->
    prependDelimiter delim builder
    immToString k builder
  | OprMemory addrMode ->
    prependDelimiter delim builder
    memToString addrMode builder

let buildComment2 opr1 opr2 (builder: DisasmBuilder<_>) =
  match opr1, opr2 with
  | OprImm imm, _ | _, OprImm imm ->
    builder.Accumulate AsmWordKind.String "     ; "
    builder.Accumulate AsmWordKind.Value (string imm)
  | OprMemory addrMode, _ | _, OprMemory addrMode ->
    match addrMode with
    | DispMode (reg, c) ->
      builder.Accumulate AsmWordKind.String "     ; "
      builder.Accumulate AsmWordKind.Value (String.i32ToHex c)
    | _ -> ()
  | _ -> ()

let buildComment3 opr1 opr2 opr3 (builder: DisasmBuilder<_>) =
  match opr1, opr2, opr3 with
  | OprImm imm, _, _ | _, OprImm imm, _ | _, _, OprImm imm ->
    builder.Accumulate AsmWordKind.String "     ; "
    builder.Accumulate AsmWordKind.Value (string imm)
  | OprMemory addrMode, _, _ | _, OprMemory addrMode, _
  | _, _, OprMemory addrMode ->
    match addrMode with
    | DispMode (reg, c) ->
      builder.Accumulate AsmWordKind.String "     ; "
      builder.Accumulate AsmWordKind.Value (String.i32ToHex c)
    | _ -> ()
  | _ -> ()

let buildComment3Bracket opr1 opr2 opr3 (builder: DisasmBuilder<_>) =
  match opr1, opr2, opr3 with
  | OprImm imm, _, _ | _, OprImm imm, _ | _, _, OprImm imm ->
    builder.Accumulate AsmWordKind.String "]     ; "
    builder.Accumulate AsmWordKind.Value (string imm)
  | OprMemory addrMode, _, _ | _, OprMemory addrMode, _
  | _, _, OprMemory addrMode ->
    match addrMode with
    | DispMode (reg, c) ->
      builder.Accumulate AsmWordKind.String "]     ; "
      builder.Accumulate AsmWordKind.Value (String.i32ToHex c)
    | _ -> ()
  | _ -> ()

let buildComment4 opr1 opr2 opr3 opr4 (builder: DisasmBuilder<_>) =
  match opr1, opr2, opr3, opr4 with
  | OprImm imm, _, _, _ | _, OprImm imm, _, _ | _, _, OprImm imm, _
  | _, _, _, OprImm imm ->
    builder.Accumulate AsmWordKind.String "     ; "
    builder.Accumulate AsmWordKind.Value (string imm)
  | _ -> ()

let buildComment5 opr1 opr2 opr3 opr4 opr5 (builder: DisasmBuilder<_>) =
  match opr1, opr2, opr3, opr4, opr5 with
  | OprImm imm, _, _, _ ,_ | _, OprImm imm, _, _, _ | _, _, OprImm imm, _, _
  | _, _, _, OprImm imm, _ | _, _, _, _, OprImm imm ->
    builder.Accumulate AsmWordKind.String "     ; "
    builder.Accumulate AsmWordKind.Value (string imm)
  | OprMemory addrMode, _, _, _, _ | _, OprMemory addrMode, _, _, _
  | _, _, OprMemory addrMode, _, _ | _, _, _, OprMemory addrMode, _
  | _, _, _, _, OprMemory addrMode ->
    match addrMode with
    | DispMode (reg, c) ->
      builder.Accumulate AsmWordKind.String "     ; "
      builder.Accumulate AsmWordKind.Value (String.i32ToHex c)
    | _ -> ()
  | _ -> ()

let buildOprs ins pc builder =
  let pcValue = int32 pc
  match ins.Operands with
  | NoOperand -> ()
  | OneOperand opr ->
    match ins.Opcode with
    | Opcode.CALL | Opcode.FBA | Opcode.FBN | Opcode.FBU | Opcode.FBG
    | Opcode.FBUG | Opcode.FBL | Opcode.FBUL | Opcode.FBLG | Opcode.FBNE
    | Opcode.FBE | Opcode.FBUE | Opcode.FBGE | Opcode.FBUGE | Opcode.FBLE
    | Opcode.FBULE | Opcode.FBO | Opcode.FBPA | Opcode.FBPN | Opcode.FBPU
    | Opcode.FBPG | Opcode.FBPUG | Opcode.FBPL | Opcode.FBPUL | Opcode.FBPLG
    | Opcode.FBPNE | Opcode.FBPE | Opcode.FBPUE | Opcode.FBPGE | Opcode.FBPUGE
    | Opcode.FBPLE | Opcode.FBPULE | Opcode.FBPO | Opcode.BA | Opcode.BN
    | Opcode.BNE | Opcode.BE | Opcode.BG | Opcode.BLE | Opcode.BGE
    | Opcode.BL | Opcode.BGU | Opcode.BLEU | Opcode.BCC | Opcode.BCS
    | Opcode.BPOS | Opcode.BNEG | Opcode.BVC | Opcode.BVS ->
       match opr with
       | OprAddr k ->
         prependDelimiter (Some " ") builder
         immToStringNoPrefix (pcValue + k) builder
       | _ -> Utils.impossible ()
    | _ ->
      oprToString ins pc opr (Some " ") builder
  | TwoOperands (opr1, opr2) ->
    match ins.Opcode with
    | Opcode.BPA | Opcode.BPN | Opcode.BPNE | Opcode.BPE | Opcode.BPG
    | Opcode.BPLE | Opcode.BPGE | Opcode.BPL | Opcode.BPGU | Opcode.BPLEU
    | Opcode.BPCC | Opcode.BPCS | Opcode.BPPOS | Opcode.BPNEG | Opcode.BPVC
    | Opcode.BPVS | Opcode.BRZ | Opcode.BRLEZ | Opcode.BRLZ | Opcode.BRNZ
    | Opcode.BRGZ | Opcode.BRGEZ ->
      match opr1, opr2 with
      | OprCC c, OprImm k ->
        prependDelimiter (Some " ") builder
        ccToString c builder
        prependDelimiter (Some ", ") builder
        immToStringNoPrefix (pcValue + k) builder
      | OprReg reg, OprImm k ->
        prependDelimiter (Some " ") builder
        buildReg ins reg builder
        prependDelimiter (Some ", ") builder
        immToStringNoPrefix (pcValue + k) builder
      | _ -> Utils.impossible ()
    | _ ->
      match (opr1, opr2) with
      | (OprReg reg, OprReg reg1) ->
        oprToString ins pc opr1 (Some " ") builder
        oprToString ins pc opr2 (Some " + ") builder
      | (OprReg reg, OprImm imm) ->
        oprToString ins pc opr1 (Some " ") builder
        oprToString ins pc opr2 (Some " + ") builder
      | _ ->
        match ins.Opcode with
        | Opcode.SETHI ->
          oprToString ins pc opr1 (Some " %hi(") builder
          oprToString ins pc opr2 (Some "), ") builder
        | _ ->
          oprToString ins pc opr1 (Some " ") builder
          oprToString ins pc opr2 (Some ", ") builder
      buildComment2 opr1 opr2 builder
  | ThreeOperands (opr1, opr2, opr3) ->
    match ins.Opcode with
    | Opcode.LDF | Opcode.LDDF | Opcode.LDQF | Opcode.LDFSR | Opcode.LDXFSR
    | Opcode.LDSB | Opcode.LDSH | Opcode.LDSW | Opcode.LDUB | Opcode.LDUH
    | Opcode.LDUW | Opcode.LDX | Opcode.LDD | Opcode.LDSTUB | Opcode.PREFETCH
    | Opcode.SWAP ->
      oprToString ins pc opr1 (Some " [") builder
      oprToString ins pc opr2 (Some " + ") builder
      oprToString ins pc opr3 (Some "], ") builder
      buildComment3 opr1 opr2 opr3 builder
    | Opcode.STF | Opcode.STDF | Opcode.STQF | Opcode.STFSR | Opcode.STXFSR
    | Opcode.STB | Opcode.STH | Opcode.STW | Opcode.STX | Opcode.STD ->
      oprToString ins pc opr1 (Some " ") builder
      oprToString ins pc opr2 (Some ", [") builder
      oprToString ins pc opr3 (Some " + ") builder
      buildComment3Bracket opr1 opr2 opr3 builder
    | _ ->
      oprToString ins pc opr1 (Some " ") builder
      oprToString ins pc opr2 (Some ", ") builder
      oprToString ins pc opr3 (Some ", ") builder
      buildComment3 opr1 opr2 opr3 builder
  | FourOperands (opr1, opr2, opr3, opr4) ->
    match ins.Opcode with
    | Opcode.LDFA | Opcode.LDDFA | Opcode.LDQFA | Opcode.PREFETCHA ->
      oprToString ins pc opr1 (Some " [") builder
      oprToString ins pc opr2 (Some " + ") builder
      oprToString ins pc opr3 (Some "], ") builder
      oprToString ins pc opr4 (Some ", ") builder
      buildComment4 opr1 opr2 opr3 opr4 builder
    | Opcode.STBA | Opcode.STHA | Opcode.STWA | Opcode.STXA | Opcode.STDA ->
      oprToString ins pc opr1 (Some " ") builder
      oprToString ins pc opr2 (Some ", [") builder
      oprToString ins pc opr3 (Some " + ") builder
      oprToString ins pc opr4 (Some "], ") builder
      buildComment4 opr1 opr2 opr3 opr4 builder
    | _ ->
      oprToString ins pc opr1 (Some " ") builder
      oprToString ins pc opr2 (Some ", ") builder
      oprToString ins pc opr3 (Some ", ") builder
      oprToString ins pc opr4 (Some ", ") builder
      buildComment4 opr1 opr2 opr3 opr4 builder
  | FiveOperands (opr1, opr2, opr3, opr4, opr5) ->
    oprToString ins pc opr1 (Some " ") builder
    oprToString ins pc opr2 (Some ", ") builder
    oprToString ins pc opr3 (Some ", ") builder
    oprToString ins pc opr4 (Some ", ") builder
    oprToString ins pc opr5 (Some ", ") builder
    buildComment5 opr1 opr2 opr3 opr4 opr5 builder

let inline buildOpcode ins (builder: DisasmBuilder<_>) =
  let str = opCodeToString ins.Opcode
  builder.Accumulate AsmWordKind.Mnemonic str

let disasm insInfo (builder: DisasmBuilder<_>) =
  let pc = insInfo.Address
  if builder.ShowAddr then builder.AccumulateAddr () else ()
  buildOpcode insInfo builder
  buildOprs insInfo pc builder

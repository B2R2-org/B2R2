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

module B2R2.FrontEnd.SPARC.Disasm

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.SPARC

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
  | Opcode.CASA -> "casa"
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
  | Opcode.FMOVsA -> "fmovsa"
  | Opcode.FMOVdA -> "fmovda"
  | Opcode.FMOVqA -> "fmovqa"
  | Opcode.FMOVN -> "fmovn"
  | Opcode.FMOVsN -> "fmovsn"
  | Opcode.FMOVdN -> "fmovdn"
  | Opcode.FMOVqN -> "fmovqn"
  | Opcode.FMOVNE -> "fmovne"
  | Opcode.FMOVsNE -> "fmovsne"
  | Opcode.FMOVdNE -> "fmovdne"
  | Opcode.FMOVqNE -> "fmovqne"
  | Opcode.FMOVE -> "fmove"
  | Opcode.FMOVsE -> "fmovse"
  | Opcode.FMOVdE -> "fmovde"
  | Opcode.FMOVqE -> "fmovqe"
  | Opcode.FMOVG -> "fmovg"
  | Opcode.FMOVsG -> "fmovsg"
  | Opcode.FMOVdG -> "fmovdg"
  | Opcode.FMOVqG -> "fmovqg"
  | Opcode.FMOVLE -> "fmovle"
  | Opcode.FMOVsLE -> "fmovsle"
  | Opcode.FMOVdLE -> "fmovdle"
  | Opcode.FMOVqLE -> "fmovqle"
  | Opcode.FMOVGE -> "fmovge"
  | Opcode.FMOVsGE -> "fmovsge"
  | Opcode.FMOVdGE -> "fmovdge"
  | Opcode.FMOVqGE -> "fmovqge"
  | Opcode.FMOVL -> "fmovl"
  | Opcode.FMOVsL -> "fmovsl"
  | Opcode.FMOVdL -> "fmovdl"
  | Opcode.FMOVqL -> "fmovql"
  | Opcode.FMOVGU -> "fmovgu"
  | Opcode.FMOVsGU -> "fmovsgu"
  | Opcode.FMOVdGU -> "fmovdgu"
  | Opcode.FMOVqGU -> "fmovqgu"
  | Opcode.FMOVLEU -> "fmovleu"
  | Opcode.FMOVsLEU -> "fmovsleu"
  | Opcode.FMOVdLEU -> "fmovdleu"
  | Opcode.FMOVqLEU -> "fmovqleu"
  | Opcode.FMOVCC -> "fmovcc"
  | Opcode.FMOVsCC -> "fmovscc"
  | Opcode.FMOVdCC -> "fmovdcc"
  | Opcode.FMOVqCC -> "fmovqcc"
  | Opcode.FMOVCS -> "fmovcs"
  | Opcode.FMOVsCS -> "fmovscs"
  | Opcode.FMOVdCS -> "fmovdcs"
  | Opcode.FMOVqCS -> "fmovqcs"
  | Opcode.FMOVPOS -> "fmovpos"
  | Opcode.FMOVsPOS -> "fmovspos"
  | Opcode.FMOVdPOS -> "fmovspos"
  | Opcode.FMOVqPOS -> "fmovqpos"
  | Opcode.FMOVNEG -> "fmovneg"
  | Opcode.FMOVsNEG -> "fmovsneg"
  | Opcode.FMOVdNEG -> "fmovdneg"
  | Opcode.FMOVqNEG -> "fmovqneg"
  | Opcode.FMOVVC -> "fmovvc"
  | Opcode.FMOVsVC -> "fmovsvc"
  | Opcode.FMOVdVC -> "fmovdvc"
  | Opcode.FMOVqVC -> "fmovqvc"
  | Opcode.FMOVVS -> "fmovvs"
  | Opcode.FMOVsVS -> "fmovsvs"
  | Opcode.FMOVdVS -> "fmovdvs"
  | Opcode.FMOVqVS -> "fmovqvs"
  | Opcode.FMOVFsA -> "fmovsa"
  | Opcode.FMOVFdA -> "fmovda"
  | Opcode.FMOVFqA -> "fmovqa"
  | Opcode.FMOVFsN -> "fmovsn"
  | Opcode.FMOVFdN -> "fmovdn"
  | Opcode.FMOVFqN -> "fmovqn"
  | Opcode.FMOVFsU -> "fmovsu"
  | Opcode.FMOVFdU -> "fmovdu"
  | Opcode.FMOVFqU -> "fmovqu"
  | Opcode.FMOVFsG -> "fmovsg"
  | Opcode.FMOVFdG -> "fmovdg"
  | Opcode.FMOVFqG -> "fmovqg"
  | Opcode.FMOVFsUG -> "fmovsug"
  | Opcode.FMOVFdUG -> "fmovdug"
  | Opcode.FMOVFqUG -> "fmovqug"
  | Opcode.FMOVFsL -> "fmovsl"
  | Opcode.FMOVFdL -> "fmovdl"
  | Opcode.FMOVFqL -> "fmovql"
  | Opcode.FMOVFsUL -> "fmovsul"
  | Opcode.FMOVFdUL -> "fmovdul"
  | Opcode.FMOVFqUL -> "fmovqul"
  | Opcode.FMOVFsLG -> "fmovslg"
  | Opcode.FMOVFdLG -> "fmovdlg"
  | Opcode.FMOVFqLG -> "fmovqlg"
  | Opcode.FMOVFsNE -> "fmovsne"
  | Opcode.FMOVFdNE -> "fmovdne"
  | Opcode.FMOVFqNE -> "fmovqne"
  | Opcode.FMOVFsE -> "fmovse"
  | Opcode.FMOVFdE -> "fmovde"
  | Opcode.FMOVFqE -> "fmovqe"
  | Opcode.FMOVFsUE -> "fmovsue"
  | Opcode.FMOVFdUE -> "fmovdue"
  | Opcode.FMOVFqUE -> "fmovque"
  | Opcode.FMOVFsGE -> "fmovsge"
  | Opcode.FMOVFdGE -> "fmovdge"
  | Opcode.FMOVFqGE -> "fmovqge"
  | Opcode.FMOVFsUGE -> "fmovsuge"
  | Opcode.FMOVFdUGE -> "fmovduge"
  | Opcode.FMOVFqUGE -> "fmovquge"
  | Opcode.FMOVFsLE -> "fmovsle"
  | Opcode.FMOVFdLE -> "fmovdle"
  | Opcode.FMOVFqLE -> "fmovqle"
  | Opcode.FMOVFsULE -> "fmovsule"
  | Opcode.FMOVFdULE -> "fmovdule"
  | Opcode.FMOVFqULE -> "fmovqule"
  | Opcode.FMOVFsO -> "fmovso"
  | Opcode.FMOVFdO -> "fmovdo"
  | Opcode.FMOVFqO -> "fmovqo"
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
  | Opcode.FMOVRsZ -> "fmovrse"
  | Opcode.FMOVRsLEZ -> "fmovrslez"
  | Opcode.FMOVRsLZ -> "fmovrslz"
  | Opcode.FMOVRsNZ -> "fmovrsne"
  | Opcode.FMOVRsGZ -> "fmovrsgz"
  | Opcode.FMOVRsGEZ -> "fmovrsgez"
  | Opcode.FMOVRdZ -> "fmovrde"
  | Opcode.FMOVRdLEZ -> "fmovrdlez"
  | Opcode.FMOVRdLZ -> "fmovrdlz"
  | Opcode.FMOVRdNZ -> "fmovrdne"
  | Opcode.FMOVRdGZ -> "fmovrdgz"
  | Opcode.FMOVRdGEZ -> "fmovrdgez"
  | Opcode.FMOVRqZ -> "fmovrqe"
  | Opcode.FMOVRqLEZ -> "fmovrqlez"
  | Opcode.FMOVRqLZ -> "fmovrqlz"
  | Opcode.FMOVRqNZ -> "fmovrqne"
  | Opcode.FMOVRqGZ -> "fmovrqgz"
  | Opcode.FMOVRqGEZ -> "fmovrqgez"
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
  | Opcode.MOVFA -> "mova"
  | Opcode.MOVFN -> "movn"
  | Opcode.MOVFU -> "movu"
  | Opcode.MOVFG -> "movg"
  | Opcode.MOVFUG -> "movug"
  | Opcode.MOVFL -> "movl"
  | Opcode.MOVFUL -> "movul"
  | Opcode.MOVFLG -> "movlg"
  | Opcode.MOVFNE -> "movne"
  | Opcode.MOVFE -> "move"
  | Opcode.MOVFUE -> "movue"
  | Opcode.MOVFGE -> "movge"
  | Opcode.MOVFUGE -> "movuge"
  | Opcode.MOVFLE -> "movle"
  | Opcode.MOVFULE -> "movule"
  | Opcode.MOVFO -> "movo"
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
  | Opcode.RDPR -> "rdpr"
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
  | Opcode.WRPR -> "wrpr"
  | Opcode.WRY -> "wr"
  | Opcode.WNOR -> "wnor"
  | Opcode.WNORcc -> "wnorcc"
  | Opcode.XOR -> "xor"
  | Opcode.XORcc -> "xorcc"
  | Opcode.XNOR -> "xnor"
  | Opcode.XNORcc -> "xnorcc"
  | Opcode.InvalidOp -> "(invalid)"
  | _ -> Utils.impossible ()

let prependDelimiter delimiter (builder: DisasmBuilder) =
  match delimiter with
  | None -> ()
  | Some delim -> builder.Accumulate AsmWordKind.String delim

let immToString imm (builder: DisasmBuilder) =
  builder.Accumulate AsmWordKind.Value (HexString.ofInt32 imm)

let immToStringNoPrefix imm (builder: DisasmBuilder) =
  builder.Accumulate AsmWordKind.Value $"{imm:x}"

let ccToString cc (builder: DisasmBuilder) =
  let cc = ConditionCode.toString cc
  builder.Accumulate AsmWordKind.Variable cc

let buildReg ins reg (builder: DisasmBuilder) =
  let reg = Register.toString reg
  builder.Accumulate AsmWordKind.Variable reg

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
  | OprPriReg prireg ->
    prependDelimiter delim builder
    buildReg ins prireg builder
  | OprAddr k ->
    prependDelimiter delim builder
    immToString k builder
  | OprMemory addrMode ->
    prependDelimiter delim builder
    memToString addrMode builder

let buildComment2 opr1 opr2 (builder: DisasmBuilder) =
  match opr1, opr2 with
  | OprImm imm, _ | _, OprImm imm ->
    builder.Accumulate AsmWordKind.String "     ! "
    builder.Accumulate AsmWordKind.Value (string imm)
  | OprMemory addrMode, _ | _, OprMemory addrMode ->
    match addrMode with
    | DispMode (reg, c) ->
      builder.Accumulate AsmWordKind.String "     ! "
      builder.Accumulate AsmWordKind.Value (HexString.ofInt32 c)
    | _ -> ()
  | _ -> ()

let buildComment3 opr1 opr2 opr3 (builder: DisasmBuilder) =
  match opr1, opr2, opr3 with
  | OprImm imm, _, _ | _, OprImm imm, _ | _, _, OprImm imm ->
    builder.Accumulate AsmWordKind.String "     ! "
    builder.Accumulate AsmWordKind.Value (string imm)
  | OprMemory addrMode, _, _ | _, OprMemory addrMode, _
  | _, _, OprMemory addrMode ->
    match addrMode with
    | DispMode (reg, c) ->
      builder.Accumulate AsmWordKind.String "     ! "
      builder.Accumulate AsmWordKind.Value (HexString.ofInt32 c)
    | _ -> ()
  | _ -> ()

let buildComment3Bracket opr1 opr2 opr3 (builder: DisasmBuilder) =
  match opr1, opr2, opr3 with
  | OprImm imm, _, _ | _, OprImm imm, _ | _, _, OprImm imm ->
    builder.Accumulate AsmWordKind.String "]     ! "
    builder.Accumulate AsmWordKind.Value (string imm)
  | OprMemory addrMode, _, _ | _, OprMemory addrMode, _
  | _, _, OprMemory addrMode ->
    match addrMode with
    | DispMode (reg, c) ->
      builder.Accumulate AsmWordKind.String "]     ! "
      builder.Accumulate AsmWordKind.Value (HexString.ofInt32 c)
    | _ -> ()
  | OprReg _, OprReg _, OprReg _ ->
    builder.Accumulate AsmWordKind.String "]"
  | _ -> ()

let buildComment4 opr1 opr2 opr3 opr4 (builder: DisasmBuilder) =
  match opr1, opr2, opr3, opr4 with
  | OprImm imm, _, _, _ | _, OprImm imm, _, _ | _, _, OprImm imm, _
  | _, _, _, OprImm imm ->
    builder.Accumulate AsmWordKind.String "     ! "
    builder.Accumulate AsmWordKind.Value (string imm)
  | _ -> ()

let buildComment5 opr1 opr2 opr3 opr4 opr5 (builder: DisasmBuilder) =
  match opr1, opr2, opr3, opr4, opr5 with
  | OprImm imm, _, _, _ ,_ | _, OprImm imm, _, _, _ | _, _, OprImm imm, _, _
  | _, _, _, OprImm imm, _ | _, _, _, _, OprImm imm ->
    builder.Accumulate AsmWordKind.String "     ! "
    builder.Accumulate AsmWordKind.Value (string imm)
  | OprMemory addrMode, _, _, _, _ | _, OprMemory addrMode, _, _, _
  | _, _, OprMemory addrMode, _, _ | _, _, _, OprMemory addrMode, _
  | _, _, _, _, OprMemory addrMode ->
    match addrMode with
    | DispMode (reg, c) ->
      builder.Accumulate AsmWordKind.String "     ! "
      builder.Accumulate AsmWordKind.Value (HexString.ofInt32 c)
    | _ -> ()
  | _ -> ()

let buildOprs ins pc builder =
  let pcValue = int32 pc
  match ins.Operands with
  | NoOperand -> ()
  | OneOperand opr ->
    match ins.Opcode with
    | Opcode.CALL ->
        match opr with
        | OprAddr k ->
         prependDelimiter (Some " 0x") builder
         immToStringNoPrefix (k) builder
        | _ -> Utils.impossible ()
    | _ ->
      oprToString ins pc opr (Some " ") builder
  | TwoOperands (opr1, opr2) ->
    match ins.Opcode with
    | Opcode.FBA  | Opcode.FBN | Opcode.FBU
    | Opcode.FBG | Opcode.FBUG | Opcode.FBL
    | Opcode.FBUL | Opcode.FBLG | Opcode.FBNE
    | Opcode.FBE | Opcode.FBUE | Opcode.FBGE | Opcode.FBUGE
    | Opcode.FBLE | Opcode.FBULE | Opcode.FBO ->
      match opr1, opr2 with
      | OprImm 0b0, OprAddr k ->
        prependDelimiter (Some " 0x") builder
        immToStringNoPrefix (k) builder
      | OprImm 0b1, OprAddr k ->
        prependDelimiter (Some ",a 0x") builder
        immToStringNoPrefix (k) builder
      | _ -> Utils.impossible ()
    | Opcode.BA | Opcode.BN
    | Opcode.BNE | Opcode.BE | Opcode.BG | Opcode.BLE | Opcode.BGE
    | Opcode.BL | Opcode.BGU | Opcode.BLEU | Opcode.BCC | Opcode.BCS
    | Opcode.BPOS | Opcode.BNEG | Opcode.BVC | Opcode.BVS ->
      match opr1, opr2 with
      | OprImm 0b0, OprAddr k ->
        prependDelimiter (Some " 0x") builder
        immToStringNoPrefix (k) builder
      | OprImm 0b1, OprAddr k ->
        prependDelimiter (Some ",a 0x") builder
        immToStringNoPrefix (k) builder
      | _ -> Utils.impossible ()
    | Opcode.FdTOx | Opcode.FNEGs | Opcode.FNEGd | Opcode.FNEGq | Opcode.FABSs
    | Opcode.FABSd | Opcode.FABSq | Opcode.FSQRTs | Opcode.FSQRTd
    | Opcode.FSQRTq | Opcode.FCMPs | Opcode.FCMPd | Opcode.FCMPq
    | Opcode.FMOVs | Opcode.FMOVd | Opcode.FMOVq ->
      oprToString ins pc opr1 (Some " ") builder
      oprToString ins pc opr2 (Some ", ") builder
    | _ ->
      match (opr1, opr2) with
      | (OprReg reg, OprReg reg1) ->
        oprToString ins pc opr1 (Some " ") builder
        oprToString ins pc opr2 (Some ", ") builder
      | (OprReg reg, OprImm imm) ->
        oprToString ins pc opr1 (Some " ") builder
        oprToString ins pc opr2 (Some ", ") builder
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
    | Opcode.JMPL ->
      oprToString ins pc opr1 (Some " ") builder
      oprToString ins pc opr2 (Some " + ") builder
      oprToString ins pc opr3 (Some ", ") builder
      buildComment3 opr1 opr2 opr3 builder
    | _ ->
      oprToString ins pc opr1 (Some " ") builder
      oprToString ins pc opr2 (Some ", ") builder
      oprToString ins pc opr3 (Some ", ") builder
      buildComment3 opr1 opr2 opr3 builder
  | FourOperands (opr1, opr2, opr3, opr4) ->
    match ins.Opcode with
    | Opcode.BPA | Opcode.BPN | Opcode.BPNE | Opcode.BPE | Opcode.BPG
    | Opcode.BPLE | Opcode.BPGE | Opcode.BPL | Opcode.BPGU | Opcode.BPLEU
    | Opcode.BPCC | Opcode.BPCS | Opcode.BPPOS | Opcode.BPNEG | Opcode.BPVC
    | Opcode.BPVS ->
      match opr1, opr2, opr3, opr4 with
      | OprCC c, OprAddr k, OprImm 0b0, OprImm 0b0 ->
        prependDelimiter (Some ",pn ") builder
        ccToString c builder
        prependDelimiter (Some ", 0x") builder
        immToStringNoPrefix (k) builder
      | OprCC c, OprAddr k, OprImm 0b1, OprImm 0b0 ->
        prependDelimiter (Some ",a,pn ") builder
        ccToString c builder
        prependDelimiter (Some ", 0x") builder
        immToStringNoPrefix (k) builder
      | OprCC c, OprAddr k, OprImm 0b0, OprImm 0b1 ->
        prependDelimiter (Some ",pt ") builder
        ccToString c builder
        prependDelimiter (Some ", 0x") builder
        immToStringNoPrefix (k) builder
      | OprCC c, OprAddr k, OprImm 0b1, OprImm 0b1 ->
        prependDelimiter (Some ",a,pt ") builder
        ccToString c builder
        prependDelimiter (Some ", 0x") builder
        immToStringNoPrefix (k) builder
      | _ -> Utils.impossible ()
    | Opcode.FBPA | Opcode.FBPN | Opcode.FBPU | Opcode.FBPG | Opcode.FBPUG
    | Opcode.FBPL | Opcode.FBPUL | Opcode.FBPLG | Opcode.FBPNE | Opcode.FBPE
    | Opcode.FBPUE | Opcode.FBPGE | Opcode.FBPUGE | Opcode.FBPLE
    | Opcode.FBPULE | Opcode.FBPO->
      match opr1, opr2, opr3, opr4 with
      | OprCC c, OprAddr k, OprImm 0b0, OprImm 0b0 ->
        prependDelimiter (Some ",pn ") builder
        ccToString c builder
        prependDelimiter (Some ", 0x") builder
        immToStringNoPrefix (k) builder
      | OprCC c, OprAddr k, OprImm 0b1, OprImm 0b0 ->
        prependDelimiter (Some ",a,pn ") builder
        ccToString c builder
        prependDelimiter (Some ", 0x") builder
        immToStringNoPrefix (k) builder
      | OprCC c, OprAddr k, OprImm 0b0, OprImm 0b1 ->
        prependDelimiter (Some ",pt ") builder
        ccToString c builder
        prependDelimiter (Some ", 0x") builder
        immToStringNoPrefix (k) builder
      | OprCC c, OprAddr k, OprImm 0b1, OprImm 0b1 ->
        prependDelimiter (Some ",a,pt ") builder
        ccToString c builder
        prependDelimiter (Some ", 0x") builder
        immToStringNoPrefix (k) builder
      | _ -> Utils.impossible ()
    | Opcode.LDFA | Opcode.LDDFA | Opcode.LDQFA | Opcode.LDSTUBA
    | Opcode.LDSBA | Opcode.LDSHA | Opcode.LDSWA | Opcode.LDUBA
    | Opcode.LDUHA | Opcode.LDUWA | Opcode.LDXA | Opcode.LDDA ->
      oprToString ins pc opr1 (Some " [") builder
      oprToString ins pc opr2 (Some " + ") builder
      oprToString ins pc opr3 (Some "] ") builder
      oprToString ins pc opr4 (Some ", ") builder
      buildComment4 opr1 opr2 opr3 opr4 builder
    | Opcode.BRZ | Opcode.BRLEZ | Opcode.BRLZ | Opcode.BRNZ
    | Opcode.BRGZ | Opcode.BRGEZ ->
      match opr1, opr2, opr3, opr4 with
      | OprReg reg, OprAddr k, OprImm 0b0, OprImm 0b0 ->
        prependDelimiter (Some ",pn ") builder
        buildReg ins reg builder
        prependDelimiter (Some ", 0x") builder
        immToStringNoPrefix (k) builder
      | OprReg reg, OprAddr k, OprImm 0b0, OprImm 0b1 ->
        prependDelimiter (Some ",pt ") builder
        buildReg ins reg builder
        prependDelimiter (Some ", 0x") builder
        immToStringNoPrefix (k) builder
      | OprReg reg, OprAddr k, OprImm 0b1, OprImm 0b0 ->
        prependDelimiter (Some ",a,pn ") builder
        buildReg ins reg builder
        prependDelimiter (Some ", 0x") builder
        immToStringNoPrefix (k) builder
      | OprReg reg, OprAddr k, OprImm 0b1, OprImm 0b1 ->
        prependDelimiter (Some ",a,pt ") builder
        buildReg ins reg builder
        prependDelimiter (Some ", 0x") builder
        immToStringNoPrefix (k) builder
      | _ -> Utils.impossible ()
    | Opcode.PREFETCHA ->
      oprToString ins pc opr1 (Some " [") builder
      oprToString ins pc opr2 (Some " + ") builder
      oprToString ins pc opr3 (Some "], ") builder
      oprToString ins pc opr4 (Some ", ") builder
      buildComment4 opr1 opr2 opr3 opr4 builder
    | Opcode.STBA | Opcode.STHA | Opcode.STWA | Opcode.STXA | Opcode.STDA ->
      oprToString ins pc opr1 (Some " ") builder
      oprToString ins pc opr2 (Some ", [") builder
      oprToString ins pc opr3 (Some " + ") builder
      oprToString ins pc opr4 (Some "] ") builder
      buildComment4 opr1 opr2 opr3 opr4 builder
    | Opcode.STFA | Opcode.STDFA | Opcode.STQFA ->
      oprToString ins pc opr1 (Some " ") builder
      oprToString ins pc opr2 (Some ", [") builder
      oprToString ins pc opr3 (Some " + ") builder
      oprToString ins pc opr4 (Some "] ") builder
      buildComment4 opr1 opr2 opr3 opr4 builder
    | Opcode.SWAPA ->
      oprToString ins pc opr1 (Some " [") builder
      oprToString ins pc opr2 (Some " + ") builder
      oprToString ins pc opr3 (Some "] ") builder
      oprToString ins pc opr4 (Some ", ") builder
      buildComment4 opr1 opr2 opr3 opr4 builder
    | Opcode.CASA | Opcode.CASXA ->
      oprToString ins pc opr1 (Some " [") builder
      oprToString ins pc opr2 (Some "] ") builder
      oprToString ins pc opr3 (Some ", ") builder
      oprToString ins pc opr4 (Some ", ") builder
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

let inline buildOpcode ins (builder: DisasmBuilder) =
  let str = opCodeToString ins.Opcode
  builder.Accumulate AsmWordKind.Mnemonic str

let disasm insInfo (builder: DisasmBuilder) =
  let pc = insInfo.Address
  if builder.ShowAddr then builder.AccumulateAddr () else ()
  buildOpcode insInfo builder
  buildOprs insInfo pc builder

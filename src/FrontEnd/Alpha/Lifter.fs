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

/// Chooses the lifter that each Alpha opcode is translated by.
module internal B2R2.FrontEnd.Alpha.Lifter

open B2R2.FrontEnd.Alpha.GeneralLifter
open B2R2.FrontEnd.Alpha.FloatLifter

/// Translates an Alpha instruction into its LowUIR statements.
let translate (ins: Instruction) bld =
  match ins.Opcode with
  | Op.LDA -> lda ins bld
  | Op.LDAH -> ldah ins bld
  | Op.LDBU -> ldbu ins bld
  | Op.LDWU -> ldwu ins bld
  | Op.LDL -> ldl ins bld
  | Op.LDQ -> ldq ins bld
  | Op.LDQ_U -> ldqu ins bld
  | Op.LDL_L -> ldll ins bld
  | Op.LDQ_L -> ldql ins bld
  | Op.STB -> stb ins bld
  | Op.STW -> stw ins bld
  | Op.STL -> stl ins bld
  | Op.STQ -> stq ins bld
  | Op.STQ_U -> stqu ins bld
  | Op.STL_C -> stlc ins bld
  | Op.STQ_C -> stqc ins bld
  | Op.LDS -> lds ins bld
  | Op.LDT -> ldt ins bld
  | Op.STS -> sts ins bld
  | Op.STT -> stt ins bld
  | Op.PREFETCH | Op.PREFETCH_EN | Op.PREFETCH_M | Op.PREFETCH_MEN
  | Op.FETCH | Op.FETCH_M | Op.ECB | Op.WH64 | Op.WH64EN
  | Op.TRAPB | Op.EXCB -> nop ins bld
  | Op.MB | Op.WMB -> memoryBarrier ins bld
  | Op.RPCC -> rpcc ins bld
  | Op.JMP -> jmp ins bld
  | Op.JSR -> jsr ins bld
  | Op.RET -> ret ins bld
  | Op.JSR_COROUTINE -> jsrCoroutine ins bld
  | Op.BR -> br ins bld
  | Op.BSR -> bsr ins bld
  | Op.BEQ -> beq ins bld
  | Op.BNE -> bne ins bld
  | Op.BLT -> blt ins bld
  | Op.BLE -> ble ins bld
  | Op.BGT -> bgt ins bld
  | Op.BGE -> bge ins bld
  | Op.BLBC -> blbc ins bld
  | Op.BLBS -> blbs ins bld
  | Op.FBEQ -> fbeq ins bld
  | Op.FBNE -> fbne ins bld
  | Op.FBLT -> fblt ins bld
  | Op.FBLE -> fble ins bld
  | Op.FBGT -> fbgt ins bld
  | Op.FBGE -> fbge ins bld
  | Op.ADDL | Op.ADDLV -> addl ins bld
  | Op.ADDQ | Op.ADDQV -> addq ins bld
  | Op.SUBL | Op.SUBLV -> subl ins bld
  | Op.SUBQ | Op.SUBQV -> subq ins bld
  | Op.S4ADDL -> s4addl ins bld
  | Op.S4ADDQ -> s4addq ins bld
  | Op.S8ADDL -> s8addl ins bld
  | Op.S8ADDQ -> s8addq ins bld
  | Op.S4SUBL -> s4subl ins bld
  | Op.S4SUBQ -> s4subq ins bld
  | Op.S8SUBL -> s8subl ins bld
  | Op.S8SUBQ -> s8subq ins bld
  | Op.CMPBGE -> cmpbge ins bld
  | Op.CMPEQ -> cmpeq ins bld
  | Op.CMPLT -> cmplt ins bld
  | Op.CMPLE -> cmple ins bld
  | Op.CMPULT -> cmpult ins bld
  | Op.CMPULE -> cmpule ins bld
  | Op.AND -> logicAnd ins bld
  | Op.BIC -> bic ins bld
  | Op.BIS -> bis ins bld
  | Op.ORNOT -> ornot ins bld
  | Op.XOR -> logicXor ins bld
  | Op.EQV -> eqv ins bld
  | Op.CMOVEQ -> cmoveq ins bld
  | Op.CMOVNE -> cmovne ins bld
  | Op.CMOVLT -> cmovlt ins bld
  | Op.CMOVLE -> cmovle ins bld
  | Op.CMOVGT -> cmovgt ins bld
  | Op.CMOVGE -> cmovge ins bld
  | Op.CMOVLBS -> cmovlbs ins bld
  | Op.CMOVLBC -> cmovlbc ins bld
  | Op.AMASK -> amask ins bld
  | Op.IMPLVER -> implver ins bld
  | Op.SLL -> sll ins bld
  | Op.SRL -> srl ins bld
  | Op.SRA -> sra ins bld
  | Op.EXTBL -> extbl ins bld
  | Op.EXTWL -> extwl ins bld
  | Op.EXTLL -> extll ins bld
  | Op.EXTQL -> extql ins bld
  | Op.EXTWH -> extwh ins bld
  | Op.EXTLH -> extlh ins bld
  | Op.EXTQH -> extqh ins bld
  | Op.INSBL -> insbl ins bld
  | Op.INSWL -> inswl ins bld
  | Op.INSLL -> insll ins bld
  | Op.INSQL -> insql ins bld
  | Op.INSWH -> inswh ins bld
  | Op.INSLH -> inslh ins bld
  | Op.INSQH -> insqh ins bld
  | Op.MSKBL -> mskbl ins bld
  | Op.MSKWL -> mskwl ins bld
  | Op.MSKLL -> mskll ins bld
  | Op.MSKQL -> mskql ins bld
  | Op.MSKWH -> mskwh ins bld
  | Op.MSKLH -> msklh ins bld
  | Op.MSKQH -> mskqh ins bld
  | Op.ZAP -> zap ins bld
  | Op.ZAPNOT -> zapnot ins bld
  | Op.MULL | Op.MULLV -> mull ins bld
  | Op.MULQ | Op.MULQV -> mulq ins bld
  | Op.UMULH -> umulh ins bld
  | Op.SEXTB -> sextb ins bld
  | Op.SEXTW -> sextw ins bld
  | Op.CTPOP -> ctpop ins bld
  | Op.CTLZ -> ctlz ins bld
  | Op.CTTZ -> cttz ins bld
  | Op.PERR -> perr ins bld
  | Op.UNPKBW -> unpkbw ins bld
  | Op.UNPKBL -> unpkbl ins bld
  | Op.PKWB -> pkwb ins bld
  | Op.PKLB -> pklb ins bld
  | Op.MINSB8 -> minsb8 ins bld
  | Op.MINSW4 -> minsw4 ins bld
  | Op.MINUB8 -> minub8 ins bld
  | Op.MINUW4 -> minuw4 ins bld
  | Op.MAXSB8 -> maxsb8 ins bld
  | Op.MAXSW4 -> maxsw4 ins bld
  | Op.MAXUB8 -> maxub8 ins bld
  | Op.MAXUW4 -> maxuw4 ins bld
  | Op.FTOIS -> ftois ins bld
  | Op.FTOIT -> ftoit ins bld
  | Op.ITOFS -> itofs ins bld
  | Op.ITOFT -> itoft ins bld
  | Op.SQRTS -> sqrts ins bld
  | Op.SQRTT -> sqrtt ins bld
  | Op.ADDS -> adds ins bld
  | Op.SUBS -> subs ins bld
  | Op.MULS -> muls ins bld
  | Op.DIVS -> divs ins bld
  | Op.ADDT -> addt ins bld
  | Op.SUBT -> subt ins bld
  | Op.MULT -> mult ins bld
  | Op.DIVT -> divt ins bld
  | Op.CMPTUN -> cmptun ins bld
  | Op.CMPTEQ -> cmpteq ins bld
  | Op.CMPTLT -> cmptlt ins bld
  | Op.CMPTLE -> cmptle ins bld
  | Op.CVTTS -> cvtts ins bld
  | Op.CVTST -> cvtst ins bld
  | Op.CVTTQ -> cvttq ins bld
  | Op.CVTQS -> cvtqs ins bld
  | Op.CVTQT -> cvtqt ins bld
  | Op.CPYS -> cpys ins bld
  | Op.CPYSN -> cpysn ins bld
  | Op.CPYSE -> cpyse ins bld
  | Op.CVTLQ -> cvtlq ins bld
  | Op.CVTQL -> cvtql ins bld
  | Op.MT_FPCR -> mtFpcr ins bld
  | Op.MF_FPCR -> mfFpcr ins bld
  | Op.FCMOVEQ -> fcmoveq ins bld
  | Op.FCMOVNE -> fcmovne ins bld
  | Op.FCMOVLT -> fcmovlt ins bld
  | Op.FCMOVLE -> fcmovle ins bld
  | Op.FCMOVGT -> fcmovgt ins bld
  | Op.FCMOVGE -> fcmovge ins bld
  | Op.LDF -> ldf ins bld
  | Op.STF -> stf ins bld
  | Op.LDG -> ldg ins bld
  | Op.STG -> stg ins bld
  | Op.ADDF -> addf ins bld
  | Op.SUBF -> subf ins bld
  | Op.MULF -> mulf ins bld
  | Op.DIVF -> divf ins bld
  | Op.ADDG -> addg ins bld
  | Op.SUBG -> subg ins bld
  | Op.MULG -> mulg ins bld
  | Op.DIVG -> divg ins bld
  | Op.SQRTF -> sqrtf ins bld
  | Op.SQRTG -> sqrtg ins bld
  | Op.CMPGEQ -> cmpgeq ins bld
  | Op.CMPGLT -> cmpglt ins bld
  | Op.CMPGLE -> cmpgle ins bld
  | Op.CVTGF -> cvtgf ins bld
  | Op.CVTGQ -> cvtgq ins bld
  | Op.CVTQF -> cvtqf ins bld
  | Op.CVTQG -> cvtqg ins bld
  | Op.CVTDG -> cvtdg ins bld
  | Op.CVTGD -> cvtgd ins bld
  | Op.ITOFF -> itoff ins bld
  | Op.CALL_PAL -> callPal ins bld
  (* rc/rs report whether an interruption or an exception happened between the
     two of them, which is not a function of the program's state at all: there
     is no value to compute here, and modelling one would be inventing an
     answer. The handbook adds that the flag's behaviour across a load-locked
     or a store-conditional is UNPREDICTABLE, and that the pair is "intended
     only for use by the VAX-to-Alpha software translator" (4.12). They are
     named rather than left to the arm below so that every opcode the parser
     produces is accounted for here, that arm covering only the encoding the
     parser reads no instruction out of. *)
  | Op.RC | Op.RS -> unsupported ins bld
  | _ -> unsupported ins bld

// vim: set tw=80 sts=2 sw=2:

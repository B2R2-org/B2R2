(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the Software), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*)

module B2R2.FrontEnd.BinLifter.SH4.Lifter

open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.SH4
open B2R2.FrontEnd.BinLifter.SH4.GeneralLifter

/// Translate IR.
let translate (ins: InsInfo) insLen (ctxt: TranslationContext) =
  match ins.Opcode with
  | Opcode.ADD ->  add ins insLen ctxt
  | Opcode.ADDC -> addc ins insLen ctxt
  | Opcode.ADDV -> addv ins insLen ctxt
  | Opcode.AND -> ``and`` ins insLen ctxt
  | Opcode.ANDB -> andb ins insLen ctxt
  | Opcode.BF ->  bf ins insLen ctxt
  | Opcode.BFS -> bfs ins insLen ctxt
  | Opcode.BRA -> bra ins insLen ctxt
  | Opcode.BRAF -> braf ins insLen ctxt
  | Opcode.BSR -> bsr ins insLen ctxt
  | Opcode.BSRF -> bsrf ins insLen ctxt
  | Opcode.BT -> bt ins insLen ctxt
  | Opcode.BTS -> bts ins insLen ctxt
  | Opcode.CLRMAC -> clrmac ins insLen ctxt
  | Opcode.CLRS -> clrs insLen ctxt
  | Opcode.CLRT -> clrt insLen ctxt
  | Opcode.CMPEQ -> cmpeq ins insLen ctxt
  | Opcode.CMPGE  -> cmpge ins insLen ctxt
  | Opcode.CMPGT -> cmpgt ins insLen ctxt
  | Opcode.CMPHI -> cmphi ins insLen ctxt
  | Opcode.CMPHS -> cmphs ins insLen ctxt
  | Opcode.CMPPL -> cmppl ins insLen ctxt
  | Opcode.CMPPZ -> cmppz ins insLen ctxt
  | Opcode.CMPSTR -> cmpstr ins insLen ctxt
  | Opcode.DIV0S -> div0s ins insLen ctxt
  | Opcode.DIV0U -> div0u ins insLen ctxt
  | Opcode.DIV1 -> div1 ins insLen ctxt
  | Opcode.DMULSL -> dmulsl ins insLen ctxt
  | Opcode.DMULUL -> dmulul ins insLen ctxt
  | Opcode.DT -> dt ins insLen ctxt
  | Opcode.EXTSB -> extsb ins insLen ctxt
  | Opcode.EXTSW -> extsw ins insLen ctxt
  | Opcode.EXTUB -> extub ins insLen ctxt
  | Opcode.EXTUW -> extuw ins insLen ctxt
  | Opcode.FABS -> fabs ins insLen ctxt
  | Opcode.FADD -> fadd ins insLen ctxt
  | Opcode.FCMPEQ -> fcmpeq ins insLen ctxt
  | Opcode.FCMPGT -> fcmpgt ins insLen ctxt
  | Opcode.FCNVDS -> fcnvds ins insLen ctxt
  | Opcode.FCNVSD -> fcnvsd ins insLen ctxt
  | Opcode.FDIV -> fdiv ins insLen ctxt
  | Opcode.FIPR -> fipr ins insLen ctxt
  | Opcode.FLDI0 -> fldi0 ins insLen ctxt
  | Opcode.FLDI1 -> fldi1 ins insLen ctxt
  | Opcode.FLDS -> flds ins insLen ctxt
  | Opcode.FLOAT -> ``float`` ins insLen ctxt
  | Opcode.FMAC -> fmac ins insLen ctxt
  | Opcode.FMOV -> fmov ins insLen ctxt
  | Opcode.FMOVS -> fmovs ins insLen ctxt
  | Opcode.FMUL -> fmul ins insLen ctxt
  | Opcode.FNEG -> fneg ins insLen ctxt
  | Opcode.FRCHG -> frchg ins insLen ctxt
  | Opcode.FSCHG -> fschg ins insLen ctxt
  | Opcode.FSQRT -> fsqrt ins insLen ctxt
  | Opcode.FSTS -> fsts ins insLen ctxt
  | Opcode.FSUB -> fsub ins insLen ctxt
  | Opcode.FTRC -> ftrc ins insLen ctxt
  | Opcode.FTRV -> ftrv ins insLen ctxt
  | Opcode.JMP -> jmp ins insLen ctxt
  | Opcode.JSR -> jsr ins insLen ctxt
  | Opcode.LDC -> ldc ins insLen ctxt
  | Opcode.LDCL -> ldcl ins insLen ctxt
  | Opcode.LDS -> lds ins insLen ctxt
  | Opcode.LDSL -> ldsl ins insLen ctxt
  | Opcode.LDTLB -> ldtlb ins insLen ctxt
  | Opcode.MACL -> macl ins insLen ctxt
  | Opcode.MACW -> macw ins insLen ctxt
  | Opcode.MOV -> mov ins insLen ctxt
  | Opcode.MOVA -> mova ins insLen ctxt
  | Opcode.MOVB -> movb ins insLen ctxt
  | Opcode.MOVW -> movw ins insLen ctxt
  | Opcode.MOVL -> movl ins insLen ctxt
  | Opcode.MOVCAL -> movcal ins insLen ctxt
  | Opcode.MOVT -> movt ins insLen ctxt
  | Opcode.MULL -> mull ins insLen ctxt
  | Opcode.MULSW -> mulsw ins insLen ctxt
  | Opcode.MULUW -> muluw ins insLen ctxt
  | Opcode.NEG -> neg ins insLen ctxt
  | Opcode.NEGC -> negc ins insLen ctxt
  | Opcode.NOP -> nop ins insLen ctxt
  | Opcode.NOT -> ``not`` ins insLen ctxt
  | Opcode.OCBI -> ocbi ins insLen ctxt
  | Opcode.OCBP -> ocbp ins insLen ctxt
  | Opcode.OCBWB -> ocbwb ins insLen ctxt
  | Opcode.OR -> ``or`` ins insLen ctxt
  | Opcode.ORB -> orb ins insLen ctxt
  | Opcode.PREF -> pref ins insLen ctxt
  | Opcode.ROTCL -> rotcl ins insLen ctxt
  | Opcode.ROTCR -> rotcr ins insLen ctxt
  | Opcode.ROTL -> rotl ins insLen ctxt
  | Opcode.ROTR -> rotr ins insLen ctxt
  | Opcode.RTE -> rte ins insLen ctxt
  | Opcode.RTS -> rts ins insLen ctxt
  | Opcode.SETS -> sets ins insLen ctxt
  | Opcode.SETT -> sett ins insLen ctxt
  | Opcode.SHAD -> shad ins insLen ctxt
  | Opcode.SHAL -> shal ins insLen ctxt
  | Opcode.SHAR -> shar ins insLen ctxt
  | Opcode.SHLD -> shld ins insLen ctxt
  | Opcode.SHLL -> shll ins insLen ctxt
  | Opcode.SHLL2 -> shll2 ins insLen ctxt
  | Opcode.SHLL8 -> shll8 ins insLen ctxt
  | Opcode.SHLL16 -> shll16 ins insLen ctxt
  | Opcode.SHLR -> shlr ins insLen ctxt
  | Opcode.SHLR2 -> shlr2 ins insLen ctxt
  | Opcode.SHLR8 -> shlr8 ins insLen ctxt
  | Opcode.SHLR16 -> shlr16 ins insLen ctxt
  | Opcode.SLEEP -> sleep ins insLen ctxt
  | Opcode.STC -> stc ins insLen ctxt
  | Opcode.STCL -> stcl ins insLen ctxt
  | Opcode.STS -> sts ins insLen ctxt
  | Opcode.STSL -> stsl ins insLen ctxt
  | Opcode.SUB -> sub ins insLen ctxt
  | Opcode.SUBC -> subc ins insLen ctxt
  | Opcode.SUBV -> subv ins insLen ctxt
  | Opcode.SWAPB -> swapb ins insLen ctxt
  | Opcode.SWAPW -> swapw ins insLen ctxt
  | Opcode.TASB -> tasb ins insLen ctxt
  | Opcode.TRAPA -> trapa ins insLen ctxt
  | Opcode.TST -> tst ins insLen ctxt
  | Opcode.TSTB -> tstb ins insLen ctxt
  | Opcode.XOR -> xor ins insLen ctxt
  | Opcode.XORB -> xorb ins insLen ctxt
  | Opcode.XTRCT -> xtrct ins insLen ctxt
  | Opcode.InvalidOp -> raise InvalidOpcodeException
  | _ -> raise InvalidOpcodeException

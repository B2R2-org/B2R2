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

module B2R2.FrontEnd.SH4.Lifter

open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.SH4.GeneralLifter

/// Translate IR.
let translate (ins: InsInfo) insLen bld =
  match ins.Opcode with
  | Opcode.ADD ->  add ins insLen bld
  | Opcode.ADDC -> addc ins insLen bld
  | Opcode.ADDV -> addv ins insLen bld
  | Opcode.AND -> ``and`` ins insLen bld
  | Opcode.ANDB -> andb ins insLen bld
  | Opcode.BF ->  bf ins insLen bld
  | Opcode.BFS -> bfs ins insLen bld
  | Opcode.BRA -> bra ins insLen bld
  | Opcode.BRAF -> braf ins insLen bld
  | Opcode.BSR -> bsr ins insLen bld
  | Opcode.BSRF -> bsrf ins insLen bld
  | Opcode.BT -> bt ins insLen bld
  | Opcode.BTS -> bts ins insLen bld
  | Opcode.CLRMAC -> clrmac ins insLen bld
  | Opcode.CLRS -> clrs ins insLen bld
  | Opcode.CLRT -> clrt ins insLen bld
  | Opcode.CMPEQ -> cmpeq ins insLen bld
  | Opcode.CMPGE  -> cmpge ins insLen bld
  | Opcode.CMPGT -> cmpgt ins insLen bld
  | Opcode.CMPHI -> cmphi ins insLen bld
  | Opcode.CMPHS -> cmphs ins insLen bld
  | Opcode.CMPPL -> cmppl ins insLen bld
  | Opcode.CMPPZ -> cmppz ins insLen bld
  | Opcode.CMPSTR -> cmpstr ins insLen bld
  | Opcode.DIV0S -> div0s ins insLen bld
  | Opcode.DIV0U -> div0u ins insLen bld
  | Opcode.DIV1 -> div1 ins insLen bld
  | Opcode.DMULSL -> dmulsl ins insLen bld
  | Opcode.DMULUL -> dmulul ins insLen bld
  | Opcode.DT -> dt ins insLen bld
  | Opcode.EXTSB -> extsb ins insLen bld
  | Opcode.EXTSW -> extsw ins insLen bld
  | Opcode.EXTUB -> extub ins insLen bld
  | Opcode.EXTUW -> extuw ins insLen bld
  | Opcode.FABS -> fabs ins insLen bld
  | Opcode.FADD -> fadd ins insLen bld
  | Opcode.FCMPEQ -> fcmpeq ins insLen bld
  | Opcode.FCMPGT -> fcmpgt ins insLen bld
  | Opcode.FCNVDS -> fcnvds ins insLen bld
  | Opcode.FCNVSD -> fcnvsd ins insLen bld
  | Opcode.FDIV -> fdiv ins insLen bld
  | Opcode.FIPR -> fipr ins insLen bld
  | Opcode.FLDI0 -> fldi0 ins insLen bld
  | Opcode.FLDI1 -> fldi1 ins insLen bld
  | Opcode.FLDS -> flds ins insLen bld
  | Opcode.FLOAT -> ``float`` ins insLen bld
  | Opcode.FMAC -> fmac ins insLen bld
  | Opcode.FMOV -> fmov ins insLen bld
  | Opcode.FMOVS -> fmovs ins insLen bld
  | Opcode.FMUL -> fmul ins insLen bld
  | Opcode.FNEG -> fneg ins insLen bld
  | Opcode.FRCHG -> frchg ins insLen bld
  | Opcode.FSCHG -> fschg ins insLen bld
  | Opcode.FSQRT -> fsqrt ins insLen bld
  | Opcode.FSTS -> fsts ins insLen bld
  | Opcode.FSUB -> fsub ins insLen bld
  | Opcode.FTRC -> ftrc ins insLen bld
  | Opcode.FTRV -> ftrv ins insLen bld
  | Opcode.JMP -> jmp ins insLen bld
  | Opcode.JSR -> jsr ins insLen bld
  | Opcode.LDC -> ldc ins insLen bld
  | Opcode.LDCL -> ldcl ins insLen bld
  | Opcode.LDS -> lds ins insLen bld
  | Opcode.LDSL -> ldsl ins insLen bld
  | Opcode.LDTLB -> ldtlb ins insLen bld
  | Opcode.MACL -> macl ins insLen bld
  | Opcode.MACW -> macw ins insLen bld
  | Opcode.MOV -> mov ins insLen bld
  | Opcode.MOVA -> mova ins insLen bld
  | Opcode.MOVB -> movb ins insLen bld
  | Opcode.MOVW -> movw ins insLen bld
  | Opcode.MOVL -> movl ins insLen bld
  | Opcode.MOVCAL -> movcal ins insLen bld
  | Opcode.MOVT -> movt ins insLen bld
  | Opcode.MULL -> mull ins insLen bld
  | Opcode.MULSW -> mulsw ins insLen bld
  | Opcode.MULUW -> muluw ins insLen bld
  | Opcode.NEG -> neg ins insLen bld
  | Opcode.NEGC -> negc ins insLen bld
  | Opcode.NOP -> nop ins insLen bld
  | Opcode.NOT -> ``not`` ins insLen bld
  | Opcode.OCBI -> ocbi ins insLen bld
  | Opcode.OCBP -> ocbp ins insLen bld
  | Opcode.OCBWB -> ocbwb ins insLen bld
  | Opcode.OR -> ``or`` ins insLen bld
  | Opcode.ORB -> orb ins insLen bld
  | Opcode.PREF -> pref ins insLen bld
  | Opcode.ROTCL -> rotcl ins insLen bld
  | Opcode.ROTCR -> rotcr ins insLen bld
  | Opcode.ROTL -> rotl ins insLen bld
  | Opcode.ROTR -> rotr ins insLen bld
  | Opcode.RTE -> rte ins insLen bld
  | Opcode.RTS -> rts ins insLen bld
  | Opcode.SETS -> sets ins insLen bld
  | Opcode.SETT -> sett ins insLen bld
  | Opcode.SHAD -> shad ins insLen bld
  | Opcode.SHAL -> shal ins insLen bld
  | Opcode.SHAR -> shar ins insLen bld
  | Opcode.SHLD -> shld ins insLen bld
  | Opcode.SHLL -> shll ins insLen bld
  | Opcode.SHLL2 -> shll2 ins insLen bld
  | Opcode.SHLL8 -> shll8 ins insLen bld
  | Opcode.SHLL16 -> shll16 ins insLen bld
  | Opcode.SHLR -> shlr ins insLen bld
  | Opcode.SHLR2 -> shlr2 ins insLen bld
  | Opcode.SHLR8 -> shlr8 ins insLen bld
  | Opcode.SHLR16 -> shlr16 ins insLen bld
  | Opcode.SLEEP -> sleep ins insLen bld
  | Opcode.STC -> stc ins insLen bld
  | Opcode.STCL -> stcl ins insLen bld
  | Opcode.STS -> sts ins insLen bld
  | Opcode.STSL -> stsl ins insLen bld
  | Opcode.SUB -> sub ins insLen bld
  | Opcode.SUBC -> subc ins insLen bld
  | Opcode.SUBV -> subv ins insLen bld
  | Opcode.SWAPB -> swapb ins insLen bld
  | Opcode.SWAPW -> swapw ins insLen bld
  | Opcode.TASB -> tasb ins insLen bld
  | Opcode.TRAPA -> trapa ins insLen bld
  | Opcode.TST -> tst ins insLen bld
  | Opcode.TSTB -> tstb ins insLen bld
  | Opcode.XOR -> xor ins insLen bld
  | Opcode.XORB -> xorb ins insLen bld
  | Opcode.XTRCT -> xtrct ins insLen bld
  | Opcode.InvalidOp -> raise InvalidOpcodeException
  | _ -> raise InvalidOpcodeException

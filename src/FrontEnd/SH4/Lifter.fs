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

module internal B2R2.FrontEnd.SH4.Lifter

open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.SH4.GeneralLifter

/// Translate IR.
let translate (ins: Instruction) bld =
  match ins.Opcode with
  | Opcode.ADD -> add ins bld
  | Opcode.ADDC -> addc ins bld
  | Opcode.ADDV -> addv ins bld
  | Opcode.AND -> ``and`` ins bld
  | Opcode.ANDB -> andb ins bld
  | Opcode.BF -> bf ins bld
  | Opcode.BFS -> bfs ins bld
  | Opcode.BRA -> bra ins bld
  | Opcode.BRAF -> braf ins bld
  | Opcode.BSR -> bsr ins bld
  | Opcode.BSRF -> bsrf ins bld
  | Opcode.BT -> bt ins bld
  | Opcode.BTS -> bts ins bld
  | Opcode.CLRMAC -> clrmac ins bld
  | Opcode.CLRS -> clrs ins bld
  | Opcode.CLRT -> clrt ins bld
  | Opcode.CMPEQ -> cmpeq ins bld
  | Opcode.CMPGE -> cmpge ins bld
  | Opcode.CMPGT -> cmpgt ins bld
  | Opcode.CMPHI -> cmphi ins bld
  | Opcode.CMPHS -> cmphs ins bld
  | Opcode.CMPPL -> cmppl ins bld
  | Opcode.CMPPZ -> cmppz ins bld
  | Opcode.CMPSTR -> cmpstr ins bld
  | Opcode.DIV0S -> div0s ins bld
  | Opcode.DIV0U -> div0u ins bld
  | Opcode.DIV1 -> div1 ins bld
  | Opcode.DMULSL -> dmulsl ins bld
  | Opcode.DMULUL -> dmulul ins bld
  | Opcode.DT -> dt ins bld
  | Opcode.EXTSB -> extsb ins bld
  | Opcode.EXTSW -> extsw ins bld
  | Opcode.EXTUB -> extub ins bld
  | Opcode.EXTUW -> extuw ins bld
  | Opcode.FABS -> fabs ins bld
  | Opcode.FADD -> fadd ins bld
  | Opcode.FCMPEQ -> fcmpeq ins bld
  | Opcode.FCMPGT -> fcmpgt ins bld
  | Opcode.FCNVDS -> fcnvds ins bld
  | Opcode.FCNVSD -> fcnvsd ins bld
  | Opcode.FDIV -> fdiv ins bld
  | Opcode.FIPR -> fipr ins bld
  | Opcode.FLDI0 -> fldi0 ins bld
  | Opcode.FLDI1 -> fldi1 ins bld
  | Opcode.FLDS -> flds ins bld
  | Opcode.FLOAT -> ``float`` ins bld
  | Opcode.FMAC -> fmac ins bld
  | Opcode.FMOV -> fmov ins bld
  | Opcode.FMOVS -> fmovs ins bld
  | Opcode.FMUL -> fmul ins bld
  | Opcode.FNEG -> fneg ins bld
  | Opcode.FRCHG -> frchg ins bld
  | Opcode.FSCHG -> fschg ins bld
  | Opcode.FSQRT -> fsqrt ins bld
  | Opcode.FSTS -> fsts ins bld
  | Opcode.FSUB -> fsub ins bld
  | Opcode.FTRC -> ftrc ins bld
  | Opcode.FTRV -> ftrv ins bld
  | Opcode.JMP -> jmp ins bld
  | Opcode.JSR -> jsr ins bld
  | Opcode.LDC -> ldc ins bld
  | Opcode.LDCL -> ldcl ins bld
  | Opcode.LDS -> lds ins bld
  | Opcode.LDSL -> ldsl ins bld
  | Opcode.LDTLB -> ldtlb ins bld
  | Opcode.MACL -> macl ins bld
  | Opcode.MACW -> macw ins bld
  | Opcode.MOV -> mov ins bld
  | Opcode.MOVA -> mova ins bld
  | Opcode.MOVB -> movb ins bld
  | Opcode.MOVW -> movw ins bld
  | Opcode.MOVL -> movl ins bld
  | Opcode.MOVCAL -> movcal ins bld
  | Opcode.MOVT -> movt ins bld
  | Opcode.MULL -> mull ins bld
  | Opcode.MULSW -> mulsw ins bld
  | Opcode.MULUW -> muluw ins bld
  | Opcode.NEG -> neg ins bld
  | Opcode.NEGC -> negc ins bld
  | Opcode.NOP -> nop ins bld
  | Opcode.NOT -> ``not`` ins bld
  | Opcode.OCBI -> ocbi ins bld
  | Opcode.OCBP -> ocbp ins bld
  | Opcode.OCBWB -> ocbwb ins bld
  | Opcode.OR -> ``or`` ins bld
  | Opcode.ORB -> orb ins bld
  | Opcode.PREF -> pref ins bld
  | Opcode.ROTCL -> rotcl ins bld
  | Opcode.ROTCR -> rotcr ins bld
  | Opcode.ROTL -> rotl ins bld
  | Opcode.ROTR -> rotr ins bld
  | Opcode.RTE -> rte ins bld
  | Opcode.RTS -> rts ins bld
  | Opcode.SETS -> sets ins bld
  | Opcode.SETT -> sett ins bld
  | Opcode.SHAD -> shad ins bld
  | Opcode.SHAL -> shal ins bld
  | Opcode.SHAR -> shar ins bld
  | Opcode.SHLD -> shld ins bld
  | Opcode.SHLL -> shll ins bld
  | Opcode.SHLL2 -> shll2 ins bld
  | Opcode.SHLL8 -> shll8 ins bld
  | Opcode.SHLL16 -> shll16 ins bld
  | Opcode.SHLR -> shlr ins bld
  | Opcode.SHLR2 -> shlr2 ins bld
  | Opcode.SHLR8 -> shlr8 ins bld
  | Opcode.SHLR16 -> shlr16 ins bld
  | Opcode.SLEEP -> sleep ins bld
  | Opcode.STC -> stc ins bld
  | Opcode.STCL -> stcl ins bld
  | Opcode.STS -> sts ins bld
  | Opcode.STSL -> stsl ins bld
  | Opcode.SUB -> sub ins bld
  | Opcode.SUBC -> subc ins bld
  | Opcode.SUBV -> subv ins bld
  | Opcode.SWAPB -> swapb ins bld
  | Opcode.SWAPW -> swapw ins bld
  | Opcode.TASB -> tasb ins bld
  | Opcode.TRAPA -> trapa ins bld
  | Opcode.TST -> tst ins bld
  | Opcode.TSTB -> tstb ins bld
  | Opcode.XOR -> xor ins bld
  | Opcode.XORB -> xorb ins bld
  | Opcode.XTRCT -> xtrct ins bld
  (* No parser produces this opcode: an undecodable encoding is reported as a
     parsing failure, so an instruction never carries it this far. *)
  | Opcode.InvalidOp -> B2R2.Terminator.impossible ()
  | o -> raise (NotImplementedIRException(o.ToString()))

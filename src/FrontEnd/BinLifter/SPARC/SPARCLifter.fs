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

module B2R2.FrontEnd.BinLifter.SPARC.Lifter

open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.SPARC
open B2R2.FrontEnd.BinLifter.SPARC.GeneralLifter

/// Translate IR.
let translate (ins: InsInfo) insLen (ctxt: TranslationContext) =
  match ins.Opcode with
  | Opcode.ADD -> add ins insLen ctxt
  | Opcode.ADDcc -> addcc ins insLen ctxt
  | Opcode.ADDC -> addC ins insLen ctxt
  | Opcode.ADDCcc -> addCcc ins insLen ctxt
  | Opcode.AND -> ``and`` ins insLen ctxt
  | Opcode.ANDcc -> andcc ins insLen ctxt
  | Opcode.ANDN -> andn ins insLen ctxt
  | Opcode.ANDNcc -> andncc ins insLen ctxt
  | Opcode.BPA | Opcode.BPN | Opcode.BPNE | Opcode.BPE | Opcode.BPG
  | Opcode.BPLE | Opcode.BPGE | Opcode.BPL | Opcode.BPGU | Opcode.BPLEU
  | Opcode.BPCC | Opcode.BPCS | Opcode.BPPOS | Opcode.BPNEG | Opcode.BPVC
  | Opcode.BPVS -> branch ins insLen ctxt
  | Opcode.BA | Opcode.BN | Opcode.BNE | Opcode.BE | Opcode.BG
  | Opcode.BLE | Opcode.BGE | Opcode.BL | Opcode.BGU | Opcode.BLEU
  | Opcode.BCC | Opcode.BCS | Opcode.BPOS | Opcode.BNEG | Opcode.BVC
  | Opcode.BVS -> branch ins insLen ctxt
  | Opcode.BRZ | Opcode.BRLEZ | Opcode.BRLZ | Opcode.BRNZ | Opcode.BRGZ
  | Opcode.BRGEZ -> branch ins insLen ctxt
  | Opcode.CALL -> call ins insLen ctxt
  | Opcode.CASA | Opcode.CASXA -> casa ins insLen ctxt
  | Opcode.DONE -> ``done`` ins insLen ctxt
  | Opcode.FABSs | Opcode.FABSd | Opcode.FABSq -> fabs ins insLen ctxt
  | Opcode.FADDs | Opcode.FADDd | Opcode.FADDq-> fadd ins insLen ctxt
  | Opcode.FBA | Opcode.FBN | Opcode.FBU | Opcode.FBG | Opcode.FBUG
  | Opcode.FBL | Opcode.FBUL | Opcode.FBLG | Opcode.FBNE | Opcode.FBE
  | Opcode.FBUE | Opcode.FBGE | Opcode.FBUGE | Opcode.FBLE | Opcode.FBULE
  | Opcode.FBO -> fbranch ins insLen ctxt
  | Opcode.FBPA | Opcode.FBPN | Opcode.FBPU | Opcode.FBPG | Opcode.FBPUG
  | Opcode.FBPL | Opcode.FBPUL | Opcode.FBPLG | Opcode.FBPNE | Opcode.FBPE
  | Opcode.FBPUE | Opcode.FBPGE | Opcode.FBPUGE | Opcode.FBPLE | Opcode.FBPULE
  | Opcode.FBPO -> fbranch ins insLen ctxt
  | Opcode.FCMPs | Opcode.FCMPd | Opcode.FCMPq | Opcode.FCMPEs | Opcode.FCMPEd
  | Opcode.FCMPEq -> fcmp ins insLen ctxt
  | Opcode.FDIVs | Opcode.FDIVd | Opcode.FDIVq -> fdiv ins insLen ctxt
  | Opcode.FiTOd | Opcode.FiTOd | Opcode.FiTOq -> fito ins insLen ctxt
  | Opcode.FMOVs | Opcode.FMOVd | Opcode.FMOVq -> fmov ins insLen ctxt
  (* Fix Me *)
  | Opcode.FMOVA | Opcode.FMOVN | Opcode.FMOVNE | Opcode.FMOVE | Opcode.FMOVG
  | Opcode.FMOVLE | Opcode.FMOVGE | Opcode.FMOVL | Opcode.FMOVGU | Opcode.FMOVLE
  | Opcode.FMOVLEU | Opcode.FMOVCC | Opcode.FMOVCS | Opcode.FMOVPOS
  | Opcode.FMOVNEG | Opcode.FMOVVC | Opcode.FMOVVS | Opcode.FMOVFA
  | Opcode.FMOVFN | Opcode.FMOVFU | Opcode.FMOVFG | Opcode.FMOVFUG
  | Opcode.FMOVFL | Opcode.FMOVFUL | Opcode.FMOVFLG | Opcode.FMOVFNE
  | Opcode.FMOVFE | Opcode.FMOVFUE | Opcode.FMOVFGE | Opcode.FMOVFUGE
  | Opcode.FMOVFLE | Opcode.FMOVFULE | Opcode.FMOVFO -> fmovcc ins insLen ctxt
  | Opcode.FMOVRZ | Opcode.FMOVRLEZ | Opcode.FMOVRLZ | Opcode.FMOVRNZ
  | Opcode.FMOVRGZ | Opcode.FMOVRGEZ -> fmovr ins insLen ctxt
  | Opcode.FMULs | Opcode.FMULd | Opcode.FMULq -> fmul ins insLen ctxt
  | Opcode.FNEGs | Opcode.FNEGd | Opcode.FNEGq -> fneg ins insLen ctxt
  | Opcode.FsMULd | Opcode.FdMULq -> fsmuld ins insLen ctxt
  | Opcode.FSQRTs | Opcode.FSQRTd | Opcode.FSQRTq -> fsqrt ins insLen ctxt
  | Opcode.FsTOx | Opcode.FdTOx | Opcode.FqTOx -> ftox ins insLen ctxt
  | Opcode.FsTOi | Opcode.FdTOi | Opcode.FqTOi -> ftoi ins insLen ctxt
  | Opcode.FsTOd | Opcode.FsTOq | Opcode.FdTOs | Opcode.FdTOq | Opcode.FqTOs
  | Opcode.FqTOd -> fto ins insLen ctxt
  | Opcode.FSUBs | Opcode.FSUBd | Opcode.FSUBq -> fsub ins insLen ctxt
  | Opcode.FxTOs | Opcode.FxTOd | Opcode.FxTOq -> fxto ins insLen ctxt
  | Opcode.JMPL -> jmpl ins insLen ctxt
  | Opcode.LDF | Opcode.LDDF | Opcode.LDQF -> ldf ins insLen ctxt
  | Opcode.LDFA | Opcode.LDDFA | Opcode.LDQFA -> ldfa ins insLen ctxt
  | Opcode.LDFSR | Opcode.LDXFSR -> ldfsr ins insLen ctxt
  | Opcode.LDSB | Opcode.LDSH | Opcode.LDSW | Opcode.LDUB | Opcode.LDUH
  | Opcode.LDUW | Opcode.LDX | Opcode.LDD -> ld ins insLen ctxt
  | Opcode.LDSBA | Opcode.LDSHA | Opcode.LDSWA | Opcode.LDUBA | Opcode.LDUHA
  | Opcode.LDUWA | Opcode.LDXA | Opcode.LDDA -> lda ins insLen ctxt
  | Opcode.LDSTUB -> ldstub ins insLen ctxt
  | Opcode.LDSTUBA -> ldstuba ins insLen ctxt
  | Opcode.MEMBAR -> membar ins insLen ctxt
  | Opcode.MOVA | Opcode.MOVN | Opcode.MOVNE | Opcode.MOVE | Opcode.MOVG
  | Opcode.MOVLE | Opcode.MOVGE | Opcode.MOVL | Opcode.MOVGU | Opcode.MOVLEU
  | Opcode.MOVCC | Opcode.MOVCS | Opcode.MOVPOS | Opcode.MOVNEG | Opcode.MOVVC
  | Opcode.MOVVS -> movcc ins insLen ctxt
  | Opcode.MOVFA | Opcode.MOVFN | Opcode.MOVFU | Opcode.MOVFG | Opcode.MOVFUG
  | Opcode.MOVFL  | Opcode.MOVFUL | Opcode.MOVFLG | Opcode.MOVFNE | Opcode.MOVFE
  | Opcode.MOVFUE | Opcode.MOVFGE | Opcode.MOVFUGE | Opcode.MOVFLE
  | Opcode.MOVFULE | Opcode.MOVFO -> movcc ins insLen ctxt
  | Opcode.MOVRZ | Opcode.MOVRLEZ | Opcode.MOVRLZ | Opcode.MOVRNZ
  | Opcode.MOVRGZ | Opcode.MOVRGEZ -> movr ins insLen ctxt
  | Opcode.MULScc -> mulscc ins insLen ctxt
  | Opcode.MULX -> mulx ins insLen ctxt
  | Opcode.NOP -> nop insLen
  | Opcode.OR | Opcode.ORcc | Opcode.ORN | Opcode.ORNcc ->
      ``or`` ins insLen ctxt
  | Opcode.POPC -> popc ins insLen ctxt
  | Opcode.PREFETCH | Opcode.PREFETCHA -> nop insLen
  | Opcode.RDASI | Opcode.RDASR | Opcode.RDCCR | Opcode.RDFPRS | Opcode.RDPC
  | Opcode.RDTICK | Opcode.RDY -> rd ins insLen ctxt
  | Opcode.RESTORE -> restore ins insLen ctxt
  | Opcode.RESTORED -> nop insLen
  | Opcode.RETRY -> retry ins insLen ctxt
  | Opcode.RETURN -> nop insLen
  | Opcode.SAVE -> save ins insLen ctxt
  | Opcode.SAVED -> nop insLen
  | Opcode.SDIVX -> sdivx ins insLen ctxt
  | Opcode.SETHI -> sethi ins insLen ctxt
  | Opcode.SIR -> nop insLen
  | Opcode.SLL | Opcode.SLLX -> sll ins insLen ctxt
  | Opcode.SMUL | Opcode.SMULcc -> smul ins insLen ctxt
  | Opcode.SRA | Opcode.SRAX -> sra ins insLen ctxt
  | Opcode.SRL | Opcode.SRLX -> srl ins insLen ctxt
  | Opcode.STB | Opcode.STH | Opcode.STW | Opcode.STX | Opcode.STD ->
      st ins insLen ctxt
  | Opcode.STBA | Opcode.STHA | Opcode.STWA | Opcode.STXA | Opcode.STDA ->
      sta ins insLen ctxt
  | Opcode.STBAR -> nop insLen
  | Opcode.STF | Opcode.STDF | Opcode.STQF | Opcode.STFSR | Opcode.STXFSR ->
      stf ins insLen ctxt
  | Opcode.STFA | Opcode.STDFA | Opcode.STQFA -> stfa ins insLen ctxt
  | Opcode.SUB -> sub ins insLen ctxt
  | Opcode.SUBcc -> subcc ins insLen ctxt
  | Opcode.SUBC -> subC ins insLen ctxt
  | Opcode.SUBCcc -> subCcc ins insLen ctxt
  | Opcode.SWAP -> swap ins insLen ctxt
  | Opcode.SWAPA -> swapa ins insLen ctxt
  | Opcode.TADDcc -> taddcc ins insLen ctxt
  | Opcode.TADDccTV -> taddcctv ins insLen ctxt
  | Opcode.TA | Opcode.TN | Opcode.TNE | Opcode.TE | Opcode.TG | Opcode.TLE
  | Opcode.TGE | Opcode.TL | Opcode.TGU | Opcode.TLEU | Opcode.TCC | Opcode.TCS
  | Opcode.TPOS | Opcode.TNEG | Opcode.TVC | Opcode.TVS -> nop insLen
  | Opcode.TSUBcc -> tsubcc ins insLen ctxt
  | Opcode.TSUBccTV -> tsubcctv ins insLen ctxt
  | Opcode.UDIVX -> udivx ins insLen ctxt
  | Opcode.UMUL -> umul ins insLen ctxt
  | Opcode.UMULcc -> umulcc ins insLen ctxt
  | Opcode.WRASI | Opcode.WRASR | Opcode.WRCCR | Opcode.WRFPRS | Opcode.WRPR
  | Opcode.WRY -> wr ins insLen ctxt
  | Opcode.XOR -> xor ins insLen ctxt
  | Opcode.XORcc -> xorcc ins insLen ctxt
  | Opcode.XNOR -> xnor ins insLen ctxt
  | Opcode.XNORcc -> xnorcc ins insLen ctxt
  (*
  To be implemented
  | Opcode.FLUSH -> flush
  | Opcode.FLUSHW -> flushw
  | Opcode.ILLTRAP -> illtrap
  | Opcode.IMPDEP1 -> impdep1
  | Opcode.IMPDEP2 -> impdep2
  | Opcode.SDIV -> sdiv
  | Opcode.SDIVcc -> sdivcc
  | Opcode.UDIV -> udiv
  | Opcode.UDIVcc -> udivcc
  *)
  | Opcode.InvalidOp -> raise InvalidOpcodeException
  | o ->
  #if DEBUG
            eprintfn "%A" o
  #endif
            raise <| NotImplementedIRException (Disasm.opCodeToString o)
  |> fun ir -> ir.ToStmts ()

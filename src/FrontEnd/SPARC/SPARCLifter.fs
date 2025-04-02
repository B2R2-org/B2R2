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

module B2R2.FrontEnd.SPARC.Lifter

open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.SPARC
open B2R2.FrontEnd.SPARC.GeneralLifter

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
  | Opcode.BPVS -> branchpcc ins insLen ctxt
  | Opcode.BA | Opcode.BN | Opcode.BNE | Opcode.BE | Opcode.BG
  | Opcode.BLE | Opcode.BGE | Opcode.BL | Opcode.BGU | Opcode.BLEU
  | Opcode.BCC | Opcode.BCS | Opcode.BPOS | Opcode.BNEG | Opcode.BVC
  | Opcode.BVS -> branchicc ins insLen ctxt
  | Opcode.BRZ | Opcode.BRLEZ | Opcode.BRLZ | Opcode.BRNZ | Opcode.BRGZ
  | Opcode.BRGEZ -> branchpr ins insLen ctxt
  | Opcode.CALL -> call ins insLen ctxt
  | Opcode.CASA -> casa ins insLen ctxt
  | Opcode.CASXA -> casxa ins insLen ctxt
  | Opcode.DONE -> ``done`` ins insLen ctxt
  | Opcode.FABSs -> fabss ins insLen ctxt
  | Opcode.FABSd -> fabsd ins insLen ctxt
  | Opcode.FABSq -> fabsq ins insLen ctxt
  | Opcode.FADDs -> fadds ins insLen ctxt
  | Opcode.FADDd -> faddd ins insLen ctxt
  | Opcode.FADDq-> faddq ins insLen ctxt
  | Opcode.FBA | Opcode.FBN | Opcode.FBU | Opcode.FBG | Opcode.FBUG
  | Opcode.FBL | Opcode.FBUL | Opcode.FBLG | Opcode.FBNE | Opcode.FBE
  | Opcode.FBUE | Opcode.FBGE | Opcode.FBUGE | Opcode.FBLE | Opcode.FBULE
  | Opcode.FBO -> fbranchfcc ins insLen ctxt
  | Opcode.FBPA | Opcode.FBPN | Opcode.FBPU | Opcode.FBPG | Opcode.FBPUG
  | Opcode.FBPL | Opcode.FBPUL | Opcode.FBPLG | Opcode.FBPNE | Opcode.FBPE
  | Opcode.FBPUE | Opcode.FBPGE | Opcode.FBPUGE | Opcode.FBPLE | Opcode.FBPULE
  | Opcode.FBPO -> fbranchpfcc ins insLen ctxt
  | Opcode.FCMPs | Opcode.FCMPEs -> fcmps ins insLen ctxt
  | Opcode.FCMPd | Opcode.FCMPEd -> fcmpd ins insLen ctxt
  | Opcode.FCMPq | Opcode.FCMPEq -> fcmpq ins insLen ctxt
  | Opcode.FDIVs -> fdivs ins insLen ctxt
  | Opcode.FDIVd -> fdivd ins insLen ctxt
  | Opcode.FDIVq -> fdivq ins insLen ctxt
  | Opcode.FiTOs -> fitos ins insLen ctxt
  | Opcode.FiTOd -> fitod ins insLen ctxt
  | Opcode.FiTOq -> fitoq ins insLen ctxt
  | Opcode.FMOVs -> fmovs ins insLen ctxt
  | Opcode.FMOVd -> fmovd ins insLen ctxt
  | Opcode.FMOVq -> fmovq ins insLen ctxt
  (* Fix Me *)
  | Opcode.FMOVsA | Opcode.FMOVsN | Opcode.FMOVsNE | Opcode.FMOVsE
  | Opcode.FMOVsG   | Opcode.FMOVsLE | Opcode.FMOVsGE | Opcode.FMOVsL
  | Opcode.FMOVsGU | Opcode.FMOVsLEU | Opcode.FMOVsCC | Opcode.FMOVsCS
  | Opcode.FMOVsPOS | Opcode.FMOVsNEG | Opcode.FMOVsVC | Opcode.FMOVsVS
    -> fmovscc ins insLen ctxt
  | Opcode.FMOVdA | Opcode.FMOVdN | Opcode.FMOVdNE | Opcode.FMOVdE
  | Opcode.FMOVdG | Opcode.FMOVdLE | Opcode.FMOVdGE | Opcode.FMOVdL
  | Opcode.FMOVdGU | Opcode.FMOVdLEU | Opcode.FMOVdCC | Opcode.FMOVdCS
  | Opcode.FMOVdPOS | Opcode.FMOVdNEG | Opcode.FMOVdVC | Opcode.FMOVdVS
    -> fmovdcc ins insLen ctxt
  | Opcode.FMOVqA | Opcode.FMOVqN | Opcode.FMOVqNE | Opcode.FMOVqE
  | Opcode.FMOVqG | Opcode.FMOVqLE | Opcode.FMOVqGE | Opcode.FMOVqL
  | Opcode.FMOVqGU | Opcode.FMOVqLEU | Opcode.FMOVqCC | Opcode.FMOVqCS
  | Opcode.FMOVqPOS | Opcode.FMOVqNEG | Opcode.FMOVqVC | Opcode.FMOVqVS
    -> fmovqcc ins insLen ctxt
  | Opcode.FMOVFsA | Opcode.FMOVFsN | Opcode.FMOVFsU | Opcode.FMOVFsG
  | Opcode.FMOVFsUG | Opcode.FMOVFsL | Opcode.FMOVFsUL | Opcode.FMOVFsLG
  | Opcode.FMOVFsNE | Opcode.FMOVFsE | Opcode.FMOVFsUE | Opcode.FMOVFsGE
  | Opcode.FMOVFsUGE | Opcode.FMOVFsLE | Opcode.FMOVFsULE | Opcode.FMOVFsO
    -> fmovfscc ins insLen ctxt
  | Opcode.FMOVFdA | Opcode.FMOVFdN | Opcode.FMOVFdU | Opcode.FMOVFdG
  | Opcode.FMOVFdUG | Opcode.FMOVFdL | Opcode.FMOVFdUL | Opcode.FMOVFdLG
  | Opcode.FMOVFdNE | Opcode.FMOVFdE | Opcode.FMOVFdUE | Opcode.FMOVFdGE
  | Opcode.FMOVFdUGE | Opcode.FMOVFdLE | Opcode.FMOVFdULE | Opcode.FMOVFdO
    -> fmovfdcc ins insLen ctxt
  | Opcode.FMOVFqA | Opcode.FMOVFqN | Opcode.FMOVFqU | Opcode.FMOVFqG
  | Opcode.FMOVFqUG | Opcode.FMOVFqL | Opcode.FMOVFqUL | Opcode.FMOVFqLG
  | Opcode.FMOVFqNE | Opcode.FMOVFqE | Opcode.FMOVFqUE | Opcode.FMOVFqGE
  | Opcode.FMOVFqUGE | Opcode.FMOVFqLE | Opcode.FMOVFqULE | Opcode.FMOVFqO
    -> fmovfqcc ins insLen ctxt
  | Opcode.FMOVRsZ | Opcode.FMOVRsLEZ | Opcode.FMOVRsLZ | Opcode.FMOVRsNZ
  | Opcode.FMOVRsGZ | Opcode.FMOVRsGEZ -> fmovrs ins insLen ctxt
  | Opcode.FMOVRdZ | Opcode.FMOVRdLEZ | Opcode.FMOVRdLZ | Opcode.FMOVRdNZ
  | Opcode.FMOVRdGZ | Opcode.FMOVRdGEZ -> fmovrd ins insLen ctxt
  | Opcode.FMOVRqZ | Opcode.FMOVRqLEZ | Opcode.FMOVRqLZ | Opcode.FMOVRqNZ
  | Opcode.FMOVRqGZ | Opcode.FMOVRqGEZ -> fmovrq ins insLen ctxt
  | Opcode.FMULs -> fmuls ins insLen ctxt
  | Opcode.FMULd -> fmuld ins insLen ctxt
  | Opcode.FMULq -> fmulq ins insLen ctxt
  | Opcode.FNEGs -> fnegs ins insLen ctxt
  | Opcode.FNEGd -> fnegd ins insLen ctxt
  | Opcode.FNEGq -> fnegq ins insLen ctxt
  | Opcode.FsMULd -> fsmuld ins insLen ctxt
  | Opcode.FdMULq -> fdmulq ins insLen ctxt
  | Opcode.FSQRTs  -> fsqrts ins insLen ctxt
  | Opcode.FSQRTd -> fsqrtd ins insLen ctxt
  | Opcode.FSQRTq -> fsqrtq ins insLen ctxt
  | Opcode.FsTOx -> fstox ins insLen ctxt
  | Opcode.FdTOx -> fdtox ins insLen ctxt
  | Opcode.FqTOx -> fqtox ins insLen ctxt
  | Opcode.FsTOi -> fstoi ins insLen ctxt
  | Opcode.FdTOi -> fdtoi ins insLen ctxt
  | Opcode.FqTOi -> fqtoi ins insLen ctxt
  | Opcode.FsTOd -> fstod ins insLen ctxt
  | Opcode.FsTOq -> fstoq ins insLen ctxt
  | Opcode.FdTOs -> fdtos ins insLen ctxt
  | Opcode.FdTOq -> fdtoq ins insLen ctxt
  | Opcode.FqTOs -> fqtos ins insLen ctxt
  | Opcode.FqTOd -> fqtod ins insLen ctxt
  | Opcode.FSUBs -> fsubs ins insLen ctxt
  | Opcode.FSUBd -> fsubd ins insLen ctxt
  | Opcode.FSUBq -> fsubq ins insLen ctxt
  | Opcode.FxTOs -> fxtos ins insLen ctxt
  | Opcode.FxTOd -> fxtod ins insLen ctxt
  | Opcode.FxTOq -> fxtoq ins insLen ctxt
  | Opcode.JMPL -> jmpl ins insLen ctxt
  | Opcode.LDF | Opcode.LDDF | Opcode.LDQF | Opcode.LDFSR
  | Opcode.LDXFSR -> ldf ins insLen ctxt
  | Opcode.LDFA | Opcode.LDDFA | Opcode.LDQFA -> ldfa ins insLen ctxt
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
  | Opcode.MOVFL  | Opcode.MOVFUL | Opcode.MOVFLG | Opcode.MOVFNE
  | Opcode.MOVFE | Opcode.MOVFUE | Opcode.MOVFGE | Opcode.MOVFUGE
  | Opcode.MOVFLE | Opcode.MOVFULE | Opcode.MOVFO -> movcc ins insLen ctxt
  | Opcode.MOVRZ | Opcode.MOVRLEZ | Opcode.MOVRLZ | Opcode.MOVRNZ
  | Opcode.MOVRGZ | Opcode.MOVRGEZ -> movr ins insLen ctxt
  | Opcode.MULScc -> mulscc ins insLen ctxt
  | Opcode.MULX -> mulx ins insLen ctxt
  | Opcode.NOP -> nop insLen
  | Opcode.OR -> ``or`` ins insLen ctxt
  | Opcode.ORcc -> orcc ins insLen ctxt
  | Opcode.ORN -> orn ins insLen ctxt
  | Opcode.ORNcc -> orncc ins insLen ctxt
  | Opcode.POPC -> popc ins insLen ctxt
  | Opcode.PREFETCH | Opcode.PREFETCHA -> nop insLen
  | Opcode.RDASI | Opcode.RDASR | Opcode.RDCCR | Opcode.RDFPRS | Opcode.RDPC
  | Opcode.RDTICK | Opcode.RDY | Opcode.RDPR -> rd ins insLen ctxt
  | Opcode.RESTORE -> restore ins insLen ctxt
  | Opcode.RESTORED -> restored ins insLen ctxt
  | Opcode.RETRY -> retry ins insLen ctxt
  | Opcode.RETURN -> ret ins insLen ctxt
  | Opcode.SAVE -> save ins insLen ctxt
  | Opcode.SAVED -> saved ins insLen ctxt
  | Opcode.SDIVX -> sdivx ins insLen ctxt
  | Opcode.SETHI -> sethi ins insLen ctxt
  | Opcode.SIR -> nop insLen
  | Opcode.SLL
  | Opcode.SLLX -> sll ins insLen ctxt
  | Opcode.SMUL -> smul ins insLen ctxt
  | Opcode.SMULcc -> smulcc ins insLen ctxt
  | Opcode.SRA
  | Opcode.SRAX -> sra ins insLen ctxt
  | Opcode.SRL
  | Opcode.SRLX -> srl ins insLen ctxt
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
  | Opcode.TADDcc -> addcc ins insLen ctxt
  | Opcode.TADDccTV -> addcc ins insLen ctxt
  | Opcode.TA | Opcode.TN | Opcode.TNE | Opcode.TE | Opcode.TG | Opcode.TLE
  | Opcode.TGE | Opcode.TL | Opcode.TGU | Opcode.TLEU | Opcode.TCC | Opcode.TCS
  | Opcode.TPOS | Opcode.TNEG | Opcode.TVC | Opcode.TVS -> nop insLen
  | Opcode.TSUBcc -> subcc ins insLen ctxt
  | Opcode.TSUBccTV -> subcc ins insLen ctxt
  | Opcode.UDIVX -> udivx ins insLen ctxt
  | Opcode.UMUL -> umul ins insLen ctxt
  | Opcode.UMULcc -> umulcc ins insLen ctxt
  | Opcode.WRASI | Opcode.WRASR | Opcode.WRCCR | Opcode.WRFPRS | Opcode.WRPR
  | Opcode.WRY -> wr ins insLen ctxt
  | Opcode.XOR -> xor ins insLen ctxt
  | Opcode.XORcc -> xorcc ins insLen ctxt
  | Opcode.XNOR -> xnor ins insLen ctxt
  | Opcode.XNORcc -> xnorcc ins insLen ctxt
  | Opcode.SDIV -> sdiv ins insLen ctxt
  | Opcode.SDIVcc -> sdivcc ins insLen ctxt
  | Opcode.UDIV -> udiv ins insLen ctxt
  | Opcode.UDIVcc -> udivcc ins insLen ctxt
  | Opcode.FLUSH | Opcode.FLUSHW | Opcode.ILLTRAP -> nop insLen
  | Opcode.InvalidOp -> raise InvalidOpcodeException
  | o ->
  #if DEBUG
            eprintfn "%A" o
  #endif
            raise <| NotImplementedIRException (Disasm.opCodeToString o)
  |> fun ir -> ir.ToStmts ()

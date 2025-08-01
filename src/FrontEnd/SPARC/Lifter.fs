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

module internal B2R2.FrontEnd.SPARC.Lifter

open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.SPARC
open B2R2.FrontEnd.SPARC.GeneralLifter

/// Translate IR.
let translate (ins: Instruction) insLen bld =
  match ins.Opcode with
  | Opcode.ADD -> add ins insLen bld
  | Opcode.ADDcc -> addcc ins insLen bld
  | Opcode.ADDC -> addC ins insLen bld
  | Opcode.ADDCcc -> addCcc ins insLen bld
  | Opcode.AND -> ``and`` ins insLen bld
  | Opcode.ANDcc -> andcc ins insLen bld
  | Opcode.ANDN -> andn ins insLen bld
  | Opcode.ANDNcc -> andncc ins insLen bld
  | Opcode.BPA | Opcode.BPN | Opcode.BPNE | Opcode.BPE | Opcode.BPG
  | Opcode.BPLE | Opcode.BPGE | Opcode.BPL | Opcode.BPGU | Opcode.BPLEU
  | Opcode.BPCC | Opcode.BPCS | Opcode.BPPOS | Opcode.BPNEG | Opcode.BPVC
  | Opcode.BPVS -> branchpcc ins insLen bld
  | Opcode.BA | Opcode.BN | Opcode.BNE | Opcode.BE | Opcode.BG
  | Opcode.BLE | Opcode.BGE | Opcode.BL | Opcode.BGU | Opcode.BLEU
  | Opcode.BCC | Opcode.BCS | Opcode.BPOS | Opcode.BNEG | Opcode.BVC
  | Opcode.BVS -> branchicc ins insLen bld
  | Opcode.BRZ | Opcode.BRLEZ | Opcode.BRLZ | Opcode.BRNZ | Opcode.BRGZ
  | Opcode.BRGEZ -> branchpr ins insLen bld
  | Opcode.CALL -> call ins insLen bld
  | Opcode.CASA -> casa ins insLen bld
  | Opcode.CASXA -> casxa ins insLen bld
  | Opcode.DONE -> ``done`` ins insLen bld
  | Opcode.FABSs -> fabss ins insLen bld
  | Opcode.FABSd -> fabsd ins insLen bld
  | Opcode.FABSq -> fabsq ins insLen bld
  | Opcode.FADDs -> fadds ins insLen bld
  | Opcode.FADDd -> faddd ins insLen bld
  | Opcode.FADDq -> faddq ins insLen bld
  | Opcode.FBA | Opcode.FBN | Opcode.FBU | Opcode.FBG | Opcode.FBUG
  | Opcode.FBL | Opcode.FBUL | Opcode.FBLG | Opcode.FBNE | Opcode.FBE
  | Opcode.FBUE | Opcode.FBGE | Opcode.FBUGE | Opcode.FBLE | Opcode.FBULE
  | Opcode.FBO -> fbranchfcc ins insLen bld
  | Opcode.FBPA | Opcode.FBPN | Opcode.FBPU | Opcode.FBPG | Opcode.FBPUG
  | Opcode.FBPL | Opcode.FBPUL | Opcode.FBPLG | Opcode.FBPNE | Opcode.FBPE
  | Opcode.FBPUE | Opcode.FBPGE | Opcode.FBPUGE | Opcode.FBPLE | Opcode.FBPULE
  | Opcode.FBPO -> fbranchpfcc ins insLen bld
  | Opcode.FCMPs | Opcode.FCMPEs -> fcmps ins insLen bld
  | Opcode.FCMPd | Opcode.FCMPEd -> fcmpd ins insLen bld
  | Opcode.FCMPq | Opcode.FCMPEq -> fcmpq ins insLen bld
  | Opcode.FDIVs -> fdivs ins insLen bld
  | Opcode.FDIVd -> fdivd ins insLen bld
  | Opcode.FDIVq -> fdivq ins insLen bld
  | Opcode.FiTOs -> fitos ins insLen bld
  | Opcode.FiTOd -> fitod ins insLen bld
  | Opcode.FiTOq -> fitoq ins insLen bld
  | Opcode.FMOVs -> fmovs ins insLen bld
  | Opcode.FMOVd -> fmovd ins insLen bld
  | Opcode.FMOVq -> fmovq ins insLen bld
  (* Fix Me *)
  | Opcode.FMOVsA | Opcode.FMOVsN | Opcode.FMOVsNE | Opcode.FMOVsE
  | Opcode.FMOVsG   | Opcode.FMOVsLE | Opcode.FMOVsGE | Opcode.FMOVsL
  | Opcode.FMOVsGU | Opcode.FMOVsLEU | Opcode.FMOVsCC | Opcode.FMOVsCS
  | Opcode.FMOVsPOS | Opcode.FMOVsNEG | Opcode.FMOVsVC | Opcode.FMOVsVS
    -> fmovscc ins insLen bld
  | Opcode.FMOVdA | Opcode.FMOVdN | Opcode.FMOVdNE | Opcode.FMOVdE
  | Opcode.FMOVdG | Opcode.FMOVdLE | Opcode.FMOVdGE | Opcode.FMOVdL
  | Opcode.FMOVdGU | Opcode.FMOVdLEU | Opcode.FMOVdCC | Opcode.FMOVdCS
  | Opcode.FMOVdPOS | Opcode.FMOVdNEG | Opcode.FMOVdVC | Opcode.FMOVdVS
    -> fmovdcc ins insLen bld
  | Opcode.FMOVqA | Opcode.FMOVqN | Opcode.FMOVqNE | Opcode.FMOVqE
  | Opcode.FMOVqG | Opcode.FMOVqLE | Opcode.FMOVqGE | Opcode.FMOVqL
  | Opcode.FMOVqGU | Opcode.FMOVqLEU | Opcode.FMOVqCC | Opcode.FMOVqCS
  | Opcode.FMOVqPOS | Opcode.FMOVqNEG | Opcode.FMOVqVC | Opcode.FMOVqVS
    -> fmovqcc ins insLen bld
  | Opcode.FMOVFsA | Opcode.FMOVFsN | Opcode.FMOVFsU | Opcode.FMOVFsG
  | Opcode.FMOVFsUG | Opcode.FMOVFsL | Opcode.FMOVFsUL | Opcode.FMOVFsLG
  | Opcode.FMOVFsNE | Opcode.FMOVFsE | Opcode.FMOVFsUE | Opcode.FMOVFsGE
  | Opcode.FMOVFsUGE | Opcode.FMOVFsLE | Opcode.FMOVFsULE | Opcode.FMOVFsO
    -> fmovfscc ins insLen bld
  | Opcode.FMOVFdA | Opcode.FMOVFdN | Opcode.FMOVFdU | Opcode.FMOVFdG
  | Opcode.FMOVFdUG | Opcode.FMOVFdL | Opcode.FMOVFdUL | Opcode.FMOVFdLG
  | Opcode.FMOVFdNE | Opcode.FMOVFdE | Opcode.FMOVFdUE | Opcode.FMOVFdGE
  | Opcode.FMOVFdUGE | Opcode.FMOVFdLE | Opcode.FMOVFdULE | Opcode.FMOVFdO
    -> fmovfdcc ins insLen bld
  | Opcode.FMOVFqA | Opcode.FMOVFqN | Opcode.FMOVFqU | Opcode.FMOVFqG
  | Opcode.FMOVFqUG | Opcode.FMOVFqL | Opcode.FMOVFqUL | Opcode.FMOVFqLG
  | Opcode.FMOVFqNE | Opcode.FMOVFqE | Opcode.FMOVFqUE | Opcode.FMOVFqGE
  | Opcode.FMOVFqUGE | Opcode.FMOVFqLE | Opcode.FMOVFqULE | Opcode.FMOVFqO
    -> fmovfqcc ins insLen bld
  | Opcode.FMOVRsZ | Opcode.FMOVRsLEZ | Opcode.FMOVRsLZ | Opcode.FMOVRsNZ
  | Opcode.FMOVRsGZ | Opcode.FMOVRsGEZ -> fmovrs ins insLen bld
  | Opcode.FMOVRdZ | Opcode.FMOVRdLEZ | Opcode.FMOVRdLZ | Opcode.FMOVRdNZ
  | Opcode.FMOVRdGZ | Opcode.FMOVRdGEZ -> fmovrd ins insLen bld
  | Opcode.FMOVRqZ | Opcode.FMOVRqLEZ | Opcode.FMOVRqLZ | Opcode.FMOVRqNZ
  | Opcode.FMOVRqGZ | Opcode.FMOVRqGEZ -> fmovrq ins insLen bld
  | Opcode.FMULs -> fmuls ins insLen bld
  | Opcode.FMULd -> fmuld ins insLen bld
  | Opcode.FMULq -> fmulq ins insLen bld
  | Opcode.FNEGs -> fnegs ins insLen bld
  | Opcode.FNEGd -> fnegd ins insLen bld
  | Opcode.FNEGq -> fnegq ins insLen bld
  | Opcode.FsMULd -> fsmuld ins insLen bld
  | Opcode.FdMULq -> fdmulq ins insLen bld
  | Opcode.FSQRTs  -> fsqrts ins insLen bld
  | Opcode.FSQRTd -> fsqrtd ins insLen bld
  | Opcode.FSQRTq -> fsqrtq ins insLen bld
  | Opcode.FsTOx -> fstox ins insLen bld
  | Opcode.FdTOx -> fdtox ins insLen bld
  | Opcode.FqTOx -> fqtox ins insLen bld
  | Opcode.FsTOi -> fstoi ins insLen bld
  | Opcode.FdTOi -> fdtoi ins insLen bld
  | Opcode.FqTOi -> fqtoi ins insLen bld
  | Opcode.FsTOd -> fstod ins insLen bld
  | Opcode.FsTOq -> fstoq ins insLen bld
  | Opcode.FdTOs -> fdtos ins insLen bld
  | Opcode.FdTOq -> fdtoq ins insLen bld
  | Opcode.FqTOs -> fqtos ins insLen bld
  | Opcode.FqTOd -> fqtod ins insLen bld
  | Opcode.FSUBs -> fsubs ins insLen bld
  | Opcode.FSUBd -> fsubd ins insLen bld
  | Opcode.FSUBq -> fsubq ins insLen bld
  | Opcode.FxTOs -> fxtos ins insLen bld
  | Opcode.FxTOd -> fxtod ins insLen bld
  | Opcode.FxTOq -> fxtoq ins insLen bld
  | Opcode.JMPL -> jmpl ins insLen bld
  | Opcode.LDF | Opcode.LDDF | Opcode.LDQF | Opcode.LDFSR
  | Opcode.LDXFSR -> ldf ins insLen bld
  | Opcode.LDFA | Opcode.LDDFA | Opcode.LDQFA -> ldfa ins insLen bld
  | Opcode.LDSB | Opcode.LDSH | Opcode.LDSW | Opcode.LDUB | Opcode.LDUH
  | Opcode.LDUW | Opcode.LDX | Opcode.LDD -> ld ins insLen bld
  | Opcode.LDSBA | Opcode.LDSHA | Opcode.LDSWA | Opcode.LDUBA | Opcode.LDUHA
  | Opcode.LDUWA | Opcode.LDXA | Opcode.LDDA -> lda ins insLen bld
  | Opcode.LDSTUB -> ldstub ins insLen bld
  | Opcode.LDSTUBA -> ldstuba ins insLen bld
  | Opcode.MEMBAR -> membar ins insLen bld
  | Opcode.MOVA | Opcode.MOVN | Opcode.MOVNE | Opcode.MOVE | Opcode.MOVG
  | Opcode.MOVLE | Opcode.MOVGE | Opcode.MOVL | Opcode.MOVGU | Opcode.MOVLEU
  | Opcode.MOVCC | Opcode.MOVCS | Opcode.MOVPOS | Opcode.MOVNEG | Opcode.MOVVC
  | Opcode.MOVVS -> movcc ins insLen bld
  | Opcode.MOVFA | Opcode.MOVFN | Opcode.MOVFU | Opcode.MOVFG | Opcode.MOVFUG
  | Opcode.MOVFL  | Opcode.MOVFUL | Opcode.MOVFLG | Opcode.MOVFNE
  | Opcode.MOVFE | Opcode.MOVFUE | Opcode.MOVFGE | Opcode.MOVFUGE
  | Opcode.MOVFLE | Opcode.MOVFULE | Opcode.MOVFO -> movcc ins insLen bld
  | Opcode.MOVRZ | Opcode.MOVRLEZ | Opcode.MOVRLZ | Opcode.MOVRNZ
  | Opcode.MOVRGZ | Opcode.MOVRGEZ -> movr ins insLen bld
  | Opcode.MULScc -> mulscc ins insLen bld
  | Opcode.MULX -> mulx ins insLen bld
  | Opcode.NOP -> nop ins insLen bld
  | Opcode.OR -> ``or`` ins insLen bld
  | Opcode.ORcc -> orcc ins insLen bld
  | Opcode.ORN -> orn ins insLen bld
  | Opcode.ORNcc -> orncc ins insLen bld
  | Opcode.POPC -> popc ins insLen bld
  | Opcode.PREFETCH | Opcode.PREFETCHA -> nop ins insLen bld
  | Opcode.RDASI | Opcode.RDASR | Opcode.RDCCR | Opcode.RDFPRS | Opcode.RDPC
  | Opcode.RDTICK | Opcode.RDY | Opcode.RDPR -> rd ins insLen bld
  | Opcode.RESTORE -> restore ins insLen bld
  | Opcode.RESTORED -> restored ins insLen bld
  | Opcode.RETRY -> retry ins insLen bld
  | Opcode.RETURN -> ret ins insLen bld
  | Opcode.SAVE -> save ins insLen bld
  | Opcode.SAVED -> saved ins insLen bld
  | Opcode.SDIVX -> sdivx ins insLen bld
  | Opcode.SETHI -> sethi ins insLen bld
  | Opcode.SIR -> nop ins insLen bld
  | Opcode.SLL
  | Opcode.SLLX -> sll ins insLen bld
  | Opcode.SMUL -> smul ins insLen bld
  | Opcode.SMULcc -> smulcc ins insLen bld
  | Opcode.SRA
  | Opcode.SRAX -> sra ins insLen bld
  | Opcode.SRL
  | Opcode.SRLX -> srl ins insLen bld
  | Opcode.STB | Opcode.STH | Opcode.STW | Opcode.STX | Opcode.STD ->
      st ins insLen bld
  | Opcode.STBA | Opcode.STHA | Opcode.STWA | Opcode.STXA | Opcode.STDA ->
      sta ins insLen bld
  | Opcode.STBAR -> nop ins insLen bld
  | Opcode.STF | Opcode.STDF | Opcode.STQF | Opcode.STFSR | Opcode.STXFSR ->
      stf ins insLen bld
  | Opcode.STFA | Opcode.STDFA | Opcode.STQFA -> stfa ins insLen bld
  | Opcode.SUB -> sub ins insLen bld
  | Opcode.SUBcc -> subcc ins insLen bld
  | Opcode.SUBC -> subC ins insLen bld
  | Opcode.SUBCcc -> subCcc ins insLen bld
  | Opcode.SWAP -> swap ins insLen bld
  | Opcode.SWAPA -> swapa ins insLen bld
  | Opcode.TADDcc -> addcc ins insLen bld
  | Opcode.TADDccTV -> addcc ins insLen bld
  | Opcode.TA | Opcode.TN | Opcode.TNE | Opcode.TE | Opcode.TG | Opcode.TLE
  | Opcode.TGE | Opcode.TL | Opcode.TGU | Opcode.TLEU | Opcode.TCC | Opcode.TCS
  | Opcode.TPOS | Opcode.TNEG | Opcode.TVC | Opcode.TVS -> nop ins insLen bld
  | Opcode.TSUBcc -> subcc ins insLen bld
  | Opcode.TSUBccTV -> subcc ins insLen bld
  | Opcode.UDIVX -> udivx ins insLen bld
  | Opcode.UMUL -> umul ins insLen bld
  | Opcode.UMULcc -> umulcc ins insLen bld
  | Opcode.WRASI | Opcode.WRASR | Opcode.WRCCR | Opcode.WRFPRS | Opcode.WRPR
  | Opcode.WRY -> wr ins insLen bld
  | Opcode.XOR -> xor ins insLen bld
  | Opcode.XORcc -> xorcc ins insLen bld
  | Opcode.XNOR -> xnor ins insLen bld
  | Opcode.XNORcc -> xnorcc ins insLen bld
  | Opcode.SDIV -> sdiv ins insLen bld
  | Opcode.SDIVcc -> sdivcc ins insLen bld
  | Opcode.UDIV -> udiv ins insLen bld
  | Opcode.UDIVcc -> udivcc ins insLen bld
  | Opcode.FLUSH | Opcode.FLUSHW | Opcode.ILLTRAP -> nop ins insLen bld
  | Opcode.InvalidOp -> raise InvalidOpcodeException
  | o ->
  #if DEBUG
            eprintfn "%A" o
  #endif
            raise <| NotImplementedIRException(Disasm.opCodeToString o)

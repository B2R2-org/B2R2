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
let translate (ins: Instruction) bld =
  match ins.Opcode with
  | Opcode.ADD ->
    add ins bld
  | Opcode.ADDcc ->
    addcc ins bld
  | Opcode.ADDC ->
    addC ins bld
  | Opcode.ADDCcc ->
    addCcc ins bld
  | Opcode.AND ->
    ``and`` ins bld
  | Opcode.ANDcc ->
    andcc ins bld
  | Opcode.ANDN ->
    andn ins bld
  | Opcode.ANDNcc ->
    andncc ins bld
  | Opcode.BPA | Opcode.BPN | Opcode.BPNE | Opcode.BPE | Opcode.BPG
  | Opcode.BPLE | Opcode.BPGE | Opcode.BPL | Opcode.BPGU | Opcode.BPLEU
  | Opcode.BPCC | Opcode.BPCS | Opcode.BPPOS | Opcode.BPNEG | Opcode.BPVC
  | Opcode.BPVS ->
    branchpcc ins bld
  | Opcode.BA | Opcode.BN | Opcode.BNE | Opcode.BE | Opcode.BG
  | Opcode.BLE | Opcode.BGE | Opcode.BL | Opcode.BGU | Opcode.BLEU
  | Opcode.BCC | Opcode.BCS | Opcode.BPOS | Opcode.BNEG | Opcode.BVC
  | Opcode.BVS ->
    branchicc ins bld
  | Opcode.BRZ | Opcode.BRLEZ | Opcode.BRLZ | Opcode.BRNZ | Opcode.BRGZ
  | Opcode.BRGEZ ->
    branchpr ins bld
  | Opcode.CALL ->
    call ins bld
  | Opcode.CASA ->
    casa ins bld
  | Opcode.CASXA ->
    casxa ins bld
  | Opcode.DONE ->
    ``done`` ins bld
  | Opcode.FABSs ->
    fabss ins bld
  | Opcode.FABSd ->
    fabsd ins bld
  | Opcode.FABSq ->
    fabsq ins bld
  | Opcode.FADDs ->
    fadds ins bld
  | Opcode.FADDd ->
    faddd ins bld
  | Opcode.FADDq ->
    faddq ins bld
  | Opcode.FBA | Opcode.FBN | Opcode.FBU | Opcode.FBG | Opcode.FBUG
  | Opcode.FBL | Opcode.FBUL | Opcode.FBLG | Opcode.FBNE | Opcode.FBE
  | Opcode.FBUE | Opcode.FBGE | Opcode.FBUGE | Opcode.FBLE | Opcode.FBULE
  | Opcode.FBO ->
    fbranchfcc ins bld
  | Opcode.FBPA | Opcode.FBPN | Opcode.FBPU | Opcode.FBPG | Opcode.FBPUG
  | Opcode.FBPL | Opcode.FBPUL | Opcode.FBPLG | Opcode.FBPNE | Opcode.FBPE
  | Opcode.FBPUE | Opcode.FBPGE | Opcode.FBPUGE | Opcode.FBPLE | Opcode.FBPULE
  | Opcode.FBPO ->
    fbranchpfcc ins bld
  | Opcode.FCMPs | Opcode.FCMPEs ->
    fcmps ins bld
  | Opcode.FCMPd | Opcode.FCMPEd ->
    fcmpd ins bld
  | Opcode.FCMPq | Opcode.FCMPEq ->
    fcmpq ins bld
  | Opcode.FDIVs ->
    fdivs ins bld
  | Opcode.FDIVd ->
    fdivd ins bld
  | Opcode.FDIVq ->
    fdivq ins bld
  | Opcode.FiTOs ->
    fitos ins bld
  | Opcode.FiTOd ->
    fitod ins bld
  | Opcode.FiTOq ->
    fitoq ins bld
  | Opcode.FMOVs ->
    fmovs ins bld
  | Opcode.FMOVd ->
    fmovd ins bld
  | Opcode.FMOVq ->
    fmovq ins bld
  (* Fix Me *)
  | Opcode.FMOVsA | Opcode.FMOVsN | Opcode.FMOVsNE | Opcode.FMOVsE
  | Opcode.FMOVsG   | Opcode.FMOVsLE | Opcode.FMOVsGE | Opcode.FMOVsL
  | Opcode.FMOVsGU | Opcode.FMOVsLEU | Opcode.FMOVsCC | Opcode.FMOVsCS
  | Opcode.FMOVsPOS | Opcode.FMOVsNEG | Opcode.FMOVsVC | Opcode.FMOVsVS ->
    fmovscc ins bld
  | Opcode.FMOVdA | Opcode.FMOVdN | Opcode.FMOVdNE | Opcode.FMOVdE
  | Opcode.FMOVdG | Opcode.FMOVdLE | Opcode.FMOVdGE | Opcode.FMOVdL
  | Opcode.FMOVdGU | Opcode.FMOVdLEU | Opcode.FMOVdCC | Opcode.FMOVdCS
  | Opcode.FMOVdPOS | Opcode.FMOVdNEG | Opcode.FMOVdVC | Opcode.FMOVdVS ->
    fmovdcc ins bld
  | Opcode.FMOVqA | Opcode.FMOVqN | Opcode.FMOVqNE | Opcode.FMOVqE
  | Opcode.FMOVqG | Opcode.FMOVqLE | Opcode.FMOVqGE | Opcode.FMOVqL
  | Opcode.FMOVqGU | Opcode.FMOVqLEU | Opcode.FMOVqCC | Opcode.FMOVqCS
  | Opcode.FMOVqPOS | Opcode.FMOVqNEG | Opcode.FMOVqVC | Opcode.FMOVqVS ->
    fmovqcc ins bld
  | Opcode.FMOVFsA | Opcode.FMOVFsN | Opcode.FMOVFsU | Opcode.FMOVFsG
  | Opcode.FMOVFsUG | Opcode.FMOVFsL | Opcode.FMOVFsUL | Opcode.FMOVFsLG
  | Opcode.FMOVFsNE | Opcode.FMOVFsE | Opcode.FMOVFsUE | Opcode.FMOVFsGE
  | Opcode.FMOVFsUGE | Opcode.FMOVFsLE | Opcode.FMOVFsULE | Opcode.FMOVFsO ->
    fmovfscc ins bld
  | Opcode.FMOVFdA | Opcode.FMOVFdN | Opcode.FMOVFdU | Opcode.FMOVFdG
  | Opcode.FMOVFdUG | Opcode.FMOVFdL | Opcode.FMOVFdUL | Opcode.FMOVFdLG
  | Opcode.FMOVFdNE | Opcode.FMOVFdE | Opcode.FMOVFdUE | Opcode.FMOVFdGE
  | Opcode.FMOVFdUGE | Opcode.FMOVFdLE | Opcode.FMOVFdULE | Opcode.FMOVFdO ->
    fmovfdcc ins bld
  | Opcode.FMOVFqA | Opcode.FMOVFqN | Opcode.FMOVFqU | Opcode.FMOVFqG
  | Opcode.FMOVFqUG | Opcode.FMOVFqL | Opcode.FMOVFqUL | Opcode.FMOVFqLG
  | Opcode.FMOVFqNE | Opcode.FMOVFqE | Opcode.FMOVFqUE | Opcode.FMOVFqGE
  | Opcode.FMOVFqUGE | Opcode.FMOVFqLE | Opcode.FMOVFqULE | Opcode.FMOVFqO ->
    fmovfqcc ins bld
  | Opcode.FMOVRsZ | Opcode.FMOVRsLEZ | Opcode.FMOVRsLZ | Opcode.FMOVRsNZ
  | Opcode.FMOVRsGZ | Opcode.FMOVRsGEZ ->
    fmovrs ins bld
  | Opcode.FMOVRdZ | Opcode.FMOVRdLEZ | Opcode.FMOVRdLZ | Opcode.FMOVRdNZ
  | Opcode.FMOVRdGZ | Opcode.FMOVRdGEZ ->
    fmovrd ins bld
  | Opcode.FMOVRqZ | Opcode.FMOVRqLEZ | Opcode.FMOVRqLZ | Opcode.FMOVRqNZ
  | Opcode.FMOVRqGZ | Opcode.FMOVRqGEZ ->
    fmovrq ins bld
  | Opcode.FMULs ->
    fmuls ins bld
  | Opcode.FMULd ->
    fmuld ins bld
  | Opcode.FMULq ->
    fmulq ins bld
  | Opcode.FNEGs ->
    fnegs ins bld
  | Opcode.FNEGd ->
    fnegd ins bld
  | Opcode.FNEGq ->
    fnegq ins bld
  | Opcode.FsMULd ->
    fsmuld ins bld
  | Opcode.FdMULq ->
    fdmulq ins bld
  | Opcode.FSQRTs ->
    fsqrts ins bld
  | Opcode.FSQRTd ->
    fsqrtd ins bld
  | Opcode.FSQRTq ->
    fsqrtq ins bld
  | Opcode.FsTOx ->
    fstox ins bld
  | Opcode.FdTOx ->
    fdtox ins bld
  | Opcode.FqTOx ->
    fqtox ins bld
  | Opcode.FsTOi ->
    fstoi ins bld
  | Opcode.FdTOi ->
    fdtoi ins bld
  | Opcode.FqTOi ->
    fqtoi ins bld
  | Opcode.FsTOd ->
    fstod ins bld
  | Opcode.FsTOq ->
    fstoq ins bld
  | Opcode.FdTOs ->
    fdtos ins bld
  | Opcode.FdTOq ->
    fdtoq ins bld
  | Opcode.FqTOs ->
    fqtos ins bld
  | Opcode.FqTOd ->
    fqtod ins bld
  | Opcode.FSUBs ->
    fsubs ins bld
  | Opcode.FSUBd ->
    fsubd ins bld
  | Opcode.FSUBq ->
    fsubq ins bld
  | Opcode.FxTOs ->
    fxtos ins bld
  | Opcode.FxTOd ->
    fxtod ins bld
  | Opcode.FxTOq ->
    fxtoq ins bld
  | Opcode.JMPL ->
    jmpl ins bld
  | Opcode.LDF | Opcode.LDDF | Opcode.LDQF | Opcode.LDFSR
  | Opcode.LDXFSR ->
    ldf ins bld
  | Opcode.LDFA | Opcode.LDDFA | Opcode.LDQFA ->
    ldfa ins bld
  | Opcode.LDSB | Opcode.LDSH | Opcode.LDSW | Opcode.LDUB | Opcode.LDUH
  | Opcode.LDUW | Opcode.LDX | Opcode.LDD ->
    ld ins bld
  | Opcode.LDSBA | Opcode.LDSHA | Opcode.LDSWA | Opcode.LDUBA | Opcode.LDUHA
  | Opcode.LDUWA | Opcode.LDXA | Opcode.LDDA ->
    lda ins bld
  | Opcode.LDSTUB ->
    ldstub ins bld
  | Opcode.LDSTUBA ->
    ldstuba ins bld
  | Opcode.MEMBAR ->
    membar ins bld
  | Opcode.MOVA | Opcode.MOVN | Opcode.MOVNE | Opcode.MOVE | Opcode.MOVG
  | Opcode.MOVLE | Opcode.MOVGE | Opcode.MOVL | Opcode.MOVGU | Opcode.MOVLEU
  | Opcode.MOVCC | Opcode.MOVCS | Opcode.MOVPOS | Opcode.MOVNEG | Opcode.MOVVC
  | Opcode.MOVVS ->
    movcc ins bld
  | Opcode.MOVFA | Opcode.MOVFN | Opcode.MOVFU | Opcode.MOVFG | Opcode.MOVFUG
  | Opcode.MOVFL  | Opcode.MOVFUL | Opcode.MOVFLG | Opcode.MOVFNE
  | Opcode.MOVFE | Opcode.MOVFUE | Opcode.MOVFGE | Opcode.MOVFUGE
  | Opcode.MOVFLE | Opcode.MOVFULE | Opcode.MOVFO ->
    movcc ins bld
  | Opcode.MOVRZ | Opcode.MOVRLEZ | Opcode.MOVRLZ | Opcode.MOVRNZ
  | Opcode.MOVRGZ | Opcode.MOVRGEZ ->
    movr ins bld
  | Opcode.MULScc ->
    mulscc ins bld
  | Opcode.MULX ->
    mulx ins bld
  | Opcode.NOP ->
    nop ins bld
  | Opcode.OR ->
    ``or`` ins bld
  | Opcode.ORcc ->
    orcc ins bld
  | Opcode.ORN ->
    orn ins bld
  | Opcode.ORNcc ->
    orncc ins bld
  | Opcode.POPC ->
    popc ins bld
  | Opcode.PREFETCH | Opcode.PREFETCHA ->
    nop ins bld
  | Opcode.RDASI | Opcode.RDASR | Opcode.RDCCR | Opcode.RDFPRS | Opcode.RDPC
  | Opcode.RDTICK | Opcode.RDY | Opcode.RDPR ->
    rd ins bld
  | Opcode.RESTORE ->
    restore ins bld
  | Opcode.RESTORED ->
    restored ins bld
  | Opcode.RETRY ->
    retry ins bld
  | Opcode.RETURN ->
    ret ins bld
  | Opcode.SAVE ->
    save ins bld
  | Opcode.SAVED ->
    saved ins bld
  | Opcode.SDIVX ->
    sdivx ins bld
  | Opcode.SETHI ->
    sethi ins bld
  | Opcode.SIR ->
    nop ins bld
  | Opcode.SLL
  | Opcode.SLLX ->
    sll ins bld
  | Opcode.SMUL ->
    smul ins bld
  | Opcode.SMULcc ->
    smulcc ins bld
  | Opcode.SRA
  | Opcode.SRAX ->
    sra ins bld
  | Opcode.SRL
  | Opcode.SRLX ->
    srl ins bld
  | Opcode.STB | Opcode.STH | Opcode.STW | Opcode.STX | Opcode.STD ->
      st ins bld
  | Opcode.STBA | Opcode.STHA | Opcode.STWA | Opcode.STXA | Opcode.STDA ->
      sta ins bld
  | Opcode.STBAR ->
    nop ins bld
  | Opcode.STF | Opcode.STDF | Opcode.STQF | Opcode.STFSR | Opcode.STXFSR ->
      stf ins bld
  | Opcode.STFA | Opcode.STDFA | Opcode.STQFA ->
    stfa ins bld
  | Opcode.SUB ->
    sub ins bld
  | Opcode.SUBcc ->
    subcc ins bld
  | Opcode.SUBC ->
    subC ins bld
  | Opcode.SUBCcc ->
    subCcc ins bld
  | Opcode.SWAP ->
    swap ins bld
  | Opcode.SWAPA ->
    swapa ins bld
  | Opcode.TADDcc ->
    addcc ins bld
  | Opcode.TADDccTV ->
    addcc ins bld
  | Opcode.TA ->
    tcc ins bld
  | Opcode.TN | Opcode.TNE | Opcode.TE | Opcode.TG | Opcode.TLE
  | Opcode.TGE | Opcode.TL | Opcode.TGU | Opcode.TLEU | Opcode.TCC | Opcode.TCS
  | Opcode.TPOS | Opcode.TNEG | Opcode.TVC | Opcode.TVS ->
    nop ins bld
  | Opcode.TSUBcc ->
    subcc ins bld
  | Opcode.TSUBccTV ->
    subcc ins bld
  | Opcode.UDIVX ->
    udivx ins bld
  | Opcode.UMUL ->
    umul ins bld
  | Opcode.UMULcc ->
    umulcc ins bld
  | Opcode.WRASI | Opcode.WRASR | Opcode.WRCCR | Opcode.WRFPRS | Opcode.WRPR
  | Opcode.WRY ->
    wr ins bld
  | Opcode.XOR ->
    xor ins bld
  | Opcode.XORcc ->
    xorcc ins bld
  | Opcode.XNOR ->
    xnor ins bld
  | Opcode.XNORcc ->
    xnorcc ins bld
  | Opcode.SDIV ->
    sdiv ins bld
  | Opcode.SDIVcc ->
    sdivcc ins bld
  | Opcode.UDIV ->
    udiv ins bld
  | Opcode.UDIVcc ->
    udivcc ins bld
  | Opcode.FZEROd | Opcode.FONEd | Opcode.FSRC1d | Opcode.FSRC2d
  | Opcode.FNOT1d | Opcode.FNOT2d | Opcode.FORd | Opcode.FNORd
  | Opcode.FANDd | Opcode.FNANDd | Opcode.FXORd | Opcode.FXNORd
  | Opcode.FORNOT1d | Opcode.FORNOT2d | Opcode.FANDNOT1d
  | Opcode.FANDNOT2d ->
    visLogic ins bld
  | Opcode.ALIGNADDR | Opcode.ALIGNADDRL ->
    alignaddr ins bld
  | Opcode.FALIGNDATAd ->
    faligndata ins bld
  | Opcode.FLUSH | Opcode.ILLTRAP ->
    nop ins bld
  | Opcode.FLUSHW ->
    flushw ins bld
  (* No parser produces this opcode: an undecodable encoding is reported as a
     parsing failure, so an instruction never carries it this far. *)
  | Opcode.InvalidOp ->
    B2R2.Terminator.impossible ()
  | o ->
  #if DEBUG
            eprintfn "%A" o
  #endif
            raise <| NotImplementedIRException(Disasm.opCodeToString o)

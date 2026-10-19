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

module internal B2R2.FrontEnd.PPC.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils
open B2R2.FrontEnd.PPC.GeneralLifter
open B2R2.FrontEnd.PPC.VectorLifter
open B2R2.FrontEnd.PPC.FPLifter
open B2R2.FrontEnd.PPC.DFPLifter
open B2R2.FrontEnd.PPC.VectorIntegerLifter
open B2R2.FrontEnd.PPC.VectorCryptoLifter
open B2R2.FrontEnd.PPC.VectorDecimalLifter
open B2R2.FrontEnd.PPC.VectorBitLifter
open B2R2.FrontEnd.PPC.VectorPermuteLifter
open B2R2.FrontEnd.PPC.VectorFloatLifter

/// Translate IR.
let translate (ins: Instruction) bld =
  match ins.Opcode with
  | Op.ADD ->
    add ins false false bld
  | Op.ADDdot ->
    add ins true false bld
  | Op.ADDO ->
    add ins false true bld
  | Op.ADDOdot ->
    add ins true true bld
  | Op.ADDC ->
    addc ins false false bld
  | Op.ADDCdot ->
    addc ins true false bld
  | Op.ADDCO ->
    addc ins false true bld
  | Op.ADDCOdot ->
    addc ins true true bld
  | Op.ADDE ->
    adde ins false false bld
  | Op.ADDEdot ->
    adde ins true false bld
  | Op.ADDEO ->
    adde ins false true bld
  | Op.ADDEOdot ->
    adde ins true true bld
  | Op.ADDI ->
    addi ins bld
  | Op.ADDIC ->
    addic ins false bld
  | Op.ADDICdot ->
    addic ins true bld
  | Op.ADDIS ->
    addis ins bld
  | Op.ADDME ->
    addme ins false false bld
  | Op.ADDMEdot ->
    addme ins true false bld
  | Op.ADDMEO ->
    addme ins false true bld
  | Op.ADDMEOdot ->
    addme ins true true bld
  | Op.ADDZE ->
    addze ins false false bld
  | Op.ADDZEdot ->
    addze ins true false bld
  | Op.ADDZEO ->
    addze ins false true bld
  | Op.ADDZEOdot ->
    addze ins true true bld
  | Op.AND ->
    andx ins false bld
  | Op.ANDdot ->
    andx ins true bld
  | Op.ANDC ->
    andc ins false bld
  | Op.ANDCdot ->
    andc ins true bld
  | Op.ANDIdot ->
    andidot ins bld
  | Op.ANDISdot ->
    andisdot ins bld
  | Op.B ->
    b ins bld false
  | Op.BA ->
    b ins bld false
  | Op.BL ->
    b ins bld true
  | Op.BLA ->
    b ins bld true
  | Op.BC ->
    bc ins bld false false
  | Op.BCA ->
    bc ins bld true false
  | Op.BCL ->
    bc ins bld false true
  | Op.BCLA ->
    bc ins bld true true
  | Op.BCCTR ->
    bcctr ins bld false
  | Op.BCCTRL ->
    bcctr ins bld true
  | Op.BCLR ->
    bclr ins bld false
  | Op.BCLRL ->
    bclr ins bld true
  | Op.CMPI | Op.CMPL | Op.CMPLI ->
    raise InvalidOperandException (* invaild *)
  | Op.CMP ->
    cmp ins bld true
  | Op.CMPW ->
    cmp ins bld true
  | Op.CMPWI ->
    cmp ins bld true
  | Op.CMPLW ->
    cmpl ins bld true
  | Op.CMPLWI ->
    cmpl ins bld true
  | Op.CMPD ->
    cmp ins bld false
  | Op.CMPDI ->
    cmp ins bld false
  | Op.CMPLD ->
    cmpl ins bld false
  | Op.CMPLDI ->
    cmpl ins bld false
  | Op.CMPB ->
    cmpb ins bld
  | Op.CNTLZW ->
    cntlzw ins false bld
  | Op.CNTLZWdot ->
    cntlzw ins true bld
  | Op.CNTLZD ->
    cntlzd ins false bld
  | Op.CNTLZDdot ->
    cntlzd ins true bld
  | Op.CRCLR ->
    crclr ins bld
  | Op.CREQV ->
    creqv ins bld
  | Op.CRXOR ->
    crxor ins bld
  | Op.CROR ->
    cror ins bld
  | Op.CRORC ->
    crorc ins bld
  | Op.CRSET ->
    crset ins bld
  | Op.CRNOR ->
    crnor ins bld
  | Op.CRNOT ->
    crnot ins bld
  | Op.CRAND ->
    crand ins bld
  | Op.CRANDC ->
    crandc ins bld
  | Op.CRNAND ->
    crnand ins bld
  | Op.CRMOVE ->
    crmove ins bld
  (* The cache-management forms are hints about a cache BRemu does not model, so
     they leave no trace; dcbz below is the exception, as it clears storage. *)
  | Op.DCBT | Op.DCBTST | Op.DCBA | Op.DCBST | Op.DCBF | Op.DCBI | Op.ICBI ->
    nop ins bld
  | Op.DCBZ ->
    dcbz ins bld
  | Op.DIVW ->
    divw ins false false bld
  | Op.DIVWdot ->
    divw ins true false bld
  | Op.DIVWO ->
    divw ins false true bld
  | Op.DIVWOdot ->
    divw ins true true bld
  | Op.DIVWU ->
    divwu ins false false bld
  | Op.DIVWUdot ->
    divwu ins true false bld
  | Op.DIVWUO ->
    divwu ins false true bld
  | Op.DIVWUOdot ->
    divwu ins true true bld
  | Op.EXTSB ->
    extsb ins false bld
  | Op.EXTSBdot ->
    extsb ins true bld
  | Op.EXTSH ->
    extsh ins false bld
  | Op.EXTSHdot ->
    extsh ins true bld
  | Op.EIEIO ->
    nop ins bld
  | Op.ECIWX ->
    eciwx ins bld
  | Op.ECOWX ->
    ecowx ins bld
  | Op.EQV ->
    eqvx ins false bld
  | Op.EQVdot ->
    eqvx ins true bld
  | Op.FABS ->
    fabs ins false bld
  | Op.FABSdot ->
    fabs ins true bld
  | Op.FADD ->
    fadd ins false true bld
  | Op.FADDS ->
    fadd ins false false bld
  | Op.FADDdot ->
    fadd ins true true bld
  | Op.FADDSdot ->
    fadd ins true false bld
  | Op.FCTIW ->
    fctiw ins false bld
  | Op.FCTIWdot ->
    fctiw ins true bld
  | Op.FCTIWZ ->
    fctiwz ins false bld
  | Op.FCTIWZdot ->
    fctiwz ins true bld
  | Op.FCMPO ->
    fcmpo ins bld
  | Op.FCMPU ->
    fcmpu ins bld
  | Op.FDIV ->
    fdiv ins false true bld
  | Op.FDIVS ->
    fdiv ins false false bld
  | Op.FDIVdot ->
    fdiv ins true true bld
  | Op.FDIVSdot ->
    fdiv ins true false bld
  | Op.FRES ->
    fres ins false bld
  | Op.FRESdot ->
    fres ins true bld
  | Op.FRSQRTE ->
    frsqrte ins false bld
  | Op.FRSQRTEdot ->
    frsqrte ins true bld
  | Op.FRSP ->
    frsp ins false bld
  | Op.FRSPdot ->
    frsp ins true bld
  | Op.FMADD ->
    fmadd ins false true bld
  | Op.FMADDS ->
    fmadd ins false false bld
  | Op.FMADDdot ->
    fmadd ins true true bld
  | Op.FMADDSdot ->
    fmadd ins true false bld
  | Op.FMR ->
    fmr ins false bld
  | Op.FMRdot ->
    fmr ins true bld
  | Op.FMSUB ->
    fmsub ins false true bld
  | Op.FMSUBS ->
    fmsub ins false false bld
  | Op.FMSUBdot ->
    fmsub ins true true bld
  | Op.FMSUBSdot ->
    fmsub ins true false bld
  | Op.FMUL ->
    fmul ins false true bld
  | Op.FMULS ->
    fmul ins false false bld
  | Op.FMULdot ->
    fmul ins true true bld
  | Op.FMULSdot ->
    fmul ins true false bld
  | Op.FNABS ->
    fnabs ins false bld
  | Op.FNABSdot ->
    fnabs ins true bld
  | Op.FNEG ->
    fneg ins false bld
  | Op.FNEGdot ->
    fneg ins true bld
  | Op.FNMADD ->
    fnmadd ins false true bld
  | Op.FNMADDdot ->
    fnmadd ins true true bld
  | Op.FNMADDS ->
    fnmadd ins false false bld
  | Op.FNMADDSdot ->
    fnmadd ins true false bld
  | Op.FNMSUB ->
    fnmsub ins false true bld
  | Op.FNMSUBdot ->
    fnmsub ins true true bld
  | Op.FNMSUBS ->
    fnmsub ins false false bld
  | Op.FNMSUBSdot ->
    fnmsub ins true false bld
  | Op.FSEL ->
    fsel ins false bld
  | Op.FSELdot ->
    fsel ins true bld
  | Op.FSUB ->
    fsub ins false true bld
  | Op.FSUBS ->
    fsub ins false false bld
  | Op.FSUBdot ->
    fsub ins true true bld
  | Op.FSUBSdot ->
    fsub ins true false bld
  | Op.FSQRT ->
    fsqrt ins false true bld
  | Op.FSQRTS ->
    fsqrt ins false false bld
  | Op.FSQRTdot ->
    fsqrt ins true true bld
  | Op.FSQRTSdot ->
    fsqrt ins true false bld
  | Op.ISYNC | Op.LWSYNC | Op.SYNC ->
    nop ins bld
  | Op.LBZ ->
    lbz ins bld
  | Op.LBZU ->
    lbzu ins bld
  | Op.LBZUX ->
    lbzux ins bld
  | Op.LBZX ->
    lbzx ins bld
  | Op.LFD ->
    lfd ins bld
  | Op.LFDU ->
    lfdu ins bld
  | Op.LFDUX ->
    lfdux ins bld
  | Op.LFDX ->
    lfdx ins bld
  | Op.LFIWAX ->
    lfiwax ins bld
  | Op.LFIWZX ->
    lfiwzx ins bld
  | Op.LFS ->
    lfs ins bld
  | Op.LFSU ->
    lfsu ins bld
  | Op.LFSUX ->
    lfsux ins bld
  | Op.LFSX ->
    lfsx ins bld
  | Op.LHA ->
    lha ins bld
  | Op.LHAU ->
    lhau ins bld
  | Op.LHAUX ->
    lhaux ins bld
  | Op.LHAX ->
    lhax ins bld
  | Op.LHBRX ->
    lhbrx ins bld
  | Op.LHZ ->
    lhz ins bld
  | Op.LHZU ->
    lhzu ins bld
  | Op.LHZUX ->
    lhzux ins bld
  | Op.LHZX ->
    lhzx ins bld
  | Op.LI ->
    li ins bld
  | Op.LIS ->
    lis ins bld
  | Op.LWARX ->
    lwarx ins bld
  | Op.LWBRX ->
    lwbrx ins bld
  | Op.LWZ ->
    lwz ins bld
  | Op.LWZU ->
    lwzu ins bld
  | Op.LWZUX ->
    lwzux ins bld
  | Op.LWZX ->
    lwzx ins bld
  | Op.LSWI ->
    lswi ins bld
  | Op.LSWX ->
    lswx ins bld
  | Op.MCRF ->
    mcrf ins bld
  | Op.MCRFS ->
    mcrfs ins bld
  | Op.MCRXR ->
    mcrxr ins bld
  (* The supervisor's instructions: the MSR and the segment registers, the
     return from interrupt, and the TLB maintenance. None has an effect a
     user-level program can see, and the registers they touch are not in the
     register file. *)
  | Op.MFMSR | Op.MFSR | Op.MFSRIN | Op.MTSR | Op.MTSRIN | Op.RFI | Op.TLBIA
  | Op.TLBIE | Op.TLBSYNC ->
    sideEffects ins bld UnsupportedInstruction
  | Op.MFCR ->
    mfcr ins bld
  | Op.MFSPR ->
    mfspr ins bld
  | Op.MFTB ->
    mftb ins bld
  | Op.MFTBU ->
    mftbu ins bld
  | Op.MFCTR ->
    mfctr ins bld
  | Op.MFFS ->
    FPLifter.mffs ins false bld
  | Op.MFFSdot ->
    FPLifter.mffs ins true bld
  | Op.MFLR ->
    mflr ins bld
  | Op.MFXER ->
    mfxer ins bld
  | Op.MR ->
    mr ins bld
  | Op.MTCTR ->
    mtctr ins bld
  | Op.MTCRF ->
    mtcrf ins bld
  | Op.MTFSFI ->
    FPLifter.mtfsfi ins false bld
  | Op.MTFSFIdot ->
    FPLifter.mtfsfi ins true bld
  | Op.MTSPR ->
    mtspr ins bld
  | Op.MTFSB0 ->
    mtfsb ins false false bld
  | Op.MTFSB0dot ->
    mtfsb ins false true bld
  | Op.MTFSB1 ->
    mtfsb ins true false bld
  | Op.MTFSB1dot ->
    mtfsb ins true true bld
  | Op.MTFSF ->
    FPLifter.mtfsf ins false bld
  | Op.MTFSFdot ->
    FPLifter.mtfsf ins true bld
  | Op.MTLR ->
    mtlr ins bld
  | Op.MTXER ->
    mtxer ins bld
  | Op.MULHW ->
    mulhw ins false bld
  | Op.MULHWdot ->
    mulhw ins true bld
  | Op.MULHWU ->
    mulhwu ins false bld
  | Op.MULHWUdot ->
    mulhwu ins true bld
  | Op.MULLI ->
    mulli ins bld
  | Op.MULLW ->
    mullw ins false false bld
  | Op.MULLWdot ->
    mullw ins true false bld
  | Op.MULLWO ->
    mullw ins false true bld
  | Op.MULLWOdot ->
    mullw ins true true bld
  | Op.NAND ->
    nand ins false bld
  | Op.NANDdot ->
    nand ins true bld
  | Op.NEG ->
    neg ins false false bld
  | Op.NEGdot ->
    neg ins true false bld
  | Op.NEGO ->
    neg ins false true bld
  | Op.NEGOdot ->
    neg ins true true bld
  | Op.NOR ->
    nor ins false bld
  | Op.NORdot ->
    nor ins true bld
  | Op.NOP ->
    nop ins bld
  | Op.ORC ->
    orc ins false bld
  | Op.ORCdot ->
    orc ins true bld
  | Op.OR ->
    orx ins false bld
  | Op.ORdot ->
    orx ins true bld
  | Op.ORI ->
    ori ins bld
  | Op.ORIS ->
    oris ins bld
  | Op.RLWIMI ->
    rlwimi ins false bld
  | Op.RLWIMIdot ->
    rlwimi ins true bld
  | Op.RLWINM ->
    rlwinm ins false bld
  | Op.RLWINMdot ->
    rlwinm ins true bld
  | Op.RLWNM ->
    rlwnm ins false bld
  | Op.RLWNMdot ->
    rlwnm ins true bld
  | Op.ROTLW ->
    rotlw ins bld
  | Op.SC ->
    sideEffects ins bld SysCall
  | Op.SLW ->
    slw ins false bld
  | Op.SLWdot ->
    slw ins true bld
  | Op.SRAW ->
    sraw ins false bld
  | Op.SRAWdot ->
    sraw ins true bld
  | Op.SRAWI ->
    srawi ins false bld
  | Op.SRAWIdot ->
    srawi ins true bld
  | Op.SRW ->
    srw ins false bld
  | Op.SRWdot ->
    srw ins true bld
  | Op.STB ->
    stb ins bld
  | Op.STBU ->
    stbu ins bld
  | Op.STBX ->
    stbx ins bld
  | Op.STBUX ->
    stbux ins bld
  | Op.STFD ->
    stfd ins bld
  | Op.STFDX ->
    stfdx ins bld
  | Op.STFDU ->
    stfdu ins bld
  | Op.STFDUX ->
    stfdux ins bld
  | Op.STFIWX ->
    stfiwx ins bld
  | Op.STFS ->
    stfs ins bld
  | Op.STFSX ->
    stfsx ins bld
  | Op.STFSU ->
    stfsu ins bld
  | Op.STFSUX ->
    stfsux ins bld
  | Op.STH ->
    sth ins bld
  | Op.STHBRX ->
    sthbrx ins bld
  | Op.STHU ->
    sthu ins bld
  | Op.STHX ->
    sthx ins bld
  | Op.STHUX ->
    sthux ins bld
  | Op.STW ->
    stw ins bld
  | Op.LMW ->
    lmw ins bld
  | Op.STMW ->
    stmw ins bld
  | Op.STWBRX ->
    stwbrx ins bld
  | Op.STWCXdot ->
    stwcxdot ins bld
  | Op.STWU ->
    stwu ins bld
  | Op.STWUX ->
    stwux ins bld
  | Op.STWX ->
    stwx ins bld
  | Op.STSWI ->
    stswi ins bld
  | Op.STSWX ->
    stswx ins bld
  | Op.SUBF ->
    subf ins false false bld
  | Op.SUBFdot ->
    subf ins true false bld
  | Op.SUBFO ->
    subf ins false true bld
  | Op.SUBFOdot ->
    subf ins true true bld
  | Op.SUBFC ->
    subfc ins false false bld
  | Op.SUBFCdot ->
    subfc ins true false bld
  | Op.SUBFCO ->
    subfc ins false true bld
  | Op.SUBFCOdot ->
    subfc ins true true bld
  | Op.SUBFE ->
    subfe ins false false bld
  | Op.SUBFEdot ->
    subfe ins true false bld
  | Op.SUBFEO ->
    subfe ins false true bld
  | Op.SUBFEOdot ->
    subfe ins true true bld
  | Op.SUBFIC ->
    subfic ins bld
  | Op.SUBFME ->
    subfme ins false false bld
  | Op.SUBFMEdot ->
    subfme ins true false bld
  | Op.SUBFMEO ->
    subfme ins false true bld
  | Op.SUBFMEOdot ->
    subfme ins true true bld
  | Op.SUBFZE ->
    subfze ins false false bld
  | Op.SUBFZEdot ->
    subfze ins true false bld
  | Op.SUBFZEO ->
    subfze ins false true bld
  | Op.SUBFZEOdot ->
    subfze ins true true bld
  | Op.TRAP | Op.TWI ->
    trap ins bld
  | Op.TWLT ->
    trapCond ins (AST.slt) bld
  | Op.TWLE ->
    trapCond ins (AST.sle) bld
  | Op.TWEQ ->
    trapCond ins (AST.eq) bld
  | Op.TWGE ->
    trapCond ins (AST.sge) bld
  | Op.TWGT ->
    trapCond ins (AST.sgt) bld
  | Op.TWNE ->
    trapCond ins (AST.neq) bld
  | Op.TWLLT ->
    trapCond ins (AST.lt) bld
  | Op.TWLLE ->
    trapCond ins (AST.le) bld
  | Op.TWLNL ->
    trapCond ins (AST.ge) bld
  | Op.TWLGT ->
    trapCond ins (AST.gt) bld
  | Op.TWLTI ->
    trapCond ins (AST.slt) bld
  | Op.TWLEI ->
    trapCond ins (AST.sle) bld
  | Op.TWEQI ->
    trapCond ins (AST.eq) bld
  | Op.TWGEI ->
    trapCond ins (AST.sge) bld
  | Op.TWGTI ->
    trapCond ins (AST.sgt) bld
  | Op.TWNEI ->
    trapCond ins (AST.neq) bld
  | Op.TWLLTI ->
    trapCond ins (AST.lt) bld
  | Op.TWLLEI ->
    trapCond ins (AST.le) bld
  | Op.TWLNLI ->
    trapCond ins (AST.ge) bld
  | Op.TWLGTI ->
    trapCond ins (AST.gt) bld
  | Op.XOR ->
    xor ins false bld
  | Op.XORdot ->
    xor ins true bld
  | Op.XORI ->
    xori ins bld
  | Op.XORIS ->
    xoris ins bld
  (* 64-bit forms. *)
  | Op.LD ->
    ld ins bld
  | Op.LDU ->
    ldu ins bld
  | Op.LDX ->
    ldx ins bld
  | Op.LDUX ->
    ldux ins bld
  | Op.LDARX ->
    ldarx ins bld
  | Op.LBARX ->
    lbarx ins bld
  | Op.LHARX ->
    lharx ins bld
  | Op.LDBRX ->
    ldbrx ins bld
  | Op.LWA ->
    lwa ins bld
  | Op.LWAX ->
    lwax ins bld
  | Op.LWAUX ->
    lwaux ins bld
  | Op.STD ->
    std ins bld
  | Op.STDU ->
    stdu ins bld
  | Op.STDX ->
    stdx ins bld
  | Op.STDUX ->
    stdux ins bld
  | Op.STDBRX ->
    stdbrx ins bld
  | Op.STDCXdot ->
    stdcxdot ins bld
  | Op.STBCXdot ->
    stbcxdot ins bld
  | Op.STHCXdot ->
    sthcxdot ins bld
  | Op.RLDICL ->
    rldicl ins false bld
  | Op.RLDICLdot ->
    rldicl ins true bld
  | Op.RLDICR ->
    rldicr ins false bld
  | Op.RLDICRdot ->
    rldicr ins true bld
  | Op.RLDIC ->
    rldic ins false bld
  | Op.RLDICdot ->
    rldic ins true bld
  | Op.RLDIMI ->
    rldimi ins false bld
  | Op.RLDIMIdot ->
    rldimi ins true bld
  | Op.RLDCL ->
    rldcl ins false bld
  | Op.RLDCLdot ->
    rldcl ins true bld
  | Op.RLDCR ->
    rldcr ins false bld
  | Op.RLDCRdot ->
    rldcr ins true bld
  | Op.SLD ->
    sld ins false bld
  | Op.SLDdot ->
    sld ins true bld
  | Op.SRD ->
    srd ins false bld
  | Op.SRDdot ->
    srd ins true bld
  | Op.SRAD ->
    srad ins false bld
  | Op.SRADdot ->
    srad ins true bld
  | Op.SRADI ->
    sradi ins false bld
  | Op.SRADIdot ->
    sradi ins true bld
  | Op.EXTSW ->
    extsw ins false bld
  | Op.EXTSWdot ->
    extsw ins true bld
  | Op.MULLD ->
    mulld ins false false bld
  | Op.MULLDdot ->
    mulld ins true false bld
  | Op.MULLDO ->
    mulld ins false true bld
  | Op.MULLDOdot ->
    mulld ins true true bld
  | Op.MULHD ->
    mulhd ins false bld
  | Op.MULHDdot ->
    mulhd ins true bld
  | Op.MULHDU ->
    mulhdu ins false bld
  | Op.MULHDUdot ->
    mulhdu ins true bld
  | Op.DIVD ->
    divd ins false false bld
  | Op.DIVDdot ->
    divd ins true false bld
  | Op.DIVDO ->
    divd ins false true bld
  | Op.DIVDOdot ->
    divd ins true true bld
  | Op.DIVDU ->
    divdu ins false false bld
  | Op.DIVDUdot ->
    divdu ins true false bld
  | Op.DIVDUO ->
    divdu ins false true bld
  | Op.DIVDUOdot ->
    divdu ins true true bld
  | Op.POPCNTB ->
    popcnt ins bld 8
  | Op.POPCNTW ->
    popcnt ins bld 32
  | Op.POPCNTD ->
    popcnt ins bld 64
  | Op.PRTYW ->
    prty ins bld 32
  | Op.PRTYD ->
    prty ins bld 64
  | Op.BPERMD ->
    bpermd ins bld
  | Op.ISEL ->
    isel ins bld
  | Op.MTOCRF ->
    mtcrf ins bld
  | Op.MFOCRF ->
    mfocrf ins bld
  | Op.MFVSRD ->
    mfvsr ins bld 64<rt>
  | Op.MFVSRWZ ->
    mfvsr ins bld 32<rt>
  | Op.MTVSRD ->
    mtvsrd ins bld
  | Op.MTVSRWA ->
    mtvsrw ins bld true
  | Op.MTVSRWZ ->
    mtvsrw ins bld false
  | Op.TD ->
    trapGeneric ins bld false
  | Op.TDI ->
    trapGeneric ins bld false
  | Op.TW ->
    trapGeneric ins bld true
  | Op.FCTID ->
    fcti ins false bld 64<rt> true false
  | Op.FCTIDdot ->
    fcti ins true bld 64<rt> true false
  | Op.FCTIDZ ->
    fcti ins false bld 64<rt> true true
  | Op.FCTIDZdot ->
    fcti ins true bld 64<rt> true true
  | Op.FCTIDU ->
    fcti ins false bld 64<rt> false false
  | Op.FCTIDUdot ->
    fcti ins true bld 64<rt> false false
  | Op.FCTIDUZ ->
    fcti ins false bld 64<rt> false true
  | Op.FCTIDUZdot ->
    fcti ins true bld 64<rt> false true
  | Op.FCTIWU ->
    fcti ins false bld 32<rt> false false
  | Op.FCTIWUdot ->
    fcti ins true bld 32<rt> false false
  | Op.FCTIWUZ ->
    fcti ins false bld 32<rt> false true
  | Op.FCTIWUZdot ->
    fcti ins true bld 32<rt> false true
  | Op.FCFID ->
    fcfid ins false bld true false
  | Op.FCFIDdot ->
    fcfid ins true bld true false
  | Op.FCFIDU ->
    fcfid ins false bld false false
  | Op.FCFIDUdot ->
    fcfid ins true bld false false
  | Op.FCFIDS ->
    fcfid ins false bld true true
  | Op.FCFIDSdot ->
    fcfid ins true bld true true
  | Op.FCFIDUS ->
    fcfid ins false bld false true
  | Op.FCFIDUSdot ->
    fcfid ins true bld false true
  | Op.FRIN ->
    frnd ins false bld RoundingMode.ToNearestAway
  | Op.FRINdot ->
    frnd ins true bld RoundingMode.ToNearestAway
  | Op.FRIZ ->
    frnd ins false bld RoundingMode.TowardZero
  | Op.FRIZdot ->
    frnd ins true bld RoundingMode.TowardZero
  | Op.FRIP ->
    frnd ins false bld RoundingMode.TowardPositive
  | Op.FRIPdot ->
    frnd ins true bld RoundingMode.TowardPositive
  | Op.FRIM ->
    frnd ins false bld RoundingMode.TowardNegative
  | Op.FRIMdot ->
    frnd ins true bld RoundingMode.TowardNegative
  (* Vector forms. *)
  | Op.LVX | Op.LVXL ->
    lvx ins bld
  | Op.STVX | Op.STVXL ->
    stvx ins bld
  | Op.LVSL ->
    lvsx ins bld true
  | Op.LVSR ->
    lvsx ins bld false
  | Op.LVEBX ->
    lvex ins bld 8<rt>
  | Op.LVEHX ->
    lvex ins bld 16<rt>
  | Op.LVEWX ->
    lvex ins bld 32<rt>
  | Op.STVEBX ->
    stvex ins bld 8<rt>
  | Op.STVEHX ->
    stvex ins bld 16<rt>
  | Op.STVEWX ->
    stvex ins bld 32<rt>
  | Op.LXVD2X ->
    lxvx ins bld 64<rt> true
  | Op.STXVD2X ->
    lxvx ins bld 64<rt> false
  | Op.LXVW4X ->
    lxvx ins bld 32<rt> true
  | Op.STXVW4X ->
    lxvx ins bld 32<rt> false
  | Op.LXSDX ->
    lxsdx ins bld false true
  | Op.LXVDSX ->
    lxsdx ins bld true true
  | Op.STXSDX ->
    lxsdx ins bld false false
  | Op.LXSD ->
    lxsd ins bld true
  | Op.STXSD ->
    lxsd ins bld false
  | Op.VAND | Op.XXLAND ->
    vecLogical ins bld (.&)
  | Op.VOR | Op.XXLOR ->
    vecLogical ins bld (.|)
  | Op.VXOR | Op.XXLXOR ->
    vecLogical ins bld (<+>)
  | Op.VANDC | Op.XXLANDC ->
    vecLogical ins bld (fun a b -> a .& AST.not b)
  | Op.VORC | Op.XXLORC ->
    vecLogical ins bld (fun a b -> a .| AST.not b)
  | Op.VNOR | Op.XXLNOR ->
    vecLogical ins bld (fun a b -> AST.not (a .| b))
  | Op.VNAND | Op.XXLNAND ->
    vecLogical ins bld (fun a b -> AST.not (a .& b))
  | Op.VEQV | Op.XXLEQV ->
    vecLogical ins bld (fun a b -> AST.not (a <+> b))
  | Op.VSEL | Op.XXSEL ->
    vecSelect ins bld
  | Op.VPERM ->
    vecPermute ins bld
  | Op.XXPERMDI ->
    vecPermuteDouble ins bld
  | Op.XXMRGHW ->
    vecMerge ins bld 32<rt> true
  | Op.XXMRGLW ->
    vecMerge ins bld 32<rt> false
  | Op.XXSPLTW ->
    xxspltw ins bld
  | Op.XXSPLTIB ->
    xxspltib ins bld
  | Op.MTVSRDD ->
    mtvsrdd ins bld
  | Op.MFVSRLD ->
    mfvsrld ins bld
  | Op.FCPSGN ->
    fcpsgn ins bld
  | Op.MFFSL ->
    mffsl ins bld
  | Op.MFFSCRN ->
    mffscrn ins bld
  | Op.MFFSCRNI ->
    mffscrn ins bld
  | Op.XSADDDP ->
    vsxScalarBinary ins bld AST.fadd true
  | Op.XVADDDP ->
    vsxVectorBinary ins bld AST.fadd
  | Op.XVSUBDP ->
    vsxVectorBinary ins bld AST.fsub
  | Op.XVMULDP ->
    vsxVectorBinary ins bld AST.fmul
  | Op.XVDIVDP ->
    vsxVectorBinary ins bld AST.fdiv
  | Op.XVNEGDP ->
    xvnegdp ins bld
  | Op.XVCMPGEDP ->
    vecCompare ins bld 64<rt> AST.fge false
  | Op.XVCMPGEDPdot ->
    vecCompare ins bld 64<rt> AST.fge true
  | Op.XVCMPGTDP ->
    vecCompare ins bld 64<rt> AST.fgt false
  | Op.XVCMPGTDPdot ->
    vecCompare ins bld 64<rt> AST.fgt true
  | Op.XVCVSXWDP ->
    xvcvsxwdp ins bld
  | Op.XSMULDP ->
    vsxScalarBinary ins bld AST.fmul true
  | Op.XSADDSP ->
    vsxScalarBinarySingle ins bld AST.fadd
  | Op.XSSUBSP ->
    vsxScalarBinarySingle ins bld AST.fsub
  | Op.XSMULSP ->
    vsxScalarBinarySingle ins bld AST.fmul
  | Op.XSDIVSP ->
    vsxScalarBinarySingle ins bld AST.fdiv
  | Op.XSSQRTDP ->
    vsxScalarUnary ins bld AST.fsqrt true
  | Op.XSSQRTSP ->
    let single b = AST.cast CastKind.FloatCast 32<rt> (AST.fsqrt b)
    let widen b = AST.cast CastKind.FloatCast 64<rt> (single b)
    vsxScalarUnary ins bld widen true
  | Op.XSSUBDP ->
    vsxScalarBinary ins bld AST.fsub true
  | Op.XSDIVDP ->
    vsxScalarBinary ins bld AST.fdiv true
  | Op.XSCPSGNDP ->
    vsxScalarBinary ins bld copySign false
  | Op.XSMADDADP ->
    xsmaddadp ins bld
  | Op.XSMADDMDP ->
    xsmaddmdp ins bld
  | Op.XSMSUBADP ->
    xsmsubadp ins bld
  | Op.XSMSUBMDP ->
    xsmsubmdp ins bld
  | Op.XSNMADDADP ->
    xsnmaddadp ins bld
  | Op.XSNMADDMDP ->
    xsnmaddmdp ins bld
  | Op.XSNMSUBADP ->
    xsnmsubadp ins bld
  | Op.XSNMSUBMDP ->
    xsnmsubmdp ins bld
  | Op.XSMADDASP ->
    xsmaddasp ins bld
  | Op.XSMADDMSP ->
    xsmaddmsp ins bld
  | Op.XSMSUBASP ->
    xsmsubasp ins bld
  | Op.XSMSUBMSP ->
    xsmsubmsp ins bld
  | Op.XSNMADDASP ->
    xsnmaddasp ins bld
  | Op.XSNMADDMSP ->
    xsnmaddmsp ins bld
  | Op.XSNMSUBASP ->
    xsnmsubasp ins bld
  | Op.XSNMSUBMSP ->
    xsnmsubmsp ins bld
  | Op.XSCVDPSXWS ->
    xscvdpsxws ins bld
  | Op.XSCVDPUXWS ->
    xscvdpuxws ins bld
  | Op.XSCVDPSXDS ->
    xscvdpsxds ins bld
  | Op.XSCVDPUXDS ->
    xscvdpuxds ins bld
  | Op.XSCVSXDDP ->
    xscvsxddp ins bld
  | Op.XSCVUXDDP ->
    xscvuxddp ins bld
  | Op.XSCVSXDSP ->
    xscvsxdsp ins bld
  | Op.XSCVUXDSP ->
    xscvuxdsp ins bld
  | Op.XSMAXDP ->
    vsxScalarBinary ins bld (fun a b -> AST.ite (AST.fgt a b) a b) true
  | Op.XSMINDP ->
    vsxScalarBinary ins bld (fun a b -> AST.ite (AST.flt a b) a b) true
  | Op.XSNEGDP ->
    vsxScalarUnary ins bld (fun b ->
      b <+> numU64 0x8000000000000000UL 64<rt>) false
  | Op.XSNABSDP ->
    vsxScalarUnary ins bld (fun b ->
      b .| numU64 0x8000000000000000UL 64<rt>) false
  | Op.XSRDPI ->
    let round = AST.roundToIntegral RoundingMode.ToNearestAway 64<rt>
    vsxScalarUnary ins bld round true
  | Op.XSRDPIZ ->
    let round = AST.roundToIntegral RoundingMode.TowardZero 64<rt>
    vsxScalarUnary ins bld round true
  | Op.XSRDPIP ->
    let round = AST.roundToIntegral RoundingMode.TowardPositive 64<rt>
    vsxScalarUnary ins bld round true
  | Op.XSRDPIM ->
    let round = AST.roundToIntegral RoundingMode.TowardNegative 64<rt>
    vsxScalarUnary ins bld round true
  | Op.XSCVDPSP ->
    xscvdpsp ins bld
  | Op.XSCVSPDP ->
    xscvspdp ins bld
  | Op.XSCMPUDP ->
    xscmpudp ins bld
  | Op.XSABSDP ->
    vsxScalarUnary ins bld (fun b ->
      b .& numU64 0x7fffffffffffffffUL 64<rt>) false
  | Op.XSRSP ->
    (* Rounding a double to single precision and keeping it in double format. *)
    vsxScalarUnary ins bld (fun b ->
      AST.cast CastKind.FloatCast 64<rt> (AST.cast CastKind.FloatCast 32<rt> b))
      true
  | Op.XSCVDPSPN ->
    xscvdpspn ins bld
  | Op.XSCVSPDPN ->
    xscvspdpn ins bld
  | Op.VSLDOI ->
    vecShiftDouble ins bld 1
  | Op.XXSLDWI ->
    vecShiftDouble ins bld 4
  | Op.VSPLTB ->
    vecSplat ins bld 8<rt>
  | Op.VSPLTH ->
    vecSplat ins bld 16<rt>
  | Op.VSPLTW ->
    vecSplat ins bld 32<rt>
  | Op.VSPLTISB ->
    vecSplatImm ins bld 8<rt>
  | Op.VSPLTISH ->
    vecSplatImm ins bld 16<rt>
  | Op.VSPLTISW ->
    vecSplatImm ins bld 32<rt>
  | Op.VMRGHB ->
    vecMerge ins bld 8<rt> true
  | Op.VMRGHH ->
    vecMerge ins bld 16<rt> true
  | Op.VMRGHW ->
    vecMerge ins bld 32<rt> true
  | Op.VMRGLB ->
    vecMerge ins bld 8<rt> false
  | Op.VMRGLH ->
    vecMerge ins bld 16<rt> false
  | Op.VMRGLW ->
    vecMerge ins bld 32<rt> false
  | Op.VMRGEW ->
    vecMergeWord ins bld true
  | Op.VMRGOW ->
    vecMergeWord ins bld false
  | Op.VPKUHUM ->
    vecPack ins bld 16<rt>
  | Op.VPKUWUM ->
    vecPack ins bld 32<rt>
  | Op.VUPKHSB ->
    vecUnpack ins bld 8<rt> true
  | Op.VUPKHSH ->
    vecUnpack ins bld 16<rt> true
  | Op.VUPKLSB ->
    vecUnpack ins bld 8<rt> false
  | Op.VUPKLSH ->
    vecUnpack ins bld 16<rt> false
  | Op.VUPKHSW ->
    vecUnpack ins bld 32<rt> true
  | Op.VUPKLSW ->
    vecUnpack ins bld 32<rt> false
  | Op.VSL ->
    vecShiftWhole ins bld true false
  | Op.VSR ->
    vecShiftWhole ins bld false false
  | Op.VSLO ->
    vecShiftWhole ins bld true true
  | Op.VSRO ->
    vecShiftWhole ins bld false true
  | Op.VGBBD ->
    vecGatherBits ins bld
  | Op.VBPERMQ ->
    vecBitPermute ins bld
  | Op.MFVSCR ->
    vscrMove ins bld true
  | Op.MTVSCR ->
    vscrMove ins bld false
  | Op.VADDUBM ->
    vecBinary ins bld 8<rt> (.+)
  | Op.VADDUHM ->
    vecBinary ins bld 16<rt> (.+)
  | Op.VADDUWM ->
    vecBinary ins bld 32<rt> (.+)
  | Op.VADDUBS ->
    vecSaturateByte ins bld true
  | Op.VSUBUBS ->
    vecSaturateByte ins bld false
  | Op.VMULUWM ->
    vecBinary ins bld 32<rt> (.*)
  | Op.VMULESW ->
    vecMulWord ins bld true
  | Op.VMULOSW ->
    vecMulWord ins bld false
  | Op.VADDUDM ->
    vecBinary ins bld 64<rt> (.+)
  | Op.VSUBUBM ->
    vecBinary ins bld 8<rt> (.-)
  | Op.VSUBUHM ->
    vecBinary ins bld 16<rt> (.-)
  | Op.VSUBUWM ->
    vecBinary ins bld 32<rt> (.-)
  | Op.VSUBUDM ->
    vecBinary ins bld 64<rt> (.-)
  | Op.VSLB ->
    vecBinary ins bld 8<rt> (elementShift 8<rt> 0)
  | Op.VSLH ->
    vecBinary ins bld 16<rt> (elementShift 16<rt> 0)
  | Op.VSLW ->
    vecBinary ins bld 32<rt> (elementShift 32<rt> 0)
  | Op.VSLD ->
    vecBinary ins bld 64<rt> (elementShift 64<rt> 0)
  | Op.VSRB ->
    vecBinary ins bld 8<rt> (elementShift 8<rt> 1)
  | Op.VSRH ->
    vecBinary ins bld 16<rt> (elementShift 16<rt> 1)
  | Op.VSRW ->
    vecBinary ins bld 32<rt> (elementShift 32<rt> 1)
  | Op.VSRD ->
    vecBinary ins bld 64<rt> (elementShift 64<rt> 1)
  | Op.VSRAB ->
    vecBinary ins bld 8<rt> (elementShift 8<rt> 2)
  | Op.VSRAH ->
    vecBinary ins bld 16<rt> (elementShift 16<rt> 2)
  | Op.VSRAW ->
    vecBinary ins bld 32<rt> (elementShift 32<rt> 2)
  | Op.VSRAD ->
    vecBinary ins bld 64<rt> (elementShift 64<rt> 2)
  | Op.VRLB ->
    vecBinary ins bld 8<rt> (elementShift 8<rt> 3)
  | Op.VRLH ->
    vecBinary ins bld 16<rt> (elementShift 16<rt> 3)
  | Op.VRLW ->
    vecBinary ins bld 32<rt> (elementShift 32<rt> 3)
  | Op.VRLD ->
    vecBinary ins bld 64<rt> (elementShift 64<rt> 3)
  | Op.VMAXUB ->
    vecBinary ins bld 8<rt> (fun a b -> AST.ite (a .> b) a b)
  | Op.VMAXUH ->
    vecBinary ins bld 16<rt> (fun a b -> AST.ite (a .> b) a b)
  | Op.VMAXUW ->
    vecBinary ins bld 32<rt> (fun a b -> AST.ite (a .> b) a b)
  | Op.VMAXUD ->
    vecBinary ins bld 64<rt> (fun a b -> AST.ite (a .> b) a b)
  | Op.VMINUB ->
    vecBinary ins bld 8<rt> (fun a b -> AST.ite (a .< b) a b)
  | Op.VMINUH ->
    vecBinary ins bld 16<rt> (fun a b -> AST.ite (a .< b) a b)
  | Op.VMINUW ->
    vecBinary ins bld 32<rt> (fun a b -> AST.ite (a .< b) a b)
  | Op.VMINUD ->
    vecBinary ins bld 64<rt> (fun a b -> AST.ite (a .< b) a b)
  | Op.VMAXSB ->
    vecBinary ins bld 8<rt> (fun a b -> AST.ite (a ?> b) a b)
  | Op.VMAXSH ->
    vecBinary ins bld 16<rt> (fun a b -> AST.ite (a ?> b) a b)
  | Op.VMAXSW ->
    vecBinary ins bld 32<rt> (fun a b -> AST.ite (a ?> b) a b)
  | Op.VMAXSD ->
    vecBinary ins bld 64<rt> (fun a b -> AST.ite (a ?> b) a b)
  | Op.VMINSB ->
    vecBinary ins bld 8<rt> (fun a b -> AST.ite (a ?< b) a b)
  | Op.VMINSH ->
    vecBinary ins bld 16<rt> (fun a b -> AST.ite (a ?< b) a b)
  | Op.VMINSW ->
    vecBinary ins bld 32<rt> (fun a b -> AST.ite (a ?< b) a b)
  | Op.VMINSD ->
    vecBinary ins bld 64<rt> (fun a b -> AST.ite (a ?< b) a b)
  | Op.VCLZB ->
    vecUnary ins bld 8<rt> (countLeadingZerosOf 8<rt>)
  | Op.VCLZH ->
    vecUnary ins bld 16<rt> (countLeadingZerosOf 16<rt>)
  | Op.VCLZW ->
    vecUnary ins bld 32<rt> (countLeadingZerosOf 32<rt>)
  | Op.VCLZD ->
    vecUnary ins bld 64<rt> (countLeadingZerosOf 64<rt>)
  | Op.VPOPCNTB ->
    vecUnary ins bld 8<rt> (popCountOf 8<rt>)
  | Op.VPOPCNTH ->
    vecUnary ins bld 16<rt> (popCountOf 16<rt>)
  | Op.VPOPCNTW ->
    vecUnary ins bld 32<rt> (popCountOf 32<rt>)
  | Op.VPOPCNTD ->
    vecUnary ins bld 64<rt> (popCountOf 64<rt>)
  | Op.VCMPEQUB ->
    vecCompare ins bld 8<rt> (==) false
  | Op.VCMPEQUBdot ->
    vecCompare ins bld 8<rt> (==) true
  | Op.VCMPEQUH ->
    vecCompare ins bld 16<rt> (==) false
  | Op.VCMPEQUHdot ->
    vecCompare ins bld 16<rt> (==) true
  | Op.VCMPEQUW ->
    vecCompare ins bld 32<rt> (==) false
  | Op.VCMPEQUWdot ->
    vecCompare ins bld 32<rt> (==) true
  | Op.VCMPEQUD ->
    vecCompare ins bld 64<rt> (==) false
  | Op.VCMPEQUDdot ->
    vecCompare ins bld 64<rt> (==) true
  | Op.VCMPGTUB ->
    vecCompare ins bld 8<rt> (.>) false
  | Op.VCMPGTUBdot ->
    vecCompare ins bld 8<rt> (.>) true
  | Op.VCMPGTUH ->
    vecCompare ins bld 16<rt> (.>) false
  | Op.VCMPGTUHdot ->
    vecCompare ins bld 16<rt> (.>) true
  | Op.VCMPGTUW ->
    vecCompare ins bld 32<rt> (.>) false
  | Op.VCMPGTUWdot ->
    vecCompare ins bld 32<rt> (.>) true
  | Op.VCMPGTUD ->
    vecCompare ins bld 64<rt> (.>) false
  | Op.VCMPGTUDdot ->
    vecCompare ins bld 64<rt> (.>) true
  | Op.VCMPGTSB ->
    vecCompare ins bld 8<rt> (?>) false
  | Op.VCMPGTSBdot ->
    vecCompare ins bld 8<rt> (?>) true
  | Op.VCMPGTSH ->
    vecCompare ins bld 16<rt> (?>) false
  | Op.VCMPGTSHdot ->
    vecCompare ins bld 16<rt> (?>) true
  | Op.VCMPGTSW ->
    vecCompare ins bld 32<rt> (?>) false
  | Op.VCMPGTSWdot ->
    vecCompare ins bld 32<rt> (?>) true
  | Op.VCMPGTSD ->
    vecCompare ins bld 64<rt> (?>) false
  | Op.VCMPGTSDdot ->
    vecCompare ins bld 64<rt> (?>) true
  (* Lane F: binary floating point and Decimal Floating-Point. *)
  | Op.FCPSGNdot ->
    fcpsgnDot ins bld
  | Op.FMRGEW ->
    fmrg ins true bld
  | Op.FMRGOW ->
    fmrg ins false bld
  | Op.FRE ->
    fre ins false bld
  | Op.FREdot ->
    fre ins true bld
  | Op.FRSQRTES ->
    frsqrtes ins false bld
  | Op.FRSQRTESdot ->
    frsqrtes ins true bld
  | Op.FTDIV ->
    ftdiv ins bld
  | Op.FTSQRT ->
    ftsqrt ins bld
  | Op.LFDP ->
    lfdp ins bld
  | Op.LFDPX ->
    lfdpx ins bld
  | Op.STFDP ->
    stfdp ins bld
  | Op.STFDPX ->
    stfdpx ins bld
  | Op.MFFSCE ->
    mffsce ins bld
  | Op.MFFSCDRN ->
    mffscdrn ins bld
  | Op.MFFSCDRNI ->
    mffscdrni ins bld
  | Op.DADD ->
    arith ins false "DADD" 1UL false bld
  | Op.DADDdot ->
    arith ins false "DADD" 1UL true bld
  | Op.DADDQ ->
    arith ins true "DADD" 1UL false bld
  | Op.DADDQdot ->
    arith ins true "DADD" 1UL true bld
  | Op.DSUB ->
    arith ins false "DSUB" 3UL false bld
  | Op.DSUBdot ->
    arith ins false "DSUB" 3UL true bld
  | Op.DSUBQ ->
    arith ins true "DSUB" 3UL false bld
  | Op.DSUBQdot ->
    arith ins true "DSUB" 3UL true bld
  | Op.DMUL ->
    arith ins false "DMUL" 5UL false bld
  | Op.DMULdot ->
    arith ins false "DMUL" 5UL true bld
  | Op.DMULQ ->
    arith ins true "DMUL" 5UL false bld
  | Op.DMULQdot ->
    arith ins true "DMUL" 5UL true bld
  | Op.DDIV ->
    arith ins false "DDIV" 7UL false bld
  | Op.DDIVdot ->
    arith ins false "DDIV" 7UL true bld
  | Op.DDIVQ ->
    arith ins true "DDIV" 7UL false bld
  | Op.DDIVQdot ->
    arith ins true "DDIV" 7UL true bld
  | Op.DCMPU ->
    compare ins false 9UL bld
  | Op.DCMPUQ ->
    compare ins true 9UL bld
  | Op.DCMPO ->
    compare ins false 11UL bld
  | Op.DCMPOQ ->
    compare ins true 11UL bld
  | Op.DTSTEX ->
    compare ins false 17UL bld
  | Op.DTSTEXQ ->
    compare ins true 17UL bld
  | Op.DTSTDC ->
    tstData ins false 13UL bld
  | Op.DTSTDCQ ->
    tstData ins true 13UL bld
  | Op.DTSTDG ->
    tstData ins false 15UL bld
  | Op.DTSTDGQ ->
    tstData ins true 15UL bld
  | Op.DTSTSF ->
    tstsf ins false bld
  | Op.DTSTSFI ->
    tstsfi ins false bld
  | Op.DTSTSFQ ->
    tstsf ins true bld
  | Op.DTSTSFIQ ->
    tstsfi ins true bld
  | Op.DQUA ->
    quantize ins false "DQUA" 25UL true false bld
  | Op.DQUAdot ->
    quantize ins false "DQUA" 25UL true true bld
  | Op.DQUAQ ->
    quantize ins true "DQUA" 25UL true false bld
  | Op.DQUAQdot ->
    quantize ins true "DQUA" 25UL true true bld
  | Op.DRRND ->
    quantize ins false "DRRND" 27UL false false bld
  | Op.DRRNDdot ->
    quantize ins false "DRRND" 27UL false true bld
  | Op.DRRNDQ ->
    quantize ins true "DRRND" 27UL false false bld
  | Op.DRRNDQdot ->
    quantize ins true "DRRND" 27UL false true bld
  | Op.DQUAI ->
    quantizeImm ins false false bld
  | Op.DQUAIdot ->
    quantizeImm ins false true bld
  | Op.DQUAIQ ->
    quantizeImm ins true false bld
  | Op.DQUAIQdot ->
    quantizeImm ins true true bld
  | Op.DRINTX ->
    roundToInt ins false "DRINTX" 29UL false bld
  | Op.DRINTXdot ->
    roundToInt ins false "DRINTX" 29UL true bld
  | Op.DRINTXQ ->
    roundToInt ins true "DRINTX" 29UL false bld
  | Op.DRINTXQdot ->
    roundToInt ins true "DRINTX" 29UL true bld
  | Op.DRINTN ->
    roundToInt ins false "DRINTN" 31UL false bld
  | Op.DRINTNdot ->
    roundToInt ins false "DRINTN" 31UL true bld
  | Op.DRINTNQ ->
    roundToInt ins true "DRINTN" 31UL false bld
  | Op.DRINTNQdot ->
    roundToInt ins true "DRINTN" 31UL true bld
  | Op.DCTDP ->
    ctdp ins false bld
  | Op.DCTDPdot ->
    ctdp ins true bld
  | Op.DCTQPQ ->
    ctqpq ins false bld
  | Op.DCTQPQdot ->
    ctqpq ins true bld
  | Op.DRSP ->
    rsp ins false bld
  | Op.DRSPdot ->
    rsp ins true bld
  | Op.DRDPQ ->
    rdpq ins false bld
  | Op.DRDPQdot ->
    rdpq ins true bld
  | Op.DCFFIX ->
    cffix ins false bld
  | Op.DCFFIXdot ->
    cffix ins true bld
  | Op.DCFFIXQ ->
    cffixq ins false bld
  | Op.DCFFIXQdot ->
    cffixq ins true bld
  | Op.DCTFIX ->
    ctfix ins false bld
  | Op.DCTFIXdot ->
    ctfix ins true bld
  | Op.DCTFIXQ ->
    ctfixq ins false bld
  | Op.DCTFIXQdot ->
    ctfixq ins true bld
  | Op.DCFFIXQQ ->
    cffixqq ins bld
  | Op.DCTFIXQQ ->
    ctfixqq ins bld
  | Op.DENBCD ->
    enbcd ins false false bld
  | Op.DENBCDdot ->
    enbcd ins false true bld
  | Op.DENBCDQ ->
    enbcd ins true false bld
  | Op.DENBCDQdot ->
    enbcd ins true true bld
  | Op.DDEDPD ->
    dedpd ins false false bld
  | Op.DDEDPDdot ->
    dedpd ins false true bld
  | Op.DDEDPDQ ->
    dedpd ins true false bld
  | Op.DDEDPDQdot ->
    dedpd ins true true bld
  | Op.DXEX ->
    xex ins false false bld
  | Op.DXEXdot ->
    xex ins false true bld
  | Op.DXEXQ ->
    xex ins true false bld
  | Op.DXEXQdot ->
    xex ins true true bld
  | Op.DIEX ->
    iex ins false false bld
  | Op.DIEXdot ->
    iex ins false true bld
  | Op.DIEXQ ->
    iex ins true false bld
  | Op.DIEXQdot ->
    iex ins true true bld
  | Op.DSCLI ->
    shift ins false "DSCLI" false bld
  | Op.DSCLIdot ->
    shift ins false "DSCLI" true bld
  | Op.DSCLIQ ->
    shift ins true "DSCLI" false bld
  | Op.DSCLIQdot ->
    shift ins true "DSCLI" true bld
  | Op.DSCRI ->
    shift ins false "DSCRI" false bld
  | Op.DSCRIdot ->
    shift ins false "DSCRI" true bld
  | Op.DSCRIQ ->
    shift ins true "DSCRI" false bld
  | Op.DSCRIQdot ->
    shift ins true "DSCRI" true bld
  (* Lane V: the vector facility, primary opcode 4. *)
  | Op.VADDSBS ->
    vecSaturating ins bld 8<rt> true true
  | Op.VADDSHS ->
    vecSaturating ins bld 16<rt> true true
  | Op.VADDSWS ->
    vecSaturating ins bld 32<rt> true true
  | Op.VADDUHS ->
    vecSaturating ins bld 16<rt> false true
  | Op.VADDUWS ->
    vecSaturating ins bld 32<rt> false true
  | Op.VSUBSBS ->
    vecSaturating ins bld 8<rt> true false
  | Op.VSUBSHS ->
    vecSaturating ins bld 16<rt> true false
  | Op.VSUBSWS ->
    vecSaturating ins bld 32<rt> true false
  | Op.VSUBUHS ->
    vecSaturating ins bld 16<rt> false false
  | Op.VSUBUWS ->
    vecSaturating ins bld 32<rt> false false
  | Op.VADDCUW ->
    vaddcuw ins bld
  | Op.VSUBCUW ->
    vsubcuw ins bld
  | Op.VAVGSB ->
    vecAverage ins bld 8<rt> true
  | Op.VAVGSH ->
    vecAverage ins bld 16<rt> true
  | Op.VAVGSW ->
    vecAverage ins bld 32<rt> true
  | Op.VAVGUB ->
    vecAverage ins bld 8<rt> false
  | Op.VAVGUH ->
    vecAverage ins bld 16<rt> false
  | Op.VAVGUW ->
    vecAverage ins bld 32<rt> false
  | Op.VABSDUB ->
    vecAbsoluteDifference ins bld 8<rt>
  | Op.VABSDUH ->
    vecAbsoluteDifference ins bld 16<rt>
  | Op.VABSDUW ->
    vecAbsoluteDifference ins bld 32<rt>
  | Op.VADDUQM ->
    vecQuadAdd ins bld false false
  | Op.VADDCUQ ->
    vecQuadAdd ins bld false true
  | Op.VADDEUQM ->
    vecQuadAdd ins bld false false
  | Op.VADDECUQ ->
    vecQuadAdd ins bld false true
  | Op.VSUBUQM ->
    vecQuadAdd ins bld true false
  | Op.VSUBCUQ ->
    vecQuadAdd ins bld true true
  | Op.VSUBEUQM ->
    vecQuadAdd ins bld true false
  | Op.VSUBECUQ ->
    vecQuadAdd ins bld true true
  | Op.VCMPEQUQ ->
    vecCompareElements ins bld 128<rt> (==) false
  | Op.VCMPEQUQdot ->
    vecCompareElements ins bld 128<rt> (==) true
  | Op.VCMPGTUQ ->
    vecCompareElements ins bld 128<rt> (.>) false
  | Op.VCMPGTUQdot ->
    vecCompareElements ins bld 128<rt> (.>) true
  | Op.VCMPGTSQ ->
    vecCompareElements ins bld 128<rt> (?>) false
  | Op.VCMPGTSQdot ->
    vecCompareElements ins bld 128<rt> (?>) true
  | Op.VCMPNEB ->
    vecCompareElements ins bld 8<rt> (!=) false
  | Op.VCMPNEBdot ->
    vecCompareElements ins bld 8<rt> (!=) true
  | Op.VCMPNEH ->
    vecCompareElements ins bld 16<rt> (!=) false
  | Op.VCMPNEHdot ->
    vecCompareElements ins bld 16<rt> (!=) true
  | Op.VCMPNEW ->
    vecCompareElements ins bld 32<rt> (!=) false
  | Op.VCMPNEWdot ->
    vecCompareElements ins bld 32<rt> (!=) true
  | Op.VCMPNEZB ->
    vecCompareElements ins bld 8<rt> (notEqualOrZero 8<rt>) false
  | Op.VCMPNEZBdot ->
    vecCompareElements ins bld 8<rt> (notEqualOrZero 8<rt>) true
  | Op.VCMPNEZH ->
    vecCompareElements ins bld 16<rt> (notEqualOrZero 16<rt>) false
  | Op.VCMPNEZHdot ->
    vecCompareElements ins bld 16<rt> (notEqualOrZero 16<rt>) true
  | Op.VCMPNEZW ->
    vecCompareElements ins bld 32<rt> (notEqualOrZero 32<rt>) false
  | Op.VCMPNEZWdot ->
    vecCompareElements ins bld 32<rt> (notEqualOrZero 32<rt>) true
  | Op.VCMPSQ ->
    vecCompareQuadToCR ins bld true
  | Op.VCMPUQ ->
    vecCompareQuadToCR ins bld false
  | Op.VMULEUW ->
    vecMulEvenOdd ins bld 32<rt> false true
  | Op.VMULOUW ->
    vecMulEvenOdd ins bld 32<rt> false false
  | Op.VMULEUB ->
    vecMulEvenOdd ins bld 8<rt> false true
  | Op.VMULOUB ->
    vecMulEvenOdd ins bld 8<rt> false false
  | Op.VMULESB ->
    vecMulEvenOdd ins bld 8<rt> true true
  | Op.VMULOSB ->
    vecMulEvenOdd ins bld 8<rt> true false
  | Op.VMULEUH ->
    vecMulEvenOdd ins bld 16<rt> false true
  | Op.VMULOUH ->
    vecMulEvenOdd ins bld 16<rt> false false
  | Op.VMULESH ->
    vecMulEvenOdd ins bld 16<rt> true true
  | Op.VMULOSH ->
    vecMulEvenOdd ins bld 16<rt> true false
  | Op.VMULEUD ->
    vecMulEvenOdd ins bld 64<rt> false true
  | Op.VMULOUD ->
    vecMulEvenOdd ins bld 64<rt> false false
  | Op.VMULESD ->
    vecMulEvenOdd ins bld 64<rt> true true
  | Op.VMULOSD ->
    vecMulEvenOdd ins bld 64<rt> true false
  | Op.VPKUDUM ->
    vecPackElements ins bld 64<rt> false Modulo
  | Op.VPKSDSS ->
    vecPackElements ins bld 64<rt> true (Saturate true)
  | Op.VPKSDUS ->
    vecPackElements ins bld 64<rt> true (Saturate false)
  | Op.VPKUDUS ->
    vecPackElements ins bld 64<rt> false (Saturate false)
  | Op.VCIPHER ->
    aesRound ins bld "AESENC"
  | Op.VCIPHERLAST ->
    aesRound ins bld "AESENCLAST"
  | Op.VNCIPHER ->
    vncipher ins bld
  | Op.VNCIPHERLAST ->
    aesRound ins bld "AESDECLAST"
  | Op.VSBOX ->
    vsbox ins bld
  | Op.VSHASIGMAW ->
    vshasigma ins bld 32<rt>
  | Op.VSHASIGMAD ->
    vshasigma ins bld 64<rt>
  | Op.VPMSUMB ->
    vpmsum ins bld 8<rt>
  | Op.VPMSUMH ->
    vpmsum ins bld 16<rt>
  | Op.VPMSUMW ->
    vpmsum ins bld 32<rt>
  | Op.VPMSUMD ->
    vpmsum ins bld 64<rt>
  | Op.VPERMXOR ->
    vpermxor ins bld
  | Op.BCDADDdot ->
    bcdAddSub ins bld false
  | Op.BCDSUBdot ->
    bcdAddSub ins bld true
  | Op.VPKUHUS ->
    vecPackElements ins bld 16<rt> false (Saturate false)
  | Op.VPKUWUS ->
    vecPackElements ins bld 32<rt> false (Saturate false)
  | Op.VPKSHSS ->
    vecPackElements ins bld 16<rt> true (Saturate true)
  | Op.VPKSWSS ->
    vecPackElements ins bld 32<rt> true (Saturate true)
  | Op.VPKSHUS ->
    vecPackElements ins bld 16<rt> true (Saturate false)
  | Op.VPKSWUS ->
    vecPackElements ins bld 32<rt> true (Saturate false)
  | Op.VPKPX ->
    vpkpx ins bld
  | Op.VUPKHPX ->
    vecUnpackPixel ins bld true
  | Op.VUPKLPX ->
    vecUnpackPixel ins bld false
  | Op.VMHADDSHS ->
    vecMultiplyHighAdd ins bld false
  | Op.VMHRADDSHS ->
    vecMultiplyHighAdd ins bld true
  | Op.VMLADDUHM ->
    vecMultiplySum ins bld 16<rt> 16<rt> unsignedSums Modulo
  | Op.VMSUMUBM ->
    vecMultiplySum ins bld 8<rt> 32<rt> unsignedSums Modulo
  | Op.VMSUMMBM ->
    vecMultiplySum ins bld 8<rt> 32<rt> mixedSums Modulo
  | Op.VMSUMUHM ->
    vecMultiplySum ins bld 16<rt> 32<rt> unsignedSums Modulo
  | Op.VMSUMUHS ->
    vecMultiplySum ins bld 16<rt> 32<rt> unsignedSums (Saturate false)
  | Op.VMSUMSHM ->
    vecMultiplySum ins bld 16<rt> 32<rt> signedSums Modulo
  | Op.VMSUMSHS ->
    vecMultiplySum ins bld 16<rt> 32<rt> signedSums (Saturate true)
  | Op.VMSUMUDM ->
    vecMultiplySum ins bld 64<rt> 128<rt> unsignedSums Modulo
  | Op.VMSUMCUD ->
    vmsumcud ins bld
  | Op.VMULHSW ->
    vecMulHigh ins bld 32<rt> true
  | Op.VMULHUW ->
    vecMulHigh ins bld 32<rt> false
  | Op.VMULHSD ->
    vecMulHigh ins bld 64<rt> true
  | Op.VMULHUD ->
    vecMulHigh ins bld 64<rt> false
  | Op.VMULLD ->
    vmulld ins bld
  | Op.MADDHD ->
    multiplyAddDoubleword ins bld true true
  | Op.MADDHDU ->
    multiplyAddDoubleword ins bld false true
  | Op.MADDLD ->
    multiplyAddDoubleword ins bld true false
  | Op.VDIVSW ->
    vecDivide ins bld 32<rt> true Quotient
  | Op.VDIVUW ->
    vecDivide ins bld 32<rt> false Quotient
  | Op.VDIVSD ->
    vecDivide ins bld 64<rt> true Quotient
  | Op.VDIVUD ->
    vecDivide ins bld 64<rt> false Quotient
  | Op.VDIVSQ ->
    vecDivide ins bld 128<rt> true Quotient
  | Op.VDIVUQ ->
    vecDivide ins bld 128<rt> false Quotient
  | Op.VDIVESW ->
    vecDivide ins bld 32<rt> true ExtendedQuotient
  | Op.VDIVEUW ->
    vecDivide ins bld 32<rt> false ExtendedQuotient
  | Op.VDIVESD ->
    vecDivide ins bld 64<rt> true ExtendedQuotient
  | Op.VDIVEUD ->
    vecDivide ins bld 64<rt> false ExtendedQuotient
  | Op.VDIVESQ ->
    vecDivide ins bld 128<rt> true ExtendedQuotient
  | Op.VDIVEUQ ->
    vecDivide ins bld 128<rt> false ExtendedQuotient
  | Op.VMODSW ->
    vecDivide ins bld 32<rt> true Remainder
  | Op.VMODUW ->
    vecDivide ins bld 32<rt> false Remainder
  | Op.VMODSD ->
    vecDivide ins bld 64<rt> true Remainder
  | Op.VMODUD ->
    vecDivide ins bld 64<rt> false Remainder
  | Op.VMODSQ ->
    vecDivide ins bld 128<rt> true Remainder
  | Op.VMODUQ ->
    vecDivide ins bld 128<rt> false Remainder
  | Op.VSUM4UBS ->
    vecSumWithin ins bld 8<rt> false
  | Op.VSUM4SBS ->
    vecSumWithin ins bld 8<rt> true
  | Op.VSUM4SHS ->
    vecSumWithin ins bld 16<rt> true
  | Op.VSUM2SWS ->
    vecSumAcross ins bld 2
  | Op.VSUMSWS ->
    vecSumAcross ins bld 1
  | Op.VCTZB ->
    vecCountTrailingZeros ins bld 8<rt>
  | Op.VCTZH ->
    vecCountTrailingZeros ins bld 16<rt>
  | Op.VCTZW ->
    vecCountTrailingZeros ins bld 32<rt>
  | Op.VCTZD ->
    vecCountTrailingZeros ins bld 64<rt>
  | Op.VCLZLSBB ->
    vecCountLsbZeroBytes ins bld true
  | Op.VCTZLSBB ->
    vecCountLsbZeroBytes ins bld false
  | Op.VNEGW ->
    vecMap1 ins bld 32<rt> AST.neg
  | Op.VNEGD ->
    vecMap1 ins bld 64<rt> AST.neg
  | Op.VPRTYBW ->
    vecParity ins bld 32<rt>
  | Op.VPRTYBD ->
    vecParity ins bld 64<rt>
  | Op.VPRTYBQ ->
    vecParity ins bld 128<rt>
  | Op.VEXTSB2W ->
    vecSignExtend ins bld 32<rt> 8<rt>
  | Op.VEXTSH2W ->
    vecSignExtend ins bld 32<rt> 16<rt>
  | Op.VEXTSB2D ->
    vecSignExtend ins bld 64<rt> 8<rt>
  | Op.VEXTSH2D ->
    vecSignExtend ins bld 64<rt> 16<rt>
  | Op.VEXTSW2D ->
    vecSignExtend ins bld 64<rt> 32<rt>
  | Op.VEXTSD2Q ->
    vecSignExtend ins bld 128<rt> 64<rt>
  | Op.VRLWNM ->
    vecRotateMask ins bld 32<rt> false
  | Op.VRLDNM ->
    vecRotateMask ins bld 64<rt> false
  | Op.VRLQNM ->
    vecRotateMask ins bld 128<rt> false
  | Op.VRLWMI ->
    vecRotateMask ins bld 32<rt> true
  | Op.VRLDMI ->
    vecRotateMask ins bld 64<rt> true
  | Op.VRLQMI ->
    vecRotateMask ins bld 128<rt> true
  | Op.VSLQ ->
    vecShiftQuad ins bld ShiftLeft
  | Op.VSRQ ->
    vecShiftQuad ins bld ShiftRight
  | Op.VSRAQ ->
    vecShiftQuad ins bld ShiftRightAlgebraic
  | Op.VRLQ ->
    vecShiftQuad ins bld RotateLeft
  | Op.VSLV ->
    vecShiftVariable ins bld true
  | Op.VSRV ->
    vecShiftVariable ins bld false
  | Op.VSLDBI ->
    vecShiftDoubleBits ins bld true
  | Op.VSRDBI ->
    vecShiftDoubleBits ins bld false
  | Op.VEXTRACTUB ->
    vecExtractImm ins bld 1
  | Op.VEXTRACTUH ->
    vecExtractImm ins bld 2
  | Op.VEXTRACTUW ->
    vecExtractImm ins bld 4
  | Op.VEXTRACTD ->
    vecExtractImm ins bld 8
  | Op.VINSERTB ->
    vecInsertImm ins bld 1
  | Op.VINSERTH ->
    vecInsertImm ins bld 2
  | Op.VINSERTW ->
    vecInsertImm ins bld 4
  | Op.VINSERTD ->
    vecInsertImm ins bld 8
  | Op.VEXTUBLX ->
    vecExtractToGpr ins bld 1 true
  | Op.VEXTUHLX ->
    vecExtractToGpr ins bld 2 true
  | Op.VEXTUWLX ->
    vecExtractToGpr ins bld 4 true
  | Op.VEXTUBRX ->
    vecExtractToGpr ins bld 1 false
  | Op.VEXTUHRX ->
    vecExtractToGpr ins bld 2 false
  | Op.VEXTUWRX ->
    vecExtractToGpr ins bld 4 false
  | Op.VEXTDUBVLX ->
    vecExtractPair ins bld 1 true
  | Op.VEXTDUBVRX ->
    vecExtractPair ins bld 1 false
  | Op.VEXTDUHVLX ->
    vecExtractPair ins bld 2 true
  | Op.VEXTDUHVRX ->
    vecExtractPair ins bld 2 false
  | Op.VEXTDUWVLX ->
    vecExtractPair ins bld 4 true
  | Op.VEXTDUWVRX ->
    vecExtractPair ins bld 4 false
  | Op.VEXTDDVLX ->
    vecExtractPair ins bld 8 true
  | Op.VEXTDDVRX ->
    vecExtractPair ins bld 8 false
  | Op.VINSBLX ->
    vecInsertAt ins bld 1 true false
  | Op.VINSHLX ->
    vecInsertAt ins bld 2 true false
  | Op.VINSWLX ->
    vecInsertAt ins bld 4 true false
  | Op.VINSDLX ->
    vecInsertAt ins bld 8 true false
  | Op.VINSBRX ->
    vecInsertAt ins bld 1 false false
  | Op.VINSHRX ->
    vecInsertAt ins bld 2 false false
  | Op.VINSWRX ->
    vecInsertAt ins bld 4 false false
  | Op.VINSDRX ->
    vecInsertAt ins bld 8 false false
  | Op.VINSBVLX ->
    vecInsertAt ins bld 1 true true
  | Op.VINSHVLX ->
    vecInsertAt ins bld 2 true true
  | Op.VINSWVLX ->
    vecInsertAt ins bld 4 true true
  | Op.VINSBVRX ->
    vecInsertAt ins bld 1 false true
  | Op.VINSHVRX ->
    vecInsertAt ins bld 2 false true
  | Op.VINSWVRX ->
    vecInsertAt ins bld 4 false true
  | Op.VINSW ->
    vecInsertGprImm ins bld 4
  | Op.VINSD ->
    vecInsertGprImm ins bld 8
  | Op.VCLRLB ->
    vecClearBytes ins bld true
  | Op.VCLRRB ->
    vecClearBytes ins bld false
  | Op.VEXPANDBM ->
    vecExpandMask ins bld 8<rt>
  | Op.VEXTRACTBM ->
    vecExtractMask ins bld 8<rt>
  | Op.MTVSRBM ->
    vecMoveToMask ins bld 8<rt>
  | Op.VCNTMBB ->
    vecCountMaskBits ins bld 8<rt>
  | Op.VEXPANDHM ->
    vecExpandMask ins bld 16<rt>
  | Op.VEXTRACTHM ->
    vecExtractMask ins bld 16<rt>
  | Op.MTVSRHM ->
    vecMoveToMask ins bld 16<rt>
  | Op.VCNTMBH ->
    vecCountMaskBits ins bld 16<rt>
  | Op.VEXPANDWM ->
    vecExpandMask ins bld 32<rt>
  | Op.VEXTRACTWM ->
    vecExtractMask ins bld 32<rt>
  | Op.MTVSRWM ->
    vecMoveToMask ins bld 32<rt>
  | Op.VCNTMBW ->
    vecCountMaskBits ins bld 32<rt>
  | Op.VEXPANDDM ->
    vecExpandMask ins bld 64<rt>
  | Op.VEXTRACTDM ->
    vecExtractMask ins bld 64<rt>
  | Op.MTVSRDM ->
    vecMoveToMask ins bld 64<rt>
  | Op.VCNTMBD ->
    vecCountMaskBits ins bld 64<rt>
  | Op.VEXPANDQM ->
    vecExpandMask ins bld 128<rt>
  | Op.VEXTRACTQM ->
    vecExtractMask ins bld 128<rt>
  | Op.MTVSRQM ->
    vecMoveToMask ins bld 128<rt>
  | Op.MTVSRBMI ->
    mtvsrbmi ins bld
  | Op.VSTRIBL ->
    vecStringIsolate ins bld 8<rt> true false
  | Op.VSTRIBLdot ->
    vecStringIsolate ins bld 8<rt> true true
  | Op.VSTRIBR ->
    vecStringIsolate ins bld 8<rt> false false
  | Op.VSTRIBRdot ->
    vecStringIsolate ins bld 8<rt> false true
  | Op.VSTRIHL ->
    vecStringIsolate ins bld 16<rt> true false
  | Op.VSTRIHLdot ->
    vecStringIsolate ins bld 16<rt> true true
  | Op.VSTRIHR ->
    vecStringIsolate ins bld 16<rt> false false
  | Op.VSTRIHRdot ->
    vecStringIsolate ins bld 16<rt> false true
  | Op.VPERMR ->
    vpermr ins bld
  | Op.VGNB ->
    vgnb ins bld
  | Op.VBPERMD ->
    vbpermd ins bld
  | Op.VCFUGED ->
    vecMaskedBits ins bld Centrifuge
  | Op.VPDEPD ->
    vecMaskedBits ins bld Deposit
  | Op.VPEXTD ->
    vecMaskedBits ins bld Extract
  | Op.VCLZDM ->
    vecMaskedBits ins bld LeadingZeros
  | Op.VCTZDM ->
    vecMaskedBits ins bld TrailingZeros
  | Op.VADDFP ->
    vecFloatBinary ins bld AST.fadd
  | Op.VSUBFP ->
    vecFloatBinary ins bld AST.fsub
  | Op.VMADDFP ->
    vecFloatMultiplyAdd ins bld false
  | Op.VNMSUBFP ->
    vecFloatMultiplyAdd ins bld true
  | Op.VMAXFP ->
    vecFloatMaxMin ins bld true
  | Op.VMINFP ->
    vecFloatMaxMin ins bld false
  | Op.VREFP ->
    vecFloatReciprocal ins bld false
  | Op.VRSQRTEFP ->
    vecFloatReciprocal ins bld true
  | Op.VEXPTEFP ->
    vecFloatExpLog ins bld true
  | Op.VLOGEFP ->
    vecFloatExpLog ins bld false
  | Op.VRFIN ->
    vecFloatRound ins bld RoundingMode.ToNearestEven
  | Op.VRFIZ ->
    vecFloatRound ins bld RoundingMode.TowardZero
  | Op.VRFIP ->
    vecFloatRound ins bld RoundingMode.TowardPositive
  | Op.VRFIM ->
    vecFloatRound ins bld RoundingMode.TowardNegative
  | Op.VCFSX ->
    vecFloatFromInt ins bld true
  | Op.VCFUX ->
    vecFloatFromInt ins bld false
  | Op.VCTSXS ->
    vecFloatToInt ins bld true
  | Op.VCTUXS ->
    vecFloatToInt ins bld false
  | Op.VCMPEQFP ->
    vecFloatCompare ins bld AST.feq false
  | Op.VCMPEQFPdot ->
    vecFloatCompare ins bld AST.feq true
  | Op.VCMPGEFP ->
    vecFloatCompare ins bld AST.fge false
  | Op.VCMPGEFPdot ->
    vecFloatCompare ins bld AST.fge true
  | Op.VCMPGTFP ->
    vecFloatCompare ins bld AST.fgt false
  | Op.VCMPGTFPdot ->
    vecFloatCompare ins bld AST.fgt true
  | Op.VCMPBFP ->
    vcmpbfp ins bld false
  | Op.VCMPBFPdot ->
    vcmpbfp ins bld true
  | Op.BCDCPSGNdot ->
    bcdcpsgn ins bld
  | Op.BCDSETSGNdot ->
    bcdsetsgn ins bld
  | Op.BCDCFSQdot ->
    bcdcfsq ins bld
  | Op.BCDCTSQdot ->
    bcdctsq ins bld
  | Op.BCDSdot ->
    bcds ins bld
  | Op.BCDUSdot ->
    bcdus ins bld
  | Op.BCDSRdot ->
    bcdsr ins bld
  | Op.BCDTRUNCdot ->
    bcdtrunc ins bld
  | Op.BCDUTRUNCdot ->
    bcdutrunc ins bld
  | Op.BCDCFNdot ->
    bcdcfn ins bld
  | Op.BCDCTNdot ->
    bcdctn ins bld
  | Op.BCDCFZdot ->
    bcdcfz ins bld
  | Op.BCDCTZdot ->
    bcdctz ins bld
  | Op.VMUL10UQ ->
    vecMultiplyByTen ins bld false false
  | Op.VMUL10CUQ ->
    vecMultiplyByTen ins bld false true
  | Op.VMUL10EUQ ->
    vecMultiplyByTen ins bld true false
  | Op.VMUL10ECUQ ->
    vecMultiplyByTen ins bld true true
  (* End of lane V. *)
  (* Lane X: VSX, MMA and quad precision. *)
  | Op.LXSIBZX ->
    VSXLifter.loadScalarInt ins bld 8<rt> AST.zext
  | Op.LXSIHZX ->
    VSXLifter.loadScalarInt ins bld 16<rt> AST.zext
  | Op.LXSIWAX ->
    VSXLifter.loadScalarInt ins bld 32<rt> AST.sext
  | Op.LXSIWZX ->
    VSXLifter.loadScalarInt ins bld 32<rt> AST.zext
  | Op.LXSSP | Op.LXSSPX ->
    VSXLifter.loadScalarSingle ins bld
  | Op.LXV | Op.LXVX ->
    VSXLifter.quadword ins bld true
  | Op.LXVB16X ->
    lxvx ins bld 8<rt> true
  | Op.LXVH8X ->
    lxvx ins bld 16<rt> true
  | Op.LXVKQ ->
    VSXLifter.lxvkq ins bld
  | Op.LXVL ->
    VSXLifter.loadWithLength ins bld false
  | Op.LXVLL ->
    VSXLifter.loadWithLength ins bld true
  | Op.LXVP | Op.LXVPX ->
    VSXLifter.pair ins bld true
  | Op.LXVRBX ->
    VSXLifter.loadRightmost ins bld 8<rt>
  | Op.LXVRHX ->
    VSXLifter.loadRightmost ins bld 16<rt>
  | Op.LXVRWX ->
    VSXLifter.loadRightmost ins bld 32<rt>
  | Op.LXVRDX ->
    VSXLifter.loadRightmost ins bld 64<rt>
  | Op.LXVWSX ->
    VSXLifter.lxvwsx ins bld
  | Op.MTVSRWS ->
    VSXLifter.mtvsrws ins bld
  | Op.STXSIBX ->
    VSXLifter.storeScalarInt ins bld 8<rt>
  | Op.STXSIHX ->
    VSXLifter.storeScalarInt ins bld 16<rt>
  | Op.STXSIWX ->
    VSXLifter.storeScalarInt ins bld 32<rt>
  | Op.STXSSP | Op.STXSSPX ->
    VSXLifter.storeScalarSingle ins bld
  | Op.STXV | Op.STXVX ->
    VSXLifter.quadword ins bld false
  | Op.STXVB16X ->
    lxvx ins bld 8<rt> false
  | Op.STXVH8X ->
    lxvx ins bld 16<rt> false
  | Op.STXVL ->
    VSXLifter.storeWithLength ins bld false
  | Op.STXVLL ->
    VSXLifter.storeWithLength ins bld true
  | Op.STXVP | Op.STXVPX ->
    VSXLifter.pair ins bld false
  | Op.STXVRBX ->
    VSXLifter.storeRightmost ins bld 8<rt>
  | Op.STXVRHX ->
    VSXLifter.storeRightmost ins bld 16<rt>
  | Op.STXVRWX ->
    VSXLifter.storeRightmost ins bld 32<rt>
  | Op.STXVRDX ->
    VSXLifter.storeRightmost ins bld 64<rt>
  | Op.XSRESP ->
    VSXLifter.reciprocalEstimateSingle ins bld false
  | Op.XSRSQRTESP ->
    VSXLifter.reciprocalEstimateSingle ins bld true
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException(Disasm.opCodeToString o)

// vim: set tw=80 sts=2 sw=2:

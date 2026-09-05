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

/// Translate IR.
let translate (ins: Instruction) insLen bld =
  match ins.Opcode with
  | Op.ADD ->
    add ins insLen false false bld
  | Op.ADDdot ->
    add ins insLen true false bld
  | Op.ADDO ->
    add ins insLen false true bld
  | Op.ADDOdot ->
    add ins insLen true true bld
  | Op.ADDC ->
    addc ins insLen false false bld
  | Op.ADDCdot ->
    addc ins insLen true false bld
  | Op.ADDCO ->
    addc ins insLen false true bld
  | Op.ADDCOdot ->
    addc ins insLen true true bld
  | Op.ADDE ->
    adde ins insLen false false bld
  | Op.ADDEdot ->
    adde ins insLen true false bld
  | Op.ADDEO ->
    adde ins insLen false true bld
  | Op.ADDEOdot ->
    adde ins insLen true true bld
  | Op.ADDI ->
    addi ins insLen bld
  | Op.ADDIC ->
    addic ins insLen false bld
  | Op.ADDICdot ->
    addic ins insLen true bld
  | Op.ADDIS ->
    addis ins insLen bld
  | Op.ADDME ->
    addme ins insLen false false bld
  | Op.ADDMEdot ->
    addme ins insLen true false bld
  | Op.ADDMEO ->
    addme ins insLen false true bld
  | Op.ADDMEOdot ->
    addme ins insLen true true bld
  | Op.ADDZE ->
    addze ins insLen false false bld
  | Op.ADDZEdot ->
    addze ins insLen true false bld
  | Op.ADDZEO ->
    addze ins insLen false true bld
  | Op.ADDZEOdot ->
    addze ins insLen true true bld
  | Op.AND ->
    andx ins insLen false bld
  | Op.ANDdot ->
    andx ins insLen true bld
  | Op.ANDC ->
    andc ins insLen false bld
  | Op.ANDCdot ->
    andc ins insLen true bld
  | Op.ANDIdot ->
    andidot ins insLen bld
  | Op.ANDISdot ->
    andisdot ins insLen bld
  | Op.B ->
    b ins insLen bld false
  | Op.BA ->
    b ins insLen bld false
  | Op.BL ->
    b ins insLen bld true
  | Op.BLA ->
    b ins insLen bld true
  | Op.BC ->
    bc ins insLen bld false false
  | Op.BCA ->
    bc ins insLen bld true false
  | Op.BCL ->
    bc ins insLen bld false true
  | Op.BCLA ->
    bc ins insLen bld true true
  | Op.BCCTR ->
    bcctr ins insLen bld false
  | Op.BCCTRL ->
    bcctr ins insLen bld true
  | Op.BCLR ->
    bclr ins insLen bld false
  | Op.BCLRL ->
    bclr ins insLen bld true
  | Op.CMPI | Op.CMPL | Op.CMPLI ->
    raise InvalidOperandException (* invaild *)
  | Op.CMP ->
    cmp ins insLen bld true
  | Op.CMPW ->
    cmp ins insLen bld true
  | Op.CMPWI ->
    cmp ins insLen bld true
  | Op.CMPLW ->
    cmpl ins insLen bld true
  | Op.CMPLWI ->
    cmpl ins insLen bld true
  | Op.CMPD ->
    cmp ins insLen bld false
  | Op.CMPDI ->
    cmp ins insLen bld false
  | Op.CMPLD ->
    cmpl ins insLen bld false
  | Op.CMPLDI ->
    cmpl ins insLen bld false
  | Op.CMPB ->
    cmpb ins insLen bld
  | Op.CNTLZW ->
    cntlzw ins insLen false bld
  | Op.CNTLZWdot ->
    cntlzw ins insLen true bld
  | Op.CNTLZD ->
    cntlzd ins insLen false bld
  | Op.CNTLZDdot ->
    cntlzd ins insLen true bld
  | Op.CRCLR ->
    crclr ins insLen bld
  | Op.CREQV ->
    creqv ins insLen bld
  | Op.CRXOR ->
    crxor ins insLen bld
  | Op.CROR ->
    cror ins insLen bld
  | Op.CRORC ->
    crorc ins insLen bld
  | Op.CRSET ->
    crset ins insLen bld
  | Op.CRNOR ->
    crnor ins insLen bld
  | Op.CRNOT ->
    crnot ins insLen bld
  | Op.CRAND ->
    crand ins insLen bld
  | Op.CRANDC ->
    crandc ins insLen bld
  | Op.CRNAND ->
    crnand ins insLen bld
  | Op.CRMOVE ->
    crmove ins insLen bld
  (* The cache-management forms are hints about a cache BRemu does not model, so
     they leave no trace; dcbz below is the exception, as it clears storage. *)
  | Op.DCBT | Op.DCBTST | Op.DCBA | Op.DCBST | Op.DCBF | Op.DCBI | Op.ICBI ->
    nop ins insLen bld
  | Op.DCBZ ->
    dcbz ins insLen bld
  | Op.DIVW ->
    divw ins insLen false false bld
  | Op.DIVWdot ->
    divw ins insLen true false bld
  | Op.DIVWO ->
    divw ins insLen false true bld
  | Op.DIVWOdot ->
    divw ins insLen true true bld
  | Op.DIVWU ->
    divwu ins insLen false false bld
  | Op.DIVWUdot ->
    divwu ins insLen true false bld
  | Op.DIVWUO ->
    divwu ins insLen false true bld
  | Op.DIVWUOdot ->
    divwu ins insLen true true bld
  | Op.EXTSB ->
    extsb ins insLen false bld
  | Op.EXTSBdot ->
    extsb ins insLen true bld
  | Op.EXTSH ->
    extsh ins insLen false bld
  | Op.EXTSHdot ->
    extsh ins insLen true bld
  | Op.EIEIO ->
    nop ins insLen bld
  | Op.EQV ->
    eqvx ins insLen false bld
  | Op.EQVdot ->
    eqvx ins insLen true bld
  | Op.FABS ->
    fabs ins insLen false bld
  | Op.FABSdot ->
    fabs ins insLen true bld
  | Op.FADD ->
    fadd ins insLen false true bld
  | Op.FADDS ->
    fadd ins insLen false false bld
  | Op.FADDdot ->
    fadd ins insLen true true bld
  | Op.FADDSdot ->
    fadd ins insLen true false bld
  | Op.FCTIW ->
    fctiw ins insLen false bld
  | Op.FCTIWdot ->
    fctiw ins insLen true bld
  | Op.FCTIWZ ->
    fctiwz ins insLen false bld
  | Op.FCTIWZdot ->
    fctiwz ins insLen true bld
  | Op.FCMPO ->
    fcmpo ins insLen bld
  | Op.FCMPU ->
    fcmpu ins insLen bld
  | Op.FDIV ->
    fdiv ins insLen false true bld
  | Op.FDIVS ->
    fdiv ins insLen false false bld
  | Op.FDIVdot ->
    fdiv ins insLen true true bld
  | Op.FDIVSdot ->
    fdiv ins insLen true false bld
  | Op.FRSP ->
    frsp ins insLen false bld
  | Op.FRSPdot ->
    frsp ins insLen true bld
  | Op.FMADD ->
    fmadd ins insLen false true bld
  | Op.FMADDS ->
    fmadd ins insLen false false bld
  | Op.FMADDdot ->
    fmadd ins insLen true true bld
  | Op.FMADDSdot ->
    fmadd ins insLen true false bld
  | Op.FMR ->
    fmr ins insLen false bld
  | Op.FMRdot ->
    fmr ins insLen true bld
  | Op.FMSUB ->
    fmsub ins insLen false true bld
  | Op.FMSUBS ->
    fmsub ins insLen false false bld
  | Op.FMSUBdot ->
    fmsub ins insLen true true bld
  | Op.FMSUBSdot ->
    fmsub ins insLen true false bld
  | Op.FMUL ->
    fmul ins insLen false true bld
  | Op.FMULS ->
    fmul ins insLen false false bld
  | Op.FMULdot ->
    fmul ins insLen true true bld
  | Op.FMULSdot ->
    fmul ins insLen true false bld
  | Op.FNABS ->
    fnabs ins insLen false bld
  | Op.FNABSdot ->
    fnabs ins insLen true bld
  | Op.FNEG ->
    fneg ins insLen false bld
  | Op.FNEGdot ->
    fneg ins insLen true bld
  | Op.FNMADD ->
    fnmadd ins insLen false true bld
  | Op.FNMADDdot ->
    fnmadd ins insLen true true bld
  | Op.FNMADDS ->
    fnmadd ins insLen false false bld
  | Op.FNMADDSdot ->
    fnmadd ins insLen true false bld
  | Op.FNMSUB ->
    fnmsub ins insLen false true bld
  | Op.FNMSUBdot ->
    fnmsub ins insLen true true bld
  | Op.FNMSUBS ->
    fnmsub ins insLen false false bld
  | Op.FNMSUBSdot ->
    fnmsub ins insLen true false bld
  | Op.FSEL ->
    fsel ins insLen false bld
  | Op.FSELdot ->
    fsel ins insLen true bld
  | Op.FSUB ->
    fsub ins insLen false true bld
  | Op.FSUBS ->
    fsub ins insLen false false bld
  | Op.FSUBdot ->
    fsub ins insLen true true bld
  | Op.FSUBSdot ->
    fsub ins insLen true false bld
  | Op.FSQRT ->
    fsqrt ins insLen false true bld
  | Op.FSQRTS ->
    fsqrt ins insLen false false bld
  | Op.FSQRTdot ->
    fsqrt ins insLen true true bld
  | Op.FSQRTSdot ->
    fsqrt ins insLen true false bld
  | Op.ISYNC | Op.LWSYNC | Op.SYNC ->
    nop ins insLen bld
  | Op.LBZ ->
    lbz ins insLen bld
  | Op.LBZU ->
    lbzu ins insLen bld
  | Op.LBZUX ->
    lbzux ins insLen bld
  | Op.LBZX ->
    lbzx ins insLen bld
  | Op.LFD ->
    lfd ins insLen bld
  | Op.LFDU ->
    lfdu ins insLen bld
  | Op.LFDUX ->
    lfdux ins insLen bld
  | Op.LFDX ->
    lfdx ins insLen bld
  | Op.LFS ->
    lfs ins insLen bld
  | Op.LFSU ->
    lfsu ins insLen bld
  | Op.LFSUX ->
    lfsux ins insLen bld
  | Op.LFSX ->
    lfsx ins insLen bld
  | Op.LHA ->
    lha ins insLen bld
  | Op.LHAU ->
    lhau ins insLen bld
  | Op.LHAUX ->
    lhaux ins insLen bld
  | Op.LHAX ->
    lhax ins insLen bld
  | Op.LHBRX ->
    lhbrx ins insLen bld
  | Op.LHZ ->
    lhz ins insLen bld
  | Op.LHZU ->
    lhzu ins insLen bld
  | Op.LHZUX ->
    lhzux ins insLen bld
  | Op.LHZX ->
    lhzx ins insLen bld
  | Op.LI ->
    li ins insLen bld
  | Op.LIS ->
    lis ins insLen bld
  | Op.LWARX ->
    lwarx ins insLen bld
  | Op.LWBRX ->
    lwbrx ins insLen bld
  | Op.LWZ ->
    lwz ins insLen bld
  | Op.LWZU ->
    lwzu ins insLen bld
  | Op.LWZUX ->
    lwzux ins insLen bld
  | Op.LWZX ->
    lwzx ins insLen bld
  | Op.MCRF ->
    mcrf ins insLen bld
  | Op.MCRXR ->
    mcrxr ins insLen bld
  | Op.MFCR ->
    mfcr ins insLen bld
  | Op.MFSPR ->
    mfspr ins insLen bld
  | Op.MFTB ->
    mftb ins insLen bld
  | Op.MFTBU ->
    mftbu ins insLen bld
  | Op.MFCTR ->
    mfctr ins insLen bld
  | Op.MFFS ->
    mffs ins insLen bld
  | Op.MFLR ->
    mflr ins insLen bld
  | Op.MFXER ->
    mfxer ins insLen bld
  | Op.MR ->
    mr ins insLen bld
  | Op.MTCTR ->
    mtctr ins insLen bld
  | Op.MTCRF ->
    mtcrf ins insLen bld
  | Op.MTFSFI ->
    mtfsfi ins insLen false bld
  | Op.MTFSFIdot ->
    mtfsfi ins insLen true bld
  | Op.MTSPR ->
    mtspr ins insLen bld
  | Op.MTFSB0 ->
    mtfsb0 ins insLen false bld
  | Op.MTFSB0dot ->
    mtfsb0 ins insLen true bld
  | Op.MTFSB1 ->
    mtfsb1 ins insLen false bld
  | Op.MTFSB1dot ->
    mtfsb1 ins insLen true bld
  | Op.MTFSF ->
    mtfsf ins insLen bld
  | Op.MTLR ->
    mtlr ins insLen bld
  | Op.MTXER ->
    mtxer ins insLen bld
  | Op.MULHW ->
    mulhw ins insLen false bld
  | Op.MULHWU ->
    mulhwu ins insLen false bld
  | Op.MULHWUdot ->
    mulhwu ins insLen true bld
  | Op.MULLI ->
    mulli ins insLen bld
  | Op.MULLW ->
    mullw ins insLen false false bld
  | Op.MULLWdot ->
    mullw ins insLen true false bld
  | Op.MULLWO ->
    mullw ins insLen false true bld
  | Op.MULLWOdot ->
    mullw ins insLen true true bld
  | Op.NAND ->
    nand ins insLen false bld
  | Op.NANDdot ->
    nand ins insLen true bld
  | Op.NEG ->
    neg ins insLen false false bld
  | Op.NEGdot ->
    neg ins insLen true false bld
  | Op.NEGO ->
    neg ins insLen false true bld
  | Op.NEGOdot ->
    neg ins insLen true true bld
  | Op.NOR ->
    nor ins insLen false bld
  | Op.NORdot ->
    nor ins insLen true bld
  | Op.NOP ->
    nop ins insLen bld
  | Op.ORC ->
    orc ins insLen false bld
  | Op.ORCdot ->
    orc ins insLen true bld
  | Op.OR ->
    orx ins insLen false bld
  | Op.ORdot ->
    orx ins insLen true bld
  | Op.ORI ->
    ori ins insLen bld
  | Op.ORIS ->
    oris ins insLen bld
  | Op.RLWIMI ->
    rlwimi ins insLen false bld
  | Op.RLWIMIdot ->
    rlwimi ins insLen true bld
  | Op.RLWINM ->
    rlwinm ins insLen false bld
  | Op.RLWINMdot ->
    rlwinm ins insLen true bld
  | Op.RLWNM ->
    rlwnm ins insLen false bld
  | Op.RLWNMdot ->
    rlwnm ins insLen true bld
  | Op.ROTLW ->
    rotlw ins insLen bld
  | Op.SC ->
    sideEffects ins insLen bld SysCall
  | Op.SLW ->
    slw ins insLen false bld
  | Op.SLWdot ->
    slw ins insLen true bld
  | Op.SRAW ->
    sraw ins insLen false bld
  | Op.SRAWdot ->
    sraw ins insLen true bld
  | Op.SRAWI ->
    srawi ins insLen false bld
  | Op.SRAWIdot ->
    srawi ins insLen true bld
  | Op.SRW ->
    srw ins insLen false bld
  | Op.SRWdot ->
    srw ins insLen true bld
  | Op.STB ->
    stb ins insLen bld
  | Op.STBU ->
    stbu ins insLen bld
  | Op.STBX ->
    stbx ins insLen bld
  | Op.STBUX ->
    stbux ins insLen bld
  | Op.STFD ->
    stfd ins insLen bld
  | Op.STFDX ->
    stfdx ins insLen bld
  | Op.STFDU ->
    stfdu ins insLen bld
  | Op.STFDUX ->
    stfdux ins insLen bld
  | Op.STFIWX ->
    stfiwx ins insLen bld
  | Op.STFS ->
    stfs ins insLen bld
  | Op.STFSX ->
    stfsx ins insLen bld
  | Op.STFSU ->
    stfsu ins insLen bld
  | Op.STFSUX ->
    stfsux ins insLen bld
  | Op.STH ->
    sth ins insLen bld
  | Op.STHBRX ->
    sthbrx ins insLen bld
  | Op.STHU ->
    sthu ins insLen bld
  | Op.STHX ->
    sthx ins insLen bld
  | Op.STHUX ->
    sthux ins insLen bld
  | Op.STW ->
    stw ins insLen bld
  | Op.LMW ->
    lmw ins insLen bld
  | Op.STMW ->
    stmw ins insLen bld
  | Op.STWBRX ->
    stwbrx ins insLen bld
  | Op.STWCXdot ->
    stwcxdot ins insLen bld
  | Op.STWU ->
    stwu ins insLen bld
  | Op.STWUX ->
    stwux ins insLen bld
  | Op.STWX ->
    stwx ins insLen bld
  | Op.SUBF ->
    subf ins insLen false false bld
  | Op.SUBFdot ->
    subf ins insLen true false bld
  | Op.SUBFO ->
    subf ins insLen false true bld
  | Op.SUBFOdot ->
    subf ins insLen true true bld
  | Op.SUBFC ->
    subfc ins insLen false false bld
  | Op.SUBFCdot ->
    subfc ins insLen true false bld
  | Op.SUBFCO ->
    subfc ins insLen false true bld
  | Op.SUBFCOdot ->
    subfc ins insLen true true bld
  | Op.SUBFE ->
    subfe ins insLen false false bld
  | Op.SUBFEdot ->
    subfe ins insLen true false bld
  | Op.SUBFEO ->
    subfe ins insLen false true bld
  | Op.SUBFEOdot ->
    subfe ins insLen true true bld
  | Op.SUBFIC ->
    subfic ins insLen bld
  | Op.SUBFME ->
    subfme ins insLen false false bld
  | Op.SUBFMEdot ->
    subfme ins insLen true false bld
  | Op.SUBFMEO ->
    subfme ins insLen false true bld
  | Op.SUBFMEOdot ->
    subfme ins insLen true true bld
  | Op.SUBFZE ->
    subfze ins insLen false false bld
  | Op.SUBFZEdot ->
    subfze ins insLen true false bld
  | Op.SUBFZEO ->
    subfze ins insLen false true bld
  | Op.SUBFZEOdot ->
    subfze ins insLen true true bld
  | Op.TRAP | Op.TWI ->
    trap ins insLen bld
  | Op.TWLT ->
    trapCond ins insLen (AST.slt) bld
  | Op.TWLE ->
    trapCond ins insLen (AST.sle) bld
  | Op.TWEQ ->
    trapCond ins insLen (AST.eq) bld
  | Op.TWGE ->
    trapCond ins insLen (AST.sge) bld
  | Op.TWGT ->
    trapCond ins insLen (AST.sgt) bld
  | Op.TWNE ->
    trapCond ins insLen (AST.neq) bld
  | Op.TWLLT ->
    trapCond ins insLen (AST.lt) bld
  | Op.TWLLE ->
    trapCond ins insLen (AST.le) bld
  | Op.TWLNL ->
    trapCond ins insLen (AST.ge) bld
  | Op.TWLGT ->
    trapCond ins insLen (AST.gt) bld
  | Op.TWLTI ->
    trapCond ins insLen (AST.slt) bld
  | Op.TWLEI ->
    trapCond ins insLen (AST.sle) bld
  | Op.TWEQI ->
    trapCond ins insLen (AST.eq) bld
  | Op.TWGEI ->
    trapCond ins insLen (AST.sge) bld
  | Op.TWGTI ->
    trapCond ins insLen (AST.sgt) bld
  | Op.TWNEI ->
    trapCond ins insLen (AST.neq) bld
  | Op.TWLLTI ->
    trapCond ins insLen (AST.lt) bld
  | Op.TWLLEI ->
    trapCond ins insLen (AST.le) bld
  | Op.TWLNLI ->
    trapCond ins insLen (AST.ge) bld
  | Op.TWLGTI ->
    trapCond ins insLen (AST.gt) bld
  | Op.XOR ->
    xor ins insLen false bld
  | Op.XORdot ->
    xor ins insLen true bld
  | Op.XORI ->
    xori ins insLen bld
  | Op.XORIS ->
    xoris ins insLen bld
  (* 64-bit forms. *)
  | Op.LD ->
    ld ins insLen bld
  | Op.LDU ->
    ldu ins insLen bld
  | Op.LDX ->
    ldx ins insLen bld
  | Op.LDUX ->
    ldux ins insLen bld
  | Op.LDARX ->
    ldarx ins insLen bld
  | Op.LBARX ->
    lbarx ins insLen bld
  | Op.LHARX ->
    lharx ins insLen bld
  | Op.LDBRX ->
    ldbrx ins insLen bld
  | Op.LWA ->
    lwa ins insLen bld
  | Op.LWAX ->
    lwax ins insLen bld
  | Op.LWAUX ->
    lwaux ins insLen bld
  | Op.STD ->
    std ins insLen bld
  | Op.STDU ->
    stdu ins insLen bld
  | Op.STDX ->
    stdx ins insLen bld
  | Op.STDUX ->
    stdux ins insLen bld
  | Op.STDBRX ->
    stdbrx ins insLen bld
  | Op.STDCXdot ->
    stdcxdot ins insLen bld
  | Op.STBCXdot ->
    stbcxdot ins insLen bld
  | Op.STHCXdot ->
    sthcxdot ins insLen bld
  | Op.RLDICL ->
    rldicl ins insLen false bld
  | Op.RLDICLdot ->
    rldicl ins insLen true bld
  | Op.RLDICR ->
    rldicr ins insLen false bld
  | Op.RLDICRdot ->
    rldicr ins insLen true bld
  | Op.RLDIC ->
    rldic ins insLen false bld
  | Op.RLDICdot ->
    rldic ins insLen true bld
  | Op.RLDIMI ->
    rldimi ins insLen false bld
  | Op.RLDIMIdot ->
    rldimi ins insLen true bld
  | Op.RLDCL ->
    rldcl ins insLen false bld
  | Op.RLDCLdot ->
    rldcl ins insLen true bld
  | Op.RLDCR ->
    rldcr ins insLen false bld
  | Op.RLDCRdot ->
    rldcr ins insLen true bld
  | Op.SLD ->
    sld ins insLen false bld
  | Op.SLDdot ->
    sld ins insLen true bld
  | Op.SRD ->
    srd ins insLen false bld
  | Op.SRDdot ->
    srd ins insLen true bld
  | Op.SRAD ->
    srad ins insLen false bld
  | Op.SRADdot ->
    srad ins insLen true bld
  | Op.SRADI ->
    sradi ins insLen false bld
  | Op.SRADIdot ->
    sradi ins insLen true bld
  | Op.EXTSW ->
    extsw ins insLen false bld
  | Op.EXTSWdot ->
    extsw ins insLen true bld
  | Op.MULLD ->
    mulld ins insLen false false bld
  | Op.MULLDdot ->
    mulld ins insLen true false bld
  | Op.MULLDO ->
    mulld ins insLen false true bld
  | Op.MULLDOdot ->
    mulld ins insLen true true bld
  | Op.MULHD ->
    mulhd ins insLen false bld
  | Op.MULHDdot ->
    mulhd ins insLen true bld
  | Op.MULHDU ->
    mulhdu ins insLen false bld
  | Op.MULHDUdot ->
    mulhdu ins insLen true bld
  | Op.DIVD ->
    divd ins insLen false false bld
  | Op.DIVDdot ->
    divd ins insLen true false bld
  | Op.DIVDO ->
    divd ins insLen false true bld
  | Op.DIVDOdot ->
    divd ins insLen true true bld
  | Op.DIVDU ->
    divdu ins insLen false false bld
  | Op.DIVDUdot ->
    divdu ins insLen true false bld
  | Op.DIVDUO ->
    divdu ins insLen false true bld
  | Op.DIVDUOdot ->
    divdu ins insLen true true bld
  | Op.POPCNTB ->
    popcnt ins insLen bld 8
  | Op.POPCNTW ->
    popcnt ins insLen bld 32
  | Op.POPCNTD ->
    popcnt ins insLen bld 64
  | Op.PRTYW ->
    prty ins insLen bld 32
  | Op.PRTYD ->
    prty ins insLen bld 64
  | Op.BPERMD ->
    bpermd ins insLen bld
  | Op.ISEL ->
    isel ins insLen bld
  | Op.MTOCRF ->
    mtcrf ins insLen bld
  | Op.MFOCRF ->
    mfcr ins insLen bld
  | Op.MFVSRD ->
    mfvsr ins insLen bld 64<rt>
  | Op.MFVSRWZ ->
    mfvsr ins insLen bld 32<rt>
  | Op.MTVSRD ->
    mtvsrd ins insLen bld
  | Op.MTVSRWA ->
    mtvsrw ins insLen bld true
  | Op.MTVSRWZ ->
    mtvsrw ins insLen bld false
  | Op.TD ->
    trapGeneric ins insLen bld false
  | Op.TDI ->
    trapGeneric ins insLen bld false
  | Op.TW ->
    trapGeneric ins insLen bld true
  | Op.FCTID ->
    fcti ins insLen false bld 64<rt> false
  | Op.FCTIDdot ->
    fcti ins insLen true bld 64<rt> false
  | Op.FCTIDZ ->
    fcti ins insLen false bld 64<rt> true
  | Op.FCTIDZdot ->
    fcti ins insLen true bld 64<rt> true
  | Op.FCTIDU ->
    fcti ins insLen false bld 64<rt> false
  | Op.FCTIDUdot ->
    fcti ins insLen true bld 64<rt> false
  | Op.FCTIDUZ ->
    fcti ins insLen false bld 64<rt> true
  | Op.FCTIDUZdot ->
    fcti ins insLen true bld 64<rt> true
  | Op.FCTIWU ->
    fcti ins insLen false bld 32<rt> false
  | Op.FCTIWUdot ->
    fcti ins insLen true bld 32<rt> false
  | Op.FCTIWUZ ->
    fcti ins insLen false bld 32<rt> true
  | Op.FCTIWUZdot ->
    fcti ins insLen true bld 32<rt> true
  | Op.FCFID ->
    fcfid ins insLen false bld true false
  | Op.FCFIDdot ->
    fcfid ins insLen true bld true false
  | Op.FCFIDU ->
    fcfid ins insLen false bld false false
  | Op.FCFIDUdot ->
    fcfid ins insLen true bld false false
  | Op.FCFIDS ->
    fcfid ins insLen false bld true true
  | Op.FCFIDSdot ->
    fcfid ins insLen true bld true true
  | Op.FCFIDUS ->
    fcfid ins insLen false bld false true
  | Op.FCFIDUSdot ->
    fcfid ins insLen true bld false true
  | Op.FRIN ->
    frnd ins insLen false bld CastKind.FtoFRound
  | Op.FRINdot ->
    frnd ins insLen true bld CastKind.FtoFRound
  | Op.FRIZ ->
    frnd ins insLen false bld CastKind.FtoFTrunc
  | Op.FRIZdot ->
    frnd ins insLen true bld CastKind.FtoFTrunc
  | Op.FRIP ->
    frnd ins insLen false bld CastKind.FtoFCeil
  | Op.FRIPdot ->
    frnd ins insLen true bld CastKind.FtoFCeil
  | Op.FRIM ->
    frnd ins insLen false bld CastKind.FtoFFloor
  | Op.FRIMdot ->
    frnd ins insLen true bld CastKind.FtoFFloor
  (* Vector forms. *)
  | Op.LVX | Op.LVXL ->
    lvx ins insLen bld
  | Op.STVX | Op.STVXL ->
    stvx ins insLen bld
  | Op.LVSL ->
    lvsx ins insLen bld true
  | Op.LVSR ->
    lvsx ins insLen bld false
  | Op.LVEBX ->
    lvex ins insLen bld 8<rt>
  | Op.LVEHX ->
    lvex ins insLen bld 16<rt>
  | Op.LVEWX ->
    lvex ins insLen bld 32<rt>
  | Op.STVEBX ->
    stvex ins insLen bld 8<rt>
  | Op.STVEHX ->
    stvex ins insLen bld 16<rt>
  | Op.STVEWX ->
    stvex ins insLen bld 32<rt>
  | Op.LXVD2X ->
    lxvx ins insLen bld 64<rt> true
  | Op.STXVD2X ->
    lxvx ins insLen bld 64<rt> false
  | Op.LXVW4X ->
    lxvx ins insLen bld 32<rt> true
  | Op.STXVW4X ->
    lxvx ins insLen bld 32<rt> false
  | Op.LXSDX ->
    lxsdx ins insLen bld false true
  | Op.LXVDSX ->
    lxsdx ins insLen bld true true
  | Op.STXSDX ->
    lxsdx ins insLen bld false false
  | Op.VAND | Op.XXLAND ->
    vecLogical ins insLen bld (.&)
  | Op.VOR | Op.XXLOR ->
    vecLogical ins insLen bld (.|)
  | Op.VXOR | Op.XXLXOR ->
    vecLogical ins insLen bld (<+>)
  | Op.VANDC | Op.XXLANDC ->
    vecLogical ins insLen bld (fun a b -> a .& AST.not b)
  | Op.VORC | Op.XXLORC ->
    vecLogical ins insLen bld (fun a b -> a .| AST.not b)
  | Op.VNOR | Op.XXLNOR ->
    vecLogical ins insLen bld (fun a b -> AST.not (a .| b))
  | Op.VNAND | Op.XXLNAND ->
    vecLogical ins insLen bld (fun a b -> AST.not (a .& b))
  | Op.VEQV | Op.XXLEQV ->
    vecLogical ins insLen bld (fun a b -> AST.not (a <+> b))
  | Op.VSEL ->
    vecSelect ins insLen bld
  | Op.VPERM ->
    vecPermute ins insLen bld
  | Op.XXPERMDI ->
    vecPermuteDouble ins insLen bld
  | Op.XXSPLTW ->
    xxspltw ins insLen bld
  | Op.XXSPLTIB ->
    xxspltib ins insLen bld
  | Op.MTVSRDD ->
    mtvsrdd ins insLen bld
  | Op.MFVSRLD ->
    mfvsrld ins insLen bld
  | Op.FCPSGN ->
    fcpsgn ins insLen bld
  | Op.MFFSL ->
    mffs ins insLen bld
  | Op.XSADDDP ->
    vsxScalarBinary ins insLen bld AST.fadd
  | Op.XSSUBDP ->
    vsxScalarBinary ins insLen bld AST.fsub
  | Op.XSDIVDP ->
    vsxScalarBinary ins insLen bld AST.fdiv
  | Op.XSCPSGNDP ->
    vsxScalarBinary ins insLen bld copySign
  | Op.XSCMPUDP ->
    xscmpudp ins insLen bld
  | Op.XSABSDP ->
    vsxScalarUnary ins insLen bld (fun b ->
      b .& numU64 0x7fffffffffffffffUL 64<rt>)
  | Op.XSRSP ->
    (* Rounding a double to single precision and keeping it in double format. *)
    vsxScalarUnary ins insLen bld (fun b ->
      AST.cast CastKind.FloatCast 64<rt> (AST.cast CastKind.FloatCast 32<rt> b))
  | Op.XSCVDPSPN ->
    vsxScalarUnary ins insLen bld (fun b ->
      AST.concat (AST.cast CastKind.FloatCast 32<rt> b) (AST.num0 32<rt>))
  | Op.XSCVSPDPN ->
    vsxScalarUnary ins insLen bld (fun b ->
      AST.cast CastKind.FloatCast 64<rt> (AST.xthi 32<rt> b))
  | Op.VSLDOI ->
    vecShiftDouble ins insLen bld 1
  | Op.XXSLDWI ->
    vecShiftDouble ins insLen bld 4
  | Op.VSPLTB ->
    vecSplat ins insLen bld 8<rt>
  | Op.VSPLTH ->
    vecSplat ins insLen bld 16<rt>
  | Op.VSPLTW ->
    vecSplat ins insLen bld 32<rt>
  | Op.VSPLTISB ->
    vecSplatImm ins insLen bld 8<rt>
  | Op.VSPLTISH ->
    vecSplatImm ins insLen bld 16<rt>
  | Op.VSPLTISW ->
    vecSplatImm ins insLen bld 32<rt>
  | Op.VMRGHB ->
    vecMerge ins insLen bld 8<rt> true
  | Op.VMRGHH ->
    vecMerge ins insLen bld 16<rt> true
  | Op.VMRGHW ->
    vecMerge ins insLen bld 32<rt> true
  | Op.VMRGLB ->
    vecMerge ins insLen bld 8<rt> false
  | Op.VMRGLH ->
    vecMerge ins insLen bld 16<rt> false
  | Op.VMRGLW ->
    vecMerge ins insLen bld 32<rt> false
  | Op.VPKUHUM ->
    vecPack ins insLen bld 16<rt>
  | Op.VPKUWUM ->
    vecPack ins insLen bld 32<rt>
  | Op.VUPKHSB ->
    vecUnpack ins insLen bld 8<rt> true
  | Op.VUPKHSH ->
    vecUnpack ins insLen bld 16<rt> true
  | Op.VUPKLSB ->
    vecUnpack ins insLen bld 8<rt> false
  | Op.VUPKLSH ->
    vecUnpack ins insLen bld 16<rt> false
  | Op.VSL ->
    vecShiftWhole ins insLen bld true false
  | Op.VSR ->
    vecShiftWhole ins insLen bld false false
  | Op.VSLO ->
    vecShiftWhole ins insLen bld true true
  | Op.VSRO ->
    vecShiftWhole ins insLen bld false true
  | Op.VGBBD ->
    vecGatherBits ins insLen bld
  | Op.VBPERMQ ->
    vecBitPermute ins insLen bld
  | Op.MFVSCR ->
    vscrMove ins insLen bld true
  | Op.MTVSCR ->
    vscrMove ins insLen bld false
  | Op.VADDUBM ->
    vecBinary ins insLen bld 8<rt> (.+)
  | Op.VADDUHM ->
    vecBinary ins insLen bld 16<rt> (.+)
  | Op.VADDUWM ->
    vecBinary ins insLen bld 32<rt> (.+)
  | Op.VADDUDM ->
    vecBinary ins insLen bld 64<rt> (.+)
  | Op.VSUBUBM ->
    vecBinary ins insLen bld 8<rt> (.-)
  | Op.VSUBUHM ->
    vecBinary ins insLen bld 16<rt> (.-)
  | Op.VSUBUWM ->
    vecBinary ins insLen bld 32<rt> (.-)
  | Op.VSUBUDM ->
    vecBinary ins insLen bld 64<rt> (.-)
  | Op.VSLB ->
    vecBinary ins insLen bld 8<rt> (elementShift 8<rt> 0)
  | Op.VSLH ->
    vecBinary ins insLen bld 16<rt> (elementShift 16<rt> 0)
  | Op.VSLW ->
    vecBinary ins insLen bld 32<rt> (elementShift 32<rt> 0)
  | Op.VSLD ->
    vecBinary ins insLen bld 64<rt> (elementShift 64<rt> 0)
  | Op.VSRB ->
    vecBinary ins insLen bld 8<rt> (elementShift 8<rt> 1)
  | Op.VSRH ->
    vecBinary ins insLen bld 16<rt> (elementShift 16<rt> 1)
  | Op.VSRW ->
    vecBinary ins insLen bld 32<rt> (elementShift 32<rt> 1)
  | Op.VSRD ->
    vecBinary ins insLen bld 64<rt> (elementShift 64<rt> 1)
  | Op.VSRAB ->
    vecBinary ins insLen bld 8<rt> (elementShift 8<rt> 2)
  | Op.VSRAH ->
    vecBinary ins insLen bld 16<rt> (elementShift 16<rt> 2)
  | Op.VSRAW ->
    vecBinary ins insLen bld 32<rt> (elementShift 32<rt> 2)
  | Op.VSRAD ->
    vecBinary ins insLen bld 64<rt> (elementShift 64<rt> 2)
  | Op.VRLB ->
    vecBinary ins insLen bld 8<rt> (elementShift 8<rt> 3)
  | Op.VRLH ->
    vecBinary ins insLen bld 16<rt> (elementShift 16<rt> 3)
  | Op.VRLW ->
    vecBinary ins insLen bld 32<rt> (elementShift 32<rt> 3)
  | Op.VRLD ->
    vecBinary ins insLen bld 64<rt> (elementShift 64<rt> 3)
  | Op.VMAXUB ->
    vecBinary ins insLen bld 8<rt> (fun a b -> AST.ite (a .> b) a b)
  | Op.VMAXUH ->
    vecBinary ins insLen bld 16<rt> (fun a b -> AST.ite (a .> b) a b)
  | Op.VMAXUW ->
    vecBinary ins insLen bld 32<rt> (fun a b -> AST.ite (a .> b) a b)
  | Op.VMAXUD ->
    vecBinary ins insLen bld 64<rt> (fun a b -> AST.ite (a .> b) a b)
  | Op.VMINUB ->
    vecBinary ins insLen bld 8<rt> (fun a b -> AST.ite (a .< b) a b)
  | Op.VMINUH ->
    vecBinary ins insLen bld 16<rt> (fun a b -> AST.ite (a .< b) a b)
  | Op.VMINUW ->
    vecBinary ins insLen bld 32<rt> (fun a b -> AST.ite (a .< b) a b)
  | Op.VMINUD ->
    vecBinary ins insLen bld 64<rt> (fun a b -> AST.ite (a .< b) a b)
  | Op.VMAXSB ->
    vecBinary ins insLen bld 8<rt> (fun a b -> AST.ite (a ?> b) a b)
  | Op.VMAXSH ->
    vecBinary ins insLen bld 16<rt> (fun a b -> AST.ite (a ?> b) a b)
  | Op.VMAXSW ->
    vecBinary ins insLen bld 32<rt> (fun a b -> AST.ite (a ?> b) a b)
  | Op.VMAXSD ->
    vecBinary ins insLen bld 64<rt> (fun a b -> AST.ite (a ?> b) a b)
  | Op.VMINSB ->
    vecBinary ins insLen bld 8<rt> (fun a b -> AST.ite (a ?< b) a b)
  | Op.VMINSH ->
    vecBinary ins insLen bld 16<rt> (fun a b -> AST.ite (a ?< b) a b)
  | Op.VMINSW ->
    vecBinary ins insLen bld 32<rt> (fun a b -> AST.ite (a ?< b) a b)
  | Op.VMINSD ->
    vecBinary ins insLen bld 64<rt> (fun a b -> AST.ite (a ?< b) a b)
  | Op.VCLZB ->
    vecUnary ins insLen bld 8<rt> (countLeadingZerosOf 8<rt>)
  | Op.VCLZH ->
    vecUnary ins insLen bld 16<rt> (countLeadingZerosOf 16<rt>)
  | Op.VCLZW ->
    vecUnary ins insLen bld 32<rt> (countLeadingZerosOf 32<rt>)
  | Op.VCLZD ->
    vecUnary ins insLen bld 64<rt> (countLeadingZerosOf 64<rt>)
  | Op.VPOPCNTB ->
    vecUnary ins insLen bld 8<rt> (popCountOf 8<rt>)
  | Op.VPOPCNTH ->
    vecUnary ins insLen bld 16<rt> (popCountOf 16<rt>)
  | Op.VPOPCNTW ->
    vecUnary ins insLen bld 32<rt> (popCountOf 32<rt>)
  | Op.VPOPCNTD ->
    vecUnary ins insLen bld 64<rt> (popCountOf 64<rt>)
  | Op.VCMPEQUB ->
    vecCompare ins insLen bld 8<rt> (==) false
  | Op.VCMPEQUBdot ->
    vecCompare ins insLen bld 8<rt> (==) true
  | Op.VCMPEQUH ->
    vecCompare ins insLen bld 16<rt> (==) false
  | Op.VCMPEQUHdot ->
    vecCompare ins insLen bld 16<rt> (==) true
  | Op.VCMPEQUW ->
    vecCompare ins insLen bld 32<rt> (==) false
  | Op.VCMPEQUWdot ->
    vecCompare ins insLen bld 32<rt> (==) true
  | Op.VCMPEQUD ->
    vecCompare ins insLen bld 64<rt> (==) false
  | Op.VCMPEQUDdot ->
    vecCompare ins insLen bld 64<rt> (==) true
  | Op.VCMPGTUB ->
    vecCompare ins insLen bld 8<rt> (.>) false
  | Op.VCMPGTUBdot ->
    vecCompare ins insLen bld 8<rt> (.>) true
  | Op.VCMPGTUH ->
    vecCompare ins insLen bld 16<rt> (.>) false
  | Op.VCMPGTUHdot ->
    vecCompare ins insLen bld 16<rt> (.>) true
  | Op.VCMPGTUW ->
    vecCompare ins insLen bld 32<rt> (.>) false
  | Op.VCMPGTUWdot ->
    vecCompare ins insLen bld 32<rt> (.>) true
  | Op.VCMPGTUD ->
    vecCompare ins insLen bld 64<rt> (.>) false
  | Op.VCMPGTUDdot ->
    vecCompare ins insLen bld 64<rt> (.>) true
  | Op.VCMPGTSB ->
    vecCompare ins insLen bld 8<rt> (?>) false
  | Op.VCMPGTSBdot ->
    vecCompare ins insLen bld 8<rt> (?>) true
  | Op.VCMPGTSH ->
    vecCompare ins insLen bld 16<rt> (?>) false
  | Op.VCMPGTSHdot ->
    vecCompare ins insLen bld 16<rt> (?>) true
  | Op.VCMPGTSW ->
    vecCompare ins insLen bld 32<rt> (?>) false
  | Op.VCMPGTSWdot ->
    vecCompare ins insLen bld 32<rt> (?>) true
  | Op.VCMPGTSD ->
    vecCompare ins insLen bld 64<rt> (?>) false
  | Op.VCMPGTSDdot ->
    vecCompare ins insLen bld 64<rt> (?>) true
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException(Disasm.opCodeToString o)

// vim: set tw=80 sts=2 sw=2:

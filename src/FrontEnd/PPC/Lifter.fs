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
  | Op.MCRF ->
    mcrf ins bld
  | Op.MCRXR ->
    mcrxr ins bld
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
    mffs ins bld
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
    mtfsfi ins false bld
  | Op.MTFSFIdot ->
    mtfsfi ins true bld
  | Op.MTSPR ->
    mtspr ins bld
  | Op.MTFSB0 ->
    mtfsb0 ins false bld
  | Op.MTFSB0dot ->
    mtfsb0 ins true bld
  | Op.MTFSB1 ->
    mtfsb1 ins false bld
  | Op.MTFSB1dot ->
    mtfsb1 ins true bld
  | Op.MTFSF ->
    mtfsf ins bld
  | Op.MTLR ->
    mtlr ins bld
  | Op.MTXER ->
    mtxer ins bld
  | Op.MULHW ->
    mulhw ins false bld
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
    mfcr ins bld
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
    fcti ins false bld 64<rt> false
  | Op.FCTIDdot ->
    fcti ins true bld 64<rt> false
  | Op.FCTIDZ ->
    fcti ins false bld 64<rt> true
  | Op.FCTIDZdot ->
    fcti ins true bld 64<rt> true
  | Op.FCTIDU ->
    fcti ins false bld 64<rt> false
  | Op.FCTIDUdot ->
    fcti ins true bld 64<rt> false
  | Op.FCTIDUZ ->
    fcti ins false bld 64<rt> true
  | Op.FCTIDUZdot ->
    fcti ins true bld 64<rt> true
  | Op.FCTIWU ->
    fcti ins false bld 32<rt> false
  | Op.FCTIWUdot ->
    fcti ins true bld 32<rt> false
  | Op.FCTIWUZ ->
    fcti ins false bld 32<rt> true
  | Op.FCTIWUZdot ->
    fcti ins true bld 32<rt> true
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
    frnd ins false bld CastKind.FtoFRound
  | Op.FRINdot ->
    frnd ins true bld CastKind.FtoFRound
  | Op.FRIZ ->
    frnd ins false bld CastKind.FtoFTrunc
  | Op.FRIZdot ->
    frnd ins true bld CastKind.FtoFTrunc
  | Op.FRIP ->
    frnd ins false bld CastKind.FtoFCeil
  | Op.FRIPdot ->
    frnd ins true bld CastKind.FtoFCeil
  | Op.FRIM ->
    frnd ins false bld CastKind.FtoFFloor
  | Op.FRIMdot ->
    frnd ins true bld CastKind.FtoFFloor
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
  | Op.VSEL ->
    vecSelect ins bld
  | Op.VPERM ->
    vecPermute ins bld
  | Op.XXPERMDI ->
    vecPermuteDouble ins bld
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
    mffs ins bld
  | Op.XSADDDP ->
    vsxScalarBinary ins bld AST.fadd
  | Op.XSSUBDP ->
    vsxScalarBinary ins bld AST.fsub
  | Op.XSDIVDP ->
    vsxScalarBinary ins bld AST.fdiv
  | Op.XSCPSGNDP ->
    vsxScalarBinary ins bld copySign
  | Op.XSCMPUDP ->
    xscmpudp ins bld
  | Op.XSABSDP ->
    vsxScalarUnary ins bld (fun b ->
      b .& numU64 0x7fffffffffffffffUL 64<rt>)
  | Op.XSRSP ->
    (* Rounding a double to single precision and keeping it in double format. *)
    vsxScalarUnary ins bld (fun b ->
      AST.cast CastKind.FloatCast 64<rt> (AST.cast CastKind.FloatCast 32<rt> b))
  | Op.XSCVDPSPN ->
    vsxScalarUnary ins bld (fun b ->
      AST.concat (AST.cast CastKind.FloatCast 32<rt> b) (AST.num0 32<rt>))
  | Op.XSCVSPDPN ->
    vsxScalarUnary ins bld (fun b ->
      AST.cast CastKind.FloatCast 64<rt> (AST.xthi 32<rt> b))
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
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException(Disasm.opCodeToString o)

// vim: set tw=80 sts=2 sw=2:

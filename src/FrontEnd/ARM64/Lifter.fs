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

module internal B2R2.FrontEnd.ARM64.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM64
open B2R2.FrontEnd.ARM64.LiftingUtils
open B2R2.FrontEnd.ARM64.GeneralLifter
open B2R2.FrontEnd.ARM64.SIMDLifter

/// Translate IR.
let translate (ins: Instruction) bld =
  match ins.Opcode with
  | Opcode.ABS ->
    abs ins bld
  | Opcode.ADC ->
    adc ins bld
  | Opcode.ADCS ->
    adcs ins bld
  | Opcode.ADD ->
    add ins bld
  | Opcode.ADDHN ->
    addSubHN ins bld false false (.+)
  | Opcode.ADDHN2 ->
    addSubHN ins bld true false (.+)
  | Opcode.RADDHN ->
    addSubHN ins bld false true (.+)
  | Opcode.RADDHN2 ->
    addSubHN ins bld true true (.+)
  | Opcode.ADDP ->
    addp ins bld
  | Opcode.ADDS ->
    adds ins bld
  | Opcode.ADDV ->
    addv ins bld
  | Opcode.ADR ->
    adr ins bld
  | Opcode.ADRP ->
    adrp ins bld
  | Opcode.AND ->
    logAnd ins bld
  | Opcode.ANDS ->
    ands ins bld
  | Opcode.ASR ->
    asrv ins bld
  | Opcode.B ->
    b ins bld
  | Opcode.BAL ->
    bCond ins bld AL
  | Opcode.BCC ->
    bCond ins bld CC
  | Opcode.BCS ->
    bCond ins bld CS
  | Opcode.BEQ ->
    bCond ins bld EQ
  | Opcode.BFI ->
    bfi ins bld
  | Opcode.BFXIL ->
    bfxil ins bld
  | Opcode.BGE ->
    bCond ins bld GE
  | Opcode.BGT ->
    bCond ins bld GT
  | Opcode.BHI ->
    bCond ins bld HI
  | Opcode.BIC ->
    bic ins bld
  | Opcode.BICS ->
    bics ins bld
  | Opcode.BIF ->
    bif ins bld
  | Opcode.BIT ->
    bit ins bld
  | Opcode.BL ->
    bl ins bld
  | Opcode.BLE ->
    bCond ins bld LE
  | Opcode.BLR ->
    blr ins bld
  | Opcode.BLS ->
    bCond ins bld LS
  | Opcode.BLT ->
    bCond ins bld LT
  | Opcode.BMI ->
    bCond ins bld MI
  | Opcode.BNE ->
    bCond ins bld NE
  | Opcode.BNV ->
    bCond ins bld NV
  | Opcode.BPL ->
    bCond ins bld PL
  | Opcode.BR ->
    br ins bld
  | Opcode.ERET ->
    eret ins bld
  | Opcode.BRK ->
    sideEffects ins bld Breakpoint
  | Opcode.BSL ->
    bsl ins bld
  | Opcode.BVC ->
    bCond ins bld VC
  | Opcode.BVS ->
    bCond ins bld VS
  | Opcode.CASP | Opcode.CASPA | Opcode.CASPL | Opcode.CASPAL ->
    compareAndSwapPair ins bld
  | Opcode.CAS | Opcode.CASA | Opcode.CASL | Opcode.CASAL ->
    compareAndSwap ins bld ins.OprSize
  | Opcode.CASB | Opcode.CASAB | Opcode.CASLB | Opcode.CASALB ->
    compareAndSwap ins bld 8<rt>
  | Opcode.CASH | Opcode.CASAH | Opcode.CASLH | Opcode.CASALH ->
    compareAndSwap ins bld 16<rt>
  | Opcode.LDADDB | Opcode.LDADDLB | Opcode.LDADDAB | Opcode.LDADDALB
  | Opcode.STADDB | Opcode.STADDLB ->
    atomicMemOp ins bld (.+) 8<rt>
  | Opcode.LDADDH | Opcode.LDADDLH | Opcode.LDADDAH | Opcode.LDADDALH
  | Opcode.STADDH | Opcode.STADDLH ->
    atomicMemOp ins bld (.+) 16<rt>
  | Opcode.LDADD | Opcode.LDADDL | Opcode.LDADDA | Opcode.LDADDAL
  | Opcode.STADD | Opcode.STADDL ->
    atomicMemOp ins bld (.+) ins.OprSize
  | Opcode.LDCLRB | Opcode.LDCLRLB | Opcode.LDCLRAB | Opcode.LDCLRALB
  | Opcode.STCLRB | Opcode.STCLRLB ->
    atomicMemOp ins bld atomicClear 8<rt>
  | Opcode.LDCLRH | Opcode.LDCLRLH | Opcode.LDCLRAH | Opcode.LDCLRALH
  | Opcode.STCLRH | Opcode.STCLRLH ->
    atomicMemOp ins bld atomicClear 16<rt>
  | Opcode.LDCLR | Opcode.LDCLRL | Opcode.LDCLRA | Opcode.LDCLRAL
  | Opcode.STCLR | Opcode.STCLRL ->
    atomicMemOp ins bld atomicClear ins.OprSize
  | Opcode.LDEORB | Opcode.LDEORLB | Opcode.LDEORAB | Opcode.LDEORALB
  | Opcode.STEORB | Opcode.STEORLB ->
    atomicMemOp ins bld (<+>) 8<rt>
  | Opcode.LDEORH | Opcode.LDEORLH | Opcode.LDEORAH | Opcode.LDEORALH
  | Opcode.STEORH | Opcode.STEORLH ->
    atomicMemOp ins bld (<+>) 16<rt>
  | Opcode.LDEOR | Opcode.LDEORL | Opcode.LDEORA | Opcode.LDEORAL
  | Opcode.STEOR | Opcode.STEORL ->
    atomicMemOp ins bld (<+>) ins.OprSize
  | Opcode.LDSETB | Opcode.LDSETLB | Opcode.LDSETAB | Opcode.LDSETALB
  | Opcode.STSETB | Opcode.STSETLB ->
    atomicMemOp ins bld (.|) 8<rt>
  | Opcode.LDSETH | Opcode.LDSETLH | Opcode.LDSETAH | Opcode.LDSETALH
  | Opcode.STSETH | Opcode.STSETLH ->
    atomicMemOp ins bld (.|) 16<rt>
  | Opcode.LDSET | Opcode.LDSETL | Opcode.LDSETA | Opcode.LDSETAL
  | Opcode.STSET | Opcode.STSETL ->
    atomicMemOp ins bld (.|) ins.OprSize
  | Opcode.LDSMAXB | Opcode.LDSMAXLB | Opcode.LDSMAXAB | Opcode.LDSMAXALB
  | Opcode.STSMAXB | Opcode.STSMAXLB ->
    atomicMemOp ins bld atomicSMax 8<rt>
  | Opcode.LDSMAXH | Opcode.LDSMAXLH | Opcode.LDSMAXAH | Opcode.LDSMAXALH
  | Opcode.STSMAXH | Opcode.STSMAXLH ->
    atomicMemOp ins bld atomicSMax 16<rt>
  | Opcode.LDSMAX | Opcode.LDSMAXL | Opcode.LDSMAXA | Opcode.LDSMAXAL
  | Opcode.STSMAX | Opcode.STSMAXL ->
    atomicMemOp ins bld atomicSMax ins.OprSize
  | Opcode.LDSMINB | Opcode.LDSMINLB | Opcode.LDSMINAB | Opcode.LDSMINALB
  | Opcode.STSMINB | Opcode.STSMINLB ->
    atomicMemOp ins bld atomicSMin 8<rt>
  | Opcode.LDSMINH | Opcode.LDSMINLH | Opcode.LDSMINAH | Opcode.LDSMINALH
  | Opcode.STSMINH | Opcode.STSMINLH ->
    atomicMemOp ins bld atomicSMin 16<rt>
  | Opcode.LDSMIN | Opcode.LDSMINL | Opcode.LDSMINA | Opcode.LDSMINAL
  | Opcode.STSMIN | Opcode.STSMINL ->
    atomicMemOp ins bld atomicSMin ins.OprSize
  | Opcode.LDUMAXB | Opcode.LDUMAXLB | Opcode.LDUMAXAB | Opcode.LDUMAXALB
  | Opcode.STUMAXB | Opcode.STUMAXLB ->
    atomicMemOp ins bld atomicUMax 8<rt>
  | Opcode.LDUMAXH | Opcode.LDUMAXLH | Opcode.LDUMAXAH | Opcode.LDUMAXALH
  | Opcode.STUMAXH | Opcode.STUMAXLH ->
    atomicMemOp ins bld atomicUMax 16<rt>
  | Opcode.LDUMAX | Opcode.LDUMAXL | Opcode.LDUMAXA | Opcode.LDUMAXAL
  | Opcode.STUMAX | Opcode.STUMAXL ->
    atomicMemOp ins bld atomicUMax ins.OprSize
  | Opcode.LDUMINB | Opcode.LDUMINLB | Opcode.LDUMINAB | Opcode.LDUMINALB
  | Opcode.STUMINB | Opcode.STUMINLB ->
    atomicMemOp ins bld atomicUMin 8<rt>
  | Opcode.LDUMINH | Opcode.LDUMINLH | Opcode.LDUMINAH | Opcode.LDUMINALH
  | Opcode.STUMINH | Opcode.STUMINLH ->
    atomicMemOp ins bld atomicUMin 16<rt>
  | Opcode.LDUMIN | Opcode.LDUMINL | Opcode.LDUMINA | Opcode.LDUMINAL
  | Opcode.STUMIN | Opcode.STUMINL ->
    atomicMemOp ins bld atomicUMin ins.OprSize
  | Opcode.SWPB | Opcode.SWPLB | Opcode.SWPAB | Opcode.SWPALB ->
    swapMem ins bld 8<rt>
  | Opcode.SWPH | Opcode.SWPLH | Opcode.SWPAH | Opcode.SWPALH ->
    swapMem ins bld 16<rt>
  | Opcode.SWP | Opcode.SWPL | Opcode.SWPA | Opcode.SWPAL ->
    swapMem ins bld ins.OprSize
  | Opcode.LDAPRB ->
    loadAcquirePc ins bld 8<rt>
  | Opcode.LDAPRH ->
    loadAcquirePc ins bld 16<rt>
  | Opcode.LDAPR ->
    loadAcquirePc ins bld ins.OprSize
  | Opcode.IRG ->
    insertRandomTag ins bld
  | Opcode.GMI ->
    tagMaskInsert ins bld
  | Opcode.LDG ->
    loadTag ins bld
  | Opcode.STG | Opcode.ST2G | Opcode.STGM ->
    storeTag ins bld
  | Opcode.LDGM ->
    loadTagMultiple ins bld
  | Opcode.STZGM ->
    storeTagZeroingMultiple ins bld
  | Opcode.STZG ->
    storeTagZeroing ins bld 1
  | Opcode.STZ2G ->
    storeTagZeroing ins bld 2
  | Opcode.STGP ->
    storeTagPair ins bld
  | Opcode.ADDG ->
    addg ins bld
  | Opcode.SUBG ->
    subg ins bld
  | Opcode.SUBP ->
    subp ins bld
  | Opcode.SUBPS | Opcode.CMPP ->
    subps ins bld
  | Opcode.FCADD ->
    fcadd ins bld
  | Opcode.FCMLA ->
    fcmla ins bld
  | Opcode.FRECPS ->
    frecps ins bld
  | Opcode.FRSQRTS ->
    frsqrts ins bld
  | Opcode.SDOT ->
    dotProduct ins bld false false
  | Opcode.UDOT ->
    dotProduct ins bld true true
  | Opcode.USDOT ->
    dotProduct ins bld true false
  | Opcode.SUDOT ->
    dotProduct ins bld false true
  | Opcode.BFCVT ->
    bfcvt ins bld
  | Opcode.BFCVTN ->
    bfcvtn ins bld false
  | Opcode.BFCVTN2 ->
    bfcvtn ins bld true
  | Opcode.FMLAL ->
    fmlal ins bld
  | Opcode.FMLAL2 ->
    fmlal2 ins bld
  | Opcode.FMLSL ->
    fmlsl ins bld
  | Opcode.FMLSL2 ->
    fmlsl2 ins bld
  | Opcode.SQRDMLAH ->
    sqrdmlah ins bld
  | Opcode.SQRDMLSH ->
    sqrdmlsh ins bld
  | Opcode.SMMLA ->
    smmla ins bld
  | Opcode.UMMLA ->
    ummla ins bld
  | Opcode.USMMLA ->
    usmmla ins bld
  | Opcode.BFDOT ->
    bfdot ins bld
  | Opcode.BFMMLA ->
    bfmmla ins bld
  | Opcode.BFMLALB ->
    bfmlalb ins bld
  | Opcode.BFMLALT ->
    bfmlalt ins bld
  | Opcode.CFINV ->
    cfinv ins bld
  | Opcode.SETF8 ->
    setFlags ins bld 8<rt>
  | Opcode.SETF16 ->
    setFlags ins bld 16<rt>
  | Opcode.AXFLAG ->
    axflag ins bld
  | Opcode.XAFLAG ->
    xaflag ins bld
  | Opcode.RMIF ->
    rotateMaskInsert ins bld
  | Opcode.CBNZ ->
    cbnz ins bld
  | Opcode.CBZ ->
    cbz ins bld
  | Opcode.CCMN ->
    ccmn ins bld
  | Opcode.CCMP ->
    ccmp ins bld
  | Opcode.CLS ->
    cls ins bld
  | Opcode.FRSQRTE ->
    frsqrte ins bld
  | Opcode.FRECPE ->
    frecpe ins bld
  | Opcode.URECPE ->
    urecpe ins bld
  | Opcode.URSQRTE ->
    ursqrte ins bld
  | Opcode.FRECPX ->
    frecpx ins bld
  | Opcode.SQDMLSL | Opcode.SQDMLSL2 ->
    sqdmlsl ins bld
  | Opcode.CRC32B ->
    crc32 ins bld false 8<rt>
  | Opcode.CRC32H ->
    crc32 ins bld false 16<rt>
  | Opcode.CRC32W ->
    crc32 ins bld false 32<rt>
  | Opcode.CRC32X ->
    crc32 ins bld false 64<rt>
  | Opcode.CRC32CB ->
    crc32 ins bld true 8<rt>
  | Opcode.CRC32CH ->
    crc32 ins bld true 16<rt>
  | Opcode.CRC32CW ->
    crc32 ins bld true 32<rt>
  | Opcode.CRC32CX ->
    crc32 ins bld true 64<rt>
  | Opcode.SHA1C ->
    sha1c ins bld
  | Opcode.SHA1P ->
    sha1p ins bld
  | Opcode.SHA1M ->
    sha1m ins bld
  | Opcode.SHA1H ->
    sha1h ins bld
  | Opcode.SHA1SU0 ->
    sha1su0 ins bld
  | Opcode.SHA1SU1 ->
    sha1su1 ins bld
  | Opcode.SHA256SU0 ->
    sha256su0 ins bld
  | Opcode.SHA256SU1 ->
    sha256su1 ins bld
  | Opcode.SHA256H ->
    sha256Hash ins bld true
  | Opcode.SHA256H2 ->
    sha256Hash ins bld false
  | Opcode.PMUL ->
    pmul ins bld
  | Opcode.PMULL ->
    pmull ins bld false
  | Opcode.PMULL2 ->
    pmull ins bld true
  | Opcode.EOR3 ->
    eor3 ins bld
  | Opcode.BCAX ->
    bcax ins bld
  | Opcode.RAX1 ->
    rax1 ins bld
  | Opcode.XAR ->
    xar ins bld
  | Opcode.SHA512H ->
    sha512h ins bld
  | Opcode.SHA512H2 ->
    sha512h2 ins bld
  | Opcode.SHA512SU0 ->
    sha512su0 ins bld
  | Opcode.SHA512SU1 ->
    sha512su1 ins bld
  | Opcode.SM3PARTW1 ->
    sm3partw1 ins bld
  | Opcode.SM3PARTW2 ->
    sm3partw2 ins bld
  | Opcode.SM3SS1 ->
    sm3ss1 ins bld
  | Opcode.SM3TT1A ->
    sm3tt1a ins bld
  | Opcode.SM3TT1B ->
    sm3tt1b ins bld
  | Opcode.SM3TT2A ->
    sm3tt2a ins bld
  | Opcode.SM3TT2B ->
    sm3tt2b ins bld
  | Opcode.SM4E ->
    sm4e ins bld
  | Opcode.SM4EKEY ->
    sm4ekey ins bld
  | Opcode.AESE ->
    aesRound ins bld false
  | Opcode.AESD ->
    aesRound ins bld true
  | Opcode.AESMC ->
    aesMixColumns ins bld false
  | Opcode.AESIMC ->
    aesMixColumns ins bld true
  | Opcode.CLZ ->
    clz ins bld
  | Opcode.CMEQ ->
    cmeq ins bld
  | Opcode.CMGE ->
    cmge ins bld
  | Opcode.CMGT ->
    cmgt ins bld
  | Opcode.CMHI ->
    cmhi ins bld
  | Opcode.CMHS ->
    cmhs ins bld
  | Opcode.CMLE ->
    cmle ins bld
  | Opcode.CMLT ->
    cmlt ins bld
  | Opcode.CMN ->
    cmn ins bld
  | Opcode.CMP ->
    cmp ins bld
  | Opcode.CMTST ->
    cmtst ins bld
  | Opcode.CNEG | Opcode.CSNEG ->
    csneg ins bld
  | Opcode.CNT ->
    cnt ins bld
  | Opcode.CSEL ->
    csel ins bld
  | Opcode.CSETM | Opcode.CINV | Opcode.CSINV ->
    csinv ins bld
  | Opcode.CSINC | Opcode.CINC | Opcode.CSET ->
    csinc ins bld
  | Opcode.CTZ ->
    ctz ins bld
  | Opcode.DCZVA ->
    dczva ins bld
  | Opcode.CLREX
  | Opcode.DMB | Opcode.DSB | Opcode.ISB | Opcode.SB ->
    nop ins bld
  | Opcode.DUP ->
    dup ins bld
  | Opcode.EOR | Opcode.EON ->
    eor ins bld
  | Opcode.EXT ->
    ext ins bld
  | Opcode.EXTR | Opcode.ROR ->
    extr ins bld
  | Opcode.FABD ->
    fabd ins bld
  | Opcode.FABS ->
    fabs ins bld
  | Opcode.FADD ->
    fadd ins bld
  | Opcode.FADDP ->
    faddp ins bld
  | Opcode.FCCMP ->
    fccmp ins bld
  | Opcode.FCCMPE ->
    fccmp ins bld
  | Opcode.FMULX ->
    fmulx ins bld
  | Opcode.FMAXP | Opcode.FMAXV ->
    fmaxp ins bld
  | Opcode.FMINP | Opcode.FMINV ->
    fminp ins bld
  | Opcode.FMAXNMP | Opcode.FMAXNMV ->
    fmaxnmp ins bld
  | Opcode.FMINNMP | Opcode.FMINNMV ->
    fminnmp ins bld
  | Opcode.FCMGT ->
    fcmgt ins bld
  | Opcode.FCMGE ->
    fcmge ins bld
  | Opcode.FCMEQ ->
    fcmeq ins bld
  | Opcode.FCMLT ->
    fcmlt ins bld
  | Opcode.FCMLE ->
    fcmle ins bld
  | Opcode.FACGT ->
    facgt ins bld
  | Opcode.FACGE ->
    facge ins bld
  | Opcode.FCMP ->
    fcmp ins bld
  | Opcode.FCMPE ->
    fcmp ins bld
  | Opcode.FCSEL ->
    fcsel ins bld
  | Opcode.FCVT ->
    fcvt ins bld
  | Opcode.FCVTL ->
    fcvtLong ins bld false
  | Opcode.FCVTL2 ->
    fcvtLong ins bld true
  | Opcode.FCVTN ->
    fcvtNarrow ins bld false
  | Opcode.FCVTN2 ->
    fcvtNarrow ins bld true
  | Opcode.FCVTNS ->
    fcvtns ins bld
  | Opcode.FCVTNU ->
    fcvtnu ins bld
  | Opcode.FCVTAS ->
    fcvtas ins bld
  | Opcode.FCVTAU ->
    fcvtau ins bld
  | Opcode.FCVTMS ->
    fcvtms ins bld
  | Opcode.FCVTMU ->
    fcvtmu ins bld
  | Opcode.FCVTPS ->
    fcvtps ins bld
  | Opcode.FCVTPU ->
    fcvtpu ins bld
  | Opcode.FCVTZS ->
    fcvtzs ins bld
  | Opcode.FCVTZU ->
    fcvtzu ins bld
  | Opcode.FDIV ->
    fdiv ins bld
  | Opcode.FMADD ->
    fmadd ins bld
  | Opcode.FMAX ->
    fmax ins bld
  | Opcode.FMAXNM ->
    fmaxnm ins bld
  | Opcode.FMIN ->
    fmin ins bld
  | Opcode.FMINNM ->
    fminnm ins bld
  | Opcode.FMLA ->
    fmla ins bld
  | Opcode.FMLS ->
    fmls ins bld
  | Opcode.FMOV ->
    fmov ins bld
  | Opcode.FMSUB ->
    fmsub ins bld
  | Opcode.FMUL ->
    fmul ins bld
  | Opcode.FNEG ->
    fneg ins bld
  | Opcode.FNMADD ->
    fnmadd ins bld
  | Opcode.FNMSUB ->
    fnmsub ins bld
  | Opcode.FNMUL ->
    fnmul ins bld
  | Opcode.FRINTA ->
    frinta ins bld
  | Opcode.FRINTM ->
    frintm ins bld
  | Opcode.FRINTP ->
    frintp ins bld
  | Opcode.FRINTI ->
    frinti ins bld
  | Opcode.FRINTN ->
    frintn ins bld
  | Opcode.FRINTX ->
    frintx ins bld
  | Opcode.FRINTZ ->
    frintz ins bld
  | Opcode.FSQRT ->
    fsqrt ins bld
  | Opcode.FSUB ->
    fsub ins bld
  | Opcode.HINT ->
    nop ins bld
  | Opcode.INS ->
    insv ins bld
  | Opcode.LD1 | Opcode.LD2 | Opcode.LD3 | Opcode.LD4 ->
    loadStoreList ins bld true
  | Opcode.LD1R | Opcode.LD2R | Opcode.LD3R | Opcode.LD4R ->
    loadRep ins bld
  | Opcode.LDAR ->
    ldar ins bld
  | Opcode.LDLAR ->
    ldar ins bld
  | Opcode.LDLARB ->
    ldarSized ins bld 8<rt>
  | Opcode.LDLARH ->
    ldarSized ins bld 16<rt>
  | Opcode.LDAPUR ->
    ldur ins bld
  | Opcode.LDAPURB ->
    ldurb ins bld
  | Opcode.LDAPURH ->
    ldurh ins bld
  | Opcode.LDAPURSB ->
    ldursb ins bld
  | Opcode.LDAPURSH ->
    ldursh ins bld
  | Opcode.LDAPURSW ->
    ldursw ins bld
  | Opcode.LDARB ->
    ldarSized ins bld 8<rt>
  | Opcode.LDARH ->
    ldarSized ins bld 16<rt>
  (* The unprivileged accesses read and write through the translation regime
     the operating system uses for its own data rather than the one the
     current level runs under. There is one regime here and no privilege to
     drop, so each of them is the unscaled access it is written like. *)
  | Opcode.LDTR ->
    ldur ins bld
  | Opcode.LDTRB ->
    ldurb ins bld
  | Opcode.LDTRH ->
    ldurh ins bld
  | Opcode.LDTRSB ->
    ldursb ins bld
  | Opcode.LDTRSH ->
    ldursh ins bld
  | Opcode.LDTRSW ->
    ldursw ins bld
  | Opcode.STTR ->
    stur ins bld
  | Opcode.STTRH ->
    sturh ins bld
  | Opcode.LDAXP | Opcode.LDXP ->
    ldaxp ins bld
  | Opcode.LDAXR | Opcode.LDXR ->
    ldaxr ins bld
  | Opcode.LDAXRB | Opcode.LDXRB ->
    ldax ins bld 8<rt>
  | Opcode.LDAXRH | Opcode.LDXRH ->
    ldax ins bld 16<rt>
  | Opcode.LDNP ->
    ldnp ins bld
  | Opcode.LDP ->
    ldp ins bld
  | Opcode.LDPSW ->
    ldpsw ins bld
  | Opcode.LDR ->
    ldr ins bld
  | Opcode.LDRB ->
    ldrb ins bld
  | Opcode.LDRH ->
    ldrh ins bld
  | Opcode.LDRSB ->
    ldrsb ins bld
  | Opcode.LDRSH ->
    ldrsh ins bld
  | Opcode.LDRSW ->
    ldrsw ins bld
  | Opcode.LDUR ->
    ldur ins bld
  | Opcode.LDURB ->
    ldurb ins bld
  | Opcode.LDURH ->
    ldurh ins bld
  | Opcode.LDURSB ->
    ldursb ins bld
  | Opcode.LDURSH ->
    ldursh ins bld
  | Opcode.LDURSW ->
    ldursw ins bld
  | Opcode.LSL ->
    distLogicalLeftShift ins bld
  | Opcode.LSR ->
    distLogicalRightShift ins bld
  | Opcode.MADD ->
    madd ins bld
  | Opcode.MLA ->
    mladdsub ins bld (.+)
  | Opcode.MLS ->
    mladdsub ins bld (.-)
  | Opcode.MNEG ->
    msub ins bld
  | Opcode.MOV ->
    mov ins bld
  | Opcode.MOVI ->
    movi ins bld
  | Opcode.MOVK ->
    movk ins bld
  | Opcode.MOVN ->
    movn ins bld
  | Opcode.MOVZ ->
    movz ins bld
  | Opcode.MRS ->
    mrs ins bld
  | Opcode.MSR ->
    msr ins bld
  | Opcode.MSUB ->
    msub ins bld
  | Opcode.MUL ->
    madd ins bld
  | Opcode.MVN ->
    orn ins bld
  | Opcode.MVNI ->
    mvni ins bld
  | Opcode.NEG ->
    sub ins bld
  | Opcode.NEGS ->
    subs ins bld
  | Opcode.NOT ->
    orn ins bld
  | Opcode.NOP ->
    nop ins bld
  | Opcode.ORN ->
    orn ins bld
  | Opcode.ORR ->
    orr ins bld
  | Opcode.PRFM | Opcode.PRFUM ->
    nop ins bld
  | Opcode.RBIT ->
    rbit ins bld
  | Opcode.RET ->
    ret ins bld
  | Opcode.REV ->
    rev ins bld
  | Opcode.REV16 ->
    rev16 ins bld
  | Opcode.REV32 ->
    rev32 ins bld
  | Opcode.REV64 ->
    rev ins bld
  | Opcode.RORV ->
    rorv ins bld
  | Opcode.SADDL | Opcode.SADDL2 ->
    saddl ins bld
  | Opcode.SADDW | Opcode.SADDW2 ->
    saddw ins bld
  | Opcode.SADDLP ->
    saddlp ins bld
  | Opcode.SADDLV ->
    saddlv ins bld
  | Opcode.SBC ->
    sbc ins bld
  | Opcode.SBCS ->
    sbcs ins bld
  | Opcode.SBFIZ ->
    sbfiz ins bld
  | Opcode.SBFX ->
    sbfx ins bld
  | Opcode.SCVTF ->
    icvtf ins bld false
  | Opcode.SDIV ->
    sdiv ins bld
  | Opcode.SHL ->
    shl ins bld
  | Opcode.SHRN ->
    shrn ins bld false false
  | Opcode.SHRN2 ->
    shrn ins bld true false
  | Opcode.RSHRN ->
    shrn ins bld false true
  | Opcode.RSHRN2 ->
    shrn ins bld true true
  | Opcode.SHLL | Opcode.SHLL2 ->
    shiftULeftLong ins bld
  | Opcode.SQRDMULH ->
    sqrdmulh ins bld
  | Opcode.SQSHL ->
    sqshlReg ins bld false
  | Opcode.SQRSHL ->
    sqshlReg ins bld true
  | Opcode.SQSHRN ->
    sqshrn ins bld false false false false
  | Opcode.SQSHRN2 ->
    sqshrn ins bld true false false false
  | Opcode.SQRSHRN ->
    sqshrn ins bld false true false false
  | Opcode.SQRSHRN2 ->
    sqshrn ins bld true true false false
  | Opcode.SQSHRUN ->
    sqshrn ins bld false false false true
  | Opcode.SQSHRUN2 ->
    sqshrn ins bld true false false true
  | Opcode.SQRSHRUN ->
    sqshrn ins bld false true false true
  | Opcode.SQRSHRUN2 ->
    sqshrn ins bld true true false true
  | Opcode.UQSHRN ->
    sqshrn ins bld false false true true
  | Opcode.UQSHRN2 ->
    sqshrn ins bld true false true true
  | Opcode.UQRSHRN ->
    sqshrn ins bld false true true true
  | Opcode.UQRSHRN2 ->
    sqshrn ins bld true true true true
  | Opcode.SQXTN ->
    qxtn ins bld false false false
  | Opcode.SQXTN2 ->
    qxtn ins bld true false false
  | Opcode.UQXTN ->
    qxtn ins bld false true true
  | Opcode.UQXTN2 ->
    qxtn ins bld true true true
  | Opcode.SQXTUN ->
    qxtn ins bld false false true
  | Opcode.SQXTUN2 ->
    qxtn ins bld true false true
  | Opcode.SRSHR ->
    rshr ins bld false false
  | Opcode.URSHR ->
    rshr ins bld true false
  | Opcode.SRSRA ->
    rshr ins bld false true
  | Opcode.URSRA ->
    rshr ins bld true true
  | Opcode.SLI ->
    shiftInsert ins bld true
  | Opcode.SRI ->
    shiftInsert ins bld false
  | Opcode.SQABS ->
    qabsneg ins bld false
  | Opcode.SQNEG ->
    qabsneg ins bld true
  | Opcode.SUQADD ->
    usqadd ins bld false
  | Opcode.USQADD ->
    usqadd ins bld true
  | Opcode.SMADDL ->
    smaddl ins bld
  | Opcode.SMOV ->
    smov ins bld
  | Opcode.SMSUBL | Opcode.SMNEGL ->
    smsubl ins bld
  | Opcode.SMULH ->
    smulh ins bld
  | Opcode.SMULL | Opcode.SMULL2 ->
    smull ins bld
  | Opcode.SSHL ->
    sshl ins bld
  | Opcode.UXTL | Opcode.UXTL2 | Opcode.USHLL | Opcode.USHLL2 ->
    shiftULeftLong ins bld
  | Opcode.SXTL | Opcode.SXTL2 | Opcode.SSHLL | Opcode.SSHLL2 ->
    shiftSLeftLong ins bld
  | Opcode.SSHR ->
    shift ins bld (?>>)
  | Opcode.SSRA ->
    shiftRight ins bld (?>>)
  | Opcode.SSUBL | Opcode.SSUBL2 ->
    ssubl ins bld
  | Opcode.SSUBW | Opcode.SSUBW2 ->
    ssubw ins bld
  | Opcode.SMAX ->
    maxMin ins bld (?>=)
  | Opcode.SMAXP ->
    maxMinp ins bld (?>=)
  | Opcode.SMAXV ->
    maxMinv ins bld (?>=)
  | Opcode.SMIN ->
    maxMin ins bld (?<=)
  | Opcode.SMINP ->
    maxMinp ins bld (?<=)
  | Opcode.SMINV ->
    maxMinv ins bld (?<=)
  | Opcode.SMLAL | Opcode.SMLAL2 ->
    smlal ins bld
  | Opcode.SMLSL | Opcode.SMLSL2 ->
    smlsl ins bld
  | Opcode.SQDMULH ->
    sqdmulh ins bld
  | Opcode.SQDMULL | Opcode.SQDMULL2 ->
    sqdmull ins bld
  | Opcode.SQDMLAL | Opcode.SQDMLAL2 ->
    sqdmlal ins bld
  | Opcode.ST1 | Opcode.ST2 | Opcode.ST3 | Opcode.ST4 ->
    loadStoreList ins bld false
  | Opcode.STLR ->
    stlr ins bld
  | Opcode.STLLR ->
    stlr ins bld
  | Opcode.STLLRB ->
    stlrSized ins bld 8<rt>
  | Opcode.STLLRH ->
    stlrSized ins bld 16<rt>
  | Opcode.STLUR ->
    stur ins bld
  | Opcode.STLURB ->
    sturb ins bld
  | Opcode.STLURH ->
    sturh ins bld
  | Opcode.STLRB ->
    stlrSized ins bld 8<rt>
  | Opcode.STLRH ->
    stlrSized ins bld 16<rt>
  | Opcode.STLXP | Opcode.STXP ->
    stlxp ins bld
  | Opcode.STLXR | Opcode.STXR ->
    stlxr ins bld
  | Opcode.STLXRB | Opcode.STXRB ->
    stlx ins bld 8<rt>
  | Opcode.STLXRH | Opcode.STXRH ->
    stlx ins bld 16<rt>
  | Opcode.STNP ->
    stnp ins bld
  | Opcode.STP ->
    stp ins bld
  | Opcode.STR ->
    str ins bld
  | Opcode.STRB ->
    strb ins bld
  | Opcode.STRH ->
    strh ins bld
  | Opcode.STTRB ->
    sttrb ins bld
  | Opcode.STUR ->
    stur ins bld
  | Opcode.STURB ->
    sturb ins bld
  | Opcode.STURH ->
    sturh ins bld
  | Opcode.SUB ->
    sub ins bld
  | Opcode.SUBHN ->
    addSubHN ins bld false false (.-)
  | Opcode.SUBHN2 ->
    addSubHN ins bld true false (.-)
  | Opcode.RSUBHN ->
    addSubHN ins bld false true (.-)
  | Opcode.RSUBHN2 ->
    addSubHN ins bld true true (.-)
  | Opcode.SUBS ->
    subs ins bld
  | Opcode.SVC ->
    svc ins bld
  | Opcode.SXTB ->
    sxtb ins bld
  | Opcode.SXTH ->
    sxth ins bld
  | Opcode.SXTW ->
    sxtw ins bld
  | Opcode.TBL ->
    tbl ins bld
  | Opcode.TBX ->
    tbx ins bld
  | Opcode.TBNZ ->
    tbnz ins bld
  | Opcode.TBZ ->
    tbz ins bld
  | Opcode.TRN1 ->
    trn1 ins bld
  | Opcode.TRN2 ->
    trn2 ins bld
  | Opcode.TST ->
    tst ins bld
  | Opcode.UABAL | Opcode.UABAL2 ->
    abal ins bld true
  | Opcode.SABAL | Opcode.SABAL2 ->
    abal ins bld false
  | Opcode.UABA ->
    absDiff ins bld true true
  | Opcode.SABA ->
    absDiff ins bld false true
  | Opcode.UABD ->
    absDiff ins bld true false
  | Opcode.SABD ->
    absDiff ins bld false false
  | Opcode.UHADD ->
    hsub ins bld true false
  | Opcode.SHADD ->
    hsub ins bld false false
  | Opcode.UHSUB ->
    hsub ins bld true true
  | Opcode.SHSUB ->
    hsub ins bld false true
  | Opcode.UABDL | Opcode.UABDL2 ->
    abdl ins bld true
  | Opcode.SABDL | Opcode.SABDL2 ->
    abdl ins bld false
  | Opcode.UADALP ->
    adalp ins bld true
  | Opcode.SADALP ->
    adalp ins bld false
  | Opcode.UADDL | Opcode.UADDL2 ->
    uaddl ins bld
  | Opcode.UADDLP ->
    uaddlp ins bld
  | Opcode.UADDLV ->
    uaddlv ins bld
  | Opcode.UADDW | Opcode.UADDW2 ->
    uaddw ins bld
  | Opcode.UBFIZ ->
    ubfiz ins bld
  | Opcode.UBFX ->
    ubfx ins bld
  | Opcode.UCVTF ->
    icvtf ins bld true
  | Opcode.UDIV ->
    udiv ins bld
  | Opcode.UMADDL ->
    umaddl ins bld
  | Opcode.UMAX ->
    maxMin ins bld (.>=)
  | Opcode.UMAXP ->
    maxMinp ins bld (.>=)
  | Opcode.UMAXV ->
    maxMinv ins bld (.>=)
  | Opcode.UMIN ->
    maxMin ins bld (.<=)
  | Opcode.UMINP ->
    maxMinp ins bld (.<=)
  | Opcode.UMINV ->
    maxMinv ins bld (.<=)
  | Opcode.UMLAL | Opcode.UMLAL2 ->
    umlal ins bld
  | Opcode.UMLSL | Opcode.UMLSL2 ->
    umlsl ins bld
  | Opcode.UMOV ->
    umov ins bld
  | Opcode.UMSUBL | Opcode.UMNEGL ->
    umsubl ins bld
  | Opcode.UMULH ->
    umulh ins bld
  | Opcode.UMULL | Opcode.UMULL2 ->
    umull ins bld
  | Opcode.UQADD ->
    qadd ins bld true
  | Opcode.SQADD ->
    qadd ins bld false
  | Opcode.UQRSHL ->
    uqrshl ins bld
  | Opcode.UQSHL ->
    uqshl ins bld
  | Opcode.UQSUB ->
    qsub ins bld true
  | Opcode.SQSUB ->
    qsub ins bld false
  | Opcode.URSHL ->
    urshl ins bld
  | Opcode.SRSHL ->
    srshl ins bld
  | Opcode.URHADD ->
    rhadd ins bld true
  | Opcode.SRHADD ->
    rhadd ins bld false
  | Opcode.USHL ->
    ushl ins bld
  | Opcode.USHR ->
    shift ins bld (>>)
  | Opcode.USRA ->
    shiftRight ins bld (>>)
  | Opcode.USUBL | Opcode.USUBL2 ->
    usubl ins bld
  | Opcode.USUBW | Opcode.USUBW2 ->
    usubw ins bld
  | Opcode.UXTB ->
    uxtb ins bld
  | Opcode.UXTH ->
    uxth ins bld
  | Opcode.UZP1 ->
    uzp ins bld 0
  | Opcode.UZP2 ->
    uzp ins bld 1
  | Opcode.XTN ->
    xtn ins bld
  | Opcode.XTN2 ->
    xtn2 ins bld
  | Opcode.ZIP1 ->
    zip ins bld true
  | Opcode.ZIP2 ->
    zip ins bld false
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException(Disasm.opCodeToString o)

// vim: set tw=80 sts=2 sw=2:

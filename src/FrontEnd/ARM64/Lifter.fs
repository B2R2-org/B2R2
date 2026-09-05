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
    addSubHN ins bld false (.+)
  | Opcode.ADDHN2 ->
    addSubHN ins bld true (.+)
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
  | Opcode.BRK ->
    sideEffects ins bld Breakpoint
  | Opcode.BSL ->
    bsl ins bld
  | Opcode.BVC ->
    bCond ins bld VC
  | Opcode.BVS ->
    bCond ins bld VS
  | Opcode.CAS | Opcode.CASA | Opcode.CASL | Opcode.CASAL ->
    compareAndSwap ins bld
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
  | Opcode.DMB | Opcode.DSB | Opcode.ISB ->
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
  | Opcode.FCMGT ->
    fcmgt ins bld
  | Opcode.FCMP ->
    fcmp ins bld
  | Opcode.FCMPE ->
    fcmp ins bld
  | Opcode.FCSEL ->
    fcsel ins bld
  | Opcode.FCVT ->
    fcvt ins bld
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
    fmaxmin ins bld AST.fgt
  | Opcode.FMAXNM ->
    unsupported ins bld
  | Opcode.FMIN ->
    fmaxmin ins bld AST.flt
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
  | Opcode.LDARB ->
    ldarb ins bld
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
    shrn ins bld false
  | Opcode.SHRN2 ->
    shrn ins bld true
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
  | Opcode.STLRB ->
    stlrb ins bld
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
    addSubHN ins bld false (.-)
  | Opcode.SUBHN2 ->
    addSubHN ins bld true (.-)
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
    uabal ins bld
  | Opcode.UABDL | Opcode.UABDL2 ->
    uabdl ins bld
  | Opcode.UADALP ->
    uadalp ins bld
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
    uqadd ins bld
  | Opcode.UQRSHL ->
    uqrshl ins bld
  | Opcode.UQSHL ->
    uqshl ins bld
  | Opcode.UQSUB ->
    uqsub ins bld
  | Opcode.URSHL ->
    urshl ins bld
  | Opcode.SRSHL ->
    srshl ins bld
  | Opcode.URHADD ->
    urhadd ins bld
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

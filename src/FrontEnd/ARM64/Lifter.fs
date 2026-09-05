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
let translate (ins: Instruction) insLen bld =
  match ins.Opcode with
  | Opcode.ABS ->
    abs ins insLen bld
  | Opcode.ADC ->
    adc ins insLen bld
  | Opcode.ADCS ->
    adcs ins insLen bld
  | Opcode.ADD ->
    add ins insLen bld
  | Opcode.ADDHN ->
    addSubHN ins insLen bld false (.+)
  | Opcode.ADDHN2 ->
    addSubHN ins insLen bld true (.+)
  | Opcode.ADDP ->
    addp ins insLen bld
  | Opcode.ADDS ->
    adds ins insLen bld
  | Opcode.ADDV ->
    addv ins insLen bld
  | Opcode.ADR ->
    adr ins insLen bld
  | Opcode.ADRP ->
    adrp ins insLen bld
  | Opcode.AND ->
    logAnd ins insLen bld
  | Opcode.ANDS ->
    ands ins insLen bld
  | Opcode.ASR ->
    asrv ins insLen bld
  | Opcode.B ->
    b ins insLen bld
  | Opcode.BAL ->
    bCond ins insLen bld AL
  | Opcode.BCC ->
    bCond ins insLen bld CC
  | Opcode.BCS ->
    bCond ins insLen bld CS
  | Opcode.BEQ ->
    bCond ins insLen bld EQ
  | Opcode.BFI ->
    bfi ins insLen bld
  | Opcode.BFXIL ->
    bfxil ins insLen bld
  | Opcode.BGE ->
    bCond ins insLen bld GE
  | Opcode.BGT ->
    bCond ins insLen bld GT
  | Opcode.BHI ->
    bCond ins insLen bld HI
  | Opcode.BIC ->
    bic ins insLen bld
  | Opcode.BICS ->
    bics ins insLen bld
  | Opcode.BIF ->
    bif ins insLen bld
  | Opcode.BIT ->
    bit ins insLen bld
  | Opcode.BL ->
    bl ins insLen bld
  | Opcode.BLE ->
    bCond ins insLen bld LE
  | Opcode.BLR ->
    blr ins insLen bld
  | Opcode.BLS ->
    bCond ins insLen bld LS
  | Opcode.BLT ->
    bCond ins insLen bld LT
  | Opcode.BMI ->
    bCond ins insLen bld MI
  | Opcode.BNE ->
    bCond ins insLen bld NE
  | Opcode.BNV ->
    bCond ins insLen bld NV
  | Opcode.BPL ->
    bCond ins insLen bld PL
  | Opcode.BR ->
    br ins insLen bld
  | Opcode.BRK ->
    sideEffects ins.Address insLen bld Breakpoint
  | Opcode.BSL ->
    bsl ins insLen bld
  | Opcode.BVC ->
    bCond ins insLen bld VC
  | Opcode.BVS ->
    bCond ins insLen bld VS
  | Opcode.CAS | Opcode.CASA | Opcode.CASL | Opcode.CASAL ->
    compareAndSwap ins insLen bld
  | Opcode.CBNZ ->
    cbnz ins insLen bld
  | Opcode.CBZ ->
    cbz ins insLen bld
  | Opcode.CCMN ->
    ccmn ins insLen bld
  | Opcode.CCMP ->
    ccmp ins insLen bld
  | Opcode.CLS ->
    cls ins insLen bld
  | Opcode.CLZ ->
    clz ins insLen bld
  | Opcode.CMEQ ->
    cmeq ins insLen bld
  | Opcode.CMGE ->
    cmge ins insLen bld
  | Opcode.CMGT ->
    cmgt ins insLen bld
  | Opcode.CMHI ->
    cmhi ins insLen bld
  | Opcode.CMHS ->
    cmhs ins insLen bld
  | Opcode.CMLT ->
    cmlt ins insLen bld
  | Opcode.CMN ->
    cmn ins insLen bld
  | Opcode.CMP ->
    cmp ins insLen bld
  | Opcode.CMTST ->
    cmtst ins insLen bld
  | Opcode.CNEG | Opcode.CSNEG ->
    csneg ins insLen bld
  | Opcode.CNT ->
    cnt ins insLen bld
  | Opcode.CSEL ->
    csel ins insLen bld
  | Opcode.CSETM | Opcode.CINV | Opcode.CSINV ->
    csinv ins insLen bld
  | Opcode.CSINC | Opcode.CINC | Opcode.CSET ->
    csinc ins insLen bld
  | Opcode.CTZ ->
    ctz ins insLen bld
  | Opcode.DCZVA ->
    dczva ins insLen bld
  | Opcode.CLREX
  | Opcode.DMB | Opcode.DSB | Opcode.ISB ->
    nop ins.Address insLen bld
  | Opcode.DUP ->
    dup ins insLen bld
  | Opcode.EOR | Opcode.EON ->
    eor ins insLen bld
  | Opcode.EXT ->
    ext ins insLen bld
  | Opcode.EXTR | Opcode.ROR ->
    extr ins insLen bld
  | Opcode.FABD ->
    fabd ins insLen bld
  | Opcode.FABS ->
    fabs ins insLen bld
  | Opcode.FADD ->
    fadd ins insLen bld
  | Opcode.FADDP ->
    faddp ins insLen bld
  | Opcode.FCCMP ->
    fccmp ins insLen bld
  | Opcode.FCCMPE ->
    fccmp ins insLen bld
  | Opcode.FCMGT ->
    fcmgt ins insLen bld
  | Opcode.FCMP ->
    fcmp ins insLen bld
  | Opcode.FCMPE ->
    fcmp ins insLen bld
  | Opcode.FCSEL ->
    fcsel ins insLen bld
  | Opcode.FCVT ->
    fcvt ins insLen bld
  | Opcode.FCVTAS ->
    fcvtas ins insLen bld
  | Opcode.FCVTAU ->
    fcvtau ins insLen bld
  | Opcode.FCVTMS ->
    fcvtms ins insLen bld
  | Opcode.FCVTMU ->
    fcvtmu ins insLen bld
  | Opcode.FCVTPS ->
    fcvtps ins insLen bld
  | Opcode.FCVTPU ->
    fcvtpu ins insLen bld
  | Opcode.FCVTZS ->
    fcvtzs ins insLen bld
  | Opcode.FCVTZU ->
    fcvtzu ins insLen bld
  | Opcode.FDIV ->
    fdiv ins insLen bld
  | Opcode.FMADD ->
    fmadd ins insLen bld
  | Opcode.FMAX ->
    fmaxmin ins insLen bld AST.fgt
  | Opcode.FMAXNM ->
    sideEffects ins.Address insLen bld UnsupportedInstruction
  | Opcode.FMIN ->
    fmaxmin ins insLen bld AST.flt
  | Opcode.FMLS ->
    fmls ins insLen bld
  | Opcode.FMOV ->
    fmov ins insLen bld
  | Opcode.FMSUB ->
    fmsub ins insLen bld
  | Opcode.FMUL ->
    fmul ins insLen bld
  | Opcode.FNEG ->
    fneg ins insLen bld
  | Opcode.FNMSUB ->
    fnmsub ins insLen bld
  | Opcode.FNMUL ->
    fnmul ins insLen bld
  | Opcode.FRINTA ->
    frinta ins insLen bld
  | Opcode.FRINTM ->
    frintm ins insLen bld
  | Opcode.FRINTP ->
    frintp ins insLen bld
  | Opcode.FRINTI ->
    frinti ins insLen bld
  | Opcode.FRINTN ->
    frintn ins insLen bld
  | Opcode.FRINTX ->
    frintx ins insLen bld
  | Opcode.FRINTZ ->
    frintz ins insLen bld
  | Opcode.FSQRT ->
    fsqrt ins insLen bld
  | Opcode.FSUB ->
    fsub ins insLen bld
  | Opcode.HINT ->
    nop ins.Address insLen bld
  | Opcode.INS ->
    insv ins insLen bld
  | Opcode.LD1 | Opcode.LD2 | Opcode.LD3 | Opcode.LD4 ->
    loadStoreList ins insLen bld true
  | Opcode.LD1R | Opcode.LD2R | Opcode.LD3R | Opcode.LD4R ->
    loadRep ins insLen bld
  | Opcode.LDAR ->
    ldar ins insLen bld
  | Opcode.LDARB ->
    ldarb ins insLen bld
  | Opcode.LDAXP | Opcode.LDXP ->
    ldaxp ins insLen bld
  | Opcode.LDAXR | Opcode.LDXR ->
    ldaxr ins insLen bld
  | Opcode.LDAXRB | Opcode.LDXRB ->
    ldax ins insLen bld 8<rt>
  | Opcode.LDAXRH | Opcode.LDXRH ->
    ldax ins insLen bld 16<rt>
  | Opcode.LDNP ->
    ldnp ins insLen bld
  | Opcode.LDP ->
    ldp ins insLen bld
  | Opcode.LDPSW ->
    ldpsw ins insLen bld
  | Opcode.LDR ->
    ldr ins insLen bld
  | Opcode.LDRB ->
    ldrb ins insLen bld
  | Opcode.LDRH ->
    ldrh ins insLen bld
  | Opcode.LDRSB ->
    ldrsb ins insLen bld
  | Opcode.LDRSH ->
    ldrsh ins insLen bld
  | Opcode.LDRSW ->
    ldrsw ins insLen bld
  | Opcode.LDUR ->
    ldur ins insLen bld
  | Opcode.LDURB ->
    ldurb ins insLen bld
  | Opcode.LDURH ->
    ldurh ins insLen bld
  | Opcode.LDURSB ->
    ldursb ins insLen bld
  | Opcode.LDURSH ->
    ldursh ins insLen bld
  | Opcode.LDURSW ->
    ldursw ins insLen bld
  | Opcode.LSL ->
    distLogicalLeftShift ins insLen bld
  | Opcode.LSR ->
    distLogicalRightShift ins insLen bld
  | Opcode.MADD ->
    madd ins insLen bld
  | Opcode.MLA ->
    mladdsub ins insLen bld (.+)
  | Opcode.MLS ->
    mladdsub ins insLen bld (.-)
  | Opcode.MNEG ->
    msub ins insLen bld
  | Opcode.MOV ->
    mov ins insLen bld
  | Opcode.MOVI ->
    movi ins insLen bld
  | Opcode.MOVK ->
    movk ins insLen bld
  | Opcode.MOVN ->
    movn ins insLen bld
  | Opcode.MOVZ ->
    movz ins insLen bld
  | Opcode.MRS ->
    mrs ins insLen bld
  | Opcode.MSR ->
    msr ins insLen bld
  | Opcode.MSUB ->
    msub ins insLen bld
  | Opcode.MUL ->
    madd ins insLen bld
  | Opcode.MVN ->
    orn ins insLen bld
  | Opcode.MVNI ->
    mvni ins insLen bld
  | Opcode.NEG ->
    sub ins insLen bld
  | Opcode.NEGS ->
    subs ins insLen bld
  | Opcode.NOT ->
    orn ins insLen bld
  | Opcode.NOP ->
    nop ins.Address insLen bld
  | Opcode.ORN ->
    orn ins insLen bld
  | Opcode.ORR ->
    orr ins insLen bld
  | Opcode.PRFM | Opcode.PRFUM ->
    nop ins.Address insLen bld
  | Opcode.RBIT ->
    rbit ins insLen bld
  | Opcode.RET ->
    ret ins insLen bld
  | Opcode.REV ->
    rev ins insLen bld
  | Opcode.REV16 ->
    rev16 ins insLen bld
  | Opcode.REV32 ->
    rev32 ins insLen bld
  | Opcode.REV64 ->
    rev ins insLen bld
  | Opcode.RORV ->
    rorv ins insLen bld
  | Opcode.SADDL | Opcode.SADDL2 ->
    saddl ins insLen bld
  | Opcode.SADDW | Opcode.SADDW2 ->
    saddw ins insLen bld
  | Opcode.SADDLP ->
    saddlp ins insLen bld
  | Opcode.SADDLV ->
    saddlv ins insLen bld
  | Opcode.SBC ->
    sbc ins insLen bld
  | Opcode.SBCS ->
    sbcs ins insLen bld
  | Opcode.SBFIZ ->
    sbfiz ins insLen bld
  | Opcode.SBFX ->
    sbfx ins insLen bld
  | Opcode.SCVTF ->
    icvtf ins insLen bld false
  | Opcode.SDIV ->
    sdiv ins insLen bld
  | Opcode.SHL ->
    shl ins insLen bld
  | Opcode.SHRN ->
    shrn ins insLen bld false
  | Opcode.SHRN2 ->
    shrn ins insLen bld true
  | Opcode.SMADDL ->
    smaddl ins insLen bld
  | Opcode.SMOV ->
    smov ins insLen bld
  | Opcode.SMSUBL | Opcode.SMNEGL ->
    smsubl ins insLen bld
  | Opcode.SMULH ->
    smulh ins insLen bld
  | Opcode.SMULL | Opcode.SMULL2 ->
    smull ins insLen bld
  | Opcode.SSHL ->
    sshl ins insLen bld
  | Opcode.UXTL | Opcode.UXTL2 | Opcode.USHLL | Opcode.USHLL2 ->
    shiftULeftLong ins insLen bld
  | Opcode.SXTL | Opcode.SXTL2 | Opcode.SSHLL | Opcode.SSHLL2 ->
    shiftSLeftLong ins insLen bld
  | Opcode.SSHR ->
    shift ins insLen bld (?>>)
  | Opcode.SSRA ->
    shiftRight ins insLen bld (?>>)
  | Opcode.SSUBL | Opcode.SSUBL2 ->
    ssubl ins insLen bld
  | Opcode.SSUBW | Opcode.SSUBW2 ->
    ssubw ins insLen bld
  | Opcode.SMAX ->
    maxMin ins insLen bld (?>=)
  | Opcode.SMAXP ->
    maxMinp ins insLen bld (?>=)
  | Opcode.SMAXV ->
    maxMinv ins insLen bld (?>=)
  | Opcode.SMIN ->
    maxMin ins insLen bld (?<=)
  | Opcode.SMINP ->
    maxMinp ins insLen bld (?<=)
  | Opcode.SMINV ->
    maxMinv ins insLen bld (?<=)
  | Opcode.SMLAL | Opcode.SMLAL2 ->
    smlal ins insLen bld
  | Opcode.SMLSL | Opcode.SMLSL2 ->
    smlsl ins insLen bld
  | Opcode.SQDMULH ->
    sqdmulh ins insLen bld
  | Opcode.SQDMULL | Opcode.SQDMULL2 ->
    sqdmull ins insLen bld
  | Opcode.SQDMLAL | Opcode.SQDMLAL2 ->
    sqdmlal ins insLen bld
  | Opcode.ST1 | Opcode.ST2 | Opcode.ST3 | Opcode.ST4 ->
    loadStoreList ins insLen bld false
  | Opcode.STLR ->
    stlr ins insLen bld
  | Opcode.STLRB ->
    stlrb ins insLen bld
  | Opcode.STLXP | Opcode.STXP ->
    stlxp ins insLen bld
  | Opcode.STLXR | Opcode.STXR ->
    stlxr ins insLen bld
  | Opcode.STLXRB | Opcode.STXRB ->
    stlx ins insLen bld 8<rt>
  | Opcode.STLXRH | Opcode.STXRH ->
    stlx ins insLen bld 16<rt>
  | Opcode.STNP ->
    stnp ins insLen bld
  | Opcode.STP ->
    stp ins insLen bld
  | Opcode.STR ->
    str ins insLen bld
  | Opcode.STRB ->
    strb ins insLen bld
  | Opcode.STRH ->
    strh ins insLen bld
  | Opcode.STTRB ->
    sttrb ins insLen bld
  | Opcode.STUR ->
    stur ins insLen bld
  | Opcode.STURB ->
    sturb ins insLen bld
  | Opcode.STURH ->
    sturh ins insLen bld
  | Opcode.SUB ->
    sub ins insLen bld
  | Opcode.SUBHN ->
    addSubHN ins insLen bld false (.-)
  | Opcode.SUBHN2 ->
    addSubHN ins insLen bld true (.-)
  | Opcode.SUBS ->
    subs ins insLen bld
  | Opcode.SVC ->
    svc ins insLen bld
  | Opcode.SXTB ->
    sxtb ins insLen bld
  | Opcode.SXTH ->
    sxth ins insLen bld
  | Opcode.SXTW ->
    sxtw ins insLen bld
  | Opcode.TBL ->
    tbl ins insLen bld
  | Opcode.TBNZ ->
    tbnz ins insLen bld
  | Opcode.TBZ ->
    tbz ins insLen bld
  | Opcode.TRN1 ->
    trn1 ins insLen bld
  | Opcode.TRN2 ->
    trn2 ins insLen bld
  | Opcode.TST ->
    tst ins insLen bld
  | Opcode.UABAL | Opcode.UABAL2 ->
    uabal ins insLen bld
  | Opcode.UABDL | Opcode.UABDL2 ->
    uabdl ins insLen bld
  | Opcode.UADALP ->
    uadalp ins insLen bld
  | Opcode.UADDL | Opcode.UADDL2 ->
    uaddl ins insLen bld
  | Opcode.UADDLP ->
    uaddlp ins insLen bld
  | Opcode.UADDLV ->
    uaddlv ins insLen bld
  | Opcode.UADDW | Opcode.UADDW2 ->
    uaddw ins insLen bld
  | Opcode.UBFIZ ->
    ubfiz ins insLen bld
  | Opcode.UBFX ->
    ubfx ins insLen bld
  | Opcode.UCVTF ->
    icvtf ins insLen bld true
  | Opcode.UDIV ->
    udiv ins insLen bld
  | Opcode.UMADDL ->
    umaddl ins insLen bld
  | Opcode.UMAX ->
    maxMin ins insLen bld (.>=)
  | Opcode.UMAXP ->
    maxMinp ins insLen bld (.>=)
  | Opcode.UMAXV ->
    maxMinv ins insLen bld (.>=)
  | Opcode.UMIN ->
    maxMin ins insLen bld (.<=)
  | Opcode.UMINP ->
    maxMinp ins insLen bld (.<=)
  | Opcode.UMINV ->
    maxMinv ins insLen bld (.<=)
  | Opcode.UMLAL | Opcode.UMLAL2 ->
    umlal ins insLen bld
  | Opcode.UMLSL | Opcode.UMLSL2 ->
    umlsl ins insLen bld
  | Opcode.UMOV ->
    umov ins insLen bld
  | Opcode.UMSUBL | Opcode.UMNEGL ->
    umsubl ins insLen bld
  | Opcode.UMULH ->
    umulh ins insLen bld
  | Opcode.UMULL | Opcode.UMULL2 ->
    umull ins insLen bld
  | Opcode.UQADD ->
    uqadd ins insLen bld
  | Opcode.UQRSHL ->
    uqrshl ins insLen bld
  | Opcode.UQSHL ->
    uqshl ins insLen bld
  | Opcode.UQSUB ->
    uqsub ins insLen bld
  | Opcode.URSHL ->
    urshl ins insLen bld
  | Opcode.SRSHL ->
    srshl ins insLen bld
  | Opcode.URHADD ->
    urhadd ins insLen bld
  | Opcode.USHL ->
    ushl ins insLen bld
  | Opcode.USHR ->
    shift ins insLen bld (>>)
  | Opcode.USRA ->
    shiftRight ins insLen bld (>>)
  | Opcode.USUBL | Opcode.USUBL2 ->
    usubl ins insLen bld
  | Opcode.USUBW | Opcode.USUBW2 ->
    usubw ins insLen bld
  | Opcode.UXTB ->
    uxtb ins insLen bld
  | Opcode.UXTH ->
    uxth ins insLen bld
  | Opcode.UZP1 ->
    uzp ins insLen bld 0
  | Opcode.UZP2 ->
    uzp ins insLen bld 1
  | Opcode.XTN ->
    xtn ins insLen bld
  | Opcode.XTN2 ->
    xtn2 ins insLen bld
  | Opcode.ZIP1 ->
    zip ins insLen bld true
  | Opcode.ZIP2 ->
    zip ins insLen bld false
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException(Disasm.opCodeToString o)

// vim: set tw=80 sts=2 sw=2:

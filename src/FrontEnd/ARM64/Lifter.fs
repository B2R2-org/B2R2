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
  let addr = ins.Address
  match ins.Opcode with
  | Opcode.ABS ->
    abs ins insLen bld addr
  | Opcode.ADC ->
    adc ins insLen bld addr
  | Opcode.ADCS ->
    adcs ins insLen bld addr
  | Opcode.ADD ->
    add ins insLen bld addr
  | Opcode.ADDHN ->
    addSubHN ins insLen bld addr false (.+)
  | Opcode.ADDHN2 ->
    addSubHN ins insLen bld addr true (.+)
  | Opcode.ADDP ->
    addp ins insLen bld addr
  | Opcode.ADDS ->
    adds ins insLen bld addr
  | Opcode.ADDV ->
    addv ins insLen bld addr
  | Opcode.ADR ->
    adr ins insLen bld addr
  | Opcode.ADRP ->
    adrp ins insLen bld addr
  | Opcode.AND ->
    logAnd ins insLen bld addr
  | Opcode.ANDS ->
    ands ins insLen bld addr
  | Opcode.ASR ->
    asrv ins insLen bld addr
  | Opcode.B ->
    b ins insLen bld addr
  | Opcode.BAL ->
    bCond ins insLen bld addr AL
  | Opcode.BCC ->
    bCond ins insLen bld addr CC
  | Opcode.BCS ->
    bCond ins insLen bld addr CS
  | Opcode.BEQ ->
    bCond ins insLen bld addr EQ
  | Opcode.BFI ->
    bfi ins insLen bld addr
  | Opcode.BFXIL ->
    bfxil ins insLen bld addr
  | Opcode.BGE ->
    bCond ins insLen bld addr GE
  | Opcode.BGT ->
    bCond ins insLen bld addr GT
  | Opcode.BHI ->
    bCond ins insLen bld addr HI
  | Opcode.BIC ->
    bic ins insLen bld addr
  | Opcode.BICS ->
    bics ins insLen bld addr
  | Opcode.BIF ->
    bif ins insLen bld addr
  | Opcode.BIT ->
    bit ins insLen bld addr
  | Opcode.BL ->
    bl ins insLen bld addr
  | Opcode.BLE ->
    bCond ins insLen bld addr LE
  | Opcode.BLR ->
    blr ins insLen bld addr
  | Opcode.BLS ->
    bCond ins insLen bld addr LS
  | Opcode.BLT ->
    bCond ins insLen bld addr LT
  | Opcode.BMI ->
    bCond ins insLen bld addr MI
  | Opcode.BNE ->
    bCond ins insLen bld addr NE
  | Opcode.BNV ->
    bCond ins insLen bld addr NV
  | Opcode.BPL ->
    bCond ins insLen bld addr PL
  | Opcode.BR ->
    br ins insLen bld addr
  | Opcode.BRK ->
    sideEffects ins.Address insLen bld Breakpoint
  | Opcode.BSL ->
    bsl ins insLen bld addr
  | Opcode.BVC ->
    bCond ins insLen bld addr VC
  | Opcode.BVS ->
    bCond ins insLen bld addr VS
  | Opcode.CAS | Opcode.CASA | Opcode.CASL | Opcode.CASAL ->
    compareAndSwap ins insLen bld addr
  | Opcode.CBNZ ->
    cbnz ins insLen bld addr
  | Opcode.CBZ ->
    cbz ins insLen bld addr
  | Opcode.CCMN ->
    ccmn ins insLen bld addr
  | Opcode.CCMP ->
    ccmp ins insLen bld addr
  | Opcode.CLS ->
    cls ins insLen bld addr
  | Opcode.CLZ ->
    clz ins insLen bld addr
  | Opcode.CMEQ ->
    cmeq ins insLen bld addr
  | Opcode.CMGE ->
    cmge ins insLen bld addr
  | Opcode.CMGT ->
    cmgt ins insLen bld addr
  | Opcode.CMHI ->
    cmhi ins insLen bld addr
  | Opcode.CMHS ->
    cmhs ins insLen bld addr
  | Opcode.CMLT ->
    cmlt ins insLen bld addr
  | Opcode.CMN ->
    cmn ins insLen bld addr
  | Opcode.CMP ->
    cmp ins insLen bld addr
  | Opcode.CMTST ->
    cmtst ins insLen bld addr
  | Opcode.CNEG | Opcode.CSNEG ->
    csneg ins insLen bld addr
  | Opcode.CNT ->
    cnt ins insLen bld addr
  | Opcode.CSEL ->
    csel ins insLen bld addr
  | Opcode.CSETM | Opcode.CINV | Opcode.CSINV ->
    csinv ins insLen bld addr
  | Opcode.CSINC | Opcode.CINC | Opcode.CSET ->
    csinc ins insLen bld addr
  | Opcode.CTZ ->
    ctz ins insLen bld addr
  | Opcode.DCZVA ->
    dczva ins insLen bld addr
  | Opcode.CLREX
  | Opcode.DMB | Opcode.DSB | Opcode.ISB ->
    nop ins.Address insLen bld
  | Opcode.DUP ->
    dup ins insLen bld addr
  | Opcode.EOR | Opcode.EON ->
    eor ins insLen bld addr
  | Opcode.EXT ->
    ext ins insLen bld addr
  | Opcode.EXTR | Opcode.ROR ->
    extr ins insLen bld addr
  | Opcode.FABD ->
    fabd ins insLen bld addr
  | Opcode.FABS ->
    fabs ins insLen bld addr
  | Opcode.FADD ->
    fadd ins insLen bld addr
  | Opcode.FADDP ->
    faddp ins insLen bld addr
  | Opcode.FCCMP ->
    fccmp ins insLen bld addr
  | Opcode.FCCMPE ->
    fccmp ins insLen bld addr
  | Opcode.FCMGT ->
    fcmgt ins insLen bld addr
  | Opcode.FCMP ->
    fcmp ins insLen bld addr
  | Opcode.FCMPE ->
    fcmp ins insLen bld addr
  | Opcode.FCSEL ->
    fcsel ins insLen bld addr
  | Opcode.FCVT ->
    fcvt ins insLen bld addr
  | Opcode.FCVTAS ->
    fcvtas ins insLen bld addr
  | Opcode.FCVTAU ->
    fcvtau ins insLen bld addr
  | Opcode.FCVTMS ->
    fcvtms ins insLen bld addr
  | Opcode.FCVTMU ->
    fcvtmu ins insLen bld addr
  | Opcode.FCVTPS ->
    fcvtps ins insLen bld addr
  | Opcode.FCVTPU ->
    fcvtpu ins insLen bld addr
  | Opcode.FCVTZS ->
    fcvtzs ins insLen bld addr
  | Opcode.FCVTZU ->
    fcvtzu ins insLen bld addr
  | Opcode.FDIV ->
    fdiv ins insLen bld addr
  | Opcode.FMADD ->
    fmadd ins insLen bld addr
  | Opcode.FMAX ->
    fmaxmin ins insLen bld addr AST.fgt
  | Opcode.FMAXNM ->
    sideEffects ins.Address insLen bld UnsupportedInstruction
  | Opcode.FMIN ->
    fmaxmin ins insLen bld addr AST.flt
  | Opcode.FMLS ->
    fmls ins insLen bld addr
  | Opcode.FMOV ->
    fmov ins insLen bld addr
  | Opcode.FMSUB ->
    fmsub ins insLen bld addr
  | Opcode.FMUL ->
    fmul ins insLen bld addr
  | Opcode.FNEG ->
    fneg ins insLen bld addr
  | Opcode.FNMSUB ->
    fnmsub ins insLen bld addr
  | Opcode.FNMUL ->
    fnmul ins insLen bld addr
  | Opcode.FRINTA ->
    frinta ins insLen bld addr
  | Opcode.FRINTM ->
    frintm ins insLen bld addr
  | Opcode.FRINTP ->
    frintp ins insLen bld addr
  | Opcode.FRINTI ->
    frinti ins insLen bld addr
  | Opcode.FRINTN ->
    frintn ins insLen bld addr
  | Opcode.FRINTX ->
    frintx ins insLen bld addr
  | Opcode.FRINTZ ->
    frintz ins insLen bld addr
  | Opcode.FSQRT ->
    fsqrt ins insLen bld addr
  | Opcode.FSUB ->
    fsub ins insLen bld addr
  | Opcode.HINT ->
    nop ins.Address insLen bld
  | Opcode.INS ->
    insv ins insLen bld addr
  | Opcode.LD1 | Opcode.LD2 | Opcode.LD3 | Opcode.LD4 ->
    loadStoreList ins insLen bld addr true
  | Opcode.LD1R | Opcode.LD2R | Opcode.LD3R | Opcode.LD4R ->
    loadRep ins insLen bld addr
  | Opcode.LDAR ->
    ldar ins insLen bld addr
  | Opcode.LDARB ->
    ldarb ins insLen bld addr
  | Opcode.LDAXP | Opcode.LDXP ->
    ldaxp ins insLen bld addr
  | Opcode.LDAXR | Opcode.LDXR ->
    ldaxr ins insLen bld addr
  | Opcode.LDAXRB | Opcode.LDXRB ->
    ldax ins insLen bld addr 8<rt>
  | Opcode.LDAXRH | Opcode.LDXRH ->
    ldax ins insLen bld addr 16<rt>
  | Opcode.LDNP ->
    ldnp ins insLen bld addr
  | Opcode.LDP ->
    ldp ins insLen bld addr
  | Opcode.LDPSW ->
    ldpsw ins insLen bld addr
  | Opcode.LDR ->
    ldr ins insLen bld addr
  | Opcode.LDRB ->
    ldrb ins insLen bld addr
  | Opcode.LDRH ->
    ldrh ins insLen bld addr
  | Opcode.LDRSB ->
    ldrsb ins insLen bld addr
  | Opcode.LDRSH ->
    ldrsh ins insLen bld addr
  | Opcode.LDRSW ->
    ldrsw ins insLen bld addr
  | Opcode.LDUR ->
    ldur ins insLen bld addr
  | Opcode.LDURB ->
    ldurb ins insLen bld addr
  | Opcode.LDURH ->
    ldurh ins insLen bld addr
  | Opcode.LDURSB ->
    ldursb ins insLen bld addr
  | Opcode.LDURSH ->
    ldursh ins insLen bld addr
  | Opcode.LDURSW ->
    ldursw ins insLen bld addr
  | Opcode.LSL ->
    distLogicalLeftShift ins insLen bld addr
  | Opcode.LSR ->
    distLogicalRightShift ins insLen bld addr
  | Opcode.MADD ->
    madd ins insLen bld addr
  | Opcode.MLA ->
    mladdsub ins insLen bld addr (.+)
  | Opcode.MLS ->
    mladdsub ins insLen bld addr (.-)
  | Opcode.MNEG ->
    msub ins insLen bld addr
  | Opcode.MOV ->
    mov ins insLen bld addr
  | Opcode.MOVI ->
    movi ins insLen bld addr
  | Opcode.MOVK ->
    movk ins insLen bld addr
  | Opcode.MOVN ->
    movn ins insLen bld addr
  | Opcode.MOVZ ->
    movz ins insLen bld addr
  | Opcode.MRS ->
    mrs ins insLen bld addr
  | Opcode.MSR ->
    msr ins insLen bld addr
  | Opcode.MSUB ->
    msub ins insLen bld addr
  | Opcode.MUL ->
    madd ins insLen bld addr
  | Opcode.MVN ->
    orn ins insLen bld addr
  | Opcode.MVNI ->
    mvni ins insLen bld addr
  | Opcode.NEG ->
    sub ins insLen bld addr
  | Opcode.NEGS ->
    subs ins insLen bld addr
  | Opcode.NOT ->
    orn ins insLen bld addr
  | Opcode.NOP ->
    nop ins.Address insLen bld
  | Opcode.ORN ->
    orn ins insLen bld addr
  | Opcode.ORR ->
    orr ins insLen bld addr
  | Opcode.PRFM | Opcode.PRFUM ->
    nop ins.Address insLen bld
  | Opcode.RBIT ->
    rbit ins insLen bld addr
  | Opcode.RET ->
    ret ins insLen bld addr
  | Opcode.REV ->
    rev ins insLen bld addr
  | Opcode.REV16 ->
    rev16 ins insLen bld addr
  | Opcode.REV32 ->
    rev32 ins insLen bld addr
  | Opcode.REV64 ->
    rev ins insLen bld addr
  | Opcode.RORV ->
    rorv ins insLen bld addr
  | Opcode.SADDL | Opcode.SADDL2 ->
    saddl ins insLen bld addr
  | Opcode.SADDW | Opcode.SADDW2 ->
    saddw ins insLen bld addr
  | Opcode.SADDLP ->
    saddlp ins insLen bld addr
  | Opcode.SADDLV ->
    saddlv ins insLen bld addr
  | Opcode.SBC ->
    sbc ins insLen bld addr
  | Opcode.SBCS ->
    sbcs ins insLen bld addr
  | Opcode.SBFIZ ->
    sbfiz ins insLen bld addr
  | Opcode.SBFX ->
    sbfx ins insLen bld addr
  | Opcode.SCVTF ->
    icvtf ins insLen bld addr false
  | Opcode.SDIV ->
    sdiv ins insLen bld addr
  | Opcode.SHL ->
    shl ins insLen bld addr
  | Opcode.SHRN ->
    shrn ins insLen bld addr false
  | Opcode.SHRN2 ->
    shrn ins insLen bld addr true
  | Opcode.SMADDL ->
    smaddl ins insLen bld addr
  | Opcode.SMOV ->
    smov ins insLen bld addr
  | Opcode.SMSUBL | Opcode.SMNEGL ->
    smsubl ins insLen bld addr
  | Opcode.SMULH ->
    smulh ins insLen bld addr
  | Opcode.SMULL | Opcode.SMULL2 ->
    smull ins insLen bld addr
  | Opcode.SSHL ->
    sshl ins insLen bld addr
  | Opcode.UXTL | Opcode.UXTL2 | Opcode.USHLL | Opcode.USHLL2 ->
    shiftULeftLong ins insLen bld addr
  | Opcode.SXTL | Opcode.SXTL2 | Opcode.SSHLL | Opcode.SSHLL2 ->
    shiftSLeftLong ins insLen bld addr
  | Opcode.SSHR ->
    shift ins insLen bld addr (?>>)
  | Opcode.SSRA ->
    shiftRight ins insLen bld addr (?>>)
  | Opcode.SSUBL | Opcode.SSUBL2 ->
    ssubl ins insLen bld addr
  | Opcode.SSUBW | Opcode.SSUBW2 ->
    ssubw ins insLen bld addr
  | Opcode.SMAX ->
    maxMin ins insLen bld addr (?>=)
  | Opcode.SMAXP ->
    maxMinp ins insLen bld addr (?>=)
  | Opcode.SMAXV ->
    maxMinv ins insLen bld addr (?>=)
  | Opcode.SMIN ->
    maxMin ins insLen bld addr (?<=)
  | Opcode.SMINP ->
    maxMinp ins insLen bld addr (?<=)
  | Opcode.SMINV ->
    maxMinv ins insLen bld addr (?<=)
  | Opcode.SMLAL | Opcode.SMLAL2 ->
    smlal ins insLen bld addr
  | Opcode.SMLSL | Opcode.SMLSL2 ->
    smlsl ins insLen bld addr
  | Opcode.SQDMULH ->
    sqdmulh ins insLen bld addr
  | Opcode.SQDMULL | Opcode.SQDMULL2 ->
    sqdmull ins insLen bld addr
  | Opcode.SQDMLAL | Opcode.SQDMLAL2 ->
    sqdmlal ins insLen bld addr
  | Opcode.ST1 | Opcode.ST2 | Opcode.ST3 | Opcode.ST4 ->
    loadStoreList ins insLen bld addr false
  | Opcode.STLR ->
    stlr ins insLen bld addr
  | Opcode.STLRB ->
    stlrb ins insLen bld addr
  | Opcode.STLXP | Opcode.STXP ->
    stlxp ins insLen bld addr
  | Opcode.STLXR | Opcode.STXR ->
    stlxr ins insLen bld addr
  | Opcode.STLXRB | Opcode.STXRB ->
    stlx ins insLen bld addr 8<rt>
  | Opcode.STLXRH | Opcode.STXRH ->
    stlx ins insLen bld addr 16<rt>
  | Opcode.STNP ->
    stnp ins insLen bld addr
  | Opcode.STP ->
    stp ins insLen bld addr
  | Opcode.STR ->
    str ins insLen bld addr
  | Opcode.STRB ->
    strb ins insLen bld addr
  | Opcode.STRH ->
    strh ins insLen bld addr
  | Opcode.STTRB ->
    sttrb ins insLen bld addr
  | Opcode.STUR ->
    stur ins insLen bld addr
  | Opcode.STURB ->
    sturb ins insLen bld addr
  | Opcode.STURH ->
    sturh ins insLen bld addr
  | Opcode.SUB ->
    sub ins insLen bld addr
  | Opcode.SUBHN ->
    addSubHN ins insLen bld addr false (.-)
  | Opcode.SUBHN2 ->
    addSubHN ins insLen bld addr true (.-)
  | Opcode.SUBS ->
    subs ins insLen bld addr
  | Opcode.SVC ->
    svc ins insLen bld
  | Opcode.SXTB ->
    sxtb ins insLen bld addr
  | Opcode.SXTH ->
    sxth ins insLen bld addr
  | Opcode.SXTW ->
    sxtw ins insLen bld addr
  | Opcode.TBL ->
    tbl ins insLen bld addr
  | Opcode.TBNZ ->
    tbnz ins insLen bld addr
  | Opcode.TBZ ->
    tbz ins insLen bld addr
  | Opcode.TRN1 ->
    trn1 ins insLen bld addr
  | Opcode.TRN2 ->
    trn2 ins insLen bld addr
  | Opcode.TST ->
    tst ins insLen bld addr
  | Opcode.UABAL | Opcode.UABAL2 ->
    uabal ins insLen bld addr
  | Opcode.UABDL | Opcode.UABDL2 ->
    uabdl ins insLen bld addr
  | Opcode.UADALP ->
    uadalp ins insLen bld addr
  | Opcode.UADDL | Opcode.UADDL2 ->
    uaddl ins insLen bld addr
  | Opcode.UADDLP ->
    uaddlp ins insLen bld addr
  | Opcode.UADDLV ->
    uaddlv ins insLen bld addr
  | Opcode.UADDW | Opcode.UADDW2 ->
    uaddw ins insLen bld addr
  | Opcode.UBFIZ ->
    ubfiz ins insLen bld addr
  | Opcode.UBFX ->
    ubfx ins insLen bld addr
  | Opcode.UCVTF ->
    icvtf ins insLen bld addr true
  | Opcode.UDIV ->
    udiv ins insLen bld addr
  | Opcode.UMADDL ->
    umaddl ins insLen bld addr
  | Opcode.UMAX ->
    maxMin ins insLen bld addr (.>=)
  | Opcode.UMAXP ->
    maxMinp ins insLen bld addr (.>=)
  | Opcode.UMAXV ->
    maxMinv ins insLen bld addr (.>=)
  | Opcode.UMIN ->
    maxMin ins insLen bld addr (.<=)
  | Opcode.UMINP ->
    maxMinp ins insLen bld addr (.<=)
  | Opcode.UMINV ->
    maxMinv ins insLen bld addr (.<=)
  | Opcode.UMLAL | Opcode.UMLAL2 ->
    umlal ins insLen bld addr
  | Opcode.UMLSL | Opcode.UMLSL2 ->
    umlsl ins insLen bld addr
  | Opcode.UMOV ->
    umov ins insLen bld addr
  | Opcode.UMSUBL | Opcode.UMNEGL ->
    umsubl ins insLen bld addr
  | Opcode.UMULH ->
    umulh ins insLen bld addr
  | Opcode.UMULL | Opcode.UMULL2 ->
    umull ins insLen bld addr
  | Opcode.UQADD ->
    uqadd ins insLen bld addr
  | Opcode.UQRSHL ->
    uqrshl ins insLen bld addr
  | Opcode.UQSHL ->
    uqshl ins insLen bld addr
  | Opcode.UQSUB ->
    uqsub ins insLen bld addr
  | Opcode.URSHL ->
    urshl ins insLen bld addr
  | Opcode.SRSHL ->
    srshl ins insLen bld addr
  | Opcode.URHADD ->
    urhadd ins insLen bld addr
  | Opcode.USHL ->
    ushl ins insLen bld addr
  | Opcode.USHR ->
    shift ins insLen bld addr (>>)
  | Opcode.USRA ->
    shiftRight ins insLen bld addr (>>)
  | Opcode.USUBL | Opcode.USUBL2 ->
    usubl ins insLen bld addr
  | Opcode.USUBW | Opcode.USUBW2 ->
    usubw ins insLen bld addr
  | Opcode.UXTB ->
    uxtb ins insLen bld addr
  | Opcode.UXTH ->
    uxth ins insLen bld addr
  | Opcode.UZP1 ->
    uzp ins insLen bld addr 0
  | Opcode.UZP2 ->
    uzp ins insLen bld addr 1
  | Opcode.XTN ->
    xtn ins insLen bld addr
  | Opcode.XTN2 ->
    xtn2 ins insLen bld addr
  | Opcode.ZIP1 ->
    zip ins insLen bld addr true
  | Opcode.ZIP2 ->
    zip ins insLen bld addr false
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException(Disasm.opCodeToString o)

// vim: set tw=80 sts=2 sw=2:

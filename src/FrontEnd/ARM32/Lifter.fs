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

module internal B2R2.FrontEnd.ARM32.Lifter

open System
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM32
open B2R2.FrontEnd.ARM32.IRHelper
open B2R2.FrontEnd.ARM32.LiftingUtils
open B2R2.FrontEnd.ARM32.GeneralLifter
open B2R2.FrontEnd.ARM32.NEONLifter
open B2R2.FrontEnd.ARM32.SystemLifter

/// Translate IR.
let translate (ins: Instruction) bld =
  match ins.Opcode with
  | _ when FP16Lifter.handles ins ->
    FP16Lifter.translate ins bld
  | Op.ADC ->
    adc false ins bld
  | Op.ADCS ->
    adcs true ins bld
  | Op.ADD | Op.ADDW ->
    add false ins bld
  | Op.ADDS ->
    adds true ins bld
  | Op.ADR ->
    adr ins bld (* for Thumb mode *)
  | Op.AESD ->
    CryptoLifter.aesRound ins bld true
  | Op.AESE ->
    CryptoLifter.aesRound ins bld false
  | Op.AESIMC ->
    CryptoLifter.aesMixColumns ins bld true
  | Op.AESMC ->
    CryptoLifter.aesMixColumns ins bld false
  | Op.AND ->
    logicalAnd false ins bld
  | Op.ANDS ->
    ands true ins bld
  | Op.ASR ->
    shiftInstr false ins ShiftOp.ASR bld
  | Op.ASRS ->
    asrs true ins bld
  | Op.B ->
    b ins bld
  | Op.BFC ->
    bfc ins bld
  | Op.BFI ->
    bfi ins bld
  | Op.BIC ->
    bic false ins bld
  | Op.BICS ->
    bics true ins bld
  | Op.BKPT ->
    sideEffects ins bld Breakpoint
  | Op.BL ->
    bl ins bld
  | Op.BLX ->
    branchWithLink ins bld
  | Op.BX ->
    bx ins bld
  | Op.BXJ ->
    bx ins bld
  | Op.CBNZ ->
    cbz true ins bld
  | Op.CBZ ->
    cbz false ins bld
  | Op.CDP | Op.CDP2 | Op.LDC | Op.LDC2 | Op.LDC2L | Op.LDCL | Op.MCR2
  | Op.MCRR | Op.MCRR2 | Op.MRC2 | Op.MRRC | Op.MRRC2 | Op.STC
  | Op.STC2 | Op.STC2L | Op.STCL ->
    (* coprocessor instructions *)
    unsupported ins bld
  | Op.CLREX ->
    clrex ins bld
  | Op.CLZ ->
    clz ins bld
  | Op.CMN ->
    cmn ins bld
  | Op.CMP ->
    cmp ins bld
  | Op.CPS | Op.CPSID | Op.CPSIE ->
    cps ins bld
  | Op.CRC32B ->
    crc32 ins bld false 8<rt>
  | Op.CRC32H ->
    crc32 ins bld false 16<rt>
  | Op.CRC32W ->
    crc32 ins bld false 32<rt>
  | Op.CRC32CB ->
    crc32 ins bld true 8<rt>
  | Op.CRC32CH ->
    crc32 ins bld true 16<rt>
  | Op.CRC32CW ->
    crc32 ins bld true 32<rt>
  | Op.DMB | Op.DSB | Op.ISB | Op.PLD | Op.PLI | Op.PLDW ->
    nop ins bld
  | Op.EOR ->
    eor false ins bld
  | Op.EORS ->
    eors true ins bld
  | Op.ERET ->
    eret ins bld
  | Op.IT | Op.ITT | Op.ITE | Op.ITTT | Op.ITET | Op.ITTE | Op.ITEE | Op.ITTTT
  | Op.ITETT | Op.ITTET | Op.ITEET | Op.ITTTE | Op.ITETE | Op.ITTEE
  | Op.ITEEE ->
    it ins bld
  (* Load-acquire: with one observer, the order it promises shows nowhere *)
  | Op.LDA ->
    ldr ins bld 32<rt> AST.zext
  | Op.LDAB ->
    ldr ins bld 8<rt> AST.zext
  | Op.LDAH ->
    ldr ins bld 16<rt> AST.zext
  | Op.LDM ->
    ldm Op.LDM ins bld (.+)
  | Op.LDMDA ->
    ldm Op.LDMDA ins bld (.-)
  | Op.LDMDB ->
    ldm Op.LDMDB ins bld (.-)
  | Op.LDMIA ->
    ldm Op.LDMIA ins bld (.+)
  | Op.LDMIB ->
    ldm Op.LDMIB ins bld (.+)
  | Op.LDR ->
    ldr ins bld 32<rt> AST.zext
  | Op.LDRB ->
    ldr ins bld 8<rt> AST.zext
  | Op.LDRBT ->
    ldr ins bld 8<rt> AST.zext
  | Op.LDRD ->
    ldrd ins bld
  | Op.LDREX | Op.LDAEX ->
    ldrex ins bld 32<rt>
  | Op.LDREXB | Op.LDAEXB ->
    ldrex ins bld 8<rt>
  | Op.LDREXH | Op.LDAEXH ->
    ldrex ins bld 16<rt>
  | Op.LDREXD | Op.LDAEXD ->
    ldrexd ins bld
  | Op.LDRH ->
    ldr ins bld 16<rt> AST.zext
  | Op.LDRHT ->
    ldr ins bld 16<rt> AST.zext
  | Op.LDRSB ->
    ldr ins bld 8<rt> AST.sext
  | Op.LDRSBT ->
    ldr ins bld 8<rt> AST.sext
  | Op.LDRSH ->
    ldr ins bld 16<rt> AST.sext
  | Op.LDRSHT ->
    ldr ins bld 16<rt> AST.sext
  | Op.LDRT ->
    ldr ins bld 32<rt> AST.zext
  | Op.LSL ->
    shiftInstr false ins ShiftOp.LSL bld
  | Op.LSLS ->
    lsls true ins bld
  | Op.LSR ->
    shiftInstr false ins ShiftOp.LSR bld
  | Op.LSRS ->
    lsrs true ins bld
  | Op.MLA ->
    mla false ins bld
  | Op.MLAS ->
    mla true ins bld
  | Op.MLS ->
    mls ins bld
  | Op.MOV | Op.MOVW ->
    mov false ins bld
  | Op.MOVS ->
    movs true ins bld
  | Op.MOVT ->
    movt ins bld
  | Op.MRS ->
    mrs ins bld
  | Op.MSR ->
    msr ins bld
  | Op.MRC ->
    mrc ins bld
  | Op.MCR ->
    mcr ins bld
  | Op.MUL ->
    mul false ins bld
  | Op.MULS ->
    mul true ins bld
  | Op.MVN ->
    mvn false ins bld
  | Op.MVNS ->
    mvns true ins bld
  | Op.NOP ->
    nop ins bld
  | Op.CSDB | Op.DBG | Op.ESB | Op.SB | Op.SEV | Op.SEVL | Op.TSB | Op.WFE
  | Op.WFI | Op.YIELD ->
    nop ins bld
  | Op.ORN ->
    orn false ins bld
  | Op.ORNS ->
    orns true ins bld
  | Op.ORR ->
    orr false ins bld
  | Op.ORRS ->
    orrs true ins bld
  | Op.PKHBT ->
    pkh ins bld false
  | Op.PKHTB ->
    pkh ins bld true
  | Op.POP ->
    pop ins bld
  | Op.PUSH ->
    push ins bld
  | Op.SADD16 ->
    parallelAddSub ins bld 16 false WrappingLane ParallelAdd
  | Op.SASX ->
    parallelAddSub ins bld 16 false WrappingLane AddSubExchange
  | Op.SSAX ->
    parallelAddSub ins bld 16 false WrappingLane SubAddExchange
  | Op.SSUB16 ->
    parallelAddSub ins bld 16 false WrappingLane ParallelSub
  | Op.SADD8 ->
    parallelAddSub ins bld 8 false WrappingLane ParallelAdd
  | Op.SSUB8 ->
    parallelAddSub ins bld 8 false WrappingLane ParallelSub
  | Op.QADD16 ->
    parallelAddSub ins bld 16 false SaturatingLane ParallelAdd
  | Op.QASX ->
    parallelAddSub ins bld 16 false SaturatingLane AddSubExchange
  | Op.QSAX ->
    parallelAddSub ins bld 16 false SaturatingLane SubAddExchange
  | Op.QSUB16 ->
    parallelAddSub ins bld 16 false SaturatingLane ParallelSub
  | Op.QADD8 ->
    parallelAddSub ins bld 8 false SaturatingLane ParallelAdd
  | Op.QSUB8 ->
    parallelAddSub ins bld 8 false SaturatingLane ParallelSub
  | Op.SHA1C ->
    CryptoLifter.sha1c ins bld
  | Op.SHA1H ->
    CryptoLifter.sha1h ins bld
  | Op.SHA1M ->
    CryptoLifter.sha1m ins bld
  | Op.SHA1P ->
    CryptoLifter.sha1p ins bld
  | Op.SHA1SU0 ->
    CryptoLifter.sha1su0 ins bld
  | Op.SHA1SU1 ->
    CryptoLifter.sha1su1 ins bld
  | Op.SHA256H ->
    CryptoLifter.sha256Hash ins bld true
  | Op.SHA256H2 ->
    CryptoLifter.sha256Hash ins bld false
  | Op.SHA256SU0 ->
    CryptoLifter.sha256su0 ins bld
  | Op.SHA256SU1 ->
    CryptoLifter.sha256su1 ins bld
  | Op.SHADD16 ->
    parallelAddSub ins bld 16 false HalvingLane ParallelAdd
  | Op.SHASX ->
    parallelAddSub ins bld 16 false HalvingLane AddSubExchange
  | Op.SHSAX ->
    parallelAddSub ins bld 16 false HalvingLane SubAddExchange
  | Op.SHSUB16 ->
    parallelAddSub ins bld 16 false HalvingLane ParallelSub
  | Op.SHADD8 ->
    parallelAddSub ins bld 8 false HalvingLane ParallelAdd
  | Op.SHSUB8 ->
    parallelAddSub ins bld 8 false HalvingLane ParallelSub
  | Op.UADD16 ->
    parallelAddSub ins bld 16 true WrappingLane ParallelAdd
  | Op.UASX ->
    parallelAddSub ins bld 16 true WrappingLane AddSubExchange
  | Op.USAX ->
    parallelAddSub ins bld 16 true WrappingLane SubAddExchange
  | Op.USUB16 ->
    parallelAddSub ins bld 16 true WrappingLane ParallelSub
  | Op.UADD8 ->
    parallelAddSub ins bld 8 true WrappingLane ParallelAdd
  | Op.USUB8 ->
    parallelAddSub ins bld 8 true WrappingLane ParallelSub
  | Op.UQADD16 ->
    parallelAddSub ins bld 16 true SaturatingLane ParallelAdd
  | Op.UQASX ->
    parallelAddSub ins bld 16 true SaturatingLane AddSubExchange
  | Op.UQSAX ->
    parallelAddSub ins bld 16 true SaturatingLane SubAddExchange
  | Op.UQSUB16 ->
    parallelAddSub ins bld 16 true SaturatingLane ParallelSub
  | Op.UQADD8 ->
    parallelAddSub ins bld 8 true SaturatingLane ParallelAdd
  | Op.UQSUB8 ->
    parallelAddSub ins bld 8 true SaturatingLane ParallelSub
  | Op.UHADD16 ->
    parallelAddSub ins bld 16 true HalvingLane ParallelAdd
  | Op.UHASX ->
    parallelAddSub ins bld 16 true HalvingLane AddSubExchange
  | Op.UHSAX ->
    parallelAddSub ins bld 16 true HalvingLane SubAddExchange
  | Op.UHSUB16 ->
    parallelAddSub ins bld 16 true HalvingLane ParallelSub
  | Op.UHADD8 ->
    parallelAddSub ins bld 8 true HalvingLane ParallelAdd
  | Op.UHSUB8 ->
    parallelAddSub ins bld 8 true HalvingLane ParallelSub
  | Op.QADD ->
    qaddsub ins bld false
  | Op.QSUB ->
    qaddsub ins bld true
  | Op.QDADD ->
    qdadd ins bld
  | Op.QDSUB ->
    qdsub ins bld
  | Op.RBIT ->
    rbit ins bld
  | Op.REV ->
    rev ins bld
  | Op.REV16 ->
    rev16 ins bld
  | Op.REVSH ->
    revsh ins bld
  | Op.RFEDA | Op.RFEDB | Op.RFEIA | Op.RFEIB ->
    rfe ins bld
  | Op.ROR ->
    shiftInstr false ins ShiftOp.ROR bld
  | Op.RORS ->
    rors true ins bld
  | Op.RRX ->
    shiftInstr false ins ShiftOp.RRX bld
  | Op.RRXS ->
    rrxs true ins bld
  | Op.RSB ->
    rsb false ins bld
  | Op.RSBS ->
    rsbs true ins bld
  | Op.RSC ->
    rsc false ins bld
  | Op.RSCS ->
    rscs true ins bld
  | Op.SBC ->
    sbc false ins bld
  | Op.SBCS ->
    sbcs true ins bld
  | Op.SBFX ->
    bfx ins bld true
  | Op.SEL ->
    sel ins bld
  | Op.SMLABB ->
    smulacchalf ins bld false false
  | Op.SMLABT ->
    smulacchalf ins bld false true
  | Op.SMLAL ->
    smulandacc false true ins bld
  | Op.SMLALS ->
    smulandacc true true ins bld
  | Op.SMLATB ->
    smulacchalf ins bld true false
  | Op.SMLATT ->
    smulacchalf ins bld true true
  (* All four halves of the matrix. BB and TB were missing while BT and TT
     were present, so a block containing either died in the raising
     fall-through -- and the lifter behind them already takes both
     half-selectors. The non-long SMLABB/BT/TB/TT above are all four wired. *)
  | Op.SMLALBB ->
    smulacclonghalf ins bld false false
  | Op.SMLALBT ->
    smulacclonghalf ins bld false true
  | Op.SMLALTB ->
    smulacclonghalf ins bld true false
  | Op.SMLALTT ->
    smulacclonghalf ins bld true true
  | Op.SMLAD ->
    smuldual ins bld false false
  | Op.SMLADX ->
    smuldual ins bld true false
  | Op.SMLSD ->
    smuldual ins bld false true
  | Op.SMLSDX ->
    smuldual ins bld true true
  | Op.SMUAD ->
    smuldual ins bld false false
  | Op.SMUADX ->
    smuldual ins bld true false
  | Op.SMUSD ->
    smuldual ins bld false true
  | Op.SMUSDX ->
    smuldual ins bld true true
  | Op.SMLALD ->
    smulacclongdual ins bld false false
  | Op.SMLALDX ->
    smulacclongdual ins bld true false
  | Op.SMLSLD ->
    smulacclongdual ins bld false true
  | Op.SMLSLDX ->
    smulacclongdual ins bld true true
  | Op.SMMLS ->
    smmls ins bld false
  | Op.SMMLSR ->
    smmls ins bld true
  | Op.SMULWB ->
    smulwordbyhalf ins bld false
  | Op.SMULWT ->
    smulwordbyhalf ins bld true
  | Op.SMLAWB ->
    smulaccwordbyhalf ins bld false
  | Op.SMLAWT ->
    smulaccwordbyhalf ins bld true
  | Op.SMMLA ->
    smmla ins bld false
  | Op.SMMLAR ->
    smmla ins bld true
  | Op.SMMUL ->
    smmul ins bld false
  | Op.SMMULR ->
    smmul ins bld true
  | Op.SMULBB ->
    smulhalf ins bld false false
  | Op.SMULBT ->
    smulhalf ins bld false true
  | Op.SMULL ->
    smulandacc false false ins bld
  | Op.SMULLS ->
    smulandacc true false ins bld
  | Op.SMULTB ->
    smulhalf ins bld true false
  | Op.SMULTT ->
    smulhalf ins bld true true
  | Op.SRSDA | Op.SRSDB | Op.SRSIA | Op.SRSIB ->
    srs ins bld
  (* Store-release, for the same reason a plain store *)
  | Op.STL ->
    str ins bld 32<rt>
  | Op.STLB ->
    str ins bld 8<rt>
  | Op.STLH ->
    str ins bld 16<rt>
  | Op.STM ->
    stm Op.STM ins bld (.+)
  | Op.STMDA ->
    stm Op.STMDA ins bld (.-)
  | Op.STMDB ->
    stm Op.STMDB ins bld (.-)
  | Op.STMEA ->
    stm Op.STMIA ins bld (.+)
  | Op.STMIA ->
    stm Op.STMIA ins bld (.+)
  | Op.STMIB ->
    stm Op.STMIB ins bld (.+)
  | Op.STR ->
    str ins bld 32<rt>
  | Op.STRB ->
    str ins bld 8<rt>
  | Op.STRBT ->
    str ins bld 8<rt>
  | Op.STRD ->
    strd ins bld
  | Op.STREX | Op.STLEX ->
    strex ins bld 32<rt>
  | Op.STREXB | Op.STLEXB ->
    strex ins bld 8<rt>
  | Op.STREXD | Op.STLEXD ->
    strexd ins bld
  | Op.STREXH | Op.STLEXH ->
    strex ins bld 16<rt>
  | Op.STRH ->
    str ins bld 16<rt>
  | Op.STRHT ->
    str ins bld 16<rt>
  | Op.STRT ->
    str ins bld 32<rt>
  | Op.SUB | Op.SUBW ->
    sub false ins bld
  | Op.SUBS ->
    subs true ins bld
  | Op.SVC ->
    svc ins bld
  | Op.SXTAB ->
    extendAndAdd ins bld AST.sext 8<rt>
  | Op.SXTAH ->
    extendAndAdd ins bld AST.sext 16<rt>
  | Op.SXTB ->
    extend ins bld AST.sext 8<rt>
  | Op.SXTB16 | Op.SXTAB16 ->
    extendHalves ins bld AST.sext
  | Op.SSAT ->
    satWord ins bld false
  | Op.USAT ->
    satWord ins bld true
  | Op.SSAT16 ->
    satHalves ins bld false
  | Op.USAT16 ->
    satHalves ins bld true
  | Op.USAD8 | Op.USADA8 ->
    usad8 ins bld
  | Op.SDIV ->
    divide ins bld false
  | Op.UDIV ->
    divide ins bld true
  | Op.SWP ->
    swap ins bld 32<rt>
  | Op.SWPB ->
    swap ins bld 8<rt>
  | Op.VBIC ->
    vbic ins bld
  | Op.VEOR ->
    veor ins bld
  | Op.VMVN ->
    vmvn ins bld
  | Op.VSWP ->
    vswp ins bld
  | Op.SXTH ->
    extend ins bld AST.sext 16<rt>
  | Op.TBH | Op.TBB ->
    tableBranch ins bld
  | Op.TEQ ->
    teq ins bld
  | Op.TST ->
    tst ins bld
  | Op.UBFX ->
    bfx ins bld false
  | Op.UDF ->
    udf ins bld
  | Op.UMAAL ->
    umaal ins bld
  | Op.UMLAL ->
    umlal false ins bld
  | Op.UMLALS ->
    umlal true ins bld
  | Op.UMULL ->
    umull false ins bld
  | Op.UMULLS ->
    umull true ins bld
  | Op.UXTAB ->
    extendAndAdd ins bld AST.zext 8<rt>
  | Op.UXTAH ->
    extendAndAdd ins bld AST.zext 16<rt>
  | Op.UXTB ->
    extend ins bld AST.zext 8<rt>
  | Op.UXTB16 | Op.UXTAB16 ->
    extendHalves ins bld AST.zext
  | Op.UXTH ->
    extend ins bld AST.zext 16<rt>
  | Op.VABS when isF32orF64 ins.SIMDTyp ->
    FPLifter.vabs ins bld
  | Op.VABS when isF16orF32orF64 ins.SIMDTyp ->
    vabsf ins bld
  | Op.VABD when isF32orF64 ins.SIMDTyp ->
    FPLifter.vabd ins bld
  | Op.VABD ->
    vabd ins bld
  | Op.VABA ->
    vaba ins bld
  | Op.VABDL ->
    vabdl ins bld
  | Op.VABAL ->
    vabal ins bld
  | Op.VSHRN ->
    vshrn ins bld
  | Op.VABS ->
    vabs ins bld
  | Op.VADD when isF32orF64 ins.SIMDTyp ->
    FPLifter.vadd ins bld
  | Op.VADD when isF16orF32orF64 ins.SIMDTyp ->
    vaddsub ins bld AST.fadd
  | Op.VADD ->
    vaddsub ins bld (.+)
  | Op.VSUBL ->
    vsubl ins bld
  | Op.VADDW ->
    vaddw ins bld
  | Op.VSUBW ->
    vsubw ins bld
  | Op.VMOVL ->
    vmovl ins bld
  | Op.VSHLL ->
    vshll ins bld
  | Op.VADDHN ->
    vaddhn ins bld
  | Op.VSUBHN ->
    vsubhn ins bld
  | Op.VRADDHN ->
    vraddhn ins bld
  | Op.VRSUBHN ->
    vrsubhn ins bld
  | Op.VADDL ->
    vaddl ins bld
  | Op.VAND ->
    vand ins bld
  | Op.VCEQ when isF32orF64 ins.SIMDTyp ->
    FPLifter.vcompare ins bld FloatingPoint.FPEqual false false
  | Op.VCGE when isF32orF64 ins.SIMDTyp ->
    FPLifter.vcompare ins bld FloatingPoint.FPGreaterOrEqual false false
  | Op.VCGT when isF32orF64 ins.SIMDTyp ->
    FPLifter.vcompare ins bld FloatingPoint.FPGreater false false
  | Op.VCLE when isF32orF64 ins.SIMDTyp ->
    FPLifter.vcompare ins bld FloatingPoint.FPGreaterOrEqual true false
  | Op.VCLT when isF32orF64 ins.SIMDTyp ->
    FPLifter.vcompare ins bld FloatingPoint.FPGreater true false
  | Op.VACGE when isF32orF64 ins.SIMDTyp ->
    FPLifter.vcompare ins bld FloatingPoint.FPGreaterOrEqual false true
  | Op.VACGT when isF32orF64 ins.SIMDTyp ->
    FPLifter.vcompare ins bld FloatingPoint.FPGreater false true
  | Op.VACLE when isF32orF64 ins.SIMDTyp ->
    FPLifter.vcompare ins bld FloatingPoint.FPGreaterOrEqual true true
  | Op.VACLT when isF32orF64 ins.SIMDTyp ->
    FPLifter.vcompare ins bld FloatingPoint.FPGreater true true
  | Op.VACGE | Op.VACGT | Op.VACLE | Op.VACLT ->
    unsupported ins bld
  | Op.VRECPE when isF32orF64 ins.SIMDTyp ->
    FPLifter.vestimateF32 ins bld false
  | Op.VRECPE ->
    vrecpe ins bld
  | Op.VRSQRTE when isF32orF64 ins.SIMDTyp ->
    FPLifter.vestimateF32 ins bld true
  | Op.VRSQRTE ->
    vrsqrte ins bld
  | Op.VRECPS when isF32orF64 ins.SIMDTyp ->
    FPLifter.vrecpstep ins bld false
  | Op.VRECPS ->
    vrecps ins bld
  | Op.VRSQRTS when isF32orF64 ins.SIMDTyp ->
    FPLifter.vrecpstep ins bld true
  | Op.VRSQRTS ->
    vrsqrts ins bld
  | Op.VCEQ ->
    vceq ins bld
  | Op.VCGE ->
    vcge ins bld
  | Op.VCGT ->
    vcgt ins bld
  | Op.VCLE ->
    vcle ins bld
  | Op.VCLT ->
    vclt ins bld
  | Op.VCLS ->
    vcls ins bld
  | Op.VCNT ->
    vcnt ins bld
  | Op.VBSL ->
    vbsl ins bld
  | Op.VBIT ->
    vbit ins bld
  | Op.VBIF ->
    vbif ins bld
  | Op.VREV16 ->
    vrev16 ins bld
  | Op.VREV32 ->
    vrev32 ins bld
  | Op.VREV64 ->
    vrev64 ins bld
  | Op.VCLZ ->
    vclz ins bld
  | Op.VCADD ->
    FPLifter.vcadd ins bld
  | Op.VCMLA ->
    FPLifter.vcmla ins bld
  | Op.VCVTR ->
    FPLifter.vcvt ins bld false
  | Op.VCVTA ->
    FPv8Lifter.vcvtRounding ins bld FPv8Lifter.TiesAway
  | Op.VCVTN ->
    FPv8Lifter.vcvtRounding ins bld FPv8Lifter.toNearest
  | Op.VCVTP ->
    FPv8Lifter.vcvtRounding ins bld FPv8Lifter.towardPlus
  | Op.VCVTM ->
    FPv8Lifter.vcvtRounding ins bld FPv8Lifter.towardMinus
  | Op.VJCVT ->
    FPv8Lifter.vjcvt ins bld
  | Op.VMAXNM ->
    FPv8Lifter.vmaxminnm ins bld true
  | Op.VMINNM ->
    FPv8Lifter.vmaxminnm ins bld false
  | Op.VRINTA ->
    FPv8Lifter.vrint ins bld FPv8Lifter.TiesAway false
  | Op.VRINTN ->
    FPv8Lifter.vrint ins bld FPv8Lifter.toNearest false
  | Op.VRINTP ->
    FPv8Lifter.vrint ins bld FPv8Lifter.towardPlus false
  | Op.VRINTM ->
    FPv8Lifter.vrint ins bld FPv8Lifter.towardMinus false
  | Op.VRINTZ ->
    FPv8Lifter.vrint ins bld FPv8Lifter.towardZero false
  | Op.VRINTR ->
    FPv8Lifter.vrint ins bld FPv8Lifter.Current false
  | Op.VRINTX ->
    FPv8Lifter.vrint ins bld FPv8Lifter.Current true
  | Op.VSELEQ ->
    FPv8Lifter.vsel ins bld Condition.EQ
  | Op.VSELGE ->
    FPv8Lifter.vsel ins bld Condition.GE
  | Op.VSELGT ->
    FPv8Lifter.vsel ins bld Condition.GT
  | Op.VSELVS ->
    FPv8Lifter.vsel ins bld Condition.VS
  (* The four fused forms, which differ only in which of Sn and Sd they pass
     through FPNeg. The flip is made on the operand, as the manual makes it,
     so that a NaN operand comes out with its sign turned over. *)
  | Op.VFMA when isF32orF64 ins.SIMDTyp ->
    FPLifter.vfma ins bld
  | Op.VFMS when isF32orF64 ins.SIMDTyp ->
    FPLifter.vfms ins bld
  | Op.VFNMA when isF32orF64 ins.SIMDTyp ->
    FPLifter.vfnma ins bld
  | Op.VFNMS when isF32orF64 ins.SIMDTyp ->
    FPLifter.vfnms ins bld
  | Op.VFMA ->
    vfpFusedMulAcc ins bld false false
  | Op.VFMS ->
    vfpFusedMulAcc ins bld true false
  | Op.VFNMA ->
    vfpFusedMulAcc ins bld true true
  | Op.VFNMS ->
    vfpFusedMulAcc ins bld false true
  | Op.VNMUL when isF32orF64 ins.SIMDTyp ->
    FPLifter.vnmul ins bld
  | Op.VNMLA when isF32orF64 ins.SIMDTyp ->
    FPLifter.vnmla ins bld
  | Op.VNMLS when isF32orF64 ins.SIMDTyp ->
    FPLifter.vnmls ins bld
  | Op.VNMUL ->
    vfpMulAcc ins bld (fun sz _ p -> fpNegBits sz p)
  | Op.VNMLA ->
    (* FPAdd(FPNeg(Sd), FPNeg(product)), not FPNeg(FPAdd(Sd, product)). The
       two agree on every finite value and part company on a signed zero:
       negating the sum of +0 and -0 gives -0, while summing their negations
       gives +0. *)
    vfpMulAcc ins bld (fun sz d p ->
      AST.fadd (fpNegBits sz d) (fpNegBits sz p))
  | Op.VNMLS ->
    (* FPAdd(FPNeg(Sd), product). A subtraction agrees on every number and
       hands a NaN accumulator back unflipped. *)
    vfpMulAcc ins bld (fun sz d p -> AST.fadd (fpNegBits sz d) p)
  | Op.VSQRT when isF32orF64 ins.SIMDTyp ->
    FPLifter.vsqrt ins bld
  | Op.VSQRT ->
    vsqrtf ins bld
  | Op.VCMP | Op.VCMPE when isF32orF64 ins.SIMDTyp ->
    FPLifter.vcmp ins bld (ins.Opcode = Op.VCMPE)
  | Op.VCMP | Op.VCMPE ->
    vcmp ins bld
  | Op.VCVT ->
    FPLifter.vcvt ins bld true
  | Op.VDIV when isF32orF64 ins.SIMDTyp ->
    FPLifter.vdiv ins bld
  | Op.VDIV ->
    vdiv ins bld
  | Op.VCVTB ->
    FPLifter.vcvtHalf ins bld false
  | Op.VCVTT ->
    FPLifter.vcvtHalf ins bld true
  | Op.VDUP ->
    vdup ins bld
  | Op.VEXT ->
    vext ins bld
  | Op.VHADD ->
    vhaddsub ins bld (.+)
  | Op.VHSUB ->
    vhaddsub ins bld (.-)
  | Op.VLD1 ->
    vld1 ins bld
  | Op.VLD2 ->
    vld2 ins bld
  | Op.VLD3 ->
    vld3 ins bld
  | Op.VLD4 ->
    vld4 ins bld
  | Op.VLDM | Op.VLDMIA | Op.VLDMDB ->
    vldm ins bld
  | Op.VLDR ->
    vldr ins bld
  | Op.VMAX when isF32orF64 ins.SIMDTyp ->
    FPLifter.vmaxmin ins bld true
  | Op.VMIN when isF32orF64 ins.SIMDTyp ->
    FPLifter.vmaxmin ins bld false
  | Op.VMAX ->
    vmaxmin ins bld true
  | Op.VMIN ->
    vmaxmin ins bld false
  | Op.VMLA when isF32orF64 ins.SIMDTyp ->
    FPLifter.vmla ins bld
  | Op.VMLS when isF32orF64 ins.SIMDTyp ->
    FPLifter.vmls ins bld
  | Op.VMLA when isF16orF32orF64 ins.SIMDTyp ->
    vfpMulAcc ins bld (fun _ d p -> AST.fadd d p)
  | Op.VMLS when isF16orF32orF64 ins.SIMDTyp ->
    (* FPAdd(Sd, FPNeg(product)), for the same reason as VNMLS. *)
    vfpMulAcc ins bld (fun sz d p -> AST.fadd d (fpNegBits sz p))
  | Op.VMLA ->
    vmla ins bld
  | Op.VMLAL ->
    vmlal ins bld
  | Op.VMLS ->
    vmls ins bld
  | Op.VMLSL ->
    vmlsl ins bld
  | Op.VMOV when isF32orF64 ins.SIMDTyp && FPLifter.isVFPMove ins ->
    FPLifter.vmov ins bld
  | Op.VMOV when isF16orF32orF64 ins.SIMDTyp && not (isSIMDF32Imm ins) ->
    vmovfp ins bld
  | Op.VMOV ->
    vmov ins bld
  | Op.VMOVN ->
    vmovn ins bld
  | Op.VMRS ->
    vmrs ins bld
  | Op.VMSR ->
    vmsr ins bld
  | Op.VMUL when isF32orF64 ins.SIMDTyp ->
    FPLifter.vmul ins bld
  | Op.VMUL when isF16orF32orF64 ins.SIMDTyp ->
    vmul ins bld AST.fmul
  | Op.VMUL ->
    vmul ins bld (.*)
  | Op.VMULL ->
    vmull ins bld
  | Op.VNEG when isF32orF64 ins.SIMDTyp ->
    FPLifter.vneg ins bld
  | Op.VNEG ->
    vneg ins bld
  | Op.VORN ->
    vorn ins bld
  | Op.VORR ->
    vorr ins bld
  | Op.VPMAX when isF32orF64 ins.SIMDTyp ->
    FPLifter.vpmaxmin ins bld true
  | Op.VPMIN when isF32orF64 ins.SIMDTyp ->
    FPLifter.vpmaxmin ins bld false
  | Op.VPMAX ->
    vpmax ins bld
  | Op.VPMIN ->
    vpmin ins bld
  | Op.VPADDL ->
    vpaddl ins bld
  | Op.VPADAL ->
    vpadal ins bld
  | Op.VPADD when isF32orF64 ins.SIMDTyp ->
    FPLifter.vpadd ins bld
  | Op.VPADD ->
    vpadd ins bld
  | Op.VPOP ->
    vpop ins bld
  | Op.VPUSH ->
    vpush ins bld
  | Op.VQADD ->
    vqadd ins bld
  | Op.VQSUB ->
    vqsub ins bld
  | Op.VQABS ->
    vqabs ins bld
  | Op.VQNEG ->
    vqneg ins bld
  | Op.VQSHL ->
    vqshl ins bld
  | Op.VQSHLU ->
    vqshlu ins bld
  | Op.VQRSHL ->
    vqrshl ins bld
  | Op.VRSHL ->
    vrshl ins bld
  | Op.VQSHRN ->
    vqshrn ins bld
  | Op.VQRSHRN ->
    vqrshrn ins bld
  | Op.VQSHRUN ->
    vqshrun ins bld
  | Op.VQRSHRUN ->
    vqrshrun ins bld
  | Op.VQDMULH ->
    vqdmulh ins bld
  | Op.VQRDMULH ->
    vqrdmulh ins bld
  | Op.VQRDMLAH ->
    SIMDv8Lifter.vqrdmlah ins bld false
  | Op.VQRDMLSH ->
    SIMDv8Lifter.vqrdmlah ins bld true
  | Op.VSDOT ->
    SIMDv8Lifter.dotProduct ins bld false false
  | Op.VUDOT ->
    SIMDv8Lifter.dotProduct ins bld true true
  | Op.VUSDOT ->
    SIMDv8Lifter.dotProduct ins bld true false
  | Op.VSUDOT ->
    SIMDv8Lifter.dotProduct ins bld false true
  | Op.VSMMLA ->
    SIMDv8Lifter.matMulAdd ins bld false false
  | Op.VUMMLA ->
    SIMDv8Lifter.matMulAdd ins bld true true
  | Op.VUSMMLA ->
    SIMDv8Lifter.matMulAdd ins bld true false
  | Op.VQDMULL ->
    vqdmull ins bld
  | Op.VQDMLAL ->
    vqdmlal ins bld
  | Op.VQDMLSL ->
    vqdmlsl ins bld
  | Op.VQMOVN ->
    vqmovn ins bld
  | Op.VQMOVUN ->
    vqmovun ins bld
  | Op.VRHADD ->
    vrhadd ins bld
  | Op.VRSHR ->
    vrshr ins bld
  | Op.VRSHRN ->
    vrshrn ins bld
  | Op.VSHL ->
    vshl ins bld
  | Op.VSHR ->
    vshr ins bld
  | Op.VRSRA ->
    vrsra ins bld
  | Op.VSLI ->
    vsli ins bld
  | Op.VSRI ->
    vsri ins bld
  | Op.VTRN ->
    vtrn ins bld
  | Op.VZIP ->
    vzip ins bld
  | Op.VSRA ->
    vsra ins bld
  | Op.VST1 ->
    vst1 ins bld
  | Op.VST2 ->
    vst2 ins bld
  | Op.VST3 ->
    vst3 ins bld
  | Op.VST4 ->
    vst4 ins bld
  | Op.VSTM | Op.VSTMIA | Op.VSTMDB ->
    vstm ins bld
  | Op.VSTR ->
    vstr ins bld
  | Op.VSUB when isF32orF64 ins.SIMDTyp ->
    FPLifter.vsub ins bld
  | Op.VSUB when isF16orF32orF64 ins.SIMDTyp ->
    vaddsub ins bld AST.fsub
  | Op.VSUB ->
    vaddsub ins bld (.-)
  | Op.VTBL ->
    vecTbl ins bld true
  | Op.VTBX ->
    vecTbl ins bld false
  | Op.VTST ->
    vtst ins bld
  | Op.VUZP ->
    vuzp ins bld
  (* No parser produces this opcode: an undecodable encoding is reported as a
     parsing failure, so an instruction never carries it this far. *)
  | Op.InvalidOP ->
    Terminator.impossible ()
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException(Disasm.opCodeToString o)

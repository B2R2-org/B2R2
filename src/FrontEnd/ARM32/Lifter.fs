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

/// Translate IR.
let translate (ins: Instruction) bld =
  match ins.Opcode with
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
  | Op.CDP | Op.CDP2 | Op.LDC | Op.LDC2 | Op.LDC2L | Op.LDCL | Op.MCR | Op.MCR2
  | Op.MCRR | Op.MCRR2 | Op.MRC2 | Op.MRRC | Op.MRRC2 | Op.STC
  | Op.STC2 | Op.STC2L | Op.STCL ->
    (* coprocessor instructions *)
    unsupported ins bld
  | Op.CLZ ->
    clz ins bld
  | Op.CMN ->
    cmn ins bld
  | Op.CMP ->
    cmp ins bld
  | Op.CLREX | Op.DMB | Op.DSB | Op.ISB | Op.PLD ->
    nop ins bld
  | Op.EOR ->
    eor false ins bld
  | Op.EORS ->
    eors true ins bld
  | Op.ERET ->
    unsupported ins bld
  | Op.IT | Op.ITT | Op.ITE | Op.ITTT | Op.ITET | Op.ITTE | Op.ITEE | Op.ITTTT
  | Op.ITETT | Op.ITTET | Op.ITEET | Op.ITTTE | Op.ITETE | Op.ITTEE
  | Op.ITEEE ->
    it ins bld
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
  | Op.MSR | Op.MRS ->
    undefined ins bld
  | Op.MRC ->
    mrc ins bld
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
  | Op.QDADD ->
    qdadd ins bld
  | Op.QDSUB ->
    qdsub ins bld
  | Op.QSAX ->
    qsax ins bld
  | Op.QSUB16 ->
    qsub16 ins bld
  | Op.RBIT ->
    rbit ins bld
  | Op.REV ->
    rev ins bld
  | Op.REV16 ->
    rev16 ins bld
  | Op.REVSH ->
    revsh ins bld
  | Op.RFEDB ->
    rfedb ins bld
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
  | Op.SMLALBT ->
    smulacclonghalf ins bld false true
  | Op.SMLALTT ->
    smulacclonghalf ins bld true true
  | Op.SMLALD ->
    smulacclongdual ins bld false
  | Op.SMLALDX ->
    smulacclongdual ins bld true
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
  | Op.SXTH ->
    extend ins bld AST.sext 16<rt>
  | Op.TBH | Op.TBB ->
    tableBranch ins bld
  | Op.TEQ ->
    teq ins bld
  | Op.TST ->
    tst ins bld
  | Op.UADD8 ->
    uadd8 ins bld
  | Op.UASX ->
    uasx ins bld
  | Op.UBFX ->
    bfx ins bld false
  | Op.UDF ->
    udf ins bld
  | Op.UHSUB16 ->
    uhsub16 ins bld
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
  | Op.UQADD16 ->
    uqopr ins bld 16 (.+)
  | Op.UQADD8 ->
    uqopr ins bld 8 (.+)
  | Op.UQSAX ->
    uqsax ins bld
  | Op.UQSUB16 ->
    uqopr ins bld 16 (.-)
  | Op.UQSUB8 ->
    uqopr ins bld 8 (.-)
  | Op.USAX ->
    usax ins bld
  | Op.UXTAB ->
    extendAndAdd ins bld AST.zext 8<rt>
  | Op.UXTAH ->
    extendAndAdd ins bld AST.zext 16<rt>
  | Op.UXTB ->
    extend ins bld AST.zext 8<rt>
  | Op.UXTB16 ->
    uxtb16 ins bld
  | Op.UXTH ->
    extend ins bld AST.zext 16<rt>
  | Op.VABS when isF16orF32orF64 ins.SIMDTyp ->
    vabsf ins bld
  | Op.VABS ->
    vabs ins bld
  | Op.VADD when isF16orF32orF64 ins.SIMDTyp ->
    vaddsub ins bld AST.fadd
  | Op.VADD ->
    vaddsub ins bld (.+)
  | Op.VADDL ->
    vaddl ins bld
  | Op.VAND ->
    vand ins bld
  | Op.VCEQ | Op.VCGE | Op.VCGT | Op.VCLE | Op.VCLT
    when isF32orF64 ins.SIMDTyp ->
    unsupported ins bld
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
  | Op.VCLZ ->
    vclz ins bld
  | Op.VCMLA ->
    unsupported ins bld
  | Op.VACGE | Op.VACGT | Op.VACLE | Op.VACLT | Op.VCVTR ->
    unsupported ins bld
  | Op.VFMA ->
    vfpMulAcc ins bld (fun _ d p -> AST.fadd d p)
  | Op.VFMS ->
    vfpMulAcc ins bld (fun _ d p -> AST.fsub d p)
  | Op.VFNMA ->
    vfpMulAcc ins bld (fun sz d p -> fpNegBits sz (AST.fadd d p))
  | Op.VFNMS ->
    vfpMulAcc ins bld (fun _ d p -> AST.fsub p d)
  | Op.VNMUL ->
    vfpMulAcc ins bld (fun sz _ p -> fpNegBits sz p)
  | Op.VNMLA ->
    vfpMulAcc ins bld (fun sz d p -> fpNegBits sz (AST.fadd d p))
  | Op.VNMLS ->
    vfpMulAcc ins bld (fun _ d p -> AST.fsub p d)
  | Op.VSQRT ->
    vsqrtf ins bld
  | Op.VCMP | Op.VCMPE ->
    vcmp ins bld
  | Op.VCVT ->
    vcvt ins bld
  | Op.VDIV ->
    vdiv ins bld
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
  | Op.VMAX | Op.VMIN when isF32orF64 ins.SIMDTyp ->
    unsupported ins bld
  | Op.VMAX ->
    vmaxmin ins bld true
  | Op.VMIN ->
    vmaxmin ins bld false
  | Op.VMLA when isF16orF32orF64 ins.SIMDTyp ->
    vfpMulAcc ins bld (fun _ d p -> AST.fadd d p)
  | Op.VMLS when isF16orF32orF64 ins.SIMDTyp ->
    vfpMulAcc ins bld (fun _ d p -> AST.fsub d p)
  | Op.VMLA ->
    vmla ins bld
  | Op.VMLAL ->
    vmlal ins bld
  | Op.VMLS ->
    vmls ins bld
  | Op.VMLSL ->
    vmlsl ins bld
  | Op.VMOV when isF16orF32orF64 ins.SIMDTyp ->
    vmovfp ins bld
  | Op.VMOV ->
    vmov ins bld
  | Op.VMOVN ->
    vmovn ins bld
  | Op.VMRS ->
    vmrs ins bld
  | Op.VMSR ->
    vmsr ins bld
  | Op.VMUL when isF16orF32orF64 ins.SIMDTyp ->
    vmul ins bld AST.fmul
  | Op.VMUL ->
    vmul ins bld (.*)
  | Op.VMULL ->
    vmull ins bld
  | Op.VNEG when isF32orF64 ins.SIMDTyp ->
    vnegf ins bld
  | Op.VNEG ->
    vneg ins bld
  | Op.VORN ->
    vorn ins bld
  | Op.VORR ->
    vorr ins bld
  | Op.VPADD when isF32orF64 ins.SIMDTyp ->
    unsupported ins bld
  | Op.VPADD ->
    vpadd ins bld
  | Op.VPOP ->
    vpop ins bld
  | Op.VPUSH ->
    vpush ins bld
  | Op.VRHADD ->
    vrhadd ins bld
  | Op.VRINTP ->
    unsupported ins bld
  | Op.VRSHR ->
    vrshr ins bld
  | Op.VRSHRN ->
    vrshrn ins bld
  | Op.VSHL ->
    vshl ins bld
  | Op.VSHR ->
    vshr ins bld
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

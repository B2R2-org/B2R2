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
let translate (ins: Instruction) insLen bld =
  match ins.Opcode with
  | Op.ADC ->
    adc false ins insLen bld
  | Op.ADCS ->
    adcs true ins insLen bld
  | Op.ADD | Op.ADDW ->
    add false ins insLen bld
  | Op.ADDS ->
    adds true ins insLen bld
  | Op.ADR ->
    adr ins insLen bld (* for Thumb mode *)
  | Op.AND ->
    logicalAnd false ins insLen bld
  | Op.ANDS ->
    ands true ins insLen bld
  | Op.ASR ->
    shiftInstr false ins insLen ShiftOp.ASR bld
  | Op.ASRS ->
    asrs true ins insLen bld
  | Op.B ->
    b ins insLen bld
  | Op.BFC ->
    bfc ins insLen bld
  | Op.BFI ->
    bfi ins insLen bld
  | Op.BIC ->
    bic false ins insLen bld
  | Op.BICS ->
    bics true ins insLen bld
  | Op.BKPT ->
    sideEffects ins insLen bld Breakpoint
  | Op.BL ->
    bl ins insLen bld
  | Op.BLX ->
    branchWithLink ins insLen bld
  | Op.BX ->
    bx ins insLen bld
  | Op.BXJ ->
    bx ins insLen bld
  | Op.CBNZ ->
    cbz true ins insLen bld
  | Op.CBZ ->
    cbz false ins insLen bld
  | Op.CDP | Op.CDP2 | Op.LDC | Op.LDC2 | Op.LDC2L | Op.LDCL | Op.MCR | Op.MCR2
  | Op.MCRR | Op.MCRR2 | Op.MRC2 | Op.MRRC | Op.MRRC2 | Op.STC
  | Op.STC2 | Op.STC2L | Op.STCL ->
    (* coprocessor instructions *)
    sideEffects ins insLen bld UnsupportedInstruction
  | Op.CLZ ->
    clz ins insLen bld
  | Op.CMN ->
    cmn ins insLen bld
  | Op.CMP ->
    cmp ins insLen bld
  | Op.CLREX | Op.DMB | Op.DSB | Op.ISB | Op.PLD ->
    nop ins insLen bld
  | Op.EOR ->
    eor false ins insLen bld
  | Op.EORS ->
    eors true ins insLen bld
  | Op.ERET ->
    sideEffects ins insLen bld UnsupportedInstruction
  | Op.IT | Op.ITT | Op.ITE | Op.ITTT | Op.ITET | Op.ITTE | Op.ITEE | Op.ITTTT
  | Op.ITETT | Op.ITTET | Op.ITEET | Op.ITTTE | Op.ITETE | Op.ITTEE
  | Op.ITEEE ->
    it ins insLen bld
  | Op.LDM ->
    ldm Op.LDM ins insLen bld (.+)
  | Op.LDMDA ->
    ldm Op.LDMDA ins insLen bld (.-)
  | Op.LDMDB ->
    ldm Op.LDMDB ins insLen bld (.-)
  | Op.LDMIA ->
    ldm Op.LDMIA ins insLen bld (.+)
  | Op.LDMIB ->
    ldm Op.LDMIB ins insLen bld (.+)
  | Op.LDR ->
    ldr ins insLen bld 32<rt> AST.zext
  | Op.LDRB ->
    ldr ins insLen bld 8<rt> AST.zext
  | Op.LDRBT ->
    ldr ins insLen bld 8<rt> AST.zext
  | Op.LDRD ->
    ldrd ins insLen bld
  | Op.LDREX | Op.LDAEX ->
    ldrex ins insLen bld 32<rt>
  | Op.LDREXB | Op.LDAEXB ->
    ldrex ins insLen bld 8<rt>
  | Op.LDREXH | Op.LDAEXH ->
    ldrex ins insLen bld 16<rt>
  | Op.LDREXD | Op.LDAEXD ->
    ldrexd ins insLen bld
  | Op.LDRH ->
    ldr ins insLen bld 16<rt> AST.zext
  | Op.LDRHT ->
    ldr ins insLen bld 16<rt> AST.zext
  | Op.LDRSB ->
    ldr ins insLen bld 8<rt> AST.sext
  | Op.LDRSBT ->
    ldr ins insLen bld 8<rt> AST.sext
  | Op.LDRSH ->
    ldr ins insLen bld 16<rt> AST.sext
  | Op.LDRSHT ->
    ldr ins insLen bld 16<rt> AST.sext
  | Op.LDRT ->
    ldr ins insLen bld 32<rt> AST.zext
  | Op.LSL ->
    shiftInstr false ins insLen ShiftOp.LSL bld
  | Op.LSLS ->
    lsls true ins insLen bld
  | Op.LSR ->
    shiftInstr false ins insLen ShiftOp.LSR bld
  | Op.LSRS ->
    lsrs true ins insLen bld
  | Op.MLA ->
    mla false ins insLen bld
  | Op.MLAS ->
    mla true ins insLen bld
  | Op.MLS ->
    mls ins insLen bld
  | Op.MOV | Op.MOVW ->
    mov false ins insLen bld
  | Op.MOVS ->
    movs true ins insLen bld
  | Op.MOVT ->
    movt ins insLen bld
  | Op.MSR | Op.MRS ->
    sideEffects ins insLen bld UndefinedInstruction
  | Op.MRC ->
    mrc ins insLen bld
  | Op.MUL ->
    mul false ins insLen bld
  | Op.MULS ->
    mul true ins insLen bld
  | Op.MVN ->
    mvn false ins insLen bld
  | Op.MVNS ->
    mvns true ins insLen bld
  | Op.NOP ->
    nop ins insLen bld
  | Op.ORN ->
    orn false ins insLen bld
  | Op.ORNS ->
    orns true ins insLen bld
  | Op.ORR ->
    orr false ins insLen bld
  | Op.ORRS ->
    orrs true ins insLen bld
  | Op.PKHBT ->
    pkh ins insLen bld false
  | Op.PKHTB ->
    pkh ins insLen bld true
  | Op.POP ->
    pop ins insLen bld
  | Op.PUSH ->
    push ins insLen bld
  | Op.QDADD ->
    qdadd ins insLen bld
  | Op.QDSUB ->
    qdsub ins insLen bld
  | Op.QSAX ->
    qsax ins insLen bld
  | Op.QSUB16 ->
    qsub16 ins insLen bld
  | Op.RBIT ->
    rbit ins insLen bld
  | Op.REV ->
    rev ins insLen bld
  | Op.REV16 ->
    rev16 ins insLen bld
  | Op.REVSH ->
    revsh ins insLen bld
  | Op.RFEDB ->
    rfedb ins insLen bld
  | Op.ROR ->
    shiftInstr false ins insLen ShiftOp.ROR bld
  | Op.RORS ->
    rors true ins insLen bld
  | Op.RRX ->
    shiftInstr false ins insLen ShiftOp.RRX bld
  | Op.RRXS ->
    rrxs true ins insLen bld
  | Op.RSB ->
    rsb false ins insLen bld
  | Op.RSBS ->
    rsbs true ins insLen bld
  | Op.RSC ->
    rsc false ins insLen bld
  | Op.RSCS ->
    rscs true ins insLen bld
  | Op.SBC ->
    sbc false ins insLen bld
  | Op.SBCS ->
    sbcs true ins insLen bld
  | Op.SBFX ->
    bfx ins insLen bld true
  | Op.SEL ->
    sel ins insLen bld
  | Op.SMLABB ->
    smulacchalf ins insLen bld false false
  | Op.SMLABT ->
    smulacchalf ins insLen bld false true
  | Op.SMLAL ->
    smulandacc false true ins insLen bld
  | Op.SMLALS ->
    smulandacc true true ins insLen bld
  | Op.SMLATB ->
    smulacchalf ins insLen bld true false
  | Op.SMLATT ->
    smulacchalf ins insLen bld true true
  | Op.SMLALBT ->
    smulacclonghalf ins insLen bld false true
  | Op.SMLALTT ->
    smulacclonghalf ins insLen bld true true
  | Op.SMLALD ->
    smulacclongdual ins insLen bld false
  | Op.SMLALDX ->
    smulacclongdual ins insLen bld true
  | Op.SMLAWB ->
    smulaccwordbyhalf ins insLen bld false
  | Op.SMLAWT ->
    smulaccwordbyhalf ins insLen bld true
  | Op.SMMLA ->
    smmla ins insLen bld false
  | Op.SMMLAR ->
    smmla ins insLen bld true
  | Op.SMMUL ->
    smmul ins insLen bld false
  | Op.SMMULR ->
    smmul ins insLen bld true
  | Op.SMULBB ->
    smulhalf ins insLen bld false false
  | Op.SMULBT ->
    smulhalf ins insLen bld false true
  | Op.SMULL ->
    smulandacc false false ins insLen bld
  | Op.SMULLS ->
    smulandacc true false ins insLen bld
  | Op.SMULTB ->
    smulhalf ins insLen bld true false
  | Op.SMULTT ->
    smulhalf ins insLen bld true true
  | Op.STM ->
    stm Op.STM ins insLen bld (.+)
  | Op.STMDA ->
    stm Op.STMDA ins insLen bld (.-)
  | Op.STMDB ->
    stm Op.STMDB ins insLen bld (.-)
  | Op.STMEA ->
    stm Op.STMIA ins insLen bld (.+)
  | Op.STMIA ->
    stm Op.STMIA ins insLen bld (.+)
  | Op.STMIB ->
    stm Op.STMIB ins insLen bld (.+)
  | Op.STR ->
    str ins insLen bld 32<rt>
  | Op.STRB ->
    str ins insLen bld 8<rt>
  | Op.STRBT ->
    str ins insLen bld 8<rt>
  | Op.STRD ->
    strd ins insLen bld
  | Op.STREX | Op.STLEX ->
    strex ins insLen bld 32<rt>
  | Op.STREXB | Op.STLEXB ->
    strex ins insLen bld 8<rt>
  | Op.STREXD | Op.STLEXD ->
    strexd ins insLen bld
  | Op.STREXH | Op.STLEXH ->
    strex ins insLen bld 16<rt>
  | Op.STRH ->
    str ins insLen bld 16<rt>
  | Op.STRHT ->
    str ins insLen bld 16<rt>
  | Op.STRT ->
    str ins insLen bld 32<rt>
  | Op.SUB | Op.SUBW ->
    sub false ins insLen bld
  | Op.SUBS ->
    subs true ins insLen bld
  | Op.SVC ->
    svc ins insLen bld
  | Op.SXTAB ->
    extendAndAdd ins insLen bld AST.sext 8<rt>
  | Op.SXTAH ->
    extendAndAdd ins insLen bld AST.sext 16<rt>
  | Op.SXTB ->
    extend ins insLen bld AST.sext 8<rt>
  | Op.SXTH ->
    extend ins insLen bld AST.sext 16<rt>
  | Op.TBH | Op.TBB ->
    tableBranch ins insLen bld
  | Op.TEQ ->
    teq ins insLen bld
  | Op.TST ->
    tst ins insLen bld
  | Op.UADD8 ->
    uadd8 ins insLen bld
  | Op.UASX ->
    uasx ins insLen bld
  | Op.UBFX ->
    bfx ins insLen bld false
  | Op.UDF ->
    udf ins insLen bld
  | Op.UHSUB16 ->
    uhsub16 ins insLen bld
  | Op.UMAAL ->
    umaal ins insLen bld
  | Op.UMLAL ->
    umlal false ins insLen bld
  | Op.UMLALS ->
    umlal true ins insLen bld
  | Op.UMULL ->
    umull false ins insLen bld
  | Op.UMULLS ->
    umull true ins insLen bld
  | Op.UQADD16 ->
    uqopr ins insLen bld 16 (.+)
  | Op.UQADD8 ->
    uqopr ins insLen bld 8 (.+)
  | Op.UQSAX ->
    uqsax ins insLen bld
  | Op.UQSUB16 ->
    uqopr ins insLen bld 16 (.-)
  | Op.UQSUB8 ->
    uqopr ins insLen bld 8 (.-)
  | Op.USAX ->
    usax ins insLen bld
  | Op.UXTAB ->
    extendAndAdd ins insLen bld AST.zext 8<rt>
  | Op.UXTAH ->
    extendAndAdd ins insLen bld AST.zext 16<rt>
  | Op.UXTB ->
    extend ins insLen bld AST.zext 8<rt>
  | Op.UXTB16 ->
    uxtb16 ins insLen bld
  | Op.UXTH ->
    extend ins insLen bld AST.zext 16<rt>
  | Op.VABS when isF16orF32orF64 ins.SIMDTyp ->
    vabsf ins insLen bld
  | Op.VABS ->
    vabs ins insLen bld
  | Op.VADD when isF16orF32orF64 ins.SIMDTyp ->
    vaddsub ins insLen bld AST.fadd
  | Op.VADD ->
    vaddsub ins insLen bld (.+)
  | Op.VADDL ->
    vaddl ins insLen bld
  | Op.VAND ->
    vand ins insLen bld
  | Op.VCEQ | Op.VCGE | Op.VCGT | Op.VCLE | Op.VCLT
    when isF32orF64 ins.SIMDTyp ->
    sideEffects ins insLen bld UnsupportedInstruction
  | Op.VCEQ ->
    vceq ins insLen bld
  | Op.VCGE ->
    vcge ins insLen bld
  | Op.VCGT ->
    vcgt ins insLen bld
  | Op.VCLE ->
    vcle ins insLen bld
  | Op.VCLT ->
    vclt ins insLen bld
  | Op.VCLZ ->
    vclz ins insLen bld
  | Op.VCMLA ->
    sideEffects ins insLen bld UnsupportedInstruction
  | Op.VACGE | Op.VACGT | Op.VACLE | Op.VACLT | Op.VCVTR ->
    sideEffects ins insLen bld UnsupportedInstruction
  | Op.VFMA ->
    vfpMulAcc ins insLen bld (fun _ d p -> AST.fadd d p)
  | Op.VFMS ->
    vfpMulAcc ins insLen bld (fun _ d p -> AST.fsub d p)
  | Op.VFNMA ->
    vfpMulAcc ins insLen bld (fun sz d p -> fpNegBits sz (AST.fadd d p))
  | Op.VFNMS ->
    vfpMulAcc ins insLen bld (fun _ d p -> AST.fsub p d)
  | Op.VNMUL ->
    vfpMulAcc ins insLen bld (fun sz _ p -> fpNegBits sz p)
  | Op.VNMLA ->
    vfpMulAcc ins insLen bld (fun sz d p -> fpNegBits sz (AST.fadd d p))
  | Op.VNMLS ->
    vfpMulAcc ins insLen bld (fun _ d p -> AST.fsub p d)
  | Op.VSQRT ->
    vsqrtf ins insLen bld
  | Op.VCMP | Op.VCMPE ->
    vcmp ins insLen bld
  | Op.VCVT ->
    vcvt ins insLen bld
  | Op.VDIV ->
    vdiv ins insLen bld
  | Op.VDUP ->
    vdup ins insLen bld
  | Op.VEXT ->
    vext ins insLen bld
  | Op.VHADD ->
    vhaddsub ins insLen bld (.+)
  | Op.VHSUB ->
    vhaddsub ins insLen bld (.-)
  | Op.VLD1 ->
    vld1 ins insLen bld
  | Op.VLD2 ->
    vld2 ins insLen bld
  | Op.VLD3 ->
    vld3 ins insLen bld
  | Op.VLD4 ->
    vld4 ins insLen bld
  | Op.VLDM | Op.VLDMIA | Op.VLDMDB ->
    vldm ins insLen bld
  | Op.VLDR ->
    vldr ins insLen bld
  | Op.VMAX | Op.VMIN when isF32orF64 ins.SIMDTyp ->
    sideEffects ins insLen bld UnsupportedInstruction
  | Op.VMAX ->
    vmaxmin ins insLen bld true
  | Op.VMIN ->
    vmaxmin ins insLen bld false
  | Op.VMLA when isF16orF32orF64 ins.SIMDTyp ->
    vfpMulAcc ins insLen bld (fun _ d p -> AST.fadd d p)
  | Op.VMLS when isF16orF32orF64 ins.SIMDTyp ->
    vfpMulAcc ins insLen bld (fun _ d p -> AST.fsub d p)
  | Op.VMLA ->
    vmla ins insLen bld
  | Op.VMLAL ->
    vmlal ins insLen bld
  | Op.VMLS ->
    vmls ins insLen bld
  | Op.VMLSL ->
    vmlsl ins insLen bld
  | Op.VMOV when isF16orF32orF64 ins.SIMDTyp ->
    vmovfp ins insLen bld
  | Op.VMOV ->
    vmov ins insLen bld
  | Op.VMOVN ->
    vmovn ins insLen bld
  | Op.VMRS ->
    vmrs ins insLen bld
  | Op.VMSR ->
    vmsr ins insLen bld
  | Op.VMUL when isF16orF32orF64 ins.SIMDTyp ->
    vmul ins insLen bld AST.fmul
  | Op.VMUL ->
    vmul ins insLen bld (.*)
  | Op.VMULL ->
    vmull ins insLen bld
  | Op.VNEG when isF32orF64 ins.SIMDTyp ->
    vnegf ins insLen bld
  | Op.VNEG ->
    vneg ins insLen bld
  | Op.VORN ->
    vorn ins insLen bld
  | Op.VORR ->
    vorr ins insLen bld
  | Op.VPADD when isF32orF64 ins.SIMDTyp ->
    sideEffects ins insLen bld UnsupportedInstruction
  | Op.VPADD ->
    vpadd ins insLen bld
  | Op.VPOP ->
    vpop ins insLen bld
  | Op.VPUSH ->
    vpush ins insLen bld
  | Op.VRHADD ->
    vrhadd ins insLen bld
  | Op.VRINTP ->
    sideEffects ins insLen bld UnsupportedInstruction
  | Op.VRSHR ->
    vrshr ins insLen bld
  | Op.VRSHRN ->
    vrshrn ins insLen bld
  | Op.VSHL ->
    vshl ins insLen bld
  | Op.VSHR ->
    vshr ins insLen bld
  | Op.VSRA ->
    vsra ins insLen bld
  | Op.VST1 ->
    vst1 ins insLen bld
  | Op.VST2 ->
    vst2 ins insLen bld
  | Op.VST3 ->
    vst3 ins insLen bld
  | Op.VST4 ->
    vst4 ins insLen bld
  | Op.VSTM | Op.VSTMIA | Op.VSTMDB ->
    vstm ins insLen bld
  | Op.VSTR ->
    vstr ins insLen bld
  | Op.VSUB when isF16orF32orF64 ins.SIMDTyp ->
    vaddsub ins insLen bld AST.fsub
  | Op.VSUB ->
    vaddsub ins insLen bld (.-)
  | Op.VTBL ->
    vecTbl ins insLen bld true
  | Op.VTBX ->
    vecTbl ins insLen bld false
  | Op.VTST ->
    vtst ins insLen bld
  | Op.VUZP ->
    vuzp ins insLen bld
  (* No parser produces this opcode: an undecodable encoding is reported as a
     parsing failure, so an instruction never carries it this far. *)
  | Op.InvalidOP ->
    Terminator.impossible ()
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException(Disasm.opCodeToString o)

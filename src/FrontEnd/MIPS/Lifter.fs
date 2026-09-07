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

module internal B2R2.FrontEnd.MIPS.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.MIPS
open B2R2.FrontEnd.MIPS.LiftingUtils
open B2R2.FrontEnd.MIPS.GeneralLifter

let translate (ins: Instruction) (bld: LowUIRBuilder) =
  match ins.Opcode with
  | Op.ABS ->
    abs ins bld
  | Op.ADD ->
    add ins bld
  | Op.ADDIU ->
    addiu ins bld
  | Op.ADDU ->
    addu ins bld
  | Op.AND ->
    logAnd ins bld
  | Op.ANDI ->
    andi ins bld
  | Op.AUI ->
    aui ins bld
  | Op.B ->
    b ins bld
  | Op.BAL ->
    bal ins bld
  | Op.BC1F ->
    bc1f ins bld
  | Op.BC1T ->
    bc1t ins bld
  | Op.BEQ | Op.BEQL ->
    beq ins bld
  | Op.BGEZ ->
    bgez ins bld
  | Op.BGEZAL ->
    bgezal ins bld
  | Op.BGTZ ->
    bgtz ins bld
  | Op.BLEZ ->
    blez ins bld
  | Op.BLTZ ->
    bltz ins bld
  | Op.BLTZAL ->
    bltzal ins bld
  | Op.BNE | Op.BNEL ->
    bne ins bld
  | Op.BREAK ->
    sideEffects ins bld Breakpoint
  | Op.C ->
    cCond ins bld
  | Op.CFC1 ->
    cfc1 ins bld
  | Op.CTC1 ->
    ctc1 ins bld
  | Op.CLZ ->
    clz ins bld
  | Op.CVTD ->
    cvtd ins bld
  | Op.CVTL ->
    cvtl ins bld
  | Op.CVTS ->
    cvts ins bld
  | Op.CVTW ->
    cvtw ins bld
  | Op.DADD ->
    dadd ins bld
  | Op.DADDU ->
    daddu ins bld
  | Op.DADDIU ->
    daddiu ins bld
  | Op.DCLZ ->
    dclz ins bld
  | Op.DDIV ->
    ddiv ins bld
  | Op.DMFC1 ->
    dmfc1 ins bld
  | Op.DMTC1 ->
    dmtc1 ins bld
  | Op.DEXT ->
    dext ins bld
  | Op.DEXTM ->
    dextx ins checkDEXTMPosSize bld
  | Op.DEXTU ->
    dextx ins checkDEXTUPosSize bld
  | Op.DINS ->
    dins ins bld
  | Op.DINSM ->
    dinsx ins checkDINSMPosSize bld
  | Op.DINSU ->
    dinsx ins checkDINSUPosSize bld
  | Op.DIV ->
    div ins bld
  | Op.DIVU ->
    divu ins bld
  | Op.DDIVU ->
    ddivu ins bld
  | Op.DMULT ->
    dmul ins bld true
  | Op.DMULTU ->
    dmul ins bld false
  | Op.DROTR ->
    drotr ins bld
  | Op.DROTR32 ->
    drotr32 ins bld
  | Op.DROTRV ->
    drotrv ins bld
  | Op.DSBH ->
    dsbh ins bld
  | Op.DSHD ->
    dshd ins bld
  | Op.DSLL ->
    dShiftLeftRight ins bld (<<)
  | Op.DSLL32 ->
    dShiftLeftRight32 ins bld (<<)
  | Op.DSLLV ->
    dShiftLeftRightVar ins bld (<<)
  | Op.DSRA ->
    dsra ins bld
  | Op.DSRAV ->
    dsrav ins bld
  | Op.DSRA32 ->
    dsra32 ins bld
  | Op.DSRL ->
    dShiftLeftRight ins bld (>>)
  | Op.DSRL32 ->
    dShiftLeftRight32 ins bld (>>)
  | Op.DSRLV ->
    dShiftLeftRightVar ins bld (>>)
  | Op.DSUBU ->
    dsubu ins bld
  | Op.EHB ->
    nop ins bld
  | Op.EXT ->
    ext ins bld
  | Op.INS ->
    insert ins bld
  | Op.J ->
    j ins bld
  | Op.JAL ->
    jal ins bld
  | Op.JALR | Op.JALRHB ->
    jalr ins bld
  | Op.JR | Op.JRHB ->
    jr ins bld
  | Op.LD | Op.LB | Op.LH | Op.LW ->
    loadSigned ins bld
  | Op.LBU | Op.LHU | Op.LWU ->
    loadUnsigned ins bld
  | Op.LL | Op.LLD ->
    loadLinked ins bld
  | Op.SDC1 | Op.SDXC1 ->
    sldc1 ins bld true
  | Op.LDC1 | Op.LDXC1 ->
    sldc1 ins bld false
  | Op.SWC1 | Op.SWXC1 ->
    slwc1 ins bld true
  | Op.LWC1 | Op.LWXC1 ->
    slwc1 ins bld false
  | Op.LUI ->
    lui ins bld
  | Op.LDL ->
    loadLeftRight ins bld (<<) (>>) (.&) 64<rt>
  | Op.LDR ->
    loadLeftRight ins bld (>>) (<<) (<+>) 64<rt>
  | Op.LWL ->
    loadLeftRight ins bld (<<) (>>) (.&) 32<rt>
  | Op.LWR ->
    loadLeftRight ins bld (>>) (<<) (<+>) 32<rt>
  | Op.MADD ->
    mAddSub ins bld true
  | Op.MADDU ->
    mAdduSubu ins bld true
  | Op.MFHI ->
    mfhi ins bld
  | Op.MFLO ->
    mflo ins bld
  | Op.MFHC1 ->
    mfhc1 ins bld
  | Op.MTHC1 ->
    mthc1 ins bld
  | Op.MTHI ->
    mthi ins bld
  | Op.MTLO ->
    mtlo ins bld
  | Op.MFC1 ->
    mfc1 ins bld
  | Op.MOV ->
    mov ins bld
  | Op.MOVT ->
    movt ins bld
  | Op.MOVF ->
    movf ins bld
  | Op.MOVZ ->
    movzOrn ins bld (==)
  | Op.MOVN ->
    movzOrn ins bld (!=)
  | Op.MSUB ->
    mAddSub ins bld false
  | Op.MSUBU ->
    mAdduSubu ins bld false
  | Op.MTC1 ->
    mtc1 ins bld
  | Op.MUL ->
    mul ins bld
  | Op.MULT ->
    mult ins bld
  | Op.MULTU ->
    multu ins bld
  | Op.NEG ->
    neg ins bld
  | Op.NMADD ->
    nmadd ins bld
  | Op.NOP ->
    nop ins bld
  | Op.NOR ->
    nor ins bld
  | Op.OR ->
    logOr ins bld
  | Op.ORI ->
    ori ins bld
  | Op.PAUSE ->
    nop ins bld
  | Op.PREF | Op.PREFE | Op.PREFX ->
    nop ins bld
  | Op.RDHWR ->
    readHWR ins bld
  | Op.ROTR ->
    rotr ins bld
  | Op.ROTRV ->
    rotrv ins bld
  | Op.RECIP ->
    recip ins bld
  | Op.RSQRT ->
    rsqrt ins bld
  | Op.SLL ->
    shiftLeftRight ins bld (<<)
  | Op.SLLV ->
    shiftLeftRightVar ins bld (<<)
  | Op.SLT ->
    sltAndU ins bld (?<)
  | Op.SLTU ->
    sltAndU ins bld (.<)
  | Op.SLTI ->
    sltiAndU ins bld (?<)
  | Op.SLTIU ->
    sltiAndU ins bld (.<)
  | Op.SSNOP ->
    nop ins bld
  | Op.SB ->
    store ins 8<rt> bld
  | Op.SC ->
    storeConditional ins 32<rt> bld
  | Op.SCD ->
    storeConditional ins 64<rt> bld
  | Op.SD ->
    store ins 64<rt> bld
  | Op.SEB ->
    seb ins bld
  | Op.SEH ->
    seh ins bld
  | Op.SH ->
    store ins 16<rt> bld
  | Op.SQRT ->
    sqrt ins bld
  | Op.SRA ->
    sra ins bld
  | Op.SRAV ->
    srav ins bld
  | Op.SRL ->
    shiftLeftRight ins bld (>>)
  | Op.SRLV ->
    shiftLeftRightVar ins bld (>>)
  | Op.SUB ->
    sub ins bld
  | Op.SUBU ->
    subu ins bld
  | Op.SW ->
    store ins 32<rt> bld
  | Op.SDL ->
    storeLeftRight ins bld (<<) (>>) (.&) 64<rt>
  | Op.SDR ->
    storeLeftRight ins bld (>>) (<<) (<+>) 64<rt>
  | Op.SWL ->
    storeLeftRight ins bld (<<) (>>) (.&) 32<rt>
  | Op.SWR ->
    storeLeftRight ins bld (>>) (<<) (<+>) 32<rt>
  | Op.SYNC | Op.SYNCI ->
    nop ins bld
  | Op.SYSCALL ->
    syscall ins bld
  | Op.TEQ ->
    teq ins bld
  | Op.TEQI ->
    teqi ins bld
  | Op.TRUNCW ->
    truncw ins bld
  | Op.TRUNCL ->
    truncl ins bld
  | Op.XOR ->
    logXor ins bld
  | Op.XORI ->
    xori ins bld
  | Op.WSBH ->
    wsbh ins bld
  | Op.BC3F | Op.BC3FL | Op.BC3T | Op.BC3TL ->
    unsupported ins bld
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException(Disasm.opCodeToString o)

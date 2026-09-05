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

let translate (ins: Instruction) insLen (bld: LowUIRBuilder) =
  match ins.Opcode with
  | Op.ABS ->
    abs ins insLen bld
  | Op.ADD ->
    add ins insLen bld
  | Op.ADDIU ->
    addiu ins insLen bld
  | Op.ADDU ->
    addu ins insLen bld
  | Op.AND ->
    logAnd ins insLen bld
  | Op.ANDI ->
    andi ins insLen bld
  | Op.AUI ->
    aui ins insLen bld
  | Op.B ->
    b ins insLen bld
  | Op.BAL ->
    bal ins insLen bld
  | Op.BC1F ->
    bc1f ins insLen bld
  | Op.BC1T ->
    bc1t ins insLen bld
  | Op.BEQ | Op.BEQL ->
    beq ins insLen bld
  | Op.BGEZ ->
    bgez ins insLen bld
  | Op.BGEZAL ->
    bgezal ins insLen bld
  | Op.BGTZ ->
    bgtz ins insLen bld
  | Op.BLEZ ->
    blez ins insLen bld
  | Op.BLTZ ->
    bltz ins insLen bld
  | Op.BLTZAL ->
    bltzal ins insLen bld
  | Op.BNE | Op.BNEL ->
    bne ins insLen bld
  | Op.BREAK ->
    sideEffects ins insLen bld Breakpoint
  | Op.C ->
    cCond ins insLen bld
  | Op.CFC1 ->
    cfc1 ins insLen bld
  | Op.CTC1 ->
    ctc1 ins insLen bld
  | Op.CLZ ->
    clz ins insLen bld
  | Op.CVTD ->
    cvtd ins insLen bld
  | Op.CVTL ->
    cvtl ins insLen bld
  | Op.CVTS ->
    cvts ins insLen bld
  | Op.CVTW ->
    cvtw ins insLen bld
  | Op.DADD ->
    dadd ins insLen bld
  | Op.DADDU ->
    daddu ins insLen bld
  | Op.DADDIU ->
    daddiu ins insLen bld
  | Op.DCLZ ->
    dclz ins insLen bld
  | Op.DDIV ->
    ddiv ins insLen bld
  | Op.DMFC1 ->
    dmfc1 ins insLen bld
  | Op.DMTC1 ->
    dmtc1 ins insLen bld
  | Op.DEXT ->
    dext ins insLen bld
  | Op.DEXTM ->
    dextx ins insLen checkDEXTMPosSize bld
  | Op.DEXTU ->
    dextx ins insLen checkDEXTUPosSize bld
  | Op.DINS ->
    dins ins insLen bld
  | Op.DINSM ->
    dinsx ins insLen checkDINSMPosSize bld
  | Op.DINSU ->
    dinsx ins insLen checkDINSUPosSize bld
  | Op.DIV ->
    div ins insLen bld
  | Op.DIVU ->
    divu ins insLen bld
  | Op.DDIVU ->
    ddivu ins insLen bld
  | Op.DMULT ->
    dmul ins insLen bld true
  | Op.DMULTU ->
    dmul ins insLen bld false
  | Op.DROTR ->
    drotr ins insLen bld
  | Op.DROTR32 ->
    drotr32 ins insLen bld
  | Op.DROTRV ->
    drotrv ins insLen bld
  | Op.DSBH ->
    dsbh ins insLen bld
  | Op.DSHD ->
    dshd ins insLen bld
  | Op.DSLL ->
    dShiftLeftRight ins insLen bld (<<)
  | Op.DSLL32 ->
    dShiftLeftRight32 ins insLen bld (<<)
  | Op.DSLLV ->
    dShiftLeftRightVar ins insLen bld (<<)
  | Op.DSRA ->
    dsra ins insLen bld
  | Op.DSRAV ->
    dsrav ins insLen bld
  | Op.DSRA32 ->
    dsra32 ins insLen bld
  | Op.DSRL ->
    dShiftLeftRight ins insLen bld (>>)
  | Op.DSRL32 ->
    dShiftLeftRight32 ins insLen bld (>>)
  | Op.DSRLV ->
    dShiftLeftRightVar ins insLen bld (>>)
  | Op.DSUBU ->
    dsubu ins insLen bld
  | Op.EHB ->
    nop ins insLen bld
  | Op.EXT ->
    ext ins insLen bld
  | Op.INS ->
    insert ins insLen bld
  | Op.J ->
    j ins insLen bld
  | Op.JAL ->
    jal ins insLen bld
  | Op.JALR | Op.JALRHB ->
    jalr ins insLen bld
  | Op.JR | Op.JRHB ->
    jr ins insLen bld
  | Op.LD | Op.LB | Op.LH | Op.LW ->
    loadSigned ins insLen bld
  | Op.LBU | Op.LHU | Op.LWU ->
    loadUnsigned ins insLen bld
  | Op.LL | Op.LLD ->
    loadLinked ins insLen bld
  | Op.SDC1 | Op.SDXC1 ->
    sldc1 ins insLen bld true
  | Op.LDC1 | Op.LDXC1 ->
    sldc1 ins insLen bld false
  | Op.SWC1 | Op.SWXC1 ->
    slwc1 ins insLen bld true
  | Op.LWC1 | Op.LWXC1 ->
    slwc1 ins insLen bld false
  | Op.LUI ->
    lui ins insLen bld
  | Op.LDL ->
    loadLeftRight ins insLen bld (<<) (>>) (.&) 64<rt>
  | Op.LDR ->
    loadLeftRight ins insLen bld (>>) (<<) (<+>) 64<rt>
  | Op.LWL ->
    loadLeftRight ins insLen bld (<<) (>>) (.&) 32<rt>
  | Op.LWR ->
    loadLeftRight ins insLen bld (>>) (<<) (<+>) 32<rt>
  | Op.MADD ->
    mAddSub ins insLen bld true
  | Op.MADDU ->
    mAdduSubu ins insLen bld true
  | Op.MFHI ->
    mfhi ins insLen bld
  | Op.MFLO ->
    mflo ins insLen bld
  | Op.MFHC1 ->
    mfhc1 ins insLen bld
  | Op.MTHC1 ->
    mthc1 ins insLen bld
  | Op.MTHI ->
    mthi ins insLen bld
  | Op.MTLO ->
    mtlo ins insLen bld
  | Op.MFC1 ->
    mfc1 ins insLen bld
  | Op.MOV ->
    mov ins insLen bld
  | Op.MOVT ->
    movt ins insLen bld
  | Op.MOVF ->
    movf ins insLen bld
  | Op.MOVZ ->
    movzOrn ins insLen bld (==)
  | Op.MOVN ->
    movzOrn ins insLen bld (!=)
  | Op.MSUB ->
    mAddSub ins insLen bld false
  | Op.MSUBU ->
    mAdduSubu ins insLen bld false
  | Op.MTC1 ->
    mtc1 ins insLen bld
  | Op.MUL ->
    mul ins insLen bld
  | Op.MULT ->
    mult ins insLen bld
  | Op.MULTU ->
    multu ins insLen bld
  | Op.NEG ->
    neg ins insLen bld
  | Op.NMADD ->
    nmadd ins insLen bld
  | Op.NOP ->
    nop ins insLen bld
  | Op.NOR ->
    nor ins insLen bld
  | Op.OR ->
    logOr ins insLen bld
  | Op.ORI ->
    ori ins insLen bld
  | Op.PAUSE ->
    nop ins insLen bld
  | Op.PREF | Op.PREFE | Op.PREFX ->
    nop ins insLen bld
  | Op.RDHWR ->
    readHWR ins insLen bld
  | Op.ROTR ->
    rotr ins insLen bld
  | Op.ROTRV ->
    rotrv ins insLen bld
  | Op.RECIP ->
    recip ins insLen bld
  | Op.RSQRT ->
    rsqrt ins insLen bld
  | Op.SLL ->
    shiftLeftRight ins insLen bld (<<)
  | Op.SLLV ->
    shiftLeftRightVar ins insLen bld (<<)
  | Op.SLT ->
    sltAndU ins insLen bld (?<)
  | Op.SLTU ->
    sltAndU ins insLen bld (.<)
  | Op.SLTI ->
    sltiAndU ins insLen bld (?<)
  | Op.SLTIU ->
    sltiAndU ins insLen bld (.<)
  | Op.SSNOP ->
    nop ins insLen bld
  | Op.SB ->
    store ins insLen 8<rt> bld
  | Op.SC ->
    storeConditional ins insLen 32<rt> bld
  | Op.SCD ->
    storeConditional ins insLen 64<rt> bld
  | Op.SD ->
    store ins insLen 64<rt> bld
  | Op.SEB ->
    seb ins insLen bld
  | Op.SEH ->
    seh ins insLen bld
  | Op.SH ->
    store ins insLen 16<rt> bld
  | Op.SQRT ->
    sqrt ins insLen bld
  | Op.SRA ->
    sra ins insLen bld
  | Op.SRAV ->
    srav ins insLen bld
  | Op.SRL ->
    shiftLeftRight ins insLen bld (>>)
  | Op.SRLV ->
    shiftLeftRightVar ins insLen bld (>>)
  | Op.SUB ->
    sub ins insLen bld
  | Op.SUBU ->
    subu ins insLen bld
  | Op.SW ->
    store ins insLen 32<rt> bld
  | Op.SDL ->
    storeLeftRight ins insLen bld (<<) (>>) (.&) 64<rt>
  | Op.SDR ->
    storeLeftRight ins insLen bld (>>) (<<) (<+>) 64<rt>
  | Op.SWL ->
    storeLeftRight ins insLen bld (<<) (>>) (.&) 32<rt>
  | Op.SWR ->
    storeLeftRight ins insLen bld (>>) (<<) (<+>) 32<rt>
  | Op.SYNC | Op.SYNCI ->
    nop ins insLen bld
  | Op.SYSCALL ->
    syscall ins insLen bld
  | Op.TEQ ->
    teq ins insLen bld
  | Op.TEQI ->
    teqi ins insLen bld
  | Op.TRUNCW ->
    truncw ins insLen bld
  | Op.TRUNCL ->
    truncl ins insLen bld
  | Op.XOR ->
    logXor ins insLen bld
  | Op.XORI ->
    xori ins insLen bld
  | Op.WSBH ->
    wsbh ins insLen bld
  | Op.BC3F | Op.BC3FL | Op.BC3T | Op.BC3TL ->
    sideEffects ins insLen bld UnsupportedInstruction
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException(Disasm.opCodeToString o)

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

module internal B2R2.FrontEnd.RISCV64.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.RISCV64.LiftingUtils
open B2R2.FrontEnd.RISCV64.GeneralLifter

let translate (ins: Instruction) insLen bld =
  match ins.Opcode with
  | Op.CdotMV
  | Op.CdotADD
  | Op.ADD ->
    add ins insLen bld
  | Op.CdotADDW
  | Op.ADDW ->
    addw ins insLen bld
  | Op.CdotSUBW
  | Op.SUBW ->
    subw ins insLen bld
  | Op.CdotAND
  | Op.AND ->
    ``and`` ins insLen bld
  | Op.CdotOR
  | Op.OR ->
    ``or`` ins insLen bld
  | Op.CdotXOR
  | Op.XOR ->
    xor ins insLen bld
  | Op.CdotSUB
  | Op.SUB ->
    sub ins insLen bld
  | Op.SLT ->
    slt ins insLen bld
  | Op.SLTU ->
    sltu ins insLen bld
  | Op.SLL ->
    sll ins insLen bld
  | Op.SLLW ->
    sllw ins insLen bld
  | Op.SRA ->
    sra ins insLen bld
  | Op.SRAW ->
    sraw ins insLen bld
  | Op.SRL ->
    srl ins insLen bld
  | Op.SRLW ->
    srlw ins insLen bld
  | Op.CdotANDI
  | Op.ANDI ->
    andi ins insLen bld
  | Op.CdotADDI16SP
  | Op.CdotLI
  | Op.CdotADDI
  | Op.CdotADDI4SPN
  | Op.ADDI ->
    addi ins insLen bld
  | Op.ORI ->
    ori ins insLen bld
  | Op.XORI ->
    xori ins insLen bld
  | Op.SLTI ->
    slti ins insLen bld
  | Op.SLTIU ->
    sltiu ins insLen bld
  | Op.CdotJ
  | Op.JAL ->
    jal ins insLen bld
  | Op.CdotJR
  | Op.CdotJALR
  | Op.JALR ->
    jalr ins insLen bld
  | Op.CdotBEQZ
  | Op.BEQ ->
    beq ins insLen bld
  | Op.CdotBNEZ
  | Op.BNE ->
    bne ins insLen bld
  | Op.BLT ->
    blt ins insLen bld
  | Op.BGE ->
    bge ins insLen bld
  | Op.BLTU ->
    bltu ins insLen bld
  | Op.BGEU ->
    bgeu ins insLen bld
  | Op.CdotLW
  | Op.CdotLD
  | Op.CdotLWSP
  | Op.CdotLDSP
  | Op.LB
  | Op.LH
  | Op.LW
  | Op.LD ->
    load ins insLen bld
  | Op.LBU
  | Op.LHU
  | Op.LWU ->
    loadu ins insLen bld
  | Op.CdotSW
  | Op.CdotSD
  | Op.CdotSWSP
  | Op.CdotSDSP
  | Op.SB
  | Op.SH
  | Op.SW
  | Op.SD ->
    store ins insLen bld
  | Op.CdotEBREAK
  | Op.EBREAK ->
    sideEffects ins insLen bld Breakpoint
  | Op.ECALL ->
    sideEffects ins insLen bld SysCall
  | Op.CdotSRAI
  | Op.SRAI ->
    srai ins insLen bld
  | Op.CdotSLLI
  | Op.SLLI ->
    slli ins insLen bld
  | Op.CdotSRLI
  | Op.SRLI ->
    srli ins insLen bld
  | Op.CdotLUI
  | Op.LUI ->
    lui ins insLen bld
  | Op.AUIPC ->
    auipc ins insLen bld
  | Op.CdotADDIW
  | Op.ADDIW ->
    addiw ins insLen bld
  | Op.SLLIW ->
    slliw ins insLen bld
  | Op.SRLIW ->
    srliw ins insLen bld
  | Op.SRAIW ->
    sraiw ins insLen bld
  | Op.MUL ->
    mul ins insLen bld
  | Op.MULH ->
    mulhSignOrUnsign ins insLen bld (true, true)
  | Op.MULHU ->
    mulhSignOrUnsign ins insLen bld (false, true)
  | Op.MULHSU ->
    mulhSignOrUnsign ins insLen bld (true, false)
  | Op.MULW ->
    mulw ins insLen bld
  | Op.CdotNOP ->
    nop ins insLen bld
  | Op.CdotFLD
  | Op.CdotFLDSP
  | Op.FLD ->
    fld ins insLen bld
  | Op.CdotFSD
  | Op.CdotFSDSP
  | Op.FSD ->
    fsd ins insLen bld
  | Op.FLTdotS ->
    fltdots ins insLen bld
  | Op.FLTdotD ->
    fltdotd ins insLen bld
  | Op.FLEdotS ->
    fledots ins insLen bld
  | Op.FLEdotD ->
    fledotd ins insLen bld
  | Op.FEQdotS ->
    feqdots ins insLen bld
  | Op.FEQdotD ->
    feqdotd ins insLen bld
  | Op.FLW ->
    flw ins insLen bld
  | Op.FSW ->
    fsw ins insLen bld
  | Op.FADDdotS ->
    fpArithmeticSingle ins insLen bld AST.fadd
  | Op.FADDdotD ->
    fpArithmeticDouble ins insLen bld AST.fadd
  | Op.FSUBdotS ->
    fpArithmeticSingle ins insLen bld AST.fsub
  | Op.FSUBdotD ->
    fpArithmeticDouble ins insLen bld AST.fsub
  | Op.FDIVdotS ->
    fpArithmeticSingle ins insLen bld AST.fdiv
  | Op.FDIVdotD ->
    fpArithmeticDouble ins insLen bld AST.fdiv
  | Op.FMULdotS ->
    fpArithmeticSingle ins insLen bld AST.fmul
  | Op.FMULdotD ->
    fpArithmeticDouble ins insLen bld AST.fmul
  | Op.FMINdotS ->
    fmindots ins insLen bld
  | Op.FMINdotD ->
    fmindotd ins insLen bld
  | Op.FMAXdotS ->
    fmaxdots ins insLen bld
  | Op.FMAXdotD ->
    fmaxdotd ins insLen bld
  | Op.FNMADDdotS ->
    fnmadddots ins insLen bld
  | Op.FNMADDdotD ->
    fnmadddotd ins insLen bld
  | Op.FNMSUBdotS ->
    fnmsubdots ins insLen bld
  | Op.FNMSUBdotD ->
    fnmsubdotd ins insLen bld
  | Op.FMADDdotS ->
    fmadddots ins insLen bld
  | Op.FMADDdotD ->
    fmadddotd ins insLen bld
  | Op.FMSUBdotS ->
    fmsubdots ins insLen bld
  | Op.FMSUBdotD ->
    fmsubdotd ins insLen bld
  | Op.FSQRTdotS ->
    fsqrtdots ins insLen bld
  | Op.FSQRTdotD ->
    fsqrtdotd ins insLen bld
  | Op.FCLASSdotS ->
    fclassdots ins insLen bld
  | Op.FCLASSdotD ->
    fclassdotd ins insLen bld
  | Op.FSGNJdotS ->
    fsgnjdots ins insLen bld
  | Op.FSGNJdotD ->
    fsgnjdotd ins insLen bld
  | Op.FSGNJNdotS ->
    fsgnjndots ins insLen bld
  | Op.FSGNJNdotD ->
    fsgnjndotd ins insLen bld
  | Op.FSGNJXdotS ->
    fsgnjxdots ins insLen bld
  | Op.FSGNJXdotD ->
    fsgnjxdotd ins insLen bld
  | Op.AMOADDdotW ->
    amow ins insLen bld (.+)
  | Op.AMOADDdotD ->
    amod ins insLen bld (.+)
  | Op.AMOANDdotW ->
    amow ins insLen bld (.&)
  | Op.AMOANDdotD ->
    amod ins insLen bld (.&)
  | Op.AMOXORdotW ->
    amow ins insLen bld (<+>)
  | Op.AMOXORdotD ->
    amod ins insLen bld (<+>)
  | Op.AMOORdotW ->
    amow ins insLen bld (.|)
  | Op.AMOORdotD ->
    amod ins insLen bld (.|)
  | Op.AMOMINdotW ->
    amow ins insLen bld (fun a b -> AST.ite (a ?< b) (a) (b))
  | Op.AMOMINdotD ->
    amod ins insLen bld (fun a b -> AST.ite (a ?< b) (a) (b))
  | Op.AMOMINUdotW ->
    amow ins insLen bld (fun a b -> AST.ite (a .< b) (a) (b))
  | Op.AMOMINUdotD ->
    amod ins insLen bld (fun a b -> AST.ite (a .< b) (a) (b))
  | Op.AMOMAXdotW ->
    amow ins insLen bld (fun a b -> AST.ite (a ?> b) (a) (b))
  | Op.AMOMAXdotD ->
    amod ins insLen bld (fun a b -> AST.ite (a ?> b) (a) (b))
  | Op.AMOMAXUdotW ->
    amow ins insLen bld (fun a b -> AST.ite (a .> b) (a) (b))
  | Op.AMOMAXUdotD ->
    amod ins insLen bld (fun a b -> AST.ite (a .> b) (a) (b))
  | Op.AMOSWAPdotW ->
    amow ins insLen bld (fun _ b -> b)
  | Op.AMOSWAPdotD ->
    amod ins insLen bld (fun _ b -> b)
  | Op.FMVdotXdotW ->
    fmvdotxdotw ins insLen bld
  | Op.FMVdotXdotD ->
    fmvdotxdotd ins insLen bld
  | Op.FMVdotWdotX ->
    fmvdotwdotx ins insLen bld
  | Op.FMVdotDdotX ->
    fmvdotddotx ins insLen bld
  | Op.DIVW ->
    divw ins insLen bld
  | Op.DIV ->
    div ins insLen bld
  | Op.DIVU ->
    divu ins insLen bld
  | Op.REM ->
    rem ins insLen bld
  | Op.REMU ->
    remu ins insLen bld
  | Op.REMW ->
    remw ins insLen bld
  | Op.DIVUW ->
    divuw ins insLen bld
  | Op.REMUW ->
    remuw ins insLen bld
  | Op.FCVTdotWdotD ->
    fcvtdotwdotd ins insLen bld
  | Op.FCVTdotWUdotD ->
    fcvtdotwudotd ins insLen bld
  | Op.FCVTdotLdotD ->
    fcvtdotldotd ins insLen bld
  | Op.FCVTdotLUdotD ->
    fcvtdotludotd ins insLen bld
  | Op.FCVTdotWdotS ->
    fcvtdotwdots ins insLen bld
  | Op.FCVTdotWUdotS ->
    fcvtdotwudots ins insLen bld
  | Op.FCVTdotLdotS ->
    fcvtdotldots ins insLen bld
  | Op.FCVTdotLUdotS ->
    fcvtdotludots ins insLen bld
  | Op.FENCE
  | Op.FENCEdotI
  | Op.FENCEdotTSO ->
    nop ins insLen bld
  | Op.LRdotW
  | Op.LRdotD ->
    lr ins insLen bld
  | Op.SCdotW ->
    sc ins insLen bld 32<rt>
  | Op.SCdotD ->
    sc ins insLen bld 64<rt>
  | Op.CSRRW
  | Op.CSRRWI ->
    csrrw ins insLen bld
  | Op.CSRRS
  | Op.CSRRSI ->
    csrrs ins insLen bld
  | Op.CSRRC
  | Op.CSRRCI ->
    csrrc ins insLen bld
  | Op.FCVTdotSdotW ->
    fcvtdotsdotw ins insLen bld
  | Op.FCVTdotSdotL ->
    fcvtdotsdotl ins insLen bld
  | Op.FCVTdotSdotD ->
    fcvtdotsdotd ins insLen bld
  | Op.FCVTdotDdotS ->
    fcvtdotddots ins insLen bld
  | Op.FCVTdotDdotW ->
    fcvtdotddotw ins insLen bld
  | Op.FCVTdotDdotL ->
    fcvtdotddotl ins insLen bld
  | Op.FCVTdotDdotWU ->
    fcvtdotddotwu ins insLen bld
  | Op.FCVTdotDdotLU ->
    fcvtdotddotlu ins insLen bld
  | Op.FCVTdotSdotWU ->
    fcvtdotsdotwu ins insLen bld
  | Op.FCVTdotSdotLU ->
    fcvtdotsdotlu ins insLen bld
  | o ->
#if DEBUG
    eprintfn "%A" o
#endif
    raise <| NotImplementedIRException(Disasm.opCodeToString o)

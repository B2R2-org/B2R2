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

let translate (ins: Instruction) bld =
  match ins.Opcode with
  | Op.CdotMV
  | Op.CdotADD
  | Op.ADD ->
    add ins bld
  | Op.CdotADDW
  | Op.ADDW ->
    addw ins bld
  | Op.CdotSUBW
  | Op.SUBW ->
    subw ins bld
  | Op.CdotAND
  | Op.AND ->
    ``and`` ins bld
  | Op.CdotOR
  | Op.OR ->
    ``or`` ins bld
  | Op.CdotXOR
  | Op.XOR ->
    xor ins bld
  | Op.CdotSUB
  | Op.SUB ->
    sub ins bld
  | Op.SLT ->
    slt ins bld
  | Op.SLTU ->
    sltu ins bld
  | Op.SLL ->
    sll ins bld
  | Op.SLLW ->
    sllw ins bld
  | Op.SRA ->
    sra ins bld
  | Op.SRAW ->
    sraw ins bld
  | Op.SRL ->
    srl ins bld
  | Op.SRLW ->
    srlw ins bld
  | Op.CdotANDI
  | Op.ANDI ->
    andi ins bld
  | Op.CdotADDI16SP
  | Op.CdotLI
  | Op.CdotADDI
  | Op.CdotADDI4SPN
  | Op.ADDI ->
    addi ins bld
  | Op.ORI ->
    ori ins bld
  | Op.XORI ->
    xori ins bld
  | Op.SLTI ->
    slti ins bld
  | Op.SLTIU ->
    sltiu ins bld
  | Op.CdotJ
  | Op.JAL ->
    jal ins bld
  | Op.CdotJR
  | Op.CdotJALR
  | Op.JALR ->
    jalr ins bld
  | Op.CdotBEQZ
  | Op.BEQ ->
    beq ins bld
  | Op.CdotBNEZ
  | Op.BNE ->
    bne ins bld
  | Op.BLT ->
    blt ins bld
  | Op.BGE ->
    bge ins bld
  | Op.BLTU ->
    bltu ins bld
  | Op.BGEU ->
    bgeu ins bld
  | Op.CdotLW
  | Op.CdotLD
  | Op.CdotLWSP
  | Op.CdotLDSP
  | Op.LB
  | Op.LH
  | Op.LW
  | Op.LD ->
    load ins bld
  | Op.LBU
  | Op.LHU
  | Op.LWU ->
    loadu ins bld
  | Op.CdotSW
  | Op.CdotSD
  | Op.CdotSWSP
  | Op.CdotSDSP
  | Op.SB
  | Op.SH
  | Op.SW
  | Op.SD ->
    store ins bld
  | Op.CdotEBREAK
  | Op.EBREAK ->
    sideEffects ins bld Breakpoint
  | Op.ECALL ->
    sideEffects ins bld SysCall
  | Op.CdotSRAI
  | Op.SRAI ->
    srai ins bld
  | Op.CdotSLLI
  | Op.SLLI ->
    slli ins bld
  | Op.CdotSRLI
  | Op.SRLI ->
    srli ins bld
  | Op.CdotLUI
  | Op.LUI ->
    lui ins bld
  | Op.AUIPC ->
    auipc ins bld
  | Op.CdotADDIW
  | Op.ADDIW ->
    addiw ins bld
  | Op.SLLIW ->
    slliw ins bld
  | Op.SRLIW ->
    srliw ins bld
  | Op.SRAIW ->
    sraiw ins bld
  | Op.MUL ->
    mul ins bld
  | Op.MULH ->
    mulhSignOrUnsign ins bld (true, true)
  | Op.MULHU ->
    mulhSignOrUnsign ins bld (false, true)
  | Op.MULHSU ->
    mulhSignOrUnsign ins bld (true, false)
  | Op.MULW ->
    mulw ins bld
  | Op.CdotNOP ->
    nop ins bld
  | Op.CdotFLD
  | Op.CdotFLDSP
  | Op.FLD ->
    fld ins bld
  | Op.CdotFSD
  | Op.CdotFSDSP
  | Op.FSD ->
    fsd ins bld
  | Op.FLTdotS ->
    fltdots ins bld
  | Op.FLTdotD ->
    fltdotd ins bld
  | Op.FLEdotS ->
    fledots ins bld
  | Op.FLEdotD ->
    fledotd ins bld
  | Op.FEQdotS ->
    feqdots ins bld
  | Op.FEQdotD ->
    feqdotd ins bld
  | Op.FLW ->
    flw ins bld
  | Op.FSW ->
    fsw ins bld
  | Op.FADDdotS ->
    fpArithmeticSingle ins bld AST.fadd
  | Op.FADDdotD ->
    fpArithmeticDouble ins bld AST.fadd
  | Op.FSUBdotS ->
    fpArithmeticSingle ins bld AST.fsub
  | Op.FSUBdotD ->
    fpArithmeticDouble ins bld AST.fsub
  | Op.FDIVdotS ->
    fpArithmeticSingle ins bld AST.fdiv
  | Op.FDIVdotD ->
    fpArithmeticDouble ins bld AST.fdiv
  | Op.FMULdotS ->
    fpArithmeticSingle ins bld AST.fmul
  | Op.FMULdotD ->
    fpArithmeticDouble ins bld AST.fmul
  | Op.FMINdotS ->
    fmindots ins bld
  | Op.FMINdotD ->
    fmindotd ins bld
  | Op.FMAXdotS ->
    fmaxdots ins bld
  | Op.FMAXdotD ->
    fmaxdotd ins bld
  | Op.FNMADDdotS ->
    fnmadddots ins bld
  | Op.FNMADDdotD ->
    fnmadddotd ins bld
  | Op.FNMSUBdotS ->
    fnmsubdots ins bld
  | Op.FNMSUBdotD ->
    fnmsubdotd ins bld
  | Op.FMADDdotS ->
    fmadddots ins bld
  | Op.FMADDdotD ->
    fmadddotd ins bld
  | Op.FMSUBdotS ->
    fmsubdots ins bld
  | Op.FMSUBdotD ->
    fmsubdotd ins bld
  | Op.FSQRTdotS ->
    fsqrtdots ins bld
  | Op.FSQRTdotD ->
    fsqrtdotd ins bld
  | Op.FCLASSdotS ->
    fclassdots ins bld
  | Op.FCLASSdotD ->
    fclassdotd ins bld
  | Op.FSGNJdotS ->
    fsgnjdots ins bld
  | Op.FSGNJdotD ->
    fsgnjdotd ins bld
  | Op.FSGNJNdotS ->
    fsgnjndots ins bld
  | Op.FSGNJNdotD ->
    fsgnjndotd ins bld
  | Op.FSGNJXdotS ->
    fsgnjxdots ins bld
  | Op.FSGNJXdotD ->
    fsgnjxdotd ins bld
  | Op.AMOADDdotW ->
    amow ins bld (.+)
  | Op.AMOADDdotD ->
    amod ins bld (.+)
  | Op.AMOANDdotW ->
    amow ins bld (.&)
  | Op.AMOANDdotD ->
    amod ins bld (.&)
  | Op.AMOXORdotW ->
    amow ins bld (<+>)
  | Op.AMOXORdotD ->
    amod ins bld (<+>)
  | Op.AMOORdotW ->
    amow ins bld (.|)
  | Op.AMOORdotD ->
    amod ins bld (.|)
  | Op.AMOMINdotW ->
    amow ins bld (fun a b -> AST.ite (a ?< b) (a) (b))
  | Op.AMOMINdotD ->
    amod ins bld (fun a b -> AST.ite (a ?< b) (a) (b))
  | Op.AMOMINUdotW ->
    amow ins bld (fun a b -> AST.ite (a .< b) (a) (b))
  | Op.AMOMINUdotD ->
    amod ins bld (fun a b -> AST.ite (a .< b) (a) (b))
  | Op.AMOMAXdotW ->
    amow ins bld (fun a b -> AST.ite (a ?> b) (a) (b))
  | Op.AMOMAXdotD ->
    amod ins bld (fun a b -> AST.ite (a ?> b) (a) (b))
  | Op.AMOMAXUdotW ->
    amow ins bld (fun a b -> AST.ite (a .> b) (a) (b))
  | Op.AMOMAXUdotD ->
    amod ins bld (fun a b -> AST.ite (a .> b) (a) (b))
  | Op.AMOSWAPdotW ->
    amow ins bld (fun _ b -> b)
  | Op.AMOSWAPdotD ->
    amod ins bld (fun _ b -> b)
  | Op.FMVdotXdotW ->
    fmvdotxdotw ins bld
  | Op.FMVdotXdotD ->
    fmvdotxdotd ins bld
  | Op.FMVdotWdotX ->
    fmvdotwdotx ins bld
  | Op.FMVdotDdotX ->
    fmvdotddotx ins bld
  | Op.DIVW ->
    divw ins bld
  | Op.DIV ->
    div ins bld
  | Op.DIVU ->
    divu ins bld
  | Op.REM ->
    rem ins bld
  | Op.REMU ->
    remu ins bld
  | Op.REMW ->
    remw ins bld
  | Op.DIVUW ->
    divuw ins bld
  | Op.REMUW ->
    remuw ins bld
  | Op.FCVTdotWdotD ->
    fcvtdotwdotd ins bld
  | Op.FCVTdotWUdotD ->
    fcvtdotwudotd ins bld
  | Op.FCVTdotLdotD ->
    fcvtdotldotd ins bld
  | Op.FCVTdotLUdotD ->
    fcvtdotludotd ins bld
  | Op.FCVTdotWdotS ->
    fcvtdotwdots ins bld
  | Op.FCVTdotWUdotS ->
    fcvtdotwudots ins bld
  | Op.FCVTdotLdotS ->
    fcvtdotldots ins bld
  | Op.FCVTdotLUdotS ->
    fcvtdotludots ins bld
  | Op.FENCE
  | Op.FENCEdotI
  | Op.FENCEdotTSO ->
    nop ins bld
  | Op.LRdotW
  | Op.LRdotD ->
    lr ins bld
  | Op.SCdotW ->
    sc ins bld 32<rt>
  | Op.SCdotD ->
    sc ins bld 64<rt>
  | Op.CSRRW
  | Op.CSRRWI ->
    csrrw ins bld
  | Op.CSRRS
  | Op.CSRRSI ->
    csrrs ins bld
  | Op.CSRRC
  | Op.CSRRCI ->
    csrrc ins bld
  | Op.FCVTdotSdotW ->
    fcvtdotsdotw ins bld
  | Op.FCVTdotSdotL ->
    fcvtdotsdotl ins bld
  | Op.FCVTdotSdotD ->
    fcvtdotsdotd ins bld
  | Op.FCVTdotDdotS ->
    fcvtdotddots ins bld
  | Op.FCVTdotDdotW ->
    fcvtdotddotw ins bld
  | Op.FCVTdotDdotL ->
    fcvtdotddotl ins bld
  | Op.FCVTdotDdotWU ->
    fcvtdotddotwu ins bld
  | Op.FCVTdotDdotLU ->
    fcvtdotddotlu ins bld
  | Op.FCVTdotSdotWU ->
    fcvtdotsdotwu ins bld
  | Op.FCVTdotSdotLU ->
    fcvtdotsdotlu ins bld
  | o ->
#if DEBUG
    eprintfn "%A" o
#endif
    raise <| NotImplementedIRException(Disasm.opCodeToString o)

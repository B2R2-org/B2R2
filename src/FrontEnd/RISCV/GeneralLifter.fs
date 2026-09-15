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

module internal B2R2.FrontEnd.RISCV.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.RISCV.LiftingUtils

let add ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    rd := rs1 .+ rs2
  }

let addw ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rs2 = AST.xtlo 32<rt> rs2
    rd := AST.sext 64<rt> (rs1 .+ rs2)
  }

let subw ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rs2 = AST.xtlo 32<rt> rs2
    rd := AST.sext 64<rt> (rs1 .- rs2)
  }

let sub ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    rd := rs1 .- rs2
  }

let ``and`` ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    rd := rs1 .& rs2
  }

let ``or`` ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    rd := rs1 .| rs2
  }

let xor ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    rd := rs1 <+> rs2
  }

let slt ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let cond = rs1 ?< rs2
    let rtVal = AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
    rd := rtVal
  }

let sltu ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let cond = rs1 .< rs2
    let rtVal = AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
    rd := rtVal
  }

let sll ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let shiftAmm = rs2 .& shiftMask bld
    rd := rs1 << shiftAmm
  }

let sllw ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rs2 = AST.xtlo 32<rt> rs2
    let shiftAmm = rs2 .& numU32 0x1fu 32<rt>
    rd := AST.sext 64<rt> (rs1 << shiftAmm)
  }

let srl ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let shiftAmm = rs2 .& shiftMask bld
    rd := rs1 >> shiftAmm
  }

let srlw ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rs2 = AST.xtlo 32<rt> rs2
    let shiftAmm = rs2 .& numU32 0x1fu 32<rt>
    rd := AST.sext 64<rt> (rs1 >> shiftAmm)
  }

let sra ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let shiftAmm = rs2 .& shiftMask bld
    rd := rs1 ?>> shiftAmm
  }

let sraw ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rs2 = AST.xtlo 32<rt> rs2
    let shiftAmm = rs2 .& numU32 0x1fu 32<rt>
    rd := AST.sext 64<rt> (rs1 ?>> shiftAmm)
  }

let srai ins bld =
  lift bld ins {
    let rd, rs1, shiftAmm = transThreeOprs ins bld
    rd := rs1 ?>> shiftAmm
  }

let srli ins bld =
  lift bld ins {
    let rd, rs1, shiftAmm = transThreeOprs ins bld
    rd := rs1 >> shiftAmm
  }

let slli ins bld =
  lift bld ins {
    let rd, rs1, shiftAmm = transThreeOprs ins bld
    rd := rs1 << shiftAmm
  }

let andi ins bld =
  lift bld ins {
    let rd, rs1, imm = transThreeOprs ins bld
    rd := rs1 .& imm
  }

let addi ins bld =
  lift bld ins {
    let rd, rs1, imm = transThreeOprs ins bld
    rd := rs1 .+ imm
  }

let ori ins bld =
  lift bld ins {
    let rd, rs1, imm = transThreeOprs ins bld
    rd := rs1 .| imm
  }

let xori ins bld =
  lift bld ins {
    let rd, rs1, imm = transThreeOprs ins bld
    rd := rs1 <+> imm
  }

let slti ins bld =
  lift bld ins {
    let rd, rs1, imm = transThreeOprs ins bld
    let cond = rs1 ?< imm
    let rtVal = AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
    rd := rtVal
  }

let sltiu ins bld =
  lift bld ins {
    let rd, rs1, imm = transThreeOprs ins bld
    let cond = rs1 .< imm
    let rtVal = AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
    rd := rtVal
  }

let nop (ins: Instruction) bld =
  lift bld ins {
  }

let jal ins bld =
  lift bld ins {
    let rd, jumpTarget = transTwoOprs ins bld
    let r = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
    rd := r
    AST.interjmp jumpTarget InterJmpKind.IsCall
  }

let jalr ins bld =
  lift bld ins {
    let rd, jumpTarget = transTwoOprs ins bld
    let r = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
    let target = tmpVar bld bld.RegType
    let actualTarget = if target = AST.num0 bld.RegType then rd else target
    target := jumpTarget
    rd := r
    AST.interjmp actualTarget InterJmpKind.IsRet
  }

let beq ins bld =
  lift bld ins {
    let rs1, rs2, offset = transThreeOprs ins bld
    let cond = rs1 == rs2
    let fallThrough = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
    AST.intercjmp cond offset fallThrough
  }

let bne ins bld =
  lift bld ins {
    let rs1, rs2, offset = transThreeOprs ins bld
    let cond = rs1 != rs2
    let fallThrough = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
    AST.intercjmp cond offset fallThrough
  }

let blt ins bld =
  lift bld ins {
    let rs1, rs2, offset = transThreeOprs ins bld
    let cond = rs1 ?< rs2
    let fallThrough = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
    AST.intercjmp cond offset fallThrough
  }

let bge ins bld =
  lift bld ins {
    let rs1, rs2, offset = transThreeOprs ins bld
    let cond = rs1 ?>= rs2
    let fallThrough = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
    AST.intercjmp cond offset fallThrough
  }

let bltu ins bld =
  lift bld ins {
    let rs1, rs2, offset = transThreeOprs ins bld
    let cond = rs1 .< rs2
    let fallThrough = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
    AST.intercjmp cond offset fallThrough
  }

let bgeu ins bld =
  lift bld ins {
    let rs1, rs2, offset = transThreeOprs ins bld
    let cond = rs1 .>= rs2
    let fallThrough = bvOfBaseAddr bld ins.Address .+ bvOfInstrLen bld ins
    AST.intercjmp cond offset fallThrough
  }

let load ins bld =
  lift bld ins {
    let rd, mem = transTwoOprs ins bld
    rd := AST.sext bld.RegType mem
  }

let loadu ins bld =
  lift bld ins {
    let rd, mem = transTwoOprs ins bld
    rd := AST.zext bld.RegType mem
  }

let store ins bld =
  lift bld ins {
    let rd, mem = transTwoOprs ins bld
    let accessLength = getAccessLength (snd (getTwoOprs ins))
    if accessLength = bld.RegType then append bld { mem := rd }
    else append bld { mem := AST.xtlo accessLength rd }
  }

let sideEffects (ins: Instruction) bld name =
  lift bld ins {
    AST.sideEffect name
  }

let lui ins bld =
  lift bld ins {
    let rd, imm = transTwoOprs ins bld
    rd := imm << numI32 12 bld.RegType
  }

let auipc ins bld =
  lift bld ins {
    let rd, imm = transTwoOprs ins bld
    let pc = bvOfBaseAddr bld ins.Address
    rd := pc .+ (imm << numI32 12 bld.RegType)
  }

let addiw ins bld =
  lift bld ins {
    let rd, rs1, imm = transThreeOprs ins bld
    let lowBitsRs1 = AST.xtlo 32<rt> rs1
    rd := AST.sext 64<rt> (lowBitsRs1 .+ AST.xtlo 32<rt> imm)
  }

let slliw ins bld =
  lift bld ins {
    let rd, rs1, shamt = transThreeOprs ins bld
    let lowBitsRs1 = AST.xtlo 32<rt> rs1
    rd := AST.sext 64<rt> (lowBitsRs1 << AST.xtlo 32<rt> shamt)
  }

let srliw ins bld =
  lift bld ins {
    let rd, rs1, shamt = transThreeOprs ins bld
    let lowBitsRs1 = AST.xtlo 32<rt> rs1
    rd := AST.sext 64<rt> (lowBitsRs1 >> AST.xtlo 32<rt> shamt)
  }

let sraiw ins bld =
  lift bld ins {
    let rd, rs1, shamt = transThreeOprs ins bld
    let lowBitsRs1 = AST.xtlo 32<rt> rs1
    rd := AST.sext 64<rt> (lowBitsRs1 ?>> AST.xtlo 32<rt> shamt)
  }

let mul ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    (* The low 64 bits of the product are the same for signed and unsigned,
       so a plain 64-bit multiply suffices -- no need to form the full 128-bit
       value. *)
    rd := rs1 .* rs2
  }

let mulhSignOrUnsign ins bld (isSign, isUnsign) =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    (* The high half of the product, from the intermediate twice a register
       wide that the evaluator holds: MULH signs both operands, MULHU neither,
       MULHSU only rs1 -- so the extend picks sext/zext per operand's
       signedness. *)
    let wide = bld.RegType * 2
    let prod =
      match isSign, isUnsign with
      | true, true -> AST.sext wide rs1 .* AST.sext wide rs2
      | true, false -> AST.sext wide rs1 .* AST.zext wide rs2
      | _ -> AST.zext wide rs1 .* AST.zext wide rs2
    rd := AST.xthi bld.RegType prod
  }

let mulw ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let lowBitsRs1 = AST.xtlo 32<rt> rs1
    let lowBitsRs2 = AST.xtlo 32<rt> rs2
    rd := AST.sext 64<rt> (lowBitsRs1 .* lowBitsRs2)
  }

let div ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let condZero = rs2 == AST.num0 bld.RegType
    let least = numI64 0x8000000000000000L bld.RegType
    let condOverflow =
      (rs2 == numI32 -1 bld.RegType) .& (rs1 == least)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblEnd = label bld "End"
    AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rd := numU64 0xFFFFFFFFFFFFFFFFuL bld.RegType
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp condOverflow (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    rd := rs1
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    rd := rs1 ?/ rs2
    AST.lmark lblEnd
  }

let divw ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rs2 = AST.xtlo 32<rt> rs2
    let condZero = rs2 == AST.num0 32<rt>
    let condOverflow =
      ((rs2 == numI32 -1 32<rt>) .& (rs1 == numI32 0x80000000 32<rt>))
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblEnd = label bld "End"
    AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp condOverflow (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    rd := AST.sext 64<rt> rs1
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    rd := AST.sext 64<rt> (rs1 ?/ rs2)
    AST.lmark lblEnd
  }

let divuw ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rs2 = AST.xtlo 32<rt> rs2
    let condZero = rs2 == AST.num0 32<rt>
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := AST.sext 64<rt> (rs1 ./ rs2)
    AST.lmark lblEnd
  }

let divu ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let condZero = rs2 == AST.num0 bld.RegType
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rd := numU64 0xFFFFFFFFFFFFFFFFuL bld.RegType
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := rs1 ./ rs2
    AST.lmark lblEnd
  }

let remu ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let condZero = rs2 == AST.num0 bld.RegType
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rd := rs1
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := rs1 .% rs2
    AST.lmark lblEnd
  }

let rem ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let condZero = rs2 == AST.num0 bld.RegType
    let least = numI64 0x8000000000000000L bld.RegType
    let condOverflow =
      (rs2 == numI32 -1 bld.RegType) .& (rs1 == least)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblEnd = label bld "End"
    AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rd := rs1
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp condOverflow (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    rd := AST.num0 bld.RegType
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    rd := rs1 ?% rs2
    AST.lmark lblEnd
  }

let remw ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rs2 = AST.xtlo 32<rt> rs2
    let condZero = rs2 == AST.num0 32<rt>
    let condOverflow =
      ((rs2 == numI32 -1 32<rt>) .& (rs1 == numI32 0x80000000 32<rt>))
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblL2 = label bld "L2"
    let lblL3 = label bld "L3"
    let lblEnd = label bld "End"
    AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rd := AST.sext 64<rt> rs1
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.cjmp condOverflow (AST.jmpDest lblL2) (AST.jmpDest lblL3)
    AST.lmark lblL2
    rd := AST.num0 64<rt>
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL3
    rd := AST.sext 64<rt> (rs1 ?% rs2)
    AST.lmark lblEnd
  }

let remuw ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = AST.xtlo 32<rt> rs1
    let rs2 = AST.xtlo 32<rt> rs2
    let condZero = rs2 == AST.num0 32<rt>
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rd := AST.sext 64<rt> rs1
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := AST.sext 64<rt> (rs1 .% rs2)
    AST.lmark lblEnd
  }

/// FLD loads the whole of a float register and nothing more: the value is a
/// doubleword and so is the register, on rv32 as much as on rv64, so there is
/// no extension either way. Widening it to the XLEN -- which is what this did
/// -- asks on rv32 for a sign extension of a sixty-four bit value to thirty-two
/// bits, which is not an extension at all.
let fld ins bld =
  lift bld ins {
    let rd, mem = transTwoOprs ins bld
    let condAlign = isAligned 64<rt> (getAddrFromMem mem)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    AST.cjmp condAlign (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect AtomicBegin
    rd := mem
    AST.sideEffect AtomicEnd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := mem
    AST.lmark lblEnd
  }

let fsd ins bld =
  lift bld ins {
    let rd, mem = transTwoOprs ins bld
    let condAlign = isAligned 64<rt> (getAddrFromMem mem)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    AST.cjmp condAlign (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect AtomicBegin
    mem := rd
    AST.sideEffect AtomicEnd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    mem := rd
    AST.lmark lblEnd
  }

let fltdots ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let checkNan = isNan 32<rt> rs1 .| isNan 32<rt> rs2
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let cond = AST.flt rs1 rs2
    let rtVal = AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
    let fflags = regVar bld R.FFLAGS
    AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0)
    AST.lmark lblL0
    rd := rtVal
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := numU64 0uL bld.RegType
    fflags := fflags .| numU32 16u 32<rt>
    AST.lmark lblEnd
  }

let fledots ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let checkNan = isNan 32<rt> rs1 .| isNan 32<rt> rs2
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let cond = AST.fle rs1 rs2
    let rtVal = AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
    let fflags = regVar bld R.FFLAGS
    AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0)
    AST.lmark lblL0
    rd := rtVal
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := numU64 0uL bld.RegType
    fflags := fflags .| numU32 16u 32<rt>
    AST.lmark lblEnd
  }

let feqdots ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let isSNan = isSNan 32<rt> rs1 .| isSNan 32<rt> rs2
    let checkNan = isNan 32<rt> rs1 .| isNan 32<rt> rs2
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let cond = fpEqual 32<rt> rs1 rs2
    let rtVal = AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
    let fflags = regVar bld R.FFLAGS
    let flagFscr = AST.ite isSNan (numU32 16u 32<rt>) (AST.num0 32<rt>)
    AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0)
    AST.lmark lblL0
    rd := rtVal
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := numU64 0uL bld.RegType
    fflags := fflags .| flagFscr
    AST.lmark lblEnd
  }

let fclassdots ins bld =
  lift bld ins {
    let rd, rs1 = transTwoOprs ins bld
    let rs1 = getFloat32FromReg rs1
    rd := fclassValue 32<rt> bld.RegType rs1
  }

let fclassdotd ins bld =
  lift bld ins {
    let rd, rs1 = transTwoOprs ins bld
    rd := fclassValue 64<rt> bld.RegType rs1
  }

let flw ins bld =
  lift bld ins {
    let rd, mem = transTwoOprs ins bld
    let tmp = tmpVar bld 32<rt>
    let condAlign = isAligned 32<rt> (getAddrFromMem mem)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    AST.cjmp condAlign (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect AtomicBegin
    tmp := mem
    rd := getNanBoxed tmp
    AST.sideEffect AtomicEnd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    tmp := mem
    rd := getNanBoxed tmp
    AST.lmark lblEnd
  }

let fsw ins bld =
  lift bld ins {
    let rd, mem = transTwoOprs ins bld
    let condAlign = isAligned 32<rt> (getAddrFromMem mem)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    AST.cjmp condAlign (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect AtomicBegin
    mem := AST.xtlo 32<rt> rd
    AST.sideEffect AtomicEnd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    mem := AST.xtlo 32<rt> rd
    AST.lmark lblEnd
  }

let fltdotd ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let checkNan = isNan 64<rt> rs1 .| isNan 64<rt> rs2
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let cond = AST.flt rs1 rs2
    let rtVal = AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
    let fflags = regVar bld R.FFLAGS
    AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0)
    AST.lmark lblL0
    rd := rtVal
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := numU64 0uL bld.RegType
    fflags := fflags .| numU32 16u 32<rt>
    AST.lmark lblEnd
  }

let fledotd ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let checkNan = isNan 64<rt> rs1 .| isNan 64<rt> rs2
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let cond = AST.fle rs1 rs2
    let rtVal = AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
    let fflags = regVar bld R.FFLAGS
    AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0)
    AST.lmark lblL0
    rd := rtVal
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := numU64 0uL bld.RegType
    fflags := fflags .| numU32 16u 32<rt>
    AST.lmark lblEnd
  }

let feqdotd ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let isSNan = isSNan 64<rt> rs1 .| isSNan 64<rt> rs2
    let checkNan = isNan 64<rt> rs1 .| isNan 64<rt> rs2
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let cond = fpEqual 64<rt> rs1 rs2
    let rtVal = AST.ite cond (AST.num1 bld.RegType) (AST.num0 bld.RegType)
    let fflags = regVar bld R.FFLAGS
    let flagFscr = AST.ite isSNan (numU32 16u 32<rt>) (AST.num0 32<rt>)
    AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0)
    AST.lmark lblL0
    rd := rtVal
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := numU64 0uL bld.RegType
    fflags := fflags .| flagFscr
    AST.lmark lblEnd
  }

/// <summary>
/// The arithmetic that reads two floating registers and writes a third -- and
/// the one ordering the lifter has to keep straight.
///
/// The flags an operation raises are a function of its OPERANDS, and rd may be
/// one of them: FDIV.S fa5, fa4, fa5 is an ordinary encoding and a compiler
/// emits it freely. So the exceptions have to be recorded before the
/// destination is written, and under the rounding direction the instruction
/// named rather than the ambient one -- which puts the whole of the work
/// between entering that direction and leaving it, with only the store to rd
/// left outside.
/// </summary>
let fpArithmeticSingle ins bld excOp operator =
  lift bld ins {
    let rd, rs1, rs2, rm = getFourOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let mode = staticRounding rm
    let value = tmpVar bld 32<rt>
    value := underRounding mode (operator rs1 rs2)
    accrueFlags bld mode 32<rt> excOp rs1 rs2
    rd := getNanBoxed (fpCanonical 32<rt> value)
  }

let fpArithmeticDouble ins bld excOp operator =
  lift bld ins {
    let rd, rs1, rs2, rm = getFourOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let mode = staticRounding rm
    let value = tmpVar bld 64<rt>
    value := underRounding mode (operator rs1 rs2)
    accrueFlags bld mode 64<rt> excOp rs1 rs2
    rd := fpCanonical 64<rt> value
  }

let fsqrtdots ins bld =
  lift bld ins {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let rs1 = getFloat32FromReg rs1
    let mode = staticRounding rm
    let root = tmpVar bld 32<rt>
    root := underRounding mode (AST.fsqrt rs1)
    accrueFlags bld mode 32<rt> FpExc.Sqrt rs1 rs1
    rd := getNanBoxed (fpCanonical 32<rt> root)
  }

let fsqrtdotd ins bld =
  lift bld ins {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let mode = staticRounding rm
    let root = tmpVar bld 64<rt>
    root := underRounding mode (AST.fsqrt rs1)
    accrueFlags bld mode 64<rt> FpExc.Sqrt rs1 rs1
    rd := fpCanonical 64<rt> root
  }

let fmindots ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rtVal = tmpVar bld 32<rt>
    rtVal := fpMinMax 32<rt> true rs1 rs2
    accrueFlags bld None 32<rt> FpExc.MinMax rs1 rs2
    rd := getNanBoxed rtVal
  }

let fmindotd ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rtVal = tmpVar bld 64<rt>
    rtVal := fpMinMax 64<rt> true rs1 rs2
    accrueFlags bld None 64<rt> FpExc.MinMax rs1 rs2
    rd := rtVal
  }

let fmaxdots ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rtVal = tmpVar bld 32<rt>
    rtVal := fpMinMax 32<rt> false rs1 rs2
    accrueFlags bld None 32<rt> FpExc.MinMax rs1 rs2
    rd := getNanBoxed rtVal
  }

let fmaxdotd ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rtVal = tmpVar bld 64<rt>
    rtVal := fpMinMax 64<rt> false rs1 rs2
    accrueFlags bld None 64<rt> FpExc.MinMax rs1 rs2
    rd := rtVal
  }

let fmadddots ins bld =
  lift bld ins {
    let rd, rs1, rs2, rs3, rm = getFiveOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs3 = transOpr ins bld rs3
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rs3 = getFloat32FromReg rs3
    let mode = staticRounding rm
    let fused = tmpVar bld 32<rt>
    fused := underRounding mode (fpFused 32<rt> false false rs1 rs2 rs3)
    accrueFmaFlags bld mode 32<rt> false false rs1 rs2 rs3
    rd := getNanBoxed (fpCanonical 32<rt> fused)
  }

let fmadddotd ins bld =
  lift bld ins {
    let rd, rs1, rs2, rs3, rm = getFiveOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs3 = transOpr ins bld rs3
    let mode = staticRounding rm
    let fused = tmpVar bld 64<rt>
    fused := underRounding mode (fpFused 64<rt> false false rs1 rs2 rs3)
    accrueFmaFlags bld mode 64<rt> false false rs1 rs2 rs3
    rd := fpCanonical 64<rt> fused
  }

let fmsubdots ins bld =
  lift bld ins {
    let rd, rs1, rs2, rs3, rm = getFiveOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs3 = transOpr ins bld rs3
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rs3 = getFloat32FromReg rs3
    let mode = staticRounding rm
    let fused = tmpVar bld 32<rt>
    fused := underRounding mode (fpFused 32<rt> false true rs1 rs2 rs3)
    accrueFmaFlags bld mode 32<rt> false true rs1 rs2 rs3
    rd := getNanBoxed (fpCanonical 32<rt> fused)
  }

let fmsubdotd ins bld =
  lift bld ins {
    let rd, rs1, rs2, rs3, rm = getFiveOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs3 = transOpr ins bld rs3
    let mode = staticRounding rm
    let fused = tmpVar bld 64<rt>
    fused := underRounding mode (fpFused 64<rt> false true rs1 rs2 rs3)
    accrueFmaFlags bld mode 64<rt> false true rs1 rs2 rs3
    rd := fpCanonical 64<rt> fused
  }

let fnmsubdots ins bld =
  lift bld ins {
    let rd, rs1, rs2, rs3, rm = getFiveOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs3 = transOpr ins bld rs3
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rs3 = getFloat32FromReg rs3
    let mode = staticRounding rm
    let fused = tmpVar bld 32<rt>
    fused := underRounding mode (fpFused 32<rt> true false rs1 rs2 rs3)
    accrueFmaFlags bld mode 32<rt> true false rs1 rs2 rs3
    rd := getNanBoxed (fpCanonical 32<rt> fused)
  }

let fnmsubdotd ins bld =
  lift bld ins {
    let rd, rs1, rs2, rs3, rm = getFiveOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs3 = transOpr ins bld rs3
    let mode = staticRounding rm
    let fused = tmpVar bld 64<rt>
    fused := underRounding mode (fpFused 64<rt> true false rs1 rs2 rs3)
    accrueFmaFlags bld mode 64<rt> true false rs1 rs2 rs3
    rd := fpCanonical 64<rt> fused
  }

let fnmadddots ins bld =
  lift bld ins {
    let rd, rs1, rs2, rs3, rm = getFiveOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs3 = transOpr ins bld rs3
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rs3 = getFloat32FromReg rs3
    let mode = staticRounding rm
    let fused = tmpVar bld 32<rt>
    fused := underRounding mode (fpFused 32<rt> true true rs1 rs2 rs3)
    accrueFmaFlags bld mode 32<rt> true true rs1 rs2 rs3
    rd := getNanBoxed (fpCanonical 32<rt> fused)
  }

let fnmadddotd ins bld =
  lift bld ins {
    let rd, rs1, rs2, rs3, rm = getFiveOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs3 = transOpr ins bld rs3
    let mode = staticRounding rm
    let fused = tmpVar bld 64<rt>
    fused := underRounding mode (fpFused 64<rt> true true rs1 rs2 rs3)
    accrueFmaFlags bld mode 64<rt> true true rs1 rs2 rs3
    rd := fpCanonical 64<rt> fused
  }

let fsgnjdots ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rtVal = tmpVar bld 32<rt>
    let mask = numU32 0x7fffffffu 32<rt>
    let sign = getSignFloat 32<rt> rs2
    rtVal := (rs1 .& mask) .| sign
    rd := getNanBoxed rtVal
  }

let fsgnjdotd ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rtVal = tmpVar bld 64<rt>
    let mask = numU64 0x7FFFFFFFFFFFFFFFuL 64<rt>
    let sign = getSignFloat 64<rt> rs2
    rtVal := (rs1 .& mask) .| sign
    rd := rtVal
  }

let fsgnjndots ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rtVal = tmpVar bld 32<rt>
    let mask = numU32 0x7fffffffu 32<rt>
    let sign = getSignFloat 32<rt> rs2 <+> numU32 0x80000000u 32<rt>
    rtVal := (rs1 .& mask) .| sign
    rd := getNanBoxed rtVal
  }

let fsgnjndotd ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rtVal = tmpVar bld 64<rt>
    let mask = numU64 0x7FFFFFFFFFFFFFFFuL 64<rt>
    let sign = getSignFloat 64<rt> rs2 <+> numU64 0x8000000000000000uL 64<rt>
    rtVal := (rs1 .& mask) .| sign
    rd := rtVal
  }

let fsgnjxdots ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rtVal = tmpVar bld 32<rt>
    let mask = numU32 0x7fffffffu 32<rt>
    let sign = (getSignFloat 32<rt> rs2) <+> (getSignFloat 32<rt> rs1)
    rtVal := (rs1 .& mask) .| sign
    rd := getNanBoxed rtVal
  }

let fsgnjxdotd ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rtVal = tmpVar bld 64<rt>
    let mask = numU64 0x7FFFFFFFFFFFFFFFuL 64<rt>
    let sign = getSignFloat 64<rt> rs2 <+> getSignFloat 64<rt> rs1
    rtVal := (rs1 .& mask) .| sign
    rd := rtVal
  }

(* FIX ME: AQRL *)
let amod ins bld op =
  lift bld ins {
    let rd, rs2, mem, _ = transFourOprs ins bld
    let cond = isAligned 64<rt> (getAddrFromMem mem)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let tmp = tmpVar bld 64<rt>
    AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect AtomicBegin
    tmp := mem
    mem := op tmp rs2
    rd := tmp
    AST.sideEffect AtomicEnd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.sideEffect (Exception MisalignedAccess)
    AST.lmark lblEnd
  }

let amow ins bld op =
  lift bld ins {
    let rd, rs2, mem, _ = transFourOprs ins bld
    let rs2 = AST.xtlo 32<rt> rs2
    let cond = isAligned 32<rt> (getAddrFromMem mem)
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    let tmp = tmpVar bld 32<rt>
    AST.cjmp cond (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    AST.sideEffect AtomicBegin
    tmp := mem
    mem := op tmp rs2
    rd := AST.sext bld.RegType tmp
    AST.sideEffect AtomicEnd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.sideEffect (Exception MisalignedAccess)
    AST.lmark lblEnd
  }

/// FMV.X.W moves bits and does not interpret them: "the bits are not modified
/// in the transfer, and in particular, the payloads of non-canonical NaNs are
/// preserved" (unprivileged ISA, the single-precision move instructions). So
/// unlike every arithmetic instruction reading a single it must NOT check the
/// NaN box -- the low word goes out as it stands even where the upper half
/// says the register holds something that is not a single at all. On rv64 that
/// word is sign-extended into the destination; on rv32 it fills it.
let fmvdotxdotw ins bld =
  lift bld ins {
    let rd, rs1 = transTwoOprs ins bld
    rd := AST.sext bld.RegType (AST.xtlo 32<rt> rs1)
  }

let fmvdotwdotx ins bld =
  lift bld ins {
    let rd, rs1 = transTwoOprs ins bld
    rd := getNanBoxed (AST.xtlo 32<rt> rs1)
  }

let fmvdotxdotd ins bld =
  lift bld ins {
    let rd, rs1 = transTwoOprs ins bld
    rd := rs1
  }

let fmvdotddotx ins bld =
  lift bld ins {
    let rd, rs1 = transTwoOprs ins bld
    rd := rs1
  }

let csrrw ins bld =
  lift bld ins {
    let rd, csr, src = getThreeOprs ins
    let oprs = transOpr ins bld csr, transOpr ins bld src
    let csr, src = maskForFCSR csr oprs
    AST.sideEffect AtomicBegin
    match rd with
    | OpReg Register.X0 ->
      assignFCSR csr src bld
    | _ ->
      let rd = transOpr ins bld rd
      let tmpVar = tmpVar bld bld.RegType
      tmpVar := AST.zext bld.RegType csr
      assignFCSR csr src bld
      rd := tmpVar
    AST.sideEffect AtomicEnd
  }

let csrrs ins bld =
  lift bld ins {
    let rd, csr, src = getThreeOprs ins
    AST.sideEffect AtomicBegin
    match rd, csr, src with
    | OpReg rdReg, OpCSR(3072us | 3073us | 3074us), OpReg Register.X0 ->
      (* rdcycle/rdtime/rdinstret (csrrs rd, cycle|time|instret, x0): the
         counter has no real CSR to read, so leave the value to the emulator
         through a ClockCounterRead side effect naming rd (a whole 64-bit read
         on RV64). *)
      AST.sideEffect
        (ClockCounterRead(Some(Register.toRegID rdReg, false)))
    | _ ->
      let rd = transOpr ins bld rd
      match src with
      | OpReg Register.X0 ->
        let csr = transOpr ins bld csr
        rd := AST.zext bld.RegType csr
      | _ ->
        let oprs = transOpr ins bld csr, transOpr ins bld src
        let csr, src = maskForFCSR csr oprs
        let tmpVar = tmpVar bld bld.RegType
        tmpVar := AST.zext bld.RegType csr
        assignFCSR csr (csr .| src) bld
        rd := tmpVar
    AST.sideEffect AtomicEnd
  }

let csrrc ins bld =
  lift bld ins {
    let rd, csr, src = getThreeOprs ins
    let rd = transOpr ins bld rd
    AST.sideEffect AtomicBegin
    match src with
    | OpReg Register.X0 ->
      let csr = transOpr ins bld csr
      rd := AST.zext bld.RegType csr
    | _ ->
      let oprs = transOpr ins bld csr, transOpr ins bld src
      let csr, src = maskForFCSR csr oprs
      let tmpVar = tmpVar bld bld.RegType
      tmpVar := AST.zext bld.RegType csr
      assignFCSR csr (csr .& AST.neg src) bld
      rd := tmpVar
    AST.sideEffect AtomicEnd
  }

/// Saturates a converted value to the destination's range: past either bound
/// it clamps, a NaN gives the high end, and each infinity goes to its own.
/// Every `fcvt` below closes this way, differing only in where the bounds sit.
let private clampConversion bld rd rtVal conds bounds =
  append bld {
    let condNaN, condInf, sign = conds
    let loFl, hiFl, lo, hi = bounds
    rd := AST.ite (AST.fle rtVal loFl) lo rd
    rd := AST.ite (AST.fge rtVal hiFl) hi rd
    rd := AST.ite condNaN hi rd
    rd := AST.ite (condInf .& AST.not sign) hi rd
    rd := AST.ite (condInf .& sign) lo rd
  }

/// The same, pinning the rounded float itself instead of the register it is
/// about to be converted into. The bounds are then the float bounds, and
/// there is no separate value to clamp to.
let private clampRounded bld rtVal conds bounds =
  append bld {
    let condNaN, condInf, sign = conds
    let loFl, hiFl = bounds
    rtVal := AST.ite (AST.fle rtVal loFl) loFl rtVal
    rtVal := AST.ite (AST.fge rtVal hiFl) hiFl rtVal
    rtVal := AST.ite condNaN hiFl rtVal
    rtVal := AST.ite (condInf .& AST.not sign) hiFl rtVal
    rtVal := AST.ite (condInf .& sign) loFl rtVal
  }

let fcvtdotldotd ins bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
  let llMaxInFloat = numU64 0x43e0000000000000uL 64<rt>
  let llMinInFloat = numU64 0xc3e0000000000000uL 64<rt>
  let llMax = numU64 0x7fffffffffffffffuL 64<rt>
  let llMin = numU64 0x8000000000000000uL 64<rt>
  let condInf = isInf 64<rt> rs1
  let condNaN = isNan 64<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  let conds = condNaN, condInf, sign
  let bounds = llMinInFloat, llMaxInFloat, llMin, llMax
  lift bld ins {
    let mode = staticRounding rm
    accrueFlags bld mode 64<rt> FpExc.ToSInt rs1 (numI32 64 32<rt>)
    (* rounded value *)
    let rtVal = tmpVar bld 64<rt>
    rtVal := underRounding mode (AST.cast CastKind.RoundToIntegral 64<rt> rs1)
    let rdVal = underRounding mode (AST.cast CastKind.FloatToSInt 64<rt> rtVal)
    rd := rdVal
    clampConversion bld rd rtVal conds bounds
  }

let fcvtdotludotd ins bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
  let ullMaxInFloat = numU64 0x43f0000000000000uL 64<rt>
  let ullMinInFloat = numU64 0uL 64<rt>
  let ullMax = numU64 0xffffffffffffffffuL 64<rt>
  let ullMin = numI32 0 64<rt>
  let condInf = isInf 64<rt> rs1
  let condNaN = isNan 64<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  let conds = condNaN, condInf, sign
  let bounds = ullMinInFloat, ullMaxInFloat, ullMin, ullMax
  lift bld ins {
    let mode = staticRounding rm
    accrueFlags bld mode 64<rt> FpExc.ToUInt rs1 (numI32 64 32<rt>)
    (* rounded value *)
    let rtVal = tmpVar bld 64<rt>
    rtVal := underRounding mode (AST.cast CastKind.RoundToIntegral 64<rt> rs1)
    let rdVal = underRounding mode (AST.cast CastKind.FloatToSInt 64<rt> rtVal)
    rd := rdVal
    clampConversion bld rd rtVal conds bounds
  }

let fcvtdotwdotd ins bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
  let intMaxInFloat = numU64 0x41dfffffffc00000uL 64<rt>
  let intMinInFloat = numU64 0xc1e0000000000000uL 64<rt>
  let intMax = AST.sext bld.RegType (numU32 0x7fffffffu 32<rt>)
  let intMin = AST.sext bld.RegType (numU32 0x80000000u 32<rt>)
  let condInf = isInf 64<rt> rs1
  let condNaN = isNan 64<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  let conds = condNaN, condInf, sign
  let bounds = intMinInFloat, intMaxInFloat, intMin, intMax
  lift bld ins {
    let mode = staticRounding rm
    accrueFlags bld mode 64<rt> FpExc.ToSInt rs1 (numI32 32 32<rt>)
    (* rounded value *)
    let rtVal = tmpVar bld 64<rt>
    rtVal := underRounding mode (AST.cast CastKind.RoundToIntegral 64<rt> rs1)
    let rdVal = underRounding mode (AST.cast CastKind.FloatToSInt 32<rt> rtVal)
    rd := AST.sext bld.RegType rdVal
    clampConversion bld rd rtVal conds bounds
  }

let fcvtdotwudotd ins bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
  let uintMaxInFloat = numU64 0x41efffffffe00000uL 64<rt>
  let uintMinInFloat = numU64 0uL 64<rt>
  let uintMax = numU64 0xffffffffffffffffuL bld.RegType
  let uintMin = numU64 0uL bld.RegType
  let condInf = isInf 64<rt> rs1
  let condNaN = isNan 64<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  let conds = condNaN, condInf, sign
  let bounds = uintMinInFloat, uintMaxInFloat, uintMin, uintMax
  lift bld ins {
    let mode = staticRounding rm
    accrueFlags bld mode 64<rt> FpExc.ToUInt rs1 (numI32 32 32<rt>)
    (* rounded value *)
    let rtVal = tmpVar bld 64<rt>
    rtVal := underRounding mode (AST.cast CastKind.RoundToIntegral 64<rt> rs1)
    (* The conversion is to an UNSIGNED word, and the IR's float-to-
       integer casts are signed: a value in [2^31, 2^32) would come
       back as the integer indefinite rather than as itself. Going
       through a doubleword, which holds the whole unsigned range with
       room to spare, and keeping its low word is the same conversion
       with nothing to saturate. *)
    let rdVal = underRounding mode (AST.cast CastKind.FloatToSInt 64<rt> rtVal)
    rd := AST.sext bld.RegType (AST.xtlo 32<rt> rdVal)
    clampConversion bld rd rtVal conds bounds
  }

let fcvtdotwdots ins bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
  let rs1 = getFloat32FromReg rs1
  let intMaxInFloat = numU32 0x4f000000u 32<rt>
  let intMinInFloat = numU32 0xcf000000u 32<rt>
  let intMax = numU32 0x7fffffffu bld.RegType
  let intMin = numU64 0xffffffff80000000uL bld.RegType
  let condInf = isInf 32<rt> rs1
  let condNaN = isNan 32<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  let conds = condNaN, condInf, sign
  let bounds = intMinInFloat, intMaxInFloat, intMin, intMax
  lift bld ins {
    let mode = staticRounding rm
    accrueFlags bld mode 32<rt> FpExc.ToSInt rs1 (numI32 32 32<rt>)
    (* rounded value *)
    let rtVal = tmpVar bld 32<rt>
    rtVal := underRounding mode (AST.cast CastKind.RoundToIntegral 32<rt> rs1)
    let rdVal = underRounding mode (AST.cast CastKind.FloatToSInt 32<rt> rtVal)
    rd := AST.sext bld.RegType rdVal
    clampConversion bld rd rtVal conds bounds
  }

let fcvtdotwudots ins bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
  let rs1 = getFloat32FromReg rs1
  let uintMaxInFloat = numU32 0x4f800000u 32<rt>
  let uintMinInFloat = numU32 0x0u 32<rt>
  let uintMax = numU64 0xffffffffffffffffUL bld.RegType
  let uintMin = numU32 0x0u bld.RegType
  let condInf = isInf 32<rt> rs1
  let condNaN = isNan 32<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  let conds = condNaN, condInf, sign
  let bounds = uintMinInFloat, uintMaxInFloat, uintMin, uintMax
  lift bld ins {
    let mode = staticRounding rm
    accrueFlags bld mode 32<rt> FpExc.ToUInt rs1 (numI32 32 32<rt>)
    (* rounded value *)
    let rtVal = tmpVar bld 32<rt>
    rtVal := underRounding mode (AST.cast CastKind.RoundToIntegral 32<rt> rs1)
    (* The conversion is to an UNSIGNED word, and the IR's float-to-
       integer casts are signed: a value in [2^31, 2^32) would come
       back as the integer indefinite rather than as itself. Going
       through a doubleword, which holds the whole unsigned range with
       room to spare, and keeping its low word is the same conversion
       with nothing to saturate. *)
    let rdVal = underRounding mode (AST.cast CastKind.FloatToSInt 64<rt> rtVal)
    rd := AST.sext bld.RegType (AST.xtlo 32<rt> rdVal)
    clampConversion bld rd rtVal conds bounds
  }

let fcvtdotldots ins bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
  let rs1 = getFloat32FromReg rs1
  let llMaxInFloat = numU64 0x43e0000000000000uL 64<rt>
  let llMinInFloat = numU64 0xc3e0000000000000uL 64<rt>
  let condInf = isInf 32<rt> rs1
  let condNaN = isNan 32<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  let conds = condNaN, condInf, sign
  let bounds = llMinInFloat, llMaxInFloat
  lift bld ins {
    let mode = staticRounding rm
    accrueFlags bld mode 32<rt> FpExc.ToSInt rs1 (numI32 64 32<rt>)
    (* rounded value *)
    let t0 = underRounding mode (AST.cast CastKind.RoundToIntegral 32<rt> rs1)
    let rtVal = tmpVar bld 64<rt>
    (* check for out-of-range *)
    rtVal := AST.cast CastKind.FloatCast 64<rt> t0
    clampRounded bld rtVal conds bounds
    let rdVal = underRounding mode (AST.cast CastKind.FloatToSInt 64<rt> rtVal)
    rd := rdVal
  }

let fcvtdotludots ins bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
  let rs1 = getFloat32FromReg rs1
  let llMaxInFloat = numU64 0x43e0000000000000uL 64<rt>
  let llMinInFloat = numU64 0uL 64<rt>
  let llMax = numU64 0xffffffffffffffffuL 64<rt>
  let llMin = numU64 0uL 64<rt>
  let condInf = isInf 32<rt> rs1
  let condNaN = isNan 32<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  let conds = condNaN, condInf, sign
  let bounds = llMinInFloat, llMaxInFloat, llMin, llMax
  lift bld ins {
    let mode = staticRounding rm
    accrueFlags bld mode 32<rt> FpExc.ToUInt rs1 (numI32 64 32<rt>)
    (* rounded value *)
    let t0 = underRounding mode (AST.cast CastKind.RoundToIntegral 32<rt> rs1)
    let rtVal = tmpVar bld 64<rt>
    (* check for out-of-range *)
    rtVal := AST.cast CastKind.FloatCast 64<rt> t0
    (* A float-to-integer conversion, not a second widening: what stood here
       cast the already-widened double to a double again and stored that in an
       integer register. FCVT.LU.S is rv64-only, so nothing on rv32 reaches
       it. *)
    rd := underRounding mode (AST.cast CastKind.FloatToSInt 64<rt> rtVal)
    clampConversion bld rd rtVal conds bounds
  }

let fcvtdotsdotw ins bld =
  lift bld ins {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let rs1 = AST.xtlo 32<rt> rs1
    let value = AST.cast CastKind.SIntToFloat 32<rt> rs1
    rd := getNanBoxed (underRounding (staticRounding rm) value)
  }

let fcvtdotsdotwu ins bld =
  lift bld ins {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let rs1 = AST.xtlo 32<rt> rs1
    let value = AST.cast CastKind.UIntToFloat 32<rt> rs1
    rd := getNanBoxed (underRounding (staticRounding rm) value)
  }

let fcvtdotsdotl ins bld =
  lift bld ins {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let value = AST.cast CastKind.SIntToFloat 32<rt> rs1
    rd := getNanBoxed (underRounding (staticRounding rm) value)
  }

let fcvtdotsdotlu ins bld =
  lift bld ins {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let value = AST.cast CastKind.UIntToFloat 32<rt> rs1
    rd := getNanBoxed (underRounding (staticRounding rm) value)
  }

let fcvtdotddotw ins bld =
  lift bld ins {
    let rd, rs1 = transTwoOprs ins bld
    rd := AST.cast CastKind.SIntToFloat 64<rt> (AST.xtlo 32<rt> rs1)
  }

let fcvtdotddotwu ins bld =
  lift bld ins {
    let rd, rs1 = transTwoOprs ins bld
    rd := AST.cast CastKind.UIntToFloat 64<rt> (AST.xtlo 32<rt> rs1)
  }

let fcvtdotddotl ins bld =
  lift bld ins {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let value = AST.cast CastKind.SIntToFloat 64<rt> rs1
    rd := underRounding (staticRounding rm) value
  }

let fcvtdotddotlu ins bld =
  lift bld ins {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let value = AST.cast CastKind.UIntToFloat 64<rt> rs1
    rd := underRounding (staticRounding rm) value
  }

/// FCVT.S.D narrows, and a narrowing is the one conversion between the two
/// floating formats where a rounding direction is felt: every single is a
/// double exactly, so the widening FCVT.D.S has nothing to round. The
/// direction belongs to the narrowing itself rather than to a pass over the
/// result afterwards, which is why the cast is what goes under the direction
/// rather than what came out of it.
let fcvtdotsdotd ins bld =
  lift bld ins {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let value = AST.cast CastKind.FloatCast 32<rt> rs1
    let single = underRounding (staticRounding rm) value
    rd := getNanBoxed (fpCanonical 32<rt> single)
  }

/// FCVT.D.S widens, which is exact for every single there is, so no rounding
/// direction can reach it. What it still owes is the canonical NaN: the host's
/// own widening carries a NaN's payload across, and RISC-V answers every
/// invalid operation with one pattern.
let fcvtdotddots ins bld =
  lift bld ins {
    let rd, rs1, _ = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let rs1 = getFloat32FromReg rs1
    rd := fpCanonical 64<rt> (AST.cast CastKind.FloatCast 64<rt> rs1)
  }

/// Load-reserved (LR.W/LR.D): records an exclusive reservation -- the reserved
/// address and the value read there -- so a later store-conditional can tell,
/// by value comparison, whether the location was written in between.
let lr ins bld =
  lift bld ins {
    let rd, mem, _ = transThreeOprs ins bld
    let addr = getAddrFromMem mem
    let sz =
      match mem with
      | Load(_, sz, _, _) -> sz
      | _ -> raise InvalidExprException
    let v = tmpVar bld sz
    AST.sideEffect AtomicBegin
    v := mem
    regVar bld R.ExMonAddr := addr
    regVar bld R.ExMonVal := AST.zext bld.RegType v
    rd := AST.sext bld.RegType v
    AST.sideEffect AtomicEnd
  }

/// <summary>
/// Store-conditional (SC.W/SC.D): stores and reports success (rd = 0) only if
/// the reservation still holds -- the address matches and memory still holds
/// the reserved value; otherwise memory is left unchanged and it reports
/// failure (rd = 1). The conditional store is a store of ite(matched, data,
/// old), so no branch is emitted.
///
/// Whether it stored or not, the reservation is gone afterwards: "regardless
/// of success or failure, executing an SC.W instruction invalidates any
/// reservation held by this hart" (unprivileged ISA, load-reserved and
/// store-conditional). Leaving it in place makes a second SC.W succeed
/// whenever the value the first one wrote happens to equal the value that was
/// reserved -- which is not a rare coincidence but the ordinary outcome of a
/// preceding AMOMAX, and an SC with no reservation behind it must always fail.
///
/// What marks it invalid is an address the comparison can never match. A
/// reservation is only ever made by an LR, which requires its address to be
/// naturally aligned, so an address with every bit set is one no live
/// reservation can hold.
/// </summary>
let sc ins bld oprSz =
  lift bld ins {
    let rd, rs2, mem, _ = transFourOprs ins bld
    let addr = getAddrFromMem mem
    let cur = tmpVar bld oprSz
    let matched = tmpVar bld 1<rt>
    AST.sideEffect AtomicBegin
    cur := mem
    matched := (addr == regVar bld R.ExMonAddr)
               .& (cur == AST.xtlo oprSz (regVar bld R.ExMonVal))
    mem := AST.ite matched (AST.xtlo oprSz rs2) cur
    rd := AST.ite matched (AST.num0 bld.RegType) (AST.num1 bld.RegType)
    regVar bld R.ExMonAddr := AST.not (AST.num0 bld.RegType)
    AST.sideEffect AtomicEnd
  }

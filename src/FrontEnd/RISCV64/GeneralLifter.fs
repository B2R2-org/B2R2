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

module internal B2R2.FrontEnd.RISCV64.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.RISCV64.LiftingUtils

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
    let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
    rd := rtVal
  }

let sltu ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let cond = rs1 .< rs2
    let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
    rd := rtVal
  }

let sll ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let shiftAmm = rs2 .& numU64 0x3fUL 64<rt>
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
    let shiftAmm = rs2 .& numU64 0x3fUL 64<rt>
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
    let shiftAmm = rs2 .& numU64 0x3fUL 64<rt>
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
    let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
    rd := rtVal
  }

let sltiu ins bld =
  lift bld ins {
    let rd, rs1, imm = transThreeOprs ins bld
    let cond = rs1 .< imm
    let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
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
    let target = tmpVar bld 64<rt>
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
    if accessLength = 64<rt> then append bld { mem := rd }
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
    (* The high 64 bits of the 64x64->128 product, from the 128-bit intermediate
       the evaluator holds: MULH signs both operands, MULHU neither, MULHSU only
       rs1 -- so the extend picks sext/zext per operand's signedness. *)
    let prod =
      match isSign, isUnsign with
      | true, true -> AST.sext 128<rt> rs1 .* AST.sext 128<rt> rs2
      | true, false -> AST.sext 128<rt> rs1 .* AST.zext 128<rt> rs2
      | _ -> AST.zext 128<rt> rs1 .* AST.zext 128<rt> rs2
    rd := AST.xthi 64<rt> prod
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
    let condZero = rs2 == AST.num0 64<rt>
    let condOverflow =
      ((rs2 == numI32 -1 64<rt>) .& (rs1 == numI64 0x8000000000000000L 64<rt>))
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
    let condZero = rs2 == AST.num0 64<rt>
    let lblL0 = label bld "L0"
    let lblL1 = label bld "L1"
    let lblEnd = label bld "End"
    AST.cjmp condZero (AST.jmpDest lblL0) (AST.jmpDest lblL1)
    AST.lmark lblL0
    rd := numU64 0xFFFFFFFFFFFFFFFFuL 64<rt>
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := rs1 ./ rs2
    AST.lmark lblEnd
  }

let remu ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let condZero = rs2 == AST.num0 64<rt>
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
    let condZero = rs2 == AST.num0 64<rt>
    let condOverflow =
      ((rs2 == numI32 -1 64<rt>) .& (rs1 == numI64 0x8000000000000000L 64<rt>))
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
    rd := AST.num0 64<rt>
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
    rd := AST.sext bld.RegType mem
    AST.sideEffect AtomicEnd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := AST.sext bld.RegType mem
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
    rd := numU64 0uL 64<rt>
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
    let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
    let fflags = regVar bld R.FFLAGS
    AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0)
    AST.lmark lblL0
    rd := rtVal
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := numU64 0uL 64<rt>
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
    let cond = rs1 == rs2
    let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
    let fflags = regVar bld R.FFLAGS
    let flagFscr = AST.ite (isSNan) (numU32 16u 32<rt>) (AST.num0 32<rt>)
    AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0)
    AST.lmark lblL0
    rd := rtVal
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := numU64 0uL 64<rt>
    fflags := fflags .| flagFscr
    AST.lmark lblEnd
  }

let fclassdots ins bld =
  lift bld ins {
    let rd, rs1 = transTwoOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let plusZero = numU32 0u 32<rt>
    let negZero = numU32 0x80000000u 32<rt>
    let sign = AST.extract rs1 1<rt> 31
    let lblPos = label bld "Pos"
    let lblNeg = label bld "Neg"
    let lblEnd = label bld "End"
    let condZero = (rs1 == plusZero) .| (rs1 == negZero)
    let condInf = isInf 32<rt> rs1
    let condSubnormal = isSubnormal 32<rt> rs1
    let condSNan = isSNan 32<rt> rs1
    let condQNan = isQNan 32<rt> rs1
    rd := AST.num0 64<rt>
    AST.cjmp sign (AST.jmpDest lblNeg) (AST.jmpDest lblPos)
    AST.lmark lblPos
    rd := AST.ite condInf (numU32 (1u <<< 7) 64<rt>) rd
    rd := AST.ite condZero (numU32 (1u <<< 4) 64<rt>) rd
    rd := AST.ite condSubnormal (numU32 (1u <<< 5) 64<rt>) rd
    rd := AST.ite condQNan (numU32 (1u <<< 9) 64<rt>) rd
    rd := AST.ite condSNan (numU32 (1u <<< 8) 64<rt>) rd
    rd := AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 6) 64<rt>) rd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblNeg
    rd := AST.ite condInf (numU32 (1u <<< 0) 64<rt>) rd
    rd := AST.ite condZero (numU32 (1u <<< 3) 64<rt>) rd
    rd := AST.ite condSubnormal (numU32 (1u <<< 2) 64<rt>) rd
    rd := AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 1) 64<rt>) rd
    AST.lmark lblEnd
  }

let fclassdotd ins bld =
  lift bld ins {
    let rd, rs1 = transTwoOprs ins bld
    let plusZero = numU64 0uL 64<rt>
    let negZero = numU64 0x8000000000000000uL 64<rt>
    let sign = AST.extract rs1 1<rt> 63
    let lblPos = label bld "Pos"
    let lblNeg = label bld "Neg"
    let lblEnd = label bld "End"
    let condZero = (rs1 == plusZero) .| (rs1 == negZero)
    let condInf = isInf 64<rt> rs1
    let condSubnormal = isSubnormal 64<rt> rs1
    let condSNan = isSNan 64<rt> rs1
    let condQNan = isQNan 64<rt> rs1
    rd := AST.num0 64<rt>
    AST.cjmp sign (AST.jmpDest lblNeg) (AST.jmpDest lblPos)
    AST.lmark lblPos
    rd := AST.ite condInf (numU32 (1u <<< 7) 64<rt>) rd
    rd := AST.ite condZero (numU32 (1u <<< 4) 64<rt>) rd
    rd := AST.ite condSubnormal (numU32 (1u <<< 5) 64<rt>) rd
    rd := AST.ite condQNan (numU32 (1u <<< 9) 64<rt>) rd
    rd := AST.ite condSNan (numU32 (1u <<< 8) 64<rt>) rd
    rd := AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 6) 64<rt>) rd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblNeg
    rd := AST.ite condInf (numU32 (1u <<< 0) 64<rt>) rd
    rd := AST.ite condZero (numU32 (1u <<< 3) 64<rt>) rd
    rd := AST.ite condSubnormal (numU32 (1u <<< 2) 64<rt>) rd
    rd := AST.ite (rd == AST.num0 64<rt>) (numU32 (1u <<< 1) 64<rt>) rd
    AST.lmark lblEnd
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
    let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
    let fflags = regVar bld R.FFLAGS
    AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0)
    AST.lmark lblL0
    rd := rtVal
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := numU64 0uL 64<rt>
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
    let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
    let fflags = regVar bld R.FFLAGS
    AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0)
    AST.lmark lblL0
    rd := rtVal
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := numU64 0uL 64<rt>
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
    let cond = rs1 == rs2
    let rtVal = AST.ite cond (AST.num1 64<rt>) (AST.num0 64<rt>)
    let fflags = regVar bld R.FFLAGS
    let flagFscr = AST.ite isSNan (numU32 16u 32<rt>) (AST.num0 32<rt>)
    AST.cjmp checkNan (AST.jmpDest lblL1) (AST.jmpDest lblL0)
    AST.lmark lblL0
    rd := rtVal
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    rd := numU64 0uL 64<rt>
    fflags := fflags .| flagFscr
    AST.lmark lblEnd
  }

let fpArithmeticSingle ins bld operator =
  lift bld ins {
    let rd, rs1, rs2, _ = getFourOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rtVal =
      let operation = operator rs1 rs2
      AST.ite (isNan 32<rt> operation) (fpDefaultNan 32<rt>) operation
    rd := getNanBoxed rtVal
  }

let fpArithmeticDouble ins bld operator =
  lift bld ins {
    let rd, rs1, rs2, _ = getFourOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rtVal =
      let operation = operator rs1 rs2
      AST.ite (isNan 64<rt> operation) (fpDefaultNan 64<rt>) operation
    rd := rtVal
  }

let fsqrtdots ins bld =
  lift bld ins {
    let rd, rs1, _ = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let rs1 = AST.xtlo 32<rt> rs1
    let rtVal = AST.fsqrt rs1
    rd := getNanBoxed rtVal
  }

let fsqrtdotd ins bld =
  lift bld ins {
    let rd, rs1, _ = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let rtVal = AST.fsqrt rs1
    rd := rtVal
  }

let fmindots ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rtVal = tmpVar bld 32<rt>
    let cond = AST.flt rs1 rs2
    rtVal := AST.ite cond rs1 rs2
    rd := getNanBoxed rtVal
  }

let fmindotd ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rtVal = tmpVar bld 64<rt>
    let cond = AST.flt rs1 rs2
    rtVal := AST.ite cond rs1 rs2
    rd := rtVal
  }

let fmaxdots ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rtVal = tmpVar bld 32<rt>
    let cond = AST.flt rs1 rs2
    rtVal := AST.ite cond rs2 rs1
    rd := getNanBoxed rtVal
  }

let fmaxdotd ins bld =
  lift bld ins {
    let rd, rs1, rs2 = transThreeOprs ins bld
    let rtVal = tmpVar bld 64<rt>
    let cond = AST.flt rs1 rs2
    rtVal := AST.ite cond rs2 rs1
    rd := rtVal
  }

let fmadddots ins bld =
  lift bld ins {
    let rd, rs1, rs2, rs3, _ = getFiveOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs3 = transOpr ins bld rs3
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rs3 = getFloat32FromReg rs3
    let rtVal = AST.fadd (AST.fmul rs1 rs2) rs3
    rd := getNanBoxed rtVal
  }

let fmadddotd ins bld =
  lift bld ins {
    let rd, rs1, rs2, rs3, _ = getFiveOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs3 = transOpr ins bld rs3
    let rtVal = AST.fadd (AST.fmul rs1 rs2) rs3
    rd := rtVal
  }

let fmsubdots ins bld =
  lift bld ins {
    let rd, rs1, rs2, rs3, _ = getFiveOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs3 = transOpr ins bld rs3
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rs3 = getFloat32FromReg rs3
    let rtVal = AST.fsub (AST.fmul rs1 rs2) rs3
    rd := getNanBoxed rtVal
  }

let fmsubdotd ins bld =
  lift bld ins {
    let rd, rs1, rs2, rs3, _ = getFiveOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs3 = transOpr ins bld rs3
    let rtVal = AST.fsub (AST.fmul rs1 rs2) rs3
    rd := rtVal
  }

let fnmsubdots ins bld =
  lift bld ins {
    let rd, rs1, rs2, rs3, _ = getFiveOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs3 = transOpr ins bld rs3
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rs3 = getFloat32FromReg rs3
    let rtVal = AST.fadd (fpNeg 32<rt> <| AST.fmul rs1 rs2) rs3
    rd := getNanBoxed rtVal
  }

let fnmsubdotd ins bld =
  lift bld ins {
    let rd, rs1, rs2, rs3, _ = getFiveOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs3 = transOpr ins bld rs3
    rd := AST.fadd (fpNeg 64<rt> <| AST.fmul rs1 rs2) rs3
  }

let fnmadddots ins bld =
  lift bld ins {
    let rd, rs1, rs2, rs3, _ = getFiveOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs3 = transOpr ins bld rs3
    let lblValid = label bld "Valid"
    let lblInvalid = label bld "Invalid operation"
    let lblEnd = label bld "End"
    let rs1 = getFloat32FromReg rs1
    let rs2 = getFloat32FromReg rs2
    let rs3 = getFloat32FromReg rs3
    let condOfNV1 = isInf 32<rt> rs1 .| isZero 32<rt> rs2
    let condOfNV2 = isZero 32<rt> rs1 .| isInf 32<rt> rs2
    let setNV = (condOfNV1 .| condOfNV2) .& isQNan 32<rt> rs3
    let fflags = regVar bld R.FFLAGS
    let rtVal = AST.fsub (fpNeg 32<rt> <| AST.fmul rs1 rs2) rs3
    rd := getNanBoxed rtVal
    AST.cjmp setNV (AST.jmpDest lblInvalid) (AST.jmpDest lblValid)
    AST.lmark lblValid
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblInvalid
    fflags := fflags .| numU32 16u 32<rt>
    AST.lmark lblEnd
  }

let fnmadddotd ins bld =
  lift bld ins {
    let rd, rs1, rs2, rs3, _ = getFiveOprs ins
    let rd = transOpr ins bld rd
    let rs1 = transOpr ins bld rs1
    let rs2 = transOpr ins bld rs2
    let rs3 = transOpr ins bld rs3
    let lblValid = label bld "Valid"
    let lblInvalid = label bld "Invalid operation"
    let lblEnd = label bld "End"
    let condOfNV1 = isInf 64<rt> rs1 .| isZero 64<rt> rs2
    let condOfNV2 = isZero 64<rt> rs1 .| isInf 64<rt> rs2
    let setNV = (condOfNV1 .| condOfNV2) .& isQNan 64<rt> rs3
    let fflags = regVar bld R.FFLAGS
    rd := AST.fsub (fpNeg 64<rt> <| AST.fmul rs1 rs2) rs3
    AST.cjmp setNV (AST.jmpDest lblInvalid) (AST.jmpDest lblValid)
    AST.lmark lblValid
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblInvalid
    fflags := fflags .| numU32 16u 32<rt>
    AST.lmark lblEnd
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
    rd := AST.sext 64<rt> tmp
    AST.sideEffect AtomicEnd
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblL1
    AST.sideEffect (Exception MisalignedAccess)
    AST.lmark lblEnd
  }

let fmvdotxdotw ins bld =
  lift bld ins {
    let rd, rs1 = transTwoOprs ins bld
    let rs1 = getFloat32FromReg rs1
    rd := AST.sext 64<rt> rs1
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
      let tmpVar = tmpVar bld 64<rt>
      tmpVar := AST.zext 64<rt> csr
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
        rd := AST.zext 64<rt> csr
      | _ ->
        let oprs = transOpr ins bld csr, transOpr ins bld src
        let csr, src = maskForFCSR csr oprs
        let tmpVar = tmpVar bld 64<rt>
        tmpVar := AST.zext 64<rt> csr
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
      rd := AST.zext 64<rt> csr
    | _ ->
      let oprs = transOpr ins bld csr, transOpr ins bld src
      let csr, src = maskForFCSR csr oprs
      let tmpVar = tmpVar bld 64<rt>
      tmpVar := AST.zext 64<rt> csr
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
  if rm <> OpRoundMode(RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = tmpVar bld 64<rt>
    lift bld ins {
      (* rounded value *)
      rtVal := AST.cast rounding 64<rt> rs1
      rd := AST.cast roundingInt 64<rt> rtVal
      clampConversion bld rd rtVal conds bounds
    }
  else
    lift bld ins {
      (* rounded value *)
      let rtVal = dynamicRoundingFl bld 64<rt> rs1
      let rdVal = dynamicRoundingInt bld 64<rt> rtVal
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
  if rm <> OpRoundMode(RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = tmpVar bld 64<rt>
    lift bld ins {
      (* rounded value *)
      rtVal := AST.cast rounding 64<rt> rs1
      rd := AST.cast roundingInt 64<rt> rtVal
      clampConversion bld rd rtVal conds bounds
    }
  else
    lift bld ins {
      (* rounded value *)
      let rtVal = dynamicRoundingFl bld 64<rt> rs1
      let rdVal = dynamicRoundingInt bld 64<rt> rtVal
      rd := rdVal
      clampConversion bld rd rtVal conds bounds
    }

let fcvtdotwdotd ins bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
  let intMaxInFloat = numU64 0x41dfffffffc00000uL 64<rt>
  let intMinInFloat = numU64 0xc1e0000000000000uL 64<rt>
  let intMax = AST.sext 64<rt> (numU32 0x7fffffffu 32<rt>)
  let intMin = AST.sext 64<rt> (numU32 0x80000000u 32<rt>)
  let condInf = isInf 64<rt> rs1
  let condNaN = isNan 64<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  let conds = condNaN, condInf, sign
  let bounds = intMinInFloat, intMaxInFloat, intMin, intMax
  if rm <> OpRoundMode(RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = tmpVar bld 64<rt>
    lift bld ins {
      (* rounded value *)
      rtVal := AST.cast rounding 64<rt> rs1
      rd := AST.sext 64<rt> (AST.cast roundingInt 32<rt> rtVal)
      clampConversion bld rd rtVal conds bounds
    }
  else
    lift bld ins {
      (* rounded value *)
      let rtVal = dynamicRoundingFl bld 64<rt> rs1
      let rdVal = dynamicRoundingInt bld 32<rt> rtVal
      rd := AST.sext 64<rt> rdVal
      clampConversion bld rd rtVal conds bounds
    }

let fcvtdotwudotd ins bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
  let uintMaxInFloat = numU64 0x41efffffffe00000uL 64<rt>
  let uintMinInFloat = numU64 0uL 64<rt>
  let uintMax = numU64 0xffffffffffffffffuL 64<rt>
  let uintMin = numU64 0uL 64<rt>
  let condInf = isInf 64<rt> rs1
  let condNaN = isNan 64<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  let conds = condNaN, condInf, sign
  let bounds = uintMinInFloat, uintMaxInFloat, uintMin, uintMax
  if rm <> OpRoundMode(RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = tmpVar bld 64<rt>
    lift bld ins {
      (* rounded value *)
      rtVal := AST.cast rounding 64<rt> rs1
      rd := AST.sext 64<rt> (AST.cast roundingInt 32<rt> rtVal)
      clampConversion bld rd rtVal conds bounds
    }
  else
    lift bld ins {
      (* rounded value *)
      let rtVal = dynamicRoundingFl bld 64<rt> rs1
      let rdVal = dynamicRoundingInt bld 32<rt> rtVal
      rd := AST.sext 64<rt> rdVal
      clampConversion bld rd rtVal conds bounds
    }

let fcvtdotwdots ins bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
  let rs1 = getFloat32FromReg rs1
  let intMaxInFloat = numU32 0x4f000000u 32<rt>
  let intMinInFloat = numU32 0xcf000000u 32<rt>
  let intMax = numU32 0x7fffffffu 64<rt>
  let intMin = numU64 0xffffffff80000000uL 64<rt>
  let condInf = isInf 32<rt> rs1
  let condNaN = isNan 32<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  let conds = condNaN, condInf, sign
  let bounds = intMinInFloat, intMaxInFloat, intMin, intMax
  if rm <> OpRoundMode(RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = tmpVar bld 32<rt>
    lift bld ins {
      (* rounded value *)
      rtVal := AST.cast rounding 32<rt> rs1
      rd := AST.sext 64<rt> (AST.cast roundingInt 32<rt> rtVal)
      clampConversion bld rd rtVal conds bounds
    }
  else
    lift bld ins {
      (* rounded value *)
      let rtVal = dynamicRoundingFl bld 32<rt> rs1
      let rdVal = dynamicRoundingInt bld 32<rt> rtVal
      rd := AST.sext 64<rt> rdVal
      clampConversion bld rd rtVal conds bounds
    }

let fcvtdotwudots ins bld =
  let rd, rs1, rm = getThreeOprs ins
  let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
  let rs1 = getFloat32FromReg rs1
  let uintMaxInFloat = numU32 0x4f800000u 32<rt>
  let uintMinInFloat = numU32 0x0u 32<rt>
  let uintMax = numU64 0xffffffffffffffffUL 64<rt>
  let uintMin = numU32 0x0u 64<rt>
  let condInf = isInf 32<rt> rs1
  let condNaN = isNan 32<rt> rs1
  let sign = AST.xthi 1<rt> rs1
  let conds = condNaN, condInf, sign
  let bounds = uintMinInFloat, uintMaxInFloat, uintMin, uintMax
  if rm <> OpRoundMode(RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let rtVal = tmpVar bld 32<rt>
    lift bld ins {
      (* rounded value *)
      rtVal := AST.cast rounding 32<rt> rs1
      rd := AST.sext 64<rt> (AST.cast roundingInt 32<rt> rtVal)
      clampConversion bld rd rtVal conds bounds
    }
  else
    lift bld ins {
      (* rounded value *)
      let rtVal = dynamicRoundingFl bld 32<rt> rs1
      let rdVal = dynamicRoundingInt bld 32<rt> rtVal
      rd := AST.sext 64<rt> rdVal
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
  if rm <> OpRoundMode(RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let t0 = tmpVar bld 32<rt>
    let rtVal = tmpVar bld 64<rt>
    lift bld ins {
      (* rounded value *)
      t0 := AST.cast rounding 32<rt> rs1
      rtVal := AST.cast CastKind.FloatCast 64<rt> t0
      clampRounded bld rtVal conds bounds
      rd := AST.cast roundingInt 64<rt> rtVal
    }
  else
    lift bld ins {
      (* rounded value *)
      let t0 = dynamicRoundingFl bld 32<rt> rs1
      let rtVal = tmpVar bld 64<rt>
      (* check for out-of-range *)
      rtVal := AST.cast CastKind.FloatCast 64<rt> t0
      clampRounded bld rtVal conds bounds
      let rdVal = dynamicRoundingInt bld 64<rt> rtVal
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
  if rm <> OpRoundMode(RoundMode.DYN) then
    let rounding = roundingToCastFloat rm
    let roundingInt = roundingToCastInt rm
    let t0 = tmpVar bld 32<rt>
    let rtVal = tmpVar bld 64<rt>
    lift bld ins {
      (* rounded value *)
      t0 := AST.cast rounding 32<rt> rs1
      rtVal := AST.cast CastKind.FloatCast 64<rt> t0
      rd := AST.cast roundingInt 64<rt> rtVal
      clampConversion bld rd rtVal conds bounds
    }
  else
    lift bld ins {
      (* rounded value *)
      let t0 = dynamicRoundingFl bld 32<rt> rs1
      let rtVal = tmpVar bld 64<rt>
      (* check for out-of-range *)
      rtVal := AST.cast CastKind.FloatCast 64<rt> t0
      rd := AST.cast CastKind.FloatCast 64<rt> rtVal
      clampConversion bld rd rtVal conds bounds
    }

let fcvtdotsdotw ins bld =
  lift bld ins {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let rs1 = AST.xtlo 32<rt> rs1
    let rtVal = tmpVar bld 32<rt>
    rtVal := AST.cast CastKind.SIntToFloat 32<rt> rs1
    writeRoundedSingle rd rtVal rm bld
  }

let fcvtdotsdotwu ins bld =
  lift bld ins {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let rs1 = AST.xtlo 32<rt> rs1
    let rtVal = tmpVar bld 32<rt>
    rtVal := AST.cast CastKind.UIntToFloat 32<rt> rs1
    writeRoundedSingle rd rtVal rm bld
  }

let fcvtdotsdotl ins bld =
  lift bld ins {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let rtVal = tmpVar bld 32<rt>
    rtVal := AST.cast CastKind.SIntToFloat 32<rt> rs1
    writeRoundedSingle rd rtVal rm bld
  }

let fcvtdotsdotlu ins bld =
  lift bld ins {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let rtVal = tmpVar bld 32<rt>
    rtVal := AST.cast CastKind.UIntToFloat 32<rt> rs1
    writeRoundedSingle rd rtVal rm bld
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
    let rtVal = AST.cast CastKind.SIntToFloat 64<rt> rs1
    writeRoundedDouble rd rtVal rm bld
  }

let fcvtdotddotlu ins bld =
  lift bld ins {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let rtVal = AST.cast CastKind.UIntToFloat 64<rt> rs1
    writeRoundedDouble rd rtVal rm bld
  }

let fcvtdotsdotd ins bld =
  lift bld ins {
    let rd, rs1, rm = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let rtVal = tmpVar bld 64<rt>
    let rs1 =
      AST.cast CastKind.FloatCast 32<rt> rs1
      |> fun single ->
           AST.ite (isNan 32<rt> single) (fpDefaultNan 32<rt>) single
    rtVal := getNanBoxed rs1
    if rm <> OpRoundMode(RoundMode.DYN) then
      let rounding = roundingToCastFloat rm
      rd := AST.cast rounding 64<rt> rtVal
    else
      rd := dynamicRoundingFl bld 64<rt> rtVal
  }

let fcvtdotddots ins bld =
  lift bld ins {
    let rd, rs1, _ = getThreeOprs ins
    let rd, rs1 = transOpr ins bld rd, transOpr ins bld rs1
    let rs1 = getFloat32FromReg rs1
    rd := AST.cast CastKind.FloatCast 64<rt> rs1
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
    regVar bld R.ExMonVal := AST.zext 64<rt> v
    rd := AST.sext 64<rt> v
    AST.sideEffect AtomicEnd
  }

/// Store-conditional (SC.W/SC.D): stores and reports success (rd = 0) only if
/// the reservation still holds -- the address matches and memory still holds
/// the reserved value; otherwise memory is left unchanged and it reports
/// failure (rd = 1). The conditional store is a store of ite(matched, data,
/// old), so no branch is emitted.
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
    rd := AST.ite matched (AST.num0 64<rt>) (AST.num1 64<rt>)
    AST.sideEffect AtomicEnd
  }

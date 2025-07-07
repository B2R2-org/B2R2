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

module internal B2R2.FrontEnd.PPC32.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC32
open B2R2.FrontEnd.PPC32.OperandHelper

let getOneOpr (ins: Instruction) =
  match ins.Operands with
  | OneOperand o -> o
  | _ -> raise InvalidOperandException

let getTwoOprs (ins: Instruction) =
  match ins.Operands with
  | TwoOperands (o1, o2) -> struct (o1, o2)
  | _ -> raise InvalidOperandException

let getThreeOprs (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) -> struct (o1, o2, o3)
  | _ -> raise InvalidOperandException

let getExtMask mb me =
  let struct (mb, me) =
    match mb, me with
    | Num (b, _), Num (m, _) ->
      struct (b.SmallValue () |> int, m.SmallValue () |> int)
    | _ -> raise InvalidExprException
  let allOnes = System.UInt32.MaxValue
  let mask =
    if mb = me + 1 then allOnes
    elif me = 31 then allOnes >>> mb
    else
      let v = (allOnes >>> mb) ^^^ (allOnes >>> (me + 1))
      if mb > me then ~~~v else v
  numU32 mask 32<rt>

let rotateLeft rs sh = (rs << sh) .| (rs >> ((numI32 32 32<rt>) .- sh))

let loadNative (bld: ILowUIRBuilder) rt addr =
  match bld.Endianness with
  | Endian.Big -> AST.loadBE rt addr
  | Endian.Little -> AST.loadLE rt addr
  | _ -> raise InvalidEndianException

/// Operand of the form d(rA) where the EA is (rA|0) + d.
let transEAWithOffset opr (bld: ILowUIRBuilder) =
  match opr with
  | OprMem (d, Register.R0) -> numI32 d bld.RegType
  | OprMem (d, b) -> regVar bld b .+ numI32 d bld.RegType
  | _ -> raise InvalidOperandException

/// Operand of the form d(rA) where the EA is rA + d. rA is updated with EA.
let transEAWithOffsetForUpdate opr (bld: ILowUIRBuilder) =
  match opr with
  | OprMem (d, b) ->
    let rA = regVar bld b
    struct (rA .+ numI32 d bld.RegType, rA)
  | _ -> raise InvalidOperandException

/// Operands of the form "rA, rB" where the EA is (rA|0) + rB.
let transEAWithIndexReg rA rB bld =
  match rA, rB with
  | OprReg Register.R0, OprReg rB -> regVar bld rB
  | OprReg reg, OprReg rB -> regVar bld reg .+ regVar bld rB
  | _ -> raise InvalidOpcodeException

/// Operands of the form "rA, rB" where the EA is rA + rB, and rA is updated.
let transEAWithIndexRegForUpdate rA rB bld =
  match rA, rB with
  | OprReg rA, OprReg rB ->
    let rA = regVar bld rA
    struct (rA .+ regVar bld rB, rA)
  | _ -> raise InvalidOpcodeException

let transOpr bld = function
  | OprReg reg -> regVar bld reg
  | OprMem (d, b) -> (* FIXME *)
    loadNative bld 32<rt> (regVar bld b .+ numI32 d bld.RegType)
  | OprImm imm -> numU64 imm bld.RegType
  | OprAddr addr ->
    numI64 (int64 addr) bld.RegType
  | OprBI bi -> getCRbitRegister bi |> regVar bld

let transOneOpr (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand o -> transOpr bld o
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands (o1, o2) ->
    struct (transOpr bld o1, transOpr bld o2)
  | _ -> raise InvalidOperandException

let transThreeOprs (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands (o1, o2, o3) ->
    struct (transOpr bld o1,
            transOpr bld o2,
            transOpr bld o3)
  | _ -> raise InvalidOperandException

let transFourOprs (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands (o1, o2, o3, o4) ->
    struct (transOpr bld o1,
            transOpr bld o2,
            transOpr bld o3,
            transOpr bld o4)
  | _ -> raise InvalidOperandException

let transFiveOprs (ins: Instruction) bld =
  match ins.Operands with
  | FiveOperands (o1, o2, o3, o4, o5) ->
    struct (transOpr bld o1,
            transOpr bld o2,
            transOpr bld o3,
            transOpr bld o4,
            transOpr bld o5)
  | _ -> raise InvalidOperandException

let transCRxToExpr bld reg =
  match reg with
  | Register.CR0 ->
    regVar bld Register.CR0_0,
    regVar bld Register.CR0_1,
    regVar bld Register.CR0_2,
    regVar bld Register.CR0_3
  | Register.CR1 ->
    regVar bld Register.CR1_0,
    regVar bld Register.CR1_1,
    regVar bld Register.CR1_2,
    regVar bld Register.CR1_3
  | Register.CR2 ->
    regVar bld Register.CR2_0,
    regVar bld Register.CR2_1,
    regVar bld Register.CR2_2,
    regVar bld Register.CR2_3
  | Register.CR3 ->
    regVar bld Register.CR3_0,
    regVar bld Register.CR3_1,
    regVar bld Register.CR3_2,
    regVar bld Register.CR3_3
  | Register.CR4 ->
    regVar bld Register.CR4_0,
    regVar bld Register.CR4_1,
    regVar bld Register.CR4_2,
    regVar bld Register.CR4_3
  | Register.CR5 ->
    regVar bld Register.CR5_0,
    regVar bld Register.CR5_1,
    regVar bld Register.CR5_2,
    regVar bld Register.CR5_3
  | Register.CR6 ->
    regVar bld Register.CR6_0,
    regVar bld Register.CR6_1,
    regVar bld Register.CR6_2,
    regVar bld Register.CR6_3
  | Register.CR7 ->
    regVar bld Register.CR7_0,
    regVar bld Register.CR7_1,
    regVar bld Register.CR7_2,
    regVar bld Register.CR7_3
  | _ -> raise InvalidOperandException

let transCmpOprs (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands (OprReg o1, o2, o3) ->
    struct (transCRxToExpr bld o1,
            transOpr bld o2,
            transOpr bld o3)

  | FourOperands (OprReg o1, _ , o3, o4) ->
    struct (transCRxToExpr bld o1,
            transOpr bld o3,
            transOpr bld o4)
  | _ -> raise InvalidOperandException

let transCondOneOpr (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand (OprReg o) ->
    transCRxToExpr bld o
  | _ -> raise InvalidOperandException

let transCondTwoOprs (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands (OprReg o1, OprReg o2) ->
    struct (transCRxToExpr bld o1, transCRxToExpr bld o2)
  | _ -> raise InvalidOperandException

let transCondThreeOprs (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands (OprReg o1, OprReg o2, OprReg o3) ->
    struct (transCRxToExpr bld o1,
            transCRxToExpr bld o2,
            transCRxToExpr bld o3)
  | _ -> raise InvalidOperandException

let transBranchTwoOprs (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands (OprImm o1, OprBI o2) ->
    struct (uint32 o1, getCRbitRegister o2 |> regVar bld)
  | _ -> raise InvalidOperandException

let transBranchThreeOprs (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands (OprImm o1, OprBI o2, OprAddr o3) ->
    struct (uint32 o1,
            getCRbitRegister o2 |> regVar bld,
            numI64 (int64 o3) bld.RegType)
  | _ -> raise InvalidOperandException

let getCRRegValue bld cr =
  bld <+ (cr := numI32 0 32<rt>)
  for i in 0 .. 31 do
    let crbit = uint32 (31 - i) |> getCRbitRegister |> regVar bld
    bld <+ (AST.extract cr 1<rt> i := crbit)

let getImmValue = function
  | OprImm imm -> uint32 imm
  | OprBI imm -> imm
  | _ -> raise InvalidOperandException

let getSPRReg bld imm  =
  match uint32 imm with
  | 1u -> regVar bld Register.XER
  | 8u -> regVar bld Register.LR
  | 9u -> regVar bld Register.CTR
  | 287u -> regVar bld Register.PVR
  | 18u | 19u | 22u | 25u | 26u | 27u | 272u | 273u | 274u | 275u | 282u | 528u
  | 529u | 530u | 531u | 532u | 533u | 534u | 535u | 536u | 537u | 538u | 539u
  | 540u | 541u | 542u | 543u | 1013u -> raise InvalidRegisterException
  | _ -> raise InvalidOperandException

let floatingNeg bld dst src rt =
  let sign = (AST.xthi 1<rt> src <+> (AST.b1))
  let tmp = tmpVar bld rt
  bld <+ (tmp := src)
  bld <+ (AST.xthi 1<rt> tmp := sign)
  bld <+ (dst := tmp)

let roundingToCastInt bld frd frb =
  let fpscr = regVar bld Register.FPSCR
  let rnA = AST.extract fpscr 1<rt> 1
  let rnB = AST.extract fpscr 1<rt> 0
  let lblRN0 = label bld "RN0x"
  let lblRN1 = label bld "RN1x"
  let lblEnd = label bld "End"
  bld <+ (AST.cjmp rnA (AST.jmpDest lblRN1) (AST.jmpDest lblRN0))
  bld <+ (AST.lmark lblRN0)
  bld <+ (frd := AST.ite rnB (AST.cast CastKind.FtoITrunc 64<rt> frb)
                            (AST.cast CastKind.FtoIRound 64<rt> frb))
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblRN1)
  bld <+ (frd := AST.ite rnB (AST.cast CastKind.FtoIFloor 64<rt> frb)
                            (AST.cast CastKind.FtoICeil 64<rt> frb))
  bld <+ (AST.lmark lblEnd)

let setCR0Reg bld result =
  let xerSO = AST.xthi 1<rt> (regVar bld Register.XER)
  let cr0LT = regVar bld Register.CR0_0
  let cr0GT = regVar bld Register.CR0_1
  let cr0EQ = regVar bld Register.CR0_2
  let cr0SO = regVar bld Register.CR0_3
  bld <+ (cr0LT := result ?< AST.num0 32<rt>)
  bld <+ (cr0GT := result ?> AST.num0 32<rt>)
  bld <+ (cr0EQ := result == AST.num0 32<rt>)
  bld <+ (cr0SO := xerSO)

let setCR1Reg bld =
  let fpscr = regVar bld Register.FPSCR
  let cr1FX = regVar bld Register.CR1_0
  let cr1FEX = regVar bld Register.CR1_1
  let cr1VX = regVar bld Register.CR1_2
  let cr1OX = regVar bld Register.CR1_3
  bld <+ (cr1FX := AST.extract fpscr 1<rt> 31)
  bld <+ (cr1FEX := AST.extract fpscr 1<rt> 30)
  bld <+ (cr1VX := AST.extract fpscr 1<rt> 29)
  bld <+ (cr1OX := AST.extract fpscr 1<rt> 28)

let isDenormailized frx =
  let exponent = (frx >> numI32 52 64<rt>) .& numI32 0x7FF 64<rt>
  let fraction = frx .& numU64 0xfffff_ffffffffUL 64<rt>
  let zero = AST.num0 64<rt>
  AST.xtlo 1<rt> ((exponent == zero) .& (fraction != zero))

let setFPRF bld result =
  let fpscr = regVar bld Register.FPSCR
  let c = AST.extract fpscr 1<rt> 16
  let fl = AST.extract fpscr 1<rt> 15
  let fg = AST.extract fpscr 1<rt> 14
  let fe = AST.extract fpscr 1<rt> 13
  let fu = AST.extract fpscr 1<rt> 12
  let nzero = numU64 0x8000000000000000UL 64<rt>
  bld <+ (c := IEEE754Double.isNaN result
             .| isDenormailized result
             .| AST.eq result nzero)
  bld <+ (fl := AST.flt result (AST.num0 64<rt>))
  bld <+ (fg := AST.fgt result (AST.num0 64<rt>))
  bld <+ (fe := AST.eq (result << AST.num1 64<rt>) (AST.num0 64<rt>))
  bld <+ (fu := IEEE754Double.isNaN result .| IEEE754Double.isInfinity result)

let setCarryOut bld res =
  let xerCA = AST.extract (regVar bld Register.XER) 1<rt> 29
  bld <+ (xerCA := AST.extract res 1<rt> 32)

let setCRRegValue bld cr =
  for i in 0 .. 31 do
    let crbit = uint32 (31 - i) |> getCRbitRegister |> regVar bld
    bld <+ (crbit := AST.extract cr 1<rt> i)

let isAddSubOV bld expA expB result =
  let struct (checkOF, t1, t2) = tmpVars3 bld 1<rt>
  let xerSO = AST.extract (regVar bld Register.XER) 1<rt> 31
  let xerOV = AST.extract (regVar bld Register.XER) 1<rt> 30
  let e1High = AST.xthi 1<rt> expA
  let e2High = AST.xthi 1<rt> expB
  let rHigh = AST.xthi 1<rt> result
  bld <+ (t1 := e1High)
  bld <+ (t2 := rHigh)
  bld <+ (checkOF := (t1 == e2High) .& (t1 <+> t2))
  bld <+ (xerOV := checkOF)
  bld <+ (xerSO := checkOF .& xerSO)

let isMulOV bld expA expB =
  let checkOF = tmpVar bld 1<rt>
  let maxValue = numI32 0x7FFFFFFF 32<rt>
  let minValue = numI32 0x80000000 32<rt>
  let xerSO = AST.extract (regVar bld Register.XER) 1<rt> 31
  let xerOV = AST.extract (regVar bld Register.XER) 1<rt> 30
  let cond1 = (expA ?> maxValue ?/ expB)
  let cond2 = (expA ?< minValue ?/ expB)
  bld <+ (checkOF := AST.ite (expB == AST.num0 32<rt>) AST.b0 (cond1 .| cond2))
  bld <+ (xerOV := checkOF)
  bld <+ (xerSO := checkOF .& xerSO)

let isSignedDivOV bld expA expB =
  let checkOF = tmpVar bld 1<rt>
  let minValue = numI32 0x80000000 32<rt>
  let xerSO = AST.extract (regVar bld Register.XER) 1<rt> 31
  let xerOV = AST.extract (regVar bld Register.XER) 1<rt> 30
  let cond = (expA == minValue) .& (expB == (numI32 0xFFFFFFFF 32<rt>))
  bld <+ (checkOF := AST.ite (expB == AST.num0 32<rt>) AST.b0 cond)
  bld <+ (xerOV := checkOF)
  bld <+ (xerSO := checkOF .& xerSO)

let isUnsignedDivOV bld expA expB =
  let checkOF = tmpVar bld 1<rt>
  let maxValue = numU32 0xFFFFFFFFu 32<rt>
  let xerSO = AST.extract (regVar bld Register.XER) 1<rt> 31
  let xerOV = AST.extract (regVar bld Register.XER) 1<rt> 30
  let cond = (expA ./ expB) .> maxValue
  bld <+ (checkOF := AST.ite (expB == AST.num0 32<rt>) AST.b0 cond)
  bld <+ (xerOV := checkOF)
  bld <+ (xerSO := checkOF .& xerSO)

let sideEffects (ins: Instruction) insLen bld name =
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.sideEffect name)
  bld --!> insLen

let add ins insLen updateCond ovCond bld =
  let struct (dst, src1, src2) = transThreeOprs ins bld
  let struct (t1, t2) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (t1 := src1)
  bld <+ (t2 := src2)
  bld <+ (dst := t1 .+ t2)
  if ovCond then isAddSubOV bld t1 t2 dst else ()
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let addc ins insLen updateCond ovCond bld =
  let struct (dst, src1, src2) = transThreeOprs ins bld
  let struct (t1, t2, t3) = tmpVars3 bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (t1 := AST.zext 64<rt> src1)
  bld <+ (t2 := AST.zext 64<rt> src2)
  bld <+ (t3 := t1 .+ t2)
  bld <+ (dst := AST.xtlo 32<rt> t3)
  setCarryOut bld t3
  if ovCond then isAddSubOV bld t1 t2 dst else ()
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let adde ins insLen updateCond ovCond bld =
  let struct (dst, src1, src2) = transThreeOprs ins bld
  let xerCA = AST.zext 64<rt> (AST.extract (regVar bld Register.XER) 1<rt> 29)
  let struct (t1, t2, t3) = tmpVars3 bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (t1 := AST.zext 64<rt> src1)
  bld <+ (t2 := AST.zext 64<rt> src2)
  bld <+ (t3 := t1 .+ t2 .+ xerCA)
  bld <+ (dst := AST.xtlo 32<rt> t3)
  setCarryOut bld t3
  if ovCond then isAddSubOV bld t1 t2 dst else ()
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let addi ins insLen bld =
  let struct (dst, src1, simm) = transThreeOprs ins bld
  let cond = src1 == AST.num0 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := (AST.ite cond simm (src1 .+ simm)))
  bld --!> insLen

let addic ins insLen updateCond bld =
  let struct (dst, src1, simm) = transThreeOprs ins bld
  let struct (t1, t2, t3) = tmpVars3 bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (t1 := AST.zext 64<rt> src1)
  bld <+ (t2 := AST.zext 64<rt> simm)
  bld <+ (t3 := t1 .+ t2)
  bld <+ (dst := AST.xtlo 32<rt> t3)
  setCarryOut bld t3
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let addis ins insLen bld =
  let struct (dst, src1, simm) = transThreeOprs ins bld
  let cond = src1 == AST.num0 32<rt>
  let simm = AST.concat (AST.xtlo 16<rt> simm) (AST.num0 16<rt>)
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := (AST.ite cond simm (src1 .+ simm)))
  bld --!> insLen

let addme ins insLen updateCond ovCond bld =
  let struct (dst, src) = transTwoOprs ins bld
  let xerCA = AST.zext 64<rt> (AST.extract (regVar bld Register.XER) 1<rt> 29)
  let struct (t1, t2, t3) = tmpVars3 bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (t1 := AST.zext 64<rt> src)
  bld <+ (t2 := xerCA)
  bld <+ (t3 := t1 .+ t2 .- AST.num1 64<rt>)
  bld <+ (dst := AST.xtlo 32<rt> t3)
  setCarryOut bld t3
  if ovCond then isAddSubOV bld t1 t2 dst else ()
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let addze ins insLen updateCond ovCond bld =
  let struct (dst, src) = transTwoOprs ins bld
  let xerCA = AST.zext 64<rt> (AST.extract (regVar bld Register.XER) 1<rt> 29)
  let struct (t1, t2, t3) = tmpVars3 bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (t1 := AST.zext 64<rt> src)
  bld <+ (t2 := xerCA)
  bld <+ (t3 := t1 .+ t2)
  bld <+ (dst := AST.xtlo 32<rt> t3)
  setCarryOut bld t3
  if ovCond then isAddSubOV bld t1 t2 dst else ()
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let andx ins insLen updateCond bld =
  let struct (dst, src1, src2) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src1 .& src2)
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let andc ins insLen updateCond bld =
  let struct (dst, src1, src2) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src1 .& AST.not(src2))
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let andidot ins insLen bld =
  let struct (dst, src, uimm) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src .& uimm)
  setCR0Reg bld dst
  bld --!> insLen

let andisdot ins insLen bld =
  let struct (dst, src, uimm) = transThreeOprs ins bld
  let uimm = uimm << numI32 16 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src .& uimm)
  setCR0Reg bld dst
  bld --!> insLen

let b ins insLen bld lk =
  let addr = transOneOpr ins bld
  let lr = regVar bld Register.LR
  bld <!-- (ins.Address, insLen)
  if lk then bld <+ (lr := numU64 ins.Address 32<rt> .+ numI32 4 32<rt>)
  bld <+ (AST.interjmp addr InterJmpKind.Base)
  bld --!> insLen

let bc ins insLen bld aa lk =
  let struct (bo, cr, addr) = transBranchThreeOprs ins bld
  let lr = regVar bld Register.LR
  let ctr = regVar bld Register.CTR
  let bo0 = numU32 ((bo >>> 4) &&& 1u) 1<rt>
  let bo1 = numU32 ((bo >>> 3) &&& 1u) 1<rt>
  let bo2 = numU32 ((bo >>> 2) &&& 1u) 1<rt>
  let bo3 = numU32 ((bo >>> 1) &&& 1u) 1<rt>
  let ctrOk = tmpVar bld 1<rt>
  let condOk = tmpVar bld 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = cia .+ numI32 4 32<rt>
  let temp = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  if lk then bld <+ (lr := nia)
  bld <+ (ctr :=
          if ((bo >>> 2) &&& 1u = 1u) then ctr else (ctr .- AST.num1 32<rt>))
  bld <+ (ctrOk := bo2 .| ((ctr != AST.num0 32<rt>) <+> bo3))
  bld <+ (condOk := bo0 .| (cr <+> AST.not bo1))
  if aa then bld <+ (temp := AST.ite (ctrOk .& condOk) addr nia)
  else bld <+ (temp := AST.ite (ctrOk .& condOk) (cia .+ addr) nia)
  bld <+ (AST.interjmp temp InterJmpKind.Base)
  bld --!> insLen

let bclr ins insLen bld lk =
  let struct (bo, cr) = transBranchTwoOprs ins bld
  let lr = regVar bld Register.LR
  let ctr = regVar bld Register.CTR
  let bo0 = numU32 ((bo >>> 4) &&& 1u) 1<rt>
  let bo1 = numU32 ((bo >>> 3) &&& 1u) 1<rt>
  let bo2 = numU32 ((bo >>> 2) &&& 1u) 1<rt>
  let bo3 = numU32 ((bo >>> 1) &&& 1u) 1<rt>
  let ctrOk = tmpVar bld 1<rt>
  let condOk = tmpVar bld 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = cia .+ numI32 4 32<rt>
  let temp = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (ctr :=
          if ((bo >>> 2) &&& 1u = 1u) then ctr else (ctr .- AST.num1 32<rt>))
  bld <+ (ctrOk := bo2 .| ((ctr != AST.num0 32<rt>) <+> bo3))
  bld <+ (condOk := bo0 .| (cr <+> AST.not bo1))
  bld <+ (temp := AST.ite (ctrOk .& condOk)
                          (lr .& numI32 0xfffffffc 32<rt>) nia)
  if lk then bld <+ (lr := AST.ite (ctrOk .& condOk) nia lr)
  bld <+ (AST.interjmp temp InterJmpKind.Base)
  bld --!> insLen

let bcctr ins insLen bld lk =
  let struct (bo, cr) = transBranchTwoOprs ins bld
  let lr = regVar bld Register.LR
  let ctr = regVar bld Register.CTR
  let bo0 = numU32 ((bo >>> 4) &&& 1u) 1<rt>
  let bo1 = numU32 ((bo >>> 3) &&& 1u) 1<rt>
  let condOk = tmpVar bld 1<rt>
  let cia = numU64 ins.Address 32<rt>
  let nia = cia .+ numI32 4 32<rt>
  let temp = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (condOk := bo0 .| (cr <+> AST.not bo1))
  bld <+ (temp := AST.ite condOk (ctr .& numI32 0xfffffffc 32<rt>) nia)
  if lk then bld <+ (lr := AST.ite condOk nia lr)
  bld <+ (AST.interjmp temp InterJmpKind.Base)
  bld --!> insLen

let cmp ins insLen bld =
  let struct ((crf0, crf1, crf2, crf3), ra, rb) = transCmpOprs ins bld
  let cond1 = ra ?< rb
  let cond2 = ra ?> rb
  let xer = regVar bld Register.XER
  bld <!-- (ins.Address, insLen)
  bld <+ (crf0 := cond1)
  bld <+ (crf1 := cond2)
  bld <+ (crf2 := AST.ite cond1 AST.b0 (AST.not cond2))
  bld <+ (crf3 := AST.xthi 1<rt> xer)
  bld --!> insLen

let cmpl ins insLen bld =
  let struct ((crf0, crf1, crf2, crf3), ra, rb) = transCmpOprs ins bld
  let cond1 = ra .< rb
  let cond2 = ra .> rb
  let xer = regVar bld Register.XER
  bld <!-- (ins.Address, insLen)
  bld <+ (crf0 := cond1)
  bld <+ (crf1 := cond2)
  bld <+ (crf2 := AST.ite cond1 AST.b0 (AST.not cond2))
  bld <+ (crf3 := AST.xthi 1<rt> xer)
  bld --!> insLen

let cmpli ins insLen bld =
  let struct ((crf0, crf1, crf2, crf3), ra, uimm) = transCmpOprs ins bld
  let cond1 = ra .< uimm
  let cond2 = ra .> uimm
  let xer = regVar bld Register.XER
  bld <!-- (ins.Address, insLen)
  bld <+ (crf0 := cond1)
  bld <+ (crf1 := cond2)
  bld <+ (crf2 := AST.ite cond1 AST.b0 (AST.not cond2))
  bld <+ (crf3 := AST.xthi 1<rt> xer)
  bld --!> insLen

let cntlzw ins insLen updateCond bld =
  let struct (ra, rs) = transTwoOprs ins bld
  let mask1 = numI32 0x55555555 32<rt>
  let mask2 = numI32 0x33333333 32<rt>
  let mask3 = numI32 0x0f0f0f0f 32<rt>
  bld <!-- (ins.Address, insLen)
  let x = tmpVar bld 32<rt>
  bld <+ (x := rs)
  bld <+ (x := x .| (x >> numI32 1 32<rt>))
  bld <+ (x := x .| (x >> numI32 2 32<rt>))
  bld <+ (x := x .| (x >> numI32 4 32<rt>))
  bld <+ (x := x .| (x >> numI32 8 32<rt>))
  bld <+ (x := x .| (x >> numI32 16 32<rt>))
  bld <+ (x := x .- ((x >> numI32 1 32<rt>) .& mask1))
  bld <+ (x := ((x >> numI32 2 32<rt>) .& mask2) .+ (x .& mask2))
  bld <+ (x := ((x >> numI32 4 32<rt>) .+ x) .& mask3)
  bld <+ (x := x .+ (x >> numI32 8 32<rt>))
  bld <+ (x := x .+ (x >> numI32 16 32<rt>))
  bld <+ (ra := numI32 32 32<rt> .- (x .& numI32 63 32<rt>))
  if updateCond then setCR0Reg bld ra else ()
  bld --!> insLen

let crclr ins insLen bld =
  let crbd = transOneOpr ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (crbd := AST.b0)
  bld --!> insLen

let cror ins insLen bld =
  let struct (crbD, crbA, crbB) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (crbD := crbA .| crbB)
  bld --!> insLen

let crorc ins insLen bld =
  let struct (crbD, crbA, crbB) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (crbD := crbA .| (AST.not crbB))
  bld --!> insLen

let creqv ins insLen bld =
  let struct (crbD, crbA, crbB) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (crbD := crbA <+> AST.not(crbB))
  bld --!> insLen

let crset ins insLen bld =
  let crbD = transOneOpr ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (crbD := crbD <+> AST.not(crbD))
  bld --!> insLen

let crnand ins insLen bld =
  let struct (crbD, crbA, crbB) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (crbD := AST.not (crbA .& crbB))
  bld --!> insLen

let crnor ins insLen bld =
  let struct (crbD, crbA, crbB) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (crbD := AST.not (crbA .| crbB))
  bld --!> insLen

let crnot ins insLen bld =
  let struct (crbD, crbA) = transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (crbD := AST.not crbA)
  bld --!> insLen

let crxor ins insLen bld =
  let struct (crbD, crbA, crbB) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (crbD := crbA <+> crbB)
  bld --!> insLen

let divw ins insLen updateCond ovCond bld =
  let struct (dst, src1, src2) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  if ovCond then isSignedDivOV bld src1 src2 else ()
  bld <+ (dst := AST.ite (src2 == AST.num0 32<rt>) dst (src1 ?/ src2))
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let divwu ins insLen updateCond ovCond bld =
  let struct (dst, src1, src2) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  if ovCond then isUnsignedDivOV bld src1 src2 else ()
  bld <+ (dst := AST.ite (src2 == AST.num0 32<rt>) dst (src1 ./ src2))
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let extsb ins insLen updateCond bld =
  let struct (ra, rs) = transTwoOprs ins bld
  let tmp = tmpVar bld 8<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmp := AST.xtlo 8<rt> rs)
  bld <+ (ra := AST.sext 32<rt> tmp)
  if updateCond then setCR0Reg bld ra else ()
  bld --!> insLen

let extsh ins insLen updateCond bld =
  let struct (ra, rs) = transTwoOprs ins bld
  let tmp = tmpVar bld 16<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmp := AST.xtlo 16<rt> rs)
  bld <+ (ra := AST.sext 32<rt> tmp)
  if updateCond then setCR0Reg bld ra else ()
  bld --!> insLen

let eqvx ins insLen updateCond bld =
  let struct (ra, rs, rb) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (ra := AST.not (rs <+> rb))
  if updateCond then setCR0Reg bld ra else ()
  bld --!> insLen

let fabs ins insLen updateCond bld =
  let struct (frd, frb) = transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (frd := frb .& numU64 0x7fffffffffffffffUL 64<rt>)
  if updateCond then setCR1Reg bld else ()
  bld --!> insLen

let fAddOrSub ins insLen updateCond isDouble fnOp bld =
  let struct (frd, fra, frb) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  if isDouble then
    bld <+ (frd := fnOp fra frb)
  else
    let fra = AST.cast CastKind.FloatCast 32<rt> fra
    let frb = AST.cast CastKind.FloatCast 32<rt> frb
    bld <+ (frd := AST.cast CastKind.FloatCast 64<rt> (fnOp fra frb))
  setFPRF bld frd
  if updateCond then setCR1Reg bld else ()
  bld --!> insLen

let fadd ins insLen updateCond isDouble bld =
  fAddOrSub ins insLen updateCond isDouble AST.fadd bld

let fcmp ins insLen bld isOrdered =
  let struct ((crf0, crf1, crf2, crf3), fra, frb) = transCmpOprs ins bld
  let fpscr = regVar bld Register.FPSCR
  let vxsnan = AST.extract fpscr 1<rt> 24
  let vxvc = AST.extract fpscr 1<rt> 19
  let fl = AST.extract fpscr 1<rt> 15
  let fg = AST.extract fpscr 1<rt> 14
  let fe = AST.extract fpscr 1<rt> 13
  let fu = AST.extract fpscr 1<rt> 12
  let ve = AST.extract fpscr 1<rt> 7
  let cond1 = AST.flt fra frb
  let cond2 = AST.fgt fra frb
  let cond3 = (IEEE754Double.isSNaN fra) .| (IEEE754Double.isSNaN frb)
  let cond4 = (IEEE754Double.isQNaN fra) .| (IEEE754Double.isQNaN frb)
  let nanFlag = tmpVar bld 1<rt>
  let lblNan = label bld "NaN"
  let lblRegular = label bld "Regular"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (fl := cond1)
  bld <+ (fg := cond2)
  bld <+ (fe := AST.ite cond1 AST.b0 (AST.not cond2))
  bld <+ (nanFlag := (IEEE754Double.isNaN fra) .| (IEEE754Double.isNaN frb))
  bld <+ (fu := nanFlag)
  bld <+ (AST.cjmp nanFlag (AST.jmpDest lblNan) (AST.jmpDest lblRegular))
  bld <+ (AST.lmark lblNan)
  bld <+ (crf0 := AST.b0)
  bld <+ (crf1 := AST.b0)
  bld <+ (crf2 := AST.b0)
  bld <+ (crf3 := AST.b1)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblRegular)
  bld <+ (crf0 := fl)
  bld <+ (crf1 := fg)
  bld <+ (crf2 := fe)
  bld <+ (crf3 := fu)
  bld <+ (AST.lmark lblEnd)
  bld <+ (vxsnan := cond3)
  if isOrdered then
    bld <+ (vxvc := AST.ite cond3 (AST.ite ve AST.b0 AST.b1) cond4)
  else ()
  bld --!> insLen

let fcmpo ins insLen bld =
  fcmp ins insLen bld true

let fcmpu ins insLen bld =
  fcmp ins insLen bld false

let fdiv ins insLen updateCond isDouble bld =
  let struct (frd, fra, frb) = transThreeOprs ins bld
  let tmp = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  if isDouble then bld <+ (frd := AST.fdiv fra frb)
  else
    let fraS = AST.cast CastKind.FloatCast 32<rt> fra
    let frbS = AST.cast CastKind.FloatCast 32<rt> frb
    bld <+ (tmp := AST.fdiv fraS frbS)
    bld <+ (frd := AST.cast CastKind.FloatCast 64<rt> tmp)
  setFPRF bld frd
  if updateCond then setCR1Reg bld else ()
  bld --!> insLen

let frsp ins insLen updateCond bld =
  let struct (frd, frb) = transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  let single = AST.cast CastKind.FloatCast 32<rt> frb
  bld <+ (frd := AST.cast CastKind.FloatCast 64<rt> single)
  setFPRF bld frd
  if updateCond then setCR1Reg bld else ()
  bld --!> insLen

let fsub ins insLen updateCond isDouble bld =
  fAddOrSub ins insLen updateCond isDouble AST.fsub bld

let fsqrt ins insLen updateCond isDouble bld =
  let struct (frd, frb) = transTwoOprs ins bld
  let tmp = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  if isDouble then bld <+ (frd := AST.fsqrt frb)
  else
    let frbS = AST.cast CastKind.FloatCast 32<rt> frb
    bld <+ (tmp := AST.fsqrt frbS)
    bld <+ (frd := AST.cast CastKind.FloatCast 64<rt> tmp)
  setFPRF bld frd
  if updateCond then setCR1Reg bld else ()
  bld --!> insLen

let fctiw ins insLen updateCond bld =
  let tmp = tmpVar bld 64<rt>
  let struct (frd, frb) = transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  roundingToCastInt bld frd frb
  setFPRF bld frd
  if updateCond then setCR1Reg bld else ()
  bld --!> insLen

let fctiwz ins insLen updateCond bld =
  let intMaxInFloat = numU64 0x41dfffffffc00000uL 64<rt>
  let intMinInFloat = numU64 0xc1e0000000000000uL 64<rt>
  let intMax = numU64 0x7fffffffUL 64<rt>
  let intMin = numU64 0x80000000UL 64<rt>
  let struct (frd, frb) = transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (frd := AST.cast CastKind.FtoITrunc 64<rt> frb)
  bld <+ (frd := AST.ite (IEEE754Double.isNaN frb) intMin frd)
  bld <+ (frd := AST.ite (AST.fle frb intMinInFloat) intMin frd)
  bld <+ (frd := AST.ite (AST.fge frb intMaxInFloat) intMax frd)
  setFPRF bld frd
  if updateCond then setCR1Reg bld else ()
  bld --!> insLen

let fmadd ins insLen updateCond isDouble bld =
  let struct (frd, fra, frc, frb) = transFourOprs ins bld
  let tmp = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  if isDouble then bld <+ (frd := AST.fadd (AST.fmul fra frc) frb)
  else
    let fraS = AST.cast CastKind.FloatCast 32<rt> fra
    let frbS = AST.cast CastKind.FloatCast 32<rt> frb
    let frcS = AST.cast CastKind.FloatCast 32<rt> frc
    bld <+ (tmp := AST.fadd (AST.fmul fraS frcS) frbS)
    bld <+ (frd := AST.cast CastKind.FloatCast 64<rt> tmp)
  setFPRF bld frd
  if updateCond then setCR1Reg bld else ()
  bld --!> insLen

let fmr ins insLen updateCond bld =
  let struct (dst, src) = transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src)
  if updateCond then setCR1Reg bld else ()
  bld --!> insLen

let fmsub ins insLen updateCond isDouble bld =
  let struct (frd, fra, frc, frb) = transFourOprs ins bld
  let tmp = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  if isDouble then bld <+ (frd := AST.fsub (AST.fmul fra frc) frb)
  else
    let fraS = AST.cast CastKind.FloatCast 32<rt> fra
    let frbS = AST.cast CastKind.FloatCast 32<rt> frb
    let frcS = AST.cast CastKind.FloatCast 32<rt> frc
    bld <+ (tmp := AST.fsub (AST.fmul fraS frcS) frbS)
    bld <+ (frd := AST.cast CastKind.FloatCast 64<rt> tmp)
  setFPRF bld frd
  if updateCond then setCR1Reg bld else ()
  bld --!> insLen

let fmul ins insLen updateCond isDouble bld =
  let struct (frd, fra, frb) = transThreeOprs ins bld
  let tmp = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  if isDouble then bld <+ (frd := AST.fmul fra frb)
  else
    let fraS = AST.cast CastKind.FloatCast 32<rt> fra
    let frbS = AST.cast CastKind.FloatCast 32<rt> frb
    bld <+ (tmp := AST.fmul fraS frbS)
    bld <+ (frd := AST.cast CastKind.FloatCast 64<rt> tmp)
  setFPRF bld frd
  if updateCond then setCR1Reg bld else ()
  bld --!> insLen

let fnabs ins insLen updateCond bld =
  let struct (frd, frb) = transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (frd := frb .| numU64 0x8000000000000000UL 64<rt>)
  if updateCond then setCR1Reg bld else ()
  bld --!> insLen

let fneg ins insLen updateCond bld =
  let struct (frd, frb) = transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  floatingNeg bld frd frb 64<rt>
  if updateCond then setCR1Reg bld else ()
  bld --!> insLen

let fnmadd ins insLen updateCond isDouble bld =
  let struct (frd, fra, frc, frb) = transFourOprs ins bld
  bld <!-- (ins.Address, insLen)
  if isDouble then
    let res = tmpVar bld 64<rt>
    bld <+ (res := (AST.fadd (AST.fmul fra frc) frb))
    floatingNeg bld frd res 64<rt>
  else
    let res = tmpVar bld 32<rt>
    let nres = tmpVar bld 32<rt>
    let fraS = AST.cast CastKind.FloatCast 32<rt> fra
    let frcS = AST.cast CastKind.FloatCast 32<rt> frc
    let frbS = AST.cast CastKind.FloatCast 32<rt> frb
    bld <+ (res := (AST.fadd (AST.fmul fraS frcS) frbS))
    floatingNeg bld nres res 32<rt>
    bld <+ (frd := AST.cast CastKind.FloatCast 64<rt> nres)
  if updateCond then setCR1Reg bld else ()
  bld --!> insLen

let fnmsub ins insLen updateCond isDouble bld =
  let struct (frd, fra, frc, frb) = transFourOprs ins bld
  bld <!-- (ins.Address, insLen)
  if isDouble then
    let res = tmpVar bld 64<rt>
    bld <+ (res := (AST.fsub (AST.fmul fra frc) frb))
    floatingNeg bld frd res 64<rt>
  else
    let res = tmpVar bld 32<rt>
    let nres = tmpVar bld 32<rt>
    let fraS = AST.cast CastKind.FloatCast 32<rt> fra
    let frcS = AST.cast CastKind.FloatCast 32<rt> frc
    let frbS = AST.cast CastKind.FloatCast 32<rt> frb
    bld <+ (res := (AST.fadd (AST.fmul fraS frcS) frbS))
    floatingNeg bld nres res 32<rt>
    bld <+ (frd := AST.cast CastKind.FloatCast 64<rt> nres)
  if updateCond then setCR1Reg bld else ()
  bld --!> insLen

let fsel ins insLen updateCond bld =
  let struct(frd, fra, frc, frb) = transFourOprs ins bld
  let cond = AST.fge fra (AST.num0 64<rt>)
  bld <!-- (ins.Address, insLen)
  bld <+ (frd := AST.ite cond frc frb)
  if updateCond then setCR1Reg bld else ()
  bld --!> insLen

let lbz ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 bld
  let dst = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (dst := AST.zext 32<rt> (loadNative bld 8<rt> tmpEA))
  bld --!> insLen

let lbzu ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
  let rd = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (rd := AST.zext 32<rt> (loadNative bld 8<rt> tmpEA))
  bld <+ (ra := tmpEA)
  bld --!> insLen

let lbzux ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr bld o1
  let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (rd := AST.zext 32<rt> (loadNative bld 8<rt> tmpEA))
  bld <+ (ra := tmpEA)
  bld --!> insLen

let lbzx ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr bld o1
  let ea = transEAWithIndexReg o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (rd := AST.zext 32<rt> (loadNative bld 8<rt> tmpEA))
  bld --!> insLen

let lfd ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 bld
  let dst = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (dst := loadNative bld 64<rt> tmpEA)
  bld --!> insLen

let lfdu ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
  let dst = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (dst := loadNative bld 64<rt> tmpEA)
  bld <+ (ra := tmpEA)
  bld --!> insLen

let lfdux ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let dst = transOpr bld o1
  let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (dst := loadNative bld 64<rt> tmpEA)
  bld <+ (ra := tmpEA)
  bld --!> insLen

let lfdx ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let dst = transOpr bld o1
  let ea = transEAWithIndexReg o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (dst := loadNative bld 64<rt> tmpEA)
  bld --!> insLen

let lfs ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 bld
  let dst = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  let v = loadNative bld 32<rt> tmpEA
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (dst := AST.cast CastKind.FloatCast 64<rt> v)
  bld --!> insLen

let lfsu ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
  let frd = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  let v = loadNative bld 32<rt> tmpEA
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (frd := AST.cast CastKind.FloatCast 64<rt> v)
  bld <+ (ra := tmpEA)
  bld --!> insLen

let lfsux ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let frd = transOpr bld o1
  let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  let v = loadNative bld 32<rt> tmpEA
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (frd := AST.cast CastKind.FloatCast 64<rt> v)
  bld <+ (ra := tmpEA)
  bld --!> insLen

let lfsx ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let frd = transOpr bld o1
  let ea = transEAWithIndexReg o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  let v = loadNative bld 32<rt> tmpEA
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (frd := AST.cast CastKind.FloatCast 64<rt> v)
  bld --!> insLen

let lha ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 bld
  let rd = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (rd := AST.sext 32<rt> (loadNative bld 16<rt> tmpEA))
  bld --!> insLen

let lhau ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
  let rd = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (rd := AST.sext 32<rt> (loadNative bld 16<rt> tmpEA))
  bld <+ (ra := tmpEA)
  bld --!> insLen

let lhaux ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr bld o1
  let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (rd := AST.sext 32<rt> (loadNative bld 16<rt> tmpEA))
  bld <+ (ra := tmpEA)
  bld --!> insLen

let lhax ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr bld o1
  let ea = transEAWithIndexReg o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (rd := AST.sext 32<rt> (loadNative bld 16<rt> tmpEA))
  bld --!> insLen

let lhbrx ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr bld o1
  let ea = transEAWithIndexReg o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  let tmpMem = tmpVar bld 16<rt>
  let revtmp = tmpVar bld 16<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (tmpMem := loadNative bld 16<rt> tmpEA)
  bld <+ (AST.xthi 8<rt> revtmp := AST.xtlo 8<rt> tmpMem)
  bld <+ (AST.xtlo 8<rt> revtmp := AST.xthi 8<rt> tmpMem)
  bld <+ (rd := AST.zext 32<rt> revtmp)
  bld --!> insLen

let lhz ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 bld
  let rd = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (rd := AST.zext 32<rt> (loadNative bld 16<rt> tmpEA))
  bld --!> insLen

let lhzu ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
  let rd = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (rd := AST.zext 32<rt> (loadNative bld 16<rt> tmpEA))
  bld <+ (ra := ea)
  bld --!> insLen

let lhzux ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr bld o1
  let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (rd := AST.zext 32<rt> (loadNative bld 16<rt> tmpEA))
  bld <+ (rA := tmpEA)
  bld --!> insLen

let lhzx ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr bld o1
  let ea = transEAWithIndexReg o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (rd := AST.zext 32<rt> (loadNative bld 16<rt> tmpEA))
  bld --!> insLen

let li ins insLen bld =
  let struct (dst, simm) = transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := simm)
  bld --!> insLen

let lis ins insLen bld =
  let struct (dst, simm) = transTwoOprs ins bld
  let simm = AST.concat (AST.xtlo 16<rt> simm) (AST.num0 16<rt>)
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := simm)
  bld --!> insLen

let lwarx ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr bld o1
  let ea = transEAWithIndexReg o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (AST.extCall <| AST.app "Reserve" [ tmpEA ] 32<rt>)
  bld <+ (rd := loadNative bld 32<rt> tmpEA)
  bld --!> insLen

let lwbrx ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr bld o1
  let ea = transEAWithIndexReg o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  let tmpMem = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (tmpMem := loadNative bld 32<rt> tmpEA)
  bld <+ (AST.extract rd 8<rt> 0 := AST.extract tmpMem 8<rt> 24)
  bld <+ (AST.extract rd 8<rt> 8 := AST.extract tmpMem 8<rt> 16)
  bld <+ (AST.extract rd 8<rt> 16 := AST.extract tmpMem 8<rt> 8)
  bld <+ (AST.extract rd 8<rt> 24 := AST.extract tmpMem 8<rt> 0)
  bld --!> insLen

let lwz ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 bld
  let dst = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (dst := loadNative bld 32<rt> tmpEA)
  bld --!> insLen

let lwzu ins insLen bld =
  let struct (o1 , o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
  let rd = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (rd := loadNative bld 32<rt> tmpEA)
  bld <+ (ra := tmpEA)
  bld --!> insLen

let lwzux ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr bld o1
  let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (rd := loadNative bld 32<rt> tmpEA)
  bld <+ (ra := tmpEA)
  bld --!> insLen

let lwzx ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rd = transOpr bld o1
  let ea = transEAWithIndexReg o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (rd := loadNative bld 32<rt> tmpEA)
  bld --!> insLen

let mcrf ins insLen bld =
  let struct ((crd0, crd1, crd2, crd3),
              (crs0, crs1, crs2, crs3)) = transCondTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (crd0 := crs0)
  bld <+ (crd1 := crs1)
  bld <+ (crd2 := crs2)
  bld <+ (crd3 := crs3)
  bld --!> insLen

let mcrxr ins insLen bld =
  let crd0, crd1, crd2, crd3 = transCondOneOpr ins bld
  let xer = regVar bld Register.XER
  bld <!-- (ins.Address, insLen)
  bld <+ (crd0 := AST.extract xer 1<rt> 31)
  bld <+ (crd1 := AST.extract xer 1<rt> 30)
  bld <+ (crd2 := AST.extract xer 1<rt> 29)
  bld <+ (crd3 := AST.extract xer 1<rt> 28)
  bld <+ (xer := xer .& numI32 0x0fffffff 32<rt>)
  bld --!> insLen

let mfcr ins insLen bld =
  let dst = transOneOpr ins bld
  let cr = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  getCRRegValue bld cr
  bld <+ (dst := cr)
  bld --!> insLen

let mfctr ins insLen bld =
  let dst = transOneOpr ins bld
  let ctr = regVar bld Register.CTR
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := ctr)
  bld --!> insLen

let mffs ins insLen bld =
  let dst = transOneOpr ins bld
  let fpscr = regVar bld Register.FPSCR
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := AST.zext 64<rt> fpscr)
  bld --!> insLen

let mflr ins insLen bld =
  let dst = transOneOpr ins bld
  let lr = regVar bld Register.LR
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := lr)
  bld --!> insLen

let mfspr (ins: Instruction) insLen bld =
  let struct (dst, spr) =
    match ins.Operands with
    | TwoOperands (o1, OprImm o2) ->
      transOpr bld o1, getSPRReg bld o2
    | _ -> raise InvalidOperandException
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := spr)
  bld --!> insLen

let mfxer ins insLen bld =
  let dst = transOneOpr ins bld
  let xer = regVar bld Register.XER
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := xer)
  bld --!> insLen

let mr ins insLen bld =
  let struct (dst, src) = transTwoOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src .| src)
  bld --!> insLen

let mtctr ins insLen bld =
  let src = transOneOpr ins bld
  let ctr = regVar bld Register.CTR
  bld <!-- (ins.Address, insLen)
  bld <+ (ctr := src)
  bld --!> insLen

let mtfsfi ins insLen updateCond bld =
  let struct (crfd, imm) = getTwoOprs ins
  let crfd = crfd |> getImmValue |> int
  let pos = 4 * (7 - crfd)
  let imm = transOpr bld imm
  let fpscr = regVar bld Register.FPSCR
  bld <!-- (ins.Address, insLen)
  if crfd = 0 then
    bld <+ (AST.extract fpscr 1<rt> 31 := AST.extract imm 1<rt> 3)
    bld <+ (AST.extract fpscr 1<rt> 28 := AST.extract imm 1<rt> 0)
  else
    bld <+ (AST.extract fpscr 1<rt> (pos + 3) := AST.extract imm 1<rt> 3)
    bld <+ (AST.extract fpscr 1<rt> (pos + 2) := AST.extract imm 1<rt> 2)
    bld <+ (AST.extract fpscr 1<rt> (pos+ 1) := AST.extract imm 1<rt> 1)
    bld <+ (AST.extract fpscr 1<rt> pos := AST.extract imm 1<rt> 0)
  bld --!> insLen

let mtspr (ins: Instruction) insLen bld =
  let struct (spr, rs) =
    match ins.Operands with
    | TwoOperands (OprImm o1, o2) ->
      getSPRReg bld o1, transOpr bld o2
    | _ -> raise InvalidOperandException
  bld <!-- (ins.Address, insLen)
  bld <+ (spr := rs)
  bld --!> insLen

let private crmMask bld crm =
  let tCrm = Array.init 4 (fun _ -> tmpVar bld 8<rt>)
  for i in 0..3 do
    let cond1 = AST.extract crm 1<rt> (i * 2)
    let cond2 = AST.extract crm 1<rt> (i * 2 + 1)
    bld <+ (tCrm[i] :=
      AST.ite cond1 (AST.ite cond2 (numI32 0xff 8<rt>)(numI32 0xf 8<rt>))
       (AST.ite cond2 (numI32 0xf0 8<rt>) (AST.num0 8<rt>)))
  tCrm |> AST.revConcat

let mtcrf ins insLen bld =
  let struct (crm, rs) = transTwoOprs ins bld
  let mask = tmpVar bld 32<rt>
  let cr = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (mask := crmMask bld crm)
  getCRRegValue bld cr
  bld <+ (cr := (rs .& mask) .| (cr .& AST.not mask))
  setCRRegValue bld cr
  bld --!> insLen

let mtlr ins insLen bld =
  let src = transOneOpr ins bld
  let lr = regVar bld Register.LR
  bld <!-- (ins.Address, insLen)
  bld <+ (lr := src)
  bld --!> insLen

let mtfsb0 ins insLen updateCond bld =
  let crbD = getOneOpr ins |> getImmValue |> int
  let fpscr = regVar bld Register.FPSCR
  bld <!-- (ins.Address, insLen)
  if crbD <> 1 && crbD <> 2 then
    bld <+ (AST.extract fpscr 1<rt> (31 - crbD) := AST.b0)
  if updateCond then setCR1Reg bld else ()
  (* Affected: FX *)
  bld --!> insLen

let mtfsb1 ins insLen updateCond bld =
  let crbD = getOneOpr ins |> getImmValue |> int
  let fpscr = regVar bld Register.FPSCR
  bld <!-- (ins.Address, insLen)
  if crbD <> 1 && crbD <> 2 then
    bld <+ (AST.extract fpscr 1<rt> (31 - crbD) := AST.b1)
  if updateCond then setCR1Reg bld else ()
  (* Affected: FX *)
  bld --!> insLen

let mtfsf ins insLen bld =
  let struct (fm, frB) = getTwoOprs ins
  let frB = transOpr bld frB
  let fm = BitVector.OfUInt32 (getImmValue fm) 32<rt> |> AST.num
  let fpscr = regVar bld Register.FPSCR
  bld <!-- (ins.Address, insLen)
  bld <+ (fpscr := AST.xtlo 32<rt> frB .& fm)
  bld --!> insLen

let mtxer ins insLen bld =
  let src = transOneOpr ins bld
  let xer = regVar bld Register.XER
  bld <!-- (ins.Address, insLen)
  bld <+ (xer := src)
  bld --!> insLen

let mulhw ins insLen updateCond bld =
  let struct (dst, ra, rb) = transThreeOprs ins bld
  let tmp = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmp := (AST.sext 64<rt> ra) .* (AST.sext 64<rt> rb))
  bld <+ (dst := AST.xthi 32<rt> tmp)
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let mulhwu ins insLen updateCond bld =
  let struct (dst, ra, rb) = transThreeOprs ins bld
  let tmp = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmp := (AST.zext 64<rt> ra) .* (AST.zext 64<rt> rb))
  bld <+ (dst := AST.xthi 32<rt> tmp)
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let mulli ins insLen bld =
  let struct (dst, ra, simm) = transThreeOprs ins bld
  let tmp = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmp := (AST.sext 64<rt> ra) .* (AST.sext 64<rt> simm))
  bld <+ (dst := AST.xtlo 32<rt> tmp)
  bld --!> insLen

let mullw ins insLen updateCond ovCond bld =
  let struct (dst, src1, src2) = transThreeOprs ins bld
  let tmp = tmpVar bld 64<rt>
  bld <!-- (ins.Address, insLen)
  if ovCond then isMulOV bld src1 src2 else ()
  bld <+ (tmp := (AST.sext 64<rt> src1) .* (AST.sext 64<rt> src2))
  bld <+ (dst := AST.xtlo 32<rt> tmp)
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let nand ins insLen updateCond bld =
  let struct (dst, src1, src2) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := AST.not(src1 .& src2))
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let neg ins insLen updateCond ovCond bld =
  let struct (dst, src) = transTwoOprs ins bld
  let struct (t1, t2) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (t1 := AST.not src)
  bld <+ (t2 := AST.num1 32<rt>)
  bld <+ (dst := t1 .+ t2)
  if ovCond then isAddSubOV bld t1 t2 dst else ()
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let nor ins insLen updateCond bld =
  let struct (dst, src1, src2) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := AST.not (src1 .| src2))
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let nop (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  bld --!> insLen

let orx ins insLen updateCond bld =
  let struct (dst, src1, src2) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src1 .| src2)
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let orc ins insLen updateCond bld =
  let struct (dst, src1, src2) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src1 .| AST.not(src2))
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let ori ins insLen bld =
  let struct (dst, src, uimm) = transThreeOprs ins bld
  let uimm = AST.zext 32<rt> (AST.xtlo 16<rt> uimm)
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src .| uimm)
  bld --!> insLen

let oris ins insLen bld =
  let struct (dst, src, uimm) = transThreeOprs ins bld
  let uimm = AST.concat (AST.xtlo 16<rt> uimm) (AST.num0 16<rt>)
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src .| uimm)
  bld --!> insLen

let rlwinm ins insLen updateCond bld =
  let struct (ra, rs, sh, mb, me) = transFiveOprs ins bld
  let rol = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rol := rotateLeft rs sh)
  bld <+ (ra := rol .& (getExtMask mb me))
  if updateCond then setCR0Reg bld ra else ()
  bld --!> insLen

let rlwimi ins insLen updateCond bld =
  let struct (ra, rs, sh, mb, me) = transFiveOprs ins bld
  let m = getExtMask mb me
  let rol = rotateLeft rs sh
  bld <!-- (ins.Address, insLen)
  bld <+ (ra := (rol .& m) .| (ra .& AST.not m))
  if updateCond then setCR0Reg bld ra else ()
  bld --!> insLen

let rlwnm ins insLen updateCond bld =
  let struct (ra, rs, rb, mb, me) = transFiveOprs ins bld
  let rol = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (rol := rb .& numI32 0x1f 32<rt>)
  bld <+ (ra := rol .& (getExtMask mb me))
  if updateCond then setCR0Reg bld ra else ()
  bld --!> insLen

let rotlw ins insLen bld =
  let struct (ra, rs, rb) = transThreeOprs ins bld
  let n = rb .& numI32 0x1f 32<rt>
  let rol = rotateLeft rs n
  bld <!-- (ins.Address, insLen)
  bld <+ (ra := rol) (* no mask *)
  bld --!> insLen

let slw ins insLen updateCond bld =
  let struct (dst, rs, rb) = transThreeOprs ins bld
  let n = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (n := rb .& numI32 0x1f 32<rt>)
  let z = AST.num0 32<rt>
  let cond1 = rb .& numI32 0x20 32<rt> == z
  bld <+ (dst := AST.ite cond1 (rs << n) (numI32 0 32<rt>))
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let sraw ins insLen updateCond bld =
  let struct (ra, rs, rb) = transThreeOprs ins bld
  let xerCA = AST.extract (regVar bld Register.XER) 1<rt> 29
  let z = AST.num0 32<rt>
  let cond1 = rb .& numI32 0x20 32<rt> == z
  let n = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (n := rb .& numI32 0x1f 32<rt>)
  bld <+ (ra := AST.ite cond1 (rs ?>> n) (rs ?>> numI32 31 32<rt>))
  let cond2 = ra ?< z
  let cond3 = (rs .& ((AST.num1 32<rt> << n) .- AST.num1 32<rt>)) == z
  bld <+ (xerCA := AST.ite cond2 (AST.ite cond3 AST.b0 AST.b1) AST.b0)
  if updateCond then setCR0Reg bld ra else ()
  bld --!> insLen

let srawi ins insLen updateCond bld =
  let struct (ra, rs, sh) = transThreeOprs ins bld
  let xerCA = AST.extract (regVar bld Register.XER) 1<rt> 29
  let z = AST.num0 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (ra := rs ?>> sh)
  let cond1 = ra ?< z
  let cond2 = (rs .& ((AST.num1 32<rt> << sh) .- AST.num1 32<rt>)) == z
  bld <+ (xerCA := AST.ite cond1 (AST.ite cond2 AST.b0 AST.b1) AST.b0)
  if updateCond then setCR0Reg bld ra else ()
  bld --!> insLen

let srw ins insLen updateCond bld =
  let struct (dst, rs, rb) = transThreeOprs ins bld
  let n = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (n := rb .& numI32 0x1f 32<rt>)
  let z = AST.num0 32<rt>
  let cond1 = rb .& numI32 0x20 32<rt> == z
  bld <+ (dst := AST.ite cond1 (rs >> n) (numI32 0 32<rt>))
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let stb ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 bld
  let src = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 8<rt> tmpEA := AST.xtlo 8<rt> src)
  bld --!> insLen

let stbx ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr bld o1
  let ea = transEAWithIndexReg o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 8<rt> tmpEA := AST.xtlo 8<rt> rs)
  bld --!> insLen

let stbu ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
  let src = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 8<rt> tmpEA := AST.xtlo 8<rt> src)
  bld <+ (ra := tmpEA)
  bld --!> insLen

let stbux ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr bld o1
  let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 8<rt> tmpEA := AST.xtlo 8<rt> rs)
  bld <+ (rA := tmpEA)
  bld --!> insLen

let stfd ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 bld
  let frs = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 64<rt> tmpEA := frs)
  bld --!> insLen

let stfdx ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let ea = transEAWithIndexReg o2 o3 bld
  let frs = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 64<rt> tmpEA := frs)
  bld --!> insLen

let stfdu ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
  let frs = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 64<rt> tmpEA := frs)
  bld <+ (ra := tmpEA)
  bld --!> insLen

let stfdux ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let frs = transOpr bld o1
  let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 64<rt> tmpEA := frs)
  bld <+ (rA := tmpEA)
  bld --!> insLen

let stfiwx ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let frs = transOpr bld o1
  let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 32<rt> tmpEA := AST.xtlo 32<rt> frs)
  bld <+ (rA := tmpEA)
  bld --!> insLen

let stfs ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 bld
  let frs = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 32<rt> tmpEA := AST.cast CastKind.FloatCast 32<rt> frs)
  bld --!> insLen

let stfsx ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let ea = transEAWithIndexReg o2 o3 bld
  let frs = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 32<rt> tmpEA := AST.cast CastKind.FloatCast 32<rt> frs)
  bld --!> insLen

let stfsu ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
  let frs = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 32<rt> tmpEA := AST.cast CastKind.FloatCast 32<rt> frs)
  bld <+ (ra := tmpEA)
  bld --!> insLen

let stfsux ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let frs = transOpr bld o1
  let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 32<rt> tmpEA := AST.cast CastKind.FloatCast 32<rt> frs)
  bld <+ (rA := tmpEA)
  bld --!> insLen

let sth ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 bld
  let src = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 16<rt> tmpEA := AST.xtlo 16<rt> src)
  bld --!> insLen

let sthbrx ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr bld o1
  let ea = transEAWithIndexReg o2 o3 bld
  let revtmp = tmpVar bld 16<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (revtmp := AST.concat (AST.extract rs 8<rt> 0)
                               (AST.extract rs 8<rt> 8))
  bld <+ (loadNative bld 16<rt> ea := revtmp)
  bld --!> insLen

let sthx ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr bld o1
  let ea = transEAWithIndexReg o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 16<rt> tmpEA := AST.xtlo 16<rt> rs)
  bld --!> insLen

let sthu ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
  let rs = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 16<rt> tmpEA := AST.xtlo 16<rt> rs)
  bld <+ (ra := tmpEA)
  bld --!> insLen

let sthux ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr bld o1
  let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 16<rt> tmpEA := AST.xtlo 16<rt> rs)
  bld <+ (rA := tmpEA)
  bld --!> insLen

let stw ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let ea = transEAWithOffset o2 bld
  let src = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 32<rt> tmpEA := src)
  bld --!> insLen

let stwbrx ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr bld o1
  let ea = transEAWithIndexReg o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  let revtmp = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (AST.extract revtmp 8<rt> 0:= AST.extract rs 8<rt> 24)
  bld <+ (AST.extract revtmp 8<rt> 8:= AST.extract rs 8<rt> 16)
  bld <+ (AST.extract revtmp 8<rt> 16:= AST.extract rs 8<rt> 8)
  bld <+ (AST.extract revtmp 8<rt> 24:= AST.extract rs 8<rt> 0)
  bld <+ (loadNative bld 32<rt> tmpEA := revtmp)
  bld --!> insLen

let stwcxdot ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr bld o1
  let ea = transEAWithIndexReg o2 o3 bld
  let res = regVar bld Register.RES
  let xerSO = AST.xthi 1<rt> (regVar bld Register.XER)
  let cr0LT = regVar bld Register.CR0_0
  let cr0GT = regVar bld Register.CR0_1
  let cr0EQ = regVar bld Register.CR0_2
  let cr0SO = regVar bld Register.CR0_3
  bld <!-- (ins.Address, insLen)
  let lblRes = label bld "Reserved"
  let lblNoRes = label bld "NotReserved"
  let lblEnd = label bld "End"
  let tmpEA = tmpVar bld 32<rt>
  bld <+ (tmpEA := ea)
  bld <+ (AST.extCall <| AST.app "IsReserved" [ tmpEA ] 32<rt>)
  bld <+ (AST.cjmp (res == AST.b1) (AST.jmpDest lblRes) (AST.jmpDest lblNoRes))
  bld <+ (AST.lmark lblRes)
  bld <+ (loadNative bld 32<rt> tmpEA := rs)
  bld <+ (res := AST.b0)
  bld <+ (cr0EQ := AST.b1)
  bld <+ (AST.jmp (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblNoRes)
  bld <+ (cr0EQ := AST.b0)
  bld <+ (AST.lmark lblEnd)
  bld <+ (cr0LT := AST.b0)
  bld <+ (cr0GT := AST.b0)
  bld <+ (cr0SO := xerSO)
  bld --!> insLen

let stwu ins insLen bld =
  let struct (o1, o2) = getTwoOprs ins
  let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
  let src = transOpr bld o1
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 32<rt> tmpEA := src)
  bld <+ (ra := tmpEA)
  bld --!> insLen

let stwux ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr bld o1
  let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 32<rt> tmpEA := rs)
  bld <+ (rA := tmpEA)
  bld --!> insLen

let stwx ins insLen bld =
  let struct (o1, o2, o3) = getThreeOprs ins
  let rs = transOpr bld o1
  let ea = transEAWithIndexReg o2 o3 bld
  let tmpEA = tmpVar bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (tmpEA := ea)
  bld <+ (loadNative bld 32<rt> tmpEA := rs)
  bld --!> insLen

let subf ins insLen updateCond ovCond bld =
  let struct (dst, src1, src2) = transThreeOprs ins bld
  let one = AST.num1 32<rt>
  let struct (t1, t2) = tmpVars2 bld 32<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (t1 := AST.not src1)
  bld <+ (t2 := src2)
  bld <+ (dst := t1 .+ t2 .+ one)
  if ovCond then isAddSubOV bld t1 t2 dst else ()
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let subfc ins insLen updateCond ovCond bld =
  let struct (dst, src1, src2) = transThreeOprs ins bld
  let one = AST.num1 64<rt>
  let struct (t1, t2, t3) = tmpVars3 bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (t1 := AST.zext 64<rt> (AST.not src1))
  bld <+ (t2 := AST.zext 64<rt> src2)
  bld <+ (t3 := t1 .+ t2 .+ one)
  bld <+ (dst := AST.xtlo 32<rt> t3)
  setCarryOut bld t3
  if ovCond then isAddSubOV bld t1 t2 dst else ()
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let subfe ins insLen updateCond ovCond bld =
  let struct (dst, src1, src2) = transThreeOprs ins bld
  let xerCA = AST.zext 64<rt> (AST.extract (regVar bld Register.XER) 1<rt> 29)
  let struct (t1, t2, t3) = tmpVars3 bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (t1 := AST.zext 64<rt> (AST.not src1))
  bld <+ (t2 := AST.zext 64<rt> src2)
  bld <+ (t3 := t1 .+ t2 .+ xerCA)
  bld <+ (dst := AST.xtlo 32<rt> t3)
  setCarryOut bld t3
  if ovCond then isAddSubOV bld t1 t2 dst else ()
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let subfic ins insLen bld  =
  let struct (dst, src1, simm) = transThreeOprs ins bld
  let struct (t1, t2, t3) = tmpVars3 bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (t1 := AST.zext 64<rt> (AST.not src1))
  bld <+ (t2 := AST.zext 64<rt> simm)
  bld <+ (t3 := t1 .+ t2 .+ AST.num1 64<rt>)
  bld <+ (dst := AST.xtlo 32<rt> t3)
  setCarryOut bld t3
  bld --!> insLen

let subfme ins insLen updateCond ovCond bld =
  let struct (dst, src) = transTwoOprs ins bld
  let xerCA = AST.zext 64<rt> (AST.extract (regVar bld Register.XER) 1<rt> 29)
  let struct (t1, t2, t3) = tmpVars3 bld 64<rt>
  let minusone = AST.num (BitVector.OfUInt32 0xffffffffu 64<rt>)
  bld <!-- (ins.Address, insLen)
  bld <+ (t1 := AST.zext 64<rt> (AST.not src))
  bld <+ (t2 := xerCA)
  bld <+ (t3 := t1 .+ t2 .+ minusone)
  bld <+ (dst := AST.xtlo 32<rt> t3)
  setCarryOut bld t3
  if ovCond then isAddSubOV bld t1 t2 dst else ()
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let subfze ins insLen updateCond ovCond bld =
  let struct (dst, src) = transTwoOprs ins bld
  let xerCA = AST.zext 64<rt> (AST.extract (regVar bld Register.XER) 1<rt> 29)
  let struct (t1, t2, t3) = tmpVars3 bld 64<rt>
  bld <!-- (ins.Address, insLen)
  bld <+ (t1 := AST.zext 64<rt> (AST.not src))
  bld <+ (t2 := xerCA)
  bld <+ (t3 := t1 .+ t2)
  bld <+ (dst := AST.xtlo 32<rt> t3)
  setCarryOut bld t3
  if ovCond then isAddSubOV bld t1 t2 dst else ()
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let trap (ins: Instruction) insLen bld =
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.sideEffect (Interrupt 0))
  bld --!> insLen

let trapCond ins insLen cmpOp bld =
  let struct (ra, rb) = transTwoOprs ins bld
  let lblTrap = label bld "Trap"
  let lblEnd = label bld "End"
  bld <!-- (ins.Address, insLen)
  bld <+ (AST.cjmp (cmpOp ra rb) (AST.jmpDest lblTrap) (AST.jmpDest lblEnd))
  bld <+ (AST.lmark lblTrap)
  bld <+ (AST.sideEffect (Interrupt 0))
  bld <+ (AST.lmark lblEnd)
  bld --!> insLen

let xor ins insLen updateCond bld =
  let struct (dst, src1, src2) = transThreeOprs ins bld
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := (src1 <+> src2))
  if updateCond then setCR0Reg bld dst else ()
  bld --!> insLen

let xori ins insLen bld =
  let struct (dst, src, uimm) = transThreeOprs ins bld
  let uimm = AST.zext 32<rt> (AST.xtlo 16<rt> uimm)
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src <+> uimm)
  bld --!> insLen

let xoris ins insLen bld =
  let struct (dst, src, uimm) = transThreeOprs ins bld
  let uimm = AST.concat (AST.xtlo 16<rt> uimm) (AST.num0 16<rt>)
  bld <!-- (ins.Address, insLen)
  bld <+ (dst := src <+> uimm)
  bld --!> insLen

/// Translate IR.
let translate (ins: Instruction) insLen bld =
  match ins.Opcode with
  | Op.ADD -> add ins insLen false false bld
  | Op.ADDdot -> add ins insLen true false bld
  | Op.ADDO -> add ins insLen false true bld
  | Op.ADDOdot -> add ins insLen true true bld
  | Op.ADDC -> addc ins insLen false false bld
  | Op.ADDCdot -> addc ins insLen true false bld
  | Op.ADDCO -> add ins insLen false true bld
  | Op.ADDCOdot -> add ins insLen true true bld
  | Op.ADDE -> adde ins insLen false false bld
  | Op.ADDEdot -> adde ins insLen true false bld
  | Op.ADDEO -> adde ins insLen false true bld
  | Op.ADDEOdot -> adde ins insLen true true bld
  | Op.ADDI -> addi ins insLen bld
  | Op.ADDIC -> addic ins insLen false bld
  | Op.ADDICdot -> addic ins insLen true bld
  | Op.ADDIS -> addis ins insLen bld
  | Op.ADDME -> addme ins insLen false false bld
  | Op.ADDMEdot -> addme ins insLen true false bld
  | Op.ADDMEO -> addme ins insLen false true bld
  | Op.ADDMEOdot -> addme ins insLen true true bld
  | Op.ADDZE -> addze ins insLen false false bld
  | Op.ADDZEdot -> addze ins insLen true false bld
  | Op.ADDZEO -> addze ins insLen false true bld
  | Op.ADDZEOdot -> addze ins insLen true true bld
  | Op.AND -> andx ins insLen false bld
  | Op.ANDdot -> andx ins insLen true bld
  | Op.ANDC -> andc ins insLen false bld
  | Op.ANDCdot -> andc ins insLen true bld
  | Op.ANDIdot -> andidot ins insLen bld
  | Op.ANDISdot -> andisdot ins insLen bld
  | Op.B -> b ins insLen bld false
  | Op.BA -> b ins insLen bld false
  | Op.BL -> b ins insLen bld true
  | Op.BLA -> b ins insLen bld true
  | Op.BC -> bc ins insLen bld false false
  | Op.BCA -> bc ins insLen bld true false
  | Op.BCL -> bc ins insLen bld false true
  | Op.BCLA -> bc ins insLen bld true true
  | Op.BCCTR -> bcctr ins insLen bld false
  | Op.BCCTRL -> bcctr ins insLen bld true
  | Op.BCLR -> bclr ins insLen bld false
  | Op.BCLRL -> bclr ins insLen bld true
  | Op.CMPI | Op.CMPL | Op.CMPLI -> raise InvalidOperandException (* invaild *)
  | Op.CMP -> cmp ins insLen bld
  | Op.CMPW -> cmp ins insLen bld
  | Op.CMPLW -> cmpl ins insLen bld
  | Op.CMPLWI -> cmpli ins insLen bld
  | Op.CMPWI -> cmp ins insLen bld
  | Op.CNTLZW -> cntlzw ins insLen false bld
  | Op.CNTLZWdot -> cntlzw ins insLen true bld
  | Op.CRCLR -> crclr ins insLen bld
  | Op.CREQV -> creqv ins insLen bld
  | Op.CRXOR -> crxor ins insLen bld
  | Op.CROR -> cror ins insLen bld
  | Op.CRORC -> crorc ins insLen bld
  | Op.CRSET -> crset ins insLen bld
  | Op.CRNOR -> crnor ins insLen bld
  | Op.CRNOT -> crnot ins insLen bld
  | Op.DCBT -> nop ins insLen bld
  | Op.DCBTST -> nop ins insLen bld
  | Op.DIVW -> divw ins insLen false true bld
  | Op.DIVWdot -> divw ins insLen false false bld
  | Op.DIVWO -> divw ins insLen true true bld
  | Op.DIVWOdot -> divw ins insLen true false bld
  | Op.DIVWU -> divwu ins insLen false true bld
  | Op.DIVWUdot -> divwu ins insLen false false bld
  | Op.DIVWUO -> divwu ins insLen true true bld
  | Op.DIVWUOdot -> divwu ins insLen true false bld
  | Op.EXTSB -> extsb ins insLen false bld
  | Op.EXTSBdot -> extsb ins insLen true bld
  | Op.EXTSH -> extsh ins insLen false bld
  | Op.EXTSHdot -> extsh ins insLen true bld
  | Op.EIEIO -> nop ins insLen bld
  | Op.EQV -> eqvx ins insLen false bld
  | Op.EQVdot -> eqvx ins insLen true bld
  | Op.FABS -> fabs ins insLen false bld
  | Op.FABSdot  -> fabs ins insLen true bld
  | Op.FADD -> fadd ins insLen false true bld
  | Op.FADDS -> fadd ins insLen false false bld
  | Op.FADDdot -> fadd ins insLen true true bld
  | Op.FADDSdot -> fadd ins insLen true false bld
  | Op.FCTIW -> fctiw ins insLen false bld
  | Op.FCTIWdot -> fctiw ins insLen true bld
  | Op.FCTIWZ -> fctiwz ins insLen false bld
  | Op.FCTIWZdot -> fctiwz ins insLen true bld
  | Op.FCMPO -> fcmpo ins insLen bld
  | Op.FCMPU -> fcmpu ins insLen bld
  | Op.FDIV -> fdiv ins insLen false true bld
  | Op.FDIVS -> fdiv ins insLen false false bld
  | Op.FDIVdot -> fdiv ins insLen true true bld
  | Op.FDIVSdot -> fdiv ins insLen true false bld
  | Op.FRSP -> frsp ins insLen false bld
  | Op.FRSPdot -> frsp ins insLen true bld
  | Op.FMADD -> fmadd ins insLen false true bld
  | Op.FMADDS -> fmadd ins insLen false false bld
  | Op.FMADDdot -> fmadd ins insLen true true bld
  | Op.FMADDSdot -> fmadd ins insLen true false bld
  | Op.FMR -> fmr ins insLen false bld
  | Op.FMRdot -> fmr ins insLen true bld
  | Op.FMSUB -> fmsub ins insLen false true bld
  | Op.FMSUBS -> fmsub ins insLen false false bld
  | Op.FMSUBdot -> fmsub ins insLen true true bld
  | Op.FMSUBSdot -> fmsub ins insLen true false bld
  | Op.FMUL -> fmul ins insLen false true bld
  | Op.FMULS -> fmul ins insLen false false bld
  | Op.FMULdot -> fmul ins insLen true true bld
  | Op.FMULSdot -> fmul ins insLen true false bld
  | Op.FNABS -> fnabs ins insLen false bld
  | Op.FNABSdot -> fnabs ins insLen true bld
  | Op.FNEG -> fneg ins insLen false bld
  | Op.FNEGdot -> fneg ins insLen true bld
  | Op.FNMADD -> fnmadd ins insLen false true bld
  | Op.FNMADDdot -> fnmadd ins insLen true true bld
  | Op.FNMADDS -> fnmadd ins insLen false false bld
  | Op.FNMADDSdot -> fnmadd ins insLen true false bld
  | Op.FNMSUB -> fnmsub ins insLen false true bld
  | Op.FNMSUBdot -> fnmsub ins insLen true true bld
  | Op.FNMSUBS -> fnmsub ins insLen false false bld
  | Op.FNMSUBSdot -> fnmsub ins insLen true false bld
  | Op.FSEL -> fsel ins insLen false bld
  | Op.FSELdot -> fsel ins insLen true bld
  | Op.FSUB -> fsub ins insLen false true bld
  | Op.FSUBS -> fsub ins insLen false false bld
  | Op.FSUBdot -> fsub ins insLen true true bld
  | Op.FSUBSdot -> fsub ins insLen true false bld
  | Op.FSQRT -> fsqrt ins insLen false true bld
  | Op.FSQRTS -> fsqrt ins insLen false false bld
  | Op.FSQRTdot -> fsqrt ins insLen true true bld
  | Op.FSQRTSdot -> fsqrt ins insLen true false bld
  | Op.ISYNC | Op.LWSYNC | Op.SYNC -> nop ins insLen bld
  | Op.LBZ -> lbz ins insLen bld
  | Op.LBZU -> lbzu ins insLen bld
  | Op.LBZUX -> lbzux ins insLen bld
  | Op.LBZX -> lbzx ins insLen bld
  | Op.LFD -> lfd ins insLen bld
  | Op.LFDU -> lfdu ins insLen bld
  | Op.LFDUX -> lfdux ins insLen bld
  | Op.LFDX -> lfdx ins insLen bld
  | Op.LFS -> lfs ins insLen bld
  | Op.LFSU -> lfsu ins insLen bld
  | Op.LFSUX -> lfsux ins insLen bld
  | Op.LFSX -> lfsx ins insLen bld
  | Op.LHA -> lha ins insLen bld
  | Op.LHAU -> lhau ins insLen bld
  | Op.LHAUX ->lhaux ins insLen bld
  | Op.LHAX -> lhax ins insLen bld
  | Op.LHBRX -> lhbrx ins insLen bld
  | Op.LHZ -> lhz ins insLen bld
  | Op.LHZU -> lhzu ins insLen bld
  | Op.LHZUX ->lhzux ins insLen bld
  | Op.LHZX -> lhzx ins insLen bld
  | Op.LI -> li ins insLen bld
  | Op.LIS -> lis ins insLen bld
  | Op.LWARX -> lwarx ins insLen bld
  | Op.LWBRX -> lwbrx ins insLen bld
  | Op.LWZ -> lwz ins insLen bld
  | Op.LWZU -> lwzu ins insLen bld
  | Op.LWZUX -> lwzux ins insLen bld
  | Op.LWZX -> lwzx ins insLen bld
  | Op.MCRF -> mcrf ins insLen bld
  | Op.MCRXR -> mcrxr ins insLen bld
  | Op.MFCR -> mfcr ins insLen bld
  | Op.MFSPR -> mfspr ins insLen bld
  | Op.MFCTR -> mfctr ins insLen bld
  | Op.MFFS -> mffs ins insLen bld
  | Op.MFLR -> mflr ins insLen bld
  | Op.MFXER -> mfxer ins insLen bld
  | Op.MR -> mr ins insLen bld
  | Op.MTCTR -> mtctr ins insLen bld
  | Op.MTCRF -> mtcrf ins insLen bld
  | Op.MTFSFI -> mtfsfi ins insLen false bld
  | Op.MTFSFIdot -> mtfsfi ins insLen true bld
  | Op.MTSPR -> mtspr ins insLen bld
  | Op.MTFSB0 -> mtfsb0 ins insLen false bld
  | Op.MTFSB0dot -> mtfsb0 ins insLen true bld
  | Op.MTFSB1 -> mtfsb1 ins insLen false bld
  | Op.MTFSB1dot -> mtfsb1 ins insLen true bld
  | Op.MTFSF -> mtfsf ins insLen bld
  | Op.MTLR -> mtlr ins insLen bld
  | Op.MTXER -> mtxer ins insLen bld
  | Op.MULHW -> mulhw ins insLen false bld
  | Op.MULHWU -> mulhwu ins insLen false bld
  | Op.MULHWUdot -> mulhwu ins insLen true bld
  | Op.MULLI -> mulli ins insLen bld
  | Op.MULLW -> mullw ins insLen false false bld
  | Op.MULLWdot -> mullw ins insLen true false bld
  | Op.MULLWO -> mullw ins insLen false true bld
  | Op.MULLWOdot -> mullw ins insLen true true bld
  | Op.NAND -> nand ins insLen false bld
  | Op.NANDdot -> nand ins insLen true bld
  | Op.NEG -> neg ins insLen false false bld
  | Op.NEGdot -> neg ins insLen true false bld
  | Op.NEGO -> neg ins insLen false true bld
  | Op.NEGOdot -> neg ins insLen true true bld
  | Op.NOR -> nor ins insLen false bld
  | Op.NORdot -> nor ins insLen true bld
  | Op.NOP -> nop ins insLen bld
  | Op.ORC -> orc ins insLen false bld
  | Op.ORCdot -> orc ins insLen true bld
  | Op.OR -> orx ins insLen false bld
  | Op.ORdot -> orx ins insLen true bld
  | Op.ORI -> ori ins insLen bld
  | Op.ORIS -> oris ins insLen bld
  | Op.RLWIMI -> rlwimi ins insLen false bld
  | Op.RLWIMIdot -> rlwimi ins insLen true bld
  | Op.RLWINM -> rlwinm ins insLen false bld
  | Op.RLWINMdot -> rlwinm ins insLen true bld
  | Op.RLWNM -> rlwnm ins insLen false bld
  | Op.RLWNMdot -> rlwnm ins insLen true bld
  | Op.ROTLW -> rotlw ins insLen bld
  | Op.SC -> sideEffects ins insLen bld SysCall
  | Op.SLW -> slw ins insLen false bld
  | Op.SLWdot -> slw ins insLen true bld
  | Op.SRAW -> sraw ins insLen false bld
  | Op.SRAWdot -> sraw ins insLen true bld
  | Op.SRAWI -> srawi ins insLen false bld
  | Op.SRAWIdot -> srawi ins insLen true bld
  | Op.SRW -> srw ins insLen false bld
  | Op.SRWdot -> srw ins insLen true bld
  | Op.STB -> stb ins insLen bld
  | Op.STBU -> stbu ins insLen bld
  | Op.STBX -> stbx ins insLen bld
  | Op.STBUX -> stbux ins insLen bld
  | Op.STFD -> stfd ins insLen bld
  | Op.STFDX -> stfdx ins insLen bld
  | Op.STFDU -> stfdu ins insLen bld
  | Op.STFDUX -> stfdux ins insLen bld
  | Op.STFIWX -> stfiwx ins insLen bld
  | Op.STFS -> stfs ins insLen bld
  | Op.STFSX -> stfsx ins insLen bld
  | Op.STFSU -> stfsu ins insLen bld
  | Op.STFSUX -> stfsux ins insLen bld
  | Op.STH -> sth ins insLen bld
  | Op.STHBRX -> sthbrx ins insLen bld
  | Op.STHU -> sthu ins insLen bld
  | Op.STHX -> sthx ins insLen bld
  | Op.STHUX -> sthux ins insLen bld
  | Op.STW -> stw ins insLen bld
  | Op.STWBRX -> stwbrx ins insLen bld
  | Op.STWCXdot -> stwcxdot ins insLen bld
  | Op.STWU -> stwu ins insLen bld
  | Op.STWUX -> stwux ins insLen bld
  | Op.STWX -> stwx ins insLen bld
  | Op.SUBF -> subf ins insLen false false bld
  | Op.SUBFdot -> subf ins insLen true false bld
  | Op.SUBFO -> subf ins insLen false true bld
  | Op.SUBFOdot -> subf ins insLen true true bld
  | Op.SUBFC -> subfc ins insLen false false bld
  | Op.SUBFCdot -> subfc ins insLen true false bld
  | Op.SUBFCO -> subfc ins insLen false true bld
  | Op.SUBFCOdot -> subfc ins insLen true true bld
  | Op.SUBFE -> subfe ins insLen false false bld
  | Op.SUBFEdot -> subfe ins insLen true false bld
  | Op.SUBFEO -> subfe ins insLen false true bld
  | Op.SUBFEOdot -> subfe ins insLen true true bld
  | Op.SUBFIC -> subfic ins insLen bld
  | Op.SUBFME -> subfme ins insLen false false bld
  | Op.SUBFMEdot -> subfme ins insLen true false bld
  | Op.SUBFMEO -> subfme ins insLen false true bld
  | Op.SUBFMEOdot -> subfme ins insLen true true bld
  | Op.SUBFZE -> subfze ins insLen false false bld
  | Op.SUBFZEdot -> subfze ins insLen true false bld
  | Op.SUBFZEO -> subfze ins insLen false true bld
  | Op.SUBFZEOdot -> subfze ins insLen true true bld
  | Op.TRAP | Op.TWI -> trap ins insLen bld
  | Op.TWLT -> trapCond ins insLen (AST.slt) bld
  | Op.TWLE -> trapCond ins insLen (AST.sle) bld
  | Op.TWEQ -> trapCond ins insLen (AST.eq) bld
  | Op.TWGE -> trapCond ins insLen (AST.sge) bld
  | Op.TWGT -> trapCond ins insLen (AST.sgt) bld
  | Op.TWNE -> trapCond ins insLen (AST.neq) bld
  | Op.TWLLT -> trapCond ins insLen (AST.lt) bld
  | Op.TWLLE -> trapCond ins insLen (AST.le) bld
  | Op.TWLNL -> trapCond ins insLen (AST.ge) bld
  | Op.TWLGT -> trapCond ins insLen (AST.gt) bld
  | Op.TWLTI -> trapCond ins insLen (AST.slt) bld
  | Op.TWLEI -> trapCond ins insLen (AST.sle) bld
  | Op.TWEQI -> trapCond ins insLen (AST.eq) bld
  | Op.TWGEI -> trapCond ins insLen (AST.sge) bld
  | Op.TWGTI -> trapCond ins insLen (AST.sgt) bld
  | Op.TWNEI -> trapCond ins insLen (AST.neq) bld
  | Op.TWLLTI -> trapCond ins insLen (AST.lt) bld
  | Op.TWLLEI -> trapCond ins insLen (AST.le) bld
  | Op.TWLNLI -> trapCond ins insLen (AST.ge) bld
  | Op.TWLGTI -> trapCond ins insLen (AST.gt) bld
  | Op.XOR -> xor ins insLen false bld
  | Op.XORdot -> xor ins insLen true bld
  | Op.XORI -> xori ins insLen bld
  | Op.XORIS -> xoris ins insLen bld
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException (Disasm.opCodeToString o)

// vim: set tw=80 sts=2 sw=2:

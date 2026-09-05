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

module internal B2R2.FrontEnd.PPC.Lifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.OperandHelper

let getOneOpr (ins: Instruction) =
  match ins.Operands with
  | OneOperand o -> o
  | _ -> raise InvalidOperandException

let getTwoOprs (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(o1, o2) -> struct (o1, o2)
  | _ -> raise InvalidOperandException

let getThreeOprs (ins: Instruction) =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) -> struct (o1, o2, o3)
  | _ -> raise InvalidOperandException

let getFourOprs (ins: Instruction) =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) -> struct (o1, o2, o3, o4)
  | _ -> raise InvalidOperandException

/// The register type of the given bit width, for the vector forms that halve or
/// double an element's width.
let regTypeOf (bits: int): RegType = LanguagePrimitives.Int32WithMeasure bits

let getExtMask mb me =
  let struct (mb, me) =
    match mb, me with
    | Num(b, _), Num(m, _) -> struct (int (b.ToUInt64()), int (m.ToUInt64()))
    | _ -> raise InvalidExprException
  let allOnes = System.UInt32.MaxValue
  let mask =
    if mb = me + 1 then
      allOnes
    elif me = 31 then
      allOnes >>> mb
    else
      let v = (allOnes >>> mb) ^^^ (allOnes >>> (me + 1))
      if mb > me then ~~~v else v
  numU32 mask 32<rt>

/// The 64-bit MASK(mb, me) of the rotate-doubleword forms: the ones run from
/// big-endian bit mb through me, wrapping when mb > me.
let getExtMask64 mb me =
  let struct (mb, me) =
    match mb, me with
    | Num(b, _), Num(m, _) -> struct (int (b.ToUInt64()), int (m.ToUInt64()))
    | _ -> raise InvalidExprException
  let allOnes = System.UInt64.MaxValue
  let mask =
    if mb = me + 1 then
      allOnes
    elif me = 63 then
      allOnes >>> mb
    else
      let v = (allOnes >>> mb) ^^^ (allOnes >>> (me + 1))
      if mb > me then ~~~v else v
  numU64 mask 64<rt>

let rotateLeft rs sh = (rs << sh) .| (rs >> ((numI32 32 32<rt>) .- sh))

/// ROTL64: rotates a doubleword left by sh, which must be in 0..63.
let rotateLeft64 rs sh = (rs << sh) .| (rs >> ((numI32 64 64<rt>) .- sh))

let loadNative (bld: ILowUIRBuilder) rt addr =
  match bld.Endianness with
  | Endian.Big -> AST.loadBE rt addr
  | Endian.Little -> AST.loadLE rt addr
  | _ -> raise InvalidEndianException

/// Operand of the form d(rA) where the EA is (rA|0) + d.
let transEAWithOffset opr (bld: ILowUIRBuilder) =
  match opr with
  | OprMem(d, Register.R0) -> numI32 d bld.RegType
  | OprMem(d, b) -> regVar bld b .+ numI32 d bld.RegType
  | _ -> raise InvalidOperandException

/// Operand of the form d(rA) where the EA is rA + d. rA is updated with EA.
let transEAWithOffsetForUpdate opr (bld: ILowUIRBuilder) =
  match opr with
  | OprMem(d, b) ->
    let rA = regVar bld b
    struct (rA .+ numI32 d bld.RegType, rA)
  | _ ->
    raise InvalidOperandException

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
  | _ ->
    raise InvalidOpcodeException

let transOpr (bld: ILowUIRBuilder) = function
  | OprReg reg ->
    regVar bld reg
  | OprMem(d, b) -> (* FIXME *)
    loadNative bld bld.RegType (regVar bld b .+ numI32 d bld.RegType)
  | OprImm imm ->
    numU64 imm bld.RegType
  | OprAddr addr ->
    numI64 (int64 addr) bld.RegType
  | OprBI bi ->
    getCRbitRegister bi |> regVar bld

let transOneOpr (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand o -> transOpr bld o
  | _ -> raise InvalidOperandException

let transTwoOprs (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(o1, o2) -> struct (transOpr bld o1, transOpr bld o2)
  | _ -> raise InvalidOperandException

let transThreeOprs (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(o1, o2, o3) ->
    struct (transOpr bld o1, transOpr bld o2, transOpr bld o3)
  | _ ->
    raise InvalidOperandException

let transFourOprs (ins: Instruction) bld =
  match ins.Operands with
  | FourOperands(o1, o2, o3, o4) ->
    struct (transOpr bld o1, transOpr bld o2, transOpr bld o3, transOpr bld o4)
  | _ ->
    raise InvalidOperandException

let transFiveOprs (ins: Instruction) bld =
  match ins.Operands with
  | FiveOperands(o1, o2, o3, o4, o5) ->
    let o1 = transOpr bld o1
    let o2 = transOpr bld o2
    let o3 = transOpr bld o3
    let o4 = transOpr bld o4
    let o5 = transOpr bld o5
    struct (o1, o2, o3, o4, o5)
  | _ ->
    raise InvalidOperandException

let transCRxToExpr bld reg =
  let rV = regVar bld
  match reg with
  | Register.CR0 ->
    rV Register.CR0_0, rV Register.CR0_1, rV Register.CR0_2, rV Register.CR0_3
  | Register.CR1 ->
    rV Register.CR1_0, rV Register.CR1_1, rV Register.CR1_2, rV Register.CR1_3
  | Register.CR2 ->
    rV Register.CR2_0, rV Register.CR2_1, rV Register.CR2_2, rV Register.CR2_3
  | Register.CR3 ->
    rV Register.CR3_0, rV Register.CR3_1, rV Register.CR3_2, rV Register.CR3_3
  | Register.CR4 ->
    rV Register.CR4_0, rV Register.CR4_1, rV Register.CR4_2, rV Register.CR4_3
  | Register.CR5 ->
    rV Register.CR5_0, rV Register.CR5_1, rV Register.CR5_2, rV Register.CR5_3
  | Register.CR6 ->
    rV Register.CR6_0, rV Register.CR6_1, rV Register.CR6_2, rV Register.CR6_3
  | Register.CR7 ->
    rV Register.CR7_0, rV Register.CR7_1, rV Register.CR7_2, rV Register.CR7_3
  | _ ->
    raise InvalidOperandException

let transCmpOprs (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg o1, o2, o3) ->
    struct (transCRxToExpr bld o1, transOpr bld o2, transOpr bld o3)
  | FourOperands(OprReg o1, _, o3, o4) ->
    struct (transCRxToExpr bld o1, transOpr bld o3, transOpr bld o4)
  | _ ->
    raise InvalidOperandException

let transCondOneOpr (ins: Instruction) bld =
  match ins.Operands with
  | OneOperand(OprReg o) -> transCRxToExpr bld o
  | _ -> raise InvalidOperandException

let transCondTwoOprs (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprReg o1, OprReg o2) ->
    struct (transCRxToExpr bld o1, transCRxToExpr bld o2)
  | _ ->
    raise InvalidOperandException

let transCondThreeOprs (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprReg o1, OprReg o2, OprReg o3) ->
    struct (transCRxToExpr bld o1, transCRxToExpr bld o2, transCRxToExpr bld o3)
  | _ ->
    raise InvalidOperandException

let transBranchTwoOprs (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprImm o1, OprBI o2) ->
    struct (uint32 o1, getCRbitRegister o2 |> regVar bld)
  | _ ->
    raise InvalidOperandException

let transBranchThreeOprs (ins: Instruction) bld =
  match ins.Operands with
  | ThreeOperands(OprImm o1, OprBI o2, OprAddr o3) ->
    let getCRbitRegister = getCRbitRegister o2 |> regVar bld
    struct (uint32 o1, getCRbitRegister, numI64 (int64 o3) bld.RegType)
  | _ ->
    raise InvalidOperandException

let getCRRegValue bld cr =
  append bld {
    cr := numI32 0 32<rt>
    for i in 0 .. 31 do
      let crbit = uint32 (31 - i) |> getCRbitRegister |> regVar bld
      AST.extract cr 1<rt> i := crbit
  }

let getImmValue = function
  | OprImm imm -> uint32 imm
  | OprBI imm -> imm
  | _ -> raise InvalidOperandException

let getSPRReg bld imm =
  match uint32 imm with
  | 1u -> regVar bld Register.XER
  | 8u -> regVar bld Register.LR
  | 9u -> regVar bld Register.CTR
  | 256u -> regVar bld Register.VRSAVE
  | 287u -> regVar bld Register.PVR
  | 18u | 19u | 22u | 25u | 26u | 27u | 272u | 273u | 274u | 275u | 282u | 528u
  | 529u | 530u | 531u | 532u | 533u | 534u | 535u | 536u | 537u | 538u | 539u
  | 540u | 541u | 542u | 543u | 1013u -> raise InvalidRegisterException
  | _ -> raise InvalidOperandException

let floatingNeg bld dst src rt =
  append bld {
    let sign = (AST.xthi 1<rt> src <+> (AST.b1))
    let tmp = tmpVar bld rt
    tmp := src
    AST.xthi 1<rt> tmp := sign
    dst := tmp
  }

let roundingToCastInt bld frd frb =
  append bld {
    let fpscr = regVar bld Register.FPSCR
    let rnA = AST.extract fpscr 1<rt> 1
    let rnB = AST.extract fpscr 1<rt> 0
    let lblRN0 = label bld "RN0x"
    let lblRN1 = label bld "RN1x"
    let lblEnd = label bld "End"
    AST.cjmp rnA (AST.jmpDest lblRN1) (AST.jmpDest lblRN0)
    AST.lmark lblRN0
    frd := AST.ite rnB
                   (AST.cast CastKind.FtoITrunc 64<rt> frb)
                   (AST.cast CastKind.FtoIRound 64<rt> frb)
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblRN1
    frd := AST.ite rnB
                   (AST.cast CastKind.FtoIFloor 64<rt> frb)
                   (AST.cast CastKind.FtoICeil 64<rt> frb)
    AST.lmark lblEnd
  }

let setCR0Reg (bld: ILowUIRBuilder) result =
  append bld {
    let zero = AST.num0 bld.RegType
    let xerSO = AST.xthi 1<rt> (regVar bld Register.XER)
    let cr0LT = regVar bld Register.CR0_0
    let cr0GT = regVar bld Register.CR0_1
    let cr0EQ = regVar bld Register.CR0_2
    let cr0SO = regVar bld Register.CR0_3
    cr0LT := result ?< zero
    cr0GT := result ?> zero
    cr0EQ := result == zero
    cr0SO := xerSO
  }

let setCR1Reg bld =
  append bld {
    let fpscr = regVar bld Register.FPSCR
    let cr1FX = regVar bld Register.CR1_0
    let cr1FEX = regVar bld Register.CR1_1
    let cr1VX = regVar bld Register.CR1_2
    let cr1OX = regVar bld Register.CR1_3
    cr1FX := AST.extract fpscr 1<rt> 31
    cr1FEX := AST.extract fpscr 1<rt> 30
    cr1VX := AST.extract fpscr 1<rt> 29
    cr1OX := AST.extract fpscr 1<rt> 28
  }

let isDenormailized frx =
  let exponent = (frx >> numI32 52 64<rt>) .& numI32 0x7FF 64<rt>
  let fraction = frx .& numU64 0xfffff_ffffffffUL 64<rt>
  let zero = AST.num0 64<rt>
  AST.xtlo 1<rt> ((exponent == zero) .& (fraction != zero))

let setFPRF bld result =
  append bld {
    let fpscr = regVar bld Register.FPSCR
    let c = AST.extract fpscr 1<rt> 16
    let fl = AST.extract fpscr 1<rt> 15
    let fg = AST.extract fpscr 1<rt> 14
    let fe = AST.extract fpscr 1<rt> 13
    let fu = AST.extract fpscr 1<rt> 12
    let nzero = numU64 0x8000000000000000UL 64<rt>
    c := IEEE754Double.isNaN result
       .| isDenormailized result
       .| AST.eq result nzero
    fl := AST.flt result (AST.num0 64<rt>)
    fg := AST.fgt result (AST.num0 64<rt>)
    fe := AST.eq (result << AST.num1 64<rt>) (AST.num0 64<rt>)
    fu := IEEE754Double.isNaN result .| IEEE754Double.isInfinity result
  }

let setCarryOut bld carry =
  append bld {
    let xerCA = AST.extract (regVar bld Register.XER) 1<rt> 29
    xerCA := carry
  }

/// The XER[CA] carry-in widened to a register-wide 0 or 1.
let carryIn (bld: ILowUIRBuilder) =
  AST.zext bld.RegType (AST.extract (regVar bld Register.XER) 1<rt> 29)

let setCRRegValue bld cr =
  append bld {
    for i in 0 .. 31 do
      let crbit = uint32 (31 - i) |> getCRbitRegister |> regVar bld
      crbit := AST.extract cr 1<rt> i
  }

/// Records an overflow in XER[OV]/XER[SO]: a signed add or subtract overflows
/// when both operands share a sign that the result does not. The operands are
/// register-wide, so taking their top bit covers either word size.
let isAddSubOV bld expA expB result =
  append bld {
    let struct (checkOF, t1, t2) = tmpVars3 bld 1<rt>
    let xerSO = AST.extract (regVar bld Register.XER) 1<rt> 31
    let xerOV = AST.extract (regVar bld Register.XER) 1<rt> 30
    t1 := AST.xthi 1<rt> expA
    t2 := AST.xthi 1<rt> result
    checkOF := (t1 == AST.xthi 1<rt> expB) .& (t1 <+> t2)
    xerOV := checkOF
    xerSO := checkOF .| xerSO
  }

/// Adds a + b + c (c a register-wide carry-in of 0 or 1) into dst, recording
/// the carry-out in XER[CA]. Each partial sum's unsigned wrap gives its carry,
/// so no intermediate wider than a register is needed.
let addWithCarryOut (bld: ILowUIRBuilder) dst a b c =
  let struct (t1, t2) = tmpVars2 bld bld.RegType
  let struct (c1, c2) = tmpVars2 bld 1<rt>
  append bld {
    t1 := a .+ b
    c1 := t1 .< a
    t2 := t1 .+ c
    c2 := t2 .< t1
    dst := t2
  }
  setCarryOut bld (c1 .| c2)

/// Records an overflow of mullw, whose 32-bit operands make a product that does
/// not fit a signed word.
let isMulwOV bld expA expB =
  append bld {
    let prod = tmpVar bld 64<rt>
    let checkOF = tmpVar bld 1<rt>
    let xerSO = AST.extract (regVar bld Register.XER) 1<rt> 31
    let xerOV = AST.extract (regVar bld Register.XER) 1<rt> 30
    let a = AST.sext 64<rt> (AST.xtlo 32<rt> expA)
    let b = AST.sext 64<rt> (AST.xtlo 32<rt> expB)
    prod := a .* b
    checkOF := prod != AST.sext 64<rt> (AST.xtlo 32<rt> prod)
    xerOV := checkOF
    xerSO := checkOF .| xerSO
  }

/// Records an overflow of mulld, whose doubleword product does not fit a signed
/// doubleword.
let isMuldOV bld expA expB =
  append bld {
    let prod = tmpVar bld 128<rt>
    let checkOF = tmpVar bld 1<rt>
    let xerSO = AST.extract (regVar bld Register.XER) 1<rt> 31
    let xerOV = AST.extract (regVar bld Register.XER) 1<rt> 30
    let a = AST.sext 128<rt> (AST.xtlo 64<rt> expA)
    let b = AST.sext 128<rt> (AST.xtlo 64<rt> expB)
    prod := a .* b
    checkOF := prod != AST.sext 128<rt> (AST.xtlo 64<rt> prod)
    xerOV := checkOF
    xerSO := checkOF .| xerSO
  }

/// Records an overflow of a signed divide of the given width: a zero divisor,
/// or the most negative dividend divided by -1.
let isSignedDivOV bld rt expA expB =
  append bld {
    let checkOF = tmpVar bld 1<rt>
    let minValue = AST.num1 rt << numI32 (int rt - 1) rt
    let xerSO = AST.extract (regVar bld Register.XER) 1<rt> 31
    let xerOV = AST.extract (regVar bld Register.XER) 1<rt> 30
    let dz = expB == AST.num0 rt
    let ovf = (expA == minValue) .& (expB == AST.not (AST.num0 rt))
    checkOF := dz .| ovf
    xerOV := checkOF
    xerSO := checkOF .| xerSO
  }

/// Records an overflow of an unsigned divide of the given width: a zero
/// divisor is the only case.
let isUnsignedDivOV bld rt expB =
  append bld {
    let checkOF = tmpVar bld 1<rt>
    let xerSO = AST.extract (regVar bld Register.XER) 1<rt> 31
    let xerOV = AST.extract (regVar bld Register.XER) 1<rt> 30
    checkOF := expB == AST.num0 rt
    xerOV := checkOF
    xerSO := checkOF .| xerSO
  }

let sideEffects (ins: Instruction) insLen bld name =
  lift bld ins insLen {
    AST.sideEffect name
  }

let add ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := src1
    t2 := src2
    dst := t1 .+ t2
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let addc ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := src1
    t2 := src2
    addWithCarryOut bld dst t1 t2 (AST.num0 bld.RegType)
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let adde ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := src1
    t2 := src2
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let addi ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, simm) = transThreeOprs ins bld
    let cond = src1 == AST.num0 bld.RegType
    dst := (AST.ite cond simm (src1 .+ simm))
  }

let addic ins insLen updateCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, simm) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := src1
    t2 := simm
    addWithCarryOut bld dst t1 t2 (AST.num0 bld.RegType)
    if updateCond then setCR0Reg bld dst else ()
  }

/// The 16-bit immediate of an addis/lis/oris/xoris shifted into the upper half
/// of a word and sign- or zero-extended to a register, as that form's shifted
/// operand.
let shiftedImm (bld: ILowUIRBuilder) signed simm =
  let hi = AST.concat (AST.xtlo 16<rt> simm) (AST.num0 16<rt>)
  if bld.RegType = 32<rt> then hi
  elif signed then AST.sext bld.RegType hi
  else AST.zext bld.RegType hi

let addis ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, simm) = transThreeOprs ins bld
    let cond = src1 == AST.num0 bld.RegType
    let simm = shiftedImm bld true simm
    dst := (AST.ite cond simm (src1 .+ simm))
  }

let addme ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := src
    t2 := AST.not (AST.num0 bld.RegType)
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let addze ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := src
    t2 := AST.num0 bld.RegType
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let andx ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := src1 .& src2
    if updateCond then setCR0Reg bld dst else ()
  }

let andc ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := src1 .& AST.not (src2)
    if updateCond then setCR0Reg bld dst else ()
  }

let andidot ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src, uimm) = transThreeOprs ins bld
    dst := src .& uimm
    setCR0Reg bld dst
  }

let andisdot ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src, uimm) = transThreeOprs ins bld
    let uimm = shiftedImm bld false uimm
    dst := src .& uimm
    setCR0Reg bld dst
  }

let b ins insLen (bld: ILowUIRBuilder) lk =
  lift bld ins insLen {
    let addr = transOneOpr ins bld
    let lr = regVar bld Register.LR
    if lk then
      lr := numU64 (ins.Address + 4UL) bld.RegType
      AST.interjmp addr InterJmpKind.IsCall
    else
      AST.interjmp addr InterJmpKind.Base
  }

let bc ins insLen (bld: ILowUIRBuilder) aa lk =
  lift bld ins insLen {
    let struct (bo, cr, addr) = transBranchThreeOprs ins bld
    let rt = bld.RegType
    let lr = regVar bld Register.LR
    let ctr = regVar bld Register.CTR
    let bo0 = numU32 ((bo >>> 4) &&& 1u) 1<rt>
    let bo1 = numU32 ((bo >>> 3) &&& 1u) 1<rt>
    let bo2 = numU32 ((bo >>> 2) &&& 1u) 1<rt>
    let bo3 = numU32 ((bo >>> 1) &&& 1u) 1<rt>
    let ctrOk = tmpVar bld 1<rt>
    let condOk = tmpVar bld 1<rt>
    let cia = numU64 ins.Address rt
    let nia = numU64 (ins.Address + 4UL) rt
    let temp = tmpVar bld rt
    if lk then append bld { lr := nia } else ()
    ctr :=
            if ((bo >>> 2) &&& 1u = 1u) then ctr else (ctr .- AST.num1 rt)
    ctrOk := bo2 .| ((ctr != AST.num0 rt) <+> bo3)
    condOk := bo0 .| (cr <+> AST.not bo1)
    if aa then append bld { temp := AST.ite (ctrOk .& condOk) addr nia }
    else append bld { temp := AST.ite (ctrOk .& condOk) (cia .+ addr) nia }
    let kind = if lk then InterJmpKind.IsCall else InterJmpKind.Base
    AST.interjmp temp kind
  }

/// The low two bits an indirect branch clears out of LR or CTR before jumping.
let private branchTargetMask (bld: ILowUIRBuilder) =
  AST.not (numI32 3 bld.RegType)

let bclr ins insLen (bld: ILowUIRBuilder) lk =
  lift bld ins insLen {
    let struct (bo, cr) = transBranchTwoOprs ins bld
    let rt = bld.RegType
    let lr = regVar bld Register.LR
    let ctr = regVar bld Register.CTR
    let bo0 = numU32 ((bo >>> 4) &&& 1u) 1<rt>
    let bo1 = numU32 ((bo >>> 3) &&& 1u) 1<rt>
    let bo2 = numU32 ((bo >>> 2) &&& 1u) 1<rt>
    let bo3 = numU32 ((bo >>> 1) &&& 1u) 1<rt>
    let ctrOk = tmpVar bld 1<rt>
    let condOk = tmpVar bld 1<rt>
    let nia = numU64 (ins.Address + 4UL) rt
    let temp = tmpVar bld rt
    ctr :=
            if ((bo >>> 2) &&& 1u = 1u) then ctr else (ctr .- AST.num1 rt)
    ctrOk := bo2 .| ((ctr != AST.num0 rt) <+> bo3)
    condOk := bo0 .| (cr <+> AST.not bo1)
    temp := AST.ite (ctrOk .& condOk) (lr .& branchTargetMask bld) nia
    if lk then append bld { lr := AST.ite (ctrOk .& condOk) nia lr } else ()
    let kind = if lk then InterJmpKind.IsCall else InterJmpKind.IsRet
    AST.interjmp temp kind
  }

let bcctr ins insLen (bld: ILowUIRBuilder) lk =
  lift bld ins insLen {
    let struct (bo, cr) = transBranchTwoOprs ins bld
    let rt = bld.RegType
    let lr = regVar bld Register.LR
    let ctr = regVar bld Register.CTR
    let bo0 = numU32 ((bo >>> 4) &&& 1u) 1<rt>
    let bo1 = numU32 ((bo >>> 3) &&& 1u) 1<rt>
    let condOk = tmpVar bld 1<rt>
    let nia = numU64 (ins.Address + 4UL) rt
    let temp = tmpVar bld rt
    condOk := bo0 .| (cr <+> AST.not bo1)
    temp := AST.ite condOk (ctr .& branchTargetMask bld) nia
    if lk then append bld { lr := AST.ite condOk nia lr } else ()
    let kind = if lk then InterJmpKind.IsCall else InterJmpKind.Base
    AST.interjmp temp kind
  }

/// Records the outcome of a comparison in a CR field. cmpOp gives the "less
/// than" and "greater than" tests, which differ between the signed and the
/// unsigned forms; equality is whatever neither of those is.
let private compare ins insLen bld ltOp gtOp narrow =
  lift bld ins insLen {
    let struct ((crf0, crf1, crf2, crf3), ra, rb) = transCmpOprs ins bld
    let ra, rb =
      if narrow then AST.xtlo 32<rt> ra, AST.xtlo 32<rt> rb else ra, rb
    let cond1 = ltOp ra rb
    let cond2 = gtOp ra rb
    let xer = regVar bld Register.XER
    crf0 := cond1
    crf1 := cond2
    crf2 := AST.ite cond1 AST.b0 (AST.not cond2)
    crf3 := AST.xthi 1<rt> xer
  }

/// A signed compare of the given width: cmpw/cmpwi narrow to a word, cmpd and
/// cmpdi take the whole register.
let cmp ins insLen bld narrow = compare ins insLen bld AST.slt AST.sgt narrow

/// An unsigned compare, narrowing as cmp does.
let cmpl ins insLen bld narrow = compare ins insLen bld AST.lt AST.gt narrow

/// Counts the leading zeroes of the low `width` bits of rs, by folding the
/// value down to a mask of the bits at or below the highest set one and then
/// counting the ones in it. The result is a register-wide count.
let private countLeadingZeros (bld: ILowUIRBuilder) ra rs width =
  append bld {
    let rt = bld.RegType
    let x = tmpVar bld width
    let n i = numI32 i width
    let mask1 = numU64 0x5555555555555555UL width
    let mask2 = numU64 0x3333333333333333UL width
    let mask3 = numU64 0x0f0f0f0f0f0f0f0fUL width
    x := AST.xtlo width rs
    x := x .| (x >> n 1)
    x := x .| (x >> n 2)
    x := x .| (x >> n 4)
    x := x .| (x >> n 8)
    x := x .| (x >> n 16)
    if width = 64<rt> then append bld { x := x .| (x >> n 32) } else ()
    x := x .- ((x >> n 1) .& mask1)
    x := ((x >> n 2) .& mask2) .+ (x .& mask2)
    x := ((x >> n 4) .+ x) .& mask3
    x := x .+ (x >> n 8)
    x := x .+ (x >> n 16)
    if width = 64<rt> then append bld { x := x .+ (x >> n 32) } else ()
    let ones = AST.zext rt (x .& n 127)
    ra := numI32 (int width) rt .- ones
  }

let cntlzw ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs) = transTwoOprs ins bld
    countLeadingZeros bld ra rs 32<rt>
    if updateCond then setCR0Reg bld ra else ()
  }

let cntlzd ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs) = transTwoOprs ins bld
    countLeadingZeros bld ra rs 64<rt>
    if updateCond then setCR0Reg bld ra else ()
  }

let crclr ins insLen bld =
  lift bld ins insLen {
    let crbd = transOneOpr ins bld
    crbd := AST.b0
  }

let cror ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA .| crbB
  }

let crorc ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA .| (AST.not crbB)
  }

let creqv ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA <+> AST.not (crbB)
  }

let crset ins insLen bld =
  lift bld ins insLen {
    let crbD = transOneOpr ins bld
    crbD := crbD <+> AST.not (crbD)
  }

let crnand ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := AST.not (crbA .& crbB)
  }

let crnor ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := AST.not (crbA .| crbB)
  }

let crnot ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA) = transTwoOprs ins bld
    crbD := AST.not crbA
  }

let crxor ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA <+> crbB
  }

let crand ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA .& crbB
  }

let crandc ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA, crbB) = transThreeOprs ins bld
    crbD := crbA .& (AST.not crbB)
  }

(* crmove crbD, crbA = cror crbD, crbA, crbA: copies one CR bit to another. *)
let crmove ins insLen bld =
  lift bld ins insLen {
    let struct (crbD, crbA) = transTwoOprs ins bld
    crbD := crbA
  }

/// A divide of the given width. A zero divisor (and the signed overflow case)
/// leaves the destination alone, as the architecture leaves it undefined.
let private divide ins
                   insLen
                   updateCond
                   ovCond
                   (bld: ILowUIRBuilder)
                   width
                   signed =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let a = AST.xtlo width src1
    let b = AST.xtlo width src2
    if ovCond && signed then isSignedDivOV bld width a b
    elif ovCond then isUnsignedDivOV bld width b
    else ()
    let q = if signed then a ?/ b else a ./ b
    let q = if signed then AST.sext bld.RegType q else AST.zext bld.RegType q
    dst := AST.ite (b == AST.num0 width) dst q
    if updateCond then setCR0Reg bld dst else ()
  }

let divw ins insLen updateCond ovCond bld =
  divide ins insLen updateCond ovCond bld 32<rt> true

let divwu ins insLen updateCond ovCond bld =
  divide ins insLen updateCond ovCond bld 32<rt> false

let divd ins insLen updateCond ovCond bld =
  divide ins insLen updateCond ovCond bld 64<rt> true

let divdu ins insLen updateCond ovCond bld =
  divide ins insLen updateCond ovCond bld 64<rt> false

/// Sign-extends the low `width` bits of rs into a whole register.
let private signExtend ins insLen updateCond (bld: ILowUIRBuilder) width =
  lift bld ins insLen {
    let struct (ra, rs) = transTwoOprs ins bld
    let tmp = tmpVar bld width
    tmp := AST.xtlo width rs
    ra := AST.sext bld.RegType tmp
    if updateCond then setCR0Reg bld ra else ()
  }

let extsb ins insLen updateCond bld = signExtend ins insLen updateCond bld 8<rt>

let extsh ins insLen updateCond bld =
  signExtend ins insLen updateCond bld 16<rt>

let extsw ins insLen updateCond bld =
  signExtend ins insLen updateCond bld 32<rt>

let eqvx ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs, rb) = transThreeOprs ins bld
    ra := AST.not (rs <+> rb)
    if updateCond then setCR0Reg bld ra else ()
  }

let fabs ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (frd, frb) = transTwoOprs ins bld
    frd := frb .& numU64 0x7fffffffffffffffUL 64<rt>
    if updateCond then setCR1Reg bld else ()
  }

let fAddOrSub ins insLen updateCond isDouble fnOp bld =
  lift bld ins insLen {
    let struct (frd, fra, frb) = transThreeOprs ins bld
    if isDouble then
      frd := fnOp fra frb
    else
      let fra = AST.cast CastKind.FloatCast 32<rt> fra
      let frb = AST.cast CastKind.FloatCast 32<rt> frb
      frd := AST.cast CastKind.FloatCast 64<rt> (fnOp fra frb)
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let fadd ins insLen updateCond isDouble bld =
  fAddOrSub ins insLen updateCond isDouble AST.fadd bld

let fcmp ins insLen bld isOrdered =
  lift bld ins insLen {
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
    fl := cond1
    fg := cond2
    fe := AST.ite cond1 AST.b0 (AST.not cond2)
    nanFlag := (IEEE754Double.isNaN fra) .| (IEEE754Double.isNaN frb)
    fu := nanFlag
    AST.cjmp nanFlag (AST.jmpDest lblNan) (AST.jmpDest lblRegular)
    AST.lmark lblNan
    crf0 := AST.b0
    crf1 := AST.b0
    crf2 := AST.b0
    crf3 := AST.b1
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblRegular
    crf0 := fl
    crf1 := fg
    crf2 := fe
    crf3 := fu
    AST.lmark lblEnd
    vxsnan := cond3
    if isOrdered then
      vxvc := AST.ite cond3 (AST.ite ve AST.b0 AST.b1) cond4
    else
      ()
  }

let fcmpo ins insLen bld = fcmp ins insLen bld true

let fcmpu ins insLen bld = fcmp ins insLen bld false

let fdiv ins insLen updateCond isDouble bld =
  lift bld ins insLen {
    let struct (frd, fra, frb) = transThreeOprs ins bld
    let tmp = tmpVar bld 32<rt>
    if isDouble then
      frd := AST.fdiv fra frb
    else
      let fraS = AST.cast CastKind.FloatCast 32<rt> fra
      let frbS = AST.cast CastKind.FloatCast 32<rt> frb
      tmp := AST.fdiv fraS frbS
      frd := AST.cast CastKind.FloatCast 64<rt> tmp
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let frsp ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (frd, frb) = transTwoOprs ins bld
    let single = AST.cast CastKind.FloatCast 32<rt> frb
    frd := AST.cast CastKind.FloatCast 64<rt> single
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let fsub ins insLen updateCond isDouble bld =
  fAddOrSub ins insLen updateCond isDouble AST.fsub bld

let fsqrt ins insLen updateCond isDouble bld =
  lift bld ins insLen {
    let struct (frd, frb) = transTwoOprs ins bld
    let tmp = tmpVar bld 32<rt>
    if isDouble then
      frd := AST.fsqrt frb
    else
      let frbS = AST.cast CastKind.FloatCast 32<rt> frb
      tmp := AST.fsqrt frbS
      frd := AST.cast CastKind.FloatCast 64<rt> tmp
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let fctiw ins insLen updateCond bld =
  lift bld ins insLen {
    let tmp = tmpVar bld 64<rt>
    let struct (frd, frb) = transTwoOprs ins bld
    roundingToCastInt bld frd frb
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let fctiwz ins insLen updateCond bld =
  lift bld ins insLen {
    let intMaxInFloat = numU64 0x41dfffffffc00000uL 64<rt>
    let intMinInFloat = numU64 0xc1e0000000000000uL 64<rt>
    let intMax = numU64 0x7fffffffUL 64<rt>
    let intMin = numU64 0x80000000UL 64<rt>
    let struct (frd, frb) = transTwoOprs ins bld
    frd := AST.cast CastKind.FtoITrunc 64<rt> frb
    frd := AST.ite (IEEE754Double.isNaN frb) intMin frd
    frd := AST.ite (AST.fle frb intMinInFloat) intMin frd
    frd := AST.ite (AST.fge frb intMaxInFloat) intMax frd
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let fmadd ins insLen updateCond isDouble bld =
  lift bld ins insLen {
    let struct (frd, fra, frc, frb) = transFourOprs ins bld
    let tmp = tmpVar bld 32<rt>
    if isDouble then
      frd := AST.fadd (AST.fmul fra frc) frb
    else
      let fraS = AST.cast CastKind.FloatCast 32<rt> fra
      let frbS = AST.cast CastKind.FloatCast 32<rt> frb
      let frcS = AST.cast CastKind.FloatCast 32<rt> frc
      tmp := AST.fadd (AST.fmul fraS frcS) frbS
      frd := AST.cast CastKind.FloatCast 64<rt> tmp
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let fmr ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs ins bld
    dst := src
    if updateCond then setCR1Reg bld else ()
  }

let fmsub ins insLen updateCond isDouble bld =
  lift bld ins insLen {
    let struct (frd, fra, frc, frb) = transFourOprs ins bld
    let tmp = tmpVar bld 32<rt>
    if isDouble then
      frd := AST.fsub (AST.fmul fra frc) frb
    else
      let fraS = AST.cast CastKind.FloatCast 32<rt> fra
      let frbS = AST.cast CastKind.FloatCast 32<rt> frb
      let frcS = AST.cast CastKind.FloatCast 32<rt> frc
      tmp := AST.fsub (AST.fmul fraS frcS) frbS
      frd := AST.cast CastKind.FloatCast 64<rt> tmp
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let fmul ins insLen updateCond isDouble bld =
  lift bld ins insLen {
    let struct (frd, fra, frb) = transThreeOprs ins bld
    let tmp = tmpVar bld 32<rt>
    if isDouble then
      frd := AST.fmul fra frb
    else
      let fraS = AST.cast CastKind.FloatCast 32<rt> fra
      let frbS = AST.cast CastKind.FloatCast 32<rt> frb
      tmp := AST.fmul fraS frbS
      frd := AST.cast CastKind.FloatCast 64<rt> tmp
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

let fnabs ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (frd, frb) = transTwoOprs ins bld
    frd := frb .| numU64 0x8000000000000000UL 64<rt>
    if updateCond then setCR1Reg bld else ()
  }

let fneg ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (frd, frb) = transTwoOprs ins bld
    floatingNeg bld frd frb 64<rt>
    if updateCond then setCR1Reg bld else ()
  }

let fnmadd ins insLen updateCond isDouble bld =
  lift bld ins insLen {
    let struct (frd, fra, frc, frb) = transFourOprs ins bld
    if isDouble then
      let res = tmpVar bld 64<rt>
      res := (AST.fadd (AST.fmul fra frc) frb)
      floatingNeg bld frd res 64<rt>
    else
      let res = tmpVar bld 32<rt>
      let nres = tmpVar bld 32<rt>
      let fraS = AST.cast CastKind.FloatCast 32<rt> fra
      let frcS = AST.cast CastKind.FloatCast 32<rt> frc
      let frbS = AST.cast CastKind.FloatCast 32<rt> frb
      res := (AST.fadd (AST.fmul fraS frcS) frbS)
      floatingNeg bld nres res 32<rt>
      frd := AST.cast CastKind.FloatCast 64<rt> nres
    if updateCond then setCR1Reg bld else ()
  }

let fnmsub ins insLen updateCond isDouble bld =
  lift bld ins insLen {
    let struct (frd, fra, frc, frb) = transFourOprs ins bld
    if isDouble then
      let res = tmpVar bld 64<rt>
      res := (AST.fsub (AST.fmul fra frc) frb)
      floatingNeg bld frd res 64<rt>
    else
      let res = tmpVar bld 32<rt>
      let nres = tmpVar bld 32<rt>
      let fraS = AST.cast CastKind.FloatCast 32<rt> fra
      let frcS = AST.cast CastKind.FloatCast 32<rt> frc
      let frbS = AST.cast CastKind.FloatCast 32<rt> frb
      res := (AST.fsub (AST.fmul fraS frcS) frbS)
      floatingNeg bld nres res 32<rt>
      frd := AST.cast CastKind.FloatCast 64<rt> nres
    if updateCond then setCR1Reg bld else ()
  }

let fsel ins insLen updateCond bld =
  lift bld ins insLen {
    let struct(frd, fra, frc, frb) = transFourOprs ins bld
    let cond = AST.fge fra (AST.num0 64<rt>)
    frd := AST.ite cond frc frb
    if updateCond then setCR1Reg bld else ()
  }

let lbz ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let dst = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    dst := AST.zext bld.RegType (loadNative bld 8<rt> tmpEA)
  }

let lbzu ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let rd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 8<rt> tmpEA)
    ra := tmpEA
  }

let lbzux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 8<rt> tmpEA)
    ra := tmpEA
  }

let lbzx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 8<rt> tmpEA)
  }

let lfd ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let dst = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    dst := loadNative bld 64<rt> tmpEA
  }

let lfdu ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let dst = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    dst := loadNative bld 64<rt> tmpEA
    ra := tmpEA
  }

let lfdux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let dst = transOpr bld o1
    let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    dst := loadNative bld 64<rt> tmpEA
    ra := tmpEA
  }

let lfdx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let dst = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    dst := loadNative bld 64<rt> tmpEA
  }

let lfs ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let dst = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    let v = loadNative bld 32<rt> tmpEA
    tmpEA := ea
    dst := AST.cast CastKind.FloatCast 64<rt> v
  }

let lfsu ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let frd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    let v = loadNative bld 32<rt> tmpEA
    tmpEA := ea
    frd := AST.cast CastKind.FloatCast 64<rt> v
    ra := tmpEA
  }

let lfsux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let frd = transOpr bld o1
    let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    let v = loadNative bld 32<rt> tmpEA
    tmpEA := ea
    frd := AST.cast CastKind.FloatCast 64<rt> v
    ra := tmpEA
  }

let lfsx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let frd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    let v = loadNative bld 32<rt> tmpEA
    tmpEA := ea
    frd := AST.cast CastKind.FloatCast 64<rt> v
  }

let lha ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let rd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.sext bld.RegType (loadNative bld 16<rt> tmpEA)
  }

let lhau ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let rd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.sext bld.RegType (loadNative bld 16<rt> tmpEA)
    ra := tmpEA
  }

let lhaux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.sext bld.RegType (loadNative bld 16<rt> tmpEA)
    ra := tmpEA
  }

let lhax ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.sext bld.RegType (loadNative bld 16<rt> tmpEA)
  }

let lhbrx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    let tmpMem = tmpVar bld 16<rt>
    let revtmp = tmpVar bld 16<rt>
    tmpEA := ea
    tmpMem := loadNative bld 16<rt> tmpEA
    AST.xthi 8<rt> revtmp := AST.xtlo 8<rt> tmpMem
    AST.xtlo 8<rt> revtmp := AST.xthi 8<rt> tmpMem
    rd := AST.zext bld.RegType revtmp
  }

let lhz ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let rd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 16<rt> tmpEA)
  }

let lhzu ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let rd = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 16<rt> tmpEA)
    ra := ea
  }

let lhzux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 16<rt> tmpEA)
    rA := tmpEA
  }

let lhzx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    rd := AST.zext bld.RegType (loadNative bld 16<rt> tmpEA)
  }

let li ins insLen bld =
  lift bld ins insLen {
    let struct (dst, simm) = transTwoOprs ins bld
    dst := simm
  }

let lis ins insLen bld =
  lift bld ins insLen {
    let struct (dst, simm) = transTwoOprs ins bld
    let simm = shiftedImm bld true simm
    dst := simm
  }

/// lwarx/ldarx: a load that arms the reservation a following store-conditional
/// checks. The reserved value is kept register-wide whatever the access size.
let private loadReserve ins insLen (bld: ILowUIRBuilder) size =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    let tmpVal = tmpVar bld bld.RegType
    tmpEA := ea
    tmpVal := AST.zext bld.RegType (loadNative bld size tmpEA)
    regVar bld Register.ExMonAddr := tmpEA
    regVar bld Register.ExMonVal := tmpVal
    rd := tmpVal
  }

let lwarx ins insLen bld = loadReserve ins insLen bld 32<rt>

let ldarx ins insLen bld = loadReserve ins insLen bld 64<rt>

let lbarx ins insLen bld = loadReserve ins insLen bld 8<rt>

let lharx ins insLen bld = loadReserve ins insLen bld 16<rt>

/// The bytes of a value of the given width, in reverse order. revConcat places
/// the array's first element in the result's least significant byte, so taking
/// the value's most significant byte first is what turns the order around.
let private reversedBytes value width =
  let n = int width / 8
  Array.init n (fun i -> AST.extract value 8<rt> ((n - 1 - i) * 8))
  |> AST.revConcat

/// lwbrx/ldbrx: a load whose bytes come back in the opposite order.
let private loadByteReverse ins insLen (bld: ILowUIRBuilder) size =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rd = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    let tmpMem = tmpVar bld size
    tmpEA := ea
    tmpMem := loadNative bld size tmpEA
    rd := AST.zext bld.RegType (reversedBytes tmpMem size)
  }

let lwbrx ins insLen bld = loadByteReverse ins insLen bld 32<rt>

let ldbrx ins insLen bld = loadByteReverse ins insLen bld 64<rt>

/// A d(rA) load of `size` bits, widened into rD by ext; when update is set the
/// effective address is also written back to rA.
let private loadOffset ins insLen (bld: ILowUIRBuilder) size ext update =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let dst = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    if update then
      let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
      tmpEA := ea
      dst := ext bld.RegType (loadNative bld size tmpEA)
      ra := tmpEA
    else
      tmpEA := transEAWithOffset o2 bld
      dst := ext bld.RegType (loadNative bld size tmpEA)
  }

/// An rA + rB load of `size` bits, widened into rD by ext, updating rA when
/// update is set.
let private loadIndexed ins insLen (bld: ILowUIRBuilder) size ext update =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let dst = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    if update then
      let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
      tmpEA := ea
      dst := ext bld.RegType (loadNative bld size tmpEA)
      ra := tmpEA
    else
      tmpEA := transEAWithIndexReg o2 o3 bld
      dst := ext bld.RegType (loadNative bld size tmpEA)
  }

let lwz ins insLen bld = loadOffset ins insLen bld 32<rt> AST.zext false

let lwzu ins insLen bld = loadOffset ins insLen bld 32<rt> AST.zext true

let lwzux ins insLen bld = loadIndexed ins insLen bld 32<rt> AST.zext true

let lwzx ins insLen bld = loadIndexed ins insLen bld 32<rt> AST.zext false

let lwa ins insLen bld = loadOffset ins insLen bld 32<rt> AST.sext false

let lwax ins insLen bld = loadIndexed ins insLen bld 32<rt> AST.sext false

let lwaux ins insLen bld = loadIndexed ins insLen bld 32<rt> AST.sext true

let ld ins insLen bld = loadOffset ins insLen bld 64<rt> AST.zext false

let ldu ins insLen bld = loadOffset ins insLen bld 64<rt> AST.zext true

let ldx ins insLen bld = loadIndexed ins insLen bld 64<rt> AST.zext false

let ldux ins insLen bld = loadIndexed ins insLen bld 64<rt> AST.zext true

let mcrf ins insLen bld =
  lift bld ins insLen {
    let struct ((crd0, crd1, crd2, crd3),
                (crs0, crs1, crs2, crs3)) = transCondTwoOprs ins bld
    crd0 := crs0
    crd1 := crs1
    crd2 := crs2
    crd3 := crs3
  }

let mcrxr ins insLen bld =
  lift bld ins insLen {
    let crd0, crd1, crd2, crd3 = transCondOneOpr ins bld
    let xer = regVar bld Register.XER
    crd0 := AST.extract xer 1<rt> 31
    crd1 := AST.extract xer 1<rt> 30
    crd2 := AST.extract xer 1<rt> 29
    crd3 := AST.extract xer 1<rt> 28
    xer := xer .& numI32 0x0fffffff 32<rt>
  }

let mfcr ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let dst = transOneOpr ins bld
    let cr = tmpVar bld 32<rt>
    getCRRegValue bld cr
    dst := AST.zext bld.RegType cr
  }

let mfctr ins insLen bld =
  lift bld ins insLen {
    let dst = transOneOpr ins bld
    let ctr = regVar bld Register.CTR
    dst := ctr
  }

let mffs ins insLen bld =
  lift bld ins insLen {
    let dst = transOneOpr ins bld
    let fpscr = regVar bld Register.FPSCR
    dst := AST.zext 64<rt> fpscr
  }

let mflr ins insLen bld =
  lift bld ins insLen {
    let dst = transOneOpr ins bld
    let lr = regVar bld Register.LR
    dst := lr
  }

let mfspr (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (dst, spr) =
      match ins.Operands with
      | TwoOperands(o1, OprImm o2) -> transOpr bld o1, getSPRReg bld o2
      | _ -> raise InvalidOperandException
    dst := spr
  }

(* mftb/mftbu read the 64-bit Time Base into rD. There is no real time base to
   read, so the value is left to the emulator via a ClockCounterRead side effect
   carrying the destination register and which 32-bit half (lower for mftb,
   upper for mftbu). *)
let mftb (ins: Instruction) insLen bld =
  let rid =
    match ins.Operands with
    | TwoOperands(OprReg rd, _) -> Register.toRegID rd
    | _ -> raise InvalidOperandException
  sideEffects ins insLen bld (ClockCounterRead(Some(rid, false)))

let mftbu (ins: Instruction) insLen bld =
  let rid =
    match ins.Operands with
    | OneOperand(OprReg rd) -> Register.toRegID rd
    | _ -> raise InvalidOperandException
  sideEffects ins insLen bld (ClockCounterRead(Some(rid, true)))

let mfxer ins insLen bld =
  lift bld ins insLen {
    let dst = transOneOpr ins bld
    let xer = regVar bld Register.XER
    dst := xer
  }

let mr ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs ins bld
    dst := src .| src
  }

let mtctr ins insLen bld =
  lift bld ins insLen {
    let src = transOneOpr ins bld
    let ctr = regVar bld Register.CTR
    ctr := src
  }

let mtfsfi ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (crfd, imm) = getTwoOprs ins
    let crfd = crfd |> getImmValue |> int
    let pos = 4 * (7 - crfd)
    let imm = transOpr bld imm
    let fpscr = regVar bld Register.FPSCR
    if crfd = 0 then
      AST.extract fpscr 1<rt> 31 := AST.extract imm 1<rt> 3
      AST.extract fpscr 1<rt> 28 := AST.extract imm 1<rt> 0
    else
      AST.extract fpscr 1<rt> (pos + 3) := AST.extract imm 1<rt> 3
      AST.extract fpscr 1<rt> (pos + 2) := AST.extract imm 1<rt> 2
      AST.extract fpscr 1<rt> (pos + 1) := AST.extract imm 1<rt> 1
      AST.extract fpscr 1<rt> pos := AST.extract imm 1<rt> 0
  }

let mtspr (ins: Instruction) insLen bld =
  lift bld ins insLen {
    let struct (spr, rs) =
      match ins.Operands with
      | TwoOperands(OprImm o1, o2) -> getSPRReg bld o1, transOpr bld o2
      | _ -> raise InvalidOperandException
    spr := rs
  }

let private crmMask bld crm =
  let tCrm = Array.init 4 (fun _ -> tmpVar bld 8<rt>)
  for i in 0..3 do
    let cond1 = AST.extract crm 1<rt> (i * 2)
    let cond2 = AST.extract crm 1<rt> (i * 2 + 1)
    append bld {
      tCrm[i] :=
        AST.ite cond1
                (AST.ite cond2 (numI32 0xff 8<rt>) (numI32 0xf 8<rt>))
                (AST.ite cond2 (numI32 0xf0 8<rt>) (AST.num0 8<rt>))
    }
  tCrm |> AST.revConcat

let mtcrf ins insLen bld =
  lift bld ins insLen {
    let struct (crm, rs) = transTwoOprs ins bld
    let mask = tmpVar bld 32<rt>
    let cr = tmpVar bld 32<rt>
    mask := crmMask bld crm
    getCRRegValue bld cr
    cr := (AST.xtlo 32<rt> rs .& mask) .| (cr .& AST.not mask)
    setCRRegValue bld cr
  }

let mtlr ins insLen bld =
  lift bld ins insLen {
    let src = transOneOpr ins bld
    let lr = regVar bld Register.LR
    lr := src
  }

let mtfsb0 ins insLen updateCond bld =
  lift bld ins insLen {
    let crbD = getOneOpr ins |> getImmValue |> int
    let fpscr = regVar bld Register.FPSCR
    if crbD <> 1 && crbD <> 2 then
      AST.extract fpscr 1<rt> (31 - crbD) := AST.b0
    else
      ()
    if updateCond then setCR1Reg bld else ()
    (* Affected: FX *)
  }

let mtfsb1 ins insLen updateCond bld =
  lift bld ins insLen {
    let crbD = getOneOpr ins |> getImmValue |> int
    let fpscr = regVar bld Register.FPSCR
    if crbD <> 1 && crbD <> 2 then
      AST.extract fpscr 1<rt> (31 - crbD) := AST.b1
    else
      ()
    if updateCond then setCR1Reg bld else ()
    (* Affected: FX *)
  }

let mtfsf ins insLen bld =
  lift bld ins insLen {
    let struct (fm, frB) = getTwoOprs ins
    let frB = transOpr bld frB
    let fm = BitVector(getImmValue fm, 32<rt>) |> AST.num
    let fpscr = regVar bld Register.FPSCR
    let mask = tmpVar bld 32<rt>
    mask := crmMask bld fm
    fpscr := (AST.xtlo 32<rt> frB .& mask) .| (fpscr .& AST.not mask)
  }

let mtxer ins insLen bld =
  lift bld ins insLen {
    let src = transOneOpr ins bld
    let xer = regVar bld Register.XER
    xer := src
  }

/// The high half of a product of two `width`-bit operands, taken in a double-
/// width temporary and placed in a whole register. A 64-bit guest leaves the
/// upper half of a mulhw's result undefined, so widening it either way is
/// allowed; sign- or zero-extending matches the operands' signedness.
let private mulHigh ins
                    insLen
                    updateCond
                    (bld: ILowUIRBuilder)
                    (width: RegType)
                    signed =
  lift bld ins insLen {
    let struct (dst, ra, rb) = transThreeOprs ins bld
    let wide = width + width
    let tmp = tmpVar bld wide
    let ext e = if signed then AST.sext wide e else AST.zext wide e
    tmp := ext (AST.xtlo width ra) .* ext (AST.xtlo width rb)
    let hi = AST.xthi width tmp
    dst := if signed then AST.sext bld.RegType hi
           else AST.zext bld.RegType hi
    if updateCond then setCR0Reg bld dst else ()
  }

let mulhw ins insLen updateCond bld =
  mulHigh ins insLen updateCond bld 32<rt> true

let mulhwu ins insLen updateCond bld =
  mulHigh ins insLen updateCond bld 32<rt> false

let mulhd ins insLen updateCond bld =
  mulHigh ins insLen updateCond bld 64<rt> true

let mulhdu ins insLen updateCond bld =
  mulHigh ins insLen updateCond bld 64<rt> false

let mulli ins insLen bld =
  lift bld ins insLen {
    let struct (dst, ra, simm) = transThreeOprs ins bld
    dst := ra .* simm
  }

/// mullw takes two word operands and, on a 64-bit part, keeps the whole
/// doubleword product; on a 32-bit one only the low word exists.
let mullw ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let tmp = tmpVar bld 64<rt>
    if ovCond then isMulwOV bld src1 src2 else ()
    let a = AST.sext 64<rt> (AST.xtlo 32<rt> src1)
    let b = AST.sext 64<rt> (AST.xtlo 32<rt> src2)
    tmp := a .* b
    dst := AST.xtlo bld.RegType tmp
    if updateCond then setCR0Reg bld dst else ()
  }

let mulld ins insLen updateCond ovCond bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    if ovCond then isMuldOV bld src1 src2 else ()
    dst := src1 .* src2
    if updateCond then setCR0Reg bld dst else ()
  }

let nand ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := AST.not (src1 .& src2)
    if updateCond then setCR0Reg bld dst else ()
  }

let neg ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := AST.not src
    t2 := AST.num1 bld.RegType
    dst := t1 .+ t2
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let nor ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := AST.not (src1 .| src2)
    if updateCond then setCR0Reg bld dst else ()
  }

let nop (ins: Instruction) insLen bld =
  lift bld ins insLen {
  }

/// The number of bytes dcbz clears. The architecture leaves the size to the
/// implementation and has software discover it from AT_DCACHEBSIZE; this is
/// the size every 64-bit Power part uses.
let [<Literal>] private CacheBlockSize = 128

/// dcbz, the one cache-management form with an effect on storage: it clears the
/// block the address falls in. Modeled as clearing that many bytes, in
/// doublewords, from the block-aligned address.
let dcbz ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithIndexReg o1 o2 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea .& AST.not (numI32 (CacheBlockSize - 1) bld.RegType)
    for i in 0 .. (CacheBlockSize / 8) - 1 do
      let addr = tmpEA .+ numI32 (i * 8) bld.RegType
      loadNative bld 64<rt> addr := AST.num0 64<rt>
  }

let orx ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := src1 .| src2
    if updateCond then setCR0Reg bld dst else ()
  }

let orc ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := src1 .| AST.not (src2)
    if updateCond then setCR0Reg bld dst else ()
  }

let ori ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src, uimm) = transThreeOprs ins bld
    let uimm = AST.zext bld.RegType (AST.xtlo 16<rt> uimm)
    dst := src .| uimm
  }

let oris ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src, uimm) = transThreeOprs ins bld
    let uimm = shiftedImm bld false uimm
    dst := src .| uimm
  }

(* The rotate-word forms all work on the low word of rS and, on a 64-bit part,
   leave the result's upper word zero -- so the whole thing is a word operation
   whose result is zero-extended back into a register. *)
let rlwinm ins insLen updateCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (ra, rs, sh, mb, me) = transFiveOprs ins bld
    let rol = tmpVar bld 32<rt>
    rol := rotateLeft (AST.xtlo 32<rt> rs) (AST.xtlo 32<rt> sh)
    ra := AST.zext bld.RegType (rol .& (getExtMask mb me))
    if updateCond then setCR0Reg bld ra else ()
  }

/// rlwimi merges a rotated word into rA under a mask that covers only the low
/// word, so unlike the other rotate-word forms it leaves rA's upper word alone
/// rather than clearing it -- which is what makes it the instruction a compiler
/// reaches for when it inserts a bit field.
let rlwimi ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs, sh, mb, me) = transFiveOprs ins bld
    let m = getExtMask mb me
    let rol = rotateLeft (AST.xtlo 32<rt> rs) (AST.xtlo 32<rt> sh)
    let merged = tmpVar bld 32<rt>
    merged := (rol .& m) .| (AST.xtlo 32<rt> ra .& AST.not m)
    AST.xtlo 32<rt> ra := merged
    if updateCond then setCR0Reg bld ra else ()
  }

let rlwnm ins insLen updateCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (ra, rs, rb, mb, me) = transFiveOprs ins bld
    let n = AST.xtlo 32<rt> rb .& numI32 0x1f 32<rt>
    let rol = tmpVar bld 32<rt>
    rol := rotateLeft (AST.xtlo 32<rt> rs) n
    ra := AST.zext bld.RegType (rol .& (getExtMask mb me))
    if updateCond then setCR0Reg bld ra else ()
  }

let rotlw ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (ra, rs, rb) = transThreeOprs ins bld
    let n = AST.xtlo 32<rt> rb .& numI32 0x1f 32<rt>
    let rol = rotateLeft (AST.xtlo 32<rt> rs) n
    ra := AST.zext bld.RegType rol (* no mask *)
  }

(* The rotate-doubleword forms take a six-bit shift and a six-bit mask bound,
   and the mask is a constant of the immediate forms. *)
let rldicl ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs, sh, mb) = transFourOprs ins bld
    let rol = tmpVar bld 64<rt>
    rol := rotateLeft64 rs sh
    ra := rol .& getExtMask64 mb (numI32 63 64<rt>)
    if updateCond then setCR0Reg bld ra else ()
  }

let rldicr ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs, sh, me) = transFourOprs ins bld
    let rol = tmpVar bld 64<rt>
    rol := rotateLeft64 rs sh
    ra := rol .& getExtMask64 (AST.num0 64<rt>) me
    if updateCond then setCR0Reg bld ra else ()
  }

/// The end of an rldic/rldimi mask, which the shift amount fixes at 63 - sh.
let private maskEndOfShift sh =
  match sh with
  | Num(n, _) -> numI32 (63 - int (n.ToUInt64())) 64<rt>
  | _ -> raise InvalidExprException

let rldic ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs, sh, mb) = transFourOprs ins bld
    let rol = tmpVar bld 64<rt>
    rol := rotateLeft64 rs sh
    ra := rol .& getExtMask64 mb (maskEndOfShift sh)
    if updateCond then setCR0Reg bld ra else ()
  }

let rldimi ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs, sh, mb) = transFourOprs ins bld
    let m = getExtMask64 mb (maskEndOfShift sh)
    let rol = tmpVar bld 64<rt>
    rol := rotateLeft64 rs sh
    ra := (rol .& m) .| (ra .& AST.not m)
    if updateCond then setCR0Reg bld ra else ()
  }

let rldcl ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs, rb, mb) = transFourOprs ins bld
    let rol = tmpVar bld 64<rt>
    rol := rotateLeft64 rs (rb .& numI32 0x3f 64<rt>)
    ra := rol .& getExtMask64 mb (numI32 63 64<rt>)
    if updateCond then setCR0Reg bld ra else ()
  }

let rldcr ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (ra, rs, rb, me) = transFourOprs ins bld
    let rol = tmpVar bld 64<rt>
    rol := rotateLeft64 rs (rb .& numI32 0x3f 64<rt>)
    ra := rol .& getExtMask64 (AST.num0 64<rt>) me
    if updateCond then setCR0Reg bld ra else ()
  }

(* A shift's count comes from the low six bits of rB, and the bit above them
   makes the result all sign (arithmetic) or all zero (logical). *)
/// A logical shift of `width` bits, left when shiftLeft is set. The count's
/// high bit -- bit 5 for a word form, bit 6 for a doubleword one -- shifts the
/// whole operand out, which the architecture defines as a zero result.
let private logicalShift ins
                         insLen
                         updateCond
                         (bld: ILowUIRBuilder)
                         width
                         shiftLeft =
  lift bld ins insLen {
    let struct (dst, rs, rb) = transThreeOprs ins bld
    let bits = int width
    let value = AST.xtlo width rs
    let count = AST.xtlo width rb
    let n = tmpVar bld width
    n := count .& numI32 (bits - 1) width
    let shifted = if shiftLeft then value << n else value >> n
    let tooFar = (count .& numI32 bits width) != AST.num0 width
    let res = AST.ite tooFar (AST.num0 width) shifted
    dst := AST.zext bld.RegType res
    if updateCond then setCR0Reg bld dst else ()
  }

let slw ins insLen updateCond bld =
  logicalShift ins insLen updateCond bld 32<rt> true

let srw ins insLen updateCond bld =
  logicalShift ins insLen updateCond bld 32<rt> false

let sld ins insLen updateCond bld =
  logicalShift ins insLen updateCond bld 64<rt> true

let srd ins insLen updateCond bld =
  logicalShift ins insLen updateCond bld 64<rt> false

/// An arithmetic right shift of `width` bits by a register count, which also
/// leaves XER[CA] set when a one was shifted out of a negative value. A count
/// past the operand's width shifts in nothing but sign.
let private arithShift ins insLen updateCond (bld: ILowUIRBuilder) width =
  lift bld ins insLen {
    let struct (ra, rs, rb) = transThreeOprs ins bld
    let bits = int width
    let z = AST.num0 width
    let value = tmpVar bld width
    let count = AST.xtlo width rb
    let inRange = (count .& numI32 bits width) == z
    let n = tmpVar bld width
    let res = tmpVar bld width
    value := AST.xtlo width rs
    n := count .& numI32 (bits - 1) width
    res := AST.ite inRange (value ?>> n)
                           (value ?>> numI32 (bits - 1) width)
    ra := AST.sext bld.RegType res
    let dropped =
      AST.ite inRange ((AST.num1 width << n) .- AST.num1 width) (AST.not z)
    let lost = (value .& dropped) != z
    AST.extract (regVar bld Register.XER) 1<rt> 29 :=
      AST.ite (res ?< z) lost AST.b0
    if updateCond then setCR0Reg bld ra else ()
  }

let sraw ins insLen updateCond bld = arithShift ins insLen updateCond bld 32<rt>

let srad ins insLen updateCond bld = arithShift ins insLen updateCond bld 64<rt>

/// An arithmetic right shift of `width` bits by an immediate count, setting
/// XER[CA] as the register-count form does.
let private arithShiftImm ins insLen updateCond (bld: ILowUIRBuilder) width =
  lift bld ins insLen {
    let struct (ra, rs, sh) = transThreeOprs ins bld
    let z = AST.num0 width
    let value = tmpVar bld width
    let n = AST.xtlo width sh
    let res = tmpVar bld width
    value := AST.xtlo width rs
    res := value ?>> n
    ra := AST.sext bld.RegType res
    let dropped = (AST.num1 width << n) .- AST.num1 width
    let lost = (value .& dropped) != z
    AST.extract (regVar bld Register.XER) 1<rt> 29 :=
      AST.ite (res ?< z) lost AST.b0
    if updateCond then setCR0Reg bld ra else ()
  }

let srawi ins insLen updateCond bld =
  arithShiftImm ins insLen updateCond bld 32<rt>

let sradi ins insLen updateCond bld =
  arithShiftImm ins insLen updateCond bld 64<rt>

let stb ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let src = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 8<rt> tmpEA := AST.xtlo 8<rt> src
  }

let stbx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 8<rt> tmpEA := AST.xtlo 8<rt> rs
  }

let stbu ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let src = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 8<rt> tmpEA := AST.xtlo 8<rt> src
    ra := tmpEA
  }

let stbux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 8<rt> tmpEA := AST.xtlo 8<rt> rs
    rA := tmpEA
  }

let stfd ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 64<rt> tmpEA := frs
  }

let stfdx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let ea = transEAWithIndexReg o2 o3 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 64<rt> tmpEA := frs
  }

let stfdu ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 64<rt> tmpEA := frs
    ra := tmpEA
  }

let stfdux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let frs = transOpr bld o1
    let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 64<rt> tmpEA := frs
    rA := tmpEA
  }

let stfiwx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let frs = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 32<rt> tmpEA := AST.xtlo 32<rt> frs
  }

let stfs ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 32<rt> tmpEA := AST.cast CastKind.FloatCast 32<rt> frs
  }

let stfsx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let ea = transEAWithIndexReg o2 o3 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 32<rt> tmpEA := AST.cast CastKind.FloatCast 32<rt> frs
  }

let stfsu ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let frs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 32<rt> tmpEA := AST.cast CastKind.FloatCast 32<rt> frs
    ra := tmpEA
  }

let stfsux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let frs = transOpr bld o1
    let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 32<rt> tmpEA := AST.cast CastKind.FloatCast 32<rt> frs
    rA := tmpEA
  }

let sth ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let ea = transEAWithOffset o2 bld
    let src = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 16<rt> tmpEA := AST.xtlo 16<rt> src
  }

let sthbrx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let revtmp = tmpVar bld 16<rt>
    revtmp := AST.concat (AST.extract rs 8<rt> 0)
                         (AST.extract rs 8<rt> 8)
    loadNative bld 16<rt> ea := revtmp
  }

let sthx ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 16<rt> tmpEA := AST.xtlo 16<rt> rs
  }

let sthu ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
    let rs = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 16<rt> tmpEA := AST.xtlo 16<rt> rs
    ra := tmpEA
  }

let sthux ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let struct (ea, rA) = transEAWithIndexRegForUpdate o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld 16<rt> tmpEA := AST.xtlo 16<rt> rs
    rA := tmpEA
  }

/// A d(rA) store of the low `size` bits of rS, updating rA when update is set.
let private storeOffset ins insLen (bld: ILowUIRBuilder) size update =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let src = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    if update then
      let struct (ea, ra) = transEAWithOffsetForUpdate o2 bld
      tmpEA := ea
      loadNative bld size tmpEA := AST.xtlo size src
      ra := tmpEA
    else
      tmpEA := transEAWithOffset o2 bld
      loadNative bld size tmpEA := AST.xtlo size src
  }

/// An rA + rB store of the low `size` bits of rS, updating rA when update is
/// set.
let private storeIndexed ins insLen (bld: ILowUIRBuilder) size update =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let src = transOpr bld o1
    let tmpEA = tmpVar bld bld.RegType
    if update then
      let struct (ea, ra) = transEAWithIndexRegForUpdate o2 o3 bld
      tmpEA := ea
      loadNative bld size tmpEA := AST.xtlo size src
      ra := tmpEA
    else
      tmpEA := transEAWithIndexReg o2 o3 bld
      loadNative bld size tmpEA := AST.xtlo size src
  }

let stw ins insLen bld = storeOffset ins insLen bld 32<rt> false

let stwu ins insLen bld = storeOffset ins insLen bld 32<rt> true

let stwx ins insLen bld = storeIndexed ins insLen bld 32<rt> false

let stwux ins insLen bld = storeIndexed ins insLen bld 32<rt> true

let std ins insLen bld = storeOffset ins insLen bld 64<rt> false

let stdu ins insLen bld = storeOffset ins insLen bld 64<rt> true

let stdx ins insLen bld = storeIndexed ins insLen bld 64<rt> false

let stdux ins insLen bld = storeIndexed ins insLen bld 64<rt> true

let lmw ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let rd =
      match o1 with
      | OprReg r -> int r
      | _ -> raise InvalidOperandException
    let ea = transEAWithOffset o2 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    for r = rd to 31 do
      let dst = regVar bld (getRegister (uint32 r))
      let addr = tmpEA .+ numI32 ((r - rd) * 4) bld.RegType
      dst := AST.zext bld.RegType (loadNative bld 32<rt> addr)
  }

let stmw ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let rs =
      match o1 with
      | OprReg r -> int r
      | _ -> raise InvalidOperandException
    let ea = transEAWithOffset o2 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    for r = rs to 31 do
      let src = regVar bld (getRegister (uint32 r))
      let addr = tmpEA .+ numI32 ((r - rs) * 4) bld.RegType
      loadNative bld 32<rt> addr := AST.xtlo 32<rt> src
  }

/// stwbrx/stdbrx: a store whose bytes go out in the opposite order.
let private storeByteReverse ins insLen (bld: ILowUIRBuilder) size =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    loadNative bld size tmpEA := reversedBytes (AST.xtlo size rs) size
  }

let stwbrx ins insLen bld = storeByteReverse ins insLen bld 32<rt>

let stdbrx ins insLen bld = storeByteReverse ins insLen bld 64<rt>

/// stwcx./stdcx.: the store half of a reservation pair. It succeeds only when
/// the address and the value both still match what the paired load reserved,
/// and reports that in CR0[EQ].
let private storeConditional ins insLen (bld: ILowUIRBuilder) size =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let rs = transOpr bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let xerSO = AST.xthi 1<rt> (regVar bld Register.XER)
    let cr0LT = regVar bld Register.CR0_0
    let cr0GT = regVar bld Register.CR0_1
    let cr0EQ = regVar bld Register.CR0_2
    let cr0SO = regVar bld Register.CR0_3
    let tmpEA = tmpVar bld bld.RegType
    let cur = tmpVar bld size
    let matched = tmpVar bld 1<rt>
    tmpEA := ea
    cur := loadNative bld size tmpEA
    matched := (tmpEA == regVar bld Register.ExMonAddr)
               .& (AST.zext bld.RegType cur
                   == regVar bld Register.ExMonVal)
    loadNative bld size tmpEA :=
      AST.ite matched (AST.xtlo size rs) cur
    cr0EQ := matched
    cr0LT := AST.b0
    cr0GT := AST.b0
    cr0SO := xerSO
  }

let stwcxdot ins insLen bld = storeConditional ins insLen bld 32<rt>

let stdcxdot ins insLen bld = storeConditional ins insLen bld 64<rt>

let stbcxdot ins insLen bld = storeConditional ins insLen bld 8<rt>

let sthcxdot ins insLen bld = storeConditional ins insLen bld 16<rt>

let subf ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let one = AST.num1 bld.RegType
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := AST.not src1
    t2 := src2
    dst := t1 .+ t2 .+ one
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let subfc ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := AST.not src1
    t2 := src2
    addWithCarryOut bld dst t1 t2 (AST.num1 bld.RegType)
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let subfe ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := AST.not src1
    t2 := src2
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let subfic ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src1, simm) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := AST.not src1
    t2 := simm
    addWithCarryOut bld dst t1 t2 (AST.num1 bld.RegType)
  }

let subfme ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := AST.not src
    t2 := AST.not (AST.num0 bld.RegType)
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let subfze ins insLen updateCond ovCond (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (dst, src) = transTwoOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    let ca = carryIn bld
    t1 := AST.not src
    t2 := AST.num0 bld.RegType
    addWithCarryOut bld dst t1 t2 ca
    if ovCond then isAddSubOV bld t1 t2 dst else ()
    if updateCond then setCR0Reg bld dst else ()
  }

let trap (ins: Instruction) insLen bld =
  lift bld ins insLen {
    AST.sideEffect (Interrupt 0)
  }

let trapCond ins insLen cmpOp bld =
  lift bld ins insLen {
    let struct (ra, rb) = transTwoOprs ins bld
    let lblTrap = label bld "Trap"
    let lblEnd = label bld "End"
    AST.cjmp (cmpOp ra rb) (AST.jmpDest lblTrap) (AST.jmpDest lblEnd)
    AST.lmark lblTrap
    AST.sideEffect (Interrupt 0)
    AST.lmark lblEnd
  }

/// The five TO bits of a tw/td, each naming one comparison that traps: from
/// bit 0, signed less-than, signed greater-than, equal, unsigned less-than and
/// unsigned greater-than.
let private trapTests = [| AST.slt; AST.sgt; AST.eq; AST.lt; AST.gt |]

/// A generic tw/td/twi/tdi, which traps when any comparison its TO field names
/// holds. The word forms compare only the low word of each operand.
let trapGeneric ins insLen (bld: ILowUIRBuilder) narrow =
  lift bld ins insLen {
    let struct (tO, ra, rb) = transThreeOprs ins bld
    let tO = match tO with
             | Num(n, _) -> int (n.ToUInt64())
             | _ -> raise InvalidExprException
    let ra, rb =
      if narrow then AST.xtlo 32<rt> ra, AST.xtlo 32<rt> rb else ra, rb
    let lblTrap = label bld "Trap"
    let lblEnd = label bld "End"
    let cond =
      Array.mapi (fun i test -> if tO &&& (1 <<< (4 - i)) <> 0 then test ra rb
                                else AST.b0) trapTests
      |> Array.reduce (.|)
    AST.cjmp cond (AST.jmpDest lblTrap) (AST.jmpDest lblEnd)
    AST.lmark lblTrap
    AST.sideEffect (Interrupt 0)
    AST.lmark lblEnd
  }

let xor ins insLen updateCond bld =
  lift bld ins insLen {
    let struct (dst, src1, src2) = transThreeOprs ins bld
    dst := (src1 <+> src2)
    if updateCond then setCR0Reg bld dst else ()
  }

let xori ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src, uimm) = transThreeOprs ins bld
    let uimm = AST.zext bld.RegType (AST.xtlo 16<rt> uimm)
    dst := src <+> uimm
  }

let xoris ins insLen bld =
  lift bld ins insLen {
    let struct (dst, src, uimm) = transThreeOprs ins bld
    let uimm = shiftedImm bld false uimm
    dst := src <+> uimm
  }

/// Sums the set bits of each `chunk`-wide field of rs, in place, by the usual
/// halving fold: pairs, then nibbles, then bytes, and so on up to the field.
let private popCountInto (bld: ILowUIRBuilder) ra rs chunk =
  append bld {
    let rt = bld.RegType
    let x = tmpVar bld rt
    let n i = numI32 i rt
    let mask v = numU64 v rt
    x := rs
    x := (x .& mask 0x5555555555555555UL)
         .+ ((x >> n 1) .& mask 0x5555555555555555UL)
    x := (x .& mask 0x3333333333333333UL)
         .+ ((x >> n 2) .& mask 0x3333333333333333UL)
    x := (x .& mask 0x0f0f0f0f0f0f0f0fUL)
         .+ ((x >> n 4) .& mask 0x0f0f0f0f0f0f0f0fUL)
    if chunk > 8 then
      x := (x .& mask 0x00ff00ff00ff00ffUL)
           .+ ((x >> n 8) .& mask 0x00ff00ff00ff00ffUL)
    else
      ()
    if chunk > 16 then
      x := (x .& mask 0x0000ffff0000ffffUL)
           .+ ((x >> n 16) .& mask 0x0000ffff0000ffffUL)
    else
      ()
    if chunk > 32 then
      x := (x .& mask 0x00000000ffffffffUL)
           .+ ((x >> n 32) .& mask 0x00000000ffffffffUL)
    else
      ()
    ra := x
  }

/// popcntb/popcntw/popcntd, which count the set bits of every byte, word or
/// doubleword of rS into the same field of rA.
let popcnt ins insLen bld chunk =
  lift bld ins insLen {
    let struct (ra, rs) = transTwoOprs ins bld
    popCountInto bld ra rs chunk
  }

/// prtyw/prtyd, which put the parity of rS's bytes -- one per word, or one for
/// the whole doubleword -- in the low bit of that field of rA. Only each byte's
/// low bit takes part, so summing those and keeping the sum's low bit gives it.
let prty ins insLen (bld: ILowUIRBuilder) chunk =
  lift bld ins insLen {
    let rt = bld.RegType
    let struct (ra, rs) = transTwoOprs ins bld
    let lowBitOfField =
      if chunk > 32 then AST.num1 rt else numU64 0x0000000100000001UL rt
    let x = tmpVar bld rt
    x := rs .& numU64 0x0101010101010101UL rt
    popCountInto bld x x chunk
    ra := x .& lowBitOfField
  }

/// bpermd, which gathers the eight bits of rB that the eight byte indices in rS
/// name into the low byte of rA; an index past 63 contributes a zero. Index i
/// counts from rS's most significant byte and lands in rA's bit 7 - i.
let bpermd ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let rt = bld.RegType
    let struct (ra, rs, rb) = transThreeOprs ins bld
    let res = tmpVar bld rt
    res := AST.num0 rt
    for i in 0 .. 7 do
      let idx = AST.zext rt (AST.extract rs 8<rt> ((7 - i) * 8))
      let bit = (rb >> (numI32 63 rt .- idx)) .& AST.num1 rt
      let inRange = idx .< numI32 64 rt
      let picked = AST.ite inRange bit (AST.num0 rt)
      res := res .| (picked << numI32 (7 - i) rt)
    ra := res
  }

/// cmpb, which sets each byte of rA to all ones where the matching bytes of rS
/// and rB are equal and to zero where they are not.
let cmpb ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let rt = bld.RegType
    let struct (ra, rs, rb) = transThreeOprs ins bld
    let res = tmpVar bld rt
    res := AST.num0 rt
    for i in 0 .. (int rt / 8) - 1 do
      let eq = AST.extract rs 8<rt> (i * 8) == AST.extract rb 8<rt> (i * 8)
      AST.extract res 8<rt> (i * 8) :=
        AST.ite eq (numI32 0xff 8<rt>) (AST.num0 8<rt>)
    ra := res
  }

/// isel, which picks rA (or zero when rA is r0) or rB by a CR bit.
let isel (ins: Instruction) insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (rd, ra, rb, crb) =
      match ins.Operands with
      | FourOperands(o1, OprReg Register.R0, o3, o4) ->
        let o1 = transOpr bld o1
        let o3 = transOpr bld o3
        let o4 = transOpr bld o4
        struct (o1, AST.num0 bld.RegType, o3, o4)
      | FourOperands(o1, o2, o3, o4) ->
        let o1 = transOpr bld o1
        let o2 = transOpr bld o2
        let o3 = transOpr bld o3
        let o4 = transOpr bld o4
        struct (o1, o2, o3, o4)
      | _ ->
        raise InvalidOperandException
    rd := AST.ite crb ra rb
  }

/// mfvsrd/mfvsrwz, which move the bits of a vector-scalar register's high
/// doubleword into a general register without converting them. The operand
/// names that doubleword, whichever kind of register holds it.
let mfvsr ins insLen (bld: ILowUIRBuilder) size =
  lift bld ins insLen {
    let struct (frs, ra) = transTwoOprs ins bld
    ra := AST.zext bld.RegType (AST.xtlo size frs)
  }

/// mtvsrd, which moves a general register's bits into a vector-scalar
/// register's high doubleword, leaving the low one undefined.
let mtvsrd ins insLen bld =
  lift bld ins insLen {
    let struct (frs, ra) = transTwoOprs ins bld
    frs := AST.zext 64<rt> ra
  }

/// mtvsrwa/mtvsrwz, which move the low word of a general register into a
/// vector-scalar register's high doubleword, sign- or zero-extended.
let mtvsrw ins insLen bld signed =
  lift bld ins insLen {
    let struct (frs, ra) = transTwoOprs ins bld
    let w = AST.xtlo 32<rt> ra
    frs := if signed then AST.sext 64<rt> w else AST.zext 64<rt> w
  }

/// fctid/fctidz/fctidu/fctiduz and fctiwu/fctiwuz: a conversion from a double
/// to an integer of `width` bits, left in the target's low bits. A "z" form
/// always truncates; the others follow FPSCR[RN].
let fcti ins insLen updateCond bld width truncate =
  lift bld ins insLen {
    let struct (frd, frb) = transTwoOprs ins bld
    if truncate then
      frd := AST.zext 64<rt> (AST.cast CastKind.FtoITrunc width frb)
    else
      let rounded = tmpVar bld 64<rt>
      roundingToCastInt bld rounded frb
      frd := AST.zext 64<rt> (AST.xtlo width rounded)
    if updateCond then setCR1Reg bld else ()
  }

/// fcfid/fcfidu/fcfids/fcfidus: a conversion from the integer in frB's whole
/// doubleword to a double, rounded to single precision by the "s" forms.
let fcfid ins insLen updateCond bld signed single =
  lift bld ins insLen {
    let struct (frd, frb) = transTwoOprs ins bld
    let kind = if signed then CastKind.SIntToFloat else CastKind.UIntToFloat
    let converted = AST.cast kind 64<rt> frb
    if single then
      let narrowed = AST.cast CastKind.FloatCast 32<rt> converted
      frd := AST.cast CastKind.FloatCast 64<rt> narrowed
    else
      frd := converted
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

/// frin/friz/frip/frim, which round a double to an integral value in place,
/// respectively to nearest, toward zero, up, and down.
let frnd ins insLen updateCond bld kind =
  lift bld ins insLen {
    let struct (frd, frb) = transTwoOprs ins bld
    frd := AST.cast kind 64<rt> frb
    setFPRF bld frd
    if updateCond then setCR1Reg bld else ()
  }

(* The vector unit. A 128-bit vector register is modeled as two 64-bit halves
   (see the Register type), and every operation below works on those halves
   rather than on a 128-bit value, so nothing needs an intermediate wider than a
   register. "hi" always holds the vector's most significant doubleword, which
   is the half PowerPC numbers first. *)
/// The high and low halves of the 128-bit register an operand names: a vector
/// register keeps its low half in the register that follows, while a VSX
/// operand naming a floating-point register keeps it in that register's
/// companion (VSR0-31 hold their high doubleword in an FPR).
let private vecHalves bld opr =
  match opr with
  | OprReg reg ->
    let lo = if reg >= Register.V0A then getLowHalf reg else getVsxLowHalf reg
    struct (regVar bld reg, regVar bld lo)
  | _ ->
    raise InvalidOperandException

/// The byte of a vector at PowerPC byte index b, where 0 is the most
/// significant byte -- which lives at the top of the high half.
let private vecByte hi lo b =
  if b < 8 then AST.extract hi 8<rt> ((7 - b) * 8)
  else AST.extract lo 8<rt> ((15 - b) * 8)

/// Writes every `esize`-wide element of one 64-bit half from f applied to the
/// matching elements of a and b.
let private applyElements (bld: ILowUIRBuilder) esize dst a b f =
  append bld {
    for i in 0 .. (64 / int esize) - 1 do
      let pos = i * int esize
      AST.extract dst esize pos :=
        f (AST.extract a esize pos) (AST.extract b esize pos)
  }

/// An element-wise "vD, vA, vB" over both halves. The result goes through
/// temporaries first, so a destination that is also a source reads its old
/// value throughout.
let private vecBinary ins insLen bld esize f =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let struct (th, tl) = tmpVars2 bld 64<rt>
    applyElements bld esize th ah bh f
    applyElements bld esize tl al bl f
    dh := th
    dl := tl
  }

/// An element-wise "vD, vB" over both halves.
let private vecUnary ins insLen bld esize f =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, bl) = vecHalves bld o2
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for i in 0 .. (64 / int esize) - 1 do
      let pos = i * int esize
      AST.extract th esize pos := f (AST.extract bh esize pos)
      AST.extract tl esize pos := f (AST.extract bl esize pos)
    dh := th
    dl := tl
  }

/// The all-ones or all-zeroes an element-wise compare writes per element.
let private compareMask esize cond =
  AST.ite cond (AST.not (AST.num0 esize)) (AST.num0 esize)

/// A vector compare. The record form also reports in CR6 whether every element
/// compared true (bit 0) or none did (bit 2).
let private vecCompare ins insLen bld esize rel record =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let struct (th, tl) = tmpVars2 bld 64<rt>
    let f x y = compareMask esize (rel x y)
    applyElements bld esize th ah bh f
    applyElements bld esize tl al bl f
    dh := th
    dl := tl
    if record then
      let ones = AST.not (AST.num0 64<rt>)
      let zero = AST.num0 64<rt>
      regVar bld Register.CR6_0 := (th == ones) .& (tl == ones)
      regVar bld Register.CR6_1 := AST.b0
      regVar bld Register.CR6_2 := (th == zero) .& (tl == zero)
      regVar bld Register.CR6_3 := AST.b0
    else
      ()
  }

/// The two addresses a 16-byte vector access uses for the vector's high and low
/// halves. A big-endian guest keeps the most significant half at the lower
/// address; on a little-endian one the whole quadword's byte order reverses,
/// which puts the most significant half at the higher address.
let private quadwordHalves (bld: ILowUIRBuilder) ea =
  let next = ea .+ numI32 8 bld.RegType
  if bld.Endianness = Endian.Big then struct (ea, next) else struct (next, ea)

/// lvx/lvxl, which load the aligned quadword the address falls in.
let private lvx ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea .& AST.not (numI32 15 bld.RegType)
    let struct (hiAddr, loAddr) = quadwordHalves bld tmpEA
    dh := loadNative bld 64<rt> hiAddr
    dl := loadNative bld 64<rt> loAddr
  }

/// stvx/stvxl, which store to the aligned quadword the address falls in.
let private stvx ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (sh, sl) = vecHalves bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea .& AST.not (numI32 15 bld.RegType)
    let struct (hiAddr, loAddr) = quadwordHalves bld tmpEA
    loadNative bld 64<rt> hiAddr := sh
    loadNative bld 64<rt> loAddr := sl
  }

/// lvsl/lvsr, which build the permute control vector that vperm needs to
/// realign data straddling two quadwords: lvsl counts up from the address's
/// offset within its quadword, lvsr counts down to it.
let private lvsx ins insLen (bld: ILowUIRBuilder) isLeft =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let sh = tmpVar bld 8<rt>
    let struct (th, tl) = tmpVars2 bld 64<rt>
    sh := AST.xtlo 8<rt> ea .& numI32 15 8<rt>
    for b in 0 .. 15 do
      let value =
        if isLeft then sh .+ numI32 b 8<rt> else numI32 (16 + b) 8<rt> .- sh
      let dst = if b < 8 then th else tl
      let pos = if b < 8 then (7 - b) * 8 else (15 - b) * 8
      AST.extract dst 8<rt> pos := value .& numI32 31 8<rt>
    dh := th
    dl := tl
  }

/// lvebx/lvehx/lvewx, which load one element into the vector slot the address
/// selects and leave the rest of the register undefined -- modeled here as
/// leaving it unchanged, which is what a real part does in practice.
let private lvex ins insLen (bld: ILowUIRBuilder) size =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let bytes = int size / 8
    let tmpEA = tmpVar bld bld.RegType
    let value = tmpVar bld size
    let index = tmpVar bld 8<rt>
    tmpEA := ea .& AST.not (numI32 (bytes - 1) bld.RegType)
    value := loadNative bld size tmpEA
    index := AST.xtlo 8<rt> tmpEA .& numI32 15 8<rt>
    (* The element's slot is fixed at run time, so every slot is written under
       the guard that the address selects it. *)
    for slot in 0 .. (16 / bytes) - 1 do
      let b = slot * bytes
      let dst = if b < 8 then dh else dl
      let pos = if b < 8 then (8 - bytes - b % 8) * 8 else (16 - bytes - b) * 8
      let picked = index == numI32 b 8<rt>
      AST.extract dst size pos :=
        AST.ite picked value (AST.extract dst size pos)
  }

/// stvebx/stvehx/stvewx, the store counterparts of lvebx and friends.
let private stvex ins insLen (bld: ILowUIRBuilder) size =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (sh, sl) = vecHalves bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let bytes = int size / 8
    let tmpEA = tmpVar bld bld.RegType
    let index = tmpVar bld 8<rt>
    let value = tmpVar bld size
    tmpEA := ea .& AST.not (numI32 (bytes - 1) bld.RegType)
    index := AST.xtlo 8<rt> tmpEA .& numI32 15 8<rt>
    value := AST.num0 size
    for slot in 0 .. (16 / bytes) - 1 do
      let b = slot * bytes
      let src = if b < 8 then sh else sl
      let pos = if b < 8 then (8 - bytes - b % 8) * 8 else (16 - bytes - b) * 8
      let picked = index == numI32 b 8<rt>
      value := AST.ite picked (AST.extract src size pos) value
    loadNative bld size tmpEA := value
  }

/// lxvd2x/stxvd2x and lxvw4x/stxvw4x, which access a quadword element by
/// element: each element keeps the guest's byte order but the elements
/// themselves are not reordered, unlike lvx.
let private lxvx ins insLen (bld: ILowUIRBuilder) esize isLoad =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let bytes = int esize / 8
    let perHalf = 8 / bytes
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    for i in 0 .. (16 / bytes) - 1 do
      let addr = tmpEA .+ numI32 (i * bytes) bld.RegType
      let reg = if i < perHalf then dh else dl
      let pos = (perHalf - 1 - i % perHalf) * int esize
      if isLoad then
        AST.extract reg esize pos := loadNative bld esize addr
      else
        loadNative bld esize addr := AST.extract reg esize pos
  }

/// lxsdx/stxsdx, which move one doubleword to or from a VSX register's high
/// half, and lxvdsx, which splats one into both halves.
let private lxsdx ins insLen (bld: ILowUIRBuilder) splat isLoad =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let ea = transEAWithIndexReg o2 o3 bld
    let tmpEA = tmpVar bld bld.RegType
    tmpEA := ea
    if isLoad then
      dh := loadNative bld 64<rt> tmpEA
      if splat then
        append bld { dl := dh }
      else
        append bld { dl := AST.num0 64<rt> }
    else
      loadNative bld 64<rt> tmpEA := dh
  }

/// A whole-register logical "xT, xA, xB", which the xxl family and the vector
/// logical ops share.
let private vecLogical ins insLen bld f = vecBinary ins insLen bld 64<rt> f

/// vsel/xxsel, a bitwise select: a set bit of vC takes vB, a clear one vA.
let private vecSelect ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let struct (ch, cl) = vecHalves bld o4
    let struct (th, tl) = tmpVars2 bld 64<rt>
    th := (bh .& ch) .| (ah .& AST.not ch)
    tl := (bl .& cl) .| (al .& AST.not cl)
    dh := th
    dl := tl
  }

/// xxpermdi, which builds a vector from one doubleword of each source: DM's
/// high bit picks which doubleword of xA lands in the result's high half, its
/// low bit which of xB lands in the low half.
let private vecPermuteDouble ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let dm =
      match o4 with
      | OprImm n -> int n
      | _ -> raise InvalidOperandException
    let struct (th, tl) = tmpVars2 bld 64<rt>
    th := if dm &&& 2 = 0 then ah else al
    tl := if dm &&& 1 = 0 then bh else bl
    dh := th
    dl := tl
  }

/// vperm, which fills each byte of vD from the byte of the 32-byte pair
/// vA || vB that the matching byte of vC indexes.
let private vecPermute ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let struct (ch, cl) = vecHalves bld o4
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for b in 0 .. 15 do
      let index = tmpVar bld 8<rt>
      index := vecByte ch cl b .& numI32 31 8<rt>
      let mutable picked = AST.num0 8<rt>
      for src in 0 .. 31 do
        let byteOf =
          if src < 16 then vecByte ah al src else vecByte bh bl (src - 16)
        picked <- AST.ite (index == numI32 src 8<rt>) byteOf picked
      let dst = if b < 8 then th else tl
      let pos = if b < 8 then (7 - b) * 8 else (15 - b) * 8
      AST.extract dst 8<rt> pos := picked
    dh := th
    dl := tl
  }

/// vsldoi and xxsldwi, which take the 16 bytes starting a given distance into
/// the 32-byte pair vA || vB -- counted in bytes by vsldoi and in words by
/// xxsldwi.
let private vecShiftDouble ins insLen bld scale =
  lift bld ins insLen {
    let struct (o1, o2, o3, o4) = getFourOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let shift =
      match o4 with
      | OprImm n -> int n * scale
      | _ -> raise InvalidOperandException
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for b in 0 .. 15 do
      let src = b + shift
      let byteOf =
        if src < 16 then vecByte ah al src else vecByte bh bl (src - 16)
      let dst = if b < 8 then th else tl
      let pos = if b < 8 then (7 - b) * 8 else (15 - b) * 8
      AST.extract dst 8<rt> pos := byteOf
    dh := th
    dl := tl
  }

/// vspltb/vsplth/vspltw, which copy one element of vB into every element of vD.
let private vecSplat ins insLen bld esize =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, bl) = vecHalves bld o2
    let index =
      match o3 with
      | OprImm n -> int n % (128 / int esize)
      | _ -> raise InvalidOperandException
    let perHalf = 64 / int esize
    let element = tmpVar bld esize
    let struct (th, tl) = tmpVars2 bld 64<rt>
    let src = if index < perHalf then bh else bl
    let pos = (perHalf - 1 - index % perHalf) * int esize
    element := AST.extract src esize pos
    for i in 0 .. perHalf - 1 do
      AST.extract th esize (i * int esize) := element
      AST.extract tl esize (i * int esize) := element
    dh := th
    dl := tl
  }

/// vspltisb/vspltish/vspltisw, which fill every element with a signed
/// immediate.
let private vecSplatImm ins insLen bld esize =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let value =
      match o2 with
      | OprImm n -> numU64 n esize
      | _ -> raise InvalidOperandException
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for i in 0 .. (64 / int esize) - 1 do
      AST.extract th esize (i * int esize) := value
      AST.extract tl esize (i * int esize) := value
    dh := th
    dl := tl
  }

/// vmrgh*/vmrgl*, which interleave the elements of one half of vA with those of
/// the matching half of vB.
let private vecMerge ins insLen bld esize high =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let bytes = int esize / 8
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for i in 0 .. (8 / bytes) - 1 do
      let src = if high then i * bytes else 8 + i * bytes
      for (half, srcH, srcL) in [ 0, ah, al; 1, bh, bl ] do
        let b = (2 * i + half) * bytes
        let dst = if b < 8 then th else tl
        let pos = if b < 8 then (8 - bytes - b) * 8 else (16 - bytes - b) * 8
        let value =
          Array.init bytes (fun k -> vecByte srcH srcL (src + k))
          |> AST.revConcat
        AST.extract dst esize pos := value
    dh := th
    dl := tl
  }

/// vpkuhum/vpkuwum, which pack the low half of each element of vA || vB into
/// the elements of vD.
let private vecPack ins insLen bld esize =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let bytes = int esize / 8
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for i in 0 .. (32 / bytes) - 1 do
      let src = i * bytes + bytes / 2 (* the element's low half *)
      let value =
        Array.init (bytes / 2) (fun k ->
          if src + k < 16 then vecByte ah al (src + k)
          else vecByte bh bl (src + k - 16))
        |> AST.revConcat
      let b = i * (bytes / 2)
      let dst = if b < 8 then th else tl
      let pos = if b < 8 then (8 - bytes / 2 - b) * 8
                else (16 - bytes / 2 - b) * 8
      AST.extract dst (regTypeOf (int esize / 2)) pos := value
    dh := th
    dl := tl
  }

/// vupkhs*/vupkls*, which sign-extend the elements of one half of vB into the
/// wider elements of vD.
let private vecUnpack ins insLen bld esize high =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, bl) = vecHalves bld o2
    let bytes = int esize / 8
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for i in 0 .. (8 / bytes) - 1 do
      let src = (if high then 0 else 8) + i * bytes
      let value =
        Array.init bytes (fun k -> vecByte bh bl (src + k)) |> AST.revConcat
      let b = i * bytes * 2
      let dst = if b < 8 then th else tl
      let pos = if b < 8 then (8 - bytes * 2 - b) * 8
                else (16 - bytes * 2 - b) * 8
      AST.extract dst (regTypeOf (int esize * 2)) pos :=
        AST.sext (regTypeOf (int esize * 2)) value
    dh := th
    dl := tl
  }

/// vsl/vsr, which shift the whole 128-bit vector by the count the low three
/// bits of vB's last byte give, and vslo/vsro, which shift it by whole octets.
let private vecShiftWhole ins insLen (bld: ILowUIRBuilder) left byOctet =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (_, bl) = vecHalves bld o3
    let struct (th, tl) = tmpVars2 bld 64<rt>
    let n = tmpVar bld 64<rt>
    if byOctet then
      n := AST.zext 64<rt> (AST.xtlo 8<rt> bl .& numI32 0x78 8<rt>)
    else
      n := AST.zext 64<rt> (AST.xtlo 8<rt> bl .& numI32 7 8<rt>)
    (* A 128-bit shift over two halves: each half keeps what stays in it and
       takes what the other half shifts across. A count of zero would shift a
       whole half's width, which is undefined, so that case is selected out. *)
    let zero = n == AST.num0 64<rt>
    let across = numI32 64 64<rt> .- n
    if left then
      th := AST.ite zero ah ((ah << n) .| (al >> across))
      tl := al << n
    else
      th := ah >> n
      tl := AST.ite zero al ((al >> n) .| (ah << across))
    dh := th
    dl := tl
  }

/// vgbbd, which transposes the bits of each doubleword's eight bytes: bit j of
/// byte i moves to bit i of byte j.
let private vecGatherBits ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, bl) = vecHalves bld o2
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for (dst, src) in [ th, bh; tl, bl ] do
      for i in 0 .. 7 do
        for j in 0 .. 7 do
          AST.extract dst 1<rt> (j * 8 + i) :=
            AST.extract src 1<rt> (i * 8 + j)
    dh := th
    dl := tl
  }

/// vbpermq, which gathers the sixteen bits of vA that vB's byte indices name
/// into the low halfword of vD; an index past 127 contributes a zero.
let private vecBitPermute ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (ah, al) = vecHalves bld o2
    let struct (bh, bl) = vecHalves bld o3
    let res = tmpVar bld 64<rt>
    res := AST.num0 64<rt>
    for i in 0 .. 15 do
      let index = tmpVar bld 8<rt>
      index := vecByte bh bl i
      let mutable bit = AST.num0 64<rt>
      for k in 0 .. 127 do
        let src = if k < 64 then ah else al
        let pos = if k < 64 then 63 - k else 127 - k
        let one = AST.zext 64<rt> (AST.extract src 1<rt> pos)
        bit <- AST.ite (index == numI32 k 8<rt>) one bit
      res := res .| (bit << numI32 (15 - i) 64<rt>)
    dh := AST.num0 64<rt>
    dl := res
  }

/// mfvscr/mtvscr, which move the vector status register to or from the low
/// word of a vector register.
let private vscrMove ins insLen bld toVector =
  lift bld ins insLen {
    let struct (dh, dl) = vecHalves bld (getOneOpr ins)
    let vscr = regVar bld Register.VSCR
    if toVector then
      dh := AST.num0 64<rt>
      dl := AST.zext 64<rt> vscr
    else
      vscr := AST.xtlo 32<rt> dl
  }

/// Counts the leading zeroes of one element, folding the value down to a mask
/// of the bits at or below its highest set one and counting the ones in it.
let private countLeadingZerosOf (esize: RegType) e =
  let n i = numI32 i esize
  let mutable x = e
  let mutable s = 1
  while s < int esize do
    x <- x .| (x >> n s)
    s <- s * 2
  let mask1 = numU64 0x5555555555555555UL esize
  let mask2 = numU64 0x3333333333333333UL esize
  let mask3 = numU64 0x0f0f0f0f0f0f0f0fUL esize
  let mutable p = x .- ((x >> n 1) .& mask1)
  p <- ((p >> n 2) .& mask2) .+ (p .& mask2)
  p <- ((p >> n 4) .+ p) .& mask3
  let mutable s = 8
  while s < int esize do
    p <- p .+ (p >> n s)
    s <- s * 2
  n (int esize) .- (p .& n 127)

/// Counts the set bits of one element by the same halving fold.
let private popCountOf (esize: RegType) e =
  let n i = numI32 i esize
  let mask1 = numU64 0x5555555555555555UL esize
  let mask2 = numU64 0x3333333333333333UL esize
  let mask3 = numU64 0x0f0f0f0f0f0f0f0fUL esize
  let mutable p = (e .& mask1) .+ ((e >> n 1) .& mask1)
  p <- (p .& mask2) .+ ((p >> n 2) .& mask2)
  p <- (p .& mask3) .+ ((p >> n 4) .& mask3)
  let mutable s = 8
  while s < int esize do
    p <- p .+ (p >> n s)
    s <- s * 2
  p .& n 127

/// The element-wise shift a vs*b/vs*h/vs*w/vs*d takes: the count comes from the
/// low bits of the matching element of vB.
let private elementShift (esize: RegType) kind a b =
  let n = b .& numI32 (int esize - 1) esize
  match kind with
  | 0 ->
    a << n
  | 1 ->
    a >> n
  | 2 ->
    a ?>> n
  | _ ->
    let width = numI32 (int esize) esize
    (a << n) .| (a >> (width .- n)) (* a rotate, whose zero count is a no-op *)
(* The VSX scalar forms work on a double in a vector-scalar register's high
   doubleword, which is the same storage the floating-point forms use for
   VSR0-31; the low doubleword the architecture leaves undefined stays put. *)

/// An "xT, xA, xB" whose operands are the doubles in the sources' high halves.
let private vsxScalarBinary ins insLen bld fnOp =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, _) = vecHalves bld o1
    let struct (ah, _) = vecHalves bld o2
    let struct (bh, _) = vecHalves bld o3
    dh := fnOp ah bh
    setFPRF bld dh
  }

/// An "xT, xB" over the double in the source's high half.
let private vsxScalarUnary ins insLen bld fnOp =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, _) = vecHalves bld o1
    let struct (bh, _) = vecHalves bld o2
    dh := fnOp bh
  }

/// xscmpudp, which compares two doubles and reports less-than, greater-than,
/// equal and unordered in a condition-register field, as fcmpu does.
let private xscmpudp ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let crf0, crf1, crf2, crf3 =
      match o1 with
      | OprReg reg -> transCRxToExpr bld reg
      | _ -> raise InvalidOperandException
    let struct (ah, _) = vecHalves bld o2
    let struct (bh, _) = vecHalves bld o3
    let unordered = tmpVar bld 1<rt>
    unordered := IEEE754Double.isNaN ah .| IEEE754Double.isNaN bh
    crf0 := AST.ite unordered AST.b0 (AST.flt ah bh)
    crf1 := AST.ite unordered AST.b0 (AST.fgt ah bh)
    crf2 := AST.ite unordered AST.b0 (AST.eq ah bh)
    crf3 := unordered
  }

/// xxspltw, which copies one word of xB into all four words of xT.
let private xxspltw ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let struct (bh, bl) = vecHalves bld o2
    let index =
      match o3 with
      | OprImm n -> int n % 4
      | _ -> raise InvalidOperandException
    let word = tmpVar bld 32<rt>
    let struct (th, tl) = tmpVars2 bld 64<rt>
    let src = if index < 2 then bh else bl
    word := AST.extract src 32<rt> ((1 - index % 2) * 32)
    for half in [ th; tl ] do
      AST.extract half 32<rt> 0 := word
      AST.extract half 32<rt> 32 := word
    dh := th
    dl := tl
  }

/// xxspltib, which fills every byte of xT with an immediate.
let private xxspltib ins insLen bld =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let value =
      match o2 with
      | OprImm n -> numU64 n 8<rt>
      | _ -> raise InvalidOperandException
    let struct (th, tl) = tmpVars2 bld 64<rt>
    for i in 0 .. 7 do
      AST.extract th 8<rt> (i * 8) := value
      AST.extract tl 8<rt> (i * 8) := value
    dh := th
    dl := tl
  }

/// mtvsrdd, which fills both halves of xT from two general registers.
let private mtvsrdd ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (o1, o2, o3) = getThreeOprs ins
    let struct (dh, dl) = vecHalves bld o1
    let ra = transOpr bld o2
    let rb = transOpr bld o3
    dh := AST.zext 64<rt> ra
    dl := AST.zext 64<rt> rb
  }

/// mfvsrld, which reads xS's low half into a general register.
let private mfvsrld ins insLen (bld: ILowUIRBuilder) =
  lift bld ins insLen {
    let struct (o1, o2) = getTwoOprs ins
    let struct (_, sl) = vecHalves bld o1
    let ra = transOpr bld o2
    ra := AST.zext bld.RegType sl
  }

/// The double whose sign comes from one operand and magnitude from the other,
/// which is what fcpsgn and xscpsgndp both compute.
let private copySign signSrc magnitude =
  let signBit = numU64 0x8000000000000000UL 64<rt>
  (signSrc .& signBit) .| (magnitude .& AST.not signBit)

/// fcpsgn frD, frA, frB.
let private fcpsgn ins insLen bld =
  lift bld ins insLen {
    let struct (frd, fra, frb) = transThreeOprs ins bld
    frd := copySign fra frb
  }

/// Translate IR.
let translate (ins: Instruction) insLen bld =
  match ins.Opcode with
  | Op.ADD ->
    add ins insLen false false bld
  | Op.ADDdot ->
    add ins insLen true false bld
  | Op.ADDO ->
    add ins insLen false true bld
  | Op.ADDOdot ->
    add ins insLen true true bld
  | Op.ADDC ->
    addc ins insLen false false bld
  | Op.ADDCdot ->
    addc ins insLen true false bld
  | Op.ADDCO ->
    addc ins insLen false true bld
  | Op.ADDCOdot ->
    addc ins insLen true true bld
  | Op.ADDE ->
    adde ins insLen false false bld
  | Op.ADDEdot ->
    adde ins insLen true false bld
  | Op.ADDEO ->
    adde ins insLen false true bld
  | Op.ADDEOdot ->
    adde ins insLen true true bld
  | Op.ADDI ->
    addi ins insLen bld
  | Op.ADDIC ->
    addic ins insLen false bld
  | Op.ADDICdot ->
    addic ins insLen true bld
  | Op.ADDIS ->
    addis ins insLen bld
  | Op.ADDME ->
    addme ins insLen false false bld
  | Op.ADDMEdot ->
    addme ins insLen true false bld
  | Op.ADDMEO ->
    addme ins insLen false true bld
  | Op.ADDMEOdot ->
    addme ins insLen true true bld
  | Op.ADDZE ->
    addze ins insLen false false bld
  | Op.ADDZEdot ->
    addze ins insLen true false bld
  | Op.ADDZEO ->
    addze ins insLen false true bld
  | Op.ADDZEOdot ->
    addze ins insLen true true bld
  | Op.AND ->
    andx ins insLen false bld
  | Op.ANDdot ->
    andx ins insLen true bld
  | Op.ANDC ->
    andc ins insLen false bld
  | Op.ANDCdot ->
    andc ins insLen true bld
  | Op.ANDIdot ->
    andidot ins insLen bld
  | Op.ANDISdot ->
    andisdot ins insLen bld
  | Op.B ->
    b ins insLen bld false
  | Op.BA ->
    b ins insLen bld false
  | Op.BL ->
    b ins insLen bld true
  | Op.BLA ->
    b ins insLen bld true
  | Op.BC ->
    bc ins insLen bld false false
  | Op.BCA ->
    bc ins insLen bld true false
  | Op.BCL ->
    bc ins insLen bld false true
  | Op.BCLA ->
    bc ins insLen bld true true
  | Op.BCCTR ->
    bcctr ins insLen bld false
  | Op.BCCTRL ->
    bcctr ins insLen bld true
  | Op.BCLR ->
    bclr ins insLen bld false
  | Op.BCLRL ->
    bclr ins insLen bld true
  | Op.CMPI | Op.CMPL | Op.CMPLI ->
    raise InvalidOperandException (* invaild *)
  | Op.CMP ->
    cmp ins insLen bld true
  | Op.CMPW ->
    cmp ins insLen bld true
  | Op.CMPWI ->
    cmp ins insLen bld true
  | Op.CMPLW ->
    cmpl ins insLen bld true
  | Op.CMPLWI ->
    cmpl ins insLen bld true
  | Op.CMPD ->
    cmp ins insLen bld false
  | Op.CMPDI ->
    cmp ins insLen bld false
  | Op.CMPLD ->
    cmpl ins insLen bld false
  | Op.CMPLDI ->
    cmpl ins insLen bld false
  | Op.CMPB ->
    cmpb ins insLen bld
  | Op.CNTLZW ->
    cntlzw ins insLen false bld
  | Op.CNTLZWdot ->
    cntlzw ins insLen true bld
  | Op.CNTLZD ->
    cntlzd ins insLen false bld
  | Op.CNTLZDdot ->
    cntlzd ins insLen true bld
  | Op.CRCLR ->
    crclr ins insLen bld
  | Op.CREQV ->
    creqv ins insLen bld
  | Op.CRXOR ->
    crxor ins insLen bld
  | Op.CROR ->
    cror ins insLen bld
  | Op.CRORC ->
    crorc ins insLen bld
  | Op.CRSET ->
    crset ins insLen bld
  | Op.CRNOR ->
    crnor ins insLen bld
  | Op.CRNOT ->
    crnot ins insLen bld
  | Op.CRAND ->
    crand ins insLen bld
  | Op.CRANDC ->
    crandc ins insLen bld
  | Op.CRNAND ->
    crnand ins insLen bld
  | Op.CRMOVE ->
    crmove ins insLen bld
  (* The cache-management forms are hints about a cache BRemu does not model, so
     they leave no trace; dcbz below is the exception, as it clears storage. *)
  | Op.DCBT | Op.DCBTST | Op.DCBA | Op.DCBST | Op.DCBF | Op.DCBI | Op.ICBI ->
    nop ins insLen bld
  | Op.DCBZ ->
    dcbz ins insLen bld
  | Op.DIVW ->
    divw ins insLen false false bld
  | Op.DIVWdot ->
    divw ins insLen true false bld
  | Op.DIVWO ->
    divw ins insLen false true bld
  | Op.DIVWOdot ->
    divw ins insLen true true bld
  | Op.DIVWU ->
    divwu ins insLen false false bld
  | Op.DIVWUdot ->
    divwu ins insLen true false bld
  | Op.DIVWUO ->
    divwu ins insLen false true bld
  | Op.DIVWUOdot ->
    divwu ins insLen true true bld
  | Op.EXTSB ->
    extsb ins insLen false bld
  | Op.EXTSBdot ->
    extsb ins insLen true bld
  | Op.EXTSH ->
    extsh ins insLen false bld
  | Op.EXTSHdot ->
    extsh ins insLen true bld
  | Op.EIEIO ->
    nop ins insLen bld
  | Op.EQV ->
    eqvx ins insLen false bld
  | Op.EQVdot ->
    eqvx ins insLen true bld
  | Op.FABS ->
    fabs ins insLen false bld
  | Op.FABSdot ->
    fabs ins insLen true bld
  | Op.FADD ->
    fadd ins insLen false true bld
  | Op.FADDS ->
    fadd ins insLen false false bld
  | Op.FADDdot ->
    fadd ins insLen true true bld
  | Op.FADDSdot ->
    fadd ins insLen true false bld
  | Op.FCTIW ->
    fctiw ins insLen false bld
  | Op.FCTIWdot ->
    fctiw ins insLen true bld
  | Op.FCTIWZ ->
    fctiwz ins insLen false bld
  | Op.FCTIWZdot ->
    fctiwz ins insLen true bld
  | Op.FCMPO ->
    fcmpo ins insLen bld
  | Op.FCMPU ->
    fcmpu ins insLen bld
  | Op.FDIV ->
    fdiv ins insLen false true bld
  | Op.FDIVS ->
    fdiv ins insLen false false bld
  | Op.FDIVdot ->
    fdiv ins insLen true true bld
  | Op.FDIVSdot ->
    fdiv ins insLen true false bld
  | Op.FRSP ->
    frsp ins insLen false bld
  | Op.FRSPdot ->
    frsp ins insLen true bld
  | Op.FMADD ->
    fmadd ins insLen false true bld
  | Op.FMADDS ->
    fmadd ins insLen false false bld
  | Op.FMADDdot ->
    fmadd ins insLen true true bld
  | Op.FMADDSdot ->
    fmadd ins insLen true false bld
  | Op.FMR ->
    fmr ins insLen false bld
  | Op.FMRdot ->
    fmr ins insLen true bld
  | Op.FMSUB ->
    fmsub ins insLen false true bld
  | Op.FMSUBS ->
    fmsub ins insLen false false bld
  | Op.FMSUBdot ->
    fmsub ins insLen true true bld
  | Op.FMSUBSdot ->
    fmsub ins insLen true false bld
  | Op.FMUL ->
    fmul ins insLen false true bld
  | Op.FMULS ->
    fmul ins insLen false false bld
  | Op.FMULdot ->
    fmul ins insLen true true bld
  | Op.FMULSdot ->
    fmul ins insLen true false bld
  | Op.FNABS ->
    fnabs ins insLen false bld
  | Op.FNABSdot ->
    fnabs ins insLen true bld
  | Op.FNEG ->
    fneg ins insLen false bld
  | Op.FNEGdot ->
    fneg ins insLen true bld
  | Op.FNMADD ->
    fnmadd ins insLen false true bld
  | Op.FNMADDdot ->
    fnmadd ins insLen true true bld
  | Op.FNMADDS ->
    fnmadd ins insLen false false bld
  | Op.FNMADDSdot ->
    fnmadd ins insLen true false bld
  | Op.FNMSUB ->
    fnmsub ins insLen false true bld
  | Op.FNMSUBdot ->
    fnmsub ins insLen true true bld
  | Op.FNMSUBS ->
    fnmsub ins insLen false false bld
  | Op.FNMSUBSdot ->
    fnmsub ins insLen true false bld
  | Op.FSEL ->
    fsel ins insLen false bld
  | Op.FSELdot ->
    fsel ins insLen true bld
  | Op.FSUB ->
    fsub ins insLen false true bld
  | Op.FSUBS ->
    fsub ins insLen false false bld
  | Op.FSUBdot ->
    fsub ins insLen true true bld
  | Op.FSUBSdot ->
    fsub ins insLen true false bld
  | Op.FSQRT ->
    fsqrt ins insLen false true bld
  | Op.FSQRTS ->
    fsqrt ins insLen false false bld
  | Op.FSQRTdot ->
    fsqrt ins insLen true true bld
  | Op.FSQRTSdot ->
    fsqrt ins insLen true false bld
  | Op.ISYNC | Op.LWSYNC | Op.SYNC ->
    nop ins insLen bld
  | Op.LBZ ->
    lbz ins insLen bld
  | Op.LBZU ->
    lbzu ins insLen bld
  | Op.LBZUX ->
    lbzux ins insLen bld
  | Op.LBZX ->
    lbzx ins insLen bld
  | Op.LFD ->
    lfd ins insLen bld
  | Op.LFDU ->
    lfdu ins insLen bld
  | Op.LFDUX ->
    lfdux ins insLen bld
  | Op.LFDX ->
    lfdx ins insLen bld
  | Op.LFS ->
    lfs ins insLen bld
  | Op.LFSU ->
    lfsu ins insLen bld
  | Op.LFSUX ->
    lfsux ins insLen bld
  | Op.LFSX ->
    lfsx ins insLen bld
  | Op.LHA ->
    lha ins insLen bld
  | Op.LHAU ->
    lhau ins insLen bld
  | Op.LHAUX ->
    lhaux ins insLen bld
  | Op.LHAX ->
    lhax ins insLen bld
  | Op.LHBRX ->
    lhbrx ins insLen bld
  | Op.LHZ ->
    lhz ins insLen bld
  | Op.LHZU ->
    lhzu ins insLen bld
  | Op.LHZUX ->
    lhzux ins insLen bld
  | Op.LHZX ->
    lhzx ins insLen bld
  | Op.LI ->
    li ins insLen bld
  | Op.LIS ->
    lis ins insLen bld
  | Op.LWARX ->
    lwarx ins insLen bld
  | Op.LWBRX ->
    lwbrx ins insLen bld
  | Op.LWZ ->
    lwz ins insLen bld
  | Op.LWZU ->
    lwzu ins insLen bld
  | Op.LWZUX ->
    lwzux ins insLen bld
  | Op.LWZX ->
    lwzx ins insLen bld
  | Op.MCRF ->
    mcrf ins insLen bld
  | Op.MCRXR ->
    mcrxr ins insLen bld
  | Op.MFCR ->
    mfcr ins insLen bld
  | Op.MFSPR ->
    mfspr ins insLen bld
  | Op.MFTB ->
    mftb ins insLen bld
  | Op.MFTBU ->
    mftbu ins insLen bld
  | Op.MFCTR ->
    mfctr ins insLen bld
  | Op.MFFS ->
    mffs ins insLen bld
  | Op.MFLR ->
    mflr ins insLen bld
  | Op.MFXER ->
    mfxer ins insLen bld
  | Op.MR ->
    mr ins insLen bld
  | Op.MTCTR ->
    mtctr ins insLen bld
  | Op.MTCRF ->
    mtcrf ins insLen bld
  | Op.MTFSFI ->
    mtfsfi ins insLen false bld
  | Op.MTFSFIdot ->
    mtfsfi ins insLen true bld
  | Op.MTSPR ->
    mtspr ins insLen bld
  | Op.MTFSB0 ->
    mtfsb0 ins insLen false bld
  | Op.MTFSB0dot ->
    mtfsb0 ins insLen true bld
  | Op.MTFSB1 ->
    mtfsb1 ins insLen false bld
  | Op.MTFSB1dot ->
    mtfsb1 ins insLen true bld
  | Op.MTFSF ->
    mtfsf ins insLen bld
  | Op.MTLR ->
    mtlr ins insLen bld
  | Op.MTXER ->
    mtxer ins insLen bld
  | Op.MULHW ->
    mulhw ins insLen false bld
  | Op.MULHWU ->
    mulhwu ins insLen false bld
  | Op.MULHWUdot ->
    mulhwu ins insLen true bld
  | Op.MULLI ->
    mulli ins insLen bld
  | Op.MULLW ->
    mullw ins insLen false false bld
  | Op.MULLWdot ->
    mullw ins insLen true false bld
  | Op.MULLWO ->
    mullw ins insLen false true bld
  | Op.MULLWOdot ->
    mullw ins insLen true true bld
  | Op.NAND ->
    nand ins insLen false bld
  | Op.NANDdot ->
    nand ins insLen true bld
  | Op.NEG ->
    neg ins insLen false false bld
  | Op.NEGdot ->
    neg ins insLen true false bld
  | Op.NEGO ->
    neg ins insLen false true bld
  | Op.NEGOdot ->
    neg ins insLen true true bld
  | Op.NOR ->
    nor ins insLen false bld
  | Op.NORdot ->
    nor ins insLen true bld
  | Op.NOP ->
    nop ins insLen bld
  | Op.ORC ->
    orc ins insLen false bld
  | Op.ORCdot ->
    orc ins insLen true bld
  | Op.OR ->
    orx ins insLen false bld
  | Op.ORdot ->
    orx ins insLen true bld
  | Op.ORI ->
    ori ins insLen bld
  | Op.ORIS ->
    oris ins insLen bld
  | Op.RLWIMI ->
    rlwimi ins insLen false bld
  | Op.RLWIMIdot ->
    rlwimi ins insLen true bld
  | Op.RLWINM ->
    rlwinm ins insLen false bld
  | Op.RLWINMdot ->
    rlwinm ins insLen true bld
  | Op.RLWNM ->
    rlwnm ins insLen false bld
  | Op.RLWNMdot ->
    rlwnm ins insLen true bld
  | Op.ROTLW ->
    rotlw ins insLen bld
  | Op.SC ->
    sideEffects ins insLen bld SysCall
  | Op.SLW ->
    slw ins insLen false bld
  | Op.SLWdot ->
    slw ins insLen true bld
  | Op.SRAW ->
    sraw ins insLen false bld
  | Op.SRAWdot ->
    sraw ins insLen true bld
  | Op.SRAWI ->
    srawi ins insLen false bld
  | Op.SRAWIdot ->
    srawi ins insLen true bld
  | Op.SRW ->
    srw ins insLen false bld
  | Op.SRWdot ->
    srw ins insLen true bld
  | Op.STB ->
    stb ins insLen bld
  | Op.STBU ->
    stbu ins insLen bld
  | Op.STBX ->
    stbx ins insLen bld
  | Op.STBUX ->
    stbux ins insLen bld
  | Op.STFD ->
    stfd ins insLen bld
  | Op.STFDX ->
    stfdx ins insLen bld
  | Op.STFDU ->
    stfdu ins insLen bld
  | Op.STFDUX ->
    stfdux ins insLen bld
  | Op.STFIWX ->
    stfiwx ins insLen bld
  | Op.STFS ->
    stfs ins insLen bld
  | Op.STFSX ->
    stfsx ins insLen bld
  | Op.STFSU ->
    stfsu ins insLen bld
  | Op.STFSUX ->
    stfsux ins insLen bld
  | Op.STH ->
    sth ins insLen bld
  | Op.STHBRX ->
    sthbrx ins insLen bld
  | Op.STHU ->
    sthu ins insLen bld
  | Op.STHX ->
    sthx ins insLen bld
  | Op.STHUX ->
    sthux ins insLen bld
  | Op.STW ->
    stw ins insLen bld
  | Op.LMW ->
    lmw ins insLen bld
  | Op.STMW ->
    stmw ins insLen bld
  | Op.STWBRX ->
    stwbrx ins insLen bld
  | Op.STWCXdot ->
    stwcxdot ins insLen bld
  | Op.STWU ->
    stwu ins insLen bld
  | Op.STWUX ->
    stwux ins insLen bld
  | Op.STWX ->
    stwx ins insLen bld
  | Op.SUBF ->
    subf ins insLen false false bld
  | Op.SUBFdot ->
    subf ins insLen true false bld
  | Op.SUBFO ->
    subf ins insLen false true bld
  | Op.SUBFOdot ->
    subf ins insLen true true bld
  | Op.SUBFC ->
    subfc ins insLen false false bld
  | Op.SUBFCdot ->
    subfc ins insLen true false bld
  | Op.SUBFCO ->
    subfc ins insLen false true bld
  | Op.SUBFCOdot ->
    subfc ins insLen true true bld
  | Op.SUBFE ->
    subfe ins insLen false false bld
  | Op.SUBFEdot ->
    subfe ins insLen true false bld
  | Op.SUBFEO ->
    subfe ins insLen false true bld
  | Op.SUBFEOdot ->
    subfe ins insLen true true bld
  | Op.SUBFIC ->
    subfic ins insLen bld
  | Op.SUBFME ->
    subfme ins insLen false false bld
  | Op.SUBFMEdot ->
    subfme ins insLen true false bld
  | Op.SUBFMEO ->
    subfme ins insLen false true bld
  | Op.SUBFMEOdot ->
    subfme ins insLen true true bld
  | Op.SUBFZE ->
    subfze ins insLen false false bld
  | Op.SUBFZEdot ->
    subfze ins insLen true false bld
  | Op.SUBFZEO ->
    subfze ins insLen false true bld
  | Op.SUBFZEOdot ->
    subfze ins insLen true true bld
  | Op.TRAP | Op.TWI ->
    trap ins insLen bld
  | Op.TWLT ->
    trapCond ins insLen (AST.slt) bld
  | Op.TWLE ->
    trapCond ins insLen (AST.sle) bld
  | Op.TWEQ ->
    trapCond ins insLen (AST.eq) bld
  | Op.TWGE ->
    trapCond ins insLen (AST.sge) bld
  | Op.TWGT ->
    trapCond ins insLen (AST.sgt) bld
  | Op.TWNE ->
    trapCond ins insLen (AST.neq) bld
  | Op.TWLLT ->
    trapCond ins insLen (AST.lt) bld
  | Op.TWLLE ->
    trapCond ins insLen (AST.le) bld
  | Op.TWLNL ->
    trapCond ins insLen (AST.ge) bld
  | Op.TWLGT ->
    trapCond ins insLen (AST.gt) bld
  | Op.TWLTI ->
    trapCond ins insLen (AST.slt) bld
  | Op.TWLEI ->
    trapCond ins insLen (AST.sle) bld
  | Op.TWEQI ->
    trapCond ins insLen (AST.eq) bld
  | Op.TWGEI ->
    trapCond ins insLen (AST.sge) bld
  | Op.TWGTI ->
    trapCond ins insLen (AST.sgt) bld
  | Op.TWNEI ->
    trapCond ins insLen (AST.neq) bld
  | Op.TWLLTI ->
    trapCond ins insLen (AST.lt) bld
  | Op.TWLLEI ->
    trapCond ins insLen (AST.le) bld
  | Op.TWLNLI ->
    trapCond ins insLen (AST.ge) bld
  | Op.TWLGTI ->
    trapCond ins insLen (AST.gt) bld
  | Op.XOR ->
    xor ins insLen false bld
  | Op.XORdot ->
    xor ins insLen true bld
  | Op.XORI ->
    xori ins insLen bld
  | Op.XORIS ->
    xoris ins insLen bld
  (* 64-bit forms. *)
  | Op.LD ->
    ld ins insLen bld
  | Op.LDU ->
    ldu ins insLen bld
  | Op.LDX ->
    ldx ins insLen bld
  | Op.LDUX ->
    ldux ins insLen bld
  | Op.LDARX ->
    ldarx ins insLen bld
  | Op.LBARX ->
    lbarx ins insLen bld
  | Op.LHARX ->
    lharx ins insLen bld
  | Op.LDBRX ->
    ldbrx ins insLen bld
  | Op.LWA ->
    lwa ins insLen bld
  | Op.LWAX ->
    lwax ins insLen bld
  | Op.LWAUX ->
    lwaux ins insLen bld
  | Op.STD ->
    std ins insLen bld
  | Op.STDU ->
    stdu ins insLen bld
  | Op.STDX ->
    stdx ins insLen bld
  | Op.STDUX ->
    stdux ins insLen bld
  | Op.STDBRX ->
    stdbrx ins insLen bld
  | Op.STDCXdot ->
    stdcxdot ins insLen bld
  | Op.STBCXdot ->
    stbcxdot ins insLen bld
  | Op.STHCXdot ->
    sthcxdot ins insLen bld
  | Op.RLDICL ->
    rldicl ins insLen false bld
  | Op.RLDICLdot ->
    rldicl ins insLen true bld
  | Op.RLDICR ->
    rldicr ins insLen false bld
  | Op.RLDICRdot ->
    rldicr ins insLen true bld
  | Op.RLDIC ->
    rldic ins insLen false bld
  | Op.RLDICdot ->
    rldic ins insLen true bld
  | Op.RLDIMI ->
    rldimi ins insLen false bld
  | Op.RLDIMIdot ->
    rldimi ins insLen true bld
  | Op.RLDCL ->
    rldcl ins insLen false bld
  | Op.RLDCLdot ->
    rldcl ins insLen true bld
  | Op.RLDCR ->
    rldcr ins insLen false bld
  | Op.RLDCRdot ->
    rldcr ins insLen true bld
  | Op.SLD ->
    sld ins insLen false bld
  | Op.SLDdot ->
    sld ins insLen true bld
  | Op.SRD ->
    srd ins insLen false bld
  | Op.SRDdot ->
    srd ins insLen true bld
  | Op.SRAD ->
    srad ins insLen false bld
  | Op.SRADdot ->
    srad ins insLen true bld
  | Op.SRADI ->
    sradi ins insLen false bld
  | Op.SRADIdot ->
    sradi ins insLen true bld
  | Op.EXTSW ->
    extsw ins insLen false bld
  | Op.EXTSWdot ->
    extsw ins insLen true bld
  | Op.MULLD ->
    mulld ins insLen false false bld
  | Op.MULLDdot ->
    mulld ins insLen true false bld
  | Op.MULLDO ->
    mulld ins insLen false true bld
  | Op.MULLDOdot ->
    mulld ins insLen true true bld
  | Op.MULHD ->
    mulhd ins insLen false bld
  | Op.MULHDdot ->
    mulhd ins insLen true bld
  | Op.MULHDU ->
    mulhdu ins insLen false bld
  | Op.MULHDUdot ->
    mulhdu ins insLen true bld
  | Op.DIVD ->
    divd ins insLen false false bld
  | Op.DIVDdot ->
    divd ins insLen true false bld
  | Op.DIVDO ->
    divd ins insLen false true bld
  | Op.DIVDOdot ->
    divd ins insLen true true bld
  | Op.DIVDU ->
    divdu ins insLen false false bld
  | Op.DIVDUdot ->
    divdu ins insLen true false bld
  | Op.DIVDUO ->
    divdu ins insLen false true bld
  | Op.DIVDUOdot ->
    divdu ins insLen true true bld
  | Op.POPCNTB ->
    popcnt ins insLen bld 8
  | Op.POPCNTW ->
    popcnt ins insLen bld 32
  | Op.POPCNTD ->
    popcnt ins insLen bld 64
  | Op.PRTYW ->
    prty ins insLen bld 32
  | Op.PRTYD ->
    prty ins insLen bld 64
  | Op.BPERMD ->
    bpermd ins insLen bld
  | Op.ISEL ->
    isel ins insLen bld
  | Op.MTOCRF ->
    mtcrf ins insLen bld
  | Op.MFOCRF ->
    mfcr ins insLen bld
  | Op.MFVSRD ->
    mfvsr ins insLen bld 64<rt>
  | Op.MFVSRWZ ->
    mfvsr ins insLen bld 32<rt>
  | Op.MTVSRD ->
    mtvsrd ins insLen bld
  | Op.MTVSRWA ->
    mtvsrw ins insLen bld true
  | Op.MTVSRWZ ->
    mtvsrw ins insLen bld false
  | Op.TD ->
    trapGeneric ins insLen bld false
  | Op.TDI ->
    trapGeneric ins insLen bld false
  | Op.TW ->
    trapGeneric ins insLen bld true
  | Op.FCTID ->
    fcti ins insLen false bld 64<rt> false
  | Op.FCTIDdot ->
    fcti ins insLen true bld 64<rt> false
  | Op.FCTIDZ ->
    fcti ins insLen false bld 64<rt> true
  | Op.FCTIDZdot ->
    fcti ins insLen true bld 64<rt> true
  | Op.FCTIDU ->
    fcti ins insLen false bld 64<rt> false
  | Op.FCTIDUdot ->
    fcti ins insLen true bld 64<rt> false
  | Op.FCTIDUZ ->
    fcti ins insLen false bld 64<rt> true
  | Op.FCTIDUZdot ->
    fcti ins insLen true bld 64<rt> true
  | Op.FCTIWU ->
    fcti ins insLen false bld 32<rt> false
  | Op.FCTIWUdot ->
    fcti ins insLen true bld 32<rt> false
  | Op.FCTIWUZ ->
    fcti ins insLen false bld 32<rt> true
  | Op.FCTIWUZdot ->
    fcti ins insLen true bld 32<rt> true
  | Op.FCFID ->
    fcfid ins insLen false bld true false
  | Op.FCFIDdot ->
    fcfid ins insLen true bld true false
  | Op.FCFIDU ->
    fcfid ins insLen false bld false false
  | Op.FCFIDUdot ->
    fcfid ins insLen true bld false false
  | Op.FCFIDS ->
    fcfid ins insLen false bld true true
  | Op.FCFIDSdot ->
    fcfid ins insLen true bld true true
  | Op.FCFIDUS ->
    fcfid ins insLen false bld false true
  | Op.FCFIDUSdot ->
    fcfid ins insLen true bld false true
  | Op.FRIN ->
    frnd ins insLen false bld CastKind.FtoFRound
  | Op.FRINdot ->
    frnd ins insLen true bld CastKind.FtoFRound
  | Op.FRIZ ->
    frnd ins insLen false bld CastKind.FtoFTrunc
  | Op.FRIZdot ->
    frnd ins insLen true bld CastKind.FtoFTrunc
  | Op.FRIP ->
    frnd ins insLen false bld CastKind.FtoFCeil
  | Op.FRIPdot ->
    frnd ins insLen true bld CastKind.FtoFCeil
  | Op.FRIM ->
    frnd ins insLen false bld CastKind.FtoFFloor
  | Op.FRIMdot ->
    frnd ins insLen true bld CastKind.FtoFFloor
  (* Vector forms. *)
  | Op.LVX | Op.LVXL ->
    lvx ins insLen bld
  | Op.STVX | Op.STVXL ->
    stvx ins insLen bld
  | Op.LVSL ->
    lvsx ins insLen bld true
  | Op.LVSR ->
    lvsx ins insLen bld false
  | Op.LVEBX ->
    lvex ins insLen bld 8<rt>
  | Op.LVEHX ->
    lvex ins insLen bld 16<rt>
  | Op.LVEWX ->
    lvex ins insLen bld 32<rt>
  | Op.STVEBX ->
    stvex ins insLen bld 8<rt>
  | Op.STVEHX ->
    stvex ins insLen bld 16<rt>
  | Op.STVEWX ->
    stvex ins insLen bld 32<rt>
  | Op.LXVD2X ->
    lxvx ins insLen bld 64<rt> true
  | Op.STXVD2X ->
    lxvx ins insLen bld 64<rt> false
  | Op.LXVW4X ->
    lxvx ins insLen bld 32<rt> true
  | Op.STXVW4X ->
    lxvx ins insLen bld 32<rt> false
  | Op.LXSDX ->
    lxsdx ins insLen bld false true
  | Op.LXVDSX ->
    lxsdx ins insLen bld true true
  | Op.STXSDX ->
    lxsdx ins insLen bld false false
  | Op.VAND | Op.XXLAND ->
    vecLogical ins insLen bld (.&)
  | Op.VOR | Op.XXLOR ->
    vecLogical ins insLen bld (.|)
  | Op.VXOR | Op.XXLXOR ->
    vecLogical ins insLen bld (<+>)
  | Op.VANDC | Op.XXLANDC ->
    vecLogical ins insLen bld (fun a b -> a .& AST.not b)
  | Op.VORC | Op.XXLORC ->
    vecLogical ins insLen bld (fun a b -> a .| AST.not b)
  | Op.VNOR | Op.XXLNOR ->
    vecLogical ins insLen bld (fun a b -> AST.not (a .| b))
  | Op.VNAND | Op.XXLNAND ->
    vecLogical ins insLen bld (fun a b -> AST.not (a .& b))
  | Op.VEQV | Op.XXLEQV ->
    vecLogical ins insLen bld (fun a b -> AST.not (a <+> b))
  | Op.VSEL ->
    vecSelect ins insLen bld
  | Op.VPERM ->
    vecPermute ins insLen bld
  | Op.XXPERMDI ->
    vecPermuteDouble ins insLen bld
  | Op.XXSPLTW ->
    xxspltw ins insLen bld
  | Op.XXSPLTIB ->
    xxspltib ins insLen bld
  | Op.MTVSRDD ->
    mtvsrdd ins insLen bld
  | Op.MFVSRLD ->
    mfvsrld ins insLen bld
  | Op.FCPSGN ->
    fcpsgn ins insLen bld
  | Op.MFFSL ->
    mffs ins insLen bld
  | Op.XSADDDP ->
    vsxScalarBinary ins insLen bld AST.fadd
  | Op.XSSUBDP ->
    vsxScalarBinary ins insLen bld AST.fsub
  | Op.XSDIVDP ->
    vsxScalarBinary ins insLen bld AST.fdiv
  | Op.XSCPSGNDP ->
    vsxScalarBinary ins insLen bld copySign
  | Op.XSCMPUDP ->
    xscmpudp ins insLen bld
  | Op.XSABSDP ->
    vsxScalarUnary ins insLen bld (fun b ->
      b .& numU64 0x7fffffffffffffffUL 64<rt>)
  | Op.XSRSP ->
    (* Rounding a double to single precision and keeping it in double format. *)
    vsxScalarUnary ins insLen bld (fun b ->
      AST.cast CastKind.FloatCast 64<rt> (AST.cast CastKind.FloatCast 32<rt> b))
  | Op.XSCVDPSPN ->
    vsxScalarUnary ins insLen bld (fun b ->
      AST.concat (AST.cast CastKind.FloatCast 32<rt> b) (AST.num0 32<rt>))
  | Op.XSCVSPDPN ->
    vsxScalarUnary ins insLen bld (fun b ->
      AST.cast CastKind.FloatCast 64<rt> (AST.xthi 32<rt> b))
  | Op.VSLDOI ->
    vecShiftDouble ins insLen bld 1
  | Op.XXSLDWI ->
    vecShiftDouble ins insLen bld 4
  | Op.VSPLTB ->
    vecSplat ins insLen bld 8<rt>
  | Op.VSPLTH ->
    vecSplat ins insLen bld 16<rt>
  | Op.VSPLTW ->
    vecSplat ins insLen bld 32<rt>
  | Op.VSPLTISB ->
    vecSplatImm ins insLen bld 8<rt>
  | Op.VSPLTISH ->
    vecSplatImm ins insLen bld 16<rt>
  | Op.VSPLTISW ->
    vecSplatImm ins insLen bld 32<rt>
  | Op.VMRGHB ->
    vecMerge ins insLen bld 8<rt> true
  | Op.VMRGHH ->
    vecMerge ins insLen bld 16<rt> true
  | Op.VMRGHW ->
    vecMerge ins insLen bld 32<rt> true
  | Op.VMRGLB ->
    vecMerge ins insLen bld 8<rt> false
  | Op.VMRGLH ->
    vecMerge ins insLen bld 16<rt> false
  | Op.VMRGLW ->
    vecMerge ins insLen bld 32<rt> false
  | Op.VPKUHUM ->
    vecPack ins insLen bld 16<rt>
  | Op.VPKUWUM ->
    vecPack ins insLen bld 32<rt>
  | Op.VUPKHSB ->
    vecUnpack ins insLen bld 8<rt> true
  | Op.VUPKHSH ->
    vecUnpack ins insLen bld 16<rt> true
  | Op.VUPKLSB ->
    vecUnpack ins insLen bld 8<rt> false
  | Op.VUPKLSH ->
    vecUnpack ins insLen bld 16<rt> false
  | Op.VSL ->
    vecShiftWhole ins insLen bld true false
  | Op.VSR ->
    vecShiftWhole ins insLen bld false false
  | Op.VSLO ->
    vecShiftWhole ins insLen bld true true
  | Op.VSRO ->
    vecShiftWhole ins insLen bld false true
  | Op.VGBBD ->
    vecGatherBits ins insLen bld
  | Op.VBPERMQ ->
    vecBitPermute ins insLen bld
  | Op.MFVSCR ->
    vscrMove ins insLen bld true
  | Op.MTVSCR ->
    vscrMove ins insLen bld false
  | Op.VADDUBM ->
    vecBinary ins insLen bld 8<rt> (.+)
  | Op.VADDUHM ->
    vecBinary ins insLen bld 16<rt> (.+)
  | Op.VADDUWM ->
    vecBinary ins insLen bld 32<rt> (.+)
  | Op.VADDUDM ->
    vecBinary ins insLen bld 64<rt> (.+)
  | Op.VSUBUBM ->
    vecBinary ins insLen bld 8<rt> (.-)
  | Op.VSUBUHM ->
    vecBinary ins insLen bld 16<rt> (.-)
  | Op.VSUBUWM ->
    vecBinary ins insLen bld 32<rt> (.-)
  | Op.VSUBUDM ->
    vecBinary ins insLen bld 64<rt> (.-)
  | Op.VSLB ->
    vecBinary ins insLen bld 8<rt> (elementShift 8<rt> 0)
  | Op.VSLH ->
    vecBinary ins insLen bld 16<rt> (elementShift 16<rt> 0)
  | Op.VSLW ->
    vecBinary ins insLen bld 32<rt> (elementShift 32<rt> 0)
  | Op.VSLD ->
    vecBinary ins insLen bld 64<rt> (elementShift 64<rt> 0)
  | Op.VSRB ->
    vecBinary ins insLen bld 8<rt> (elementShift 8<rt> 1)
  | Op.VSRH ->
    vecBinary ins insLen bld 16<rt> (elementShift 16<rt> 1)
  | Op.VSRW ->
    vecBinary ins insLen bld 32<rt> (elementShift 32<rt> 1)
  | Op.VSRD ->
    vecBinary ins insLen bld 64<rt> (elementShift 64<rt> 1)
  | Op.VSRAB ->
    vecBinary ins insLen bld 8<rt> (elementShift 8<rt> 2)
  | Op.VSRAH ->
    vecBinary ins insLen bld 16<rt> (elementShift 16<rt> 2)
  | Op.VSRAW ->
    vecBinary ins insLen bld 32<rt> (elementShift 32<rt> 2)
  | Op.VSRAD ->
    vecBinary ins insLen bld 64<rt> (elementShift 64<rt> 2)
  | Op.VRLB ->
    vecBinary ins insLen bld 8<rt> (elementShift 8<rt> 3)
  | Op.VRLH ->
    vecBinary ins insLen bld 16<rt> (elementShift 16<rt> 3)
  | Op.VRLW ->
    vecBinary ins insLen bld 32<rt> (elementShift 32<rt> 3)
  | Op.VRLD ->
    vecBinary ins insLen bld 64<rt> (elementShift 64<rt> 3)
  | Op.VMAXUB ->
    vecBinary ins insLen bld 8<rt> (fun a b -> AST.ite (a .> b) a b)
  | Op.VMAXUH ->
    vecBinary ins insLen bld 16<rt> (fun a b -> AST.ite (a .> b) a b)
  | Op.VMAXUW ->
    vecBinary ins insLen bld 32<rt> (fun a b -> AST.ite (a .> b) a b)
  | Op.VMAXUD ->
    vecBinary ins insLen bld 64<rt> (fun a b -> AST.ite (a .> b) a b)
  | Op.VMINUB ->
    vecBinary ins insLen bld 8<rt> (fun a b -> AST.ite (a .< b) a b)
  | Op.VMINUH ->
    vecBinary ins insLen bld 16<rt> (fun a b -> AST.ite (a .< b) a b)
  | Op.VMINUW ->
    vecBinary ins insLen bld 32<rt> (fun a b -> AST.ite (a .< b) a b)
  | Op.VMINUD ->
    vecBinary ins insLen bld 64<rt> (fun a b -> AST.ite (a .< b) a b)
  | Op.VMAXSB ->
    vecBinary ins insLen bld 8<rt> (fun a b -> AST.ite (a ?> b) a b)
  | Op.VMAXSH ->
    vecBinary ins insLen bld 16<rt> (fun a b -> AST.ite (a ?> b) a b)
  | Op.VMAXSW ->
    vecBinary ins insLen bld 32<rt> (fun a b -> AST.ite (a ?> b) a b)
  | Op.VMAXSD ->
    vecBinary ins insLen bld 64<rt> (fun a b -> AST.ite (a ?> b) a b)
  | Op.VMINSB ->
    vecBinary ins insLen bld 8<rt> (fun a b -> AST.ite (a ?< b) a b)
  | Op.VMINSH ->
    vecBinary ins insLen bld 16<rt> (fun a b -> AST.ite (a ?< b) a b)
  | Op.VMINSW ->
    vecBinary ins insLen bld 32<rt> (fun a b -> AST.ite (a ?< b) a b)
  | Op.VMINSD ->
    vecBinary ins insLen bld 64<rt> (fun a b -> AST.ite (a ?< b) a b)
  | Op.VCLZB ->
    vecUnary ins insLen bld 8<rt> (countLeadingZerosOf 8<rt>)
  | Op.VCLZH ->
    vecUnary ins insLen bld 16<rt> (countLeadingZerosOf 16<rt>)
  | Op.VCLZW ->
    vecUnary ins insLen bld 32<rt> (countLeadingZerosOf 32<rt>)
  | Op.VCLZD ->
    vecUnary ins insLen bld 64<rt> (countLeadingZerosOf 64<rt>)
  | Op.VPOPCNTB ->
    vecUnary ins insLen bld 8<rt> (popCountOf 8<rt>)
  | Op.VPOPCNTH ->
    vecUnary ins insLen bld 16<rt> (popCountOf 16<rt>)
  | Op.VPOPCNTW ->
    vecUnary ins insLen bld 32<rt> (popCountOf 32<rt>)
  | Op.VPOPCNTD ->
    vecUnary ins insLen bld 64<rt> (popCountOf 64<rt>)
  | Op.VCMPEQUB ->
    vecCompare ins insLen bld 8<rt> (==) false
  | Op.VCMPEQUBdot ->
    vecCompare ins insLen bld 8<rt> (==) true
  | Op.VCMPEQUH ->
    vecCompare ins insLen bld 16<rt> (==) false
  | Op.VCMPEQUHdot ->
    vecCompare ins insLen bld 16<rt> (==) true
  | Op.VCMPEQUW ->
    vecCompare ins insLen bld 32<rt> (==) false
  | Op.VCMPEQUWdot ->
    vecCompare ins insLen bld 32<rt> (==) true
  | Op.VCMPEQUD ->
    vecCompare ins insLen bld 64<rt> (==) false
  | Op.VCMPEQUDdot ->
    vecCompare ins insLen bld 64<rt> (==) true
  | Op.VCMPGTUB ->
    vecCompare ins insLen bld 8<rt> (.>) false
  | Op.VCMPGTUBdot ->
    vecCompare ins insLen bld 8<rt> (.>) true
  | Op.VCMPGTUH ->
    vecCompare ins insLen bld 16<rt> (.>) false
  | Op.VCMPGTUHdot ->
    vecCompare ins insLen bld 16<rt> (.>) true
  | Op.VCMPGTUW ->
    vecCompare ins insLen bld 32<rt> (.>) false
  | Op.VCMPGTUWdot ->
    vecCompare ins insLen bld 32<rt> (.>) true
  | Op.VCMPGTUD ->
    vecCompare ins insLen bld 64<rt> (.>) false
  | Op.VCMPGTUDdot ->
    vecCompare ins insLen bld 64<rt> (.>) true
  | Op.VCMPGTSB ->
    vecCompare ins insLen bld 8<rt> (?>) false
  | Op.VCMPGTSBdot ->
    vecCompare ins insLen bld 8<rt> (?>) true
  | Op.VCMPGTSH ->
    vecCompare ins insLen bld 16<rt> (?>) false
  | Op.VCMPGTSHdot ->
    vecCompare ins insLen bld 16<rt> (?>) true
  | Op.VCMPGTSW ->
    vecCompare ins insLen bld 32<rt> (?>) false
  | Op.VCMPGTSWdot ->
    vecCompare ins insLen bld 32<rt> (?>) true
  | Op.VCMPGTSD ->
    vecCompare ins insLen bld 64<rt> (?>) false
  | Op.VCMPGTSDdot ->
    vecCompare ins insLen bld 64<rt> (?>) true
  | o ->
#if DEBUG
         eprintfn "%A" o
#endif
         raise <| NotImplementedIRException(Disasm.opCodeToString o)

// vim: set tw=80 sts=2 sw=2:

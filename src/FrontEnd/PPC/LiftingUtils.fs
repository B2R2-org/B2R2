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

module internal B2R2.FrontEnd.PPC.LiftingUtils

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
    | Num(Value = b), Num(Value = m) ->
      struct (int (b.ToUInt64()), int (m.ToUInt64()))
    | _ ->
      raise InvalidExprException
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
    | Num(Value = b), Num(Value = m) ->
      struct (int (b.ToUInt64()), int (m.ToUInt64()))
    | _ ->
      raise InvalidExprException
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

/// The mask a rotate-word form applies on a 64-bit part: MASK(mb+32, me+32),
/// which reaches into the high word when mb > me.
let getWordMaskIn64 mb me =
  match mb, me with
  | Num(Value = b), Num(Value = m) ->
    getExtMask64 (numI32 (int (b.ToUInt64()) + 32) 32<rt>)
                 (numI32 (int (m.ToUInt64()) + 32) 32<rt>)
  | _ ->
    raise InvalidExprException

let rotateLeft rs sh = (rs << sh) .| (rs >> ((numI32 32 32<rt>) .- sh))

/// ROTL64: rotates a doubleword left by sh, which must be in 0..63.
let rotateLeft64 rs sh = (rs << sh) .| (rs >> ((numI32 64 64<rt>) .- sh))

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

let getSPRReg bld (imm: Imm) =
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

let isDenormalized frx =
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
       .| isDenormalized result
       .| AST.eq result nzero
    fl := AST.flt result (AST.num0 64<rt>)
    fg := AST.fgt result (AST.num0 64<rt>)
    fe := AST.eq (result << AST.num1 64<rt>) (AST.num0 64<rt>)
    fu := IEEE754Double.isNaN result .| IEEE754Double.isInfinity result
  }

/// A bit of XER, numbered from the least significant of the 32 kept here: the
/// Power ISA's bit 32 + n is bit 31 - n, so SO, OV and CA are 31, 30 and 29,
/// and ISA 3.0's OV32 and CA32 are 19 and 18.
let xerBit bld pos = AST.extract (regVar bld Register.XER) 1<rt> pos

/// Whether the processor has OV32 and CA32, the 32-bit twins ISA 3.0 gave OV
/// and CA. A 32-bit processor predates them and keeps bits 44 and 45 of XER
/// reserved, so only a 64-bit one writes them.
let private hasTwins (bld: ILowUIRBuilder) = bld.RegType = 64<rt>

/// Writes XER[CA], and XER[CA32] where the processor has it.
let setCarry bld carry carry32 =
  append bld {
    xerBit bld 29 := carry
    if hasTwins bld then xerBit bld 18 := carry32 else ()
  }

/// Writes XER[OV], and XER[OV32] where the processor has it, and ORs OV into
/// the sticky XER[SO]. Both values are read before any bit is written.
let setOverflow bld ov ov32 =
  append bld {
    xerBit bld 30 := ov
    if hasTwins bld then xerBit bld 19 := ov32 else ()
    xerBit bld 31 := ov .| xerBit bld 31
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

/// Records an overflow in XER[OV], XER[OV32] and XER[SO]: a signed add or
/// subtract overflows when both operands share a sign that the result does
/// not. OV takes the signs at the register's top bit, OV32 the signs of the
/// low words, which is what OV would be in 32-bit mode.
let isAddSubOV bld expA expB result =
  let signsAt pos =
    let a = AST.extract expA 1<rt> pos
    (a == AST.extract expB 1<rt> pos) .& (a <+> AST.extract result 1<rt> pos)
  let struct (ov, ov32) = tmpVars2 bld 1<rt>
  append bld {
    ov := signsAt (int (Expr.typeOf expA) - 1)
    ov32 := signsAt 31
    setOverflow bld ov ov32
  }

/// Adds a + b + c (c a register-wide carry-in of 0 or 1) into dst, recording
/// the carry-out in XER[CA]. Each partial sum's unsigned wrap gives its carry,
/// so no intermediate wider than a register is needed. The carry out of the
/// low word, CA32, is the carry into bit 32, which is bit 32 of a ^ b ^ sum
/// since the carry-in only reaches bit 0.
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
  let carry32 =
    if bld.RegType = 64<rt> then AST.extract (a <+> b <+> t2) 1<rt> 32
    else c1 .| c2
  setCarry bld (c1 .| c2) carry32

/// Records a multiply's or a divide's overflow, which is the same in either
/// mode: OV32 is OV.
let setWholeOverflow bld cond =
  let ov = tmpVar bld 1<rt>
  append bld {
    ov := cond
    setOverflow bld ov ov
  }

/// Records an overflow of mullw, whose 32-bit operands make a product that does
/// not fit a signed word.
let isMulwOV bld expA expB =
  let prod = tmpVar bld 64<rt>
  let a = AST.sext 64<rt> (AST.xtlo 32<rt> expA)
  let b = AST.sext 64<rt> (AST.xtlo 32<rt> expB)
  append bld {
    prod := a .* b
    setWholeOverflow bld (prod != AST.sext 64<rt> (AST.xtlo 32<rt> prod))
  }

/// Records an overflow of mulld, whose doubleword product does not fit a signed
/// doubleword.
let isMuldOV bld expA expB =
  let prod = tmpVar bld 128<rt>
  let a = AST.sext 128<rt> (AST.xtlo 64<rt> expA)
  let b = AST.sext 128<rt> (AST.xtlo 64<rt> expB)
  append bld {
    prod := a .* b
    setWholeOverflow bld (prod != AST.sext 128<rt> (AST.xtlo 64<rt> prod))
  }

/// Records an overflow of a signed divide of the given width: a zero divisor,
/// or the most negative dividend divided by -1.
let isSignedDivOV bld rt expA expB =
  let minValue = AST.num1 rt << numI32 (int rt - 1) rt
  let dz = expB == AST.num0 rt
  let ovf = (expA == minValue) .& (expB == AST.not (AST.num0 rt))
  setWholeOverflow bld (dz .| ovf)

/// Records an overflow of an unsigned divide of the given width: a zero
/// divisor is the only case.
let isUnsignedDivOV bld rt expB =
  setWholeOverflow bld (expB == AST.num0 rt)

let sideEffects (ins: Instruction) bld name =
  lift bld ins {
    AST.sideEffect name
  }

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

/// <summary>
/// Lifts the instructions of Variable Length Encoding (VLE) that have no
/// instruction of the base encoding to be lifted as. The rest are lifted by
/// the lifter of the instruction they are another encoding of, which is the
/// Power ISA's own statement that they mean the same.
/// </summary>
module internal B2R2.FrontEnd.PPC.VLELifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.PPC
open B2R2.FrontEnd.PPC.LiftingUtils

/// What an instruction made only to be lifted holds in place of the lifter of
/// instructions, which it is never asked for.
let private noLifter = Unchecked.defaultof<ILiftable>

/// <summary>
/// The instruction of the base encoding that a VLE instruction is another
/// encoding of, given the operands that instruction takes. The lifters of the
/// base encoding read only the address, the length and the operands of what
/// they lift, so what they lift here is the same operation with the same
/// statements, which is the Power ISA's own statement that the two mean the
/// same.
/// </summary>
let private asBase (ins: Instruction) operands =
  let size, ea = ins.OperationSize, ins.EffectiveAddress
  Instruction(ins.Address, ins.Length, ins.Opcode, operands, size, ea, noLifter)

/// RX = f(RX, RY), as the instruction of three registers that names RX twice
/// does.
let dyadic (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(rx, ry) -> asBase ins (ThreeOperands(rx, rx, ry))
  | _ -> raise InvalidOperandException

/// RX = f(RY, RX), which is what a subtraction of RY from RX asks of the
/// instruction that subtracts its first source from its second.
let reversed (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(rx, ry) -> asBase ins (ThreeOperands(rx, ry, rx))
  | _ -> raise InvalidOperandException

/// RX = f(RX), as the instruction of two registers that names RX twice does.
let monadic (ins: Instruction) =
  match ins.Operands with
  | OneOperand rx -> asBase ins (TwoOperands(rx, rx))
  | _ -> raise InvalidOperandException

/// RX = f(RX, RX), as the instruction of three registers that names RX three
/// times does, which is how the base encoding complements a register.
let repeated (ins: Instruction) =
  match ins.Operands with
  | OneOperand rx -> asBase ins (ThreeOperands(rx, rx, rx))
  | _ -> raise InvalidOperandException

/// RX with all but the bits from n to 31 of its low word cleared, as the
/// rotate by nothing that keeps those bits does.
let clearLeft (ins: Instruction) n =
  match ins.Operands with
  | OneOperand rx ->
    asBase ins (FiveOperands(rx, rx, OprImm 0UL, OprImm n, OprImm 31UL))
  | _ ->
    raise InvalidOperandException

/// RX = RX + a number.
let addImmediate (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, imm) = transTwoOprs ins bld
    dst := dst .+ imm
  }

/// RX = RX - a number, which records CR0 where the instruction says so.
let subtractImmediate (ins: Instruction) (bld: ILowUIRBuilder) record =
  lift bld ins {
    let struct (dst, imm) = transTwoOprs ins bld
    dst := dst .- imm
    if record then setCR0Reg bld dst else ()
  }

/// RX = RX & a number.
let andImmediate (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, imm) = transTwoOprs ins bld
    dst := dst .& imm
  }

/// RX shifted left by a number n, which is the rotate by n that keeps the bits
/// from 0 to 31 - n of the word.
let shiftLeftImmediate (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(rx, OprImm n) ->
    asBase ins (FiveOperands(rx, rx, OprImm n, OprImm 0UL, OprImm(31UL - n)))
  | _ ->
    raise InvalidOperandException

/// RX shifted right by a number n, which is the rotate by 32 - n that keeps
/// the bits from n to 31 of the word.
let shiftRightImmediate (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(rx, OprImm n) ->
    let sh = OprImm((32UL - n) &&& 31UL)
    asBase ins (FiveOperands(rx, rx, sh, OprImm n, OprImm 31UL))
  | _ ->
    raise InvalidOperandException

/// RX shifted right algebraically by a number, as the instruction of two
/// registers and a number that names RX twice does.
let shiftRightAlgebraicImmediate (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(rx, n) -> asBase ins (ThreeOperands(rx, rx, n))
  | _ -> raise InvalidOperandException

/// A comparison of two operands that puts its result in CR0, which is the
/// field the instructions of a halfword have no way to name, as the comparison
/// that names the field does.
let compareInCR0 (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(rx, ry) ->
    asBase ins (ThreeOperands(OprReg Register.CR0, rx, ry))
  | _ ->
    ins

/// The number an instruction of a register and a number takes.
let private numberOf (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(_, OprImm n) -> int n
  | _ -> raise InvalidOperandException

/// The mask that selects bit UI5 + 32 of a register, which is bit 31 - UI5
/// counted from the least significant.
let private bitSelected (ins: Instruction) (bld: ILowUIRBuilder) =
  numU64 (1UL <<< (31 - numberOf ins)) bld.RegType

/// se_bclri, which clears one bit of a register.
let clearBit (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, _) = transTwoOprs ins bld
    dst := dst .& AST.not (bitSelected ins bld)
  }

/// se_bgeni, which puts a one in one bit of a register and zeros in the rest.
let generateBit (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, _) = transTwoOprs ins bld
    dst := bitSelected ins bld
  }

/// se_bseti, which sets one bit of a register.
let setBit (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, _) = transTwoOprs ins bld
    dst := dst .| bitSelected ins bld
  }

/// se_bmaski, which puts ones in as many of the low bits of a register as the
/// number says, and every bit of it when the number is zero.
let generateMask (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, _) = transTwoOprs ins bld
    let n = numberOf ins
    if n = 0 then
      dst := AST.not (AST.num0 bld.RegType)
    else
      dst := numU64 ((1UL <<< n) - 1UL) bld.RegType
  }

/// se_btsti, which records one bit of a register in CR0: LT is cleared, GT says
/// the bit is one, EQ that it is zero, and SO is copied from XER.
let testBit (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (src, _) = transTwoOprs ins bld
    let tested = tmpVar bld bld.RegType
    let zero = AST.num0 bld.RegType
    tested := src .& bitSelected ins bld
    regVar bld Register.CR0_0 := AST.b0
    regVar bld Register.CR0_1 := tested != zero
    regVar bld Register.CR0_2 := tested == zero
    regVar bld Register.CR0_3 := AST.xthi 1<rt> (regVar bld Register.XER)
  }

/// A comparison of the low halfwords of two registers, signed or unsigned,
/// whose result goes in the CR field the instruction names.
let compareHalfword (ins: Instruction) (bld: ILowUIRBuilder) signed =
  lift bld ins {
    let struct ((lt, gt, eq, so), a, b) = transCmpOprs (compareInCR0 ins) bld
    let a, b = AST.xtlo 16<rt> a, AST.xtlo 16<rt> b
    let less = if signed then AST.slt a b else AST.lt a b
    let greater = if signed then AST.sgt a b else AST.gt a b
    lt := less
    gt := greater
    eq := AST.ite less AST.b0 (AST.not greater)
    so := AST.xthi 1<rt> (regVar bld Register.XER)
  }

/// The address a branch with a displacement goes to: the address of the
/// instruction plus the displacement, which the operand holds sign-extended to
/// the width of a register, and which wraps at that width.
let private branchTarget (ins: Instruction) (bld: ILowUIRBuilder) =
  match ins.Operands with
  | OneOperand(OprAddr disp)
  | ThreeOperands(_, _, OprAddr disp) ->
    numU64 (ins.Address + disp) bld.RegType
  | _ ->
    raise InvalidOperandException

/// The address of the instruction after one, which a branch that links puts in
/// LR and a branch that does not take goes on to.
let private nextAddress (ins: Instruction) (bld: ILowUIRBuilder) =
  numU64 (ins.Address + uint64 ins.Length) bld.RegType

/// A branch to the address a displacement names, which writes the address of
/// the instruction after it into LR when it links.
let branch (ins: Instruction) (bld: ILowUIRBuilder) link =
  lift bld ins {
    let target = branchTarget ins bld
    if link then
      regVar bld Register.LR := nextAddress ins bld
      AST.interjmp target InterJmpKind.IsCall
    else
      AST.interjmp target InterJmpKind.Base
  }

/// se_bc: a branch to the address a displacement names when the bit of CR0 the
/// instruction names equals BO16, and on to the next instruction otherwise.
let branchOnBit (ins: Instruction) (bld: ILowUIRBuilder) =
  let struct (bo, bi) =
    match ins.Operands with
    | ThreeOperands(OprImm bo, OprBI bi, _) -> struct (bo, bi)
    | _ -> raise InvalidOperandException
  lift bld ins {
    let bit = regVar bld (OperandHelper.getCRbitRegister bi)
    let target = branchTarget ins bld
    let next = tmpVar bld bld.RegType
    next := AST.ite (bit == numU64 bo 1<rt>) target (nextAddress ins bld)
    AST.interjmp next InterJmpKind.Base
  }

/// e_bc and e_bcl: a branch to the address a displacement names that is decided
/// by BO32, whose high bit says whether the counter is decremented and tested
/// and whose low bit says what the test, or the bit of the condition register,
/// has to be: the counter forms branch when it is not zero (2) or zero (3),
/// the others when the bit is zero (0) or one (1). A branch that links writes
/// the address of the instruction after it into LR whether it is taken or not.
let branchConditional (ins: Instruction) (bld: ILowUIRBuilder) link =
  let struct (bo, bi) =
    match ins.Operands with
    | ThreeOperands(OprImm bo, OprBI bi, _) -> struct (bo, bi)
    | _ -> raise InvalidOperandException
  lift bld ins {
    let rt = bld.RegType
    let ctr = regVar bld Register.CTR
    let bit = regVar bld (OperandHelper.getCRbitRegister bi)
    let target = branchTarget ins bld
    let next = nextAddress ins bld
    let dest = tmpVar bld rt
    if link then regVar bld Register.LR := next else ()
    if bo >= 2UL then ctr := ctr .- AST.num1 rt else ()
    let zero = AST.num0 rt
    let counterTest = if bo = 2UL then ctr != zero else ctr == zero
    let test = if bo >= 2UL then counterTest else bit == numU64 bo 1<rt>
    dest := AST.ite test target next
    AST.interjmp dest (if link then InterJmpKind.IsCall else InterJmpKind.Base)
  }

/// e_addi and e_addi.: RT = RA + a number, which records CR0 where the
/// instruction says so. Register 0 is an ordinary register here.
let addScaled (ins: Instruction) (bld: ILowUIRBuilder) record =
  lift bld ins {
    let struct (dst, src, imm) = transThreeOprs ins bld
    dst := src .+ imm
    if record then setCR0Reg bld dst else ()
  }

/// e_subfic.: RT = ~RA + a number + 1 with the carry out of the register in
/// XER[CA], and CR0 recorded.
let subtractFromScaledRecord (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, src, imm) = transThreeOprs ins bld
    let struct (t1, t2) = tmpVars2 bld bld.RegType
    t1 := AST.not src
    t2 := imm
    addWithCarryOut bld dst t1 t2 (AST.num1 bld.RegType)
    setCR0Reg bld dst
  }

/// The logical instructions that take a scaled immediate: RA = RS op a number,
/// which records CR0 where the instruction says so.
let logicalScaled (ins: Instruction) (bld: ILowUIRBuilder) operation record =
  lift bld ins {
    let struct (dst, src, imm) = transThreeOprs ins bld
    dst := operation src imm
    if record then setCR0Reg bld dst else ()
  }

/// The number of an instruction of a register and a number, shifted left 16
/// bits if the instruction says so and extended as it says.
let private shiftedNumber (bld: ILowUIRBuilder) shifted signed imm =
  if shifted then GeneralLifter.shiftedImm bld signed imm else imm

/// e_add2i. and e_add2is: RA = RA + a signed number, which is shifted left 16
/// bits in the second; the first records CR0.
let addToRegister (ins: Instruction) (bld: ILowUIRBuilder) shifted =
  lift bld ins {
    let struct (dst, imm) = transTwoOprs ins bld
    dst := dst .+ shiftedNumber bld shifted true imm
    if shifted then () else setCR0Reg bld dst
  }

/// e_and2i. and e_and2is.: RT = RT & an unsigned number, shifted left 16 bits
/// in the second, which record CR0.
let andWithRegister (ins: Instruction) (bld: ILowUIRBuilder) shifted =
  lift bld ins {
    let struct (dst, imm) = transTwoOprs ins bld
    dst := dst .& shiftedNumber bld shifted false imm
    setCR0Reg bld dst
  }

/// e_or2i and e_or2is: RT = RT | an unsigned number, shifted left 16 bits in
/// the second, which leave CR0 alone.
let orWithRegister (ins: Instruction) (bld: ILowUIRBuilder) shifted =
  lift bld ins {
    let struct (dst, imm) = transTwoOprs ins bld
    dst := dst .| shiftedNumber bld shifted false imm
  }

/// e_lis: RT = an unsigned number shifted left 16 bits, whatever RT held.
let loadShifted (ins: Instruction) (bld: ILowUIRBuilder) =
  lift bld ins {
    let struct (dst, imm) = transTwoOprs ins bld
    dst := GeneralLifter.shiftedImm bld false imm
  }

/// e_mull2i: RA = RA x a signed number, as the multiply of two registers and a
/// number that names RA twice does.
let multiplyRegister (ins: Instruction) =
  match ins.Operands with
  | TwoOperands(ra, imm) -> asBase ins (ThreeOperands(ra, ra, imm))
  | _ -> raise InvalidOperandException

/// A load of a size from an address that is a base register plus a
/// displacement, zero-extended into the register it names. The base register
/// is whichever the instruction names, register 0 included.
let loadFromBase (ins: Instruction) (bld: ILowUIRBuilder) size =
  let struct (rz, rx, disp) =
    match ins.Operands with
    | TwoOperands(OprReg rz, OprMem(disp, rx)) -> struct (rz, rx, disp)
    | _ -> raise InvalidOperandException
  lift bld ins {
    let ea = tmpVar bld bld.RegType
    ea := regVar bld rx .+ numI32 disp bld.RegType
    regVar bld rz := AST.zext bld.RegType (loadNative bld size ea)
  }

/// A store of a size to an address that is a base register plus a
/// displacement, of the low bits of the register it names. The base register
/// is whichever the instruction names, register 0 included.
let storeToBase (ins: Instruction) (bld: ILowUIRBuilder) size =
  let struct (rz, rx, disp) =
    match ins.Operands with
    | TwoOperands(OprReg rz, OprMem(disp, rx)) -> struct (rz, rx, disp)
    | _ -> raise InvalidOperandException
  lift bld ins {
    let ea = tmpVar bld bld.RegType
    ea := regVar bld rx .+ numI32 disp bld.RegType
    loadNative bld size ea := AST.xtlo size (regVar bld rz)
  }

/// Rotates the low word, repeating it in both halves on a 64-bit processor.
let rotateWord (ins: Instruction) (bld: ILowUIRBuilder) record =
  lift bld ins {
    let struct (dst, src, count) = transThreeOprs ins bld
    let n = AST.xtlo 32<rt> count .& numI32 31 32<rt>
    let result = tmpVar bld 32<rt>
    result := rotateLeft (AST.xtlo 32<rt> src) n
    let value =
      if bld.RegType = 64<rt> then AST.concat result result else result
    dst := value
    if record then setCR0Reg bld dst else ()
  }

/// The word shifts clear the high word, including when the shift is zero.
let shiftWord (ins: Instruction) (bld: ILowUIRBuilder) left record =
  lift bld ins {
    let struct (dst, src, count) = transThreeOprs ins bld
    let word = AST.xtlo 32<rt> src
    let n = AST.xtlo 32<rt> count
    let value = if left then word << n else word >> n
    dst := AST.zext bld.RegType value
    if record then setCR0Reg bld dst else ()
  }

/// se_illegal, which asks for an Illegal Instruction exception.
let illegal ins bld = sideEffects ins bld UndefinedInstruction

/// A branch to the address in a register, whose low bit is the only one it
/// clears: an instruction sits on a halfword, so the bit below that is not
/// masked as the base encoding masks it. A branch that links writes the
/// address of the instruction after it, which is two bytes on, only once it
/// has read where it goes.
let branchToRegister (ins: Instruction) (bld: ILowUIRBuilder) reg link =
  lift bld ins {
    let rt = bld.RegType
    let target = tmpVar bld rt
    target := regVar bld reg .& AST.not (AST.num1 rt)
    if link then
      regVar bld Register.LR := numU64 (ins.Address + uint64 ins.Length) rt
      AST.interjmp target InterJmpKind.IsCall
    elif reg = Register.LR then
      AST.interjmp target InterJmpKind.IsRet
    else
      AST.interjmp target InterJmpKind.Base
  }

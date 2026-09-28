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

/// A module for the AArch64 general-purpose IR translation functions
module internal B2R2.FrontEnd.ARM64.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.ARM64
open B2R2.FrontEnd.ARM64.LiftingUtils

let sideEffects ins bld name =
  lift bld ins {
    AST.sideEffect name
  }

/// An instruction that is valid but outside what this lifter models, left to
/// the emulator to report rather than silently mis-executed.
let unsupported ins bld = sideEffects ins bld UnsupportedInstruction

let adc ins bld =
  lift bld ins {
    let dst, src1, src2 = transThreeOprs ins bld
    let c = AST.zext ins.OprSize (regVar bld R.C)
    let result, _ = addWithCarry src1 src2 c ins.OprSize
    sized ins.OprSize dst := result
  }

let adcs ins bld =
  lift bld ins {
    let dst, src1, src2 = transThreeOprs ins bld
    let c = tmpVar bld ins.OprSize
    direct c := AST.zext ins.OprSize (regVar bld R.C)
    let result, (n, z, c, v) = addWithCarry src1 src2 c ins.OprSize
    direct (regVar bld R.N) := n
    direct (regVar bld R.Z) := z
    direct (regVar bld R.C) := c
    direct (regVar bld R.V) := v
    sized ins.OprSize dst := result
  }

let adds ins bld =
  lift bld ins {
    let dst, src1, src2 = transFourOprsWithBarrelShift ins bld
    let oSz = ins.OprSize
    let result, (n, z, c, v) = addWithCarry src1 src2 (AST.num0 oSz) oSz
    direct (regVar bld R.N) := n
    direct (regVar bld R.Z) := z
    direct (regVar bld R.C) := c
    direct (regVar bld R.V) := v
    sized ins.OprSize dst := result
  }

let adr ins bld =
  lift bld ins {
    let dst, label = transTwoOprs ins bld
    direct dst := getPC bld .+ label
  }

let adrp ins bld =
  lift bld ins {
    let dst, lbl = transTwoOprs ins bld
    direct dst := (getPC bld .& numI64 0xfffffffffffff000L 64<rt>) .+ lbl
  }

let asrv ins bld =
  lift bld ins {
    let dst, src1, src2 = transThreeOprs ins bld
    let amount = src2 .% oprSzToExpr ins.OprSize
    sized ins.OprSize dst := shiftReg src1 amount ins.OprSize ASR
  }

let ands ins bld =
  lift bld ins {
    let dst, src1, src2 = transOprOfAND ins bld
    let result = tmpVar bld ins.OprSize
    direct result := src1 .& src2
    direct (regVar bld R.N) := AST.xthi 1<rt> result
    direct (regVar bld R.Z) := (result == AST.num0 ins.OprSize)
    direct (regVar bld R.C) := AST.b0
    direct (regVar bld R.V) := AST.b0
    sized ins.OprSize dst := result
  }

let b ins bld =
  lift bld ins {
    let label = transOneOpr ins bld
    let pc = numU64 (ins:Instruction).Address bld.RegType
    AST.interjmp (pc .+ label) InterJmpKind.Base
    return NoEndMark
  }

let bCond ins bld cond =
  lift bld ins {
    let label = transOneOpr ins bld
    let pc = numU64 (ins:Instruction).Address bld.RegType
    let fall = pc .+ numU32 ins.Length 64<rt>
    AST.intercjmp (conditionHolds bld cond) (pc .+ label) fall
    return NoEndMark
  }

let bfm (ins: Instruction) bld dst src immr imms =
  lift bld ins {
    let oSz = ins.OprSize
    let width = oprSzToExpr ins.OprSize
    let struct (wmask, tmask) = decodeBitMasks immr imms (int oSz)
    let dst = transOpr ins bld dst
    let src = transOpr ins bld src
    let immr = transOpr ins bld immr
    let struct (wMask, tMask) = tmpVars2 bld oSz
    let bot = tmpVar bld ins.OprSize
    direct wMask := numI64 wmask oSz
    direct tMask := numI64 tmask oSz
    direct bot := (dst .& AST.not wMask) .| (rorForIR src immr width .& wMask)
    sized ins.OprSize dst := (dst .& AST.not tMask) .| (bot .& tMask)
  }

let bfi ins bld =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let immr = ((getImmValue lsb * -1L) &&& 0x3FL) % int64 ins.OprSize |> OprImm
  let imms = getImmValue width - 1L |> OprImm
  bfm ins bld dst src immr imms

let bfxil ins bld =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let imms = (getImmValue lsb) + (getImmValue width) - 1L |> OprImm
  bfm ins bld dst src lsb imms

let bics ins bld =
  lift bld ins {
    let dst, src1, src2 = transFourOprsWithBarrelShift ins bld
    let result = tmpVar bld ins.OprSize
    direct result := src1 .& AST.not src2
    direct (regVar bld R.N) := AST.xthi 1<rt> result
    direct (regVar bld R.Z) := result == AST.num0 ins.OprSize
    direct (regVar bld R.C) := AST.b0
    direct (regVar bld R.V) := AST.b0
    sized ins.OprSize dst := result
  }

let bl ins bld =
  lift bld ins {
    let label = transOneOpr ins bld
    let pc = numU64 (ins:Instruction).Address bld.RegType
    direct (regVar bld R.X30) := pc .+ numI64 4L ins.OprSize
    (* FIXME: BranchTo (BranchType_DIRCALL) *)
    AST.interjmp (pc .+ label) InterJmpKind.IsCall
    return NoEndMark
  }

let blr ins bld =
  lift bld ins {
    let src = transOneOpr ins bld
    let pc = numU64 (ins:Instruction).Address bld.RegType
    direct (regVar bld R.X30) := pc .+ numI64 4L ins.OprSize
    (* FIXME: BranchTo (BranchType_INDCALL) *)
    AST.interjmp src InterJmpKind.IsCall
    return NoEndMark
  }

let br ins bld =
  lift bld ins {
    let dst = transOneOpr ins bld
    (* FIXME: BranchTo (BranchType_INDIR) *)
    AST.interjmp dst InterJmpKind.Base
    return NoEndMark
  }

let inline private compareBranch ins bld cmp =
  lift bld ins {
    let test, label = transTwoOprs ins bld
    let pc = numU64 (ins: Instruction).Address bld.RegType
    let fall = pc .+ numU32 ins.Length 64<rt>
    AST.intercjmp (cmp test (AST.num0 ins.OprSize)) (pc .+ label) fall
    return NoEndMark
  }

/// <summary>
/// CAS, whose access is as wide as its name says and not as wide as the
/// registers it names: the byte and halfword forms compare and store one
/// byte or one halfword, and the comparison register comes back holding what
/// was there with the rest of it zeroed.
/// </summary>
let compareAndSwap (ins: Instruction) bld accSz =
  lift bld ins {
    let oprSz = ins.OprSize
    let dst, src, (bReg, offset) = transThreeOprsSepMem ins bld
    let struct (compareVal, newVal, oldVal) = tmpVars3 bld accSz
    let address = tmpVar bld 64<rt>
    let cond = oldVal == compareVal
    let narrow e = if accSz = oprSz then e else AST.xtlo accSz e
    direct address := bReg .+ offset
    direct compareVal := narrow dst
    direct newVal := narrow src
    direct oldVal := AST.loadLE accSz address
    direct (AST.loadLE accSz address) := AST.ite cond newVal oldVal
    sized oprSz dst := AST.zext oprSz oldVal
  }

/// <summary>
/// CASP, CASPA, CASPAL and CASPL: the compare and swap of a PAIR -- two words
/// or two doublewords, which the manual reads as one access of twice the
/// size. They are compared with the first pair of registers and replaced by
/// the second where both match, and the first pair gets what memory held. On
/// a little-endian access the lower register of each pair goes with the
/// lower address.
/// </summary>
let compareAndSwapPair (ins: Instruction) bld =
  lift bld ins {
    let oprSz = ins.OprSize
    match ins.Operands with
    | FiveOperands(s1, s2, t1, t2, mem) ->
      let bReg, offset = transOpr ins bld mem |> separateMemExpr
      let struct (address, high) = tmpVars2 bld 64<rt>
      let struct (oldLo, oldHi) = tmpVars2 bld oprSz
      let reg o = transOpr ins bld o
      let matches = (oldLo == reg s1) .& (oldHi == reg s2)
      direct address := bReg .+ offset
      direct high := address .+ numI32 (int oprSz / 8) 64<rt>
      direct oldLo := AST.loadLE oprSz address
      direct oldHi := AST.loadLE oprSz high
      direct (AST.loadLE oprSz address) := AST.ite matches (reg t1) oldLo
      direct (AST.loadLE oprSz high) := AST.ite matches (reg t2) oldHi
      sized oprSz (reg s1) := oldLo
      sized oprSz (reg s2) := oldHi
    | _ ->
      raise InvalidOperandException
  }

/// The four operations whose name is not already an operator. CLR clears the
/// bits the operand names, which is why it is not an AND, and the four
/// extremes differ only in whether the comparison reads the sign.
let atomicClear (a: Expr) (b: Expr) = a .& AST.not b

let atomicSMax (a: Expr) (b: Expr) = AST.ite (a ?> b) a b

let atomicSMin (a: Expr) (b: Expr) = AST.ite (a ?< b) a b

let atomicUMax (a: Expr) (b: Expr) = AST.ite (a .> b) a b

let atomicUMin (a: Expr) (b: Expr) = AST.ite (a .< b) a b

/// <summary>
/// The atomic memory operations: a load, an operation on what was loaded and
/// a store, in one instruction.
///
/// What goes back to the destination is the value the location held BEFORE
/// the operation, so it is latched into a temporary first -- the source
/// register may also be the destination, and the store must not read back
/// what it is about to write.
///
/// The store form has no destination at all. It is the same encoding with the
/// destination reading as the zero register, and it arrives here with two
/// operands rather than three because that is how the manual spells it.
///
/// The acquire and release suffixes say nothing here. They order this access
/// against others on the same processor, and a model that runs one
/// instruction after another has nothing for them to constrain.
///
/// The width of the ACCESS is not the width of the registers and arrives
/// separately. A byte form names two 32-bit registers and reads one byte, and
/// the operation is done on that byte: LDSMAXB compares eight signed bits,
/// not thirty-two, and what comes back is the old byte with the rest of the
/// register zeroed.
/// </summary>
let atomicMemOp (ins: Instruction) bld op accSz =
  lift bld ins {
    let oprSz = ins.OprSize
    let struct (operand, oldVal) = tmpVars2 bld accSz
    let address = tmpVar bld 64<rt>
    let narrow e = if accSz = oprSz then e else AST.xtlo accSz e
    match ins.Operands with
    | ThreeOperands _ ->
      let src, dst, (bReg, offset) = transThreeOprsSepMem ins bld
      direct address := bReg .+ offset
      direct operand := narrow src
      direct oldVal := AST.loadLE accSz address
      direct (AST.loadLE accSz address) := op oldVal operand
      sized oprSz dst := AST.zext oprSz oldVal
    | _ ->
      let src, (bReg, offset) = transTwoOprsSepMem ins bld
      direct address := bReg .+ offset
      direct operand := narrow src
      direct oldVal := AST.loadLE accSz address
      direct (AST.loadLE accSz address) := op oldVal operand
  }

/// SWP, which is the same class with nothing to combine: what goes to memory
/// is the operand itself.
let swapMem ins bld accSz =
  atomicMemOp ins bld (fun _ operand -> operand) accSz

/// LDAPR, a load that shares the atomic class and is not atomic: the acquire
/// ordering it carries is the whole of what distinguishes it from LDR, and
/// ordering is not modelled.
let loadAcquirePc (ins: Instruction) bld accSz =
  lift bld ins {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    direct address := bReg .+ offset
    sized ins.OprSize dst :=
      AST.zext ins.OprSize (AST.loadLE accSz address)
  }

/// CFINV, which inverts the carry flag and touches nothing else.
let cfinv ins bld =
  lift bld ins {
    let c = regVar bld R.C
    direct c := AST.not c
  }

/// <summary>
/// SETF8 and SETF16, which set N, Z and V from a value narrower than a
/// register as though a subtraction had just produced it.
///
/// N is the value's top bit at the width named, Z is whether the whole of
/// that width is zero, and V is whether the bits above it disagree with the
/// sign -- which is what an overflow out of that width looks like. C is left
/// alone, because nothing here carried.
/// </summary>
let setFlags ins bld width =
  lift bld ins {
    let src = transOneOpr ins bld
    let value = AST.xtlo (width + 1<rt>) src
    let sign = AST.extract value 1<rt> (RegType.toBitWidth width - 1)
    direct (regVar bld R.N) := sign
    direct (regVar bld R.Z) :=
      AST.xtlo width src == AST.num0 width
    direct (regVar bld R.V) := sign <+> AST.xthi 1<rt> value
  }

/// <summary>
/// AXFLAG and XAFLAG, which convert between the condition flags an Arm
/// floating-point compare leaves and the ones another format expects.
///
/// The Arm form distinguishes unordered from less-than; the other does not,
/// and folds the unordered case into equality. AXFLAG goes one way and
/// XAFLAG the other, and neither reads or writes anything but the flags.
/// </summary>
let axflag ins bld =
  lift bld ins {
    let struct (z, c, v) = tmpVars3 bld 1<rt>
    direct z := regVar bld R.Z
    direct c := regVar bld R.C
    direct v := regVar bld R.V
    direct (regVar bld R.N) := AST.b0
    direct (regVar bld R.Z) := z .| v
    direct (regVar bld R.C) := c .& AST.not v
    direct (regVar bld R.V) := AST.b0
  }

let xaflag ins bld =
  lift bld ins {
    let struct (z, c) = tmpVars2 bld 1<rt>
    direct z := regVar bld R.Z
    direct c := regVar bld R.C
    direct (regVar bld R.N) := AST.not c .& AST.not z
    direct (regVar bld R.Z) := c .& z
    direct (regVar bld R.C) := c .| z
    direct (regVar bld R.V) := AST.not c .& z
  }

/// <summary>
/// RMIF: one register rotated right by an immediate, its bottom four bits
/// copied into NZCV, and a mask saying which of the four to write.
///
/// The mask's bits run the same way the flags do -- bit 3 is N and bit 0 is
/// V -- so a flag the mask leaves out keeps what it had. That is the whole
/// of the instruction, and it is the only one of FEAT_FlagM's three that
/// reads a register at all.
/// </summary>
let rotateMaskInsert (ins: Instruction) bld =
  lift bld ins {
    let struct (src, shift, mask) = getThreeOprs ins
    let n = transOpr ins bld src
    let amount = int (getImmValue shift)
    let m = int (getImmValue mask)
    let rotated = tmpVar bld 64<rt>
    let ror =
      if amount = 0 then n
      else (n >> numI32 amount 64<rt>) .| (n << numI32 (64 - amount) 64<rt>)
    direct rotated := ror
    let flags = [ R.N, 3; R.Z, 2; R.C, 1; R.V, 0 ]
    for reg, bit in flags do
      if m &&& (1 <<< bit) <> 0 then
        direct (regVar bld reg) := AST.extract rotated 1<rt> bit
      else
        ()
  }

let cbnz ins bld = compareBranch ins bld (!=)

let cbz ins bld = compareBranch ins bld (==)

let ccmn ins bld =
  lift bld ins {
    let src, imm, nzcv, cond = transOprOfCCMN ins bld
    let oSz = ins.OprSize
    let tCond = tmpVar bld 1<rt>
    direct tCond := conditionHolds bld cond
    let _, (n, z, c, v) = addWithCarry src imm (AST.num0 oSz) oSz
    direct (regVar bld R.N) := (AST.ite tCond n (AST.extract nzcv 1<rt> 3))
    direct (regVar bld R.Z) := (AST.ite tCond z (AST.extract nzcv 1<rt> 2))
    direct (regVar bld R.C) := (AST.ite tCond c (AST.extract nzcv 1<rt> 1))
    direct (regVar bld R.V) := (AST.ite tCond v (AST.xtlo 1<rt> nzcv))
  }

let ccmp ins bld =
  lift bld ins {
    let src, imm, nzcv, cond = transOprOfCCMP ins bld
    let oSz = ins.OprSize
    let tCond = tmpVar bld 1<rt>
    direct tCond := conditionHolds bld cond
    let _, (n, z, c, v) = addWithCarry src (AST.not imm) (AST.num1 oSz) oSz
    direct (regVar bld R.N) := (AST.ite tCond n (AST.extract nzcv 1<rt> 3))
    direct (regVar bld R.Z) := (AST.ite tCond z (AST.extract nzcv 1<rt> 2))
    direct (regVar bld R.C) := (AST.ite tCond c (AST.extract nzcv 1<rt> 1))
    direct (regVar bld R.V) := (AST.ite tCond v (AST.xtlo 1<rt> nzcv))
  }

let clzBits src bitSize oprSize bld =
  let x = tmpVar bld oprSize
  match oprSize with
  | 8<rt> ->
    let mask1 = numI32 0x55 8<rt>
    let mask2 = numI32 0x33 8<rt>
    let mask3 = numI32 0x0f 8<rt>
    append bld {
      direct x := src
      direct x := x .| (x >> numI32 1 8<rt>)
      direct x := x .| (x >> numI32 2 8<rt>)
      direct x := x .| (x >> numI32 4 8<rt>)
      direct x := x .- ((x >> numI32 1 8<rt>) .& mask1)
      direct x := ((x >> numI32 2 8<rt>) .& mask2) .+ (x .& mask2)
      direct x := ((x >> numI32 4 8<rt>) .+ x) .& mask3
    }
    numI32 bitSize 8<rt> .- (x .& numI32 15 8<rt>)
  | 16<rt> ->
    let mask1 = numI32 0x5555 16<rt>
    let mask2 = numI32 0x3333 16<rt>
    let mask3 = numI32 0x0f0f 16<rt>
    append bld {
      direct x := src
      direct x := x .| (x >> numI32 1 16<rt>)
      direct x := x .| (x >> numI32 2 16<rt>)
      direct x := x .| (x >> numI32 4 16<rt>)
      direct x := x .| (x >> numI32 8 16<rt>)
      direct x := x .- ((x >> numI32 1 16<rt>) .& mask1)
      direct x := ((x >> numI32 2 16<rt>) .& mask2) .+ (x .& mask2)
      direct x := ((x >> numI32 4 16<rt>) .+ x) .& mask3
      direct x := x .+ (x >> numI32 8 16<rt>)
    }
    numI32 bitSize 16<rt> .- (x .& numI32 31 16<rt>)
  | 32<rt> ->
    let mask1 = numI32 0x55555555 32<rt>
    let mask2 = numI32 0x33333333 32<rt>
    let mask3 = numI32 0x0f0f0f0f 32<rt>
    append bld {
      direct x := src
      direct x := x .| (x >> numI32 1 32<rt>)
      direct x := x .| (x >> numI32 2 32<rt>)
      direct x := x .| (x >> numI32 4 32<rt>)
      direct x := x .| (x >> numI32 8 32<rt>)
      direct x := x .| (x >> numI32 16 32<rt>)
      direct x := x .- ((x >> numI32 1 32<rt>) .& mask1)
      direct x := ((x >> numI32 2 32<rt>) .& mask2) .+ (x .& mask2)
      direct x := ((x >> numI32 4 32<rt>) .+ x) .& mask3
      direct x := x .+ (x >> numI32 8 32<rt>)
      direct x := x .+ (x >> numI32 16 32<rt>)
    }
    numI32 bitSize 32<rt> .- (x .& numI32 63 32<rt>)
  | 64<rt> ->
    let mask1 = numU64 0x5555555555555555UL 64<rt>
    let mask2 = numU64 0x3333333333333333UL 64<rt>
    let mask3 = numU64 0x0f0f0f0f0f0f0f0fUL 64<rt>
    append bld {
      direct x := src
      direct x := x .| (x >> numI32 1 64<rt>)
      direct x := x .| (x >> numI32 2 64<rt>)
      direct x := x .| (x >> numI32 4 64<rt>)
      direct x := x .| (x >> numI32 8 64<rt>)
      direct x := x .| (x >> numI32 16 64<rt>)
      direct x := x .| (x >> numI32 32 64<rt>)
      direct x := x .- ((x >> numI32 1 64<rt>) .& mask1)
      direct x := ((x >> numI32 2 64<rt>) .& mask2) .+ (x .& mask2)
      direct x := ((x >> numI32 4 64<rt>) .+ x) .& mask3
      direct x := x .+ (x >> numI32 8 64<rt>)
      direct x := x .+ (x >> numI32 16 64<rt>)
      direct x := x .+ (x >> numI32 32 64<rt>)
    }
    numI32 bitSize 64<rt> .- (x .& numI32 127 64<rt>)
  | _ ->
    raise InvalidOperandSizeException

let cmn ins bld =
  lift bld ins {
    let src1, src2 = transThreeOprsWithBarrelShift ins bld
    let oSz = ins.OprSize
    let _, (n, z, c, v) = addWithCarry src1 src2 (AST.num0 oSz) oSz
    direct (regVar bld R.N) := n
    direct (regVar bld R.Z) := z
    direct (regVar bld R.C) := c
    direct (regVar bld R.V) := v
  }

let cmp ins bld =
  lift bld ins {
    let src1, src2 = transOprOfCMP ins bld
    let oSz = ins.OprSize
    let _, (n, z, c, v) = addWithCarry src1 (AST.not src2) (AST.num1 oSz) oSz
    direct (regVar bld R.N) := n
    direct (regVar bld R.Z) := z
    direct (regVar bld R.C) := c
    direct (regVar bld R.V) := v
  }

let csel ins bld =
  lift bld ins {
    let dst, s1, s2, cond = transOprOfCSEL ins bld
    sized ins.OprSize dst := AST.ite (conditionHolds bld cond) s1 s2
  }

let csinc ins bld =
  lift bld ins {
    let dst, s1, s2, cond = transOprOfCSINC ins bld
    let oprSize = ins.OprSize
    let cond = conditionHolds bld cond
    sized oprSize dst := AST.ite cond s1 (s2 .+ AST.num1 oprSize)
  }

let csinv ins bld =
  lift bld ins {
    let dst, src1, src2, cond = transOprOfCSINV ins bld
    let cond = conditionHolds bld cond
    sized ins.OprSize dst := AST.ite cond src1 (AST.not src2)
  }

let csneg ins bld =
  lift bld ins {
    let dst, s1, s2, cond = transOprOfCSNEG ins bld
    let s2 = AST.not s2 .+ AST.num1 ins.OprSize
    sized ins.OprSize dst := AST.ite (conditionHolds bld cond) s1 s2
  }

let ctz ins bld =
  lift bld ins {
    let dst, src = transTwoOprs ins bld
    let revSrc = tmpVar bld ins.OprSize
    direct revSrc := bitReverse src ins.OprSize
    let res = countLeadingZeroBitsForIR revSrc (int ins.OprSize) ins.OprSize bld
    sized ins.OprSize dst := res
  }

let dczva ins bld =
  lift bld ins {
    let src = transOneOpr ins bld
    let dczid = regVar bld R.DCZIDEL0
    let struct (idx, n4, len) = tmpVars3 bld 64<rt>
    let lblLoop = label bld "Loop"
    let lblLoopCont = label bld "LoopContinue"
    let lblEnd = label bld "End"
    direct idx := AST.num0 64<rt>
    direct n4 := numI32 4 64<rt>
    direct len := (numI32 2 64<rt> << (dczid .+ numI32 1 64<rt>))
    direct len := len ./ n4
    AST.lmark lblLoop
    AST.cjmp (idx == len) (AST.jmpDest lblEnd) (AST.jmpDest lblLoopCont)
    AST.lmark lblLoopCont
    direct (AST.loadLE 32<rt> (src .+ (idx .* n4))) := AST.num0 32<rt>
    direct idx := idx .+ AST.num1 64<rt>
    AST.jmp (AST.jmpDest lblLoop)
    AST.lmark lblEnd
  }

let checkZero bld dataSize fpVal =
  let isFZ = (regVar bld R.FPCR >> numI32 24 64<rt>) |> AST.xtlo 1<rt>
  let struct (n0, f0) = tmpVars2 bld dataSize
  append bld {
    direct n0 := AST.num0 dataSize
    direct f0 := fpZero fpVal dataSize
  }
  let inline isOnes exp =
    match dataSize with
    | 32<rt> -> exp == numI32 0xFF 32<rt>
    | 64<rt> -> exp == numI32 0x7FF 64<rt>
    | _ -> raise InvalidOperandSizeException
  let struct (exp, frac) = tmpVars2 bld dataSize
  match dataSize with
  | 32<rt> ->
    append bld {
      direct exp := (fpVal >> numI32 23 32<rt>) .& numI32 0xff 32<rt>
      direct frac := fpVal .& numU32 0x7fffffu 32<rt>
    }
  | 64<rt> ->
    append bld {
      direct exp := (fpVal >> numI64 52L 64<rt>) .& numI64 0x7ffL 64<rt>
      direct frac := fpVal .& numU64 0xfffffffffffffUL 64<rt>
    }
  | _ ->
    raise InvalidOperandSizeException
  AST.ite ((exp == n0) .& (frac == n0 .| isFZ))
    f0
    (AST.ite ((isOnes exp) .& (frac != n0)) f0 fpVal)

let private fpCompare bld oprSz src1 src2 =
  let struct (v1, v2) = tmpVars2 bld oprSz
  let isOpNaN = tmpVar bld 1<rt>
  let result = tmpVar bld 8<rt>
  append bld {
    direct v1 := checkZero bld oprSz src1
    direct v2 := checkZero bld oprSz src2
  }
  let lblOpNaN = label bld "OpNaN"
  let lblCmp = label bld "Cmp"
  let lblEq = label bld "Eq"
  let lblNeq = label bld "Neq"
  let lblEnd = label bld "End"
  append bld {
    direct isOpNaN := isNaN oprSz src1 .| isNaN oprSz src2
    AST.cjmp isOpNaN (AST.jmpDest lblOpNaN) (AST.jmpDest lblCmp)
    AST.lmark lblOpNaN
    direct result := numI32 0b0011 8<rt>
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblCmp
    AST.cjmp (AST.feq v1 v2) (AST.jmpDest lblEq) (AST.jmpDest lblNeq)
    AST.lmark lblEq
    direct result := numI32 0b110 8<rt>
    AST.jmp (AST.jmpDest lblEnd)
    AST.lmark lblNeq
  }
  let cond = AST.flt v1 v2
  append bld {
    direct result := AST.ite cond (numI32 0b1000 8<rt>) (numI32 0b0010 8<rt>)
    AST.lmark lblEnd
  }
  result

/// <summary>
/// Whether a comparison raises Invalid: FCMP and FCCMP for a signalling NaN,
/// FCMPE and FCCMPE -- the signalling comparisons -- for any NaN.
/// </summary>
let private compareInvalid (ins: Instruction) src1 src2 =
  let sz = ins.OprSize
  match ins.Opcode with
  | Opcode.FCMPE | Opcode.FCCMPE -> isNaN sz src1 .| isNaN sz src2
  | _ -> isSNaN sz src1 .| isSNaN sz src2

let fcmp (ins: Instruction) bld =
  lift bld ins {
    let src1, src2 = transTwoOprs ins bld
    let flags = tmpVar bld 8<rt>
    direct flags := fpCompare bld ins.OprSize src1 src2
    fpExceptionsInvalidOnly bld (compareInvalid ins src1 src2)
    direct (regVar bld R.N) := AST.extract flags 1<rt> 3
    direct (regVar bld R.Z) := AST.extract flags 1<rt> 2
    direct (regVar bld R.C) := AST.extract flags 1<rt> 1
    direct (regVar bld R.V) := AST.extract flags 1<rt> 0
  }

let fccmp (ins: Instruction) bld =
  lift bld ins {
    let src1, src2, nzcv, cond = transOprOfCCMP ins bld
    let flags = tmpVar bld 8<rt>
    let holds = tmpVar bld 1<rt>
    direct holds := conditionHolds bld cond
    let comp = fpCompare bld ins.OprSize src1 src2
    direct flags := AST.ite holds comp (AST.xtlo 8<rt> nzcv)
    (* nothing is compared where the condition fails, so nothing is raised *)
    fpExceptionsInvalidOnly bld (holds .& compareInvalid ins src1 src2)
    direct (regVar bld R.N) := AST.extract flags 1<rt> 3
    direct (regVar bld R.Z) := AST.extract flags 1<rt> 2
    direct (regVar bld R.C) := AST.extract flags 1<rt> 1
    direct (regVar bld R.V) := AST.extract flags 1<rt> 0
  }

let ldar ins bld =
  lift bld ins {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    direct address := bReg .+ offset
    sized ins.OprSize dst := AST.loadLE ins.OprSize address
  }

let ldarb ins bld =
  lift bld ins {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    direct address := bReg .+ offset
    sized ins.OprSize dst := AST.loadLE 8<rt> address
  }

let ldax ins bld size =
  lift bld ins {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    let value = tmpVar bld size
    direct address := bReg .+ offset
    direct value := AST.loadLE size address
    reserveExclusive bld address value
    sized ins.OprSize dst := value
  }

let ldaxr ins bld =
  lift bld ins {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    let value = tmpVar bld ins.OprSize
    direct address := bReg .+ offset
    direct value := AST.loadLE ins.OprSize address
    reserveExclusive bld address value
    sized ins.OprSize dst := value
  }

let ldaxp ins bld =
  lift bld ins {
    let dst1, dst2, (bReg, offset) = transThreeOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    direct address := bReg .+ offset
    reserveExclusive bld address (AST.loadLE 64<rt> address)
    if ins.OprSize = 32<rt> then
      let src = AST.loadLE 64<rt> address
      sized ins.OprSize dst1 := AST.xtlo 32<rt> src
      sized ins.OprSize dst2 := AST.xthi 32<rt> src
    else
      direct dst1 := (AST.loadLE 64<rt> address)
      direct dst2 := (AST.loadLE 64<rt> (address .+ numI32 8 64<rt>))
  }

let ldpsw ins bld =
  lift bld ins {
    let src1, src2, (bReg, offset) = transThreeOprsSepMem ins bld
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data1 = tmpVar bld 32<rt>
    let data2 = tmpVar bld 32<rt>
    direct address := bReg
    direct address := if isPostIndex then address else address .+ offset
    direct data1 := AST.loadLE 32<rt> address
    direct data2 := AST.loadLE 32<rt> (address .+ numI32 4 64<rt>)
    direct src1 := AST.sext 64<rt> data1
    direct src2 := AST.sext 64<rt> data2
    writeBack bld isWBack isPostIndex bReg address offset
  }

let ldrb ins bld =
  lift bld ins {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 8<rt>
    direct address := bReg
    direct address := if isPostIndex then address else address .+ offset
    direct data := AST.loadLE 8<rt> address
    sized ins.OprSize dst := AST.zext 32<rt> data
    writeBack bld isWBack isPostIndex bReg address offset
  }

let ldrh ins bld =
  lift bld ins {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 16<rt>
    direct address := bReg
    direct address := if isPostIndex then address else address .+ offset
    direct data := AST.loadLE 16<rt> address
    sized ins.OprSize dst := AST.zext 32<rt> data
    writeBack bld isWBack isPostIndex bReg address offset
  }

let ldrsb ins bld =
  lift bld ins {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 8<rt>
    direct address := bReg
    direct address := if isPostIndex then address else address .+ offset
    direct data := AST.loadLE 8<rt> address
    sized ins.OprSize dst := AST.sext ins.OprSize data
    writeBack bld isWBack isPostIndex bReg address offset
  }

let ldrsh ins bld =
  lift bld ins {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 16<rt>
    direct address := bReg
    direct address := if isPostIndex then address else address .+ offset
    direct data := AST.loadLE 16<rt> address
    sized ins.OprSize dst := AST.sext ins.OprSize data
    writeBack bld isWBack isPostIndex bReg address offset
  }

let ldrsw (ins: Instruction) bld =
  lift bld ins {
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 32<rt>
    match ins.Operands with
    | TwoOperands(o1, OprMemory(LiteralMode o2)) ->
      let dst = transOpr ins bld o1
      let offset = transOpr ins bld (OprMemory(LiteralMode o2))
      direct address := getPC bld .+ offset
      direct data := AST.loadLE 32<rt> address
      direct dst := AST.sext 64<rt> data
    | TwoOperands(o1, o2) ->
      let dst = transOpr ins bld o1
      let bReg, offset = transOpr ins bld o2 |> separateMemExpr
      let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
      direct address := bReg
      direct address := if isPostIndex then address else address .+ offset
      direct data := AST.loadLE 32<rt> address
      direct dst := AST.sext 64<rt> data
      writeBack bld isWBack isPostIndex bReg address offset
    | _ ->
      raise InvalidOperandException
  }

let ldtr ins bld =
  lift bld ins {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld ins.OprSize
    direct address := bReg .+ offset
    direct data := AST.loadLE ins.OprSize address
    sized ins.OprSize dst := AST.zext ins.OprSize data
  }

let ldurb ins bld =
  lift bld ins {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 8<rt>
    direct address := bReg
    direct address := address .+ offset
    direct data := AST.loadLE 8<rt> address
    sized ins.OprSize src := AST.zext 32<rt> data
  }

let ldurh ins bld =
  lift bld ins {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 16<rt>
    direct address := bReg
    direct address := address .+ offset
    direct data := AST.loadLE 16<rt> address
    sized ins.OprSize src := AST.zext 32<rt> data
  }

let ldursb ins bld =
  lift bld ins {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 8<rt>
    direct address := bReg .+ offset
    direct data := AST.loadLE 8<rt> address
    sized ins.OprSize dst := AST.sext ins.OprSize data
  }

let ldursh ins bld =
  lift bld ins {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 16<rt>
    direct address := bReg .+ offset
    direct data := AST.loadLE 16<rt> address
    sized ins.OprSize dst := AST.sext ins.OprSize data
  }

let ldursw ins bld =
  lift bld ins {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 32<rt>
    direct address := bReg
    direct address := address .+ offset
    direct data := AST.loadLE 32<rt> address
    sized ins.OprSize dst := AST.sext 64<rt> data
  }

let lslv ins bld =
  lift bld ins {
    let dst, src1, src2 = transThreeOprs ins bld
    let oprSz = ins.OprSize
    let dataSize = numI32 (RegType.toBitWidth ins.OprSize) oprSz
    let result = shiftReg src1 (src2 .% dataSize) oprSz LSL
    sized ins.OprSize dst := result
  }

let lsrv ins bld =
  lift bld ins {
    let dst, src1, src2 = transThreeOprs ins bld
    let oprSz = ins.OprSize
    let dataSize = numI32 (RegType.toBitWidth oprSz) oprSz
    let result = shiftReg src1 (src2 .% dataSize) oprSz LSR
    sized ins.OprSize dst := result
  }

let movn (ins: Instruction) bld =
  lift bld ins {
    let dst, src = transThreeOprsWithBarrelShift ins bld
    sized ins.OprSize dst := AST.not src
  }

let movz (ins: Instruction) bld =
  lift bld ins {
    let dst, src = transThreeOprsWithBarrelShift ins bld
    sized ins.OprSize dst := src
  }

let msr (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    match dst with
    | OprRegister R.NZCV ->
      let src = transOpr ins bld src
      direct (regVar bld R.N) := AST.extract src 1<rt> 31
      direct (regVar bld R.Z) := AST.extract src 1<rt> 30
      direct (regVar bld R.C) := AST.extract src 1<rt> 29
      direct (regVar bld R.V) := AST.extract src 1<rt> 28
    | _ ->
      let dst = transOpr ins bld dst
      let src = transOpr ins bld src
      direct dst := src
  }

let msub ins bld =
  lift bld ins {
    let dst, src1, src2, src3 = transOprOfMSUB ins bld
    sized ins.OprSize dst := src3 .- (src1 .* src2)
  }

let nop ins bld =
  lift bld ins { }

let ret ins bld =
  lift bld ins {
    let src = transOneOpr ins bld
    let target = tmpVar bld 64<rt>
    direct target := src
    branchTo ins bld target BrTypeRET InterJmpKind.IsRet
    return NoEndMark
  }

let rorv ins bld =
  lift bld ins {
    let dst, src1, src2 = transThreeOprs ins bld
    let amount = src2 .% oprSzToExpr ins.OprSize
    sized ins.OprSize dst := shiftReg src1 amount ins.OprSize ROR
  }

let sbc ins bld =
  lift bld ins {
    let dst, src1, src2 = transThreeOprs ins bld
    let c = AST.zext ins.OprSize (regVar bld R.C)
    let result, _ = addWithCarry src1 (AST.not src2) c ins.OprSize
    sized ins.OprSize dst := result
  }

let sbcs ins bld =
  lift bld ins {
    let dst, src1, src2 = transThreeOprs ins bld
    let c = tmpVar bld ins.OprSize
    direct c := AST.zext ins.OprSize (regVar bld R.C)
    let result, (n, z, c, v) = addWithCarry src1 (AST.not src2) c ins.OprSize
    direct (regVar bld R.N) := n
    direct (regVar bld R.Z) := z
    direct (regVar bld R.C) := c
    direct (regVar bld R.V) := v
    sized ins.OprSize dst := result
  }

let sbfm (ins: Instruction) bld dst src immr imms =
  lift bld ins {
    let oprSz = ins.OprSize
    let width = oprSzToExpr oprSz
    let struct (wmask, tmask) = decodeBitMasks immr imms (int oprSz)
    let immr = transOpr ins bld immr
    let imms = transOpr ins bld imms
    let n0 = AST.num0 oprSz
    let struct (bot, srcS, top, tMask) = tmpVars4 bld oprSz
    direct bot := rorForIR src immr width .& (numI64 wmask oprSz)
    direct srcS := (src >> imms) .& (AST.num1 oprSz)
    direct top := AST.ite (srcS == n0) n0 (numI32 -1 oprSz)
    direct tMask := numI64 tmask oprSz
    sized ins.OprSize dst := (top .& AST.not tMask) .| (bot .& tMask)
  }

let sbfiz ins bld =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let dst = transOpr ins bld dst
  let src = transOpr ins bld src
  let immr = ((getImmValue lsb * -1L) &&& 0x3FL) % int64 ins.OprSize |> OprImm
  let imms = getImmValue width - 1L |> OprImm
  sbfm ins bld dst src immr imms

let sbfx ins bld =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let dst = transOpr ins bld dst
  let src = transOpr ins bld src
  let imms = (getImmValue lsb) + (getImmValue width) - 1L |> OprImm
  sbfm ins bld dst src lsb imms

let sdiv ins bld =
  lift bld ins {
    let dst, src1, src2 = transThreeOprs ins bld
    let intMin =
      numI64 (1L <<< (RegType.toBitWidth ins.OprSize - 1)) ins.OprSize
    let isZero = AST.eq src2 (AST.num0 ins.OprSize)
    let isOverflow =
      (AST.eq src1 intMin) .& (AST.eq src2 (numI64 -1L ins.OprSize))
    let result =
      AST.ite isZero (AST.num0 ins.OprSize)
                     (AST.ite isOverflow intMin (src1 ?/ src2))
    sized ins.OprSize dst := result
  }

let smaddl ins bld =
  lift bld ins {
    let dst, src1, src2, src3 = transFourOprs ins bld
    direct dst := src3 .+ (AST.sext 64<rt> src1 .* AST.sext 64<rt> src2)
  }

let smov (ins: Instruction) bld =
  lift bld ins {
    let result = tmpVar bld ins.OprSize
    let dst, src = transTwoOprs ins bld
    direct result := AST.sext ins.OprSize src
    sized ins.OprSize dst := result
  }

let smsubl ins bld =
  lift bld ins {
    let dst, src1, src2, src3 = transOprOfSMSUBL ins bld
    direct dst := src3 .- (AST.sext 64<rt> src1 .* AST.sext 64<rt> src2)
  }

let stlr ins bld =
  lift bld ins {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    direct address := bReg .+ offset
    sized ins.OprSize (AST.loadLE ins.OprSize address) := src
  }

let stlrb ins bld =
  lift bld ins {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 8<rt>
    direct address := bReg .+ offset
    direct data := AST.xtlo 8<rt> src
    direct (AST.loadLE 8<rt> address) := data
  }

let stlx ins bld size =
  lift bld ins {
    let src1, src2, (bReg, offset) = transThreeOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld size
    direct address := bReg .+ offset
    direct data := AST.xtlo size src2
    let status = storeExclusive bld address size data
    sized 32<rt> src1 := status
  }

let stlxr ins bld =
  lift bld ins {
    let src1, src2, (bReg, offset) = transThreeOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld ins.OprSize
    direct address := bReg .+ offset
    direct data := AST.zext ins.OprSize src2
    let status = storeExclusive bld address ins.OprSize data
    sized 32<rt> src1 := status
  }

let stlxp ins bld =
  lift bld ins {
    let src1, src2, src3, (bReg, offset) = transFourOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    direct address := bReg .+ offset
    if ins.OprSize = 32<rt> then
      let data = tmpVar bld 64<rt>
      direct data := AST.concat (AST.xtlo 32<rt> src3) (AST.xtlo 32<rt> src2)
      let status = storeExclusive bld address 64<rt> data
      sized 32<rt> src1 := status
    else
      let status = storeExclusivePair bld address 64<rt> src2 src3
      sized 32<rt> src1 := status
  }

let strb ins bld =
  lift bld ins {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 8<rt>
    direct address := bReg
    direct address := if isPostIndex then address else address .+ offset
    direct data := AST.xtlo 8<rt> src
    direct (AST.loadLE 8<rt> address) := data
    writeBack bld isWBack isPostIndex bReg address offset
  }

let strh ins bld =
  lift bld ins {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 16<rt>
    direct address := bReg
    direct address := if isPostIndex then address else address .+ offset
    direct data := AST.xtlo 16<rt> src
    direct (AST.loadLE 16<rt> address) := data
    writeBack bld isWBack isPostIndex bReg address offset
  }

let sttrb ins bld =
  lift bld ins {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 8<rt>
    direct address := bReg
    direct address := address .+ offset
    direct data := AST.xtlo 8<rt> src
    direct (AST.loadLE 8<rt> address) := data
  }

let sturb ins bld =
  lift bld ins {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 8<rt>
    direct address := bReg
    direct address := address .+ offset
    direct data := AST.xtlo 8<rt> src
    direct (AST.loadLE 8<rt> address) := data
  }

let sturh ins bld =
  lift bld ins {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    let data = tmpVar bld 16<rt>
    direct address := bReg
    direct address := address .+ offset
    direct data := AST.xtlo 16<rt> src
    direct (AST.loadLE 16<rt> address) := data
  }

let subs (ins: Instruction) bld =
  lift bld ins {
    let dst, src1, src2 = transOprOfSUBS ins bld
    let result, (n, z, c, v) =
      addWithCarry src1 src2 (AST.num1 ins.OprSize) ins.OprSize
    direct (regVar bld R.N) := n
    direct (regVar bld R.Z) := z
    direct (regVar bld R.C) := c
    direct (regVar bld R.V) := v
    sized ins.OprSize dst := result
  }

let svc (ins: Instruction) bld =
  lift bld ins {
    let n =
      match ins.Operands with
      | OneOperand(OprImm n) -> int n
      | _ -> raise InvalidOperandException
    AST.sideEffect (Interrupt n)
  }

let sxtb ins bld =
  let struct (dst, src) = getTwoOprs ins
  let dst = transOpr ins bld dst
  let src = transOpr ins bld src
  let src = if ins.OprSize = 64<rt> then unwrapReg src else src
  sbfm ins bld dst src (OprImm 0L) (OprImm 7L)

let sxth ins bld =
  let struct (dst, src) = getTwoOprs ins
  let dst = transOpr ins bld dst
  let src = transOpr ins bld src
  let src = if ins.OprSize = 64<rt> then unwrapReg src else src
  sbfm ins bld dst src (OprImm 0L) (OprImm 15L)

let sxtw ins bld =
  let struct (dst, src) = getTwoOprs ins
  let dst = transOpr ins bld dst
  let src = transOpr ins bld src |> unwrapReg
  sbfm ins bld dst src (OprImm 0L) (OprImm 31L)

let tbnz ins bld =
  lift bld ins {
    let test, imm, label = transThreeOprs ins bld
    let pc = numU64 (ins:Instruction).Address bld.RegType
    let fall = pc .+ numU32 ins.Length 64<rt>
    let cond = (test >> imm .& AST.num1 ins.OprSize) == AST.num1 ins.OprSize
    AST.intercjmp cond (pc .+ label) fall
    return NoEndMark
  }

let tbz ins bld =
  lift bld ins {
    let test, imm, label = transThreeOprs ins bld
    let pc = numU64 (ins:Instruction).Address bld.RegType
    let fall = pc .+ numU32 ins.Length 64<rt>
    let cond = (test >> imm .& AST.num1 ins.OprSize) == AST.num0 ins.OprSize
    AST.intercjmp cond (pc .+ label) fall
    return NoEndMark
  }

let tst ins bld =
  lift bld ins {
    let src1, src2 = transOprOfTST ins bld
    let result = tmpVar bld ins.OprSize
    direct result := src1 .& src2
    direct (regVar bld R.N) := AST.xthi 1<rt> result
    direct (regVar bld R.Z) := result == AST.num0 ins.OprSize
    direct (regVar bld R.C) := AST.b0
    direct (regVar bld R.V) := AST.b0
  }

let ubfm (ins: Instruction) bld dst src immr imms =
  lift bld ins {
    let oSz = ins.OprSize
    let width = oprSzToExpr oSz
    let struct (wmask, tmask) = decodeBitMasks immr imms (int oSz)
    let dst = transOpr ins bld dst
    let src = transOpr ins bld src
    let immr = transOpr ins bld immr
    let bot = tmpVar bld oSz
    direct bot := rorForIR src immr width .& (numI64 wmask oSz)
    sized ins.OprSize dst := bot .& (numI64 tmask oSz)
  }

let ubfiz ins bld =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let immr = ((getImmValue lsb * -1L) &&& 0x3FL) % int64 ins.OprSize |> OprImm
  let imms = getImmValue width - 1L |> OprImm
  ubfm ins bld dst src immr imms

let ubfx ins bld =
  let struct (dst, src, lsb, width) = getFourOprs ins
  let imms = (getImmValue lsb) + (getImmValue width) - 1L |> OprImm
  ubfm ins bld dst src lsb imms

let udiv ins bld =
  lift bld ins {
    let dst, src1, src2 = transThreeOprs ins bld
    let num0 = AST.num0 ins.OprSize
    let cond1 = AST.eq src2 num0
    let divSrc = src1 ./ src2
    let result = AST.ite cond1 num0 divSrc
    sized ins.OprSize dst := result
  }

let umaddl ins bld =
  lift bld ins {
    let dst, src1, src2, src3 = transFourOprs ins bld
    direct dst := src3 .+ (AST.zext 64<rt> src1 .* AST.zext 64<rt> src2)
  }

let umov (ins: Instruction) bld =
  lift bld ins {
    let dst, src = transTwoOprs ins bld
    sized ins.OprSize dst := src
  }

let umsubl ins bld =
  lift bld ins {
    let dst, src1, src2, src3 = transOprOfUMADDL ins bld
    direct dst := src3 .- (AST.zext 64<rt> src1 .* AST.zext 64<rt> src2)
  }

let uxtb ins bld =
  let struct (dst, src) = getTwoOprs ins
  ubfm ins bld dst src (OprImm 0L) (OprImm 7L)

let uxth ins bld =
  let struct (dst, src) = getTwoOprs ins
  ubfm ins bld dst src (OprImm 0L) (OprImm 15L)

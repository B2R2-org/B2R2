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

/// <summary>
/// The four bits of an address that hold a memory tag, and the same as a
/// mask.
///
/// A tagged pointer keeps its tag in bits 59:56, which are part of the top
/// byte an address does not use for addressing.
/// </summary>
let private tagShift = numI32 56 64<rt>

let private tagMask = numU64 0x0f00000000000000UL 64<rt>

/// <summary>
/// IRG, which replaces the tag of an address with one chosen at random from
/// the tags that are not excluded.
///
/// Which tag it chooses is not fixed by the architecture, and the exclusion
/// set that decides it lives in a system register this model does not carry.
/// A process that has not asked for tagging has every tag excluded, and
/// ChooseNonExcludedTag answers zero when there is nothing to choose from --
/// which is the answer the reference gives and the one taken here.
/// </summary>
let insertRandomTag (ins: Instruction) bld =
  lift bld ins {
    (* The third operand, where it is written, names tag values to keep the
       choice away from. The tag a process gets here is zero whichever
       values it excludes, so the operand is read and not used. *)
    let struct (dst, src) =
      match ins.Operands with
      | TwoOperands(d, s) | ThreeOperands(d, s, _) ->
        struct (transOpr ins bld d, transOpr ins bld s)
      | _ ->
        raise InvalidOperandException
    sized 64<rt> dst := src .& AST.not tagMask
  }

/// <summary>
/// GMI, which adds a tag to a set of them.
///
/// The set is a sixteen-bit mask with one bit per tag value, and this sets
/// the bit the first operand's tag names, leaving the rest of the second
/// operand as it was.
/// </summary>
let tagMaskInsert ins bld =
  lift bld ins {
    let dst, src1, src2 = transThreeOprs ins bld
    let tag = (src1 .& tagMask) >> tagShift
    sized 64<rt> dst := src2 .| (AST.num1 64<rt> << tag)
  }

/// <summary>
/// LDG, which reads the tag of the granule an address points into and puts
/// it in the destination, keeping every other bit of it.
///
/// There is no tag memory here, so what it reads is zero -- the tag an
/// untagged granule has. The rest of the register is kept, which is the part
/// of this instruction a model can be wrong about.
/// </summary>
let loadTag ins bld =
  lift bld ins {
    let struct (dst, _) = getTwoOprs ins
    let dst = transOpr ins bld dst
    sized 64<rt> dst := dst .& AST.not tagMask
  }

/// <summary>
/// STG, ST2G and STGM, which write a tag to one granule, to two, or to a
/// whole block.
///
/// The tag memory they write is not addressable and nothing here reads it
/// back, so what they leave behind is nothing. The zeroing forms below are
/// the ones with an effect a program can see.
/// </summary>
let storeTag ins bld =
  lift bld ins {
    ()
  }

/// <summary>
/// STZG and STZ2G, which write a tag AND clear the granule it belongs to.
///
/// The clearing is the part that shows: sixteen bytes for the one-granule
/// form and thirty-two for the other, at the address the operand names with
/// its tag bits still in place -- the address an instruction uses is the
/// whole of it.
/// </summary>
let storeTagZeroing ins bld granules =
  lift bld ins {
    let struct (_, mem) = getTwoOprs ins
    let bReg, offset = transOpr ins bld mem |> separateMemExpr
    let address = tmpVar bld 64<rt>
    direct address := bReg .+ offset
    for i in 0 .. granules * 2 - 1 do
      direct (AST.loadLE 64<rt> (address .+ numI32 (i * 8) 64<rt>)) :=
        AST.num0 64<rt>
  }

/// <summary>
/// STGP, which stores a pair of registers and a tag at once.
///
/// The pair is stored the way any pair is; the tag goes where the other tag
/// stores go, which is nowhere a program can look.
/// </summary>
let storeTagPair ins bld =
  lift bld ins {
    let struct (o1, o2, mem) = getThreeOprs ins
    let src1 = transOpr ins bld o1
    let src2 = transOpr ins bld o2
    let bReg, offset = transOpr ins bld mem |> separateMemExpr
    let address = tmpVar bld 64<rt>
    direct address := bReg .+ offset
    direct (AST.loadLE 64<rt> address) := src1
    direct (AST.loadLE 64<rt> (address .+ numI32 8 64<rt>)) := src2
  }

/// <summary>
/// LDGM, which reads the tags of a whole block of granules into a register.
///
/// With no tag memory every tag is zero, and the bits no tag is written to
/// are zero by definition, so the register becomes zero.
/// </summary>
let loadTagMultiple ins bld =
  lift bld ins {
    let struct (dst, _) = getTwoOprs ins
    let dst = transOpr ins bld dst
    sized 64<rt> dst := AST.num0 64<rt>
  }

/// <summary>
/// Clears the block DC ZVA clears around an address: 4 << DCZID_EL0.BS
/// bytes, from the address aligned down to that size, a word at a time.
/// </summary>
let private zeroBlock bld address =
  let dczid = regVar bld R.DCZIDEL0
  let struct (size, start, idx) = tmpVars3 bld 64<rt>
  let lblLoop = label bld "Loop"
  let lblLoopCont = label bld "LoopContinue"
  let lblEnd = label bld "End"
  append bld {
    direct size := numI32 4 64<rt> << (dczid .& numI32 0xf 64<rt>)
    direct start := address .& AST.not (size .- AST.num1 64<rt>)
    direct idx := AST.num0 64<rt>
    AST.lmark lblLoop
    AST.cjmp (idx == size) (AST.jmpDest lblEnd) (AST.jmpDest lblLoopCont)
    AST.lmark lblLoopCont
    direct (AST.loadLE 32<rt> (start .+ idx)) := AST.num0 32<rt>
    direct idx := idx .+ numI32 4 64<rt>
    AST.jmp (AST.jmpDest lblLoop)
    AST.lmark lblEnd
  }

/// <summary>
/// STZGM, which writes the tags of the block DC ZVA clears and clears it.
/// The tags go nowhere a program can read, the way STG's do; the clearing
/// is what shows.
/// </summary>
let storeTagZeroingMultiple ins bld =
  lift bld ins {
    let struct (_, mem) = getTwoOprs ins
    let bReg, offset = transOpr ins bld mem |> separateMemExpr
    zeroBlock bld (bReg .+ offset)
  }

/// <summary>
/// ADDG and SUBG, which move an address by an offset and give it a tag.
///
/// The two halves are independent: the offset never carries into the tag and
/// the tag never disturbs the address. The offset is what the operand says,
/// and the tag is the one ChooseNonExcludedTag picks starting from the
/// address's own -- except that the whole of that choosing is gated on
/// allocation tag access being enabled, and where it is not the tag written
/// is zero however the operands read. That is the same gate <see
/// cref="insertRandomTag"/> answers zero for, and the same answer.
///
/// So the second immediate is read and not used, and the tag field is
/// cleared rather than left as it was -- an address arriving here with a tag
/// already in it loses it.
/// </summary>
let private tagOffset (ins: Instruction) bld isSub =
  lift bld ins {
    let struct (dst, src, off, _) = getFourOprs ins
    let d = transOpr ins bld dst
    let n = transOpr ins bld src
    let offset = numI64 (getImmValue off) 64<rt>
    let addr = if isSub then n .- offset else n .+ offset
    sized 64<rt> d := addr .& AST.not tagMask
  }

let addg ins bld = tagOffset ins bld false

let subg ins bld = tagOffset ins bld true

/// <summary>
/// SUBP, SUBPS and CMPP: the difference of two addresses with their tags
/// ignored.
///
/// Ignored means SIGN EXTENDED from bit 55, not masked off: the difference
/// of two addresses in the upper half of the space has to come out the same
/// as the difference of two in the lower half, and masking would make one of
/// them enormous. SUBPS sets the flags from that subtraction, and CMPP is
/// the SUBPS that throws the answer away.
/// </summary>
let private tagSubtract (ins: Instruction) bld setsFlags =
  lift bld ins {
    let struct (d, n, m) =
      match ins.Operands with
      | ThreeOperands(a, b, c) ->
        struct (transOpr ins bld a, transOpr ins bld b, transOpr ins bld c)
      | TwoOperands(b, c) ->
        struct (regVar bld R.XZR, transOpr ins bld b, transOpr ins bld c)
      | _ ->
        raise InvalidOperandException
    let bare e = AST.sext 64<rt> (AST.xtlo 56<rt> e)
    let struct (x, y) = tmpVars2 bld 64<rt>
    direct x := bare n
    direct y := bare m
    let one = AST.num1 64<rt>
    let result, (nf, zf, cf, vf) = addWithCarry x (AST.not y) one 64<rt>
    if setsFlags then
      direct (regVar bld R.N) := nf
      direct (regVar bld R.Z) := zf
      direct (regVar bld R.C) := cf
      direct (regVar bld R.V) := vf
    else
      ()
    sized 64<rt> d := result
  }

let subp ins bld = tagSubtract ins bld false

let subps ins bld = tagSubtract ins bld true

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

/// <summary>
/// One step of a bit-reflected CRC: shift the remainder down by a bit and,
/// when the bit that fell out was set, subtract the polynomial.
///
/// The polynomial is given reflected too, which is what lets the whole thing
/// run from the bottom of the word rather than the top. Subtraction over GF(2)
/// is exclusive or, so there is no borrow to carry between steps.
/// </summary>
let private crcStep bld poly crc =
  let one = AST.num1 32<rt>
  let shifted = crc >> one
  let next = AST.ite ((crc .& one) == one) (shifted <+> poly) shifted
  append bld { direct crc := next }

/// <summary>
/// CRC32 and CRC32C, over a byte, a halfword, a word or a doubleword.
///
/// The manual states them by reversing the accumulator and the data, running
/// a polynomial division from the top, and reversing the answer. Reversing
/// the POLYNOMIAL instead says the same thing and leaves everything else the
/// right way up, which is why the constants below are the reflections of
/// 0x04C11DB7 and 0x1EDC6F41.
///
/// A doubleword is two words: the low word is mixed in and thirty-two steps
/// run, then the high word and thirty-two more. That is the same division,
/// written the way a table-driven implementation writes it.
/// </summary>
let crc32 (ins: Instruction) bld isCastagnoli (size: int<rt>) =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let dst = transOpr ins bld dst
    let acc = transOpr ins bld src1 |> AST.xtlo 32<rt>
    let value = transOpr ins bld src2
    let poly =
      if isCastagnoli then numU32 0x82F63B78u 32<rt>
      else numU32 0xEDB88320u 32<rt>
    let crc = tmpVar bld 32<rt>
    let wordOf pos =
      if size = 64<rt> then AST.extract value 32<rt> pos
      elif size = 32<rt> then AST.xtlo 32<rt> value
      else AST.zext 32<rt> (AST.xtlo size value)
    direct crc := acc <+> wordOf 0
    (* A doubleword is two words: the low one is mixed in above and the high
       one here, each followed by thirty-two steps. *)
    let rounds = if size = 64<rt> then [ 32 ] else []
    for _ in 1 .. min (int size) 32 do
      crcStep bld poly crc
    for pos in rounds do
      direct crc := crc <+> wordOf pos
      for _ in 1 .. 32 do
        crcStep bld poly crc
    sized 32<rt> dst := crc
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
/// The comparison at the operands' own width: a half's in doubles, which
/// hold every half exactly and so order them the same way.
/// </summary>
let private fpCompareAt bld oprSz src1 src2 =
  if oprSz = 16<rt> then
    let struct (w1, w2) = tmpVars2 bld 64<rt>
    let e1 = halfToWide false 64<rt> bld src1
    let e2 = halfToWide false 64<rt> bld src2
    append bld {
      direct w1 := e1
      direct w2 := e2
    }
    fpCompare bld 64<rt> w1 w2
  else
    fpCompare bld oprSz src1 src2

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
    direct flags := fpCompareAt bld ins.OprSize src1 src2
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
    let comp = fpCompareAt bld ins.OprSize src1 src2
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

/// An acquiring load of less than a whole register, zero-extended into it.
/// The width of the access is what the mnemonic's last letter says.
let ldarSized ins bld accSz =
  lift bld ins {
    let dst, (bReg, offset) = transTwoOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    direct address := bReg .+ offset
    sized ins.OprSize dst := AST.loadLE accSz address
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

/// A releasing store of less than a whole register, taking the low bits of
/// it. The width of the access is what the mnemonic's last letter says.
let stlrSized ins bld accSz =
  lift bld ins {
    let src, (bReg, offset) = transTwoOprsSepMem ins bld
    let address = tmpVar bld 64<rt>
    direct address := bReg .+ offset
    direct (AST.loadLE accSz address) := AST.xtlo accSz src
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

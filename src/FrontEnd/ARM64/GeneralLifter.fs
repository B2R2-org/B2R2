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
    let result = sumWithCarry src1 src2 c
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
    sized ins.OprSize dst := getPC bld .+ label
  }

let adrp ins bld =
  lift bld ins {
    let dst, lbl = transTwoOprs ins bld
    sized ins.OprSize dst :=
      (getPC bld .& numI64 0xfffffffffffff000L 64<rt>) .+ lbl
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

/// BLR, which reads its target before it writes the link register: the two
/// are the same register in BLR X30.
let blr ins bld =
  lift bld ins {
    let target = tmpVar bld 64<rt>
    direct target := transOneOpr ins bld
    let pc = numU64 (ins:Instruction).Address bld.RegType
    direct (regVar bld R.X30) := pc .+ numI64 4L ins.OprSize
    (* FIXME: BranchTo (BranchType_INDCALL) *)
    AST.interjmp target InterJmpKind.IsCall
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
///
/// The manual's MemAtomicCompareAndSwap is
/// <c>_Mem[memaddrdesc, size DIV 8, ...]</c>, which is four for the W forms.
/// The address used to come in through transThreeOprs, whose memory path
/// hardcodes a 64-bit load, so a 32-bit CAS read eight bytes and on a
/// successful swap wrote eight -- corrupting the word above the one it was
/// given, and faulting on a four-byte CAS at the end of a mapped page.
///
/// The destination is the other half of it. <c>direct dst :=</c> bypasses
/// assignXZRAware, so a W-form result was written as a partial register,
/// leaving Xd's high half from before the instruction where the manual says
/// <c>X[s] = ZeroExtend(data, regsize)</c>, and a write to XZR was stored
/// rather than discarded. <c>sized</c> is the form every other GPR-writing
/// lifter in this file uses; this one was the outlier.
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
/// back, so what they leave behind is the base register alone, which the
/// post-index and pre-index forms write the address back to as any store
/// does. The zeroing forms below have an effect on memory too.
/// </summary>
let storeTag ins bld =
  lift bld ins {
    let struct (_, mem) = getTwoOprs ins
    let bReg, offset = transOpr ins bld mem |> separateMemExpr
    let isWBack, _ = getIsWBackAndIsPostIndex ins.Operands
    if isWBack then direct bReg := bReg .+ offset else ()
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
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    direct address := if isPostIndex then bReg else bReg .+ offset
    for i in 0 .. granules * 2 - 1 do
      direct (AST.loadLE 64<rt> (address .+ numI32 (i * 8) 64<rt>)) :=
        AST.num0 64<rt>
    writeBack bld isWBack isPostIndex bReg address offset
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
    let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
    let address = tmpVar bld 64<rt>
    direct address := if isPostIndex then bReg else bReg .+ offset
    direct (AST.loadLE 64<rt> address) := src1
    direct (AST.loadLE 64<rt> (address .+ numI32 8 64<rt>)) := src2
    writeBack bld isWBack isPostIndex bReg address offset
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

/// <summary>
/// The bits a pointer authentication code occupies, for a pointer whose
/// address is forty-eight bits: the whole of 63:56 and 54:48, with bit 55
/// left alone because it is what the rest is a sign extension of.
/// </summary>
let private pacFieldMask = 0xff7f000000000000UL

/// <summary>
/// A pointer with its authentication code taken off, which is bit 55
/// extended back over the field.
///
/// This is XPAC, and it is also the first thing every signing and
/// authenticating instruction does -- what is signed is the ADDRESS, not
/// whatever was in the field before.
/// </summary>
let private stripPAC bld x =
  let mask = numU64 pacFieldMask 64<rt>
  (* bit 55, which is what the field either side of it is a sign extension
     of -- not bit 63, and not what shifting the whole word left by one and
     taking its top bit gives, which is bit 62 *)
  let upper = AST.extract x 1<rt> 55
  let t = tmpVar bld 64<rt>
  append bld {
    direct t := AST.ite (upper == AST.b1) (x .| mask) (x .& AST.not mask)
  }
  t

/// <summary>
/// The signature of an address under a modifier.
///
/// The architecture leaves the function itself IMPLEMENTATION DEFINED and
/// fixes only where the answer goes, so this is a mixing function of this
/// front end's own -- a multiply by an odd constant and two folds, which is
/// enough to make the signature depend on every bit of both inputs. What a
/// program can hold it to is that signing changes the pointer and that
/// authenticating undoes it, and both of those are true of any deterministic
/// function.
///
/// The fifteen bits it produces are split the way the field is: eight above
/// bit 55 and seven below it.
/// </summary>
let private pacSignature bld addr modifier =
  let s = tmpVar bld 64<rt>
  let mixed = (addr <+> modifier) .* numU64 0x9e3779b97f4a7c15UL 64<rt>
  append bld {
    direct s := (mixed >> numI32 49 64<rt>) <+> (mixed >> numI32 17 64<rt>)
  }
  let bits = s .& numI32 0x7fff 64<rt>
  ((bits >> numI32 7 64<rt>) << numI32 56 64<rt>)
  .| ((bits .& numI32 0x7f 64<rt>) << numI32 48 64<rt>)

/// <summary>
/// What a failed authentication makes of the address. The manual's Auth()
/// (J1-7662) writes key_number:NOT(key_number) into bits 62:61 in place of
/// what was there -- 01 under an A key, 10 under a B key -- so the pointer is
/// non-canonical in either half of the address space; setting one bit on top
/// would leave an upper-half address, whose top bits are all ones, as it was.
/// The keys are numbered A, B, A, B here, so the low bit is the key_number.
/// Under TBI the code would go in 54:53, but this front end keeps the
/// signature where TBI is off, as stripPAC does.
/// </summary>
let private poisoned addr key =
  let code = if key &&& 1 = 0 then 0b01UL else 0b10UL
  (addr .& numU64 0x9fffffffffffffffUL 64<rt>) .| numU64 (code <<< 61) 64<rt>

/// The single operand of a Z form, which names the register it signs and
/// nothing else.
let private oneOpr (ins: Instruction) =
  match ins.Operands with
  | OneOperand o -> o
  | _ -> raise InvalidOperandException

/// <summary>
/// What PAC* and AUT* both do: strip the pointer, sign the address under the
/// modifier, and either write that signature in or check it against what was
/// there.
///
/// Which KEY is named makes no difference to what this computes -- the
/// architecture allows five independent keys and this front end has one --
/// but it does make a difference to what ROUND-TRIPS: a pointer signed with
/// one key and authenticated with another must not come back, so the key's
/// number is mixed into the modifier.
///
/// An authentication that fails leaves an error code in the top bits. The
/// architecture allows that or an exception (FEAT_FPAC); the code is what is
/// done here, because it is a value rather than a trap and a model with no
/// exception to raise can still say it.
/// </summary>
let private pacWrite bld d m key isAuth =
  let addr = stripPAC bld d
  let keyed = m <+> numI32 key 64<rt>
  let expected = tmpVar bld 64<rt>
  append bld { direct expected := addr .| pacSignature bld addr keyed }
  if isAuth then AST.ite (expected == d) addr (poisoned addr key)
  else expected

/// The forms that name a modifier register.
let private pacTwo (ins: Instruction) bld key isAuth =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let d = transOpr ins bld dst
    let m = transOpr ins bld src
    sized 64<rt> d := pacWrite bld d m key isAuth
  }

/// The Z forms, whose modifier is zero.
let private pacOne (ins: Instruction) bld key isAuth =
  lift bld ins {
    let d = transOpr ins bld (oneOpr ins)
    sized 64<rt> d := pacWrite bld d (AST.num0 64<rt>) key isAuth
  }

/// XPACI and XPACD, which take the signature off and leave everything else.
let xpac (ins: Instruction) bld =
  lift bld ins {
    let d = transOpr ins bld (oneOpr ins)
    sized 64<rt> d := stripPAC bld d
  }

/// <summary>
/// PACGA: a code over two whole registers rather than over an address.
///
/// It is not a pointer signer and has no inverse. What the architecture
/// fixes about it is where the answer goes -- the top half, with the bottom
/// half zero -- and that is the whole of what a case can hold it to.
/// </summary>
let pacga (ins: Instruction) bld =
  lift bld ins {
    let struct (dst, src1, src2) = getThreeOprs ins
    let d = transOpr ins bld dst
    let n = transOpr ins bld src1
    let m = transOpr ins bld src2
    let mixed = tmpVar bld 64<rt>
    direct mixed := (n <+> m) .* numU64 0x9e3779b97f4a7c15UL 64<rt>
    let folded = (mixed >> numI32 32 64<rt>) <+> mixed
    let low = folded .& numU64 0xffffffffUL 64<rt>
    sized 64<rt> d := low << numI32 32 64<rt>
  }

let pacia ins bld = pacTwo ins bld 0 false

let pacib ins bld = pacTwo ins bld 1 false

let pacda ins bld = pacTwo ins bld 2 false

let pacdb ins bld = pacTwo ins bld 3 false

let paciza ins bld = pacOne ins bld 0 false

let pacizb ins bld = pacOne ins bld 1 false

let pacdza ins bld = pacOne ins bld 2 false

let pacdzb ins bld = pacOne ins bld 3 false

let autia ins bld = pacTwo ins bld 0 true

let autib ins bld = pacTwo ins bld 1 true

let autda ins bld = pacTwo ins bld 2 true

let autdb ins bld = pacTwo ins bld 3 true

let autiza ins bld = pacOne ins bld 0 true

let autizb ins bld = pacOne ins bld 1 true

let autdza ins bld = pacOne ins bld 2 true

let autdzb ins bld = pacOne ins bld 3 true

/// <summary>
/// The implicit forms, which name no register: the link register is the
/// pointer, and the modifier is the stack pointer, zero, or X16 with X17 as
/// the pointer instead.
///
/// They are encoded in the HINT space, which is what lets a processor
/// without FEAT_PAuth run them and do nothing -- and is why B2R2 read them
/// as `hint #N` until they were given arms of their own.
/// </summary>
let private pacImplicit (ins: Instruction) bld key isAuth ptr modifier =
  let modifier: Register option = modifier
  lift bld ins {
    let d = regVar bld ptr
    let m =
      match modifier with
      | Some r -> regVar bld r
      | None -> AST.num0 64<rt>
    direct d := pacWrite bld d m key isAuth
  }

let paciaz ins bld = pacImplicit ins bld 0 false R.X30 None

let paciasp ins bld = pacImplicit ins bld 0 false R.X30 (Some R.SP)

let pacibz ins bld = pacImplicit ins bld 1 false R.X30 None

let pacibsp ins bld = pacImplicit ins bld 1 false R.X30 (Some R.SP)

let autiaz ins bld = pacImplicit ins bld 0 true R.X30 None

let autiasp ins bld = pacImplicit ins bld 0 true R.X30 (Some R.SP)

let autibz ins bld = pacImplicit ins bld 1 true R.X30 None

let autibsp ins bld = pacImplicit ins bld 1 true R.X30 (Some R.SP)

let pacia1716 ins bld = pacImplicit ins bld 0 false R.X17 (Some R.X16)

let pacib1716 ins bld = pacImplicit ins bld 1 false R.X17 (Some R.X16)

let autia1716 ins bld = pacImplicit ins bld 0 true R.X17 (Some R.X16)

let autib1716 ins bld = pacImplicit ins bld 1 true R.X17 (Some R.X16)

/// XPACLRI, which is XPACI on the link register.
let xpaclri (ins: Instruction) bld =
  lift bld ins {
    let d = regVar bld R.X30
    direct d := stripPAC bld d
  }

/// <summary>
/// LDRAA and LDRAB: a load whose BASE is authenticated before the offset is
/// added.
///
/// The modifier is X[31], which the manual's pseudocode means as the ZERO
/// register -- the same page writes `SP[]` two lines further down where it
/// means the stack pointer. So a pointer signed with PACDZA authenticates
/// here and one signed against the stack pointer does not.
///
/// The offset counts eight-byte words and is signed, and it is added AFTER
/// the authentication: what is signed is the base, not the address the load
/// reaches.
/// </summary>
let private loadAuth (ins: Instruction) bld isKeyB =
  lift bld ins {
    let struct (dst, src) = getTwoOprs ins
    let d = transOpr ins bld dst
    let struct (bReg, offset) =
      match src with
      | OprMemory(BaseMode(ImmOffset(BaseOffset(b, o)))) ->
        struct (regVar bld b, defaultArg o 0L)
      | OprMemory(PreIdxMode(ImmOffset(BaseOffset(b, o)))) ->
        struct (regVar bld b, defaultArg o 0L)
      | _ ->
        raise InvalidOperandException
    let key = if isKeyB then 3 else 2
    let authed = tmpVar bld 64<rt>
    direct authed := pacWrite bld bReg (AST.num0 64<rt>) key true
    let address = authed .+ numI64 offset 64<rt>
    sized 64<rt> d := AST.loadLE 64<rt> address
  }

let ldraa ins bld = loadAuth ins bld false

let ldrab ins bld = loadAuth ins bld true

/// <summary>
/// The target of BRAA, BLRAA and their Z and key-B forms: the first operand
/// authenticated under the key, against the second operand where there is
/// one and against zero where there is not. It goes into a temporary before
/// anything is written, since BLRAA's target can be the link register BLRAA
/// writes.
/// </summary>
let private authenticatedTarget (ins: Instruction) bld key =
  let target, modifier =
    match ins.Operands with
    | OneOperand o -> transOpr ins bld o, AST.num0 64<rt>
    | TwoOperands(o1, o2) -> transOpr ins bld o1, transOpr ins bld o2
    | _ -> raise InvalidOperandException
  let t = tmpVar bld 64<rt>
  append bld { direct t := pacWrite bld target modifier key true }
  t

/// BRAA, BRAAZ, BRAB and BRABZ: BR to a target authenticated first.
let branchAuth ins bld key =
  lift bld ins {
    let target = authenticatedTarget ins bld key
    AST.interjmp target InterJmpKind.Base
    return NoEndMark
  }

/// BLRAA, BLRAAZ, BLRAB and BLRABZ: BLR to a target authenticated first.
let branchLinkAuth (ins: Instruction) bld key =
  lift bld ins {
    let target = authenticatedTarget ins bld key
    let pc = numU64 ins.Address bld.RegType
    direct (regVar bld R.X30) := pc .+ numI64 4L 64<rt>
    AST.interjmp target InterJmpKind.IsCall
    return NoEndMark
  }

/// RETAA and RETAB: RET to the link register, authenticated against the
/// stack pointer first.
let returnAuth ins bld key =
  lift bld ins {
    let lr = regVar bld R.X30
    let target = tmpVar bld 64<rt>
    direct target := pacWrite bld lr (regVar bld R.SP) key true
    branchTo ins bld target BrTypeRET InterJmpKind.IsRet
    return NoEndMark
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

/// DC ZVA, which clears the block DCZID_EL0 names around the address it is
/// given.
let dczva ins bld =
  lift bld ins {
    let src = transOneOpr ins bld
    zeroBlock bld src
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
      sized ins.OprSize dst1 := (AST.loadLE 64<rt> address)
      sized ins.OprSize dst2 :=
        (AST.loadLE 64<rt> (address .+ numI32 8 64<rt>))
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
    sized ins.OprSize src1 := AST.sext 64<rt> data1
    sized ins.OprSize src2 := AST.sext 64<rt> data2
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
      sized ins.OprSize dst := AST.sext 64<rt> data
    | TwoOperands(o1, o2) ->
      let dst = transOpr ins bld o1
      let bReg, offset = transOpr ins bld o2 |> separateMemExpr
      let isWBack, isPostIndex = getIsWBackAndIsPostIndex ins.Operands
      direct address := bReg
      direct address := if isPostIndex then address else address .+ offset
      direct data := AST.loadLE 32<rt> address
      sized ins.OprSize dst := AST.sext 64<rt> data
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

/// <summary>
/// The bits of its register a field of PSTATE occupies, which are the bits
/// SPSR keeps it at. Every other bit of such a register is RES0, so a write
/// keeps only these and a read finds nothing else. Zero for a register that
/// is no such window.
/// </summary>
let private pstateBits = function
  | R.DAIF -> 0x3c0UL
  | R.PAN -> 1UL <<< 22
  | R.UAO -> 1UL <<< 23
  | R.DIT -> 1UL <<< 24
  | R.TCO -> 1UL <<< 25
  | R.SSBS -> 1UL <<< 12
  | _ -> 0UL

/// The register the field an MSR (immediate) names is read back through.
let private fieldRegister = function
  | SPSEL -> R.SPSEL
  | UAO -> R.UAO
  | PAN -> R.PAN
  | SSBS -> R.SSBS
  | DIT -> R.DIT
  | TCO -> R.TCO
  | DAIFSET | DAIFCLR -> R.DAIF

/// <summary>
/// Makes SP name the stack pointer a selection asks for: SP_EL0 for zero,
/// and EL1's own for one. SP always holds whichever is selected, so a change
/// of selection parks the one being left in its own register and brings the
/// other one in; a selection that changes nothing moves nothing.
/// </summary>
let private selectStack bld sel =
  let sp = regVar bld R.SP
  let spsel = regVar bld R.SPSEL
  let el0 = regVar bld R.SPEL0
  let el1 = regVar bld R.SPEL1
  let next = tmpVar bld 64<rt>
  let old = tmpVar bld 64<rt>
  let toEL0 = tmpVar bld 1<rt>
  let toEL1 = tmpVar bld 1<rt>
  append bld {
    direct next := sel
    direct old := sp
    direct toEL0 := (spsel != next) .& (next == AST.num0 64<rt>)
    direct toEL1 := (spsel != next) .& (next != AST.num0 64<rt>)
    direct sp := AST.ite toEL0 el0 (AST.ite toEL1 el1 old)
    direct el1 := AST.ite toEL0 old el1
    direct el0 := AST.ite toEL1 old el0
    direct spsel := next
  }

/// MSR (immediate). DAIFSet and DAIFClr set and clear the masks the four
/// bits of the immediate name, SPSel selects a stack pointer, and every other
/// field takes the immediate's low bit and ignores the rest.
let private msrImmediate ins bld field (imm: int64) =
  let imm = uint64 imm
  let daif = regVar bld R.DAIF
  let reg = fieldRegister field
  lift bld ins {
    match field with
    | DAIFSET ->
      direct daif := daif .| numU64 (imm <<< 6) 64<rt>
    | DAIFCLR ->
      direct daif := daif .& numU64 (~~~(imm <<< 6)) 64<rt>
    | SPSEL ->
      selectStack bld (numU64 (imm &&& 1UL) 64<rt>)
    | _ ->
      direct (regVar bld reg) := numU64 ((imm &&& 1UL) * pstateBits reg) 64<rt>
  }

/// MSR SPSel, Xt, which selects the stack pointer bit 0 of Xt names.
let private msrStackSelect ins bld src =
  lift bld ins {
    let src = transOpr ins bld src
    selectStack bld (src .& AST.num1 64<rt>)
  }

/// MSR to a register that is a window onto PSTATE, which keeps only the bits
/// of the field it names.
let private msrWindow ins bld reg src =
  lift bld ins {
    let src = transOpr ins bld src
    direct (regVar bld reg) := src .& numU64 (pstateBits reg) 64<rt>
  }

let msr (ins: Instruction) bld =
  match ins.Operands with
  | TwoOperands(OprSysReg _, _) ->
    unsupported ins bld
  | TwoOperands(OprPstate field, OprImm imm) ->
    msrImmediate ins bld field imm
  | TwoOperands(OprRegister R.SPSEL, src) ->
    msrStackSelect ins bld src
  | TwoOperands(OprRegister reg, src) when pstateBits reg <> 0UL ->
    msrWindow ins bld reg src
  | _ ->
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

/// The one-bit fields of PSTATE an exception return takes out of SPSR, each
/// into the register that reads it back, at the bit SPSR keeps it at.
let private restoreFields bld spsr =
  for reg in [ R.PAN; R.UAO; R.DIT; R.TCO; R.SSBS ] do
    let bits = numU64 (pstateBits reg) 64<rt>
    append bld { direct (regVar bld reg) := spsr .& bits }

/// <summary>
/// ERET, which returns from an exception: the saved program status becomes
/// the current one and the exception link register becomes the program
/// counter.
///
/// What is restored here is the part of PSTATE this model carries. The
/// condition flags are kept as four one-bit registers, so they are taken out
/// of SPSR_EL1 one at a time; the interrupt masks are kept in DAIF at the
/// bits SPSR holds them at, so those move across as a field; and PAN, UAO,
/// DIT, TCO and SSBS each move across as the one bit its register keeps. The
/// low bit of SPSR's mode field says which stack pointer to return on, and
/// that selection is made.
///
/// What is NOT restored is the exception level, which the rest of the mode
/// field names. There is one level in this model, so there is nothing for it
/// to select between -- and code that read CurrentEL across an ERET would be
/// reading a register this does not write. That is a limit worth stating
/// rather than papering over with a value that looks right.
///
/// ERETAA and ERETAB are the same return with the address authenticated
/// against the stack pointer first, under the key given here; what they
/// authenticate is not written back to the link register.
/// </summary>
let private exceptionReturn ins bld key =
  lift bld ins {
    let spsr = regVar bld R.SPSREL1
    let elr = regVar bld R.ELREL1
    let source =
      match key with
      | Some k -> pacWrite bld elr (regVar bld R.SP) k true
      | None -> elr
    let target = tmpVar bld 64<rt>
    direct target := source
    direct (regVar bld R.N) := AST.extract spsr 1<rt> 31
    direct (regVar bld R.Z) := AST.extract spsr 1<rt> 30
    direct (regVar bld R.C) := AST.extract spsr 1<rt> 29
    direct (regVar bld R.V) := AST.extract spsr 1<rt> 28
    (* D, A, I and F sit at 9:6 in both registers, so the field moves without
       being taken apart. *)
    direct (regVar bld R.DAIF) :=
      (regVar bld R.DAIF .& AST.not (numU64 0x3c0UL 64<rt>))
      .| (spsr .& numU64 0x3c0UL 64<rt>)
    restoreFields bld spsr
    selectStack bld (spsr .& AST.num1 64<rt>)
    branchTo ins bld target BrTypeRET InterJmpKind.IsRet
    return NoEndMark
  }

let eret ins bld = exceptionReturn ins bld None

let eretaa ins bld = exceptionReturn ins bld (Some 0)

let eretab ins bld = exceptionReturn ins bld (Some 1)

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
    let result = sumWithCarry src1 (AST.not src2) c
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

/// NGC and NGCS are the Rn==31 aliases of SBC and SBCS, and the parser emits
/// them under those names -- dropping the zero-register operand as it goes,
/// so they arrive with TWO operands. That is why they cannot simply be
/// dispatched to sbc/sbcs, which read three: the zero register is implied by
/// the alias, not carried by it. DDI0487F C6.2.185.
let ngc ins bld =
  lift bld ins {
    let dst, src = transTwoOprs ins bld
    let c = AST.zext ins.OprSize (regVar bld R.C)
    let result = sumWithCarry (AST.num0 ins.OprSize) (AST.not src) c
    sized ins.OprSize dst := result
  }

let ngcs ins bld =
  lift bld ins {
    let dst, src = transTwoOprs ins bld
    let c = tmpVar bld ins.OprSize
    direct c := AST.zext ins.OprSize (regVar bld R.C)
    let result, (n, z, c, v) =
      addWithCarry (AST.num0 ins.OprSize) (AST.not src) c ins.OprSize
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
    sized ins.OprSize dst :=
      src3 .+ (AST.sext 64<rt> src1 .* AST.sext 64<rt> src2)
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
    sized ins.OprSize dst :=
      src3 .- (AST.sext 64<rt> src1 .* AST.sext 64<rt> src2)
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
    sized ins.OprSize dst :=
      src3 .+ (AST.zext 64<rt> src1 .* AST.zext 64<rt> src2)
  }

let umov (ins: Instruction) bld =
  lift bld ins {
    let dst, src = transTwoOprs ins bld
    sized ins.OprSize dst := src
  }

let umsubl ins bld =
  lift bld ins {
    let dst, src1, src2, src3 = transOprOfUMADDL ins bld
    sized ins.OprSize dst :=
      src3 .- (AST.zext 64<rt> src1 .* AST.zext 64<rt> src2)
  }

let uxtb ins bld =
  let struct (dst, src) = getTwoOprs ins
  ubfm ins bld dst src (OprImm 0L) (OprImm 7L)

let uxth ins bld =
  let struct (dst, src) = getTwoOprs ins
  ubfm ins bld dst src (OprImm 0L) (OprImm 15L)

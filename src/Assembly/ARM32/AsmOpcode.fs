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
/// Encodes one instruction into the A32 word that means it. Every encoder here
/// takes the instruction as the source wrote it and returns that word, so the
/// families whose members differ only in a few bits are one function applied to
/// different bits rather than one function each.
/// </summary>
module internal B2R2.Assembly.ARM32.AsmOpcode

open B2R2
open B2R2.FrontEnd.ARM32
open B2R2.Assembly.ARM32.ParserHelper
open B2R2.Assembly.ARM32.AsmField

(* Data-processing instructions. *)
/// The operand2 of a data-processing instruction, bits 11 to 0, together with
/// the I bit that says whether it is an immediate. A register operand2 may
/// carry a shift by an immediate or by another register.
let private operand2 ins operands =
  match operands with
  | [ OprImm imm ] -> (1u <<< 25) ||| modifiedImm imm
  | [ OprReg rm ] -> coreReg rm
  | [ OprReg rm; OprShift shift ] -> immShift shift ||| coreReg rm
  | [ OprReg rm; OprRegShift(shift, rs) ] -> regShift (shift, rs) ||| coreReg rm
  | _ -> wrongOperands ins

/// The bits every data-processing instruction shares: a four-bit opcode, the S
/// bit that says whether it sets the flags, and the condition.
let private dataProcHead opcode s ins =
  cond ins ||| (opcode <<< 21) ||| (s <<< 20)

/// {<Rd>,} <Rn>, <operand2>, the form the arithmetic and logical instructions
/// take.
let private dataProc opcode s ins =
  match getOperandsAsList ins.Operands with
  | OprReg rd :: OprReg rn :: operands ->
    dataProcHead opcode s ins ||| (coreReg rn <<< 16) ||| (coreReg rd <<< 12)
    ||| operand2 ins operands
  | _ ->
    wrongOperands ins

/// Encodes <Rn>, <operand2>, the form of the instructions that only set the
/// flags and so name no destination.
let private testAndCompare opcode ins =
  match getOperandsAsList ins.Operands with
  | OprReg rn :: operands ->
    dataProcHead opcode 1u ins ||| (coreReg rn <<< 16) ||| operand2 ins operands
  | _ ->
    wrongOperands ins

/// Encodes <Rd>, <operand2>, the form of the moves, which read no first source.
let private moveOperand2 opcode s ins =
  match getOperandsAsList ins.Operands with
  | OprReg rd :: operands ->
    dataProcHead opcode s ins ||| (coreReg rd <<< 12) ||| operand2 ins operands
  | _ ->
    wrongOperands ins

/// <summary>
/// The shift instructions, which the manual defines as aliases of MOV: what
/// the source writes as an opcode is the shift in that MOV's operand2.
///
/// RRX takes no amount because it rotates by exactly one place, and the
/// disassembler writes that place as its amount.
/// </summary>
let private shiftAlias shift s ins =
  let move rd operand2 =
    dataProcHead 0b1101u s ins ||| (coreReg rd <<< 12) ||| operand2
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprReg rm, OprImm amount) ->
    move rd (aliasImmShift shift (uint32 amount) ||| coreReg rm)
  | ThreeOperands(OprReg rd, OprReg rm, OprReg rs) ->
    move rd (regShift (shift, rs) ||| coreReg rm)
  | TwoOperands(OprReg rd, OprReg rm) when shift = ShiftOp.RRX ->
    move rd (immShift (shift, Imm 1u) ||| coreReg rm)
  | _ ->
    wrongOperands ins

/// <summary>
/// ADR, which the manual defines as an addition to the program counter: how far
/// the place it names is from there decides whether it adds or subtracts.
///
/// The distance was worked out before encoding, so what arrives here is an
/// offset rather than an address.
/// </summary>
let private adr ins =
  match ins.Operands with
  | TwoOperands(OprReg rd, OprMemory(LiteralMode offset)) ->
    let opcode = if offset < 0L then 0b0010u else 0b0100u
    dataProcHead opcode 0u ins ||| (1u <<< 25) ||| (0xfu <<< 16)
    ||| (coreReg rd <<< 12) ||| modifiedImm (abs offset)
  | _ ->
    wrongOperands ins

/// MOVW and MOVT, whose sixteen-bit immediate is split between the field that
/// holds Rn elsewhere and the operand2 field.
let private moveHalfword opcodeBits ins =
  match ins.Operands with
  | TwoOperands(OprReg rd, OprImm imm) ->
    let imm16 = unsignedImm 16 imm
    cond ins ||| (opcodeBits <<< 20) ||| ((imm16 >>> 12) <<< 16)
    ||| (coreReg rd <<< 12) ||| (imm16 &&& 0xfffu)
  | _ ->
    wrongOperands ins

(* Multiply instructions. *)
/// The bits every multiply in the data-processing space shares: a four-bit
/// opcode above the destination, and the 1001 pattern that tells this space
/// from the shifts.
let private mulHead opcodeBits ins =
  cond ins ||| (opcodeBits <<< 20) ||| (0b1001u <<< 4)

/// Encodes <Rd>, <Rn>, <Rm>, which writes Rd where other instructions write Rn.
let private mul3 opcodeBits ins =
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprReg rn, OprReg rm) ->
    mulHead opcodeBits ins ||| (coreReg rd <<< 16) ||| (coreReg rm <<< 8)
    ||| coreReg rn
  | _ ->
    wrongOperands ins

/// Encodes <Rd>, <Rn>, <Rm>, <Ra>, the accumulating form.
let private mul4 opcodeBits ins =
  match ins.Operands with
  | FourOperands(OprReg rd, OprReg rn, OprReg rm, OprReg ra) ->
    mulHead opcodeBits ins ||| (coreReg rd <<< 16) ||| (coreReg ra <<< 12)
    ||| (coreReg rm <<< 8) ||| coreReg rn
  | _ ->
    wrongOperands ins

/// Encodes <RdLo>, <RdHi>, <Rn>, <Rm>, the form whose result is sixty-four bits
/// wide.
let private mulLong opcodeBits ins =
  match ins.Operands with
  | FourOperands(OprReg rdLo, OprReg rdHi, OprReg rn, OprReg rm) ->
    mulHead opcodeBits ins ||| (coreReg rdHi <<< 16) ||| (coreReg rdLo <<< 12)
    ||| (coreReg rm <<< 8) ||| coreReg rn
  | _ ->
    wrongOperands ins

/// The bits the halfword multiplies share. They sit in the miscellaneous space
/// rather than with the other multiplies, and pick which half of each source
/// to read with the two bits below their opcode.
let private halfMulHead opcode mn ins =
  cond ins ||| (0b00010u <<< 23) ||| (opcode <<< 21) ||| (1u <<< 7)
  ||| (mn <<< 5)

let private halfMul3 opcode mn ins =
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprReg rn, OprReg rm) ->
    halfMulHead opcode mn ins ||| (coreReg rd <<< 16) ||| (coreReg rm <<< 8)
    ||| coreReg rn
  | _ ->
    wrongOperands ins

let private halfMul4 opcode mn ins =
  match ins.Operands with
  | FourOperands(OprReg rd, OprReg rn, OprReg rm, OprReg ra) ->
    halfMulHead opcode mn ins ||| (coreReg rd <<< 16) ||| (coreReg ra <<< 12)
    ||| (coreReg rm <<< 8) ||| coreReg rn
  | _ ->
    wrongOperands ins

let private halfMulLong opcode mn ins =
  match ins.Operands with
  | FourOperands(OprReg rdLo, OprReg rdHi, OprReg rn, OprReg rm) ->
    halfMulHead opcode mn ins ||| (coreReg rdHi <<< 16)
    ||| (coreReg rdLo <<< 12) ||| (coreReg rm <<< 8) ||| coreReg rn
  | _ ->
    wrongOperands ins

(* Branches and the miscellaneous space. *)
/// BX, BXJ and BLX, which branch to an address held in a register. The fields
/// the manual leaves as "should be one" are written as ones, which is what
/// every other assembler emits and what a reader expects to see.
let private branchReg op1 ins =
  match ins.Operands with
  | OneOperand(OprReg rm) ->
    cond ins ||| (0b00010010u <<< 20) ||| (0xfffu <<< 8) ||| (op1 <<< 4)
    ||| coreReg rm
  | _ ->
    wrongOperands ins

/// CLZ, which counts the leading zeroes of one register into another.
let private clz ins =
  match ins.Operands with
  | TwoOperands(OprReg rd, OprReg rm) ->
    cond ins ||| (0b00010110u <<< 20) ||| (0xfu <<< 16) ||| (coreReg rd <<< 12)
    ||| (0xfu <<< 8) ||| (0b0001u <<< 4) ||| coreReg rm
  | _ ->
    wrongOperands ins

/// ERET, which returns from an exception and has nothing to encode.
let private eret ins =
  match ins.Operands with
  | NoOperand ->
    cond ins ||| (0b00010110u <<< 20) ||| (0b0110u <<< 4) ||| 0b1110u
  | _ ->
    wrongOperands ins

/// HLT, BKPT and HVC, whose sixteen-bit immediate is split between the field
/// above the fixed pattern and the four bits below it.
let private exception16 opcode ins =
  match ins.Operands with
  | OneOperand(OprImm imm) ->
    let imm16 = unsignedImm 16 imm
    alwaysCond ins ||| (0b00010u <<< 23) ||| (opcode <<< 21)
    ||| ((imm16 >>> 4) <<< 8) ||| (0b0111u <<< 4) ||| (imm16 &&& 0xfu)
  | _ ->
    wrongOperands ins

/// SMC, which has only four bits of immediate to name a monitor call.
let private smc ins =
  match ins.Operands with
  | OneOperand(OprImm imm) ->
    cond ins ||| (0b00010110u <<< 20) ||| (0b0111u <<< 4) ||| unsignedImm 4 imm
  | _ ->
    wrongOperands ins

/// SVC, whose twenty-four bit immediate the supervisor reads rather than the
/// processor.
let private svc ins =
  match ins.Operands with
  | OneOperand(OprImm imm) ->
    cond ins ||| (0b1111u <<< 24) ||| unsignedImm 24 imm
  | _ ->
    wrongOperands ins

/// UDF, the encoding the manual promises will always be undefined.
let private udf ins =
  match ins.Operands with
  | OneOperand(OprImm imm) ->
    let imm16 = unsignedImm 16 imm
    alwaysCond ins ||| (0b01111111u <<< 20) ||| ((imm16 >>> 4) <<< 8)
    ||| (0b1111u <<< 4) ||| (imm16 &&& 0xfu)
  | _ ->
    wrongOperands ins

/// The saturating add and subtract instructions, which name their operands in
/// the order Rd, Rm, Rn rather than the usual one.
let private saturatingArith opcode ins =
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprReg rm, OprReg rn) ->
    cond ins ||| (0b00010u <<< 23) ||| (opcode <<< 21) ||| (coreReg rn <<< 16)
    ||| (coreReg rd <<< 12) ||| (0b0101u <<< 4) ||| coreReg rm
  | _ ->
    wrongOperands ins

/// The cyclic redundancy check instructions, told apart by the width they read
/// and by which polynomial they use.
let private crc32 size c ins =
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprReg rn, OprReg rm) ->
    cond ins ||| (0b00010u <<< 23) ||| (size <<< 21) ||| (coreReg rn <<< 16)
    ||| (coreReg rd <<< 12) ||| (c <<< 9) ||| (0b0100u <<< 4) ||| coreReg rm
  | _ ->
    wrongOperands ins

/// The bits an instruction that moves a banked register shares: the selector
/// that names one is split, with its top bit sitting below the four others.
let private bankedHead r ins =
  cond ins ||| (0b00010u <<< 23) ||| (r <<< 22) ||| (0b001u <<< 9)

/// <summary>
/// MRS, which copies a status register into a general one.
///
/// The disassembler calls the current status register APSR, and it names a
/// mode's own copy of a register the same way it names a status register, which
/// is why one operand covers both encodings here.
/// </summary>
let private mrs ins =
  match ins.Operands with
  | TwoOperands(OprReg rd, OprReg reg) when isBankedReg reg ->
    let r, selector = bankedReg reg
    bankedHead r ins ||| ((selector &&& 0xfu) <<< 16) ||| (coreReg rd <<< 12)
    ||| ((selector >>> 4) <<< 8)
  | TwoOperands(OprReg rd, OprReg sreg) ->
    cond ins ||| (0b00010u <<< 23) ||| (statusRegBit sreg <<< 22)
    ||| (0xfu <<< 16) ||| (coreReg rd <<< 12)
  | _ ->
    wrongOperands ins

/// MSR, which writes the fields of a status register that its first operand
/// names, from a general register or from an immediate.
let private msr ins =
  let head sreg =
    cond ins ||| (0b00010u <<< 23) ||| (statusRegBit sreg <<< 22)
    ||| (0b10u <<< 20) ||| (0xfu <<< 12)
  match ins.Operands with
  | TwoOperands(OprReg reg, OprReg rn) when isBankedReg reg ->
    let r, selector = bankedReg reg
    bankedHead r ins ||| (0b10u <<< 20) ||| ((selector &&& 0xfu) <<< 16)
    ||| (0xfu <<< 12) ||| ((selector >>> 4) <<< 8) ||| coreReg rn
  | TwoOperands(OprSpecReg(sreg, flag), OprReg rn) ->
    head sreg ||| (psrMask flag <<< 16) ||| coreReg rn
  | TwoOperands(OprReg sreg, OprReg rn) ->
    head sreg ||| coreReg rn
  | TwoOperands(OprSpecReg(sreg, flag), OprImm imm) ->
    cond ins ||| (0b00110u <<< 23) ||| (statusRegBit sreg <<< 22)
    ||| (0b10u <<< 20) ||| (psrMask flag <<< 16) ||| (0xfu <<< 12)
    ||| modifiedImm imm
  | _ ->
    wrongOperands ins

/// CPS, which masks or unmasks the interrupts its operand names, changes to
/// the mode it names, or both; imod says which way the flags go, and M that a
/// mode is named.
let private changeState imod ins =
  let head = unconditional ins ||| (0b0001u <<< 24) ||| (imod <<< 18)
  match ins.Operands with
  | OneOperand(OprIflag flags) ->
    head ||| (iflagBits flags <<< 6)
  | TwoOperands(OprIflag flags, OprImm mode) ->
    head ||| (1u <<< 17) ||| (iflagBits flags <<< 6) ||| unsignedImm 5 mode
  | OneOperand(OprImm mode) ->
    head ||| (1u <<< 17) ||| unsignedImm 5 mode
  | _ ->
    wrongOperands ins

/// <summary>
/// B and BL, whose target is written as a word offset from the program
/// counter. The offset itself was worked out before encoding, so what arrives
/// here is how far the target is from this instruction rather than where it
/// is.
/// </summary>
let private branch opcodeBits ins =
  match ins.Operands with
  | OneOperand(OprMemory(LiteralMode offset)) when offset % 4L = 0L ->
    cond ins ||| (opcodeBits <<< 24) ||| signedImm 24 (offset / 4L)
  | OneOperand(OprMemory(LiteralMode _)) ->
    fail $"{ins.Opcode} can only reach a word-aligned target"
  | _ ->
    wrongOperands ins

/// <summary>
/// BLX, which branches to a target it takes either from a register or from a
/// label, and changes to Thumb state either way.
///
/// The label form's target is a halfword offset, so the lowest bit of it lives
/// on its own above the rest, and it exists only in the unconditional space.
/// </summary>
let private branchLinkExchange ins =
  match ins.Operands with
  | OneOperand(OprReg _) ->
    branchReg 0b0011u ins
  | OneOperand(OprMemory(LiteralMode offset)) when offset % 2L = 0L ->
    let halfwords = signedImm 25 (offset / 2L)
    unconditional ins ||| (0b101u <<< 25) ||| ((halfwords &&& 1u) <<< 24)
    ||| (halfwords >>> 1)
  | OneOperand(OprMemory(LiteralMode _)) ->
    fail "blx can only reach a halfword-aligned target"
  | _ ->
    wrongOperands ins

(* Hints and barriers. *)
/// The hint instructions, which are a move to the status register that writes
/// no field: only the low byte tells one hint from another.
let private hint imm8 ins =
  match ins.Operands with
  | NoOperand -> cond ins ||| (0b00110010u <<< 20) ||| (0xfu <<< 12) ||| imm8
  | _ -> wrongOperands ins

/// DBG, the one hint that names how much to say.
let private dbg ins =
  match ins.Operands with
  | OneOperand(OprImm imm) ->
    cond ins ||| (0b00110010u <<< 20) ||| (0xfu <<< 12) ||| (0xfu <<< 4)
    ||| unsignedImm 4 imm
  | _ ->
    wrongOperands ins

/// TSB, the one hint written with an option, CSYNC being the only one it has.
let private tsb ins =
  match ins.Operands with
  | OneOperand(OprHintOpt CSYNC) ->
    cond ins ||| (0b00110010u <<< 20) ||| (0xfu <<< 12) ||| 0x12u
  | _ ->
    wrongOperands ins

/// <summary>
/// The barriers and CLREX, which share one encoding in the unconditional
/// space and differ in the four bits above their option.
///
/// A barrier written with no option means the widest one, which is how the
/// manual reads an absent option too.
/// </summary>
let private barrier op defaultOption ins =
  let head =
    unconditional ins ||| (0b01010111u <<< 20) ||| (0xfu <<< 16)
    ||| (0xfu <<< 12) ||| (op <<< 4)
  match ins.Operands with
  | NoOperand -> head ||| defaultOption
  | OneOperand(OprOption option) -> head ||| (uint32 (int option) &&& 0xfu)
  | OneOperand(OprImm imm) -> head ||| unsignedImm 4 imm
  | _ -> wrongOperands ins

/// SETEND, which chooses the endianness the loads and stores that follow read.
let private setend ins =
  match ins.Operands with
  | OneOperand(OprEndian endian) ->
    let e = if endian = Endian.Big then 1u else 0u
    unconditional ins ||| (0b00010000u <<< 20) ||| (1u <<< 16) ||| (e <<< 9)
  | _ ->
    wrongOperands ins

/// SETPAN, whose one bit of immediate says whether privileged access to user
/// memory is turned off.
let private setpan ins =
  match ins.Operands with
  | OneOperand(OprImm imm) ->
    unconditional ins ||| (0b00010001u <<< 20) ||| (unsignedImm 1 imm <<< 9)
  | _ ->
    wrongOperands ins

(* Loads and stores. *)
/// <summary>
/// Where a word or byte load or store reads: the base register, the bits that
/// say how it is indexed, and the offset, which is either an immediate of
/// twelve bits or a register that may be shifted.
///
/// A literal is the same thing with the program counter as the base. How far
/// the target is from there arrived as the offset, so there is nothing left to
/// work out here.
/// </summary>
let private wordMemory ins mode =
  match mode, indexBits mode with
  | _, Some(p, w, ImmOffset(rn, sign, imm)) ->
    let u, value = signedOffset sign (defaultArg imm 0L)
    (p <<< 24) ||| (u <<< 23) ||| (w <<< 21) ||| (coreReg rn <<< 16)
    ||| unsignedImm 12 value
  | _, Some(p, w, RegOffset(rn, sign, rm, shift)) ->
    (1u <<< 25) ||| (p <<< 24) ||| (addBit sign <<< 23) ||| (w <<< 21)
    ||| (coreReg rn <<< 16)
    ||| immShift (defaultArg shift (ShiftOp.LSL, Imm 0u)) ||| coreReg rm
  | LiteralMode offset, _ ->
    let u, value = signedOffset None offset
    (1u <<< 24) ||| (u <<< 23) ||| (0xfu <<< 16) ||| unsignedImm 12 value
  | _ ->
    wrongOperands ins

/// The word and byte loads and stores, which differ only in the bit that says
/// which width they read and the one that says which way it goes.
let private loadStore b l ins =
  match ins.Operands with
  | TwoOperands(OprReg rt, OprMemory mode) ->
    cond ins ||| (0b01u <<< 26) ||| (b <<< 22) ||| (l <<< 20)
    ||| (coreReg rt <<< 12) ||| wordMemory ins mode
  | _ ->
    wrongOperands ins

/// The unprivileged loads and stores, which read and write as though the
/// processor were in user mode. They are the post-indexed forms with the bit
/// that means writeback elsewhere set.
let private loadStoreUnpriv b l ins =
  match ins.Operands with
  | TwoOperands(OprReg rt, OprMemory(PostIdxMode _ as mode)) ->
    cond ins ||| (0b01u <<< 26) ||| (b <<< 22) ||| (1u <<< 21) ||| (l <<< 20)
    ||| (coreReg rt <<< 12) ||| wordMemory ins mode
  | _ ->
    wrongOperands ins

/// Where a halfword, doubleword or sign-extending load or store reads. Its
/// immediate offset is only eight bits wide and is split in two, and its
/// register offset carries no shift.
let private extraMemory ins mode =
  match mode, indexBits mode with
  | _, Some(p, w, ImmOffset(rn, sign, imm)) ->
    let u, value = signedOffset sign (defaultArg imm 0L)
    let value = unsignedImm 8 value
    (p <<< 24) ||| (u <<< 23) ||| (1u <<< 22) ||| (w <<< 21)
    ||| (coreReg rn <<< 16) ||| ((value >>> 4) <<< 8) ||| (value &&& 0xfu)
  | _, Some(p, w, RegOffset(rn, sign, rm, None)) ->
    (p <<< 24) ||| (addBit sign <<< 23) ||| (w <<< 21) ||| (coreReg rn <<< 16)
    ||| coreReg rm
  | LiteralMode offset, _ ->
    let u, value = signedOffset None offset
    let value = unsignedImm 8 value
    (1u <<< 24) ||| (u <<< 23) ||| (1u <<< 22) ||| (0xfu <<< 16)
    ||| ((value >>> 4) <<< 8) ||| (value &&& 0xfu)
  | _ ->
    wrongOperands ins

/// The bits the halfword, doubleword and sign-extending accesses share: they
/// sit among the data-processing instructions and are told from them by the
/// pattern below their offset.
let private extraHead l op2 ins =
  cond ins ||| (l <<< 20) ||| (1u <<< 7) ||| (op2 <<< 5) ||| (1u <<< 4)

let private extraLoadStore l op2 ins =
  match ins.Operands with
  | TwoOperands(OprReg rt, OprMemory mode) ->
    extraHead l op2 ins ||| (coreReg rt <<< 12) ||| extraMemory ins mode
  | _ ->
    wrongOperands ins

/// The unprivileged halfword and sign-extending accesses, which like the word
/// ones are post-indexed with the writeback bit set.
let private extraLoadStoreUnpriv l op2 ins =
  match ins.Operands with
  | TwoOperands(OprReg rt, OprMemory(PostIdxMode _ as mode)) ->
    extraHead l op2 ins ||| (1u <<< 21) ||| (coreReg rt <<< 12)
    ||| extraMemory ins mode
  | _ ->
    wrongOperands ins

/// The doubleword loads and stores, which name two registers even though only
/// the first is encoded: the second is always the one after it.
let private loadStoreDual l op2 ins =
  match ins.Operands with
  | ThreeOperands(OprReg rt, OprReg rt2, OprMemory mode) ->
    if int rt2 <> int rt + 1 then
      fail $"{Register.toString rt2} does not follow {Register.toString rt}"
    else
      extraHead l op2 ins ||| (coreReg rt <<< 12) ||| extraMemory ins mode
  | _ ->
    wrongOperands ins

/// The bits the exclusive and ordered accesses share. The two bits above the
/// fixed pattern say whether the access is exclusive, ordered, or both.
let private exclusiveHead size l order ins =
  cond ins ||| (0b00011u <<< 23) ||| (size <<< 21) ||| (l <<< 20)
  ||| (0b11u <<< 10) ||| (order <<< 8) ||| (0b1001u <<< 4)

/// A store that releases, whose value register sits where another store would
/// keep its offset.
let private storeOrdered size ins =
  match ins.Operands with
  | TwoOperands(OprReg rt, OprMemory(OffsetMode(ImmOffset(rn, _, None)))) ->
    exclusiveHead size 0u 0b00u ins ||| (coreReg rn <<< 16) ||| (0xfu <<< 12)
    ||| coreReg rt
  | _ ->
    wrongOperands ins

/// A load that acquires, and the exclusive loads, which read one register from
/// an address with no offset.
let private loadExclusive size order ins =
  match ins.Operands with
  | TwoOperands(OprReg rt, OprMemory(OffsetMode(ImmOffset(rn, _, None)))) ->
    exclusiveHead size 1u order ins ||| (coreReg rn <<< 16)
    ||| (coreReg rt <<< 12) ||| 0xfu
  | _ ->
    wrongOperands ins

/// The exclusive stores, which report in a register of their own whether the
/// store succeeded.
let private storeExclusive size order ins =
  match ins.Operands with
  | ThreeOperands(OprReg rd,
                  OprReg rt,
                  OprMemory(OffsetMode(ImmOffset(rn, _, None)))) ->
    exclusiveHead size 0u order ins ||| (coreReg rn <<< 16)
    ||| (coreReg rd <<< 12) ||| coreReg rt
  | _ ->
    wrongOperands ins

/// The exclusive doubleword loads, which read the register after the one they
/// name as well.
let private loadExclusiveDual order ins =
  match ins.Operands with
  | ThreeOperands(OprReg rt,
                  OprReg rt2,
                  OprMemory(OffsetMode(ImmOffset(rn, _, None)))) ->
    if int rt2 <> int rt + 1 then
      fail $"{Register.toString rt2} does not follow {Register.toString rt}"
    else
      exclusiveHead 0b01u 1u order ins ||| (coreReg rn <<< 16)
      ||| (coreReg rt <<< 12) ||| 0xfu
  | _ ->
    wrongOperands ins

/// The exclusive doubleword stores, which write the register after the one they
/// name as well.
let private storeExclusiveDual order ins =
  match ins.Operands with
  | FourOperands(OprReg rd,
                 OprReg rt,
                 OprReg rt2,
                 OprMemory(OffsetMode(ImmOffset(rn, _, None)))) ->
    if int rt2 <> int rt + 1 then
      fail $"{Register.toString rt2} does not follow {Register.toString rt}"
    else
      exclusiveHead 0b01u 0u order ins ||| (coreReg rn <<< 16)
      ||| (coreReg rd <<< 12) ||| coreReg rt
  | _ ->
    wrongOperands ins

/// SWP and SWPB, which read a word and write another back in one step. ARMv7
/// deprecated them and ARMv8 removed them, but the decoder still reads them.
let private swap b ins =
  match ins.Operands with
  | ThreeOperands(OprReg rt,
                  OprReg rt2,
                  OprMemory(OffsetMode(ImmOffset(rn, _, None)))) ->
    cond ins ||| (0b00010u <<< 23) ||| (b <<< 22) ||| (coreReg rn <<< 16)
    ||| (coreReg rt <<< 12) ||| (0b1001u <<< 4) ||| coreReg rt2
  | _ ->
    wrongOperands ins

/// Where a preload reads. It never updates the base register, so the bits that
/// would say when it did are free for saying which hint this is.
let private preloadMemory ins mode =
  match mode with
  | OffsetMode(ImmOffset(rn, sign, imm)) ->
    let u, value = signedOffset sign (defaultArg imm 0L)
    (u <<< 23) ||| (coreReg rn <<< 16) ||| unsignedImm 12 value
  | OffsetMode(RegOffset(rn, sign, rm, shift)) ->
    (1u <<< 25) ||| (addBit sign <<< 23) ||| (coreReg rn <<< 16)
    ||| immShift (defaultArg shift (ShiftOp.LSL, Imm 0u)) ||| coreReg rm
  | LiteralMode offset ->
    let u, value = signedOffset None offset
    (u <<< 23) ||| (0xfu <<< 16) ||| unsignedImm 12 value
  | _ ->
    wrongOperands ins

/// The preload hints, which name a place the way a load does but read nothing.
let private preload d r ins =
  match ins.Operands with
  | OneOperand(OprMemory mode) ->
    unconditional ins ||| (0b01u <<< 26) ||| (d <<< 24) ||| (r <<< 22)
    ||| (0b01u <<< 20) ||| (0xfu <<< 12) ||| preloadMemory ins mode
  | _ ->
    wrongOperands ins

(* Block transfers. *)
/// The bits every load or store of several registers shares. Which way the
/// address moves and whether it moves before or after each access is what
/// tells one of these from another; the caret, if the source wrote one, says
/// whose registers are moved.
let private blockHead p u s l ins =
  let w = if ins.WriteBack then 1u else 0u
  cond ins ||| (0b100u <<< 25) ||| (p <<< 24) ||| (u <<< 23) ||| (s <<< 22)
  ||| (w <<< 21) ||| (l <<< 20)

let private blockTransfer p u l ins =
  match ins.Operands with
  | TwoOperands(OprReg rn, OprRegList regs) ->
    blockHead p u (caretBit ins) l ins ||| (coreReg rn <<< 16) ||| regList regs
  | _ ->
    wrongOperands ins

/// <summary>
/// PUSH and POP, which the manual defines as aliases: pushing is storing
/// downwards through the stack pointer and popping is loading upwards from it.
///
/// A list of one register is written as a plain store or load instead, which is
/// the form the disassembler reads back as PUSH or POP, so that is the form
/// emitted here.
/// </summary>
let private stackTransfer ins =
  checkNoCaret ins
  let single rt =
    if ins.Opcode = Opcode.PUSH then
      (* str <Rt>, [sp, #-4]! *)
      cond ins ||| (0x52du <<< 16) ||| (coreReg rt <<< 12) ||| 4u
    else
      (* ldr <Rt>, [sp], #4 *)
      cond ins ||| (0x49du <<< 16) ||| (coreReg rt <<< 12) ||| 4u
  match ins.Operands with
  | OneOperand(OprRegList [ rt ]) ->
    single rt
  | OneOperand(OprRegList regs) ->
    let ins = { ins with WriteBack = true }
    let head =
      if ins.Opcode = Opcode.PUSH then blockHead 1u 0u 0u 0u ins
      else blockHead 0u 1u 0u 1u ins
    head ||| (coreReg Register.SP <<< 16) ||| regList regs
  | _ ->
    wrongOperands ins

/// RFE, which returns from an exception by loading the program counter and the
/// status register from the stack a mode of its own keeps.
let private returnFromException p u ins =
  let w = if ins.WriteBack then 1u else 0u
  match ins.Operands with
  | OneOperand(OprReg rn) ->
    unconditional ins ||| (0b100u <<< 25) ||| (p <<< 24) ||| (u <<< 23)
    ||| (w <<< 21) ||| (1u <<< 20) ||| (coreReg rn <<< 16) ||| (0x0au <<< 8)
  | _ ->
    wrongOperands ins

/// SRS, which stores the return state of the mode its immediate names.
let private storeReturnState p u ins =
  let w = if ins.WriteBack then 1u else 0u
  match ins.Operands with
  | TwoOperands(OprReg Register.SP, OprImm mode) ->
    unconditional ins ||| (0b100u <<< 25) ||| (p <<< 24) ||| (u <<< 23)
    ||| (1u <<< 22) ||| (w <<< 21) ||| (0xdu <<< 16) ||| (0x05u <<< 8)
    ||| unsignedImm 5 mode
  | _ ->
    wrongOperands ins

(* The media instructions. *)
/// The parallel arithmetic, which adds and subtracts several narrow values held
/// in one register at once. Two fields say which operation and which width.
let private parallelArith op1 op2 ins =
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprReg rn, OprReg rm) ->
    cond ins ||| (0b01100u <<< 23) ||| (op1 <<< 20) ||| (coreReg rn <<< 16)
    ||| (coreReg rd <<< 12) ||| (0xfu <<< 8) ||| (op2 <<< 5) ||| (1u <<< 4)
    ||| coreReg rm
  | _ ->
    wrongOperands ins

/// SEL, which picks each byte of its result from one source or the other
/// according to the flags a parallel addition left behind.
let private sel ins =
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprReg rn, OprReg rm) ->
    cond ins ||| (0b01101000u <<< 20) ||| (coreReg rn <<< 16)
    ||| (coreReg rd <<< 12) ||| (0xfu <<< 8) ||| (0b1011u <<< 4) ||| coreReg rm
  | _ ->
    wrongOperands ins

/// PKHBT and PKHTB, which build one register out of a halfword from each
/// source. Which halves they take is what the shift below them says.
let private pack tb ins =
  let rd, rn, rm, shift = packOperands tb ins
  cond ins ||| (0b01101000u <<< 20) ||| (coreReg rn <<< 16)
  ||| (coreReg rd <<< 12) ||| immShift shift ||| (1u <<< 4) ||| coreReg rm

/// The saturating moves, which clamp a value to the width their immediate
/// names. The signed one counts from one, so what it encodes is one less.
let private saturate u bias ins =
  let head satImm =
    cond ins ||| (0b0110101u <<< 21) ||| (u <<< 22)
    ||| (unsignedImm 5 satImm <<< 16) ||| (1u <<< 4)
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprImm satImm, OprReg rn) ->
    head (satImm - bias) ||| (coreReg rd <<< 12) ||| coreReg rn
  | FourOperands(OprReg rd, OprImm satImm, OprReg rn, OprShift shift) ->
    head (satImm - bias) ||| (coreReg rd <<< 12) ||| immShift shift
    ||| coreReg rn
  | _ ->
    wrongOperands ins

/// The saturating moves that clamp two halfwords at once, which take no shift.
let private saturate16 u bias ins =
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprImm satImm, OprReg rn) ->
    cond ins ||| (0b0110101u <<< 21) ||| (u <<< 22)
    ||| (unsignedImm 4 (satImm - bias) <<< 16) ||| (coreReg rd <<< 12)
    ||| (0xfu <<< 8) ||| (0b0011u <<< 4) ||| coreReg rn
  | _ ->
    wrongOperands ins

/// The byte-reversing moves and RBIT, which differ in two bits far apart.
let private reverse o1 o2 ins =
  match ins.Operands with
  | TwoOperands(OprReg rd, OprReg rm) ->
    cond ins ||| (0b0110101u <<< 21) ||| (o1 <<< 22) ||| (1u <<< 20)
    ||| (0xfu <<< 16) ||| (coreReg rd <<< 12) ||| (0xfu <<< 8) ||| (o2 <<< 7)
    ||| (0b0011u <<< 4) ||| coreReg rm
  | _ ->
    wrongOperands ins

/// The rotate a sign- or zero-extending move applies before it extends, which
/// the encoding holds as a count of bytes rather than of bits.
let private extendRotate = function
  | Some(ShiftOp.ROR, Imm amount) when amount % 8u = 0u && amount < 32u ->
    (amount / 8u) <<< 10
  | None ->
    0u
  | Some(shift, Imm amount) ->
    fail $"an extending move cannot {shift} by #{amount}"

/// The sign- and zero-extending moves, and the ones that add what they
/// extended to another register. Naming the program counter as the source of
/// the addition is how the manual writes the form that adds nothing.
let private extend opcode ins =
  let head rn rotate =
    cond ins ||| (0b01101u <<< 23) ||| (opcode <<< 20) ||| (coreReg rn <<< 16)
    ||| rotate ||| (0b0111u <<< 4)
  match ins.Operands with
  | TwoOperands(OprReg rd, OprReg rm) ->
    head Register.PC 0u ||| (coreReg rd <<< 12) ||| coreReg rm
  | ThreeOperands(OprReg rd, OprReg rm, OprShift shift) ->
    head Register.PC (extendRotate (Some shift)) ||| (coreReg rd <<< 12)
    ||| coreReg rm
  | ThreeOperands(OprReg rd, OprReg rn, OprReg rm) ->
    head rn 0u ||| (coreReg rd <<< 12) ||| coreReg rm
  | FourOperands(OprReg rd, OprReg rn, OprReg rm, OprShift shift) ->
    head rn (extendRotate (Some shift)) ||| (coreReg rd <<< 12) ||| coreReg rm
  | _ ->
    wrongOperands ins

/// USAD8 and USADA8, which add up how far apart the bytes of two registers
/// are. Naming the program counter where the sum would accumulate is how the
/// manual writes the form that accumulates nothing.
let private absoluteDifference ins =
  let head = cond ins ||| (0b01111000u <<< 20) ||| (1u <<< 4)
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprReg rn, OprReg rm) ->
    head ||| (coreReg rd <<< 16) ||| (0xfu <<< 12) ||| (coreReg rm <<< 8)
    ||| coreReg rn
  | FourOperands(OprReg rd, OprReg rn, OprReg rm, OprReg ra) ->
    head ||| (coreReg rd <<< 16) ||| (coreReg ra <<< 12)
    ||| (coreReg rm <<< 8) ||| coreReg rn
  | _ ->
    wrongOperands ins

/// The bits the signed multiplies of the media space share, which is a
/// different space from the one the other multiplies live in.
let private signedMulHead opcode op2 ins =
  cond ins ||| (0b01110u <<< 23) ||| (opcode <<< 20) ||| (op2 <<< 5)
  ||| (1u <<< 4)

/// The signed multiplies that accumulate into a fourth register.
let private signedMul4 opcode op2 ins =
  match ins.Operands with
  | FourOperands(OprReg rd, OprReg rn, OprReg rm, OprReg ra) ->
    signedMulHead opcode op2 ins ||| (coreReg rd <<< 16)
    ||| (coreReg ra <<< 12) ||| (coreReg rm <<< 8) ||| coreReg rn
  | _ ->
    wrongOperands ins

/// The signed multiplies that accumulate nothing, which name the program
/// counter where the others name the register they accumulate into.
let private signedMul3 opcode op2 ins =
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprReg rn, OprReg rm) ->
    signedMulHead opcode op2 ins ||| (coreReg rd <<< 16) ||| (0xfu <<< 12)
    ||| (coreReg rm <<< 8) ||| coreReg rn
  | _ ->
    wrongOperands ins

/// The signed multiplies whose result is sixty-four bits wide.
let private signedMulLong opcode op2 ins =
  match ins.Operands with
  | FourOperands(OprReg rdLo, OprReg rdHi, OprReg rn, OprReg rm) ->
    signedMulHead opcode op2 ins ||| (coreReg rdHi <<< 16)
    ||| (coreReg rdLo <<< 12) ||| (coreReg rm <<< 8) ||| coreReg rn
  | _ ->
    wrongOperands ins

/// BFI and BFC, which write a field of one register into another and clear
/// one. Naming the program counter as the source is how the manual writes the
/// form that clears.
let private bitfieldInsert ins =
  let head lsb width =
    cond ins ||| (0b0111110u <<< 21) ||| (endOfBitfield lsb width <<< 16)
    ||| (unsignedImm 5 lsb <<< 7) ||| (1u <<< 4)
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprImm lsb, OprImm width) ->
    head lsb width ||| (coreReg rd <<< 12) ||| 0xfu
  | FourOperands(OprReg rd, OprReg rn, OprImm lsb, OprImm width) ->
    head lsb width ||| (coreReg rd <<< 12) ||| coreReg rn
  | _ ->
    wrongOperands ins

/// The bitfield extracts, which hold the width of the field they read as one
/// less than it is.
let private bitfieldExtract u ins =
  match ins.Operands with
  | FourOperands(OprReg rd, OprReg rn, OprImm lsb, OprImm width) ->
    cond ins ||| (0b0111101u <<< 21) ||| (u <<< 22)
    ||| (unsignedImm 5 (width - 1L) <<< 16) ||| (coreReg rd <<< 12)
    ||| (unsignedImm 5 lsb <<< 7) ||| (0b0101u <<< 4) ||| coreReg rn
  | _ ->
    wrongOperands ins

(* The coprocessor space. *)
/// The bits every coprocessor instruction shares. The instructions whose
/// mnemonic ends in a two live in the unconditional encoding space, which is
/// how a second coprocessor interface is reached.
let private coprocHead two ins =
  if two = 1u then unconditional ins else cond ins

/// CDP, which asks the coprocessor to do something with its own registers.
let private cdp two ins =
  match ins.Operands with
  | SixOperands(OprReg p,
                OprImm opc1,
                OprReg crd,
                OprReg crn,
                OprReg crm,
                OprImm opc2) ->
    coprocHead two ins ||| (0b1110u <<< 24) ||| (unsignedImm 4 opc1 <<< 20)
    ||| (coprocRegNum crn <<< 16) ||| (coprocRegNum crd <<< 12)
    ||| (coprocReg p <<< 8) ||| (unsignedImm 3 opc2 <<< 5) ||| coprocRegNum crm
  | _ ->
    wrongOperands ins

/// MCR and MRC, which move one core register to or from the coprocessor.
let private moveCoproc two l ins =
  match ins.Operands with
  | SixOperands(OprReg p,
                OprImm opc1,
                OprReg rt,
                OprReg crn,
                OprReg crm,
                OprImm opc2) ->
    coprocHead two ins ||| (0b1110u <<< 24) ||| (unsignedImm 3 opc1 <<< 21)
    ||| (l <<< 20) ||| (coprocRegNum crn <<< 16) ||| (coreReg rt <<< 12)
    ||| (coprocReg p <<< 8) ||| (unsignedImm 3 opc2 <<< 5) ||| (1u <<< 4)
    ||| coprocRegNum crm
  | _ ->
    wrongOperands ins

/// MCRR and MRRC, which move two core registers at once.
let private moveCoprocPair two l ins =
  match ins.Operands with
  | FiveOperands(OprReg p, OprImm opc1, OprReg rt, OprReg rt2, OprReg crm) ->
    coprocHead two ins ||| (0b1100u <<< 24) ||| (0b010u <<< 21) ||| (l <<< 20)
    ||| (coreReg rt2 <<< 16) ||| (coreReg rt <<< 12) ||| (coprocReg p <<< 8)
    ||| (unsignedImm 4 opc1 <<< 4) ||| coprocRegNum crm
  | _ ->
    wrongOperands ins

/// <summary>
/// The P and W bits a coprocessor access sets, which do not mean quite what
/// they do elsewhere: a post-indexed coprocessor access sets the bit that means
/// writeback, and leaving both clear is what marks the unindexed form.
/// </summary>
let private coprocIndexBits = function
  | OffsetMode offset -> Some(1u, 0u, offset)
  | PreIdxMode offset -> Some(1u, 1u, offset)
  | PostIdxMode offset -> Some(0u, 1u, offset)
  | UnIdxMode _ | LiteralMode _ -> None

/// Where a coprocessor load or store reads, whose immediate offset counts in
/// words. The unindexed form names something the coprocessor reads instead of
/// a place, so it keeps its value as it stands.
let private coprocMemory ins mode =
  match mode, coprocIndexBits mode with
  | _, Some(p, w, ImmOffset(rn, sign, imm)) ->
    let u, value = signedOffset sign (defaultArg imm 0L)
    if value % 4L <> 0L then
      fail "a coprocessor offset counts in words"
    else
      (p <<< 24) ||| (u <<< 23) ||| (w <<< 21) ||| (coreReg rn <<< 16)
      ||| unsignedImm 8 (value / 4L)
  | UnIdxMode(rn, option), _ ->
    (1u <<< 23) ||| (coreReg rn <<< 16) ||| unsignedImm 8 option
  | LiteralMode offset, _ ->
    let u, value = signedOffset None offset
    if value % 4L <> 0L then
      fail "a coprocessor offset counts in words"
    else
      (1u <<< 24) ||| (u <<< 23) ||| (0xfu <<< 16)
      ||| unsignedImm 8 (value / 4L)
  | _ ->
    wrongOperands ins

/// LDC and STC, which move words between memory and the coprocessor. The long
/// variants say with one bit that the coprocessor decides how much to move.
let private loadStoreCoproc two n l ins =
  match ins.Operands with
  | ThreeOperands(OprReg p, OprReg crd, OprMemory mode) ->
    coprocHead two ins ||| (0b110u <<< 25) ||| (n <<< 22) ||| (l <<< 20)
    ||| (coprocRegNum crd <<< 12) ||| (coprocReg p <<< 8)
    ||| coprocMemory ins mode
  | _ ->
    wrongOperands ins

(* The floating-point instructions. *)
/// <summary>
/// Bits 11:8 of a floating-point instruction, which name the floating-point
/// unit and the precision: 0b1001 for halves, 0b1010 for singles and 0b1011
/// for doubles. A half is held in a single-precision register, so it is the
/// data type that tells the two apart.
/// </summary>
let private fpSize ins dd =
  match ins.SIMDTyp with
  | Some(OneDT SIMDTypF16) -> 0b1001u <<< 8
  | _ -> if isSingleReg dd then 0b1010u <<< 8 else 0b1011u <<< 8

/// The register fields of a floating-point instruction, which sit at either end
/// of their register's number depending on how wide it is, and the size field
/// that says which width this is.
let private fpFields ins dd dn dm =
  if isSingleReg dd then fpSize ins dd ||| sd dd ||| sn dn ||| sm dm
  else fpSize ins dd ||| vd dd ||| vn dn ||| vm dm

/// The destination and source fields of an operation on two floating-point
/// registers, each placed by its own width: a conversion's two need not be as
/// wide as each other.
let private fpDestination reg = if isSingleReg reg then sd reg else vd reg

let private fpSource reg = if isSingleReg reg then sm reg else vm reg

let private fpFields2 ins dd dm =
  fpSize ins dd ||| fpDestination dd ||| fpSource dm

/// <summary>
/// The bits every floating-point operation on three registers shares.
///
/// Its opcode is split around the bit carrying the top of the destination
/// register: two of its bits sit below that one and one above.
/// </summary>
let private fpHead opcode op ins =
  cond ins ||| (0b1110u <<< 24) ||| ((opcode >>> 2) <<< 23)
  ||| ((opcode &&& 0b11u) <<< 20) ||| (op <<< 6)

let private fp3 opcode op ins =
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector dd)),
                  OprSIMD(SFReg(Vector dn)),
                  OprSIMD(SFReg(Vector dm))) ->
    fpHead opcode op ins ||| fpFields ins dd dn dm
  | _ ->
    wrongOperands ins

/// VSEL, which picks one source or the other by a condition it holds itself
/// rather than by the one every other instruction is written with.
let private fpSelect cc ins =
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector dd)),
                  OprSIMD(SFReg(Vector dn)),
                  OprSIMD(SFReg(Vector dm))) ->
    unconditional ins ||| (0b1110u <<< 24) ||| (cc <<< 20)
    ||| fpFields ins dd dn dm
  | _ ->
    wrongOperands ins

/// VMAXNM and VMINNM, which say what to do with a NaN rather than leaving it to
/// the flags, and so live in the unconditional space.
let private fpMinMax op ins =
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector dd)),
                  OprSIMD(SFReg(Vector dn)),
                  OprSIMD(SFReg(Vector dm))) ->
    unconditional ins ||| (0b1110u <<< 24) ||| (1u <<< 23) ||| (op <<< 6)
    ||| fpFields ins dd dn dm
  | _ ->
    wrongOperands ins

/// The bits the floating-point operations on two registers share, whose second
/// opcode names which one this is.
let private fpTwoRegHead opcode2 op3 =
  (0b1110u <<< 24) ||| (0b1011u <<< 20) ||| (opcode2 <<< 16) ||| (op3 <<< 6)

/// VRINT, which rounds to an integer in the way its mnemonic names. The modes
/// that name a rounding of their own are an ARMv8 addition, so they sit in the
/// unconditional space.
let private fpRoundInt mode ins =
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector dd)), OprSIMD(SFReg(Vector dm))) ->
    unconditional ins ||| fpTwoRegHead (0b1000u ||| mode) 0b01u
    ||| fpFields2 ins dd dm
  | _ ->
    wrongOperands ins

/// VABS, VNEG and VSQRT on one floating-point register.
let private fp2 opcode2 op3 ins =
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector dd)), OprSIMD(SFReg(Vector dm))) ->
    cond ins ||| fpTwoRegHead opcode2 op3 ||| fpFields2 ins dd dm
  | _ ->
    wrongOperands ins

/// VJCVT, which converts to a signed integer the way a certain language
/// requires rather than the way the manual would otherwise.
let private fpJavaConvert ins =
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector sdd)), OprSIMD(SFReg(Vector dm))) ->
    cond ins ||| fpTwoRegHead 0b1001u 0b11u ||| (0b1011u <<< 8) ||| sd sdd
    ||| vm dm
  | _ ->
    wrongOperands ins

/// VCMP and VCMPE, which compare two floating-point registers or one with zero
/// and set FPSCR's flags; E says a quiet NaN signals as well.
let private fpCompare e ins =
  let op3 = (e <<< 1) ||| 1u
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector dd)), OprSIMD(SFReg(Vector dm))) ->
    cond ins ||| fpTwoRegHead 0b0100u op3 ||| fpFields2 ins dd dm
  | TwoOperands(OprSIMD(SFReg(Vector dd)), OprImm 0L) ->
    cond ins ||| fpTwoRegHead 0b0101u op3 ||| fpSize ins dd
    ||| fpDestination dd
  | _ ->
    wrongOperands ins

/// Bits 9:8 of a conversion, which name the width of the floating-point number
/// on one side of it: 0b01 for a half, 0b10 for a single, 0b11 for a double.
let private fpWidthBits dt =
  match dt with
  | SIMDTypF16 -> 0b01u
  | SIMDTypF32 -> 0b10u
  | _ -> 0b11u

/// Whether one side of a conversion is a floating-point number and the other
/// an integer the given test accepts.
let private floatAndInt isInt dst src =
  (isFloatType dst && isInt src) || (isInt dst && isFloatType src)

/// Whether a data type names a 32-bit integer.
let private isWord dt = dt = SIMDTypS32 || dt = SIMDTypU32

/// The register of one side of a conversion, which must be as wide as the
/// number its data type names: a double fills a doubleword register, and any
/// narrower number a single-precision one.
let private typedReg dt reg =
  if (dt = SIMDTypF64) = isSingleReg reg then
    fail $"{Register.toString reg} is the wrong width for its data type"
  else
    reg

/// <summary>
/// VCVT and VCVTR between a floating-point number and a 32-bit integer.
///
/// To an integer, the second opcode says whether it is signed, and op whether
/// to round toward zero rather than the way FPSCR says, which is VCVTR's way.
/// From one, op says whether it is signed, and the width is the result's.
/// </summary>
let private fpIntConvert towardZero ins =
  match ins.Operands, ins.SIMDTyp with
  | TwoOperands(OprSIMD(SFReg(Vector dd)), OprSIMD(SFReg(Vector dm))),
    Some(TwoDT(dst, src)) when floatAndInt isWord dst src ->
    let signed dt = 1u - unsignedOf dt
    let head opcode2 op width =
      cond ins ||| fpTwoRegHead opcode2 ((op <<< 1) ||| 1u) ||| (0b10u <<< 10)
      ||| (fpWidthBits width <<< 8)
    let dd, dm = typedReg dst dd, typedReg src dm
    if isFloatType dst then
      head 0b1000u (signed src) dst ||| fpDestination dd ||| sm dm
    else
      head (0b1100u ||| signed dst) towardZero src ||| sd dd ||| fpSource dm
  | _ ->
    wrongOperands ins

/// Whether a conversion goes between a single and a double, either way.
let private isWidthConversion dst src =
  match dst, src with
  | SIMDTypF32, SIMDTypF64 | SIMDTypF64, SIMDTypF32 -> true
  | _ -> false

/// VCVT between a single and a double, whose sz bit says the source is the
/// double.
let private fpWidthConvert ins =
  match ins.Operands, ins.SIMDTyp with
  | TwoOperands(OprSIMD(SFReg(Vector dd)), OprSIMD(SFReg(Vector dm))),
    Some(TwoDT(dst, src)) when isWidthConversion dst src ->
    let sz = if src = SIMDTypF64 then 1u else 0u
    cond ins ||| fpTwoRegHead 0b0111u 0b11u ||| (0b101u <<< 9) ||| (sz <<< 8)
    ||| fpDestination (typedReg dst dd) ||| fpSource (typedReg src dm)
  | _ ->
    wrongOperands ins

/// Whether a data type names an integer a fixed-point VCVT converts, of 16 or
/// 32 bits.
let private isFixed dt = isWord dt || dt = SIMDTypS16 || dt = SIMDTypU16

/// The U and sx bits of a fixed-point number, which say whether it is unsigned
/// and whether it is 32 bits wide rather than 16, and that width.
let private fixedPointBits dt =
  match dt with
  | SIMDTypS32 | SIMDTypU32 -> unsignedOf dt, 1u, 32L
  | _ -> unsignedOf dt, 0u, 16L

/// <summary>
/// VCVT between a floating-point number and a fixed-point one held in the same
/// register, which it names twice, and whose op bit says which way it
/// converts.
///
/// The immediate names how many of the fixed-point number's bits are fraction,
/// which the encoding counts down from its width, splitting the count across
/// the bottom four bits and bit 5.
/// </summary>
let private fpFixedConvert ins =
  match ins.Operands, ins.SIMDTyp with
  | ThreeOperands(OprSIMD(SFReg(Vector dd)),
                  OprSIMD(SFReg(Vector dm)),
                  OprImm fbits),
    Some(TwoDT(dst, src)) when dd = dm && floatAndInt isFixed dst src ->
    let toFixed = if isFloatType dst then 0u else 1u
    let fixedType, floatType = if toFixed = 1u then dst, src else src, dst
    let u, sx, width = fixedPointBits fixedType
    let imm5 = unsignedImm 5 (width - fbits)
    let opcode2 = 0b1010u ||| (toFixed <<< 2) ||| u
    cond ins ||| fpTwoRegHead opcode2 ((sx <<< 1) ||| 1u) ||| (0b10u <<< 10)
    ||| (fpWidthBits floatType <<< 8) ||| ((imm5 &&& 1u) <<< 5)
    ||| (imm5 >>> 1) ||| fpDestination (typedReg floatType dd)
  | _ ->
    wrongOperands ins

/// Whether a conversion goes between a half and a single or a double.
let private isHalfConversion dst src =
  let isWider dt = dt = SIMDTypF32 || dt = SIMDTypF64
  (dst = SIMDTypF16 && isWider src) || (isWider dst && src = SIMDTypF16)

/// <summary>
/// VCVTB and VCVTT, which convert to or from the half-precision number in the
/// bottom or the top half of a single-precision register; T says which half.
///
/// The op bit says the half is what it writes, and sz that the number on the
/// other side is a double. The brain floating-point form only narrows singles,
/// and is written in coprocessor 9's space.
/// </summary>
let private fpHalfConvert t ins =
  let op3 = (t <<< 1) ||| 1u
  match ins.Operands, ins.SIMDTyp with
  | TwoOperands(OprSIMD(SFReg(Vector sdd)), OprSIMD(SFReg(Vector sdm))),
    Some(TwoDT(BF16, SIMDTypF32)) ->
    cond ins ||| fpTwoRegHead 0b0011u op3 ||| (0b1001u <<< 8)
    ||| sd (typedReg BF16 sdd) ||| sm (typedReg SIMDTypF32 sdm)
  | TwoOperands(OprSIMD(SFReg(Vector dd)), OprSIMD(SFReg(Vector dm))),
    Some(TwoDT(dst, src)) when isHalfConversion dst src ->
    let op = if dst = SIMDTypF16 then 1u else 0u
    let sz = if dst = SIMDTypF64 || src = SIMDTypF64 then 1u else 0u
    cond ins ||| fpTwoRegHead (0b0010u ||| op) op3 ||| (0b101u <<< 9)
    ||| (sz <<< 8) ||| fpDestination (typedReg dst dd)
    ||| fpSource (typedReg src dm)
  | _ ->
    wrongOperands ins

/// VCVTA, VCVTN, VCVTP and VCVTM on one floating-point register, which round to
/// an integer the way their mnemonic says rather than the way FPSCR does; RM
/// names that way and op says the integer is signed.
let private fpDirectedConvert rm ins =
  match ins.Operands, ins.SIMDTyp with
  | TwoOperands(OprSIMD(SFReg(Vector sdd)), OprSIMD(SFReg(Vector dm))),
    Some(TwoDT(dst, src)) when isWord dst && isFloatType src ->
    let op3 = ((1u - unsignedOf dst) <<< 1) ||| 1u
    unconditional ins ||| fpTwoRegHead (0b1100u ||| rm) op3 ||| (0b10u <<< 10)
    ||| (fpWidthBits src <<< 8) ||| sd sdd ||| fpSource (typedReg src dm)
  | _ ->
    wrongOperands ins

/// VMOVX and VINS, which move the top half of a single-precision register to
/// the bottom of another, or the bottom of one into the top of another.
let private fpHalfMove t ins =
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector sdd)), OprSIMD(SFReg(Vector sdm))) ->
    unconditional ins ||| fpTwoRegHead 0b0000u ((t <<< 1) ||| 1u)
    ||| (0b1010u <<< 8) ||| sd sdd ||| sm sdm
  | _ ->
    wrongOperands ins

/// The floating-point move of an immediate, whose eight bits stand for a sign,
/// a short exponent and four bits of significand; the width it stands for is
/// the one the data type names.
let private fpMoveImm ins =
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector dd)), OprImm imm) ->
    let width =
      if ins.SIMDTyp = Some(OneDT SIMDTypF16) then 16
      elif isSingleReg dd then 32
      else 64
    let imm8 = fpImm8 width imm
    cond ins ||| (0b1110u <<< 24) ||| (0b1011u <<< 20)
    ||| ((imm8 >>> 4) <<< 16) ||| (imm8 &&& 0xfu) ||| fpSize ins dd
    ||| fpDestination dd
  | _ ->
    wrongOperands ins

/// Where a floating-point load or store reads, whose immediate offset counts in
/// words and cannot be written back.
let private fpMemoryScaled ins scale mode =
  let offsetBits u value rn =
    if value % scale <> 0L then
      fail $"a floating-point offset counts in {scale} bytes at a time"
    else
      (u <<< 23) ||| (rn <<< 16) ||| unsignedImm 8 (value / scale)
  match mode with
  | OffsetMode(ImmOffset(rn, sign, imm)) ->
    let u, value = signedOffset sign (defaultArg imm 0L)
    offsetBits u value (coreReg rn)
  | LiteralMode offset ->
    let u, value = signedOffset None offset
    offsetBits u value 0xfu
  | _ ->
    wrongOperands ins

let private fpMemory ins mode = fpMemoryScaled ins 4L mode

/// VLDR and VSTR, which move one floating-point register to or from memory.
let private fpLoadStore l ins =
  let half =
    match ins.SIMDTyp with
    | Some(OneDT SIMDTyp16) | Some(OneDT SIMDTypF16) -> true
    | _ -> false
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector dd)), OprMemory mode) when half ->
    (* Half-precision numbers are moved by their own encoding, whose offset
       counts in halfwords rather than in words. *)
    cond ins ||| (0b1101u <<< 24) ||| (l <<< 20) ||| (0b1001u <<< 8) ||| sd dd
    ||| fpMemoryScaled ins 2L mode
  | TwoOperands(OprSIMD(SFReg(Vector dd)), OprMemory mode) ->
    cond ins ||| (0b1101u <<< 24) ||| (l <<< 20) ||| (0b101u <<< 9)
    ||| (if isSingleReg dd then sd dd else (1u <<< 8) ||| vd dd)
    ||| fpMemory ins mode
  | _ ->
    wrongOperands ins

/// <summary>
/// VLDM and VSTM, which move as many floating-point registers as their list
/// names. What the encoding holds is where the list starts and how long it is
/// in words, so the registers have to run consecutively.
/// </summary>
let private fpBlockTransfer p u l ins =
  match ins.Operands with
  | TwoOperands(OprReg rn, OprRegList(first :: _ as regs)) ->
    let count = uint32 (List.length regs)
    let consecutive =
      regs |> List.mapi (fun i reg -> int reg - i) |> List.distinct
    if List.length consecutive <> 1 then
      fail $"{ins.Opcode} needs a run of registers"
    else
      let w = if ins.WriteBack then 1u else 0u
      let words = if isSingleReg first then count else count * 2u
      cond ins ||| (0b110u <<< 25) ||| (p <<< 24) ||| (u <<< 23) ||| (w <<< 21)
      ||| (l <<< 20) ||| (coreReg rn <<< 16) ||| (0b101u <<< 9)
      ||| unsignedImm 8 (int64 words)
      ||| (if isSingleReg first then sd first else (1u <<< 8) ||| vd first)
  | _ ->
    wrongOperands ins

/// FLDMX and FSTMX, which move doubleword registers as VLDM and VSTM do and
/// tell themselves apart by a word count one more than the registers fill.
let private fpBlockTransferX p u l ins =
  match ins.Operands with
  | TwoOperands(_, OprRegList(first :: _)) when not (isSingleReg first) ->
    fpBlockTransfer p u l ins ||| 1u
  | _ ->
    wrongOperands ins

(* The Advanced SIMD instructions. *)
/// The Q bit, which says whether the operands are quadword registers, and the
/// three register fields. Both widths are written the same way, so which one an
/// instruction uses is read off the registers themselves.
let private neonFields q dd dn dm = (q <<< 6) ||| vd dd ||| vn dn ||| vm dm

/// The bits every Advanced SIMD instruction in the data-processing space
/// shares: it lives in the unconditional encoding space, and so takes no
/// condition of its own.
let private neonHead ins = unconditional ins ||| (0b001u <<< 25)

/// <summary>
/// The operations on three registers of the same length, which read the same
/// number of elements as they write.
///
/// The U bit tells some of these apart from one another and says of others
/// whether their elements are unsigned; a row that names it fixes it, and one
/// that does not reads it from the data type.
/// </summary>
let private neon3With u size opcode op ins =
  let head =
    neonHead ins ||| (u <<< 24) ||| (size <<< 20) ||| (opcode <<< 8)
    ||| (op <<< 4)
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector dd)),
                  OprSIMD(SFReg(Vector dn)),
                  OprSIMD(SFReg(Vector dm))) ->
    let q = if isQuadReg dd then 1u else 0u
    head ||| neonFields q dd dn dm
  | _ ->
    wrongOperands ins

let private neon3 u opcode op ins = neon3With u (elementSize ins) opcode op ins

let private neon3Signed opcode op ins = neon3 (unsignedBit ins) opcode op ins

/// <summary>
/// The operations whose size field says which operation this is rather than how
/// wide its elements are.
///
/// The floating-point ones among the SIMD instructions name their width in the
/// data type, which leaves that field free for telling one from another.
/// </summary>
let private neon3Float u size opcode ins = neon3With u size opcode 1u ins

/// The same, for the ones that come in both widths of floating-point number:
/// the low bit of that field says which width, and the high one which of the
/// pair of operations sharing it this is.
let private neon3FloatDt u variant opcode ins =
  let half = if elementSize ins = 1u then 1u else 0u
  neon3With u ((variant <<< 1) ||| half) opcode 1u ins

/// The floating-point operations on three registers whose op bit, bit 4, is
/// the row's own: the low size bit says the width and the high one which of a
/// pair of operations this is.
let private neon3FloatOp u variant opcode op ins =
  let half = if elementSize ins = 1u then 1u else 0u
  neon3With u ((variant <<< 1) ||| half) opcode op ins

/// The operations whose floating-point form is encoded elsewhere than their
/// integer one, which the data type tells apart.
let private byType float integer ins =
  match dataType ins with
  | SIMDTypF16 | SIMDTypF32 -> float ins
  | _ -> integer ins

/// The bitwise operations, which name no data type, and the two that also read
/// an immediate instead of a register.
let private neonBitwise u size withImmediate ins =
  match ins.Operands with
  | TwoOperands(_, OprImm _) -> withImmediate ins
  | _ -> neon3With u size 0b0001u 1u ins

/// The operations that name the register holding how far to shift after the one
/// holding what to shift, which is the other way round from every other
/// operation on three registers.
let private neon3Reversed opcode op ins =
  match ins.Operands with
  | ThreeOperands(dd, dm, dn) ->
    neon3Signed opcode op { ins with Operands = ThreeOperands(dd, dn, dm) }
  | _ ->
    wrongOperands ins

/// <summary>
/// The operations both units have, which name their registers the same way
/// either way.
///
/// What tells them apart is what those registers hold: the floating-point unit
/// works on one number at a time, in a register of its own width, and the SIMD
/// unit on several at once.
/// </summary>
let private eitherUnit vfp neon ins =
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector reg)), _, _)
  | TwoOperands(OprSIMD(SFReg(Vector reg)), _) ->
    if isSingleReg reg then
      vfp ins
    elif isQuadReg reg then
      neon ins
    else
      match ins.SIMDTyp with
      | Some(OneDT SIMDTypF64) -> vfp ins
      | _ -> neon ins
  | _ ->
    neon ins

/// The operations on three registers of different lengths, which write elements
/// twice as wide as the ones they read. Their destination is always the wide
/// one, so the bit that would say which width this is is free.
let private neon3Long u opcode ins =
  let head =
    neonHead ins ||| (u <<< 24) ||| (1u <<< 23) ||| (elementSize ins <<< 20)
    ||| (opcode <<< 8)
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector qd)),
                  OprSIMD(SFReg(Vector dn)),
                  OprSIMD(SFReg(Vector dm))) ->
    head ||| vd qd ||| vn dn ||| vm dm
  | _ ->
    wrongOperands ins

let private neon3LongSigned opcode ins = neon3Long (unsignedBit ins) opcode ins

/// The operations on three registers that write elements half as wide as the
/// ones they read; the size field names the narrow width, one less than the
/// data type's.
let private neon3Narrow u opcode ins =
  let head =
    neonHead ins ||| (u <<< 24) ||| (1u <<< 23)
    ||| ((elementSize ins - 1u) <<< 20) ||| (opcode <<< 8)
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector dd)),
                  OprSIMD(SFReg(Vector qn)),
                  OprSIMD(SFReg(Vector qm))) ->
    head ||| vd dd ||| vn qn ||| vm qm
  | _ ->
    wrongOperands ins

/// <summary>
/// The immediate field of a shift by an amount, which the manual writes as a
/// count from the width of an element rather than from nothing.
///
/// Which width that is, the field says itself: it is read back from the field
/// rather than from the data type, so the width the data type names is tried
/// first and any field that means the same amount stands in when the amount
/// does not fit it.
/// </summary>
let private shiftAmountField isLeft width (amount: uint32) =
  if width = 64u then
    let imm6 = if isLeft then amount else 64u - amount
    (1u <<< 7) ||| ((imm6 &&& 0x3fu) <<< 16)
  else
    let means imm6 =
      if imm6 >= 32u then (if isLeft then imm6 - 32u else 64u - imm6)
      elif imm6 >= 16u then (if isLeft then imm6 - 16u else 32u - imm6)
      else (if isLeft then imm6 - 8u else 16u - imm6)
    let named = if isLeft then width + amount else 2u * width - amount
    if named >= width && named < 2u * width then
      named <<< 16
    else
      match [ 8u .. 63u ] |> List.tryFind (fun imm6 -> means imm6 = amount) with
      | Some imm6 -> imm6 <<< 16
      | None -> fail $"#{amount} is not a shift of elements that wide"

/// How wide the elements a shift counts from are. A shift that narrows counts
/// from the width it writes rather than the one it reads, which is half of what
/// its data type names.
let private shiftWidth narrowing ins =
  let width = 8u <<< int (elementSize ins)
  if narrowing then width / 2u else width

/// The shifts of two registers by an immediate, which count the amount down
/// from the width of an element rather than up from nothing.
let private neonShiftWith u isLeft narrowing opcode ins =
  let head =
    neonHead ins ||| (u <<< 24) ||| (1u <<< 23) ||| (opcode <<< 8)
    ||| (1u <<< 4)
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector dd)),
                  OprSIMD(SFReg(Vector dm)),
                  OprImm amount) ->
    (* A shift that narrows or widens names one register of each width, and
       says which is which by what it does rather than by this bit. *)
    let q = if isQuadReg dd && isQuadReg dm then 1u else 0u
    head ||| shiftAmountField isLeft (shiftWidth narrowing ins) (uint32 amount)
    ||| (q <<< 6) ||| vd dd
    ||| vm dm
  | _ ->
    wrongOperands ins

let private neonShift opcode ins =
  neonShiftWith (unsignedBit ins) false false opcode ins

/// <summary>
/// VCVT between a floating-point number and a fixed-point one, which the manual
/// counts as a shift: how many of the fixed-point number's bits are fractional
/// is the amount.
/// </summary>
let private neonConvertFixed ins =
  let toFloat =
    match dataType ins with
    | SIMDTypF16 | SIMDTypF32 | SIMDTypF64 -> true
    | _ -> false
  let fixedType =
    match ins.SIMDTyp, toFloat with
    | Some(TwoDT(_, dt)), true -> dt
    | Some(TwoDT(dt, _)), false -> dt
    | _ -> fail $"{ins.Opcode} names what it converts from and what to"
  let u =
    match fixedType with
    | SIMDTypU8 | SIMDTypU16 | SIMDTypU32 | SIMDTypU64 -> 1u
    | _ -> 0u
  let half = elementSize ins = 1u
  let opcode =
    match toFloat, half with
    | true, true -> 0b1100u
    | false, true -> 0b1101u
    | true, false -> 0b1110u
    | false, false -> 0b1111u
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector dd)),
                  OprSIMD(SFReg(Vector dm)),
                  OprImm amount) ->
    (* However wide its elements, this one counts what it converts from the
       widest they could be. *)
    let q = if isQuadReg dd then 1u else 0u
    neonHead ins ||| (u <<< 24) ||| (1u <<< 23) ||| (opcode <<< 8)
    ||| (1u <<< 4) ||| shiftAmountField false 32u (uint32 amount)
    ||| (q <<< 6) ||| vd dd ||| vm dm
  | _ ->
    wrongOperands ins

/// The shifts that write elements half as wide as the ones they read.
let private neonShiftNarrow opcode ins =
  neonShiftWith (unsignedBit ins) false true opcode ins

/// <summary>
/// The scalar an instruction multiplies every element by, which names one
/// element of one register.
///
/// How many registers it can name depends on how wide the element is, because
/// the wider the element the more of the field the index needs.
/// </summary>
let private scalarField ins reg index =
  let number = simdReg reg
  match elementSize ins with
  | 1u when number < 8u && index < 4u ->
    ((index &&& 1u) <<< 3) ||| number ||| ((index >>> 1) <<< 5)
  | 2u when number < 16u && index < 2u ->
    number ||| (index <<< 5)
  | _ ->
    fail $"{Register.toString reg}[{index}] is not a scalar"

/// The operations that multiply every element of one register by one element of
/// another. Their destination may be as wide as their sources or twice as wide,
/// and the bit that would say which is free for the ones that are always wide.
let private neonScalar readQ opcode ins =
  let head =
    neonHead ins ||| (1u <<< 23) ||| (elementSize ins <<< 20)
    ||| (opcode <<< 8) ||| (1u <<< 6)
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector dd)),
                  OprSIMD(SFReg(Vector dn)),
                  OprSIMD(SFReg(Scalar(dm, Some index)))) ->
    let q = if readQ && isQuadReg dd then 1u else 0u
    head ||| (q <<< 24) ||| vd dd ||| vn dn
    ||| scalarField ins dm (uint32 index)
  | _ ->
    wrongOperands ins

/// VEXT, which reads one register's worth of bytes starting part way through a
/// pair of them.
let private neonExtract ins =
  let head = neonHead ins ||| (1u <<< 23) ||| (0b11u <<< 20)
  match ins.Operands with
  | FourOperands(OprSIMD(SFReg(Vector dd)),
                 OprSIMD(SFReg(Vector dn)),
                 OprSIMD(SFReg(Vector dm)),
                 OprImm offset) ->
    let q = if isQuadReg dd then 1u else 0u
    head ||| (unsignedImm 4 offset <<< 8) ||| neonFields q dd dn dm
  | _ ->
    wrongOperands ins

/// The bits the operations on two registers share, whose opcode is split in two
/// and sits on either side of the destination.
let private neonTwoRegHead a b ins =
  neonHead ins ||| (1u <<< 24) ||| (1u <<< 23) ||| (0b11u <<< 20)
  ||| (elementSize ins <<< 18) ||| (a <<< 16) ||| (b <<< 7)

let private neonTwoReg a b ins =
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector dd)), OprSIMD(SFReg(Vector dm))) ->
    let q = if isQuadReg dd then 1u else 0u
    neonTwoRegHead a b ins ||| (q <<< 6) ||| vd dd ||| vm dm
  | _ ->
    wrongOperands ins

/// The operations on two registers whose bit 6 is the last bit of their opcode
/// rather than the Q bit, and whose size field the caller names.
let private neonTwoRegOp size a op ins =
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector dd)), OprSIMD(SFReg(Vector dm))) ->
    neonHead ins ||| (1u <<< 24) ||| (1u <<< 23) ||| (0b11u <<< 20)
    ||| (size <<< 18) ||| (a <<< 16) ||| (op <<< 6) ||| vd dd ||| vm dm
  | _ ->
    wrongOperands ins

/// The operations on two registers whose size field is fixed rather than read
/// from a data type, which some of them do not name.
let private neonTwoRegSized size a b ins =
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector dd)), _) ->
    let q = if isQuadReg dd then 1u else 0u
    neonTwoRegOp size a ((b <<< 1) ||| q) ins
  | _ ->
    wrongOperands ins

/// The pairwise adds into wider elements, whose U bit sits in the opcode.
let private pairwiseLong b ins = neonTwoReg 0b00u (b ||| unsignedBit ins) ins

/// <summary>
/// The cryptographic operations on two quadword registers, AES and SHA, whose
/// bit 6 is the last bit of the opcode rather than the Q bit.
/// </summary>
let private neonCrypto2 a op ins = neonTwoRegOp (elementSize ins) a op ins

/// VMOVN, VQMOVUN and VQMOVN, which narrow every element of a quadword into a
/// doubleword; the size field names the width they write, one step below the
/// one their data type names.
let private neonMoveNarrow op ins =
  neonTwoRegOp (elementSize ins - 1u) 0b10u (0b01000u ||| op) ins

/// VQMOVN, whose last opcode bit says the elements are unsigned.
let private saturatingMoveNarrow ins =
  neonMoveNarrow (0b10u ||| unsignedBit ins) ins

/// VRECPE and VRSQRTE, which estimate a reciprocal or a reciprocal square root
/// of each element; F says the elements are floating-point.
let private neonEstimate op ins =
  let f = if isFloatType (dataType ins) then 1u else 0u
  neonTwoReg 0b11u (0b1000u ||| (f <<< 1) ||| op) ins

/// The compares with zero, which name a register and #0; bit 10, F, says the
/// elements are floating-point.
let private neonCompareZero op ins =
  let f =
    match dataType ins with
    | SIMDTypF16 | SIMDTypF32 -> 1u
    | _ -> 0u
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector dd)),
                  OprSIMD(SFReg(Vector dm)),
                  OprImm _) ->
    let q = if isQuadReg dd then 1u else 0u
    neonTwoRegHead 0b01u ((f <<< 3) ||| op) ins ||| (q <<< 6) ||| vd dd
    ||| vm dm
  | _ ->
    wrongOperands ins

/// The compares that name a register or #0 to compare with.
let private orZero op threeRegisters ins =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm _) -> neonCompareZero op ins
  | _ -> threeRegisters ins

/// VABS and VNEG on Advanced SIMD registers, whose F bit says the elements are
/// floating-point, or on one floating-point register.
let private absNeg neonOp fpOpcode2 fpOp3 ins =
  let f = if isFloatType (dataType ins) then 0b1000u else 0u
  eitherUnit (fp2 fpOpcode2 fpOp3) (neonTwoReg 0b01u (f ||| neonOp)) ins

/// The registers of a SIMD list, which a table lookup reads as one table.
let private simdListRegs list =
  let named = function
    | Vector reg | Scalar(reg, None) -> reg
    | Scalar _ -> fail "this list names whole registers or every element"
  match list with
  | OneReg r -> [ named r ]
  | TwoRegs(r1, r2) -> [ named r1; named r2 ]
  | ThreeRegs(r1, r2, r3) -> [ named r1; named r2; named r3 ]
  | FourRegs(r1, r2, r3, r4) -> [ named r1; named r2; named r3; named r4 ]
  | SFReg r -> [ named r ]

/// VTBL and VTBX, which read each byte of their result from wherever in a table
/// of up to four registers the matching byte of their index names.
let private neonTableLookup op ins =
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector dd)),
                  OprSIMD table,
                  OprSIMD(SFReg(Vector dm))) ->
    let regs = simdListRegs table
    let consecutive =
      regs |> List.mapi (fun i reg -> int reg - i) |> List.distinct
    if List.length consecutive <> 1 then
      fail $"{ins.Opcode} needs a run of registers"
    else
      neonHead ins ||| (1u <<< 24) ||| (1u <<< 23) ||| (0b11u <<< 20)
      ||| (0b10u <<< 10) ||| (uint32 (List.length regs - 1) <<< 8)
      ||| (op <<< 6) ||| vd dd ||| vn (List.head regs) ||| vm dm
  | _ ->
    wrongOperands ins

/// The imm4 field of a VDUP of one element, whose lowest set bit says how
/// wide the element is and whose bits above it say which one it is.
let private duplicateIndex ins (index: uint32) =
  match elementSize ins with
  | 0u when index < 8u -> (index <<< 1) ||| 0b1u
  | 1u when index < 4u -> (index <<< 2) ||| 0b10u
  | 2u when index < 2u -> (index <<< 3) ||| 0b100u
  | _ -> fail $"a doubleword has no element {index} of that width"

/// VDUP, which fills every element of a SIMD register with one core register
/// or with one element of a doubleword. From a core register, its two size
/// bits sit far apart, and its destination is written where an instruction of
/// the same shape would write its first source.
let private neonDuplicate ins =
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector dd)), OprReg rt) ->
    let b, e =
      match elementSize ins with
      | 0u -> 1u, 0u
      | 1u -> 0u, 1u
      | 2u -> 0u, 0u
      | _ -> fail $"{ins.Opcode} cannot duplicate into elements that wide"
    let q = if isQuadReg dd then 1u else 0u
    cond ins ||| (0b1110u <<< 24) ||| (1u <<< 23) ||| (b <<< 22) ||| (q <<< 21)
    ||| (coreReg rt <<< 12) ||| (0b1011u <<< 8) ||| (e <<< 5) ||| (1u <<< 4)
    ||| vn dd
  | TwoOperands(OprSIMD(SFReg(Vector dd)),
                OprSIMD(SFReg(Scalar(dm, Some index)))) ->
    let q = if isQuadReg dd then 1u else 0u
    neonHead ins ||| (1u <<< 24) ||| (1u <<< 23) ||| (0b11u <<< 20)
    ||| (duplicateIndex ins (uint32 index) <<< 16) ||| (0b11000u <<< 7)
    ||| (q <<< 6) ||| vd dd ||| vm dm
  | _ ->
    wrongOperands ins

/// The three fields an eight-bit SIMD immediate is split across: one bit well
/// above the rest, three in the middle and four at the bottom.
let private splitSimdImm8 (imm8: uint32) =
  ((imm8 >>> 7) <<< 24) ||| (((imm8 >>> 4) &&& 0b111u) <<< 16)
  ||| (imm8 &&& 0xfu)

/// <summary>
/// The two words VMOV and VMVN can build that the instructions which also read
/// their register cannot: a byte shifted in over eight ones, or over sixteen.
/// </summary>
let private onesShifted (value: uint32) =
  if value >>> 16 = 0u && value &&& 0xffu = 0xffu then
    (0b1100u <<< 8) ||| splitSimdImm8 (value >>> 8)
  elif value >>> 24 = 0u && value &&& 0xffffu = 0xffffu then
    (0b1101u <<< 8) ||| splitSimdImm8 (value >>> 16)
  else
    fail $"#{value} is not a SIMD immediate"

/// <summary>
/// The immediate a SIMD instruction builds each of its elements from, which is
/// one byte together with a code saying where in the element it sits and what
/// fills the rest.
///
/// The byte can only sit on a byte boundary, so which boundary it is comes from
/// the value itself: the code is chosen to put it back where it was found.
/// </summary>
let private simdImmediate ins withRegister (value: int64) =
  let value = uint32 value
  let placed positions baseCode =
    let fits shift =
      (value >>> shift) < 0x100u && (value >>> shift) <<< shift = value
    match positions |> List.tryFind fits with
    | Some shift ->
      let code = baseCode ||| (uint32 (shift / 8) <<< 1)
      ((code ||| (if withRegister then 1u else 0u)) <<< 8)
      ||| splitSimdImm8 (value >>> shift)
    | None ->
      fail $"#{value} is not a SIMD immediate"
  match elementSize ins with
  | 2u when not withRegister && value > 0xffu && value &&& 0xffu = 0xffu ->
    onesShifted value
  | 2u ->
    placed [ 0; 8; 16; 24 ] 0b0000u
  | 1u ->
    placed [ 0; 8 ] 0b1000u
  | 0u when not withRegister && value < 0x100u ->
    (0b1110u <<< 8) ||| splitSimdImm8 value
  | _ ->
    fail $"#{value} is not a SIMD immediate of this width"

/// <summary>
/// The immediate that fills a whole element rather than a byte of one, whose
/// eight bits stand for eight bytes: each bit says whether its byte is all ones
/// or all zeroes.
/// </summary>
let private wideSimdImmediate (value: int64) =
  let bytes =
    [ 0 .. 7 ] |> List.map (fun i -> (uint64 value >>> (i * 8)) &&& 0xffUL)
  if bytes |> List.forall (fun b -> b = 0UL || b = 0xffUL) then
    let imm8 =
      bytes
      |> List.mapi (fun i b -> if b = 0xffUL then 1u <<< i else 0u)
      |> List.reduce (|||)
    (0b1110u <<< 8) ||| splitSimdImm8 imm8
  else
    fail $"#{value} is not a SIMD immediate of that width"

/// The immediate a single-precision VMOV fills its elements with: the eight
/// bits of a floating-point move, under a code of their own.
let private floatSimdImmediate (value: int64) =
  (0b1111u <<< 8) ||| splitSimdImm8 (fpImm8 32 value)

/// The instructions that build every element of a register out of one
/// immediate, either on its own or together with what the register held.
let private neonImmediate withRegister op ins =
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector dd)), OprImm imm) ->
    let q = if isQuadReg dd then 1u else 0u
    let bits, op =
      if elementSize ins = 3u then wideSimdImmediate imm, 1u
      elif dataType ins = SIMDTypF32 then floatSimdImmediate imm, 0u
      else simdImmediate ins withRegister imm, op
    neonHead ins ||| (1u <<< 23) ||| bits ||| (q <<< 6) ||| (op <<< 5)
    ||| (1u <<< 4) ||| vd dd
  | _ ->
    wrongOperands ins

/// <summary>
/// Which element of a SIMD register a move names, as the two fields that say
/// so.
///
/// How wide the element is decides how much of the index the fields have to
/// hold, so the two are written together: the wider the element, the fewer
/// elements there are to tell apart.
/// </summary>
let private scalarIndexFields ins (index: uint32) =
  let opc1, opc2 =
    match elementSize ins with
    | 0u when index < 8u -> 0b10u ||| ((index >>> 2) &&& 1u), index &&& 0b11u
    | 1u when index < 4u -> (index >>> 1) &&& 1u, ((index &&& 1u) <<< 1) ||| 1u
    | 2u when index < 2u -> index, 0u
    | _ -> fail $"a SIMD register has no element {index} of that width"
  (opc1 <<< 21) ||| (opc2 <<< 5)

/// <summary>
/// VMOV, which moves between the core registers, the SIMD ones and an
/// immediate, and whose operands are the only thing saying which of those it
/// is doing.
/// </summary>
let private vmov ins =
  let head = cond ins ||| (0b1110u <<< 24) ||| (0b1011u <<< 8) ||| (1u <<< 4)
  let pairHead size op =
    cond ins ||| (0b1100u <<< 24) ||| (0b010u <<< 21) ||| (op <<< 20)
    ||| (size <<< 8) ||| (1u <<< 4)
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector dd)), OprImm _) ->
    (match dataType ins with
     | SIMDTypF16 | SIMDTypF32 when isSingleReg dd -> fpMoveImm ins
     | SIMDTypF64 -> fpMoveImm ins
     | _ -> neonImmediate false 0u ins)
  | TwoOperands(OprSIMD(SFReg(Vector dd)), OprSIMD(SFReg(Vector dm))) ->
    cond ins ||| fpTwoRegHead 0b0000u 0b01u ||| fpFields2 ins dd dm
  | TwoOperands(OprReg rt, OprSIMD(SFReg(Scalar(dn, Some index)))) ->
    head ||| (unsignedBit ins <<< 23) ||| (1u <<< 20)
    ||| scalarIndexFields ins (uint32 index) ||| (coreReg rt <<< 12) ||| vn dn
  | TwoOperands(OprSIMD(SFReg(Scalar(dd, Some index))), OprReg rt) ->
    head ||| scalarIndexFields ins (uint32 index) ||| (coreReg rt <<< 12)
    ||| vn dd
  | TwoOperands(OprSIMD(SFReg(Vector sn)), OprReg rt) ->
    let size = if elementSizeOrNone ins = Some 1u then 0b1001u else 0b1010u
    cond ins ||| (0b1110u <<< 24) ||| (size <<< 8) ||| (1u <<< 4)
    ||| (coreReg rt <<< 12) ||| AsmField.sn sn
  | TwoOperands(OprReg rt, OprSIMD(SFReg(Vector sn))) ->
    let size = if elementSizeOrNone ins = Some 1u then 0b1001u else 0b1010u
    cond ins ||| (0b1110u <<< 24) ||| (1u <<< 20) ||| (size <<< 8)
    ||| (1u <<< 4) ||| (coreReg rt <<< 12) ||| AsmField.sn sn
  | ThreeOperands(OprSIMD(SFReg(Vector dm)), OprReg rt, OprReg rt2) ->
    pairHead 0b1011u 0u ||| (coreReg rt2 <<< 16) ||| (coreReg rt <<< 12)
    ||| vm dm
  | ThreeOperands(OprReg rt, OprReg rt2, OprSIMD(SFReg(Vector dm))) ->
    pairHead 0b1011u 1u ||| (coreReg rt2 <<< 16) ||| (coreReg rt <<< 12)
    ||| vm dm
  (* Two single-precision registers hold as much as one double-precision one,
     so the pair that moves them names four registers rather than three. *)
  | FourOperands(OprSIMD(SFReg(Vector first)),
                 OprSIMD(SFReg(Vector _)),
                 OprReg rt,
                 OprReg rt2) ->
    pairHead 0b1010u 0u ||| (coreReg rt2 <<< 16) ||| (coreReg rt <<< 12)
    ||| sm first
  | FourOperands(OprReg rt,
                 OprReg rt2,
                 OprSIMD(SFReg(Vector first)),
                 OprSIMD(SFReg(Vector _))) ->
    pairHead 0b1010u 1u ||| (coreReg rt2 <<< 16) ||| (coreReg rt <<< 12)
    ||| sm first
  | _ ->
    wrongOperands ins

/// VMLA and VMLS, which both the floating-point unit and the SIMD unit have.
/// Only the SIMD ones multiply by one element of a register, so what the third
/// operand names is what says which unit is meant; by an element, bit 8 says
/// whether the elements are floating-point.
let private mulAccumulate opcode op scalarOpcode variant ins =
  match ins.Operands with
  | ThreeOperands(_, _, OprSIMD(SFReg(Scalar _))) ->
    let isFloat =
      match dataType ins with
      | SIMDTypF16 | SIMDTypF32 -> 1u
      | _ -> 0u
    neonScalar true (scalarOpcode ||| isFloat) ins
  | _ ->
    let float = neon3FloatDt 0u variant 0b1101u
    eitherUnit (fp3 opcode op) (byType float (neon3 variant 0b1001u 0u)) ins

/// <summary>
/// Where a SIMD access that names whole structures reads, which is the only
/// place these say anything about stepping the base register: a register named
/// after the brackets steps it by whatever that register holds, and the two
/// values no register could usefully name say to step it by the size of the
/// transfer or not at all.
/// </summary>
let private structureMemory ins mode =
  let bits rn align rm =
    let align =
      match align with
      | None | Some 0L -> 0u
      | Some 64L -> 1u
      | Some 128L -> 2u
      | Some 256L -> 3u
      | Some align -> fail $"{align} is not an alignment"
    (coreReg rn <<< 16) ||| (align <<< 4) ||| coreReg rm
  match mode with
  | OffsetMode(AlignOffset(rn, align, None)) -> bits rn align Register.PC
  | PreIdxMode(AlignOffset(rn, align, None)) -> bits rn align Register.SP
  | PostIdxMode(AlignOffset(rn, align, Some rm)) -> bits rn align rm
  | _ -> wrongOperands ins

/// The base register and the one that steps it, without the alignment: a
/// single-lane transfer writes its own alignment beside the element it names.
let private laneMemory ins mode =
  match mode with
  | OffsetMode(AlignOffset(rn, _, None)) ->
    (coreReg rn <<< 16) ||| coreReg Register.PC
  | PreIdxMode(AlignOffset(rn, _, None)) ->
    (coreReg rn <<< 16) ||| coreReg Register.SP
  | PostIdxMode(AlignOffset(rn, _, Some rm)) ->
    (coreReg rn <<< 16) ||| coreReg rm
  | _ ->
    wrongOperands ins

/// The bits the SIMD accesses that name whole structures share. They live in
/// the unconditional encoding space, as every SIMD access does.
let private structureHead single l ins =
  unconditional ins ||| (0b0100u <<< 24) ||| (single <<< 23) ||| (l <<< 21)

/// <summary>
/// Which registers a transfer of several structures moves, as the code the
/// encoding holds.
///
/// The code says both how many registers there are and how far apart they sit,
/// and which codes exist depends on how many registers each structure needs, so
/// this is a table rather than a calculation.
/// </summary>
let private structureType opcode count spacing =
  match opcode, count, spacing with
  | (Opcode.VLD1 | Opcode.VST1), 1, 1 -> 0b0111u
  | (Opcode.VLD1 | Opcode.VST1), 2, 1 -> 0b1010u
  | (Opcode.VLD1 | Opcode.VST1), 3, 1 -> 0b0110u
  | (Opcode.VLD1 | Opcode.VST1), 4, 1 -> 0b0010u
  | (Opcode.VLD2 | Opcode.VST2), 2, 1 -> 0b1000u
  | (Opcode.VLD2 | Opcode.VST2), 2, 2 -> 0b1001u
  | (Opcode.VLD2 | Opcode.VST2), 4, 1 -> 0b0011u
  | (Opcode.VLD3 | Opcode.VST3), 3, 1 -> 0b0100u
  | (Opcode.VLD3 | Opcode.VST3), 3, 2 -> 0b0101u
  | (Opcode.VLD4 | Opcode.VST4), 4, 1 -> 0b0000u
  | (Opcode.VLD4 | Opcode.VST4), 4, 2 -> 0b0001u
  | _ -> fail $"{opcode} does not move {count} registers {spacing} apart"

/// The transfers of several structures at once, which move whole registers.
let private structureTransfer l ins =
  match ins.Operands with
  | ThreeOperands(OprSIMD list, OprMemory mode, _)
  | TwoOperands(OprSIMD list, OprMemory mode) ->
    let regs = simdListRegs list
    let spacing =
      match regs |> List.map int with
      | first :: second :: _ -> second - first
      | _ -> 1
    let evenlySpaced =
      regs |> List.mapi (fun i reg -> int reg - i * spacing) |> List.distinct
    if List.length evenlySpaced <> 1 || (spacing <> 1 && spacing <> 2) then
      fail $"{ins.Opcode} needs evenly spaced registers"
    else
      structureHead 0u l ins
      ||| (structureType ins.Opcode (List.length regs) spacing <<< 8)
      ||| (elementSize ins <<< 6) ||| vd (List.head regs)
      ||| structureMemory ins mode
  | _ ->
    wrongOperands ins

/// The registers of a SIMD list that names one element of each, together with
/// the element they all name.
let private simdLaneRegs list =
  let regs =
    match list with
    | OneReg s -> [ s ]
    | TwoRegs(s1, s2) -> [ s1; s2 ]
    | ThreeRegs(s1, s2, s3) -> [ s1; s2; s3 ]
    | FourRegs(s1, s2, s3, s4) -> [ s1; s2; s3; s4 ]
    | SFReg s -> [ s ]
  let named =
    regs
    |> List.choose (function
      | Scalar(reg, Some index) -> Some(reg, uint32 index)
      | Vector _ | Scalar(_, None) -> None)
  if List.length named <> List.length regs then
    fail "a lane transfer names one element of each register"
  else
    named

/// <summary>
/// What a single-lane transfer promises about the address it reads, as the code
/// that says so.
///
/// What may be promised is that the address is aligned to the whole structure,
/// which is why the code depends on how many registers the structure spans as
/// well as on how wide its elements are.
/// </summary>
let private laneAlignCode count size (align: int64) =
  match count, size, align with
  | _, _, 0L -> 0u
  | 1, 1u, 16L | 2, 0u, 16L | 2, 1u, 32L | 2, 2u, 64L -> 1u
  | 4, 0u, 32L | 4, 1u, 64L | 4, 2u, 64L -> 1u
  | 1, 2u, 32L -> 3u
  | 4, 2u, 128L -> 2u
  | _ -> fail $"{align} is not an alignment for this transfer"

/// <summary>
/// The transfers that move one element of each register they name.
///
/// How wide the element is decides how much of the field below the structure
/// count the index needs, and what is left of that field says what the address
/// is aligned to.
/// </summary>
let private structureLane l ins =
  match ins.Operands with
  | ThreeOperands(OprSIMD list, OprMemory mode, _)
  | TwoOperands(OprSIMD list, OprMemory mode) ->
    let named = simdLaneRegs list
    let first, index = List.head named
    let count = List.length named
    let size = elementSize ins
    let spacing =
      match named |> List.map (fst >> int) with
      | [ _ ] -> 1
      | first :: second :: _ -> second - first
      | [] -> 0
    let evenlySpaced =
      named
      |> List.mapi (fun i (reg, _) -> int reg - i * spacing)
      |> List.distinct
    let sameLane = named |> List.map snd |> List.distinct
    if List.length evenlySpaced <> 1 || List.length sameLane <> 1 then
      fail $"{ins.Opcode} names one element of evenly spaced registers"
    elif spacing <> 1 && (spacing <> 2 || count = 1 || size = 0u) then
      fail $"{ins.Opcode} cannot step {spacing} registers at a time"
    elif index >= (8u >>> int size) then
      fail $"a SIMD register has no element {index} of that width"
    else
      let align =
        match mode with
        | OffsetMode(AlignOffset(_, Some align, _))
        | PreIdxMode(AlignOffset(_, Some align, _))
        | PostIdxMode(AlignOffset(_, Some align, _)) -> align
        | _ -> 0L
      (* The bit that says how far apart the registers are sits between the
         element and what the address promises, and only exists where more than
         one register is named and the elements are wider than a byte. *)
      let stride = if spacing = 2 then 1u else 0u
      let indexAlign =
        (index <<< (int size + 1)) ||| (stride <<< int size)
        ||| laneAlignCode count size align
      structureHead 1u l ins ||| (size <<< 10)
      ||| (uint32 (count - 1) <<< 8) ||| (indexAlign <<< 4) ||| vd first
      ||| laneMemory ins mode
  | _ ->
    wrongOperands ins

/// <summary>
/// The loads that read one element into every lane of the registers they name,
/// which the source writes as an element with no number.
///
/// Bits 9:8 say how many elements a structure has, which is the mnemonic's
/// number and not the count of registers: VLD1 fills one register or two, and
/// says which with T, where the others say with T how far apart theirs are.
/// VLD4 of words promises a quadword with a size field of 11, the one
/// alignment the field has no other room for.
/// </summary>
let private structureAllLanes ins =
  match ins.Operands with
  | ThreeOperands(OprSIMD list, OprMemory mode, _)
  | TwoOperands(OprSIMD list, OprMemory mode) ->
    let named = simdListRegs list
    let structure =
      match ins.Opcode with
      | Opcode.VLD1 -> 1
      | Opcode.VLD2 -> 2
      | Opcode.VLD3 -> 3
      | _ -> 4
    let spacing =
      match named |> List.map int with
      | first :: second :: _ -> second - first
      | _ -> 1
    let t =
      if structure = 1 then uint32 (List.length named - 1)
      elif spacing = 2 then 1u
      else 0u
    let align =
      match mode with
      | OffsetMode(AlignOffset(_, Some align, _))
      | PreIdxMode(AlignOffset(_, Some align, _))
      | PostIdxMode(AlignOffset(_, Some align, _)) -> align
      | _ -> 0L
    let size, a =
      match structure, elementSize ins, align with
      | _, size, 0L -> size, 0u
      | 4, 0b10u, 128L -> 0b11u, 1u
      | _, size, _ -> size, 1u
    structureHead 1u 1u ins ||| (0b11u <<< 10)
    ||| (uint32 (structure - 1) <<< 8) ||| (size <<< 6) ||| (t <<< 5)
    ||| (a <<< 4) ||| vd (List.head named) ||| laneMemory ins mode
  | _ ->
    wrongOperands ins

/// VLD and VST, which move whole structures or one element of one. Which of the
/// two is meant is what the operand names.
let private structureAccess l ins =
  let namesOneLane = function
    | OneReg(Scalar(_, Some _)) | TwoRegs(Scalar(_, Some _), _)
    | ThreeRegs(Scalar(_, Some _), _, _)
    | FourRegs(Scalar(_, Some _), _, _, _) -> true
    | _ -> false
  let namesEveryLane = function
    | OneReg(Scalar(_, None)) | TwoRegs(Scalar(_, None), _)
    | ThreeRegs(Scalar(_, None), _, _)
    | FourRegs(Scalar(_, None), _, _, _) -> true
    | _ -> false
  match ins.Operands with
  | ThreeOperands(OprSIMD list, _, _)
  | TwoOperands(OprSIMD list, _) when namesOneLane list ->
    structureLane l ins
  | ThreeOperands(OprSIMD list, _, _)
  | TwoOperands(OprSIMD list, _) when namesEveryLane list ->
    structureAllLanes ins
  | _ ->
    structureTransfer l ins

(* The encoder tables. Each is a function so that its rows are built when an
   assembler asks for them rather than living for as long as the process. *)
/// The instructions of the data-processing space: the arithmetic and logical
/// operations, the moves, and the shifts the manual defines as aliases of MOV.
let dataProcessingEncoders () =
  [ Opcode.AND, dataProc 0b0000u 0u
    Opcode.ANDS, dataProc 0b0000u 1u
    Opcode.EOR, dataProc 0b0001u 0u
    Opcode.EORS, dataProc 0b0001u 1u
    Opcode.SUB, dataProc 0b0010u 0u
    Opcode.SUBS, dataProc 0b0010u 1u
    Opcode.RSB, dataProc 0b0011u 0u
    Opcode.RSBS, dataProc 0b0011u 1u
    Opcode.ADD, dataProc 0b0100u 0u
    Opcode.ADDS, dataProc 0b0100u 1u
    Opcode.ADC, dataProc 0b0101u 0u
    Opcode.ADCS, dataProc 0b0101u 1u
    Opcode.SBC, dataProc 0b0110u 0u
    Opcode.SBCS, dataProc 0b0110u 1u
    Opcode.RSC, dataProc 0b0111u 0u
    Opcode.RSCS, dataProc 0b0111u 1u
    Opcode.ORR, dataProc 0b1100u 0u
    Opcode.ORRS, dataProc 0b1100u 1u
    Opcode.BIC, dataProc 0b1110u 0u
    Opcode.BICS, dataProc 0b1110u 1u
    Opcode.TST, testAndCompare 0b1000u
    Opcode.TEQ, testAndCompare 0b1001u
    Opcode.CMP, testAndCompare 0b1010u
    Opcode.CMN, testAndCompare 0b1011u
    Opcode.MOV, moveOperand2 0b1101u 0u
    Opcode.MOVS, moveOperand2 0b1101u 1u
    Opcode.MVN, moveOperand2 0b1111u 0u
    Opcode.MVNS, moveOperand2 0b1111u 1u
    Opcode.LSL, shiftAlias ShiftOp.LSL 0u
    Opcode.LSLS, shiftAlias ShiftOp.LSL 1u
    Opcode.LSR, shiftAlias ShiftOp.LSR 0u
    Opcode.LSRS, shiftAlias ShiftOp.LSR 1u
    Opcode.ASR, shiftAlias ShiftOp.ASR 0u
    Opcode.ASRS, shiftAlias ShiftOp.ASR 1u
    Opcode.ROR, shiftAlias ShiftOp.ROR 0u
    Opcode.RORS, shiftAlias ShiftOp.ROR 1u
    Opcode.RRX, shiftAlias ShiftOp.RRX 0u
    Opcode.RRXS, shiftAlias ShiftOp.RRX 1u
    Opcode.ADR, adr
    Opcode.MOVW, moveHalfword 0b00110000u
    Opcode.MOVT, moveHalfword 0b00110100u ]

/// The multiplies, both the ones whose result is one register wide and the
/// ones that read or write half a register at a time.
let multiplyEncoders () =
  [ Opcode.MUL, mul3 0b0000u
    Opcode.MULS, mul3 0b0001u
    Opcode.MLA, mul4 0b0010u
    Opcode.MLAS, mul4 0b0011u
    Opcode.UMAAL, mulLong 0b0100u
    Opcode.MLS, mul4 0b0110u
    Opcode.UMULL, mulLong 0b1000u
    Opcode.UMULLS, mulLong 0b1001u
    Opcode.UMLAL, mulLong 0b1010u
    Opcode.UMLALS, mulLong 0b1011u
    Opcode.SMULL, mulLong 0b1100u
    Opcode.SMULLS, mulLong 0b1101u
    Opcode.SMLAL, mulLong 0b1110u
    Opcode.SMLALS, mulLong 0b1111u
    Opcode.SMLABB, halfMul4 0b00u 0b00u
    Opcode.SMLATB, halfMul4 0b00u 0b01u
    Opcode.SMLABT, halfMul4 0b00u 0b10u
    Opcode.SMLATT, halfMul4 0b00u 0b11u
    Opcode.SMLAWB, halfMul4 0b01u 0b00u
    Opcode.SMULWB, halfMul3 0b01u 0b01u
    Opcode.SMLAWT, halfMul4 0b01u 0b10u
    Opcode.SMULWT, halfMul3 0b01u 0b11u
    Opcode.SMLALBB, halfMulLong 0b10u 0b00u
    Opcode.SMLALTB, halfMulLong 0b10u 0b01u
    Opcode.SMLALBT, halfMulLong 0b10u 0b10u
    Opcode.SMLALTT, halfMulLong 0b10u 0b11u
    Opcode.SMULBB, halfMul3 0b11u 0b00u
    Opcode.SMULTB, halfMul3 0b11u 0b01u
    Opcode.SMULBT, halfMul3 0b11u 0b10u
    Opcode.SMULTT, halfMul3 0b11u 0b11u ]

/// The branches, and the instructions of the miscellaneous space that sits
/// between the data-processing instructions and the multiplies.
let miscellaneousEncoders () =
  [ Opcode.B, branch 0b1010u
    Opcode.BL, branch 0b1011u
    Opcode.BLX, branchLinkExchange
    Opcode.BX, branchReg 0b0001u
    Opcode.BXJ, branchReg 0b0010u
    Opcode.CLZ, clz
    Opcode.ERET, eret
    Opcode.HLT, exception16 0b00u
    Opcode.BKPT, exception16 0b01u
    Opcode.HVC, exception16 0b10u
    Opcode.SMC, smc
    Opcode.SVC, svc
    Opcode.UDF, udf
    Opcode.QADD, saturatingArith 0b00u
    Opcode.QSUB, saturatingArith 0b01u
    Opcode.QDADD, saturatingArith 0b10u
    Opcode.QDSUB, saturatingArith 0b11u
    Opcode.CRC32B, crc32 0b00u 0u
    Opcode.CRC32CB, crc32 0b00u 1u
    Opcode.CRC32H, crc32 0b01u 0u
    Opcode.CRC32CH, crc32 0b01u 1u
    Opcode.CRC32W, crc32 0b10u 0u
    Opcode.CRC32CW, crc32 0b10u 1u
    Opcode.MRS, mrs
    Opcode.MSR, msr
    Opcode.CPS, changeState 0b00u
    Opcode.CPSIE, changeState 0b10u
    Opcode.CPSID, changeState 0b11u ]

/// The hints, the barriers, and the two instructions that change how the
/// processor reads memory rather than reading any itself.
let hintEncoders () =
  [ Opcode.NOP, hint 0x00u
    Opcode.YIELD, hint 0x01u
    Opcode.WFE, hint 0x02u
    Opcode.WFI, hint 0x03u
    Opcode.SEV, hint 0x04u
    Opcode.SEVL, hint 0x05u
    Opcode.ESB, hint 0x10u
    Opcode.CSDB, hint 0x14u
    Opcode.TSB, tsb
    Opcode.DBG, dbg
    Opcode.CLREX, barrier 0b0001u 0xfu
    Opcode.DSB, barrier 0b0100u 0xfu
    Opcode.SSBB, barrier 0b0100u 0x0u
    Opcode.PSSBB, barrier 0b0100u 0x4u
    Opcode.DMB, barrier 0b0101u 0xfu
    Opcode.ISB, barrier 0b0110u 0xfu
    Opcode.SB, barrier 0b0111u 0x0u
    Opcode.SETEND, setend
    Opcode.SETPAN, setpan ]

/// The loads and stores, from the plain word and byte ones to the exclusive
/// and ordered accesses and the preload hints.
let loadStoreEncoders () =
  [ Opcode.STR, loadStore 0u 0u
    Opcode.LDR, loadStore 0u 1u
    Opcode.STRB, loadStore 1u 0u
    Opcode.LDRB, loadStore 1u 1u
    Opcode.STRT, loadStoreUnpriv 0u 0u
    Opcode.LDRT, loadStoreUnpriv 0u 1u
    Opcode.STRBT, loadStoreUnpriv 1u 0u
    Opcode.LDRBT, loadStoreUnpriv 1u 1u
    Opcode.STRH, extraLoadStore 0u 0b01u
    Opcode.LDRH, extraLoadStore 1u 0b01u
    Opcode.LDRSB, extraLoadStore 1u 0b10u
    Opcode.LDRSH, extraLoadStore 1u 0b11u
    Opcode.STRHT, extraLoadStoreUnpriv 0u 0b01u
    Opcode.LDRHT, extraLoadStoreUnpriv 1u 0b01u
    Opcode.LDRSBT, extraLoadStoreUnpriv 1u 0b10u
    Opcode.LDRSHT, extraLoadStoreUnpriv 1u 0b11u
    Opcode.LDRD, loadStoreDual 0u 0b10u
    Opcode.STRD, loadStoreDual 0u 0b11u
    Opcode.STL, storeOrdered 0b00u
    Opcode.STLB, storeOrdered 0b10u
    Opcode.STLH, storeOrdered 0b11u
    Opcode.LDA, loadExclusive 0b00u 0b00u
    Opcode.LDAB, loadExclusive 0b10u 0b00u
    Opcode.LDAH, loadExclusive 0b11u 0b00u
    Opcode.LDAEX, loadExclusive 0b00u 0b10u
    Opcode.LDAEXB, loadExclusive 0b10u 0b10u
    Opcode.LDAEXH, loadExclusive 0b11u 0b10u
    Opcode.LDREX, loadExclusive 0b00u 0b11u
    Opcode.LDREXB, loadExclusive 0b10u 0b11u
    Opcode.LDREXH, loadExclusive 0b11u 0b11u
    Opcode.STLEX, storeExclusive 0b00u 0b10u
    Opcode.STLEXB, storeExclusive 0b10u 0b10u
    Opcode.STLEXH, storeExclusive 0b11u 0b10u
    Opcode.STREX, storeExclusive 0b00u 0b11u
    Opcode.STREXB, storeExclusive 0b10u 0b11u
    Opcode.STREXH, storeExclusive 0b11u 0b11u
    Opcode.LDAEXD, loadExclusiveDual 0b10u
    Opcode.LDREXD, loadExclusiveDual 0b11u
    Opcode.STLEXD, storeExclusiveDual 0b10u
    Opcode.STREXD, storeExclusiveDual 0b11u
    Opcode.SWP, swap 0u
    Opcode.SWPB, swap 1u
    Opcode.PLD, preload 1u 1u
    Opcode.PLDW, preload 1u 0u
    Opcode.PLI, preload 0u 1u ]

/// The instructions that move several registers at once, and the two that save
/// and restore the state an exception left behind.
let blockTransferEncoders () =
  [ Opcode.STMDA, blockTransfer 0u 0u 0u
    Opcode.LDMDA, blockTransfer 0u 0u 1u
    Opcode.STM, blockTransfer 0u 1u 0u
    Opcode.STMIA, blockTransfer 0u 1u 0u
    Opcode.LDM, blockTransfer 0u 1u 1u
    Opcode.LDMIA, blockTransfer 0u 1u 1u
    Opcode.STMDB, blockTransfer 1u 0u 0u
    Opcode.LDMDB, blockTransfer 1u 0u 1u
    Opcode.STMIB, blockTransfer 1u 1u 0u
    Opcode.LDMIB, blockTransfer 1u 1u 1u
    Opcode.PUSH, stackTransfer
    Opcode.POP, stackTransfer
    Opcode.RFEDA, returnFromException 0u 0u
    Opcode.RFEIA, returnFromException 0u 1u
    Opcode.RFEDB, returnFromException 1u 0u
    Opcode.RFEIB, returnFromException 1u 1u
    Opcode.SRSDA, storeReturnState 0u 0u
    Opcode.SRSIA, storeReturnState 0u 1u
    Opcode.SRSDB, storeReturnState 1u 0u
    Opcode.SRSIB, storeReturnState 1u 1u ]

/// The media instructions: the parallel arithmetic, the saturating and
/// extending moves, the bitfield operations and the signed multiplies that
/// read half a register at a time.
let mediaEncoders () =
  [ Opcode.SADD16, parallelArith 0b001u 0b000u
    Opcode.SASX, parallelArith 0b001u 0b001u
    Opcode.SSAX, parallelArith 0b001u 0b010u
    Opcode.SSUB16, parallelArith 0b001u 0b011u
    Opcode.SADD8, parallelArith 0b001u 0b100u
    Opcode.SSUB8, parallelArith 0b001u 0b111u
    Opcode.QADD16, parallelArith 0b010u 0b000u
    Opcode.QASX, parallelArith 0b010u 0b001u
    Opcode.QSAX, parallelArith 0b010u 0b010u
    Opcode.QSUB16, parallelArith 0b010u 0b011u
    Opcode.QADD8, parallelArith 0b010u 0b100u
    Opcode.QSUB8, parallelArith 0b010u 0b111u
    Opcode.SHADD16, parallelArith 0b011u 0b000u
    Opcode.SHASX, parallelArith 0b011u 0b001u
    Opcode.SHSAX, parallelArith 0b011u 0b010u
    Opcode.SHSUB16, parallelArith 0b011u 0b011u
    Opcode.SHADD8, parallelArith 0b011u 0b100u
    Opcode.SHSUB8, parallelArith 0b011u 0b111u
    Opcode.UADD16, parallelArith 0b101u 0b000u
    Opcode.UASX, parallelArith 0b101u 0b001u
    Opcode.USAX, parallelArith 0b101u 0b010u
    Opcode.USUB16, parallelArith 0b101u 0b011u
    Opcode.UADD8, parallelArith 0b101u 0b100u
    Opcode.USUB8, parallelArith 0b101u 0b111u
    Opcode.UQADD16, parallelArith 0b110u 0b000u
    Opcode.UQASX, parallelArith 0b110u 0b001u
    Opcode.UQSAX, parallelArith 0b110u 0b010u
    Opcode.UQSUB16, parallelArith 0b110u 0b011u
    Opcode.UQADD8, parallelArith 0b110u 0b100u
    Opcode.UQSUB8, parallelArith 0b110u 0b111u
    Opcode.UHADD16, parallelArith 0b111u 0b000u
    Opcode.UHASX, parallelArith 0b111u 0b001u
    Opcode.UHSAX, parallelArith 0b111u 0b010u
    Opcode.UHSUB16, parallelArith 0b111u 0b011u
    Opcode.UHADD8, parallelArith 0b111u 0b100u
    Opcode.UHSUB8, parallelArith 0b111u 0b111u
    Opcode.SEL, sel
    Opcode.PKHBT, pack 0u
    Opcode.PKHTB, pack 1u
    Opcode.SSAT, saturate 0u 1L
    Opcode.USAT, saturate 1u 0L
    Opcode.SSAT16, saturate16 0u 1L
    Opcode.USAT16, saturate16 1u 0L
    Opcode.REV, reverse 0u 0u
    Opcode.REV16, reverse 0u 1u
    Opcode.RBIT, reverse 1u 0u
    Opcode.REVSH, reverse 1u 1u
    Opcode.SXTAB16, extend 0b000u
    Opcode.SXTB16, extend 0b000u
    Opcode.SXTAB, extend 0b010u
    Opcode.SXTB, extend 0b010u
    Opcode.SXTAH, extend 0b011u
    Opcode.SXTH, extend 0b011u
    Opcode.UXTAB16, extend 0b100u
    Opcode.UXTB16, extend 0b100u
    Opcode.UXTAB, extend 0b110u
    Opcode.UXTB, extend 0b110u
    Opcode.UXTAH, extend 0b111u
    Opcode.UXTH, extend 0b111u
    Opcode.SMLAD, signedMul4 0b000u 0b000u
    Opcode.SMUAD, signedMul3 0b000u 0b000u
    Opcode.SMLADX, signedMul4 0b000u 0b001u
    Opcode.SMUADX, signedMul3 0b000u 0b001u
    Opcode.SMLSD, signedMul4 0b000u 0b010u
    Opcode.SMUSD, signedMul3 0b000u 0b010u
    Opcode.SMLSDX, signedMul4 0b000u 0b011u
    Opcode.SMUSDX, signedMul3 0b000u 0b011u
    Opcode.SDIV, signedMul3 0b001u 0b000u
    Opcode.UDIV, signedMul3 0b011u 0b000u
    Opcode.SMLALD, signedMulLong 0b100u 0b000u
    Opcode.SMLALDX, signedMulLong 0b100u 0b001u
    Opcode.SMLSLD, signedMulLong 0b100u 0b010u
    Opcode.SMLSLDX, signedMulLong 0b100u 0b011u
    Opcode.SMMLA, signedMul4 0b101u 0b000u
    Opcode.SMMUL, signedMul3 0b101u 0b000u
    Opcode.SMMLAR, signedMul4 0b101u 0b001u
    Opcode.SMMULR, signedMul3 0b101u 0b001u
    Opcode.SMMLS, signedMul4 0b101u 0b110u
    Opcode.SMMLSR, signedMul4 0b101u 0b111u
    Opcode.USAD8, absoluteDifference
    Opcode.USADA8, absoluteDifference
    Opcode.BFC, bitfieldInsert
    Opcode.BFI, bitfieldInsert
    Opcode.SBFX, bitfieldExtract 0u
    Opcode.UBFX, bitfieldExtract 1u ]

/// The coprocessor instructions, which say what to do rather than doing it: the
/// coprocessor reads the fields the manual leaves to it.
let coprocessorEncoders () =
  [ Opcode.CDP, cdp 0u
    Opcode.CDP2, cdp 1u
    Opcode.MCR, moveCoproc 0u 0u
    Opcode.MCR2, moveCoproc 1u 0u
    Opcode.MRC, moveCoproc 0u 1u
    Opcode.MRC2, moveCoproc 1u 1u
    Opcode.MCRR, moveCoprocPair 0u 0u
    Opcode.MCRR2, moveCoprocPair 1u 0u
    Opcode.MRRC, moveCoprocPair 0u 1u
    Opcode.MRRC2, moveCoprocPair 1u 1u
    Opcode.STC, loadStoreCoproc 0u 0u 0u
    Opcode.STCL, loadStoreCoproc 0u 1u 0u
    Opcode.STC2, loadStoreCoproc 1u 0u 0u
    Opcode.STC2L, loadStoreCoproc 1u 1u 0u
    Opcode.LDC, loadStoreCoproc 0u 0u 1u
    Opcode.LDCL, loadStoreCoproc 0u 1u 1u
    Opcode.LDC2, loadStoreCoproc 1u 0u 1u
    Opcode.LDC2L, loadStoreCoproc 1u 1u 1u ]

/// VCVT between floating-point numbers and integers as wide as each other on
/// the SIMD unit; op says which way and whether the integers are unsigned.
let private neonIntConvert ins =
  match ins.SIMDTyp with
  | Some(TwoDT(dst, src)) ->
    let toInteger = if isFloatType dst then 0u else 1u
    let floatType, intType = if toInteger = 1u then src, dst else dst, src
    let op = (toInteger <<< 1) ||| unsignedOf intType
    neonTwoRegSized (fpWidthBits floatType) 0b11u (0b1100u ||| op) ins
  | _ ->
    wrongOperands ins

/// VCVT on the SIMD unit: between halves and singles, which write a
/// doubleword from a quadword or the other way round, to brain floating-point,
/// between floating-point numbers and integers, and to and from fixed point.
let private neonConvert ins =
  match ins.Operands, ins.SIMDTyp with
  | ThreeOperands _, _ ->
    neonConvertFixed ins
  | _, Some(TwoDT(BF16, SIMDTypF32)) ->
    neonTwoRegOp 0b01u 0b10u 0b11001u ins
  | _, Some(TwoDT(SIMDTypF16, SIMDTypF32)) ->
    neonTwoRegOp 0b01u 0b10u 0b11000u ins
  | _, Some(TwoDT(SIMDTypF32, SIMDTypF16)) ->
    neonTwoRegOp 0b01u 0b10u 0b11100u ins
  | _ ->
    neonIntConvert ins

/// VCVT on the floating-point unit: between a single and a double, to and from
/// an integer, and to and from fixed point.
let private fpConvert ins =
  match ins.Operands, ins.SIMDTyp with
  | ThreeOperands _, _ ->
    fpFixedConvert ins
  | _, Some(TwoDT(dst, src)) when isFloatType dst && isFloatType src ->
    fpWidthConvert ins
  | _ ->
    fpIntConvert 1u ins

/// Whether a conversion is the floating-point unit's, which names a
/// single-precision register or converts to or from a double; the SIMD unit
/// does neither.
let private isFPConversion ins =
  match ins.Operands, ins.SIMDTyp with
  | TwoOperands(OprSIMD(SFReg(Vector reg)), _), Some(TwoDT(dst, src))
  | ThreeOperands(OprSIMD(SFReg(Vector reg)), _, _), Some(TwoDT(dst, src)) ->
    isSingleReg reg || dst = SIMDTypF64 || src = SIMDTypF64
  | _ ->
    false

/// VCVT, which converts between the number formats its two data types name;
/// as for the other operations both units have, the registers say which unit
/// converts.
let private convert ins =
  if isFPConversion ins then fpConvert ins else neonConvert ins

/// VCVTA, VCVTN, VCVTP and VCVTM, which the floating-point unit writes to a
/// single-precision register and the SIMD unit to a doubleword or quadword;
/// RM says which way they round, and on the SIMD unit op that the integers are
/// unsigned.
let private directedConvert rm ins =
  match ins.Operands with
  | TwoOperands(OprSIMD(SFReg(Vector reg)), _) when isSingleReg reg ->
    fpDirectedConvert rm ins
  | _ ->
    neonTwoReg 0b11u ((rm <<< 1) ||| unsignedBit ins) ins

/// The floating-point instructions, which share one encoding space with the
/// coprocessor ones and are told from them by the number they name.
let floatingPointEncoders () =
  let vadd = byType (neon3FloatOp 0u 0u 0b1101u 0u) (neon3 0u 0b1000u 0u)
  let vsub = byType (neon3FloatOp 0u 1u 0b1101u 0u) (neon3 1u 0b1000u 0u)
  [ Opcode.VMLA, mulAccumulate 0b000u 0u 0b0000u 0u
    Opcode.VMLS, mulAccumulate 0b000u 1u 0b0100u 1u
    Opcode.VNMLS, fp3 0b001u 0u
    Opcode.VNMLA, fp3 0b001u 1u
    Opcode.VNMUL, fp3 0b010u 1u
    Opcode.VADD, eitherUnit (fp3 0b011u 0u) vadd
    Opcode.VSUB, eitherUnit (fp3 0b011u 1u) vsub
    Opcode.VSQRT, fp2 0b0001u 0b11u
    Opcode.VDIV, fp3 0b100u 0u
    Opcode.VFNMS, fp3 0b101u 0u
    Opcode.VFNMA, fp3 0b101u 1u
    Opcode.VFMA, eitherUnit (fp3 0b110u 0u) (neon3FloatDt 0u 0u 0b1100u)
    Opcode.VFMS, eitherUnit (fp3 0b110u 1u) (neon3FloatDt 0u 1u 0b1100u)
    Opcode.VSELEQ, fpSelect 0b00u
    Opcode.VSELVS, fpSelect 0b01u
    Opcode.VSELGE, fpSelect 0b10u
    Opcode.VSELGT, fpSelect 0b11u
    Opcode.VMAXNM, eitherUnit (fpMinMax 0u) (neon3FloatDt 1u 0u 0b1111u)
    Opcode.VMINNM, eitherUnit (fpMinMax 1u) (neon3FloatDt 1u 1u 0b1111u)
    Opcode.VRINTA, eitherUnit (fpRoundInt 0b000u) (neonTwoReg 0b10u 0b1010u)
    Opcode.VRINTN, eitherUnit (fpRoundInt 0b001u) (neonTwoReg 0b10u 0b1000u)
    Opcode.VRINTP, eitherUnit (fpRoundInt 0b010u) (neonTwoReg 0b10u 0b1111u)
    Opcode.VRINTM, eitherUnit (fpRoundInt 0b011u) (neonTwoReg 0b10u 0b1101u)
    Opcode.VRINTR, fp2 0b0110u 0b01u
    Opcode.VRINTZ, eitherUnit (fp2 0b0110u 0b11u) (neonTwoReg 0b10u 0b1011u)
    Opcode.VRINTX, eitherUnit (fp2 0b0111u 0b01u) (neonTwoReg 0b10u 0b1001u)
    Opcode.VCMP, fpCompare 0u
    Opcode.VCMPE, fpCompare 1u
    Opcode.VCVT, convert
    Opcode.VCVTR, fpIntConvert 0u
    Opcode.VCVTB, fpHalfConvert 0u
    Opcode.VCVTT, fpHalfConvert 1u
    Opcode.VCVTA, directedConvert 0b00u
    Opcode.VCVTN, directedConvert 0b01u
    Opcode.VCVTP, directedConvert 0b10u
    Opcode.VCVTM, directedConvert 0b11u
    Opcode.VMOVX, fpHalfMove 0u
    Opcode.VINS, fpHalfMove 1u
    Opcode.VJCVT, fpJavaConvert
    Opcode.VLDR, fpLoadStore 1u
    Opcode.VSTR, fpLoadStore 0u
    Opcode.VLDMIA, fpBlockTransfer 0u 1u 1u
    Opcode.VLDMDB, fpBlockTransfer 1u 0u 1u
    Opcode.VSTMIA, fpBlockTransfer 0u 1u 0u
    Opcode.VSTMDB, fpBlockTransfer 1u 0u 0u
    Opcode.FLDMIAX, fpBlockTransferX 0u 1u 1u
    Opcode.FLDMDBX, fpBlockTransferX 1u 0u 1u
    Opcode.FSTMIAX, fpBlockTransferX 0u 1u 0u
    Opcode.FSTMDBX, fpBlockTransferX 1u 0u 0u ]

/// VQSHL, which shifts by an amount held in a register or written as one.
let private saturatingShift ins =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm _) ->
    neonShiftWith (unsignedBit ins) true false 0b0111u ins
  | _ ->
    neon3Reversed 0b0100u 1u ins

/// VMUL, which multiplies integers, polynomials or floating-point numbers, and
/// says which in its data type.
let private neonMultiply ins =
  match dataType ins with
  | SIMDTypP8 | SIMDTypP64 -> neon3 1u 0b1001u 1u ins
  | SIMDTypF16 | SIMDTypF32 -> neon3FloatDt 1u 0u 0b1101u ins
  | _ -> neon3 0u 0b1001u 1u ins

/// VMUL by one element of a register, whose F bit says the elements are
/// floating-point.
let private neonMultiplyScalar ins =
  match dataType ins with
  | SIMDTypF16 | SIMDTypF32 -> neonScalar true 0b1001u ins
  | _ -> neonScalar true 0b1000u ins

/// The multiplies that have a form by one element of a register as well as
/// one of three registers, which the last operand tells apart.
let private orByScalar byScalar threeRegisters ins =
  match ins.Operands with
  | ThreeOperands(_, _, OprSIMD(SFReg(Scalar _))) -> byScalar ins
  | _ -> threeRegisters ins

/// The shifts that name a register holding how far, or an immediate.
let private orShiftByImmediate byImmediate byRegister ins =
  match ins.Operands with
  | ThreeOperands(_, _, OprImm _) -> byImmediate ins
  | _ -> byRegister ins

/// The long multiplies by one element, which are always wide and so keep U
/// where the others keep Q.
let private neonScalarLong opcode ins =
  neonScalar false opcode ins ||| (unsignedBit ins <<< 24)

/// <summary>
/// VMULL, which multiplies integers or polynomials into elements twice as
/// wide, and says which in its data type.
///
/// The product of two doubleword polynomials is written with the size field
/// of words.
/// </summary>
let private neonMultiplyLong ins =
  match dataType ins with
  | SIMDTypP8 ->
    neon3Long 0u 0b1110u ins
  | SIMDTypP64 ->
    (neon3Long 0u 0b1110u ins &&& ~~~(0b11u <<< 20)) ||| (0b10u <<< 20)
  | _ ->
    orByScalar (neonScalarLong 0b1010u) (neon3LongSigned 0b1100u) ins

/// VSHLL, whose shift by the whole width of an element has an encoding of its
/// own among the operations on two registers, since the shift field cannot
/// hold that amount.
let private neonShiftLeftLong ins =
  match ins.Operands with
  | ThreeOperands(qd, dm, OprImm amount)
    when amount = (8L <<< int (elementSize ins)) ->
    let ins = { ins with Operands = TwoOperands(qd, dm) }
    neonTwoRegOp (elementSize ins) 0b10u 0b01100u ins
  | _ ->
    neonShiftWith (unsignedBit ins) true false 0b1010u ins

/// VMOVL, which is VSHLL by nothing: the shift field's top bit is what says how
/// wide an element is.
let private neonMoveLong ins =
  match ins.Operands with
  | TwoOperands(qd, dm) ->
    let ins = { ins with Operands = ThreeOperands(qd, dm, OprImm 0L) }
    neonShiftWith (unsignedBit ins) true false 0b1010u ins
  | _ ->
    wrongOperands ins

/// VMVN, of an immediate or of a register.
let private neonNot ins =
  match ins.Operands with
  | TwoOperands(_, OprImm _) -> neonImmediate false 1u ins
  | _ -> neonTwoRegSized 0u 0b00u 0b1011u ins

/// The rounding form of a narrowing shift, which is the plain one with bit 6
/// set.
let private rounding encode ins = encode ins ||| (1u <<< 6)

/// <summary>
/// The dot products, which multiply four bytes of each source and add the four
/// results into one word of the destination.
///
/// One of them reads the same word of its second source for every word of its
/// first, which is what naming an element rather than a register says.
/// </summary>
let private neonDotProduct u op size ins =
  let head =
    (0b11111100u <<< 24) ||| (op <<< 23) ||| (size <<< 20)
    ||| (0b1101u <<< 8) ||| (u <<< 4)
  let scalarHead = head ||| (1u <<< 25)
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector dd)),
                  OprSIMD(SFReg(Vector dn)),
                  OprSIMD(SFReg(Vector dm))) ->
    let q = if isQuadReg dd then 1u else 0u
    head ||| neonFields q dd dn dm
  | ThreeOperands(OprSIMD(SFReg(Vector dd)),
                  OprSIMD(SFReg(Vector dn)),
                  OprSIMD(SFReg(Scalar(dm, Some index)))) ->
    let q = if isQuadReg dd then 1u else 0u
    scalarHead ||| (q <<< 6) ||| vd dd ||| vn dn
    ||| (simdReg dm &&& 0xfu) ||| ((uint32 index &&& 1u) <<< 5)
  | _ ->
    wrongOperands ins

/// A source of a widening multiply, which is a single-precision register when
/// it writes a doubleword and a doubleword when it writes a quadword.
let private fusedLongSource doubleField singleField reg =
  if isSingleReg reg then singleField reg else doubleField reg

/// <summary>
/// The element a widening multiply reads, named by one bit above the register
/// number. A single-precision register keeps its lowest bit apart, in M, as
/// any does; a doubleword, read by the quadword form, fits in three bits and
/// leaves M for the index's top bit.
/// </summary>
let private fusedLongElement reg index =
  let number = simdReg reg
  if isSingleReg reg && number < 16u && index < 2u then
    ((index &&& 1u) <<< 3) ||| (number >>> 1) ||| ((number &&& 1u) <<< 5)
  elif not (isSingleReg reg) && number < 8u && index < 4u then
    ((index &&& 1u) <<< 3) ||| number ||| ((index >>> 1) <<< 5)
  else
    fail $"{Register.toString reg}[{index}] is not a scalar"

/// <summary>
/// The half-precision multiplies that accumulate into single-precision numbers,
/// which read half as much as they write.
/// </summary>
let private neonFusedLong op ins =
  (* Which of the pair this is sits above the registers when it reads a whole
     one, and below them when it reads one element of one. *)
  let head = (0b11111100u <<< 24) ||| (0b1000u <<< 8) ||| (1u <<< 4)
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector dd)),
                  OprSIMD(SFReg(Vector sourceN)),
                  OprSIMD(SFReg(Vector sourceM))) ->
    let q = if isQuadReg dd then 1u else 0u
    head ||| (op <<< 23) ||| (0b10u <<< 20) ||| (q <<< 6) ||| vd dd
    ||| fusedLongSource vn sn sourceN ||| fusedLongSource vm sm sourceM
  | ThreeOperands(OprSIMD(SFReg(Vector dd)),
                  OprSIMD(SFReg(Vector sourceN)),
                  OprSIMD(SFReg(Scalar(sourceM, Some index)))) ->
    let q = if isQuadReg dd then 1u else 0u
    head ||| (1u <<< 25) ||| (op <<< 20) ||| (q <<< 6) ||| vd dd
    ||| fusedLongSource vn sn sourceN
    ||| fusedLongElement sourceM (uint32 index)
  | _ ->
    wrongOperands ins

/// The rotation a complex operation names, in quarter turns.
let private quarterTurns (degrees: int64) =
  match degrees with
  | 0L | 90L | 180L | 270L -> uint32 (degrees / 90L)
  | _ -> fail $"#{degrees} is not a rotation by a multiple of ninety degrees"

/// The element VCMLA reads: a pair of halves among the two a doubleword holds,
/// named by M, or the one pair of singles there is, which leaves M to the
/// register number.
let private complexElement s reg index =
  let number = simdReg reg
  if s = 0u && number < 16u && index < 2u then number ||| (index <<< 5)
  elif s = 1u && index = 0u then vm reg
  else fail $"{Register.toString reg}[{index}] is not a scalar"

/// <summary>
/// VCMLA, which multiplies complex numbers held as pairs of elements and
/// accumulates, the second operand rotated by the multiple of ninety degrees it
/// names; S says the elements are singles rather than halves.
///
/// By one element, a pair of halves is named by four bits of register and M,
/// and a pair of singles, the whole doubleword, by five bits.
/// </summary>
let private complexMulAdd ins =
  let s = if dataType ins = SIMDTypF32 then 1u else 0u
  match ins.Operands with
  | FourOperands(OprSIMD(SFReg(Vector dd)),
                 OprSIMD(SFReg(Vector dn)),
                 OprSIMD(SFReg(Vector dm)),
                 OprImm rotation) ->
    let q = if isQuadReg dd then 1u else 0u
    unconditional ins ||| (0b110u <<< 25) ||| (quarterTurns rotation <<< 23)
    ||| (1u <<< 21) ||| (s <<< 20) ||| (0b1000u <<< 8) ||| neonFields q dd dn dm
  | FourOperands(OprSIMD(SFReg(Vector dd)),
                 OprSIMD(SFReg(Vector dn)),
                 OprSIMD(SFReg(Scalar(dm, Some index))),
                 OprImm rotation) ->
    let q = if isQuadReg dd then 1u else 0u
    unconditional ins ||| (0b1110u <<< 24) ||| (s <<< 23)
    ||| (quarterTurns rotation <<< 20) ||| (0b1000u <<< 8) ||| (q <<< 6)
    ||| vd dd ||| vn dn ||| complexElement s dm (uint32 index)
  | _ ->
    wrongOperands ins

/// VCADD, which adds complex numbers held as pairs of elements, the second
/// rotated by ninety degrees one way or the other; S says the elements are
/// singles.
let private complexAdd ins =
  let s = if dataType ins = SIMDTypF32 then 1u else 0u
  match ins.Operands with
  | FourOperands(OprSIMD(SFReg(Vector dd)),
                 OprSIMD(SFReg(Vector dn)),
                 OprSIMD(SFReg(Vector dm)),
                 OprImm rotation) ->
    let rot =
      match rotation with
      | 90L -> 0u
      | 270L -> 1u
      | _ -> fail $"#{rotation} is not a rotation VCADD makes"
    let q = if isQuadReg dd then 1u else 0u
    unconditional ins ||| (0b110u <<< 25) ||| (rot <<< 24) ||| (1u <<< 23)
    ||| (s <<< 20) ||| (0b1000u <<< 8) ||| neonFields q dd dn dm
  | _ ->
    wrongOperands ins

/// VFMAB and VFMAT, which multiply the even or the odd brain floating-point
/// elements and accumulate into singles; T says which. By one element, the
/// register fits in three bits and the index takes M and the bit above them.
let private bfloatMulAdd t ins =
  let head =
    unconditional ins ||| (0b1100u <<< 24) ||| (0b11u <<< 20)
    ||| (0b1000u <<< 8) ||| (t <<< 6) ||| (1u <<< 4)
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector qd)),
                  OprSIMD(SFReg(Vector qn)),
                  OprSIMD(SFReg(Vector qm))) ->
    head ||| vd qd ||| vn qn ||| vm qm
  | ThreeOperands(OprSIMD(SFReg(Vector qd)),
                  OprSIMD(SFReg(Vector qn)),
                  OprSIMD(SFReg(Scalar(dm, Some index)))) ->
    head ||| (1u <<< 25) ||| vd qd ||| vn qn
    ||| fusedLongElement dm (uint32 index)
  | _ ->
    wrongOperands ins

/// VUSDOT, which multiplies unsigned bytes by signed ones; by one element it
/// is written with the size field of bytes, and of three registers with that
/// of words.
let private mixedDotProduct ins =
  orByScalar (neonDotProduct 0u 1u 0b00u) (neonDotProduct 0u 1u 0b10u) ins

/// The matrix multiplies, which read two quadwords as matrices and accumulate
/// their product into a third; bits 23 and 21:20 and U say which kind of
/// elements they hold.
let private neonMatrixMultiply op size u ins =
  match ins.Operands with
  | ThreeOperands(OprSIMD(SFReg(Vector qd)),
                  OprSIMD(SFReg(Vector qn)),
                  OprSIMD(SFReg(Vector qm))) ->
    unconditional ins ||| (0b1100u <<< 24) ||| (op <<< 23) ||| (size <<< 20)
    ||| (0b1100u <<< 8) ||| (1u <<< 6) ||| (u <<< 4) ||| vd qd ||| vn qn
    ||| vm qm
  | _ ->
    wrongOperands ins

/// The reg field of a floating-point system register: VMRS reads any of these,
/// and VMSR writes FPSID, FPSCR and FPEXC alone (DDI0406C B9.3.21 and B9.3.22;
/// DDI0487F.c F6.1.144 adds MVFR2).
let private fpSystemReg l reg =
  match reg with
  | Register.FPSID -> 0b0000u
  | Register.FPSCR -> 0b0001u
  | Register.MVFR2 when l = 1u -> 0b0101u
  | Register.MVFR1 when l = 1u -> 0b0110u
  | Register.MVFR0 when l = 1u -> 0b0111u
  | Register.FPEXC -> 0b1000u
  | _ -> fail $"{Register.toString reg} is not a register this move reaches"

/// The Rt field of a VMRS: a core register, or APSR as 0b1111, which only
/// FPSCR's flags go to (DDI0406C A8.8.349).
let private vmrsTarget sreg rt =
  match rt with
  | Register.APSR when sreg = Register.FPSCR -> 0b1111u
  | _ -> coreReg rt

/// VMRS and VMSR, which move a floating-point system register to or from a
/// core register.
let private fpStatusMove l ins =
  let head = cond ins ||| (0b11101110u <<< 20) ||| (0b111u <<< 21)
  let fields sreg rt =
    head ||| (l <<< 20) ||| (fpSystemReg l sreg <<< 16) ||| (rt <<< 12)
    ||| (0b1010u <<< 8) ||| (1u <<< 4)
  match ins.Operands with
  | TwoOperands(OprReg rt, OprReg sreg) when l = 1u ->
    fields sreg (vmrsTarget sreg rt)
  | TwoOperands(OprReg sreg, OprReg rt) when l = 0u ->
    fields sreg (coreReg rt)
  | _ ->
    wrongOperands ins

/// The Advanced SIMD instructions that read and write whole registers.
let advancedSIMDEncoders () =
  let vmul = orByScalar neonMultiplyScalar neonMultiply
  let vcgt = byType (neon3FloatOp 1u 1u 0b1110u 0u) (neon3Signed 0b0011u 0u)
  let vcge = byType (neon3FloatOp 1u 0u 0b1110u 0u) (neon3Signed 0b0011u 1u)
  let vceq = byType (neon3FloatOp 0u 0u 0b1110u 0u) (neon3 1u 0b1000u 1u)
  let vpmax = byType (neon3FloatOp 1u 0u 0b1111u 0u) (neon3Signed 0b1010u 0u)
  let vpmin = byType (neon3FloatOp 1u 1u 0b1111u 0u) (neon3Signed 0b1010u 1u)
  let vmax = byType (neon3FloatOp 0u 0u 0b1111u 0u) (neon3Signed 0b0110u 0u)
  let vmin = byType (neon3FloatOp 0u 1u 0b1111u 0u) (neon3Signed 0b0110u 1u)
  let vabd = byType (neon3FloatOp 1u 1u 0b1101u 0u) (neon3Signed 0b0111u 0u)
  let shiftByImmediate = neonShiftWith 0u true false 0b0101u
  let vshl = orShiftByImmediate shiftByImmediate (neon3Reversed 0b0100u 0u)
  [ Opcode.VHADD, neon3Signed 0b0000u 0u
    Opcode.VQADD, neon3Signed 0b0000u 1u
    Opcode.VCGT, orZero 0b000u vcgt
    Opcode.VCGE, orZero 0b001u vcge
    Opcode.VCLE, orZero 0b011u wrongOperands
    Opcode.VCLT, orZero 0b100u wrongOperands
    Opcode.VQDMULH, orByScalar (neonScalar true 0b1100u) (neon3 0u 0b1011u 0u)
    Opcode.VPADD, byType (neon3FloatOp 1u 0u 0b1101u 0u) (neon3 0u 0b1011u 1u)
    Opcode.VQRDMULH, orByScalar (neonScalar true 0b1101u) (neon3 1u 0b1011u 0u)
    Opcode.VQRDMLAH, orByScalar (neonScalar true 0b1110u) (neon3 1u 0b1011u 1u)
    Opcode.VADDL, neon3LongSigned 0b0000u
    Opcode.VMLAL, orByScalar (neonScalarLong 0b0010u) (neon3LongSigned 0b1000u)
    Opcode.VMLSL, orByScalar (neonScalarLong 0b0110u) (neon3LongSigned 0b1010u)
    Opcode.VMULL, neonMultiplyLong
    Opcode.VQDMLSL, orByScalar (neonScalar false 0b0111u) (neon3Long 0u 0b1011u)
    Opcode.VSHR, neonShift 0b0000u
    Opcode.VSRA, neonShift 0b0001u
    Opcode.VRSHR, neonShift 0b0010u
    Opcode.VRSRA, neonShift 0b0011u
    Opcode.VSRI, neonShiftWith 1u false false 0b0100u
    Opcode.VSHL, vshl
    Opcode.VSLI, neonShiftWith 1u true false 0b0101u
    Opcode.VQSHLU, neonShiftWith 1u true false 0b0110u
    Opcode.VSHRN, neonShiftNarrow 0b1000u
    Opcode.VRSHRN, rounding (neonShiftNarrow 0b1000u)
    (* U says which of the two the opcode field stands for, and it is not the
       sign of the data type here: VQSHRUN reads signed elements and writes
       unsigned ones, so U is set while its type names a signed size. *)
    Opcode.VQSHRUN, neonShiftWith 1u false true 0b1000u
    Opcode.VQRSHRUN, rounding (neonShiftWith 1u false true 0b1000u)
    Opcode.VQSHRN, neonShiftNarrow 0b1001u
    Opcode.VQRSHRN, rounding (neonShiftNarrow 0b1001u)
    Opcode.VSHLL, neonShiftLeftLong
    Opcode.VMOVL, neonMoveLong
    Opcode.VMOV, vmov
    Opcode.VMVN, neonNot
    Opcode.VQDMLAL, orByScalar (neonScalar false 0b0011u) (neon3Long 0u 0b1001u)
    Opcode.VQDMULL, orByScalar (neonScalar false 0b1011u) (neon3Long 0u 0b1101u)
    Opcode.VEXT, neonExtract
    Opcode.VREV64, neonTwoReg 0b00u 0b0000u
    Opcode.VREV32, neonTwoReg 0b00u 0b0001u
    Opcode.VREV16, neonTwoReg 0b00u 0b0010u
    Opcode.VABS, absNeg 0b0110u 0b0000u 0b11u
    Opcode.VNEG, absNeg 0b0111u 0b0001u 0b01u
    Opcode.VTBL, neonTableLookup 0u
    Opcode.VTBX, neonTableLookup 1u
    Opcode.VAND, neon3With 0u 0b00u 0b0001u 1u
    Opcode.VBIC, neonBitwise 0u 0b01u (neonImmediate true 1u)
    Opcode.VORR, neonBitwise 0u 0b10u (neonImmediate true 0u)
    Opcode.VORN, neon3With 0u 0b11u 0b0001u 1u
    Opcode.VEOR, neon3With 1u 0b00u 0b0001u 1u
    Opcode.VBSL, neon3With 1u 0b01u 0b0001u 1u
    Opcode.VBIT, neon3With 1u 0b10u 0b0001u 1u
    Opcode.VBIF, neon3With 1u 0b11u 0b0001u 1u
    Opcode.VQSUB, neon3Signed 0b0010u 1u
    Opcode.VQSHL, saturatingShift
    Opcode.VQRSHL, neon3Reversed 0b0101u 1u
    Opcode.VMAX, vmax
    Opcode.VMIN, vmin
    Opcode.VABA, neon3Signed 0b0111u 1u
    Opcode.VTST, neon3 0u 0b1000u 1u
    Opcode.VCEQ, orZero 0b010u vceq
    Opcode.VMUL, eitherUnit (fp3 0b010u 0u) vmul
    Opcode.VPMAX, vpmax
    Opcode.VPMIN, vpmin
    Opcode.VQRDMLSH, orByScalar (neonScalar true 0b1111u) (neon3 1u 0b1100u 1u)
    Opcode.VACGE, neon3FloatDt 1u 0u 0b1110u
    Opcode.VACGT, neon3FloatDt 1u 1u 0b1110u
    Opcode.VRECPS, neon3FloatDt 0u 0u 0b1111u
    Opcode.VRSQRTS, neon3FloatDt 0u 1u 0b1111u
    Opcode.VUDOT, neonDotProduct 1u 0u 0b10u
    Opcode.VSDOT, neonDotProduct 0u 0u 0b10u
    Opcode.VSUDOT, neonDotProduct 1u 1u 0b00u
    Opcode.VFMAL, neonFusedLong 0u
    Opcode.VFMSL, neonFusedLong 1u
    Opcode.VMRS, fpStatusMove 1u
    Opcode.VMSR, fpStatusMove 0u
    Opcode.VDUP, neonDuplicate
    Opcode.VLD1, structureAccess 1u
    Opcode.VLD2, structureAccess 1u
    Opcode.VLD3, structureAccess 1u
    Opcode.VLD4, structureAccess 1u
    Opcode.VST1, structureAccess 0u
    Opcode.VST2, structureAccess 0u
    Opcode.VST3, structureAccess 0u
    Opcode.VST4, structureAccess 0u
    Opcode.VRHADD, neon3Signed 0b0001u 0u
    Opcode.VHSUB, neon3Signed 0b0010u 0u
    Opcode.VRSHL, neon3Reversed 0b0101u 0u
    Opcode.VABD, vabd
    Opcode.VADDW, neon3LongSigned 0b0001u
    Opcode.VSUBL, neon3LongSigned 0b0010u
    Opcode.VSUBW, neon3LongSigned 0b0011u
    Opcode.VABAL, neon3LongSigned 0b0101u
    Opcode.VABDL, neon3LongSigned 0b0111u
    Opcode.VADDHN, neon3Narrow 0u 0b0100u
    Opcode.VRADDHN, neon3Narrow 1u 0b0100u
    Opcode.VSUBHN, neon3Narrow 0u 0b0110u
    Opcode.VRSUBHN, neon3Narrow 1u 0b0110u
    Opcode.VPADDL, pairwiseLong 0b0100u
    Opcode.VPADAL, pairwiseLong 0b1100u
    Opcode.VCLS, neonTwoReg 0b00u 0b1000u
    Opcode.VCLZ, neonTwoReg 0b00u 0b1001u
    Opcode.VCNT, neonTwoReg 0b00u 0b1010u
    Opcode.VQABS, neonTwoReg 0b00u 0b1110u
    Opcode.VQNEG, neonTwoReg 0b00u 0b1111u
    Opcode.AESE, neonCrypto2 0b00u 0b01100u
    Opcode.AESD, neonCrypto2 0b00u 0b01101u
    Opcode.AESMC, neonCrypto2 0b00u 0b01110u
    Opcode.AESIMC, neonCrypto2 0b00u 0b01111u
    Opcode.SHA1H, neonCrypto2 0b01u 0b01011u
    Opcode.SHA1SU1, neonCrypto2 0b10u 0b01110u
    Opcode.SHA256SU0, neonCrypto2 0b10u 0b01111u
    Opcode.SHA1C, neon3With 0u 0b00u 0b1100u 0u
    Opcode.SHA1P, neon3With 0u 0b01u 0b1100u 0u
    Opcode.SHA1M, neon3With 0u 0b10u 0b1100u 0u
    Opcode.SHA1SU0, neon3With 0u 0b11u 0b1100u 0u
    Opcode.SHA256H, neon3With 1u 0b00u 0b1100u 0u
    Opcode.SHA256H2, neon3With 1u 0b01u 0b1100u 0u
    Opcode.SHA256SU1, neon3With 1u 0b10u 0b1100u 0u
    Opcode.VSWP, neonTwoRegSized 0b00u 0b10u 0b0000u
    Opcode.VTRN, neonTwoReg 0b10u 0b0001u
    Opcode.VUZP, neonTwoReg 0b10u 0b0010u
    Opcode.VZIP, neonTwoReg 0b10u 0b0011u
    Opcode.VMOVN, neonMoveNarrow 0b00u
    Opcode.VQMOVUN, neonMoveNarrow 0b01u
    Opcode.VQMOVN, saturatingMoveNarrow
    Opcode.VRECPE, neonEstimate 0u
    Opcode.VRSQRTE, neonEstimate 1u
    Opcode.VCMLA, complexMulAdd
    Opcode.VCADD, complexAdd
    Opcode.VFMAB, bfloatMulAdd 0u
    Opcode.VFMAT, bfloatMulAdd 1u
    Opcode.VDOT, neonDotProduct 0u 0u 0b00u
    Opcode.VUSDOT, mixedDotProduct
    Opcode.VMMLA, neonMatrixMultiply 0u 0b00u 0u
    Opcode.VSMMLA, neonMatrixMultiply 0u 0b10u 0u
    Opcode.VUMMLA, neonMatrixMultiply 0u 0b10u 1u
    Opcode.VUSMMLA, neonMatrixMultiply 1u 0b10u 0u ]

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
/// Encodes one instruction into the Thumb halfword or halfwords that mean it.
///
/// T32 says most of what A32 says, but says almost none of it the same way, so
/// these are their own encoders rather than the A32 ones with a different head.
/// What they do share is the shape of an instruction as the source wrote it.
/// </summary>
module internal B2R2.Assembly.ARM32.AsmThumb

open B2R2.FrontEnd.ARM32
open B2R2.Assembly.ARM32.ParserHelper
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.ARM32.AsmField
open B2R2.Assembly.ARM32.AsmOpcode

/// One halfword, which is what the narrow encodings amount to.
let private narrow (value: uint32) = Narrow(uint16 value)

/// A register one of the narrow encodings names, which only reaches the first
/// eight.
let private lowReg reg =
  let number = coreReg reg
  if number < 8u then number
  else fail $"{Register.toString reg} cannot be named by a narrow encoding"

/// A narrow instruction takes no condition of its own. What the source wrote
/// on one was checked against the block it sits in and taken off before it got
/// here, so anything left is a condition that belongs nowhere.
let private noCondition (ins: AsmInsInfo) =
  match ins.Condition with
  | None | Some Condition.AL | Some Condition.UN -> ()
  | Some _ -> fail $"{ins.Opcode} takes no condition of its own"

/// <summary>
/// The shifts, which the manual defines as narrow encodings of their own rather
/// than as aliases of a move.
///
/// A shift right by nothing shares its bits with a shift by the width of the
/// register, so the amounts each one accepts differ.
/// </summary>
let private shiftImmediate opcode ins =
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprReg rm, OprImm amount) ->
    let amount =
      match opcode, amount with
      | 0b00u, amount when amount >= 0L && amount < 32L -> uint32 amount
      | (0b01u | 0b10u), amount when amount >= 1L && amount <= 32L ->
        uint32 amount % 32u
      | _ -> fail $"#{amount} is not a shift of that kind"
    noCondition ins
    narrow ((opcode <<< 11) ||| (amount <<< 6) ||| (lowReg rm <<< 3)
            ||| lowReg rd)
  | _ -> wrongOperands ins

/// The additions and subtractions of three registers, or of two and a small
/// immediate.
let private addSubtract op ins =
  let head = 0b000110u <<< 10
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprReg rn, OprReg rm) ->
    noCondition ins
    narrow (head ||| (op <<< 9) ||| (lowReg rm <<< 6) ||| (lowReg rn <<< 3)
            ||| lowReg rd)
  | ThreeOperands(OprReg rd, OprReg rn, OprImm imm) ->
    noCondition ins
    narrow (head ||| (1u <<< 10) ||| (op <<< 9) ||| (unsignedImm 3 imm <<< 6)
            ||| (lowReg rn <<< 3) ||| lowReg rd)
  | _ -> wrongOperands ins

/// The operations on one register and an eight-bit immediate, which is the
/// widest immediate a narrow encoding holds.
let private immediate8 op ins =
  match ins.Operands with
  | TwoOperands(OprReg rdn, OprImm imm) ->
    noCondition ins
    narrow ((0b001u <<< 13) ||| (op <<< 11) ||| (lowReg rdn <<< 8)
            ||| unsignedImm 8 imm)
  | _ -> wrongOperands ins

/// The data-processing operations, which read and write the same register and
/// so name it once in the encoding however many times the source writes it.
let private dataProcWord op rdn rm =
  (0b010000u <<< 10) ||| (op <<< 6) ||| (lowReg rm <<< 3) ||| lowReg rdn

let private dataProc op ins =
  let encode rdn rm =
    noCondition ins
    narrow (dataProcWord op rdn rm)
  match ins.Operands with
  | TwoOperands(OprReg rdn, OprReg rm) -> encode rdn rm
  | ThreeOperands(OprReg rd, OprReg rn, OprReg rm) when rd = rn -> encode rd rm
  | ThreeOperands(OprReg rd, OprReg rn, OprImm 0L) -> encode rd rn
  | _ -> wrongOperands ins

/// MULS, which names the register it reads and writes on either side of the one
/// it only reads.
let private multiply ins =
  match ins.Operands with
  | ThreeOperands(OprReg rdm, OprReg rn, OprReg rdm2) when rdm = rdm2 ->
    noCondition ins
    narrow ((0b0100001101u <<< 6) ||| (lowReg rn <<< 3) ||| lowReg rdm)
  | _ -> wrongOperands ins

/// The operations that may name any register rather than only the first eight,
/// which they do by keeping the top bit of each register apart.
let private specialDataWord op rdn rm =
  let rdn, rm = coreReg rdn, coreReg rm
  (0b010001u <<< 10) ||| (op <<< 8) ||| ((rdn >>> 3) <<< 7) ||| (rm <<< 3)
  ||| (rdn &&& 0b111u)

let private specialData op ins =
  let encode rdn rm =
    noCondition ins
    narrow (specialDataWord op rdn rm)
  match ins.Operands with
  | TwoOperands(OprReg rdn, OprReg rm) -> encode rdn rm
  | ThreeOperands(OprReg rd, OprReg rn, OprReg rm) when rd = rn -> encode rd rm
  | _ -> wrongOperands ins

/// BX and BLX, which branch to an address a register holds and may change
/// instruction set on the way.
let private branchExchange link ins =
  match ins.Operands with
  | OneOperand(OprReg rm) ->
    noCondition ins
    narrow ((0b010001110u <<< 7) ||| (link <<< 7) ||| (coreReg rm <<< 3))
  | _ -> wrongOperands ins

/// The offset of a literal an instruction reads, which counts in words from the
/// program counter and so is always positive here.
let private literalOffset ins (offset: int64) =
  if offset < 0L || offset % 4L <> 0L then
    fail $"{ins.Opcode} cannot reach that literal"
  else
    unsignedImm 8 (offset / 4L)

/// The loads and stores whose offset is held in a register.
let private loadStoreReg op ins =
  match ins.Operands with
  | TwoOperands(OprReg rt,
                OprMemory(OffsetMode(RegOffset(rn, _, rm, None)))) ->
    noCondition ins
    narrow ((0b0101u <<< 12) ||| (op <<< 9) ||| (lowReg rm <<< 6)
            ||| (lowReg rn <<< 3) ||| lowReg rt)
  | _ -> wrongOperands ins

/// <summary>
/// The loads and stores whose offset is an immediate, which counts in whatever
/// the instruction transfers rather than in bytes.
///
/// The same mnemonic reads a literal or the stack when it names the program
/// counter or the stack pointer, and those keep the offset somewhere else, so
/// they are encoded here too.
/// </summary>
let private loadStoreImm head scale l ins =
  match ins.Operands with
  | TwoOperands(OprReg rt, OprMemory(LiteralMode offset)) when l = 1u ->
    noCondition ins
    narrow ((0b01001u <<< 11) ||| (lowReg rt <<< 8)
            ||| literalOffset ins offset)
  | TwoOperands(OprReg rt,
                OprMemory(OffsetMode(ImmOffset(Register.SP, _, imm))))
    when scale = 4u ->
    let imm = defaultArg imm 0L
    if imm % 4L <> 0L then fail "a stack offset counts in words"
    else
      noCondition ins
      narrow ((0b1001u <<< 12) ||| (l <<< 11) ||| (lowReg rt <<< 8)
              ||| unsignedImm 8 (imm / 4L))
  | TwoOperands(OprReg rt, OprMemory(OffsetMode(ImmOffset(rn, _, imm)))) ->
    let imm = defaultArg imm 0L
    if imm % int64 scale <> 0L then
      fail $"an offset of {scale} bytes at a time cannot be #{imm}"
    else
      noCondition ins
      narrow (head ||| (l <<< 11)
              ||| (unsignedImm 5 (imm / int64 scale) <<< 6)
              ||| (lowReg rn <<< 3) ||| lowReg rt)
  | _ -> wrongOperands ins

/// ADR, which names a place rather than a value, and the addition to the stack
/// pointer beside it, which the manual encodes the same way.
let private addressOrStack op ins =
  match ins.Operands with
  | TwoOperands(OprReg rd, OprMemory(LiteralMode offset)) when op = 0u ->
    noCondition ins
    narrow ((0b10100u <<< 11) ||| (lowReg rd <<< 8)
            ||| literalOffset ins offset)
  | ThreeOperands(OprReg rd, OprReg Register.SP, OprImm imm) when op = 1u ->
    if imm % 4L <> 0L then fail "a stack offset counts in words"
    else
      noCondition ins
      narrow ((0b10101u <<< 11) ||| (lowReg rd <<< 8)
              ||| unsignedImm 8 (imm / 4L))
  | _ -> wrongOperands ins

/// The additions and subtractions that move the stack pointer itself, whose
/// immediate counts in words and has seven bits of its own.
let private adjustStack op ins =
  match ins.Operands with
  | ThreeOperands(OprReg Register.SP, OprReg Register.SP, OprImm imm) ->
    if imm % 4L <> 0L then fail "a stack adjustment counts in words"
    else
      noCondition ins
      narrow ((0b101100000u <<< 7) ||| (op <<< 7) ||| unsignedImm 7 (imm / 4L))
  | _ -> wrongOperands ins

/// CBZ and CBNZ, which branch on a register being zero without reading the
/// flags, and can only reach forwards.
let private compareBranch op ins =
  match ins.Operands with
  | TwoOperands(OprReg rn, OprMemory(LiteralMode offset)) ->
    if offset < 0L || offset > 126L || offset % 2L <> 0L then
      fail $"{ins.Opcode} cannot reach that far"
    else
      let imm = uint32 (offset / 2L)
      noCondition ins
      narrow ((0b1011u <<< 12) ||| (op <<< 11) ||| (1u <<< 8)
              ||| ((imm >>> 5) <<< 9) ||| ((imm &&& 0x1fu) <<< 3) ||| lowReg rn)
  | _ -> wrongOperands ins

/// The sign- and zero-extending moves, and the byte-reversing ones, which
/// share a shape and differ in the two bits above their registers.
let private twoRegister head op ins =
  match ins.Operands with
  | TwoOperands(OprReg rd, OprReg rm) ->
    noCondition ins
    narrow (head ||| (op <<< 6) ||| (lowReg rm <<< 3) ||| lowReg rd)
  | _ -> wrongOperands ins

/// PUSH and POP, whose register list reaches the first eight registers and one
/// more: the link register when pushing and the program counter when popping.
let private stack extra l ins =
  match ins.Operands with
  | OneOperand(OprRegList regs) ->
    let bits = regList regs
    let allowed = 0xffu ||| (1u <<< int (coreReg extra))
    if bits &&& ~~~allowed <> 0u then
      fail $"{ins.Opcode} cannot name that register"
    else
      noCondition ins
      narrow ((0b1011u <<< 12) ||| (l <<< 11) ||| (0b10u <<< 9)
              ||| (((bits >>> int (coreReg extra)) &&& 1u) <<< 8)
              ||| (bits &&& 0xffu))
  | _ -> wrongOperands ins

/// The transfers of several registers at once, which always step the base
/// register on a store and step it on a load unless the load reads it back.
let private blockTransfer l ins =
  match ins.Operands with
  | TwoOperands(OprReg rn, OprRegList regs) ->
    let bits = regList regs
    if bits > 0xffu then fail $"{ins.Opcode} cannot name that register"
    else
      noCondition ins
      narrow ((0b1100u <<< 12) ||| (l <<< 11) ||| (lowReg rn <<< 8) ||| bits)
  | _ -> wrongOperands ins

/// The conditional branch, whose condition the mnemonic carries rather than a
/// field of its own, and which reaches half as far as the unconditional one.
let private conditionalBranch ins =
  match ins.Operands, ins.Condition with
  | OneOperand(OprMemory(LiteralMode offset)), Some cond ->
    if offset % 2L <> 0L then fail "a branch reaches halfwords"
    else
      narrow ((0b1101u <<< 12) ||| (condField cond <<< 8)
              ||| signedImm 8 (offset / 2L))
  | OneOperand(OprMemory(LiteralMode offset)), None ->
    if offset % 2L <> 0L then fail "a branch reaches halfwords"
    else narrow ((0b11100u <<< 11) ||| signedImm 11 (offset / 2L))
  | _ -> wrongOperands ins

/// The instructions that name nothing but a number, which whatever reads them
/// makes sense of.
let private serviceCall head width ins =
  match ins.Operands with
  | OneOperand(OprImm imm) ->
    noCondition ins
    narrow (head ||| unsignedImm width imm)
  | _ -> wrongOperands ins

/// The hints, which do nothing a program can see and are told apart by the four
/// bits above the ones an IT block would use.
let private hint value ins =
  match ins.Operands with
  | NoOperand ->
    noCondition ins
    narrow ((0b10111111u <<< 8) ||| (value <<< 4))
  | _ -> wrongOperands ins

/// <summary>
/// IT, which says what the condition of the instructions after it is.
///
/// How many follow is written into the mnemonic as one letter each, and the
/// mask holds those letters as bits: one for a following instruction that runs
/// under the same condition and zero for one that runs under its opposite,
/// ended by a one below them.
/// </summary>
let private ifThen letters ins =
  match ins.Operands with
  | NoOperand | OneOperand(OprCond Condition.AL) ->
    (* The disassembler prints nothing for the condition that always holds, so
       an IT block written under it names no condition at all. *)
    noCondition ins
    narrow ((0b10111111u <<< 8) ||| (0b1110u <<< 4)
            ||| ((1u <<< (3 - String.length letters)) &&& 0xfu))
  | OneOperand(OprCond cond) ->
    let cond = condField cond
    let bit letter = if letter = 't' then cond &&& 1u else ~~~cond &&& 1u
    (* Each letter puts one bit above the one that ends the mask, and what is
       left below it is what says how many instructions the block holds. *)
    let mask = letters |> Seq.fold (fun mask l -> (mask <<< 1) ||| bit l) 0u
    let mask = ((mask <<< 1) ||| 1u) <<< (3 - String.length letters)
    noCondition ins
    narrow ((0b10111111u <<< 8) ||| (cond <<< 4) ||| (mask &&& 0xfu))
  | _ -> wrongOperands ins

/// CPS, which turns the interrupts its operand names on or off.
let private changeState disable ins =
  match ins.Operands with
  | OneOperand(OprIflag flags) ->
    let bits =
      match flags with
      | A -> 0b100u
      | I -> 0b010u
      | F -> 0b001u
      | AI -> 0b110u
      | AF -> 0b101u
      | IF -> 0b011u
      | AIF -> 0b111u
    noCondition ins
    narrow ((0b10110110011u <<< 5) ||| (disable <<< 4) ||| bits)
  | _ -> wrongOperands ins

/// SETEND, which chooses the endianness the loads and stores that follow read.
let private setEndian ins =
  match ins.Operands with
  | OneOperand(OprEndian endian) ->
    let e = if endian = B2R2.Endian.Big then 1u else 0u
    noCondition ins
    narrow ((0b101101100100u <<< 4) ||| (e <<< 3))
  | _ -> wrongOperands ins

/// SETPAN, whose one bit of immediate says whether privileged access to user
/// memory is turned off.
let private setPan ins =
  match ins.Operands with
  | OneOperand(OprImm imm) ->
    noCondition ins
    narrow ((0b1011011000000u <<< 3) ||| (unsignedImm 1 imm <<< 3))
  | _ -> wrongOperands ins

/// MOVS, which moves an immediate, a register, or a register shifted by
/// another. What the operands name is what says which of those it is.
let private moveShifted ins =
  match ins.Operands with
  | TwoOperands(OprReg _, OprImm _) -> immediate8 0b00u ins
  | TwoOperands(OprReg rd, OprReg rm) ->
    noCondition ins
    narrow ((lowReg rm <<< 3) ||| lowReg rd)
  | ThreeOperands(OprReg rd, OprReg rm, OprRegShift(shift, rs)) when rd = rm ->
    let op =
      match shift with
      | ShiftOp.LSL -> 0b0010u
      | ShiftOp.LSR -> 0b0011u
      | ShiftOp.ASR -> 0b0100u
      | ShiftOp.ROR -> 0b0111u
      | ShiftOp.RRX -> fail "a narrow move cannot rotate through carry"
    noCondition ins
    narrow (dataProcWord op rd rs)
  | _ -> wrongOperands ins

/// CMP, which reads an immediate or a register, and which of the two encodings
/// that read a register is used depends on whether either is a high one.
let private compare ins =
  match ins.Operands with
  | TwoOperands(OprReg _, OprImm _) -> immediate8 0b01u ins
  | TwoOperands(OprReg rn, OprReg rm) when coreReg rn < 8u && coreReg rm < 8u ->
    dataProc 0b1010u ins
  | TwoOperands(OprReg _, OprReg _) -> specialData 0b01u ins
  | _ -> wrongOperands ins

/// ADD, which reaches any register, the stack pointer, or a place.
let private add ins =
  match ins.Operands with
  | ThreeOperands(OprReg Register.SP, OprReg Register.SP, OprImm _) ->
    adjustStack 0u ins
  | ThreeOperands(OprReg _, OprReg Register.SP, OprImm _) ->
    addressOrStack 1u ins
  | ThreeOperands(OprReg Register.SP, OprReg Register.SP, OprReg rm) ->
    noCondition ins
    narrow (specialDataWord 0b00u Register.SP rm)
  | ThreeOperands(OprReg rd, OprReg Register.SP, OprReg rm) when rd = rm ->
    noCondition ins
    narrow (specialDataWord 0b00u rd Register.SP)
  | TwoOperands(OprReg _, OprReg _) -> specialData 0b00u ins
  | _ -> wrongOperands ins

/// ADDS and SUBS, which read a register or one of two widths of immediate.
let private addSubtractOrImmediate op ins =
  match ins.Operands with
  | TwoOperands(OprReg _, OprImm _) -> immediate8 (0b10u ||| op) ins
  | _ -> addSubtract op ins

/// SUB, which narrow encodings only use to move the stack pointer.
let private subtract ins = adjustStack 1u ins

/// The loads and stores, whose offset is either a register or an immediate.
let private loadStore head scale l regOp ins =
  match ins.Operands with
  | TwoOperands(_, OprMemory(OffsetMode(RegOffset _))) ->
    loadStoreReg regOp ins
  | _ -> loadStoreImm head scale l ins

(* The wide encodings, which are two halfwords. *)
/// Two halfwords from the word they spell, which is how the wide encodings are
/// laid out either way: the first halfword is the one that comes first.
let private wide (word: uint32) = Wide(uint16 (word >>> 16), uint16 word)

/// <summary>
/// The Thumb encoding of an instruction that both instruction sets spell the
/// same way.
///
/// The SIMD, floating-point and coprocessor spaces hold the same fields in the
/// same bits in T32 as in A32, and differ only in what sits above them: where
/// A32 keeps a condition these never use, T32 keeps the bits that mark a wide
/// encoding.
/// </summary>
let private asThumbWord (word: uint32) =
  if word >>> 28 <> 0xfu then word
  elif (word >>> 25) &&& 0b111u = 0b001u then
    (0b111u <<< 29) ||| (((word >>> 24) &&& 1u) <<< 28) ||| (0xfu <<< 24)
    ||| (word &&& 0xffffffu)
  elif (word >>> 24) &&& 0xfu = 0b0100u then
    (0xf9u <<< 24) ||| (word &&& 0xffffffu)
  else
    word

/// Borrows an A32 encoder for one of the spaces the two instruction sets spell
/// alike.
let private shared encode ins = wide (asThumbWord (encode ins))

/// <summary>
/// The twelve bits that stand for a wide data-processing immediate, which hold
/// either a byte repeated through the word in one of four ways or a byte with
/// its top bit set, rotated.
///
/// The manual gives the expansion rather than its inverse, so this works back
/// from the value: which of the two kinds it is is what the value itself says.
/// </summary>
let private thumbModifiedImm (value: int64) =
  let value = uint32 value
  let byte0 = value &&& 0xffu
  let repeated = (byte0 <<< 16) ||| byte0
  let rotations =
    [ 8 .. 31 ]
    |> List.tryFind (fun r ->
      let rotated = (value <<< r) ||| (value >>> (32 - r))
      rotated >= 0x80u && rotated < 0x100u)
  if value < 0x100u then value
  elif value = repeated then 0x100u ||| byte0
  elif value = (repeated <<< 8) then 0x200u ||| ((value >>> 8) &&& 0xffu)
  elif value = (repeated ||| (repeated <<< 8)) then 0x300u ||| byte0
  else
    match rotations with
    | Some r ->
      let rotated = (value <<< r) ||| (value >>> (32 - r))
      (uint32 r <<< 7) ||| (rotated &&& 0x7fu)
    | None -> fail $"#{value} is not a wide Thumb immediate"

/// The three fields a wide immediate is split across: one bit in the first
/// halfword and the rest in the second.
let private splitImm12 (imm12: uint32) =
  ((imm12 >>> 11) <<< 26) ||| (((imm12 >>> 8) &&& 0b111u) <<< 12)
  ||| (imm12 &&& 0xffu)

/// The shift a wide data-processing operand may carry, split the same way.
let private wideShift shift =
  let bits imm5 typ =
    ((imm5 >>> 2) <<< 12) ||| ((imm5 &&& 0b11u) <<< 6) ||| (typ <<< 4)
  match shift with
  | ShiftOp.LSL, Imm 0u -> 0u
  | ShiftOp.LSL, Imm amount when amount < 32u -> bits amount 0u
  | ShiftOp.LSR, Imm amount when amount >= 1u && amount <= 32u ->
    bits (amount % 32u) 1u
  | ShiftOp.ASR, Imm amount when amount >= 1u && amount <= 32u ->
    bits (amount % 32u) 2u
  | ShiftOp.ROR, Imm amount when amount >= 1u && amount < 32u ->
    bits amount 3u
  | ShiftOp.RRX, _ -> bits 0u 3u
  | shift, Imm amount -> fail $"{shift} by #{amount} is not encodable"

/// The bits every wide data-processing instruction shares, whichever kind its
/// second operand is.
let private wideDataHead head op s rn =
  head ||| (op <<< 21) ||| (s <<< 20) ||| (coreReg rn <<< 16)

/// The wide data-processing instructions, which read either an immediate or a
/// register that may be shifted.
let private wideData op s ins =
  let immediate rn rd imm =
    wide (wideDataHead (0b11110u <<< 27) op s rn ||| (coreReg rd <<< 8)
          ||| splitImm12 (thumbModifiedImm imm))
  let register rn rd rm shift =
    wide (wideDataHead (0b11101010u <<< 24) op s rn ||| (coreReg rd <<< 8)
          ||| wideShift shift ||| coreReg rm)
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprReg rn, OprImm imm) -> immediate rn rd imm
  | ThreeOperands(OprReg rd, OprReg rn, OprReg rm) ->
    register rn rd rm (ShiftOp.LSL, Imm 0u)
  | FourOperands(OprReg rd, OprReg rn, OprReg rm, OprShift shift) ->
    register rn rd rm shift
  | _ -> wrongOperands ins

/// The wide comparisons, which set the flags and name no destination.
let private wideCompare op ins =
  let head = wideDataHead
  match ins.Operands with
  | TwoOperands(OprReg rn, OprImm imm) ->
    wide (head (0b11110u <<< 27) op 1u rn ||| (0xfu <<< 8)
          ||| splitImm12 (thumbModifiedImm imm))
  | TwoOperands(OprReg rn, OprReg rm) ->
    wide (head (0b11101010u <<< 24) op 1u rn ||| (0xfu <<< 8) ||| coreReg rm)
  | ThreeOperands(OprReg rn, OprReg rm, OprShift shift) ->
    wide (head (0b11101010u <<< 24) op 1u rn ||| (0xfu <<< 8)
          ||| wideShift shift ||| coreReg rm)
  | _ -> wrongOperands ins

/// ADDW, SUBW, MOVW and MOVT, whose immediate is written as it stands rather
/// than built out of a byte.
let private widePlainImm opcode ins =
  let head = (0b11110u <<< 27) ||| (1u <<< 25) ||| (opcode <<< 20)
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprReg rn, OprImm imm) ->
    wide (head ||| (coreReg rn <<< 16) ||| (coreReg rd <<< 8)
          ||| splitImm12 (unsignedImm 12 imm))
  | TwoOperands(OprReg rd, OprImm imm) ->
    let imm16 = unsignedImm 16 imm
    wide (head ||| ((imm16 >>> 12) <<< 16) ||| (coreReg rd <<< 8)
          ||| splitImm12 (imm16 &&& 0xfffu))
  | _ -> wrongOperands ins

/// The saturating moves and the bitfield instructions, which share a space and
/// hold what they act on in the bits below the destination.
let private wideBitfield opcode bias ins =
  let head field opcode =
    (0b11110u <<< 27) ||| (1u <<< 25) ||| (opcode <<< 20) ||| (field <<< 16)
  match ins.Operands with
  | ThreeOperands(OprReg rd, OprImm satImm, OprReg rn) ->
    wide (head (coreReg rn) opcode ||| (coreReg rd <<< 8)
          ||| unsignedImm 5 (satImm - bias))
  | FourOperands(OprReg rd, OprImm satImm, OprReg rn,
                 OprShift(shift, Imm amount)) ->
    (* Which way the value is shifted is a bit of the opcode here rather than a
       field of its own, and the one below it is the amount. *)
    let opcode =
      match shift with
      | ShiftOp.LSL -> opcode
      | ShiftOp.ASR -> opcode ||| 0b10u
      | _ -> fail $"{ins.Opcode} shifts left or right and no other way"
    wide (head (coreReg rn) opcode ||| (coreReg rd <<< 8)
          ||| wideShift (ShiftOp.LSL, Imm amount)
          ||| unsignedImm 5 (satImm - bias))
  | _ -> wrongOperands ins

/// SBFX and UBFX, which read a field and say how wide it is, and BFI and BFC,
/// which write one and say where it ends.
let private wideExtract opcode ins =
  let head = (0b11110u <<< 27) ||| (1u <<< 25) ||| (opcode <<< 20)
  let fields rd (lsb: int64) =
    (coreReg rd <<< 8) ||| (((uint32 lsb >>> 2) &&& 0b111u) <<< 12)
    ||| ((uint32 lsb &&& 0b11u) <<< 6)
  match ins.Operands with
  | FourOperands(OprReg rd, OprReg rn, OprImm lsb, OprImm width) ->
    let last =
      if opcode = 0b10110u then endOfBitfield lsb width
      else unsignedImm 5 (width - 1L)
    wide (head ||| (coreReg rn <<< 16) ||| fields rd lsb ||| last)
  | ThreeOperands(OprReg rd, OprImm lsb, OprImm width) ->
    wide (head ||| (0xfu <<< 16) ||| fields rd lsb
          ||| endOfBitfield lsb width)
  | _ -> wrongOperands ins

/// The two halfwords of a wide encoding, written as the fields of each rather
/// than as one number.
let private wideWord (hw1: uint32) (hw2: uint32) = wide ((hw1 <<< 16) ||| hw2)

/// <summary>
/// The P and W bits a wide access sets. A post-indexed access writes its base
/// back, and T32 says so with the bit that means writeback rather than leaving
/// it to be understood, as A32 does.
/// </summary>
let private thumbIndexBits = function
  | OffsetMode offset -> Some(1u, 0u, offset)
  | PreIdxMode offset -> Some(1u, 1u, offset)
  | PostIdxMode offset -> Some(0u, 1u, offset)
  | UnIdxMode _ | LiteralMode _ -> None

/// <summary>
/// Where a wide load or store reads. Four ways of naming a place share the
/// encoding: an offset of twelve bits, one of eight with the bits that say when
/// the base is updated, one that reads as though the processor were in user
/// mode, and a register that may be shifted left a little.
/// </summary>
let private wideMemory ins rt mode =
  let hw2 rest = (coreReg rt <<< 12) ||| rest
  match mode, thumbIndexBits mode with
  | _, Some(p, w, ImmOffset(rn, sign, imm)) ->
    let u, value = signedOffset sign (defaultArg imm 0L)
    if p = 1u && w = 0u && u = 1u && value < 0x1000L then
      (1u <<< 7) ||| coreReg rn, hw2 (unsignedImm 12 value)
    else
      coreReg rn,
      hw2 ((1u <<< 11) ||| (p <<< 10) ||| (u <<< 9) ||| (w <<< 8)
           ||| unsignedImm 8 value)
  | _, Some(1u, 0u, RegOffset(rn, _, rm, shift)) ->
    let amount =
      match defaultArg shift (ShiftOp.LSL, Imm 0u) with
      | ShiftOp.LSL, Imm amount when amount < 4u -> amount
      | _ -> fail "a wide load shifts its index left by three at most"
    coreReg rn, hw2 ((amount <<< 4) ||| coreReg rm)
  | LiteralMode offset, _ ->
    let u, value = signedOffset None offset
    (u <<< 7) ||| 0xfu, hw2 (unsignedImm 12 value)
  | _ -> wrongOperands ins

/// The wide loads and stores, which reach any register and every way of naming
/// a place. What they transfer is two bits, and whether they extend its sign is
/// one more.
let private wideLoadStore signed size l ins =
  let head = (0b11111u <<< 11) ||| (signed <<< 8) ||| (size <<< 5) ||| (l <<< 4)
  match ins.Operands with
  | TwoOperands(OprReg rt, OprMemory mode) ->
    let extra, hw2 = wideMemory ins rt mode
    wideWord (head ||| extra) hw2
  | _ -> wrongOperands ins

/// The unprivileged loads and stores, which read and write as though the
/// processor were in user mode and so keep their offset where the others keep
/// the bits that say when the base is updated.
let private wideUnprivileged signed size l ins =
  let head = (0b11111u <<< 11) ||| (signed <<< 8) ||| (size <<< 5) ||| (l <<< 4)
  match ins.Operands with
  | TwoOperands(OprReg rt, OprMemory(OffsetMode(ImmOffset(rn, _, imm)))) ->
    wideWord (head ||| coreReg rn)
             ((coreReg rt <<< 12) ||| (0b1110u <<< 8)
              ||| unsignedImm 8 (defaultArg imm 0L))
  | _ -> wrongOperands ins

/// The preload hints, which name a place the way a load does and name no
/// register to read it into.
let private widePreload signed size ins =
  match ins.Operands with
  | OneOperand(OprMemory mode) ->
    let head =
      (0b11111u <<< 11) ||| (signed <<< 8) ||| (size <<< 5) ||| (1u <<< 4)
    let extra, hw2 = wideMemory ins Register.PC mode
    wideWord (head ||| extra) hw2
  | _ -> wrongOperands ins

/// Where a load or store of two registers reads, whose offset counts in words.
let private widePairMemory ins mode =
  match mode, thumbIndexBits mode with
  | _, Some(p, w, ImmOffset(rn, sign, imm)) ->
    let u, value = signedOffset sign (defaultArg imm 0L)
    if value % 4L <> 0L then fail "a paired offset counts in words"
    else
      (p <<< 8) ||| (u <<< 7) ||| (w <<< 5) ||| coreReg rn,
      unsignedImm 8 (value / 4L)
  | _ -> wrongOperands ins

/// LDRD and STRD, which move two registers the source names in full.
let private widePair l ins =
  match ins.Operands with
  | ThreeOperands(OprReg rt, OprReg rt2, OprMemory mode) ->
    let head, imm8 = widePairMemory ins mode
    wideWord ((0b1110100u <<< 9) ||| (1u <<< 6) ||| (l <<< 4) ||| head)
             ((coreReg rt <<< 12) ||| (coreReg rt2 <<< 8) ||| imm8)
  | _ -> wrongOperands ins

/// The exclusive accesses, whose offset counts in words and which report in a
/// register of their own whether a store succeeded.
let private wideExclusive l ins =
  let head rn =
    (0b111010000u <<< 7) ||| (1u <<< 6) ||| (l <<< 4) ||| coreReg rn
  let offset imm =
    if imm % 4L <> 0L then fail "an exclusive offset counts in words"
    else unsignedImm 8 (imm / 4L)
  match ins.Operands with
  | TwoOperands(OprReg rt, OprMemory(OffsetMode(ImmOffset(rn, _, imm)))) ->
    wideWord (head rn)
             ((coreReg rt <<< 12) ||| (0xfu <<< 8)
              ||| offset (defaultArg imm 0L))
  | ThreeOperands(OprReg rd, OprReg rt,
                  OprMemory(OffsetMode(ImmOffset(rn, _, imm)))) ->
    wideWord (head rn)
             ((coreReg rt <<< 12) ||| (coreReg rd <<< 8)
              ||| offset (defaultArg imm 0L))
  | _ -> wrongOperands ins

/// The wide transfers of several registers at once, and the two that save and
/// restore the state an exception left behind, which share their space.
let private wideBlock op l ins =
  let w = if ins.WriteBack then 1u else 0u
  let head rn =
    (0b1110100u <<< 9) ||| (op <<< 7) ||| (w <<< 5) ||| (l <<< 4) ||| coreReg rn
  match ins.Operands with
  | TwoOperands(OprReg rn, OprRegList regs) -> wideWord (head rn) (regList regs)
  | OneOperand(OprReg rn) -> wideWord (head rn) 0xc000u
  | TwoOperands(OprReg Register.SP, OprImm mode) ->
    wideWord (head Register.SP) (0xc000u ||| unsignedImm 6 mode)
  | _ -> wrongOperands ins

/// <summary>
/// The wide branches, whose reach is split across both halfwords and two bits
/// that are held as what they differ from the sign by rather than as
/// themselves.
/// </summary>
let private wideBranch link exchange ins =
  match ins.Operands, ins.Condition with
  | OneOperand(OprMemory(LiteralMode offset)), Some cond when link = 0u ->
    let value = signedImm 21 (offset / 2L)
    let sign = (value >>> 19) &&& 1u
    wideWord ((0b11110u <<< 11) ||| (sign <<< 10) ||| (condField cond <<< 6)
              ||| ((value >>> 11) &&& 0x3fu))
             ((0b10u <<< 14) ||| (((value >>> 17) &&& 1u) <<< 13)
              ||| (((value >>> 16) &&& 1u) <<< 11) ||| (value &&& 0x7ffu))
  | OneOperand(OprMemory(LiteralMode offset)), _ ->
    let value = signedImm 25 (offset / 2L)
    let sign = (value >>> 23) &&& 1u
    let j1 = ((value >>> 22) &&& 1u) ^^^ sign ^^^ 1u
    let j2 = ((value >>> 21) &&& 1u) ^^^ sign ^^^ 1u
    wideWord ((0b11110u <<< 11) ||| (sign <<< 10)
              ||| ((value >>> 11) &&& 0x3ffu))
             ((1u <<< 15) ||| (link <<< 14) ||| (j1 <<< 13)
              ||| (exchange <<< 12) ||| (j2 <<< 11) ||| (value &&& 0x7ffu))
  | _ -> wrongOperands ins

/// The signed multiplies that read half of each source, which name the halves
/// in the two bits below their opcode.
let private wideHalfMul op1 op2 ins =
  let head rn = (0b111110110u <<< 7) ||| (op1 <<< 4) ||| coreReg rn
  match ins.Operands with
  | FourOperands(OprReg rd, OprReg rn, OprReg rm, OprReg ra) ->
    wideWord (head rn)
             ((coreReg ra <<< 12) ||| (coreReg rd <<< 8) ||| (op2 <<< 4)
              ||| coreReg rm)
  | ThreeOperands(OprReg rd, OprReg rn, OprReg rm) ->
    wideWord (head rn)
             ((0xfu <<< 12) ||| (coreReg rd <<< 8) ||| (op2 <<< 4)
              ||| coreReg rm)
  | _ -> wrongOperands ins

/// The instructions that name nothing but a number, whose bits sit on either
/// side of the halfword boundary.
let private wideException head hw2Head width ins =
  match ins.Operands with
  | OneOperand(OprImm imm) ->
    let imm16 = unsignedImm width imm
    wideWord (head ||| (imm16 >>> 12)) (hw2Head ||| (imm16 &&& 0xfffu))
  | _ -> wrongOperands ins

/// <summary>
/// MRS and MSR, which move a status register, or the copy of a register that a
/// mode the processor is not in keeps.
///
/// Which of the two it is decides where the selector sits: reading one keeps it
/// beside the source, and writing one keeps it beside the destination.
/// </summary>
let private wideStatusMove read ins =
  let banked reg = if isBankedReg reg then bankedReg reg else 0u, 0u
  match ins.Operands, read with
  | TwoOperands(OprReg rd, OprReg reg), true when isBankedReg reg ->
    let r, selector = banked reg
    wideWord ((0b1111001111u <<< 6) ||| (1u <<< 5) ||| (r <<< 4)
              ||| (selector &&& 0xfu))
             (0x8000u ||| (coreReg rd <<< 8) ||| ((selector >>> 4) <<< 5)
              ||| (1u <<< 4))
  | TwoOperands(OprReg reg, OprReg rn), false when isBankedReg reg ->
    let r, selector = banked reg
    wideWord ((0b1111001110u <<< 6) ||| (r <<< 4) ||| coreReg rn)
             (0x8000u ||| ((selector &&& 0xfu) <<< 8)
              ||| ((selector >>> 4) <<< 5) ||| (1u <<< 4))
  | TwoOperands(OprReg rd, OprReg sreg), true ->
    wideWord ((0b1111001111u <<< 6) ||| (1u <<< 5) ||| (statusRegBit sreg <<< 4)
              ||| 0xfu)
             (0x8000u ||| (coreReg rd <<< 8))
  | TwoOperands(OprSpecReg(sreg, flag), OprReg rn), false ->
    wideWord ((0b1111001110u <<< 6) ||| (statusRegBit sreg <<< 4)
              ||| coreReg rn)
             (0x8000u ||| (psrMask flag <<< 8))
  | _ -> wrongOperands ins

/// CPS, which turns the interrupts its operand names on or off and may say
/// which mode to change to at the same time.
let private wideChangeState imod ins =
  let flagBits = function
    | A -> 0b100u
    | I -> 0b010u
    | F -> 0b001u
    | AI -> 0b110u
    | AF -> 0b101u
    | IF -> 0b011u
    | AIF -> 0b111u
  let head = (0b11110011101u <<< 5) ||| 0xfu
  match ins.Operands with
  | OneOperand(OprIflag flags) ->
    wideWord head (0x8000u ||| (imod <<< 9) ||| (flagBits flags <<< 5))
  | TwoOperands(OprIflag flags, OprImm mode) ->
    wideWord head (0x8000u ||| (imod <<< 9) ||| (1u <<< 8)
                   ||| (flagBits flags <<< 5) ||| unsignedImm 5 mode)
  | _ -> wrongOperands ins

/// SMC, whose four bits of immediate name a monitor call and sit in the first
/// halfword rather than the second.
let private wideSecureMonitor ins =
  match ins.Operands with
  | OneOperand(OprImm imm) ->
    wideWord (0xf7f0u ||| unsignedImm 4 imm) 0x8000u
  | _ -> wrongOperands ins

/// BXJ, which branches to an address a register holds and would once have
/// changed to a third instruction set on the way.
let private wideBranchExchangeJazelle ins =
  match ins.Operands with
  | OneOperand(OprReg rm) ->
    wideWord ((0b111100111100u <<< 4) ||| coreReg rm) 0x8f00u
  | _ -> wrongOperands ins

/// The wide hints, which do nothing a program can see and are told apart by
/// their low byte.
let private wideHint value ins =
  match ins.Operands with
  | NoOperand ->
    wideWord ((0b11110011101u <<< 5) ||| 0xfu) ((0b1000u <<< 12) ||| value)
  | _ -> wrongOperands ins

/// The narrow Thumb instructions, which are what a halfword on its own can say.
let thumbNarrowEncoders () =
  [ Opcode.LSLS, shiftImmediate 0b00u
    Opcode.LSRS, shiftImmediate 0b01u
    Opcode.ASRS, shiftImmediate 0b10u
    Opcode.ADDS, addSubtractOrImmediate 0u
    Opcode.SUBS, addSubtractOrImmediate 1u
    Opcode.ANDS, dataProc 0b0000u
    Opcode.EORS, dataProc 0b0001u
    Opcode.ADCS, dataProc 0b0101u
    Opcode.SBCS, dataProc 0b0110u
    Opcode.TST, dataProc 0b1000u
    Opcode.RSBS, dataProc 0b1001u
    Opcode.CMN, dataProc 0b1011u
    Opcode.ORRS, dataProc 0b1100u
    Opcode.BICS, dataProc 0b1110u
    Opcode.MVNS, dataProc 0b1111u
    Opcode.MULS, multiply
    Opcode.MOVS, moveShifted
    Opcode.MOV, specialData 0b10u
    Opcode.CMP, compare
    Opcode.ADD, add
    Opcode.SUB, subtract
    Opcode.BX, branchExchange 0u
    Opcode.BLX, branchExchange 1u
    Opcode.STR, loadStore (0b011u <<< 13) 4u 0u 0b000u
    Opcode.LDR, loadStore (0b011u <<< 13) 4u 1u 0b100u
    Opcode.STRB, loadStore (0b0111u <<< 12) 1u 0u 0b010u
    Opcode.LDRB, loadStore (0b0111u <<< 12) 1u 1u 0b110u
    Opcode.STRH, loadStore (0b1000u <<< 12) 2u 0u 0b001u
    Opcode.LDRH, loadStore (0b1000u <<< 12) 2u 1u 0b101u
    Opcode.LDRSB, loadStoreReg 0b011u
    Opcode.LDRSH, loadStoreReg 0b111u
    Opcode.ADR, addressOrStack 0u
    Opcode.CBZ, compareBranch 0u
    Opcode.CBNZ, compareBranch 1u
    Opcode.SXTH, twoRegister (0b10110010u <<< 8) 0b00u
    Opcode.SXTB, twoRegister (0b10110010u <<< 8) 0b01u
    Opcode.UXTH, twoRegister (0b10110010u <<< 8) 0b10u
    Opcode.UXTB, twoRegister (0b10110010u <<< 8) 0b11u
    Opcode.REV, twoRegister (0b10111010u <<< 8) 0b00u
    Opcode.REV16, twoRegister (0b10111010u <<< 8) 0b01u
    Opcode.REVSH, twoRegister (0b10111010u <<< 8) 0b11u
    Opcode.PUSH, stack Register.LR 0u
    Opcode.POP, stack Register.PC 1u
    Opcode.STM, blockTransfer 0u
    Opcode.LDM, blockTransfer 1u
    Opcode.B, conditionalBranch
    Opcode.UDF, serviceCall (0b11011110u <<< 8) 8
    Opcode.SVC, serviceCall (0b11011111u <<< 8) 8
    Opcode.BKPT, serviceCall (0b10111110u <<< 8) 8
    Opcode.HLT, serviceCall (0b1011101010u <<< 6) 6
    Opcode.NOP, hint 0b0000u
    Opcode.YIELD, hint 0b0001u
    Opcode.WFE, hint 0b0010u
    Opcode.WFI, hint 0b0011u
    Opcode.SEV, hint 0b0100u
    Opcode.SEVL, hint 0b0101u
    Opcode.IT, ifThen ""
    Opcode.ITT, ifThen "t"
    Opcode.ITE, ifThen "e"
    Opcode.ITTT, ifThen "tt"
    Opcode.ITTE, ifThen "te"
    Opcode.ITET, ifThen "et"
    Opcode.ITEE, ifThen "ee"
    Opcode.ITTTT, ifThen "ttt"
    Opcode.ITTTE, ifThen "tte"
    Opcode.ITTET, ifThen "tet"
    Opcode.ITTEE, ifThen "tee"
    Opcode.ITETT, ifThen "ett"
    Opcode.ITETE, ifThen "ete"
    Opcode.ITEET, ifThen "eet"
    Opcode.ITEEE, ifThen "eee"
    Opcode.CPSIE, changeState 0u
    Opcode.CPSID, changeState 1u
    Opcode.SETEND, setEndian
    Opcode.SETPAN, setPan ]

/// <summary>
/// Prefers the narrow encoding of an instruction that has both.
///
/// The wide one takes over when what the source wrote does not fit the narrow
/// one, and a ".w" written on the mnemonic says to skip the narrow one
/// outright: that is how the disassembler marks a wide encoding whose operands
/// a narrow one could also have held.
/// </summary>
let preferNarrow narrowEncode wideEncode (ins: AsmInsInfo) =
  if ins.Qualifier = W then wideEncode ins
  else
    try narrowEncode ins with :? EncodingFailureException -> wideEncode ins

/// The wide Thumb instructions, which are what two halfwords together say.
let thumbWideEncoders () =
  [ Opcode.AND, wideData 0b0000u 0u
    Opcode.ANDS, wideData 0b0000u 1u
    Opcode.BIC, wideData 0b0001u 0u
    Opcode.BICS, wideData 0b0001u 1u
    Opcode.ORR, wideData 0b0010u 0u
    Opcode.ORRS, wideData 0b0010u 1u
    Opcode.ORN, wideData 0b0011u 0u
    Opcode.ORNS, wideData 0b0011u 1u
    Opcode.EOR, wideData 0b0100u 0u
    Opcode.EORS, wideData 0b0100u 1u
    Opcode.ADD, wideData 0b1000u 0u
    Opcode.ADDS, wideData 0b1000u 1u
    Opcode.ADC, wideData 0b1010u 0u
    Opcode.ADCS, wideData 0b1010u 1u
    Opcode.SBC, wideData 0b1011u 0u
    Opcode.SBCS, wideData 0b1011u 1u
    Opcode.SUB, wideData 0b1101u 0u
    Opcode.SUBS, wideData 0b1101u 1u
    Opcode.RSB, wideData 0b1110u 0u
    Opcode.RSBS, wideData 0b1110u 1u
    Opcode.TST, wideCompare 0b0000u
    Opcode.TEQ, wideCompare 0b0100u
    Opcode.CMN, wideCompare 0b1000u
    Opcode.CMP, wideCompare 0b1101u
    Opcode.ADDW, widePlainImm 0b00000u
    Opcode.MOVW, widePlainImm 0b00100u
    Opcode.SUBW, widePlainImm 0b01010u
    Opcode.MOVT, widePlainImm 0b01100u
    Opcode.SSAT, wideBitfield 0b10000u 1L
    Opcode.SSAT16, wideBitfield 0b10010u 1L
    Opcode.USAT, wideBitfield 0b11000u 0L
    Opcode.USAT16, wideBitfield 0b11010u 0L
    Opcode.SBFX, wideExtract 0b10100u
    Opcode.BFI, wideExtract 0b10110u
    Opcode.BFC, wideExtract 0b10110u
    Opcode.UBFX, wideExtract 0b11100u
    Opcode.LDR, wideLoadStore 0u 0b10u 1u
    Opcode.STR, wideLoadStore 0u 0b10u 0u
    Opcode.LDRB, wideLoadStore 0u 0b00u 1u
    Opcode.STRB, wideLoadStore 0u 0b00u 0u
    Opcode.LDRH, wideLoadStore 0u 0b01u 1u
    Opcode.STRH, wideLoadStore 0u 0b01u 0u
    Opcode.LDRSB, wideLoadStore 1u 0b00u 1u
    Opcode.LDRSH, wideLoadStore 1u 0b01u 1u
    Opcode.LDRT, wideUnprivileged 0u 0b10u 1u
    Opcode.STRT, wideUnprivileged 0u 0b10u 0u
    Opcode.LDRBT, wideUnprivileged 0u 0b00u 1u
    Opcode.STRBT, wideUnprivileged 0u 0b00u 0u
    Opcode.LDRHT, wideUnprivileged 0u 0b01u 1u
    Opcode.STRHT, wideUnprivileged 0u 0b01u 0u
    Opcode.LDRSBT, wideUnprivileged 1u 0b00u 1u
    Opcode.LDRSHT, wideUnprivileged 1u 0b01u 1u
    Opcode.PLD, widePreload 0u 0b00u
    Opcode.PLDW, widePreload 0u 0b01u
    Opcode.PLI, widePreload 1u 0b00u
    Opcode.LDRD, widePair 1u
    Opcode.STRD, widePair 0u
    Opcode.LDREX, wideExclusive 1u
    Opcode.STREX, wideExclusive 0u
    Opcode.LDM, wideBlock 0b01u 1u
    Opcode.LDMIA, wideBlock 0b01u 1u
    Opcode.STM, wideBlock 0b01u 0u
    Opcode.STMIA, wideBlock 0b01u 0u
    Opcode.LDMDB, wideBlock 0b10u 1u
    Opcode.STMDB, wideBlock 0b10u 0u
    Opcode.RFEIA, wideBlock 0b11u 1u
    Opcode.RFEDB, wideBlock 0b00u 1u
    Opcode.SRSIA, wideBlock 0b11u 0u
    Opcode.SRSDB, wideBlock 0b00u 0u
    Opcode.B, wideBranch 0u 1u
    Opcode.BL, wideBranch 1u 1u
    Opcode.BLX, wideBranch 1u 0u
    Opcode.BXJ, wideBranchExchangeJazelle
    Opcode.SMLATT, wideHalfMul 0b001u 0b11u
    Opcode.SMULTT, wideHalfMul 0b001u 0b11u
    Opcode.HVC, wideException 0xf7e0u 0x8000u 16
    Opcode.SMC, wideSecureMonitor
    Opcode.UDF, wideException 0xf7f0u 0xa000u 16
    Opcode.NOP, wideHint 0x00u
    Opcode.YIELD, wideHint 0x01u
    Opcode.WFE, wideHint 0x02u
    Opcode.WFI, wideHint 0x03u
    Opcode.SEV, wideHint 0x04u
    Opcode.SEVL, wideHint 0x05u
    Opcode.MRS, wideStatusMove true
    Opcode.MSR, wideStatusMove false
    Opcode.CPSIE, wideChangeState 0b10u
    Opcode.CPSID, wideChangeState 0b11u ]

/// The SIMD, floating-point and coprocessor instructions, whose Thumb
/// encodings are the A32 ones with different bits above them.
let thumbSharedEncoders () =
  [ floatingPointEncoders ()
    advancedSIMDEncoders ()
    coprocessorEncoders () ]
  |> List.concat
  |> List.map (fun (opcode, encode) -> opcode, shared encode)

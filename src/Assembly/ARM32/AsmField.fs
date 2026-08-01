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
/// Turns the pieces of an instruction into the bit fields an A32 encoding is
/// built from. Every function here rejects what does not fit rather than
/// truncating it, because a field that silently drops a bit encodes an
/// instruction the source did not ask for.
/// </summary>
module internal B2R2.Assembly.ARM32.AsmField

open B2R2.FrontEnd.ARM32
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.ARM32.ParserHelper

/// Reports a source this assembler cannot encode.
let fail msg = raise <| EncodingFailureException msg

/// Reports operands that do not belong to the given opcode.
let wrongOperands (ins: AsmInsInfo) =
  fail $"{ins.Opcode} does not take these operands"

/// The four bits that stand for a condition.
let condField = function
  | Condition.EQ -> 0b0000u
  | Condition.NE -> 0b0001u
  | Condition.CS | Condition.HS -> 0b0010u
  | Condition.CC | Condition.LO -> 0b0011u
  | Condition.MI -> 0b0100u
  | Condition.PL -> 0b0101u
  | Condition.VS -> 0b0110u
  | Condition.VC -> 0b0111u
  | Condition.HI -> 0b1000u
  | Condition.LS -> 0b1001u
  | Condition.GE -> 0b1010u
  | Condition.LT -> 0b1011u
  | Condition.GT -> 0b1100u
  | Condition.LE -> 0b1101u
  | Condition.AL -> 0b1110u
  (* The 0b1111 encoding that once meant NV now marks the unconditional
     encoding space, so an instruction written with an NV suffix cannot be
     encoded as itself. *)
  | cond -> fail $"{cond} is not an encodable A32 condition"

/// <summary>
/// The condition that holds exactly when the given one does not, which is what
/// the "e" of an IT block names.
///
/// The condition that always holds has no opposite, which is why an IT block
/// written under it can only say "then".
/// </summary>
let oppositeCondition = function
  | Condition.EQ -> Condition.NE
  | Condition.NE -> Condition.EQ
  | Condition.CS | Condition.HS -> Condition.CC
  | Condition.CC | Condition.LO -> Condition.CS
  | Condition.MI -> Condition.PL
  | Condition.PL -> Condition.MI
  | Condition.VS -> Condition.VC
  | Condition.VC -> Condition.VS
  | Condition.HI -> Condition.LS
  | Condition.LS -> Condition.HI
  | Condition.GE -> Condition.LT
  | Condition.LT -> Condition.GE
  | Condition.GT -> Condition.LE
  | Condition.LE -> Condition.GT
  | cond -> fail $"{cond} has no opposite to run the other half of a block on"

/// The condition field of an instruction that takes a condition, bits 31 to
/// 28. A mnemonic written without a suffix is unconditional, which A32 spells
/// AL.
let cond (ins: AsmInsInfo) =
  match ins.Condition with
  | None -> 0b1110u <<< 28
  | Some c -> condField c <<< 28

/// The condition field of an instruction that exists only in the unconditional
/// encoding space, bits 31 to 28. Such an instruction takes no condition
/// suffix, so one that was written is a mistake in the source.
let unconditional (ins: AsmInsInfo) =
  match ins.Condition with
  | None | Some Condition.UN -> 0b1111u <<< 28
  | Some _ -> fail $"{ins.Opcode} takes no condition"

/// The condition field of an instruction the manual makes unconditional even
/// though its encoding sits in the conditional space. BKPT and UDF are two:
/// the decoder reports no condition for either, so a condition written here
/// could not be read back from what it encodes.
let alwaysCond (ins: AsmInsInfo) =
  match ins.Condition with
  | None | Some Condition.AL | Some Condition.UN -> 0b1110u <<< 28
  | Some _ -> fail $"{ins.Opcode} takes no condition"

/// The four-bit register number every core-register field holds.
let coreReg (reg: Register) =
  let number = int reg
  if number <= int Register.PC then uint32 number
  else fail $"{Register.toString reg} is not a core register"

/// The coprocessor number of a "p<n>" operand.
let coprocReg (reg: Register) =
  let number = int reg - int Register.P0
  if number >= 0 && number <= 15 then uint32 number
  else fail $"{Register.toString reg} is not a coprocessor"

/// The register number of a "c<n>" coprocessor register operand.
let coprocRegNum (reg: Register) =
  let number = int reg - int Register.C0
  if number >= 0 && number <= 15 then uint32 number
  else fail $"{Register.toString reg} is not a coprocessor register"

/// The R bit, which says whether a status-register instruction names the saved
/// program status register or the current one. The disassembler calls the
/// current one APSR, so both of its names are accepted here.
let statusRegBit (reg: Register) =
  match reg with
  | Register.APSR | Register.CPSR -> 0u
  | Register.SPSR -> 1u
  | _ -> fail $"{Register.toString reg} is not a status register"

/// <summary>
/// The mask that says which fields of a status register an MSR writes, bits 19
/// to 16. The four bits stand for the flags, the status, the extension and the
/// control field, from the top down.
///
/// The names APSR wears cover the same bits: its flags are the top one and its
/// SIMD greater-than bits the one below, which is why they map onto the same
/// mask as the status and flags fields of CPSR.
/// </summary>
let psrMask = function
  | None -> 0b0000u
  | Some PSRc -> 0b0001u
  | Some PSRx -> 0b0010u
  | Some PSRxc -> 0b0011u
  | Some PSRs | Some PSRg -> 0b0100u
  | Some PSRsc -> 0b0101u
  | Some PSRsx -> 0b0110u
  | Some PSRsxc -> 0b0111u
  | Some PSRf | Some PSRnzcv | Some PSRnzcvq -> 0b1000u
  | Some PSRfc -> 0b1001u
  | Some PSRfx -> 0b1010u
  | Some PSRfxc -> 0b1011u
  | Some PSRfs | Some PSRnzcvqg -> 0b1100u
  | Some PSRfsc -> 0b1101u
  | Some PSRfsx -> 0b1110u
  | Some PSRfsxc -> 0b1111u

/// The R bit and the five-bit selector that name a banked register, inverted
/// from the table the disassembler reads them with.
let private bankedRegSelector (reg: Register) =
  match reg with
  | Register.R8usr -> Some(0u, 0b00000u)
  | Register.R9usr -> Some(0u, 0b00001u)
  | Register.R10usr -> Some(0u, 0b00010u)
  | Register.R11usr -> Some(0u, 0b00011u)
  | Register.R12usr -> Some(0u, 0b00100u)
  | Register.SPusr -> Some(0u, 0b00101u)
  | Register.LRusr -> Some(0u, 0b00110u)
  | Register.R8fiq -> Some(0u, 0b01000u)
  | Register.R9fiq -> Some(0u, 0b01001u)
  | Register.R10fiq -> Some(0u, 0b01010u)
  | Register.R11fiq -> Some(0u, 0b01011u)
  | Register.R12fiq -> Some(0u, 0b01100u)
  | Register.SPfiq -> Some(0u, 0b01101u)
  | Register.LRfiq -> Some(0u, 0b01110u)
  | Register.LRirq -> Some(0u, 0b10000u)
  | Register.SPirq -> Some(0u, 0b10001u)
  | Register.LRsvc -> Some(0u, 0b10010u)
  | Register.SPsvc -> Some(0u, 0b10011u)
  | Register.LRabt -> Some(0u, 0b10100u)
  | Register.SPabt -> Some(0u, 0b10101u)
  | Register.LRund -> Some(0u, 0b10110u)
  | Register.SPund -> Some(0u, 0b10111u)
  | Register.LRmon -> Some(0u, 0b11100u)
  | Register.SPmon -> Some(0u, 0b11101u)
  | Register.ELRhyp -> Some(0u, 0b11110u)
  | Register.SPhyp -> Some(0u, 0b11111u)
  | Register.SPSRfiq -> Some(1u, 0b01110u)
  | Register.SPSRirq -> Some(1u, 0b10000u)
  | Register.SPSRsvc -> Some(1u, 0b10010u)
  | Register.SPSRabt -> Some(1u, 0b10100u)
  | Register.SPSRund -> Some(1u, 0b10110u)
  | Register.SPSRmon -> Some(1u, 0b11100u)
  | Register.SPSRhyp -> Some(1u, 0b11110u)
  | _ -> None

/// Whether the register names a mode's own copy of one. The instructions that
/// read and write the status registers reach those with a different encoding
/// from the one they use for the mode the processor is in.
let isBankedReg reg = bankedRegSelector reg |> Option.isSome

/// <summary>
/// The R bit and the five-bit selector that name a banked register.
///
/// The selector is split in the encoding: its top bit sits on its own well
/// below the four that follow it, which is why what comes back here is the
/// selector rather than the bits of one field.
/// </summary>
let bankedReg (reg: Register) =
  match bankedRegSelector reg with
  | Some selector -> selector
  | None -> fail $"{Register.toString reg} is not a banked register"

/// The S bit of a block transfer, which says it names the registers of another
/// mode or returns from an exception. The source writes that as a caret after
/// the register list.
let caretBit (ins: AsmInsInfo) = if ins.Caret then 1u else 0u

/// Rejects a caret on an instruction that has nowhere to put one.
let checkNoCaret (ins: AsmInsInfo) =
  if ins.Caret then fail $"{ins.Opcode} takes no '^'" else ()

/// <summary>
/// The number of a SIMD or floating-point register, from zero.
///
/// A doubleword register and a quadword one share a numbering: the quadword
/// register is the pair starting at twice its own number, which is what its
/// encoding holds.
/// </summary>
let simdReg (reg: Register) =
  let number = int reg
  if number >= int Register.S0 && number <= int Register.S31 then
    uint32 (number - int Register.S0)
  elif number >= int Register.D0 && number <= int Register.D31 then
    uint32 (number - int Register.D0)
  elif number >= int Register.Q0 && number <= int Register.Q15 then
    uint32 (number - int Register.Q0) * 2u
  else
    fail $"{Register.toString reg} is not a SIMD register"

/// <summary>
/// Whether the register is a quadword one, which is what the Q bit of a SIMD
/// instruction says.
let isQuadReg (reg: Register) =
  int reg >= int Register.Q0 && int reg <= int Register.Q15

/// Whether the register is single-precision, which is what the size bit of a
/// floating-point instruction says and what decides which end of its number
/// each register field keeps.
let isSingleReg (reg: Register) =
  int reg >= int Register.S0 && int reg <= int Register.S31

/// Places a SIMD register in one of the three fields that hold one, together
/// with the bit that carries its top bit.
///
/// Which end that bit belongs to depends on the width: a doubleword register
/// keeps its top bit apart and the four below it in the field, while a
/// single-precision one keeps its four top bits in the field and its lowest
/// bit apart.
/// </summary>
let private simdField isSingle fieldPos topPos reg =
  let number = simdReg reg
  if isSingle then
    ((number &&& 1u) <<< topPos) ||| ((number >>> 1) <<< fieldPos)
  else
    ((number >>> 4) <<< topPos) ||| ((number &&& 0xfu) <<< fieldPos)

/// The destination field of a SIMD instruction, bits 15 to 12 and bit 22.
let vd reg = simdField false 12 22 reg

/// The first source field, bits 19 to 16 and bit 7.
let vn reg = simdField false 16 7 reg

/// The second source field, bits 3 to 0 and bit 5.
let vm reg = simdField false 0 5 reg

/// The same three fields for a single-precision register, whose top bit sits
/// at the other end of its number.
let sd reg = simdField true 12 22 reg

let sn reg = simdField true 16 7 reg

let sm reg = simdField true 0 5 reg

/// How wide one element of a SIMD operand is, as the two bits that say so.
let private sizeOfType = function
  | SIMDTyp8 | SIMDTypS8 | SIMDTypU8 | SIMDTypI8 | SIMDTypP8 -> 0u
  | SIMDTyp16 | SIMDTypS16 | SIMDTypU16 | SIMDTypI16 | SIMDTypF16 -> 1u
  | SIMDTyp32 | SIMDTypS32 | SIMDTypU32 | SIMDTypI32 | SIMDTypF32 -> 2u
  | SIMDTyp64 | SIMDTypS64 | SIMDTypU64 | SIMDTypI64 | SIMDTypF64
  | SIMDTypP64 -> 3u
  | BF16 -> 1u

/// The data type an instruction was written with, which every SIMD instruction
/// needs and which says how wide its elements are.
let dataType (ins: AsmInsInfo) =
  match ins.SIMDTyp with
  | Some(OneDT dt) -> dt
  | Some(TwoDT(dt, _)) -> dt
  | None -> fail $"{ins.Opcode} needs a data type"

/// The size field, which says how wide one element is.
let elementSize ins = sizeOfType (dataType ins)

/// The same, for the instructions that may be written without a data type at
/// all: what is absent says nothing about the width rather than naming one.
let elementSizeOrNone (ins: AsmInsInfo) =
  match ins.SIMDTyp with
  | Some(OneDT dt) | Some(TwoDT(dt, _)) -> Some(sizeOfType dt)
  | None -> None

/// The U bit, which says whether the elements are read as unsigned. Only the
/// types that name a sign carry one; the rest are read as signed.
let unsignedBit ins =
  match dataType ins with
  | SIMDTypU8 | SIMDTypU16 | SIMDTypU32 | SIMDTypU64 -> 1u
  | _ -> 0u

/// <summary>
/// The eight bits that stand for a floating-point immediate, which hold a sign,
/// a short exponent and four bits of significand.
///
/// The manual gives the expansion rather than its inverse, so this searches for
/// the byte that expands to the value asked for: there are only two hundred and
/// fifty-six of them, and no other byte can expand to the same value.
/// </summary>
let fpImm8 width (value: int64) =
  let expand (imm8: uint32) =
    let sign = (imm8 >>> 7) &&& 1u
    let b6 = (imm8 >>> 6) &&& 1u
    let exponentBits = if width = 64 then 8 else 5
    let repeated = if b6 = 1u then (1UL <<< exponentBits) - 1UL else 0UL
    let exponent =
      (uint64 (1u - b6) <<< (exponentBits + 2)) ||| (repeated <<< 2)
      ||| uint64 ((imm8 >>> 4) &&& 0b11u)
    let fraction = uint64 (imm8 &&& 0xfu)
    if width = 64 then
      (uint64 sign <<< 63) ||| (exponent <<< 52) ||| (fraction <<< 48)
    else
      (uint64 sign <<< 31) ||| (exponent <<< 23) ||| (fraction <<< 19)
  let matches imm8 = expand imm8 = uint64 value
  match [ 0u .. 255u ] |> List.tryFind matches with
  | Some imm8 -> imm8
  | None -> fail $"#{value} is not a floating-point immediate"

/// The P and W bits an addressing mode sets, which together say whether the
/// base register is updated and whether the offset applies before or after the
/// access, paired with the offset itself.
let indexBits = function
  | OffsetMode offset -> Some(1u, 0u, offset)
  | PreIdxMode offset -> Some(1u, 1u, offset)
  | PostIdxMode offset -> Some(0u, 0u, offset)
  | UnIdxMode _ | LiteralMode _ -> None

/// The bitfield instructions name the field they act on by where it starts and
/// how wide it is. What the encoding holds instead is where the field ends.
let endOfBitfield (lsb: int64) (width: int64) =
  let msb = lsb + width - 1L
  if msb < lsb || msb > 31L then
    fail $"a field of #{width} bits cannot start at #{lsb}"
  else
    uint32 msb

/// The bitmap of a register list, one bit per core register.
let regList regs =
  if List.isEmpty regs then fail "A register list cannot be empty"
  else regs |> List.fold (fun acc reg -> acc ||| (1u <<< int (coreReg reg))) 0u

/// A value that has to fit an unsigned field of the given width.
let unsignedImm width (value: int64) =
  if value >= 0L && value < (1L <<< width) then uint32 value
  else fail $"#{value} does not fit in an unsigned {width}-bit field"

/// A value that has to fit a signed field of the given width, kept as the bit
/// pattern the field holds.
let signedImm width (value: int64) =
  let limit = 1L <<< (width - 1)
  if value >= -limit && value < limit then
    uint32 value &&& ((1u <<< width) - 1u)
  else
    fail $"#{value} does not fit in a signed {width}-bit field"

/// Rotates a word left, which is how a modified immediate is taken apart.
let private rotateLeft (value: uint32) amount =
  if amount = 0 then value
  else (value <<< amount) ||| (value >>> (32 - amount))

/// <summary>
/// The imm12 field of a data-processing instruction, which holds an eight-bit
/// value together with the even rotation to the right that expands it.
///
/// The smallest rotation that works is chosen. That is what the disassembler's
/// expansion inverts, so a value it printed comes back as the same bits it was
/// decoded from.
/// </summary>
let modifiedImm (value: int64) =
  let value = uint32 value
  let rec search rotation =
    if rotation > 15 then
      fail $"#{value} is not an A32 modified immediate"
    else
      let imm8 = rotateLeft value (rotation * 2)
      if imm8 < 0x100u then (uint32 rotation <<< 8) ||| imm8
      else search (rotation + 1)
  search 0

/// The stype and imm5 fields of a shift by an immediate, bits 11 to 5. An LSR
/// or ASR by 32 shares its bit pattern with a shift by 0, and a ROR by 0 is
/// RRX, which is why the amounts accepted differ per shift.
let immShift = function
  | ShiftOp.LSL, Imm 0u -> 0u
  | ShiftOp.LSL, Imm amount when amount < 32u -> amount <<< 7
  | ShiftOp.LSR, Imm amount when amount >= 1u && amount <= 32u ->
    ((amount % 32u) <<< 7) ||| (0b01u <<< 5)
  | ShiftOp.ASR, Imm amount when amount >= 1u && amount <= 32u ->
    ((amount % 32u) <<< 7) ||| (0b10u <<< 5)
  | ShiftOp.ROR, Imm amount when amount >= 1u && amount < 32u ->
    (amount <<< 7) ||| (0b11u <<< 5)
  (* RRX is a rotate right through carry by one place, and the disassembler
     writes that one as its amount; there is no other amount to encode. *)
  | ShiftOp.RRX, _ -> 0b11u <<< 5
  | shift, Imm amount -> fail $"{shift} by #{amount} is not encodable"

/// <summary>
/// The shift a MOV alias carries, whose amount is written differently from the
/// same shift inside an operand2: for an alias the disassembler prints the
/// field rather than what it means, so an LSR or ASR by nothing there is how it
/// writes one by thirty-two.
/// </summary>
let aliasImmShift shift amount =
  match shift, amount with
  | ShiftOp.LSR, 0u | ShiftOp.ASR, 0u -> immShift (shift, Imm 32u)
  | _ -> immShift (shift, Imm amount)

/// The stype field of a shift by a register, bits 6 to 5. RRX has no
/// register-shift form.
let private regShiftType = function
  | ShiftOp.LSL -> 0b00u <<< 5
  | ShiftOp.LSR -> 0b01u <<< 5
  | ShiftOp.ASR -> 0b10u <<< 5
  | ShiftOp.ROR -> 0b11u <<< 5
  | shift -> fail $"{shift} takes no register amount"

/// The Rs and stype fields of a shift by a register, bits 11 to 5.
let regShift (shift, reg) =
  (coreReg reg <<< 8) ||| regShiftType shift ||| (1u <<< 4)

/// The U bit, which says whether an offset is added to the base register or
/// subtracted from it. An offset written without a sign is added.
let addBit = function
  | Some Minus -> 0u
  | Some Plus | None -> 1u

/// The magnitude of a signed offset, together with the U bit that carries its
/// sign, so that a source may write the sign either way round.
let signedOffset sign (value: int64) =
  match sign, value with
  | Some Minus, value -> 0u, abs value
  | _, value when value < 0L -> 0u, abs value
  | _, value -> 1u, value

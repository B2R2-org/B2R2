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
/// Encodes the MIPS16e form of an instruction.
///
/// MIPS16e is a third encoding of the same instruction set, so the text an
/// instruction is written as is the text the other two are written as and
/// everything above this module is shared with them. What differs is the
/// halfword underneath.
///
/// Two things about it decide the shape of everything here.
///
/// A register field is THREE bits and reaches eight registers, so a source
/// naming any of the other twenty-four cannot be encoded at all -- except by
/// MOVE, which spends five bits on one side for exactly that reason. An
/// encoder that silently narrowed the number would write a different
/// instruction, so <c>reg3</c> refuses instead.
///
/// And an immediate that does not fit is not an error but a longer
/// instruction: EXTEND is a prefix that widens the one after it. Where an
/// instruction has an extended form, that is what this writes, whether or not
/// the short one would have done. The alternative is to choose by the value,
/// which would make the LENGTH of an instruction depend on its operands --
/// and the addresses of everything after it depend on that in turn, which is
/// the one thing a single-pass assembler cannot have. microMIPS is written
/// the same way and for the same reason.
/// </summary>
module internal B2R2.Assembly.MIPS.AsmMIPS16

open B2R2
open B2R2.FrontEnd.MIPS
open B2R2.Assembly.MIPS.ParserHelper
open B2R2.Assembly.MIPS.AsmField

/// <summary>
/// The three-bit field a register is written in, which is not its number.
///
/// The inverse of MD00076's Xlat. Eight of the thirty-two are reachable and
/// the rest are refused here rather than narrowed, because a narrowed number
/// names another register and the instruction would assemble to something
/// else that reads correctly.
/// </summary>
let private reg3 (reg: Register) =
  match reg with
  | Register.R16 ->
    0u
  | Register.R17 ->
    1u
  | Register.R2 ->
    2u
  | Register.R3 ->
    3u
  | Register.R4 ->
    4u
  | Register.R5 ->
    5u
  | Register.R6 ->
    6u
  | Register.R7 ->
    7u
  | _ ->
    fail $"MIPS16e cannot name {Register.toString reg WordSize.Bit32}"

/// <summary>
/// The five-bit field MOVE writes its source in, which is the register
/// number rotated.
///
/// MD00076 section 3.14.10: "The r32 field uses special bit encoding. For
/// example, the encoding for $7 (00111) is 11100 in the r32 field." Bits 2..0
/// of the number sit at the top of the field and bits 4..3 at the bottom.
/// </summary>
let private rotated (reg: Register) =
  let n = gpr reg
  ((n &&& 0b111u) <<< 2) ||| ((n >>> 3) &&& 0b11u)

/// A halfword of the short form, which is the whole instruction.
let private short (major: uint32) (lower: uint32) = (major <<< 11) ||| lower

/// <summary>
/// The two halfwords of an extended instruction, as the one word the caller
/// hands back.
///
/// MD00076 sections 3.14.13 onwards agree on where the extra bits live: the
/// prefix carries immediate 10:5 and 15:11 and the instruction keeps 4:0.
/// The prefix itself is major opcode 0b11110.
/// </summary>
let private extended (upper: uint32) (lower: uint32) =
  ((0b11110u <<< 11) ||| upper) <<< 16 ||| lower

/// The prefix of an ordinary extended immediate, which is the two pieces the
/// instruction cannot hold.
let private extImm (value: uint32) =
  (((value >>> 5) &&& 0b111111u) <<< 5) ||| ((value >>> 11) &&& 0b11111u)

/// An immediate of the given width, refused rather than truncated where it
/// does not fit. Signed and unsigned are separate because a value that fits
/// one does not fit the other.
let private fits width signed (value: uint64) =
  let v = int64 value
  let ok =
    if signed then
      v >= -(1L <<< (width - 1)) && v < (1L <<< (width - 1))
    else
      uint64 value < (1UL <<< width)
  if ok then uint32 (value &&& ((1UL <<< width) - 1UL))
  else fail $"{value} does not fit a {width}-bit MIPS16e immediate"

/// <summary>
/// The value an offset or immediate holds once the instruction's own scale is
/// taken out.
///
/// Every MIPS16e load and store counts its offset in units of what it moves,
/// so a source writing 8 for a word load means the second word and the field
/// holds 2. A value the scale does not divide names no offset the instruction
/// can reach.
/// </summary>
let private scaled by (value: int64) =
  if value % by <> 0L then
    fail $"{value} is not a multiple of {by}"
  else
    value / by

/// The registers a saved-set operand names, as the three flags the encoding
/// spends on them. Anything else belongs to the extended form's own fields.
let private svrsFlags regs =
  let has r = if List.contains r regs then 1u else 0u
  (has Register.R31 <<< 6) ||| (has Register.R16 <<< 5)
  ||| (has Register.R17 <<< 4)

/// <summary>
/// A two-register operation of the RR pool, written with the destination
/// repeated: the decoder prints <c>and s0, s0, s1</c> where the encoding
/// holds two fields, because the base architecture's lifter reads three.
/// </summary>
let private rrAccum (funct: uint32) ins =
  match ins.Operands with
  | ThreeOperands(Rg rx, Rg rx', Rg ry) when rx = rx' ->
    short 0b11101u ((reg3 rx <<< 8) ||| (reg3 ry <<< 5) ||| funct)
  | _ ->
    wrongOperands ins

/// A two-register operation written with two operands, which is what the
/// ones with no destination of their own look like.
let private rrPair (funct: uint32) ins =
  match ins.Operands with
  | TwoOperands(Rg rx, Rg ry) ->
    short 0b11101u ((reg3 rx <<< 8) ||| (reg3 ry <<< 5) ||| funct)
  | _ ->
    wrongOperands ins

/// A variable shift, whose destination is also what is shifted.
let private rrShiftVar (funct: uint32) ins =
  match ins.Operands with
  | ThreeOperands(Rg ry, Rg ry', Rg rx) when ry = ry' ->
    short 0b11101u ((reg3 rx <<< 8) ||| (reg3 ry <<< 5) ||| funct)
  | _ ->
    wrongOperands ins

/// A one-register operation of the RR pool, whose ry field is a sub-function
/// rather than a register.
let private rrOne (funct: uint32) (sub: uint32) ins =
  match ins.Operands with
  | OneOperand(Rg rx) ->
    short 0b11101u ((reg3 rx <<< 8) ||| (sub <<< 5) ||| funct)
  | TwoOperands(Rg rx, Rg rx') when rx = rx' ->
    short 0b11101u ((reg3 rx <<< 8) ||| (sub <<< 5) ||| funct)
  | _ ->
    wrongOperands ins

/// A three-register operation of the RRR pool.
let private rrr (f: uint32) ins =
  match ins.Operands with
  | ThreeOperands(Rg rz, Rg rx, Rg ry) ->
    short 0b11100u
      ((reg3 rx <<< 8) ||| (reg3 ry <<< 5) ||| (reg3 rz <<< 2) ||| f)
  | _ ->
    wrongOperands ins

/// <summary>
/// A load or a store, in the extended form so that any offset reaches.
///
/// MD00076 writes them all as <c>LW ry, offset(rx)</c>, so the register is
/// the second field and the base the first -- the other way round from how a
/// three-operand arithmetic instruction of this encoding reads. The extended
/// offset is a plain sixteen bits and is not scaled, which is the other thing
/// EXTEND buys here.
/// </summary>
let private memExt (major: uint32) ins =
  match ins.Operands with
  | TwoOperands(Rg ry, Mem(bse, offset)) ->
    let v = fits 16 true (uint64 offset)
    extended (extImm v)
      (short major ((reg3 bse <<< 8) ||| (reg3 ry <<< 5) ||| (v &&& 0x1fu)))
  | _ ->
    wrongOperands ins

/// The same on the stack pointer, whose base is not in the instruction.
let private memSpExt (major: uint32) ins =
  match ins.Operands with
  | TwoOperands(Rg rx, Mem(bse, offset)) when bse = Register.R29 ->
    let v = fits 16 true (uint64 offset)
    extended (extImm v) (short major ((reg3 rx <<< 8) ||| (v &&& 0x1fu)))
  | _ ->
    wrongOperands ins

/// <summary>
/// An instruction whose one operand is an immediate, extended.
///
/// The EXT-RI box: the register sits where it does in the short form and the
/// three bits below it are zero.
/// </summary>
let private riExt (major: uint32) ins =
  match ins.Operands with
  | TwoOperands(Rg rx, Im value) ->
    let v = fits 16 false value
    extended (extImm v) (short major ((reg3 rx <<< 8) ||| (v &&& 0x1fu)))
  | _ ->
    wrongOperands ins

/// ADDIU written with the destination repeated, which is the eight-bit form.
let private addiu8Ext ins =
  match ins.Operands with
  | ThreeOperands(Rg rx, Rg rx', Im value) when rx = rx' ->
    let v = fits 16 true value
    extended (extImm v) (short 0b01001u ((reg3 rx <<< 8) ||| (v &&& 0x1fu)))
  | _ ->
    wrongOperands ins

/// ADDIU and DADDIU of two different registers, whose extended immediate is
/// fifteen bits because the instruction spends bit 4 on which of the two it
/// is.
let private rriaExt (f: uint32) ins =
  match ins.Operands with
  | ThreeOperands(Rg ry, Rg rx, Im value) ->
    let v = fits 15 true value
    let upper =
      (((v >>> 4) &&& 0b1111111u) <<< 4) ||| ((v >>> 11) &&& 0b1111u)
    let lower =
      short 0b01000u
        ((reg3 rx <<< 8) ||| (reg3 ry <<< 5) ||| (f <<< 4) ||| (v &&& 0xfu))
    extended upper lower
  | _ ->
    wrongOperands ins

/// ADDIU or DADDIU of a register and the stack pointer.
let private spRelExt (major: uint32) ins =
  match ins.Operands with
  | ThreeOperands(Rg rx, Rg sp, Im value) when sp = Register.R29 ->
    let v = fits 16 true value
    extended (extImm v) (short major ((reg3 rx <<< 8) ||| (v &&& 0x1fu)))
  | _ ->
    wrongOperands ins

/// The stack adjustment, which is I8 with a function code of its own.
let private adjspExt (funct: uint32) ins =
  match ins.Operands with
  | ThreeOperands(Rg sp, Rg sp', Im value) when sp = Register.R29
                                                && sp' = Register.R29 ->
    let v = fits 16 true value
    extended (extImm v)
      (short 0b01100u ((funct <<< 8) ||| (v &&& 0x1fu)))
  | _ ->
    wrongOperands ins

/// <summary>
/// A shift by a constant, extended.
///
/// The one immediate that is not assembled the way the others are: MD00076
/// section 3.14.18 puts five bits of amount at the top of the prefix and
/// nothing of it in the instruction, and the extended form does not make the
/// zero-means-eight substitution the short one does.
/// </summary>
let private shiftExt (f: uint32) ins =
  match ins.Operands with
  | ThreeOperands(Rg rx, Rg ry, Im amount) ->
    let sa = fits 5 false amount
    extended (sa <<< 6)
      (short 0b00110u ((reg3 rx <<< 8) ||| (reg3 ry <<< 5) ||| f))
  | _ ->
    wrongOperands ins

/// The two doubleword shifts by a constant, which sit in the RR pool and name
/// their register in ry.
let private dshiftExt (funct: uint32) ins =
  match ins.Operands with
  | ThreeOperands(Rg ry, Rg ry', Im amount) when ry = ry' ->
    let sa = fits 6 false amount
    extended ((sa &&& 0b11111u) <<< 6 ||| ((sa >>> 5) <<< 5))
      (short 0b11101u ((reg3 ry <<< 5) ||| funct))
  | _ ->
    wrongOperands ins

/// <summary>
/// A branch, always extended.
///
/// Not because the offset needs the room but because it may: how far a label
/// is cannot be known until everything before it has a length, and a length
/// that depended on the answer would be circular. Sixteen bits reach
/// everywhere a MIPS16e branch can go.
///
/// The field counts halfwords from the instruction AFTER the branch, and the
/// extended form is two halfwords, which is the four taken off here. The
/// unextended form would take off two, and it is never emitted.
/// </summary>
let private branchExt (major: uint32) (rx: uint32) ins distance =
  let v = fits 16 true (uint64 (scaled 2L (distance - 4L)))
  extended (extImm v) (short major ((rx <<< 8) ||| (v &&& 0x1fu)))

let private branchZero (major: uint32) ins =
  match ins.Operands with
  | TwoOperands(Rg rx, Place distance) ->
    branchExt major (reg3 rx) ins distance
  | _ ->
    wrongOperands ins

let private branchPlain (major: uint32) ins =
  match ins.Operands with
  | OneOperand(Place distance) -> branchExt major 0u ins distance
  | _ -> wrongOperands ins

let private branchT (funct: uint32) ins =
  match ins.Operands with
  | OneOperand(Place distance) -> branchExt 0b01100u funct ins distance
  | _ -> wrongOperands ins

/// <summary>
/// The two PC-relative address instructions.
///
/// MD00076 forms the address from the instruction's own with its low two bits
/// cleared, and what arrives here is the distance from the instruction -- so
/// the two agree only where the instruction is word-aligned. An encoder sees
/// the operands and not the address, so that is the assumption made: a
/// MIPS16e instruction may sit at a halfword-odd address and one of these
/// written there would be encoded two bytes long. Every one this harness
/// assembles is word-aligned.
/// </summary>
let private pcRelExt (major: uint32) ins =
  match ins.Operands with
  | TwoOperands(Rg rx, Place distance) ->
    let v = fits 16 false (uint64 distance)
    extended (extImm v) (short major ((reg3 rx <<< 8) ||| (v &&& 0x1fu)))
  | _ ->
    wrongOperands ins

/// <summary>
/// JAL and JALX, which are two halfwords without an EXTEND in front of them.
///
/// MD00076 section 3.14.12 scatters the target: bits 20..16 where an
/// immediate's low bits would be, bits 25..21 after them, and bits 15..0 in
/// the second halfword.
/// </summary>
let private jal (x: uint32) ins =
  match ins.Operands with
  | OneOperand(Im target) ->
    let idx = uint32 (scaled 4L (int64 target))
    let upper =
      (0b00011u <<< 11) ||| (x <<< 10) ||| (((idx >>> 16) &&& 0x1fu) <<< 5)
      ||| ((idx >>> 21) &&& 0x1fu)
    (upper <<< 16) ||| (idx &&& 0xffffu)
  | _ ->
    wrongOperands ins

/// The four registers an extended SAVE or RESTORE may keep as static, which
/// are the ones a call passes its arguments in.
let private argRegisters =
  [ Register.R4
    Register.R5
    Register.R6
    Register.R7 ]

/// The seven a source names through the xsregs field, which MD00076 writes
/// as nested conditions rather than as a set.
let private statics =
  [ Register.R18
    Register.R19
    Register.R20
    Register.R21
    Register.R22
    Register.R23
    Register.R30 ]

/// <summary>
/// The eight registers a three-bit field reaches.
///
/// What tells MOVE's two forms apart: the side that is one of these is the
/// side written in three bits, and the other is the one the encoding spends
/// five on.
/// </summary>
let private reachable =
  [ Register.R16
    Register.R17
    Register.R2
    Register.R3
    Register.R4
    Register.R5
    Register.R6
    Register.R7 ]

/// MOVE, whose two forms differ in which side holds the five-bit field.
let private move ins =
  match ins.Operands with
  | TwoOperands(Rg dst, Rg src) ->
    if List.contains dst reachable then
      short 0b01100u ((0b111u <<< 8) ||| (reg3 dst <<< 5) ||| gpr src)
    else
      short 0b01100u ((0b101u <<< 8) ||| (rotated dst <<< 3) ||| reg3 src)
  | _ ->
    wrongOperands ins

/// <summary>
/// SAVE and RESTORE, always extended.
///
/// The short form reaches only three registers and a four-bit frame; the
/// extended one reaches the static and argument sets as well, and writing it
/// always means one encoder rather than two and a rule for choosing.
/// </summary>
let private svrs (s: uint32) ins =
  let frame, args, saved =
    match ins.Operands with
    | ThreeOperands(Im f, OpRegList a, OpRegList sv) -> f, a, sv
    (* What a source writes has one list, not two: which of $4 to $7 arrived
       as arguments and which are being kept is not in the text, and a
       prologue that saves neither -- which is every one the short form can
       write -- needs no way to say. *)
    | TwoOperands(Im f, OpRegList sv) -> f, [], sv
    | OneOperand(Im f) -> f, [], []
    | _ -> wrongOperands ins |> ignore; 0UL, [], []
  match [ OpImm frame ] with
  | _ ->
    let kept =
      argRegisters |> List.filter (fun r -> List.contains r saved)
    let xs = statics |> List.filter (fun r -> List.contains r saved)
    let aregs =
      match List.length args, List.length kept with
      | 0, 0 -> 0b0000u
      | 0, 1 -> 0b0001u
      | 0, 2 -> 0b0010u
      | 0, 3 -> 0b0011u
      | 0, 4 -> 0b1011u
      | 1, 0 -> 0b0100u
      | 1, 1 -> 0b0101u
      | 1, 2 -> 0b0110u
      | 1, 3 -> 0b0111u
      | 2, 0 -> 0b1000u
      | 2, 1 -> 0b1001u
      | 2, 2 -> 0b1010u
      | 3, 0 -> 0b1100u
      | 3, 1 -> 0b1101u
      | 4, 0 -> 0b1110u
      | _ -> fail "no MIPS16e aregs encoding names that pair of sets"
    let f = fits 8 false (uint64 (scaled 8L (int64 frame)))
    let hiFrame = ((f >>> 4) &&& 0xfu) <<< 4
    let upper = (uint32 (List.length xs) <<< 8) ||| hiFrame ||| aregs
    let lower =
      short 0b01100u
        ((0b100u <<< 8) ||| (s <<< 7) ||| svrsFlags saved ||| (f &&& 0xfu))
    extended upper lower

/// <summary>
/// The jumps of the RR pool, whose ry field says which of the six it is.
///
/// JR and JRC come in two forms and the field tells them apart: through a
/// register the field names, or through $31, which it does not -- so the
/// second form's rx is not a register number and MD00076 requires it to be
/// zero.
/// </summary>
let private jump (sub: uint32) ins =
  match ins.Operands with
  | OneOperand(Rg ra) when ra = Register.R31 ->
    short 0b11101u ((sub + 1u) <<< 5)
  | OneOperand(Rg rx) ->
    short 0b11101u ((reg3 rx <<< 8) ||| (sub <<< 5))
  | TwoOperands(Rg ra, Rg rx) when ra = Register.R31 ->
    short 0b11101u ((reg3 rx <<< 8) ||| (sub <<< 5))
  | _ ->
    wrongOperands ins

/// BREAK and SDBBP, whose six-bit code fills the two register fields.
let private coded (funct: uint32) ins =
  match ins.Operands with
  | OneOperand(Im code) -> short 0b11101u ((fits 6 false code <<< 5) ||| funct)
  | NoOperand -> short 0b11101u funct
  | _ -> wrongOperands ins

/// NOP, which MD00076 lists as an instruction and which is MOVE of $16 into
/// $0.
let private nop ins =
  match ins.Operands with
  | NoOperand -> 0x6500u
  | _ -> wrongOperands ins

/// ASMACRO, whose fields are the implementation's to read and this
/// assembler's only to carry.
let private asmacro ins = wrongOperands ins

/// <summary>
/// How many bytes an instruction takes.
///
/// It follows from the opcode and the operand shape alone, never from the
/// VALUE of an operand: the extended form is written wherever there is one,
/// so the only two-byte instructions are the ones with no extended form at
/// all. That is what lets the addresses of a whole source be worked out
/// before any of it is encoded.
/// </summary>
let size ins =
  match ins.Opcode with
  | Opcode.JAL | Opcode.JALX
  | Opcode.ADDIU | Opcode.DADDIU | Opcode.ADDIUPC | Opcode.DADDIUPC
  | Opcode.B | Opcode.BEQZ | Opcode.BNEZ | Opcode.BTEQZ | Opcode.BTNEZ
  | Opcode.CMPI | Opcode.LI | Opcode.SLTI | Opcode.SLTIU
  | Opcode.LB | Opcode.LBU | Opcode.LH | Opcode.LHU | Opcode.LW
  | Opcode.LWU | Opcode.LD | Opcode.SB | Opcode.SH | Opcode.SW | Opcode.SD
  | Opcode.SLL | Opcode.SRL | Opcode.SRA
  | Opcode.DSLL | Opcode.DSRL | Opcode.DSRA
  | Opcode.SAVE | Opcode.RESTORE ->
    4
  | _ ->
    2

/// <summary>
/// The bytes an encoded instruction is stored as.
///
/// A four-byte instruction is two halfwords and the one holding the prefix or
/// the major opcode is stored first, so the word cannot simply be written out
/// in the endianness of the target: that would put the halves the wrong way
/// round.
/// </summary>
let toBytes endian length (word: uint32) =
  let half (value: uint32) =
    let bytes = [| byte value; byte (value >>> 8) |]
    if endian = Endian.Big then Array.rev bytes else bytes
  if length = 2 then half word
  else Array.append (half (word >>> 16)) (half (word &&& 0xffffu))

/// <summary>
/// The I64 pool, which MIPS64 puts at major opcode 0b11111.
///
/// Its layout is not the one every other major opcode has: bits 10..8 hold a
/// FUNCTION code and the register moves down to 7..5, because eight
/// doubleword forms share the one opcode. Writing the register where the
/// other majors keep it -- which is what this did first -- encodes a
/// different instruction of the same pool, and the sweep read back LD where
/// the source said DADDIU.
/// </summary>
let private i64Ext (funct: uint32) (ry: uint32) (v: uint32) =
  extended (extImm v)
    (short 0b11111u ((funct <<< 8) ||| (ry <<< 5) ||| (v &&& 0x1fu)))

/// A doubleword load or store on the stack pointer.
let private i64MemSp (funct: uint32) ins =
  match ins.Operands with
  | TwoOperands(Rg ry, Mem(bse, offset)) when bse = Register.R29 ->
    i64Ext funct (reg3 ry) (fits 16 true (uint64 offset))
  | _ ->
    wrongOperands ins

/// The store of the return address, which names no register the field can
/// hold and spends the whole immediate instead.
let private i64SdRa ins =
  match ins.Operands with
  | TwoOperands(Rg ra, Mem(bse, offset)) when ra = Register.R31
                                              && bse = Register.R29 ->
    let v = fits 16 true (uint64 offset)
    extended (extImm v) (short 0b11111u ((0b010u <<< 8) ||| (v &&& 0x1fu)))
  | _ ->
    wrongOperands ins

/// The doubleword stack adjustment.
let private i64AdjSp ins =
  match ins.Operands with
  | ThreeOperands(Rg sp, Rg sp', Im value) when sp = Register.R29
                                                && sp' = Register.R29 ->
    let v = fits 16 true value
    extended (extImm v) (short 0b11111u ((0b011u <<< 8) ||| (v &&& 0x1fu)))
  | _ ->
    wrongOperands ins

/// The doubleword load relative to the program counter.
let private i64LdPc ins =
  match ins.Operands with
  | TwoOperands(Rg ry, Place distance) ->
    i64Ext 0b100u (reg3 ry) (fits 16 false (uint64 distance))
  | _ ->
    wrongOperands ins

/// DADDIU of a register and itself.
let private i64Daddiu5 ins =
  match ins.Operands with
  | ThreeOperands(Rg ry, Rg ry', Im value) when ry = ry' ->
    i64Ext 0b101u (reg3 ry) (fits 16 true value)
  | _ ->
    wrongOperands ins

/// DADDIU relative to the program counter.
let private i64DaddiuPc ins =
  match ins.Operands with
  | TwoOperands(Rg ry, Place distance) ->
    i64Ext 0b110u (reg3 ry) (fits 16 false (uint64 distance))
  | _ ->
    wrongOperands ins

/// DADDIU of a register and the stack pointer.
let private i64DaddiuSp ins =
  match ins.Operands with
  | ThreeOperands(Rg ry, Rg sp, Im value) when sp = Register.R29 ->
    i64Ext 0b111u (reg3 ry) (fits 16 true value)
  | _ ->
    wrongOperands ins

/// <summary>
/// ADDIU, whose five forms are told apart by their operands and not by
/// anything in the text.
///
/// MD00076 spends three major opcodes and one I8 function code on them,
/// because what each adds to is different: the stack pointer, the program
/// counter, another register, or the register written.
/// </summary>
let private addiu ins =
  match ins.Operands with
  | ThreeOperands(Rg sp, Rg sp', Im _) when sp = Register.R29
                                            && sp' = Register.R29 ->
    adjspExt 0b011u ins
  | ThreeOperands(Rg _, Rg sp, Im _) when sp = Register.R29 ->
    spRelExt 0b00000u ins
  | ThreeOperands(Rg rx, Rg rx', Im _) when rx = rx' ->
    addiu8Ext ins
  | _ ->
    rriaExt 0u ins

/// DADDIU, which MIPS64 gives the same four shapes.
let private daddiu ins =
  match ins.Operands with
  | ThreeOperands(Rg sp, Rg sp', Im _) when sp = Register.R29
                                            && sp' = Register.R29 ->
    i64AdjSp ins
  | ThreeOperands(Rg _, Rg sp, Im _) when sp = Register.R29 ->
    i64DaddiuSp ins
  | ThreeOperands(Rg ry, Rg ry', Im _) when ry = ry' ->
    i64Daddiu5 ins
  | _ ->
    rriaExt 1u ins

/// <summary>
/// The store of the return address on the stack, which MD00076 gives an I8
/// function code of its own.
///
/// It has to: $31 is not one of the eight a three-bit field reaches, and
/// saving it is what every function prologue does.
/// </summary>
let private swraspExt ins =
  match ins.Operands with
  | TwoOperands(Rg ra, Mem(bse, offset)) when ra = Register.R31
                                              && bse = Register.R29 ->
    let v = fits 16 true (uint64 offset)
    extended (extImm v) (short 0b01100u ((0b010u <<< 8) ||| (v &&& 0x1fu)))
  | _ ->
    wrongOperands ins

/// The same for the doubleword, which MIPS64 puts in the I64 pool.
let private sdraspExt ins =
  match ins.Operands with
  | TwoOperands(Rg ra, Mem(bse, offset)) when ra = Register.R31
                                              && bse = Register.R29 ->
    let v = fits 16 true (uint64 offset)
    extended (extImm v) (short 0b11111u ((0b010u <<< 8) ||| (v &&& 0x1fu)))
  | _ ->
    wrongOperands ins

/// A load or a store, whose base decides which of the three forms it is.
let private memory (onReg: uint32) (onSp: uint32) ins =
  match ins.Operands with
  | TwoOperands(_, Mem(bse, _)) when bse = Register.R29 -> memSpExt onSp ins
  | _ -> memExt onReg ins

/// <summary>
/// The loads and stores, whose base decides which of the three forms each is:
/// a register, the stack pointer, or the program counter.
///
/// The last is not written with a base at all -- the disassembler prints the
/// address it resolved -- so it arrives as a place and not as a memory
/// operand, which is what tells it apart here.
/// </summary>
let private memoryWith onReg onSp onPc ins =
  match ins.Operands with
  (* The two that name the return address are neither of the other forms:
     $31 is not one of the eight a three-bit field reaches, so each has a
     function code of its own. They arrive with a memory operand all the
     same, which is why they are told apart by the register. *)
  | TwoOperands(Rg ra, Mem(bse, _)) when ra = Register.R31
                                         && bse = Register.R29 ->
    onPc ins
  | TwoOperands(_, Mem(bse, _)) when bse = Register.R29 ->
    onSp ins
  | TwoOperands(_, Place _) ->
    onPc ins
  | _ ->
    onReg ins

/// LW and SW, whose three forms are a register base, the stack pointer, and
/// the program counter -- the last of which SW reaches only by naming the
/// return address, there being nothing to store relative to the PC.
let private lw =
  memoryWith (memExt 0b10011u) (memSpExt 0b10010u) (pcRelExt 0b10110u)

let private sw = memoryWith (memExt 0b11011u) (memSpExt 0b11010u) swraspExt

/// The doubleword pair, whose stack and PC forms live in the I64 pool.
let private ld = memoryWith (memExt 0b00111u) (i64MemSp 0b000u) i64LdPc

let private sd = memoryWith (memExt 0b01111u) (i64MemSp 0b001u) i64SdRa

/// Builds the lookup from an opcode to the encoder for it.
let buildEncoderTable (_release: MIPSRelease) =
  [ Opcode.ADDIU, addiu
    Opcode.DADDIU, daddiu
    Opcode.ADDIUPC, pcRelExt 0b00001u
    Opcode.DADDIUPC, i64DaddiuPc
    Opcode.ADDU, rrr 0b01u
    Opcode.SUBU, rrr 0b11u
    Opcode.DADDU, rrr 0b00u
    Opcode.DSUBU, rrr 0b10u
    Opcode.AND, rrAccum 0b01100u
    Opcode.OR, rrAccum 0b01101u
    Opcode.XOR, rrAccum 0b01110u
    Opcode.NOT, rrPair 0b01111u
    Opcode.NEG16, rrPair 0b01011u
    Opcode.CMP16, rrPair 0b01010u
    Opcode.SLT, rrPair 0b00010u
    Opcode.SLTU, rrPair 0b00011u
    Opcode.SLLV, rrShiftVar 0b00100u
    Opcode.SRLV, rrShiftVar 0b00110u
    Opcode.SRAV, rrShiftVar 0b00111u
    Opcode.DSLLV, rrShiftVar 0b10100u
    Opcode.DSRLV, rrShiftVar 0b10110u
    Opcode.DSRAV, rrShiftVar 0b10111u
    Opcode.MULT, rrPair 0b11000u
    Opcode.MULTU, rrPair 0b11001u
    Opcode.DIV, rrPair 0b11010u
    Opcode.DIVU, rrPair 0b11011u
    Opcode.DMULT, rrPair 0b11100u
    Opcode.DMULTU, rrPair 0b11101u
    Opcode.DDIV, rrPair 0b11110u
    Opcode.DDIVU, rrPair 0b11111u
    Opcode.MFHI, rrOne 0b10000u 0u
    Opcode.MFLO, rrOne 0b10010u 0u
    Opcode.ZEB, rrOne 0b10001u 0b000u
    Opcode.ZEH, rrOne 0b10001u 0b001u
    Opcode.ZEW, rrOne 0b10001u 0b010u
    Opcode.SEB, rrOne 0b10001u 0b100u
    Opcode.SEH, rrOne 0b10001u 0b101u
    Opcode.SEW, rrOne 0b10001u 0b110u
    Opcode.JR, jump 0b000u
    Opcode.JALR, jump 0b010u
    Opcode.JRC, jump 0b100u
    Opcode.JALRC, jump 0b110u
    Opcode.BREAK, coded 0b00101u
    Opcode.SDBBP, coded 0b00001u
    Opcode.NOP, nop
    Opcode.MOVE, move
    Opcode.LI, riExt 0b01101u
    Opcode.CMPI, riExt 0b01110u
    Opcode.SLTI, riExt 0b01010u
    Opcode.SLTIU, riExt 0b01011u
    Opcode.SLL, shiftExt 0b00u
    Opcode.DSLL, shiftExt 0b01u
    Opcode.SRL, shiftExt 0b10u
    Opcode.SRA, shiftExt 0b11u
    Opcode.DSRL, dshiftExt 0b01000u
    Opcode.DSRA, dshiftExt 0b10011u
    Opcode.LB, memory 0b10000u 0b10000u
    Opcode.LBU, memory 0b10100u 0b10100u
    Opcode.LH, memory 0b10001u 0b10001u
    Opcode.LHU, memory 0b10101u 0b10101u
    Opcode.LW, lw
    Opcode.LWU, memory 0b10111u 0b10111u
    Opcode.SB, memory 0b11000u 0b11000u
    Opcode.SH, memory 0b11001u 0b11001u
    Opcode.SW, sw
    Opcode.LD, ld
    Opcode.SD, sd
    (* The two names this encoding spends on instructions the base
       architecture spends on floating-point ones. A source written for
       MIPS16e says `cmp` and `neg` and means these; the mnemonic table is
       the disassembler's and answers with the floating-point opcodes, so
       both are claimed here. *)
    Opcode.CMP, rrPair 0b01010u
    Opcode.NEG, rrPair 0b01011u
    Opcode.B, branchPlain 0b00010u
    Opcode.BEQZ, branchZero 0b00100u
    Opcode.BNEZ, branchZero 0b00101u
    Opcode.BTEQZ, branchT 0b000u
    Opcode.BTNEZ, branchT 0b001u
    Opcode.JAL, jal 0u
    Opcode.JALX, jal 1u
    Opcode.SAVE, svrs 1u
    Opcode.RESTORE, svrs 0u
    Opcode.ASMACRO, asmacro ]
  |> Map.ofList

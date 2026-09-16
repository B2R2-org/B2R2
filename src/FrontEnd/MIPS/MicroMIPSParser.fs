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
/// The microMIPS64 decoder, which is the architecture's other encoding of its
/// own instruction set rather than an extension of it.
///
/// A processor is in one encoding or the other at any moment, and what it
/// decodes says nothing about what it does: a microMIPS ADDU is the ADDU the
/// lifter already knows. So this file produces the opcodes that are already
/// in <c>Opcode.fs</c> and nothing here reaches the lifter at all. Where the
/// encoding names something MIPS64 writes another way -- MOVE16 is OR with
/// the zero register, LI16 is ADDIU from it -- the MIPS64 form is what comes
/// out, because that is the instruction.
///
/// Two revisions are covered, the way the rest of this front end covers two:
/// a `release` parameter, and arms guarded on it where the two disagree.
/// MD00594 revision 5.04 gives the pre-Release 6 encoding and revision 6.01
/// the Release 6 one; Release 6 moved several pools and took JALX away.
/// </summary>
module internal B2R2.FrontEnd.MIPS.MicroMIPSParser

open B2R2
open B2R2.FrontEnd.BinLifter

/// <summary>
/// The general register a three-bit field names.
///
/// Eight of the thirty-two are reachable this way and the numbering is not
/// the architecture's: MD00594 Table 5.4 maps 0 and 1 onto $16 and $17 and
/// the rest onto $2 to $7. Reading the field as a register number would name
/// the wrong register every time.
/// </summary>
let private reg3 = function
  | 0u -> R.R16
  | 1u -> R.R17
  | 2u -> R.R2
  | 3u -> R.R3
  | 4u -> R.R4
  | 5u -> R.R5
  | 6u -> R.R6
  | _ -> R.R7

/// <summary>
/// The same field where a store names its source.
///
/// MD00594 Table 5.5 differs from Table 5.4 in one entry: SB16, SH16 and
/// SW16 can store the zero register, so 0 is $0 there and $16 is not
/// reachable. Storing a constant zero is worth more to a compiler than
/// storing a callee-saved register.
/// </summary>
let private reg3Store = function
  | 0u -> R.R0
  | 1u -> R.R17
  | 2u -> R.R2
  | 3u -> R.R3
  | 4u -> R.R4
  | 5u -> R.R5
  | 6u -> R.R6
  | _ -> R.R7

/// The general register a five-bit field names, which is the architecture's
/// own numbering: the wide fields reach all thirty-two.
let private reg5 (n: uint32) = Helper.getRegister (byte n)

let private oprReg r = OpReg r

let private imm (v: uint64) = OpImm v

/// <summary>
/// Whether the halfword begins a 16-bit instruction.
///
/// MD00594: "The instruction size can be completely derived from the major
/// opcode." The major opcode is bits 15..10, and Table 7.2 indexes it as a
/// grid whose ROW is bits 12..10 and whose column is bits 15..13; rows 1, 2
/// and 3 hold every 16-bit form and no other row holds any.
/// </summary>
let isHalfword (h: uint16) =
  match (uint32 h >>> 10) &&& 0b111u with
  | 1u | 2u | 3u -> true
  | _ -> false

/// <summary>
/// The value a three-bit immediate stands for in ADDIUR2.
///
/// MD00594 Table 5.9. The field is not the number: it selects one of eight,
/// seven of them small multiples of four and the eighth minus one.
/// </summary>
let private addiur2Imm = function
  | 0u -> 1L
  | 1u -> 4L
  | 2u -> 8L
  | 3u -> 12L
  | 4u -> 16L
  | 5u -> 20L
  | 6u -> 24L
  | _ -> -1L

/// <summary>
/// The value ADDIUSP's nine-bit immediate stands for.
///
/// MD00594 Table 5.10, which is a rotation rather than a range: 0 and 1 mean
/// 256 and 257, the middle of the field means itself, and the top quarter is
/// negative -- with 510 and 511 meaning -258 and -257 rather than continuing
/// downwards. Every value is a multiple of four once shifted, which is what
/// makes it a stack adjustment.
/// </summary>
let private addiuspImm (v: uint32) =
  let raw =
    match v with
    | 0u -> 256L
    | 1u -> 257L
    | 510u -> -258L
    | 511u -> -257L
    | v when v < 256u -> int64 v
    | v -> int64 v - 512L
  raw <<< 2

/// <summary>
/// The value LI16's seven-bit immediate stands for: itself, except that the
/// top of the range is minus one. MD00594 Table 5.12.
/// </summary>
let private li16Imm (v: uint32) = if v = 0x7Fu then -1L else int64 v

/// <summary>
/// The value a four-bit load or store offset stands for: itself, except that
/// the top of the range is minus one. MD00594 Table 5.11.
/// </summary>
let private off4 (v: uint32) = if v = 0xFu then -1L else int64 v

/// <summary>
/// The value ANDI16's four-bit immediate stands for.
///
/// MD00594's table under ANDI16. The sixteen values are the masks a compiler
/// actually emits -- the low bit runs, the byte and halfword masks, and the
/// two sign bits -- rather than a range.
/// </summary>
let private andi16Imm = function
  | 0u -> 128UL
  | 1u -> 1UL
  | 2u -> 2UL
  | 3u -> 3UL
  | 4u -> 4UL
  | 5u -> 7UL
  | 6u -> 8UL
  | 7u -> 15UL
  | 8u -> 16UL
  | 9u -> 31UL
  | 10u -> 32UL
  | 11u -> 63UL
  | 12u -> 64UL
  | 13u -> 255UL
  | 14u -> 32768UL
  | _ -> 65535UL

let private bits (h: uint32) hi lo =
  (h >>> int lo) &&& ((1u <<< int (hi - lo + 1u)) - 1u)

/// A branch offset, which every 16-bit form holds as a halfword count.
let private rel (v: int64) = OpAddr(Relative((v <<< 1) + 2L))

/// Sign-extends an n-bit field.
let private signed n (v: uint32) =
  let m = 1L <<< (n - 1)
  ((int64 v ^^^ m) - m)

/// <summary>
/// A register-to-register operation of POOL16A and POOL16B.
///
/// The field order is NOT the one the pool's own page appears to give: the
/// destination is the topmost field. Checked against binutils, which encodes
/// <c>subu $2, $3, $4</c> as 0x0547 -- 9..7 holding 2, 6..4 holding 4 and
/// 3..1 holding 3.
/// </summary>
let private pool16A h =
  let rd = reg3 (bits h 9u 7u) |> oprReg
  let rt = reg3 (bits h 6u 4u) |> oprReg
  let rs = reg3 (bits h 3u 1u) |> oprReg
  let opcode = if bits h 0u 0u = 0u then Op.ADDU else Op.SUBU
  opcode, None, None, ThreeOperands(rd, rs, rt)

let private pool16B h =
  let rd = reg3 (bits h 9u 7u) |> oprReg
  let rt = reg3 (bits h 6u 4u) |> oprReg
  (* A shift of zero would be a no-operation, so the field holds eight rather
     than zero and the other seven stand for themselves. *)
  let sa = let v = bits h 3u 1u in if v = 0u then 8UL else uint64 v
  let opcode = if bits h 0u 0u = 0u then Op.SLL else Op.SRL
  opcode, None, None, ThreeOperands(rd, rt, OpShiftAmount sa)

let private pool16D h =
  if bits h 0u 0u = 0u then
    let rd = reg5 (bits h 9u 5u) |> oprReg
    let v = signed 4 (bits h 4u 1u)
    Op.ADDIU, None, None, ThreeOperands(rd, rd, imm (uint64 v))
  else
    let sp = oprReg R.R29
    let v = addiuspImm (bits h 9u 1u)
    Op.ADDIU, None, None, ThreeOperands(sp, sp, imm (uint64 v))

let private pool16E h =
  if bits h 0u 0u = 0u then
    let rd = reg3 (bits h 9u 7u) |> oprReg
    let rs = reg3 (bits h 6u 4u) |> oprReg
    let v = addiur2Imm (bits h 3u 1u)
    Op.ADDIU, None, None, ThreeOperands(rd, rs, imm (uint64 v))
  else
    let rd = reg3 (bits h 9u 7u) |> oprReg
    let v = int64 (bits h 6u 1u) <<< 2
    let oprs = ThreeOperands(rd, oprReg R.R29, imm (uint64 v))
    Op.ADDIU, None, None, oprs

/// <summary>
/// The registers a two-bit list field names.
///
/// A list is always the callee-saved registers counted from the lowest with
/// the return address last, which is what a prologue saves and an epilogue
/// restores, so two bits are enough to say how many.
/// </summary>
let private regList = function
  | 0u -> [ R.R16; R.R31 ]
  | 1u -> [ R.R16; R.R17; R.R31 ]
  | 2u -> [ R.R16; R.R17; R.R18; R.R31 ]
  | _ -> [ R.R16; R.R17; R.R18; R.R19; R.R31 ]

/// <summary>
/// The general register MOVEP's two source fields name.
///
/// It is a set of its own, not the one Table 5.4 gives: the zero register is
/// reachable where Table 5.4 has $16, and $18 to $20 are reachable where it
/// has $4 to $7. Checked against binutils, which takes $0, $2, $3 and $16 to
/// $20 in these fields and rejects every other register.
/// </summary>
let private movepReg = function
  | 0u -> R.R0
  | 1u -> R.R17
  | 2u -> R.R2
  | 3u -> R.R3
  | 4u -> R.R16
  | 5u -> R.R18
  | 6u -> R.R19
  | _ -> R.R20

/// <summary>
/// The register pair MOVEP's three-bit destination field names.
///
/// The eight are the argument registers a call sets up, taken two at a time
/// in the combinations a compiler emits, so the field is a choice of eight
/// rather than a register number.
/// </summary>
let private movepPair = function
  | 0u -> R.R5, R.R6
  | 1u -> R.R5, R.R7
  | 2u -> R.R6, R.R7
  | 3u -> R.R4, R.R21
  | 4u -> R.R4, R.R22
  | 5u -> R.R4, R.R5
  | 6u -> R.R4, R.R6
  | _ -> R.R4, R.R7

/// MOVEP, whose two destinations come from one field and whose two sources
/// have a field each.
let private movep h rsField =
  let rd, re = movepPair (bits h 9u 7u)
  let rt = movepReg (bits h 6u 4u) |> oprReg
  let rs = movepReg rsField |> oprReg
  let oprs = FourOperands(oprReg rd, oprReg re, rs, rt)
  Op.MOVEP, None, None, oprs

/// A load or store multiple, whose base is the stack pointer and whose
/// offset counts words.
let private memMultiple opcode list off =
  let mem = OpMem(R.R29, Imm(int64 off <<< 2), 32<rt>)
  opcode, None, None, TwoOperands(OpRegList(regList list), mem)

/// <summary>
/// POOL16C before Release 6, whose minor opcode is the TOP of what the major
/// leaves.
///
/// Minor opcodes in the 16-bit encodings are left-aligned, so the field the
/// pool is read from grows downwards from bit 9 as the instruction needs
/// fewer operand bits: four bits for the ones taking two registers, five for
/// the ones taking one, six for the ones taking none.
/// </summary>
let private pool16C h =
  match bits h 9u 6u with
  | 0b0000u ->
    (* NOT16 is NOR against the zero register, which is how MIPS64 writes it
       too. *)
    let rt = reg3 (bits h 5u 3u) |> oprReg
    let rs = reg3 (bits h 2u 0u) |> oprReg
    Op.NOR, None, None, ThreeOperands(rt, rs, oprReg R.R0)
  | 0b0001u ->
    let rt = reg3 (bits h 5u 3u) |> oprReg
    let rs = reg3 (bits h 2u 0u) |> oprReg
    Op.XOR, None, None, ThreeOperands(rt, rt, rs)
  | 0b0010u ->
    let rt = reg3 (bits h 5u 3u) |> oprReg
    let rs = reg3 (bits h 2u 0u) |> oprReg
    Op.AND, None, None, ThreeOperands(rt, rt, rs)
  | 0b0011u ->
    let rt = reg3 (bits h 5u 3u) |> oprReg
    let rs = reg3 (bits h 2u 0u) |> oprReg
    Op.OR, None, None, ThreeOperands(rt, rt, rs)
  | 0b0100u ->
    memMultiple Op.LWM (bits h 5u 4u) (bits h 3u 0u)
  | 0b0101u ->
    memMultiple Op.SWM (bits h 5u 4u) (bits h 3u 0u)
  | _ ->
    match bits h 9u 5u with
    | 0b01100u ->
      Op.JR, None, None, OneOperand(reg5 (bits h 4u 0u) |> oprReg)
    | 0b01101u ->
      Op.JRC, None, None, OneOperand(reg5 (bits h 4u 0u) |> oprReg)
    | 0b01110u ->
      Op.JALR, None, None, OneOperand(reg5 (bits h 4u 0u) |> oprReg)
    | 0b01111u ->
      Op.JALRS, None, None, OneOperand(reg5 (bits h 4u 0u) |> oprReg)
    | 0b10000u ->
      Op.MFHI, None, None, OneOperand(reg5 (bits h 4u 0u) |> oprReg)
    | 0b10010u ->
      Op.MFLO, None, None, OneOperand(reg5 (bits h 4u 0u) |> oprReg)
    | 0b11000u ->
      Op.JRADDIUSP, None, None, OneOperand(imm (uint64 (bits h 4u 0u) <<< 2))
    | _ ->
      match bits h 9u 4u with
      | 0b101000u ->
        Op.BREAK, None, None, OneOperand(imm (uint64 (bits h 3u 0u)))
      | 0b101100u ->
        Op.SDBBP, None, None, OneOperand(imm (uint64 (bits h 3u 0u)))
      | _ ->
        raise ParsingFailureException

/// <summary>
/// POOL16C from Release 6, whose minor opcode is the BOTTOM of the halfword.
///
/// Release 6 recoded the pool the way the 32-bit encodings already were,
/// with the minor opcode right-aligned and the operands above it. Nothing
/// but the position moved for most of them; JRADDIUSP became the compact
/// JRCADDIUSP, and MOVEP came in from POOL16F.
/// </summary>
let private pool16CR6 h =
  if bits h 2u 2u = 1u then
    movep h ((bits h 3u 3u <<< 2) ||| bits h 1u 0u)
  elif bits h 1u 0u = 0b11u then
    match bits h 4u 3u with
    | 0b00u ->
      Op.JRC, None, None, OneOperand(reg5 (bits h 9u 5u) |> oprReg)
    | 0b01u ->
      Op.JALRC, None, None, OneOperand(reg5 (bits h 9u 5u) |> oprReg)
    | 0b10u ->
      let adjust = OneOperand(imm (uint64 (bits h 9u 5u) <<< 2))
      Op.JRCADDIUSP, None, None, adjust
    | _ ->
      let code = imm (uint64 (bits h 9u 6u))
      let opcode = if bits h 5u 5u = 0u then Op.BREAK else Op.SDBBP
      opcode, None, None, OneOperand code
  else
    let rt = reg3 (bits h 9u 7u) |> oprReg
    let rs = reg3 (bits h 6u 4u) |> oprReg
    match bits h 3u 0u with
    | 0b0000u ->
      Op.NOR, None, None, ThreeOperands(rt, rs, oprReg R.R0)
    | 0b0001u ->
      Op.AND, None, None, ThreeOperands(rt, rt, rs)
    | 0b0010u ->
      memMultiple Op.LWM (bits h 9u 8u) (bits h 7u 4u)
    | 0b1000u ->
      Op.XOR, None, None, ThreeOperands(rt, rt, rs)
    | 0b1001u ->
      Op.OR, None, None, ThreeOperands(rt, rt, rs)
    | 0b1010u ->
      memMultiple Op.SWM (bits h 9u 8u) (bits h 7u 4u)
    | _ ->
      raise ParsingFailureException

/// A load or store whose base and offset are three and four bits wide, with
/// the offset scaled by the width of the access.
let private mem3 h opcode shift (regOf: uint32 -> Register) width =
  let rt = regOf (bits h 9u 7u) |> oprReg
  let bse = reg3 (bits h 6u 4u)
  let off = off4 (bits h 3u 0u) <<< shift
  opcode, None, None, TwoOperands(rt, OpMem(bse, Imm off, width))

/// A load or store relative to the stack pointer, whose register field is
/// five bits wide and whose offset is a word count.
let private memSP h opcode =
  let rt = reg5 (bits h 9u 5u) |> oprReg
  let off = int64 (bits h 4u 0u) <<< 2
  opcode, None, None, TwoOperands(rt, OpMem(R.R29, Imm off, 32<rt>))

/// <summary>
/// One 16-bit instruction.
///
/// Every arm produces the MIPS64 opcode the encoding stands for, so that
/// nothing downstream has to know which encoding it came from.
/// </summary>
let private parseHalfword (release: MIPSRelease) (h: uint32) =
  match bits h 15u 10u with
  | 0b000001u ->
    pool16A h
  | 0b001001u ->
    pool16B h
  | 0b010001u ->
    if release = MIPSRelease.R6 then pool16CR6 h else pool16C h
  | 0b100001u when release <> MIPSRelease.R6 ->
    (* POOL16F holds MOVEP alone, and Release 6 emptied it by moving that
       one into POOL16C. *)
    if bits h 0u 0u = 0u then movep h (bits h 3u 1u)
    else raise ParsingFailureException
  | 0b011001u ->
    (* LWGP: the base is the global pointer and has no field of its own. *)
    let rt = reg3 (bits h 9u 7u) |> oprReg
    let off = int64 (bits h 6u 0u) <<< 2
    Op.LW, None, None, TwoOperands(rt, OpMem(R.R28, Imm off, 32<rt>))
  | 0b000010u ->
    mem3 h Op.LBU 0 reg3 8<rt>
  | 0b001010u ->
    mem3 h Op.LHU 1 reg3 16<rt>
  | 0b010010u ->
    memSP h Op.LW
  | 0b011010u ->
    mem3 h Op.LW 2 reg3 32<rt>
  | 0b100010u ->
    mem3 h Op.SB 0 reg3Store 8<rt>
  | 0b101010u ->
    mem3 h Op.SH 1 reg3Store 16<rt>
  | 0b110010u ->
    memSP h Op.SW
  | 0b111010u ->
    mem3 h Op.SW 2 reg3Store 32<rt>
  | 0b000011u ->
    (* MOVE16 reaches all thirty-two registers, which is why its two fields
       are five bits wide. MIPS64 writes the same thing as an OR with the
       zero register, and that is the instruction this is. *)
    let rd = reg5 (bits h 9u 5u) |> oprReg
    let rs = reg5 (bits h 4u 0u) |> oprReg
    Op.OR, None, None, ThreeOperands(rd, rs, oprReg R.R0)
  | 0b001011u ->
    let rd = reg3 (bits h 9u 7u) |> oprReg
    let rs = reg3 (bits h 6u 4u) |> oprReg
    let oprs = ThreeOperands(rd, rs, imm (andi16Imm (bits h 3u 0u)))
    Op.ANDI, None, None, oprs
  | 0b010011u ->
    pool16D h
  | 0b011011u ->
    pool16E h
  | 0b100011u ->
    let rs = reg3 (bits h 9u 7u) |> oprReg
    let off = rel (signed 7 (bits h 6u 0u))
    if release = MIPSRelease.R6 then
      Op.BEQZC, None, None, TwoOperands(rs, off)
    else
      (* Before Release 6 the comparison against zero has no encoding of its
         own, so this is the ordinary branch with the zero register named. *)
      Op.BEQ, None, None, ThreeOperands(rs, oprReg R.R0, off)
  | 0b101011u ->
    let rs = reg3 (bits h 9u 7u) |> oprReg
    let off = rel (signed 7 (bits h 6u 0u))
    if release = MIPSRelease.R6 then
      Op.BNEZC, None, None, TwoOperands(rs, off)
    else
      (* Before Release 6 the comparison against zero has no encoding of its
         own, so this is the ordinary branch with the zero register named. *)
      Op.BNE, None, None, ThreeOperands(rs, oprReg R.R0, off)
  | 0b110011u ->
    (* Release 6 made the unconditional one compact, which is a different
       instruction and not a different name: B16 has a delay slot and BC16
       has none. *)
    let off = rel (signed 10 (bits h 9u 0u))
    let opcode = if release = MIPSRelease.R6 then Op.BC else Op.B
    opcode, None, None, OneOperand off
  | 0b111011u ->
    let rd = reg3 (bits h 9u 7u) |> oprReg
    let v = li16Imm (bits h 6u 0u)
    let oprs = ThreeOperands(rd, oprReg R.R0, imm (uint64 v))
    Op.ADDIU, None, None, oprs
  | _ ->
    raise ParsingFailureException

/// <summary>
/// The general register the topmost wide field names.
///
/// This is where the 32-bit encodings begin. A word holds rt, rs and rd in
/// that order from the top, which is NOT the order the older encoding holds
/// them in: rs comes first there. The names of these three are the field's
/// rather than the operand's, so an instruction whose destination is rt says
/// so.
/// </summary>
let private fRt w = reg5 (bits w 25u 21u) |> oprReg

/// The general register the middle wide field names.
let private fRs w = reg5 (bits w 20u 16u) |> oprReg

/// The general register the lowest wide field names.
let private fRd w = reg5 (bits w 15u 11u) |> oprReg

/// The floating-point register the topmost wide field names.
let private fFt w = Helper.getFRegister (byte (bits w 25u 21u)) |> oprReg

/// The floating-point register the middle wide field names.
let private fFs w = Helper.getFRegister (byte (bits w 20u 16u)) |> oprReg

/// The floating-point register the lowest wide field names.
let private fFd w = Helper.getFRegister (byte (bits w 15u 11u)) |> oprReg

/// The sixteen-bit immediate a 32-bit form holds at the bottom, widened the
/// way a logical operation reads it.
let private immZ w = imm (uint64 (bits w 15u 0u))

/// The same immediate widened the way an arithmetic operation reads it.
let private immS w = imm (uint64 (signed 16 (bits w 15u 0u)))

/// <summary>
/// A 32-bit branch offset.
///
/// It counts halfwords rather than words, an instruction being able to begin
/// at any even address here, and it is measured from the instruction that
/// follows this one.
/// </summary>
let private rel16 w = OpAddr(Relative((signed 16 (bits w 15u 0u) <<< 1) + 4L))

/// The offset of a branch that spends every bit below the major opcode on
/// one, which is again a halfword count from the instruction that follows.
let private rel26 w = (signed 26 (bits w 25u 0u) <<< 1) + 4L

/// A memory operand whose offset is the whole bottom of the word.
let private memOff w width =
  OpMem(reg5 (bits w 20u 16u), Imm(signed 16 (bits w 15u 0u)), width)

/// A memory operand of the pools that spend four bits on a minor opcode.
let private memOff12 w width =
  OpMem(reg5 (bits w 20u 16u), Imm(signed 12 (bits w 11u 0u)), width)

/// A memory operand of the load and store forms that reach the address a
/// user-mode program would see, which spend three more bits saying so.
let private memOff9 w width =
  OpMem(reg5 (bits w 20u 16u), Imm(signed 9 (bits w 8u 0u)), width)

/// A memory operand whose offset is a register.
let private memIdx w width =
  OpMem(reg5 (bits w 20u 16u), Reg(reg5 (bits w 25u 21u)), width)

/// <summary>
/// The registers a five-bit list field names.
///
/// The low four bits count the callee-saved registers from the lowest, and
/// the fifth says whether the return address joins them. Checked against
/// binutils, which encodes the set holding every one of them as 24.
/// </summary>
let private wideRegList v =
  let n = int (v &&& 0xFu)
  if n > 8 then raise ParsingFailureException else ()
  let saved = [ for i in 0 .. n - 1 -> Helper.getRegister (byte (16 + i)) ]
  let regs = if v &&& 0x10u = 0u then saved else saved @ [ R.R31 ]
  if List.isEmpty regs then raise ParsingFailureException else ()
  OpRegList regs

/// The position and size an EXT-like field pair stands for, which the older
/// encoding holds in the same two places.
let private posSize w add32Pos add32Size isIns =
  let msb = bits w 15u 11u |> int
  let lsb = bits w 10u 6u |> int
  let pos = lsb + (if add32Pos then 32 else 0)
  let size = (if isIns then msb - lsb else msb) + (if add32Size then 33 else 1)
  imm (uint64 pos), imm (uint64 size)

/// <summary>
/// POOL32Axf, the pool of everything POOL32A has no room for.
///
/// Its extension grows upwards as the instruction needs fewer operand bits,
/// so what identifies one is read in three steps: the three bits above the
/// pool, then three more, then the top four.
/// </summary>
let private pool32Axf release w =
  match bits w 8u 6u with
  | 0b000u ->
    (* The conditional traps, whose ten spare bits are a code the hardware
       ignores and software reads out of the word. *)
    let oprs = TwoOperands(fRs w, fRt w)
    match bits w 11u 9u with
    | 0b000u ->
      Op.TEQ, None, None, oprs
    | 0b001u ->
      Op.TGE, None, None, oprs
    | 0b010u ->
      Op.TGEU, None, None, oprs
    | 0b100u ->
      Op.TLT, None, None, oprs
    | 0b101u ->
      Op.TLTU, None, None, oprs
    | 0b110u ->
      Op.TNE, None, None, oprs
    | _ ->
      raise ParsingFailureException
  | 0b011u ->
    (* The coprocessor 0 moves. The bit above the two that tell them apart
       belongs to the select field, which is why the pool's own page shows
       each of them twice. *)
    let rd = bits w 20u 16u |> uint64 |> OpImm
    let sel = bits w 13u 11u |> uint64 |> OpImm
    let oprs = ThreeOperands(fRt w, rd, sel)
    match bits w 10u 9u with
    | 0b00u ->
      Op.MFC0, None, None, oprs
    | 0b01u ->
      Op.MTC0, None, None, oprs
    | _ ->
      raise ParsingFailureException
  | 0b100u ->
    match bits w 11u 9u, bits w 15u 12u with
    | 0b111u, 0b0000u ->
      Op.JALR, None, None, TwoOperands(fRt w, fRs w)
    | 0b111u, 0b0001u ->
      Op.JALRHB, None, None, TwoOperands(fRt w, fRs w)
    | 0b111u, 0b0100u when release <> MIPSRelease.R6 ->
      Op.JALRS, None, None, TwoOperands(fRt w, fRs w)
    | 0b111u, 0b0101u when release <> MIPSRelease.R6 ->
      Op.JALRSHB, None, None, TwoOperands(fRt w, fRs w)
    | 0b101u, 0b0010u ->
      Op.SEB, None, None, TwoOperands(fRt w, fRs w)
    | 0b101u, 0b0011u ->
      Op.SEH, None, None, TwoOperands(fRt w, fRs w)
    | 0b101u, 0b0100u ->
      Op.CLO, None, None, TwoOperands(fRt w, fRs w)
    | 0b101u, 0b0101u ->
      Op.CLZ, None, None, TwoOperands(fRt w, fRs w)
    | 0b101u, 0b0110u ->
      Op.RDHWR, None, None, TwoOperands(fRt w, fRs w)
    | 0b101u, 0b0111u ->
      Op.WSBH, None, None, TwoOperands(fRt w, fRs w)
    | 0b101u, 0b1000u when release <> MIPSRelease.R6 ->
      Op.MULT, None, None, TwoOperands(fRs w, fRt w)
    | 0b101u, 0b1001u when release <> MIPSRelease.R6 ->
      Op.MULTU, None, None, TwoOperands(fRs w, fRt w)
    | 0b101u, 0b1010u when release <> MIPSRelease.R6 ->
      Op.DIV, None, None, TwoOperands(fRs w, fRt w)
    | 0b101u, 0b1011u when release <> MIPSRelease.R6 ->
      Op.DIVU, None, None, TwoOperands(fRs w, fRt w)
    | 0b101u, 0b1100u when release <> MIPSRelease.R6 ->
      Op.MADD, None, None, TwoOperands(fRs w, fRt w)
    | 0b101u, 0b1101u when release <> MIPSRelease.R6 ->
      Op.MADDU, None, None, TwoOperands(fRs w, fRt w)
    | 0b101u, 0b1110u when release <> MIPSRelease.R6 ->
      Op.MSUB, None, None, TwoOperands(fRs w, fRt w)
    | 0b101u, 0b1111u when release <> MIPSRelease.R6 ->
      Op.MSUBU, None, None, TwoOperands(fRs w, fRt w)
    | _ ->
      raise ParsingFailureException
  | 0b101u ->
    (* The code a debug or system instruction carries fills every bit the
       operands leave, which is the whole top of the word. *)
    let code = imm (uint64 (bits w 25u 16u))
    match bits w 11u 9u, bits w 15u 12u with
    | 0b000u, 0b1110u ->
      Op.RDPGPR, None, None, TwoOperands(fRt w, fRs w)
    | 0b000u, 0b1111u ->
      Op.WRPGPR, None, None, TwoOperands(fRt w, fRs w)
    | 0b001u, 0b0000u ->
      Op.TLBP, None, None, NoOperand
    | 0b001u, 0b0001u ->
      Op.TLBR, None, None, NoOperand
    | 0b001u, 0b0010u ->
      Op.TLBWI, None, None, NoOperand
    | 0b001u, 0b0011u ->
      Op.TLBWR, None, None, NoOperand
    | 0b001u, 0b1001u ->
      Op.WAIT, None, None, OneOperand code
    | 0b001u, 0b1110u ->
      Op.DERET, None, None, NoOperand
    | 0b001u, 0b1111u ->
      Op.ERET, None, None, NoOperand
    | 0b011u, 0b0100u ->
      Op.DI, None, None, OneOperand(fRs w)
    | 0b011u, 0b0101u ->
      Op.EI, None, None, OneOperand(fRs w)
    | 0b101u, 0b0110u ->
      Op.SYNC, None, None, OneOperand(imm (uint64 (bits w 20u 16u)))
    | 0b101u, 0b1000u ->
      Op.SYSCALL, None, None, OneOperand code
    | 0b101u, 0b1101u ->
      Op.SDBBP, None, None, OneOperand code
    | 0b110u, 0b0000u when release <> MIPSRelease.R6 ->
      Op.MFHI, None, None, OneOperand(fRs w)
    | 0b110u, 0b0001u when release <> MIPSRelease.R6 ->
      Op.MFLO, None, None, OneOperand(fRs w)
    | 0b110u, 0b0010u when release <> MIPSRelease.R6 ->
      Op.MTHI, None, None, OneOperand(fRs w)
    | 0b110u, 0b0011u when release <> MIPSRelease.R6 ->
      Op.MTLO, None, None, OneOperand(fRs w)
    | _ ->
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

/// <summary>
/// POOL32A's own table, which is read as a grid: the three bits above the
/// pool select a column and the four above those a row.
/// </summary>
let private pool32AGrid release w =
  let sa = OpShiftAmount(uint64 (bits w 15u 11u))
  match bits w 5u 3u, bits w 9u 6u with
  | 0b000u, 0b0000u ->
    Op.SLL, None, None, ThreeOperands(fRt w, fRs w, sa)
  | 0b000u, 0b0001u ->
    Op.SRL, None, None, ThreeOperands(fRt w, fRs w, sa)
  | 0b000u, 0b0010u ->
    Op.SRA, None, None, ThreeOperands(fRt w, fRs w, sa)
  | 0b000u, 0b0011u ->
    Op.ROTR, None, None, ThreeOperands(fRt w, fRs w, sa)
  | 0b010u, 0b0000u ->
    Op.SLLV, None, None, ThreeOperands(fRd w, fRt w, fRs w)
  | 0b010u, 0b0001u ->
    Op.SRLV, None, None, ThreeOperands(fRd w, fRt w, fRs w)
  | 0b010u, 0b0010u ->
    Op.SRAV, None, None, ThreeOperands(fRd w, fRt w, fRs w)
  | 0b010u, 0b0011u ->
    Op.ROTRV, None, None, ThreeOperands(fRd w, fRt w, fRs w)
  | 0b010u, 0b0100u ->
    Op.ADD, None, None, ThreeOperands(fRd w, fRs w, fRt w)
  | 0b010u, 0b0101u ->
    Op.ADDU, None, None, ThreeOperands(fRd w, fRs w, fRt w)
  | 0b010u, 0b0110u ->
    Op.SUB, None, None, ThreeOperands(fRd w, fRs w, fRt w)
  | 0b010u, 0b0111u ->
    Op.SUBU, None, None, ThreeOperands(fRd w, fRs w, fRt w)
  | 0b010u, 0b1000u ->
    Op.MUL, None, None, ThreeOperands(fRd w, fRs w, fRt w)
  | 0b010u, 0b1001u ->
    Op.AND, None, None, ThreeOperands(fRd w, fRs w, fRt w)
  | 0b010u, 0b1010u ->
    Op.OR, None, None, ThreeOperands(fRd w, fRs w, fRt w)
  | 0b010u, 0b1011u ->
    Op.NOR, None, None, ThreeOperands(fRd w, fRs w, fRt w)
  | 0b010u, 0b1100u ->
    Op.XOR, None, None, ThreeOperands(fRd w, fRs w, fRt w)
  | 0b010u, 0b1101u ->
    Op.SLT, None, None, ThreeOperands(fRd w, fRs w, fRt w)
  | 0b010u, 0b1110u ->
    Op.SLTU, None, None, ThreeOperands(fRd w, fRs w, fRt w)
  | 0b011u, 0b0000u when release <> MIPSRelease.R6 ->
    Op.MOVN, None, None, ThreeOperands(fRd w, fRs w, fRt w)
  | 0b011u, 0b0001u when release <> MIPSRelease.R6 ->
    Op.MOVZ, None, None, ThreeOperands(fRd w, fRs w, fRt w)
  | 0b011u, 0b0100u ->
    Op.LWXS, None, None, TwoOperands(fRd w, memIdx w 32<rt>)
  | 0b100u, _ when release = MIPSRelease.R6 ->
    (* LSA's shift is two bits of what the grid would otherwise read as a
       row, which is why the row is not matched here. *)
    let sa2 = imm (uint64 (bits w 7u 6u))
    Op.LSA, None, None, FourOperands(fRd w, fRs w, fRt w, sa2)
  | _ ->
    raise ParsingFailureException

/// <summary>
/// POOL32A, which holds what the older encoding calls SPECIAL.
/// </summary>
let private pool32A release w =
  match bits w 2u 0u with
  | 0b000u when bits w 10u 10u = 0u ->
    pool32AGrid release w
  | 0b100u ->
    match bits w 5u 3u with
    | 0b001u ->
      let pos, size = posSize w false false true
      Op.INS, None, None, FourOperands(fRt w, fRs w, pos, size)
    | 0b101u ->
      let pos, size = posSize w false false false
      Op.EXT, None, None, FourOperands(fRt w, fRs w, pos, size)
    | 0b111u ->
      pool32Axf release w
    | _ ->
      raise ParsingFailureException
  | 0b111u when bits w 5u 3u = 0u ->
    Op.BREAK, None, None, OneOperand(imm (uint64 (bits w 25u 6u)))
  | _ ->
    raise ParsingFailureException

/// <summary>
/// POOL32Sxf, which is to POOL32S what POOL32Axf is to POOL32A: the same
/// extension field in the same place, holding the 64-bit members.
/// </summary>
let private pool32Sxf release w =
  match bits w 8u 6u with
  | 0b011u ->
    let rd = bits w 20u 16u |> uint64 |> OpImm
    let sel = bits w 13u 11u |> uint64 |> OpImm
    let oprs = ThreeOperands(fRt w, rd, sel)
    match bits w 10u 9u with
    | 0b00u ->
      Op.DMFC0, None, None, oprs
    | 0b01u ->
      Op.DMTC0, None, None, oprs
    | _ ->
      raise ParsingFailureException
  | 0b100u ->
    match bits w 11u 9u, bits w 15u 12u with
    | 0b101u, 0b0100u ->
      Op.DCLO, None, None, TwoOperands(fRt w, fRs w)
    | 0b101u, 0b0101u ->
      Op.DCLZ, None, None, TwoOperands(fRt w, fRs w)
    | 0b101u, 0b0111u ->
      Op.DSBH, None, None, TwoOperands(fRt w, fRs w)
    | 0b101u, 0b1111u ->
      Op.DSHD, None, None, TwoOperands(fRt w, fRs w)
    | 0b101u, 0b1000u when release <> MIPSRelease.R6 ->
      Op.DMULT, None, None, TwoOperands(fRs w, fRt w)
    | 0b101u, 0b1001u when release <> MIPSRelease.R6 ->
      Op.DMULTU, None, None, TwoOperands(fRs w, fRt w)
    | 0b101u, 0b1010u when release <> MIPSRelease.R6 ->
      Op.DDIV, None, None, TwoOperands(fRs w, fRt w)
    | 0b101u, 0b1011u when release <> MIPSRelease.R6 ->
      Op.DDIVU, None, None, TwoOperands(fRs w, fRt w)
    | _ ->
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

/// <summary>
/// POOL32S, which holds the 64-bit members of what POOL32A holds.
///
/// The layout is POOL32A's, and so are the minor opcodes: a doubleword
/// instruction sits at the same row and column its word counterpart does.
/// The shifts are the exception, the ones reaching past bit 31 taking a
/// column of their own.
/// </summary>
let private pool32S release w =
  let sa = OpShiftAmount(uint64 (bits w 15u 11u))
  match bits w 2u 0u with
  | 0b000u when bits w 10u 10u = 0u ->
    match bits w 5u 3u, bits w 9u 6u with
    | 0b000u, 0b0000u ->
      Op.DSLL, None, None, ThreeOperands(fRt w, fRs w, sa)
    | 0b000u, 0b0001u ->
      Op.DSRL, None, None, ThreeOperands(fRt w, fRs w, sa)
    | 0b000u, 0b0010u ->
      Op.DSRA, None, None, ThreeOperands(fRt w, fRs w, sa)
    | 0b000u, 0b0011u ->
      Op.DROTR, None, None, ThreeOperands(fRt w, fRs w, sa)
    | 0b001u, 0b0000u ->
      Op.DSLL32, None, None, ThreeOperands(fRt w, fRs w, sa)
    | 0b001u, 0b0001u ->
      Op.DSRL32, None, None, ThreeOperands(fRt w, fRs w, sa)
    | 0b001u, 0b0010u ->
      Op.DSRA32, None, None, ThreeOperands(fRt w, fRs w, sa)
    | 0b001u, 0b0011u ->
      Op.DROTR32, None, None, ThreeOperands(fRt w, fRs w, sa)
    | 0b010u, 0b0000u ->
      Op.DSLLV, None, None, ThreeOperands(fRd w, fRt w, fRs w)
    | 0b010u, 0b0001u ->
      Op.DSRLV, None, None, ThreeOperands(fRd w, fRt w, fRs w)
    | 0b010u, 0b0010u ->
      Op.DSRAV, None, None, ThreeOperands(fRd w, fRt w, fRs w)
    | 0b010u, 0b0011u ->
      Op.DROTRV, None, None, ThreeOperands(fRd w, fRt w, fRs w)
    | 0b010u, 0b0100u ->
      Op.DADD, None, None, ThreeOperands(fRd w, fRs w, fRt w)
    | 0b010u, 0b0101u ->
      Op.DADDU, None, None, ThreeOperands(fRd w, fRs w, fRt w)
    | 0b010u, 0b0110u ->
      Op.DSUB, None, None, ThreeOperands(fRd w, fRs w, fRt w)
    | 0b010u, 0b0111u ->
      Op.DSUBU, None, None, ThreeOperands(fRd w, fRs w, fRt w)
    | 0b100u, _ when release = MIPSRelease.R6 ->
      let sa2 = imm (uint64 (bits w 7u 6u))
      Op.DLSA, None, None, FourOperands(fRd w, fRs w, fRt w, sa2)
    | _ ->
      raise ParsingFailureException
  | 0b100u ->
    let oprs add32Pos add32Size isIns =
      let pos, size = posSize w add32Pos add32Size isIns
      FourOperands(fRt w, fRs w, pos, size)
    match bits w 5u 3u with
    | 0b000u ->
      Op.DINSM, None, None, oprs false true true
    | 0b001u ->
      Op.DINS, None, None, oprs false false true
    | 0b010u ->
      Op.DEXTU, None, None, oprs true false false
    | 0b100u ->
      Op.DEXTM, None, None, oprs false true false
    | 0b101u ->
      Op.DEXT, None, None, oprs false false false
    | 0b110u ->
      Op.DINSU, None, None, oprs true false true
    | 0b111u ->
      pool32Sxf release w
    | _ ->
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

/// <summary>
/// POOL32B, the loads and stores that move more than one register.
///
/// Every member spends four bits on the minor opcode and keeps twelve for
/// the offset, which is why they are here rather than among the majors.
/// </summary>
let private pool32B w =
  match bits w 15u 12u with
  | 0b0001u ->
    let second = reg5 (bits w 25u 21u + 1u) |> oprReg
    let oprs = ThreeOperands(fRt w, second, memOff12 w 32<rt>)
    Op.LWP, None, None, oprs
  | 0b0100u ->
    let second = reg5 (bits w 25u 21u + 1u) |> oprReg
    let oprs = ThreeOperands(fRt w, second, memOff12 w 64<rt>)
    Op.LDP, None, None, oprs
  | 0b0101u ->
    let regs = wideRegList (bits w 25u 21u)
    Op.LWM, None, None, TwoOperands(regs, memOff12 w 32<rt>)
  | 0b0110u ->
    let hint = bits w 25u 21u |> uint64 |> OpImm
    Op.CACHE, None, None, TwoOperands(hint, memOff12 w 32<rt>)
  | 0b0111u ->
    let regs = wideRegList (bits w 25u 21u)
    Op.LDM, None, None, TwoOperands(regs, memOff12 w 64<rt>)
  | 0b1001u ->
    let second = reg5 (bits w 25u 21u + 1u) |> oprReg
    let oprs = ThreeOperands(fRt w, second, memOff12 w 32<rt>)
    Op.SWP, None, None, oprs
  | 0b1100u ->
    let second = reg5 (bits w 25u 21u + 1u) |> oprReg
    let oprs = ThreeOperands(fRt w, second, memOff12 w 64<rt>)
    Op.SDP, None, None, oprs
  | 0b1101u ->
    let regs = wideRegList (bits w 25u 21u)
    Op.SWM, None, None, TwoOperands(regs, memOff12 w 32<rt>)
  | 0b1111u ->
    let regs = wideRegList (bits w 25u 21u)
    Op.SDM, None, None, TwoOperands(regs, memOff12 w 64<rt>)
  | _ ->
    raise ParsingFailureException

/// The loads and stores that reach the address a user-mode program would
/// see, which spend three more bits saying which and keep nine for the
/// offset.
let private eva w =
  match bits w 15u 12u, bits w 11u 9u with
  | 0b0110u, 0b000u ->
    Op.LBUE, None, None, TwoOperands(fRt w, memOff9 w 8<rt>)
  | 0b0110u, 0b001u ->
    Op.LHUE, None, None, TwoOperands(fRt w, memOff9 w 16<rt>)
  | 0b0110u, 0b010u ->
    Op.LWLE, None, None, TwoOperands(fRt w, memOff9 w 32<rt>)
  | 0b0110u, 0b011u ->
    Op.LWRE, None, None, TwoOperands(fRt w, memOff9 w 32<rt>)
  | 0b0110u, 0b100u ->
    Op.LBE, None, None, TwoOperands(fRt w, memOff9 w 8<rt>)
  | 0b0110u, 0b101u ->
    Op.LHE, None, None, TwoOperands(fRt w, memOff9 w 16<rt>)
  | 0b0110u, 0b110u ->
    Op.LLE, None, None, TwoOperands(fRt w, memOff9 w 32<rt>)
  | 0b0110u, 0b111u ->
    Op.LWE, None, None, TwoOperands(fRt w, memOff9 w 32<rt>)
  | 0b1010u, 0b000u ->
    Op.SWLE, None, None, TwoOperands(fRt w, memOff9 w 32<rt>)
  | 0b1010u, 0b001u ->
    Op.SWRE, None, None, TwoOperands(fRt w, memOff9 w 32<rt>)
  | 0b1010u, 0b010u ->
    let hint = bits w 25u 21u |> uint64 |> OpImm
    Op.PREFE, None, None, TwoOperands(hint, memOff9 w 32<rt>)
  | 0b1010u, 0b011u ->
    let hint = bits w 25u 21u |> uint64 |> OpImm
    Op.CACHEE, None, None, TwoOperands(hint, memOff9 w 32<rt>)
  | 0b1010u, 0b100u ->
    Op.SBE, None, None, TwoOperands(fRt w, memOff9 w 8<rt>)
  | 0b1010u, 0b101u ->
    Op.SHE, None, None, TwoOperands(fRt w, memOff9 w 16<rt>)
  | 0b1010u, 0b110u ->
    Op.SCE, None, None, TwoOperands(fRt w, memOff9 w 32<rt>)
  | _ ->
    Op.SWE, None, None, TwoOperands(fRt w, memOff9 w 32<rt>)

/// <summary>
/// POOL32C, the loads and stores the older encoding gives a major opcode of
/// its own and this one cannot: they need four bits of minor.
/// </summary>
let private pool32C w =
  match bits w 15u 12u with
  | 0b0000u ->
    Op.LWL, None, None, TwoOperands(fRt w, memOff12 w 32<rt>)
  | 0b0001u ->
    Op.LWR, None, None, TwoOperands(fRt w, memOff12 w 32<rt>)
  | 0b0010u ->
    let hint = bits w 25u 21u |> uint64 |> OpImm
    Op.PREF, None, None, TwoOperands(hint, memOff12 w 32<rt>)
  | 0b0011u ->
    Op.LL, None, None, TwoOperands(fRt w, memOff12 w 32<rt>)
  | 0b0100u ->
    Op.LDL, None, None, TwoOperands(fRt w, memOff12 w 64<rt>)
  | 0b0101u ->
    Op.LDR, None, None, TwoOperands(fRt w, memOff12 w 64<rt>)
  | 0b0110u ->
    eva w
  | 0b0111u ->
    Op.LLD, None, None, TwoOperands(fRt w, memOff12 w 64<rt>)
  | 0b1000u ->
    Op.SWL, None, None, TwoOperands(fRt w, memOff12 w 32<rt>)
  | 0b1001u ->
    Op.SWR, None, None, TwoOperands(fRt w, memOff12 w 32<rt>)
  | 0b1010u ->
    eva w
  | 0b1011u ->
    Op.SC, None, None, TwoOperands(fRt w, memOff12 w 32<rt>)
  | 0b1100u ->
    Op.SDL, None, None, TwoOperands(fRt w, memOff12 w 64<rt>)
  | 0b1101u ->
    Op.SDR, None, None, TwoOperands(fRt w, memOff12 w 64<rt>)
  | 0b1110u ->
    Op.LWU, None, None, TwoOperands(fRt w, memOff12 w 32<rt>)
  | _ ->
    Op.SCD, None, None, TwoOperands(fRt w, memOff12 w 64<rt>)

/// <summary>
/// POOL32I, whose minor opcode sits where a register would.
///
/// Everything here names one register and one sixteen-bit value, so the
/// field the older encoding spends on the second register is free.
/// </summary>
let private pool32I release w =
  let rs = fRs w
  match bits w 25u 21u with
  | 0b00000u ->
    Op.BLTZ, None, None, TwoOperands(rs, rel16 w)
  | 0b00001u when release <> MIPSRelease.R6 ->
    Op.BLTZAL, None, None, TwoOperands(rs, rel16 w)
  | 0b00010u ->
    Op.BGEZ, None, None, TwoOperands(rs, rel16 w)
  | 0b00011u when release <> MIPSRelease.R6 ->
    Op.BGEZAL, None, None, TwoOperands(rs, rel16 w)
  | 0b00100u ->
    Op.BLEZ, None, None, TwoOperands(rs, rel16 w)
  | 0b00101u ->
    Op.BNEZC, None, None, TwoOperands(rs, rel16 w)
  | 0b00110u ->
    Op.BGTZ, None, None, TwoOperands(rs, rel16 w)
  | 0b00111u ->
    Op.BEQZC, None, None, TwoOperands(rs, rel16 w)
  | 0b01000u when release <> MIPSRelease.R6 ->
    Op.TLTI, None, None, TwoOperands(rs, immS w)
  | 0b01001u when release <> MIPSRelease.R6 ->
    Op.TGEI, None, None, TwoOperands(rs, immS w)
  | 0b01010u when release <> MIPSRelease.R6 ->
    Op.TLTIU, None, None, TwoOperands(rs, immS w)
  | 0b01011u when release <> MIPSRelease.R6 ->
    Op.TGEIU, None, None, TwoOperands(rs, immS w)
  | 0b01100u when release <> MIPSRelease.R6 ->
    Op.TNEI, None, None, TwoOperands(rs, immS w)
  | 0b01101u ->
    Op.LUI, None, None, TwoOperands(rs, immZ w)
  | 0b01110u when release <> MIPSRelease.R6 ->
    Op.TEQI, None, None, TwoOperands(rs, immS w)
  | 0b10000u ->
    Op.SYNCI, None, None, OneOperand(memOff w 32<rt>)
  | 0b10001u when release <> MIPSRelease.R6 ->
    Op.BLTZALS, None, None, TwoOperands(rs, rel16 w)
  | 0b10011u when release <> MIPSRelease.R6 ->
    Op.BGEZALS, None, None, TwoOperands(rs, rel16 w)
  | 0b11100u when release <> MIPSRelease.R6 ->
    let cc = bits w 20u 18u |> uint64 |> OpImm
    Op.BC1F, None, None, TwoOperands(cc, rel16 w)
  | 0b11101u when release <> MIPSRelease.R6 ->
    let cc = bits w 20u 18u |> uint64 |> OpImm
    Op.BC1T, None, None, TwoOperands(cc, rel16 w)
  | _ ->
    raise ParsingFailureException

/// <summary>
/// POOL32Fxf, the floating-point instructions that name two registers and
/// nothing else.
///
/// The ten bits above the pool are matched whole rather than split, because
/// the format is not one field: it sits in two different places depending on
/// which member is being read, and every value below was measured.
/// </summary>
let private pool32Fxf w =
  match bits w 12u 6u with
  | 0b0000101u ->
    let cc = bits w 15u 13u |> uint64 |> OpImm
    Op.MOVF, None, None, ThreeOperands(fRt w, fRs w, cc)
  | 0b0100101u ->
    let cc = bits w 15u 13u |> uint64 |> OpImm
    Op.MOVT, None, None, ThreeOperands(fRt w, fRs w, cc)
  | _ ->
    let two opcode fmt = opcode, None, Some fmt, TwoOperands(fFt w, fFs w)
    let move opcode = opcode, None, None, TwoOperands(fRt w, fFs w)
    match bits w 15u 6u with
    | 0x001u ->
      two Op.MOV Fmt.S
    | 0x081u ->
      two Op.MOV Fmt.D
    | 0x101u ->
      two Op.MOV Fmt.PS
    | 0x00Du ->
      two Op.ABS Fmt.S
    | 0x08Du ->
      two Op.ABS Fmt.D
    | 0x10Du ->
      two Op.ABS Fmt.PS
    | 0x02Du ->
      two Op.NEG Fmt.S
    | 0x0ADu ->
      two Op.NEG Fmt.D
    | 0x12Du ->
      two Op.NEG Fmt.PS
    | 0x028u ->
      two Op.SQRT Fmt.S
    | 0x128u ->
      two Op.SQRT Fmt.D
    | 0x048u ->
      two Op.RECIP Fmt.S
    | 0x148u ->
      two Op.RECIP Fmt.D
    | 0x008u ->
      two Op.RSQRT Fmt.S
    | 0x108u ->
      two Op.RSQRT Fmt.D
    | 0x04Du ->
      two Op.CVTD Fmt.S
    | 0x0CDu ->
      two Op.CVTD Fmt.W
    | 0x14Du ->
      two Op.CVTD Fmt.L
    | 0x06Du ->
      two Op.CVTS Fmt.D
    | 0x0EDu ->
      two Op.CVTS Fmt.W
    | 0x16Du ->
      two Op.CVTS Fmt.L
    | 0x024u ->
      two Op.CVTW Fmt.S
    | 0x124u ->
      two Op.CVTW Fmt.D
    | 0x004u ->
      two Op.CVTL Fmt.S
    | 0x104u ->
      two Op.CVTL Fmt.D
    | 0x084u ->
      Op.CVTSPL, None, None, TwoOperands(fFt w, fFs w)
    | 0x0A4u ->
      Op.CVTSPU, None, None, TwoOperands(fFt w, fFs w)
    | 0x0ACu ->
      two Op.TRUNCW Fmt.S
    | 0x1ACu ->
      two Op.TRUNCW Fmt.D
    | 0x08Cu ->
      two Op.TRUNCL Fmt.S
    | 0x18Cu ->
      two Op.TRUNCL Fmt.D
    | 0x06Cu ->
      two Op.CEILW Fmt.S
    | 0x16Cu ->
      two Op.CEILW Fmt.D
    | 0x04Cu ->
      two Op.CEILL Fmt.S
    | 0x14Cu ->
      two Op.CEILL Fmt.D
    | 0x02Cu ->
      two Op.FLOORW Fmt.S
    | 0x12Cu ->
      two Op.FLOORW Fmt.D
    | 0x00Cu ->
      two Op.FLOORL Fmt.S
    | 0x10Cu ->
      two Op.FLOORL Fmt.D
    | 0x0ECu ->
      two Op.ROUNDW Fmt.S
    | 0x1ECu ->
      two Op.ROUNDW Fmt.D
    | 0x0CCu ->
      two Op.ROUNDL Fmt.S
    | 0x1CCu ->
      two Op.ROUNDL Fmt.D
    | 0x080u ->
      move Op.MFC1
    | 0x0A0u ->
      move Op.MTC1
    | 0x090u ->
      move Op.DMFC1
    | 0x0B0u ->
      move Op.DMTC1
    | 0x0C0u ->
      move Op.MFHC1
    | 0x0E0u ->
      move Op.MTHC1
    | 0x040u ->
      move Op.CFC1
    | 0x060u ->
      move Op.CTC1
    | _ ->
      raise ParsingFailureException

/// <summary>
/// The format a floating-point instruction's own two bits name.
///
/// <c>shift</c> says where they are, which is not the same place for every
/// member of the pool: the conditional moves that read a condition code have
/// them one bit higher than the ones that read a register. Checked against
/// binutils, which encodes <c>movf.ps</c> as 0x420 where <c>movz.ps</c> is
/// 0x278.
/// </summary>
let private fmt2 shift w =
  match bits w (shift + 1u) shift with
  | 0u -> Fmt.S
  | 1u -> Fmt.D
  | 2u -> Fmt.PS
  | _ -> raise ParsingFailureException

/// <summary>
/// POOL32F's grid, which is read the way POOL32A's is: three bits above the
/// pool select a column and three more a row.
/// </summary>
let private pool32FGrid release w =
  match bits w 5u 3u, bits w 8u 6u with
  | 0b000u, 0b010u when release <> MIPSRelease.R6 ->
    Op.PLLPS, None, None, ThreeOperands(fFd w, fFs w, fFt w)
  | 0b000u, 0b011u when release <> MIPSRelease.R6 ->
    Op.PLUPS, None, None, ThreeOperands(fFd w, fFs w, fFt w)
  | 0b000u, 0b100u when release <> MIPSRelease.R6 ->
    Op.PULPS, None, None, ThreeOperands(fFd w, fFs w, fFt w)
  | 0b000u, 0b101u when release <> MIPSRelease.R6 ->
    Op.PUUPS, None, None, ThreeOperands(fFd w, fFs w, fFt w)
  | 0b000u, 0b110u ->
    Op.CVTPSS, None, None, ThreeOperands(fFd w, fFs w, fFt w)
  | 0b001u, 0b001u when release <> MIPSRelease.R6 ->
    Op.LWXC1, None, None, TwoOperands(fFd w, memIdx w 32<rt>)
  | 0b001u, 0b010u when release <> MIPSRelease.R6 ->
    Op.SWXC1, None, None, TwoOperands(fFd w, memIdx w 32<rt>)
  | 0b001u, 0b011u when release <> MIPSRelease.R6 ->
    Op.LDXC1, None, None, TwoOperands(fFd w, memIdx w 64<rt>)
  | 0b001u, 0b100u when release <> MIPSRelease.R6 ->
    Op.SDXC1, None, None, TwoOperands(fFd w, memIdx w 64<rt>)
  | 0b001u, 0b101u when release <> MIPSRelease.R6 ->
    Op.LUXC1, None, None, TwoOperands(fFd w, memIdx w 64<rt>)
  | 0b001u, 0b110u when release <> MIPSRelease.R6 ->
    Op.SUXC1, None, None, TwoOperands(fFd w, memIdx w 64<rt>)
  | 0b100u, 0b110u when release <> MIPSRelease.R6 ->
    let hint = bits w 15u 11u |> uint64 |> OpImm
    Op.PREFX, None, None, TwoOperands(hint, memIdx w 32<rt>)
  | 0b100u, _ when release <> MIPSRelease.R6 ->
    (* MOVF and MOVT read a condition code where the others read a register,
       so the destination moves up into the field above. *)
    let cc = bits w 15u 13u |> uint64 |> OpImm
    let opcode = if bits w 6u 6u = 0u then Op.MOVF else Op.MOVT
    opcode, None, Some(fmt2 9u w), ThreeOperands(fFt w, fFs w, cc)
  | 0b110u, _ ->
    let oprs = ThreeOperands(fFd w, fFs w, fFt w)
    let fmt = fmt2 8u w
    let opcode =
      match bits w 7u 6u with
      | 0u -> Op.ADD
      | 1u -> Op.SUB
      | 2u -> Op.MUL
      | _ when fmt <> Fmt.PS -> Op.DIV
      (* There is no paired-single divide, and reading one out of a word
         that holds a reserved encoding would invent an instruction. *)
      | _ -> raise ParsingFailureException
    opcode, None, Some fmt, oprs
  | 0b111u, _ when release <> MIPSRelease.R6 ->
    let opcode = if bits w 6u 6u = 0u then Op.MOVN else Op.MOVZ
    opcode, None, Some(fmt2 8u w), ThreeOperands(fFd w, fFs w, fRt w)
  | _ ->
    raise ParsingFailureException

/// <summary>
/// POOL32F, which holds the floating-point unit.
/// </summary>
let private pool32F release w =
  match bits w 5u 0u with
  | 0b111011u ->
    pool32Fxf w
  | 0b111100u when release <> MIPSRelease.R6 ->
    (* The comparisons, whose result goes to one of eight condition codes
       rather than to a register. Release 6 replaced them with CMP.cond.fmt,
       whose result goes to a float register instead. *)
    let cc = bits w 15u 13u |> uint64 |> OpImm
    let cond = bits w 9u 6u |> int |> LanguagePrimitives.EnumOfValue
    let fmt =
      match bits w 12u 10u with
      | 0u -> Fmt.S
      | 1u -> Fmt.D
      | 2u -> Fmt.PS
      | _ -> raise ParsingFailureException
    Op.C, Some cond, Some fmt, ThreeOperands(cc, fFs w, fFt w)
  | _ ->
    match bits w 2u 0u with
    | 0b000u ->
      pool32FGrid release w
    | 0b001u
    | 0b010u when release <> MIPSRelease.R6 ->
      (* The fused families, whose fourth register sits in the bits the
         others spend on a minor opcode. Release 6 emptied both rows: what
         it put in their place is MADDF and MSUBF, which round once and are
         therefore not these instructions. *)
      let fr = Helper.getFRegister (byte (bits w 10u 6u)) |> oprReg
      let oprs = FourOperands(fFd w, fr, fFs w, fFt w)
      let sub = if bits w 2u 0u = 0b001u then Op.MADD else Op.NMADD
      let sub2 = if bits w 2u 0u = 0b001u then Op.MSUB else Op.NMSUB
      match bits w 5u 3u with
      | 0b000u ->
        sub, None, Some Fmt.S, oprs
      | 0b001u ->
        sub, None, Some Fmt.D, oprs
      | 0b010u ->
        sub, None, Some Fmt.PS, oprs
      | 0b011u when bits w 2u 0u = 0b001u ->
        (* The byte count has a field of its own -- the one the fused
           families beside it keep their fourth register in. Reading it out
           of bits 25..21 printed the same five bits twice, once as ft and
           once as a general register. binutils encodes
           <c>alnv.ps $f0, $f2, $f4, $9</c> as 0x54820259 and the same with
           $10 as 0x54820299, which is bits 10..6 and nothing else. *)
        let rs = reg5 (bits w 10u 6u) |> oprReg
        Op.ALNVPS, None, None, FourOperands(fFd w, fFs w, fFt w, rs)
      | 0b100u ->
        sub2, None, Some Fmt.S, oprs
      | 0b101u ->
        sub2, None, Some Fmt.D, oprs
      | 0b110u ->
        sub2, None, Some Fmt.PS, oprs
      | _ ->
        raise ParsingFailureException
    | _ ->
      raise ParsingFailureException

/// <summary>
/// The branches Release 6 gave one major opcode to several of.
///
/// Which one a word means is settled by the two register fields: one of them
/// being zero, or the two being equal, names a compare-with-zero form, and
/// anything else names the two-register one. The rule is the older
/// encoding's, the instructions being the same instructions; only the places
/// the two fields sit have moved.
/// </summary>
let private zeroBranchR6 w zeroForm eqForm cmpForm =
  let rt = bits w 25u 21u
  let rs = bits w 20u 16u
  if rt = 0u then
    raise ParsingFailureException
  elif rs = 0u then
    zeroForm, None, None, TwoOperands(fRt w, rel16 w)
  elif rs = rt then
    eqForm, None, None, TwoOperands(fRt w, rel16 w)
  else
    cmpForm, None, None, ThreeOperands(fRs w, fRt w, rel16 w)

/// <summary>
/// The Release 6 branches whose two-register form is an overflow check.
///
/// These take the two fields the other way round: the two-register form is
/// the one whose rs is BELOW its rt, and rs at or above rt names the check.
/// </summary>
let private overflowBranchR6 w ovfForm zeroForm cmpForm =
  let rt = bits w 25u 21u
  let rs = bits w 20u 16u
  if rs >= rt then
    ovfForm, None, None, ThreeOperands(fRs w, fRt w, rel16 w)
  elif rs = 0u then
    zeroForm, None, None, TwoOperands(fRt w, rel16 w)
  else
    cmpForm, None, None, ThreeOperands(fRs w, fRt w, rel16 w)

/// <summary>
/// POP40 and POP50, which hold an indexed jump and a compact
/// compare-with-zero branch under one major opcode.
///
/// The jump is the one whose top register field is zero, that field being
/// the base it does not need; the branch takes the field for itself and
/// spends the twenty-one bits below it on an offset where the jump has
/// sixteen.
/// </summary>
let private indexedOrBranchR6 w jump branch =
  if bits w 25u 21u = 0u then
    let off = imm (uint64 (signed 16 (bits w 15u 0u)))
    jump, None, None, TwoOperands(fRs w, off)
  else
    let off = OpAddr(Relative((signed 21 (bits w 20u 0u) <<< 1) + 4L))
    branch, None, None, TwoOperands(fRt w, off)

/// <summary>
/// PCREL, the major opcode Release 6 gave to the PC-relative family.
///
/// Which member a word means is settled by a field starting at bit 20 whose
/// LENGTH varies, so the wider selectors have to be tested after the
/// narrower ones fail rather than alongside them.
/// </summary>
let private pcrel addr w =
  let rt = fRt w
  let bse = int64 (addr &&& ~~~3UL) - int64 addr
  let target off = OpAddr(Relative(bse + int64 (off: uint64)))
  let off19 = uint64 (signed 19 (bits w 18u 0u) <<< 2)
  match bits w 20u 19u with
  | 0b00u ->
    Op.ADDIUPC, None, None, TwoOperands(rt, target off19)
  | 0b01u ->
    Op.LWPC, None, None, TwoOperands(rt, target off19)
  | 0b10u ->
    Op.LWUPC, None, None, TwoOperands(rt, target off19)
  | _ ->
    match bits w 20u 18u with
    | 0b110u ->
      let off18 = uint64 (signed 18 (bits w 17u 0u) <<< 3)
      Op.LDPC, None, None, TwoOperands(rt, target off18)
    | _ ->
      let imm = imm (uint64 (bits w 15u 0u))
      match bits w 20u 16u with
      | 0b11110u ->
        Op.AUIPC, None, None, TwoOperands(rt, imm)
      | 0b11111u ->
        Op.ALUIPC, None, None, TwoOperands(rt, imm)
      | _ ->
        raise ParsingFailureException

/// <summary>
/// One 32-bit instruction.
///
/// The major opcode is the same six bits a 16-bit instruction's is, and the
/// table it indexes is the same table: rows 0 and 4 to 7 hold these.
/// </summary>
let private parseWord release addr w =
  match bits w 31u 26u with
  | 0b000000u ->
    pool32A release w
  | 0b001000u ->
    pool32B w
  | 0b010000u ->
    pool32I release w
  | 0b011000u ->
    pool32C w
  | 0b100000u when release = MIPSRelease.R6 ->
    indexedOrBranchR6 w Op.JIC Op.BEQZC
  | 0b101000u when release = MIPSRelease.R6 ->
    indexedOrBranchR6 w Op.JIALC Op.BNEZC
  | 0b110000u when release = MIPSRelease.R6 ->
    zeroBranchR6 w Op.BLEZALC Op.BGEZALC Op.BGEUC
  | 0b111000u when release = MIPSRelease.R6 ->
    zeroBranchR6 w Op.BGTZALC Op.BLTZALC Op.BLTUC
  | 0b011111u when release = MIPSRelease.R6 ->
    overflowBranchR6 w Op.BNVC Op.BNEZALC Op.BNEC
  | 0b000100u ->
    (* Release 6 took ADDI away and gave the major opcode to AUI, which the
       assembler writes as LUI when it adds to the zero register. *)
    if release <> MIPSRelease.R6 then
      Op.ADDI, None, None, ThreeOperands(fRt w, fRs w, immS w)
    elif bits w 20u 16u = 0u then
      Op.LUI, None, None, TwoOperands(fRt w, immZ w)
    else
      Op.AUI, None, None, ThreeOperands(fRt w, fRs w, immZ w)
  | 0b001100u ->
    Op.ADDIU, None, None, ThreeOperands(fRt w, fRs w, immS w)
  | 0b010100u ->
    Op.ORI, None, None, ThreeOperands(fRt w, fRs w, immZ w)
  | 0b011100u ->
    Op.XORI, None, None, ThreeOperands(fRt w, fRs w, immZ w)
  | 0b100100u ->
    Op.SLTI, None, None, ThreeOperands(fRt w, fRs w, immS w)
  | 0b101100u ->
    Op.SLTIU, None, None, ThreeOperands(fRt w, fRs w, immS w)
  | 0b110100u ->
    Op.ANDI, None, None, ThreeOperands(fRt w, fRs w, immZ w)
  | 0b111100u ->
    if release = MIPSRelease.R6 then
      Op.DAUI, None, None, ThreeOperands(fRt w, fRs w, immZ w)
    else
      (* JALX crosses into the other encoding, so its target is a WORD index
         where every other jump here holds a halfword one. *)
      let idx = uint64 (bits w 25u 0u) <<< 2
      Op.JALX, None, None, OneOperand(OpAddr(Region idx))
  | 0b000101u ->
    Op.LBU, None, None, TwoOperands(fRt w, memOff w 8<rt>)
  | 0b001101u ->
    Op.LHU, None, None, TwoOperands(fRt w, memOff w 16<rt>)
  | 0b010101u ->
    pool32F release w
  | 0b011101u ->
    if release = MIPSRelease.R6 then
      overflowBranchR6 w Op.BOVC Op.BEQZALC Op.BEQC
    else
      let idx = uint64 (bits w 25u 0u) <<< 1
      Op.JALS, None, None, OneOperand(OpAddr(Region idx))
  | 0b100101u ->
    if release = MIPSRelease.R6 then
      Op.BC, None, None, OneOperand(OpAddr(Relative(rel26 w)))
    else
      Op.BEQ, None, None, ThreeOperands(fRs w, fRt w, rel16 w)
  | 0b101101u ->
    if release = MIPSRelease.R6 then
      Op.BALC, None, None, OneOperand(OpAddr(Relative(rel26 w)))
    else
      Op.BNE, None, None, ThreeOperands(fRs w, fRt w, rel16 w)
  | 0b110101u ->
    if release = MIPSRelease.R6 then
      zeroBranchR6 w Op.BGTZC Op.BLTZC Op.BLTC
    else
      let idx = uint64 (bits w 25u 0u) <<< 1
      Op.J, None, None, OneOperand(OpAddr(Region idx))
  | 0b111101u ->
    if release = MIPSRelease.R6 then
      zeroBranchR6 w Op.BLEZC Op.BGEZC Op.BGEC
    else
      let idx = uint64 (bits w 25u 0u) <<< 1
      Op.JAL, None, None, OneOperand(OpAddr(Region idx))
  | 0b000110u ->
    Op.SB, None, None, TwoOperands(fRt w, memOff w 8<rt>)
  | 0b001110u ->
    Op.SH, None, None, TwoOperands(fRt w, memOff w 16<rt>)
  | 0b010110u ->
    pool32S release w
  | 0b011110u ->
    if release = MIPSRelease.R6 then
      pcrel addr w
    else
      (* ADDIUPC counts from this instruction's own address with the low two
         bits cleared, which a halfword-aligned instruction can differ
         from. *)
      let rd = reg3 (bits w 25u 23u) |> oprReg
      let target = (addr &&& ~~~3UL) + (uint64 (bits w 22u 0u) <<< 2)
      let off = int64 target - int64 addr
      Op.ADDIUPC, None, None, TwoOperands(rd, OpAddr(Relative off))
  | 0b100110u ->
    Op.SWC1, None, None, TwoOperands(fFt w, memOff w 32<rt>)
  | 0b101110u ->
    Op.SDC1, None, None, TwoOperands(fFt w, memOff w 64<rt>)
  | 0b110110u ->
    Op.SD, None, None, TwoOperands(fRt w, memOff w 64<rt>)
  | 0b111110u ->
    Op.SW, None, None, TwoOperands(fRt w, memOff w 32<rt>)
  | 0b000111u ->
    Op.LB, None, None, TwoOperands(fRt w, memOff w 8<rt>)
  | 0b001111u ->
    Op.LH, None, None, TwoOperands(fRt w, memOff w 16<rt>)
  | 0b010111u ->
    Op.DADDIU, None, None, ThreeOperands(fRt w, fRs w, immS w)
  | 0b100111u ->
    Op.LWC1, None, None, TwoOperands(fFt w, memOff w 32<rt>)
  | 0b101111u ->
    Op.LDC1, None, None, TwoOperands(fFt w, memOff w 64<rt>)
  | 0b110111u ->
    Op.LD, None, None, TwoOperands(fRt w, memOff w 64<rt>)
  | 0b111111u ->
    Op.LW, None, None, TwoOperands(fRt w, memOff w 32<rt>)
  | _ ->
    raise ParsingFailureException

/// <summary>
/// Decodes one microMIPS instruction, which is one halfword or two.
///
/// Nothing but the major opcode says which, so the second halfword is read
/// only once the first has settled the length.
/// </summary>
let parse lifter span (reader: IBinReader) wordSize release addr =
  let first = reader.ReadUInt16(span = span, offset = 0)
  let len, (opcode, cond, fmt, oprs) =
    if isHalfword first then
      2u, parseHalfword release (uint32 first)
    else
      let second = reader.ReadUInt16(span = span, offset = 2)
      let w = (uint32 first <<< 16) ||| uint32 second
      4u, parseWord release addr w
  if wordSize = WordSize.Bit32 && ParsingMain.isMIPS64Only opcode then
    raise ParsingFailureException
  else
    ()
  let sz = ParsingMain.getOperationSize opcode wordSize
  Instruction(addr, len, cond, fmt, opcode, oprs, sz, wordSize, true, lifter)

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
/// The MIPS16e decoder.
///
/// MIPS16e is an Application-Specific Extension rather than a base encoding
/// -- MD00076 for MIPS32 and MD00077 for MIPS64, Volume IV-a of each -- and
/// what it is an extension of is the instruction set's SIZE and not its
/// meaning. A MIPS16e ADDU is the ADDU the lifter already knows, so what
/// comes out of here is the opcodes that are already in <c>Opcode.fs</c>
/// wherever the base architecture has the instruction.
///
/// Where it does not, the ASE's own opcode comes out instead. That is not the
/// choice microMIPS made -- there, MOVE16 decodes to the OR it stands for --
/// and the reason for the difference is the register field. A MIPS16e field
/// is THREE bits and reaches eight registers, so an instruction the base
/// architecture writes against $0 cannot be written that way here: LI is not
/// reachable as ADDIU from the zero register, and NOT is not reachable as NOR
/// against it. Decoding them to the base opcode would print a form no
/// MIPS16e assembler can read back, which the round-trip sweep would then
/// fail.
///
/// Release 6 removes the ASE, so nothing here takes a release.
/// </summary>
module internal B2R2.FrontEnd.MIPS.MIPS16Parser

open B2R2
open B2R2.FrontEnd.BinLifter

/// <summary>
/// The general register a three-bit field names.
///
/// Eight of the thirty-two are reachable this way and the numbering is not
/// the architecture's. MD00076 writes the mapping as a function rather than
/// as a widening -- "Xlat[x]: translation of the MIPS16e GPR number x into
/// the corresponding 32-bit GPR number" -- and reading the field as a
/// register number would name the wrong register for six of the eight.
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

/// The general register a five-bit field names, which is the architecture's
/// own numbering. Only MOVE has one.
let private reg5 (n: uint32) = Helper.getRegister (byte n)

/// <summary>
/// The register MOVE's r32 field names when it is the SOURCE.
///
/// MD00076 section 3.14.10: "The r32 field uses special bit encoding. For
/// example, the encoding for $7 (00111) is 11100 in the r32 field." The five
/// bits hold the number rotated -- bits 2..0 of the register in the high
/// three and bits 4..3 in the low two -- which is what that example says and
/// what the sweep confirms.
/// </summary>
let private regRot (n: uint32) =
  reg5 (((n >>> 2) &&& 0b111u) ||| ((n &&& 0b11u) <<< 3))

let private oprReg r = OpReg r

let private imm (v: uint64) = OpImm v

/// The bits of a halfword, inclusive, as the manual numbers them.
let inline private bits (h: uint32) high low =
  (h >>> low) &&& ((1u <<< (high - low + 1)) - 1u)

/// A field read as a signed value of the given width. The arithmetic is done
/// at sixty-four bits because a narrower one does not sign-extend on the way
/// out: an eleven-bit -1024 came back as 4294966272.
let inline private signedOf width (v: uint32) =
  let m = 1L <<< (width - 1)
  (int64 v ^^^ m) - m

/// <summary>
/// The shift amount a three-bit field stands for.
///
/// MD00076 section 3.14.7: "The three-bit sa field can encode a shift amount
/// of 0 through 7. 0 bit shifts (NOPs) are not possible; a 0 value translates
/// to a shift amount of 8." The extended forms do not make that
/// substitution, which is how a shift of zero is written at all.
/// </summary>
let private sa3 (v: uint32) = if v = 0u then 8UL else uint64 v

/// <summary>
/// A memory operand of the loads and stores, whose base is rx.
///
/// MD00076 writes them all as <c>LW ry, offset(rx)</c>: the register that is
/// loaded or stored is the SECOND field and the base is the first, which is
/// the other way round from how a three-operand arithmetic instruction of
/// this encoding reads.
/// </summary>
let private mem3 h width scale =
  OpMem(reg3 (bits h 10 8), Imm(int64 (bits h 4 0) * scale), width)

/// A memory operand on the stack pointer, whose offset is eight bits wide
/// because the base is not in the instruction.
let private memSp h width scale =
  OpMem(R.R29, Imm(int64 (bits h 7 0) * scale), width)

/// <summary>
/// A branch target, counted in halfwords from the instruction AFTER this one.
///
/// The length is added in here rather than left to the disassembler, because
/// what the disassembler adds is the instruction's own address -- so an
/// offset that did not carry the length would resolve one instruction early.
/// microMIPS says the same thing the same way.
/// </summary>
let private branch len width (v: uint32) =
  OpAddr(Relative(signedOf width v * 2L + int64 (len: uint32)))

/// <summary>
/// A PC-relative address, which MIPS16e forms from the instruction's address
/// with its low bits cleared.
///
/// A halfword-aligned instruction can sit at an address those bits are not
/// zero at, so this is not the instruction's own address and the difference
/// is not constant -- which is why the operand is built here from the address
/// rather than left to the disassembler.
///
/// How many bits are cleared is the size of what is being addressed: four for
/// the word forms and EIGHT for the doubleword load, which reads its operand
/// aligned the way it will load it.
/// </summary>
let private pcRel (addr: Addr) align (v: uint32) scale =
  let bse = addr &&& ~~~(align - 1UL)
  OpAddr(Relative(int64 (bse + uint64 v * scale) - int64 addr))

/// <summary>
/// RR, the pool of two-register operations, which MD00076 Table 3-24 indexes
/// by bits 4..0 -- and twice over by bits 7..5 as well, for the two function
/// codes that spend the ry field on a sub-function instead of a register.
/// </summary>
let private rrPool h =
  let rx = reg3 (bits h 10 8) |> oprReg
  let ry = reg3 (bits h 7 5) |> oprReg
  let two op = op, TwoOperands(rx, ry)
  (* <summary> is not allowed on a local binding, so this says it here: the
     ASE writes a two-register operation with the destination named once --
     `AND rx, ry` is rx = rx AND ry -- and the base architecture writes the
     same instruction with three fields. The lifter is the base
     architecture's, so the destination is repeated here rather than the arm
     being written twice. What the disassembler then prints is the explicit
     form, which every MIPS16e assembler reads. *)
  let accum op = op, ThreeOperands(rx, rx, ry)
  (* The variable shifts count the other way round: `SLLV ry, rx` shifts ry
     by rx, so ry is both the destination and the value. *)
  let shiftBy op = op, ThreeOperands(ry, ry, rx)
  (* MFHI and MFLO name one register and the ry field is not one, so it has
     to be zero. A decoder that let it vary would accept eight encodings of
     each where the architecture has one. *)
  let oneReg op =
    if bits h 7 5 = 0u then op, OneOperand rx
    else raise ParsingFailureException
  (* The width conversions name one register too, and the base architecture
     writes them with two. *)
  let widen op = op, TwoOperands(rx, rx)
  (* The two doubleword shifts by a constant, which MD00077 writes as
     "DSRL ry, sa": the register is the second field and the amount is in the
     first, where every other RR entry has a register. *)
  let shiftBySa op = op, ThreeOperands(ry, ry, imm (sa3 (bits h 10 8)))
  match bits h 4 0 with
  | 0b00000u ->                                   (* J(AL)R(C), by ry *)
    (* The two that jump through $31 have no rx, and the field is not free:
       MD00076 requires it to be zero and binutils decodes nothing else. *)
    let viaRa op =
      if bits h 10 8 = 0u then op, OneOperand(oprReg R.R31)
      else raise ParsingFailureException
    match bits h 7 5 with
    | 0b000u ->
      Op.JR, OneOperand rx
    | 0b001u ->
      viaRa Op.JR
    | 0b010u ->
      Op.JALR, TwoOperands(oprReg R.R31, rx)
    | 0b100u ->
      Op.JRC, OneOperand rx
    | 0b101u ->
      viaRa Op.JRC
    | 0b110u ->
      Op.JALRC, TwoOperands(oprReg R.R31, rx)
    | _ ->
      raise ParsingFailureException
  | 0b00001u ->
    Op.SDBBP, OneOperand(imm (uint64 (bits h 10 5)))
  | 0b00010u ->
    two Op.SLT
  | 0b00011u ->
    two Op.SLTU
  | 0b00100u ->
    shiftBy Op.SLLV
  | 0b00101u ->
    Op.BREAK, OneOperand(imm (uint64 (bits h 10 5)))
  | 0b00110u ->
    shiftBy Op.SRLV
  | 0b00111u ->
    shiftBy Op.SRAV
  | 0b01000u ->
    shiftBySa Op.DSRL
  | 0b01010u ->
    two Op.CMP16
  | 0b01011u ->
    two Op.NEG16
  | 0b01100u ->
    accum Op.AND
  | 0b01101u ->
    accum Op.OR
  | 0b01110u ->
    accum Op.XOR
  | 0b01111u ->
    two Op.NOT
  | 0b10000u ->
    oneReg Op.MFHI
  | 0b10001u ->                                   (* CNVT, by ry *)
    match bits h 7 5 with
    | 0b000u ->
      widen Op.ZEB
    | 0b001u ->
      widen Op.ZEH
    | 0b010u ->
      widen Op.ZEW
    | 0b100u ->
      widen Op.SEB
    | 0b101u ->
      widen Op.SEH
    | 0b110u ->
      widen Op.SEW
    | _ ->
      raise ParsingFailureException
  | 0b10010u ->
    oneReg Op.MFLO
  | 0b10011u ->
    shiftBySa Op.DSRA
  | 0b10100u ->
    shiftBy Op.DSLLV
  | 0b10110u ->
    shiftBy Op.DSRLV
  | 0b10111u ->
    shiftBy Op.DSRAV
  | 0b11000u ->
    two Op.MULT
  | 0b11001u ->
    two Op.MULTU
  | 0b11010u ->
    two Op.DIV
  | 0b11011u ->
    two Op.DIVU
  | 0b11100u ->
    two Op.DMULT
  | 0b11101u ->
    two Op.DMULTU
  | 0b11110u ->
    two Op.DDIV
  | 0b11111u ->
    two Op.DDIVU
  | _ ->
    raise ParsingFailureException

/// <summary>
/// The static registers an extended SAVE or RESTORE names.
///
/// MD00076 writes the set as seven nested conditions rather than as a table,
/// and the nesting is what gives the membership: the innermost reached is
/// $30 and the outermost $18, so a field of 7 means all of $18 to $23 and
/// $30, and a field of 1 means $18 alone.
/// </summary>
let private xsRegs n =
  [ R.R18; R.R19; R.R20; R.R21; R.R22; R.R23; R.R30 ]
  |> List.truncate (min (int n) 7)

/// <summary>
/// The two counts the four-bit aregs field stands for: how many of $4 to $7
/// arrived as arguments, and how many are to be kept as static registers.
///
/// MD00076 gives it as a sixteen-row table and not as two fields, which is
/// why this is a table here too. The one row it leaves Reserved is the one
/// this refuses.
/// </summary>
let private aRegs = function
  | 0b0000u -> struct (0, 0)
  | 0b0001u -> struct (0, 1)
  | 0b0010u -> struct (0, 2)
  | 0b0011u -> struct (0, 3)
  | 0b1011u -> struct (0, 4)
  | 0b0100u -> struct (1, 0)
  | 0b0101u -> struct (1, 1)
  | 0b0110u -> struct (1, 2)
  | 0b0111u -> struct (1, 3)
  | 0b1000u -> struct (2, 0)
  | 0b1001u -> struct (2, 1)
  | 0b1010u -> struct (2, 2)
  | 0b1100u -> struct (3, 0)
  | 0b1101u -> struct (3, 1)
  | 0b1110u -> struct (4, 0)
  | _ -> raise ParsingFailureException

/// <summary>
/// SAVE and RESTORE, which name SETS of registers rather than one.
///
/// MD00076 Table 3-26 puts the two under one function code and tells them
/// apart by bit 7. The three sets are not interchangeable and the operands
/// keep them apart: the ARGUMENTS are stored upwards from the stack pointer
/// as it arrives, and everything else downwards from it, so a lifter handed
/// one flat list could not place either.
///
/// The extended form is the one place EXTEND buys something other than a
/// wider immediate. It adds the static registers and the argument set, and
/// its frame size is eight bits -- where the short form spends four and
/// cannot express the largest frame, which is why a zero there means 128
/// and a zero here means zero.
/// </summary>
let private svrs (ext: uint32 option) h =
  let op = if bits h 7 7 = 1u then Op.SAVE else Op.RESTORE
  let struct (args, statics, xs, frame) =
    match ext with
    | Some e ->
      let struct (a, st) = aRegs (bits e 3 0)
      let f = uint64 ((bits e 7 4 <<< 4) ||| bits h 3 0) * 8UL
      struct (a, st, xsRegs (bits e 10 8), f)
    | None ->
      let f = uint64 (bits h 3 0) * 8UL
      struct (0, 0, [], if f = 0UL then 128UL else f)
  let argRegs = [ R.R4; R.R5; R.R6; R.R7 ] |> List.truncate args
  let flagged bit r = if bits h bit bit = 1u then [ r ] else []
  (* Named in the order a reader expects and a disassembler prints, which is
     not the order the instruction touches them in -- that one descends, and
     working it out is the lifter's, which has the architecture's sequence. *)
  let saved =
    List.concat
      [ flagged 6 R.R31
        xs
        flagged 5 R.R16
        flagged 4 R.R17
        [ R.R4; R.R5; R.R6; R.R7 ] |> List.skip (4 - statics) ]
  op, ThreeOperands(imm frame, OpRegList argRegs, OpRegList saved)

/// <summary>
/// I8, the pool the major opcode 0b01100 holds, indexed by bits 10..8.
///
/// Six of the eight are ordinary instructions with an eight-bit immediate;
/// the other two are MOVE, which is the only way this encoding reaches the
/// registers a three-bit field cannot name.
/// </summary>
let private i8Pool h =
  match bits h 10 8 with
  | 0b000u ->
    Op.BTEQZ, OneOperand(branch 2u 8 (bits h 7 0))
  | 0b001u ->
    Op.BTNEZ, OneOperand(branch 2u 8 (bits h 7 0))
  | 0b010u ->                                     (* SW ra, offset(sp) *)
    Op.SW, TwoOperands(oprReg R.R31, memSp h 32<rt> 4L)
  | 0b011u ->                                     (* ADDIU sp, immediate *)
    let v = imm (uint64 (signedOf 8 (bits h 7 0) * 8L))
    Op.ADDIU, ThreeOperands(oprReg R.R29, oprReg R.R29, v)
  | 0b100u ->
    svrs None h
  | 0b101u ->                                     (* MOVE r32, rz *)
    Op.MOVE, TwoOperands(oprReg (regRot (bits h 7 3)),
                         oprReg (reg3 (bits h 2 0)))
  | 0b111u ->                                     (* MOVE ry, r32 *)
    Op.MOVE, TwoOperands(oprReg (reg3 (bits h 7 5)),
                         oprReg (reg5 (bits h 4 0)))
  | _ ->
    raise ParsingFailureException

/// <summary>
/// I64, the pool MIPS64 puts at major opcode 0b11111, indexed by bits 10..8.
///
/// Every one of them is a doubleword form of something the 32-bit encoding
/// already has, which is why MD00076 has no such pool and MD00077 Table 3-25
/// does.
/// </summary>
let private i64Pool addr h =
  match bits h 10 8 with
  | 0b000u ->                                     (* LD ry, offset(sp) *)
    let m = OpMem(R.R29, Imm(int64 (bits h 4 0) * 8L), 64<rt>)
    Op.LD, TwoOperands(oprReg (reg3 (bits h 7 5)), m)
  | 0b001u ->                                     (* SD ry, offset(sp) *)
    let m = OpMem(R.R29, Imm(int64 (bits h 4 0) * 8L), 64<rt>)
    Op.SD, TwoOperands(oprReg (reg3 (bits h 7 5)), m)
  | 0b010u ->                                     (* SD ra, offset(sp) *)
    let m = OpMem(R.R29, Imm(int64 (bits h 7 0) * 8L), 64<rt>)
    Op.SD, TwoOperands(oprReg R.R31, m)
  | 0b011u ->                                     (* DADDIU sp, immediate *)
    let v = imm (uint64 (signedOf 8 (bits h 7 0) * 8L))
    Op.DADDIU, ThreeOperands(oprReg R.R29, oprReg R.R29, v)
  | 0b100u ->                                     (* LD ry, offset(pc) *)
    let t = pcRel addr 8UL (bits h 4 0) 8UL
    Op.LD, TwoOperands(oprReg (reg3 (bits h 7 5)), t)
  | 0b101u ->                                     (* DADDIU ry, immediate *)
    let r = oprReg (reg3 (bits h 7 5))
    let v = imm (uint64 (signedOf 5 (bits h 4 0)))
    Op.DADDIU, ThreeOperands(r, r, v)
  | 0b110u ->                                     (* DADDIU ry, pc, imm *)
    let t = pcRel addr 4UL (bits h 4 0) 4UL
    Op.DADDIUPC, TwoOperands(oprReg (reg3 (bits h 7 5)), t)
  | 0b111u ->                                     (* DADDIU ry, sp, imm *)
    let v = imm (uint64 (bits h 4 0) * 4UL)
    Op.DADDIU, ThreeOperands(oprReg (reg3 (bits h 7 5)), oprReg R.R29, v)
  | _ ->
    raise ParsingFailureException

/// <summary>
/// One MIPS16e instruction that is not extended, from its single halfword.
///
/// The major opcode is bits 15..11 throughout, which MD00076 Table 3-18 lays
/// out as a grid of bits 15..14 against bits 13..11; it is read here as one
/// five-bit field, the grid being a way of printing it rather than of
/// decoding it.
/// </summary>
let private parseHalfword addr (h: uint32) =
  let rx () = reg3 (bits h 10 8) |> oprReg
  let ry () = reg3 (bits h 7 5) |> oprReg
  let load op width scale = op, TwoOperands(ry (), mem3 h width scale)
  match bits h 15 11 with
  | 0b00000u ->                                   (* ADDIU rx, sp, imm *)
    let v = imm (uint64 (bits h 7 0) * 4UL)
    Op.ADDIU, ThreeOperands(rx (), oprReg R.R29, v)
  | 0b00001u ->                                   (* ADDIU rx, pc, imm *)
    Op.ADDIUPC, TwoOperands(rx (), pcRel addr 4UL (bits h 7 0) 4UL)
  | 0b00010u ->
    Op.B, OneOperand(branch 2u 11 (bits h 10 0))
  | 0b00100u ->
    Op.BEQZ, TwoOperands(rx (), branch 2u 8 (bits h 7 0))
  | 0b00101u ->
    Op.BNEZ, TwoOperands(rx (), branch 2u 8 (bits h 7 0))
  | 0b00110u ->                                   (* SHIFT, by bits 1..0 *)
    let sa = imm (sa3 (bits h 4 2))
    let three op = op, ThreeOperands(rx (), ry (), sa)
    match bits h 1 0 with
    | 0b00u ->
      three Op.SLL
    | 0b01u ->
      three Op.DSLL
    | 0b10u ->
      three Op.SRL
    | _ ->
      three Op.SRA
  | 0b00111u ->
    load Op.LD 64<rt> 8L
  | 0b01000u ->                                   (* RRI-A, by bit 4 *)
    let op = if bits h 4 4 = 0u then Op.ADDIU else Op.DADDIU
    op, ThreeOperands(ry (), rx (), imm (uint64 (signedOf 4 (bits h 3 0))))
  | 0b01001u ->                                   (* ADDIU rx, immediate *)
    let v = imm (uint64 (signedOf 8 (bits h 7 0)))
    Op.ADDIU, ThreeOperands(rx (), rx (), v)
  | 0b01010u ->
    Op.SLTI, TwoOperands(rx (), imm (uint64 (bits h 7 0)))
  | 0b01011u ->
    Op.SLTIU, TwoOperands(rx (), imm (uint64 (bits h 7 0)))
  | 0b01100u ->
    (* The one halfword the manuals name NOP. It is MOVE of $16 into $0, and
       both disassemblers print the name rather than the move. *)
    if h = 0x6500u then Op.NOP, NoOperand else i8Pool h
  | 0b01101u ->
    Op.LI, TwoOperands(rx (), imm (uint64 (bits h 7 0)))
  | 0b01110u ->
    Op.CMPI, TwoOperands(rx (), imm (uint64 (bits h 7 0)))
  | 0b01111u ->
    load Op.SD 64<rt> 8L
  | 0b10000u ->
    load Op.LB 8<rt> 1L
  | 0b10001u ->
    load Op.LH 16<rt> 2L
  | 0b10010u ->                                   (* LW rx, offset(sp) *)
    Op.LW, TwoOperands(rx (), memSp h 32<rt> 4L)
  | 0b10011u ->
    load Op.LW 32<rt> 4L
  | 0b10100u ->
    load Op.LBU 8<rt> 1L
  | 0b10101u ->
    load Op.LHU 16<rt> 2L
  | 0b10110u ->                                   (* LW rx, offset(pc) *)
    Op.LW, TwoOperands(rx (), pcRel addr 4UL (bits h 7 0) 4UL)
  | 0b10111u ->
    load Op.LWU 32<rt> 4L
  | 0b11000u ->
    load Op.SB 8<rt> 1L
  | 0b11001u ->
    load Op.SH 16<rt> 2L
  | 0b11010u ->                                   (* SW rx, offset(sp) *)
    Op.SW, TwoOperands(rx (), memSp h 32<rt> 4L)
  | 0b11011u ->
    load Op.SW 32<rt> 4L
  | 0b11100u ->                                   (* RRR, by bits 1..0 *)
    let rz = reg3 (bits h 4 2) |> oprReg
    let three op = op, ThreeOperands(rz, rx (), ry ())
    match bits h 1 0 with
    | 0b00u ->
      three Op.DADDU
    | 0b01u ->
      three Op.ADDU
    | 0b10u ->
      three Op.DSUBU
    | _ ->
      three Op.SUBU
  | 0b11101u ->
    rrPool h
  | 0b11111u ->
    i64Pool addr h
  | _ ->
    raise ParsingFailureException

/// <summary>
/// JAL and JALX, the only instructions of this encoding that are two
/// halfwords without an EXTEND in front of them.
///
/// MD00076 section 3.14.12 scatters the target across both: bits 20..16 sit
/// where an immediate's low bits would, bits 25..21 after them, and bits
/// 15..0 fill the second halfword. Which of the two it is comes from bit 26.
/// </summary>
let private parseJal (h: uint32) (second: uint32) =
  let op = if bits h 10 10 = 0u then Op.JAL else Op.JALX
  let idx =
    (uint64 (bits h 4 0) <<< 21) ||| (uint64 (bits h 9 5) <<< 16)
    ||| uint64 second
  op, OneOperand(OpAddr(Region(idx <<< 2)))

/// <summary>
/// An instruction an EXTEND prefixes, which is the same instruction with a
/// wider immediate.
///
/// MD00076 sections 3.14.13 to 3.14.20 give one layout per format, and they
/// agree on where the extra bits live: immediate 10..5 in bits 26..21 of the
/// pair, immediate 15..11 in bits 20..16, and the instruction's own field
/// keeping immediate 4..0. So the widened value is assembled here and the
/// second halfword is then decoded as itself with that value put in.
///
/// The shifts are the exception the manual calls out: an extended shift
/// takes a five-bit amount from bits 26..22 and does not make the 0-to-8
/// substitution, which is the only way a shift of zero can be written.
/// </summary>
let private parseExtended addr (ext: uint32) (h: uint32) =
  let wide () =
    (bits ext 10 5 <<< 5) ||| (bits ext 4 0 <<< 11) ||| (bits h 4 0)
  let wideS () = signedOf 16 (wide ())
  (* An extended branch counts from the instruction after it, the same as a
     short one -- and an extended instruction is four bytes. The sweep cannot
     reach these: it follows every halfword with a NOP, so the only extended
     instruction it builds is an extended NOP. *)
  let branchTo () = OpAddr(Relative(wideS () * 2L + 4L))
  let rx () = reg3 (bits h 10 8) |> oprReg
  let ry () = reg3 (bits h 7 5) |> oprReg
  let mem width = OpMem(reg3 (bits h 10 8), Imm(wideS ()), width)
  let load op width = op, TwoOperands(ry (), mem width)
  match bits h 15 11 with
  | 0b00000u ->
    Op.ADDIU, ThreeOperands(rx (), oprReg R.R29, imm (uint64 (wideS ())))
  | 0b00001u ->
    Op.ADDIUPC, TwoOperands(rx (), pcRel addr 4UL (wide ()) 1UL)
  | 0b00010u ->
    Op.B, OneOperand(branchTo ())
  | 0b00100u ->
    Op.BEQZ, TwoOperands(rx (), branchTo ())
  | 0b00101u ->
    Op.BNEZ, TwoOperands(rx (), branchTo ())
  | 0b00110u ->
    let sa = imm (uint64 (bits ext 10 6))
    let three op = op, ThreeOperands(rx (), ry (), sa)
    match bits h 1 0 with
    | 0b00u ->
      three Op.SLL
    | 0b01u ->
      three Op.DSLL
    | 0b10u ->
      three Op.SRL
    | _ ->
      three Op.SRA
  | 0b00111u ->
    load Op.LD 64<rt>
  | 0b01000u ->
    (* The one immediate that is fifteen bits rather than sixteen: the
       manual's EXT-RRI-A box spends bit 4 of the instruction on `f`. *)
    let v = (bits ext 10 4 <<< 4) ||| (bits ext 3 0 <<< 11) ||| (bits h 3 0)
    let op = if bits h 4 4 = 0u then Op.ADDIU else Op.DADDIU
    op, ThreeOperands(ry (), rx (), imm (uint64 (signedOf 15 v)))
  | 0b01001u ->
    Op.ADDIU, ThreeOperands(rx (), rx (), imm (uint64 (wideS ())))
  | 0b01010u ->
    Op.SLTI, TwoOperands(rx (), imm (uint64 (wideS ())))
  | 0b01011u ->
    Op.SLTIU, TwoOperands(rx (), imm (uint64 (wideS ())))
  | 0b01100u ->
    match bits h 10 8 with
    | 0b000u ->
      Op.BTEQZ, OneOperand(branchTo ())
    | 0b001u ->
      Op.BTNEZ, OneOperand(branchTo ())
    | 0b010u ->
      let m = OpMem(R.R29, Imm(wideS ()), 32<rt>)
      Op.SW, TwoOperands(oprReg R.R31, m)
    | 0b011u ->
      let v = imm (uint64 (wideS ()))
      Op.ADDIU, ThreeOperands(oprReg R.R29, oprReg R.R29, v)
    | 0b100u ->
      svrs (Some ext) h
    | _ ->
      raise ParsingFailureException
  | 0b01101u ->
    Op.LI, TwoOperands(rx (), imm (uint64 (wide ())))
  | 0b01110u ->
    Op.CMPI, TwoOperands(rx (), imm (uint64 (wide ())))
  | 0b01111u ->
    load Op.SD 64<rt>
  | 0b10000u ->
    load Op.LB 8<rt>
  | 0b10001u ->
    load Op.LH 16<rt>
  | 0b10010u ->
    Op.LW, TwoOperands(rx (), OpMem(R.R29, Imm(wideS ()), 32<rt>))
  | 0b10011u ->
    load Op.LW 32<rt>
  | 0b10100u ->
    load Op.LBU 8<rt>
  | 0b10101u ->
    load Op.LHU 16<rt>
  | 0b10110u ->
    Op.LW, TwoOperands(rx (), pcRel addr 4UL (wide ()) 1UL)
  | 0b10111u ->
    load Op.LWU 32<rt>
  | 0b11000u ->
    load Op.SB 8<rt>
  | 0b11001u ->
    load Op.SH 16<rt>
  | 0b11010u ->
    Op.SW, TwoOperands(rx (), OpMem(R.R29, Imm(wideS ()), 32<rt>))
  | 0b11011u ->
    load Op.SW 32<rt>
  | 0b11101u ->
    (* The RR pool has exactly two extensible members, and MD00077 gives them
       a box of their own: five bits of amount above the prefix's middle and
       the sixth beside them, where every other extended form spends those
       bits on an immediate. The zero-means-eight substitution the short form
       makes is not made here, which is the only way to shift by nothing. *)
    let sa = (bits ext 10 6) ||| ((bits ext 5 5) <<< 5)
    let ry = reg3 (bits h 7 5) |> oprReg
    match bits h 4 0 with
    | 0b01000u ->
      Op.DSRL, ThreeOperands(ry, ry, imm (uint64 sa))
    | 0b10011u ->
      Op.DSRA, ThreeOperands(ry, ry, imm (uint64 sa))
    | _ ->
      raise ParsingFailureException
  | 0b11111u ->
    i64Pool addr h
  | _ ->
    raise ParsingFailureException

/// <summary>
/// Decodes one MIPS16e instruction, which is one halfword or two.
///
/// Two of the majors say the instruction is two halfwords -- EXTEND, which
/// widens the one after it, and JAL(X), which spends both on its target --
/// and nothing else does. So the second halfword is read only once the first
/// has settled the length, which is also what keeps a decoder from reading
/// past the end of a block that ends in a one-halfword instruction.
/// </summary>
let parse lifter span (reader: IBinReader) wordSize addr =
  let first = uint32 (reader.ReadUInt16(span = span, offset = 0))
  let major = bits first 15 11
  let len = if major = 0b11110u || major = 0b00011u then 4u else 2u
  let opcode, oprs =
    if major = 0b11110u then
      let second = uint32 (reader.ReadUInt16(span = span, offset = 2))
      parseExtended addr first second
    elif major = 0b00011u then
      let second = uint32 (reader.ReadUInt16(span = span, offset = 2))
      parseJal first second
    else
      parseHalfword addr first
  if wordSize = WordSize.Bit32 && ParsingMain.isMIPS64Only opcode then
    raise ParsingFailureException
  else
    ()
  let sz = ParsingMain.getOperationSize opcode wordSize
  let mode = MIPSISAMode.MIPS16
  Instruction(addr, len, None, None, opcode, oprs, sz, wordSize, mode, lifter)

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
/// Encodes the microMIPS form of an instruction.
///
/// microMIPS is a second encoding of the same instruction set, so the text an
/// instruction is written as is the same text the other encoding is written
/// as and everything above this module is shared with it. What differs is the
/// word underneath: an instruction is two bytes or four rather than always
/// four, the two halves of a four-byte one are stored the higher first, and
/// the three wide register fields run rt, rs, rd from the top where the older
/// encoding runs rs, rt, rd.
///
/// Where both a 16-bit and a 32-bit form of an instruction exist, the 32-bit
/// one is what this writes. The two say the same thing, and picking the
/// shorter would make the length of an instruction depend on what its
/// operands turned out to be, which the addresses of everything after it
/// would then depend on as well.
/// </summary>
module internal B2R2.Assembly.MIPS.AsmMicroMIPS

open B2R2
open B2R2.FrontEnd.MIPS
open B2R2.Assembly.MIPS.ParserHelper
open B2R2.Assembly.MIPS.AsmField

/// <summary>
/// How many bytes an instruction takes.
///
/// It follows from the opcode alone because the longer form is always the one
/// written, so the only instructions of two bytes are the ones that have no
/// form of four: the short jumps, the short branch, and the pair move.
/// </summary>
let size ins =
  match ins.Opcode with
  | Opcode.B | Opcode.JR | Opcode.JRC | Opcode.JALRC | Opcode.JRADDIUSP
  | Opcode.JRCADDIUSP | Opcode.MOVEP ->
    2
  | Opcode.JALR | Opcode.JALRS ->
    (* These have a long form as well, and what tells the two apart is that
       the short one names the register it returns to by leaving it out. *)
    match ins.Operands with
    | OneOperand _ -> 2
    | _ -> 4
  | _ ->
    4

/// <summary>
/// The bytes an encoded instruction is stored as.
///
/// A four-byte instruction is two halfwords and the one holding the major
/// opcode is stored first, so the word cannot simply be written out in the
/// endianness of the target the way a fixed four-byte encoding can: that
/// would put the halves the wrong way round on a little-endian machine.
/// </summary>
let toBytes endian length (word: uint32) =
  let half (value: uint32) =
    let bytes = [| byte value; byte (value >>> 8) |]
    if endian = Endian.Big then Array.rev bytes else bytes
  if length = 2 then half word
  else Array.append (half (word >>> 16)) (half (word &&& 0xffffu))

/// One word, given its major opcode and the sixteen bits below the two wide
/// fields. The fields are named for what they hold in the encoding rather
/// than for what the operand they take is called.
let private word (major: uint32) rt rs (lower: uint32) =
  (major <<< 26) ||| (rt <<< 21) ||| (rs <<< 16) ||| lower

/// The place a branch names, which the encoding holds as a count of HALFWORDS
/// from the instruction after this one. The older encoding counts words, an
/// instruction there being unable to begin at an odd multiple of two.
let private branchOffset width (distance: int64) =
  if distance % 2L = 0L then signed width ((distance - 4L) >>> 1)
  else fail "a branch cannot reach a place that is not a whole halfword away"

/// The word of the region a jump names, counted in halfwords -- or, for the
/// jump that crosses into the other encoding, in words, because what it
/// lands on is an instruction of that encoding.
let private jumpTarget shift (target: uint64) =
  if target % (1UL <<< shift) <> 0UL then
    fail "a jump cannot reach a place that is not a whole step away"
  elif target >= (1UL <<< (26 + shift)) then
    fail $"0x{target:x} lies outside the region a jump can name"
  else
    uint32 (target >>> shift)

(* The instructions the major opcode names on its own, which take their
   operands from the two wide fields and the sixteen bits below them. *)
/// Encodes <rt>, <rs>, <immediate>.
let private rtRsImm major width ins =
  match ins.Operands with
  | ThreeOperands(Rg rt, Rg rs, Im value) ->
    let bits =
      if width = 16 then immediate16 value else unsigned width value
    word major (gpr rt) (gpr rs) bits
  | _ ->
    wrongOperands ins

/// Encodes <rt>, <immediate>: the one form that leaves the middle field
/// empty because what it adds to is nothing rather than a register.
let private rtImm major ins =
  match ins.Operands with
  | TwoOperands(Rg rt, Im value) -> word major (gpr rt) 0u (unsigned 16 value)
  | _ -> wrongOperands ins

/// Encodes <rt>, <offset>(<base>): a load or a store on the general
/// registers, whose offset is the whole bottom of the word.
let private memWide major ins =
  match ins.Operands with
  | TwoOperands(Rg rt, Mem(baseReg, offset)) ->
    word major (gpr rt) (gpr baseReg) (signed 16 offset)
  | _ ->
    wrongOperands ins

/// The same for the four that name a floating-point register instead.
let private memWideFP major ins =
  match ins.Operands with
  | TwoOperands(Rg ft, Mem(baseReg, offset)) ->
    word major (fpr ft) (gpr baseReg) (signed 16 offset)
  | _ ->
    wrongOperands ins

/// <summary>
/// Encodes <rs>, <rt>, <place>: the two branches that compare a pair of
/// registers.
///
/// The operands are written the way the older encoding writes them, so the
/// first of the two lands in the LOWER of the wide fields -- the one the
/// encoding calls rs -- and the second in the upper.
/// </summary>
let private branchPair major ins =
  match ins.Operands with
  | ThreeOperands(Rg rs, Rg rt, Place distance) ->
    word major (gpr rt) (gpr rs) (branchOffset 16 distance)
  | _ ->
    wrongOperands ins

/// Encodes <place> alone, held as a count of halfwords in every bit below the
/// major opcode.
let private branchWide major ins =
  match ins.Operands with
  | OneOperand(Place distance) -> (major <<< 26) ||| branchOffset 26 distance
  | _ -> wrongOperands ins

/// Encodes the jumps, which name a word of the region they sit in rather than
/// a distance.
let private jump major shift ins =
  match ins.Operands with
  | OneOperand(Im target) -> (major <<< 26) ||| jumpTarget shift target
  | _ -> wrongOperands ins

(* POOL32A, which holds what the older encoding calls SPECIAL. What tells its
   members apart is read in three steps: the three bits at the very bottom
   pick the group, and within the group a row of three bits and a column of
   four say which instruction it is. *)
/// One word of the grid POOL32A opens with. The field above the two wide ones
/// holds the destination for most of it and a shift distance for the four
/// that shift by a written one.
let private grid major rt rs rdOrSa col row =
  word major rt rs ((rdOrSa <<< 11) ||| (col <<< 6) ||| (row <<< 3))

/// Encodes <rt>, <rs>, <sa>: a shift by a written distance.
let private shiftImm major row col ins =
  match ins.Operands with
  | ThreeOperands(Rg rt, Rg rs, Im sa) ->
    grid major (gpr rt) (gpr rs) (unsigned 5 sa) col row
  | _ ->
    wrongOperands ins

/// Encodes <rd>, <rt>, <rs>: a shift by a distance a register holds.
let private shiftReg major col ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rt, Rg rs) ->
    grid major (gpr rt) (gpr rs) (gpr rd) col 0b010u
  | _ ->
    wrongOperands ins

/// Encodes <rd>, <rs>, <rt>: the arithmetic and the logic on two registers.
let private threeReg major row col ins =
  match ins.Operands with
  | ThreeOperands(Rg rd, Rg rs, Rg rt) ->
    grid major (gpr rt) (gpr rs) (gpr rd) col row
  | _ ->
    wrongOperands ins

/// Encodes <rd>, <index>(<base>): the load that scales its index by the width
/// of what it reads.
let private loadScaled ins =
  match ins.Operands with
  | TwoOperands(Rg rd, MemIdx(baseReg, index)) ->
    grid 0b000000u (gpr index) (gpr baseReg) (gpr rd) 0b0100u 0b011u
  | _ ->
    wrongOperands ins

/// <summary>
/// Encodes <rt>, <rs>, <pos>, <size>: the two that name one field of a
/// register.
///
/// The encoding holds where the field starts and where it ENDS, and the two
/// end differently: the extract keeps the length in the upper field while the
/// insert keeps the position of the last bit.
/// </summary>
let private fieldPair major col (add32Pos, add32Size, isIns) ins =
  match ins.Operands with
  | FourOperands(Rg rt, Rg rs, Im pos, Im size) ->
    let lsb = unsigned 6 pos - (if add32Pos then 32u else 0u)
    let last = unsigned 7 size - (if add32Size then 33u else 1u)
    let msb = if isIns then lsb + last else last
    if lsb > 31u || msb > 31u then fail "the field named does not fit" else ()
    let low = (msb <<< 11) ||| (lsb <<< 6) ||| (col <<< 3) ||| 0b100u
    word major (gpr rt) (gpr rs) low
  | _ ->
    wrongOperands ins

/// Encodes <code>: the breakpoint, whose twenty spare bits are a number the
/// hardware ignores and software reads out of the word.
let private breakpoint ins =
  match ins.Operands with
  | OneOperand(Im code) ->
    (unsigned 20 code <<< 6) ||| 0b111u
  | _ ->
    wrongOperands ins

(* POOL32Axf, the pool of everything POOL32A has no room for. Its extension
   grows upwards as the instruction needs fewer operand bits, so what
   identifies one is written in three steps: the three bits above the pool,
   three more above those, and the top four. *)
/// One word of POOL32Axf, given the three fields that name the instruction.
let private axf major rt rs row sub group =
  let low = (row <<< 12) ||| (sub <<< 9) ||| (group <<< 6) ||| 0b111100u
  word major rt rs low

/// The same where the two wide fields hold a number the hardware ignores
/// rather than registers.
let private axfCode (code: uint32) row sub group =
  axf 0b000000u (code >>> 5) (code &&& 0x1fu) row sub group

/// Encodes <rs>, <rt>: a trap that compares two registers. The number it
/// leaves behind for whatever handles it is not printed, so nothing written
/// here can say one and it comes out as zero.
let private trap sub ins =
  match ins.Operands with
  | TwoOperands(Rg rs, Rg rt) ->
    axf 0b000000u (gpr rt) (gpr rs) 0u sub 0b000u
  | _ ->
    wrongOperands ins

/// <summary>
/// Encodes <rt>, <rd>, <sel>: a move to or from a coprocessor 0 register.
///
/// The select field lies where the pool's other members keep the top of
/// their extension, which is why what tells these two apart is two bits
/// rather than three.
/// </summary>
let private moveCP0 major sub ins =
  match ins.Operands with
  | ThreeOperands(Rg rt, Im rd, Im sel) ->
    let low = (unsigned 3 sel <<< 11) ||| (sub <<< 9) ||| 0b011111100u
    word major (gpr rt) (unsigned 5 rd) low
  | _ ->
    wrongOperands ins

/// Encodes <rt>, <rs>: the jumps that leave a return address behind, and the
/// instructions on the bits of one register.
let private twoRegAxf major row sub ins =
  match ins.Operands with
  | TwoOperands(Rg rt, Rg rs) -> axf major (gpr rt) (gpr rs) row sub 0b100u
  | _ -> wrongOperands ins

/// Encodes <rs>, <rt>: the multiplies and divides that write the pair of
/// registers a product too wide for one of them needs. The operands are
/// written the other way round from the instructions above.
let private mulDiv major row ins =
  match ins.Operands with
  | TwoOperands(Rg rs, Rg rt) ->
    axf major (gpr rt) (gpr rs) row 0b101u 0b100u
  | _ ->
    wrongOperands ins

/// Encodes <rt>, <rs>: the two that move between the shadow register sets.
let private shadowMove row ins =
  match ins.Operands with
  | TwoOperands(Rg rt, Rg rs) ->
    axf 0b000000u (gpr rt) (gpr rs) row 0b000u 0b101u
  | _ ->
    wrongOperands ins

/// Encodes the instructions that take no operand at all.
let private noOperandAxf row ins =
  match ins.Operands with
  | NoOperand -> axf 0b000000u 0u 0u row 0b001u 0b101u
  | _ -> wrongOperands ins

/// Encodes <code>: a debug or system instruction whose number fills every bit
/// the operands leave.
let private withCode row sub ins =
  match ins.Operands with
  | OneOperand(Im code) -> axfCode (unsigned 10 code) row sub 0b101u
  | _ -> wrongOperands ins

/// Encodes <rs>: one register in the lower of the two wide fields.
let private oneRegAxf row sub ins =
  match ins.Operands with
  | OneOperand(Rg rs) -> axf 0b000000u 0u (gpr rs) row sub 0b101u
  | _ -> wrongOperands ins

/// Encodes <stype>: how much of what came before has to have been seen before
/// what comes after may run. It sits in the field a register would.
let private sync ins =
  match ins.Operands with
  | OneOperand(Im stype) ->
    axf 0b000000u 0u (unsigned 5 stype) 0b0110u 0b101u 0b101u
  | _ ->
    wrongOperands ins

/// The rows of POOL32Axf that every release has.
let private pool32AxfEncoders () =
  [ Opcode.TEQ, trap 0b000u
    Opcode.TGE, trap 0b001u
    Opcode.TGEU, trap 0b010u
    Opcode.TLT, trap 0b100u
    Opcode.TLTU, trap 0b101u
    Opcode.TNE, trap 0b110u
    Opcode.MFC0, moveCP0 0b000000u 0b00u
    Opcode.MTC0, moveCP0 0b000000u 0b01u
    Opcode.JALR, twoRegAxf 0b000000u 0b0000u 0b111u
    Opcode.JALRHB, twoRegAxf 0b000000u 0b0001u 0b111u
    Opcode.SEB, twoRegAxf 0b000000u 0b0010u 0b101u
    Opcode.SEH, twoRegAxf 0b000000u 0b0011u 0b101u
    Opcode.CLO, twoRegAxf 0b000000u 0b0100u 0b101u
    Opcode.CLZ, twoRegAxf 0b000000u 0b0101u 0b101u
    Opcode.RDHWR, twoRegAxf 0b000000u 0b0110u 0b101u
    Opcode.WSBH, twoRegAxf 0b000000u 0b0111u 0b101u
    Opcode.RDPGPR, shadowMove 0b1110u
    Opcode.WRPGPR, shadowMove 0b1111u
    Opcode.TLBP, noOperandAxf 0b0000u
    Opcode.TLBR, noOperandAxf 0b0001u
    Opcode.TLBWI, noOperandAxf 0b0010u
    Opcode.TLBWR, noOperandAxf 0b0011u
    Opcode.WAIT, withCode 0b1001u 0b001u
    Opcode.DERET, noOperandAxf 0b1110u
    Opcode.ERET, noOperandAxf 0b1111u
    Opcode.DI, oneRegAxf 0b0100u 0b011u
    Opcode.EI, oneRegAxf 0b0101u 0b011u
    Opcode.SYNC, sync
    Opcode.SYSCALL, withCode 0b1000u 0b101u
    Opcode.SDBBP, withCode 0b1101u 0b101u ]

/// The rows of POOL32Axf that Release 6 took away, which are the multiplies
/// and divides that write HI and LO and the four that read and write them.
let private pool32AxfPreR6Encoders () =
  [ Opcode.MULT, mulDiv 0b000000u 0b1000u
    Opcode.MULTU, mulDiv 0b000000u 0b1001u
    Opcode.DIV, mulDiv 0b000000u 0b1010u
    Opcode.DIVU, mulDiv 0b000000u 0b1011u
    Opcode.MADD, mulDiv 0b000000u 0b1100u
    Opcode.MADDU, mulDiv 0b000000u 0b1101u
    Opcode.MSUB, mulDiv 0b000000u 0b1110u
    Opcode.MSUBU, mulDiv 0b000000u 0b1111u
    Opcode.JALRS, twoRegAxf 0b000000u 0b0100u 0b111u
    Opcode.JALRSHB, twoRegAxf 0b000000u 0b0101u 0b111u
    Opcode.MFHI, oneRegAxf 0b0000u 0b110u
    Opcode.MFLO, oneRegAxf 0b0001u 0b110u
    Opcode.MTHI, oneRegAxf 0b0010u 0b110u
    Opcode.MTLO, oneRegAxf 0b0011u 0b110u ]

/// The rows of POOL32A that the grid at the bottom of it names.
let private pool32AEncoders () =
  [ Opcode.SLL, shiftImm 0b000000u 0b000u 0b0000u
    Opcode.SRL, shiftImm 0b000000u 0b000u 0b0001u
    Opcode.SRA, shiftImm 0b000000u 0b000u 0b0010u
    Opcode.ROTR, shiftImm 0b000000u 0b000u 0b0011u
    Opcode.SLLV, shiftReg 0b000000u 0b0000u
    Opcode.SRLV, shiftReg 0b000000u 0b0001u
    Opcode.SRAV, shiftReg 0b000000u 0b0010u
    Opcode.ROTRV, shiftReg 0b000000u 0b0011u
    Opcode.ADD, threeReg 0b000000u 0b010u 0b0100u
    Opcode.ADDU, threeReg 0b000000u 0b010u 0b0101u
    Opcode.SUB, threeReg 0b000000u 0b010u 0b0110u
    Opcode.SUBU, threeReg 0b000000u 0b010u 0b0111u
    Opcode.MUL, threeReg 0b000000u 0b010u 0b1000u
    Opcode.AND, threeReg 0b000000u 0b010u 0b1001u
    Opcode.OR, threeReg 0b000000u 0b010u 0b1010u
    Opcode.NOR, threeReg 0b000000u 0b010u 0b1011u
    Opcode.XOR, threeReg 0b000000u 0b010u 0b1100u
    Opcode.SLT, threeReg 0b000000u 0b010u 0b1101u
    Opcode.SLTU, threeReg 0b000000u 0b010u 0b1110u
    Opcode.LWXS, loadScaled
    Opcode.INS, fieldPair 0b000000u 0b001u (false, false, true)
    Opcode.EXT, fieldPair 0b000000u 0b101u (false, false, false)
    Opcode.BREAK, breakpoint ]

/// The two the grid holds only before Release 6, which took their place for
/// the select instructions.
let private pool32AMoveEncoders () =
  [ Opcode.MOVN, threeReg 0b000000u 0b011u 0b0000u
    Opcode.MOVZ, threeReg 0b000000u 0b011u 0b0001u ]

(* POOL32B and POOL32C, the loads and stores that need four bits of minor
   opcode and so cannot have a major of their own. Both keep the base in the
   lower wide field and spend what is left below the minor on the offset. *)
/// One word of a pool whose minor opcode is the four bits above the offset.
let private pooledMem major rt rs minor (offset: uint32) =
  word major rt rs ((minor <<< 12) ||| (offset &&& 0xfffu))

/// Encodes <rt>, <offset>(<base>): a load or a store with a twelve-bit
/// offset.
let private mem12 major minor ins =
  match ins.Operands with
  | TwoOperands(Rg rt, Mem(baseReg, offset)) ->
    pooledMem major (gpr rt) (gpr baseReg) minor (signed 12 offset)
  | _ ->
    wrongOperands ins

/// The same where what the upper field holds is a hint rather than a
/// register, which is how the two that only touch the caches are written.
let private hint12 major minor ins =
  match ins.Operands with
  | TwoOperands(Im hint, Mem(baseReg, offset)) ->
    pooledMem major (unsigned 5 hint) (gpr baseReg) minor (signed 12 offset)
  | _ ->
    wrongOperands ins

/// <summary>
/// Encodes <rt>, <rt+1>, <offset>(<base>): a pair moved in one instruction.
///
/// Only the first of the two registers is held; the second is the one above
/// it, so a source naming any other pair is asking for an instruction that
/// does not exist rather than for one this cannot encode.
/// </summary>
let private memPair major minor ins =
  match ins.Operands with
  | ThreeOperands(Rg rt, Rg second, Mem(baseReg, offset)) ->
    if gpr second <> gpr rt + 1u then
      fail (string second + " is not the register above " + string rt)
    else
      ()
    pooledMem major (gpr rt) (gpr baseReg) minor (signed 12 offset)
  | _ ->
    wrongOperands ins

/// <summary>
/// The five bits a list of registers is written into.
///
/// The low four count the callee-saved registers from the lowest, so the list
/// is always a run starting at the first of them, and the fifth says whether
/// the return address joins them at the end.
/// </summary>
let private regList regs =
  let saved, withRa =
    match List.rev regs with
    | Register.R31 :: rest -> List.rev rest, 0x10u
    | _ -> regs, 0x00u
  (* MD00594's reglist table ends at 01001, "GPR[16] ... GPR[23], GPR[30]".
     The frame pointer closes a FULL run of eight rather than continuing it,
     $24 not being callee-saved, so it is the one register that may follow
     the run and only behind all eight. *)
  let saved, withFp =
    match List.rev saved with
    | Register.R30 :: rest -> List.rev rest, true
    | _ -> saved, false
  let count = List.length saved
  let expected =
    [ for i in 0 .. count - 1 ->
        LanguagePrimitives.EnumOfValue<int, Register>(16 + i) ]
  if count > 8 || saved <> expected || (withFp && count <> 8) then
    fail "a register list is a run from $16, then $30, then $31"
  else
    ()
  (if withFp then 9u else uint32 count) ||| withRa

/// Encodes <registers>, <offset>(<base>): the loads and stores of a whole
/// list.
let private memList major minor ins =
  match ins.Operands with
  | TwoOperands(OpRegList regs, Mem(baseReg, offset)) ->
    pooledMem major (regList regs) (gpr baseReg) minor (signed 12 offset)
  | _ ->
    wrongOperands ins

/// Encodes a load or store that reaches the address a user-mode program would
/// see, which spends three more bits saying which and keeps nine for the
/// offset.
let private mem9 minor sub ins =
  match ins.Operands with
  | TwoOperands(Rg rt, Mem(baseReg, offset)) ->
    let low = (minor <<< 12) ||| (sub <<< 9) ||| (signed 9 offset &&& 0x1ffu)
    word 0b011000u (gpr rt) (gpr baseReg) low
  | _ ->
    wrongOperands ins

/// The same for the two of them whose upper field holds a hint.
let private hint9 minor sub ins =
  match ins.Operands with
  | TwoOperands(Im hint, Mem(baseReg, offset)) ->
    let low = (minor <<< 12) ||| (sub <<< 9) ||| (signed 9 offset &&& 0x1ffu)
    word 0b011000u (unsigned 5 hint) (gpr baseReg) low
  | _ ->
    wrongOperands ins

/// The rows of POOL32B, which are the pairs, the lists and the cache hint.
let private pool32BEncoders () =
  [ Opcode.LWP, memPair 0b001000u 0b0001u
    Opcode.LDP, memPair 0b001000u 0b0100u
    Opcode.LWM, memList 0b001000u 0b0101u
    Opcode.CACHE, hint12 0b001000u 0b0110u
    Opcode.LDM, memList 0b001000u 0b0111u
    Opcode.SWP, memPair 0b001000u 0b1001u
    Opcode.SDP, memPair 0b001000u 0b1100u
    Opcode.SWM, memList 0b001000u 0b1101u
    Opcode.SDM, memList 0b001000u 0b1111u ]

/// The rows of POOL32C, which are the unaligned accesses, the ones that pair
/// with a store-conditional, and the EVA forms below them.
let private pool32CEncoders () =
  [ Opcode.LWL, mem12 0b011000u 0b0000u
    Opcode.LWR, mem12 0b011000u 0b0001u
    Opcode.PREF, hint12 0b011000u 0b0010u
    Opcode.LL, mem12 0b011000u 0b0011u
    Opcode.LDL, mem12 0b011000u 0b0100u
    Opcode.LDR, mem12 0b011000u 0b0101u
    Opcode.LLD, mem12 0b011000u 0b0111u
    Opcode.SWL, mem12 0b011000u 0b1000u
    Opcode.SWR, mem12 0b011000u 0b1001u
    Opcode.SC, mem12 0b011000u 0b1011u
    Opcode.SDL, mem12 0b011000u 0b1100u
    Opcode.SDR, mem12 0b011000u 0b1101u
    Opcode.LWU, mem12 0b011000u 0b1110u
    Opcode.SCD, mem12 0b011000u 0b1111u
    Opcode.LBUE, mem9 0b0110u 0b000u
    Opcode.LHUE, mem9 0b0110u 0b001u
    Opcode.LWLE, mem9 0b0110u 0b010u
    Opcode.LWRE, mem9 0b0110u 0b011u
    Opcode.LBE, mem9 0b0110u 0b100u
    Opcode.LHE, mem9 0b0110u 0b101u
    Opcode.LLE, mem9 0b0110u 0b110u
    Opcode.LWE, mem9 0b0110u 0b111u
    Opcode.SWLE, mem9 0b1010u 0b000u
    Opcode.SWRE, mem9 0b1010u 0b001u
    Opcode.PREFE, hint9 0b1010u 0b010u
    Opcode.CACHEE, hint9 0b1010u 0b011u
    Opcode.SBE, mem9 0b1010u 0b100u
    Opcode.SHE, mem9 0b1010u 0b101u
    Opcode.SCE, mem9 0b1010u 0b110u
    Opcode.SWE, mem9 0b1010u 0b111u ]

(* POOL32I, whose minor opcode sits where the upper register would. Everything
   here names one register and one sixteen-bit value, so the field the older
   encoding spends on a second register is free for the minor. *)
/// Encodes <rs>, <place>: a branch that compares one register against zero.
let private branchZero minor ins =
  match ins.Operands with
  | TwoOperands(Rg rs, Place distance) ->
    word 0b010000u minor (gpr rs) (branchOffset 16 distance)
  | _ ->
    wrongOperands ins

/// Encodes <rs>, <immediate>: a trap that compares a register against a
/// written number, and the load of a number into the top of a register.
let private immPool32I minor width ins =
  match ins.Operands with
  | TwoOperands(Rg rs, Im value) ->
    let bits =
      if width = 16 then immediate16 value else unsigned width value
    word 0b010000u minor (gpr rs) bits
  | _ ->
    wrongOperands ins

/// Encodes <offset>(<base>): the one member that names memory rather than a
/// register and a number.
let private synci ins =
  match ins.Operands with
  | OneOperand(Mem(baseReg, offset)) ->
    word 0b010000u 0b10000u (gpr baseReg) (signed 16 offset)
  | _ ->
    wrongOperands ins

/// Encodes <cc>, <place>: a branch on what the floating-point unit last
/// tested. The condition it reads sits above the field the minor opcode
/// leaves.
let private branchFP minor ins =
  match ins.Operands with
  | TwoOperands(Im cc, Place distance) ->
    word 0b010000u minor (unsigned 3 cc <<< 2) (branchOffset 16 distance)
  | _ ->
    wrongOperands ins

/// The rows of POOL32I every release has.
let private pool32IEncoders () =
  [ Opcode.BLTZ, branchZero 0b00000u
    Opcode.BGEZ, branchZero 0b00010u
    Opcode.BLEZ, branchZero 0b00100u
    Opcode.BNEZC, branchZero 0b00101u
    Opcode.BGTZ, branchZero 0b00110u
    Opcode.BEQZC, branchZero 0b00111u
    Opcode.LUI, immPool32I 0b01101u 16
    Opcode.SYNCI, synci ]

/// The rows of POOL32I that Release 6 took away, which are the branches that
/// leave a return address behind and the traps on a written number.
let private pool32IPreR6Encoders () =
  [ Opcode.BLTZAL, branchZero 0b00001u
    Opcode.BGEZAL, branchZero 0b00011u
    Opcode.TLTI, immPool32I 0b01000u 16
    Opcode.TGEI, immPool32I 0b01001u 16
    Opcode.TLTIU, immPool32I 0b01010u 16
    Opcode.TGEIU, immPool32I 0b01011u 16
    Opcode.TNEI, immPool32I 0b01100u 16
    Opcode.TEQI, immPool32I 0b01110u 16
    Opcode.BLTZALS, branchZero 0b10001u
    Opcode.BGEZALS, branchZero 0b10011u
    Opcode.BC1F, branchFP 0b11100u
    Opcode.BC1T, branchFP 0b11101u ]

(* POOL32S, which holds the 64-bit members of what POOL32A holds. The layout
   is POOL32A's and so are the minor opcodes: a doubleword instruction sits at
   the same row and column its word counterpart does. The shifts are the
   exception, the ones reaching past bit 31 taking a row of their own. *)
/// The rows of POOL32S every release has.
let private pool32SEncoders () =
  [ Opcode.DSLL, shiftImm 0b010110u 0b000u 0b0000u
    Opcode.DSRL, shiftImm 0b010110u 0b000u 0b0001u
    Opcode.DSRA, shiftImm 0b010110u 0b000u 0b0010u
    Opcode.DROTR, shiftImm 0b010110u 0b000u 0b0011u
    Opcode.DSLL32, shiftImm 0b010110u 0b001u 0b0000u
    Opcode.DSRL32, shiftImm 0b010110u 0b001u 0b0001u
    Opcode.DSRA32, shiftImm 0b010110u 0b001u 0b0010u
    Opcode.DROTR32, shiftImm 0b010110u 0b001u 0b0011u
    Opcode.DSLLV, shiftReg 0b010110u 0b0000u
    Opcode.DSRLV, shiftReg 0b010110u 0b0001u
    Opcode.DSRAV, shiftReg 0b010110u 0b0010u
    Opcode.DROTRV, shiftReg 0b010110u 0b0011u
    Opcode.DADD, threeReg 0b010110u 0b010u 0b0100u
    Opcode.DADDU, threeReg 0b010110u 0b010u 0b0101u
    Opcode.DSUB, threeReg 0b010110u 0b010u 0b0110u
    Opcode.DSUBU, threeReg 0b010110u 0b010u 0b0111u
    Opcode.DINSM, fieldPair 0b010110u 0b000u (false, true, true)
    Opcode.DINS, fieldPair 0b010110u 0b001u (false, false, true)
    Opcode.DEXTU, fieldPair 0b010110u 0b010u (true, false, false)
    Opcode.DEXTM, fieldPair 0b010110u 0b100u (false, true, false)
    Opcode.DEXT, fieldPair 0b010110u 0b101u (false, false, false)
    Opcode.DINSU, fieldPair 0b010110u 0b110u (true, false, true)
    Opcode.DMFC0, moveCP0 0b010110u 0b00u
    Opcode.DMTC0, moveCP0 0b010110u 0b01u
    Opcode.DCLO, twoRegAxf 0b010110u 0b0100u 0b101u
    Opcode.DCLZ, twoRegAxf 0b010110u 0b0101u 0b101u
    Opcode.DSBH, twoRegAxf 0b010110u 0b0111u 0b101u
    Opcode.DSHD, twoRegAxf 0b010110u 0b1111u 0b101u ]

/// The four of POOL32S that Release 6 took away, which write the pair of
/// registers a doubleword product needs.
let private pool32SPreR6Encoders () =
  [ Opcode.DMULT, mulDiv 0b010110u 0b1000u
    Opcode.DMULTU, mulDiv 0b010110u 0b1001u
    Opcode.DDIV, mulDiv 0b010110u 0b1010u
    Opcode.DDIVU, mulDiv 0b010110u 0b1011u ]

(* POOL32F, which holds the floating-point unit. Its members are told apart
   the way POOL32A's are, except that the format an instruction reads is
   itself part of what names it. *)
/// The two bits a format is written as where the encoding keeps it in a field
/// of its own. They are not the numbers the format is named by elsewhere.
let private fmtBits ins =
  match ins.Fmt with
  | Some FPRFormat.S -> 0b00u
  | Some FPRFormat.D -> 0b01u
  | Some FPRFormat.PS -> 0b10u
  | _ -> fail (string ins.Opcode + " does not come in that format")

/// The ten bits a member of POOL32Fxf is named by, chosen by the format the
/// mnemonic carries. The format is not one field there, sitting in a
/// different place for different members, so each pair is listed rather than
/// derived.
let private codeFor codes ins =
  let ofFmt f = List.tryFind (fst >> (=) f) codes
  match Option.bind ofFmt ins.Fmt with
  | Some(_, code) -> code
  | None -> fail (string ins.Opcode + " does not come in that format")

/// One word of POOL32Fxf, whose members name two registers and nothing else.
let private fxf upper lower code =
  word 0b010101u upper lower ((code <<< 6) ||| 0b111011u)

/// Encodes <ft>, <fs>: a floating-point instruction on two floating-point
/// registers.
let private fxfTwo codes ins =
  match ins.Operands with
  | TwoOperands(Rg ft, Rg fs) -> fxf (fpr ft) (fpr fs) (codeFor codes ins)
  | _ -> wrongOperands ins

/// Encodes <rt>, <fs>: a move between a general register and a
/// floating-point one, which names one of each.
let private fxfMove code ins =
  match ins.Operands with
  | TwoOperands(Rg rt, Rg fs) -> fxf (gpr rt) (fpr fs) code
  | _ -> wrongOperands ins

/// The same for the two whose name already carries the format they read, so
/// that nothing is left for a table of formats to choose between.
let private fxfFixed code ins =
  match ins.Operands with
  | TwoOperands(Rg ft, Rg fs) -> fxf (fpr ft) (fpr fs) code
  | _ -> wrongOperands ins

/// Encodes <rt>, <rs>, <cc>: the move on a condition the floating-point unit
/// last tested, which writes a GENERAL register and so is named among the
/// two-register members rather than among the formatted ones.
let private fxfMoveCC code ins =
  match ins.Operands with
  | ThreeOperands(Rg rt, Rg rs, Im cc) ->
    let low = (unsigned 3 cc <<< 13) ||| (code <<< 6) ||| 0b111011u
    word 0b010101u (gpr rt) (gpr rs) low
  | _ ->
    wrongOperands ins

/// Encodes <cc>, <fs>, <ft>: a comparison, whose result goes to one of eight
/// condition codes rather than to a register.
let private compare ins =
  match ins.Operands, ins.Condition with
  | ThreeOperands(Im cc, Rg fs, Rg ft), Some cond ->
    let fmt =
      match ins.Fmt with
      | Some FPRFormat.S -> 0b000u
      | Some FPRFormat.D -> 0b001u
      | Some FPRFormat.PS -> 0b010u
      | _ -> fail "a comparison comes in three formats"
    word 0b010101u (fpr ft) (fpr fs)
      ((unsigned 3 cc <<< 13) ||| (fmt <<< 10) ||| (uint32 (int cond) <<< 6)
       ||| 0b111100u)
  | _ ->
    wrongOperands ins

/// One word of the grid POOL32F opens with, whose row and column sit where
/// POOL32A's do.
let private fgrid upper lower low row col =
  word 0b010101u upper lower ((low <<< 11) ||| (col <<< 6) ||| (row <<< 3))

/// Encodes <fd>, <fs>, <ft>: the four that pair halves of two registers and
/// the one that builds a pair out of two singles.
let private threeFPR row col ins =
  match ins.Operands with
  | ThreeOperands(Rg fd, Rg fs, Rg ft) ->
    fgrid (fpr ft) (fpr fs) (fpr fd) row col
  | _ ->
    wrongOperands ins

/// Encodes <fd>, <index>(<base>): a floating-point access whose offset is a
/// register rather than a written number.
let private memIdxFPR row col ins =
  match ins.Operands with
  | TwoOperands(Rg fd, MemIdx(baseReg, index)) ->
    fgrid (gpr index) (gpr baseReg) (fpr fd) row col
  | _ ->
    wrongOperands ins

/// The same where the upper field holds a hint rather than a register.
let private prefx ins =
  match ins.Operands with
  | TwoOperands(Im hint, MemIdx(baseReg, index)) ->
    fgrid (gpr index) (gpr baseReg) (unsigned 5 hint) 0b100u 0b110u
  | _ ->
    wrongOperands ins

/// Encodes <ft>, <fs>, <cc>: a formatted move on a condition. The condition
/// it reads sits where the destination does for the rest of the grid, which
/// is why the destination is the upper field here.
let private moveOnCC tf ins =
  match ins.Operands with
  | ThreeOperands(Rg ft, Rg fs, Im cc) ->
    word 0b010101u (fpr ft) (fpr fs)
      ((unsigned 3 cc <<< 13) ||| (fmtBits ins <<< 9) ||| (tf <<< 6)
       ||| 0b100000u)
  | _ ->
    wrongOperands ins

/// Encodes <fd>, <fs>, <ft>: the arithmetic, whose format sits one bit lower
/// than the conditional move's.
let private arith op ins =
  match ins.Operands with
  | ThreeOperands(Rg fd, Rg fs, Rg ft) ->
    let low =
      (fpr fd <<< 11) ||| (fmtBits ins <<< 8) ||| (op <<< 6) ||| 0b110000u
    word 0b010101u (fpr ft) (fpr fs) low
  | _ ->
    wrongOperands ins

/// Encodes <fd>, <fs>, <rt>: a formatted move on whether a GENERAL register
/// is zero.
let private moveOnZero tf ins =
  match ins.Operands with
  | ThreeOperands(Rg fd, Rg fs, Rg rt) ->
    let low =
      (fpr fd <<< 11) ||| (fmtBits ins <<< 8) ||| (tf <<< 6) ||| 0b111000u
    word 0b010101u (gpr rt) (fpr fs) low
  | _ ->
    wrongOperands ins

/// Encodes <fd>, <fr>, <fs>, <ft>: one of the fused families, whose fourth
/// register sits in the bits the rest of the pool spends on a minor opcode.
let private fused sub row ins =
  match ins.Operands with
  | FourOperands(Rg fd, Rg fr, Rg fs, Rg ft) ->
    word 0b010101u (fpr ft) (fpr fs)
      ((fpr fd <<< 11) ||| (fpr fr <<< 6) ||| ((row + fmtBits ins) <<< 3)
       ||| sub)
  | _ ->
    wrongOperands ins

/// Encodes <fd>, <fs>, <ft>, <rs>: the align, which reads a byte count out of
/// a general register where the fused families read a fourth float.
let private alnv ins =
  match ins.Operands with
  | FourOperands(Rg fd, Rg fs, Rg ft, Rg rs) ->
    let low = (fpr fd <<< 11) ||| (gpr rs <<< 6) ||| 0b011001u
    word 0b010101u (fpr ft) (fpr fs) low
  | _ ->
    wrongOperands ins

/// The three formats a move, an absolute value or a negation comes in, and
/// the three a conversion to double or to single reads.
let private movCodes =
  [ FPRFormat.S, 0x001u; FPRFormat.D, 0x081u; FPRFormat.PS, 0x101u ]

let private absCodes =
  [ FPRFormat.S, 0x00Du; FPRFormat.D, 0x08Du; FPRFormat.PS, 0x10Du ]

let private negCodes =
  [ FPRFormat.S, 0x02Du; FPRFormat.D, 0x0ADu; FPRFormat.PS, 0x12Du ]

let private cvtdCodes =
  [ FPRFormat.S, 0x04Du; FPRFormat.W, 0x0CDu; FPRFormat.L, 0x14Du ]

let private cvtsCodes =
  [ FPRFormat.D, 0x06Du; FPRFormat.W, 0x0EDu; FPRFormat.L, 0x16Du ]

/// The rows of POOL32F every release has.
let private pool32FEncoders () =
  [ Opcode.MOV, fxfTwo movCodes
    Opcode.ABS, fxfTwo absCodes
    Opcode.NEG, fxfTwo negCodes
    Opcode.SQRT, fxfTwo [ FPRFormat.S, 0x028u; FPRFormat.D, 0x128u ]
    Opcode.RECIP, fxfTwo [ FPRFormat.S, 0x048u; FPRFormat.D, 0x148u ]
    Opcode.RSQRT, fxfTwo [ FPRFormat.S, 0x008u; FPRFormat.D, 0x108u ]
    Opcode.CVTD, fxfTwo cvtdCodes
    Opcode.CVTS, fxfTwo cvtsCodes
    Opcode.CVTW, fxfTwo [ FPRFormat.S, 0x024u; FPRFormat.D, 0x124u ]
    Opcode.CVTL, fxfTwo [ FPRFormat.S, 0x004u; FPRFormat.D, 0x104u ]
    Opcode.TRUNCW, fxfTwo [ FPRFormat.S, 0x0ACu; FPRFormat.D, 0x1ACu ]
    Opcode.TRUNCL, fxfTwo [ FPRFormat.S, 0x08Cu; FPRFormat.D, 0x18Cu ]
    Opcode.CEILW, fxfTwo [ FPRFormat.S, 0x06Cu; FPRFormat.D, 0x16Cu ]
    Opcode.CEILL, fxfTwo [ FPRFormat.S, 0x04Cu; FPRFormat.D, 0x14Cu ]
    Opcode.FLOORW, fxfTwo [ FPRFormat.S, 0x02Cu; FPRFormat.D, 0x12Cu ]
    Opcode.FLOORL, fxfTwo [ FPRFormat.S, 0x00Cu; FPRFormat.D, 0x10Cu ]
    Opcode.ROUNDW, fxfTwo [ FPRFormat.S, 0x0ECu; FPRFormat.D, 0x1ECu ]
    Opcode.ROUNDL, fxfTwo [ FPRFormat.S, 0x0CCu; FPRFormat.D, 0x1CCu ]
    Opcode.MFC1, fxfMove 0x080u
    Opcode.MTC1, fxfMove 0x0A0u
    Opcode.DMFC1, fxfMove 0x090u
    Opcode.DMTC1, fxfMove 0x0B0u
    Opcode.MFHC1, fxfMove 0x0C0u
    Opcode.MTHC1, fxfMove 0x0E0u
    Opcode.CFC1, fxfMove 0x040u
    Opcode.CTC1, fxfMove 0x060u
    Opcode.MOVF, fxfMoveCC 0b0000101u
    Opcode.MOVT, fxfMoveCC 0b0100101u
    Opcode.CVTSPL, fxfFixed 0x084u
    Opcode.CVTSPU, fxfFixed 0x0A4u
    Opcode.CVTPSS, threeFPR 0b000u 0b110u
    Opcode.ADD, arith 0b00u
    Opcode.SUB, arith 0b01u
    Opcode.MUL, arith 0b10u
    Opcode.DIV, arith 0b11u ]

/// The rows of POOL32F that Release 6 took away: the paired-single shuffles,
/// the indexed accesses, the conditional moves and the fused families.
let private pool32FPreR6Encoders () =
  [ Opcode.PLLPS, threeFPR 0b000u 0b010u
    Opcode.PLUPS, threeFPR 0b000u 0b011u
    Opcode.PULPS, threeFPR 0b000u 0b100u
    Opcode.PUUPS, threeFPR 0b000u 0b101u
    Opcode.LWXC1, memIdxFPR 0b001u 0b001u
    Opcode.SWXC1, memIdxFPR 0b001u 0b010u
    Opcode.LDXC1, memIdxFPR 0b001u 0b011u
    Opcode.SDXC1, memIdxFPR 0b001u 0b100u
    Opcode.LUXC1, memIdxFPR 0b001u 0b101u
    Opcode.SUXC1, memIdxFPR 0b001u 0b110u
    Opcode.PREFX, prefx
    Opcode.MOVF, moveOnCC 0u
    Opcode.MOVT, moveOnCC 1u
    Opcode.MOVN, moveOnZero 0u
    Opcode.MOVZ, moveOnZero 1u
    Opcode.C, compare
    Opcode.MADD, fused 0b001u 0b000u
    Opcode.MSUB, fused 0b001u 0b100u
    Opcode.NMADD, fused 0b010u 0b000u
    Opcode.NMSUB, fused 0b010u 0b100u
    Opcode.ALNVPS, alnv ]

/// <summary>
/// The rows the major opcode alone decides, which are the same under every
/// release.
/// </summary>
let private majorEncoders () =
  [ Opcode.ADDIU, rtRsImm 0b001100u 16
    Opcode.ORI, rtRsImm 0b010100u 16
    Opcode.XORI, rtRsImm 0b011100u 16
    Opcode.SLTI, rtRsImm 0b100100u 16
    Opcode.SLTIU, rtRsImm 0b101100u 16
    Opcode.ANDI, rtRsImm 0b110100u 16
    Opcode.DADDIU, rtRsImm 0b010111u 16
    Opcode.LB, memWide 0b000111u
    Opcode.LBU, memWide 0b000101u
    Opcode.LH, memWide 0b001111u
    Opcode.LHU, memWide 0b001101u
    Opcode.LW, memWide 0b111111u
    Opcode.LD, memWide 0b110111u
    Opcode.SB, memWide 0b000110u
    Opcode.SH, memWide 0b001110u
    Opcode.SW, memWide 0b111110u
    Opcode.SD, memWide 0b110110u
    Opcode.LWC1, memWideFP 0b100111u
    Opcode.LDC1, memWideFP 0b101111u
    Opcode.SWC1, memWideFP 0b100110u
    Opcode.SDC1, memWideFP 0b101110u ]

/// <summary>
/// The three bits a register is written into where a field holds only eight
/// of the thirty-two.
///
/// The eight are the two a compiler keeps values in across a call and the six
/// it passes arguments and returns results in, which is what a short encoding
/// spends its register bits on.
/// </summary>
let private reg3 (reg: Register) =
  match reg with
  | Register.R16 -> 0u
  | Register.R17 -> 1u
  | Register.R2 -> 2u
  | Register.R3 -> 3u
  | Register.R4 -> 4u
  | Register.R5 -> 5u
  | Register.R6 -> 6u
  | Register.R7 -> 7u
  | _ -> fail (string reg + " is not one of the eight a short field names")

/// <summary>
/// Encodes <rd>, <place>: the add of a distance to the address this
/// instruction is at.
///
/// What the encoding holds counts from that address with the low TWO bits
/// cleared, and an instruction here may begin at any even one, so a source
/// that puts this at an odd halfword accounts for the two bytes itself: what
/// reaches here is a distance and not the address it was taken from. The
/// distance is read as unsigned, so it only ever points forwards.
/// </summary>
let private addiupc ins =
  match ins.Operands with
  | TwoOperands(Rg rd, Place distance) ->
    if distance % 4L <> 0L then fail "the place named is not a word away"
    else ()
    (0b011110u <<< 26) ||| (reg3 rd <<< 23)
    ||| unsigned 23 (uint64 distance >>> 2)
  | _ ->
    wrongOperands ins

/// The rows the releases before 6 have and Release 6 does not, which are the
/// ones whose major opcode it took for something else.
let private preR6Encoders () =
  [ Opcode.ADDI, rtRsImm 0b000100u 16
    Opcode.BEQ, branchPair 0b100101u
    Opcode.BNE, branchPair 0b101101u
    Opcode.J, jump 0b110101u 1
    Opcode.JAL, jump 0b111101u 1
    Opcode.JALS, jump 0b011101u 1
    (* JALX crosses into the other encoding, so what it names is a WORD of
       the region where every other jump here names a halfword. *)
    Opcode.JALX, jump 0b111100u 2
    Opcode.ADDIUPC, addiupc ]

/// The rows Release 6 put in their place.
let private r6Encoders () =
  [ Opcode.LUI, rtImm 0b000100u
    Opcode.AUI, rtRsImm 0b000100u 16
    Opcode.DAUI, rtRsImm 0b111100u 16
    Opcode.BC, branchWide 0b100101u
    Opcode.BALC, branchWide 0b101101u ]

(* The branches Release 6 gave one major opcode to several of. Which one a
   word means is settled by the two register fields -- one of them being zero,
   or the two being equal, names a compare-with-zero form -- so an encoder
   that let a source write any pair would write one instruction and read back
   another. Each of them refuses the pairs that are not its own. *)
/// Encodes <rt>, <place>: the member of a shared major opcode whose lower
/// register field is the one that says which member it is.
let private branchOneR6 major sameField ins =
  match ins.Operands with
  | TwoOperands(Rg rt, Place distance) ->
    let rt = gpr rt
    if rt = 0u then fail "this branch does not name the zero register"
    else ()
    let rs = if sameField then rt else 0u
    word major rt rs (branchOffset 16 distance)
  | _ ->
    wrongOperands ins

/// Encodes <rs>, <rt>, <place>: the member that compares two registers, which
/// is the one the other two are not.
let private branchTwoR6 major wantsOrder ins =
  match ins.Operands with
  | ThreeOperands(Rg rs, Rg rt, Place distance) ->
    let rs, rt = gpr rs, gpr rt
    if wantsOrder && rs >= rt then
      fail "this branch reads the lower register as the smaller"
    elif not wantsOrder && (rt = 0u || rs = 0u || rs = rt) then
      fail "this branch does not name that pair"
    else
      ()
    word major rt rs (branchOffset 16 distance)
  | _ ->
    wrongOperands ins

/// Encodes <rs>, <rt>, <place>: the one that branches on an overflow, which
/// is the member whose lower field is at or above its upper one.
let private branchOverflowR6 major ins =
  match ins.Operands with
  | ThreeOperands(Rg rs, Rg rt, Place distance) ->
    if gpr rs < gpr rt then
      fail "this branch reads the lower register as the greater"
    else
      ()
    word major (gpr rt) (gpr rs) (branchOffset 16 distance)
  | _ ->
    wrongOperands ins

/// Encodes <rs>, <offset>: an indexed jump, which is the member of its major
/// opcode whose upper register field is the base it does not need.
let private indexedJumpR6 major ins =
  match ins.Operands with
  | TwoOperands(Rg rs, Im offset) ->
    word major 0u (gpr rs) (immediate16 offset)
  | _ ->
    wrongOperands ins

/// Encodes <rt>, <place>: the compact branch beside that jump, which takes
/// the upper field for itself and spends the twenty-one bits below it on an
/// offset where the jump has sixteen.
let private branchWideR6 major ins =
  match ins.Operands with
  | TwoOperands(Rg rt, Place distance) ->
    let rt = gpr rt
    if rt = 0u then fail "this branch does not name the zero register"
    else ()
    (major <<< 26) ||| (rt <<< 21) ||| branchOffset 21 distance
  | _ ->
    wrongOperands ins

/// <summary>
/// Encodes <rt>, <place>: a member of PCREL, the major opcode Release 6 gave
/// to the family that reads from a distance away.
///
/// The field that says which member it is starts at bit 20 and its LENGTH
/// varies, so what a member holds below its own selector is what is left.
/// </summary>
let private pcrelR6 selector width shift ins =
  match ins.Operands with
  | TwoOperands(Rg rt, Place distance) ->
    let step = 1L <<< shift
    if distance % step <> 0L then fail "the place named is not a step away"
    else ()
    let bits = signed (width - shift) (distance >>> shift)
    (0b011110u <<< 26) ||| (gpr rt <<< 21) ||| (selector <<< (width - shift))
    ||| bits
  | _ ->
    wrongOperands ins

/// The two members of PCREL that hold a written number rather than a place,
/// which is what makes them the ones with the longest selector.
let private pcrelImmR6 selector ins =
  match ins.Operands with
  | TwoOperands(Rg rt, Im value) ->
    word 0b011110u (gpr rt) selector (unsigned 16 value)
  | _ ->
    wrongOperands ins

/// Encodes <rd>, <rs>, <rt>, <sa>: the add of one register to another shifted
/// left by a written one or two.
let private shiftAdd major ins =
  match ins.Operands with
  | FourOperands(Rg rd, Rg rs, Rg rt, Im sa) ->
    let low = (gpr rd <<< 11) ||| (unsigned 2 sa <<< 6) ||| 0b100000u
    word major (gpr rt) (gpr rs) low
  | _ ->
    wrongOperands ins

/// The rows Release 6 has and the releases before it do not.
let private r6BranchEncoders () =
  [ Opcode.BLEZALC, branchOneR6 0b110000u false
    Opcode.BGEZALC, branchOneR6 0b110000u true
    Opcode.BGEUC, branchTwoR6 0b110000u false
    Opcode.BGTZALC, branchOneR6 0b111000u false
    Opcode.BLTZALC, branchOneR6 0b111000u true
    Opcode.BLTUC, branchTwoR6 0b111000u false
    Opcode.BGTZC, branchOneR6 0b110101u false
    Opcode.BLTZC, branchOneR6 0b110101u true
    Opcode.BLTC, branchTwoR6 0b110101u false
    Opcode.BLEZC, branchOneR6 0b111101u false
    Opcode.BGEZC, branchOneR6 0b111101u true
    Opcode.BGEC, branchTwoR6 0b111101u false
    Opcode.BNVC, branchOverflowR6 0b011111u
    Opcode.BNEZALC, branchOneR6 0b011111u false
    Opcode.BNEC, branchTwoR6 0b011111u true
    Opcode.BOVC, branchOverflowR6 0b011101u
    Opcode.BEQZALC, branchOneR6 0b011101u false
    Opcode.BEQC, branchTwoR6 0b011101u true
    Opcode.JIC, indexedJumpR6 0b100000u
    Opcode.BEQZC, branchWideR6 0b100000u
    Opcode.JIALC, indexedJumpR6 0b101000u
    Opcode.BNEZC, branchWideR6 0b101000u
    Opcode.ADDIUPC, pcrelR6 0b00u 21 2
    Opcode.LWPC, pcrelR6 0b01u 21 2
    Opcode.LWUPC, pcrelR6 0b10u 21 2
    Opcode.LDPC, pcrelR6 0b110u 21 3
    Opcode.AUIPC, pcrelImmR6 0b11110u
    Opcode.ALUIPC, pcrelImmR6 0b11111u
    Opcode.LSA, shiftAdd 0b000000u
    Opcode.DLSA, shiftAdd 0b010110u ]

(* The short forms that have no long one. Everything else this assembler
   writes is four bytes, because where both lengths exist they say the same
   thing; these say something no four-byte word does. *)
/// One halfword, given the major opcode and what it leaves.
let private halfword (major: uint32) (low: uint32) = (major <<< 10) ||| low

/// The place a short branch names, which is a count of halfwords from the
/// instruction after this one -- and that one is two bytes along, not four.
let private shortOffset width (distance: int64) =
  if distance % 2L = 0L then signed width ((distance - 2L) >>> 1)
  else fail "a branch cannot reach a place that is not a whole halfword away"

/// Encodes <rs>: a jump to what one register holds, which POOL16C names with
/// five bits of minor opcode above five of register.
let private shortJump minor ins =
  match ins.Operands with
  | OneOperand(Rg rs) -> halfword 0b010001u ((minor <<< 5) ||| gpr rs)
  | _ -> wrongOperands ins

/// The same under Release 6, which moved the minor opcode to the bottom of
/// the halfword and the register to the top.
let private shortJumpR6 selector ins =
  match ins.Operands with
  | OneOperand(Rg rs) ->
    halfword 0b010001u ((gpr rs <<< 5) ||| (selector <<< 3) ||| 0b11u)
  | _ ->
    wrongOperands ins

/// Encodes <adjust>: the return that adds to the stack pointer on its way,
/// whose adjustment is a count of words.
let private jumpAdjust ins =
  match ins.Operands with
  | OneOperand(Im adjust) ->
    halfword 0b010001u ((0b11000u <<< 5) ||| unsigned 5 (adjust >>> 2))
  | _ ->
    wrongOperands ins

/// The same under Release 6, where the return is compact and the adjustment
/// sits above the minor opcode rather than below it.
let private jumpAdjustR6 ins =
  match ins.Operands with
  | OneOperand(Im adjust) ->
    halfword 0b010001u ((unsigned 5 (adjust >>> 2) <<< 5) ||| 0b10011u)
  | _ ->
    wrongOperands ins

/// Encodes <place>: the unconditional branch, which spends every bit the
/// major opcode leaves on how far it goes.
let private shortBranch ins =
  match ins.Operands with
  | OneOperand(Place distance) -> halfword 0b110011u (shortOffset 10 distance)
  | _ -> wrongOperands ins

/// <summary>
/// The three bits MOVEP writes a source register into.
///
/// It is a set of its own, not the one the other short fields use: the zero
/// register is reachable where they have $16, and $18 to $20 are reachable
/// where they have $4 to $7.
/// </summary>
let private movepReg (reg: Register) =
  match reg with
  | Register.R0 -> 0u
  | Register.R17 -> 1u
  | Register.R2 -> 2u
  | Register.R3 -> 3u
  | Register.R16 -> 4u
  | Register.R18 -> 5u
  | Register.R19 -> 6u
  | Register.R20 -> 7u
  | _ -> fail (string reg + " is not a register MOVEP moves from")

/// <summary>
/// The three bits MOVEP writes its pair of destinations into.
///
/// The eight are the argument registers a call sets up, taken two at a time
/// in the combinations a compiler emits, so the field is a choice of eight
/// pairs rather than two register numbers.
/// </summary>
let private movepPair (rd: Register) (re: Register) =
  match rd, re with
  | Register.R5, Register.R6 -> 0u
  | Register.R5, Register.R7 -> 1u
  | Register.R6, Register.R7 -> 2u
  | Register.R4, Register.R21 -> 3u
  | Register.R4, Register.R22 -> 4u
  | Register.R4, Register.R5 -> 5u
  | Register.R4, Register.R6 -> 6u
  | Register.R4, Register.R7 -> 7u
  | _ -> fail (string rd + " and " + string re + " are not a pair MOVEP writes")

/// Encodes <rd>, <re>, <rs>, <rt>: the move of two registers at once, which
/// is the whole of POOL16F before Release 6.
let private movep ins =
  match ins.Operands with
  | FourOperands(Rg rd, Rg re, Rg rs, Rg rt) ->
    halfword 0b100001u
      ((movepPair rd re <<< 7) ||| (movepReg rt <<< 4) ||| (movepReg rs <<< 1))
  | _ ->
    wrongOperands ins

/// The same under Release 6, which moved it into POOL16C and spread the
/// field naming its first source over three places.
let private movepR6 ins =
  match ins.Operands with
  | FourOperands(Rg rd, Rg re, Rg rs, Rg rt) ->
    let rs = movepReg rs
    halfword 0b010001u
      ((movepPair rd re <<< 7) ||| (movepReg rt <<< 4) ||| ((rs >>> 2) <<< 3)
       ||| 0b100u ||| (rs &&& 0b11u))
  | _ ->
    wrongOperands ins

/// The short forms the releases before 6 have.
let private shortEncoders () =
  [ Opcode.JR, shortJump 0b01100u
    Opcode.JRC, shortJump 0b01101u
    Opcode.JALR, shortJump 0b01110u
    Opcode.JALRS, shortJump 0b01111u
    Opcode.JRADDIUSP, jumpAdjust
    Opcode.B, shortBranch
    Opcode.MOVEP, movep ]

/// The short forms Release 6 has, which are the same instructions recoded
/// and the two it made compact.
let private shortR6Encoders () =
  [ Opcode.JRC, shortJumpR6 0b00u
    Opcode.JALRC, shortJumpR6 0b01u
    Opcode.JRCADDIUSP, jumpAdjustR6
    Opcode.MOVEP, movepR6 ]

/// <summary>
/// Adds a table of encoders to another, keeping what was already there for
/// the instructions the new rows do not claim.
///
/// A dozen names belong both to the general registers and to the
/// floating-point ones, and what tells the two apart is the format written
/// into the mnemonic, so where a name is in both the two encoders are put
/// behind one that reads that.
/// </summary>
let private addEncoders claims table rows =
  rows
  |> List.fold (fun table (opcode, encode) ->
    match Map.tryFind opcode table with
    | Some other ->
      let choose ins = if claims ins then encode ins else other ins
      Map.add opcode choose table
    | None ->
      Map.add opcode encode table) table

/// <summary>
/// Builds the lookup from an opcode to the encoder for it, for the release
/// the source is written at.
/// </summary>
/// <param name="release">
/// Which release the source is written for. Release 6 is a different encoding
/// space, not an extension: it took major opcodes away from one instruction
/// and gave them to another, so the release is what tells the two apart --
/// nothing in the source text does.
/// </param>
let buildEncoderTable (release: MIPSRelease) =
  let general =
    majorEncoders ()
    @ pool32AEncoders ()
    @ pool32AxfEncoders ()
    @ pool32BEncoders ()
    @ pool32CEncoders ()
    @ pool32IEncoders ()
    @ pool32SEncoders ()
    |> Map.ofList
  let general =
    if release = MIPSRelease.R6 then
      addEncoders (fun _ -> true) general (r6Encoders () @ r6BranchEncoders ())
    else
      addEncoders (fun _ -> true) general
        (preR6Encoders ()
         @ pool32AMoveEncoders ()
         @ pool32AxfPreR6Encoders ()
         @ pool32IPreR6Encoders ()
         @ pool32SPreR6Encoders ())
  let withFloat =
    addEncoders (fun ins -> Option.isSome ins.Fmt) general (pool32FEncoders ())
  let withFloat =
    if release = MIPSRelease.R6 then
      withFloat
    else
      addEncoders (fun ins -> Option.isSome ins.Fmt) withFloat
        (pool32FPreR6Encoders ())
  (* A short form that shares its name with a long one is claimed by naming
     one operand where the long one names two. *)
  let named1 ins =
    match ins.Operands with
    | OneOperand _ -> true
    | _ -> false
  if release = MIPSRelease.R6 then
    addEncoders named1 withFloat (shortR6Encoders ())
  else
    addEncoders named1 withFloat (shortEncoders ())

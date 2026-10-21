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
/// Reads Variable Length Encoding (VLE) instructions, which are one halfword
/// or two long. The fields below are named and numbered as Book VLE draws
/// them, from the most significant bit of the instruction down.
/// </summary>
module internal B2R2.FrontEnd.PPC.ParsingVLE

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils
open B2R2.FrontEnd.PPC.OperandHelper

/// Whether a halfword begins an instruction of two: bit 0 is clear and bit 3
/// set, which is what the 32-bit primary opcodes (those of the form 0001,
/// 0011, 0101 and 0111 in their first four bits) have in common.
let private isLong (first: uint32) = first &&& 0x9000u = 0x1000u

/// The instructions of a halfword that name nothing.
let private parseControl half =
  match half with
  | 0x0000u -> struct (Op.SE_ILLEGAL, NoOperand)
  | 0x0001u -> struct (Op.SE_ISYNC, NoOperand)
  | 0x0002u -> struct (Op.SE_SC, NoOperand)
  | 0x0004u -> struct (Op.SE_BLR, NoOperand)
  | 0x0005u -> struct (Op.SE_BLRL, NoOperand)
  | 0x0006u -> struct (Op.SE_BCTR, NoOperand)
  | 0x0007u -> struct (Op.SE_BCTRL, NoOperand)
  | _ -> raise ParsingFailureException

/// The general register a four-bit field of a 16-bit instruction names, which
/// reaches r0 to r7 and r24 to r31 and no others.
let private gpr16Register n = getRegister (if n < 8u then n else n + 16u)

/// The same as an operand.
let private gpr16 n = gpr16Register n |> OprReg

/// The "alternate" register a four-bit field names, which is one of r8 to r23.
let private alternate n = getRegister (n + 8u) |> OprReg

/// The 16-bit instructions of the control and monadic forms, whose register is
/// in the low four bits and whose opcode is the rest of the halfword above it.
let private parseMonadic half =
  let rx = gpr16 (Bits.extract half 3u 0u)
  match half >>> 4 with
  | 0x002u -> struct (Op.SE_NOT, OneOperand rx)
  | 0x003u -> struct (Op.SE_NEG, OneOperand rx)
  | 0x008u -> struct (Op.SE_MFLR, OneOperand rx)
  | 0x009u -> struct (Op.SE_MTLR, OneOperand rx)
  | 0x00Au -> struct (Op.SE_MFCTR, OneOperand rx)
  | 0x00Bu -> struct (Op.SE_MTCTR, OneOperand rx)
  | 0x00Cu -> struct (Op.SE_EXTZB, OneOperand rx)
  | 0x00Du -> struct (Op.SE_EXTSB, OneOperand rx)
  | 0x00Eu -> struct (Op.SE_EXTZH, OneOperand rx)
  | 0x00Fu -> struct (Op.SE_EXTSH, OneOperand rx)
  | _ -> raise ParsingFailureException

/// The instructions that fill a halfword and name two registers: RX in the low
/// four bits and RY in the four above them.
let private parseDyadic half =
  let rx = gpr16 (Bits.extract half 3u 0u)
  let ry = gpr16 (Bits.extract half 7u 4u)
  let arx = alternate (Bits.extract half 3u 0u)
  let ary = alternate (Bits.extract half 7u 4u)
  match half >>> 8 with
  | 0x01u -> struct (Op.SE_MR, TwoOperands(rx, ry))
  | 0x02u -> struct (Op.SE_MTAR, TwoOperands(arx, ry))
  | 0x03u -> struct (Op.SE_MFAR, TwoOperands(rx, ary))
  | 0x04u -> struct (Op.SE_ADD, TwoOperands(rx, ry))
  | 0x05u -> struct (Op.SE_MULLW, TwoOperands(rx, ry))
  | 0x06u -> struct (Op.SE_SUB, TwoOperands(rx, ry))
  | 0x07u -> struct (Op.SE_SUBF, TwoOperands(rx, ry))
  | 0x0Cu -> struct (Op.SE_CMP, TwoOperands(rx, ry))
  | 0x0Du -> struct (Op.SE_CMPL, TwoOperands(rx, ry))
  | 0x0Eu -> struct (Op.SE_CMPH, TwoOperands(rx, ry))
  | 0x0Fu -> struct (Op.SE_CMPHL, TwoOperands(rx, ry))
  | 0x40u -> struct (Op.SE_SRW, TwoOperands(rx, ry))
  | 0x41u -> struct (Op.SE_SRAW, TwoOperands(rx, ry))
  | 0x42u -> struct (Op.SE_SLW, TwoOperands(rx, ry))
  | 0x44u -> struct (Op.SE_OR, TwoOperands(rx, ry))
  | 0x45u -> struct (Op.SE_ANDC, TwoOperands(rx, ry))
  | 0x46u -> struct (Op.SE_AND, TwoOperands(rx, ry))
  | 0x47u -> struct (Op.SE_ANDdot, TwoOperands(rx, ry))
  | _ -> raise ParsingFailureException

/// The instructions that fill a halfword and take a five-bit number in the
/// bits above RX, whether as it stands or as one less than the number meant.
let private parseImmediate5 half =
  let rx = gpr16 (Bits.extract half 3u 0u)
  let ui5 = Bits.extract half 8u 4u |> uint64
  let oimm = OprImm(ui5 + 1UL)
  match half >>> 9 with
  | 0x10u -> struct (Op.SE_ADDI, TwoOperands(rx, oimm))
  | 0x11u -> struct (Op.SE_CMPLI, TwoOperands(rx, oimm))
  | 0x12u -> struct (Op.SE_SUBI, TwoOperands(rx, oimm))
  | 0x13u -> struct (Op.SE_SUBIdot, TwoOperands(rx, oimm))
  | 0x15u -> struct (Op.SE_CMPI, TwoOperands(rx, OprImm ui5))
  | 0x16u -> struct (Op.SE_BMASKI, TwoOperands(rx, OprImm ui5))
  | 0x17u -> struct (Op.SE_ANDI, TwoOperands(rx, OprImm ui5))
  | 0x30u -> struct (Op.SE_BCLRI, TwoOperands(rx, OprImm ui5))
  | 0x31u -> struct (Op.SE_BGENI, TwoOperands(rx, OprImm ui5))
  | 0x32u -> struct (Op.SE_BSETI, TwoOperands(rx, OprImm ui5))
  | 0x33u -> struct (Op.SE_BTSTI, TwoOperands(rx, OprImm ui5))
  | 0x34u -> struct (Op.SE_SRWI, TwoOperands(rx, OprImm ui5))
  | 0x35u -> struct (Op.SE_SRAWI, TwoOperands(rx, OprImm ui5))
  | 0x36u -> struct (Op.SE_SLWI, TwoOperands(rx, OprImm ui5))
  | _ -> raise ParsingFailureException

/// se_li, whose seven-bit number sits above RX.
let private parseLoadImmediate half =
  let rx = gpr16 (Bits.extract half 3u 0u)
  let ui7 = Bits.extract half 10u 4u |> uint64
  struct (Op.SE_LI, TwoOperands(rx, OprImm ui7))

/// The displacement of a 16-bit branch: its eight bits followed by a zero,
/// sign-extended to the width of a register.
let private displacement8 bitLen half =
  let distance = Bits.extract half 7u 0u <<< 1 |> uint64
  Bits.signExtend 9 bitLen distance |> uint64 |> OprAddr

/// The 16-bit branches: se_b and se_bl, which differ in the bit that says
/// whether they link, and se_bc, which tests a bit of CR0.
let private parseBranch bitLen half =
  let disp = displacement8 bitLen half
  if half >>> 9 = 0x74u then
    let op = if Bits.pick half 8u = 0u then Op.SE_B else Op.SE_BL
    struct (op, OneOperand disp)
  else
    let bo = Bits.pick half 10u |> uint64 |> OprImm
    let bi = Bits.extract half 9u 8u |> OprBI
    struct (Op.SE_BC, ThreeOperands(bo, bi, disp))

/// The 16-bit loads and stores, which name RZ above the base register RX and a
/// displacement of four bits above that, scaled by the size of what they move.
let private parseAccess half =
  let rx = gpr16Register (Bits.extract half 3u 0u)
  let rz = gpr16 (Bits.extract half 7u 4u)
  let sd4 = int (Bits.extract half 11u 8u)
  match half >>> 12 with
  | 0x8u -> struct (Op.SE_LBZ, TwoOperands(rz, OprMem(sd4, rx)))
  | 0x9u -> struct (Op.SE_STB, TwoOperands(rz, OprMem(sd4, rx)))
  | 0xAu -> struct (Op.SE_LHZ, TwoOperands(rz, OprMem(sd4 * 2, rx)))
  | 0xBu -> struct (Op.SE_STH, TwoOperands(rz, OprMem(sd4 * 2, rx)))
  | 0xCu -> struct (Op.SE_LWZ, TwoOperands(rz, OprMem(sd4 * 4, rx)))
  | _ -> struct (Op.SE_STW, TwoOperands(rz, OprMem(sd4 * 4, rx)))

/// Whether the byte that begins a halfword is the one of an instruction of two
/// registers.
let private isDyadic b =
  (b >= 0x01u && b <= 0x07u) || (b >= 0x0Cu && b <= 0x0Fu)
  || (b >= 0x40u && b <= 0x42u) || (b >= 0x44u && b <= 0x47u)

/// The instructions that fill a halfword.
let private parse16 bitLen (half: uint32) =
  match half >>> 8 with
  | 0x00u when half < 0x10u -> parseControl half
  | 0x00u -> parseMonadic half
  | b when isDyadic b -> parseDyadic half
  | _ when half >>> 11 = 0x09u -> parseLoadImmediate half
  | _ when half >>> 12 >= 0x8u && half >>> 12 <= 0xDu -> parseAccess half
  | _ when half >>> 11 = 0x1Cu || half >>> 9 = 0x74u -> parseBranch bitLen half
  | _ -> parseImmediate5 half

/// The displacement of a D-form instruction: sixteen bits, sign-extended.
let private disp16 bin =
  Bits.signExtend 16 32 (uint64 (Bits.extract bin 15u 0u)) |> int32

/// The displacement of a D8-form instruction: eight bits, sign-extended.
let private disp8 bin =
  Bits.signExtend 8 32 (uint64 (Bits.extract bin 7u 0u)) |> int32

/// A load or a store of a register at a base register and a displacement, which
/// is how the D-form and the D8-form both name what they reach.
let private parseAccess32 op disp bin =
  let rt = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  struct (op, TwoOperands(rt, OprMem(disp, ra)))

/// The D8-form instructions, which a byte at bits 16 to 23 tells apart: the
/// loads and stores that update the base register, and the multiple-word ones.
let private parseD8 bin =
  let disp = disp8 bin
  match Bits.extract bin 15u 8u with
  | 0x00u -> parseAccess32 Op.E_LBZU disp bin
  | 0x01u -> parseAccess32 Op.E_LHZU disp bin
  | 0x02u -> parseAccess32 Op.E_LWZU disp bin
  | 0x03u -> parseAccess32 Op.E_LHAU disp bin
  | 0x04u -> parseAccess32 Op.E_STBU disp bin
  | 0x05u -> parseAccess32 Op.E_STHU disp bin
  | 0x06u -> parseAccess32 Op.E_STWU disp bin
  | 0x08u -> parseAccess32 Op.E_LMW disp bin
  | 0x09u -> parseAccess32 Op.E_STMW disp bin
  | _ -> raise ParsingFailureException

/// e_b and e_bl, which count their distance in 24 bits, and e_bc and e_bcl,
/// which count it in 15 and name a condition: the bit of CR0 to CR3 to test
/// and what to do with it and the counter.
let private parseBranch32 bitLen bin =
  let link = Bits.pick bin 0u = 1u
  match Bits.extract bin 25u 22u with
  | 0b1000u ->
    let distance = Bits.extract bin 15u 1u <<< 1 |> uint64
    let disp = Bits.signExtend 16 bitLen distance |> uint64 |> OprAddr
    let bo = Bits.extract bin 21u 20u |> uint64 |> OprImm
    let bi = Bits.extract bin 19u 16u |> OprBI
    let op = if link then Op.E_BCL else Op.E_BC
    struct (op, ThreeOperands(bo, bi, disp))
  | n when n < 8u ->
    let distance = Bits.extract bin 24u 1u <<< 1 |> uint64
    let disp = Bits.signExtend 25 bitLen distance |> uint64 |> OprAddr
    struct ((if link then Op.E_BL else Op.E_B), OneOperand disp)
  | _ ->
    raise ParsingFailureException

/// The instructions that combine two bits of the condition register into a
/// third, which name the three bits in the fields the base encoding keeps its
/// registers in.
let private parseCRLogic op bin =
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException else ()
  let bt = Bits.extract bin 25u 21u |> OprBI
  let ba = Bits.extract bin 20u 16u |> OprBI
  let bb = Bits.extract bin 15u 11u |> OprBI
  struct (op, ThreeOperands(bt, ba, bb))

/// e_mcrf, which names two fields of the condition register.
let private parseMCRF bin =
  if Bits.extract bin 22u 21u <> 0u then raise ParsingFailureException else ()
  if Bits.extract bin 17u 11u <> 0u then raise ParsingFailureException else ()
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException else ()
  let bf = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
  let bfa = getCondRegister (Bits.extract bin 20u 18u) |> OprReg
  struct (Op.E_MCRF, TwoOperands(bf, bfa))

/// e_sc, whose only operand is the level of the call it makes, which is left
/// out when it is zero.
let private parseSystemCall bin =
  if Bits.extract bin 25u 16u <> 0u then raise ParsingFailureException else ()
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException else ()
  match Bits.extract bin 15u 11u with
  | 0u -> struct (Op.E_SC, NoOperand)
  | elev -> struct (Op.E_SC, OneOperand(OprImm(uint64 elev)))

/// The instructions of primary opcode 31 that exist only in VLE, which the ten
/// bits of the extended opcode tell apart. The rest are the base encoding's.
let private parseOpcode31 bin =
  match Bits.extract bin 10u 1u with
  | 16u -> ValueSome(parseMCRF bin)
  | 33u -> ValueSome(parseCRLogic Op.E_CRNOR bin)
  | 36u -> ValueSome(parseSystemCall bin)
  | 129u -> ValueSome(parseCRLogic Op.E_CRANDC bin)
  | 193u -> ValueSome(parseCRLogic Op.E_CRXOR bin)
  | 225u -> ValueSome(parseCRLogic Op.E_CRNAND bin)
  | 257u -> ValueSome(parseCRLogic Op.E_CRAND bin)
  | 289u -> ValueSome(parseCRLogic Op.E_CREQV bin)
  | 417u -> ValueSome(parseCRLogic Op.E_CRORC bin)
  | 449u -> ValueSome(parseCRLogic Op.E_CROR bin)
  | _ -> ValueNone

/// The instructions that fill two halfwords and are not the base encoding.
let private parse32 bitLen (bin: uint32) =
  match bin >>> 26 with
  | 0x1Eu -> parseBranch32 bitLen bin
  | 0x06u -> parseD8 bin
  | 0x0Cu -> parseAccess32 Op.E_LBZ (disp16 bin) bin
  | 0x0Du -> parseAccess32 Op.E_STB (disp16 bin) bin
  | 0x0Eu -> parseAccess32 Op.E_LHA (disp16 bin) bin
  | 0x14u -> parseAccess32 Op.E_LWZ (disp16 bin) bin
  | 0x15u -> parseAccess32 Op.E_STW (disp16 bin) bin
  | 0x16u -> parseAccess32 Op.E_LHZ (disp16 bin) bin
  | 0x17u -> parseAccess32 Op.E_STH (disp16 bin) bin
  | _ -> raise ParsingFailureException

/// <summary>
/// Reads one instruction, which is a halfword long or two. What VLE keeps of
/// the base encoding is read as the base encoding is read.
/// </summary>
let parse lifter category (span: ByteSpan) (reader: IBinReader) addr rt =
  if reader.Endianness <> Endian.Big then raise ParsingFailureException else ()
  let first = uint32 (reader.ReadUInt16(span, 0))
  if not (isLong first) then
    let struct (opcode, operands) = parse16 (int rt) first
    Instruction(addr, 2u, opcode, operands, rt, 0UL, lifter)
  else
    let bin = reader.ReadUInt32(span, 0)
    match bin >>> 26 with
    | 0x4u ->
      ParsingMain.parse lifter category span reader addr rt
    | 0x1Fu ->
      match parseOpcode31 bin with
      | ValueSome(struct (opcode, operands)) ->
        Instruction(addr, 4u, opcode, operands, rt, 0UL, lifter)
      | ValueNone ->
        raise ParsingFailureException
    | _ ->
      let struct (opcode, operands) = parse32 (int rt) bin
      Instruction(addr, 4u, opcode, operands, rt, 0UL, lifter)

// vim: set tw=80 sts=2 sw=2:

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
/// Decodes the instructions of the Transactional Memory category (Power ISA
/// 2.07B Book II chapter 5), all of primary opcode 31, and the moves to and
/// from its three special registers, which the manual gives their own
/// mnemonics. No server instruction
/// of the ISAs B2R2 reads shares their encodings, so they read the same under
/// every category; ParsingLegacy hands a word here once its own tables are done
/// with it.
/// </summary>
module internal B2R2.FrontEnd.PPC.ParsingTM

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils
open B2R2.FrontEnd.PPC.OperandHelper

/// The bits of a word that are not its extended opcode, its primary opcode or
/// its record bit: a form says which of them it uses, and every other is
/// reserved and must be zero.
let private reservedBits = 0x03FFF800u

/// Whether a word of this form uses only the fields in mask, and has the record
/// bit a form says it has.
let private wellFormed usedFields record bin =
  (bin &&& reservedBits &&& ~~~usedFields) = 0u && Bits.pick bin 0u = record

/// tbegin., "R": the bit 10 a rollback-only transaction sets.
let private parseTbegin bin =
  if wellFormed 0x00200000u 1u bin then
    struct (Op.TBEGINdot, OneOperand(Bits.pick bin 21u |> uint64 |> OprImm))
  else
    raise ParsingFailureException

/// tend., "A": bit 6 ends every nested transaction at once.
let private parseTend bin =
  if wellFormed 0x02000000u 1u bin then
    struct (Op.TENDdot, OneOperand(Bits.pick bin 25u |> uint64 |> OprImm))
  else
    raise ParsingFailureException

/// tabort., "rA": the register whose low byte is the failure code.
let private parseTabort bin =
  if wellFormed 0x001F0000u 1u bin then
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    struct (Op.TABORTdot, OneOperand ra)
  else
    raise ParsingFailureException

/// The conditional aborts, "TO, rA, rB": the comparison the TO bits select.
let private parseAbortRegister opcode bin =
  if wellFormed 0x03FFF800u 1u bin then
    let ct = Bits.extract bin 25u 21u |> uint64 |> OprImm
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (opcode, ThreeOperands(ct, ra, rb))
  else
    raise ParsingFailureException

/// The conditional aborts against an immediate, "TO, rA, SI": SI is the five
/// bits 16:20, a signed number, read at the width of a register.
let private parseAbortImmediate opcode bitLen bin =
  if wellFormed 0x03FFF800u 1u bin then
    let ct = Bits.extract bin 25u 21u |> uint64 |> OprImm
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let si = Bits.extract bin 15u 11u |> uint64 |> Bits.signExtend 5 bitLen
    struct (opcode, ThreeOperands(ct, ra, OprImm(uint64 si)))
  else
    raise ParsingFailureException

/// tcheck, "BF": the condition register field that receives the state. It has
/// no record bit.
let private parseTcheck bin =
  if wellFormed 0x03800000u 0u bin then
    let bf = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    struct (Op.TCHECK, OneOperand bf)
  else
    raise ParsingFailureException

/// tsr., "L": bit 10 says resume rather than suspend.
let private parseTsr bin =
  if wellFormed 0x00200000u 1u bin then
    struct (Op.TSRdot, OneOperand(Bits.pick bin 21u |> uint64 |> OprImm))
  else
    raise ParsingFailureException

/// The number a move to or from a special register names, whose two five-bit
/// halves sit in the word the other way round.
let private sprNumber bin =
  Bits.concat (Bits.extract bin 15u 11u) (Bits.extract bin 20u 16u) 5

/// The move from one of the three special registers of the category, or of the
/// upper word of TEXASR, which the manual's extended mnemonics name: the
/// register is the one operand, and bit 31 is reserved. Any other special
/// register is not this module's.
let private parseSprMove (moves: Opcode[]) bin =
  let spr = sprNumber bin
  if spr < 128u || spr > 131u then
    ValueNone
  elif Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    let reg = getRegister (Bits.extract bin 25u 21u) |> OprReg
    ValueSome(struct (moves[int spr - 128], OneOperand reg))

/// The moves from TFHAR, TFIAR, TEXASR and TEXASRU, SPRs 128 to 131.
let private fromSprs =
  [| Op.MFTFHAR; Op.MFTFIAR; Op.MFTEXASR; Op.MFTEXASRU |]

/// The moves to them.
let private toSprs =
  [| Op.MTTFHAR; Op.MTTFIAR; Op.MTTEXASR; Op.MTTEXASRU |]

/// The instruction a word of primary opcode 31 is, if it is a transactional
/// one, by its ten-bit extended opcode, at a register width of bitLen bits.
let tryParse31 bitLen bin =
  match Bits.extract bin 10u 1u with
  | 339u ->
    parseSprMove fromSprs bin
  | 467u ->
    parseSprMove toSprs bin
  | 654u ->
    ValueSome(parseTbegin bin)
  | 686u ->
    ValueSome(parseTend bin)
  | 718u ->
    ValueSome(parseTcheck bin)
  | 750u ->
    ValueSome(parseTsr bin)
  | 782u ->
    ValueSome(parseAbortRegister Op.TABORTWCdot bin)
  | 814u ->
    ValueSome(parseAbortRegister Op.TABORTDCdot bin)
  | 846u ->
    ValueSome(parseAbortImmediate Op.TABORTWCIdot bitLen bin)
  | 878u ->
    ValueSome(parseAbortImmediate Op.TABORTDCIdot bitLen bin)
  | 910u ->
    ValueSome(parseTabort bin)
  | _ ->
    ValueNone

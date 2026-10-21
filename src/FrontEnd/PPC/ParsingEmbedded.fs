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
/// Decodes the instructions the embedded environment adds to primary opcodes
/// 19 and 31 (Power ISA 2.07B Book II and Book III-E): the cache-locking
/// instructions, Decorated Storage, the debug, hypervisor and device moves, and
/// the memory barrier whose word a server processor reads as eieio. No server
/// instruction shares the other encodings, so they read the same under every
/// category; ParsingLegacy hands a word here once its own tables are done with
/// it.
/// </summary>
module internal B2R2.FrontEnd.PPC.ParsingEmbedded

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils
open B2R2.FrontEnd.PPC.OperandHelper

/// The cache-locking instructions, "CT, rA, rB": CT is the four bits 7:10 and
/// bit 6 above it is reserved. The record bit is part of the encoding of the
/// two queries and reserved in the others, which is what the second argument
/// says it must be.
let private parseCacheLock opcode record bin =
  if Bits.pick bin 25u <> 0u || Bits.pick bin 0u <> record then
    raise ParsingFailureException
  else
    let ct = Bits.extract bin 24u 21u |> uint64 |> OprImm
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (opcode, ThreeOperands(ct, ra, rb))

/// mbar, "MO": the five bits 6:10 hold what the server reading of the word,
/// eieio, leaves reserved. Everything below them is reserved.
let private parseMbar bin =
  if Bits.extract bin 20u 11u <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    struct (Op.MBAR, OneOperand(Bits.extract bin 25u 21u |> uint64 |> OprImm))

/// ehpriv, "OC": the fifteen bits 6:20 are the operand code the hypervisor
/// reads back; bit 31 is reserved.
let private parseEhpriv bin =
  if Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    struct (Op.EHPRIV, OneOperand(Bits.extract bin 25u 11u |> uint64 |> OprImm))

/// The number a move to or from a performance monitor register names, whose
/// two five-bit halves sit in the word the other way round.
let private pmrNumber bin =
  Bits.concat (Bits.extract bin 15u 11u) (Bits.extract bin 20u 16u) 5

/// mfpmr and mtpmr, "rT, PMRN" and "PMRN, rS"; bit 31 is reserved.
let private parsePmrMove opcode bin =
  let reg = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let pmrn = pmrNumber bin |> uint64 |> OprImm
  if Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  elif opcode = Op.MFPMR then
    struct (opcode, TwoOperands(reg, pmrn))
  else
    struct (opcode, TwoOperands(pmrn, reg))

/// mfdcrux and mtdcrux, which name the device control register by the number
/// in rA. Bits 16:20 and 31 are reserved. objdump writes mtdcrux's operands in
/// the order rA, rS, where the manual writes rS, rA; the operands here are in
/// objdump's, as the sweep that compares the two reads them.
let private parseDcrMove opcode bin =
  let reg = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  if Bits.extract bin 15u 11u <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  elif opcode = Op.MFDCRUX then
    struct (opcode, TwoOperands(reg, ra))
  else
    struct (opcode, TwoOperands(ra, reg))

/// A decorated load or store of Decorated Storage, "rT, rA, rB", rT named by
/// the function given. The address is rB alone and rA holds the decoration;
/// bit 31 is reserved.
let private parseDecorated opcode regOf bin =
  if Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    let rt = regOf (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (opcode, ThreeOperands(rt, ra, rb))

/// A decorated doubleword access, which only the 64-bit category has.
let private parseDecorated64 opcode bitLen bin =
  if bitLen = 32 then
    raise ParsingFailureException
  else
    parseDecorated opcode getRegister bin

/// dsn, "rA, rB": the field where the other decorated accesses keep their
/// register is reserved, and so is bit 31.
let private parseDsn bin =
  if Bits.extract bin 25u 21u <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.DSN, TwoOperands(ra, rb))

/// The instruction a word of primary opcode 31 is, if it is one of the
/// embedded categories', by its ten-bit extended opcode. The categories decide
/// the one word the server reading gives another meaning, and the register
/// width the doubleword forms of Decorated Storage.
let tryParse31 category bitLen bin =
  match Bits.extract bin 10u 1u with
  | 134u ->
    ValueSome(parseCacheLock Op.DCBTSTLS 0u bin)
  | 166u ->
    ValueSome(parseCacheLock Op.DCBTLS 0u bin)
  | 198u ->
    ValueSome(parseCacheLock Op.ICBLQdot 1u bin)
  | 230u ->
    ValueSome(parseCacheLock Op.ICBLC 0u bin)
  | 270u ->
    ValueSome(parseEhpriv bin)
  | 291u ->
    ValueSome(parseDcrMove Op.MFDCRUX bin)
  | 334u ->
    ValueSome(parsePmrMove Op.MFPMR bin)
  | 390u ->
    ValueSome(parseCacheLock Op.DCBLC 0u bin)
  | 419u ->
    ValueSome(parseDcrMove Op.MTDCRUX bin)
  | 422u ->
    ValueSome(parseCacheLock Op.DCBLQdot 1u bin)
  | 462u ->
    ValueSome(parsePmrMove Op.MTPMR bin)
  | 483u ->
    ValueSome(parseDsn bin)
  | 486u ->
    ValueSome(parseCacheLock Op.ICBTLS 0u bin)
  | 515u ->
    ValueSome(parseDecorated Op.LBDX getRegister bin)
  | 547u ->
    ValueSome(parseDecorated Op.LHDX getRegister bin)
  | 579u ->
    ValueSome(parseDecorated Op.LWDX getRegister bin)
  | 611u ->
    ValueSome(parseDecorated64 Op.LDDX bitLen bin)
  | 643u ->
    ValueSome(parseDecorated Op.STBDX getRegister bin)
  | 675u ->
    ValueSome(parseDecorated Op.STHDX getRegister bin)
  | 707u ->
    ValueSome(parseDecorated Op.STWDX getRegister bin)
  | 739u ->
    ValueSome(parseDecorated64 Op.STDDX bitLen bin)
  | 803u ->
    ValueSome(parseDecorated Op.LFDDX getFPRegister bin)
  | 854u when Category.includes Category.Embedded category ->
    ValueSome(parseMbar bin)
  | 931u ->
    ValueSome(parseDecorated Op.STFDDX getFPRegister bin)
  | _ ->
    ValueNone

/// The instruction a word of primary opcode 19 is, if it is one of the
/// embedded categories': dnh, "DUI, DUIS", whose bit 31 is reserved.
let tryParse19 bin =
  if Bits.extract bin 10u 1u <> 198u then
    ValueNone
  elif Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    let dui = Bits.extract bin 25u 21u |> uint64 |> OprImm
    let duis = Bits.extract bin 20u 11u |> uint64 |> OprImm
    ValueSome(struct (Op.DNH, TwoOperands(dui, duis)))

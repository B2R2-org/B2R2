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
/// Decodes the instructions the embedded environment adds to primary opcode 31
/// (Power ISA 2.07B Book III-E): the cache-locking instructions here, and the
/// ones the other themes of the embedded categories bring. No server
/// instruction shares their encodings, so they read the same under every
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

/// The instruction a word of primary opcode 31 is, if it is one of the
/// embedded categories', by its ten-bit extended opcode.
let tryParse31 bin =
  match Bits.extract bin 10u 1u with
  | 134u ->
    ValueSome(parseCacheLock Op.DCBTSTLS 0u bin)
  | 166u ->
    ValueSome(parseCacheLock Op.DCBTLS 0u bin)
  | 198u ->
    ValueSome(parseCacheLock Op.ICBLQdot 1u bin)
  | 230u ->
    ValueSome(parseCacheLock Op.ICBLC 0u bin)
  | 390u ->
    ValueSome(parseCacheLock Op.DCBLC 0u bin)
  | 422u ->
    ValueSome(parseCacheLock Op.DCBLQdot 1u bin)
  | 486u ->
    ValueSome(parseCacheLock Op.ICBTLS 0u bin)
  | _ ->
    ValueNone

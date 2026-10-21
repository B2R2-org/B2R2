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

/// The instructions that fill a halfword.
let private parse16 (half: uint32) =
  match half with
  | 0x0000u -> struct (Op.SE_ILLEGAL, NoOperand)
  | 0x0001u -> struct (Op.SE_ISYNC, NoOperand)
  | 0x0002u -> struct (Op.SE_SC, NoOperand)
  | 0x0004u -> struct (Op.SE_BLR, NoOperand)
  | 0x0005u -> struct (Op.SE_BLRL, NoOperand)
  | 0x0006u -> struct (Op.SE_BCTR, NoOperand)
  | 0x0007u -> struct (Op.SE_BCTRL, NoOperand)
  | _ -> raise ParsingFailureException

/// The instructions that fill two halfwords and are not the base encoding.
let private parse32 (_bin: uint32) =
  raise ParsingFailureException

/// <summary>
/// Reads one instruction, which is a halfword long or two. What VLE keeps of
/// the base encoding is read as the base encoding is read.
/// </summary>
let parse lifter category (span: ByteSpan) (reader: IBinReader) addr rt =
  if reader.Endianness <> Endian.Big then raise ParsingFailureException else ()
  let first = uint32 (reader.ReadUInt16(span, 0))
  if not (isLong first) then
    let struct (opcode, operands) = parse16 first
    Instruction(addr, 2u, opcode, operands, rt, 0UL, lifter)
  else
    let bin = reader.ReadUInt32(span, 0)
    match bin >>> 26 with
    | 0x4u ->
      ParsingMain.parse lifter category span reader addr rt
    | _ ->
      let struct (opcode, operands) = parse32 bin
      Instruction(addr, 4u, opcode, operands, rt, 0UL, lifter)

// vim: set tw=80 sts=2 sw=2:

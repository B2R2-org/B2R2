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

/// Reads the two words of a Power ISA 3.1 prefixed instruction.
module internal B2R2.FrontEnd.PPC.ParsingPrefixed

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils
open B2R2.FrontEnd.PPC.OperandHelper

/// The prefix kind and suffix primary opcode select the storage form.
let private accesses =
  [ (0x06000000u, 34u), (Op.PLBZ, 0)
    (0x04000000u, 57u), (Op.PLD, 0)
    (0x06000000u, 50u), (Op.PLFD, 1)
    (0x06000000u, 48u), (Op.PLFS, 1)
    (0x06000000u, 42u), (Op.PLHA, 0)
    (0x06000000u, 40u), (Op.PLHZ, 0)
    (0x04000000u, 56u), (Op.PLQ, 0)
    (0x04000000u, 41u), (Op.PLWA, 0)
    (0x06000000u, 32u), (Op.PLWZ, 0)
    (0x04000000u, 42u), (Op.PLXSD, 2)
    (0x04000000u, 43u), (Op.PLXSSP, 2)
    (0x04000000u, 50u), (Op.PLXV, 3)
    (0x04000000u, 51u), (Op.PLXV, 3)
    (0x04000000u, 58u), (Op.PLXVP, 4)
    (0x06000000u, 38u), (Op.PSTB, 0)
    (0x04000000u, 61u), (Op.PSTD, 0)
    (0x06000000u, 54u), (Op.PSTFD, 1)
    (0x06000000u, 52u), (Op.PSTFS, 1)
    (0x06000000u, 44u), (Op.PSTH, 0)
    (0x04000000u, 60u), (Op.PSTQ, 0)
    (0x06000000u, 36u), (Op.PSTW, 0)
    (0x04000000u, 46u), (Op.PSTXSD, 2)
    (0x04000000u, 47u), (Op.PSTXSSP, 2)
    (0x04000000u, 54u), (Op.PSTXV, 3)
    (0x04000000u, 55u), (Op.PSTXV, 3)
    (0x04000000u, 62u), (Op.PSTXVP, 4) ] |> Map.ofList

/// The target field names a GPR, FPR, vector, VSR, or even VSR pair.
let private target kind word =
  let n = Bits.extract word 25u 21u
  let reg =
    match kind with
    | 0 -> getRegister n
    | 1 -> getFPRegister n
    | 2 -> getVecRegister n
    | 3 -> getVsxRegister (n ||| ((Bits.pick word 26u) <<< 5))
    | _ -> getVsxRegister ((n &&& 30u) ||| ((n &&& 1u) <<< 5))
  OprReg reg

/// si0||si1 is a signed 34-bit immediate; R selects CIA instead of RA|0.
let private addressFields prefix suffix =
  let ra = Bits.extract suffix 20u 16u
  let relative = Bits.pick prefix 20u
  if relative = 1u && ra <> 0u then raise ParsingFailureException else ()
  let raw = (uint64 (prefix &&& 0x3ffffu) <<< 16)
            ||| uint64 (suffix &&& 0xffffu)
  let displacement = Bits.signExtend 34 64 raw |> int64
  getRegister ra, displacement, OprImm(uint64 relative)

/// The PNOP suffix may not encode a branch or context-synchronizing form.
let private parseNop suffix =
  let po = suffix >>> 26
  let xo = Bits.extract suffix 10u 1u
  let forbidden =
    po = 16u || po = 17u || po = 18u
    || (po = 19u && xo <> 150u)
    || (po = 31u && (xo = 146u || xo = 178u))
    || suffix = 0x00000200u
  if forbidden then raise ParsingFailureException else ()
  struct (Op.PNOP, NoOperand)

/// XX4 stores the high register bits beside the suffix opcode.
let private parseVector prefix suffix =
  let operand field bit =
    let low = Bits.extract suffix (field + 4u) field
    OprReg(getVsxRegister (low ||| (Bits.pick suffix bit <<< 5)))
  let t, a = operand 21u 0u, operand 16u 2u
  let b, c = operand 11u 1u, operand 6u 3u
  let xo = Bits.extract suffix 5u 4u
  match suffix >>> 26 with
  | 33u ->
    let op = [| Op.XXBLENDVB; Op.XXBLENDVH; Op.XXBLENDVW; Op.XXBLENDVD |]
    struct (op[int xo], FourOperands(t, a, b, c))
  | 34u when xo = 0u || xo = 1u ->
    let op, mask = if xo = 0u then Op.XXPERMX, 7u else Op.XXEVAL, 255u
    struct (op, FiveOperands(t, a, b, c, OprImm(uint64 (prefix &&& mask))))
  | 32u ->
    let t = operand 21u 16u
    let imm = (uint64 (prefix &&& 0xffffu) <<< 16)
              ||| uint64 (suffix &&& 0xffffu) |> OprImm
    match Bits.extract suffix 20u 17u with
    | 0u | 1u as index ->
      struct (Op.XXSPLTI32DX, ThreeOperands(t, OprImm(uint64 index), imm))
    | 2u ->
      struct (Op.XXSPLTIDP, TwoOperands(t, imm))
    | 3u ->
      struct (Op.XXSPLTIW, TwoOperands(t, imm))
    | _ ->
      raise ParsingFailureException
  | _ ->
    raise ParsingFailureException

let private decode prefix suffix =
  if prefix &&& 0xffff0000u = 0x05000000u then
    parseVector prefix suffix
  elif prefix &&& 0xfff3ffffu = 0x07000000u then
    parseNop suffix
  else
    let form = prefix &&& 0xffec0000u
    let ra, displacement, relative = addressFields prefix suffix
    if form = 0x06000000u && suffix >>> 26 = 14u then
      let rt = getRegister (Bits.extract suffix 25u 21u) |> OprReg
      let imm = OprImm(uint64 displacement)
      struct (Op.PADDI, FourOperands(rt, OprReg ra, imm, relative))
    else
      match Map.tryFind (form, suffix >>> 26) accesses with
      | Some(op, kind) ->
        let n = Bits.extract suffix 25u 21u
        if (op = Op.PLQ || op = Op.PSTQ) && n &&& 1u <> 0u then
          raise ParsingFailureException
        else
          ()
        if op = Op.PLQ && getRegister n = ra then
          raise ParsingFailureException
        else
          ()
        let mem = OprMem64(displacement, ra)
        struct (op, ThreeOperands(target kind suffix, mem, relative))
      | None ->
        raise ParsingFailureException

/// Prefixed instructions consist of two separately byte-ordered words.
let parse lifter (span: ByteSpan) (reader: IBinReader) addr rt =
  if rt <> 64<rt> || addr &&& 63UL > 56UL then
    raise ParsingFailureException
  else
    ()
  let prefix = reader.ReadUInt32(span, 0)
  let suffix = reader.ReadUInt32(span, 4)
  let struct (op, operands) = decode prefix suffix
  Instruction(addr, 8u, op, operands, rt, 0UL, lifter)

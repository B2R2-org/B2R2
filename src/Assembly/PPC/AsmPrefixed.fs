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

/// Encodes the prefix and suffix of Power ISA 3.1 instructions.
module internal B2R2.Assembly.PPC.AsmPrefixed

open B2R2
open B2R2.FrontEnd.PPC
open B2R2.Assembly.PPC.ParserHelper
open B2R2.Assembly.PPC.AsmField

/// Prefix, suffix primary opcode, and target-register layout by mnemonic.
let private accesses =
  [ Op.PLBZ, (0x06000000u, 0x88000000u, 0)
    Op.PLD, (0x04000000u, 0xe4000000u, 0)
    Op.PLFD, (0x06000000u, 0xc8000000u, 1)
    Op.PLFS, (0x06000000u, 0xc0000000u, 1)
    Op.PLHA, (0x06000000u, 0xa8000000u, 0)
    Op.PLHZ, (0x06000000u, 0xa0000000u, 0)
    Op.PLQ, (0x04000000u, 0xe0000000u, 0)
    Op.PLWA, (0x04000000u, 0xa4000000u, 0)
    Op.PLWZ, (0x06000000u, 0x80000000u, 0)
    Op.PLXSD, (0x04000000u, 0xa8000000u, 2)
    Op.PLXSSP, (0x04000000u, 0xac000000u, 2)
    Op.PLXV, (0x04000000u, 0xc8000000u, 3)
    Op.PLXVP, (0x04000000u, 0xe8000000u, 4)
    Op.PSTB, (0x06000000u, 0x98000000u, 0)
    Op.PSTD, (0x04000000u, 0xf4000000u, 0)
    Op.PSTFD, (0x06000000u, 0xd8000000u, 1)
    Op.PSTFS, (0x06000000u, 0xd0000000u, 1)
    Op.PSTH, (0x06000000u, 0xb0000000u, 0)
    Op.PSTQ, (0x04000000u, 0xf0000000u, 0)
    Op.PSTW, (0x06000000u, 0x90000000u, 0)
    Op.PSTXSD, (0x04000000u, 0xb8000000u, 2)
    Op.PSTXSSP, (0x04000000u, 0xbc000000u, 2)
    Op.PSTXV, (0x04000000u, 0xd8000000u, 3)
    Op.PSTXVP, (0x04000000u, 0xf8000000u, 4) ] |> Map.ofList

let isPrefixed opcode =
  opcode = Op.PADDI || opcode = Op.PNOP || Map.containsKey opcode accesses

/// The displacement must fit the signed 34-bit field before it is split.
let private displacement (value: int64) =
  let limit = 1L <<< 33
  if value < -limit || value >= limit then fail "Displacement exceeds 34 bits"
  else uint64 value &&& 0x3ffffffffUL

let private prefixWord prefix ra relative value =
  if relative > 1UL || (relative = 1UL && ra <> 0u) then
    fail "PC-relative addressing requires RA zero and R one"
  else
    ()
  prefix ||| (uint32 relative <<< 20) ||| uint32 (value >>> 16)

let private target kind reg =
  match kind with
  | 0 ->
    gpr reg <<< 21
  | 1 ->
    fpr reg <<< 21
  | 2 ->
    vr reg <<< 21
  | 3 ->
    let n = vsr reg
    ((n &&& 31u) <<< 21) ||| ((n >>> 5) <<< 26)
  | _ ->
    let n = vsr reg
    if n &&& 1u <> 0u then fail "VSR pair must start even" else ()
    ((n &&& 30u) <<< 21) ||| ((n >>> 5) <<< 21)

let private addImmediate ins =
  let operands =
    if List.length ins.Operands = 3 then ins.Operands @ [ AsmImm 0UL ]
    else ins.Operands
  match operands with
  | [ AsmReg dst; AsmReg ra; AsmImm imm; AsmImm relative ] ->
    let value = displacement (int64 imm)
    let a = gpr ra
    let prefix = prefixWord 0x06000000u a relative value
    let suffix = 0x38000000u ||| (gpr dst <<< 21) ||| (a <<< 16)
                 ||| uint32 (value &&& 0xffffUL)
    struct (prefix, suffix)
  | _ ->
    wrongOperands ins

let private memoryFields ins =
  let operands =
    if List.length ins.Operands = 2 then ins.Operands @ [ AsmImm 0UL ]
    else ins.Operands
  match operands with
  | [ AsmReg reg; AsmMem(d, ra); AsmImm r ] -> reg, int64 d, ra, r
  | [ AsmReg reg; AsmMem64(d, ra); AsmImm r ] -> reg, d, ra, r
  | _ -> wrongOperands ins

let private memory ins =
  let prefix, suffix, kind = Map.find ins.Opcode accesses
  let reg, offset, baseReg, relative = memoryFields ins
  let a = gpr baseReg
  if (ins.Opcode = Op.PLQ || ins.Opcode = Op.PSTQ) && gpr reg &&& 1u <> 0u then
    fail "GPR pair must start even"
  else
    ()
  if ins.Opcode = Op.PLQ && reg = baseReg then fail "PLQ target aliases RA"
  else ()
  let value = displacement offset
  let p = prefixWord prefix a relative value
  let s = suffix ||| target kind reg ||| (a <<< 16)
          ||| uint32 (value &&& 0xffffUL)
  struct (p, s)

/// The prefix precedes the suffix even in little-endian byte order.
let encode (ins: AsmInsInfo) =
  if ins.Address &&& 63UL > 56UL then fail "Prefix crosses a 64-byte boundary"
  else ()
  match ins.Opcode with
  | Op.PADDI -> addImmediate ins
  | Op.PNOP when List.isEmpty ins.Operands -> struct (0x07000000u, 0u)
  | _ -> memory ins

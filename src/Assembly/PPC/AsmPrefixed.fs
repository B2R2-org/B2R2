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

let private vectorOps =
  set [ Op.XXBLENDVB
        Op.XXBLENDVD
        Op.XXBLENDVH
        Op.XXBLENDVW
        Op.XXEVAL
        Op.XXPERMX
        Op.XXSPLTI32DX
        Op.XXSPLTIDP
        Op.XXSPLTIW ]

let private matrixOps =
  [
    Op.PMXVBF16GER2, 51u
    Op.PMXVBF16GER2NN, 242u
    Op.PMXVBF16GER2NP, 114u
    Op.PMXVBF16GER2PN, 178u
    Op.PMXVBF16GER2PP, 50u
    Op.PMXVF16GER2, 19u
    Op.PMXVF16GER2NN, 210u
    Op.PMXVF16GER2NP, 82u
    Op.PMXVF16GER2PN, 146u
    Op.PMXVF16GER2PP, 18u
    Op.PMXVF32GER, 27u
    Op.PMXVF32GERNN, 218u
    Op.PMXVF32GERNP, 90u
    Op.PMXVF32GERPN, 154u
    Op.PMXVF32GERPP, 26u
    Op.PMXVF64GER, 59u
    Op.PMXVF64GERNN, 250u
    Op.PMXVF64GERNP, 122u
    Op.PMXVF64GERPN, 186u
    Op.PMXVF64GERPP, 58u
    Op.PMXVI16GER2, 75u
    Op.PMXVI16GER2PP, 107u
    Op.PMXVI16GER2S, 43u
    Op.PMXVI16GER2SPP, 42u
    Op.PMXVI4GER8, 35u
    Op.PMXVI4GER8PP, 34u
    Op.PMXVI8GER4, 3u
    Op.PMXVI8GER4PP, 2u
    Op.PMXVI8GER4SPP, 99u
  ] |> Map.ofList

let isPrefixed opcode =
  opcode = Op.PADDI || opcode = Op.PNOP || Map.containsKey opcode accesses
  || Set.contains opcode vectorOps || Map.containsKey opcode matrixOps

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
  | [ AsmReg reg; AsmMem(d, ra); AsmImm r ] ->
    reg, int64 d, ra, r
  | [ AsmReg reg; AsmMem64(d, ra); AsmImm r ] ->
    reg, d, ra, r
  | _ ->
    wrongOperands ins

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

let private vectorFourFields ins t a b c imm =
  let fields t a b c =
    ((t &&& 31u) <<< 21) ||| ((a &&& 31u) <<< 16)
    ||| ((b &&& 31u) <<< 11) ||| ((c &&& 31u) <<< 6)
    ||| (t >>> 5) ||| ((a >>> 5) <<< 2)
    ||| ((b >>> 5) <<< 1) ||| ((c >>> 5) <<< 3)
  let field = fields (vsr t) (vsr a) (vsr b) (vsr c)
  match ins.Opcode with
  | Op.XXBLENDVB ->
    struct (0x05000000u, 0x84000000u ||| field)
  | Op.XXBLENDVH ->
    struct (0x05000000u, 0x84000010u ||| field)
  | Op.XXBLENDVW ->
    struct (0x05000000u, 0x84000020u ||| field)
  | Op.XXBLENDVD ->
    struct (0x05000000u, 0x84000030u ||| field)
  | Op.XXEVAL ->
    struct (0x05000000u ||| unsigned 8 imm, 0x88000010u ||| field)
  | Op.XXPERMX ->
    struct (0x05000000u ||| unsigned 3 imm, 0x88000000u ||| field)
  | _ ->
    wrongOperands ins

let private vectorFields ins =
  let blend =
    match ins.Opcode with
    | Op.XXBLENDVB | Op.XXBLENDVH | Op.XXBLENDVW | Op.XXBLENDVD -> true
    | _ -> false
  match ins.Operands with
  | [ AsmReg t; AsmReg a; AsmReg b; AsmReg c ]
    when blend || ins.Opcode = Op.XXEVAL || ins.Opcode = Op.XXPERMX ->
    vectorFourFields ins t a b c 0UL
  | [ AsmReg t; AsmReg a; AsmReg b; AsmReg c; AsmImm imm ]
    when ins.Opcode = Op.XXEVAL || ins.Opcode = Op.XXPERMX ->
    vectorFourFields ins t a b c imm
  | operands ->
    let t, imm, op =
      match operands with
      | [ AsmReg t; AsmImm ix; AsmImm imm ] when ins.Opcode = Op.XXSPLTI32DX ->
        t, imm, unsigned 1 ix
      | [ AsmReg t; AsmImm imm ] when ins.Opcode = Op.XXSPLTIDP ->
        t, imm, 2u
      | [ AsmReg t; AsmImm imm ] when ins.Opcode = Op.XXSPLTIW ->
        t, imm, 3u
      | _ ->
        wrongOperands ins
    let n = vsr t
    let value = unsigned 32 imm
    let suffix = 0x80000000u ||| ((n &&& 31u) <<< 21)
                 ||| ((n >>> 5) <<< 16) ||| (op <<< 17) ||| (value &&& 0xffffu)
    struct (0x05000000u ||| (value >>> 16), suffix)

/// The masks retain the manual's row, column and product order.
let private matrixFields ins =
  let xo = Map.find ins.Opcode matrixOps
  let double = xo = 58u || xo = 59u || xo = 122u || xo = 186u || xo = 250u
  let single = xo = 26u || xo = 27u || xo = 90u || xo = 154u || xo = 218u
  let operands =
    if double || single then ins.Operands @ [ AsmImm 0UL ] else ins.Operands
  match operands with
  | [ AsmReg acc; AsmReg a; AsmReg b; AsmImm x; AsmImm y; AsmImm p ] ->
    if acc < Register.ACC0 || acc > Register.ACC7 then
      fail "Expected an accumulator"
    else
      ()
    let at = uint32 (int acc - int Register.ACC0)
    let na, nb = vsr a, vsr b
    let overlaps n = n >= 4u * at && n < 4u * at + 4u
    if overlaps na || overlaps nb || (double && na &&& 1u <> 0u) then
      fail "Matrix source overlaps the accumulator or an invalid pair"
    else
      ()
    let pb =
      if xo = 34u || xo = 35u then 8
      elif xo = 2u || xo = 3u || xo = 99u then 4
      else 2
    let masks = (unsigned 4 x <<< 4)
                ||| (if double then unsigned 2 y <<< 2 else unsigned 4 y)
    let products = if double || single then 0u else unsigned pb p <<< (16 - pb)
    let prefix = 0x07900000u ||| masks ||| products
    let suffix = 0xec000000u ||| (at <<< 23) ||| ((na &&& 31u) <<< 16)
                 ||| ((nb &&& 31u) <<< 11) ||| (xo <<< 3)
                 ||| ((na >>> 5) <<< 2) ||| ((nb >>> 5) <<< 1)
    struct (prefix, suffix)
  | _ ->
    wrongOperands ins

/// The prefix precedes the suffix even in little-endian byte order.
let encode (ins: AsmInsInfo) =
  if ins.Address &&& 63UL > 56UL then fail "Prefix crosses a 64-byte boundary"
  else ()
  match ins.Opcode with
  | op when Map.containsKey op matrixOps ->
    matrixFields ins
  | op when Set.contains op vectorOps ->
    vectorFields ins
  | Op.PADDI ->
    addImmediate ins
  | Op.PNOP when List.isEmpty ins.Operands ->
    struct (0x07000000u, 0u)
  | _ ->
    memory ins

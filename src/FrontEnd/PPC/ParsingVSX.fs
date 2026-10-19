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
/// Decodes the Vector-Scalar Extension forms ISA 3.0 and 3.1 added: the VSX
/// loads and stores, the vector-scalar arithmetic beyond what a compiler of
/// the ISA 2.06 generation emitted, the quad-precision forms and the matrix
/// accumulators. Each decode function here is reached from the dispatcher of
/// its primary opcode in ParsingMain once that dispatcher has tried its own
/// forms.
/// </summary>
module internal B2R2.FrontEnd.PPC.ParsingVSX

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils
open B2R2.FrontEnd.PPC.OperandHelper

/// The six-bit number of a vector-scalar register whose five low bits sit at
/// `lo` and whose high bit is the instruction's bit `hi`.
let private vsxNumber bin hi lo =
  (Bits.pick bin hi <<< 5) ||| Bits.extract bin (lo + 4u) lo

/// The vector-scalar register XT (or XS) of a form that keeps its sixth bit at
/// the very end of the instruction.
let private xt bin = getVsxRegister (vsxNumber bin 0u 21u) |> OprReg

/// A general register named by the five bits starting at `lo`.
let private gpr bin lo = getRegister (Bits.extract bin (lo + 4u) lo) |> OprReg

/// An X-form VSX access "xT, rA, rB".
let private parseXIndexed op bin =
  struct (op, ThreeOperands(xt bin, gpr bin 16u, gpr bin 11u))

/// The register pair XTp of a paired access: its four-bit field counts pairs,
/// and the bit below it says which half of the vector-scalar registers the
/// pair lies in, so only an even register can be named.
let private pairRegister bin =
  let n = (Bits.pick bin 21u <<< 5) ||| (Bits.extract bin 25u 22u <<< 1)
  getVsxRegister n |> OprReg

/// lxvpx and stxvpx, "xTp, rA, rB".
let private parsePairIndexed op bin =
  struct (op, ThreeOperands(pairRegister bin, gpr bin 16u, gpr bin 11u))

/// mtvsrws, "xT, rA": the word to splat comes from a general register.
let private parseMTVSRWS bin =
  if Bits.extract bin 15u 11u <> 0u then raise ParsingFailureException
  else struct (Op.MTVSRWS, TwoOperands(xt bin, gpr bin 16u))

/// <summary>
/// The VSX loads and stores of primary opcode 31 that ISA 3.0 and 3.1 added,
/// and mtvsrws, which sits among them. The ten bits above the last one are
/// the extended opcode; the last bit extends the register number.
/// </summary>
let parse1F fallback bin =
  match Bits.extract bin 10u 1u with
  | 12u -> parseXIndexed Op.LXSIWZX bin
  | 13u -> parseXIndexed Op.LXVRBX bin
  | 45u -> parseXIndexed Op.LXVRHX bin
  | 76u -> parseXIndexed Op.LXSIWAX bin
  | 77u -> parseXIndexed Op.LXVRWX bin
  | 109u -> parseXIndexed Op.LXVRDX bin
  | 140u -> parseXIndexed Op.STXSIWX bin
  | 141u -> parseXIndexed Op.STXVRBX bin
  | 173u -> parseXIndexed Op.STXVRHX bin
  | 205u -> parseXIndexed Op.STXVRWX bin
  | 237u -> parseXIndexed Op.STXVRDX bin
  | 268u -> parseXIndexed Op.LXVX bin
  | 269u -> parseXIndexed Op.LXVL bin
  | 301u -> parseXIndexed Op.LXVLL bin
  | 333u -> parsePairIndexed Op.LXVPX bin
  | 364u -> parseXIndexed Op.LXVWSX bin
  | 396u -> parseXIndexed Op.STXVX bin
  | 397u -> parseXIndexed Op.STXVL bin
  | 403u -> parseMTVSRWS bin
  | 429u -> parseXIndexed Op.STXVLL bin
  | 461u -> parsePairIndexed Op.STXVPX bin
  | 524u -> parseXIndexed Op.LXSSPX bin
  | 652u -> parseXIndexed Op.STXSSPX bin
  | 781u -> parseXIndexed Op.LXSIBZX bin
  | 812u -> parseXIndexed Op.LXVH8X bin
  | 813u -> parseXIndexed Op.LXSIHZX bin
  | 876u -> parseXIndexed Op.LXVB16X bin
  | 909u -> parseXIndexed Op.STXSIBX bin
  | 940u -> parseXIndexed Op.STXVH8X bin
  | 941u -> parseXIndexed Op.STXSIHX bin
  | 1004u -> parseXIndexed Op.STXVB16X bin
  | _ -> fallback bin

/// The displacement of a DS-form, whose two low bits the encoding leaves out.
let private dsDisp bin =
  Bits.extract bin 15u 2u <<< 2 |> uint64 |> Bits.signExtend 16 64
  |> int64 |> int32

/// The displacement of a DQ-form, whose four low bits the encoding leaves out.
let private dqDisp bin =
  Bits.extract bin 15u 4u <<< 4 |> uint64 |> Bits.signExtend 16 64
  |> int64 |> int32

/// lxssp and stxssp, "vRT, DS(rA)": the register is a vector register, the
/// upper half of the vector-scalar registers, named by five bits.
let private parseScalarSingleDS op bin =
  let vr = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  struct (op, TwoOperands(vr, OprMem(dsDisp bin, ra)))

/// lxv and stxv, "xT, DQ(rA)", whose register number keeps its sixth bit
/// just above the three bits that say which form this is.
let private parseVectorDQ op bin =
  let x = getVsxRegister (vsxNumber bin 3u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  struct (op, TwoOperands(x, OprMem(dqDisp bin, ra)))

/// The DS-form load lxssp, which primary opcode 57 holds beside lxsd and
/// lfdp.
let parse39 bin =
  match Bits.extract bin 1u 0u with
  | 0b11u -> parseScalarSingleDS Op.LXSSP bin
  | _ -> raise ParsingFailureException

/// The stores and the vector load of primary opcode 61 beside stxsd and
/// stfdp: stxssp (DS-form) and the DQ-form lxv and stxv, whose three low bits
/// end in 01.
let parse3D bin =
  match Bits.extract bin 1u 0u, Bits.pick bin 2u with
  | 0b11u, _ -> parseScalarSingleDS Op.STXSSP bin
  | 0b01u, 0u -> parseVectorDQ Op.LXV bin
  | 0b01u, _ -> parseVectorDQ Op.STXV bin
  | _ -> raise ParsingFailureException

/// Primary opcode 6, the paired loads and stores: "xTp, DQ(rA)", the four low
/// bits saying which.
let parse06 bin =
  let mem = OprMem(dqDisp bin, getRegister (Bits.extract bin 20u 16u))
  match Bits.extract bin 3u 0u with
  | 0b0000u -> struct (Op.LXVP, TwoOperands(pairRegister bin, mem))
  | 0b0001u -> struct (Op.STXVP, TwoOperands(pairRegister bin, mem))
  | _ -> raise ParsingFailureException

/// The register an XX2 or XX3 form names in its B field, extended by the bit
/// above the last one.
let private xb bin = getVsxRegister (vsxNumber bin 1u 11u) |> OprReg

/// An XX2-form "xT, xB".
let private parseXX2 op bin = struct (op, TwoOperands(xt bin, xb bin))

/// The register an XX3 form names in its A field, extended by bit 2.
let private xa bin = getVsxRegister (vsxNumber bin 2u 16u) |> OprReg

/// An XX3-form "xT, xA, xB".
let private parseXX3 op bin = struct (op, ThreeOperands(xt bin, xa bin, xb bin))

/// xxextractuw and xxinsertw, "xT, xB, UIM": the byte index sits in the low
/// four bits of the A field, the bit above them reserved.
let private parseXX2Uim op bin =
  let uim = Bits.extract bin 19u 16u |> uint64 |> OprImm
  if Bits.pick bin 20u <> 0u then raise ParsingFailureException
  else struct (op, ThreeOperands(xt bin, xb bin, uim))

/// The xxgenpcv forms, "xT, vRB, IMM": the mask is a vector register, and
/// only IMM 0 to 3 are defined.
let private parseGenPCV op bin =
  let imm = Bits.extract bin 20u 16u
  let vrb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  if imm > 3u then raise ParsingFailureException
  else struct (op, ThreeOperands(xt bin, vrb, OprImm(uint64 imm)))

/// The condition-register field an XX form names in place of xT, the two
/// bits below it reserved.
let private crField bin =
  if Bits.extract bin 22u 21u <> 0u then raise ParsingFailureException
  else getCondRegister (Bits.extract bin 25u 23u) |> OprReg

/// An XX2 form that reports in a condition-register field: "BF, xB".
let private parseXX2CR op bin = struct (op, TwoOperands(crField bin, xb bin))

/// The UIM values lxvkq defines; the others are reserved.
let private isQuadConstant uim =
  (uim >= 1u && uim <= 9u) || (uim >= 16u && uim <= 24u)

/// lxvkq, "xT, UIM": a constant from a table, named where xxspltib keeps the
/// top of its byte, by the five ones that xxspltib can never hold there.
let private parseLXVKQ bin =
  let uim = Bits.extract bin 15u 11u
  if Bits.extract bin 20u 16u <> 31u || not (isQuadConstant uim) then
    raise ParsingFailureException
  else
    struct (Op.LXVKQ, TwoOperands(xt bin, OprImm(uint64 uim)))

/// The XX2 forms of extended opcode 475, which its A field tells apart.
let private parseXO475 bin =
  match Bits.extract bin 20u 16u with
  | 2u -> parseXX2CR Op.XVTLSBB bin
  | 7u -> parseXX2 Op.XXBRH bin
  | 15u -> parseXX2 Op.XXBRW bin
  | 23u -> parseXX2 Op.XXBRD bin
  | 31u -> parseXX2 Op.XXBRQ bin
  | _ -> raise ParsingFailureException

/// The X-forms of primary opcode 60, whose extended opcode is ten bits.
let private parse3CX bin =
  match Bits.extract bin 10u 1u with
  | 916u -> parseGenPCV Op.XXGENPCVBM bin
  | 917u -> parseGenPCV Op.XXGENPCVHM bin
  | 948u -> parseGenPCV Op.XXGENPCVWM bin
  | 949u -> parseGenPCV Op.XXGENPCVDM bin
  | _ -> raise ParsingFailureException

/// The XX3 forms of primary opcode 60, keyed by their eight-bit extended
/// opcode.
let private parse3CXX3 bin =
  match Bits.extract bin 10u 3u with
  | 26u -> parseXX3 Op.XXPERM bin
  | 58u -> parseXX3 Op.XXPERMR bin
  | _ -> parse3CX bin

/// <summary>
/// The forms of primary opcode 60 that ParsingMain does not decode itself.
/// An XX2 form's extended opcode is nine bits, ending above the two
/// register-extension bits; an XX3 form's is eight; an X-form's ten.
/// </summary>
let parse3C bin =
  match Bits.extract bin 10u 2u with
  | 10u -> parseXX2 Op.XSRSQRTESP bin
  | 26u -> parseXX2 Op.XSRESP bin
  | 165u -> parseXX2Uim Op.XXEXTRACTUW bin
  | 180u -> parseLXVKQ bin
  | 181u -> parseXX2Uim Op.XXINSERTW bin
  | 475u -> parseXO475 bin
  | _ -> parse3CXX3 bin

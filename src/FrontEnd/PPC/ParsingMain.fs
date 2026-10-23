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

module internal B2R2.FrontEnd.PPC.ParsingMain

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ParsingUtils
open B2R2.FrontEnd.PPC.OperandHelper

(*
  Decodes the Vector-Scalar Extension forms ISA 3.0 and 3.1 added: the VSX
  loads and stores, the vector-scalar arithmetic beyond what a compiler of
  the ISA 2.06 generation emitted, the quad-precision forms and the matrix
  accumulators. Each decode function here is reached from the dispatcher of
  its primary opcode in ParsingMain once that dispatcher has tried its own
  forms.
*)
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

/// The accumulator an MMA form names in its top three bits, the two bits
/// below them reserved.
let private accField bin =
  if Bits.extract bin 22u 21u <> 0u then
    raise ParsingFailureException
  else
    let n = int Register.ACC0 + int (Bits.extract bin 25u 23u)
    OprReg(LanguagePrimitives.EnumOfValue n)

/// xxmfacc, xxmtacc and xxsetaccz, "AS" or "AT", told apart by the A field.
let private parseAccumulatorMove bin =
  if Bits.extract bin 15u 11u <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    match Bits.extract bin 20u 16u with
    | 0u -> struct (Op.XXMFACC, OneOperand(accField bin))
    | 1u -> struct (Op.XXMTACC, OneOperand(accField bin))
    | 3u -> struct (Op.XXSETACCZ, OneOperand(accField bin))
    | _ -> raise ParsingFailureException

/// <summary>
/// The VSX loads and stores of primary opcode 31 that ISA 3.0 and 3.1 added,
/// and mtvsrws and the accumulator moves, which sit among them. The ten bits
/// above the last one are the extended opcode; the last bit extends the
/// register number.
/// </summary>
let parseVSX1F fallback bin =
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
  | 177u -> parseAccumulatorMove bin
  | _ -> fallback bin

/// The displacement of a DS-form, whose two low bits the encoding leaves out.
let private vsxDSDisp bin =
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
  struct (op, TwoOperands(vr, OprMem(vsxDSDisp bin, ra)))

/// lxv and stxv, "xT, DQ(rA)", whose register number keeps its sixth bit
/// just above the three bits that say which form this is.
let private parseVectorDQ op bin =
  let x = getVsxRegister (vsxNumber bin 3u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  struct (op, TwoOperands(x, OprMem(dqDisp bin, ra)))

/// The DS-form load lxssp, which primary opcode 57 holds beside lxsd and
/// lfdp.
let parseVSX39 bin =
  match Bits.extract bin 1u 0u with
  | 0b11u -> parseScalarSingleDS Op.LXSSP bin
  | _ -> raise ParsingFailureException

/// The stores and the vector load of primary opcode 61 beside stxsd and
/// stfdp: stxssp (DS-form) and the DQ-form lxv and stxv, whose three low bits
/// end in 01.
let parseVSX3D bin =
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
let private parseVSX2 op bin = struct (op, TwoOperands(xt bin, xb bin))

/// The register an XX3 form names in its A field, extended by bit 2.
let private xa bin = getVsxRegister (vsxNumber bin 2u 16u) |> OprReg

/// An XX3-form "xT, xA, xB".
let private parseVSX3 op bin =
  struct (op, ThreeOperands(xt bin, xa bin, xb bin))

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

/// An XX3 form that reports in a condition-register field: "BF, xA, xB".
let private parseXX3CR op bin =
  struct (op, ThreeOperands(crField bin, xa bin, xb bin))

/// xststdcdp and xststdcsp, "BF, xB, DCMX": the seven-bit mask lies below
/// the field, where an XX form keeps the bottom of xT and the A field.
let private parseScalarDCMX op bin =
  let dcmx = Bits.extract bin 22u 16u |> uint64 |> OprImm
  let bf = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
  struct (op, ThreeOperands(bf, xb bin, dcmx))

/// xvtstdcdp and xvtstdcsp, "xT, xB, DCMX": the mask is split three ways,
/// dc above the extended opcode's low part, dm beside the register bits and
/// dx in the A field.
let private parseVectorDCMX op bin =
  let dcmx =
    (Bits.pick bin 6u <<< 6) ||| (Bits.pick bin 2u <<< 5)
    ||| Bits.extract bin 20u 16u
  struct (op, ThreeOperands(xt bin, xb bin, OprImm(uint64 dcmx)))

/// xsxexpdp and xsxsigdp, "rT, xB", whose target is a general register.
let private parseToGPR op bin =
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  else struct (op, TwoOperands(gpr bin 21u, xb bin))

/// xsiexpdp, "xT, rA, rB", whose sources are general registers.
let private parseXSIEXPDP bin =
  struct (Op.XSIEXPDP, ThreeOperands(xt bin, gpr bin 16u, gpr bin 11u))

/// The XX2 forms of extended opcode 347, which its A field tells apart.
let private parseXO347 bin =
  match Bits.extract bin 20u 16u with
  | 0u -> parseToGPR Op.XSXEXPDP bin
  | 1u -> parseToGPR Op.XSXSIGDP bin
  | 16u -> parseVSX2 Op.XSCVHPDP bin
  | 17u -> parseVSX2 Op.XSCVDPHP bin
  | _ -> raise ParsingFailureException

/// The XX2 forms of extended opcode 475, which its A field tells apart.
let private parseXO475 bin =
  match Bits.extract bin 20u 16u with
  | 0u -> parseVSX2 Op.XVXEXPDP bin
  | 1u -> parseVSX2 Op.XVXSIGDP bin
  | 2u -> parseXX2CR Op.XVTLSBB bin
  | 7u -> parseVSX2 Op.XXBRH bin
  | 8u -> parseVSX2 Op.XVXEXPSP bin
  | 9u -> parseVSX2 Op.XVXSIGSP bin
  | 15u -> parseVSX2 Op.XXBRW bin
  | 16u -> parseVSX2 Op.XVCVBF16SPN bin
  | 17u -> parseVSX2 Op.XVCVSPBF16 bin
  | 23u -> parseVSX2 Op.XXBRD bin
  | 24u -> parseVSX2 Op.XVCVHPSP bin
  | 25u -> parseVSX2 Op.XVCVSPHP bin
  | 31u -> parseVSX2 Op.XXBRQ bin
  | _ -> raise ParsingFailureException

/// The X-forms of primary opcode 60, whose extended opcode is ten bits.
let private parse3CX bin =
  match Bits.extract bin 10u 1u with
  | 916u -> parseGenPCV Op.XXGENPCVBM bin
  | 918u -> parseXSIEXPDP bin
  | 917u -> parseGenPCV Op.XXGENPCVHM bin
  | 948u -> parseGenPCV Op.XXGENPCVWM bin
  | 949u -> parseGenPCV Op.XXGENPCVDM bin
  | _ -> raise ParsingFailureException

/// The XX3 forms of primary opcode 60, keyed by their eight-bit extended
/// opcode.
let private parse3CXX3 bin =
  match Bits.extract bin 10u 3u with
  | 3u -> parseVSX3 Op.XSCMPEQDP bin
  | 11u -> parseVSX3 Op.XSCMPGTDP bin
  | 19u -> parseVSX3 Op.XSCMPGEDP bin
  | 26u -> parseVSX3 Op.XXPERM bin
  | 43u -> parseXX3CR Op.XSCMPODP bin
  | 58u -> parseVSX3 Op.XXPERMR bin
  | 59u -> parseXX3CR Op.XSCMPEXPDP bin
  | 61u -> parseXX3CR Op.XSTDIVDP bin
  | 64u -> parseVSX3 Op.XVADDSP bin
  | 65u -> parseVSX3 Op.XVMADDASP bin
  | 67u -> parseVSX3 Op.XVCMPEQSP bin
  | 72u -> parseVSX3 Op.XVSUBSP bin
  | 73u -> parseVSX3 Op.XVMADDMSP bin
  | 75u -> parseVSX3 Op.XVCMPGTSP bin
  | 80u -> parseVSX3 Op.XVMULSP bin
  | 81u -> parseVSX3 Op.XVMSUBASP bin
  | 83u -> parseVSX3 Op.XVCMPGESP bin
  | 88u -> parseVSX3 Op.XVDIVSP bin
  | 89u -> parseVSX3 Op.XVMSUBMSP bin
  | 93u -> parseXX3CR Op.XVTDIVSP bin
  | 97u -> parseVSX3 Op.XVMADDADP bin
  | 99u -> parseVSX3 Op.XVCMPEQDP bin
  | 105u -> parseVSX3 Op.XVMADDMDP bin
  | 113u -> parseVSX3 Op.XVMSUBADP bin
  | 121u -> parseVSX3 Op.XVMSUBMDP bin
  | 125u -> parseXX3CR Op.XVTDIVDP bin
  | 128u -> parseVSX3 Op.XSMAXCDP bin
  | 136u -> parseVSX3 Op.XSMINCDP bin
  | 144u -> parseVSX3 Op.XSMAXJDP bin
  | 152u -> parseVSX3 Op.XSMINJDP bin
  | 192u -> parseVSX3 Op.XVMAXSP bin
  | 193u -> parseVSX3 Op.XVNMADDASP bin
  | 195u -> parseVSX3 Op.XVCMPEQSPdot bin
  | 200u -> parseVSX3 Op.XVMINSP bin
  | 201u -> parseVSX3 Op.XVNMADDMSP bin
  | 203u -> parseVSX3 Op.XVCMPGTSPdot bin
  | 208u -> parseVSX3 Op.XVCPSGNSP bin
  | 209u -> parseVSX3 Op.XVNMSUBASP bin
  | 211u -> parseVSX3 Op.XVCMPGESPdot bin
  | 213u -> parseVectorDCMX Op.XVTSTDCSP bin
  | 216u -> parseVSX3 Op.XVIEXPSP bin
  | 217u -> parseVSX3 Op.XVNMSUBMSP bin
  | 221u -> parseVectorDCMX Op.XVTSTDCSP bin
  | 224u -> parseVSX3 Op.XVMAXDP bin
  | 225u -> parseVSX3 Op.XVNMADDADP bin
  | 227u -> parseVSX3 Op.XVCMPEQDPdot bin
  | 232u -> parseVSX3 Op.XVMINDP bin
  | 233u -> parseVSX3 Op.XVNMADDMDP bin
  | 240u -> parseVSX3 Op.XVCPSGNDP bin
  | 241u -> parseVSX3 Op.XVNMSUBADP bin
  | 245u -> parseVectorDCMX Op.XVTSTDCDP bin
  | 248u -> parseVSX3 Op.XVIEXPDP bin
  | 249u -> parseVSX3 Op.XVNMSUBMDP bin
  | 253u -> parseVectorDCMX Op.XVTSTDCDP bin
  | _ -> parse3CX bin

/// <summary>
/// The forms of primary opcode 60 that ParsingMain does not decode itself.
/// An XX2 form's extended opcode is nine bits, ending above the two
/// register-extension bits; an XX3 form's is eight; an X-form's ten.
/// </summary>
let parseVSX3C bin =
  match Bits.extract bin 10u 2u with
  | 10u -> parseVSX2 Op.XSRSQRTESP bin
  | 26u -> parseVSX2 Op.XSRESP bin
  | 74u -> parseVSX2 Op.XSRSQRTEDP bin
  | 90u -> parseVSX2 Op.XSREDP bin
  | 106u -> parseXX2CR Op.XSTSQRTDP bin
  | 107u -> parseVSX2 Op.XSRDPIC bin
  | 136u -> parseVSX2 Op.XVCVSPUXWS bin
  | 137u -> parseVSX2 Op.XVRSPI bin
  | 138u -> parseVSX2 Op.XVRSQRTESP bin
  | 139u -> parseVSX2 Op.XVSQRTSP bin
  | 152u -> parseVSX2 Op.XVCVSPSXWS bin
  | 153u -> parseVSX2 Op.XVRSPIZ bin
  | 154u -> parseVSX2 Op.XVRESP bin
  | 165u -> parseXX2Uim Op.XXEXTRACTUW bin
  | 168u -> parseVSX2 Op.XVCVUXWSP bin
  | 169u -> parseVSX2 Op.XVRSPIP bin
  | 170u -> parseXX2CR Op.XVTSQRTSP bin
  | 171u -> parseVSX2 Op.XVRSPIC bin
  | 180u -> parseLXVKQ bin
  | 181u -> parseXX2Uim Op.XXINSERTW bin
  | 184u -> parseVSX2 Op.XVCVSXWSP bin
  | 185u -> parseVSX2 Op.XVRSPIM bin
  | 200u -> parseVSX2 Op.XVCVDPUXWS bin
  | 201u -> parseVSX2 Op.XVRDPI bin
  | 202u -> parseVSX2 Op.XVRSQRTEDP bin
  | 203u -> parseVSX2 Op.XVSQRTDP bin
  | 216u -> parseVSX2 Op.XVCVDPSXWS bin
  | 217u -> parseVSX2 Op.XVRDPIZ bin
  | 218u -> parseVSX2 Op.XVREDP bin
  | 232u -> parseVSX2 Op.XVCVUXWDP bin
  | 233u -> parseVSX2 Op.XVRDPIP bin
  | 234u -> parseXX2CR Op.XVTSQRTDP bin
  | 235u -> parseVSX2 Op.XVRDPIC bin
  | 249u -> parseVSX2 Op.XVRDPIM bin
  | 298u -> parseScalarDCMX Op.XSTSTDCSP bin
  | 347u -> parseXO347 bin
  | 362u -> parseScalarDCMX Op.XSTSTDCDP bin
  | 392u -> parseVSX2 Op.XVCVSPUXDS bin
  | 393u -> parseVSX2 Op.XVCVDPSP bin
  | 408u -> parseVSX2 Op.XVCVSPSXDS bin
  | 409u -> parseVSX2 Op.XVABSSP bin
  | 424u -> parseVSX2 Op.XVCVUXDSP bin
  | 425u -> parseVSX2 Op.XVNABSSP bin
  | 440u -> parseVSX2 Op.XVCVSXDSP bin
  | 441u -> parseVSX2 Op.XVNEGSP bin
  | 456u -> parseVSX2 Op.XVCVDPUXDS bin
  | 457u -> parseVSX2 Op.XVCVSPDP bin
  | 472u -> parseVSX2 Op.XVCVDPSXDS bin
  | 473u -> parseVSX2 Op.XVABSDP bin
  | 475u -> parseXO475 bin
  | 488u -> parseVSX2 Op.XVCVUXDDP bin
  | 489u -> parseVSX2 Op.XVNABSDP bin
  | 504u -> parseVSX2 Op.XVCVSXDDP bin
  | _ -> parse3CXX3 bin

(* The quad-precision forms of primary opcode 63. Their extended opcodes all
   end in 0b00100 (the X-forms) or 0b00101 (the Z23-forms), which none of
   the floating-point forms ParsingMain decodes there do. *)
/// The vector register named by the five bits starting at lo.
let private vrAt bin lo =
  getVecRegister (Bits.extract bin (lo + 4u) lo) |> OprReg

/// A quad X-form "vRT, vRA, vRB" whose last bit is reserved.
let private parseQuad op bin =
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  else struct (op, ThreeOperands(vrAt bin 21u, vrAt bin 16u, vrAt bin 11u))

/// A quad X-form "vRT, vRA, vRB" whose last bit asks for round to odd.
let private parseQuadRO op opO bin =
  let op = if Bits.pick bin 0u = 0u then op else opO
  struct (op, ThreeOperands(vrAt bin 21u, vrAt bin 16u, vrAt bin 11u))

/// A quad compare into a condition-register field: "BF, vRA, vRB".
let private parseQuadCR op bin =
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  else struct (op, ThreeOperands(crField bin, vrAt bin 16u, vrAt bin 11u))

/// A quad X-form "vRT, vRB" whose A field is part of the opcode, its last
/// bit reserved unless the form rounds to odd by it.
let private parseQuadUnary op opO bin =
  let op =
    match opO with
    | Some o when Bits.pick bin 0u = 1u -> o
    | None when Bits.pick bin 0u = 1u -> raise ParsingFailureException
    | _ -> op
  struct (op, TwoOperands(vrAt bin 21u, vrAt bin 11u))

/// xststdcqp, "BF, vRB, DCMX".
let private parseQuadDCMX bin =
  let dcmx = Bits.extract bin 22u 16u |> uint64 |> OprImm
  let bf = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  else struct (Op.XSTSTDCQP, ThreeOperands(bf, vrAt bin 11u, dcmx))

/// The quad forms of extended opcode 804, which the A field tells apart.
let private parseXO804 bin =
  match Bits.extract bin 20u 16u with
  | 0u -> parseQuadUnary Op.XSABSQP None bin
  | 2u -> parseQuadUnary Op.XSXEXPQP None bin
  | 8u -> parseQuadUnary Op.XSNABSQP None bin
  | 16u -> parseQuadUnary Op.XSNEGQP None bin
  | 18u -> parseQuadUnary Op.XSXSIGQP None bin
  | 27u -> parseQuadUnary Op.XSSQRTQP (Some Op.XSSQRTQPO) bin
  | _ -> raise ParsingFailureException

/// The quad conversions of extended opcode 836, which the A field tells
/// apart.
let private parseXO836 bin =
  match Bits.extract bin 20u 16u with
  | 0u -> parseQuadUnary Op.XSCVQPUQZ None bin
  | 1u -> parseQuadUnary Op.XSCVQPUWZ None bin
  | 2u -> parseQuadUnary Op.XSCVUDQP None bin
  | 3u -> parseQuadUnary Op.XSCVUQQP None bin
  | 8u -> parseQuadUnary Op.XSCVQPSQZ None bin
  | 9u -> parseQuadUnary Op.XSCVQPSWZ None bin
  | 10u -> parseQuadUnary Op.XSCVSDQP None bin
  | 11u -> parseQuadUnary Op.XSCVSQQP None bin
  | 17u -> parseQuadUnary Op.XSCVQPUDZ None bin
  | 20u -> parseQuadUnary Op.XSCVQPDP (Some Op.XSCVQPDPO) bin
  | 22u -> parseQuadUnary Op.XSCVDPQP None bin
  | 25u -> parseQuadUnary Op.XSCVQPSDZ None bin
  | _ -> raise ParsingFailureException

/// <summary>
/// A Z23-form "R, vRT, vRB, RMC". R = 0 defines only RMC = 0 (to nearest,
/// ties away) and RMC = 3 (FPSCR[RN]); the other two are reserved.
/// </summary>
let private parseZ23 op bin =
  let r = Bits.pick bin 16u
  let rmc = Bits.extract bin 10u 9u
  if Bits.extract bin 20u 17u <> 0u || (r = 0u && (rmc = 1u || rmc = 2u)) then
    raise ParsingFailureException
  else
    let vrt, vrb = vrAt bin 21u, vrAt bin 11u
    struct (op, FourOperands(OprImm(uint64 r), vrt, vrb, OprImm(uint64 rmc)))

/// The Z23-forms: xsrqpi and xsrqpix (EX in the last bit), xsrqpxp.
let private parseQuadZ23 bin =
  match Bits.extract bin 8u 1u with
  | 5u when Bits.pick bin 0u = 0u -> parseZ23 Op.XSRQPI bin
  | 5u -> parseZ23 Op.XSRQPIX bin
  | 37u when Bits.pick bin 0u = 0u -> parseZ23 Op.XSRQPXP bin
  | _ -> raise ParsingFailureException

/// The quad-precision forms of primary opcode 63.
let parseVSX3F bin =
  if Bits.extract bin 5u 1u = 5u then
    parseQuadZ23 bin
  else
    match Bits.extract bin 10u 1u with
    | 4u -> parseQuadRO Op.XSADDQP Op.XSADDQPO bin
    | 36u -> parseQuadRO Op.XSMULQP Op.XSMULQPO bin
    | 68u -> parseQuad Op.XSCMPEQQP bin
    | 100u -> parseQuad Op.XSCPSGNQP bin
    | 132u -> parseQuadCR Op.XSCMPOQP bin
    | 164u -> parseQuadCR Op.XSCMPEXPQP bin
    | 196u -> parseQuad Op.XSCMPGEQP bin
    | 228u -> parseQuad Op.XSCMPGTQP bin
    | 388u -> parseQuadRO Op.XSMADDQP Op.XSMADDQPO bin
    | 420u -> parseQuadRO Op.XSMSUBQP Op.XSMSUBQPO bin
    | 452u -> parseQuadRO Op.XSNMADDQP Op.XSNMADDQPO bin
    | 484u -> parseQuadRO Op.XSNMSUBQP Op.XSNMSUBQPO bin
    | 516u -> parseQuadRO Op.XSSUBQP Op.XSSUBQPO bin
    | 548u -> parseQuadRO Op.XSDIVQP Op.XSDIVQPO bin
    | 644u -> parseQuadCR Op.XSCMPUQP bin
    | 676u -> parseQuad Op.XSMAXCQP bin
    | 708u -> parseQuadDCMX bin
    | 740u -> parseQuad Op.XSMINCQP bin
    | 804u -> parseXO804 bin
    | 836u -> parseXO836 bin
    | 868u -> parseQuad Op.XSIEXPQP bin
    | _ -> raise ParsingFailureException

(* The Matrix-Multiply Assist forms. *)
/// The rank-k update an eight-bit extended opcode (instruction bits 21:28)
/// of primary opcode 59 names, or InvalOP.
let private matrixOp xo =
  match xo with
  | 2u -> Op.XVI8GER4PP
  | 3u -> Op.XVI8GER4
  | 18u -> Op.XVF16GER2PP
  | 19u -> Op.XVF16GER2
  | 26u -> Op.XVF32GERPP
  | 27u -> Op.XVF32GER
  | 34u -> Op.XVI4GER8PP
  | 35u -> Op.XVI4GER8
  | 42u -> Op.XVI16GER2SPP
  | 43u -> Op.XVI16GER2S
  | 50u -> Op.XVBF16GER2PP
  | 51u -> Op.XVBF16GER2
  | 58u -> Op.XVF64GERPP
  | 59u -> Op.XVF64GER
  | 75u -> Op.XVI16GER2
  | 82u -> Op.XVF16GER2NP
  | 90u -> Op.XVF32GERNP
  | 99u -> Op.XVI8GER4SPP
  | 107u -> Op.XVI16GER2PP
  | 114u -> Op.XVBF16GER2NP
  | 122u -> Op.XVF64GERNP
  | 146u -> Op.XVF16GER2PN
  | 154u -> Op.XVF32GERPN
  | 178u -> Op.XVBF16GER2PN
  | 186u -> Op.XVF64GERPN
  | 210u -> Op.XVF16GER2NN
  | 218u -> Op.XVF32GERNN
  | 242u -> Op.XVBF16GER2NN
  | 250u -> Op.XVF64GERNN
  | _ -> Op.InvalOP

/// Whether a word of primary opcode 59 is one of the rank-k updates.
let isMatrixForm bin = matrixOp (Bits.extract bin 10u 3u) <> Op.InvalOP

/// Whether a rank-k update reads its xA as a pair: the 64-bit ones.
let private readsPair op =
  match op with
  | Op.XVF64GER | Op.XVF64GERPP | Op.XVF64GERPN | Op.XVF64GERNP
  | Op.XVF64GERNN -> true
  | _ -> false

/// <summary>
/// The rank-k updates, "AT, xA, xB". The form is invalid where xA or xB is
/// one of the four registers the accumulator overlays, or where the pair a
/// 64-bit form reads starts at an odd register; the last bit is reserved.
/// </summary>
let parseVSX3B bin =
  let op = matrixOp (Bits.extract bin 10u 3u)
  let first = 4u * Bits.extract bin 25u 23u
  let overlaps n = n >= first && n <= first + 3u
  let na, nb = vsxNumber bin 2u 16u, vsxNumber bin 1u 11u
  let oddPair = readsPair op && na &&& 1u = 1u
  if Bits.pick bin 0u <> 0u || overlaps na || overlaps nb || oddPair then
    raise ParsingFailureException
  else
    struct (op, ThreeOperands(accField bin, xa bin, xb bin))

(*
  Decodes the instructions the embedded environment adds to primary opcodes
  19 and 31 (Power ISA 2.07B Book II and Book III-E): the cache-locking
  instructions, Decorated Storage, the debug, hypervisor and device moves, and
  the memory barrier whose word a server processor reads as eieio. No server
  instruction shares the other encodings, so they read the same under every
  category; ParsingLegacy hands a word here once its own tables are done with
  it.
*)
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
let tryParseEmbedded31 category bitLen bin =
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

(*
  Decodes the instructions of the Transactional Memory category (Power ISA
  2.07B Book II chapter 5), all of primary opcode 31, and the moves to and
  from its three special registers, which the manual gives their own
  mnemonics. No server instruction
  of the ISAs B2R2 reads shares their encodings, so they read the same under
  every category; ParsingLegacy hands a word here once its own tables are done
  with it.
*)
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
let tryParseTM31 bitLen bin =
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

(*
  Decodes the instructions of the Power ISA 2.07B categories that 3.1 no
  longer has, and the encodings whose reading the categories of a processor
  decide (see Category). ParsingMain hands a word here first; a word this
  module does not take goes on to ParsingMain's own decoder.
*)
/// The three general registers of an X- or XO-form, in the order the fields
/// hold them: rT (or rS), rA, rB.
let private threeRegisters bin =
  let rt = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  ThreeOperands(rt, ra, rb)

/// The halfword multiplies, by the ten-bit extended opcode of their X-form,
/// each with the name that records CR0 after the one that does not.
let private multiplies = function
  | 8u -> ValueSome [| Op.MULHHWU; Op.MULHHWUdot |]
  | 40u -> ValueSome [| Op.MULHHW; Op.MULHHWdot |]
  | 136u -> ValueSome [| Op.MULCHWU; Op.MULCHWUdot |]
  | 168u -> ValueSome [| Op.MULCHW; Op.MULCHWdot |]
  | 392u -> ValueSome [| Op.MULLHWU; Op.MULLHWUdot |]
  | 424u -> ValueSome [| Op.MULLHW; Op.MULLHWdot |]
  | _ -> ValueNone

/// The multiply-accumulates, by the nine-bit extended opcode their XO-form
/// keeps below OE, each as its four names: plain, recording CR0, recording
/// OV, and recording both.
let private accumulates = function
  | 12u ->
    [| Op.MACHHWU; Op.MACHHWUdot; Op.MACHHWUO; Op.MACHHWUOdot |]
  | 44u ->
    [| Op.MACHHW; Op.MACHHWdot; Op.MACHHWO; Op.MACHHWOdot |]
  | 46u ->
    [| Op.NMACHHW; Op.NMACHHWdot; Op.NMACHHWO; Op.NMACHHWOdot |]
  | 76u ->
    [| Op.MACHHWSU; Op.MACHHWSUdot; Op.MACHHWSUO; Op.MACHHWSUOdot |]
  | 108u ->
    [| Op.MACHHWS; Op.MACHHWSdot; Op.MACHHWSO; Op.MACHHWSOdot |]
  | 110u ->
    [| Op.NMACHHWS; Op.NMACHHWSdot; Op.NMACHHWSO; Op.NMACHHWSOdot |]
  | 140u ->
    [| Op.MACCHWU; Op.MACCHWUdot; Op.MACCHWUO; Op.MACCHWUOdot |]
  | 172u ->
    [| Op.MACCHW; Op.MACCHWdot; Op.MACCHWO; Op.MACCHWOdot |]
  | 174u ->
    [| Op.NMACCHW; Op.NMACCHWdot; Op.NMACCHWO; Op.NMACCHWOdot |]
  | 204u ->
    [| Op.MACCHWSU; Op.MACCHWSUdot; Op.MACCHWSUO; Op.MACCHWSUOdot |]
  | 236u ->
    [| Op.MACCHWS; Op.MACCHWSdot; Op.MACCHWSO; Op.MACCHWSOdot |]
  | 238u ->
    [| Op.NMACCHWS; Op.NMACCHWSdot; Op.NMACCHWSO; Op.NMACCHWSOdot |]
  | 396u ->
    [| Op.MACLHWU; Op.MACLHWUdot; Op.MACLHWUO; Op.MACLHWUOdot |]
  | 428u ->
    [| Op.MACLHW; Op.MACLHWdot; Op.MACLHWO; Op.MACLHWOdot |]
  | 430u ->
    [| Op.NMACLHW; Op.NMACLHWdot; Op.NMACLHWO; Op.NMACLHWOdot |]
  | 460u ->
    [| Op.MACLHWSU; Op.MACLHWSUdot; Op.MACLHWSUO; Op.MACLHWSUOdot |]
  | 492u ->
    [| Op.MACLHWS; Op.MACLHWSdot; Op.MACLHWSO; Op.MACLHWSOdot |]
  | 494u ->
    [| Op.NMACLHWS; Op.NMACLHWSdot; Op.NMACLHWSO; Op.NMACLHWSOdot |]
  | _ ->
    raise ParsingFailureException

/// <summary>
/// Primary opcode 4 on a processor with the Legacy Integer
/// Multiply-Accumulate category, which has no vector facility to share it
/// with. A multiply is an X-form whose bit 21 is part of its extended opcode;
/// a multiply-accumulate is an XO-form whose bit 21 is OE.
/// </summary>
let private parseLegacyMultiply bin =
  match multiplies (Bits.extract bin 10u 1u) with
  | ValueSome ops ->
    struct (ops[int (Bits.pick bin 0u)], threeRegisters bin)
  | ValueNone ->
    let ops = accumulates (Bits.extract bin 9u 1u)
    let form = Bits.pick bin 10u * 2u + Bits.pick bin 0u
    struct (ops[int form], threeRegisters bin)

/// Whether the categories give primary opcode 4 to the Legacy Integer
/// Multiply-Accumulate instructions.
let private hasLegacyMultiply category =
  Category.includes Category.LegacyIntegerMultiplyAccumulate category

/// dlmzb and dlmzb., the one instruction of the Legacy Move Assist category:
/// "rA, rS, rB", rS being the field above rA in the word.
let private parseDlmzb bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  let opcode = if Bits.pick bin 0u = 0u then Op.DLMZB else Op.DLMZBdot
  struct (opcode, ThreeOperands(ra, rs, rb))

/// The instructions of primary opcode 31, by the ten-bit extended opcode:
/// dlmzb, which only the category that has it reads (a server processor reads
/// its word with rS and rA zero as msgsndu), what the embedded environment adds
/// and the transactional memory instructions.
let private parse31 category bitLen bin =
  match Bits.extract bin 10u 1u with
  | 78u when Category.includes Category.LegacyMoveAssist category ->
    ValueSome(parseDlmzb bin)
  | _ ->
    match tryParseEmbedded31 category bitLen bin with
    | ValueNone -> tryParseTM31 bitLen bin
    | parsed -> parsed

/// The instruction a word is, if it is one this module takes on a processor
/// implementing the categories given, with registers of bitLen bits.
let tryParse category bitLen bin =
  match bin >>> 26 with
  | 4u when hasLegacyMultiply category ->
    ValueSome(parseLegacyMultiply bin)
  | 19u ->
    tryParse19 bin
  | 26u when bin = 0x68000000u ->
    ValueSome(struct (Op.XNOP, NoOperand))
  | 31u ->
    parse31 category bitLen bin
  | _ ->
    ValueNone

/// Sign-extends a 16-bit signed-immediate field to the guest's register width,
/// so a negative immediate reads as one on either word size.
let private simm16 bitLen bin =
  Bits.extract bin 15u 0u |> uint64 |> Bits.signExtend 16 bitLen |> uint64

let parseTWI bitLen bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let value = simm16 bitLen bin |> OprImm
  match Bits.extract bin 25u 21u with
  (* twlgti ra,value = twi 1,ra,value *)
  | 1u ->
    struct (Op.TWLGTI, TwoOperands(ra, value))
  (* twllti ra,value = twi 2,ra,value *)
  | 2u ->
    struct (Op.TWLLTI, TwoOperands(ra, value))
  (* tweqi ra,value = twi 4,ra,value *)
  | 4u ->
    struct (Op.TWEQI, TwoOperands(ra, value))
  (* twlnli ra,value = twi 5,ra,value *)
  | 5u ->
    struct (Op.TWLNLI, TwoOperands(ra, value))
  (* twllei ra,value = twi 6,ra,value *)
  | 6u ->
    struct (Op.TWLLEI, TwoOperands(ra, value))
  (* twgti ra,value = twi 8,ra,value *)
  | 8u ->
    struct (Op.TWGTI, TwoOperands(ra, value))
  (* twgei ra,value = twi 12,ra,value *)
  | 12u ->
    struct (Op.TWGEI, TwoOperands(ra, value))
  (* twlti ra,value = twi 16,ra,value *)
  | 16u ->
    struct (Op.TWLTI, TwoOperands(ra, value))
  (* twlei ra,value = twi 20,ra,value *)
  | 20u ->
    struct (Op.TWLEI, TwoOperands(ra, value))
  (* twnei ra,value = twi 24,ra,value *)
  | 24u ->
    struct (Op.TWNEI, TwoOperands(ra, value))
  (* twllei ra,value = twlngi ra, value = twi 6,ra,value
     twgei ra,value = twlgei ra, value = twnli ra, value = twi 12,ra,value
     twlei ra,value = twngi ra, value = twi 20,ra,value *)
  | _ ->
    let tO = Bits.extract bin 25u 21u |> uint64 |> OprImm
    struct (Op.TWI, ThreeOperands(tO, ra, value))

let parseMULLI bitLen bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let value = simm16 bitLen bin |> OprImm
  struct (Op.MULLI, ThreeOperands(rd, ra, value))

let parseSUBFIC bitLen bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let value = simm16 bitLen bin |> OprImm
  struct (Op.SUBFIC, ThreeOperands(rd, ra, value))

let parseCMPLI bin =
  match Bits.pick bin 22u with
  | 0b0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let uimm = Bits.extract bin 15u 0u |> uint64 |> OprImm
    match Bits.pick bin 21u with
    (* cmplwi crfd,ra,uimm = cmpli crfd,0,ra,uimm *)
    | 0b0u -> struct (Op.CMPLWI, ThreeOperands(crfd, ra, uimm))
    (* cmpldi crfd,ra,uimm = cmpli crfd,1,ra,uimm *)
    | _ -> struct (Op.CMPLDI, ThreeOperands(crfd, ra, uimm))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseCMPI bitLen bin =
  match Bits.pick bin 22u with
  | 0b0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let value = simm16 bitLen bin |> OprImm
    match Bits.pick bin 21u with
    (* cmpwi crfd,ra,simm = cmpi crfd,0,ra,simm *)
    | 0b0u -> struct (Op.CMPWI, ThreeOperands(crfd, ra, value))
    (* cmpdi crfd,ra,simm = cmpi crfd,1,ra,simm *)
    | _ -> struct (Op.CMPDI, ThreeOperands(crfd, ra, value))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseADDIC bitLen bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let value = simm16 bitLen bin |> OprImm
  (* subic rd,ra,value = addic rd,ra,-value *)
  struct (Op.ADDIC, ThreeOperands(rd, ra, value))

let parseADDICdot bitLen bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let value = simm16 bitLen bin |> OprImm
  (* subic. rd,ra,value = addic. rd,ra,-value *)
  struct (Op.ADDICdot, ThreeOperands(rd, ra, value))

let parseADDI bitLen bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let value = simm16 bitLen bin |> OprImm
  match Bits.extract bin 20u 16u with
  | 0b0u ->
    struct (Op.LI, TwoOperands(rd, value))
  (* subi rd,ra,value = addi rd,ra,-value *)
  | _ ->
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    struct (Op.ADDI, ThreeOperands(rd, ra, value))

let parseADDIS bitLen bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let value = simm16 bitLen bin |> OprImm
  match Bits.extract bin 20u 16u with
  | 0b0u ->
    struct (Op.LIS, TwoOperands(rd, value))
  (* subis rd,ra,value = addis rd,ra,-value *)
  | _ ->
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    struct (Op.ADDIS, ThreeOperands(rd, ra, value))

let parseBCx bitLen bin =
  let idx = (Bits.extract bin 1u 0u |> int) (* opcode *)
  let bd = Bits.extract bin 15u 2u <<< 2 |> uint64
  let value = Bits.signExtend 16 bitLen bd |> uint64 |> OprAddr
  let op = [| Op.BC; Op.BCL; Op.BCA; Op.BCLA |].[idx]
  let bo = Bits.extract bin 25u 21u |> uint64 |> OprImm
  struct (op, ThreeOperands(bo, OprBI(Bits.extract bin 20u 16u), value))

let parseSC bin =
  match Bits.pick bin 1u with
  | 0b1u -> struct (Op.SC, NoOperand)
  | _ -> raise ParsingFailureException

/// scv LEV, whose seven-bit LEV sits in bits 20 to 26.
let parseSCV bin =
  let lev = Bits.extract bin 11u 5u |> uint64
  struct (Op.SCV, OneOperand(OprImm lev))

let parseBx bitLen bin addr =
  let li = Bits.extract bin 25u 2u |> uint64
  let signExtended = Bits.signExtend 26 bitLen (li <<< 2) |> uint64
  let mask = System.UInt64.MaxValue >>> (64 - bitLen)
  match Bits.extract bin 1u 0u (* AA:LK *) with
  | 0b00u ->
    let value = (addr + signExtended) &&& mask |> OprImm
    struct (Op.B, OneOperand value)
  | 0b01u ->
    let value = (addr + signExtended) &&& mask |> OprImm
    struct (Op.BL, OneOperand value)
  | 0b10u ->
    let value = signExtended |> OprImm
    struct (Op.BA, OneOperand value)
  | _ (* 11 *) ->
    let value = signExtended |> OprImm
    struct (Op.BLA, OneOperand value)

let parseMCRF bin =
  match Bits.pick bin 0u with
  | 0b0u when Bits.concat (Bits.extract bin 22u 21u)
                          (Bits.extract bin 17u 11u)
                          2 = 0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    let crfs = getCondRegister (Bits.extract bin 20u 18u) |> OprReg
    struct (Op.MCRF, TwoOperands(crfd, crfs))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseBCLRx bin =
  if Bits.extract bin 15u 11u <> 0u then
    raise ParsingFailureException
  else
    let idx = Bits.pick bin 0u |> int (* opcode *)
    let op = [| Op.BCLR; Op.BCLRL |].[idx]
    let bo = Bits.extract bin 25u 21u |> uint64 |> OprImm
    struct (op, TwoOperands(bo, OprBI(Bits.extract bin 20u 16u)))

let parseCRNOR bin =
  match Bits.pick bin 0u with
  | 0b0u ->
    let crbd = Bits.extract bin 25u 21u |> OprBI
    let crba = Bits.extract bin 20u 16u |> OprBI
    (* crnot crbd,crba = crnor crbd,crba,crba *)
    if Bits.extract bin 20u 16u = Bits.extract bin 15u 11u then
      struct (Op.CRNOT, TwoOperands(crbd, crba))
    else
      let crbb = Bits.extract bin 15u 11u |> OprBI
      struct (Op.CRNOR, ThreeOperands(crbd, crba, crbb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseRFI bin =
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 25u 11u = 0u -> struct (Op.RFI, NoOperand)
  | _ (* 1 *) -> raise ParsingFailureException

let parseCRANDC bin =
  match Bits.pick bin 0u with
  | 0b0u ->
    let crbd = Bits.extract bin 25u 21u |> OprBI
    let crba = Bits.extract bin 20u 16u |> OprBI
    let crbb = Bits.extract bin 15u 11u |> OprBI
    struct (Op.CRANDC, ThreeOperands(crbd, crba, crbb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseISYNC bin =
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 25u 11u = 0u -> struct (Op.ISYNC, NoOperand)
  | _ (* 1 *) -> raise ParsingFailureException

let parseCRXOR bin =
  match Bits.pick bin 0u with
  | 0b0u ->
    let crbd = Bits.extract bin 25u 21u |> OprBI
    let crba = Bits.extract bin 20u 16u |> OprBI
    let crbb = Bits.extract bin 15u 11u |> OprBI
    if (crbd = crba) && (crbd = crbb) then struct (Op.CRCLR, OneOperand crbd)
    else struct (Op.CRXOR, ThreeOperands(crbd, crba, crbb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseCRNAND bin =
  match Bits.pick bin 0u with
  | 0b0u ->
    let crbd = Bits.extract bin 25u 21u |> OprBI
    let crba = Bits.extract bin 20u 16u |> OprBI
    let crbb = Bits.extract bin 15u 11u |> OprBI
    struct (Op.CRNAND, ThreeOperands(crbd, crba, crbb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseCRAND bin =
  match Bits.pick bin 0u with
  | 0b0u ->
    let crbd = Bits.extract bin 25u 21u |> OprBI
    let crba = Bits.extract bin 20u 16u |> OprBI
    let crbb = Bits.extract bin 15u 11u |> OprBI
    struct (Op.CRAND, ThreeOperands(crbd, crba, crbb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseCREQV bin =
  match Bits.pick bin 0u with
  | 0b0u ->
    let crbd = Bits.extract bin 25u 21u |> OprBI
    (* crset crbd = creqv crbd,crbd,crbd *)
    if Bits.extract bin 25u 21u = Bits.extract bin 20u 16u then
      if Bits.extract bin 20u 16u = Bits.extract bin 15u 11u then
        struct (Op.CRSET, OneOperand crbd)
      else
        let crba = Bits.extract bin 20u 16u |> OprBI
        let crbb = Bits.extract bin 15u 11u |> OprBI
        struct (Op.CREQV, ThreeOperands(crbd, crba, crbb))
    else
      let crba = Bits.extract bin 20u 16u |> OprBI
      let crbb = Bits.extract bin 15u 11u |> OprBI
      struct (Op.CREQV, ThreeOperands(crbd, crba, crbb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseCRORC bin =
  match Bits.pick bin 0u with
  | 0b0u ->
    let crbd = Bits.extract bin 25u 21u |> OprBI
    let crba = Bits.extract bin 20u 16u |> OprBI
    let crbb = Bits.extract bin 15u 11u |> OprBI
    struct (Op.CRORC, ThreeOperands(crbd, crba, crbb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseCROR bin =
  match Bits.pick bin 0u with
  | 0b0u ->
    let crbd = Bits.extract bin 25u 21u |> OprBI
    let crba = Bits.extract bin 20u 16u |> OprBI
    (* crmove crbd,crba = cror crbd,crba,crba *)
    if Bits.extract bin 20u 16u = Bits.extract bin 15u 11u then
      struct (Op.CRMOVE, TwoOperands(crbd, crba))
    else
      let crbb = Bits.extract bin 15u 11u |> OprBI
      struct (Op.CROR, ThreeOperands(crbd, crba, crbb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseBCCTRx bin =
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 15u 11u = 0u ->
    let bo = Bits.extract bin 25u 21u |> uint64 |> OprImm
    struct (Op.BCCTR, TwoOperands(bo, OprBI(Bits.extract bin 20u 16u)))
  | 0b1u when Bits.extract bin 15u 11u = 0u ->
    let bo = Bits.extract bin 25u 21u |> uint64 |> OprImm
    struct (Op.BCCTRL, TwoOperands(bo, OprBI(Bits.extract bin 20u 16u)))
  | _ ->
    raise ParsingFailureException

/// addpcis rT, D, a DX form whose sixteen-bit D is split three ways: d0 in
/// bits 16-25, d1 in bits 11-15 and d2 in bit 31. Its extended opcode is the
/// five bits 26-30 alone, which no XL form of primary opcode 19 shares.
let parseADDPCIS bitLen bin =
  let rt = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let d0 = Bits.extract bin 15u 6u
  let d1 = Bits.extract bin 20u 16u
  let d = (d0 <<< 6) ||| (d1 <<< 1) ||| Bits.pick bin 0u
  let value = d |> uint64 |> Bits.signExtend 16 bitLen |> uint64
  struct (Op.ADDPCIS, TwoOperands(rt, OprImm value))

/// rfebb S, which returns from an event-based branch and sets BESCR[GE] to
/// S, the one bit it names.
let parseRFEBB bin =
  if Bits.extract bin 25u 12u <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    struct (Op.RFEBB, OneOperand(Bits.pick bin 11u |> uint64 |> OprImm))

/// bctar/bctarl, which branch to TAR. Bits 16-18 are reserved; the BH hint in
/// bits 19-20 is carried as a third operand only where it is not zero, which
/// is how the assembler language leaves it out.
let parseBCTARx bin =
  if Bits.extract bin 15u 13u <> 0u then
    raise ParsingFailureException
  else
    let op = if Bits.pick bin 0u = 0u then Op.BCTAR else Op.BCTARL
    let bo = Bits.extract bin 25u 21u |> uint64 |> OprImm
    let bi = OprBI(Bits.extract bin 20u 16u)
    match Bits.extract bin 12u 11u with
    | 0u -> struct (op, TwoOperands(bo, bi))
    | bh -> struct (op, ThreeOperands(bo, bi, OprImm(uint64 bh)))

/// The forms of primary opcode 19. rfebb and bctar belong to the event-based
/// branch and target address facilities of the 64-bit processors only.
let parse13 bitLen bin =
  match Bits.extract bin 10u 1u with
  | xo when xo &&& 0x1Fu = 2u -> parseADDPCIS bitLen bin
  | 0x0u -> parseMCRF bin
  | 0x10u -> parseBCLRx bin
  | 0x21u -> parseCRNOR bin
  | 0x32u -> parseRFI bin
  | 0x92u when bitLen = 64 -> parseRFEBB bin
  | 0x81u -> parseCRANDC bin
  | 0x96u -> parseISYNC bin
  | 0xC1u -> parseCRXOR bin
  | 0xE1u -> parseCRNAND bin
  | 0x101u -> parseCRAND bin
  | 0x121u -> parseCREQV bin
  | 0x1A1u -> parseCRORC bin
  | 0x1C1u -> parseCROR bin
  | 0x210u -> parseBCCTRx bin
  | 0x230u when bitLen = 64 -> parseBCTARx bin
  | _ -> raise ParsingFailureException

let parseRLWIMIx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let sh = Bits.extract bin 15u 11u |> uint64 |> OprImm
  let mb = Bits.extract bin 10u 6u |> uint64 |> OprImm
  let me = Bits.extract bin 5u 1u |> uint64 |> OprImm
  match Bits.pick bin 0u with
  (* inslwi ra,rs,n,b = rlwimi ra,rs,32-b,b,b+n-1
     insrwi ra,rs,n,b (n>0) = rlwimi ra,rs,32-(b+n),b,(b+n)-1 *)
  | 0b0u -> struct (Op.RLWIMI, FiveOperands(ra, rs, sh, mb, me))
  | _ (* 1 *) -> struct (Op.RLWIMIdot, FiveOperands(ra, rs, sh, mb, me))

let parseRLWINMx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u ->
    let sh = Bits.extract bin 15u 11u |> uint64 |> OprImm
    let mb = Bits.extract bin 10u 6u |> uint64 |> OprImm
    let me = Bits.extract bin 5u 1u |> uint64 |> OprImm
    struct (Op.RLWINM, FiveOperands(ra, rs, sh, mb, me))
  | _ (* 1 *) ->
    let sh = Bits.extract bin 15u 11u |> uint64 |> OprImm
    let mb = Bits.extract bin 10u 6u |> uint64 |> OprImm
    let me = Bits.extract bin 5u 1u |> uint64 |> OprImm
    struct (Op.RLWINMdot, FiveOperands(ra, rs, sh, mb, me))

let parseRLWNMx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u ->
    match Bits.extract bin 10u 1u with
    (* rotlw ra,rs,rb = rlwnm ra,rs,rb,mb,me *)
    | 0x1Fu ->
      struct (Op.ROTLW, ThreeOperands(ra, rs, rb))
    | _ ->
      let mb = Bits.extract bin 10u 6u |> uint64 |> OprImm
      let me = Bits.extract bin 5u 1u |> uint64 |> OprImm
      struct (Op.RLWNM, FiveOperands(ra, rs, rb, mb, me))
  | _ (* 1 *) ->
    let mb = Bits.extract bin 10u 6u |> uint64 |> OprImm
    let me = Bits.extract bin 5u 1u |> uint64 |> OprImm
    struct (Op.RLWNMdot, FiveOperands(ra, rs, rb, mb, me))

let parseORI bin =
  match Bits.extract bin 25u 0u with
  (* nop = ori 0,0,0 *)
  | 0b0u ->
    struct (Op.NOP, NoOperand)
  | _ ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let uimm = Bits.extract bin 15u 0u |> uint64 |> OprImm
    struct (Op.ORI, ThreeOperands(ra, rs, uimm))

let parseORIS bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let uimm = Bits.extract bin 15u 0u |> uint64 |> OprImm
  struct (Op.ORIS, ThreeOperands(ra, rs, uimm))

let parseXORI bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let uimm = Bits.extract bin 15u 0u |> uint64 |> OprImm
  struct (Op.XORI, ThreeOperands(ra, rs, uimm))

let parseXORIS bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let uimm = Bits.extract bin 15u 0u |> uint64 |> OprImm
  struct (Op.XORIS, ThreeOperands(ra, rs, uimm))

let parseANDIdot bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let uimm = Bits.extract bin 15u 0u |> uint64 |> OprImm
  struct (Op.ANDIdot, ThreeOperands(ra, rs, uimm))

let parseANDISdot bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let uimm = Bits.extract bin 15u 0u |> uint64 |> OprImm
  struct (Op.ANDISdot, ThreeOperands(ra, rs, uimm))

let parseCMPandMCRXR bin =
  match Bits.pick bin 10u with
  | 0b0u when Bits.pick bin 22u = 0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    match Bits.pick bin 21u with
    (* cmpw crfd,ra,rb = cmp crfd,0,ra,rb *)
    | 0b0u -> struct (Op.CMPW, ThreeOperands(crfd, ra, rb))
    (* cmpd crfd,ra,rb = cmp crfd,1,ra,rb *)
    | _ (* 1 *) -> struct (Op.CMPD, ThreeOperands(crfd, ra, rb))
  | 0b1u when Bits.extract bin 22u 11u = 0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    struct (Op.MCRXR, OneOperand(crfd))
  | _ ->
    raise ParsingFailureException

let parseTW bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    match Bits.extract bin 25u 21u with
    (* twlgt ra,rb = tw 1,ra,rb *)
    | 1u ->
      struct (Op.TWLGT, TwoOperands(ra, rb))
    (* twllt ra,rb = tw 2,ra,rb *)
    | 2u ->
      struct (Op.TWLLT, TwoOperands(ra, rb))
    (* tweq ra,rb = tw 4,ra,rb *)
    | 4u ->
      struct (Op.TWEQ, TwoOperands(ra, rb))
    (* twlnl ra,rb = tw 5,ra,rb *)
    | 5u ->
      struct (Op.TWLNL, TwoOperands(ra, rb))
    (* twllel ra,rb = tw 6,ra,rb *)
    | 6u ->
      struct (Op.TWLLE, TwoOperands(ra, rb))
    (* twgt ra,rb = tw 8,ra,rb *)
    | 8u ->
      struct (Op.TWGT, TwoOperands(ra, rb))
    (* twge ra,rb = tw 12,ra,rb *)
    | 12u ->
      struct (Op.TWGE, TwoOperands(ra, rb))
    (* twlt ra,rb = tw 16,ra,rb *)
    | 16u ->
      struct (Op.TWLT, TwoOperands(ra, rb))
    (* twle ra,rb = tw 20,ra,rb *)
    | 20u ->
      struct (Op.TWLE, TwoOperands(ra, rb))
    (* twne ra,rb = tw 24,ra,rb *)
    | 24u ->
      struct (Op.TWNE, TwoOperands(ra, rb))
    | 31u when Bits.extract bin 20u 11u = 0u ->
      struct (Op.TRAP, NoOperand)
    | _ ->
      let tO = Bits.extract bin 25u 21u |> uint64 |> OprImm
      struct (Op.TW, ThreeOperands(tO, ra, rb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseSUBFCx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  (* subc rd,ra,rb = subfc rd,rb,ra *)
  | 0b00u -> struct (Op.SUBFC, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.SUBFCdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.SUBFCO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.SUBFCOdot, ThreeOperands(rd, ra, rb))

let parseADDCx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.ADDC, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.ADDCdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.ADDCO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.ADDCOdot, ThreeOperands(rd, ra, rb))

let parseMULHWUx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.MULHWU, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) -> struct (Op.MULHWUdot, ThreeOperands(rd, ra, rb))

let parseMFCR bin =
  match Bits.pick bin 10u with
  | 0b0u when Bits.extract bin 20u 11u = 0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.MFCR, OneOperand(rd))
  (* mfocrf rd,FXM names one CR field with a one-hot mask, which the lifter
     needs to know which field to read. *)
  | 0b0u when Bits.pick bin 20u = 1u && Bits.pick bin 11u = 0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let fxm = Bits.extract bin 19u 12u |> uint64 |> OprImm
    struct (Op.MFOCRF, TwoOperands(rd, fxm))
  | _ ->
    raise ParsingFailureException

/// lwarx, whose last bit is the EH hint rather than a reserved bit: it only
/// tells the processor how the reservation is expected to be used, so both
/// values lift the same way.
let parseLWARX bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.LWARX, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseLSWX bin =
  match Bits.pick bin 10u with
  | 0b1u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.LSWX, ThreeOperands(rd, ra, rb))
  | _ (* 0 *) ->
    raise ParsingFailureException

let parseLWBRX bin =
  match Bits.pick bin 10u with
  | 0b1u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.LWBRX, ThreeOperands(rd, ra, rb))
  | _ (* 0 *) ->
    raise ParsingFailureException

let parseLWZXandLFSX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LWZX, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) ->
    let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LFSX, ThreeOperands(frd, ra, rb))

let parseSLWxandSRWx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.SLW, ThreeOperands(ra, rs, rb))
  | 0b01u -> struct (Op.SLWdot, ThreeOperands(ra, rs, rb))
  | 0b10u -> struct (Op.SRW, ThreeOperands(ra, rs, rb))
  | _ (* 11 *) -> struct (Op.SRWdot, ThreeOperands(ra, rs, rb))

let parseCNTLZWx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  | 0b00u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.CNTLZW, TwoOperands(ra, rs))
  | 0b01u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.CNTLZWdot, TwoOperands(ra, rs))
  | _ (* 1x *) ->
    raise ParsingFailureException

let parseANDx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.AND, ThreeOperands(ra, rs, rb))
  | 0b01u -> struct (Op.ANDdot, ThreeOperands(ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseCMPL bin =
  match Bits.pick bin 10u with
  | 0b0u when Bits.pick bin 22u = 0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    match Bits.pick bin 21u with
    (* cmplw crfd,ra,rb = cmpl crfd,0,ra,rb *)
    | 0b0u -> struct (Op.CMPLW, ThreeOperands(crfd, ra, rb))
    (* cmpld crfd,ra,rb = cmpl crfd,1,ra,rb *)
    | _ (* 1 *) -> struct (Op.CMPLD, ThreeOperands(crfd, ra, rb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseSUBFx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  (* sub rd,rb,ra = subf rd,ra,rb *)
  | 0b00u -> struct (Op.SUBF, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.SUBFdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.SUBFO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.SUBFOdot, ThreeOperands(rd, ra, rb))

let parseDCBSTandTLBSYNC bin =
  match Bits.pick bin 10u with
  | 0b0u when Bits.extract bin 25u 21u = 0u ->
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.DCBST, TwoOperands(ra, rb))
  | 0b1u when Bits.extract bin 25u 11u = 0u ->
    struct (Op.TLBSYNC, NoOperand)
  | _ ->
    raise ParsingFailureException

let parseLWZUXandLFSUX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LWZUX, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) ->
    let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LFSUX, ThreeOperands(frd, ra, rb))

let parseANDCx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.ANDC, ThreeOperands(ra, rs, rb))
  | 0b01u -> struct (Op.ANDCdot, ThreeOperands(ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseMULHWx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.MULHW, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) -> struct (Op.MULHWdot, ThreeOperands(rd, ra, rb))

let parseMFMSRandMFSR bin =
  match Bits.pick bin 10u with
  | 0b0u when Bits.extract bin 20u 11u = 0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.MFMSR, OneOperand(rd))
  | 0b1u when (Bits.concat (Bits.pick bin 20u)
                           (Bits.extract bin 15u 11u)
                           1) = 0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    (* FIXME: SegRegister *)
    let sr = getSegRegister (Bits.extract bin 19u 16u)
    struct (Op.MFSR, TwoOperands(rd, sr))
  | _ ->
    raise ParsingFailureException

let parseLSWI bin =
  match Bits.pick bin 10u with
  | 0b1u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let nb = Bits.extract bin 15u 11u |> uint64 |> OprImm
    struct (Op.LSWI, ThreeOperands(rd, ra, nb))
  | _ (* 0 *) ->
    raise ParsingFailureException

/// The operands of a cache hint or flush: rA, rB and, where it is not zero,
/// the field the instruction keeps where an X form keeps rD.
let private cacheOperands field bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  if field = 0u then TwoOperands(ra, rb)
  else ThreeOperands(ra, rb, OprImm(uint64 field))

/// <summary>
/// dcbf rA, rB, L. The ISA defines L = 0 (dcbf), 1 (dcbfl), 3 (dcbflp), 4
/// (dcbfps) and 6 (dcbstps) and reserves the other values, an invalid form;
/// the two bits above L are reserved.
/// </summary>
let private parseDCBF bin =
  match Bits.extract bin 25u 21u with
  | 0u | 1u | 3u | 4u | 6u as l -> struct (Op.DCBF, cacheOperands l bin)
  | _ -> raise ParsingFailureException

/// <summary>
/// sync L, SC, each valid combination of which has a name of its own (Book
/// II 4.6.3, Figure 5); any other combination, or a reserved bit set, is an
/// invalid form.
/// </summary>
let private parseSYNC bin =
  let reserved =
    Bits.extract bin 25u 24u ||| Bits.extract bin 20u 18u
    ||| Bits.extract bin 15u 11u
  if reserved <> 0u then
    raise ParsingFailureException
  else
    match Bits.extract bin 23u 21u, Bits.extract bin 17u 16u with
    | 0u, 0u -> struct (Op.SYNC, NoOperand)
    | 1u, 0u -> struct (Op.LWSYNC, NoOperand)
    | 2u, 0u -> struct (Op.PTESYNC, NoOperand)
    | 4u, 0u -> struct (Op.PHWSYNC, NoOperand)
    | 5u, 0u -> struct (Op.PLWSYNC, NoOperand)
    | 1u, 1u -> struct (Op.STNCISYNC, NoOperand)
    | 0u, 2u -> struct (Op.STCISYNC, NoOperand)
    | 0u, 3u -> struct (Op.STSYNC, NoOperand)
    | _ -> raise ParsingFailureException

let parseDCBFandSYNC bin =
  if Bits.pick bin 10u = 0u then parseDCBF bin else parseSYNC bin

let parseLBZXandLFDX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LBZX, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) ->
    let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.LFDX, ThreeOperands(frd, ra, rb))

let parseNEGx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.NEG, TwoOperands(rd, ra))
  | 0b01u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.NEGdot, TwoOperands(rd, ra))
  | 0b10u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.NEGO, TwoOperands(rd, ra))
  | 0b11u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.NEGOdot, TwoOperands(rd, ra))
  | _ ->
    raise ParsingFailureException

let parseLBZUXandLFDUX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LBZUX, ThreeOperands(rd, ra, rb))
  | 0b1u ->
    let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LFDUX, ThreeOperands(frd, ra, rb))
  | _ ->
    raise ParsingFailureException

let parseNORx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  (* not rd,rs = nor ra,rs,rs *)
  | 0b00u -> struct (Op.NOR, ThreeOperands(ra, rs, rb))
  | 0b01u -> struct (Op.NORdot, ThreeOperands(ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseSUBFEx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.SUBFE, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.SUBFEdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.SUBFEO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.SUBFEOdot, ThreeOperands(rd, ra, rb))

let parseADDEx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.ADDE, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.ADDEdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.ADDEO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.ADDEOdot, ThreeOperands(rd, ra, rb))

let parseMTCRF bin =
  match Bits.pick bin 10u with
  (* mtcr rs = mtcrf 0xff,rs *)
  | 0b0u when Bits.concat (Bits.pick bin 20u) (Bits.pick bin 11u) 1 = 00u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let crm = Bits.extract bin 19u 12u |> uint64 |> OprImm
    struct (Op.MTCRF, TwoOperands(crm, rs))
  (* mtocrf crm,rs writes the single CR field its one-hot mask names, which is
     what mtcrf with that same mask does. *)
  | 0b0u when Bits.pick bin 20u = 1u && Bits.pick bin 11u = 0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let crm = Bits.extract bin 19u 12u |> uint64 |> OprImm
    struct (Op.MTOCRF, TwoOperands(crm, rs))
  | _ ->
    raise ParsingFailureException

let parseMTMSR bin =
  match Bits.pick bin 10u with
  | 0b0u when Bits.extract bin 20u 11u = 0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.MFMSR, OneOperand rs)
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseMFSRIN bin =
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b10u when Bits.extract bin 20u 16u = 0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.MFSRIN, TwoOperands(rd, rb))
  | _ (* 11, 0x *) ->
    raise ParsingFailureException

let parseSTSWX bin =
  match Bits.pick bin 10u with
  | 0b1u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.STSWX, ThreeOperands(rs, ra, rb))
  | _ (* 0 *) ->
    raise ParsingFailureException

let parseSTWCXdotandSTWBRX bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b01u -> struct (Op.STWCXdot, ThreeOperands(rs, ra, rb))
  | 0b10u -> struct (Op.STWBRX, ThreeOperands(rs, ra, rb))
  | _ (* 00, 11 *) -> raise ParsingFailureException

let parseSTWXandSTFSX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.STWX, ThreeOperands(rs, ra, rb))
  | _ (* 1 *) ->
    let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.STFSX, ThreeOperands(frs, ra, rb))

let parseSTWUXandSTFSUX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.STWUX, ThreeOperands(rs, ra, rb))
  | _ (* 1 *) ->
    let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.STFSUX, ThreeOperands(frs, ra, rb))

let parseSUBFZEx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.SUBFZE, TwoOperands(rd, ra))
  | 0b01u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.SUBFZEdot, TwoOperands(rd, ra))
  | 0b10u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.SUBFZEO, TwoOperands(rd, ra))
  | 0b11u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.SUBFZEOdot, TwoOperands(rd, ra))
  | _ ->
    raise ParsingFailureException

let parseADDZEx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.ADDZE, TwoOperands(rd, ra))
  | 0b01u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.ADDZEdot, TwoOperands(rd, ra))
  | 0b10u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.ADDZEO, TwoOperands(rd, ra))
  | 0b11u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.ADDZEOdot, TwoOperands(rd, ra))
  | _ ->
    raise ParsingFailureException

let parseMTSR bin =
  match Bits.pick bin 10u with
  | 0b0u when (Bits.concat (Bits.pick bin 20u)
                           (Bits.extract bin 15u 11u)
                           1) = 0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    (* FIXME: SegRegister *)
    let sr = getSegRegister (Bits.extract bin 19u 16u)
    struct (Op.MTSR, TwoOperands(sr, rs))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseSTSWI bin =
  match Bits.pick bin 10u with
  | 0b1u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let nb = Bits.extract bin 15u 11u |> uint64 |> OprImm
    struct (Op.STSWI, ThreeOperands(rs, ra, nb))
  | _ (* 0 *) ->
    raise ParsingFailureException

let parseSTBXandSTFDX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b00u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.STBX, ThreeOperands(rs, ra, rb))
  | 0b10u ->
    let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.STFDX, ThreeOperands(frs, ra, rb))
  | _ (* 01, 11 *) ->
    raise ParsingFailureException

let parseSUBFMEx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.SUBFME, TwoOperands(rd, ra))
  | 0b01u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.SUBFMEdot, TwoOperands(rd, ra))
  | 0b10u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.SUBFMEO, TwoOperands(rd, ra))
  | 0b11u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.SUBFMEOdot, TwoOperands(rd, ra))
  | _ ->
    raise ParsingFailureException

let parseADDMEx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.ADDME, TwoOperands(rd, ra))
  | 0b01u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.ADDMEdot, TwoOperands(rd, ra))
  | 0b10u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.ADDMEO, TwoOperands(rd, ra))
  | 0b11u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.ADDMEOdot, TwoOperands(rd, ra))
  | _ ->
    raise ParsingFailureException

let parseMULLWx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.MULLW, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.MULLWdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.MULLWO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.MULLWOdot, ThreeOperands(rd, ra, rb))

let parseMTSRIN bin =
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b10u when Bits.extract bin 20u 16u = 0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.MTSRIN, TwoOperands(rs, rb))
  | _ (* 11, 0x *) ->
    raise ParsingFailureException

/// dcbtst rA, rB, TH, whose TH hint is an optional third operand, and dcba.
let parseDCBTSTandDCBA bin =
  let th = Bits.extract bin 25u 21u
  match Bits.pick bin 10u with
  | 0b0u -> struct (Op.DCBTST, cacheOperands th bin)
  | 0b1u when th = 0u -> struct (Op.DCBA, cacheOperands 0u bin)
  | _ -> raise ParsingFailureException

let parseSTBUXandSTFDUX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b00u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.STBUX, ThreeOperands(rs, ra, rb))
  | 0b10u ->
    let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.STFDUX, ThreeOperands(frs, ra, rb))
  | _ (* 01, 11 *) ->
    raise ParsingFailureException

let parseADDx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.ADD, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.ADDdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.ADDO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.ADDOdot, ThreeOperands(rd, ra, rb))

/// dcbt rA, rB, TH, whose TH hint is an optional third operand, and lhbrx.
let parseDCBTandLHBRX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u ->
    struct (Op.DCBT, cacheOperands (Bits.extract bin 25u 21u) bin)
  | _ ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LHBRX, ThreeOperands(rd, ra, rb))

let parseLHZX bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.LHZX, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseSRAWx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 1:RC *) with
  | 0b10u -> struct (Op.SRAW, ThreeOperands(ra, rs, rb))
  | 0b11u -> struct (Op.SRAWdot, ThreeOperands(ra, rs, rb))
  | _ (* 0x *) -> raise ParsingFailureException

let parseEQVx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:Rc *) with
  | 0b00u -> struct (Op.EQV, ThreeOperands(ra, rs, rb))
  | 0b01u -> struct (Op.EQVdot, ThreeOperands(ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseTLBIE bin =
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b00u ->
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.TLBIE, OneOperand rb)
  | _ (* 01, 1x *) ->
    raise ParsingFailureException

let parseECIWX bin =
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b00u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.ECIWX, ThreeOperands(rd, ra, rb))
  | _ (* 01, 1x *) ->
    raise ParsingFailureException

let parseLHZUX bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.LHZUX, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseSRAWIx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let sh = Bits.extract bin 15u 11u |> uint64 |> OprImm
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.SRAWI, ThreeOperands(ra, rs, sh))
  | _ (* 1 *) -> struct (Op.SRAWIdot, ThreeOperands(ra, rs, sh))

let parseXORx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.XOR, ThreeOperands(ra, rs, rb))
  | 0b01u -> struct (Op.XORdot, ThreeOperands(ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseMFSPR bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    match Bits.concat (Bits.extract bin 15u 11u)
                      (Bits.extract bin 20u 16u)
                      5 with
    (* mfxer rd = mfspr rd,1 *)
    | 1u ->
      struct (Op.MFXER, OneOperand rd)
    (* mflr rd = mfspr rd,8 *)
    | 8u ->
      struct (Op.MFLR, OneOperand rd)
    (* mfctr rd = mfspr rd,9 *)
    | 9u ->
      struct (Op.MFCTR, OneOperand rd)
    (* On a 64-bit part the time base is read through mfspr, not mftb: SPR 268
       is the whole 64-bit counter and 269 its upper half. *)
    | 268u ->
      struct (Op.MFTB, TwoOperands(rd, OprImm 268UL))
    | 269u ->
      struct (Op.MFTBU, OneOperand rd)
    (* mfvrsave rd = mfspr rd,256 *)
    | 256u ->
      struct (Op.MFSPR, TwoOperands(rd, OprImm 256UL))
    | 18u | 19u | 22u | 25u | 26u | 27u | 272u | 273u | 274u | 275u | 282u
    | 287u | 528u | 529u | 530u | 531u | 532u | 533u | 534u | 535u | 536u
    | 537u | 538u | 539u | 540u | 541u | 542u | 543u | 1013u
    | 800u | 801u | 802u | 803u | 804u | 805u | 806u | 815u
    | 3u | 13u | 136u | 259u | 808u | 809u | 810u | 811u | 896u | 898u ->
      let spr =
        getSPRegister (Bits.concat (Bits.extract bin 15u 11u)
                                   (Bits.extract bin 20u 16u)
                                   5)
      struct (Op.MFSPR, TwoOperands(rd, spr))
    | _ ->
      raise ParsingFailureException
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseEIEIO bin =
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b10u when Bits.extract bin 25u 11u = 0u -> struct (Op.EIEIO, NoOperand)
  | _ (* 11, 0x *) -> raise ParsingFailureException

let parseLHAXandLFIWAX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LHAX, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) ->
    let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LFIWAX, ThreeOperands(frd, ra, rb))

let parseTLBIA bin =
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b00u -> struct (Op.TLBIA, NoOperand)
  | _ (* 01, 1x *) -> raise ParsingFailureException

let parseMFTB bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    (* FIXME: TBRRegister *)
    let tbr =
      getTBRRegister (Bits.concat (Bits.extract bin 15u 11u)
                                  (Bits.extract bin 20u 16u)
                                  5)
    match Bits.concat (Bits.extract bin 15u 11u)
                      (Bits.extract bin 20u 16u)
                      5 with
    (* mftbu rd = mftb rd,269 *)
    | 0x10du -> struct (Op.MFTBU, OneOperand rd)
    (* mftb rd = mftb rd,268 *)
    | _ -> struct (Op.MFTB, TwoOperands(rd, tbr))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseLHAUXandLFIWZX bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u ->
    let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LHAUX, ThreeOperands(rd, ra, rb))
  | _ (* 1 *) ->
    let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.LFIWZX, ThreeOperands(frd, ra, rb))

let parseSTHBRX bin =
  match Bits.pick bin 10u with
  | 0b1u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.STHBRX, ThreeOperands(rs, ra, rb))
  | _ (* 0 *) ->
    raise ParsingFailureException

let parseSTHX bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.STHX, ThreeOperands(rs, ra, rb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseEXTSHx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 1:Rc *) with
  | 0b10u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.EXTSH, TwoOperands(ra, rs))
  | 0b11u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.EXTSHdot, TwoOperands(ra, rs))
  | _ (* 0x *) ->
    raise ParsingFailureException

let parseORCx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.ORC, ThreeOperands(ra, rs, rb))
  | 0b01u -> struct (Op.ORCdot, ThreeOperands(ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseECOWX bin =
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 with
  | 0b00u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.ECOWX, ThreeOperands(rs, ra, rb))
  | _ (* 01, 1x *) ->
    raise ParsingFailureException

let parseSTHUX bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.STHUX, ThreeOperands(rs, ra, rb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseEXTSBx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 1:Rc *) with
  | 0b10u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.EXTSB, TwoOperands(ra, rs))
  | 0b11u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.EXTSBdot, TwoOperands(ra, rs))
  | _ (* 0x *) ->
    raise ParsingFailureException

let parseORx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  (* mr ra,rs = or ra,rs,rs *)
  | 0b00u ->
    if Bits.extract bin 25u 21u = Bits.extract bin 15u 11u then
      struct (Op.MR, TwoOperands(ra, rs))
    else
      let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
      struct (Op.OR, ThreeOperands(ra, rs, rb))
  | 0b01u ->
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.ORdot, ThreeOperands(ra, rs, rb))
  | _ (* 1x *) ->
    raise ParsingFailureException

let parseDIVWUx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.DIVWU, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.DIVWUdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.DIVWUO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.DIVWUOdot, ThreeOperands(rd, ra, rb))

let parseMTSPR bin =
  match Bits.pick bin 10u with
  | 0b0u ->
    let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
    match Bits.concat (Bits.extract bin 15u 11u)
                      (Bits.extract bin 20u 16u)
                      5 with
    (* mtxer rd = mtspr rd,1 *)
    | 0x1u ->
      struct (Op.MTXER, OneOperand rs)
    (* mtlr rd = mtspr rd,8 *)
    | 0x8u ->
      struct (Op.MTLR, OneOperand rs)
    (* mtctr rd = mtspr rd,9 *)
    | 0x9u ->
      struct (Op.MTCTR, OneOperand rs)
    | _ ->
      (* FIXME: SPRegister *)
      let spr =
        getSPRegister (Bits.concat (Bits.extract bin 15u 11u)
                                   (Bits.extract bin 20u 16u)
                                   5)
      struct (Op.MTSPR, TwoOperands(spr, rs))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseDCBIandICBI bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 10u with
  | 0b0u when Bits.extract bin 25u 21u = 0u ->
    struct (Op.DCBI, TwoOperands(ra, rb))
  | 0b1u when Bits.extract bin 25u 21u = 0u ->
    struct (Op.ICBI, TwoOperands(ra, rb))
  | _ ->
    raise ParsingFailureException

let parseSTFIWX bin =
  match Bits.pick bin 10u with
  | 0b1u ->
    let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.STFIWX, ThreeOperands(frs, ra, rb))
  | _ (* 0 *) ->
    raise ParsingFailureException

let parseNANDx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* 0:RC *) with
  | 0b00u -> struct (Op.NAND, ThreeOperands(ra, rs, rb))
  | 0b01u -> struct (Op.NANDdot, ThreeOperands(ra, rs, rb))
  | _ (* 1x *) -> raise ParsingFailureException

let parseDIVWx bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 (* OE:RC *) with
  | 0b00u -> struct (Op.DIVW, ThreeOperands(rd, ra, rb))
  | 0b01u -> struct (Op.DIVWdot, ThreeOperands(rd, ra, rb))
  | 0b10u -> struct (Op.DIVWO, ThreeOperands(rd, ra, rb))
  | _ (* 11 *) -> struct (Op.DIVWOdot, ThreeOperands(rd, ra, rb))

let parseDCBZ bin =
  match Bits.pick bin 10u with
  | 0b1u when Bits.extract bin 25u 21u = 0u ->
    let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
    let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.DCBZ, TwoOperands(ra, rb))
  | _ (* 0 *) ->
    raise ParsingFailureException

(* The 64-bit forms all live in the same primary opcodes as their 32-bit
   siblings; only the extended opcode tells them apart. Because the word forms
   below are dispatched on nine of the extended opcode's ten bits, the 64-bit
   ones are picked out first (parse1F) on the full ten. *)
/// The three registers of an X-form "rD, rA, rB", in that order.
let private xFormRegs bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  struct (rd, ra, rb)

/// An X-form load or store indexed, whose operands are "rD, rA, rB".
let private parseXFormIndexed op bin =
  let struct (rd, ra, rb) = xFormRegs bin
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  else struct (op, ThreeOperands(rd, ra, rb))

/// A load-and-reserve indexed, whose last bit is the EH hint rather than a
/// reserved bit: it only says how the reservation is expected to be used, so
/// both values lift the same way.
let private parseReserveIndexed op bin =
  let struct (rd, ra, rb) = xFormRegs bin
  struct (op, ThreeOperands(rd, ra, rb))

/// A store-conditional indexed, whose record bit is not optional -- the store
/// always reports in CR0 whether the reservation still held.
let private parseStoreConditional op bin =
  let struct (rs, ra, rb) = xFormRegs bin
  if Bits.pick bin 0u <> 1u then raise ParsingFailureException
  else struct (op, ThreeOperands(rs, ra, rb))

/// An XO-form "rD, rA, rB" whose OE:Rc pair names four opcodes, given in the
/// order plain, dot, overflow, overflow-dot.
let private parseXOForm (ops: Opcode[]) bin =
  let struct (rd, ra, rb) = xFormRegs bin
  let idx = Bits.concat (Bits.pick bin 10u) (Bits.pick bin 0u) 1 |> int
  struct (ops[idx], ThreeOperands(rd, ra, rb))

/// An X-form "rD, rA, rB" whose Rc bit names two opcodes.
let private parseXFormArith op opDot bin =
  let struct (rd, ra, rb) = xFormRegs bin
  if Bits.pick bin 0u = 0u then struct (op, ThreeOperands(rd, ra, rb))
  else struct (opDot, ThreeOperands(rd, ra, rb))

/// An X-form "rA, rS" with no third register, whose Rc bit names two opcodes.
let private parseXFormUnary op opDot bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  if Bits.extract bin 15u 11u <> 0u then raise ParsingFailureException
  elif Bits.pick bin 0u = 0u then struct (op, TwoOperands(ra, rs))
  else struct (opDot, TwoOperands(ra, rs))

/// An X-form "rA, rS" with neither a third register nor an Rc bit.
let private parseXFormCount op bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  if Bits.extract bin 15u 11u <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    struct (op, TwoOperands(ra, rs))

/// An X-form "rA, rS, rB" whose Rc bit names two opcodes.
let private parseXFormLogical op opDot bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.pick bin 0u = 0u then struct (op, ThreeOperands(ra, rs, rb))
  else struct (opDot, ThreeOperands(ra, rs, rb))

/// An X-form "rA, rS, rB" with no Rc bit.
let private parseXFormPerm op bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  else struct (op, ThreeOperands(ra, rs, rb))

/// sradi/sradi., whose shift amount spans the extended-opcode field: the low
/// five bits sit where an X-form rB would, and the sixth is bit 1.
let private parseSRADIx bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let sh = (Bits.pick bin 1u <<< 5) ||| Bits.extract bin 15u 11u
  let sh = sh |> uint64 |> OprImm
  if Bits.pick bin 0u = 0u then struct (Op.SRADI, ThreeOperands(ra, rs, sh))
  else struct (Op.SRADIdot, ThreeOperands(ra, rs, sh))

/// td, whose TO field selects the comparison the same way tw's does; the
/// generic three-operand form carries TO to the lifter.
let private parseTD bin =
  let struct (_, ra, rb) = xFormRegs bin
  let tO = Bits.extract bin 25u 21u |> uint64 |> OprImm
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  else struct (Op.TD, ThreeOperands(tO, ra, rb))

/// isel rD, rA, rB, crb: the condition bit sits where an X-form keeps the
/// extended opcode's high bits, so the whole "bits 26-30 = 15" space is isel.
let private parseISEL bin =
  let struct (rd, ra, rb) = xFormRegs bin
  let crb = Bits.extract bin 10u 6u |> OprBI
  struct (Op.ISEL, FourOperands(rd, ra, rb, crb))

/// mtvsrdd, which fills both halves of a vector-scalar register from two
/// general ones.
let private parseMTVSRDD bin =
  let xt = (Bits.pick bin 0u <<< 5) ||| Bits.extract bin 25u 21u
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  struct (Op.MTVSRDD, ThreeOperands(getVsxRegister xt |> OprReg, ra, rb))

/// mfvsrld, which reads a vector-scalar register's low doubleword.
let private parseMFVSRLD bin =
  let xs = (Bits.pick bin 0u <<< 5) ||| Bits.extract bin 25u 21u
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  struct (Op.MFVSRLD, TwoOperands(getVsxRegister xs |> OprReg, ra))

/// A VSX direct move between a vector-scalar register and a general one. The
/// operand names the VSX register's high doubleword, which is a floating-point
/// register for VSR0-31 and a vector register for VSR32-63.
let private parseVsrMove op bin =
  let n = (Bits.pick bin 0u <<< 5) ||| Bits.extract bin 25u 21u
  let xs = getVsxRegister n |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  struct (op, TwoOperands(xs, ra))

(* The vector forms. A vector operand names a register by its high half; the
   lifter reaches its low half from there. A VSX operand's register number is
   six bits: five in the usual field plus a low-order bit at the very end of the
   instruction, which is why the forms below do not treat that bit as reserved
   the way an integer X-form does. *)
/// A VMX load or store indexed: "vD, rA, rB" in primary opcode 31.
let private parseVmxIndexed op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  else struct (op, ThreeOperands(vd, ra, rb))

/// A VSX load or store indexed: "xT, rA, rB", the register number's high bit
/// being the instruction's last bit.
let private parseVsxIndexed op bin =
  let n = (Bits.pick bin 0u <<< 5) ||| Bits.extract bin 25u 21u
  let xt = getVsxRegister n |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  struct (op, ThreeOperands(xt, ra, rb))

/// A VX-form "vD, vA, vB".
let private parseVX op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let va = getVecRegister (Bits.extract bin 20u 16u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  struct (op, ThreeOperands(vd, va, vb))

/// A VX-form "vD, vB" whose middle field is unused.
let private parseVX2 op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.extract bin 20u 16u <> 0u then raise ParsingFailureException
  else struct (op, TwoOperands(vd, vb))

/// A VX-form "vD, SIM" carrying a five-bit signed immediate to splat.
let private parseVXImm op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let sim = Bits.extract bin 20u 16u |> uint64 |> Bits.signExtend 5 64 |> uint64
  struct (op, TwoOperands(vd, OprImm sim))

/// A VX-form "vD, vB, UIM" whose immediate picks an element to splat.
let private parseVXUimm op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let uim = Bits.extract bin 20u 16u |> uint64 |> OprImm
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  struct (op, ThreeOperands(vd, vb, uim))

/// A VX-form naming just one vector register, for mfvscr and mtvscr.
let private parseVXOne op bin =
  let v = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  struct (op, OneOperand v)

/// A VX-form with a single vB (mtvscr keeps its source in the vB field).
let private parseVXOneB op bin =
  let v = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  struct (op, OneOperand v)

/// A VA-form "vD, vA, vB, vC".
let private parseVA op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let va = getVecRegister (Bits.extract bin 20u 16u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  let vc = getVecRegister (Bits.extract bin 10u 6u) |> OprReg
  struct (op, FourOperands(vd, va, vb, vc))

/// vsldoi, a VA-form whose fourth operand is the shift its rC field holds.
let private parseVSLDOI bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let va = getVecRegister (Bits.extract bin 20u 16u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  let sh = Bits.extract bin 9u 6u |> uint64 |> OprImm
  struct (Op.VSLDOI, FourOperands(vd, va, vb, sh))

/// A VC-form compare, whose Rc bit chooses between the two record forms.
let private parseVC op opDot bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let va = getVecRegister (Bits.extract bin 20u 16u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  let op = if Bits.pick bin 10u = 0u then op else opDot
  struct (op, ThreeOperands(vd, va, vb))

/// An XX3-form "xT, xA, xB", each register number extended by one of the three
/// bits at the end of the instruction.
let private parseXX3 op bin =
  let xt = (Bits.pick bin 0u <<< 5) ||| Bits.extract bin 25u 21u
  let xa = (Bits.pick bin 2u <<< 5) ||| Bits.extract bin 20u 16u
  let xb = (Bits.pick bin 1u <<< 5) ||| Bits.extract bin 15u 11u
  struct (op, ThreeOperands(getVsxRegister xt |> OprReg,
                            getVsxRegister xa |> OprReg,
                            getVsxRegister xb |> OprReg))

/// vcmpsq/vcmpuq, which compare into the CR field BF; the two bits below BF
/// are reserved.
let private parseVXCompareToCR op bin =
  let bf = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
  let va = getVecRegister (Bits.extract bin 20u 16u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.extract bin 22u 21u <> 0u then raise ParsingFailureException
  else struct (op, ThreeOperands(bf, va, vb))

/// A VX-form "vD, vA" whose vB field is unused (vsbox).
let private parseVXA op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let va = getVecRegister (Bits.extract bin 20u 16u) |> OprReg
  if Bits.extract bin 15u 11u <> 0u then raise ParsingFailureException
  else struct (op, TwoOperands(vd, va))

/// vshasigmaw/vshasigmad: "vD, vA, ST, SIX", ST and SIX filling the vB field.
let private parseVXSigma op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let va = getVecRegister (Bits.extract bin 20u 16u) |> OprReg
  let st = Bits.pick bin 15u |> uint64 |> OprImm
  let six = Bits.extract bin 14u 11u |> uint64 |> OprImm
  struct (op, FourOperands(vd, va, st, six))

/// A decimal add or subtract, "vD, vA, vB, PS", the preferred-sign bit PS
/// sitting just above the nine-bit extended opcode.
let private parseVXDecimal op bin =
  let struct (_, oprs) = parseVX op bin
  let ps = Bits.pick bin 9u |> uint64 |> OprImm
  match oprs with
  | ThreeOperands(vd, va, vb) -> struct (op, FourOperands(vd, va, vb, ps))
  | _ -> raise ParsingFailureException

/// A VX-form "vD, vB" whose vA field holds a further extended opcode.
let private parseVXSubB op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  struct (op, TwoOperands(vd, vb))

/// A VX-form "rD, vB" whose vA field holds a further extended opcode.
let private parseVXGprB op bin =
  let rt = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  struct (op, TwoOperands(rt, vb))

/// The forms of extended opcode 1538, told apart by their vA field: the
/// counts, the negations, the parities and the sign extensions of vB.
let private parse04Unary bin =
  match Bits.extract bin 20u 16u with
  | 0u -> parseVXGprB Op.VCLZLSBB bin
  | 1u -> parseVXGprB Op.VCTZLSBB bin
  | 6u -> parseVXSubB Op.VNEGW bin
  | 7u -> parseVXSubB Op.VNEGD bin
  | 8u -> parseVXSubB Op.VPRTYBW bin
  | 9u -> parseVXSubB Op.VPRTYBD bin
  | 10u -> parseVXSubB Op.VPRTYBQ bin
  | 16u -> parseVXSubB Op.VEXTSB2W bin
  | 17u -> parseVXSubB Op.VEXTSH2W bin
  | 24u -> parseVXSubB Op.VEXTSB2D bin
  | 25u -> parseVXSubB Op.VEXTSH2D bin
  | 26u -> parseVXSubB Op.VEXTSW2D bin
  | 27u -> parseVXSubB Op.VEXTSD2Q bin
  | 28u -> parseVXSubB Op.VCTZB bin
  | 29u -> parseVXSubB Op.VCTZH bin
  | 30u -> parseVXSubB Op.VCTZW bin
  | 31u -> parseVXSubB Op.VCTZD bin
  | _ -> raise ParsingFailureException

/// vsldbi/vsrdbi, the VN form "vD, vA, vB, SH": bit 9 tells left from right,
/// bit 10 above it is zero, and the three-bit SH sits below them.
let private parseVN bin =
  let struct (_, oprs) = parseVX Op.VSLDBI bin
  let sh = Bits.extract bin 8u 6u |> uint64 |> OprImm
  let op =
    match Bits.extract bin 10u 9u with
    | 0u -> Op.VSLDBI
    | 1u -> Op.VSRDBI
    | _ -> raise ParsingFailureException
  match oprs with
  | ThreeOperands(vd, va, vb) -> struct (op, FourOperands(vd, va, vb, sh))
  | _ -> raise ParsingFailureException

/// A VX-form "vD, vB, UIM" whose four-bit UIM names a byte, the bit above it
/// reserved.
let private parseVXByteImm op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  let uim = Bits.extract bin 19u 16u |> uint64 |> OprImm
  if Bits.pick bin 20u <> 0u then raise ParsingFailureException
  else struct (op, ThreeOperands(vd, vb, uim))

/// vinsw/vinsd "vD, rB, UIM", the source a general register in the vB field.
let private parseVXGprImm op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  let uim = Bits.extract bin 19u 16u |> uint64 |> OprImm
  if Bits.pick bin 20u <> 0u then raise ParsingFailureException
  else struct (op, ThreeOperands(vd, rb, uim))

/// A VX-form whose three fields are registers of the kinds given, which the
/// extracts and inserts mix: rD, rA, vB; vD, rA, rB; vD, rA, vB; vD, vA, rB.
let private parseVXMixed op d a b bin =
  let reg isVec n = if isVec then getVecRegister n else getRegister n
  let rd = reg d (Bits.extract bin 25u 21u) |> OprReg
  let ra = reg a (Bits.extract bin 20u 16u) |> OprReg
  let rb = reg b (Bits.extract bin 15u 11u) |> OprReg
  struct (op, ThreeOperands(rd, ra, rb))

/// vext*v*x "vD, vA, vB, rC", a VA form whose fourth register is a general one.
let private parseVAIndex op bin =
  let struct (_, oprs) = parseVX op bin
  let rc = getRegister (Bits.extract bin 10u 6u) |> OprReg
  match oprs with
  | ThreeOperands(vd, va, vb) -> struct (op, FourOperands(vd, va, vb, rc))
  | _ -> raise ParsingFailureException

/// A VX-form "vD, rB" whose vA field holds a further extended opcode.
let private parseVXVecGpr op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  struct (op, TwoOperands(vd, rb))

/// vcntmb* "rD, vB, MP", the MP bit being the lowest of the vA field.
let private parseVXCountMask op bin =
  let rt = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  let mp = Bits.pick bin 16u |> uint64 |> OprImm
  struct (op, ThreeOperands(rt, vb, mp))

/// The forms of extended opcode 1602, told apart by their vA field: the
/// expands, extracts and moves of a mask, and the counts of its bits, whose
/// result is a doubleword.
let private parse04Mask bitLen bin =
  match Bits.extract bin 20u 16u with
  | 0u -> parseVXSubB Op.VEXPANDBM bin
  | 1u -> parseVXSubB Op.VEXPANDHM bin
  | 2u -> parseVXSubB Op.VEXPANDWM bin
  | 3u -> parseVXSubB Op.VEXPANDDM bin
  | 4u -> parseVXSubB Op.VEXPANDQM bin
  | 8u -> parseVXGprB Op.VEXTRACTBM bin
  | 9u -> parseVXGprB Op.VEXTRACTHM bin
  | 10u -> parseVXGprB Op.VEXTRACTWM bin
  | 11u -> parseVXGprB Op.VEXTRACTDM bin
  | 12u -> parseVXGprB Op.VEXTRACTQM bin
  | 16u -> parseVXVecGpr Op.MTVSRBM bin
  | 17u -> parseVXVecGpr Op.MTVSRHM bin
  | 18u -> parseVXVecGpr Op.MTVSRWM bin
  | 19u -> parseVXVecGpr Op.MTVSRDM bin
  | 20u -> parseVXVecGpr Op.MTVSRQM bin
  | 24u | 25u when bitLen = 64 -> parseVXCountMask Op.VCNTMBB bin
  | 26u | 27u when bitLen = 64 -> parseVXCountMask Op.VCNTMBH bin
  | 28u | 29u when bitLen = 64 -> parseVXCountMask Op.VCNTMBW bin
  | 30u | 31u when bitLen = 64 -> parseVXCountMask Op.VCNTMBD bin
  | _ -> raise ParsingFailureException

/// mtvsrbmi "vD, bm", a DX form whose sixteen-bit bm is split in three: ten
/// bits where vB and the field below it sit, five where vA does, and the
/// last at the very end.
let private parseMTVSRBMI bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let b0 = Bits.extract bin 15u 6u
  let b1 = Bits.extract bin 20u 16u
  let bm = (b0 <<< 6) ||| (b1 <<< 1) ||| Bits.pick bin 0u
  struct (Op.MTVSRBMI, TwoOperands(vd, bm |> uint64 |> OprImm))

/// The string isolates, VX forms with a record bit whose vA field picks
/// bytes or halfwords and the end they start from.
let private parse04String bin =
  let struct (_, oprs) = parseVXSubB Op.VSTRIBL bin
  let record = Bits.pick bin 10u = 1u
  let op =
    match Bits.extract bin 20u 16u, record with
    | 0u, false -> Op.VSTRIBL
    | 0u, true -> Op.VSTRIBLdot
    | 1u, false -> Op.VSTRIBR
    | 1u, true -> Op.VSTRIBRdot
    | 2u, false -> Op.VSTRIHL
    | 2u, true -> Op.VSTRIHLdot
    | 3u, false -> Op.VSTRIHR
    | 3u, true -> Op.VSTRIHRdot
    | _ -> raise ParsingFailureException
  struct (op, oprs)

/// vgnb "rD, vB, N": N, the stride, in the low three bits of the vA field and
/// the two above it reserved; a stride below 2 is not a valid form.
let private parseVGNB bin =
  let rt = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  let n = Bits.extract bin 18u 16u
  if Bits.extract bin 20u 19u <> 0u || n < 2u then raise ParsingFailureException
  else struct (Op.VGNB, ThreeOperands(rt, vb, n |> uint64 |> OprImm))

/// vmaddfp/vnmsubfp "vD, vA, vC, vB", a VA form written with vC before vB.
let private parseVAFloat op bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let va = getVecRegister (Bits.extract bin 20u 16u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  let vc = getVecRegister (Bits.extract bin 10u 6u) |> OprReg
  struct (op, FourOperands(vd, va, vc, vb))

/// The decimal conversions and bcdsetsgn., told apart by their vA field;
/// PS sits above the nine-bit extended opcode, where the two that take none
/// leave it clear.
let private parse04Decimal bin =
  let vd = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let vb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
  let ps = Bits.pick bin 9u
  let withPS op = struct (op, ThreeOperands(vd, vb, ps |> uint64 |> OprImm))
  match Bits.extract bin 20u 16u with
  | 0u when ps = 0u -> struct (Op.BCDCTSQdot, TwoOperands(vd, vb))
  | 2u -> withPS Op.BCDCFSQdot
  | 4u -> withPS Op.BCDCTZdot
  | 5u when ps = 0u -> struct (Op.BCDCTNdot, TwoOperands(vd, vb))
  | 6u -> withPS Op.BCDCFZdot
  | 7u -> withPS Op.BCDCFNdot
  | 31u -> withPS Op.BCDSETSGNdot
  | _ -> raise ParsingFailureException

/// maddhd/maddhdu/maddld, the VA form whose four registers are general ones.
let private parseVAGpr op bin =
  let rt = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  let rc = getRegister (Bits.extract bin 10u 6u) |> OprReg
  struct (op, FourOperands(rt, ra, rb, rc))

/// The forms of primary opcode 4 named by their low six bits alone: the VA
/// forms, whose fourth operand fills the field above.
let private parse04Wide bitLen bin =
  match Bits.extract bin 5u 0u with
  | 20u | 21u -> parseMTVSRBMI bin
  | 22u -> parseVN bin
  | 23u -> parseVA Op.VMSUMCUD bin
  | 24u -> parseVAIndex Op.VEXTDUBVLX bin
  | 25u -> parseVAIndex Op.VEXTDUBVRX bin
  | 26u -> parseVAIndex Op.VEXTDUHVLX bin
  | 27u -> parseVAIndex Op.VEXTDUHVRX bin
  | 28u -> parseVAIndex Op.VEXTDUWVLX bin
  | 29u -> parseVAIndex Op.VEXTDUWVRX bin
  | 30u -> parseVAIndex Op.VEXTDDVLX bin
  | 31u -> parseVAIndex Op.VEXTDDVRX bin
  | 32u -> parseVA Op.VMHADDSHS bin
  | 33u -> parseVA Op.VMHRADDSHS bin
  | 34u -> parseVA Op.VMLADDUHM bin
  | 35u -> parseVA Op.VMSUMUDM bin
  | 36u -> parseVA Op.VMSUMUBM bin
  | 37u -> parseVA Op.VMSUMMBM bin
  | 38u -> parseVA Op.VMSUMUHM bin
  | 39u -> parseVA Op.VMSUMUHS bin
  | 40u -> parseVA Op.VMSUMSHM bin
  | 41u -> parseVA Op.VMSUMSHS bin
  | 45u -> parseVA Op.VPERMXOR bin
  | 46u -> parseVAFloat Op.VMADDFP bin
  | 47u -> parseVAFloat Op.VNMSUBFP bin
  | 48u when bitLen = 64 -> parseVAGpr Op.MADDHD bin
  | 49u when bitLen = 64 -> parseVAGpr Op.MADDHDU bin
  | 51u when bitLen = 64 -> parseVAGpr Op.MADDLD bin
  | 59u -> parseVA Op.VPERMR bin
  | 60u -> parseVA Op.VADDEUQM bin
  | 61u -> parseVA Op.VADDECUQ bin
  | 62u -> parseVA Op.VSUBEUQM bin
  | 63u -> parseVA Op.VSUBECUQ bin
  | _ -> raise ParsingFailureException

/// The vector instructions in primary opcode 4, whose extended opcode is a
/// plain eleven-bit field except in the VA and VC forms.
let private parse04 bitLen bin =
  match Bits.extract bin 5u 0u with
  | 42u ->
    parseVA Op.VSEL bin
  | 43u ->
    parseVA Op.VPERM bin
  | 44u ->
    parseVSLDOI bin
  | xo when xo >= 20u ->
    parse04Wide bitLen bin
  | _ ->
    match Bits.extract bin 9u 0u with
    | 6u ->
      parseVC Op.VCMPEQUB Op.VCMPEQUBdot bin
    | 70u ->
      parseVC Op.VCMPEQUH Op.VCMPEQUHdot bin
    | 134u ->
      parseVC Op.VCMPEQUW Op.VCMPEQUWdot bin
    | 199u ->
      parseVC Op.VCMPEQUD Op.VCMPEQUDdot bin
    | 518u ->
      parseVC Op.VCMPGTUB Op.VCMPGTUBdot bin
    | 582u ->
      parseVC Op.VCMPGTUH Op.VCMPGTUHdot bin
    | 646u ->
      parseVC Op.VCMPGTUW Op.VCMPGTUWdot bin
    | 711u ->
      parseVC Op.VCMPGTUD Op.VCMPGTUDdot bin
    | 774u ->
      parseVC Op.VCMPGTSB Op.VCMPGTSBdot bin
    | 838u ->
      parseVC Op.VCMPGTSH Op.VCMPGTSHdot bin
    | 902u ->
      parseVC Op.VCMPGTSW Op.VCMPGTSWdot bin
    | 967u ->
      parseVC Op.VCMPGTSD Op.VCMPGTSDdot bin
    | 198u ->
      parseVC Op.VCMPEQFP Op.VCMPEQFPdot bin
    | 454u ->
      parseVC Op.VCMPGEFP Op.VCMPGEFPdot bin
    | 710u ->
      parseVC Op.VCMPGTFP Op.VCMPGTFPdot bin
    | 966u ->
      parseVC Op.VCMPBFP Op.VCMPBFPdot bin
    | 7u ->
      parseVC Op.VCMPNEB Op.VCMPNEBdot bin
    | 71u ->
      parseVC Op.VCMPNEH Op.VCMPNEHdot bin
    | 135u ->
      parseVC Op.VCMPNEW Op.VCMPNEWdot bin
    | 263u ->
      parseVC Op.VCMPNEZB Op.VCMPNEZBdot bin
    | 327u ->
      parseVC Op.VCMPNEZH Op.VCMPNEZHdot bin
    | 391u ->
      parseVC Op.VCMPNEZW Op.VCMPNEZWdot bin
    | 455u ->
      parseVC Op.VCMPEQUQ Op.VCMPEQUQdot bin
    | 647u ->
      parseVC Op.VCMPGTUQ Op.VCMPGTUQdot bin
    | 903u ->
      parseVC Op.VCMPGTSQ Op.VCMPGTSQdot bin
    | _ ->
      match Bits.extract bin 10u 0u with
      | 0u -> parseVX Op.VADDUBM bin
      | 2u -> parseVX Op.VMAXUB bin
      | 4u -> parseVX Op.VRLB bin
      | 12u -> parseVX Op.VMRGHB bin
      | 14u -> parseVX Op.VPKUHUM bin
      | 64u -> parseVX Op.VADDUHM bin
      | 66u -> parseVX Op.VMAXUH bin
      | 68u -> parseVX Op.VRLH bin
      | 76u -> parseVX Op.VMRGHH bin
      | 78u -> parseVX Op.VPKUWUM bin
      | 128u -> parseVX Op.VADDUWM bin
      | 130u -> parseVX Op.VMAXUW bin
      | 132u -> parseVX Op.VRLW bin
      | 137u -> parseVX Op.VMULUWM bin
      | 140u -> parseVX Op.VMRGHW bin
      | 192u -> parseVX Op.VADDUDM bin
      | 194u -> parseVX Op.VMAXUD bin
      | 196u -> parseVX Op.VRLD bin
      | 258u -> parseVX Op.VMAXSB bin
      | 260u -> parseVX Op.VSLB bin
      | 268u -> parseVX Op.VMRGLB bin
      | 322u -> parseVX Op.VMAXSH bin
      | 324u -> parseVX Op.VSLH bin
      | 332u -> parseVX Op.VMRGLH bin
      | 386u -> parseVX Op.VMAXSW bin
      | 388u -> parseVX Op.VSLW bin
      | 392u -> parseVX Op.VMULOSW bin
      | 396u -> parseVX Op.VMRGLW bin
      | 450u -> parseVX Op.VMAXSD bin
      | 452u -> parseVX Op.VSL bin
      | 512u -> parseVX Op.VADDUBS bin
      | 514u -> parseVX Op.VMINUB bin
      | 516u -> parseVX Op.VSRB bin
      | 524u -> parseVXUimm Op.VSPLTB bin
      | 526u -> parseVX2 Op.VUPKHSB bin
      | 578u -> parseVX Op.VMINUH bin
      | 580u -> parseVX Op.VSRH bin
      | 588u -> parseVXUimm Op.VSPLTH bin
      | 590u -> parseVX2 Op.VUPKHSH bin
      | 642u -> parseVX Op.VMINUW bin
      | 644u -> parseVX Op.VSRW bin
      | 652u -> parseVXUimm Op.VSPLTW bin
      | 654u -> parseVX2 Op.VUPKLSB bin
      | 706u -> parseVX Op.VMINUD bin
      | 708u -> parseVX Op.VSR bin
      | 718u -> parseVX2 Op.VUPKLSH bin
      | 770u -> parseVX Op.VMINSB bin
      | 772u -> parseVX Op.VSRAB bin
      | 780u -> parseVXImm Op.VSPLTISB bin
      | 834u -> parseVX Op.VMINSH bin
      | 836u -> parseVX Op.VSRAH bin
      | 844u -> parseVXImm Op.VSPLTISH bin
      | 898u -> parseVX Op.VMINSW bin
      | 900u -> parseVX Op.VSRAW bin
      | 904u -> parseVX Op.VMULESW bin
      | 908u -> parseVXImm Op.VSPLTISW bin
      | 962u -> parseVX Op.VMINSD bin
      | 964u -> parseVX Op.VSRAD bin
      | 1024u -> parseVX Op.VSUBUBM bin
      | 1028u -> parseVX Op.VAND bin
      | 1036u -> parseVX Op.VSLO bin
      | 1088u -> parseVX Op.VSUBUHM bin
      | 1092u -> parseVX Op.VANDC bin
      | 1100u -> parseVX Op.VSRO bin
      | 1152u -> parseVX Op.VSUBUWM bin
      | 1156u -> parseVX Op.VOR bin
      | 1216u -> parseVX Op.VSUBUDM bin
      | 1220u -> parseVX Op.VXOR bin
      | 1284u -> parseVX Op.VNOR bin
      | 1292u -> parseVX2 Op.VGBBD bin
      | 1348u -> parseVX Op.VORC bin
      | 1356u -> parseVX Op.VBPERMQ bin
      | 1412u -> parseVX Op.VNAND bin
      | 1476u -> parseVX Op.VSLD bin
      | 1536u -> parseVX Op.VSUBUBS bin
      | 1540u -> parseVXOne Op.MFVSCR bin
      | 1604u -> parseVXOneB Op.MTVSCR bin
      | 1668u -> parseVX Op.VEQV bin
      | 1676u -> parseVX Op.VMRGOW bin
      | 1732u -> parseVX Op.VSRD bin
      | 1794u -> parseVX2 Op.VCLZB bin
      | 1795u -> parseVX2 Op.VPOPCNTB bin
      | 1858u -> parseVX2 Op.VCLZH bin
      | 1859u -> parseVX2 Op.VPOPCNTH bin
      | 1922u -> parseVX2 Op.VCLZW bin
      | 1923u -> parseVX2 Op.VPOPCNTW bin
      | 1932u -> parseVX Op.VMRGEW bin
      | 1614u -> parseVX2 Op.VUPKHSW bin
      | 1742u -> parseVX2 Op.VUPKLSW bin
      | 1986u -> parseVX2 Op.VCLZD bin
      | 1987u -> parseVX2 Op.VPOPCNTD bin
      | 768u -> parseVX Op.VADDSBS bin
      | 832u -> parseVX Op.VADDSHS bin
      | 896u -> parseVX Op.VADDSWS bin
      | 576u -> parseVX Op.VADDUHS bin
      | 640u -> parseVX Op.VADDUWS bin
      | 1792u -> parseVX Op.VSUBSBS bin
      | 1856u -> parseVX Op.VSUBSHS bin
      | 1920u -> parseVX Op.VSUBSWS bin
      | 1600u -> parseVX Op.VSUBUHS bin
      | 1664u -> parseVX Op.VSUBUWS bin
      | 384u -> parseVX Op.VADDCUW bin
      | 1408u -> parseVX Op.VSUBCUW bin
      | 1282u -> parseVX Op.VAVGSB bin
      | 1346u -> parseVX Op.VAVGSH bin
      | 1410u -> parseVX Op.VAVGSW bin
      | 1026u -> parseVX Op.VAVGUB bin
      | 1090u -> parseVX Op.VAVGUH bin
      | 1154u -> parseVX Op.VAVGUW bin
      | 1027u -> parseVX Op.VABSDUB bin
      | 1091u -> parseVX Op.VABSDUH bin
      | 1155u -> parseVX Op.VABSDUW bin
      | 256u -> parseVX Op.VADDUQM bin
      | 320u -> parseVX Op.VADDCUQ bin
      | 1280u -> parseVX Op.VSUBUQM bin
      | 1344u -> parseVX Op.VSUBCUQ bin
      | 321u -> parseVXCompareToCR Op.VCMPSQ bin
      | 257u -> parseVXCompareToCR Op.VCMPUQ bin
      | 648u -> parseVX Op.VMULEUW bin
      | 136u -> parseVX Op.VMULOUW bin
      | 520u -> parseVX Op.VMULEUB bin
      | 8u -> parseVX Op.VMULOUB bin
      | 776u -> parseVX Op.VMULESB bin
      | 264u -> parseVX Op.VMULOSB bin
      | 584u -> parseVX Op.VMULEUH bin
      | 72u -> parseVX Op.VMULOUH bin
      | 840u -> parseVX Op.VMULESH bin
      | 328u -> parseVX Op.VMULOSH bin
      | 712u -> parseVX Op.VMULEUD bin
      | 200u -> parseVX Op.VMULOUD bin
      | 968u -> parseVX Op.VMULESD bin
      | 456u -> parseVX Op.VMULOSD bin
      | 1102u -> parseVX Op.VPKUDUM bin
      | 1486u -> parseVX Op.VPKSDSS bin
      | 1358u -> parseVX Op.VPKSDUS bin
      | 1230u -> parseVX Op.VPKUDUS bin
      | 1409u | 1921u -> parse04Decimal bin
      | 833u -> parseVX Op.BCDCPSGNdot bin
      | 1217u | 1729u -> parseVXDecimal Op.BCDSdot bin
      | 1153u -> parseVX Op.BCDUSdot bin
      | 1473u | 1985u -> parseVXDecimal Op.BCDSRdot bin
      | 1281u | 1793u -> parseVXDecimal Op.BCDTRUNCdot bin
      | 1345u -> parseVX Op.BCDUTRUNCdot bin
      | 513u -> parseVXA Op.VMUL10UQ bin
      | 1u -> parseVXA Op.VMUL10CUQ bin
      | 577u -> parseVX Op.VMUL10EUQ bin
      | 65u -> parseVX Op.VMUL10ECUQ bin
      | 10u -> parseVX Op.VADDFP bin
      | 74u -> parseVX Op.VSUBFP bin
      | 1034u -> parseVX Op.VMAXFP bin
      | 1098u -> parseVX Op.VMINFP bin
      | 266u -> parseVX2 Op.VREFP bin
      | 330u -> parseVX2 Op.VRSQRTEFP bin
      | 394u -> parseVX2 Op.VEXPTEFP bin
      | 458u -> parseVX2 Op.VLOGEFP bin
      | 522u -> parseVX2 Op.VRFIN bin
      | 586u -> parseVX2 Op.VRFIZ bin
      | 650u -> parseVX2 Op.VRFIP bin
      | 714u -> parseVX2 Op.VRFIM bin
      | 778u -> parseVXUimm Op.VCFUX bin
      | 842u -> parseVXUimm Op.VCFSX bin
      | 906u -> parseVXUimm Op.VCTUXS bin
      | 970u -> parseVXUimm Op.VCTSXS bin
      | 1228u when bitLen = 64 -> parseVGNB bin
      | 1484u -> parseVX Op.VBPERMD bin
      | 1357u -> parseVX Op.VCFUGED bin
      | 1485u -> parseVX Op.VPDEPD bin
      | 1421u -> parseVX Op.VPEXTD bin
      | 1924u -> parseVX Op.VCLZDM bin
      | 1988u -> parseVX Op.VCTZDM bin
      | 1602u -> parse04Mask bitLen bin
      | 13u | 1037u -> parse04String bin
      | 525u -> parseVXByteImm Op.VEXTRACTUB bin
      | 589u -> parseVXByteImm Op.VEXTRACTUH bin
      | 653u -> parseVXByteImm Op.VEXTRACTUW bin
      | 717u -> parseVXByteImm Op.VEXTRACTD bin
      | 781u -> parseVXByteImm Op.VINSERTB bin
      | 845u -> parseVXByteImm Op.VINSERTH bin
      | 909u -> parseVXByteImm Op.VINSERTW bin
      | 973u -> parseVXByteImm Op.VINSERTD bin
      | 207u -> parseVXGprImm Op.VINSW bin
      | 463u when bitLen = 64 -> parseVXGprImm Op.VINSD bin
      | 1549u -> parseVXMixed Op.VEXTUBLX false false true bin
      | 1613u -> parseVXMixed Op.VEXTUHLX false false true bin
      | 1677u -> parseVXMixed Op.VEXTUWLX false false true bin
      | 1805u -> parseVXMixed Op.VEXTUBRX false false true bin
      | 1869u -> parseVXMixed Op.VEXTUHRX false false true bin
      | 1933u -> parseVXMixed Op.VEXTUWRX false false true bin
      | 527u -> parseVXMixed Op.VINSBLX true false false bin
      | 591u -> parseVXMixed Op.VINSHLX true false false bin
      | 655u -> parseVXMixed Op.VINSWLX true false false bin
      | 783u -> parseVXMixed Op.VINSBRX true false false bin
      | 847u -> parseVXMixed Op.VINSHRX true false false bin
      | 911u -> parseVXMixed Op.VINSWRX true false false bin
      | 719u when bitLen = 64 -> parseVXMixed Op.VINSDLX true false false bin
      | 975u when bitLen = 64 -> parseVXMixed Op.VINSDRX true false false bin
      | 15u -> parseVXMixed Op.VINSBVLX true false true bin
      | 79u -> parseVXMixed Op.VINSHVLX true false true bin
      | 143u -> parseVXMixed Op.VINSWVLX true false true bin
      | 271u -> parseVXMixed Op.VINSBVRX true false true bin
      | 335u -> parseVXMixed Op.VINSHVRX true false true bin
      | 399u -> parseVXMixed Op.VINSWVRX true false true bin
      | 397u -> parseVXMixed Op.VCLRLB true true false bin
      | 461u -> parseVXMixed Op.VCLRRB true true false bin
      | 1538u -> parse04Unary bin
      | 133u -> parseVX Op.VRLWMI bin
      | 197u -> parseVX Op.VRLDMI bin
      | 69u -> parseVX Op.VRLQMI bin
      | 389u -> parseVX Op.VRLWNM bin
      | 453u -> parseVX Op.VRLDNM bin
      | 325u -> parseVX Op.VRLQNM bin
      | 5u -> parseVX Op.VRLQ bin
      | 261u -> parseVX Op.VSLQ bin
      | 517u -> parseVX Op.VSRQ bin
      | 773u -> parseVX Op.VSRAQ bin
      | 1860u -> parseVX Op.VSLV bin
      | 1796u -> parseVX Op.VSRV bin
      | 905u -> parseVX Op.VMULHSW bin
      | 649u -> parseVX Op.VMULHUW bin
      | 969u -> parseVX Op.VMULHSD bin
      | 713u -> parseVX Op.VMULHUD bin
      | 457u -> parseVX Op.VMULLD bin
      | 395u -> parseVX Op.VDIVSW bin
      | 139u -> parseVX Op.VDIVUW bin
      | 459u -> parseVX Op.VDIVSD bin
      | 203u -> parseVX Op.VDIVUD bin
      | 267u -> parseVX Op.VDIVSQ bin
      | 11u -> parseVX Op.VDIVUQ bin
      | 907u -> parseVX Op.VDIVESW bin
      | 651u -> parseVX Op.VDIVEUW bin
      | 971u -> parseVX Op.VDIVESD bin
      | 715u -> parseVX Op.VDIVEUD bin
      | 779u -> parseVX Op.VDIVESQ bin
      | 523u -> parseVX Op.VDIVEUQ bin
      | 1931u -> parseVX Op.VMODSW bin
      | 1675u -> parseVX Op.VMODUW bin
      | 1995u -> parseVX Op.VMODSD bin
      | 1739u -> parseVX Op.VMODUD bin
      | 1803u -> parseVX Op.VMODSQ bin
      | 1547u -> parseVX Op.VMODUQ bin
      | 1544u -> parseVX Op.VSUM4UBS bin
      | 1800u -> parseVX Op.VSUM4SBS bin
      | 1608u -> parseVX Op.VSUM4SHS bin
      | 1672u -> parseVX Op.VSUM2SWS bin
      | 1928u -> parseVX Op.VSUMSWS bin
      | 142u -> parseVX Op.VPKUHUS bin
      | 206u -> parseVX Op.VPKUWUS bin
      | 398u -> parseVX Op.VPKSHSS bin
      | 462u -> parseVX Op.VPKSWSS bin
      | 270u -> parseVX Op.VPKSHUS bin
      | 334u -> parseVX Op.VPKSWUS bin
      | 782u -> parseVX Op.VPKPX bin
      | 846u -> parseVX2 Op.VUPKHPX bin
      | 974u -> parseVX2 Op.VUPKLPX bin
      | 1288u -> parseVX Op.VCIPHER bin
      | 1289u -> parseVX Op.VCIPHERLAST bin
      | 1352u -> parseVX Op.VNCIPHER bin
      | 1353u -> parseVX Op.VNCIPHERLAST bin
      | 1480u -> parseVXA Op.VSBOX bin
      | 1666u -> parseVXSigma Op.VSHASIGMAW bin
      | 1730u -> parseVXSigma Op.VSHASIGMAD bin
      | 1032u -> parseVX Op.VPMSUMB bin
      | 1096u -> parseVX Op.VPMSUMH bin
      | 1160u -> parseVX Op.VPMSUMW bin
      | 1224u -> parseVX Op.VPMSUMD bin
      | 1025u | 1537u -> parseVXDecimal Op.BCDADDdot bin
      | 1089u | 1601u -> parseVXDecimal Op.BCDSUBdot bin
      | _ -> raise ParsingFailureException

/// xxpermdi, whose two-bit DM field picks one doubleword of each source. Its
/// six-bit extended opcode sits below DM, so the whole instruction shares the
/// eight bits the logical forms use as one field; the logical opcodes are
/// xxpermdi and xxsldwi, whose two-bit DM or SHW field sits inside the eight
/// bits the logical forms use as one extended opcode: bit 10 is clear, bits 9
/// and 8 hold the field, and bits 7 down to 3 identify the instruction. The
/// logical opcodes all have bit 10 set, so the two groups never overlap.
let private parseXXPERMDIx op bin =
  let struct (op, oprs) = parseXX3 op bin
  let dm = Bits.extract bin 9u 8u |> uint64 |> OprImm
  match oprs with
  | ThreeOperands(xt, xa, xb) -> struct (op, FourOperands(xt, xa, xb, dm))
  | _ -> raise ParsingFailureException

/// An XX2-form "xT, xB", whose extended opcode is nine bits wide because only
/// two register-extension bits follow it.
let private parseXX2 op bin =
  let xt = (Bits.pick bin 0u <<< 5) ||| Bits.extract bin 25u 21u
  let xb = (Bits.pick bin 1u <<< 5) ||| Bits.extract bin 15u 11u
  struct (op, TwoOperands(getVsxRegister xt |> OprReg,
                          getVsxRegister xb |> OprReg))

/// xxspltw, an XX2 form whose spare field selects the word to splat.
let private parseXXSPLTW bin =
  let struct (op, oprs) = parseXX2 Op.XXSPLTW bin
  let uim = Bits.extract bin 17u 16u |> uint64 |> OprImm
  match oprs with
  | TwoOperands(xt, xb) -> struct (op, ThreeOperands(xt, xb, uim))
  | _ -> raise ParsingFailureException

/// xxspltib, which carries the byte to splat as an eight-bit immediate. The
/// two bits above that byte are zero; lxvkq shares the extended opcode with
/// them set.
let private parseXXSPLTIB bin =
  let xt = (Bits.pick bin 0u <<< 5) ||| Bits.extract bin 25u 21u
  let imm = Bits.extract bin 18u 11u |> uint64 |> OprImm
  struct (Op.XXSPLTIB, TwoOperands(getVsxRegister xt |> OprReg, imm))

/// An XX3-form scalar compare, which reports in a condition-register field
/// rather than in a vector-scalar register.
let private parseXX3Compare op bin =
  let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
  let xa = (Bits.pick bin 2u <<< 5) ||| Bits.extract bin 20u 16u
  let xb = (Bits.pick bin 1u <<< 5) ||| Bits.extract bin 15u 11u
  struct (op, ThreeOperands(crfd,
                            getVsxRegister xa |> OprReg,
                            getVsxRegister xb |> OprReg))

/// xxsel, the one XX4 form: "xT, xA, xB, xC", the fourth register number
/// extended by the CX bit, which sits above the other three at the end.
let private parseXXSEL bin =
  let xt = (Bits.pick bin 0u <<< 5) ||| Bits.extract bin 25u 21u
  let xa = (Bits.pick bin 2u <<< 5) ||| Bits.extract bin 20u 16u
  let xb = (Bits.pick bin 1u <<< 5) ||| Bits.extract bin 15u 11u
  let xc = (Bits.pick bin 3u <<< 5) ||| Bits.extract bin 10u 6u
  struct (Op.XXSEL, FourOperands(getVsxRegister xt |> OprReg,
                                 getVsxRegister xa |> OprReg,
                                 getVsxRegister xb |> OprReg,
                                 getVsxRegister xc |> OprReg))

/// The XX3 and XX2 forms of primary opcode 60: the logical forms, the ones that
/// shuffle doublewords and words, the scalar double-precision arithmetic, and
/// the vector double-precision arithmetic, compares and conversions a compiler
/// emits for a vectorized loop. The forms ISA 3.0 and 3.1 added share the space
/// and go on to ParsingVSX. An XX3 form's extended opcode is eight bits and an
/// XX2 form's is nine, so the wider ones are matched first. A vector compare's
/// record bit is the top bit of its eight, so the two forms are two cases.
let private parse3CExtended bin =
  match Bits.extract bin 10u 3u with
  | 0u ->
    parseXX3 Op.XSADDSP bin
  | 8u ->
    parseXX3 Op.XSSUBSP bin
  | 16u ->
    parseXX3 Op.XSMULSP bin
  | 24u ->
    parseXX3 Op.XSDIVSP bin
  | 32u ->
    parseXX3 Op.XSADDDP bin
  | 48u ->
    parseXX3 Op.XSMULDP bin
  | 160u ->
    parseXX3 Op.XSMAXDP bin
  | 168u ->
    parseXX3 Op.XSMINDP bin
  | 35u ->
    parseXX3Compare Op.XSCMPUDP bin
  | 40u ->
    parseXX3 Op.XSSUBDP bin
  | 56u ->
    parseXX3 Op.XSDIVDP bin
  | 96u ->
    parseXX3 Op.XVADDDP bin
  | 104u ->
    parseXX3 Op.XVSUBDP bin
  | 112u ->
    parseXX3 Op.XVMULDP bin
  | 120u ->
    parseXX3 Op.XVDIVDP bin
  | 107u ->
    parseXX3 Op.XVCMPGTDP bin
  | 235u ->
    parseXX3 Op.XVCMPGTDPdot bin
  | 115u ->
    parseXX3 Op.XVCMPGEDP bin
  | 243u ->
    parseXX3 Op.XVCMPGEDPdot bin
  | 130u ->
    parseXX3 Op.XXLAND bin
  | 138u ->
    parseXX3 Op.XXLANDC bin
  | 146u ->
    parseXX3 Op.XXLOR bin
  | 154u ->
    parseXX3 Op.XXLXOR bin
  | 162u ->
    parseXX3 Op.XXLNOR bin
  | 170u ->
    parseXX3 Op.XXLORC bin
  | 176u ->
    parseXX3 Op.XSCPSGNDP bin
  | 178u ->
    parseXX3 Op.XXLNAND bin
  | 186u ->
    parseXX3 Op.XXLEQV bin
  | 18u ->
    parseXX3 Op.XXMRGHW bin
  | 50u ->
    parseXX3 Op.XXMRGLW bin
  | 1u ->
    parseXX3 Op.XSMADDASP bin
  | 9u ->
    parseXX3 Op.XSMADDMSP bin
  | 17u ->
    parseXX3 Op.XSMSUBASP bin
  | 25u ->
    parseXX3 Op.XSMSUBMSP bin
  | 33u ->
    parseXX3 Op.XSMADDADP bin
  | 41u ->
    parseXX3 Op.XSMADDMDP bin
  | 49u ->
    parseXX3 Op.XSMSUBADP bin
  | 57u ->
    parseXX3 Op.XSMSUBMDP bin
  | 129u ->
    parseXX3 Op.XSNMADDASP bin
  | 137u ->
    parseXX3 Op.XSNMADDMSP bin
  | 145u ->
    parseXX3 Op.XSNMSUBASP bin
  | 153u ->
    parseXX3 Op.XSNMSUBMSP bin
  | 161u ->
    parseXX3 Op.XSNMADDADP bin
  | 169u ->
    parseXX3 Op.XSNMADDMDP bin
  | 177u ->
    parseXX3 Op.XSNMSUBADP bin
  | 185u ->
    parseXX3 Op.XSNMSUBMDP bin
  | xo when xo &&& 0x9Fu = 0x0Au ->
    parseXXPERMDIx Op.XXPERMDI bin
  | xo when xo &&& 0x9Fu = 0x02u ->
    parseXXPERMDIx Op.XXSLDWI bin
  | _ ->
    match Bits.extract bin 10u 2u with
    | 164u -> parseXXSPLTW bin
    | 180u when Bits.extract bin 20u 19u = 0u -> parseXXSPLTIB bin
    | 72u -> parseXX2 Op.XSCVDPUXWS bin
    | 88u -> parseXX2 Op.XSCVDPSXWS bin
    | 11u -> parseXX2 Op.XSSQRTSP bin
    | 73u -> parseXX2 Op.XSRDPI bin
    | 89u -> parseXX2 Op.XSRDPIZ bin
    | 105u -> parseXX2 Op.XSRDPIP bin
    | 121u -> parseXX2 Op.XSRDPIM bin
    | 75u -> parseXX2 Op.XSSQRTDP bin
    | 265u -> parseXX2 Op.XSCVDPSP bin
    | 267u -> parseXX2 Op.XSCVDPSPN bin
    | 296u -> parseXX2 Op.XSCVUXDSP bin
    | 312u -> parseXX2 Op.XSCVSXDSP bin
    | 328u -> parseXX2 Op.XSCVDPUXDS bin
    | 344u -> parseXX2 Op.XSCVDPSXDS bin
    | 360u -> parseXX2 Op.XSCVUXDDP bin
    | 376u -> parseXX2 Op.XSCVSXDDP bin
    | 281u -> parseXX2 Op.XSRSP bin
    | 329u -> parseXX2 Op.XSCVSPDP bin
    | 331u -> parseXX2 Op.XSCVSPDPN bin
    | 345u -> parseXX2 Op.XSABSDP bin
    | 361u -> parseXX2 Op.XSNABSDP bin
    | 377u -> parseXX2 Op.XSNEGDP bin
    | 248u -> parseXX2 Op.XVCVSXWDP bin
    | 505u -> parseXX2 Op.XVNEGDP bin
    | _ -> parseVSX3C bin

/// The VSX instructions in primary opcode 60. xxsel's four register fields
/// leave it only bits 26-27 of an extended opcode, which no other form
/// there sets both of, so it is told apart first.
let private parse3C bin =
  if Bits.extract bin 5u 4u = 3u then parseXXSEL bin
  else parse3CExtended bin

/// The VMX and VSX memory accesses that live in primary opcode 31.
let private parse1FVector fallback bin =
  match Bits.extract bin 10u 1u with
  | 6u -> parseVmxIndexed Op.LVSL bin
  | 7u -> parseVmxIndexed Op.LVEBX bin
  | 38u -> parseVmxIndexed Op.LVSR bin
  | 39u -> parseVmxIndexed Op.LVEHX bin
  | 71u -> parseVmxIndexed Op.LVEWX bin
  | 103u -> parseVmxIndexed Op.LVX bin
  | 135u -> parseVmxIndexed Op.STVEBX bin
  | 167u -> parseVmxIndexed Op.STVEHX bin
  | 199u -> parseVmxIndexed Op.STVEWX bin
  | 231u -> parseVmxIndexed Op.STVX bin
  | 359u -> parseVmxIndexed Op.LVXL bin
  | 487u -> parseVmxIndexed Op.STVXL bin
  | 332u -> parseVsxIndexed Op.LXVDSX bin
  | 588u -> parseVsxIndexed Op.LXSDX bin
  | 716u -> parseVsxIndexed Op.STXSDX bin
  | 780u -> parseVsxIndexed Op.LXVW4X bin
  | 844u -> parseVsxIndexed Op.LXVD2X bin
  | 908u -> parseVsxIndexed Op.STXVW4X bin
  | 972u -> parseVsxIndexed Op.STXVD2X bin
  | _ -> parseVSX1F fallback bin

let private parse1FDouble fallback bin =
  match Bits.extract bin 10u 1u with
  | 0x009u -> parseXFormArith Op.MULHDU Op.MULHDUdot bin
  | 0x015u -> parseXFormIndexed Op.LDX bin
  | 0x01Bu -> parseXFormLogical Op.SLD Op.SLDdot bin
  | 0x033u -> parseVsrMove Op.MFVSRD bin
  | 0x035u -> parseXFormIndexed Op.LDUX bin
  | 0x03Au -> parseXFormUnary Op.CNTLZD Op.CNTLZDdot bin
  | 0x044u -> parseTD bin
  | 0x049u -> parseXFormArith Op.MULHD Op.MULHDdot bin
  | 0x054u -> parseReserveIndexed Op.LDARX bin
  | 0x073u -> parseVsrMove Op.MFVSRWZ bin
  | 0x095u -> parseXFormIndexed Op.STDX bin
  | 0x0B3u -> parseVsrMove Op.MTVSRD bin
  | 0x0B5u -> parseXFormIndexed Op.STDUX bin
  | 0x0BAu -> parseXFormCount Op.PRTYD bin
  | 0x0D3u -> parseVsrMove Op.MTVSRWA bin
  | 0x0D6u -> parseStoreConditional Op.STDCXdot bin
  (* An XO form keeps OE in bit 10, so its overflow-recording forms read
     0x200 higher than the plain ones and are reached from both. *)
  | 0x0E9u | 0x2E9u -> parseXOForm [| Op.MULLD
                                      Op.MULLDdot
                                      Op.MULLDO
                                      Op.MULLDOdot |] bin
  | 0x0F3u -> parseVsrMove Op.MTVSRWZ bin
  | 0x133u -> parseMFVSRLD bin
  | 0x1B3u -> parseMTVSRDD bin
  | 0x0FCu -> parseXFormPerm Op.BPERMD bin
  | 0x155u -> parseXFormIndexed Op.LWAX bin
  | 0x175u -> parseXFormIndexed Op.LWAUX bin
  | 0x1C9u | 0x3C9u -> parseXOForm [| Op.DIVDU
                                      Op.DIVDUdot
                                      Op.DIVDUO
                                      Op.DIVDUOdot |] bin
  | 0x1E9u | 0x3E9u -> parseXOForm [| Op.DIVD
                                      Op.DIVDdot
                                      Op.DIVDO
                                      Op.DIVDOdot |] bin
  | 0x1FAu -> parseXFormCount Op.POPCNTD bin
  | 0x214u -> parseXFormIndexed Op.LDBRX bin
  | 0x21Bu -> parseXFormLogical Op.SRD Op.SRDdot bin
  | 0x294u -> parseXFormIndexed Op.STDBRX bin
  | 0x31Au -> parseXFormLogical Op.SRAD Op.SRADdot bin
  | 0x33Au | 0x33Bu -> parseSRADIx bin
  | 0x3DAu -> parseXFormUnary Op.EXTSW Op.EXTSWdot bin
  | _ -> fallback bin

let private parse1FWord bin =
  match Bits.extract bin 9u 1u with
  | 0x0u when Bits.pick bin 0u = 0u -> parseCMPandMCRXR bin
  | 0x4u when Bits.pick bin 0u = 0u -> parseTW bin
  | 0x8u -> parseSUBFCx bin
  | 0xAu -> parseADDCx bin
  | 0xBu when Bits.pick bin 10u = 0u -> parseMULHWUx bin
  | 0x13u when Bits.pick bin 0u = 0u -> parseMFCR bin
  (* FIXME: LWARX RegA = 0 *)
  | 0x14u when Bits.pick bin 10u = 0u -> parseLWARX bin
  | 0x15u when Bits.pick bin 0u = 0u -> parseLSWX bin
  (* FIXME: LWBRX RegA = 0 *)
  | 0x16u when Bits.pick bin 0u = 0u -> parseLWBRX bin
  (* FIXME: LWZX / LFSX RegA = 0 *)
  | 0x17u when Bits.pick bin 0u = 0u -> parseLWZXandLFSX bin
  | 0x18u -> parseSLWxandSRWx bin
  | 0x1Au -> parseCNTLZWx bin
  | 0x1Cu -> parseANDx bin
  | 0x20u when Bits.pick bin 0u = 0u -> parseCMPL bin
  | 0x28u -> parseSUBFx bin
  (* FIXME: DCBST RegA = 0 *)
  | 0x36u when Bits.pick bin 0u = 0u -> parseDCBSTandTLBSYNC bin
  (* FIXME: LWZUX / LFSUX RegA = 0 *)
  | 0x37u when Bits.pick bin 0u = 0u -> parseLWZUXandLFSUX bin
  | 0x3Cu -> parseANDCx bin
  | 0x4Bu when Bits.pick bin 10u = 0u -> parseMULHWx bin
  (* FIXME: SegRegister *)
  | 0x53u when Bits.pick bin 0u = 0u -> parseMFMSRandMFSR bin
  | 0x55u when Bits.pick bin 0u = 0u -> parseLSWI bin
  (* FIXME: DCBF RegA = 0 *)
  | 0x56u when Bits.pick bin 0u = 0u -> parseDCBFandSYNC bin
  (* FIXME: LBZX / LFDX RegA = 0 *)
  | 0x57u when Bits.pick bin 0u = 0u -> parseLBZXandLFDX bin
  | 0x68u -> parseNEGx bin
  (* FIXME: LBZUX / LFDUX RegA = 0 *)
  | 0x77u when Bits.pick bin 0u = 0u -> parseLBZUXandLFDUX bin
  | 0x7Cu -> parseNORx bin
  | 0x88u -> parseSUBFEx bin
  | 0x8Au -> parseADDEx bin
  (* FIXME: CRM *)
  | 0x90u when Bits.pick bin 0u = 0u -> parseMTCRF bin
  | 0x92u when Bits.pick bin 0u = 0u -> parseMTMSR bin
  | 0x93u -> parseMFSRIN bin
  | 0x95u when Bits.pick bin 0u = 0u -> parseSTSWX bin
  (* FIXME: STWCXdot / STWBRX RegA = 0 *)
  | 0x96u -> parseSTWCXdotandSTWBRX bin
  (* FIXME: STWX / STFSX RegA = 0 *)
  | 0x97u when Bits.pick bin 0u = 0u -> parseSTWXandSTFSX bin
  (* FIXME: STWUX / STFSUX RegA = 0 *)
  | 0xB7u when Bits.pick bin 0u = 0u -> parseSTWUXandSTFSUX bin
  | 0xC8u -> parseSUBFZEx bin
  | 0xCAu -> parseADDZEx bin
  (* FIXME: SegRegister *)
  | 0xD2u when Bits.pick bin 0u = 0u -> parseMTSR bin
  (* FIXME: SpecialRegister *)
  | 0xD5u when Bits.pick bin 0u = 0u -> parseSTSWI bin
  (* FIXME: STBX / STFDX RegA = 0 *)
  | 0xD7u -> parseSTBXandSTFDX bin
  | 0xE8u -> parseSUBFMEx bin
  | 0xEAu -> parseADDMEx bin
  | 0xEBu -> parseMULLWx bin
  | 0xF2u -> parseMTSRIN bin
  (* FIXME: DCBTST / DCBA RegA = 0 *)
  | 0xF6u when Bits.pick bin 0u = 0u -> parseDCBTSTandDCBA bin
  (* FIXME: STBUX / STFDUX RegA = 0 *)
  | 0xF7u -> parseSTBUXandSTFDUX bin
  | 0x10Au -> parseADDx bin
  (* FIXME: DCBT / LHBRX RegA = 0 *)
  | 0x116u when Bits.pick bin 0u = 0u -> parseDCBTandLHBRX bin
  (* FIXME: LHZX RegA = 0 *)
  | 0x117u when Bits.pick bin 0u = 0u -> parseLHZX bin
  | 0x118u -> parseSRAWx bin
  | 0x11Cu -> parseEQVx bin
  | 0x132u -> parseTLBIE bin
  | 0x136u when Bits.pick bin 0u = 0u -> parseECIWX bin
  (* FIXME: LHZUX RegA = 0 *)
  | 0x137u when Bits.pick bin 0u = 0u -> parseLHZUX bin
  | 0x138u when Bits.pick bin 10u = 1u -> parseSRAWIx bin
  | 0x13Cu -> parseXORx bin
  (* FIXME: SpecialRegister *)
  | 0x153u when Bits.pick bin 0u = 0u -> parseMFSPR bin
  | 0x156u when Bits.pick bin 0u = 0u -> parseEIEIO bin
  (* FIXME: LHAX RegA = 0 *)
  | 0x157u when Bits.pick bin 0u = 0u -> parseLHAXandLFIWAX bin
  | 0x172u -> parseTLBIA bin
  (* FIXME: TBRRegister *)
  | 0x173u when Bits.pick bin 0u = 0u -> parseMFTB bin
  (* FIXME: LHAUX RegA = 0 *)
  | 0x177u when Bits.pick bin 0u = 0u -> parseLHAUXandLFIWZX bin
  (* FIXME: STHBRX RegA = 0 *)
  | 0x196u when Bits.pick bin 0u = 0u -> parseSTHBRX bin
  (* FIXME: STHX RegA = 0 *)
  | 0x197u when Bits.pick bin 0u = 0u -> parseSTHX bin
  | 0x19Au -> parseEXTSHx bin
  | 0x19Cu -> parseORCx bin
  | 0x1B6u when Bits.pick bin 0u = 0u -> parseECOWX bin
  (* FIXME: STHUX RegA = 0 *)
  | 0x1B7u when Bits.pick bin 0u = 0u -> parseSTHUX bin
  | 0x1BAu -> parseEXTSBx bin
  | 0x1BCu -> parseORx bin
  | 0x1CBu -> parseDIVWUx bin
  | 0x1D3u when Bits.pick bin 0u = 0u -> parseMTSPR bin
  (* FIXME: DCBI / ICBI RegA = 0 *)
  | 0x1D6u when Bits.pick bin 0u = 0u -> parseDCBIandICBI bin
  (* FIXME: STFIWX RegA = 0 *)
  | 0x1D7u when Bits.pick bin 0u = 0u -> parseSTFIWX bin
  | 0x1DCu -> parseNANDx bin
  | 0x1EBu -> parseDIVWx bin
  (* FIXME: DCBZ RegA = 0 *)
  | 0x1F6u when Bits.pick bin 0u = 0u -> parseDCBZ bin
  | _ -> raise ParsingFailureException

/// The even register of an even-odd pair of floating-point registers, which
/// a pair operand names; an odd one makes the form invalid.
let private getFPPairRegister n =
  if n &&& 1u <> 0u then raise ParsingFailureException
  else getFPRegister n

/// Whether an opcode-31 word is lfdpx or stfdpx, the indexed accesses of a
/// floating-point register pair.
let private isFPPairIndexed bin =
  let xo = Bits.extract bin 10u 1u
  (xo = 791u || xo = 919u) && Bits.pick bin 0u = 0u

/// lfdpx and stfdpx, "frp, rA, rB".
let private parseFPPairIndexed bin =
  let frp = getFPPairRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  let op = if Bits.extract bin 10u 1u = 791u then Op.LFDPX else Op.STFDPX
  struct (op, ThreeOperands(frp, ra, rb))

/// icbt CT, rA, rB, an instruction cache touch, whose CT hint is carried only
/// where it is not zero. Bit 6 is reserved.
let private parseICBT bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.pick bin 25u <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    match Bits.extract bin 24u 21u with
    | 0u -> struct (Op.ICBT, TwoOperands(ra, rb))
    | ct -> struct (Op.ICBT, ThreeOperands(OprImm(uint64 ct), ra, rb))

/// stqcx. rSp, rA, rB, which stores an even-odd register pair: an odd rSp is
/// an invalid form.
let private parseSTQCX bin =
  let struct (rs, ra, rb) = xFormRegs bin
  if Bits.pick bin 21u <> 0u || Bits.pick bin 0u <> 1u then
    raise ParsingFailureException
  else
    struct (Op.STQCXdot, ThreeOperands(rs, ra, rb))

/// lqarx rTp, rA, rB, which loads an even-odd register pair: an odd rTp, or
/// one that rA or rB names too, is an invalid form that the processor
/// refuses (Book II 4.6.2.2). The last bit is the EH hint.
let private parseLQARX bin =
  let rt = Bits.extract bin 25u 21u
  let clash = rt = Bits.extract bin 20u 16u || rt = Bits.extract bin 15u 11u
  if rt % 2u <> 0u || clash then
    raise ParsingFailureException
  else
    let struct (rd, ra, rb) = xFormRegs bin
    struct (Op.LQARX, ThreeOperands(rd, ra, rb))

/// mfbhrbe rT, BHRBE, whose entry number sits where an XFX form keeps an SPR
/// number, but in order rather than in two swapped halves.
let private parseMFBHRBE bin =
  let rt = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let entry = Bits.extract bin 20u 11u |> uint64 |> OprImm
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  else struct (Op.MFBHRBE, TwoOperands(rt, entry))

/// clrbhrb, which clears the branch history rolling buffer.
let private parseCLRBHRB bin =
  if Bits.extract bin 25u 11u <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    struct (Op.CLRBHRB, NoOperand)

/// setb rT, BFA, whose CR field is the top three bits of the rA field; the
/// other two are reserved, as is rB.
let private parseSETB bin =
  let rt = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let bfa = getCondRegister (Bits.extract bin 20u 18u) |> OprReg
  if Bits.extract bin 17u 11u <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    struct (Op.SETB, TwoOperands(rt, bfa))

/// addex rT, rA, rB, CY, whose CY (bits 21-22) is 0 in every defined form;
/// the dispatcher reaches this only for CY = 0.
let private parseADDEX bin =
  let struct (rt, ra, rb) = xFormRegs bin
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  else struct (Op.ADDEX, FourOperands(rt, ra, rb, OprImm 0UL))

/// cmprb BF, L, rA, rB. Bit 9 is reserved.
let private parseCMPRB bin =
  let bf = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
  let l = Bits.pick bin 21u |> uint64 |> OprImm
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.pick bin 22u <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    struct (Op.CMPRB, FourOperands(bf, l, ra, rb))

/// cmpeqb BF, rA, rB. Bits 9-10 are reserved.
let private parseCMPEQB bin =
  let bf = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.extract bin 22u 21u <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    struct (Op.CMPEQB, ThreeOperands(bf, ra, rb))

/// mcrxrx BF; everything below BF is reserved.
let private parseMCRXRX bin =
  let bf = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
  if Bits.extract bin 22u 11u <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    struct (Op.MCRXRX, OneOperand bf)

/// darn rT, L, whose L (bits 14-15) of 3 is reserved.
let private parseDARN bin =
  let rt = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let l = Bits.extract bin 17u 16u
  let reserved = Bits.extract bin 20u 18u ||| Bits.extract bin 15u 11u
  if l = 3u || reserved <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    struct (Op.DARN, TwoOperands(rt, OprImm(uint64 l)))

/// extswsli rA, rS, SH, an XS form whose shift keeps its sixth bit in bit 30.
let private parseEXTSWSLI bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let sh = (Bits.pick bin 1u <<< 5) ||| Bits.extract bin 15u 11u
  let op = if Bits.pick bin 0u = 0u then Op.EXTSWSLI else Op.EXTSWSLIdot
  struct (op, ThreeOperands(ra, rs, OprImm(uint64 sh)))

/// <summary>
/// copy rA, rB, whose bit 10 v3.1 fixes at 1, and paste[.] rA, rB, L, whose
/// L sits there and is left out where it is 1, the extended mnemonic; the
/// bits above are reserved.
/// </summary>
let private parseCopyPaste bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  let l = Bits.pick bin 21u
  let operands =
    if l = 1u then TwoOperands(ra, rb)
    else ThreeOperands(ra, rb, OprImm(uint64 l))
  let reserved, xo = Bits.extract bin 25u 22u, Bits.extract bin 10u 1u
  match reserved, xo, l, Bits.pick bin 0u with
  | 0u, 902u, _, 1u -> struct (Op.PASTEdot, operands)
  | 0u, 902u, _, _ -> struct (Op.PASTE, operands)
  | 0u, _, 1u, 0u -> struct (Op.COPY, TwoOperands(ra, rb))
  | _ -> raise ParsingFailureException

/// cpabort, whose fields are all reserved.
let private parseCPABORT bin =
  if Bits.extract bin 25u 11u <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    struct (Op.CPABORT, NoOperand)

/// <summary>
/// wait WC, PL, both left out where both are 0. WC = 3 is reserved, an
/// invalid form; a reserved PL is not (the instruction is then a no-op).
/// Bits 6 and 7 may hold an implementation-dependent field and are not
/// checked.
/// </summary>
let private parseWAIT bin =
  let wc = Bits.extract bin 22u 21u
  let reserved =
    Bits.pick bin 23u ||| Bits.extract bin 20u 18u ||| Bits.extract bin 15u 11u
    ||| Bits.pick bin 0u
  if wc = 3u || reserved <> 0u then
    raise ParsingFailureException
  else
    match wc, Bits.extract bin 17u 16u with
    | 0u, 0u ->
      struct (Op.WAIT, NoOperand)
    | _, pl ->
      struct (Op.WAIT, TwoOperands(OprImm(uint64 wc), OprImm(uint64 pl)))

/// <summary>
/// lwat, ldat, stwat and stdat rT, rA, FC, whose function code sits where an
/// X form keeps rB. A code Book II does not list is not an invalid form: the
/// processor invokes the data storage error handler when it runs.
/// </summary>
let private parseAtomic op bin =
  let struct (rt, ra, _) = xFormRegs bin
  let fc = Bits.extract bin 15u 11u |> uint64 |> OprImm
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  else struct (op, ThreeOperands(rt, ra, fc))

/// setbc, setbcr, setnbc and setnbcr rT, BI, which name a CR bit where an X
/// form keeps rA.
let private parseSETBC op bin =
  let rt = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let bi = Bits.extract bin 20u 16u |> OprBI
  if Bits.extract bin 15u 11u <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    struct (op, TwoOperands(rt, bi))

/// <summary>
/// forms of primary opcode 31, tried before the word dispatcher
/// they otherwise fall back to. The forms on doublewords and the quadword
/// pair need 64-bit registers, and the branch history buffer belongs to the
/// 64-bit server processors; icbt and the word forms decode on either. So do
/// popcntb, popcntw, prtyw, cmpb and the byte and halfword reservation pairs,
/// which the ISA gives a 32-bit processor too.
/// </summary>
let private parse1FLaneA is64 fallback bin =
  match Bits.extract bin 10u 1u with
  | 0x016u ->
    parseICBT bin
  | 0x01Eu when is64 ->
    parseWAIT bin
  | 0x034u ->
    parseReserveIndexed Op.LBARX bin
  | 0x03Bu when is64 ->
    parseXFormPerm Op.CNTLZDM bin
  | 0x04Au ->
    parseXFormIndexed Op.ADDG6S bin
  | 0x074u ->
    parseReserveIndexed Op.LHARX bin
  | 0x07Au ->
    parseXFormCount Op.POPCNTB bin
  | 0x080u ->
    parseSETB bin
  | 0x09Au ->
    parseXFormCount Op.PRTYW bin
  | 0x09Bu ->
    parseXFormCount Op.BRW bin
  | 0x09Cu when is64 ->
    parseXFormPerm Op.PDEPD bin
  | 0x0AAu ->
    parseADDEX bin
  | 0x0B6u when is64 ->
    parseSTQCX bin
  | 0x0BBu when is64 ->
    parseXFormCount Op.BRD bin
  | 0x0BCu when is64 ->
    parseXFormPerm Op.PEXTD bin
  | 0x0C0u ->
    parseCMPRB bin
  | 0x0DBu ->
    parseXFormCount Op.BRH bin
  | 0x0DCu when is64 ->
    parseXFormPerm Op.CFUGED bin
  | 0x0E0u when is64 ->
    parseCMPEQB bin
  | 0x109u when is64 ->
    parseXFormIndexed Op.MODUD bin
  | 0x10Bu ->
    parseXFormIndexed Op.MODUW bin
  | 0x114u when is64 ->
    parseLQARX bin
  | 0x11Au ->
    parseXFormCount Op.CDTBCD bin
  | 0x12Eu when is64 ->
    parseMFBHRBE bin
  | 0x13Au ->
    parseXFormCount Op.CBCDTD bin
  | 0x17Au ->
    parseXFormCount Op.POPCNTW bin
  | 0x180u ->
    parseSETBC Op.SETBC bin
  | 0x189u | 0x389u when is64 ->
    parseXOForm [| Op.DIVDEU; Op.DIVDEUdot; Op.DIVDEUO; Op.DIVDEUOdot |] bin
  | 0x18Bu | 0x38Bu ->
    parseXOForm [| Op.DIVWEU; Op.DIVWEUdot; Op.DIVWEUO; Op.DIVWEUOdot |] bin
  | 0x1A0u ->
    parseSETBC Op.SETBCR bin
  | 0x1A9u | 0x3A9u when is64 ->
    parseXOForm [| Op.DIVDE; Op.DIVDEdot; Op.DIVDEO; Op.DIVDEOdot |] bin
  | 0x1ABu | 0x3ABu ->
    parseXOForm [| Op.DIVWE; Op.DIVWEdot; Op.DIVWEO; Op.DIVWEOdot |] bin
  | 0x1AEu when is64 ->
    parseCLRBHRB bin
  | 0x1C0u ->
    parseSETBC Op.SETNBC bin
  | 0x1E0u ->
    parseSETBC Op.SETNBCR bin
  | 0x1FCu ->
    parseXFormPerm Op.CMPB bin
  | 0x21Au ->
    parseXFormUnary Op.CNTTZW Op.CNTTZWdot bin
  | 0x23Au when is64 ->
    parseXFormUnary Op.CNTTZD Op.CNTTZDdot bin
  | 0x23Bu when is64 ->
    parseXFormPerm Op.CNTTZDM bin
  | 0x240u ->
    parseMCRXRX bin
  | 0x246u when is64 ->
    parseAtomic Op.LWAT bin
  | 0x266u when is64 ->
    parseAtomic Op.LDAT bin
  | 0x2B6u ->
    parseStoreConditional Op.STBCXdot bin
  | 0x2C6u when is64 ->
    parseAtomic Op.STWAT bin
  | 0x2D6u ->
    parseStoreConditional Op.STHCXdot bin
  | 0x2E6u when is64 ->
    parseAtomic Op.STDAT bin
  | 0x2F3u when is64 ->
    parseDARN bin
  | 0x306u when is64 ->
    parseCopyPaste bin
  | 0x309u when is64 ->
    parseXFormIndexed Op.MODSD bin
  | 0x30Bu ->
    parseXFormIndexed Op.MODSW bin
  | 0x346u when is64 ->
    parseCPABORT bin
  | 0x37Au | 0x37Bu when is64 ->
    parseEXTSWSLI bin
  | 0x386u when is64 ->
    parseCopyPaste bin
  | _ ->
    fallback bin

let parse1F is64 bin =
  let parse1FWord = parse1FLaneA is64 parse1FWord
  if Bits.extract bin 5u 1u = 0xFu then parseISEL bin
  elif isFPPairIndexed bin then parseFPPairIndexed bin
  elif is64 then parse1FVector (parse1FDouble parse1FWord) bin
  else parse1FVector parse1FWord bin

let parseLWZ bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LWZ, TwoOperands(rd, mem))

let parseLWZU bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LWZU, TwoOperands(rd, mem))

let parseLBZ bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LBZ, TwoOperands(rd, mem))

let parseLBZU bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LBZU, TwoOperands(rd, mem))

let parseSTW bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STW, TwoOperands(rs, mem))

let parseSTWU bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STWU, TwoOperands(rs, mem))

let parseSTB bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STB, TwoOperands(rs, mem))

let parseSTBU bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STBU, TwoOperands(rs, mem))

let parseLHZ bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LHZ, TwoOperands(rd, mem))

let parseLHZU bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LHZU, TwoOperands(rd, mem))

let parseLHA bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LHA, TwoOperands(rd, mem))

let parseLHAU bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LHAU, TwoOperands(rd, mem))

let parseSTH bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STH, TwoOperands(rs, mem))

let parseSTHU bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STHU, TwoOperands(rs, mem))

let parseLMW bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LMW, TwoOperands(rd, mem))

let parseSTMW bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STMW, TwoOperands(rs, mem))

let parseLFS bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LFS, TwoOperands(frd, mem))

let parseLFSU bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LFSU, TwoOperands(frd, mem))

let parseLFD bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LFD, TwoOperands(frd, mem))

let parseLFDU bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.LFDU, TwoOperands(frd, mem))

let parseSTFS bin =
  let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STFS, TwoOperands(frs, mem))

let parseSTFSU bin =
  let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STFSU, TwoOperands(frs, mem))

let parseSTFD bin =
  let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STFD, TwoOperands(frs, mem))

let parseSTFDU bin =
  let frs = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let d = Bits.extract bin 15u 0u |> uint64
  let value = Bits.signExtend 16 32 d |> int32
  let mem = (value, ra) |> OprMem (* d (rA) *)
  struct (Op.STFDU, TwoOperands(frs, mem))

let parseFDIVSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FDIVS, ThreeOperands(frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FDIVSdot, ThreeOperands(frd, fra, frb))

let parseFSUBSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FSUBS, ThreeOperands(frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FSUBSdot, ThreeOperands(frd, fra, frb))

let parseFADDSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FADDS, ThreeOperands(frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FADDSdot, ThreeOperands(frd, fra, frb))

let parseFSQRTSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FSQRTS, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FSQRTSdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseFRESx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FRES, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FRESdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseFMULSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.FMULS, ThreeOperands(frd, fra, frc))
  | 0b1u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.FMULSdot, ThreeOperands(frd, fra, frc))
  | _ ->
    raise ParsingFailureException

let parseFMSUBSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FMSUBS, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FMSUBSdot, FourOperands(frd, fra, frc, frb))

let parseFMADDSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FMADDS, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FMADDSdot, FourOperands(frd, fra, frc, frb))

let parseFNMSUBSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FNMSUBS, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FNMSUBSdot, FourOperands(frd, fra, frc, frb))

let parseFNMADDSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FNMADDS, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FNMADDSdot, FourOperands(frd, fra, frc, frb))

/// fcpsgn, which takes a sign from one operand and a magnitude from the other.
let private parseFCPSGN bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.pick bin 0u = 0u then struct (Op.FCPSGN, ThreeOperands(frd, fra, frb))
  else struct (Op.FCPSGNdot, ThreeOperands(frd, fra, frb))

/// An A-form estimate, "frD, frB": fre, fres, frsqrte and frsqrtes, whose frA
/// and frC fields are reserved.
let private parseFPEstimate op opDot bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.extract bin 20u 16u <> 0u || Bits.extract bin 10u 6u <> 0u then
    raise ParsingFailureException
  elif Bits.pick bin 0u = 0u then
    struct (op, TwoOperands(frd, frb))
  else
    struct (opDot, TwoOperands(frd, frb))

/// fmrgew and fmrgow, "frD, frA, frB", which have no record form.
let private parseFPMerge op bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  else struct (op, ThreeOperands(frd, fra, frb))

/// ftdiv, "BF, frA, frB", which tests the operands of a divide into a CR
/// field.
let private parseFTDIV bin =
  let bf = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.extract bin 22u 21u <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    struct (Op.FTDIV, ThreeOperands(bf, fra, frb))

/// ftsqrt, "BF, frB", which tests the operand of a square root.
let private parseFTSQRT bin =
  let bf = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.extract bin 22u 16u <> 0u || Bits.pick bin 0u <> 0u then
    raise ParsingFailureException
  else
    struct (Op.FTSQRT, TwoOperands(bf, frb))

/// An X-form floating-point "frD, frB" whose Rc bit names two opcodes.
let private parseFPUnary op opDot bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  if Bits.extract bin 20u 16u <> 0u then raise ParsingFailureException
  elif Bits.pick bin 0u = 0u then struct (op, TwoOperands(frd, frb))
  else struct (opDot, TwoOperands(frd, frb))

/// Whether a DFP word is in primary opcode 63, which holds the quad forms: the
/// instructions on the extended format (decimal128), under the extended
/// opcodes primary opcode 59 gives those on the long format (decimal64).
let private isDFPQuad bin = Bits.extract bin 31u 26u = 0x3Fu

/// The FPR a DFP operand names: where a quad form takes the operand in the
/// extended format, the even register of the pair that holds it.
let private getDFPRegister isPair n =
  if isPair then getFPPairRegister n else getFPRegister n

/// The FPR operand in the FRT field, bits 25:21, of a DFP word.
let private dfpT isPair bin =
  getDFPRegister isPair (Bits.extract bin 25u 21u) |> OprReg

/// The FPR operand in the FRA field, bits 20:16, of a DFP word.
let private dfpA isPair bin =
  getDFPRegister isPair (Bits.extract bin 20u 16u) |> OprReg

/// The FPR operand in the FRB field, bits 15:11, of a DFP word.
let private dfpB isPair bin =
  getDFPRegister isPair (Bits.extract bin 15u 11u) |> OprReg

/// The opcode a DFP word with a record bit names: the long or the quad form,
/// each with that bit clear or set.
let private dfpOpcode bin (long, longDot) (quad, quadDot) =
  match isDFPQuad bin, Bits.pick bin 0u with
  | false, 0u -> long
  | false, _ -> longDot
  | true, 0u -> quad
  | true, _ -> quadDot

/// dadd, dmul, dsub, ddiv and diex, "FRT, FRA, FRB": the quad forms take each
/// operand as a pair, except diex's FRA (pairA false), the exponent to insert.
let private parseDFPThree pairA ops opsQ bin =
  let q = isDFPQuad bin
  let operands = ThreeOperands(dfpT q bin, dfpA (q && pairA) bin, dfpB q bin)
  struct (dfpOpcode bin ops opsQ, operands)

/// The CR field, bits 25:23, a DFP comparison or test sets; bits 22:21 below
/// it are reserved.
let private dfpBF bin =
  if Bits.extract bin 22u 21u <> 0u then raise ParsingFailureException
  else getCondRegister (Bits.extract bin 25u 23u) |> OprReg

/// The opcode a DFP word with no record bit names, whose bit 0 is reserved.
let private dfpPlainOpcode bin long quad =
  if Bits.pick bin 0u <> 0u then raise ParsingFailureException
  elif isDFPQuad bin then quad
  else long

/// dcmpo, dcmpu, dtstex and dtstsf, "BF, FRA, FRB": the quad forms take each
/// FPR operand as a pair, except dtstsf's FRA (pairA false), the reference
/// significance.
let private parseDFPCompare pairA long quad bin =
  let q = isDFPQuad bin
  let operands = ThreeOperands(dfpBF bin, dfpA (q && pairA) bin, dfpB q bin)
  struct (dfpPlainOpcode bin long quad, operands)

/// The X-forms "FRT, FRB", whose FRA field is reserved: the conversions and
/// the roundings between the formats, and dxex. Which of the two operands the
/// quad form takes as a pair, (pairT, pairB), depends on the instruction.
let private parseDFPUnary (pairT, pairB) ops opsQ bin =
  let q = isDFPQuad bin
  let frt = dfpT (q && pairT) bin
  let frb = dfpB (q && pairB) bin
  if Bits.extract bin 20u 16u <> 0u then raise ParsingFailureException
  else struct (dfpOpcode bin ops opsQ, TwoOperands(frt, frb))

/// ddedpd "SP, FRT, FRB" and denbcd "S, FRT, FRB", whose immediate is bits
/// 20:lo, the top of the FRA field; the bits below it are reserved.
let private parseDFPCode lo ops opsQ bin =
  let q = isDFPQuad bin
  let imm = Bits.extract bin 20u lo |> uint64 |> OprImm
  let operands = ThreeOperands(imm, dfpT q bin, dfpB q bin)
  if Bits.extract bin (lo - 1u) 16u <> 0u then raise ParsingFailureException
  else struct (dfpOpcode bin ops opsQ, operands)

/// dcffixqq "FRTp, VRB" and dctfixqq "VRT, FRBp", which only primary opcode 63
/// holds and the FRA field tells apart; neither has a record bit.
let private parseDFPQuadword bin =
  match isDFPQuad bin, Bits.extract bin 20u 16u, Bits.pick bin 0u with
  | true, 0u, 0u ->
    let vrb = getVecRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.DCFFIXQQ, TwoOperands(dfpT true bin, vrb))
  | true, 1u, 0u ->
    let vrt = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
    struct (Op.DCTFIXQQ, TwoOperands(vrt, dfpB true bin))
  | _ ->
    raise ParsingFailureException

/// dscli and dscri, "FRT, FRA, SH": Z22-forms, whose six-bit SH is bits 15:10.
let private parseDFPShift ops opsQ bin =
  let q = isDFPQuad bin
  let sh = Bits.extract bin 15u 10u |> uint64 |> OprImm
  struct (dfpOpcode bin ops opsQ, ThreeOperands(dfpT q bin, dfpA q bin, sh))

/// dtstdc and dtstdg, "BF, FRA, DCM" and "BF, FRA, DGM": Z22-forms with no
/// record bit, whose six-bit mask is bits 15:10.
let private parseDFPTestData long quad bin =
  let fra = dfpA (isDFPQuad bin) bin
  let mask = Bits.extract bin 15u 10u |> uint64 |> OprImm
  struct (dfpPlainOpcode bin long quad, ThreeOperands(dfpBF bin, fra, mask))

/// A DFP Z22-form, told by bits 9:1; bit 10 belongs to its six-bit field.
let private parseDFPZ22 bin =
  match Bits.extract bin 9u 1u with
  | 66u -> parseDFPShift (Op.DSCLI, Op.DSCLIdot) (Op.DSCLIQ, Op.DSCLIQdot) bin
  | 98u -> parseDFPShift (Op.DSCRI, Op.DSCRIdot) (Op.DSCRIQ, Op.DSCRIQdot) bin
  | 194u -> parseDFPTestData Op.DTSTDC Op.DTSTDCQ bin
  | 226u -> parseDFPTestData Op.DTSTDG Op.DTSTDGQ bin
  | _ -> raise ParsingFailureException

/// A DFP word whose bits 5:1 are 2: an X-form, told by bits 10:1, or else a
/// Z22-form, none of whose extended opcodes is the low nine bits of an
/// X-form's.
let private parseDFPX bin =
  let widen = parseDFPUnary (true, false)
  let toFixed = parseDFPUnary (false, true)
  match Bits.extract bin 10u 1u with
  | 2u ->
    parseDFPThree true (Op.DADD, Op.DADDdot) (Op.DADDQ, Op.DADDQdot) bin
  | 34u ->
    parseDFPThree true (Op.DMUL, Op.DMULdot) (Op.DMULQ, Op.DMULQdot) bin
  | 130u ->
    parseDFPCompare true Op.DCMPO Op.DCMPOQ bin
  | 162u ->
    parseDFPCompare true Op.DTSTEX Op.DTSTEXQ bin
  | 258u ->
    widen (Op.DCTDP, Op.DCTDPdot) (Op.DCTQPQ, Op.DCTQPQdot) bin
  | 290u ->
    toFixed (Op.DCTFIX, Op.DCTFIXdot) (Op.DCTFIXQ, Op.DCTFIXQdot) bin
  | 322u ->
    parseDFPCode 19u (Op.DDEDPD, Op.DDEDPDdot) (Op.DDEDPDQ, Op.DDEDPDQdot) bin
  | 354u ->
    toFixed (Op.DXEX, Op.DXEXdot) (Op.DXEXQ, Op.DXEXQdot) bin
  | 514u ->
    parseDFPThree true (Op.DSUB, Op.DSUBdot) (Op.DSUBQ, Op.DSUBQdot) bin
  | 546u ->
    parseDFPThree true (Op.DDIV, Op.DDIVdot) (Op.DDIVQ, Op.DDIVQdot) bin
  | 642u ->
    parseDFPCompare true Op.DCMPU Op.DCMPUQ bin
  | 674u ->
    parseDFPCompare false Op.DTSTSF Op.DTSTSFQ bin
  | 770u ->
    parseDFPUnary (true, true) (Op.DRSP, Op.DRSPdot) (Op.DRDPQ, Op.DRDPQdot) bin
  | 802u ->
    widen (Op.DCFFIX, Op.DCFFIXdot) (Op.DCFFIXQ, Op.DCFFIXQdot) bin
  | 834u ->
    parseDFPCode 20u (Op.DENBCD, Op.DENBCDdot) (Op.DENBCDQ, Op.DENBCDQdot) bin
  | 866u ->
    parseDFPThree false (Op.DIEX, Op.DIEXdot) (Op.DIEXQ, Op.DIEXQdot) bin
  | 994u ->
    parseDFPQuadword bin
  | _ ->
    parseDFPZ22 bin

/// dtstsfi, "BF, UIM, FRB", which has no record bit: its six-bit UIM, bits
/// 21:16, leaves only bit 22 reserved below BF.
let private parseDTSTSFI bin =
  let bf = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
  let uim = Bits.extract bin 21u 16u |> uint64 |> OprImm
  let op = dfpPlainOpcode bin Op.DTSTSFI Op.DTSTSFIQ
  if Bits.pick bin 22u <> 0u then raise ParsingFailureException
  else struct (op, ThreeOperands(bf, uim, dfpB (isDFPQuad bin) bin))

/// The RMC field, bits 10:9, of a DFP Z23-form, which says how to round.
let private dfpRMC bin = Bits.extract bin 10u 9u |> uint64 |> OprImm

/// dqua and drrnd, "FRT, FRA, FRB, RMC": the quad forms take each operand as a
/// pair, except drrnd's FRA (pairA false), the reference significance.
let private parseDFPQuantize pairA ops opsQ bin =
  let q = isDFPQuad bin
  let fra = dfpA (q && pairA) bin
  let operands = FourOperands(dfpT q bin, fra, dfpB q bin, dfpRMC bin)
  struct (dfpOpcode bin ops opsQ, operands)

/// dquai "TE, FRT, FRB, RMC" and drintx and drintn "R, FRT, FRB, RMC":
/// Z23-forms whose first operand, which readImm reads, fills the FRA field.
let private parseDFPImmZ23 readImm ops opsQ bin =
  let q = isDFPQuad bin
  let operands = FourOperands(readImm bin, dfpT q bin, dfpB q bin, dfpRMC bin)
  struct (dfpOpcode bin ops opsQ, operands)

/// The TE of dquai, bits 20:16: a signed exponent, -16 to 15.
let private dfpTE bin =
  let te = Bits.extract bin 20u 16u |> uint64 |> Bits.signExtend 5 64 |> uint64
  OprImm te

/// The R of drintx and drintn, bit 16, which picks the encoding RMC is read
/// in; bits 20:17 above it are reserved.
let private dfpR bin =
  if Bits.extract bin 20u 17u <> 0u then raise ParsingFailureException
  else Bits.pick bin 16u |> uint64 |> OprImm

/// A DFP Z23-form, told by bits 8:1, below its RMC field.
let private parseDFPZ23 bin =
  let roundInt = parseDFPImmZ23 dfpR
  match Bits.extract bin 8u 1u with
  | 3u ->
    parseDFPQuantize true (Op.DQUA, Op.DQUAdot) (Op.DQUAQ, Op.DQUAQdot) bin
  | 35u ->
    parseDFPQuantize false (Op.DRRND, Op.DRRNDdot) (Op.DRRNDQ, Op.DRRNDQdot) bin
  | 67u ->
    parseDFPImmZ23 dfpTE (Op.DQUAI, Op.DQUAIdot) (Op.DQUAIQ, Op.DQUAIQdot) bin
  | 99u ->
    roundInt (Op.DRINTX, Op.DRINTXdot) (Op.DRINTXQ, Op.DRINTXQdot) bin
  | 227u ->
    roundInt (Op.DRINTN, Op.DRINTNdot) (Op.DRINTNQ, Op.DRINTNQdot) bin
  | _ ->
    raise ParsingFailureException

/// <summary>
/// A Decimal Floating-Point word, in primary opcode 59 or 63. Its bits 5:1
/// are 2 or 3, as those of no other instruction in either opcode are: 2 in an
/// X-form or a Z22-form, and 3 in a Z23-form or in dtstsfi, the one X-form
/// among them whose extended opcode ends in 3.
/// </summary>
let private parseDFP bin =
  if Bits.extract bin 5u 1u = 2u then parseDFPX bin
  elif Bits.extract bin 10u 1u = 675u then parseDTSTSFI bin
  else parseDFPZ23 bin

let parse3B bin =
  match Bits.extract bin 5u 1u with
  | _ when isMatrixForm bin ->
    parseVSX3B bin
  | 0x2u | 0x3u ->
    parseDFP bin
  | 0xEu ->
    match Bits.extract bin 10u 6u with
    | 0x1Au -> parseFPUnary Op.FCFIDS Op.FCFIDSdot bin
    | 0x1Eu -> parseFPUnary Op.FCFIDUS Op.FCFIDUSdot bin
    | _ -> raise ParsingFailureException
  | 0x12u when Bits.extract bin 10u 6u = 0u ->
    parseFDIVSx bin
  | 0x14u when Bits.extract bin 10u 6u = 0u ->
    parseFSUBSx bin
  | 0x15u when Bits.extract bin 10u 6u = 0u ->
    parseFADDSx bin
  | 0x16u when Bits.extract bin 10u 6u = 0u ->
    parseFSQRTSx bin
  | 0x18u when Bits.extract bin 10u 6u = 0u ->
    parseFRESx bin
  | 0x19u ->
    parseFMULSx bin
  | 0x1Au ->
    parseFPEstimate Op.FRSQRTES Op.FRSQRTESdot bin
  | 0x1Cu ->
    parseFMSUBSx bin
  | 0x1Du ->
    parseFMADDSx bin
  | 0x1Eu ->
    parseFNMSUBSx bin
  | 0x1Fu ->
    parseFNMADDSx bin
  | _ ->
    raise ParsingFailureException

let parseFCMPU bin =
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 22u 21u = 0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
    let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.FCMPU, ThreeOperands(crfd, fra, frb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseFRSPx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FRSP, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FRSPdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseFCTIWx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FCTIW, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FCTIWdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseFCTIWZx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FCTIWZ, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FCTIWZdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseFDIVx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FDIV, ThreeOperands(frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FDIVdot, ThreeOperands(frd, fra, frb))

let parseFSUBx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FSUB, ThreeOperands(frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FSUBdot, ThreeOperands(frd, fra, frb))

let parseFADDx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FADD, ThreeOperands(frd, fra, frb))
  | _ (* 1 *) -> struct (Op.FADDdot, ThreeOperands(frd, fra, frb))

let parseFSQRTx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FSQRT, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FSQRTdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseFSELx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FSEL, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FSELdot, FourOperands(frd, fra, frc, frb))

let parseFMULx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.FMUL, ThreeOperands(frd, fra, frc))
  | 0b1u when Bits.extract bin 15u 11u = 0u ->
    struct (Op.FMULdot, ThreeOperands(frd, fra, frc))
  | _ ->
    raise ParsingFailureException

let parseFMSUBx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FMSUB, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FMSUBdot, FourOperands(frd, fra, frc, frb))

let parseFMADDx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FMADD, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FMADDdot, FourOperands(frd, fra, frc, frb))

let parseFNMSUBx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FNMSUB, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FNMSUBdot, FourOperands(frd, fra, frc, frb))

let parseFNMADDx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let frc = getFPRegister (Bits.extract bin 10u 6u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u -> struct (Op.FNMADD, FourOperands(frd, fra, frc, frb))
  | _ (* 1 *) -> struct (Op.FNMADDdot, FourOperands(frd, fra, frc, frb))

let parseFCMPO bin =
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 22u 21u = 0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    let fra = getFPRegister (Bits.extract bin 20u 16u) |> OprReg
    let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.FCMPO, ThreeOperands(crfd, fra, frb))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseMTFSB1x bin =
  let crbd = getFPSCRBit (Bits.extract bin 25u 21u)
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 11u = 0u ->
    (* FIXME: FPSCRegister *)
    struct (Op.MTFSB1, OneOperand crbd)
  | 0b1u when Bits.extract bin 20u 11u = 0u ->
    (* FIXME: FPSCRegister *)
    struct (Op.MTFSB1dot, OneOperand crbd)
  | _ ->
    raise ParsingFailureException

let parseFNEGx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FNEG, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FNEGdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseMCRFS bin =
  match Bits.pick bin 0u with
  | 0b0u when Bits.concat (Bits.extract bin 22u 21u)
                          (Bits.extract bin 17u 11u)
                          2 = 0u ->
    let crfd = getCondRegister (Bits.extract bin 25u 23u) |> OprReg
    let crfs = getCondRegister (Bits.extract bin 20u 18u) |> OprReg
    struct (Op.MCRFS, TwoOperands(crfd, crfs))
  | _ (* 1 *) ->
    raise ParsingFailureException

let parseMTFSB0x bin =
  let crbd = getFPSCRBit (Bits.extract bin 25u 21u)
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 11u = 0u ->
    (* FIXME: FPSCRegister *)
    struct (Op.MTFSB0, OneOperand crbd)
  | 0b1u when Bits.extract bin 20u 11u = 0u ->
    (* FIXME: FPSCRegister *)
    struct (Op.MTFSB0dot, OneOperand crbd)
  | _ ->
    raise ParsingFailureException

let parseFMRx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FMR, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FMRdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

/// mtfsfi BF, U[, W]: W (bit 16) names the high word of the FPSCR, and the
/// extended form without it is what a word with W = 0 prints as.
let parseMTFSFIx bin =
  let crfd = Bits.extract bin 25u 23u |> uint64 |> OprImm
  let imm = Bits.extract bin 15u 12u |> uint64 |> OprImm
  let op = if Bits.pick bin 0u = 0u then Op.MTFSFI else Op.MTFSFIdot
  if Bits.extract bin 22u 17u <> 0u || Bits.pick bin 11u <> 0u then
    raise ParsingFailureException
  elif Bits.pick bin 16u = 0u then
    struct (op, TwoOperands(crfd, imm))
  else
    struct (op, ThreeOperands(crfd, imm, OprImm 1UL))

let parseFNABSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FNABS, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FNABSdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseFABSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FABS, TwoOperands(frd, frb))
  | 0b1u when Bits.extract bin 20u 16u = 0u ->
    struct (Op.FABSdot, TwoOperands(frd, frb))
  | _ ->
    raise ParsingFailureException

let parseMFFSx bin =
  let frd = getFPRegister (Bits.extract bin 25u 21u) |> OprReg
  match Bits.pick bin 0u with
  | 0b0u when Bits.extract bin 20u 11u = 0u ->
    struct (Op.MFFS, OneOperand frd)
  | 0b1u when Bits.extract bin 20u 11u = 0u ->
    struct (Op.MFFSdot, OneOperand frd)
  (* mffsl reads the FPSCR's control and status bits and leaves the rest zero;
     reading the whole register covers what it asks for. *)
  | 0b0u when Bits.extract bin 20u 16u = 24u && Bits.extract bin 15u 11u = 0u ->
    struct (Op.MFFSL, OneOperand frd)
  (* mffscrn and mffscrni read the FPSCR and then put a new rounding mode in
     force, one from a register and the other from a two-bit immediate. *)
  | 0b0u when Bits.extract bin 20u 16u = 22u ->
    let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.MFFSCRN, TwoOperands(frd, frb))
  | 0b0u when Bits.extract bin 20u 16u = 23u ->
    let rm = Bits.extract bin 12u 11u |> uint64 |> OprImm
    struct (Op.MFFSCRNI, TwoOperands(frd, rm))
  (* mffsce reads the FPSCR and clears its enables; mffscdrn and mffscdrni
     read its control bits and put a new DRN in force, from bits 29:31 of a
     register or from a three-bit immediate. *)
  | 0b0u when Bits.extract bin 20u 16u = 1u && Bits.extract bin 15u 11u = 0u ->
    struct (Op.MFFSCE, OneOperand frd)
  | 0b0u when Bits.extract bin 20u 16u = 20u ->
    let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
    struct (Op.MFFSCDRN, TwoOperands(frd, frb))
  | 0b0u when Bits.extract bin 20u 16u = 21u && Bits.extract bin 15u 14u = 0u ->
    let drm = Bits.extract bin 13u 11u |> uint64 |> OprImm
    struct (Op.MFFSCDRNI, TwoOperands(frd, drm))
  | _ ->
    raise ParsingFailureException

/// mtfsf FLM, frB[, L, W]: L (bit 25) writes the whole FPSCR and W (bit 16)
/// names its high word; the extended form without them is what a word with
/// both zero prints as.
let parseMTFSFx bin =
  let fm = Bits.extract bin 24u 17u |> uint64 |> OprImm
  let frb = getFPRegister (Bits.extract bin 15u 11u) |> OprReg
  let l = Bits.pick bin 25u
  let w = Bits.pick bin 16u
  let op = if Bits.pick bin 0u = 0u then Op.MTFSF else Op.MTFSFdot
  if l = 0u && w = 0u then
    struct (op, TwoOperands(fm, frb))
  else
    struct (op, FourOperands(fm, frb, OprImm(uint64 l), OprImm(uint64 w)))

let parse3F bin =
  match Bits.extract bin 5u 1u with
  | 0x0u ->
    match Bits.extract bin 10u 6u with
    | 0x0u -> parseFCMPU bin
    | 0x1u -> parseFCMPO bin
    | 0x2u -> parseMCRFS bin
    | 0x4u -> parseFTDIV bin
    | 0x5u -> parseFTSQRT bin
    | _ -> raise ParsingFailureException
  | 0x2u | 0x3u ->
    parseDFP bin
  | 0x6u ->
    (* FIXME: FPSCRegister *)
    match Bits.extract bin 10u 6u with
    | 0x1u -> parseMTFSB1x bin
    (* FIXME: FPSCRegister *)
    | 0x2u -> parseMTFSB0x bin
    | 0x4u -> parseMTFSFIx bin
    | 0x1Au -> parseFPMerge Op.FMRGOW bin
    | 0x1Eu -> parseFPMerge Op.FMRGEW bin
    | _ -> raise ParsingFailureException
  | 0x7u ->
    match Bits.extract bin 10u 6u with
    | 0x12u -> parseMFFSx bin
    | 0x16u -> parseMTFSFx bin
    | _ -> raise ParsingFailureException
  | 0x8u ->
    match Bits.extract bin 10u 6u with
    | 0x0u -> parseFCPSGN bin
    | 0x1u -> parseFNEGx bin
    | 0x2u -> parseFMRx bin
    | 0x4u -> parseFNABSx bin
    | 0x8u -> parseFABSx bin
    | 0xCu -> parseFPUnary Op.FRIN Op.FRINdot bin
    | 0xDu -> parseFPUnary Op.FRIZ Op.FRIZdot bin
    | 0xEu -> parseFPUnary Op.FRIP Op.FRIPdot bin
    | 0xFu -> parseFPUnary Op.FRIM Op.FRIMdot bin
    | _ -> raise ParsingFailureException
  | 0xCu when Bits.extract bin 10u 6u = 0u ->
    parseFRSPx bin
  | 0xEu ->
    match Bits.extract bin 10u 6u with
    | 0x0u -> parseFCTIWx bin
    | 0x4u -> parseFPUnary Op.FCTIWU Op.FCTIWUdot bin
    | 0x19u -> parseFPUnary Op.FCTID Op.FCTIDdot bin
    | 0x1Au -> parseFPUnary Op.FCFID Op.FCFIDdot bin
    | 0x1Du -> parseFPUnary Op.FCTIDU Op.FCTIDUdot bin
    | 0x1Eu -> parseFPUnary Op.FCFIDU Op.FCFIDUdot bin
    | _ -> raise ParsingFailureException
  | 0xFu ->
    match Bits.extract bin 10u 6u with
    | 0x0u -> parseFCTIWZx bin
    | 0x4u -> parseFPUnary Op.FCTIWUZ Op.FCTIWUZdot bin
    | 0x19u -> parseFPUnary Op.FCTIDZ Op.FCTIDZdot bin
    | 0x1Du -> parseFPUnary Op.FCTIDUZ Op.FCTIDUZdot bin
    | _ -> raise ParsingFailureException
  | 0x12u when Bits.extract bin 10u 6u = 0u ->
    parseFDIVx bin
  | 0x14u when Bits.extract bin 10u 6u = 0u ->
    parseFSUBx bin
  | 0x15u when Bits.extract bin 10u 6u = 0u ->
    parseFADDx bin
  | 0x16u when Bits.extract bin 10u 6u = 0u ->
    parseFSQRTx bin
  | 0x17u ->
    parseFSELx bin
  | 0x18u ->
    parseFPEstimate Op.FRE Op.FREdot bin
  | 0x19u ->
    parseFMULx bin
  | 0x1Au ->
    parseFPEstimate Op.FRSQRTE Op.FRSQRTEdot bin
  | 0x1Cu ->
    parseFMSUBx bin
  | 0x1Du ->
    parseFMADDx bin
  | 0x1Eu ->
    parseFNMSUBx bin
  | 0x1Fu ->
    parseFNMADDx bin
  | 0x4u | 0x5u ->
    parseVSX3F bin
  | _ ->
    raise ParsingFailureException

/// tdi, whose TO field selects the comparison the same way twi's does.
let private parseTDI bitLen bin =
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let value = simm16 bitLen bin |> OprImm
  let tO = Bits.extract bin 25u 21u |> uint64 |> OprImm
  struct (Op.TDI, ThreeOperands(tO, ra, value))

/// The displacement of a DS-form load or store: a 14-bit signed field that the
/// encoding leaves scaled by four.
let private dsDisp bin =
  Bits.extract bin 15u 2u <<< 2 |> uint64 |> Bits.signExtend 16 64
  |> int64 |> int32

/// lfdp and stfdp, the DS-form accesses of a floating-point register pair:
/// primary opcodes 57 and 61 with the low two bits clear.
let private parseFPPair op bin =
  let frp = getFPPairRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let mem = (dsDisp bin, ra) |> OprMem (* ds (rA) *)
  struct (op, TwoOperands(frp, mem))
/// <summary>
/// lq rTp, DQ(rA), which loads an even-odd register pair: an odd rTp, or one
/// that rA names too -- r0 with rA = 0 included -- is an invalid form the
/// processor refuses (Book I 3.3.4). The displacement is a 12-bit signed
/// field the encoding leaves scaled by sixteen, and the four bits below it
/// are reserved.
/// </summary>
let private parseLQ bin =
  let rt = Bits.extract bin 25u 21u
  let ra = Bits.extract bin 20u 16u
  if rt % 2u <> 0u || rt = ra then
    raise ParsingFailureException
  else
    let disp =
      Bits.extract bin 15u 4u <<< 4 |> uint64 |> Bits.signExtend 16 64
      |> int64 |> int32
    let mem = (disp, getRegister ra) |> OprMem (* dq (rA) *)
    struct (Op.LQ, TwoOperands(getRegister rt |> OprReg, mem))

/// The ISA 3.0 DS-form loads of primary opcode 57: lxsd, which names a vector
/// register (VSR32-63) by its five-bit number, and lxssp, which ParsingVSX
/// decodes. The other encoding is lfdp, which is not modeled.
let private parse39 bin =
  let vrt = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let mem = (dsDisp bin, ra) |> OprMem (* ds (rA) *)
  match Bits.extract bin 1u 0u with
  | 0b10u -> struct (Op.LXSD, TwoOperands(vrt, mem))
  | _ -> parseVSX39 bin

/// The DS-form loads: ld, ldu and lwa, told apart by the low two bits.
let private parse3A bin =
  let rd = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let mem = (dsDisp bin, ra) |> OprMem (* ds (rA) *)
  match Bits.extract bin 1u 0u with
  | 0b00u -> struct (Op.LD, TwoOperands(rd, mem))
  | 0b01u -> struct (Op.LDU, TwoOperands(rd, mem))
  | 0b10u -> struct (Op.LWA, TwoOperands(rd, mem))
  | _ (* 11 *) -> raise ParsingFailureException

/// The ISA 3.0 DS-form stores of primary opcode 61: stxsd here, and stxssp
/// and the DQ-form lxv and stxv in ParsingVSX. The other encoding is stfdp,
/// which is not modeled.
let private parse3D bin =
  let vrs = getVecRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let mem = (dsDisp bin, ra) |> OprMem (* ds (rA) *)
  match Bits.extract bin 1u 0u with
  | 0b10u -> struct (Op.STXSD, TwoOperands(vrs, mem))
  | _ -> parseVSX3D bin

/// The DS-form stores: std, stdu and stq. stq stores an even-odd register
/// pair, so an odd rSp is an invalid form.
let private parse3E bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u)
  let mem = (dsDisp bin, ra) |> OprMem (* ds (rA) *)
  match Bits.extract bin 1u 0u with
  | 0b00u -> struct (Op.STD, TwoOperands(rs, mem))
  | 0b01u -> struct (Op.STDU, TwoOperands(rs, mem))
  | 0b10u when Bits.pick bin 21u = 0u -> struct (Op.STQ, TwoOperands(rs, mem))
  | _ -> raise ParsingFailureException

/// The rotate-left-doubleword forms. In an MD form the six-bit mask bound and
/// shift amount are both split: the bound keeps its high bit in bit 5, and the
/// shift its sixth bit in bit 1. An MDS form takes the shift from rB instead,
/// so only the bound is split.
let private parse1E bin =
  let rs = getRegister (Bits.extract bin 25u 21u) |> OprReg
  let ra = getRegister (Bits.extract bin 20u 16u) |> OprReg
  let bound = (Bits.pick bin 5u <<< 5) ||| Bits.extract bin 10u 6u
  let bound = bound |> uint64 |> OprImm
  let sh = (Bits.pick bin 1u <<< 5) ||| Bits.extract bin 15u 11u
  let sh = sh |> uint64 |> OprImm
  let rb = getRegister (Bits.extract bin 15u 11u) |> OprReg
  let dot = Bits.pick bin 0u = 1u
  match Bits.extract bin 4u 2u with
  | 0b000u ->
    let op = if dot then Op.RLDICLdot else Op.RLDICL
    struct (op, FourOperands(ra, rs, sh, bound))
  | 0b001u ->
    let op = if dot then Op.RLDICRdot else Op.RLDICR
    struct (op, FourOperands(ra, rs, sh, bound))
  | 0b010u ->
    let op = if dot then Op.RLDICdot else Op.RLDIC
    struct (op, FourOperands(ra, rs, sh, bound))
  | 0b011u ->
    let op = if dot then Op.RLDIMIdot else Op.RLDIMI
    struct (op, FourOperands(ra, rs, sh, bound))
  | 0b100u when Bits.pick bin 1u = 0u ->
    let op = if dot then Op.RLDCLdot else Op.RLDCL
    struct (op, FourOperands(ra, rs, rb, bound))
  | 0b100u ->
    let op = if dot then Op.RLDCRdot else Op.RLDCR
    struct (op, FourOperands(ra, rs, rb, bound))
  | _ ->
    raise ParsingFailureException

(* The primary opcodes below hold only 64-bit forms, so a 32-bit guest must not
   recognize them; the extended-opcode space of 0x1F is shared, and parse1F
   takes the word size to decide how much of it to look at. *)
let private parseInstruction bitLen bin addr =
  match Bits.extract bin 31u 26u with
  | 0x2u when bitLen = 64 -> parseTDI bitLen bin
  | 0x3u -> parseTWI bitLen bin
  | 0x4u -> parse04 bitLen bin
  | 0x6u -> parse06 bin
  | 0x7u -> parseMULLI bitLen bin
  | 0x8u -> parseSUBFIC bitLen bin
  | 0xAu -> parseCMPLI bin
  | 0xBu -> parseCMPI bitLen bin
  | 0xCu -> parseADDIC bitLen bin
  | 0xDu -> parseADDICdot bitLen bin
  | 0xEu -> parseADDI bitLen bin
  | 0xFu -> parseADDIS bitLen bin
  | 0x10u -> parseBCx bitLen bin
  | 0x11u when Bits.pick bin 0u = 0u -> parseSC bin
  | 0x11u when bitLen = 64 && Bits.extract bin 1u 0u = 1u -> parseSCV bin
  | 0x12u -> parseBx bitLen bin addr
  | 0x13u -> parse13 bitLen bin
  | 0x14u -> parseRLWIMIx bin
  | 0x15u -> parseRLWINMx bin
  | 0x17u -> parseRLWNMx bin
  | 0x18u -> parseORI bin
  | 0x19u -> parseORIS bin
  | 0x1Au -> parseXORI bin
  | 0x1Bu -> parseXORIS bin
  | 0x1Cu -> parseANDIdot bin
  | 0x1Du -> parseANDISdot bin
  | 0x1Eu when bitLen = 64 -> parse1E bin
  | 0x1Fu -> parse1F (bitLen = 64) bin
  | 0x20u -> parseLWZ bin
  | 0x21u -> parseLWZU bin
  | 0x22u -> parseLBZ bin
  | 0x23u -> parseLBZU bin
  | 0x24u -> parseSTW bin
  | 0x25u -> parseSTWU bin
  | 0x26u -> parseSTB bin
  | 0x27u -> parseSTBU bin
  | 0x28u -> parseLHZ bin
  | 0x29u -> parseLHZU bin
  | 0x2Au -> parseLHA bin
  | 0x2Bu -> parseLHAU bin
  | 0x2Cu -> parseSTH bin
  | 0x2Du -> parseSTHU bin
  | 0x2Eu -> parseLMW bin
  | 0x2Fu -> parseSTMW bin
  | 0x30u -> parseLFS bin
  | 0x31u -> parseLFSU bin
  | 0x32u -> parseLFD bin
  | 0x33u -> parseLFDU bin
  | 0x34u -> parseSTFS bin
  | 0x35u -> parseSTFSU bin
  | 0x36u -> parseSTFD bin
  | 0x37u -> parseSTFDU bin
  | 0x38u when bitLen = 64 -> parseLQ bin
  | 0x39u when Bits.extract bin 1u 0u = 0u -> parseFPPair Op.LFDP bin
  | 0x39u when bitLen = 64 -> parse39 bin
  | 0x3Au when bitLen = 64 -> parse3A bin
  | 0x3Bu -> parse3B bin
  | 0x3Cu -> parse3C bin
  | 0x3Du when Bits.extract bin 1u 0u = 0u -> parseFPPair Op.STFDP bin
  | 0x3Du when bitLen = 64 -> parse3D bin
  | 0x3Eu when bitLen = 64 -> parse3E bin
  | 0x3Fu -> parse3F bin
  | _ -> raise ParsingFailureException

let parse lifter category (span: ByteSpan) (reader: IBinReader) addr rt =
  let bin = reader.ReadUInt32(span, 0)
  let struct (opcode, operands) =
    match tryParse category (int rt) bin with
    | ValueSome parsed ->
      parsed
    | ValueNone ->
      match ParsingSPE.tryParse category bin with
      | ValueSome parsed -> parsed
      | ValueNone -> parseInstruction (int rt) bin addr
  Instruction(addr, 4u, opcode, operands, rt, 0UL, lifter)

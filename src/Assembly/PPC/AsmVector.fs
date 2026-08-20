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
/// Encodes the instructions on the wide registers.
///
/// There are two sets of them. The older names its registers in five bits the
/// way the general registers are named; the newer widens the floating-point
/// registers instead and reaches twice as many, so its register numbers are six
/// bits wide and keep their highest bit at the very end of the instruction --
/// which is why the bits an integer form leaves reserved are not reserved here.
/// </summary>
module internal B2R2.Assembly.PPC.AsmVector

open B2R2.FrontEnd.PPC
open B2R2.Assembly.PPC.ParserHelper
open B2R2.Assembly.PPC.AsmField

/// A VMX load or store indexed, which names a vector register where the
/// integer form beside it names a general one.
let private vmxIndexed xo ins =
  match ins.Operands with
  | [ Rg v; Rg a; Rg b ] -> xForm 31u (vr v) (gpr a) (gpr b) xo 0u
  | _ -> wrongOperands ins

/// A VSX load or store indexed, and the moves between a vector-scalar register
/// and the general ones, which all keep the sixth bit of the register number at
/// the very end of the instruction.
let private vsxIndexed xo ins =
  match ins.Operands with
  | [ Rg x; Rg a; Rg b ] ->
    let n = vsr x
    word 31u (n &&& 0x1Fu) (gpr a) (gpr b) ((xo <<< 1) ||| (n >>> 5))
  | [ Rg x; Rg a ] ->
    let n = vsr x
    word 31u (n &&& 0x1Fu) (gpr a) 0u ((xo <<< 1) ||| (n >>> 5))
  | _ ->
    wrongOperands ins

/// A VX-form "vD, vA, vB".
let private vx xo ins =
  match ins.Operands with
  | [ Rg d; Rg a; Rg b ] -> word 4u (vr d) (vr a) (vr b) xo
  | _ -> wrongOperands ins

/// A VX-form "vD, vB", whose middle field no register fills.
let private vx2 xo ins =
  match ins.Operands with
  | [ Rg d; Rg b ] -> word 4u (vr d) 0u (vr b) xo
  | _ -> wrongOperands ins

/// A VX-form "vD, SIM", which fills every element of a register with the same
/// small signed number.
let private vxSplatImm xo ins =
  match ins.Operands with
  | [ Rg d; Im v ] -> word 4u (vr d) (signed 5 (int64 v)) 0u xo
  | _ -> wrongOperands ins

/// A VX-form "vD, vB, UIM", whose number says which element of the source to
/// fill the whole of the destination with.
let private vxSplat xo ins =
  match ins.Operands with
  | [ Rg d; Rg b; Im u ] -> word 4u (vr d) (unsigned 5 u) (vr b) xo
  | _ -> wrongOperands ins

/// A VX-form naming one vector register, which is how the register saying what
/// the unit is to do is read and written.
let private vxOne xo ins =
  match ins.Operands with
  | [ Rg v ] -> word 4u (vr v) 0u 0u xo
  | _ -> wrongOperands ins

/// A VA-form "vD, vA, vB, vC".
let private va xo ins =
  match ins.Operands with
  | [ Rg d; Rg a; Rg b; Rg c ] ->
    word 4u (vr d) (vr a) (vr b) (((vr c) <<< 6) ||| xo)
  | _ ->
    wrongOperands ins

/// vsldoi, a VA-form whose fourth operand says how far to shift rather than
/// naming a register.
let private vaShift ins =
  match ins.Operands with
  | [ Rg d; Rg a; Rg b; Im sh ] ->
    word 4u (vr d) (vr a) (vr b) (((unsigned 4 sh) <<< 6) ||| 44u)
  | _ ->
    wrongOperands ins

/// A VC-form comparison, whose record bit sits above its extended opcode
/// rather than below it.
let private vc xo rc ins =
  match ins.Operands with
  | [ Rg d; Rg a; Rg b ] -> word 4u (vr d) (vr a) (vr b) ((rc <<< 10) ||| xo)
  | _ -> wrongOperands ins

/// One word naming vector-scalar registers, given what fills the bits below
/// the registers and the three six-bit register numbers.
let private vsxWord rest t a b =
  let tail = rest ||| ((a >>> 5) <<< 2) ||| ((b >>> 5) <<< 1) ||| (t >>> 5)
  word 60u (t &&& 0x1Fu) (a &&& 0x1Fu) (b &&& 0x1Fu) tail

/// An XX3-form "xT, xA, xB".
let private xx3 xo ins =
  match ins.Operands with
  | [ Rg t; Rg a; Rg b ] -> vsxWord (xo <<< 3) (vsr t) (vsr a) (vsr b)
  | _ -> wrongOperands ins

/// An XX3-form comparison, which reports in a field of the condition register
/// rather than in a vector-scalar one.
let private xx3Compare xo ins =
  match ins.Operands with
  | [ Rg f; Rg a; Rg b ] -> vsxWord (xo <<< 3) ((crf f) <<< 2) (vsr a) (vsr b)
  | _ -> wrongOperands ins

/// xxpermdi and xxsldwi, whose fourth operand says which halves or which words
/// of the two sources to take and lies inside the extended opcode.
let private xx3Pick xo ins =
  match ins.Operands with
  | [ Rg t; Rg a; Rg b; Im n ] ->
    let extended = ((unsigned 2 n) <<< 5) ||| xo
    vsxWord (extended <<< 3) (vsr t) (vsr a) (vsr b)
  | _ ->
    wrongOperands ins

/// An XX2-form "xT, xB", whose extended opcode is a bit wider because only two
/// of the register-extension bits follow it.
let private xx2 xo ins =
  match ins.Operands with
  | [ Rg t; Rg b ] -> vsxWord (xo <<< 2) (vsr t) 0u (vsr b)
  | _ -> wrongOperands ins

/// xxspltw, an XX2 form whose spare field says which word to take.
let private xx2Splat ins =
  match ins.Operands with
  | [ Rg t; Rg b; Im u ] -> vsxWord (164u <<< 2) (vsr t) (unsigned 2 u) (vsr b)
  | _ -> wrongOperands ins

/// xxspltib, whose byte to fill a register with straddles the two fields the
/// other forms keep registers in.
let private xx2SplatByte ins =
  match ins.Operands with
  | [ Rg t; Im v ] ->
    let imm = unsigned 8 v
    let n = vsr t
    let tail = (180u <<< 2) ||| (n >>> 5)
    word 60u (n &&& 0x1Fu) (imm >>> 3) ((imm &&& 0x7u) <<< 2) tail
  | _ ->
    wrongOperands ins

/// The loads and the stores of a wide register, and the moves between one and
/// the general registers.
let private wideMemoryEncoders () =
  [ Op.LVSL, vmxIndexed 6u
    Op.LVEBX, vmxIndexed 7u
    Op.LVSR, vmxIndexed 38u
    Op.LVEHX, vmxIndexed 39u
    Op.LVEWX, vmxIndexed 71u
    Op.LVX, vmxIndexed 103u
    Op.STVEBX, vmxIndexed 135u
    Op.STVEHX, vmxIndexed 167u
    Op.STVEWX, vmxIndexed 199u
    Op.STVX, vmxIndexed 231u
    Op.LVXL, vmxIndexed 359u
    Op.STVXL, vmxIndexed 487u
    Op.LXVDSX, vsxIndexed 332u
    Op.LXSDX, vsxIndexed 588u
    Op.STXSDX, vsxIndexed 716u
    Op.LXVW4X, vsxIndexed 780u
    Op.LXVD2X, vsxIndexed 844u
    Op.STXVW4X, vsxIndexed 908u
    Op.STXVD2X, vsxIndexed 972u
    Op.MFVSRD, vsxIndexed 51u
    Op.MFVSRWZ, vsxIndexed 115u
    Op.MTVSRD, vsxIndexed 179u
    Op.MTVSRWA, vsxIndexed 211u
    Op.MTVSRWZ, vsxIndexed 243u
    Op.MFVSRLD, vsxIndexed 307u
    Op.MTVSRDD, vsxIndexed 435u ]

/// The instructions that work on every element of a vector at once: the
/// arithmetic, the logic, the shifts, and the ones that pick a smaller or a
/// larger element of two.
let private elementwiseEncoders () =
  [ Op.VADDUBM, vx 0u
    Op.VADDUHM, vx 64u
    Op.VADDUWM, vx 128u
    Op.VADDUDM, vx 192u
    Op.VSUBUBM, vx 1024u
    Op.VSUBUHM, vx 1088u
    Op.VSUBUWM, vx 1152u
    Op.VSUBUDM, vx 1216u
    Op.VMAXUB, vx 2u
    Op.VMAXUH, vx 66u
    Op.VMAXUW, vx 130u
    Op.VMAXUD, vx 194u
    Op.VMAXSB, vx 258u
    Op.VMAXSH, vx 322u
    Op.VMAXSW, vx 386u
    Op.VMAXSD, vx 450u
    Op.VMINUB, vx 514u
    Op.VMINUH, vx 578u
    Op.VMINUW, vx 642u
    Op.VMINUD, vx 706u
    Op.VMINSB, vx 770u
    Op.VMINSH, vx 834u
    Op.VMINSW, vx 898u
    Op.VMINSD, vx 962u
    Op.VRLB, vx 4u
    Op.VRLH, vx 68u
    Op.VRLW, vx 132u
    Op.VRLD, vx 196u
    Op.VSLB, vx 260u
    Op.VSLH, vx 324u
    Op.VSLW, vx 388u
    Op.VSLD, vx 1476u
    Op.VSRB, vx 516u
    Op.VSRH, vx 580u
    Op.VSRW, vx 644u
    Op.VSRD, vx 1732u
    Op.VSRAB, vx 772u
    Op.VSRAH, vx 836u
    Op.VSRAW, vx 900u
    Op.VSRAD, vx 964u
    Op.VSL, vx 452u
    Op.VSR, vx 708u
    Op.VSLO, vx 1036u
    Op.VSRO, vx 1100u
    Op.VAND, vx 1028u
    Op.VANDC, vx 1092u
    Op.VOR, vx 1156u
    Op.VXOR, vx 1220u
    Op.VNOR, vx 1284u
    Op.VORC, vx 1348u
    Op.VNAND, vx 1412u
    Op.VEQV, vx 1668u ]

/// The instructions that move elements about rather than compute with them,
/// and the ones that count or gather what the bits of a vector say.
let private shuffleEncoders () =
  [ Op.VMRGHB, vx 12u
    Op.VMRGHH, vx 76u
    Op.VMRGHW, vx 140u
    Op.VMRGLB, vx 268u
    Op.VMRGLH, vx 332u
    Op.VMRGLW, vx 396u
    Op.VMRGOW, vx 1676u
    Op.VMRGEW, vx 1932u
    Op.VPKUHUM, vx 14u
    Op.VPKUWUM, vx 78u
    Op.VBPERMQ, vx 1356u
    Op.VUPKHSB, vx2 526u
    Op.VUPKHSH, vx2 590u
    Op.VUPKLSB, vx2 654u
    Op.VUPKLSH, vx2 718u
    Op.VGBBD, vx2 1292u
    Op.VCLZB, vx2 1794u
    Op.VCLZH, vx2 1858u
    Op.VCLZW, vx2 1922u
    Op.VCLZD, vx2 1986u
    Op.VPOPCNTB, vx2 1795u
    Op.VPOPCNTH, vx2 1859u
    Op.VPOPCNTW, vx2 1923u
    Op.VPOPCNTD, vx2 1987u
    Op.VSPLTB, vxSplat 524u
    Op.VSPLTH, vxSplat 588u
    Op.VSPLTW, vxSplat 652u
    Op.VSPLTISB, vxSplatImm 780u
    Op.VSPLTISH, vxSplatImm 844u
    Op.VSPLTISW, vxSplatImm 908u
    Op.MFVSCR, vxOne 1540u
    Op.MTVSCR, vxOne 1604u
    Op.VSEL, va 42u
    Op.VPERM, va 43u
    Op.VSLDOI, vaShift ]

/// The comparisons, each of which is written both with and without the bit
/// that records what it found.
let private vectorCompareEncoders () =
  List.concat
    [ recording vc 6u Op.VCMPEQUB Op.VCMPEQUBdot
      recording vc 70u Op.VCMPEQUH Op.VCMPEQUHdot
      recording vc 134u Op.VCMPEQUW Op.VCMPEQUWdot
      recording vc 199u Op.VCMPEQUD Op.VCMPEQUDdot
      recording vc 518u Op.VCMPGTUB Op.VCMPGTUBdot
      recording vc 582u Op.VCMPGTUH Op.VCMPGTUHdot
      recording vc 646u Op.VCMPGTUW Op.VCMPGTUWdot
      recording vc 711u Op.VCMPGTUD Op.VCMPGTUDdot
      recording vc 774u Op.VCMPGTSB Op.VCMPGTSBdot
      recording vc 838u Op.VCMPGTSH Op.VCMPGTSHdot
      recording vc 902u Op.VCMPGTSW Op.VCMPGTSWdot
      recording vc 967u Op.VCMPGTSD Op.VCMPGTSDdot ]

/// The instructions on the vector-scalar registers: the logic on a whole
/// register, the ones that shuffle its halves and its words, and the arithmetic
/// on the one double-precision number it holds.
let private scalarVectorEncoders () =
  [ Op.XSADDDP, xx3 32u
    Op.XSSUBDP, xx3 40u
    Op.XSDIVDP, xx3 56u
    Op.XSCPSGNDP, xx3 176u
    Op.XSCMPUDP, xx3Compare 35u
    Op.XXLAND, xx3 130u
    Op.XXLANDC, xx3 138u
    Op.XXLOR, xx3 146u
    Op.XXLXOR, xx3 154u
    Op.XXLNOR, xx3 162u
    Op.XXLORC, xx3 170u
    Op.XXLNAND, xx3 178u
    Op.XXLEQV, xx3 186u
    Op.XXPERMDI, xx3Pick 10u
    Op.XXSLDWI, xx3Pick 2u
    Op.XXSPLTW, xx2Splat
    Op.XXSPLTIB, xx2SplatByte
    Op.XSCVDPSPN, xx2 267u
    Op.XSRSP, xx2 281u
    Op.XSCVSPDPN, xx2 331u
    Op.XSABSDP, xx2 345u ]

/// Every instruction on the wide registers.
let vectorEncoders () =
  List.concat
    [ wideMemoryEncoders ()
      elementwiseEncoders ()
      shuffleEncoders ()
      vectorCompareEncoders ()
      scalarVectorEncoders () ]

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

module B2R2.FrontEnd.BinLifter.ARM64.Parser

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.ARM64.Utils
open B2R2.FrontEnd.BinLifter.ARM64.OperandHelper

/// Opcode functions
let getOpcodeByQ bin op1 op2 = if valQ bin = 0u then op1 else op2

/// Operand functions
// One operand
let getOptionOrimm bin = OneOperand (optionOrimm bin)

// Two operands
(** Register - Register **)
let getWdWn bin = TwoOperands (wd bin, wn bin)
let getXdXn bin = TwoOperands (xd bin, xn bin)
let getWdSn bin = TwoOperands (wd bin, sn bin)
let getWdDn bin = TwoOperands (wd bin, dn bin)
let getXdSn bin = TwoOperands (xd bin, sn bin)
let getXdDn bin = TwoOperands (xd bin, dn bin)
let getSdWn bin = TwoOperands (sd bin, wn bin)
let getDdWn bin = TwoOperands (dd bin, wn bin)
let getSdXn bin = TwoOperands (sd bin, xn bin)
let getDdXn bin = TwoOperands (dd bin, xn bin)
let getSdSn bin = TwoOperands (sd bin, sn bin)
let getDdDn bin = TwoOperands (dd bin, dn bin)
let getDdSn bin = TwoOperands (dd bin, sn bin)
let getHdSn bin = TwoOperands (hd bin, sn bin)
let getSdDn bin = TwoOperands (sd bin, dn bin)
let getHdDn bin = TwoOperands (hd bin, dn bin)
let getSdHn bin = TwoOperands (sd bin, hn bin)
let getDdHn bin = TwoOperands (dd bin, hn bin)
let getDnDm bin = TwoOperands (dn bin, dm bin)
let getSnSm bin = TwoOperands (sn bin, sm bin)
let getXdVnD1 bin = TwoOperands (xd bin, vnD1 bin)
let getVdVnt1 bin r = r bin; TwoOperands (vd1 bin, vntsq1 bin)
let getVdVnt2 bin r = r bin; TwoOperands (vd2 bin, vntsq1 bin)
let getVdVnt3 bin r = r bin; TwoOperands (vd3a bin, vntszq1 bin)
let getVdVnt4 bin r = r bin; TwoOperands (vd2 bin, vnts2 bin)
let getVdVnt5 bin = TwoOperands (vd3a bin, vntsz3 bin)
let getVdD1Xn bin = TwoOperands (vdD1 bin, xn bin)
let getVd16BVn16B bin = TwoOperands (vd16B bin, vn16B bin)
let getVdVn bin r = r bin; TwoOperands (vd2 bin, vn2 bin)
let getVdVn2 bin = TwoOperands (vd3a bin, vn3 bin)
let getVbdVan bin r = r bin; TwoOperands (vd2 bin, vn1 bin)
let getVbdVan2 bin r = r bin; TwoOperands (vd3b bin, vn3 bin)
let getVdtVnt bin r = r bin; TwoOperands (vdtsq1 bin, vntsq1 bin)
let getVdtVnt2 bin r = r bin; TwoOperands (vdtszq1 bin, vntszq1 bin)
let getVdtVnt3 bin = TwoOperands (vdtq1 bin, vntq1 bin)
let getVdtaVntb bin r = r bin; TwoOperands (vdtsq2 bin, vntsq1 bin)
let getVdtaVntb2 bin = TwoOperands (vdtsz1 bin, vntszq2 bin)
let getVdtbVnta bin r = r bin; TwoOperands (vdtsq1 bin, vnts1 bin)
let getVdtbVnta2 bin r = r bin; TwoOperands (vdtszq2 bin, vntsz1 bin)
let getVd4SVn4S bin = TwoOperands (vd4S bin, vn4S bin)
let getVdtVntsidx bin = TwoOperands (vdti5q bin, vtsidx1 bin valN)
let getVdtRn bin = TwoOperands (vdti5q bin, rn bin)
let getWdVntsidx bin r = r bin; TwoOperands (wd bin, vtsidx1 bin valN)
let getXdVntsidx bin r = r bin; TwoOperands (xd bin, vtsidx1 bin valN)
let getVdtsidxRn bin = TwoOperands (vtsidx1 bin valD, rn bin)
let getVdtsidx1Vntsidx2 bin = TwoOperands (vtsidx1 bin valD, vtsidx2 bin valN)
let getVdVntidx bin = TwoOperands (vd4 bin, vntidx bin)

(** Register - Immediate **)
let getSnP0 bin = TwoOperands (sn bin, p0)
let getDnP0 bin = TwoOperands (dn bin, p0)
let getSdImm8 bin = TwoOperands (sd bin, fScalarImm8 bin)
let getDdImm8 bin = TwoOperands (dd bin, fScalarImm8 bin)
let getDdImm bin = TwoOperands (dd bin, imm64 bin)
let getVd2DImm bin = TwoOperands (vd2D bin, imm64 bin)
let getVdtFImm bin = TwoOperands (vdtq2 bin, fVecImm8 bin)
let getVd2DFImm bin = TwoOperands (vd2D bin, fVecImm8 bin)

(** Register - Memory **)
let getWtMXSn bin = TwoOperands (wt1 bin, memXSn bin)
let getXtMXSn bin = TwoOperands (xt1 bin, memXSn bin)
let getWtBIXSnpimm bin scale = TwoOperands (wt1 bin, memXSnPimm bin scale)
let getXtBIXSnpimm bin scale = TwoOperands (xt1 bin, memXSnPimm bin scale)
let getBtBIXSnpimm bin = TwoOperands (bt bin, memXSnPimm bin 1u)
let getHtBIXSnpimm bin = TwoOperands (ht bin, memXSnPimm bin 2u)
let getStBIXSnpimm bin = TwoOperands (st1 bin, memXSnPimm bin 4u)
let getDtBIXSnpimm bin = TwoOperands (dt1 bin, memXSnPimm bin 8u)
let getQtBIXSnpimm bin = TwoOperands (qt1 bin, memXSnPimm bin 16u)
let getPrfopimm5BIXSnpimm bin = TwoOperands (prfopImm5 bin, memXSnPimm bin 8u)
let getWt1Wt2BIXSnimm b scl = ThreeOperands (wt1 b, wt2 b, memXSnSimm7 b scl)
let getXt1Xt2BIXSnimm b scl = ThreeOperands (xt1 b, xt2 b, memXSnSimm7 b scl)
let getSt1St2BIXSnimm b scl = ThreeOperands (st1 b, st2 b, memXSnSimm7 b scl)
let getDt1Dt2BIXSnimm b scl = ThreeOperands (dt1 b, dt2 b, memXSnSimm7 b scl)
let getQt1Qt2BIXSnimm b scl = ThreeOperands (qt1 b, qt2 b, memXSnSimm7 b scl)
let getVt1tMXSn bin r = r bin; TwoOperands (vt1t bin, memXSn bin)
let getVt2tMXSn bin r = r bin; TwoOperands (vt2t bin, memXSn bin)
let getVt3tMXSn bin r = r bin; TwoOperands (vt3t bin, memXSn bin)
let getVt4tMXSn bin r = r bin; TwoOperands (vt4t bin, memXSn bin)

let getvtntidxMXSn bin t n = TwoOperands (vtntidx bin t n, memXSn bin)
let getVt1BidxMXSn bin = getvtntidxMXSn bin VecB 1u
let getVt2BidxMXSn bin = getvtntidxMXSn bin VecB 2u
let getVt3BidxMXSn bin = getvtntidxMXSn bin VecB 3u
let getVt4BidxMXSn bin = getvtntidxMXSn bin VecB 4u
let getVt1HidxMXSn bin = getvtntidxMXSn bin VecH 1u
let getVt2HidxMXSn bin = getvtntidxMXSn bin VecH 2u
let getVt3HidxMXSn bin = getvtntidxMXSn bin VecH 3u
let getVt4HidxMXSn bin = getvtntidxMXSn bin VecH 4u
let getVt1SidxMXSn bin = getvtntidxMXSn bin VecS 1u
let getVt2SidxMXSn bin = getvtntidxMXSn bin VecS 2u
let getVt3SidxMXSn bin = getvtntidxMXSn bin VecS 3u
let getVt4SidxMXSn bin = getvtntidxMXSn bin VecS 4u
let getVt1DidxMXSn bin = getvtntidxMXSn bin VecD 1u
let getVt2DidxMXSn bin = getvtntidxMXSn bin VecD 2u
let getVt3DidxMXSn bin = getvtntidxMXSn bin VecD 3u
let getVt4DidxMXSn bin = getvtntidxMXSn bin VecD 4u
let getWtBIXSnsimm bin = TwoOperands (wt1 bin, memXSnSimm9 bin)
let getXtBIXSnsimm bin = TwoOperands (xt1 bin, memXSnSimm9 bin)
let getBtBIXSnsimm bin = TwoOperands (bt bin, memXSnSimm9 bin)
let getHtBIXSnsimm bin = TwoOperands (ht bin, memXSnSimm9 bin)
let getStBIXSnsimm bin = TwoOperands (st1 bin, memXSnSimm9 bin)
let getDtBIXSnsimm bin = TwoOperands (dt1 bin, memXSnSimm9 bin)
let getQtBIXSnsimm bin = TwoOperands (qt1 bin, memXSnSimm9 bin)
let getPrfopimm5BIXSnsimm bin = TwoOperands (prfopImm5 bin, memXSnSimm9 bin)
let getWtBEXSnrmamt bin amt = TwoOperands (wt1 bin, memExtXSnRmAmt bin amt)
let getWtBRXSnxmamt bin = TwoOperands (wt1 bin, memShfXSnXmAmt bin 0L)
let getXtBEXSnrmamt bin amt = TwoOperands (xt1 bin, memExtXSnRmAmt bin amt)
let getXtBRXSnxmamt bin = TwoOperands (xt1 bin, memShfXSnXmAmt bin 0L)
let getBtBEXSnrmamt bin = TwoOperands (bt bin, memExtXSnRmAmt bin 0L)
let getBtBRXSnxmamt bin = TwoOperands (bt bin, memShfXSnXmAmt bin 0L)
let getHtBEXSnrmamt bin = TwoOperands (ht bin, memExtXSnRmAmt bin 1L)
let getStBEXSnrmamt bin = TwoOperands (st1 bin, memExtXSnRmAmt bin 2L)
let getDtBEXSnrmamt bin = TwoOperands (dt1 bin, memExtXSnRmAmt bin 3L)
let getQtBEXSnrmamt bin = TwoOperands (qt1 bin, memExtXSnRmAmt bin 4L)
let getPrfopimm5BEXSnrmamt b = TwoOperands (prfopImm5 b, memExtXSnRmAmt b 3L)
let getWtPoXSnsimm bin = TwoOperands (wt1 bin, memPostXSnSimm bin)
let getXtPoXSnsimm bin = TwoOperands (xt1 bin, memPostXSnSimm bin)
let getBtPoXSnsimm bin = TwoOperands (bt bin, memPostXSnSimm bin)
let getHtPoXSnsimm bin = TwoOperands (ht bin, memPostXSnSimm bin)
let getStPoXSnsimm bin = TwoOperands (st1 bin, memPostXSnSimm bin)
let getDtPoXSnsimm bin = TwoOperands (dt1 bin, memPostXSnSimm bin)
let getQtPoXSnsimm bin = TwoOperands (qt1 bin, memPostXSnSimm bin)
let getWt1Wt2PoXSnimm b = ThreeOperands (wt1 b, wt2 b, memPostXSnImm b 2)
let getXt1Xt2PoXSnimm b s = ThreeOperands (xt1 b, xt2 b, memPostXSnImm b s)
let getSt1St2PoXSnimm b = ThreeOperands (st1 b, st2 b, memPostXSnImm b 2)
let getDt1Dt2PoXSnimm b = ThreeOperands (dt1 b, dt2 b, memPostXSnImm b 3)
let getQt1Qt2PoXSnimm b = ThreeOperands (qt1 b, qt2 b, memPostXSnImm b 4)
let getWtPrXSnsimm bin = TwoOperands (wt1 bin, memPreXSnSimm bin)
let getXtPrXSnsimm bin = TwoOperands (xt1 bin, memPreXSnSimm bin)
let getBtPrXSnsimm bin = TwoOperands (bt bin, memPreXSnSimm bin)
let getHtPrXSnsimm bin = TwoOperands (ht bin, memPreXSnSimm bin)
let getStPrXSnsimm bin = TwoOperands (st1 bin, memPreXSnSimm bin)
let getDtPrXSnsimm bin = TwoOperands (dt1 bin, memPreXSnSimm bin)
let getQtPrXSnsimm bin = TwoOperands (qt1 bin, memPreXSnSimm bin)
let getWt1Wt2PrXSnimm bin = ThreeOperands (wt1 bin, wt2 bin, memPreXSnImm bin 2)
let getXt1Xt2PrXSnimm b s = ThreeOperands (xt1 b, xt2 b, memPreXSnImm b s)
let getSt1St2PrXSnimm bin = ThreeOperands (st1 bin, st2 bin, memPreXSnImm bin 2)
let getDt1Dt2PrXSnimm bin = ThreeOperands (dt1 bin, dt2 bin, memPreXSnImm bin 3)
let getQt1Qt2PrXSnimm bin = ThreeOperands (qt1 bin, qt2 bin, memPreXSnImm bin 4)

let getvtntidxPoXSnXm b t n = TwoOperands (vtntidx b t n, memPostRegXSnxm b)
let getVt1BidxPoXSnXm bin = getvtntidxPoXSnXm bin VecB 1u
let getVt2BidxPoXSnXm bin = getvtntidxPoXSnXm bin VecB 2u
let getVt3BidxPoXSnXm bin = getvtntidxPoXSnXm bin VecB 3u
let getVt4BidxPoXSnXm bin = getvtntidxPoXSnXm bin VecB 4u
let getVt1HidxPoXSnXm bin = getvtntidxPoXSnXm bin VecH 1u
let getVt2HidxPoXSnXm bin = getvtntidxPoXSnXm bin VecH 2u
let getVt3HidxPoXSnXm bin = getvtntidxPoXSnXm bin VecH 3u
let getVt4HidxPoXSnXm bin = getvtntidxPoXSnXm bin VecH 4u
let getVt1SidxPoXSnXm bin = getvtntidxPoXSnXm bin VecS 1u
let getVt2SidxPoXSnXm bin = getvtntidxPoXSnXm bin VecS 2u
let getVt3SidxPoXSnXm bin = getvtntidxPoXSnXm bin VecS 3u
let getVt4SidxPoXSnXm bin = getvtntidxPoXSnXm bin VecS 4u
let getVt1DidxPoXSnXm bin = getvtntidxPoXSnXm bin VecD 1u
let getVt2DidxPoXSnXm bin = getvtntidxPoXSnXm bin VecD 2u
let getVt3DidxPoXSnXm bin = getvtntidxPoXSnXm bin VecD 3u
let getVt4DidxPoXSnXm bin = getvtntidxPoXSnXm bin VecD 4u
let getVt1tPoXSnXm bin r = r bin; TwoOperands (vt1t bin, memPostRegXSnxm bin)
let getVt2tPoXSnXm bin r = r bin; TwoOperands (vt2t bin, memPostRegXSnxm bin)
let getVt3tPoXSnXm bin r = r bin; TwoOperands (vt3t bin, memPostRegXSnxm bin)
let getVt4tPoXSnXm bin r = r bin; TwoOperands (vt4t bin, memPostRegXSnxm bin)

let getvtntidxPoXSnImm b t n =
  TwoOperands (vtntidx b t n, memPostImmXSnimm b (iX t n))
let getVt1BidxPoXSnI1 bin = getvtntidxPoXSnImm bin VecB 1u
let getVt2BidxPoXSnI2 bin = getvtntidxPoXSnImm bin VecB 2u
let getVt3BidxPoXSnI3 bin = getvtntidxPoXSnImm bin VecB 3u
let getVt4BidxPoXSnI4 bin = getvtntidxPoXSnImm bin VecB 4u
let getVt1HidxPoXSnI2 bin = getvtntidxPoXSnImm bin VecH 1u
let getVt2HidxPoXSnI4 bin = getvtntidxPoXSnImm bin VecH 2u
let getVt3HidxPoXSnI6 bin = getvtntidxPoXSnImm bin VecH 3u
let getVt4HidxPoXSnI8 bin = getvtntidxPoXSnImm bin VecH 4u
let getVt1SidxPoXSnI4 bin = getvtntidxPoXSnImm bin VecS 1u
let getVt2SidxPoXSnI8 bin = getvtntidxPoXSnImm bin VecS 2u
let getVt3SidxPoXSnI12 bin = getvtntidxPoXSnImm bin VecS 3u
let getVt4SidxPoXSnI16 bin = getvtntidxPoXSnImm bin VecS 4u
let getVt1DidxPoXSnI8 bin = getvtntidxPoXSnImm bin VecD 1u
let getVt2DidxPoXSnI16 bin = getvtntidxPoXSnImm bin VecD 2u
let getVt3DidxPoXSnI24 bin = getvtntidxPoXSnImm bin VecD 3u
let getVt4DidxPoXSnI32 bin = getvtntidxPoXSnImm bin VecD 4u
let getVttPoXSnImm1 b r vt i =
  r b; TwoOperands (vt b, memPostImmXSnimm b (immQ b i))
let getVt1tPoXSnImm1 b r = getVttPoXSnImm1 b r vt1t 1L
let getVt2tPoXSnImm1 b r = getVttPoXSnImm1 b r vt2t 2L
let getVt3tPoXSnImm1 b r = getVttPoXSnImm1 b r vt3t 3L
let getVt4tPoXSnImm1 b r = getVttPoXSnImm1 b r vt4t 4L
let getVttPoXSnImm2 b vt i = TwoOperands (vt b, memPostImmXSnimm b (iN b i))
let getVt1tPoXSnImm2 b = getVttPoXSnImm2 b vt1t 1
let getVt2tPoXSnImm2 b = getVttPoXSnImm2 b vt2t 2
let getVt3tPoXSnImm2 b = getVttPoXSnImm2 b vt3t 3
let getVt4tPoXSnImm2 b = getVttPoXSnImm2 b vt4t 4

(** Register - Label **)
let getXdLabel bin amt = TwoOperands (xd bin, label bin amt) (* <xd>, <label> *)
let getWtLabel bin = TwoOperands (wt1 bin, lbImm19 bin) (* <Wt>, <label> *)
let getXtLabel bin = TwoOperands (xt1 bin, lbImm19 bin) (* <Xt>, <label> *)
let getStLabel bin = TwoOperands (st1 bin, lbImm19 bin) (* <St>, <label> *)
let getDtLabel bin = TwoOperands (dt1 bin, lbImm19 bin) (* <Dt>, <label> *)
let getQtLabel bin = TwoOperands (qt1 bin, lbImm19 bin) (* <Qt>, <label> *)
let getPrfopImm5Label bin =
  TwoOperands (prfopImm5 bin, lbImm19 bin) (* <prfop>|#<imm5>), <label> *)

(* etc *)
let getSysregOrctrlXt bin = TwoOperands (systemregOrctrl bin, xt1 bin)
let getXtSysregOrctrl bin = TwoOperands (xt1 bin, systemregOrctrl bin)
let getPstatefieldImm bin = TwoOperands (pstatefield bin, imm bin)

// Three Operands
(** Register - Register - Register **)
let getWdWnWm bin = ThreeOperands (wd bin, wn bin, wm bin)
let getWdWnXm bin = ThreeOperands (wd bin, wn bin, xm bin)
let getXdXnXm bin = ThreeOperands (xd bin, xn bin, xm bin)
let getVdtaVntbVmtb b r = r b; ThreeOperands (vdts1 b, vntsq1 b, vmtsq1 b)
let getVdtaVntaVmtb b r = r b; ThreeOperands (vdts1 b, vnts1 b, vmtsq1 b)
let getVdtbVntaVmta b r = r b; ThreeOperands (vdtsq1 b, vnts1 b, vmts1 b)
let getVdtVntVmt1 b r = r b; ThreeOperands (vdtsq1 b, vntsq1 b, vmtsq1 b)
let getVdtVntVmt2 b r = r b; ThreeOperands (vdtszq1 b, vntszq1 b, vmtszq1 b)
let getVdtVntVmt3 bin = ThreeOperands (vdtq1 bin, vntq1 bin, vmtq1 bin)
let getSdSnSm bin = ThreeOperands (sd bin, sn bin, sm bin)
let getDdDnDm bin = ThreeOperands (dd bin, dn bin, dm bin)
let getVdVnVm1 bin r = r bin; ThreeOperands (vd2 bin, vn2 bin, vm2 bin)
let getVdVnVm2 bin = ThreeOperands (vd3a bin, vn3 bin, vm3 bin)
let getVadVbnVbm bin r = r bin; ThreeOperands (vd1 bin, vn2 bin, vm2 bin)
let getQdSnVm4S bin = ThreeOperands (qd bin, sn bin, vm4S bin)
let getVd4SVn4SVm4S bin = ThreeOperands (vd4S bin, vn4S bin, vm4S bin)
let getQdQnVm4S bin = ThreeOperands (qd bin, qn bin, vm4S bin)
let getVdtVntVmt b r = r b; ThreeOperands (vdtsq1 b, vntsq1 b, vmtsq1 b)
let getVdtaVntbVmtsidx b r = r b; ThreeOperands (vdts1 b, vntsq1 b, vmtsidx1 b)
let getVdtVntVmtsidx1 bin r =  (* size:Q - 3bit *)
  r bin; ThreeOperands (vdtsq1 bin, vntsq1 bin, vmtsidx1 bin)
let getVdtVntVmtsidx2 bin r =  (* sz:Q - 2bit *)
  r bin; ThreeOperands (vdtszq1 bin, vntszq1 bin, vmtsidx2 bin)
let getVadVbnVmtsidx b r = r b; ThreeOperands (vd1 b, vn2 b, vmtsidx1 b)
let getVdVnVmtsidx1 b r = r b; ThreeOperands (vd2 b, vn2 b, vmtsidx1 b)
let getVdVnVmtsidx2 b r = r b; ThreeOperands (vd3a b, vn3 b, vmtsidx2 b)
let getVdtaVn116BVmta bin = ThreeOperands (vdtq1 bin, vn116B bin, vmtq1 bin)
let getVdtaVn216BVmta bin = ThreeOperands (vdtq1 bin, vn216B bin, vmtq1 bin)
let getVdtaVn316BVmta bin = ThreeOperands (vdtq1 bin, vn316B bin, vmtq1 bin)
let getVdtaVn416BVmta bin = ThreeOperands (vdtq1 bin, vn416B bin, vmtq1 bin)

(** Register - Register - Immediate **)
let getVdtVntI0 b r = r b; ThreeOperands (vdtsq1 b, vntsq1 b, OprImm 0L)
let getVdtVntF0 b r = r b; ThreeOperands (vdtszq1 b, vntszq1 b, OprFPImm 0.0)
let getWSdWnImm bin = ThreeOperands (wsd bin, wn bin, immNsr bin 32<rt>)
let getWdWnImm bin = ThreeOperands (wd bin, wn bin, immNsr bin 32<rt>)
let getXSdXnImm bin = ThreeOperands (xsd bin, xn bin, immNsr bin 64<rt>)
let getXdXnImm bin = ThreeOperands (xd bin, xn bin, immNsr bin 64<rt>)
let getVdVnI0 bin r = r bin; ThreeOperands (vd2 bin, vn2 bin, OprImm 0L)
let getVdVnF0 bin = ThreeOperands (vd3a bin, vn3 bin, OprFPImm 0.0)

(** Register - Register - Shift **)
let getVdtaVntbShf2 b r = r b; ThreeOperands (vdts1 b, vntsq1 b, lshf1 b)
let getVdVnShf bin r = r bin; ThreeOperands (vd5 bin, vn5 bin, rshfAmt bin)
let getVdVnShf2 bin r = r bin; ThreeOperands (vd5 bin, vn5 bin, lshfAmt bin)
let getVbdVanShf bin r = r bin; ThreeOperands (vd5 bin, vn6 bin, rshfAmt bin)

(** Register - Register - fbits **)
let getSdWnFbits bin = ThreeOperands (sd bin, wn bin, fbits2 bin)
let getWdSnFbits bin = ThreeOperands (wd bin, sn bin, fbits2 bin)
let getDdWnFbits bin = ThreeOperands (dd bin, wn bin, fbits2 bin)
let getWdDnFbits bin = ThreeOperands (wd bin, dn bin, fbits2 bin)
let getSdXnFbits bin = ThreeOperands (sd bin, xn bin, fbits2 bin)
let getXdSnFbits bin = ThreeOperands (xd bin, sn bin, fbits2 bin)
let getDdXnFbits bin = ThreeOperands (dd bin, xn bin, fbits2 bin)
let getXdDnFbits bin = ThreeOperands (xd bin, dn bin, fbits2 bin)
let getVdVnFbits bin r = r bin; ThreeOperands (vd5 bin, vn5 bin, fbits1 bin)

(** Register - Register - Memory **)
let getWsWtMXSn bin = ThreeOperands (ws bin, wt1 bin, memXSn bin)
let getXsXtMXSn bin = ThreeOperands (xs bin, xt1 bin, memXSn bin)
let getWsXtMXSn bin = ThreeOperands (ws bin, xt1 bin, memXSn bin)
let getWt1Wt2MXSn bin = ThreeOperands (wt1 bin, wt2 bin, memXSn bin)
let getXt1Xt2MXSn bin = ThreeOperands (xt1 bin, xt2 bin, memXSn bin)

(** Register - Immediate - Shift **)
let getVdtImm8LAmt bin oprVdt = function
  | Some s -> ThreeOperands (oprVdt bin, imm8 bin, s)
  | None -> TwoOperands (oprVdt bin, imm8 bin)
let getVdtImm8LAmt1 bin = getVdtImm8LAmt bin vdtq1 None (* 8-bit *)
let getVdtImm8LAmt2 bin = getVdtImm8LAmt bin vdtq3 (lAmt bin amt16Imm)
let getVdtImm8LAmt3 bin = getVdtImm8LAmt bin vdtq2 (lAmt bin amt32Imm)
let getVdtImm8MAmt bin = ThreeOperands (vdtq2 bin, imm8 bin, mAmt bin)
let getWdImmLShf bin = ThreeOperands (wd bin, imm16 bin, lshf3 bin)
let getXdImmLShf bin = ThreeOperands (xd bin, imm16 bin, lshf3 bin)
let getVdtVntShf1 bin = ThreeOperands (vdtihq bin, vntihq bin, rshfAmt bin)
let getVdtVntShf2 bin = ThreeOperands (vdtihq bin, vntihq bin, lshfAmt bin)
let getVdtbVntaShf b r = r b; ThreeOperands (vdtihq b, vntih b, rshfAmt b)
let getVdtaVntbShf b r = r b; ThreeOperands (vdtih b, vntihq b, lshfAmt b)
let getVdtVntFbits b r = r b; ThreeOperands (vdtihq b, vntihq b, fbits1 b)

// Four Operands
let getWdWnWmWa bin = FourOperands (wd bin, wn bin, wm bin, wa bin)
let getXdWnWmXa bin = FourOperands (xd bin, wn bin, wm bin, xa bin)
let getXdXnXmXa bin = FourOperands (xd bin, xn bin, xm bin, xa bin)
let getVdtVntVmtIdx b = FourOperands (vdtq1 b, vntq1 b, vmtq1 b, index b)
let getWnWmNzcvCond bin = FourOperands (wn bin, wm bin, nzcv bin, cond bin)
let getXnXmNzcvCond bin = FourOperands (xn bin, xm bin, nzcv bin, cond bin)
let getWnImmNzcvCond bin = FourOperands (wn bin, imm5 bin, nzcv bin, cond bin)
let getXnImmNzcvCond bin = FourOperands (xn bin, imm5 bin, nzcv bin, cond bin)
let getWdWnWmCond bin = FourOperands (wd bin, wn bin, wm bin, cond bin)
let getXdXnXmCond bin = FourOperands (xd bin, xn bin, xm bin, cond bin)
let getSdSnSmSa bin = FourOperands (sd bin, sn bin, sm bin, sa bin)
let getDdDnDmDa bin = FourOperands (dd bin, dn bin, dm bin, da bin)
let getSdSnSmCond bin = FourOperands (sd bin, sn bin, sm bin, cond bin)
let getDdDnDmCond bin = FourOperands (dd bin, dn bin, dm bin, cond bin)
let getWdWnWmShfamt bin = FourOperands (wd bin, wn bin, wm bin, shfamt bin)
let getXdXnXmShfamt bin = FourOperands (xd bin, xn bin, xm bin, shfamt bin)
let getWSdWSnWmExtamt bin = FourOperands (wsd bin, wsn bin, wm bin, extamt bin)
let getXSdXSnRmExtamt bin = FourOperands (xsd bin, xsn bin, rm bin, extamt bin)
let getWdWSnImmShf bin = FourOperands (wd bin, wsn bin, imm12 bin, lshf2 bin)
let getXdXSnImmShf bin = FourOperands (xd bin, xsn bin, imm12 bin, lshf2 bin)
let getWSdWSnImmShf bin = FourOperands (wsd bin, wsn bin, imm12 bin, lshf2 bin)
let getXSdXSnImmShf bin = FourOperands (xsd bin, xsn bin, imm12 bin, lshf2 bin)
let getWdWnImmrImms bin =
  FourOperands (wd bin, wn bin, immr bin 31u, imms bin 31u)
let getXdXnImmrImms bin =
  FourOperands (xd bin, xn bin, immr bin 63u, imms bin 63u)
let getWdWnWmLsb bin = FourOperands (wd bin, wn bin, wm bin, lsb bin 31u)
let getXdXnXmLsb bin = FourOperands (xd bin, xn bin, xm bin, lsb bin 63u)
let getWsWt1Wt2MXSn bin = FourOperands (ws bin, wt1 bin, wt2 bin, memXSn bin)
let getWsXt1Xt2MXSn bin = FourOperands (ws bin, xt1 bin, xt2 bin, memXSn bin)
let getSnSmNZCVCond bin = FourOperands (sn bin, sm bin, nzcv bin, cond bin)
let getDnDmNZCVCond bin = FourOperands (dn bin, dm bin, nzcv bin, cond bin)

let getOp1cncmop2Xt bin =
  FiveOperands (op1 bin, cn bin, cm bin, op2 bin, xt1 bin)

let getXtOp1cncmop2 bin =
  FiveOperands (xt1 bin, op1 bin, cn bin, cm bin, op2 bin)

let getOprSizeByVector = function
  | VecB -> 8<rt>
  | VecH -> 16<rt>
  | VecS -> 32<rt>
  | VecD -> 64<rt>
  | EightB -> 64<rt>
  | SixteenB -> 128<rt>
  | FourH -> 64<rt>
  | EightH -> 128<rt>
  | TwoS -> 64<rt>
  | FourS -> 128<rt>
  | OneD -> 64<rt>
  | TwoD -> 128<rt>
  | OneQ -> 128<rt>

let getOprSizeBySIMDReg reg =
  match reg with
  | SIMDVecReg (_, v) -> getOprSizeByVector v
  | SIMDVecRegWithIdx (_, v, _) -> getOprSizeByVector v
  | _ -> raise InvalidOperandException

let getFstOperand = function
  | OneOperand o -> o
  | TwoOperands (o1, _) -> o1
  | ThreeOperands (o1, _, _) -> o1
  | FourOperands (o1, _, _, _) -> o1
  | FiveOperands (o1, _, _, _, _) -> o1
  | _ -> raise InvalidOperandException

let getSIMDOperand = function
  | OprSIMD simd -> simd
  | _ -> raise InvalidOperandException

let getSIMDVectorOprSize (op, oprs) =
  op, oprs, getFstOperand oprs |> getSIMDOperand |> getOprSizeBySIMDReg

let getSIMDScalarOprSize o size (op, oprs) =
  match o with
  | 0b00u | 0b01u | 0b10u -> op, oprs, getVectorWidthBySize1 size
  | 0b11u -> op, oprs, getVectorWidthBySize2 size
  | _ -> raise InvalidOperandException

let changeToAliasOfAddSubImm bin instr =
  let isImm12Zero = valImm12 bin = 0b000000000000u
  match instr with
  | Opcode.ADD, FourOperands (rd, rn, _, _), oprSize
    when (valShift bin = 0b00u) && isImm12Zero
         && (valD bin = 0b11111u || valN bin = 0b11111u) ->
    Opcode.MOV, TwoOperands (rd, rn), oprSize
  | Opcode.ADDS, FourOperands (_, rn, imm, shf), oprSize
    when valD bin = 0b11111u ->
    Opcode.CMN, ThreeOperands (rn, imm, shf), oprSize
  | Opcode.SUBS, FourOperands (_, rn, imm, shf), oprSize
    when valD bin = 0b11111u ->
    Opcode.CMP, ThreeOperands (rn, imm, shf), oprSize
  | _ -> instr

let parseAddSubImm bin =
  let cond = extract bin 31u 29u (* sf:op:S *)
  match cond with
  | c when c &&& 0b000u = 0b000u && (extract bin 23u 22u >>> 1) = 0b1u ->
    raise UnallocatedException
  | 0b000u -> Opcode.ADD, getWSdWSnImmShf bin, 32<rt>
  | 0b001u -> Opcode.ADDS, getWdWSnImmShf bin, 32<rt>
  | 0b010u -> Opcode.SUB, getWSdWSnImmShf bin, 32<rt>
  | 0b011u -> Opcode.SUBS, getWdWSnImmShf bin, 32<rt>
  | 0b100u -> Opcode.ADD, getXSdXSnImmShf bin, 64<rt>
  | 0b101u -> Opcode.ADDS, getXdXSnImmShf bin, 64<rt>
  | 0b110u -> Opcode.SUB, getXSdXSnImmShf bin, 64<rt>
  | 0b111u -> Opcode.SUBS, getXdXSnImmShf bin, 64<rt>
  | _ -> raise InvalidOperandException
  |> changeToAliasOfAddSubImm bin

let changeToAliasOfBitfield bin instr =
  let sf = valMSB bin
  match instr with
  | Opcode.SBFM, FourOperands (rd, rn, immr, OprImm imms), oprSize
      when (sf = 0u && imms = 0b011111L) || (sf = 1u && imms = 0b111111L) ->
    Opcode.ASR, ThreeOperands (rd, rn, immr), oprSize
  | Opcode.SBFM, FourOperands (rd, rn, OprImm immr, OprImm imms), oSz
      when imms < immr ->
    let lsb = (RegType.toBitWidth oSz |> int64) - immr
    Opcode.SBFIZ,
    FourOperands (rd, rn, OprImm lsb, OprImm (imms + 1L)), oSz
  | Opcode.SBFM, FourOperands (rd, rn, OprImm r, OprImm s), oSz
      when BFXPreferred sf 0u (uint32 s) (uint32 r) ->
    Opcode.SBFX, FourOperands (rd, rn, OprImm r, OprImm (s - r + 1L)), oSz
  | Opcode.SBFM, FourOperands (rd, _, OprImm immr, OprImm imms), oprSz
      when (immr = 0b000000L) && (imms = 0b000111L) ->
    Opcode.SXTB,
    TwoOperands (rd, getRegister64 32<rt> (valN bin |> byte) |> OprRegister),
    oprSz
  | Opcode.SBFM, FourOperands (rd, _, OprImm immr, OprImm imms), oprSz
      when (immr = 0b000000L) && (imms = 0b001111L) ->
    Opcode.SXTH,
    TwoOperands (rd, getRegister64 32<rt> (valN bin |> byte) |> OprRegister),
    oprSz
  | Opcode.SBFM, FourOperands (rd, _, OprImm immr, OprImm imms), oprSz
      when (immr = 0b000000L) && (imms = 0b011111L) ->
    Opcode.SXTW,
    TwoOperands (rd, getRegister64 32<rt> (valN bin |> byte) |> OprRegister),
    oprSz
  | Opcode.BFM, FourOperands (rd, rn, OprImm immr, OprImm imms), oprSize
      when (valN bin <> 0b11111u) && (imms < immr) ->
    let lsb = (RegType.toBitWidth oprSize |> int64) - immr
    Opcode.BFI,
    FourOperands (rd, rn, OprImm lsb, OprImm (imms + 1L)), oprSize
  | Opcode.BFM, FourOperands (d, n, OprImm immr, OprImm imms), oprSize
      when imms >= immr ->
    Opcode.BFXIL,
    FourOperands (d, n, OprImm immr, OprImm (imms - immr + 1L)), oprSize
  | Opcode.UBFM, FourOperands (rd, rn, OprImm immr, OprImm imms), oprSize
      when (oprSize = 32<rt>) && (imms <> 0b011111L) && (imms + 1L = immr) ->
    Opcode.LSL, ThreeOperands (rd, rn, OprImm (31L - imms)), oprSize
  | Opcode.UBFM, FourOperands (rd, rn, OprImm immr, OprImm imms), oprSize
      when (oprSize = 64<rt>) && (imms <> 0b111111L) && (imms + 1L = immr) ->
    Opcode.LSL, ThreeOperands (rd, rn, OprImm (63L - imms)), oprSize
  | Opcode.UBFM, FourOperands (rd, rn, immr, OprImm imms), oprSize
      when (oprSize = 32<rt>) && (imms = 0b011111L) ->
    Opcode.LSR, ThreeOperands (rd, rn, immr), oprSize
  | Opcode.UBFM, FourOperands (rd, rn, immr, OprImm imms), oprSize
      when (oprSize = 64<rt>) && (imms = 0b111111L) ->
    Opcode.LSR, ThreeOperands (rd, rn, immr), oprSize
  | Opcode.UBFM, FourOperands (rd, rn, OprImm immr, OprImm imms), oprSize
      when imms < immr ->
    let lsb = (RegType.toBitWidth oprSize |> int64) - immr
    Opcode.UBFIZ, FourOperands (rd, rn, OprImm lsb, OprImm (imms + 1L)),
    oprSize
  | Opcode.UBFM, FourOperands (rd, rn, OprImm immr, OprImm imms), oprSize
      when BFXPreferred sf 1u (uint32 imms) (uint32 immr) ->
    Opcode.UBFX,
    FourOperands (rd, rn, OprImm immr, OprImm (imms - immr + 1L)), oprSize
  | Opcode.UBFM, FourOperands (rd, rn, OprImm immr, OprImm imms), oprSize
      when immr = 0b000000L && imms = 0b000111L ->
    Opcode.UXTB, TwoOperands (rd, rn), oprSize
  | Opcode.UBFM, FourOperands (rd, rn, OprImm immr, OprImm imms), oprSize
      when immr = 0b000000L && imms = 0b001111L ->
    Opcode.UXTH, TwoOperands (rd, rn), oprSize
  | _ -> instr

let parseBitfield bin =
  let cond = concat (extract bin 31u 29u) (pickBit bin 22u) 1 (* sf:opc:N *)
  match cond with
  | c when c &&& 0b0110u = 0b0110u -> raise UnallocatedException
  | c when c &&& 0b1001u = 0b0001u -> raise UnallocatedException
  | 0b0000u -> Opcode.SBFM, getWdWnImmrImms bin, 32<rt>
  | 0b0010u -> Opcode.BFM, getWdWnImmrImms bin, 32<rt>
  | 0b0100u -> Opcode.UBFM, getWdWnImmrImms bin, 32<rt>
  | c when c &&& 0b1001u = 0b1000u -> raise UnallocatedException
  | 0b1001u -> Opcode.SBFM, getXdXnImmrImms bin, 64<rt>
  | 0b1011u -> Opcode.BFM, getXdXnImmrImms bin, 64<rt>
  | 0b1101u -> Opcode.UBFM, getXdXnImmrImms bin, 64<rt>
  | _ -> raise InvalidOperandException
  |> changeToAliasOfBitfield bin

let changeToAliasOfExtract instr =
  match instr with
  | Opcode.EXTR, FourOperands (rd, rn, rm, lsb), oprSize when rn = rm ->
    Opcode.ROR, ThreeOperands (rd, rn, lsb), oprSize
  | _ -> instr

let parseExtract bin =
  let cond = concat (concat (extract bin 31u 29u) (extract bin 22u 21u) 2)
                    (extract bin 15u 10u) 6 (* sf:op21:N:o0:imms *)
  match cond with
  | c when c &&& 0b00100000000u = 0b00100000000u -> raise UnallocatedException
  | c when c &&& 0b01101000000u = 0b00001000000u -> raise UnallocatedException
  | c when c &&& 0b01000000000u = 0b01000000000u -> raise UnallocatedException
  | c when c &&& 0b10000100000u = 0b00000100000u -> raise UnallocatedException
  | c when c &&& 0b10010000000u = 0b00010000000u -> raise UnallocatedException
  | c when c &&& 0b11111100000u = 0b00000000000u ->
    Opcode.EXTR, getWdWnWmLsb bin, 32<rt>
  | c when c &&& 0b11111000000u = 0b10010000000u ->
    Opcode.EXTR, getXdXnXmLsb bin, 64<rt>
  | c when c &&& 0b10010000000u = 0b10000000000u -> raise UnallocatedException
  | _ -> raise InvalidOperandException
  |> changeToAliasOfExtract

let changeToAliasOfLogical bin instr =
  match instr with
  | Opcode.ORR, ThreeOperands (rd, _, imm), oprSize
      when valN bin = 0b11111u && (not (moveWidePreferred bin))
    -> Opcode.MOV, TwoOperands (rd, imm), oprSize
  | Opcode.ANDS, ThreeOperands (_, rn, imm), oprSize when valD bin = 0b11111u ->
    Opcode.TST, TwoOperands (rn, imm), oprSize
  | _ -> instr

let parseLogical bin =
  let cond = concat (extract bin 31u 29u) (pickBit bin 22u) 1 (* sf:opc:N *)
  match cond with
  | c when c &&& 0b1001u = 0b0001u -> raise UnallocatedException
  | 0b0000u -> Opcode.AND, getWSdWnImm bin, 32<rt>
  | 0b0010u -> Opcode.ORR, getWSdWnImm bin, 32<rt>
  | 0b0100u -> Opcode.EOR, getWSdWnImm bin, 32<rt>
  | 0b0110u -> Opcode.ANDS, getWdWnImm bin, 32<rt>
  | c when c &&& 0b1110u = 0b1000u -> Opcode.AND, getXSdXnImm bin, 64<rt>
  | c when c &&& 0b1110u = 0b1010u -> Opcode.ORR, getXSdXnImm bin, 64<rt>
  | c when c &&& 0b1110u = 0b1100u -> Opcode.EOR, getXSdXnImm bin, 64<rt>
  | c when c &&& 0b1110u = 0b1110u -> Opcode.ANDS, getXdXnImm bin, 64<rt>
  | _ -> raise InvalidOperandException
  |> changeToAliasOfLogical bin

let changeToAliasOfMoveWide bin instr =
  let is64Bit = valMSB bin = 1u
  let hw = extract bin 22u 21u
  match instr with
  (* C6.2.122 MOV (inverted wide immediate) *)
  | Opcode.MOVN, ThreeOperands (xd, OprImm imm16, OprShift (_, Imm amt)), oprSz
      when is64Bit && not (0b0L = imm16 && hw <> 0b00u) ->
    let imm = ~~~ (imm16 <<< int32 amt)
    Opcode.MOV, TwoOperands (xd, OprImm imm), oprSz
  | Opcode.MOVN, ThreeOperands (wd, OprImm imm16, OprShift (_, Imm amt)), oprSz
      when not is64Bit && not (0b0L = imm16 && hw <> 0b00u)
           && (0b1111111111111111L <> imm16) ->
    let imm = ~~~ (uint32 (imm16 <<< int32 amt)) |> int64
    Opcode.MOV, TwoOperands (wd, OprImm imm), oprSz
  (* C6.2.123 MOV (wide immediate) *)
  | Opcode.MOVZ, ThreeOperands (rd, OprImm imm16, OprShift (_, Imm amt)), oprSz
    when not (imm16 = 0b0L && hw <> 0b00u) ->
    let imm = imm16 <<< (int32 amt)
    Opcode.MOV, TwoOperands (rd, OprImm imm), oprSz
  | _ -> instr

let parseMoveWide bin =
  let cond = concat (extract bin 31u 29u) (extract bin 22u 21u) 2
  match cond with (* sf:opc:hw *)
  | c when c &&& 0b01100u = 0b00100u -> raise UnallocatedException
  | c when c &&& 0b10010u = 0b00010u -> raise UnallocatedException
  | c when c &&& 0b11100u = 0b00000u -> Opcode.MOVN, getWdImmLShf bin, 32<rt>
  | c when c &&& 0b11100u = 0b01000u -> Opcode.MOVZ, getWdImmLShf bin, 32<rt>
  | c when c &&& 0b11100u = 0b01100u -> Opcode.MOVK, getWdImmLShf bin, 32<rt>
  | c when c &&& 0b11100u = 0b10000u -> Opcode.MOVN, getXdImmLShf bin, 64<rt>
  | c when c &&& 0b11100u = 0b11000u -> Opcode.MOVZ, getXdImmLShf bin, 64<rt>
  | c when c &&& 0b11100u = 0b11100u -> Opcode.MOVK, getXdImmLShf bin, 64<rt>
  | _ -> raise InvalidOperandException
  |> changeToAliasOfMoveWide bin

let parsePCRel bin =
  if (pickBit bin 31u) = 0u then Opcode.ADR, getXdLabel bin 0, 64<rt>
  else Opcode.ADRP, getXdLabel bin 12, 64<rt>

/// Data processing - immediate
let parse64Group1 bin =
  let op0 = extract bin 25u 23u
  match op0 with
  | op0 when op0 &&& 0b110u = 0b000u -> parsePCRel bin
  | op0 when op0 &&& 0b110u = 0b010u -> parseAddSubImm bin
  | 0b100u -> parseLogical bin
  | 0b101u -> parseMoveWide bin
  | 0b110u -> parseBitfield bin
  | 0b111u -> parseExtract bin
  | _ -> raise InvalidOpcodeException

let parseCompareAndBranchImm bin =
  let cond = concat (pickBit bin 31u) (pickBit bin 24u) 1 (* sf:op *)
  match cond with
  | 0b00u -> Opcode.CBZ, getWtLabel bin, 32<rt>
  | 0b01u -> Opcode.CBNZ, getWtLabel bin, 32<rt>
  | 0b10u -> Opcode.CBZ, getXtLabel bin, 64<rt>
  | 0b11u -> Opcode.CBNZ, getXtLabel bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let parseCondBranchImm bin =
  let cond = concat (pickBit bin 24u) (pickBit bin 4u) 1 (* o1:o0 *)
  let opCode =
    match cond with
    | 0b00u -> getConditionOpcode (extract bin 3u 0u |> byte)
    | 0b01u -> raise UnallocatedException
    | 0b10u | 0b11u -> raise UnallocatedException
    | _ -> raise InvalidOpcodeException
  opCode, OneOperand (memLabel (signExtend 19 64 (valImm19 bin <<< 2 |> uint64)
                               |> int64)), 64<rt>

let parseExcepGen bin =
  let cond = concat (extract bin 23u 21u) (extract bin 4u 0u) 5
  let opCode =
    match cond with (* opc:op2:LL *)
    | c when c &&& 0b00000100u = 0b00000100u -> raise UnallocatedException
    | c when c &&& 0b00001000u = 0b00001000u -> raise UnallocatedException
    | c when c &&& 0b00010000u = 0b00010000u -> raise UnallocatedException
    | 0b00000000u -> raise UnallocatedException
    | 0b00000001u -> Opcode.SVC
    | 0b00000010u -> Opcode.HVC
    | 0b00000011u -> Opcode.SMC
    | c when c &&& 0b11111101u = 0b00100001u -> raise UnallocatedException
    | 0b00100000u -> Opcode.BRK
    | c when c &&& 0b11111110u = 0b00100010u -> raise UnallocatedException
    | c when c &&& 0b11111101u = 0b01000001u -> raise UnallocatedException
    | 0b01000000u -> Opcode.HLT
    | c when c &&& 0b11111110u = 0b01000010u -> raise UnallocatedException
    | c when c &&& 0b11111100u = 0b01100000u -> raise UnallocatedException
    | c when c &&& 0b11111100u = 0b10000000u -> raise UnallocatedException
    | 0b10100000u -> raise UnallocatedException
    | 0b10100001u -> Opcode.DCPS1
    | 0b10100010u -> Opcode.DCPS2
    | 0b10100011u -> Opcode.DCPS3
    | c when c &&& 0b11011100u = 0b11000000u -> raise UnallocatedException
    | _ -> raise InvalidOpcodeException
  opCode, OneOperand (OprImm (valImm16 bin |> int64)), 0<rt>

let getISBOprs = function
  | 0b1111L -> OneOperand (OprOption SY)
  | imm -> OneOperand (OprImm imm)

let private getDCInstruction bin =
  match extract bin 18u 5u with
  | 0b01101110100001u -> Opcode.DCZVA
  | 0b00001110110001u -> Opcode.DCIVAC
  | 0b00001110110010u -> Opcode.DCISW
  | 0b01101111010001u -> Opcode.DCCVAC
  | 0b00001111010010u -> Opcode.DCCSW
  | 0b01101111011001u -> Opcode.DCCVAU
  | 0b01101111110001u -> Opcode.DCCIVAC
  | 0b00001111110010u -> Opcode.DCCISW
  (* C5.3 A64 system instructions for cache maintenance *)
  | _ -> raise InvalidOpcodeException

let changeToAliasOfSystem bin instr =
  match instr with
  | Opcode.SYS, FiveOperands (_, OprRegister cn, _, _, xt), oSz
      when cn = R.C7 && SysOp bin = SysDC ->
    getDCInstruction bin, OneOperand xt, oSz
  | _ -> instr

let parseSystem bin =
  let cond = concat (extract bin 21u 12u) (extract bin 7u 5u) 3
  let rt = extract bin 4u 0u
  let isRt1F = rt = 0b11111u
  let crm = extract bin 11u 8u |> int64
  let isCRmZero = crm = 0b00000L
  match cond with (* L:op0:op1:CRn:CRm:op2 *)
  | c when c &&& 0b1110001110000u = 0b0000000000000u ->
    raise UnallocatedException
  | c when c &&& 0b1110001111000u = 0b0000000100000u && not isRt1F ->
    raise UnallocatedException
  | c when c &&& 0b1110001111000u = 0b0000000100000u && isRt1F ->
    Opcode.MSR, getPstatefieldImm bin, 0<rt>
  | c when c &&& 0b1110001111000u = 0b0000000101000u ->
    raise UnallocatedException
  | c when c &&& 0b1110001110000u = 0b0000000110000u ->
    raise UnallocatedException
  | c when c &&& 0b1110001000000u = 0b0000001000000u ->
    raise UnallocatedException
  | c when c &&& 0b1110011110000u = 0b0000000010000u ->
    raise UnallocatedException
  | c when c &&& 0b1110101110000u = 0b0000000010000u ->
    raise UnallocatedException
  | c when c &&& 0b1111111110000u = 0b0000110010000u && not isRt1F ->
    raise UnallocatedException
  | c when c &&& 0b1111111111000u = 0b0000110010000u &&
           not isCRmZero && isRt1F ->
    let imm = concat (uint32 crm) (extract bin 7u 5u) 3 |> int64
    Opcode.HINT, OneOperand (OprImm imm), 0<rt> (* Hints 8 to 127 variant *)
  | 0b0000110010000u when isCRmZero && isRt1F -> Opcode.NOP, NoOperand, 0<rt>
  | 0b0000110010001u when isCRmZero && isRt1F -> Opcode.YIELD, NoOperand, 0<rt>
  | 0b0000110010010u when isCRmZero && isRt1F -> Opcode.WFE, NoOperand, 0<rt>
  | 0b0000110010011u when isCRmZero && isRt1F -> Opcode.WFI, NoOperand, 0<rt>
  | 0b0000110010100u when isCRmZero && isRt1F -> Opcode.SEV, NoOperand, 0<rt>
  | 0b0000110010101u when isCRmZero && isRt1F -> Opcode.SEVL, NoOperand, 0<rt>
  | c when c &&& 0b1111111111110u = 0b0000110010110u && isCRmZero && isRt1F ->
    let imm = concat (uint32 crm) (extract bin 7u 5u) 3 |> int64
    Opcode.HINT, OneOperand (OprImm imm), 0<rt> (* Hints 6 and 7 variant *)
  | 0b0000110011000u -> raise UnallocatedException
  | 0b0000110011001u -> raise UnallocatedException
  | 0b0000110011010u when isRt1F ->
    Opcode.CLREX, OneOperand (OprImm crm), 0<rt>
  | 0b0000110011011u -> raise UnallocatedException
  | 0b0000110011100u when isRt1F -> Opcode.DSB, getOptionOrimm bin, 0<rt>
  | 0b0000110011101u when isRt1F -> Opcode.DMB, getOptionOrimm bin, 0<rt>
  | 0b0000110011110u when isRt1F -> Opcode.ISB, getISBOprs crm, 0<rt>
  | 0b0000110011111u -> raise UnallocatedException
  | c when c &&& 0b1111001110000u = 0b0001000010000u ->
    raise UnallocatedException
  | c when c &&& 0b1110000000000u = 0b0010000000000u ->
    Opcode.SYS, getOp1cncmop2Xt bin, 0<rt>
  | c when c &&& 0b1100000000000u = 0b0100000000000u ->
    Opcode.MSR, getSysregOrctrlXt bin, 0<rt>
  | c when c &&& 0b1110000000000u = 0b1000000000000u ->
    raise UnallocatedException
  | c when c &&& 0b1110000000000u = 0b1010000000000u ->
    Opcode.SYSL, getXtOp1cncmop2 bin, 0<rt>
  | c when c &&& 0b1100000000000u = 0b1100000000000u ->
    Opcode.MRS, getXtSysregOrctrl bin, 0<rt>
  | _ -> raise InvalidOperandException
  |> changeToAliasOfSystem bin

let parseTestBranchImm bin =
  let opCode = if (pickBit bin 24u) = 0u then Opcode.TBZ else Opcode.TBNZ
  let b5 = pickBit bin 31u
  let oprSize = getOprSizeByMSB b5
  let rt = getRegister64 oprSize (extract bin 4u 0u |> byte)
  let imm = concat b5 (extract bin 23u 19u) 5 |> int64
  let label =
    memLabel (extract bin 18u 5u <<< 2 |> uint64 |> signExtend 16 64 |> int64)
  opCode, ThreeOperands (OprRegister rt, OprImm imm, label), oprSize

let parseUncondBranchImm bin =
  let opCode = if (pickBit bin 31u) = 0u then Opcode.B else Opcode.BL
  let imm26 = signExtend 26 64 (extract bin 25u 0u <<< 2 |> uint64) |> int64
  opCode, OneOperand (memLabel imm26), 64<rt>

let parseUncondBranchReg bin =
  let opc = extract bin 24u 21u
  let isOp21F = extract bin 20u 16u = 0b11111u
  let isOp3Zero = extract bin 15u 10u = 0b000000u
  let rn = extract bin 9u 5u
  let isRn1F = rn = 0b11111u
  let isOp4Zero = extract bin 4u 0u = 0b00000u
  if not isOp4Zero || not isOp3Zero || not isOp21F then
    raise UnallocatedException
  match opc with
  | 0b0000u when isOp21F && isOp3Zero && isOp4Zero ->
    Opcode.BR,
    OneOperand (OprRegister <| getRegister64 64<rt> (byte rn)),
    0<rt>
  | 0b0001u when isOp21F && isOp3Zero && isOp4Zero ->
    Opcode.BLR,
    OneOperand (OprRegister <| getRegister64 64<rt> (byte rn)),
    64<rt>
  | 0b0010u when isOp21F && isOp3Zero && isOp4Zero ->
    Opcode.RET,
    OneOperand (OprRegister <| getRegister64 64<rt> (byte rn)),
    64<rt>
  | 0b0011u -> raise UnallocatedException
  | o when o &&& 1110u = 0100u && not isRn1F -> raise UnallocatedException
  | 0b0100u when isOp21F && isOp3Zero && isRn1F && isOp4Zero ->
    Opcode.ERET, NoOperand, 0<rt>
  | 0b0101u when isOp21F && isOp3Zero && isRn1F && isOp4Zero ->
    Opcode.DRPS, NoOperand, 0<rt>
  | o when o &&& 1110u = 0110u -> raise UnallocatedException
  | o when o &&& 1000u = 1000u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

/// Branches, exception generating and system instructions
let parse64Group2 bin =
  let op0 = extract bin 31u 29u
  let op1 = extract bin 25u 22u
  let ops = concat op0 op1 4
  match ops with
  | ops when ops &&& 0b1111000u = 0b0100000u -> parseCondBranchImm bin
  | ops when ops &&& 0b1111000u = 0b0101000u -> raise UnallocatedException
  | ops when ops &&& 0b1111100u = 0b1100000u -> parseExcepGen bin
  | ops when ops &&& 0b1111111u = 0b1100100u -> parseSystem bin
  | ops when ops &&& 0b1111111u = 0b1100101u -> raise UnallocatedException
  | ops when ops &&& 0b1111110u = 0b1100110u -> raise UnallocatedException
  | ops when ops &&& 0b1111000u = 0b1101000u -> parseUncondBranchReg bin
  | ops when ops &&& 0b0110000u = 0b0000000u -> parseUncondBranchImm bin
  | ops when ops &&& 0b0111000u = 0b0010000u -> parseCompareAndBranchImm bin
  | ops when ops &&& 0b0111000u = 0b0011000u -> parseTestBranchImm bin
  | ops when ops &&& 0b0110000u = 0b0110000u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseAdvSIMDMul bin =
  let cond = concat (pickBit bin 22u) (extract bin 15u 12u) 4 (* L:opcode *)
  let oprSize = if pickBit bin 30u = 1u then 128<rt> else 64<rt>
  match cond with
  | 0b00000u -> Opcode.ST4, getVt4tMXSn bin sizeQ110b, 0<rt>
  | 0b00001u -> raise UnallocatedException
  | 0b00010u -> Opcode.ST1, getVt4tMXSn bin resNone, 0<rt>
  | 0b00011u -> raise UnallocatedException
  | 0b00100u -> Opcode.ST3, getVt3tMXSn bin sizeQ110b, 0<rt>
  | 0b00101u -> raise UnallocatedException
  | 0b00110u -> Opcode.ST1, getVt3tMXSn bin resNone, 0<rt>
  | 0b00111u -> Opcode.ST1, getVt1tMXSn bin resNone, 0<rt>
  | 0b01000u -> Opcode.ST2, getVt2tMXSn bin sizeQ110b, 0<rt>
  | 0b01001u -> raise UnallocatedException
  | 0b01010u -> Opcode.ST1, getVt2tMXSn bin resNone, 0<rt>
  | 0b01011u -> raise UnallocatedException
  | c when c &&& 0b11100u = 0b01100u -> raise UnallocatedException
  | 0b10000u -> Opcode.LD4, getVt4tMXSn bin sizeQ110b, 0<rt>
  | 0b10001u -> raise UnallocatedException
  | 0b10010u -> Opcode.LD1, getVt4tMXSn bin resNone, oprSize
  | 0b10011u -> raise UnallocatedException
  | 0b10100u -> Opcode.LD3, getVt3tMXSn bin sizeQ110b, 0<rt>
  | 0b10101u -> raise UnallocatedException
  | 0b10110u -> Opcode.LD1, getVt3tMXSn bin resNone, oprSize
  | 0b10111u -> Opcode.LD1, getVt1tMXSn bin resNone, oprSize
  | 0b11000u -> Opcode.LD2, getVt2tMXSn bin sizeQ110b, 0<rt>
  | 0b11001u -> raise UnallocatedException
  | 0b11010u -> Opcode.LD1, getVt2tMXSn bin resNone, oprSize
  | 0b11011u -> raise UnallocatedException
  | c when c &&& 0b11100u = 0b11100u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseAdvSIMDMulPostIndexed bin =
  let cond = concat (pickBit bin 22u) (extract bin 15u 12u) 4 (* L:opcode *)
  let isRm11111 = (extract bin 20u 16u) = 0b11111u
  match cond with
  | 0b00001u -> raise UnallocatedException
  | 0b00011u -> raise UnallocatedException
  | 0b00101u -> raise UnallocatedException
  | 0b01001u -> raise UnallocatedException
  | 0b01011u -> raise UnallocatedException
  | c when c &&& 0b11100u = 0b01100u -> raise UnallocatedException
  | 0b00000u when not isRm11111 ->
    Opcode.ST4, getVt4tPoXSnXm bin sizeQ110b, 0<rt>
  | 0b00010u when not isRm11111 -> Opcode.ST1, getVt4tPoXSnXm bin resNone, 0<rt>
  | 0b00100u when not isRm11111 ->
    Opcode.ST3, getVt3tPoXSnXm bin sizeQ110b, 0<rt>
  | 0b00110u when not isRm11111 -> Opcode.ST1, getVt3tPoXSnXm bin resNone, 0<rt>
  | 0b00111u when not isRm11111 -> Opcode.ST1, getVt1tPoXSnXm bin resNone, 0<rt>
  | 0b01000u when not isRm11111 ->
    Opcode.ST2, getVt2tPoXSnXm bin sizeQ110b, 0<rt>
  | 0b01010u when not isRm11111 -> Opcode.ST1, getVt2tPoXSnXm bin resNone, 0<rt>
  | 0b00000u when isRm11111 -> Opcode.ST4, getVt4tPoXSnImm1 bin sizeQ110b, 0<rt>
  | 0b00010u when isRm11111 -> Opcode.ST1, getVt4tPoXSnImm1 bin resNone, 0<rt>
  | 0b00100u when isRm11111 -> Opcode.ST3, getVt3tPoXSnImm1 bin sizeQ110b, 0<rt>
  | 0b00110u when isRm11111 -> Opcode.ST1, getVt3tPoXSnImm1 bin resNone, 0<rt>
  | 0b00111u when isRm11111 -> Opcode.ST1, getVt1tPoXSnImm1 bin resNone, 0<rt>
  | 0b01000u when isRm11111 -> Opcode.ST2, getVt2tPoXSnImm1 bin sizeQ110b, 0<rt>
  | 0b01010u when isRm11111 -> Opcode.ST1, getVt2tPoXSnImm1 bin resNone, 0<rt>
  | 0b10001u -> raise UnallocatedException
  | 0b10011u -> raise UnallocatedException
  | 0b10101u -> raise UnallocatedException
  | 0b11001u -> raise UnallocatedException
  | 0b11011u -> raise UnallocatedException
  | c when c &&& 0b11100u = 0b11100u -> raise UnallocatedException
  | 0b10000u when not isRm11111 ->
    Opcode.LD4, getVt4tPoXSnXm bin sizeQ110b, 0<rt>
  | 0b10010u when not isRm11111 -> Opcode.LD1, getVt4tPoXSnXm bin resNone, 0<rt>
  | 0b10100u when not isRm11111 ->
    Opcode.LD3, getVt3tPoXSnXm bin sizeQ110b, 0<rt>
  | 0b10110u when not isRm11111 -> Opcode.LD1, getVt3tPoXSnXm bin resNone, 0<rt>
  | 0b10111u when not isRm11111 -> Opcode.LD1, getVt1tPoXSnXm bin resNone, 0<rt>
  | 0b11000u when not isRm11111 ->
    Opcode.LD2, getVt2tPoXSnXm bin sizeQ110b, 0<rt>
  | 0b11010u when not isRm11111 -> Opcode.LD1, getVt2tPoXSnXm bin resNone, 0<rt>
  | 0b10000u when isRm11111 -> Opcode.LD4, getVt4tPoXSnImm1 bin sizeQ110b, 0<rt>
  | 0b10010u when isRm11111 -> Opcode.LD1, getVt4tPoXSnImm1 bin resNone, 0<rt>
  | 0b10100u when isRm11111 -> Opcode.LD3, getVt3tPoXSnImm1 bin sizeQ110b, 0<rt>
  | 0b10110u when isRm11111 -> Opcode.LD1, getVt3tPoXSnImm1 bin resNone, 0<rt>
  | 0b10111u when isRm11111 -> Opcode.LD1, getVt1tPoXSnImm1 bin resNone, 0<rt>
  | 0b11000u when isRm11111 -> Opcode.LD2, getVt2tPoXSnImm1 bin sizeQ110b, 0<rt>
  | 0b11010u when isRm11111 -> Opcode.LD1, getVt2tPoXSnImm1 bin resNone, 0<rt>
  | _ -> raise InvalidOpcodeException

let parseAdvSIMDSingle bin =
  let cond = concat (extract bin 22u 21u) (extract bin 15u 10u) 6
  match cond with (* L:R:opcode:S:size *)
  | c when c &&& 0b10110000u = 0b00110000u -> raise UnallocatedException
  | c when c &&& 0b11111000u = 0b00000000u ->
    Opcode.ST1, getVt1BidxMXSn bin, 0<rt>
  | c when c &&& 0b11111000u = 0b00001000u ->
    Opcode.ST3, getVt3BidxMXSn bin, 0<rt>
  | c when c &&& 0b11111001u = 0b00010000u ->
    Opcode.ST1, getVt1HidxMXSn bin, 0<rt>
  | c when c &&& 0b11111001u = 0b00010001u ->
    raise UnallocatedException
  | c when c &&& 0b11111001u = 0b00011000u ->
    Opcode.ST3, getVt3HidxMXSn bin, 0<rt>
  | c when c &&& 0b11111001u = 0b00011001u ->
    raise UnallocatedException
  | c when c &&& 0b11111011u = 0b00100000u ->
    Opcode.ST1, getVt1SidxMXSn bin, 0<rt>
  | c when c &&& 0b11111010u = 0b00100010u ->
    raise UnallocatedException
  | 0b00100001u -> Opcode.ST1, getVt1DidxMXSn bin, 0<rt>
  | 0b00100101u -> raise UnallocatedException
  | c when c &&& 0b11111011u = 0b00101000u ->
    Opcode.ST3, getVt3SidxMXSn bin, 0<rt>
  | c when c &&& 0b11111011u = 0b00101010u -> raise UnallocatedException
  | 0b00101001u -> Opcode.ST3, getVt3DidxMXSn bin, 0<rt>
  | 0b00101011u -> raise UnallocatedException
  | c when c &&& 0b11111101u = 0b00101101u -> raise UnallocatedException
  | c when c &&& 0b11111000u = 0b01000000u ->
    Opcode.ST2, getVt2BidxMXSn bin, 0<rt>
  | c when c &&& 0b11111000u = 0b01001000u ->
    Opcode.ST4, getVt4BidxMXSn bin, 0<rt>
  | c when c &&& 0b11111001u = 0b01010000u ->
    Opcode.ST2, getVt2HidxMXSn bin, 0<rt>
  | c when c &&& 0b11111001u = 0b01010001u -> raise UnallocatedException
  | c when c &&& 0b11111001u = 0b01011000u ->
    Opcode.ST4, getVt4HidxMXSn bin, 0<rt>
  | c when c &&& 0b11111001u = 0b01011001u -> raise UnallocatedException
  | c when c &&& 0b11111011u = 0b01100000u ->
    Opcode.ST2, getVt2SidxMXSn bin, 0<rt>
  | c when c &&& 0b11111011u = 0b01100010u -> raise UnallocatedException
  | 0b01100001u -> Opcode.ST2, getVt2DidxMXSn bin, 0<rt>
  | 0b01100011u -> raise UnallocatedException
  | c when c &&& 0b11111101u = 0b01100101u -> raise UnallocatedException
  | c when c &&& 0b11111011u = 0b01101000u ->
    Opcode.ST4, getVt4SidxMXSn bin, 0<rt>
  | c when c &&& 0b11111011u = 0b01101010u -> raise UnallocatedException
  | 0b01101001u -> Opcode.ST4, getVt4DidxMXSn bin, 0<rt>
  | 0b01101011u -> raise UnallocatedException
  | c when c &&& 0b11111101u = 0b01101101u -> raise UnallocatedException
  | c when c &&& 0b11111000u = 0b10000000u ->
    Opcode.LD1, getVt1BidxMXSn bin, 0<rt>
  | c when c &&& 0b11111000u = 0b10001000u ->
    Opcode.LD3, getVt3BidxMXSn bin, 0<rt>
  | c when c &&& 0b11111001u = 0b10010000u ->
    Opcode.LD1, getVt1HidxMXSn bin, 0<rt>
  | c when c &&& 0b11111001u = 0b10010001u -> raise UnallocatedException
  | c when c &&& 0b11111001u = 0b10011000u ->
    Opcode.LD3, getVt3HidxMXSn bin, 0<rt>
  | c when c &&& 0b11111001u = 0b10011001u -> raise UnallocatedException
  | c when c &&& 0b11111011u = 0b10100000u ->
    Opcode.LD1, getVt1SidxMXSn bin, 0<rt>
  | c when c &&& 0b11111010u = 0b10100010u -> raise UnallocatedException
  | 0b10100001u ->
    Opcode.LD1, getVt1DidxMXSn bin, 0<rt> // LD1(single struct)-64bit
  | 0b10100101u -> raise UnallocatedException
  | c when c &&& 0b11111011u = 0b10101000u ->
    Opcode.LD3, getVt3SidxMXSn bin, 0<rt>
  | c when c &&& 0b11111011u = 0b10101010u -> raise UnallocatedException
  | 0b10101001u -> Opcode.LD3, getVt3DidxMXSn bin, 0<rt>
  | 0b10101011u -> raise UnallocatedException
  | c when c &&& 0b11111101u = 0b10101101u -> raise UnallocatedException
  | c when c &&& 0b11111100u = 0b10110000u ->
    Opcode.LD1R, getVt1tMXSn bin resNone, 0<rt>
  | c when c &&& 0b11111100u = 0b10110100u -> raise UnallocatedException
  | c when c &&& 0b11111100u = 0b10111000u ->
    Opcode.LD3R, getVt3tMXSn bin resNone, 0<rt>
  | c when c &&& 0b11111100u = 0b10111100u -> raise UnallocatedException
  | c when c &&& 0b11111000u = 0b11000000u ->
    Opcode.LD2, getVt2BidxMXSn bin, 0<rt>
  | c when c &&& 0b11111000u = 0b11001000u ->
    Opcode.LD4, getVt4BidxMXSn bin, 0<rt>
  | c when c &&& 0b11111001u = 0b11010000u ->
    Opcode.LD2, getVt2HidxMXSn bin, 0<rt>
  | c when c &&& 0b11111001u = 0b11010001u -> raise UnallocatedException
  | c when c &&& 0b11111001u = 0b11011000u ->
    Opcode.LD4, getVt4HidxMXSn bin, 0<rt>
  | c when c &&& 0b11111001u = 0b11011001u -> raise UnallocatedException
  | c when c &&& 0b11111011u = 0b11100000u ->
    Opcode.LD2, getVt2SidxMXSn bin, 0<rt>
  | c when c &&& 0b11111011u = 0b11100010u -> raise UnallocatedException
  | 0b11100001u -> Opcode.LD2, getVt2DidxMXSn bin, 0<rt>
  | 0b11100011u -> raise UnallocatedException
  | c when c &&& 0b11111101u = 0b11100101u -> raise UnallocatedException
  | c when c &&& 0b11111011u = 0b11101000u ->
    Opcode.LD4, getVt4SidxMXSn bin, 0<rt>
  | c when c &&& 0b11111011u = 0b11101010u -> raise UnallocatedException
  | 0b11101001u -> Opcode.LD4, getVt4DidxMXSn bin, 0<rt>
  | 0b11101011u -> raise UnallocatedException
  | c when c &&& 0b11111101u = 0b11101101u -> raise UnallocatedException
  | c when c &&& 0b11111100u = 0b11110000u ->
    Opcode.LD2R, getVt2tMXSn bin resNone, 0<rt>
  | c when c &&& 0b11111100u = 0b11110100u -> raise UnallocatedException
  | c when c &&& 0b11111100u = 0b11111000u ->
    Opcode.LD4R, getVt4tMXSn bin resNone, 0<rt>
  | c when c &&& 0b11111100u = 0b11111100u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseAdvSIMDSinglePostIndexed bin =
  let cond = concat (extract bin 22u 21u) (extract bin 15u 10u) 6
  let isRm11111 = (extract bin 20u 16u) = 0b11111u
  match cond with (* L:R:opcode:S:size *)
  | c when c &&& 0b10110000u = 0b00110000u -> raise UnallocatedException
  | c when c &&& 0b11111001u = 0b00010001u -> raise UnallocatedException
  | c when c &&& 0b11111001u = 0b00011001u -> raise UnallocatedException
  | c when c &&& 0b11111010u = 0b00100010u -> raise UnallocatedException
  | c when c &&& 0b11111111u = 0b00100101u -> raise UnallocatedException
  | c when c &&& 0b11111011u = 0b00101010u -> raise UnallocatedException
  | c when c &&& 0b11111111u = 0b00101011u -> raise UnallocatedException
  | c when c &&& 0b11111101u = 0b00101101u -> raise UnallocatedException
  | c when c &&& 0b11111000u = 0b00000000u && not isRm11111 ->
    Opcode.ST1, getVt1BidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111000u = 0b00001000u && not isRm11111 ->
    Opcode.ST3, getVt3BidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111001u = 0b00010000u && not isRm11111 ->
    Opcode.ST1, getVt1HidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111001u = 0b00011000u && not isRm11111 ->
    Opcode.ST3, getVt3HidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111011u = 0b00100000u && not isRm11111 ->
    Opcode.ST1, getVt1SidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111111u = 0b00100001u && not isRm11111 ->
    Opcode.ST1, getVt1DidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111011u = 0b00101000u && not isRm11111 ->
    Opcode.ST3, getVt3SidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111111u = 0b00101001u && not isRm11111 ->
    Opcode.ST3, getVt3DidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111000u = 0b00000000u && isRm11111 ->
    Opcode.ST1, getVt1BidxPoXSnI1 bin, 0<rt>
  | c when c &&& 0b11111000u = 0b00001000u && isRm11111 ->
    Opcode.ST3, getVt3BidxPoXSnI3 bin, 0<rt>
  | c when c &&& 0b11111001u = 0b00010000u && isRm11111 ->
    Opcode.ST1, getVt1HidxPoXSnI2 bin, 0<rt>
  | c when c &&& 0b11111001u = 0b00011000u && isRm11111 ->
    Opcode.ST3, getVt3HidxPoXSnI6 bin, 0<rt>
  | c when c &&& 0b11111011u = 0b00100000u && isRm11111 ->
    Opcode.ST1, getVt1SidxPoXSnI4 bin, 0<rt>
  | c when c &&& 0b11111111u = 0b00100001u && isRm11111 ->
    Opcode.ST1, getVt1DidxPoXSnI8 bin, 0<rt>
  | c when c &&& 0b11111011u = 0b00101000u && isRm11111 ->
    Opcode.ST3, getVt3SidxPoXSnI12 bin, 0<rt>
  | c when c &&& 0b11111111u = 0b00101001u && isRm11111 ->
    Opcode.ST3, getVt3DidxPoXSnI24 bin, 0<rt>
  | c when c &&& 0b11111001u = 0b01010001u -> raise UnallocatedException
  | c when c &&& 0b11111001u = 0b01011001u -> raise UnallocatedException
  | c when c &&& 0b11111011u = 0b01100010u -> raise UnallocatedException
  | c when c &&& 0b11111111u = 0b01100011u -> raise UnallocatedException
  | c when c &&& 0b11111101u = 0b01100101u -> raise UnallocatedException
  | c when c &&& 0b11111011u = 0b01101010u -> raise UnallocatedException
  | c when c &&& 0b11111111u = 0b01101011u -> raise UnallocatedException
  | c when c &&& 0b11111101u = 0b01101101u -> raise UnallocatedException
  | c when c &&& 0b11111000u = 0b01000000u && not isRm11111 ->
    Opcode.ST2, getVt2BidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111000u = 0b01001000u && not isRm11111 ->
    Opcode.ST4, getVt4BidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111001u = 0b01010000u && not isRm11111 ->
    Opcode.ST2, getVt2HidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111001u = 0b01011000u && not isRm11111 ->
    Opcode.ST4, getVt4HidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111011u = 0b01100000u && not isRm11111 ->
    Opcode.ST2, getVt2SidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111111u = 0b01100001u && not isRm11111 ->
    Opcode.ST2, getVt2DidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111011u = 0b01101000u && not isRm11111 ->
    Opcode.ST4, getVt4SidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111111u = 0b01101001u && not isRm11111 ->
    Opcode.ST4, getVt4DidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111000u = 0b01000000u && isRm11111 ->
    Opcode.ST2, getVt2BidxPoXSnI2 bin, 0<rt>
  | c when c &&& 0b11111000u = 0b01001000u && isRm11111 ->
    Opcode.ST4, getVt4BidxPoXSnI4 bin, 0<rt>
  | c when c &&& 0b11111001u = 0b01010000u && isRm11111 ->
    Opcode.ST2, getVt2HidxPoXSnI4 bin, 0<rt>
  | c when c &&& 0b11111001u = 0b01011000u && isRm11111 ->
    Opcode.ST4, getVt4HidxPoXSnI8 bin, 0<rt>
  | c when c &&& 0b11111011u = 0b01100000u && isRm11111 ->
    Opcode.ST2, getVt2SidxPoXSnI8 bin, 0<rt>
  | c when c &&& 0b11111111u = 0b01100001u && isRm11111 ->
    Opcode.ST2, getVt2DidxPoXSnI16 bin, 0<rt>
  | c when c &&& 0b11111011u = 0b01101000u && isRm11111 ->
    Opcode.ST4, getVt4SidxPoXSnI16 bin, 0<rt>
  | c when c &&& 0b11111111u = 0b01101001u && isRm11111 ->
    Opcode.ST4, getVt4DidxPoXSnI32 bin, 0<rt>
  | c when c &&& 0b11111001u = 0b10010001u -> raise UnallocatedException
  | c when c &&& 0b11111001u = 0b10011001u -> raise UnallocatedException
  | c when c &&& 0b11111010u = 0b10100010u -> raise UnallocatedException
  | c when c &&& 0b11111111u = 0b10100101u -> raise UnallocatedException
  | c when c &&& 0b11111011u = 0b10101010u -> raise UnallocatedException
  | c when c &&& 0b11111111u = 0b10101011u -> raise UnallocatedException
  | c when c &&& 0b11111101u = 0b10101101u -> raise UnallocatedException
  | c when c &&& 0b11111100u = 0b10110100u -> raise UnallocatedException
  | c when c &&& 0b11111100u = 0b10111100u -> raise UnallocatedException
  | c when c &&& 0b11111000u = 0b10000000u && not isRm11111 ->
    Opcode.LD1, getVt1BidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111000u = 0b10001000u && not isRm11111 ->
    Opcode.LD3, getVt3BidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111001u = 0b10010000u && not isRm11111 ->
    Opcode.LD1, getVt1HidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111001u = 0b10011000u && not isRm11111 ->
    Opcode.LD3, getVt3HidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111011u = 0b10100000u && not isRm11111 ->
    Opcode.LD1, getVt1SidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111111u = 0b10100001u && not isRm11111 ->
    Opcode.LD1, getVt1DidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111011u = 0b10101000u && not isRm11111 ->
    Opcode.LD3, getVt3SidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111111u = 0b10101001u && not isRm11111 ->
    Opcode.LD3, getVt3DidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111100u = 0b10110000u && not isRm11111 ->
    Opcode.LD1R, getVt1tPoXSnXm bin resNone, 0<rt>
  | c when c &&& 0b11111100u = 0b10111000u && not isRm11111 ->
    Opcode.LD3R, getVt3tPoXSnXm bin resNone, 0<rt>
  | c when c &&& 0b11111000u = 0b10000000u && isRm11111 ->
    Opcode.LD1, getVt1BidxPoXSnI1 bin, 0<rt>
  | c when c &&& 0b11111000u = 0b10001000u && isRm11111 ->
    Opcode.LD3, getVt3BidxPoXSnI3 bin, 0<rt>
  | c when c &&& 0b11111001u = 0b10010000u && isRm11111 ->
    Opcode.LD1, getVt1HidxPoXSnI2 bin, 0<rt>
  | c when c &&& 0b11111001u = 0b10011000u && isRm11111 ->
    Opcode.LD3, getVt3HidxPoXSnI6 bin, 0<rt>
  | c when c &&& 0b11111011u = 0b10100000u && isRm11111 ->
    Opcode.LD1, getVt1SidxPoXSnI4 bin, 0<rt>
  | c when c &&& 0b11111111u = 0b10100001u && isRm11111 ->
    Opcode.LD1, getVt1DidxPoXSnI8 bin, 0<rt>
  | c when c &&& 0b11111011u = 0b10101000u && isRm11111 ->
    Opcode.LD3, getVt3SidxPoXSnI12 bin, 0<rt>
  | c when c &&& 0b11111111u = 0b10101001u && isRm11111 ->
    Opcode.LD3, getVt3DidxPoXSnI24 bin, 0<rt>
  | c when c &&& 0b11111100u = 0b10110000u && isRm11111 ->
    Opcode.LD1R, getVt1tPoXSnImm2 bin, 0<rt>
  | c when c &&& 0b11111100u = 0b10111000u && isRm11111 ->
    Opcode.LD3R, getVt3tPoXSnImm2 bin, 0<rt>
  | c when c &&& 0b11111001u = 0b11010001u -> raise UnallocatedException
  | c when c &&& 0b11111001u = 0b11011001u -> raise UnallocatedException
  | c when c &&& 0b11111011u = 0b11100010u -> raise UnallocatedException
  | c when c &&& 0b11111111u = 0b11100011u -> raise UnallocatedException
  | c when c &&& 0b11111101u = 0b11100101u -> raise UnallocatedException
  | c when c &&& 0b11111011u = 0b11101010u -> raise UnallocatedException
  | c when c &&& 0b11111111u = 0b11101011u -> raise UnallocatedException
  | c when c &&& 0b11111101u = 0b11101101u -> raise UnallocatedException
  | c when c &&& 0b11111100u = 0b11110100u -> raise UnallocatedException
  | c when c &&& 0b11111100u = 0b11111100u -> raise UnallocatedException
  | c when c &&& 0b11111000u = 0b11000000u && not isRm11111 ->
    Opcode.LD2, getVt2BidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111000u = 0b11001000u && not isRm11111 ->
    Opcode.LD4, getVt4BidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111001u = 0b11010000u && not isRm11111 ->
    Opcode.LD2, getVt2HidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111001u = 0b11011000u && not isRm11111 ->
    Opcode.LD4, getVt4HidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111011u = 0b11100000u && not isRm11111 ->
    Opcode.LD2, getVt2SidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111111u = 0b11100001u && not isRm11111 ->
    Opcode.LD2, getVt2DidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111011u = 0b11101000u && not isRm11111 ->
    Opcode.LD4, getVt4SidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111111u = 0b11101001u && not isRm11111 ->
    Opcode.LD4, getVt4DidxPoXSnXm bin, 0<rt>
  | c when c &&& 0b11111100u = 0b11110000u && not isRm11111 ->
    Opcode.LD2R, getVt2tPoXSnXm bin resNone, 0<rt>
  | c when c &&& 0b11111100u = 0b11111000u && not isRm11111 ->
    Opcode.LD4R, getVt4tPoXSnXm bin resNone, 0<rt>
  | c when c &&& 0b11111000u = 0b11000000u && isRm11111 ->
    Opcode.LD2, getVt2BidxPoXSnI2 bin, 0<rt>
  | c when c &&& 0b11111000u = 0b11001000u && isRm11111 ->
    Opcode.LD4, getVt4BidxPoXSnI4 bin, 0<rt>
  | c when c &&& 0b11111001u = 0b11010000u && isRm11111 ->
    Opcode.LD2, getVt2HidxPoXSnI4 bin, 0<rt>
  | c when c &&& 0b11111001u = 0b11011000u && isRm11111 ->
    Opcode.LD4, getVt4HidxPoXSnI8 bin, 0<rt>
  | c when c &&& 0b11111011u = 0b11100000u && isRm11111 ->
    Opcode.LD2, getVt2SidxPoXSnI8 bin, 0<rt>
  | c when c &&& 0b11111111u = 0b11100001u && isRm11111 ->
    Opcode.LD2, getVt2DidxPoXSnI16 bin, 0<rt>
  | c when c &&& 0b11111011u = 0b11101000u && isRm11111 ->
    Opcode.LD4, getVt4SidxPoXSnI16 bin, 0<rt>
  | c when c &&& 0b11111111u = 0b11101001u && isRm11111 ->
    Opcode.LD4, getVt4DidxPoXSnI32 bin, 0<rt>
  | c when c &&& 0b11111100u = 0b11110000u && isRm11111 ->
    Opcode.LD2R, getVt2tPoXSnImm2 bin, 0<rt>
  | c when c &&& 0b11111100u = 0b11111000u && isRm11111 ->
    Opcode.LD4R, getVt4tPoXSnImm2 bin, 0<rt>
  | _ -> raise InvalidOpcodeException

let parseLoadRegLiteral bin =
  let cond = concat (extract bin 31u 30u) (pickBit bin 26u) 1 (* opc:V *)
  match cond with
  | 0b000u -> Opcode.LDR, getWtLabel bin, 32<rt>
  | 0b001u -> Opcode.LDR, getStLabel bin, 32<rt>
  | 0b010u -> Opcode.LDR, getXtLabel bin, 64<rt>
  | 0b011u -> Opcode.LDR, getDtLabel bin, 64<rt>
  | 0b100u -> Opcode.LDRSW, getXtLabel bin, 64<rt>
  | 0b101u -> Opcode.LDR, getQtLabel bin, 128<rt>
  | 0b110u -> Opcode.PRFM, getPrfopImm5Label bin, 0<rt>
  | 0b111u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseLoadStoreExclusive bin =
  let cond = concat (concat (extract bin 31u 30u) (extract bin 23u 21u) 3)
                    (pickBit bin 15u) 1 (* size:o2:L:o1:o0 *)
  let rt2 = extract bin 14u 10u
  match cond with
  | c when c &&& 0b001011u = 0b001000u (* FEAT_LOR *) ->
    raise UnallocatedException
  | c when c &&& 0b001010u = 0b001010u && rt2 <> 0b11111u ->
    raise UnallocatedException
  | c when c &&& 0b100010u = 0b000010u && rt2 <> 0b11111u ->
    raise UnallocatedException
  | 0b000000u -> Opcode.STXRB, getWsWtMXSn bin, 32<rt>
  | 0b000001u -> Opcode.STLXRB, getWsWtMXSn bin, 32<rt>
  | 0b000100u -> Opcode.LDXRB, getWtMXSn bin, 32<rt>
  | 0b000101u -> Opcode.LDAXRB, getWtMXSn bin, 32<rt>
  | 0b001001u -> Opcode.STLRB, getWtMXSn bin, 32<rt>
  | 0b001101u -> Opcode.LDARB, getWtMXSn bin, 32<rt>
  | 0b010000u -> Opcode.STXRH, getWsWtMXSn bin, 32<rt>
  | 0b010001u -> Opcode.STLXRH, getWsWtMXSn bin, 32<rt>
  | 0b010100u -> Opcode.LDXRH, getWtMXSn bin, 32<rt>
  | 0b010101u -> Opcode.LDAXRH, getWtMXSn bin, 32<rt>
  | 0b011001u -> Opcode.STLRH, getWtMXSn bin, 32<rt>
  | 0b011101u -> Opcode.LDARH, getWtMXSn bin, 32<rt>
  | 0b100000u -> Opcode.STXR, getWsWtMXSn bin, 32<rt>
  | 0b100001u -> Opcode.STLXR, getWsWtMXSn bin, 32<rt>
  | 0b100010u -> Opcode.STXP, getWsWt1Wt2MXSn bin, 32<rt>
  | 0b100011u -> Opcode.STLXP, getWsWt1Wt2MXSn bin, 32<rt>
  | 0b100100u -> Opcode.LDXR, getWtMXSn bin, 32<rt>
  | 0b100101u -> Opcode.LDAXR, getWtMXSn bin, 32<rt>
  | 0b100110u -> Opcode.LDXP, getWt1Wt2MXSn bin, 32<rt>
  | 0b100111u -> Opcode.LDAXP, getWt1Wt2MXSn bin, 32<rt>
  | 0b101001u -> Opcode.STLR, getWtMXSn bin, 32<rt>
  | 0b101010u when rt2 = 0b11111u -> Opcode.CAS, getWsWtMXSn bin, 32<rt>
  | 0b101011u when rt2 = 0b11111u -> Opcode.CASL, getWsWtMXSn bin, 32<rt>
  | 0b101101u -> Opcode.LDAR, getWtMXSn bin, 32<rt>
  | 0b101110u when rt2 = 0b11111u -> Opcode.CASA, getWsWtMXSn bin, 32<rt>
  | 0b101111u when rt2 = 0b11111u -> Opcode.CASAL, getWsWtMXSn bin, 32<rt>
  | 0b110000u -> Opcode.STXR, getWsXtMXSn bin, 64<rt>
  | 0b110001u -> Opcode.STLXR, getWsXtMXSn bin, 64<rt>
  | 0b110010u -> Opcode.STXP, getWsXt1Xt2MXSn bin, 64<rt>
  | 0b110011u -> Opcode.STLXP, getWsXt1Xt2MXSn bin, 64<rt>
  | 0b110100u -> Opcode.LDXR, getXtMXSn bin, 64<rt>
  | 0b110101u -> Opcode.LDAXR, getXtMXSn bin, 64<rt>
  | 0b110110u -> Opcode.LDXP, getXt1Xt2MXSn bin, 64<rt>
  | 0b110111u -> Opcode.LDAXP, getXt1Xt2MXSn bin, 64<rt>
  | 0b111001u -> Opcode.STLR, getXtMXSn bin, 64<rt>
  | 0b111010u when rt2 = 0b11111u -> Opcode.CAS, getXsXtMXSn bin, 64<rt>
  | 0b111011u when rt2 = 0b11111u -> Opcode.CASL, getXsXtMXSn bin, 64<rt>
  | 0b111101u -> Opcode.LDAR, getXtMXSn bin, 64<rt>
  | 0b111110u when rt2 = 0b11111u -> Opcode.CASA, getXsXtMXSn bin, 64<rt>
  | 0b111111u when rt2 = 0b11111u -> Opcode.CASAL, getXsXtMXSn bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let parseLoadStoreNoAllocatePairOffset bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (pickBit bin 22u) 1 (* opc:V:L *)
  match cond with
  | 0b0000u -> Opcode.STNP, getWt1Wt2BIXSnimm bin 2, 32<rt>
  | 0b0001u -> Opcode.LDNP, getWt1Wt2BIXSnimm bin 2, 32<rt>
  | 0b0010u -> Opcode.STNP, getSt1St2BIXSnimm bin 2, 32<rt>
  | 0b0011u -> Opcode.LDNP, getSt1St2BIXSnimm bin 2, 32<rt>
  | c when c &&& 0b1110u = 0b0100u -> raise UnallocatedException
  | 0b0110u -> Opcode.STNP, getDt1Dt2BIXSnimm bin 3, 64<rt>
  | 0b0111u -> Opcode.LDNP, getDt1Dt2BIXSnimm bin 3, 64<rt>
  | 0b1000u -> Opcode.STNP, getXt1Xt2BIXSnimm bin 3, 64<rt>
  | 0b1001u -> Opcode.LDNP, getXt1Xt2BIXSnimm bin 3, 64<rt>
  | 0b1010u -> Opcode.STNP, getQt1Qt2BIXSnimm bin 4, 128<rt>
  | 0b1011u -> Opcode.LDNP, getQt1Qt2BIXSnimm bin 4, 128<rt>
  | c when c &&& 0b1100u = 0b1100u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseLoadStoreRegImmPostIndexed bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (extract bin 23u 22u) 2 (* size:V:opc *)
  match cond with
  | c when c &&& 0b01110u = 0b01110u -> raise UnallocatedException
  | 0b00000u -> Opcode.STRB, getWtPoXSnsimm bin, 32<rt>
  | 0b00001u -> Opcode.LDRB, getWtPoXSnsimm bin, 32<rt>
  | 0b00010u -> Opcode.LDRSB, getXtPoXSnsimm bin, 64<rt>
  | 0b00011u -> Opcode.LDRSB, getWtPoXSnsimm bin, 32<rt>
  | 0b00100u -> Opcode.STR, getBtPoXSnsimm bin, 8<rt>
  | 0b00101u -> Opcode.LDR, getBtPoXSnsimm bin, 8<rt>
  | 0b00110u -> Opcode.STR, getQtPoXSnsimm bin, 128<rt>
  | 0b00111u -> Opcode.LDR, getQtPoXSnsimm bin, 128<rt>
  | 0b01000u -> Opcode.STRH, getWtPoXSnsimm bin, 32<rt>
  | 0b01001u -> Opcode.LDRH, getWtPoXSnsimm bin, 32<rt>
  | 0b01010u -> Opcode.LDRSH, getXtPoXSnsimm bin, 64<rt>
  | 0b01011u -> Opcode.LDRSH, getWtPoXSnsimm bin, 32<rt>
  | 0b01100u -> Opcode.STR, getHtPoXSnsimm bin, 16<rt>
  | 0b01101u -> Opcode.LDR, getHtPoXSnsimm bin, 16<rt>
  | c when c &&& 0b10111u = 0b10011u -> raise UnallocatedException
  | c when c &&& 0b10110u = 0b10110u -> raise UnallocatedException
  | 0b10000u -> Opcode.STR, getWtPoXSnsimm bin, 32<rt>
  | 0b10001u -> Opcode.LDR, getWtPoXSnsimm bin, 32<rt>
  | 0b10010u -> Opcode.LDRSW, getXtPoXSnsimm bin, 64<rt>
  | 0b10100u -> Opcode.STR, getStPoXSnsimm bin, 32<rt>
  | 0b10101u -> Opcode.LDR, getStPoXSnsimm bin, 32<rt>
  | 0b11000u -> Opcode.STR, getXtPoXSnsimm bin, 64<rt>
  | 0b11001u -> Opcode.LDR, getXtPoXSnsimm bin, 64<rt>
  | 0b11010u -> raise UnallocatedException
  | 0b11100u -> Opcode.STR, getDtPoXSnsimm bin, 64<rt>
  | 0b11101u -> Opcode.LDR, getDtPoXSnsimm bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let parseLoadStoreRegImmPreIndexed bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (extract bin 23u 22u) 2 (* size:V:opc *)
  match cond with
  | c when c &&& 0b01110u = 0b01110u -> raise UnallocatedException
  | 0b00000u -> Opcode.STRB, getWtPrXSnsimm bin, 32<rt>
  | 0b00001u -> Opcode.LDRB, getWtPrXSnsimm bin, 32<rt>
  | 0b00010u -> Opcode.LDRSB, getXtPrXSnsimm bin, 64<rt>
  | 0b00011u -> Opcode.LDRSB, getWtPrXSnsimm bin, 32<rt>
  | 0b00100u -> Opcode.STR, getBtPrXSnsimm bin, 8<rt>
  | 0b00101u -> Opcode.LDR, getBtPrXSnsimm bin, 8<rt>
  | 0b00110u -> Opcode.STR, getQtPrXSnsimm bin, 128<rt>
  | 0b00111u -> Opcode.LDR, getQtPrXSnsimm bin, 128<rt>
  | 0b01000u -> Opcode.STRH, getWtPrXSnsimm bin, 32<rt>
  | 0b01001u -> Opcode.LDRH, getWtPrXSnsimm bin, 32<rt>
  | 0b01010u -> Opcode.LDRSH, getXtPrXSnsimm bin, 64<rt>
  | 0b01011u -> Opcode.LDRSH, getWtPrXSnsimm bin, 32<rt>
  | 0b01100u -> Opcode.STR, getHtPrXSnsimm bin, 16<rt>
  | 0b01101u -> Opcode.LDR, getHtPrXSnsimm bin, 16<rt>
  | c when c &&& 0b10111u = 0b10011u -> raise UnallocatedException
  | c when c &&& 0b10110u = 0b10110u -> raise UnallocatedException
  | 0b10000u -> Opcode.STR, getWtPrXSnsimm bin, 32<rt>
  | 0b10001u -> Opcode.LDR, getWtPrXSnsimm bin, 32<rt>
  | 0b10010u -> Opcode.LDRSW, getXtPrXSnsimm bin, 64<rt>
  | 0b10100u -> Opcode.STR, getStPrXSnsimm bin, 32<rt>
  | 0b10101u -> Opcode.LDR, getStPrXSnsimm bin, 32<rt>
  | 0b11100u -> Opcode.STR, getDtPrXSnsimm bin, 64<rt>
  | 0b11101u -> Opcode.LDR, getDtPrXSnsimm bin, 64<rt>
  | 0b11010u -> raise UnallocatedException
  | 0b11000u -> Opcode.STR, getXtPrXSnsimm bin, 64<rt>
  | 0b11001u -> Opcode.LDR, getXtPrXSnsimm bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let parseLoadStoreRegOffset bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (extract bin 23u 22u) 2
  let option = extract bin 15u 13u
  let isOption011 = option = 0b011u
  if option &&& 0b010u = 0b000u then raise UnallocatedException else ()
  match cond with (* size:V:opc *)
  | c when c &&& 0b01110u = 0b01110u -> raise UnallocatedException
  | 0b00000u when not isOption011 -> Opcode.STRB, getWtBEXSnrmamt bin 0L, 32<rt>
  | 0b00000u when isOption011 -> Opcode.STRB, getWtBRXSnxmamt bin, 32<rt>
  | 0b00001u when not isOption011 -> Opcode.LDRB, getWtBEXSnrmamt bin 0L, 32<rt>
  | 0b00001u when isOption011 -> Opcode.LDRB, getWtBRXSnxmamt bin, 32<rt>
  | 0b00010u when not isOption011 ->
    Opcode.LDRSB, getXtBEXSnrmamt bin 0L, 64<rt>
  | 0b00010u when isOption011 -> Opcode.LDRSB, getXtBRXSnxmamt bin, 64<rt>
  | 0b00011u when not isOption011 ->
    Opcode.LDRSB, getWtBEXSnrmamt bin 0L, 32<rt>
  | 0b00011u when isOption011 -> Opcode.LDRSB, getWtBRXSnxmamt bin, 32<rt>
  | 0b00100u when not isOption011 -> Opcode.STR, getBtBEXSnrmamt bin, 8<rt>
  | 0b00100u when isOption011 -> Opcode.STR, getBtBRXSnxmamt bin, 8<rt>
  | 0b00101u when not isOption011 -> Opcode.LDR, getBtBEXSnrmamt bin, 8<rt>
  | 0b00101u when isOption011 -> Opcode.LDR, getBtBRXSnxmamt bin, 8<rt>
  | 0b00110u -> Opcode.STR, getQtBEXSnrmamt bin, 128<rt>
  | 0b00111u -> Opcode.LDR, getQtBEXSnrmamt bin, 128<rt>
  | 0b01000u -> Opcode.STRH, getWtBEXSnrmamt bin 1L, 32<rt>
  | 0b01001u -> Opcode.LDRH, getWtBEXSnrmamt bin 1L, 32<rt>
  | 0b01010u -> Opcode.LDRSH, getXtBEXSnrmamt bin 1L, 64<rt>
  | 0b01011u -> Opcode.LDRSH, getWtBEXSnrmamt bin 1L, 32<rt>
  | 0b01100u -> Opcode.STR, getHtBEXSnrmamt bin, 16<rt>
  | 0b11101u -> Opcode.LDR, getHtBEXSnrmamt bin, 16<rt>
  | c when c &&& 0b10111u = 0b10011u -> raise UnallocatedException
  | c when c &&& 0b10110u = 0b10110u -> raise UnallocatedException
  | 0b10000u -> Opcode.STR, getWtBEXSnrmamt bin 2L, 32<rt>
  | 0b10001u -> Opcode.LDR, getWtBEXSnrmamt bin 2L, 32<rt>
  | 0b10010u -> Opcode.LDRSW, getXtBEXSnrmamt bin 2L, 64<rt>
  | 0b10100u -> Opcode.STR, getStBEXSnrmamt bin, 32<rt>
  | 0b10101u -> Opcode.LDR, getStBEXSnrmamt bin, 32<rt>
  | 0b11000u -> Opcode.STR, getXtBEXSnrmamt bin 3L, 64<rt>
  | 0b11001u -> Opcode.LDR, getXtBEXSnrmamt bin 3L, 64<rt>
  | 0b11010u -> Opcode.PRFM, getPrfopimm5BEXSnrmamt bin, 0<rt>
  | 0b11100u -> Opcode.STR, getDtBEXSnrmamt bin, 64<rt>
  | 0b01101u -> Opcode.LDR, getDtBEXSnrmamt bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let parseLoadStoreRegUnprivileged bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (extract bin 23u 22u) 2 (* size:V:opc *)
  match cond with
  | c when c &&& 0b00100u = 0b00100u -> raise UnallocatedException
  | 0b00000u -> Opcode.STTRB, getWtBIXSnsimm bin, 32<rt>
  | 0b00001u -> Opcode.LDTRB, getWtBIXSnsimm bin, 32<rt>
  | 0b00010u -> Opcode.LDTRSB, getXtBIXSnsimm bin, 64<rt>
  | 0b00011u -> Opcode.LDTRSB, getWtBIXSnsimm bin, 32<rt>
  | 0b01000u -> Opcode.STTRH, getWtBIXSnsimm bin, 32<rt>
  | 0b01001u -> Opcode.LDTRH, getWtBIXSnsimm bin, 32<rt>
  | 0b01010u -> Opcode.LDTRSH, getXtBIXSnsimm bin, 64<rt>
  | 0b01011u -> Opcode.LDTRSH, getWtBIXSnsimm bin, 32<rt>
  | c when c &&& 0b10111u = 0b10011u -> raise UnallocatedException
  | 0b10000u -> Opcode.STTR, getWtBIXSnsimm bin, 32<rt>
  | 0b10001u -> Opcode.LDTR, getWtBIXSnsimm bin, 32<rt>
  | 0b10010u -> Opcode.LDTRSW, getXtBIXSnsimm bin, 64<rt>
  | 0b11000u -> Opcode.STTR, getXtBIXSnsimm bin, 64<rt>
  | 0b11001u -> Opcode.LDTR, getXtBIXSnsimm bin, 64<rt>
  | 0b11010u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseLoadStoreRegUnscaledImm bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (extract bin 23u 22u) 2 (* size:V:opc *)
  match cond with
  | c when c &&& 0b01110u = 0b01110u -> raise UnallocatedException
  | 0b00000u -> Opcode.STURB, getWtBIXSnsimm bin, 32<rt>
  | 0b00001u -> Opcode.LDURB, getWtBIXSnsimm bin, 32<rt>
  | 0b00010u -> Opcode.LDURSB, getXtBIXSnsimm bin, 64<rt>
  | 0b00011u -> Opcode.LDURSB, getWtBIXSnsimm bin, 32<rt>
  | 0b00100u -> Opcode.STUR, getBtBIXSnsimm bin, 8<rt>
  | 0b00101u -> Opcode.LDUR, getBtBIXSnsimm bin, 8<rt>
  | 0b00110u -> Opcode.STUR, getQtBIXSnsimm bin, 128<rt>
  | 0b00111u -> Opcode.LDUR, getQtBIXSnsimm bin, 128<rt>
  | 0b01000u -> Opcode.STURH, getWtBIXSnsimm bin, 32<rt>
  | 0b01001u -> Opcode.LDURH, getWtBIXSnsimm bin, 32<rt>
  | 0b01010u -> Opcode.LDURSH, getXtBIXSnsimm bin, 64<rt>
  | 0b01011u -> Opcode.LDURSH, getWtBIXSnsimm bin, 32<rt>
  | 0b01100u -> Opcode.STUR, getHtBIXSnsimm bin, 16<rt>
  | 0b01101u -> Opcode.LDUR, getHtBIXSnsimm bin, 16<rt>
  | c when c &&& 0b10111u = 0b10011u -> raise UnallocatedException
  | c when c &&& 0b10110u = 0b10110u -> raise UnallocatedException
  | 0b10000u -> Opcode.STUR, getWtBIXSnsimm bin, 32<rt>
  | 0b10001u -> Opcode.LDUR, getWtBIXSnsimm bin, 32<rt>
  | 0b10010u -> Opcode.LDURSW, getXtBIXSnsimm bin, 64<rt>
  | 0b10100u -> Opcode.STUR, getStBIXSnsimm bin, 32<rt>
  | 0b10101u -> Opcode.LDUR, getStBIXSnsimm bin, 32<rt>
  | 0b11000u -> Opcode.STUR, getXtBIXSnsimm bin, 64<rt>
  | 0b11001u -> Opcode.LDUR, getXtBIXSnsimm bin, 64<rt>
  | 0b11010u -> Opcode.PRFUM, getPrfopimm5BIXSnsimm bin, 0<rt>
  | 0b11100u -> Opcode.STUR, getDtBIXSnsimm bin, 64<rt>
  | 0b11101u -> Opcode.LDUR, getDtBIXSnsimm bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let parseLoadStoreRegUnsignedImm bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (extract bin 23u 22u) 2 (* size:V:opc *)
  match cond with
  | c when c &&& 0b01110u = 0b01110u -> raise UnallocatedException
  | 0b00000u -> Opcode.STRB, getWtBIXSnpimm bin 1u, 8<rt>
  | 0b00001u -> Opcode.LDRB, getWtBIXSnpimm bin 1u, 32<rt>
  | 0b00010u -> Opcode.LDRSB, getXtBIXSnpimm bin 1u, 64<rt>
  | 0b00011u -> Opcode.LDRSB, getWtBIXSnpimm bin 1u, 32<rt>
  | 0b00100u -> Opcode.STR, getBtBIXSnpimm bin, 8<rt>
  | 0b00101u -> Opcode.LDR, getBtBIXSnpimm bin, 8<rt>
  | 0b00110u -> Opcode.STR, getQtBIXSnpimm bin, 128<rt>
  | 0b00111u -> Opcode.LDR, getQtBIXSnpimm bin, 128<rt>
  | 0b01000u -> Opcode.STRH, getWtBIXSnpimm bin 2u, 32<rt>
  | 0b01001u -> Opcode.LDRH, getWtBIXSnpimm bin 2u, 32<rt>
  | 0b01010u -> Opcode.LDRSH, getXtBIXSnpimm bin 2u, 64<rt>
  | 0b01011u -> Opcode.LDRSH, getWtBIXSnpimm bin 2u, 32<rt>
  | 0b01100u -> Opcode.STR, getHtBIXSnpimm bin, 16<rt>
  | 0b01101u -> Opcode.LDR, getHtBIXSnpimm bin, 16<rt>
  | c when c &&& 0b10111u = 0b10011u -> raise UnallocatedException
  | c when c &&& 0b10110u = 0b10110u -> raise UnallocatedException
  | 0b10000u -> Opcode.STR, getWtBIXSnpimm bin 4u, 32<rt>
  | 0b10001u -> Opcode.LDR, getWtBIXSnpimm bin 4u, 32<rt>
  | 0b10010u -> Opcode.LDRSW, getXtBIXSnpimm bin 4u, 64<rt>
  | 0b10100u -> Opcode.STR, getStBIXSnpimm bin, 32<rt>
  | 0b10101u -> Opcode.LDR, getStBIXSnpimm bin, 32<rt>
  | 0b11000u -> Opcode.STR, getXtBIXSnpimm bin 8u, 64<rt>
  | 0b11001u -> Opcode.LDR, getXtBIXSnpimm bin 8u, 64<rt>
  | 0b11010u -> Opcode.PRFM, getPrfopimm5BIXSnpimm bin, 0<rt>
  | 0b11100u -> Opcode.STR, getDtBIXSnpimm bin, 64<rt>
  | 0b11101u -> Opcode.LDR, getDtBIXSnpimm bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let parseLoadStoreRegPairOffset bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (pickBit bin 22u) 1 (* opc:V:L *)
  match cond with
  | 0b0000u -> Opcode.STP, getWt1Wt2BIXSnimm bin 2, 32<rt>
  | 0b0001u -> Opcode.LDP, getWt1Wt2BIXSnimm bin 2, 32<rt>
  | 0b0010u -> Opcode.STP, getSt1St2BIXSnimm bin 2, 32<rt>
  | 0b0011u -> Opcode.LDP, getSt1St2BIXSnimm bin 2, 32<rt>
  | 0b0100u -> raise UnallocatedException
  | 0b0101u -> Opcode.LDPSW, getXt1Xt2BIXSnimm bin 2, 64<rt>
  | 0b0110u -> Opcode.STP, getDt1Dt2BIXSnimm bin 3, 64<rt>
  | 0b0111u -> Opcode.LDP, getDt1Dt2BIXSnimm bin 3, 64<rt>
  | 0b1000u -> Opcode.STP, getXt1Xt2BIXSnimm bin 3, 64<rt>
  | 0b1001u -> Opcode.LDP, getXt1Xt2BIXSnimm bin 3, 64<rt>
  | 0b1010u -> Opcode.STP, getQt1Qt2BIXSnimm bin 4, 128<rt>
  | 0b1011u -> Opcode.LDP, getQt1Qt2BIXSnimm bin 4, 128<rt>
  | c when c &&& 0b1100u = 0b1100u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseLoadStoreRegPairPostIndexed bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (pickBit bin 22u) 1 (* opc:V:L *)
  match cond with
  | 0b0000u -> Opcode.STP, getWt1Wt2PoXSnimm bin, 32<rt>
  | 0b0001u -> Opcode.LDP, getWt1Wt2PoXSnimm bin, 32<rt>
  | 0b0010u -> Opcode.STP, getSt1St2PoXSnimm bin, 32<rt>
  | 0b0011u -> Opcode.LDP, getSt1St2PoXSnimm bin, 32<rt>
  | 0b0100u -> raise UnallocatedException
  | 0b0101u -> Opcode.LDPSW, getXt1Xt2PoXSnimm bin 2, 64<rt>
  | 0b0110u -> Opcode.STP, getDt1Dt2PoXSnimm bin, 64<rt>
  | 0b0111u -> Opcode.LDP, getDt1Dt2PoXSnimm bin, 64<rt>
  | 0b1000u -> Opcode.STP, getXt1Xt2PoXSnimm bin 3, 64<rt>
  | 0b1001u -> Opcode.LDP, getXt1Xt2PoXSnimm bin 3, 64<rt>
  | 0b1010u -> Opcode.STP, getQt1Qt2PoXSnimm bin, 128<rt>
  | 0b1011u -> Opcode.LDP, getQt1Qt2PoXSnimm bin, 128<rt>
  | c when c &&& 0b1100u = 0b1100u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseLoadStoreRegPairPreIndexed bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (pickBit bin 22u) 1 (* opc:V:L *)
  match cond with
  | 0b0000u -> Opcode.STP, getWt1Wt2PrXSnimm bin, 32<rt>
  | 0b0001u -> Opcode.LDP, getWt1Wt2PrXSnimm bin, 32<rt>
  | 0b0010u -> Opcode.STP, getSt1St2PrXSnimm bin, 32<rt>
  | 0b0011u -> Opcode.LDP, getSt1St2PrXSnimm bin, 32<rt>
  | 0b0100u -> raise UnallocatedException
  | 0b0101u -> Opcode.LDPSW, getXt1Xt2PrXSnimm bin 2, 64<rt>
  | 0b0110u -> Opcode.STP, getDt1Dt2PrXSnimm bin, 64<rt>
  | 0b0111u -> Opcode.LDP, getDt1Dt2PrXSnimm bin, 64<rt>
  | 0b1000u -> Opcode.STP, getXt1Xt2PrXSnimm bin 3, 64<rt>
  | 0b1001u -> Opcode.LDP, getXt1Xt2PrXSnimm bin 3, 64<rt>
  | 0b1010u -> Opcode.STP, getQt1Qt2PrXSnimm bin, 128<rt>
  | 0b1011u -> Opcode.LDP, getQt1Qt2PrXSnimm bin, 128<rt>
  | c when c &&& 0b1100u = 0b1100u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

/// Loads and stores
let parse64Group3 bin =
  let op0 = pickBit bin 31u
  let op1 = extract bin 29u 28u
  let op2 = pickBit bin 26u
  let op3 = extract bin 24u 23u
  let op4 = extract bin 21u 16u
  let op5 = extract bin 11u 10u
  let cond =
    concat (concat (concat (concat (concat op0 op1 2) op2 1) op3 2) op4 6) op5 2
  match cond with
  | c when c &&& 0b11111111111100u = 0b00010000000000u -> parseAdvSIMDMul bin
  | c when c &&& 0b11111110000000u = 0b00010100000000u ->
    parseAdvSIMDMulPostIndexed bin
  | c when c &&& 0b11111010000000u = 0b00010010000000u ->
    raise UnallocatedException
  | c when c &&& 0b11111101111100u = 0b00011000000000u ->
    parseAdvSIMDSingle bin
  | c when c &&& 0b11111100000000u = 0b00011100000000u ->
    parseAdvSIMDSinglePostIndexed bin
  | c when c &&& 0b11110101000000u = 0b00010001000000u ->
    raise UnallocatedException
  | c when c &&& 0b11110100100000u = 0b00010000100000u ->
    raise UnallocatedException
  | c when c &&& 0b11110100010000u = 0b00010000010000u ->
    raise UnallocatedException
  | c when c &&& 0b11110100001000u = 0b00010000001000u ->
    raise UnallocatedException
  | c when c &&& 0b11110100000100u = 0b00010000000100u ->
    raise UnallocatedException
  | c when c &&& 0b11110000000000u = 0b10010000000000u ->
    raise UnallocatedException
  | c when c &&& 0b01111000000000u = 0b00000000000000u ->
    parseLoadStoreExclusive bin
  | c when c &&& 0b01111000000000u = 0b00001000000000u ->
    raise UnallocatedException
  | c when c &&& 0b01101000000000u = 0b00100000000000u ->
    parseLoadRegLiteral bin
  | c when c &&& 0b01101000000000u = 0b00101000000000u ->
    raise UnallocatedException
  | c when c &&& 0b01101100000000u = 0b01000000000000u ->
    parseLoadStoreNoAllocatePairOffset bin
  | c when c &&& 0b01101100000000u = 0b01000100000000u ->
    parseLoadStoreRegPairPostIndexed bin
  | c when c &&& 0b01101100000000u = 0b01001000000000u ->
    parseLoadStoreRegPairOffset bin
  | c when c &&& 0b01101100000000u = 0b01001100000000u ->
    parseLoadStoreRegPairPreIndexed bin
  | c when c &&& 0b01101010000011u = 0b01100000000000u ->
    parseLoadStoreRegUnscaledImm bin
  | c when c &&& 0b01101010000011u = 0b01100000000001u ->
    parseLoadStoreRegImmPostIndexed bin
  | c when c &&& 0b01101010000011u = 0b01100000000010u ->
    parseLoadStoreRegUnprivileged bin
  | c when c &&& 0b01101010000011u = 0b01100000000011u ->
    parseLoadStoreRegImmPreIndexed bin
  | c when c &&& 0b01101010000011u = 0b01100010000000u ->
    raise UnallocatedException
  | c when c &&& 0b01101010000011u = 0b01100010000001u ->
    raise UnallocatedException
  | c when c &&& 0b01101010000011u = 0b01100010000010u ->
    parseLoadStoreRegOffset bin
  | c when c &&& 0b01101010000011u = 0b01100010000011u ->
    raise UnallocatedException
  | c when c &&& 0b01101000000000u = 0b01101000000000u ->
    parseLoadStoreRegUnsignedImm bin
  | _ -> raise InvalidOpcodeException

/// The alias is always the preferred disassembly.
let toAliasFromLSLV _ = Opcode.LSL
let toAliasFromLSRV _ = Opcode.LSR
let toAliasFromASRV _ = Opcode.ASR

let parseDataProcessing2Src bin =
  let cond = concat (concat (pickBit bin 31u) (pickBit bin 29u) 1)
                    (extract bin 15u 10u) 6  (* sf:S:opcode *)
  match cond with
  | c when c &&& 0b00111110u = 0b00000000u -> raise UnallocatedException
  | c when c &&& 0b00111000u = 0b00011000u -> raise UnallocatedException
  | c when c &&& 0b00100000u = 0b00100000u -> raise UnallocatedException
  | c when c &&& 0b01111100u = 0b00000100u -> raise UnallocatedException
  | c when c &&& 0b01111100u = 0b00001100u -> raise UnallocatedException
  | c when c &&& 0b01000000u = 0b01000000u -> raise UnallocatedException
  | 0b00000010u -> Opcode.UDIV, getWdWnWm bin, 32<rt>
  | 0b00000011u -> Opcode.SDIV, getWdWnWm bin, 32<rt>
  | 0b00001000u -> toAliasFromLSLV Opcode.LSLV, getWdWnWm bin, 32<rt>
  | 0b00001001u -> toAliasFromLSRV Opcode.LSRV, getWdWnWm bin, 32<rt>
  | 0b00001010u -> toAliasFromASRV Opcode.ASRV, getWdWnWm bin, 32<rt>
  | 0b00001011u -> Opcode.RORV, getWdWnWm bin, 32<rt>
  | c when c &&& 0b11111011u = 0b00010011u -> raise UnallocatedException
  | 0b00010000u -> Opcode.CRC32B, getWdWnWm bin, 32<rt>
  | 0b00010001u -> Opcode.CRC32H, getWdWnWm bin, 32<rt>
  | 0b00010010u -> Opcode.CRC32W, getWdWnWm bin, 32<rt>
  | 0b00010100u -> Opcode.CRC32CB, getWdWnWm bin, 32<rt>
  | 0b00010101u -> Opcode.CRC32CH, getWdWnWm bin, 32<rt>
  | 0b00010110u -> Opcode.CRC32CW, getWdWnWm bin, 32<rt>
  | 0b10000010u -> Opcode.UDIV, getXdXnXm bin, 64<rt>
  | 0b10000011u -> Opcode.SDIV, getXdXnXm bin, 64<rt>
  | 0b10001000u -> toAliasFromLSLV Opcode.LSLV, getXdXnXm bin, 64<rt>
  | 0b10001001u -> toAliasFromLSRV Opcode.LSRV, getXdXnXm bin, 64<rt>
  | 0b10001010u -> toAliasFromASRV Opcode.ASRV, getXdXnXm bin, 64<rt>
  | 0b10001011u -> Opcode.RORV, getXdXnXm bin, 64<rt>
  | c when c &&& 0b11111001u = 0b10010000u -> raise UnallocatedException
  | c when c &&& 0b11111010u = 0b10010000u -> raise UnallocatedException
  | 0b10010011u -> Opcode.CRC32X, getWdWnXm bin, 32<rt>
  | 0b10010111u -> Opcode.CRC32CX, getWdWnXm bin, 32<rt>
  | _ -> raise InvalidOpcodeException

let parseDataProcessing1Src bin =
  let cond = concat (concat (pickBit bin 31u) (pickBit bin 29u) 1)
                    (extract bin 20u 10u) 11 (* sf:S:opcode2:opcode *)
  let r = raise
  match cond with
  | c when c &&& 0b0000000001000u = 0b0000000001000u -> r UnallocatedException
  | c when c &&& 0b0000000010000u = 0b0000000010000u -> r UnallocatedException
  | c when c &&& 0b0000000100000u = 0b0000000100000u -> r UnallocatedException
  | c when c &&& 0b0000001000000u = 0b0000001000000u -> r UnallocatedException
  | c when c &&& 0b0000010000000u = 0b0000010000000u -> r UnallocatedException
  | c when c &&& 0b0000100000000u = 0b0000100000000u -> r UnallocatedException
  | c when c &&& 0b0001000000000u = 0b0001000000000u -> r UnallocatedException
  | c when c &&& 0b0010000000000u = 0b0010000000000u -> r UnallocatedException
  | c when c &&& 0b0111111111110u = 0b0000000000110u -> r UnallocatedException
  | c when c &&& 0b0100000000000u = 0b0100000000000u -> r UnallocatedException
  | 0b0000000000000u -> Opcode.RBIT, getWdWn bin, 32<rt>
  | 0b0000000000001u -> Opcode.REV16, getWdWn bin, 32<rt>
  | 0b0000000000010u -> Opcode.REV, getWdWn bin, 32<rt>
  | 0b0000000000011u -> raise UnallocatedException
  | 0b0000000000100u -> Opcode.CLZ, getWdWn bin, 32<rt>
  | 0b0000000000101u -> Opcode.CLS, getWdWn bin, 32<rt>
  | 0b1000000000000u -> Opcode.RBIT, getXdXn bin, 64<rt>
  | 0b1000000000001u -> Opcode.REV16, getXdXn bin, 64<rt>
  | 0b1000000000010u -> Opcode.REV32, getXdXn bin, 64<rt>
  | 0b1000000000011u -> Opcode.REV, getXdXn bin, 64<rt>
  | 0b1000000000100u -> Opcode.CLZ, getXdXn bin, 64<rt>
  | 0b1000000000101u -> Opcode.CLS, getXdXn bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let changeToAliasOfShiftReg bin instr =
  let isShfZero = (valShift bin) = 0b00u
  let isI6Zero = imm6 bin = 0b000000u
  let isRn11111 = valN bin = 0b11111u
  match instr with
  | Opcode.ORR, FourOperands (rd, _, rm, _), oprSize
      when isShfZero && isI6Zero && isRn11111 ->
    Opcode.MOV, TwoOperands (rd, rm), oprSize
  | Opcode.ORN, FourOperands (rd, _, rm, s), oprSize when isRn11111 ->
    Opcode.MVN, ThreeOperands (rd, rm, s), oprSize
  | Opcode.ANDS, FourOperands (_, rn, rm, s), oprSz when valD bin = 0b11111u ->
    Opcode.TST, ThreeOperands (rn, rm, s), oprSz
  | _ -> instr

let parseLogicalShiftedReg bin =
  let cond = concat (extract bin 31u 29u) (pickBit bin 21u) 1
  let imm6 = extract bin 15u 10u
  match cond with
  | c when c &&& 0b1000u = 0b0000u && imm6 &&& 0b100000u = 0b100000u ->
    raise UnallocatedException
  | 0b0000u -> Opcode.AND, getWdWnWmShfamt bin, 32<rt>
  | 0b0001u -> Opcode.BIC, getWdWnWmShfamt bin, 32<rt>
  | 0b0010u -> Opcode.ORR, getWdWnWmShfamt bin, 32<rt>
  | 0b0011u -> Opcode.ORN, getWdWnWmShfamt bin, 32<rt>
  | 0b0100u -> Opcode.EOR, getWdWnWmShfamt bin, 32<rt>
  | 0b0101u -> Opcode.EON, getWdWnWmShfamt bin, 32<rt>
  | 0b0110u -> Opcode.ANDS, getWdWnWmShfamt bin, 32<rt>
  | 0b0111u -> Opcode.BICS, getWdWnWmShfamt bin, 32<rt>
  | 0b1000u -> Opcode.AND, getXdXnXmShfamt bin, 64<rt>
  | 0b1001u -> Opcode.BIC, getXdXnXmShfamt bin, 64<rt>
  | 0b1010u -> Opcode.ORR, getXdXnXmShfamt bin, 64<rt>
  | 0b1011u -> Opcode.ORN, getXdXnXmShfamt bin, 64<rt>
  | 0b1100u -> Opcode.EOR, getXdXnXmShfamt bin, 64<rt>
  | 0b1101u -> Opcode.EON, getXdXnXmShfamt bin, 64<rt>
  | 0b1110u -> Opcode.ANDS, getXdXnXmShfamt bin, 64<rt>
  | 0b1111u -> Opcode.BICS, getXdXnXmShfamt bin, 64<rt>
  | _ -> raise InvalidOpcodeException
  |> changeToAliasOfShiftReg bin

let changeToAliasOfAddSubShiftReg bin instr =
  match instr with
  | Opcode.ADDS, FourOperands (_, rn, rm, shf), oprSize when valD bin = 0b11111u
    -> Opcode.CMN, ThreeOperands (rn, rm, shf), oprSize
  | Opcode.SUB, FourOperands (rd, _, rm, shf), oprSize when valN bin = 0b11111u
    -> Opcode.NEG, ThreeOperands (rd, rm, shf), oprSize
  | Opcode.SUBS, FourOperands (_, rn, rm, shf), oprSize when valD bin = 0b11111u
    -> Opcode.CMP, ThreeOperands (rn, rm, shf), oprSize
  | Opcode.SUBS, FourOperands (rd, _, rm, shf), oprSize when valN bin = 0b11111u
    -> Opcode.NEGS, ThreeOperands (rd, rm, shf), oprSize
  | _ -> instr

let parseAddSubShiftReg bin =
  if valShift bin = 0b11u then raise UnallocatedException else ()
  match extract bin 31u 29u with
  | c when c &&& 0b100u = 0b000u && imm6 bin &&& 0b100000u = 0b100000u ->
    raise UnallocatedException
  | 0b000u -> Opcode.ADD, getWdWnWmShfamt bin, 32<rt>
  | 0b001u -> Opcode.ADDS, getWdWnWmShfamt bin, 32<rt>
  | 0b010u -> Opcode.SUB, getWdWnWmShfamt bin, 32<rt>
  | 0b011u -> Opcode.SUBS, getWdWnWmShfamt bin, 32<rt>
  | 0b100u -> Opcode.ADD, getXdXnXmShfamt bin, 64<rt>
  | 0b101u -> Opcode.ADDS, getXdXnXmShfamt bin, 64<rt>
  | 0b110u -> Opcode.SUB, getXdXnXmShfamt bin, 64<rt>
  | 0b111u -> Opcode.SUBS, getXdXnXmShfamt bin, 64<rt>
  | _ -> raise InvalidOpcodeException
  |> changeToAliasOfAddSubShiftReg bin

let changeToAliasOfExtReg bin = function
  | Opcode.ADDS, FourOperands (_, rn, rm, ext), oprSize when valD bin = 0b11111u
    -> Opcode.CMN, ThreeOperands (rn, rm, ext), oprSize
  | Opcode.SUBS, FourOperands (_, rn, rm, ext), oprSize when valD bin = 0b11111u
    -> Opcode.CMP, ThreeOperands (rn, rm, ext), oprSize
  | instr -> instr

let parseAddSubExtReg bin =
  let imm3 = extract bin 12u 10u
  if imm3 &&& 0b101u = 0b101u || imm3 &&& 0b110u = 0b110u then
    raise UnallocatedException
  let cond = concat (extract bin 31u 29u) (extract bin 23u 22u) 2
  match cond with (* sf:op:S:opt *)
  | c when c &&& 0b00001u = 0b00001u || c &&& 0b00010u = 0b00010u ->
    raise UnallocatedException
  | 0b00000u -> Opcode.ADD, getWSdWSnWmExtamt bin, 32<rt>
  | 0b00100u -> Opcode.ADDS, getWSdWSnWmExtamt bin, 32<rt>
  | 0b01000u -> Opcode.SUB, getWSdWSnWmExtamt bin, 32<rt>
  | 0b01100u -> Opcode.SUBS, getWSdWSnWmExtamt bin, 32<rt>
  | 0b10000u -> Opcode.ADD, getXSdXSnRmExtamt bin, 64<rt>
  | 0b10100u -> Opcode.ADDS, getXSdXSnRmExtamt bin, 64<rt>
  | 0b11000u -> Opcode.SUB, getXSdXSnRmExtamt bin, 64<rt>
  | 0b11100u -> Opcode.SUBS, getXSdXSnRmExtamt bin, 64<rt>
  | _ -> raise InvalidOpcodeException
  |> changeToAliasOfExtReg bin

let changeToAliasOfWithCarry = function
  | Opcode.SBC, ThreeOperands (rd, _, rm), oSz ->
    Opcode.NGC, TwoOperands (rd, rm), oSz
  | Opcode.SBCS, ThreeOperands (rd, _, rm), oSz ->
    Opcode.NGCS, TwoOperands (rd, rm), oSz
  | instr -> instr

let parseAddSubWithCarry bin =
  let cond = concat (extract bin 31u 29u) (extract bin 15u 10u) 6
  let instr =
    match cond with  (* sf:op:s:opcode2 *)
    | c when c &&& 0b000111111u = 0b000000001u -> raise UnallocatedException
    | c when c &&& 0b000111111u = 0b000000010u -> raise UnallocatedException
    | c when c &&& 0b000111111u = 0b000000100u -> raise UnallocatedException
    | c when c &&& 0b000111111u = 0b000001000u -> raise UnallocatedException
    | c when c &&& 0b000111111u = 0b000010000u -> raise UnallocatedException
    | c when c &&& 0b000111111u = 0b000100000u -> raise UnallocatedException
    | 0b000000000u -> Opcode.ADC, getWdWnWm bin, 32<rt>
    | 0b001000000u -> Opcode.ADCS, getWdWnWm bin, 32<rt>
    | 0b010000000u -> Opcode.SBC, getWdWnWm bin, 32<rt>
    | 0b011000000u -> Opcode.SBCS, getWdWnWm bin, 32<rt>
    | 0b100000000u -> Opcode.ADC, getXdXnXm bin, 64<rt>
    | 0b101000000u -> Opcode.ADCS, getXdXnXm bin, 64<rt>
    | 0b110000000u -> Opcode.SBC, getXdXnXm bin, 64<rt>
    | 0b111000000u -> Opcode.SBCS, getXdXnXm bin, 64<rt>
    | _ -> raise InvalidOpcodeException
  if valN bin <> 0b11111u then instr else changeToAliasOfWithCarry instr

let parseCondCmpReg bin =
  let cond = concat (concat (extract bin 31u 29u) (pickBit bin 10u) 1)
                    (pickBit bin 4u) 1 (* sf:op:S:o2:o3 *)
  match cond with
  | c when c &&& 0b00001u = 0b00001u -> raise UnallocatedException
  | c when c &&& 0b00010u = 0b00010u -> raise UnallocatedException
  | c when c &&& 0b00100u = 0b00000u -> raise UnallocatedException
  | 0b00100u -> Opcode.CCMN, getWnWmNzcvCond bin, 32<rt>
  | 0b01100u -> Opcode.CCMP, getWnWmNzcvCond bin, 32<rt>
  | 0b10100u -> Opcode.CCMN, getXnXmNzcvCond bin, 64<rt>
  | 0b11100u -> Opcode.CCMP, getXnXmNzcvCond bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let parseCondCmpImm bin =
  let cond = concat (concat (extract bin 31u 29u) (pickBit bin 10u) 1)
                    (pickBit bin 4u) 1 (* sf:op:S:o2:o3 *)
  match cond with
  | c when c &&& 0b00001u = 0b00001u -> raise UnallocatedException
  | c when c &&& 0b00010u = 0b00010u -> raise UnallocatedException
  | c when c &&& 0b00100u = 0b00000u -> raise UnallocatedException
  | 0b00100u -> Opcode.CCMN, getWnImmNzcvCond bin, 32<rt>
  | 0b01100u -> Opcode.CCMP, getWnImmNzcvCond bin, 32<rt>
  | 0b10100u -> Opcode.CCMN, getXnImmNzcvCond bin, 64<rt>
  | 0b11100u -> Opcode.CCMP, getXnImmNzcvCond bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let changeToAliasOfCondSelect bin instr =
  let rm = valM bin
  let rn = valN bin
  let cnd = extract bin 15u 12u
  let cond = if cnd % 2u = 0b0u then cnd + 1u else cnd - 1u
             |> byte |> getCondition |> OprCond
  let isCondNot1111x = (extract bin 15u 12u) &&& 0b1110u <> 0b1110u
  let cond1 = rm <> 0b11111u && isCondNot1111x && rn <> 0b11111u && rn = rm
  let cond2 = rm = 0b11111u && isCondNot1111x && rn = 0b11111u
  let cond3 = isCondNot1111x && rn = rm
  match instr with
  | Opcode.CSINC, FourOperands (rd, rn, _, _), oprSize when cond1 ->
    Opcode.CINC, ThreeOperands (rd, rn, cond), oprSize
  | Opcode.CSINC, FourOperands (rd, _, _, _), oprSize when cond2 ->
    Opcode.CSET, TwoOperands (rd, cond), oprSize
  | Opcode.CSINV, FourOperands (rd, rn, _, _), oprSize when cond1 ->
    Opcode.CINV, ThreeOperands (rd, rn, cond), oprSize
  | Opcode.CSINV, FourOperands (rd, _, _, _), oprSize when cond2 ->
    Opcode.CSETM, TwoOperands (rd, cond), oprSize
  | Opcode.CSNEG, FourOperands (rd, rn, _, _), oprSize when cond3 ->
    Opcode.CNEG, ThreeOperands (rd, rn, cond), oprSize
  | instr -> instr

let parseCondSelect bin =
  let cond = concat (extract bin 31u 29u) (extract bin 11u 10u) 2
  match cond with  (* sf:op:S:op2 *)
  | c when c &&& 0b00010u = 0b00010u -> raise UnallocatedException
  | c when c &&& 0b00100u = 0b00100u -> raise UnallocatedException
  | 0b00000u -> Opcode.CSEL, getWdWnWmCond bin, 32<rt>
  | 0b00001u -> Opcode.CSINC, getWdWnWmCond bin, 32<rt>
  | 0b01000u -> Opcode.CSINV, getWdWnWmCond bin, 32<rt>
  | 0b01001u -> Opcode.CSNEG, getWdWnWmCond bin, 32<rt>
  | 0b10000u -> Opcode.CSEL, getXdXnXmCond bin, 64<rt>
  | 0b10001u -> Opcode.CSINC, getXdXnXmCond bin, 64<rt>
  | 0b11000u -> Opcode.CSINV, getXdXnXmCond bin, 64<rt>
  | 0b11001u -> Opcode.CSNEG, getXdXnXmCond bin, 64<rt>
  | _ -> raise InvalidOpcodeException
  |> changeToAliasOfCondSelect bin

let changeToAliasOfDataProcessing3Src = function
  | Opcode.MADD, FourOperands (rd, rn, rm, _), oprSize ->
    Opcode.MUL, ThreeOperands (rd, rn, rm), oprSize
  | Opcode.MSUB, FourOperands (rd, rn, rm, _), oprSize ->
    Opcode.MNEG, ThreeOperands (rd, rn, rm), oprSize
  | Opcode.SMADDL, FourOperands (rd, rn, rm, _), oprSize ->
    Opcode.SMULL, ThreeOperands (rd, rn, rm), oprSize
  | Opcode.SMSUBL, FourOperands (rd, rn, rm, _), oprSize ->
    Opcode.SMNEGL, ThreeOperands (rd, rn, rm), oprSize
  | Opcode.UMADDL, FourOperands (rd, rn, rm, _), oprSize ->
    Opcode.UMULL, ThreeOperands (rd, rn, rm), oprSize
  | Opcode.UMSUBL, FourOperands (rd, rn, rm, _), oprSize ->
    Opcode.UMNEGL, ThreeOperands (rd, rn, rm), oprSize
  | instr -> instr

let parseDataProcessing3Src bin =
  let cond = concat (concat (extract bin 31u 29u) (extract bin 23u 21u) 3)
                    (pickBit bin 15u) 1
  match cond with
  | c when c &&& 0b0111111u = 0b0000101u -> raise UnallocatedException
  | c when c &&& 0b0111110u = 0b0000110u -> raise UnallocatedException
  | c when c &&& 0b0111110u = 0b0010000u -> raise UnallocatedException
  | c when c &&& 0b0111111u = 0b0001101u -> raise UnallocatedException
  | c when c &&& 0b0111110u = 0b0001110u -> raise UnallocatedException
  | c when c &&& 0b0110000u = 0b0010000u -> raise UnallocatedException
  | c when c &&& 0b0100000u = 0b0100000u -> raise UnallocatedException
  | 0b0000000u -> Opcode.MADD, getWdWnWmWa bin, 32<rt>
  | 0b0000001u -> Opcode.MSUB, getWdWnWmWa bin, 32<rt>
  | 0b0000010u -> raise UnallocatedException
  | 0b0000011u -> raise UnallocatedException
  | 0b0000100u -> raise UnallocatedException
  | 0b0001010u -> raise UnallocatedException
  | 0b0001011u -> raise UnallocatedException
  | 0b0001100u -> raise UnallocatedException
  | 0b1000000u -> Opcode.MADD, getXdXnXmXa bin, 64<rt>
  | 0b1000001u -> Opcode.MSUB, getXdXnXmXa bin, 64<rt>
  | 0b1000010u -> Opcode.SMADDL, getXdWnWmXa bin, 64<rt>
  | 0b1000011u -> Opcode.SMSUBL, getXdWnWmXa bin, 64<rt>
  | 0b1000100u -> Opcode.SMULH, getXdXnXm bin, 64<rt>
  | 0b1001010u -> Opcode.UMADDL, getXdWnWmXa bin, 64<rt>
  | 0b1001011u -> Opcode.UMSUBL, getXdWnWmXa bin, 64<rt>
  | 0b1001100u -> Opcode.UMULH, getXdXnXm bin, 64<rt>
  | _ -> raise InvalidOpcodeException
  |> fun instr -> if valA bin <> 0b11111u then instr
                  else changeToAliasOfDataProcessing3Src instr

/// Data processing - register
let parse64Group4 bin =
  let cond = concat (pickBit bin 28u) (extract bin 24u 21u) 4
  let op0 = pickBit bin 30u
  let op3 = pickBit bin 11u
  match cond with
  | 0b10110u when op0 = 0b0u -> parseDataProcessing2Src bin
  | 0b10110u when op0 = 0b1u -> parseDataProcessing1Src bin
  | c when c &&& 0b11000u = 0b00000u -> parseLogicalShiftedReg bin
  | c when c &&& 0b11001u = 0b01000u -> parseAddSubShiftReg bin
  | c when c &&& 0b11001u = 0b01001u -> parseAddSubExtReg bin
  | 0b10000u -> parseAddSubWithCarry bin
  | 0b10010u when op3 = 0b0u -> parseCondCmpReg bin
  | 0b10010u when op3 = 0b1u -> parseCondCmpImm bin
  | 0b10100u -> parseCondSelect bin
  | c when c &&& 0b11001u = 0b10001u -> raise UnallocatedException
  | c when c &&& 0b11000u = 0b11000u -> parseDataProcessing3Src bin
  | _ -> raise InvalidOpcodeException

let parseCryptAES bin =
  let cond = concat (extract bin 23u 22u) (extract bin 16u 12u) 5
  match cond with (* size:opcode *)
  | c when c &&& 0b0001000u = 0b0001000u -> raise UnallocatedException
  | c when c &&& 0b0011100u = 0b0000000u -> raise UnallocatedException
  | c when c &&& 0b0010000u = 0b0010000u -> raise UnallocatedException
  | c when c &&& 0b0100000u = 0b0100000u -> raise UnallocatedException
  | 0b0000100u -> Opcode.AESE, getVd16BVn16B bin, 0<rt>
  | 0b0000101u -> Opcode.AESD, getVd16BVn16B bin, 0<rt>
  | 0b0000110u -> Opcode.AESMC, getVd16BVn16B bin, 0<rt>
  | 0b0000111u -> Opcode.AESIMC, getVd16BVn16B bin, 0<rt>
  | c when c &&& 0b1000000u = 0b1000000u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseAdvSIMDTableLookup bin =
  let cond = concat (extract bin 23u 22u) (extract bin 14u 12u) 3
  match cond with  (* op2:len:op *)
  | c when c &&& 0b01000u = 0b01000u -> raise UnallocatedException
  | 0b00000u -> Opcode.TBL, getVdtaVn116BVmta bin, 0<rt>
  | 0b00001u -> Opcode.TBX, getVdtaVn116BVmta bin, 0<rt>
  | 0b00010u -> Opcode.TBL, getVdtaVn216BVmta bin, 0<rt>
  | 0b00011u -> Opcode.TBX, getVdtaVn216BVmta bin, 0<rt>
  | 0b00100u -> Opcode.TBL, getVdtaVn316BVmta bin, 0<rt>
  | 0b00101u -> Opcode.TBX, getVdtaVn316BVmta bin, 0<rt>
  | 0b00110u -> Opcode.TBL, getVdtaVn416BVmta bin, 0<rt>
  | 0b00111u -> Opcode.TBX, getVdtaVn416BVmta bin, 0<rt>
  | c when c &&& 0b10000u = 0b10000u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

/// [Opcode] <Vd>.<T>, <Vn>.<T>, <Vm>.<T>
let parseAdvSIMDPermute bin =
  match extract bin 14u 12u with (* opcode *)
  | 0b000u -> raise UnallocatedException
  | 0b001u -> Opcode.UZP1, getVdtVntVmt bin sizeQ110, 0<rt>
  | 0b010u -> Opcode.TRN1, getVdtVntVmt bin sizeQ110, 0<rt>
  | 0b011u -> Opcode.ZIP1, getVdtVntVmt bin sizeQ110, 0<rt>
  | 0b100u -> raise UnallocatedException
  | 0b101u -> Opcode.UZP2, getVdtVntVmt bin sizeQ110, 0<rt>
  | 0b110u -> Opcode.TRN2, getVdtVntVmt bin sizeQ110, 0<rt>
  | 0b111u -> Opcode.ZIP2, getVdtVntVmt bin sizeQ110, 0<rt>
  | _ -> raise InvalidOpcodeException

let parseAdvSIMDExtract bin =
  match extract bin 23u 22u with
  | c when c &&& 0b01u = 0b01u -> raise UnallocatedException
  | 0b00u -> Opcode.EXT, getVdtVntVmtIdx bin, 0<rt>
  | c when c &&& 0b10u = 0b10u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let changeToAliasOfAdvSIMDCopy bin =
  let imm5 = valImm5 bin in function
  | Opcode.UMOV, oprs, oprSize
      when imm5 &&& 0b01111u = 0b01000u || imm5 &&& 0b00111u = 0b00100u ->
    Opcode.MOV, oprs, oprSize
  | instr -> instr

let parseAdvSIMDCopy bin =
  let cond = concat (concat (extract bin 30u 29u) (extract bin 20u 16u) 5)
                    (extract bin 14u 11u) 4 (* Q:op:imm5:imm4 *)
  match cond with
  | c when c &&& 0b00011110000u = 0b00000000000u -> raise UnallocatedException
  | c when c &&& 0b01000001111u = 0b00000000000u ->
    Opcode.DUP, getVdtVntsidx bin, 0<rt>
  | c when c &&& 0b01000001111u = 0b00000000001u ->
    Opcode.DUP, getVdtRn bin, 0<rt>
  | c when c &&& 0b01000001111u = 0b00000000010u -> raise UnallocatedException
  | c when c &&& 0b01000001111u = 0b00000000100u -> raise UnallocatedException
  | c when c &&& 0b01000001111u = 0b00000000110u -> raise UnallocatedException
  | c when c &&& 0b01000001000u = 0b00000001000u -> raise UnallocatedException
  | c when c &&& 0b11000001111u = 0b00000000011u -> raise UnallocatedException
  | c when c &&& 0b11000001111u = 0b00000000101u ->
    Opcode.SMOV, getWdVntsidx bin imm5xxx00, 32<rt>
  | c when c &&& 0b11000001111u = 0b00000000111u ->
    Opcode.UMOV, getWdVntsidx bin imm5xx000, 32<rt>
  | c when c &&& 0b11000000000u = 0b01000000000u -> raise UnallocatedException
  | c when c &&& 0b11000001111u = 0b10000000011u ->
    Opcode.INS, getVdtsidxRn bin, 0<rt>
  | c when c &&& 0b11000001111u = 0b10000000101u ->
    Opcode.SMOV, getXdVntsidx bin imm5xx000, 64<rt>
  | c when c &&& 0b11011111111u = 0b10010000111u ->
    Opcode.UMOV, getXdVntsidx bin imm5notx1000, 64<rt>
  | c when c &&& 0b11000000000u = 0b11000000000u ->
    Opcode.INS, getVdtsidx1Vntsidx2 bin, 0<rt>
  | _ -> raise InvalidOpcodeException
  |> changeToAliasOfAdvSIMDCopy bin

let toAliasFromNOT _ = Opcode.MVN

let parseAdvSIMDTwoReg bin =
  let cond = concat (concat (pickBit bin 29u) (extract bin 23u 22u) 2)
                    (extract bin 16u 12u) 5 (* U:size:opcode *)
  match cond with
  | c when c &&& 0b00011110u = 0b00010000u -> raise UnallocatedException
  | c when c &&& 0b00011111u = 0b00010101u -> raise UnallocatedException
  | c when c &&& 0b00011111u = 0b00011110u -> raise UnallocatedException
  | c when c &&& 0b01011100u = 0b00001100u -> raise UnallocatedException
  | c when c &&& 0b01011111u = 0b00011111u -> raise UnallocatedException
  | c when c &&& 0b01011111u = 0b01010110u -> raise UnallocatedException
  | c when c &&& 0b01011111u = 0b01010111u -> raise UnallocatedException
  | c when c &&& 0b10011111u = 0b00000000u ->
    Opcode.REV64, getVdtVnt bin sizeQ110, 0<rt>
  | c when c &&& 0b10011111u = 0b00000001u ->
    Opcode.REV16, getVdtVnt bin sizeQ01x1xx, 0<rt>
  | c when c &&& 0b10011111u = 0b00000010u ->
    Opcode.SADDLP, getVdtaVntb bin sizeQ11x, 0<rt>
  | c when c &&& 0b10011111u = 0b00000011u ->
    Opcode.SUQADD, getVdtVnt bin sizeQ11x, 0<rt>
  | c when c &&& 0b10011111u = 0b00000100u ->
    Opcode.CLS, getVdtVnt bin sizeQ11x, 0<rt>
  | c when c &&& 0b10011111u = 0b00000101u ->
    Opcode.CNT, getVdtVnt bin sizeQ01x1xx, 0<rt>
  | c when c &&& 0b10011111u = 0b00000110u ->
    Opcode.SADALP, getVdtaVntb bin sizeQ11x, 0<rt>
  | c when c &&& 0b10011111u = 0b00000111u ->
    Opcode.SQABS, getVdtVnt bin sizeQ110, 0<rt>
  | c when c &&& 0b10011111u = 0b00001000u ->
    Opcode.CMGT, getVdtVntI0 bin sizeQ110, 0<rt>
  | c when c &&& 0b10011111u = 0b00001001u ->
    Opcode.CMEQ, getVdtVntI0 bin sizeQ110, 0<rt>
  | c when c &&& 0b10011111u = 0b00001010u ->
    Opcode.CMLT, getVdtVntI0 bin sizeQ110, 0<rt>
  | c when c &&& 0b10011111u = 0b00001011u ->
    Opcode.ABS, getVdtVnt bin sizeQ110, 0<rt>
  | c when c &&& 0b10011111u = 0b00010010u ->
    getOpcodeByQ bin Opcode.XTN Opcode.XTN2, getVdtbVnta bin sizeQ11x, 0<rt>
  | c when c &&& 0b10011111u = 0b00010011u -> raise UnallocatedException
  | c when c &&& 0b10011111u = 0b00010100u ->
    getOpcodeByQ bin Opcode.SQXTN Opcode.SQXTN2, getVdtbVnta bin sizeQ11x, 0<rt>
  | c when c &&& 0b11011111u = 0b00010110u ->
    getOpcodeByQ bin Opcode.FCVTN Opcode.FCVTN2, getVdtbVnta2 bin resNone, 0<rt>
  | c when c &&& 0b11011111u = 0b00010111u ->
    getOpcodeByQ bin Opcode.FCVTL Opcode.FCVTL2, getVdtaVntb2 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b00011000u ->
    Opcode.FRINTN, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b00011001u ->
    Opcode.FRINTM, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b00011010u ->
    Opcode.FCVTNS, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b00011011u ->
    Opcode.FCVTMS, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b00011100u ->
    Opcode.FCVTAS, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b00011101u ->
    Opcode.SCVTF, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b01001100u ->
    Opcode.FCMGT, getVdtVntF0 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b01001101u ->
    Opcode.FCMEQ, getVdtVntF0 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b01001110u ->
    Opcode.FCMLT, getVdtVntF0 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b01001111u ->
    Opcode.FABS, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b01011000u ->
    Opcode.FRINTP, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b01011001u ->
    Opcode.FRINTZ, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b01011010u ->
    Opcode.FCVTPS, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b01011011u ->
    Opcode.FCVTZS, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b01011100u ->
    Opcode.URECPE, getVdtVnt2 bin szQ1x, 0<rt>
  | c when c &&& 0b11011111u = 0b01011101u ->
    Opcode.FRECPE, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b01011111u -> raise UnallocatedException
  | c when c &&& 0b10011111u = 0b10000000u ->
    Opcode.REV32, getVdtVnt bin sizeQ1xx, 0<rt>
  | c when c &&& 0b10011111u = 0b10000001u -> raise UnallocatedException
  | c when c &&& 0b10011111u = 0b10000010u ->
    Opcode.UADDLP, getVdtaVntb bin sizeQ11x, 0<rt>
  | c when c &&& 0b10011111u = 0b10000011u ->
    Opcode.USQADD, getVdtVnt bin sizeQ110, 0<rt>
  | c when c &&& 0b10011111u = 0b10000100u ->
    Opcode.CLZ, getVdtVnt bin sizeQ11x, 0<rt>
  | c when c &&& 0b10011111u = 0b10000110u ->
    Opcode.UADALP, getVdtaVntb bin sizeQ11x, 0<rt>
  | c when c &&& 0b10011111u = 0b10000111u ->
    Opcode.SQNEG, getVdtVnt bin sizeQ110, 0<rt>
  | c when c &&& 0b10011111u = 0b10001000u ->
    Opcode.CMGE, getVdtVntI0 bin sizeQ110, 0<rt>
  | c when c &&& 0b10011111u = 0b10001001u ->
    Opcode.CMLE, getVdtVntI0 bin sizeQ110, 0<rt>
  | c when c &&& 0b10011111u = 0b10001010u -> raise UnallocatedException
  | c when c &&& 0b10011111u = 0b10001011u ->
    Opcode.NEG, getVdtVnt bin sizeQ110, 0<rt>
  | c when c &&& 0b10011111u = 0b10010010u ->
    getOpcodeByQ bin Opcode.SQXTUN Opcode.SQXTUN2, getVdtbVnta bin size11, 0<rt>
  | c when c &&& 0b10011111u = 0b10010011u ->
    getOpcodeByQ bin Opcode.SHLL Opcode.SHLL2, getVdtaVntbShf2 bin size11, 0<rt>
  | c when c &&& 0b10011111u = 0b10010100u ->
    getOpcodeByQ bin Opcode.UQXTN Opcode.UQXTN2, getVdtbVnta bin sizeQ11x, 0<rt>
  | c when c &&& 0b11011111u = 0b10010110u ->
    getOpcodeByQ bin Opcode.FCVTXN Opcode.FCVTXN2, getVdtbVnta2 bin szQ0x, 0<rt>
  | c when c &&& 0b11011111u = 0b10010111u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b10011000u ->
    Opcode.FRINTA, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b10011001u ->
    Opcode.FRINTX, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b10011010u ->
    Opcode.FCVTNU, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b10011011u ->
    Opcode.FCVTMU, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b10011100u ->
    Opcode.FCVTAU, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b10011101u ->
    Opcode.UCVTF, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11111111u = 0b10000101u ->
    toAliasFromNOT Opcode.NOT, getVdtVnt3 bin, 0<rt>
  | c when c &&& 0b11111111u = 0b10100101u ->
    (Opcode.RBIT, getVdtVnt3 bin) |> getSIMDVectorOprSize
  | c when c &&& 0b11011111u = 0b11000101u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b11001100u ->
    Opcode.FCMGE, getVdtVntF0 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b11001101u ->
    Opcode.FCMLE, getVdtVntF0 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b11001110u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b11001111u ->
    Opcode.FNEG, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b11011000u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b11011001u ->
    Opcode.FRINTI, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b11011010u ->
    Opcode.FCVTPU, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b11011011u ->
    Opcode.FCVTZU, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b11011100u ->
    Opcode.URSQRTE, getVdtVnt2 bin szQ1x, 0<rt>
  | c when c &&& 0b11011111u = 0b11011101u ->
    Opcode.FRSQRTE, getVdtVnt2 bin szQ10, 0<rt>
  | c when c &&& 0b11011111u = 0b11011111u ->
    Opcode.FSQRT, getVdtVnt2 bin szQ10, 0<rt>
  | _ -> raise InvalidOpcodeException

let parseAdvSIMDAcrossLanes bin =
  let cond = concat (concat (pickBit bin 29u) (extract bin 23u 22u) 2)
                    (extract bin 16u 12u) 5 (* U:size:opcode *)
  match cond with
  | c when c &&& 0b00011110u = 0b00000000u -> raise UnallocatedException
  | c when c &&& 0b00011111u = 0b00000010u -> raise UnallocatedException
  | c when c &&& 0b00011100u = 0b00000100u -> raise UnallocatedException
  | c when c &&& 0b00011110u = 0b00001000u -> raise UnallocatedException
  | c when c &&& 0b00011111u = 0b00001011u -> raise UnallocatedException
  | c when c &&& 0b00011111u = 0b00001101u -> raise UnallocatedException
  | c when c &&& 0b00011111u = 0b00001110u -> raise UnallocatedException
  | c when c &&& 0b00011000u = 0b00010000u -> raise UnallocatedException
  | c when c &&& 0b00011110u = 0b00011000u -> raise UnallocatedException
  | c when c &&& 0b00011100u = 0b00011100u -> raise UnallocatedException
  | c when c &&& 0b10011111u = 0b00000011u ->
    Opcode.SADDLV, getVdVnt1 bin sizeQ10011x, 0<rt>
  | c when c &&& 0b10011111u = 0b00001010u ->
    Opcode.SMAXV, getVdVnt2 bin sizeQ10011x, 0<rt>
  | c when c &&& 0b10011111u = 0b00011010u ->
    Opcode.SMINV, getVdVnt2 bin sizeQ10011x, 0<rt>
  | c when c &&& 0b10011111u = 0b00011011u ->
    Opcode.ADDV, getVdVnt2 bin sizeQ10011x, 0<rt>
  | c when c &&& 0b10011111u = 0b10000011u ->
    Opcode.UADDLV, getVdVnt1 bin sizeQ10011x, 0<rt>
  | c when c &&& 0b10011111u = 0b10001010u ->
    Opcode.UMAXV, getVdVnt2 bin sizeQ10011x, 0<rt>
  | c when c &&& 0b10011111u = 0b10011010u ->
    Opcode.UMINV, getVdVnt2 bin sizeQ10011x, 0<rt>
  | c when c &&& 0b10011111u = 0b10011011u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b10001100u ->
    Opcode.FMAXNMV, getVdVnt3 bin szQx011, 0<rt>
  | c when c &&& 0b11011111u = 0b10001111u ->
    Opcode.FMAXV, getVdVnt3 bin szQx011, 0<rt>
  | c when c &&& 0b11011111u = 0b11001100u ->
    Opcode.FMINNMV, getVdVnt3 bin szQx011, 0<rt>
  | c when c &&& 0b11011111u = 0b11001111u ->
    Opcode.FMINV, getVdVnt3 bin szQx011, 0<rt>
  | _ -> raise InvalidOpcodeException

let parseAdvSIMDThreeDiff bin =
  let cond = concat (pickBit bin 29u) (extract bin 15u 12u) 4 (* U:opcode *)
  match cond with
  | c when c &&& 0b01111u = 0b01111u -> raise UnallocatedException
  | 0b00000u -> getOpcodeByQ bin Opcode.SADDL Opcode.SADDL2,
                getVdtaVntbVmtb bin size11, 0<rt>
  | 0b00001u -> getOpcodeByQ bin Opcode.SADDW Opcode.SADDW2,
                getVdtaVntaVmtb bin size11, 0<rt>
  | 0b00010u -> getOpcodeByQ bin Opcode.SSUBL Opcode.SSUBL2,
                getVdtaVntbVmtb bin size11, 0<rt>
  | 0b00011u -> getOpcodeByQ bin Opcode.SSUBW Opcode.SSUBW2,
                getVdtaVntaVmtb bin size11, 0<rt>
  | 0b00100u -> getOpcodeByQ bin Opcode.ADDHN Opcode.ADDHN2,
                getVdtbVntaVmta bin size11, 0<rt>
  | 0b00101u -> getOpcodeByQ bin Opcode.SABAL Opcode.SABAL2,
                getVdtaVntbVmtb bin size11, 0<rt>
  | 0b00110u -> getOpcodeByQ bin Opcode.SUBHN Opcode.SUBHN2,
                getVdtbVntaVmta bin size11, 0<rt>
  | 0b00111u -> getOpcodeByQ bin Opcode.SABDL Opcode.SABDL2,
                getVdtaVntbVmtb bin size11, 0<rt>
  | 0b01000u -> getOpcodeByQ bin Opcode.SMLAL Opcode.SMLAL2,
                getVdtaVntbVmtb bin size11, 0<rt>
  | 0b01001u -> getOpcodeByQ bin Opcode.SQDMLAL Opcode.SQDMLAL2,
                getVdtaVntbVmtb bin size0011, 0<rt>
  | 0b01010u -> getOpcodeByQ bin Opcode.SMLSL Opcode.SMLSL2,
                getVdtaVntbVmtb bin size11, 0<rt>
  | 0b01011u -> getOpcodeByQ bin Opcode.SQDMLSL Opcode.SQDMLSL2,
                getVdtaVntbVmtb bin size0011, 0<rt>
  | 0b01100u -> getOpcodeByQ bin Opcode.SMULL Opcode.SMULL2,
                getVdtaVntbVmtb bin size0011, 0<rt>
  | 0b01101u -> getOpcodeByQ bin Opcode.SQDMULL Opcode.SQDMULL2,
                getVdtaVntbVmtb bin size0011, 0<rt>
  | 0b01110u -> getOpcodeByQ bin Opcode.PMULL Opcode.PMULL2,
                getVdtaVntbVmtb bin size0110, 0<rt>
  | 0b10000u -> getOpcodeByQ bin Opcode.UADDL Opcode.UADDL2,
                getVdtaVntbVmtb bin size11, 0<rt>
  | 0b10001u -> getOpcodeByQ bin Opcode.UADDW Opcode.UADDW2,
                getVdtaVntaVmtb bin size11, 0<rt>
  | 0b10010u -> getOpcodeByQ bin Opcode.USUBL Opcode.USUBL2,
                getVdtaVntbVmtb bin size11, 0<rt>
  | 0b10011u -> getOpcodeByQ bin Opcode.USUBW Opcode.USUBW2,
                getVdtaVntaVmtb bin size11, 0<rt>
  | 0b10100u -> getOpcodeByQ bin Opcode.RADDHN Opcode.RADDHN2,
                getVdtbVntaVmta bin size11, 0<rt>
  | 0b10101u -> getOpcodeByQ bin Opcode.UABAL Opcode.UABAL2,
                getVdtaVntbVmtb bin size11, 0<rt>
  | 0b10110u -> getOpcodeByQ bin Opcode.RSUBHN Opcode.RSUBHN2,
                getVdtbVntaVmta bin size11, 0<rt>
  | 0b10111u -> getOpcodeByQ bin Opcode.UABDL Opcode.UABDL2,
                getVdtaVntbVmtb bin size11, 0<rt>
  | 0b11000u -> getOpcodeByQ bin Opcode.UMLAL Opcode.UMLAL2,
                getVdtaVntbVmtb bin size11, 0<rt>
  | 0b11001u -> raise UnallocatedException
  | 0b11010u -> getOpcodeByQ bin Opcode.UMLSL Opcode.UMLSL2,
                getVdtaVntbVmtb bin size11, 0<rt>
  | 0b11011u -> raise UnallocatedException
  | 0b11100u -> getOpcodeByQ bin Opcode.UMULL Opcode.UMULL2,
                getVdtaVntbVmtb bin size11, 0<rt>
  | 0b11101u -> raise UnallocatedException
  | 0b11110u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let changeToAliasOfAdvSIMDThreeSame bin = function
  | Opcode.ORR, ThreeOperands (vdt, vnt, _) when valM bin = valN bin ->
    Opcode.MOV, TwoOperands (vdt, vnt)
  | instr -> instr

let parseAdvSIMDThreeSame b =
  let cond = concat (concat (pickBit b 29u) (extract b 23u 22u) 2)
                    (extract b 15u 11u) 5 (* U:size:opcode *)
  match cond with
  | c when c &&& 0b10011111u = 0b00000000u ->
    Opcode.SHADD, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00000001u ->
    Opcode.SQADD, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00000010u ->
    Opcode.SRHADD, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00000100u ->
    Opcode.SHSUB, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00000101u ->
    Opcode.SQSUB, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00000110u ->
    Opcode.CMGT, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00000111u ->
    Opcode.CMGE, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00001000u ->
    Opcode.SSHL, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00001001u ->
    Opcode.SQSHL, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00001010u ->
    Opcode.SRSHL, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00001011u ->
    Opcode.SQRSHL, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00001100u ->
    Opcode.SMAX, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00001101u ->
    Opcode.SMIN, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00001110u ->
    Opcode.SABD, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00001111u ->
    Opcode.SABA, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00010000u ->
    Opcode.ADD, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00010001u ->
    Opcode.CMTST, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00010010u -> Opcode.MLA, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00010011u -> Opcode.MUL, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00010100u ->
    Opcode.SMAXP, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00010101u ->
    Opcode.SMINP, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00010110u ->
    Opcode.SQDMULH, getVdtVntVmt1 b szQ10
  | c when c &&& 0b10011111u = 0b00010111u ->
    Opcode.ADDP, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b11011111u = 0b00011000u ->
    Opcode.FMAXNM, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b00011001u -> Opcode.FMLA, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b00011010u -> Opcode.FADD, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b00011011u ->
    Opcode.FMULX, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b00011100u ->
    Opcode.FCMEQ, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b00011101u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b00011110u -> Opcode.FMAX, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b00011111u ->
    Opcode.FRECPS, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11111111u = 0b00000011u -> Opcode.AND, getVdtVntVmt3 b
  | c when c &&& 0b11111111u = 0b00100011u -> Opcode.BIC, getVdtVntVmt3 b
  | c when c &&& 0b11011111u = 0b01011000u ->
    Opcode.FMINNM, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b01011001u -> Opcode.FMLS, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b01011010u -> Opcode.FSUB, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b01011011u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b01011100u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b01011101u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b01011110u -> Opcode.FMIN, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b01011111u ->
    Opcode.FRSQRTS, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11111111u = 0b01000011u -> Opcode.ORR, getVdtVntVmt3 b
  | c when c &&& 0b11111111u = 0b01100011u -> Opcode.ORN, getVdtVntVmt3 b
  | c when c &&& 0b10011111u = 0b10000000u ->
    Opcode.UHADD, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10000001u ->
    Opcode.UQADD, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10000010u ->
    Opcode.URHADD, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10000100u ->
    Opcode.UHSUB, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10000101u ->
    Opcode.UQSUB, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10000110u ->
    Opcode.CMHI, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10000111u ->
    Opcode.CMHS, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10001000u ->
    Opcode.USHL, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10001001u ->
    Opcode.UQSHL, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10001010u ->
    Opcode.URSHL, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10001011u ->
    Opcode.UQRSHL, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10001100u ->
    Opcode.UMAX, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10001101u ->
    Opcode.UMIN, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10001110u ->
    Opcode.UABD, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10001111u ->
    Opcode.UABA, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10010000u ->
    Opcode.SUB, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10010001u ->
    Opcode.CMEQ, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10010010u -> Opcode.MLS, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10010011u ->
    Opcode.PMUL, getVdtVntVmt1 b size011011
  | c when c &&& 0b10011111u = 0b10010100u ->
    Opcode.UMAXP, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10010101u ->
    Opcode.UMINP, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10010110u ->
    Opcode.SQRDMULH, getVdtVntVmt1 b size0011
  | c when c &&& 0b10011111u = 0b10010111u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b10011000u ->
    Opcode.FMAXNMP, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b10011001u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b10011010u ->
    Opcode.FADDP, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b10011011u -> Opcode.FMUL, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b10011100u ->
    Opcode.FCMGE, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b10011101u ->
    Opcode.FACGE, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b10011110u ->
    Opcode.FMAXP, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b10011111u -> Opcode.FDIV, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11111111u = 0b10000011u -> Opcode.EOR, getVdtVntVmt3 b
  | c when c &&& 0b11111111u = 0b10100011u -> Opcode.BSL, getVdtVntVmt3 b
  | c when c &&& 0b11011111u = 0b11011000u ->
    Opcode.FMINNMP, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b11011001u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b11011010u -> Opcode.FABD, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b11011011u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b11011100u ->
    Opcode.FCMGT, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b11011101u ->
    Opcode.FACGT, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b11011110u ->
    Opcode.FMINP, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b11011111u -> raise UnallocatedException
  | c when c &&& 0b11111111u = 0b11000011u -> Opcode.BIT, getVdtVntVmt3 b
  | c when c &&& 0b11111111u = 0b11100011u -> Opcode.BIF, getVdtVntVmt3 b
  | _ -> raise InvalidOpcodeException
  |> changeToAliasOfAdvSIMDThreeSame b
  |> getSIMDVectorOprSize

let parseAdvSIMDModImm bin =
  let cond = concat (extract bin 30u 29u) (extract bin 15u 11u) 5
  match cond with (* Q:op:cmode:o2 *)
  | c when c &&& 0b0000001u = 0b0000001u -> raise UnallocatedException
  | c when c &&& 0b0110011u = 0b0000000u ->
    Opcode.MOVI, getVdtImm8LAmt3 bin, 0<rt>
  | c when c &&& 0b0110011u = 0b0000010u ->
    Opcode.ORR, getVdtImm8LAmt3 bin, 64<rt>
  | c when c &&& 0b0111011u = 0b0010000u ->
    Opcode.MOVI, getVdtImm8LAmt2 bin, 0<rt>
  | c when c &&& 0b0111011u = 0b0010010u ->
    Opcode.ORR, getVdtImm8LAmt2 bin, 64<rt>
  | c when c &&& 0b0111101u = 0b0011000u ->
    Opcode.MOVI, getVdtImm8MAmt bin, 0<rt>
  | c when c &&& 0b0111111u = 0b0011100u ->
    Opcode.MOVI, getVdtImm8LAmt1 bin, 0<rt>
  | c when c &&& 0b0111111u = 0b0011110u -> Opcode.FMOV, getVdtFImm bin, 0<rt>
  | c when c &&& 0b0110011u = 0b0100000u ->
    Opcode.MVNI, getVdtImm8LAmt3 bin, 0<rt>
  | c when c &&& 0b0110011u = 0b0100010u ->
    Opcode.BIC, getVdtImm8LAmt3 bin, 0<rt>
  | c when c &&& 0b0111011u = 0b0110000u ->
    Opcode.MVNI, getVdtImm8LAmt2 bin, 0<rt>
  | c when c &&& 0b0111011u = 0b0110010u ->
    Opcode.BIC, getVdtImm8LAmt2 bin, 0<rt>
  | c when c &&& 0b0111101u = 0b0111000u ->
    Opcode.MVNI, getVdtImm8MAmt bin, 0<rt>
  | c when c &&& 0b1111111u = 0b0111100u -> Opcode.MOVI, getDdImm bin, 0<rt>
  | c when c &&& 0b1111111u = 0b0111110u -> raise UnallocatedException
  | c when c &&& 0b1111111u = 0b1111100u -> Opcode.MOVI, getVd2DImm bin, 0<rt>
  | c when c &&& 0b1111111u = 0b1111110u -> Opcode.FMOV, getVd2DFImm bin, 0<rt>
  | _ -> raise InvalidOpcodeException

let getAdvSIMDShfByImm b =
  let cond = concat (pickBit b 29u) (extract b 15u 11u) 5 (* U:opcode *)
  match cond with
  | c when c &&& 0b011111u = 0b000001u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b000011u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b000101u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b000111u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b001001u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b001011u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b001101u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b001111u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b010101u -> raise UnallocatedException
  | c when c &&& 0b011110u = 0b010110u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b011101u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b011110u -> raise UnallocatedException
  | 0b000000u -> Opcode.SSHR, getVdtVntShf1 b, 0<rt>
  | 0b000010u -> Opcode.SSRA, getVdtVntShf1 b, 0<rt>
  | 0b000100u -> Opcode.SRSHR, getVdtVntShf1 b, 0<rt>
  | 0b000110u -> Opcode.SRSRA, getVdtVntShf1 b, 0<rt>
  | 0b001000u -> raise UnallocatedException
  | 0b001010u -> Opcode.SHL, getVdtVntShf2 b, 0<rt>
  | 0b001100u -> raise UnallocatedException
  | 0b001110u -> Opcode.SQSHL, getVdtVntShf2 b, 0<rt>
  | 0b010000u -> getOpcodeByQ b Opcode.SHRN Opcode.SHRN2,
                 getVdtbVntaShf b immh1xxx, 0<rt>
  | 0b010001u -> getOpcodeByQ b Opcode.RSHRN Opcode.RSHRN2,
                 getVdtbVntaShf b immh1xxx, 0<rt>
  | 0b010010u -> getOpcodeByQ b Opcode.SQSHRN Opcode.SQSHRN2,
                 getVdtbVntaShf b immh1xxx, 0<rt>
  | 0b010011u -> getOpcodeByQ b Opcode.SQRSHRN Opcode.SQRSHRN2,
                 getVdtbVntaShf b immh1xxx, 0<rt>
  | 0b010100u -> getOpcodeByQ b Opcode.SSHLL Opcode.SSHLL2,
                 getVdtaVntbShf b immh1xxx, 0<rt>
  | 0b011100u -> Opcode.SCVTF, getVdtVntFbits b immhQ1, 0<rt>
  | 0b011111u -> Opcode.FCVTZS, getVdtVntFbits b immhQ1, 0<rt>
  | 0b100000u -> Opcode.USHR, getVdtVntShf1 b, 0<rt>
  | 0b100010u -> Opcode.USRA, getVdtVntShf1 b, 0<rt>
  | 0b100100u -> Opcode.URSHR, getVdtVntShf1 b, 0<rt>
  | 0b100110u -> Opcode.URSRA, getVdtVntShf1 b, 0<rt>
  | 0b101000u -> Opcode.SRI, getVdtVntShf1 b, 0<rt>
  | 0b101010u -> Opcode.SLI, getVdtVntShf2 b, 0<rt>
  | 0b101100u -> Opcode.SQSHLU, getVdtVntShf2 b, 0<rt>
  | 0b101110u -> Opcode.UQSHL, getVdtVntShf2 b, 0<rt>
  | 0b110000u -> getOpcodeByQ b Opcode.SQSHRUN Opcode.SQSHRUN2,
                 getVdtbVntaShf b immh1xxx, 0<rt>
  | 0b110001u -> getOpcodeByQ b Opcode.SQRSHRUN Opcode.SQRSHRUN2,
                 getVdtbVntaShf b immh1xxx, 0<rt>
  | 0b110010u -> getOpcodeByQ b Opcode.UQSHRN Opcode.UQSHRN2,
                 getVdtbVntaShf b immh1xxx, 0<rt>
  | 0b110011u -> getOpcodeByQ b Opcode.UQRSHRN Opcode.UQRSHRN2,
                 getVdtbVntaShf b immh1xxx, 0<rt>
  | 0b110100u -> getOpcodeByQ b Opcode.USHLL Opcode.USHLL2,
                 getVdtaVntbShf b immh1xxx, 0<rt>
  | 0b111100u -> Opcode.UCVTF, getVdtVntFbits b immhQ1, 0<rt>
  | 0b111111u -> Opcode.FCVTZU, getVdtVntFbits b immhQ1, 0<rt>
  | _ -> raise InvalidOpcodeException

let parseAdvSIMDVecXIdxElem bin =
  let cond = concat (concat (pickBit bin 29u) (extract bin 23u 22u) 2)
                    (extract bin 15u 12u) 4 (* U:size:opcode *)
  match cond with
  | c when c &&& 0b0001110u = 0b0001110u -> raise UnallocatedException
  | c when c &&& 0b1001111u = 0b0000000u -> raise UnallocatedException
  | c when c &&& 0b1001111u = 0b0000010u ->
    getOpcodeByQ bin Opcode.SMLAL Opcode.SMLAL2,
    getVdtaVntbVmtsidx bin size0011, 0<rt>
  | c when c &&& 0b1001111u = 0b0000011u ->
    getOpcodeByQ bin Opcode.SQDMLAL Opcode.SQDMLAL2,
    getVdtaVntbVmtsidx bin size0011, 0<rt>
  | c when c &&& 0b1001111u = 0b0000100u -> raise UnallocatedException
  | c when c &&& 0b1001111u = 0b0000110u ->
    getOpcodeByQ bin Opcode.SMLSL Opcode.SMLSL2,
    getVdtaVntbVmtsidx bin size0011, 0<rt>
  | c when c &&& 0b1001111u = 0b0000111u ->
    getOpcodeByQ bin Opcode.SQDMLSL Opcode.SQDMLSL2,
    getVdtaVntbVmtsidx bin size0011, 0<rt>
  | c when c &&& 0b1001111u = 0b0001000u ->
    Opcode.MUL, getVdtVntVmtsidx1 bin size0011, 0<rt>
  | c when c &&& 0b1001111u = 0b0001010u ->
    getOpcodeByQ bin Opcode.SMULL Opcode.SMULL2,
    getVdtaVntbVmtsidx bin size0011, 0<rt>
  | c when c &&& 0b1001111u = 0b0001011u ->
    getOpcodeByQ bin Opcode.SQDMULL Opcode.SQDMULL2,
    getVdtaVntbVmtsidx bin size0011, 0<rt>
  | c when c &&& 0b1001111u = 0b0001100u ->
    Opcode.SQDMULH, getVdtVntVmtsidx1 bin size0011, 0<rt>
  | c when c &&& 0b1001111u = 0b0001101u ->
    Opcode.SQRDMULH, getVdtVntVmtsidx1 bin size0011, 0<rt>
  | c when c &&& 0b1101111u = 0b0100001u ->
    Opcode.FMLA, getVdtVntVmtsidx2 bin szL11, 0<rt>
  | c when c &&& 0b1101111u = 0b0100101u ->
    Opcode.FMLS, getVdtVntVmtsidx2 bin szL11, 0<rt>
  | c when c &&& 0b1101111u = 0b0101001u ->
    Opcode.FMUL, getVdtVntVmtsidx2 bin szL11, 0<rt>
  | c when c &&& 0b1001111u = 0b1000000u ->
    Opcode.MLA, getVdtVntVmtsidx1 bin size0011, 0<rt>
  | c when c &&& 0b1001111u = 0b1000010u ->
    getOpcodeByQ bin Opcode.UMLAL Opcode.UMLAL2,
    getVdtaVntbVmtsidx bin size0011, 0<rt>
  | c when c &&& 0b1001111u = 0b1000011u -> raise UnallocatedException
  | c when c &&& 0b1001111u = 0b1000100u ->
    Opcode.MLS, getVdtVntVmtsidx1 bin size0011, 0<rt>
  | c when c &&& 0b1001111u = 0b1000110u ->
    getOpcodeByQ bin Opcode.UMLSL Opcode.UMLSL2,
    getVdtaVntbVmtsidx bin size0011, 0<rt>
  | c when c &&& 0b1001111u = 0b1000111u -> raise UnallocatedException
  | c when c &&& 0b1001111u = 0b1001000u -> raise UnallocatedException
  | c when c &&& 0b1001111u = 0b1001010u ->
    getOpcodeByQ bin Opcode.UMULL Opcode.UMULL2,
    getVdtaVntbVmtsidx bin size0011, 0<rt>
  | c when c &&& 0b1001111u = 0b1001011u -> raise UnallocatedException
  | c when c &&& 0b1001110u = 0b1001100u -> raise UnallocatedException
  | c when c &&& 0b1101111u = 0b1100001u -> raise UnallocatedException
  | c when c &&& 0b1101111u = 0b1100101u -> raise UnallocatedException
  | c when c &&& 0b1101111u = 0b1101001u ->
    Opcode.FMULX, getVdtVntVmtsidx2 bin szL11, 0<rt>
  | _ -> raise InvalidOpcodeException

/// Data processing - SIMD and FP - 1
let parse64Group5 bin =
  let cond = concat (concat (extract bin 31u 28u) (extract bin 24u 17u) 8)
                    (extract bin 15u 10u) 6 (* op0:op1:op2:op3:op4 *)
  match cond with
  | c when c &&& 0b111110011111000011u = 0b000000010100000010u ->
    raise UnallocatedException
  | c when c &&& 0b111110011111000011u = 0b001000010100000010u ->
    raise UnallocatedException
  | c when c &&& 0b111110011111000011u = 0b010000010100000010u ->
    parseCryptAES bin
  | c when c &&& 0b111110011111000011u = 0b011000010100000010u ->
    raise UnallocatedException
  | c when c &&& 0b101110010000100011u = 0b000000000000000000u ->
    parseAdvSIMDTableLookup bin
  | c when c &&& 0b101110010000100011u = 0b000000000000000010u ->
    parseAdvSIMDPermute bin
  | c when c &&& 0b101110010000100001u = 0b001000000000000000u ->
    parseAdvSIMDExtract bin
  | c when c &&& 0b100111110000100001u = 0b000000000000000001u ->
    parseAdvSIMDCopy bin
  | c when c &&& 0b100111010000100001u = 0b000001000000000001u ->
    raise UnallocatedException
  | c when c &&& 0b100110111111000011u = 0b000000011100000010u ->
    raise UnallocatedException
  | c when c &&& 0b100110110000110001u = 0b000000100000010001u ->
    raise UnallocatedException
  | c when c &&& 0b100110010000100000u = 0b000000000000100000u ->
    raise UnallocatedException
  | c when c &&& 0b100110011111000011u = 0b000000010000000010u ->
    parseAdvSIMDTwoReg bin
  | c when c &&& 0b100110011111000011u = 0b000000011000000010u ->
    parseAdvSIMDAcrossLanes bin
  | c when c &&& 0b100110010010000011u = 0b000000010010000010u ->
    raise UnallocatedException
  | c when c &&& 0b100110010001000011u = 0b000000010001000010u ->
    raise UnallocatedException
  | c when c &&& 0b100110010000000011u = 0b000000010000000000u ->
    parseAdvSIMDThreeDiff bin
  | c when c &&& 0b100110010000000001u = 0b000000010000000001u ->
    parseAdvSIMDThreeSame bin
  | c when c &&& 0b100111111100000001u = 0b000010000000000001u ->
    parseAdvSIMDModImm bin
  | c when c &&& 0b100111000000000001u = 0b000010000000000001u &&
           extract c 11u 8u <> 0b0000u -> getAdvSIMDShfByImm bin
  | c when c &&& 0b100111000000000001u = 0b000011000000000001u ->
    raise UnallocatedException
  | c when c &&& 0b100110000000000001u = 0b000010000000000000u ->
    parseAdvSIMDVecXIdxElem bin
  | c when c &&& 0b100100000000000000u = 0b100000000000000000u ->
    raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseCryptThreeRegSHA bin =
  let cond = concat (extract bin 23u 22u) (extract bin 14u 12u) 3
  match cond with (* size:opcode *)
  | c when c &&& 0b00111u = 0b00111u -> raise UnallocatedException
  | c when c &&& 0b01000u = 0b01000u -> raise UnallocatedException
  | 0b00000u -> Opcode.SHA1C, getQdSnVm4S bin, 128<rt>
  | 0b00001u -> Opcode.SHA1P, getQdSnVm4S bin, 128<rt>
  | 0b00010u -> Opcode.SHA1M, getQdSnVm4S bin, 128<rt>
  | 0b00011u -> Opcode.SHA1SU0, getVd4SVn4SVm4S bin, 0<rt>
  | 0b00100u -> Opcode.SHA256H, getQdQnVm4S bin, 128<rt>
  | 0b00101u -> Opcode.SHA256H2, getQdQnVm4S bin, 128<rt>
  | 0b00110u -> Opcode.SHA256SU1, getVd4SVn4SVm4S bin, 0<rt>
  | _ -> raise InvalidOpcodeException

let parseCryptTwoRegSHA bin =
  let cond = concat (extract bin 23u 22u) (extract bin 16u 12u) 5
  match cond with (* size:opcode *)
  | c when c &&& 0b0000100u = 0b0000100u -> raise UnallocatedException
  | c when c &&& 0b0001000u = 0b0001000u -> raise UnallocatedException
  | c when c &&& 0b0010000u = 0b0010000u -> raise UnallocatedException
  | c when c &&& 0b0100000u = 0b0100000u -> raise UnallocatedException
  | 0b0000000u -> Opcode.SHA1H, getSdSn bin, 32<rt>
  | 0b0000001u -> Opcode.SHA1SU1, getVd4SVn4S bin, 0<rt>
  | 0b0000010u -> Opcode.SHA256SU0, getVd4SVn4S bin, 0<rt>
  | 0b0000011u -> raise UnallocatedException
  | c when c &&& 0b1000000u = 0b1000000u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

/// This instruction is used by the alias MOV (scalar).
/// The alias is always the preferred disassembly.
let toAliasFromDUP _ = Opcode.MOV

let parseAdvSIMDScalarCopy bin =
  let cond = concat (concat (extract bin 29u 29u) (extract bin 20u 16u) 5)
                    (extract bin 14u 11u) 4 (* op:imm5:imm4 *)
  match cond with
  | c when c &&& 0b1000000001u = 0b0000000001u -> raise UnallocatedException
  | c when c &&& 0b1000000010u = 0b0000000010u -> raise UnallocatedException
  | c when c &&& 0b1000000100u = 0b0000000100u -> raise UnallocatedException
  | c when c &&& 0b1000001111u = 0b0000000000u ->
    toAliasFromDUP Opcode.DUP, getVdVntidx bin, 0<rt>
  | c when c &&& 0b1000001000u = 0b0000001000u -> raise UnallocatedException
  | c when c &&& 0b1011111111u = 0b0000000000u -> raise UnallocatedException
  | c when c &&& 0b1000000000u = 0b1000000000u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseAdvSIMDScalarTwoReg bin =
  let cond = concat (concat (extract bin 29u 29u) (extract bin 23u 22u) 2)
                    (extract bin 16u 12u) 5 (* U + size + opcode *)
  match cond with
  | c when c &&& 0b00011110u = 0b00000000u -> raise UnallocatedException
  | c when c &&& 0b00011111u = 0b00000010u -> raise UnallocatedException
  | c when c &&& 0b00011110u = 0b00000100u -> raise UnallocatedException
  | c when c &&& 0b00011111u = 0b00000110u -> raise UnallocatedException
  | c when c &&& 0b00011111u = 0b00001111u -> raise UnallocatedException
  | c when c &&& 0b00011110u = 0b00010000u -> raise UnallocatedException
  | c when c &&& 0b00011111u = 0b00010011u -> raise UnallocatedException
  | c when c &&& 0b00011111u = 0b00010101u -> raise UnallocatedException
  | c when c &&& 0b00011111u = 0b00010111u -> raise UnallocatedException
  | c when c &&& 0b00011110u = 0b00011000u -> raise UnallocatedException
  | c when c &&& 0b00011111u = 0b00011110u -> raise UnallocatedException
  | c when c &&& 0b01011100u = 0b00001100u -> raise UnallocatedException
  | c when c &&& 0b01011111u = 0b00011111u -> raise UnallocatedException
  | c when c &&& 0b01011111u = 0b01010110u -> raise UnallocatedException
  | c when c &&& 0b01011111u = 0b01011100u -> raise UnallocatedException
  | c when c &&& 0b10011111u = 0b00000011u ->
    Opcode.SUQADD, getVdVn bin resNone, 0<rt>
  | c when c &&& 0b10011111u = 0b00000111u ->
    Opcode.SQABS, getVdVn bin resNone, 0<rt>
  | c when c &&& 0b10011111u = 0b00001000u ->
    Opcode.CMGT, getVdVnI0 bin size0x10, 0<rt>
  | c when c &&& 0b10011111u = 0b00001001u ->
    Opcode.CMEQ, getVdVnI0 bin size0x10, 0<rt>
  | c when c &&& 0b10011111u = 0b00001010u ->
    Opcode.CMLT, getVdVnI0 bin size0x10, 0<rt>
  | c when c &&& 0b10011111u = 0b00001011u ->
    Opcode.ABS, getVdVn bin size0x10, 0<rt>
  | c when c &&& 0b10011111u = 0b00010010u -> raise UnallocatedException
  | c when c &&& 0b10011111u = 0b00010100u ->
    Opcode.SQXTN, getVbdVan bin size11, 0<rt>
  | c when c &&& 0b11011111u = 0b00010110u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b00011010u -> Opcode.FCVTNS, getVdVn2 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b00011011u -> Opcode.FCVTMS, getVdVn2 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b00011100u -> Opcode.FCVTAS, getVdVn2 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b00011101u -> Opcode.SCVTF, getVdVn2 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b01001100u -> Opcode.FCMGT, getVdVnF0 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b01001101u -> Opcode.FCMEQ, getVdVnF0 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b01001110u -> Opcode.FCMLT, getVdVnF0 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b01011010u -> Opcode.FCVTPS, getVdVn2 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b01011011u -> Opcode.FCVTZS, getVdVn2 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b01011101u -> Opcode.FRECPE, getVdVn2 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b01011111u -> Opcode.FRECPX, getVdVn2 bin, 0<rt>
  | c when c &&& 0b10011111u = 0b10000011u ->
    Opcode.USQADD, getVdVn bin resNone, 0<rt>
  | c when c &&& 0b10011111u = 0b10000111u ->
    Opcode.SQNEG, getVdVn bin resNone, 0<rt>
  | c when c &&& 0b10011111u = 0b10001000u ->
    Opcode.CMGE, getVdVnI0 bin size0x10, 0<rt>
  | c when c &&& 0b10011111u = 0b10001001u ->
    Opcode.CMLE, getVdVnI0 bin size0x10, 0<rt>
  | c when c &&& 0b10011111u = 0b10001010u -> raise UnallocatedException
  | c when c &&& 0b10011111u = 0b10001011u ->
    Opcode.NEG, getVdVn bin size0x10, 0<rt>
  | c when c &&& 0b10011111u = 0b10010010u ->
    Opcode.SQXTUN, getVbdVan bin size11, 0<rt>
  | c when c &&& 0b10011111u = 0b10010100u ->
    Opcode.UQXTN, getVbdVan bin size11, 0<rt>
  | c when c &&& 0b11011111u = 0b10010110u ->
    Opcode.FCVTXN, getVbdVan2 bin sz0, 0<rt>
  | c when c &&& 0b11011111u = 0b10011010u -> Opcode.FCVTNU, getVdVn2 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b10011011u -> Opcode.FCVTMU, getVdVn2 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b10011100u -> Opcode.FCVTAU, getVdVn2 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b10011101u -> Opcode.UCVTF, getVdVn2 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b11001100u -> Opcode.FCMGE, getVdVnF0 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b11001101u -> Opcode.FCMLE, getVdVnF0 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b11001110u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b11011010u -> Opcode.FCVTPU, getVdVn2 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b11011011u -> Opcode.FCVTZU, getVdVn2 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b11011101u ->
    Opcode.FRSQRTE, getVdVn2 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b11011111u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseAdvSIMDScalarPairwise bin =
  let cond = concat (concat (extract bin 29u 29u) (extract bin 23u 22u) 2)
                    (extract bin 16u 12u) 5 (* U:size:opcode *)
  match cond with
  | c when c &&& 0b00011000u = 0b00000000u -> raise UnallocatedException
  | c when c &&& 0b00011100u = 0b00001000u -> raise UnallocatedException
  | c when c &&& 0b00011111u = 0b00001110u -> raise UnallocatedException
  | c when c &&& 0b00011000u = 0b00010000u -> raise UnallocatedException
  | c when c &&& 0b00011110u = 0b00011000u -> raise UnallocatedException
  | c when c &&& 0b00011111u = 0b00011010u -> raise UnallocatedException
  | c when c &&& 0b00011100u = 0b00011100u -> raise UnallocatedException
  | c when c &&& 0b01011111u = 0b01001101u -> raise UnallocatedException
  | c when c &&& 0b10011111u = 0b00011011u ->
    Opcode.ADDP, getVdVnt4 bin size0x10, 0<rt>
  | c when c &&& 0b10011111u = 0b10011011u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b10001100u ->
    Opcode.FMAXNMP, getVdVnt5 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b10001101u -> Opcode.FADDP, getVdVnt5 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b10001111u -> Opcode.FMAXP, getVdVnt5 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b11001100u ->
    Opcode.FMINNMP, getVdVnt5 bin, 0<rt>
  | c when c &&& 0b11011111u = 0b11001111u -> Opcode.FMINP, getVdVnt5 bin, 0<rt>
  | _ -> raise InvalidOpcodeException

let parseAdvSIMDScalarThreeDiff bin =
  let cond = concat (extract bin 29u 29u) (extract bin 15u 12u) 4
  match cond with
  | c when c &&& 0b01100u = 0b00000u -> raise UnallocatedException
  | c when c &&& 0b01100u = 0b00100u -> raise UnallocatedException
  | c when c &&& 0b01111u = 0b01000u -> raise UnallocatedException
  | c when c &&& 0b01111u = 0b01010u -> raise UnallocatedException
  | c when c &&& 0b01111u = 0b01100u -> raise UnallocatedException
  | c when c &&& 0b01110u = 0b01110u -> raise UnallocatedException
  | c when c &&& 0b11111u = 0b01001u ->
    Opcode.SQDMLAL, getVadVbnVbm bin size0011, 0<rt>
  | c when c &&& 0b11111u = 0b01011u ->
    Opcode.SQDMLSL, getVadVbnVbm bin size0011, 0<rt>
  | c when c &&& 0b11111u = 0b01101u ->
    Opcode.SQDMULL, getVadVbnVbm bin size0011, 0<rt>
  | c when c &&& 0b11111u = 0b11001u -> raise UnallocatedException
  | c when c &&& 0b11111u = 0b11011u -> raise UnallocatedException
  | c when c &&& 0b11111u = 0b11101u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseAdvSIMDScalarThreeSame bin =
  let cond = concat (concat (extract bin 29u 29u) (extract bin 23u 22u) 2)
                    (extract bin 15u 11u) 5 (* U:size:opcode *)
  match cond with
  | c when c &&& 0b00011111u = 0b00000000u -> raise UnallocatedException
  | c when c &&& 0b00011110u = 0b00000010u -> raise UnallocatedException
  | c when c &&& 0b00011111u = 0b00000100u -> raise UnallocatedException
  | c when c &&& 0b00011100u = 0b00001100u -> raise UnallocatedException
  | c when c &&& 0b00011110u = 0b00010010u -> raise UnallocatedException
  | c when c &&& 0b01011111u = 0b01011011u -> raise UnallocatedException
  | c when c &&& 0b10011111u = 0b00000001u ->
    Opcode.SQADD, getVdVnVm1 bin resNone
  | c when c &&& 0b10011111u = 0b00000101u ->
    Opcode.SQSUB, getVdVnVm1 bin resNone
  | c when c &&& 0b10011111u = 0b00000110u ->
    Opcode.CMGT, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b00000111u ->
    Opcode.CMGE, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b00001000u ->
    Opcode.SSHL, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b00001001u ->
    Opcode.SQSHL, getVdVnVm1 bin resNone
  | c when c &&& 0b10011111u = 0b00001010u ->
    Opcode.SRSHL, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b00001011u ->
    Opcode.SQRSHL, getVdVnVm1 bin resNone
  | c when c &&& 0b10011111u = 0b00010000u ->
    Opcode.ADD, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b00010001u ->
    Opcode.CMTST, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b00010100u -> raise UnallocatedException
  | c when c &&& 0b10011111u = 0b00010101u -> raise UnallocatedException
  | c when c &&& 0b10011111u = 0b00010110u ->
    Opcode.SQDMULH, getVdVnVm1 bin size0011
  | c when c &&& 0b10011111u = 0b00010111u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b00011000u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b00011001u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b00011010u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b00011011u -> Opcode.FMULX, getVdVnVm2 bin
  | c when c &&& 0b11011111u = 0b00011100u -> Opcode.FCMEQ, getVdVnVm2 bin
  | c when c &&& 0b11011111u = 0b00011101u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b00011110u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b00011111u -> Opcode.FRECPS, getVdVnVm2 bin
  | c when c &&& 0b11011111u = 0b01011000u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b01011001u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b01011010u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b01011100u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b01011101u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b01011110u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b01011111u -> Opcode.FRSQRTS, getVdVnVm2 bin
  | c when c &&& 0b10011111u = 0b10000001u ->
    Opcode.UQADD, getVdVnVm1 bin resNone
  | c when c &&& 0b10011111u = 0b10000101u ->
    Opcode.UQSUB, getVdVnVm1 bin resNone
  | c when c &&& 0b10011111u = 0b10000110u ->
    Opcode.CMHI, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b10000111u ->
    Opcode.CMHS, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b10001000u ->
    Opcode.USHL, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b10001001u ->
    Opcode.UQSHL, getVdVnVm1 bin resNone
  | c when c &&& 0b10011111u = 0b10001010u ->
    Opcode.URSHL, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b10001011u ->
    Opcode.UQRSHL, getVdVnVm1 bin resNone
  | c when c &&& 0b10011111u = 0b10010000u ->
    Opcode.SUB, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b10010001u ->
    Opcode.CMEQ, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b10010100u -> raise UnallocatedException
  | c when c &&& 0b10011111u = 0b10010101u -> raise UnallocatedException
  | c when c &&& 0b10011111u = 0b10010110u ->
    Opcode.SQRDMULH, getVdVnVm1 bin size0011
  | c when c &&& 0b10011111u = 0b10010111u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b10011000u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b10011001u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b10011010u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b10011011u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b10011100u -> Opcode.FCMGE, getVdVnVm2 bin
  | c when c &&& 0b11011111u = 0b10011101u -> Opcode.FACGE, getVdVnVm2 bin
  | c when c &&& 0b11011111u = 0b10011110u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b10011111u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b11011000u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b11011001u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b11011010u -> Opcode.FABD, getVdVnVm2 bin
  | c when c &&& 0b11011111u = 0b11011100u -> Opcode.FCMGT, getVdVnVm2 bin
  | c when c &&& 0b11011111u = 0b11011101u -> Opcode.FACGT, getVdVnVm2 bin
  | c when c &&& 0b11011111u = 0b11011110u -> raise UnallocatedException
  | c when c &&& 0b11011111u = 0b11011111u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException
  |> getSIMDScalarOprSize (extract bin 15u 14u) (valSize1 bin)

let parseAdvSIMDScalarShiftByImm bin =
  let cond = concat (extract bin 29u 29u) (extract bin 15u 11u) 5 (* U:opcode *)
  let isImmhZero = (extract bin 22u 19u) = 0b0000u
  if isImmhZero then raise UnallocatedException
  match cond with
  | c when c &&& 0b011111u = 0b000001u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b000011u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b000101u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b000111u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b001001u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b001011u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b001101u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b001111u -> raise UnallocatedException
  | c when c &&& 0b011100u = 0b010100u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b011001u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b011010u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b011101u -> raise UnallocatedException
  | c when c &&& 0b011111u = 0b011110u -> raise UnallocatedException
  | 0b000000u -> Opcode.SSHR, getVdVnShf bin immh0xxx, 0<rt>
  | 0b000010u -> Opcode.SSRA, getVdVnShf bin immh0xxx, 0<rt>
  | 0b000100u -> Opcode.SRSHR, getVdVnShf bin immh0xxx, 0<rt>
  | 0b000110u -> Opcode.SRSRA, getVdVnShf bin immh0xxx, 0<rt>
  | 0b001000u -> raise UnallocatedException
  | 0b001010u -> Opcode.SHL, getVdVnShf2 bin immh0xxx, 0<rt>
  | 0b001100u -> raise UnallocatedException
  | 0b001110u -> Opcode.SQSHL, getVdVnShf2 bin immh0000, 0<rt>
  | 0b010000u -> raise UnallocatedException
  | 0b010001u -> raise UnallocatedException
  | 0b010010u -> Opcode.SQSHRN, getVbdVanShf bin immh00001xxx, 0<rt>
  | 0b010011u -> Opcode.SQRSHRN, getVbdVanShf bin immh00001xxx, 0<rt>
  | 0b011100u -> Opcode.SCVTF, getVdVnFbits bin immh00xx, 0<rt>
  | 0b011111u -> Opcode.FCVTZS, getVdVnFbits bin immh00xx, 0<rt>
  | 0b100000u -> Opcode.USHR, getVdVnShf bin immh0xxx, 0<rt>
  | 0b100010u -> Opcode.USRA, getVdVnShf bin immh0xxx, 0<rt>
  | 0b100100u -> Opcode.URSHR, getVdVnShf bin immh0xxx, 0<rt>
  | 0b100110u -> Opcode.URSRA, getVdVnShf bin immh0xxx, 0<rt>
  | 0b101000u -> Opcode.SRI, getVdVnShf bin immh0xxx, 0<rt>
  | 0b101010u -> Opcode.SLI, getVdVnShf2 bin immh0xxx, 0<rt>
  | 0b101100u -> Opcode.SQSHLU, getVdVnShf2 bin immh0000, 0<rt>
  | 0b101110u -> Opcode.UQSHL, getVdVnShf2 bin immh0000, 0<rt>
  | 0b110000u -> Opcode.SQSHRUN, getVbdVanShf bin immh00001xxx, 0<rt>
  | 0b110001u -> Opcode.SQRSHRUN, getVbdVanShf bin immh00001xxx, 0<rt>
  | 0b110010u -> Opcode.UQSHRN, getVbdVanShf bin immh00001xxx, 0<rt>
  | 0b110011u -> Opcode.UQRSHRN, getVbdVanShf bin immh00001xxx, 0<rt>
  | 0b111100u -> Opcode.UCVTF, getVdVnFbits bin immh00xx, 0<rt>
  | 0b111111u -> Opcode.FCVTZU, getVdVnFbits bin immh00xx, 0<rt>
  | _ -> raise InvalidOpcodeException

let parseAdvSIMDScalarXIdxElem b =
  let cond = concat (concat (extract b 29u 29u) (extract b 23u 22u) 2)
                    (extract b 15u 12u) 4 (* U:size:opcode *)
  match cond with
  | c when c &&& 0b0001111u = 0b0000000u -> raise UnallocatedException
  | c when c &&& 0b0001111u = 0b0000100u -> raise UnallocatedException
  | c when c &&& 0b0001111u = 0b0000100u -> raise UnallocatedException
  | c when c &&& 0b0001111u = 0b0000110u -> raise UnallocatedException
  | c when c &&& 0b0001111u = 0b0001000u -> raise UnallocatedException
  | c when c &&& 0b0001111u = 0b0001010u -> raise UnallocatedException
  | c when c &&& 0b0001110u = 0b0001110u -> raise UnallocatedException
  | c when c &&& 0b1001111u = 0b0000011u ->
    Opcode.SQDMLAL, getVadVbnVmtsidx b size0011, 0<rt>
  | c when c &&& 0b1001111u = 0b0000111u ->
    Opcode.SQDMLSL, getVadVbnVmtsidx b size0011, 0<rt>
  | c when c &&& 0b1001111u = 0b0001011u ->
    Opcode.SQDMULL, getVadVbnVmtsidx b size0011, 0<rt>
  | c when c &&& 0b1001111u = 0b0001100u ->
    Opcode.SQDMULH, getVdVnVmtsidx1 b size0011, 0<rt>
  | c when c &&& 0b1001111u = 0b0001101u ->
    Opcode.SQRDMULH, getVdVnVmtsidx1 b size0011, 0<rt>
  | c when c &&& 0b1101111u = 0b0100001u ->
    Opcode.FMLA, getVdVnVmtsidx2 b szL11, 0<rt>
  | c when c &&& 0b1101111u = 0b0100101u ->
    Opcode.FMLS, getVdVnVmtsidx2 b szL11, 0<rt>
  | c when c &&& 0b1101111u = 0b0101001u ->
    Opcode.FMUL, getVdVnVmtsidx2 b szL11, 0<rt>
  | c when c &&& 0b1001111u = 0b1000011u -> raise UnallocatedException
  | c when c &&& 0b1001111u = 0b1000111u -> raise UnallocatedException
  | c when c &&& 0b1001111u = 0b1001011u -> raise UnallocatedException
  | c when c &&& 0b1001110u = 0b1001100u -> raise UnallocatedException
  | c when c &&& 0b1101111u = 0b1100001u -> raise UnallocatedException
  | c when c &&& 0b1101111u = 0b1100101u -> raise UnallocatedException
  | c when c &&& 0b1101111u = 0b1101001u ->
    Opcode.FMULX, getVdVnVmtsidx2 b szL11, 0<rt>
  | _ -> raise InvalidOpcodeException

let parseConvBetwFPAndFixedPt bin =
  let cond = concat (concat (concat (pickBit bin 31u) (pickBit bin 29u) 1)
                            (extract bin 23u 22u) 2)
                    (extract bin 20u 16u) 5 (* sf:S:type:rmode:opcode *)
  match cond with
  | c when c &&& 0b000000100u = 0b000000100u -> raise UnallocatedException
  | c when c &&& 0b000001110u = 0b000000000u -> raise UnallocatedException
  | c when c &&& 0b000001110u = 0b000001010u -> raise UnallocatedException
  | c when c &&& 0b000010110u = 0b000000000u -> raise UnallocatedException
  | c when c &&& 0b000010110u = 0b000010010u -> raise UnallocatedException
  | c when c &&& 0b001100000u = 0b001000000u -> raise UnallocatedException
  | c when c &&& 0b010000000u = 0b010000000u -> raise UnallocatedException
  | c when c &&& 0b100000000u = 0b000000000u &&
           (extract bin 15u 10u) >>> 5 = 0b0u -> raise UnallocatedException
  | 0b000000010u -> Opcode.SCVTF, getSdWnFbits bin, 32<rt>
  | 0b000000011u -> Opcode.UCVTF, getSdWnFbits bin, 32<rt>
  | 0b000011000u -> Opcode.FCVTZS, getWdSnFbits bin, 32<rt>
  | 0b000011001u -> Opcode.FCVTZU, getWdSnFbits bin, 32<rt>
  | 0b000100010u -> Opcode.SCVTF, getDdWnFbits bin, 64<rt>
  | 0b000100011u -> Opcode.UCVTF, getDdWnFbits bin, 64<rt>
  | 0b000111000u -> Opcode.FCVTZS, getWdDnFbits bin, 32<rt>
  | 0b000111001u -> Opcode.FCVTZU, getWdDnFbits bin, 32<rt>
  | 0b100000010u -> Opcode.SCVTF, getSdXnFbits bin, 32<rt>
  | 0b100000011u -> Opcode.UCVTF, getSdXnFbits bin, 32<rt>
  | 0b100011000u -> Opcode.FCVTZS, getXdSnFbits bin, 64<rt>
  | 0b100011001u -> Opcode.FCVTZU, getXdSnFbits bin, 64<rt>
  | 0b100100010u -> Opcode.SCVTF, getDdXnFbits bin, 64<rt>
  | 0b100100011u -> Opcode.UCVTF, getDdXnFbits bin, 64<rt>
  | 0b100111000u -> Opcode.FCVTZS, getXdDnFbits bin, 64<rt>
  | 0b100111001u -> Opcode.FCVTZU, getXdDnFbits bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let parseConvBetwFPAndInt bin =
  let cond = concat (concat (concat (pickBit bin 31u) (pickBit bin 29u) 1)
                            (extract bin 23u 22u) 2)
                    (extract bin 20u 16u) 5 (* sf:S:type:rmode:opcode *)
  match cond with
  | c when c &&& 0b000001110u = 0b000001010u -> raise UnallocatedException
  | c when c &&& 0b000001110u = 0b000001100u -> raise UnallocatedException
  | c when c &&& 0b000010110u = 0b000010010u -> raise UnallocatedException
  | c when c &&& 0b000010110u = 0b000010100u -> raise UnallocatedException
  | c when c &&& 0b011100100u = 0b001000000u -> raise UnallocatedException
  | c when c &&& 0b011100110u = 0b001000100u -> raise UnallocatedException
  | c when c &&& 0b010000000u = 0b010000000u -> raise UnallocatedException
  | c when c &&& 0b111101110u = 0b000001110u -> raise UnallocatedException
  | 0b000000000u -> Opcode.FCVTNS, getWdSn bin, 32<rt>
  | 0b000000001u -> Opcode.FCVTNU, getWdSn bin, 32<rt>
  | 0b000000010u -> Opcode.SCVTF, getSdWn bin, 32<rt>
  | 0b000000011u -> Opcode.UCVTF, getSdWn bin, 32<rt>
  | 0b000000100u -> Opcode.FCVTAS, getWdSn bin, 32<rt>
  | 0b000000101u -> Opcode.FCVTAU, getWdSn bin, 32<rt>
  | 0b000000110u -> Opcode.FMOV, getWdSn bin, 32<rt>
  | 0b000000111u -> Opcode.FMOV, getSdWn bin, 32<rt>
  | 0b000001000u -> Opcode.FCVTPS, getWdSn bin, 32<rt>
  | 0b000001001u -> Opcode.FCVTPU, getWdSn bin, 32<rt>
  | c when c &&& 0b111110110u = 0b000010110u -> raise UnallocatedException
  | 0b000010000u -> Opcode.FCVTMS, getWdSn bin, 32<rt>
  | 0b000010001u -> Opcode.FCVTMU, getWdSn bin, 32<rt>
  | 0b000011000u -> Opcode.FCVTZS, getWdSn bin, 32<rt>
  | 0b000011001u -> Opcode.FCVTZU, getWdSn bin, 32<rt>
  | c when c &&& 0b111100110u = 0b000100110u -> raise UnallocatedException
  | 0b000100000u -> Opcode.FCVTNS, getWdDn bin, 32<rt>
  | 0b000100001u -> Opcode.FCVTNU, getWdDn bin, 32<rt>
  | 0b000100010u -> Opcode.SCVTF, getDdWn bin, 64<rt>
  | 0b000100011u -> Opcode.UCVTF, getDdWn bin, 64<rt>
  | 0b000100100u -> Opcode.FCVTAS, getWdDn bin, 32<rt>
  | 0b000100101u -> Opcode.FCVTAU, getWdDn bin, 32<rt>
  | 0b000101000u -> Opcode.FCVTPS, getWdDn bin, 32<rt>
  | 0b000101001u -> Opcode.FCVTPU, getWdDn bin, 32<rt>
  | 0b000110000u -> Opcode.FCVTMS, getWdDn bin, 32<rt>
  | 0b000110001u -> Opcode.FCVTMU, getWdDn bin, 32<rt>
  | 0b000111000u -> Opcode.FCVTZS, getWdDn bin, 32<rt>
  | 0b000111001u -> Opcode.FCVTZU, getWdDn bin, 32<rt>
  | c when c &&& 0b111100110u = 0b001000110u -> raise UnallocatedException
  | c when c &&& 0b111100110u = 0b100000110u -> raise UnallocatedException
  | 0b100000000u -> Opcode.FCVTNS, getXdSn bin, 64<rt>
  | 0b100000001u -> Opcode.FCVTNU, getXdSn bin, 64<rt>
  | 0b100000010u -> Opcode.SCVTF, getSdXn bin, 32<rt>
  | 0b100000011u -> Opcode.UCVTF, getSdXn bin, 32<rt>
  | 0b100000100u -> Opcode.FCVTAS, getXdSn bin, 64<rt>
  | 0b100000101u -> Opcode.FCVTAU, getXdSn bin, 64<rt>
  | 0b100001000u -> Opcode.FCVTPS, getXdSn bin, 64<rt>
  | 0b100001001u -> Opcode.FCVTPU, getXdSn bin, 64<rt>
  | 0b100010000u -> Opcode.FCVTMS, getXdSn bin, 64<rt>
  | 0b100010001u -> Opcode.FCVTMU, getXdSn bin, 64<rt>
  | 0b100011000u -> Opcode.FCVTZS, getXdSn bin, 64<rt>
  | 0b100011001u -> Opcode.FCVTZU, getXdSn bin, 64<rt>
  | c when c &&& 0b111101110u = 0b100101110u -> raise UnallocatedException
  | 0b100100000u -> Opcode.FCVTNS, getXdDn bin, 64<rt>
  | 0b100100001u -> Opcode.FCVTNU, getXdDn bin, 64<rt>
  | 0b100100010u -> Opcode.SCVTF, getDdXn bin, 64<rt>
  | 0b100100011u -> Opcode.UCVTF, getDdXn bin, 64<rt>
  | 0b100100100u -> Opcode.FCVTAS, getXdDn bin, 64<rt>
  | 0b100100101u -> Opcode.FCVTAU, getXdDn bin, 64<rt>
  | 0b100100110u -> Opcode.FMOV, getXdDn bin, 64<rt>
  | 0b100100111u -> Opcode.FMOV, getDdXn bin, 64<rt>
  | 0b100101000u -> Opcode.FCVTPS, getXdDn bin, 64<rt>
  | 0b100101001u -> Opcode.FCVTPU, getXdDn bin, 64<rt>
  | c when c &&& 0b111110110u = 0b100110110u -> raise UnallocatedException
  | 0b100110000u -> Opcode.FCVTMS, getXdDn bin, 64<rt>
  | 0b100110001u -> Opcode.FCVTMU, getXdDn bin, 64<rt>
  | 0b100111000u -> Opcode.FCVTZS, getXdDn bin, 64<rt>
  | 0b100111001u -> Opcode.FCVTZU, getXdDn bin, 64<rt>
  | c when c &&& 0b111101110u = 0b101000110u -> raise UnallocatedException
  | 0b101001110u -> Opcode.FMOV, getXdVnD1 bin, 64<rt>
  | 0b101001111u -> Opcode.FMOV, getVdD1Xn bin, 0<rt>
  | c when c &&& 0b111110110u = 0b101010110u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseFPDP1Src bin =
  let cond = concat (concat (concat (pickBit bin 31u) (pickBit bin 29u) 1)
                            (extract bin 23u 22u) 2)
                    (extract bin 20u 15u) 6 (* M:S:type:opcode *)
  match cond with
  | c when c &&& 0b0000010000u = 0b0000010000u -> raise UnallocatedException
  | c when c &&& 0b0000100000u = 0b0000100000u -> raise UnallocatedException
  | c when c &&& 0b0100000000u = 0b0100000000u -> raise UnallocatedException
  | 0b0000000000u -> Opcode.FMOV, getSdSn bin, 32<rt>
  | 0b0000000001u -> Opcode.FABS, getSdSn bin, 32<rt>
  | 0b0000000010u -> Opcode.FNEG, getSdSn bin, 32<rt>
  | 0b0000000011u -> Opcode.FSQRT, getSdSn bin, 32<rt>
  | 0b0000000100u -> raise UnallocatedException
  | 0b0000000101u -> Opcode.FCVT, getDdSn bin, 64<rt>
  | 0b0000000110u -> raise UnallocatedException
  | 0b0000000111u -> Opcode.FCVT, getHdSn bin, 16<rt>
  | 0b0000001000u -> Opcode.FRINTN, getSdSn bin, 32<rt>
  | 0b0000001001u -> Opcode.FRINTP, getSdSn bin, 32<rt>
  | 0b0000001010u -> Opcode.FRINTM, getSdSn bin, 32<rt>
  | 0b0000001011u -> Opcode.FRINTZ, getSdSn bin, 32<rt>
  | 0b0000001100u -> Opcode.FRINTA, getSdSn bin, 32<rt>
  | 0b0000001101u -> raise UnallocatedException
  | 0b0000001110u -> Opcode.FRINTX, getSdSn bin, 32<rt>
  | 0b0000001111u -> Opcode.FRINTI, getSdSn bin, 32<rt>
  | 0b0001000000u -> Opcode.FMOV, getDdDn bin, 64<rt>
  | 0b0001000001u -> Opcode.FABS, getDdDn bin, 64<rt>
  | 0b0001000010u -> Opcode.FNEG, getDdDn bin, 64<rt>
  | 0b0001000011u -> Opcode.FSQRT, getDdDn bin, 64<rt>
  | 0b0001000100u -> Opcode.FCVT, getSdDn bin, 32<rt>
  | 0b0001000101u -> raise UnallocatedException
  | 0b0001000110u -> raise UnallocatedException
  | 0b0001000111u -> Opcode.FCVT, getHdDn bin, 16<rt>
  | 0b0001001000u -> Opcode.FRINTN, getDdDn bin, 64<rt>
  | 0b0001001001u -> Opcode.FRINTP, getDdDn bin, 64<rt>
  | 0b0001001010u -> Opcode.FRINTM, getDdDn bin, 64<rt>
  | 0b0001001011u -> Opcode.FRINTZ, getDdDn bin, 64<rt>
  | 0b0001001100u -> Opcode.FRINTA, getDdDn bin, 64<rt>
  | 0b0001001101u -> raise UnallocatedException
  | 0b0001001110u -> Opcode.FRINTX, getDdDn bin, 64<rt>
  | 0b0001001111u -> Opcode.FRINTI, getDdDn bin, 64<rt>
  | c when c &&& 0b1111110000u = 0b0010000000u -> raise UnallocatedException
  | 0b0011000100u -> Opcode.FCVT, getSdHn bin, 32<rt>
  | 0b0011000101u -> Opcode.FCVT, getDdHn bin, 64<rt>
  | c when c &&& 0b1111111110u = 0b0011000110u -> raise UnallocatedException
  | 0b0011001101u -> raise UnallocatedException
  | c when c &&& 0b1000000000u = 0b1000000000u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseFPCompare bin =
  let cond = concat (concat (concat (concat (pickBit bin 31u)
                                            (pickBit bin 29u) 1)
                                    (extract bin 23u 22u) 2)
                            (extract bin 15u 14u) 2)
                    (extract bin 4u 0u) 5 (* M:S:type:op:opcode2 *)
  match cond with
  | c when c &&& 0b00000000001u = 0b00000000001u -> raise UnallocatedException
  | c when c &&& 0b00000000010u = 0b00000000010u -> raise UnallocatedException
  | c when c &&& 0b00000000100u = 0b00000000100u -> raise UnallocatedException
  | c when c &&& 0b00000100000u = 0b00000100000u -> raise UnallocatedException
  | c when c &&& 0b00001000000u = 0b00001000000u -> raise UnallocatedException
  | c when c &&& 0b00110000000u = 0b00100000000u -> raise UnallocatedException
  | c when c &&& 0b01000000000u = 0b01000000000u -> raise UnallocatedException
  | 0b00000000000u -> Opcode.FCMP, getSnSm bin, 32<rt>
  | 0b00000001000u -> Opcode.FCMP, getSnP0 bin, 32<rt>
  | 0b00000010000u -> Opcode.FCMPE, getSnSm bin, 32<rt>
  | 0b00000011000u -> Opcode.FCMPE, getSnP0 bin, 32<rt>
  | 0b00010000000u -> Opcode.FCMP, getDnDm bin, 64<rt>
  | 0b00010001000u -> Opcode.FCMP, getDnP0 bin, 64<rt>
  | 0b00010010000u -> Opcode.FCMPE, getDnDm bin, 64<rt>
  | 0b00010011000u -> Opcode.FCMPE, getDnP0 bin, 64<rt>
  | c when c &&& 0b10000000000u = 0b10000000000u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseFPImm bin =
  let cond = concat (concat (concat (pickBit bin 31u) (pickBit bin 29u) 1)
                            (extract bin 23u 22u) 2)
                    (extract bin 9u 5u) 5 (* M:S:type:imm5 *)
  match cond with
  | c when c &&& 0b000000001u = 0b000000001u -> raise UnallocatedException
  | c when c &&& 0b000000010u = 0b000000010u -> raise UnallocatedException
  | c when c &&& 0b000000100u = 0b000000100u -> raise UnallocatedException
  | c when c &&& 0b000001000u = 0b000001000u -> raise UnallocatedException
  | c when c &&& 0b000010000u = 0b000010000u -> raise UnallocatedException
  | c when c &&& 0b001100000u = 0b001000000u -> raise UnallocatedException
  | c when c &&& 0b010000000u = 0b010000000u -> raise UnallocatedException
  | 0b000000000u -> Opcode.FMOV, getSdImm8 bin, 32<rt>
  | 0b000100000u -> Opcode.FMOV, getDdImm8 bin, 64<rt>
  | c when c &&& 0b100000000u = 0b100000000u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseFPCondComp bin =
  let cond = concat (concat (concat (pickBit bin 31u) (pickBit bin 29u) 1)
                            (extract bin 23u 22u) 2)
                    (pickBit bin 4u) 1 (* M:S:type:op *)
  match cond with
  | c when c &&& 0b00110u = 0b00100u -> raise UnallocatedException
  | c when c &&& 0b01000u = 0b01000u -> raise UnallocatedException
  | 0b00000u -> Opcode.FCCMP, getSnSmNZCVCond bin, 32<rt>
  | 0b00001u -> Opcode.FCCMPE, getSnSmNZCVCond bin, 32<rt>
  | 0b00010u -> Opcode.FCCMP, getDnDmNZCVCond bin, 64<rt>
  | 0b00011u -> Opcode.FCCMPE, getDnDmNZCVCond bin, 64<rt>
  | c when c &&& 0b10000u = 0b10000u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseFPDP2Src bin =
  let cond = concat (concat (concat (pickBit bin 31u) (pickBit bin 29u) 1)
                            (extract bin 23u 22u) 2)
                    (extract bin 15u 12u) 4 (* M:S:type:opcode *)
  match cond with
  | c when c &&& 0b00001001u = 0b00001001u -> raise UnallocatedException
  | c when c &&& 0b00001010u = 0b00001010u -> raise UnallocatedException
  | c when c &&& 0b00001100u = 0b00001100u -> raise UnallocatedException
  | c when c &&& 0b00110000u = 0b00100000u -> raise UnallocatedException
  | c when c &&& 0b01000000u = 0b01000000u -> raise UnallocatedException
  | 0b00000000u -> Opcode.FMUL, getSdSnSm bin, 32<rt>
  | 0b00000001u -> Opcode.FDIV, getSdSnSm bin, 32<rt>
  | 0b00000010u -> Opcode.FADD, getSdSnSm bin, 32<rt>
  | 0b00000011u -> Opcode.FSUB, getSdSnSm bin, 32<rt>
  | 0b00000100u -> Opcode.FMAX, getSdSnSm bin, 32<rt>
  | 0b00000101u -> Opcode.FMIN , getSdSnSm bin, 32<rt>
  | 0b00000110u -> Opcode.FMAXNM, getSdSnSm bin, 32<rt>
  | 0b00000111u -> Opcode.FMINNM, getSdSnSm bin, 32<rt>
  | 0b00001000u -> Opcode.FNMUL, getSdSnSm bin, 32<rt>
  | 0b00010000u -> Opcode.FMUL, getDdDnDm bin, 64<rt>
  | 0b00010001u -> Opcode.FDIV, getDdDnDm bin, 64<rt>
  | 0b00010010u -> Opcode.FADD, getDdDnDm bin, 64<rt>
  | 0b00010011u -> Opcode.FSUB, getDdDnDm bin, 64<rt>
  | 0b00010100u -> Opcode.FMAX, getDdDnDm bin, 64<rt>
  | 0b00010101u -> Opcode.FMIN, getDdDnDm bin, 64<rt>
  | 0b00010110u -> Opcode.FMAXNM, getDdDnDm bin, 64<rt>
  | 0b00010111u -> Opcode.FMINNM, getDdDnDm bin, 64<rt>
  | 0b00011000u -> Opcode.FNMUL, getDdDnDm bin, 64<rt>
  | c when c &&& 0b10000000u = 0b10000000u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseFPCondSelect bin =
  let cond = concat (concat (pickBit bin 31u) (pickBit bin 29u) 1)
                    (extract bin 23u 22u) 2 (* M:S:type *)
  match cond with
  | c when c &&& 0b0011u = 0b0010u -> raise UnallocatedException
  | c when c &&& 0b0100u = 0b0100u -> raise UnallocatedException
  | 0b0000u -> Opcode.FCSEL, getSdSnSmCond bin, 32<rt>
  | 0b0001u -> Opcode.FCSEL, getDdDnDmCond bin, 64<rt>
  | c when c &&& 0b1000u = 0b1000u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

let parseFPDP3Src bin =
  let cond = concat (concat (concat (pickBit bin 31u) (pickBit bin 29u) 1)
                            (extract bin 23u 21u) 3)
                    (pickBit bin 15u) 1 (* M:S:o1:o0 *)
  match cond with
  | c when c &&& 0b001100u = 0b001000u -> raise UnallocatedException
  | c when c &&& 0b010000u = 0b010000u -> raise UnallocatedException
  | 0b000000u -> Opcode.FMADD, getSdSnSmSa bin, 32<rt>
  | 0b000001u -> Opcode.FMSUB, getSdSnSmSa bin, 32<rt>
  | 0b000010u -> Opcode.FNMADD, getSdSnSmSa bin, 32<rt>
  | 0b000011u -> Opcode.FNMSUB, getSdSnSmSa bin, 32<rt>
  | 0b000100u -> Opcode.FMADD, getDdDnDmDa bin, 64<rt>
  | 0b000101u -> Opcode.FMSUB, getDdDnDmDa bin, 64<rt>
  | 0b000110u -> Opcode.FNMADD, getDdDnDmDa bin, 64<rt>
  | 0b000111u -> Opcode.FNMSUB, getDdDnDmDa bin, 64<rt>
  | c when c &&& 0b100000u = 0b100000u -> raise UnallocatedException
  | _ -> raise InvalidOpcodeException

/// Data processing - SIMD and FP - 2
let parse64Group6 bin =
  let cond = concat (concat (extract bin 31u 28u) (extract bin 24u 17u) 8)
                    (extract bin 15u 10u) 6 (* op0:op1:op2:op3:op4 *)
  match cond with
  | c when c &&& 0b111110010000100011u = 0b010100000000000000u ->
    parseCryptThreeRegSHA bin
  | c when c &&& 0b111110010000100011u = 0b010100000000000010u ->
    raise UnallocatedException
  | c when c &&& 0b111110011111000011u = 0b010100010100000010u ->
    parseCryptTwoRegSHA bin
  | c when c &&& 0b111110010000100001u = 0b011100000000000000u ->
    raise UnallocatedException
  | c when c &&& 0b111110011111000011u = 0b011100010100000010u ->
    raise UnallocatedException
  | c when c &&& 0b110111110000100001u = 0b010100000000000001u ->
    parseAdvSIMDScalarCopy bin
  | c when c &&& 0b110111010000100001u = 0b010101000000000001u ->
    raise UnallocatedException
  | c when c &&& 0b110110111111000011u = 0b010100011100000010u ->
    raise UnallocatedException
  | c when c &&& 0b110110011111000011u = 0b010100010000000010u ->
    parseAdvSIMDScalarTwoReg bin
  | c when c &&& 0b110110011111000011u = 0b010100011000000010u ->
    parseAdvSIMDScalarPairwise bin
  | c when c &&& 0b110110010010000011u = 0b010100010010000010u ->
    raise UnallocatedException
  | c when c &&& 0b110110010001000011u = 0b010100010001000010u ->
    raise UnallocatedException
  | c when c &&& 0b110110010000000011u = 0b010100010000000000u ->
    parseAdvSIMDScalarThreeDiff bin
  | c when c &&& 0b110110010000000001u = 0b010100010000000001u ->
    parseAdvSIMDScalarThreeSame bin
  | c when c &&& 0b110111000000000001u = 0b010110000000000001u ->
    parseAdvSIMDScalarShiftByImm bin
  | c when c &&& 0b110111000000000001u = 0b010111000000000001u ->
    raise UnallocatedException
  | c when c &&& 0b110110000000000001u = 0b010110000000000000u ->
    parseAdvSIMDScalarXIdxElem bin
  | c when c &&& 0b110100000000000000u = 0b110100000000000000u ->
    raise UnallocatedException
  | c when c &&& 0b010110010000000000u = 0b000100000000000000u ->
    parseConvBetwFPAndFixedPt bin
  | c when c &&& 0b010110010000111111u = 0b000100010000000000u ->
    parseConvBetwFPAndInt bin
  | c when c &&& 0b010110010000111111u = 0b000100010000100000u ->
    raise UnallocatedException
  | c when c &&& 0b010110010000011111u = 0b000100010000010000u ->
    parseFPDP1Src bin
  | c when c &&& 0b010110010000001111u = 0b000100010000001000u ->
    parseFPCompare bin
  | c when c &&& 0b010110010000000111u = 0b000100010000000100u ->
    parseFPImm bin
  | c when c &&& 0b010110010000000011u = 0b000100010000000001u ->
    parseFPCondComp bin
  | c when c &&& 0b010110010000000011u = 0b000100010000000010u ->
    parseFPDP2Src bin
  | c when c &&& 0b010110010000000011u = 0b000100010000000011u ->
    parseFPCondSelect bin
  | c when c &&& 0b010110000000000000u = 0b000110000000000000u ->
    parseFPDP3Src bin
  | _ -> raise InvalidOpcodeException

let parseByGroupOfB64 bin =
  let op0 = extract bin 28u 25u
  match op0 with
  | op0 when op0 &&& 0b1100u = 0b0000u -> raise UnallocatedException
  (* Data processing - immediate *)
  | op0 when op0 &&& 0b1110u = 0b1000u -> parse64Group1 bin
  (* Branches, exception generating and system instructions *)
  | op0 when op0 &&& 0b1110u = 0b1010u -> parse64Group2 bin
  (* Loads and stores *)
  | op0 when op0 &&& 0b0101u = 0b0100u -> parse64Group3 bin
  (* Data processing - register *)
  | op0 when op0 &&& 0b0111u = 0b0101u -> parse64Group4 bin
  (* Data processing - SIMD and floating point *)
  | op0 when op0 &&& 0b1111u = 0b0111u -> parse64Group5 bin
  (* Data processing - SIMD and floating point *)
  | op0 when op0 &&& 0b1111u = 0b1111u -> parse64Group6 bin
  | _ -> raise InvalidOpcodeException

let parse (span: ByteSpan) (reader: IBinReader) addr =
  let bin = reader.ReadUInt32 (span, 0)
  let opcode, operands, oprSize = parseByGroupOfB64 bin
  let insInfo =
    {
      Address = addr
      NumBytes = 4u
      Condition = None
      Opcode = opcode
      Operands = operands
      OprSize = oprSize
    }
  ARM64Instruction (addr, 4u, insInfo, WordSize.Bit64 (* FIXME *))

// vim: set tw=80 sts=2 sw=2:

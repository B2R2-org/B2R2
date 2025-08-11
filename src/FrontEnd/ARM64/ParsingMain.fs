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

module internal B2R2.FrontEnd.ARM64.ParsingMain

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM64.Utils
open B2R2.FrontEnd.ARM64.OperandHelper

/// Opcode functions
let getOpcodeByQ bin op1 op2 = if valQ bin = 0u then op1 else op2

/// Operand functions
let getOptionOrimm bin = OneOperand(optionOrimm bin)

(* Register - Register *)
let getWdWn bin = TwoOperands(wd bin, wn bin)

let getXdXn bin = TwoOperands(xd bin, xn bin)

let getHdXn bin = TwoOperands(hd bin, xn bin)

let getWdSn bin = TwoOperands(wd bin, sn bin)

let getWdDn bin = TwoOperands(wd bin, dn bin)

let getXdSn bin = TwoOperands(xd bin, sn bin)

let getXdDn bin = TwoOperands(xd bin, dn bin)

let getSdWn bin = TwoOperands(sd bin, wn bin)

let getDdWn bin = TwoOperands(dd bin, wn bin)

let getHdWn bin = TwoOperands(hd bin, wn bin)

let getSdXn bin = TwoOperands(sd bin, xn bin)

let getDdXn bin = TwoOperands(dd bin, xn bin)

let getSdSn bin = TwoOperands(sd bin, sn bin)

let getDdDn bin = TwoOperands(dd bin, dn bin)

let getDdSn bin = TwoOperands(dd bin, sn bin)

let getHdSn bin = TwoOperands(hd bin, sn bin)

let getSdDn bin = TwoOperands(sd bin, dn bin)

let getHdDn bin = TwoOperands(hd bin, dn bin)

let getSdHn bin = TwoOperands(sd bin, hn bin)

let getDdHn bin = TwoOperands(dd bin, hn bin)

let getDnDm bin = TwoOperands(dn bin, dm bin)

let getSnSm bin = TwoOperands(sn bin, sm bin)

let getXdVnD1 bin = TwoOperands(xd bin, vnD1 bin)

let getVdVnt1 bin r = r bin; TwoOperands(vd1 bin, vntsq1 bin)

let getVdVnt2 bin r = r bin; TwoOperands(vd2 bin, vntsq1 bin)

let getVdVnt3 bin r = r bin; TwoOperands(vd3a bin, vntszq1 bin)

let getVdVnt4 bin r = r bin; TwoOperands(vd2 bin, vnts2 bin)

let getVdVnt5 bin = TwoOperands(vd3a bin, vntsz3 bin)

let getVdD1Xn bin = TwoOperands(vdD1 bin, xn bin)

let getVd16BVn16B bin = TwoOperands(vd16B bin, vn16B bin)

let getVdVn bin r = r bin; TwoOperands(vd2 bin, vn2 bin)

let getVdVn2 bin = TwoOperands(vd3a bin, vn3 bin)

let getVbdVan bin r = r bin; TwoOperands(vd2 bin, vn1 bin)

let getVbdVan2 bin r = r bin; TwoOperands(vd3b bin, vn3 bin)

let getVdtVnt bin r = r bin; TwoOperands(vdtsq1 bin, vntsq1 bin)

let getVdtVnt2 bin r = r bin; TwoOperands(vdtszq1 bin, vntszq1 bin)

let getVdtVnt3 bin = TwoOperands(vdtq1 bin, vntq1 bin)

let getVdtaVntb bin r = r bin; TwoOperands(vdtsq2 bin, vntsq1 bin)

let getVdtaVntb2 bin = TwoOperands(vdtsz1 bin, vntszq2 bin)

let getVdtbVnta bin r = r bin; TwoOperands(vdtsq1 bin, vnts1 bin)

let getVdtbVnta2 bin r = r bin; TwoOperands(vdtszq2 bin, vntsz1 bin)

let getVd4SVn4S bin = TwoOperands(vd4S bin, vn4S bin)

let getVdtVntsidx bin = TwoOperands(vdti5q bin, vtsidx1 bin valN)

let getVdtRn bin = TwoOperands(vdti5q bin, rn bin)

let getWdVntsidx bin r = r bin; TwoOperands(wd bin, vtsidx1 bin valN)

let getXdVntsidx bin r = r bin; TwoOperands(xd bin, vtsidx1 bin valN)

let getVdtsidxRn bin = TwoOperands(vtsidx1 bin valD, rn bin)

let getVdtsidx1Vntsidx2 bin = TwoOperands(vtsidx1 bin valD, vtsidx2 bin valN)

let getVdVntidx bin = TwoOperands(vd4 bin, vntidx bin)

(* Register - Immediate *)
let getSnP0 bin = TwoOperands(sn bin, p0)

let getDnP0 bin = TwoOperands(dn bin, p0)

let getSdImm8 bin = TwoOperands(sd bin, fScalarImm8 bin)

let getDdImm8 bin = TwoOperands(dd bin, fScalarImm8 bin)

let getDdImm bin = TwoOperands(dd bin, imm64 bin)

let getVd2DImm bin = TwoOperands(vd2D bin, imm64 bin)

let getVdtFImm bin = TwoOperands(vdtq2 bin, fVecImm8 bin)

let getVd2DFImm bin = TwoOperands(vd2D bin, fVecImm8 bin)

(* Register - Memory *)
let getWtMXSn bin = TwoOperands(wt1 bin, memXSn bin)

let getXtMXSn bin = TwoOperands(xt1 bin, memXSn bin)

let getWtBIXSnpimm bin scale = TwoOperands(wt1 bin, memXSnPimm bin scale)

let getXtBIXSnpimm bin scale = TwoOperands(xt1 bin, memXSnPimm bin scale)

let getBtBIXSnpimm bin = TwoOperands(bt bin, memXSnPimm bin 1u)

let getHtBIXSnpimm bin = TwoOperands(ht bin, memXSnPimm bin 2u)

let getStBIXSnpimm bin = TwoOperands(st1 bin, memXSnPimm bin 4u)

let getDtBIXSnpimm bin = TwoOperands(dt1 bin, memXSnPimm bin 8u)

let getQtBIXSnpimm bin = TwoOperands(qt1 bin, memXSnPimm bin 16u)

let getPrfopimm5BIXSnpimm bin = TwoOperands(prfopImm5 bin, memXSnPimm bin 8u)

let getWt1Wt2BIXSnimm b scl = ThreeOperands(wt1 b, wt2 b, memXSnSimm7 b scl)

let getXt1Xt2BIXSnimm b scl = ThreeOperands(xt1 b, xt2 b, memXSnSimm7 b scl)

let getSt1St2BIXSnimm b scl = ThreeOperands(st1 b, st2 b, memXSnSimm7 b scl)

let getDt1Dt2BIXSnimm b scl = ThreeOperands(dt1 b, dt2 b, memXSnSimm7 b scl)

let getQt1Qt2BIXSnimm b scl = ThreeOperands(qt1 b, qt2 b, memXSnSimm7 b scl)

let getVt1tMXSn bin r = r bin; TwoOperands(vt1t bin, memXSn bin)

let getVt2tMXSn bin r = r bin; TwoOperands(vt2t bin, memXSn bin)

let getVt3tMXSn bin r = r bin; TwoOperands(vt3t bin, memXSn bin)

let getVt4tMXSn bin r = r bin; TwoOperands(vt4t bin, memXSn bin)

let getvtntidxMXSn bin t n = TwoOperands(vtntidx bin t n, memXSn bin)

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

let getWtBIXSnsimm bin = TwoOperands(wt1 bin, memXSnSimm9 bin)

let getXtBIXSnsimm bin = TwoOperands(xt1 bin, memXSnSimm9 bin)

let getBtBIXSnsimm bin = TwoOperands(bt bin, memXSnSimm9 bin)

let getHtBIXSnsimm bin = TwoOperands(ht bin, memXSnSimm9 bin)

let getStBIXSnsimm bin = TwoOperands(st1 bin, memXSnSimm9 bin)

let getDtBIXSnsimm bin = TwoOperands(dt1 bin, memXSnSimm9 bin)

let getQtBIXSnsimm bin = TwoOperands(qt1 bin, memXSnSimm9 bin)

let getPrfopimm5BIXSnsimm bin = TwoOperands(prfopImm5 bin, memXSnSimm9 bin)

let getWtBEXSnrmamt bin amt = TwoOperands(wt1 bin, memExtXSnRmAmt bin amt)

let getWtBRXSnxmamt bin = TwoOperands(wt1 bin, memShfXSnXmAmt bin 0L)

let getXtBEXSnrmamt bin amt = TwoOperands(xt1 bin, memExtXSnRmAmt bin amt)

let getXtBRXSnxmamt bin = TwoOperands(xt1 bin, memShfXSnXmAmt bin 0L)

let getBtBEXSnrmamt bin = TwoOperands(bt bin, memExtXSnRmAmt bin 0L)

let getBtBRXSnxmamt bin = TwoOperands(bt bin, memShfXSnXmAmt bin 0L)

let getHtBEXSnrmamt bin = TwoOperands(ht bin, memExtXSnRmAmt bin 1L)

let getStBEXSnrmamt bin = TwoOperands(st1 bin, memExtXSnRmAmt bin 2L)

let getDtBEXSnrmamt bin = TwoOperands(dt1 bin, memExtXSnRmAmt bin 3L)

let getQtBEXSnrmamt bin = TwoOperands(qt1 bin, memExtXSnRmAmt bin 4L)

let getPrfopimm5BEXSnrmamt b = TwoOperands(prfopImm5 b, memExtXSnRmAmt b 3L)

let getWtPoXSnsimm bin = TwoOperands(wt1 bin, memPostXSnSimm bin)

let getXtPoXSnsimm bin = TwoOperands(xt1 bin, memPostXSnSimm bin)

let getBtPoXSnsimm bin = TwoOperands(bt bin, memPostXSnSimm bin)

let getHtPoXSnsimm bin = TwoOperands(ht bin, memPostXSnSimm bin)

let getStPoXSnsimm bin = TwoOperands(st1 bin, memPostXSnSimm bin)

let getDtPoXSnsimm bin = TwoOperands(dt1 bin, memPostXSnSimm bin)

let getQtPoXSnsimm bin = TwoOperands(qt1 bin, memPostXSnSimm bin)

let getWt1Wt2PoXSnimm b = ThreeOperands(wt1 b, wt2 b, memPostXSnImm b 2)

let getXt1Xt2PoXSnimm b s = ThreeOperands(xt1 b, xt2 b, memPostXSnImm b s)

let getSt1St2PoXSnimm b = ThreeOperands(st1 b, st2 b, memPostXSnImm b 2)

let getDt1Dt2PoXSnimm b = ThreeOperands(dt1 b, dt2 b, memPostXSnImm b 3)

let getQt1Qt2PoXSnimm b = ThreeOperands(qt1 b, qt2 b, memPostXSnImm b 4)

let getWtPrXSnsimm bin = TwoOperands(wt1 bin, memPreXSnSimm bin)

let getXtPrXSnsimm bin = TwoOperands(xt1 bin, memPreXSnSimm bin)

let getBtPrXSnsimm bin = TwoOperands(bt bin, memPreXSnSimm bin)

let getHtPrXSnsimm bin = TwoOperands(ht bin, memPreXSnSimm bin)

let getStPrXSnsimm bin = TwoOperands(st1 bin, memPreXSnSimm bin)

let getDtPrXSnsimm bin = TwoOperands(dt1 bin, memPreXSnSimm bin)

let getQtPrXSnsimm bin = TwoOperands(qt1 bin, memPreXSnSimm bin)

let getWt1Wt2PrXSnimm bin = ThreeOperands(wt1 bin, wt2 bin, memPreXSnImm bin 2)

let getXt1Xt2PrXSnimm b s = ThreeOperands(xt1 b, xt2 b, memPreXSnImm b s)

let getSt1St2PrXSnimm bin = ThreeOperands(st1 bin, st2 bin, memPreXSnImm bin 2)

let getDt1Dt2PrXSnimm bin = ThreeOperands(dt1 bin, dt2 bin, memPreXSnImm bin 3)

let getQt1Qt2PrXSnimm bin = ThreeOperands(qt1 bin, qt2 bin, memPreXSnImm bin 4)

let getvtntidxPoXSnXm b t n = TwoOperands(vtntidx b t n, memPostRegXSnxm b)

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

let getVt1tPoXSnXm bin r = r bin; TwoOperands(vt1t bin, memPostRegXSnxm bin)

let getVt2tPoXSnXm bin r = r bin; TwoOperands(vt2t bin, memPostRegXSnxm bin)

let getVt3tPoXSnXm bin r = r bin; TwoOperands(vt3t bin, memPostRegXSnxm bin)

let getVt4tPoXSnXm bin r = r bin; TwoOperands(vt4t bin, memPostRegXSnxm bin)

let getvtntidxPoXSnImm b t n =
  TwoOperands(vtntidx b t n, memPostImmXSnimm b (iX t n))

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
  r b; TwoOperands(vt b, memPostImmXSnimm b (immQ b i))

let getVt1tPoXSnImm1 b r = getVttPoXSnImm1 b r vt1t 1L

let getVt2tPoXSnImm1 b r = getVttPoXSnImm1 b r vt2t 2L

let getVt3tPoXSnImm1 b r = getVttPoXSnImm1 b r vt3t 3L

let getVt4tPoXSnImm1 b r = getVttPoXSnImm1 b r vt4t 4L

let getVttPoXSnImm2 b vt i = TwoOperands(vt b, memPostImmXSnimm b (iN b i))

let getVt1tPoXSnImm2 b = getVttPoXSnImm2 b vt1t 1

let getVt2tPoXSnImm2 b = getVttPoXSnImm2 b vt2t 2

let getVt3tPoXSnImm2 b = getVttPoXSnImm2 b vt3t 3

let getVt4tPoXSnImm2 b = getVttPoXSnImm2 b vt4t 4

(* Register - Label *)
let getXdLabel bin amt = TwoOperands(xd bin, label bin amt) (* <xd>, <label> *)

let getWtLabel bin = TwoOperands(wt1 bin, lbImm19 bin) (* <Wt>, <label> *)

let getXtLabel bin = TwoOperands(xt1 bin, lbImm19 bin) (* <Xt>, <label> *)

let getStLabel bin = TwoOperands(st1 bin, lbImm19 bin) (* <St>, <label> *)

let getDtLabel bin = TwoOperands(dt1 bin, lbImm19 bin) (* <Dt>, <label> *)

let getQtLabel bin = TwoOperands(qt1 bin, lbImm19 bin) (* <Qt>, <label> *)

let getPrfopImm5Label bin =
  TwoOperands(prfopImm5 bin, lbImm19 bin) (* <prfop>|#<imm5>), <label> *)

(* etc *)
let getSysregOrctrlXt bin = TwoOperands(systemregOrctrl bin, xt1 bin)

let getXtSysregOrctrl bin = TwoOperands(xt1 bin, systemregOrctrl bin)

let getPstatefieldImm bin = TwoOperands(pstatefield bin, imm bin)

(* Register - Register - Register *)
let getWdWnWm bin = ThreeOperands(wd bin, wn bin, wm bin)

let getWdWnXm bin = ThreeOperands(wd bin, wn bin, xm bin)

let getXdXnXm bin = ThreeOperands(xd bin, xn bin, xm bin)

let getVdtaVntbVmtb b r = r b; ThreeOperands(vdts1 b, vntsq1 b, vmtsq1 b)

let getVdtaVntaVmtb b r = r b; ThreeOperands(vdts1 b, vnts1 b, vmtsq1 b)

let getVdtbVntaVmta b r = r b; ThreeOperands(vdtsq1 b, vnts1 b, vmts1 b)

let getVdtVntVmt1 b r = r b; ThreeOperands(vdtsq1 b, vntsq1 b, vmtsq1 b)

let getVdtVntVmt2 b r = r b; ThreeOperands(vdtszq1 b, vntszq1 b, vmtszq1 b)

let getVdtVntVmt3 bin = ThreeOperands(vdtq1 bin, vntq1 bin, vmtq1 bin)

let getSdSnSm bin = ThreeOperands(sd bin, sn bin, sm bin)

let getDdDnDm bin = ThreeOperands(dd bin, dn bin, dm bin)

let getVdVnVm1 bin r = r bin; ThreeOperands(vd2 bin, vn2 bin, vm2 bin)

let getVdVnVm2 bin = ThreeOperands(vd3a bin, vn3 bin, vm3 bin)

let getVadVbnVbm bin r = r bin; ThreeOperands(vd1 bin, vn2 bin, vm2 bin)

let getQdSnVm4S bin = ThreeOperands(qd bin, sn bin, vm4S bin)

let getVd4SVn4SVm4S bin = ThreeOperands(vd4S bin, vn4S bin, vm4S bin)

let getQdQnVm4S bin = ThreeOperands(qd bin, qn bin, vm4S bin)

let getVdtVntVmt b r = r b; ThreeOperands(vdtsq1 b, vntsq1 b, vmtsq1 b)

let getVdtaVntbVmtsidx b r = r b; ThreeOperands(vdts1 b, vntsq1 b, vmtsidx1 b)

let getVdtVntVmtsidx1 bin r =  (* size:Q - 3bit *)
  r bin; ThreeOperands(vdtsq1 bin, vntsq1 bin, vmtsidx1 bin)

let getVdtVntVmtsidx2 bin r =  (* sz:Q - 2bit *)
  r bin; ThreeOperands(vdtszq1 bin, vntszq1 bin, vmtsidx2 bin)

let getVadVbnVmtsidx b r = r b; ThreeOperands(vd1 b, vn2 b, vmtsidx1 b)

let getVdVnVmtsidx1 b r = r b; ThreeOperands(vd2 b, vn2 b, vmtsidx1 b)

let getVdVnVmtsidx2 b r = r b; ThreeOperands(vd3a b, vn3 b, vmtsidx2 b)

let getVdtaVn116BVmta bin = ThreeOperands(vdtq1 bin, vn116B bin, vmtq1 bin)

let getVdtaVn216BVmta bin = ThreeOperands(vdtq1 bin, vn216B bin, vmtq1 bin)

let getVdtaVn316BVmta bin = ThreeOperands(vdtq1 bin, vn316B bin, vmtq1 bin)

let getVdtaVn416BVmta bin = ThreeOperands(vdtq1 bin, vn416B bin, vmtq1 bin)

(* Register - Register - Immediate *)
let getVdtVntI0 b r = r b; ThreeOperands(vdtsq1 b, vntsq1 b, OprImm 0L)

let getVdtVntF0 b r = r b; ThreeOperands(vdtszq1 b, vntszq1 b, OprFPImm 0.0)

let getWSdWnImm bin = ThreeOperands(wsd bin, wn bin, immNsr bin 32<rt>)

let getWdWnImm bin = ThreeOperands(wd bin, wn bin, immNsr bin 32<rt>)

let getXSdXnImm bin = ThreeOperands(xsd bin, xn bin, immNsr bin 64<rt>)

let getXdXnImm bin = ThreeOperands(xd bin, xn bin, immNsr bin 64<rt>)

let getVdVnI0 bin r = r bin; ThreeOperands(vd2 bin, vn2 bin, OprImm 0L)

let getVdVnF0 bin = ThreeOperands(vd3a bin, vn3 bin, OprFPImm 0.0)

(* Register - Register - Shift *)
let getVdtaVntbShf2 b r = r b; ThreeOperands(vdts1 b, vntsq1 b, lshf1 b)

let getVdVnShf bin r = r bin; ThreeOperands(vd5 bin, vn5 bin, rshfAmt bin)

let getVdVnShf2 bin r = r bin; ThreeOperands(vd5 bin, vn5 bin, lshfAmt bin)

let getVbdVanShf bin r = r bin; ThreeOperands(vd5 bin, vn6 bin, rshfAmt bin)

(* Register - Register - fbits *)
let getHdWnFbits bin = ThreeOperands(hd bin, wn bin, fbits2 bin)

let getSdWnFbits bin = ThreeOperands(sd bin, wn bin, fbits2 bin)

let getWdSnFbits bin = ThreeOperands(wd bin, sn bin, fbits2 bin)

let getDdWnFbits bin = ThreeOperands(dd bin, wn bin, fbits2 bin)

let getWdDnFbits bin = ThreeOperands(wd bin, dn bin, fbits2 bin)

let getHdXnFbits bin = ThreeOperands(hd bin, xn bin, fbits2 bin)

let getSdXnFbits bin = ThreeOperands(sd bin, xn bin, fbits2 bin)

let getXdSnFbits bin = ThreeOperands(xd bin, sn bin, fbits2 bin)

let getDdXnFbits bin = ThreeOperands(dd bin, xn bin, fbits2 bin)

let getXdDnFbits bin = ThreeOperands(xd bin, dn bin, fbits2 bin)

let getVdVnFbits bin r = r bin; ThreeOperands(vd5 bin, vn5 bin, fbits1 bin)

(* Register - Register - Memory *)
let getWsWtMXSn bin = ThreeOperands(ws bin, wt1 bin, memXSn bin)

let getXsXtMXSn bin = ThreeOperands(xs bin, xt1 bin, memXSn bin)

let getWsXtMXSn bin = ThreeOperands(ws bin, xt1 bin, memXSn bin)

let getWt1Wt2MXSn bin = ThreeOperands(wt1 bin, wt2 bin, memXSn bin)

let getXt1Xt2MXSn bin = ThreeOperands(xt1 bin, xt2 bin, memXSn bin)

(* Register - Immediate - Shift *)
let getVdtImm8LAmt bin oprVdt = function
  | Some s -> ThreeOperands(oprVdt bin, imm8 bin, s)
  | None -> TwoOperands(oprVdt bin, imm8 bin)

let getVdtImm8LAmt1 bin = getVdtImm8LAmt bin vdtq1 None (* 8-bit *)

let getVdtImm8LAmt2 bin = getVdtImm8LAmt bin vdtq3 (lAmt bin amt16Imm)

let getVdtImm8LAmt3 bin = getVdtImm8LAmt bin vdtq2 (lAmt bin amt32Imm)

let getVdtImm8MAmt bin = ThreeOperands(vdtq2 bin, imm8 bin, mAmt bin)

let getWdImmLShf bin = ThreeOperands(wd bin, imm16 bin, lshf3 bin)

let getXdImmLShf bin = ThreeOperands(xd bin, imm16 bin, lshf3 bin)

let getVdtVntShf1 bin = ThreeOperands(vdtihq bin, vntihq bin, rshfAmt bin)

let getVdtVntShf2 bin = ThreeOperands(vdtihq bin, vntihq bin, lshfAmt bin)

let getVdtbVntaShf b r = r b; ThreeOperands(vdtihq b, vntih b, rshfAmt b)

let getVdtaVntbShf b r = r b; ThreeOperands(vdtih b, vntihq b, lshfAmt b)

let getVdtVntFbits b r = r b; ThreeOperands(vdtihq b, vntihq b, fbits1 b)

(* Four Operands *)
let getWdWnWmWa bin = FourOperands(wd bin, wn bin, wm bin, wa bin)

let getXdWnWmXa bin = FourOperands(xd bin, wn bin, wm bin, xa bin)

let getXdXnXmXa bin = FourOperands(xd bin, xn bin, xm bin, xa bin)

let getVdtVntVmtIdx b = FourOperands(vdtq1 b, vntq1 b, vmtq1 b, index b)

let getWnWmNzcvCond bin = FourOperands(wn bin, wm bin, nzcv bin, cond bin)

let getXnXmNzcvCond bin = FourOperands(xn bin, xm bin, nzcv bin, cond bin)

let getWnImmNzcvCond bin = FourOperands(wn bin, imm5 bin, nzcv bin, cond bin)

let getXnImmNzcvCond bin = FourOperands(xn bin, imm5 bin, nzcv bin, cond bin)

let getWdWnWmCond bin = FourOperands(wd bin, wn bin, wm bin, cond bin)

let getXdXnXmCond bin = FourOperands(xd bin, xn bin, xm bin, cond bin)

let getSdSnSmSa bin = FourOperands(sd bin, sn bin, sm bin, sa bin)

let getDdDnDmDa bin = FourOperands(dd bin, dn bin, dm bin, da bin)

let getSdSnSmCond bin = FourOperands(sd bin, sn bin, sm bin, cond bin)

let getDdDnDmCond bin = FourOperands(dd bin, dn bin, dm bin, cond bin)

let getWdWnWmShfamt bin = FourOperands(wd bin, wn bin, wm bin, shfamt bin)

let getXdXnXmShfamt bin = FourOperands(xd bin, xn bin, xm bin, shfamt bin)

let getWSdWSnWmExtamt bin = FourOperands(wsd bin, wsn bin, wm bin, extamt bin)

let getXSdXSnRmExtamt bin = FourOperands(xsd bin, xsn bin, rm bin, extamt bin)

let getWdWSnImmShf bin = FourOperands(wd bin, wsn bin, imm12 bin, lshf2 bin)

let getXdXSnImmShf bin = FourOperands(xd bin, xsn bin, imm12 bin, lshf2 bin)

let getWSdWSnImmShf bin = FourOperands(wsd bin, wsn bin, imm12 bin, lshf2 bin)

let getXSdXSnImmShf bin = FourOperands(xsd bin, xsn bin, imm12 bin, lshf2 bin)

let getWdWnImmrImms bin =
  FourOperands(wd bin, wn bin, immr bin 31u, imms bin 31u)

let getXdXnImmrImms bin =
  FourOperands(xd bin, xn bin, immr bin 63u, imms bin 63u)

let getWdWnWmLsb bin = FourOperands(wd bin, wn bin, wm bin, lsb bin 31u)

let getXdXnXmLsb bin = FourOperands(xd bin, xn bin, xm bin, lsb bin 63u)

let getWsWt1Wt2MXSn bin = FourOperands(ws bin, wt1 bin, wt2 bin, memXSn bin)

let getWsXt1Xt2MXSn bin = FourOperands(ws bin, xt1 bin, xt2 bin, memXSn bin)

let getSnSmNZCVCond bin = FourOperands(sn bin, sm bin, nzcv bin, cond bin)

let getDnDmNZCVCond bin = FourOperands(dn bin, dm bin, nzcv bin, cond bin)

let getOp1cncmop2Xt bin =
  FiveOperands(op1 bin, cn bin, cm bin, op2 bin, xt1 bin)

let getXtOp1cncmop2 bin =
  FiveOperands(xt1 bin, op1 bin, cn bin, cm bin, op2 bin)

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
  | VecReg(_, v) -> getOprSizeByVector v
  | VecRegWithIdx(_, v, _) -> getOprSizeByVector v
  | _ -> raise InvalidOperandException

let getFstOperand = function
  | OneOperand o -> o
  | TwoOperands(o1, _) -> o1
  | ThreeOperands(o1, _, _) -> o1
  | FourOperands(o1, _, _, _) -> o1
  | FiveOperands(o1, _, _, _, _) -> o1
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
  | Op.ADD, FourOperands(rd, rn, _, _), oprSize
    when (valShift bin = 0b00u) && isImm12Zero
         && (valD bin = 0b11111u || valN bin = 0b11111u) ->
    Op.MOV, TwoOperands(rd, rn), oprSize
  | Op.ADDS, FourOperands(_, rn, imm, shf), oprSize when valD bin = 0b11111u ->
    Op.CMN, ThreeOperands(rn, imm, shf), oprSize
  | Op.SUBS, FourOperands(_, rn, imm, shf), oprSize
    when valD bin = 0b11111u ->
    Op.CMP, ThreeOperands(rn, imm, shf), oprSize
  | _ -> instr

let parseAddSubImm bin =
  let cond = extract bin 31u 29u (* sf:op:S *)
  match cond with
  | c when c &&& 0b000u = 0b000u && (extract bin 23u 22u >>> 1) = 0b1u ->
    unallocated ()
  | 0b000u -> Op.ADD, getWSdWSnImmShf bin, 32<rt>
  | 0b001u -> Op.ADDS, getWdWSnImmShf bin, 32<rt>
  | 0b010u -> Op.SUB, getWSdWSnImmShf bin, 32<rt>
  | 0b011u -> Op.SUBS, getWdWSnImmShf bin, 32<rt>
  | 0b100u -> Op.ADD, getXSdXSnImmShf bin, 64<rt>
  | 0b101u -> Op.ADDS, getXdXSnImmShf bin, 64<rt>
  | 0b110u -> Op.SUB, getXSdXSnImmShf bin, 64<rt>
  | 0b111u -> Op.SUBS, getXdXSnImmShf bin, 64<rt>
  | _ -> raise InvalidOperandException
  |> changeToAliasOfAddSubImm bin

let changeToAliasOfBitfield bin instr =
  let sf = valMSB bin
  match instr with
  | Op.SBFM, FourOperands(rd, rn, immr, OprImm imms), oprSize
      when (sf = 0u && imms = 0b011111L) || (sf = 1u && imms = 0b111111L) ->
    Op.ASR, ThreeOperands(rd, rn, immr), oprSize
  | Op.SBFM, FourOperands(rd, rn, OprImm immr, OprImm imms), oSz
      when imms < immr ->
    let lsb = (RegType.toBitWidth oSz |> int64) - immr
    Op.SBFIZ, FourOperands(rd, rn, OprImm lsb, OprImm(imms + 1L)), oSz
  | Op.SBFM, FourOperands(rd, rn, OprImm r, OprImm s), oSz
      when bfxPreferred sf 0u (uint32 s) (uint32 r) ->
    Op.SBFX, FourOperands(rd, rn, OprImm r, OprImm(s - r + 1L)), oSz
  | Op.SBFM, FourOperands(rd, _, OprImm immr, OprImm imms), oprSz
      when (immr = 0b000000L) && (imms = 0b000111L) ->
    Op.SXTB,
    TwoOperands(rd, getRegister64 32<rt> (valN bin |> byte) |> OprRegister),
    oprSz
  | Op.SBFM, FourOperands(rd, _, OprImm immr, OprImm imms), oprSz
      when (immr = 0b000000L) && (imms = 0b001111L) ->
    Op.SXTH,
    TwoOperands(rd, getRegister64 32<rt> (valN bin |> byte) |> OprRegister),
    oprSz
  | Op.SBFM, FourOperands(rd, _, OprImm immr, OprImm imms), oprSz
      when (immr = 0b000000L) && (imms = 0b011111L) ->
    Op.SXTW,
    TwoOperands(rd, getRegister64 32<rt> (valN bin |> byte) |> OprRegister),
    oprSz
  | Op.BFM, FourOperands(rd, rn, OprImm immr, OprImm imms), oprSize
      when (valN bin <> 0b11111u) && (imms < immr) ->
    let lsb = (RegType.toBitWidth oprSize |> int64) - immr
    Op.BFI,
    FourOperands(rd, rn, OprImm lsb, OprImm(imms + 1L)), oprSize
  | Op.BFM, FourOperands(d, n, OprImm immr, OprImm imms), oprSize
      when imms >= immr ->
    Op.BFXIL,
    FourOperands(d, n, OprImm immr, OprImm(imms - immr + 1L)), oprSize
  | Op.UBFM, FourOperands(rd, rn, OprImm immr, OprImm imms), oprSize
      when (oprSize = 32<rt>) && (imms <> 0b011111L) && (imms + 1L = immr) ->
    Op.LSL, ThreeOperands(rd, rn, OprImm(31L - imms)), oprSize
  | Op.UBFM, FourOperands(rd, rn, OprImm immr, OprImm imms), oprSize
      when (oprSize = 64<rt>) && (imms <> 0b111111L) && (imms + 1L = immr) ->
    Op.LSL, ThreeOperands(rd, rn, OprImm(63L - imms)), oprSize
  | Op.UBFM, FourOperands(rd, rn, immr, OprImm imms), oprSize
      when (oprSize = 32<rt>) && (imms = 0b011111L) ->
    Op.LSR, ThreeOperands(rd, rn, immr), oprSize
  | Op.UBFM, FourOperands(rd, rn, immr, OprImm imms), oprSize
      when (oprSize = 64<rt>) && (imms = 0b111111L) ->
    Op.LSR, ThreeOperands(rd, rn, immr), oprSize
  | Op.UBFM, FourOperands(rd, rn, OprImm immr, OprImm imms), oprSize
      when imms < immr ->
    let lsb = (RegType.toBitWidth oprSize |> int64) - immr
    Op.UBFIZ, FourOperands(rd, rn, OprImm lsb, OprImm(imms + 1L)),
    oprSize
  | Op.UBFM, FourOperands(rd, rn, OprImm immr, OprImm imms), oprSize
      when bfxPreferred sf 1u (uint32 imms) (uint32 immr) ->
    Op.UBFX,
    FourOperands(rd, rn, OprImm immr, OprImm(imms - immr + 1L)), oprSize
  | Op.UBFM, FourOperands(rd, rn, OprImm immr, OprImm imms), oprSize
      when immr = 0b000000L && imms = 0b000111L ->
    Op.UXTB, TwoOperands(rd, rn), oprSize
  | Op.UBFM, FourOperands(rd, rn, OprImm immr, OprImm imms), oprSize
      when immr = 0b000000L && imms = 0b001111L ->
    Op.UXTH, TwoOperands(rd, rn), oprSize
  | _ -> instr

let parseBitfield bin =
  let cond = concat (extract bin 31u 29u) (pickBit bin 22u) 1 (* sf:opc:N *)
  match cond with
  | c when c &&& 0b0110u = 0b0110u -> unallocated ()
  | c when c &&& 0b1001u = 0b0001u -> unallocated ()
  | 0b0000u -> Op.SBFM, getWdWnImmrImms bin, 32<rt>
  | 0b0010u -> Op.BFM, getWdWnImmrImms bin, 32<rt>
  | 0b0100u -> Op.UBFM, getWdWnImmrImms bin, 32<rt>
  | c when c &&& 0b1001u = 0b1000u -> unallocated ()
  | 0b1001u -> Op.SBFM, getXdXnImmrImms bin, 64<rt>
  | 0b1011u -> Op.BFM, getXdXnImmrImms bin, 64<rt>
  | 0b1101u -> Op.UBFM, getXdXnImmrImms bin, 64<rt>
  | _ -> raise InvalidOperandException
  |> changeToAliasOfBitfield bin

let changeToAliasOfExtract instr =
  match instr with
  | Op.EXTR, FourOperands(rd, rn, rm, lsb), oprSize when rn = rm ->
    Op.ROR, ThreeOperands(rd, rn, lsb), oprSize
  | _ -> instr

let parseExtract bin =
  let cond = concat (concat (extract bin 31u 29u) (extract bin 22u 21u) 2)
                    (extract bin 15u 10u) 6 (* sf:op21:N:o0:imms *)
  match cond with
  | c when c &&& 0b00100000000u = 0b00100000000u -> unallocated ()
  | c when c &&& 0b01101000000u = 0b00001000000u -> unallocated ()
  | c when c &&& 0b01000000000u = 0b01000000000u -> unallocated ()
  | c when c &&& 0b10000100000u = 0b00000100000u -> unallocated ()
  | c when c &&& 0b10010000000u = 0b00010000000u -> unallocated ()
  | c when c &&& 0b11111100000u = 0b00000000000u ->
    Op.EXTR, getWdWnWmLsb bin, 32<rt>
  | c when c &&& 0b11111000000u = 0b10010000000u ->
    Op.EXTR, getXdXnXmLsb bin, 64<rt>
  | c when c &&& 0b10010000000u = 0b10000000000u -> unallocated ()
  | _ -> raise InvalidOperandException
  |> changeToAliasOfExtract

let changeToAliasOfLogical bin instr =
  match instr with
  | Op.ORR, ThreeOperands(rd, _, imm), oprSize
      when valN bin = 0b11111u && (not (moveWidePreferred bin)) ->
    Op.MOV, TwoOperands(rd, imm), oprSize
  | Op.ANDS, ThreeOperands(_, rn, imm), oprSize when valD bin = 0b11111u ->
    Op.TST, TwoOperands(rn, imm), oprSize
  | _ -> instr

let parseLogical bin =
  let cond = concat (extract bin 31u 29u) (pickBit bin 22u) 1 (* sf:opc:N *)
  match cond with
  | c when c &&& 0b1001u = 0b0001u -> unallocated ()
  | 0b0000u -> Op.AND, getWSdWnImm bin, 32<rt>
  | 0b0010u -> Op.ORR, getWSdWnImm bin, 32<rt>
  | 0b0100u -> Op.EOR, getWSdWnImm bin, 32<rt>
  | 0b0110u -> Op.ANDS, getWdWnImm bin, 32<rt>
  | c when c &&& 0b1110u = 0b1000u -> Op.AND, getXSdXnImm bin, 64<rt>
  | c when c &&& 0b1110u = 0b1010u -> Op.ORR, getXSdXnImm bin, 64<rt>
  | c when c &&& 0b1110u = 0b1100u -> Op.EOR, getXSdXnImm bin, 64<rt>
  | c when c &&& 0b1110u = 0b1110u -> Op.ANDS, getXdXnImm bin, 64<rt>
  | _ -> raise InvalidOperandException
  |> changeToAliasOfLogical bin

let changeToAliasOfMoveWide bin instr =
  let is64Bit = valMSB bin = 1u
  let hw = extract bin 22u 21u
  match instr with
  (* C6.2.122 MOV (inverted wide immediate) *)
  | Op.MOVN, ThreeOperands(xd, OprImm imm16, OprShift(_, Imm amt)), oprSz
      when is64Bit && not (0b0L = imm16 && hw <> 0b00u) ->
    let imm = ~~~ (imm16 <<< int32 amt)
    Op.MOV, TwoOperands(xd, OprImm imm), oprSz
  | Op.MOVN, ThreeOperands(wd, OprImm imm16, OprShift(_, Imm amt)), oprSz
      when not is64Bit && not (0b0L = imm16 && hw <> 0b00u)
           && (0b1111111111111111L <> imm16) ->
    let imm = ~~~ (uint32 (imm16 <<< int32 amt)) |> int64
    Op.MOV, TwoOperands(wd, OprImm imm), oprSz
  (* C6.2.123 MOV (wide immediate) *)
  | Op.MOVZ, ThreeOperands(rd, OprImm imm16, OprShift(_, Imm amt)), oprSz
    when not (imm16 = 0b0L && hw <> 0b00u) ->
    Op.MOV, TwoOperands(rd, OprImm(imm16 <<< (int32 amt))), oprSz
  | _ -> instr

let parseMoveWide bin =
  let cond = concat (extract bin 31u 29u) (extract bin 22u 21u) 2
  match cond with (* sf:opc:hw *)
  | c when c &&& 0b01100u = 0b00100u -> unallocated ()
  | c when c &&& 0b10010u = 0b00010u -> unallocated ()
  | c when c &&& 0b11100u = 0b00000u -> Op.MOVN, getWdImmLShf bin, 32<rt>
  | c when c &&& 0b11100u = 0b01000u -> Op.MOVZ, getWdImmLShf bin, 32<rt>
  | c when c &&& 0b11100u = 0b01100u -> Op.MOVK, getWdImmLShf bin, 32<rt>
  | c when c &&& 0b11100u = 0b10000u -> Op.MOVN, getXdImmLShf bin, 64<rt>
  | c when c &&& 0b11100u = 0b11000u -> Op.MOVZ, getXdImmLShf bin, 64<rt>
  | c when c &&& 0b11100u = 0b11100u -> Op.MOVK, getXdImmLShf bin, 64<rt>
  | _ -> raise InvalidOperandException
  |> changeToAliasOfMoveWide bin

let parsePCRel bin =
  if (pickBit bin 31u) = 0u then Op.ADR, getXdLabel bin 0, 64<rt>
  else Op.ADRP, getXdLabel bin 12, 64<rt>

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
  | 0b00u -> Op.CBZ, getWtLabel bin, 32<rt>
  | 0b01u -> Op.CBNZ, getWtLabel bin, 32<rt>
  | 0b10u -> Op.CBZ, getXtLabel bin, 64<rt>
  | 0b11u -> Op.CBNZ, getXtLabel bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let parseCondBranchImm bin =
  let cond = concat (pickBit bin 24u) (pickBit bin 4u) 1 (* o1:o0 *)
  let opCode =
    match cond with
    | 0b00u -> getConditionOpcode (extract bin 3u 0u |> byte)
    | 0b01u -> unallocated ()
    | 0b10u | 0b11u -> unallocated ()
    | _ -> raise InvalidOpcodeException
  let offs = memLabel (signExtend 21 64 (valImm19 bin <<< 2 |> uint64) |> int64)
  opCode, OneOperand offs, 64<rt>

/// Exception generation on page C4-272.
let parseExcepGen bin =
  let cond = concat (extract bin 23u 21u) (extract bin 4u 0u) 5
  let opCode =
    match cond with (* opc:op2:LL *)
    | c when c &&& 0b00000100u = 0b00000100u -> unallocated ()
    | c when c &&& 0b00001000u = 0b00001000u -> unallocated ()
    | c when c &&& 0b00010000u = 0b00010000u -> unallocated ()
    | 0b00000000u -> unallocated ()
    | 0b00000001u -> Op.SVC
    | 0b00000010u -> Op.HVC
    | 0b00000011u -> Op.SMC
    | c when c &&& 0b11111101u = 0b00100001u -> unallocated ()
    | 0b00100000u -> Op.BRK
    | c when c &&& 0b11111110u = 0b00100010u -> unallocated ()
    | c when c &&& 0b11111101u = 0b01000001u -> unallocated ()
    | 0b01000000u -> Op.HLT
    | c when c &&& 0b11111110u = 0b01000010u -> unallocated ()
    | c when c &&& 0b11111100u = 0b01100000u -> unallocated ()
    | c when c &&& 0b11111100u = 0b10000000u -> unallocated ()
    | 0b10100000u -> unallocated ()
    | 0b10100001u -> Op.DCPS1
    | 0b10100010u -> Op.DCPS2
    | 0b10100011u -> Op.DCPS3
    | c when c &&& 0b11011100u = 0b11000000u -> unallocated ()
    | _ -> raise InvalidOpcodeException
  opCode, OneOperand(OprImm(valImm16 bin |> int64)), 16<rt>

let getISBOprs = function
  | 0b1111L -> OneOperand(OprOption SY)
  | imm -> OneOperand(OprImm imm)

let private getDCInstruction bin =
  match extract bin 18u 5u with
  | 0b01101110100001u -> Op.DCZVA
  | 0b00001110110001u -> Op.DCIVAC
  | 0b00001110110010u -> Op.DCISW
  | 0b01101111010001u -> Op.DCCVAC
  | 0b00001111010010u -> Op.DCCSW
  | 0b01101111011001u -> Op.DCCVAU
  | 0b01101111110001u -> Op.DCCIVAC
  | 0b00001111110010u -> Op.DCCISW
  (* C5.3 A64 system instructions for cache maintenance *)
  | _ -> raise InvalidOpcodeException

let changeToAliasOfSystem bin instr =
  match instr with
  | Op.SYS, FiveOperands(_, OprRegister cn, _, _, xt), oSz
      when cn = R.C7 && sysOp bin = SysDC ->
    getDCInstruction bin, OneOperand xt, oSz
  | _ -> instr

let parseSystem bin =
  let cond = concat (extract bin 21u 12u) (extract bin 7u 5u) 3
  let rt = extract bin 4u 0u
  let isRt1F = rt = 0b11111u
  let crm = extract bin 11u 8u |> int64
  let isCRmZero = crm = 0b00000L
  match cond with (* L:op0:op1:CRn:CRm:op2 *)
  | c when c &&& 0b1110001110000u = 0b0000000000000u -> unallocated ()
  | c when c &&& 0b1110001111000u = 0b0000000100000u && not isRt1F ->
    unallocated ()
  | c when c &&& 0b1110001111000u = 0b0000000100000u && isRt1F ->
    Op.MSR, getPstatefieldImm bin, 0<rt>
  | c when c &&& 0b1110001111000u = 0b0000000101000u -> unallocated ()
  | c when c &&& 0b1110001110000u = 0b0000000110000u -> unallocated ()
  | c when c &&& 0b1110001000000u = 0b0000001000000u -> unallocated ()
  | c when c &&& 0b1110011110000u = 0b0000000010000u -> unallocated ()
  | c when c &&& 0b1110101110000u = 0b0000000010000u -> unallocated ()
  | c when c &&& 0b1111111110000u = 0b0000110010000u && not isRt1F ->
    unallocated ()
  | c when c &&& 0b1111111111000u = 0b0000110010000u &&
           not isCRmZero && isRt1F ->
    let imm = concat (uint32 crm) (extract bin 7u 5u) 3 |> int64
    Op.HINT, OneOperand(OprImm imm), 0<rt> (* Hints 8 to 127 variant *)
  | 0b0000110010000u when isCRmZero && isRt1F -> Op.NOP, NoOperand, 0<rt>
  | 0b0000110010001u when isCRmZero && isRt1F -> Op.YIELD, NoOperand, 0<rt>
  | 0b0000110010010u when isCRmZero && isRt1F -> Op.WFE, NoOperand, 0<rt>
  | 0b0000110010011u when isCRmZero && isRt1F -> Op.WFI, NoOperand, 0<rt>
  | 0b0000110010100u when isCRmZero && isRt1F -> Op.SEV, NoOperand, 0<rt>
  | 0b0000110010101u when isCRmZero && isRt1F -> Op.SEVL, NoOperand, 0<rt>
  | c when c &&& 0b1111111111110u = 0b0000110010110u && isCRmZero && isRt1F ->
    let imm = concat (uint32 crm) (extract bin 7u 5u) 3 |> int64
    Op.HINT, OneOperand(OprImm imm), 0<rt> (* Hints 6 and 7 variant *)
  | 0b0000110011000u -> unallocated ()
  | 0b0000110011001u -> unallocated ()
  | 0b0000110011010u when isRt1F ->
    Op.CLREX, OneOperand(OprImm crm), 0<rt>
  | 0b0000110011011u -> unallocated ()
  | 0b0000110011100u when isRt1F -> Op.DSB, getOptionOrimm bin, 0<rt>
  | 0b0000110011101u when isRt1F -> Op.DMB, getOptionOrimm bin, 0<rt>
  | 0b0000110011110u when isRt1F -> Op.ISB, getISBOprs crm, 0<rt>
  | 0b0000110011111u -> unallocated ()
  | c when c &&& 0b1111001110000u = 0b0001000010000u -> unallocated ()
  | c when c &&& 0b1110000000000u = 0b0010000000000u ->
    Op.SYS, getOp1cncmop2Xt bin, 0<rt>
  | c when c &&& 0b1100000000000u = 0b0100000000000u ->
    Op.MSR, getSysregOrctrlXt bin, 0<rt>
  | c when c &&& 0b1110000000000u = 0b1010000000000u ->
    Op.SYSL, getXtOp1cncmop2 bin, 0<rt>
  | c when c &&& 0b1000000000000u = 0b1000000000000u ->
    Op.MRS, getXtSysregOrctrl bin, 0<rt>
  | _ -> raise InvalidOperandException
  |> changeToAliasOfSystem bin

let parseTestBranchImm bin =
  let opCode = if (pickBit bin 24u) = 0u then Op.TBZ else Op.TBNZ
  let b5 = pickBit bin 31u
  let oprSize = getOprSizeByMSB b5
  let rt = getRegister64 oprSize (extract bin 4u 0u |> byte)
  let imm = concat b5 (extract bin 23u 19u) 5 |> int64
  let label =
    memLabel (extract bin 18u 5u <<< 2 |> uint64 |> signExtend 16 64 |> int64)
  opCode, ThreeOperands(OprRegister rt, OprImm imm, label), oprSize

let parseUncondBranchImm bin =
  let opCode = if (pickBit bin 31u) = 0u then Op.B else Op.BL
  let offset = signExtend 28 64 (extract bin 25u 0u <<< 2 |> uint64) |> int64
  opCode, OneOperand(memLabel offset), 64<rt>

let parseUncondBranchReg bin =
  let opc = extract bin 24u 21u
  let isOp21F = extract bin 20u 16u = 0b11111u
  let isOp3Zero = extract bin 15u 10u = 0b000000u
  let rn = extract bin 9u 5u
  let isRn1F = rn = 0b11111u
  let isOp4Zero = extract bin 4u 0u = 0b00000u
  if not isOp4Zero || not isOp3Zero || not isOp21F then unallocated ()
  match opc with
  | 0b0000u when isOp21F && isOp3Zero && isOp4Zero ->
    Op.BR,
    OneOperand(OprRegister <| getRegister64 64<rt> (byte rn)), 64<rt>
  | 0b0001u when isOp21F && isOp3Zero && isOp4Zero ->
    Op.BLR,
    OneOperand(OprRegister <| getRegister64 64<rt> (byte rn)),
    64<rt>
  | 0b0010u when isOp21F && isOp3Zero && isOp4Zero ->
    Op.RET,
    OneOperand(OprRegister <| getRegister64 64<rt> (byte rn)),
    64<rt>
  | 0b0011u -> unallocated ()
  | o when o &&& 1110u = 0100u && not isRn1F -> unallocated ()
  | 0b0100u when isOp21F && isOp3Zero && isRn1F && isOp4Zero ->
    Op.ERET, NoOperand, 0<rt>
  | 0b0101u when isOp21F && isOp3Zero && isRn1F && isOp4Zero ->
    Op.DRPS, NoOperand, 0<rt>
  | o when o &&& 1110u = 0110u -> unallocated ()
  | o when o &&& 1000u = 1000u -> unallocated ()
  | _ -> raise InvalidOpcodeException

/// Branches, exception generating and system instructions
let parse64Group2 bin =
  let op0 = extract bin 31u 29u
  let op1 = extract bin 25u 22u
  let ops = concat op0 op1 4
  match ops with
  | ops when ops &&& 0b1111000u = 0b0100000u -> parseCondBranchImm bin
  | ops when ops &&& 0b1111000u = 0b0101000u -> unallocated ()
  | ops when ops &&& 0b1111100u = 0b1100000u -> parseExcepGen bin
  | ops when ops &&& 0b1111111u = 0b1100100u -> parseSystem bin
  | ops when ops &&& 0b1111111u = 0b1100101u -> unallocated ()
  | ops when ops &&& 0b1111110u = 0b1100110u -> unallocated ()
  | ops when ops &&& 0b1111000u = 0b1101000u -> parseUncondBranchReg bin
  | ops when ops &&& 0b0110000u = 0b0000000u -> parseUncondBranchImm bin
  | ops when ops &&& 0b0111000u = 0b0010000u -> parseCompareAndBranchImm bin
  | ops when ops &&& 0b0111000u = 0b0011000u -> parseTestBranchImm bin
  | ops when ops &&& 0b0110000u = 0b0110000u -> unallocated ()
  | _ -> raise InvalidOpcodeException

/// Advanced SIMD load/store multiple structures on page C4-281.
let parseAdvSIMDMul bin =
  let cond = concat (pickBit bin 22u) (extract bin 15u 12u) 4 (* L:opcode *)
  let oprSize = getOprSizeByQ bin
  match cond with
  | 0b00000u -> Op.ST4, getVt4tMXSn bin sizeQ110b, oprSize
  | 0b00001u -> unallocated ()
  | 0b00010u -> Op.ST1, getVt4tMXSn bin resNone, oprSize
  | 0b00011u -> unallocated ()
  | 0b00100u -> Op.ST3, getVt3tMXSn bin sizeQ110b, oprSize
  | 0b00101u -> unallocated ()
  | 0b00110u -> Op.ST1, getVt3tMXSn bin resNone, oprSize
  | 0b00111u -> Op.ST1, getVt1tMXSn bin resNone, oprSize
  | 0b01000u -> Op.ST2, getVt2tMXSn bin sizeQ110b, oprSize
  | 0b01001u -> unallocated ()
  | 0b01010u -> Op.ST1, getVt2tMXSn bin resNone, oprSize
  | 0b01011u -> unallocated ()
  | c when c &&& 0b11100u = 0b01100u -> unallocated ()
  | 0b10000u -> Op.LD4, getVt4tMXSn bin sizeQ110b, oprSize
  | 0b10001u -> unallocated ()
  | 0b10010u -> Op.LD1, getVt4tMXSn bin resNone, oprSize
  | 0b10011u -> unallocated ()
  | 0b10100u -> Op.LD3, getVt3tMXSn bin sizeQ110b, oprSize
  | 0b10101u -> unallocated ()
  | 0b10110u -> Op.LD1, getVt3tMXSn bin resNone, oprSize
  | 0b10111u -> Op.LD1, getVt1tMXSn bin resNone, oprSize
  | 0b11000u -> Op.LD2, getVt2tMXSn bin sizeQ110b, oprSize
  | 0b11001u -> unallocated ()
  | 0b11010u -> Op.LD1, getVt2tMXSn bin resNone, oprSize
  | 0b11011u -> unallocated ()
  | c when c &&& 0b11100u = 0b11100u -> unallocated ()
  | _ -> raise InvalidOpcodeException

/// Advanced SIMD load/store multiple structures (post-indexed) on page C4-282.
let parseAdvSIMDMulPostIndexed bin =
  let cond = concat (pickBit bin 22u) (extract bin 15u 12u) 4 (* L:opcode *)
  let isRm11111 = (extract bin 20u 16u) = 0b11111u
  let oSz = getOprSizeByQ bin
  match cond with
  | 0b00001u -> unallocated ()
  | 0b00011u -> unallocated ()
  | 0b00101u -> unallocated ()
  | 0b01001u -> unallocated ()
  | 0b01011u -> unallocated ()
  | c when c &&& 0b11100u = 0b01100u -> unallocated ()
  | 0b00000u when not isRm11111 ->
    Op.ST4, getVt4tPoXSnXm bin sizeQ110b, oSz
  | 0b00010u when not isRm11111 -> Op.ST1, getVt4tPoXSnXm bin resNone, oSz
  | 0b00100u when not isRm11111 -> Op.ST3, getVt3tPoXSnXm bin sizeQ110b, oSz
  | 0b00110u when not isRm11111 -> Op.ST1, getVt3tPoXSnXm bin resNone, oSz
  | 0b00111u when not isRm11111 -> Op.ST1, getVt1tPoXSnXm bin resNone, oSz
  | 0b01000u when not isRm11111 -> Op.ST2, getVt2tPoXSnXm bin sizeQ110b, oSz
  | 0b01010u when not isRm11111 -> Op.ST1, getVt2tPoXSnXm bin resNone, oSz
  | 0b00000u when isRm11111 -> Op.ST4, getVt4tPoXSnImm1 bin sizeQ110b, oSz
  | 0b00010u when isRm11111 -> Op.ST1, getVt4tPoXSnImm1 bin resNone, oSz
  | 0b00100u when isRm11111 -> Op.ST3, getVt3tPoXSnImm1 bin sizeQ110b, oSz
  | 0b00110u when isRm11111 -> Op.ST1, getVt3tPoXSnImm1 bin resNone, oSz
  | 0b00111u when isRm11111 -> Op.ST1, getVt1tPoXSnImm1 bin resNone, oSz
  | 0b01000u when isRm11111 -> Op.ST2, getVt2tPoXSnImm1 bin sizeQ110b, oSz
  | 0b01010u when isRm11111 -> Op.ST1, getVt2tPoXSnImm1 bin resNone, oSz
  | 0b10001u -> unallocated ()
  | 0b10011u -> unallocated ()
  | 0b10101u -> unallocated ()
  | 0b11001u -> unallocated ()
  | 0b11011u -> unallocated ()
  | c when c &&& 0b11100u = 0b11100u -> unallocated ()
  | 0b10000u when not isRm11111 -> Op.LD4, getVt4tPoXSnXm bin sizeQ110b, oSz
  | 0b10010u when not isRm11111 -> Op.LD1, getVt4tPoXSnXm bin resNone, oSz
  | 0b10100u when not isRm11111 -> Op.LD3, getVt3tPoXSnXm bin sizeQ110b, oSz
  | 0b10110u when not isRm11111 -> Op.LD1, getVt3tPoXSnXm bin resNone, oSz
  | 0b10111u when not isRm11111 -> Op.LD1, getVt1tPoXSnXm bin resNone, oSz
  | 0b11000u when not isRm11111 -> Op.LD2, getVt2tPoXSnXm bin sizeQ110b, oSz
  | 0b11010u when not isRm11111 -> Op.LD1, getVt2tPoXSnXm bin resNone, oSz
  | 0b10000u when isRm11111 -> Op.LD4, getVt4tPoXSnImm1 bin sizeQ110b, oSz
  | 0b10010u when isRm11111 -> Op.LD1, getVt4tPoXSnImm1 bin resNone, oSz
  | 0b10100u when isRm11111 -> Op.LD3, getVt3tPoXSnImm1 bin sizeQ110b, oSz
  | 0b10110u when isRm11111 -> Op.LD1, getVt3tPoXSnImm1 bin resNone, oSz
  | 0b10111u when isRm11111 -> Op.LD1, getVt1tPoXSnImm1 bin resNone, oSz
  | 0b11000u when isRm11111 -> Op.LD2, getVt2tPoXSnImm1 bin sizeQ110b, oSz
  | 0b11010u when isRm11111 -> Op.LD1, getVt2tPoXSnImm1 bin resNone, oSz
  | _ -> raise InvalidOpcodeException

/// Advanced SIMD load/store single structure on page C4-283.
let parseAdvSIMDSingle bin =
  let cond = concat (extract bin 22u 21u) (extract bin 15u 10u) 6
  let oprSize = getOprSizeByQ bin
  match cond with (* L:R:opcode:S:size *)
  | c when c &&& 0b10110000u = 0b00110000u -> unallocated ()
  | c when c &&& 0b11111000u = 0b00000000u ->
    Op.ST1, getVt1BidxMXSn bin, oprSize
  | c when c &&& 0b11111000u = 0b00001000u ->
    Op.ST3, getVt3BidxMXSn bin, oprSize
  | c when c &&& 0b11111001u = 0b00010000u ->
    Op.ST1, getVt1HidxMXSn bin, oprSize
  | c when c &&& 0b11111001u = 0b00010001u -> unallocated ()
  | c when c &&& 0b11111001u = 0b00011000u ->
    Op.ST3, getVt3HidxMXSn bin, oprSize
  | c when c &&& 0b11111001u = 0b00011001u -> unallocated ()
  | c when c &&& 0b11111011u = 0b00100000u ->
    Op.ST1, getVt1SidxMXSn bin, oprSize
  | c when c &&& 0b11111010u = 0b00100010u -> unallocated ()
  | 0b00100001u -> Op.ST1, getVt1DidxMXSn bin, oprSize
  | 0b00100101u -> unallocated ()
  | c when c &&& 0b11111011u = 0b00101000u ->
    Op.ST3, getVt3SidxMXSn bin, oprSize
  | c when c &&& 0b11111011u = 0b00101010u -> unallocated ()
  | 0b00101001u -> Op.ST3, getVt3DidxMXSn bin, oprSize
  | 0b00101011u -> unallocated ()
  | c when c &&& 0b11111101u = 0b00101101u -> unallocated ()
  | c when c &&& 0b11111000u = 0b01000000u ->
    Op.ST2, getVt2BidxMXSn bin, oprSize
  | c when c &&& 0b11111000u = 0b01001000u ->
    Op.ST4, getVt4BidxMXSn bin, oprSize
  | c when c &&& 0b11111001u = 0b01010000u ->
    Op.ST2, getVt2HidxMXSn bin, oprSize
  | c when c &&& 0b11111001u = 0b01010001u -> unallocated ()
  | c when c &&& 0b11111001u = 0b01011000u ->
    Op.ST4, getVt4HidxMXSn bin, oprSize
  | c when c &&& 0b11111001u = 0b01011001u -> unallocated ()
  | c when c &&& 0b11111011u = 0b01100000u ->
    Op.ST2, getVt2SidxMXSn bin, oprSize
  | c when c &&& 0b11111011u = 0b01100010u -> unallocated ()
  | 0b01100001u -> Op.ST2, getVt2DidxMXSn bin, oprSize
  | 0b01100011u -> unallocated ()
  | c when c &&& 0b11111101u = 0b01100101u -> unallocated ()
  | c when c &&& 0b11111011u = 0b01101000u ->
    Op.ST4, getVt4SidxMXSn bin, oprSize
  | c when c &&& 0b11111011u = 0b01101010u -> unallocated ()
  | 0b01101001u -> Op.ST4, getVt4DidxMXSn bin, oprSize
  | 0b01101011u -> unallocated ()
  | c when c &&& 0b11111101u = 0b01101101u -> unallocated ()
  | c when c &&& 0b11111000u = 0b10000000u ->
    Op.LD1, getVt1BidxMXSn bin, oprSize
  | c when c &&& 0b11111000u = 0b10001000u ->
    Op.LD3, getVt3BidxMXSn bin, oprSize
  | c when c &&& 0b11111001u = 0b10010000u ->
    Op.LD1, getVt1HidxMXSn bin, oprSize
  | c when c &&& 0b11111001u = 0b10010001u -> unallocated ()
  | c when c &&& 0b11111001u = 0b10011000u ->
    Op.LD3, getVt3HidxMXSn bin, oprSize
  | c when c &&& 0b11111001u = 0b10011001u -> unallocated ()
  | c when c &&& 0b11111011u = 0b10100000u ->
    Op.LD1, getVt1SidxMXSn bin, oprSize
  | c when c &&& 0b11111010u = 0b10100010u -> unallocated ()
  | 0b10100001u -> Op.LD1, getVt1DidxMXSn bin, oprSize
  | 0b10100101u -> unallocated ()
  | c when c &&& 0b11111011u = 0b10101000u ->
    Op.LD3, getVt3SidxMXSn bin, oprSize
  | c when c &&& 0b11111011u = 0b10101010u -> unallocated ()
  | 0b10101001u -> Op.LD3, getVt3DidxMXSn bin, oprSize
  | 0b10101011u -> unallocated ()
  | c when c &&& 0b11111101u = 0b10101101u -> unallocated ()
  | c when c &&& 0b11111100u = 0b10110000u ->
    Op.LD1R, getVt1tMXSn bin resNone, oprSize
  | c when c &&& 0b11111100u = 0b10110100u -> unallocated ()
  | c when c &&& 0b11111100u = 0b10111000u ->
    Op.LD3R, getVt3tMXSn bin resNone, oprSize
  | c when c &&& 0b11111100u = 0b10111100u -> unallocated ()
  | c when c &&& 0b11111000u = 0b11000000u ->
    Op.LD2, getVt2BidxMXSn bin, oprSize
  | c when c &&& 0b11111000u = 0b11001000u ->
    Op.LD4, getVt4BidxMXSn bin, oprSize
  | c when c &&& 0b11111001u = 0b11010000u ->
    Op.LD2, getVt2HidxMXSn bin, oprSize
  | c when c &&& 0b11111001u = 0b11010001u -> unallocated ()
  | c when c &&& 0b11111001u = 0b11011000u ->
    Op.LD4, getVt4HidxMXSn bin, oprSize
  | c when c &&& 0b11111001u = 0b11011001u -> unallocated ()
  | c when c &&& 0b11111011u = 0b11100000u ->
    Op.LD2, getVt2SidxMXSn bin, oprSize
  | c when c &&& 0b11111011u = 0b11100010u -> unallocated ()
  | 0b11100001u -> Op.LD2, getVt2DidxMXSn bin, oprSize
  | 0b11100011u -> unallocated ()
  | c when c &&& 0b11111101u = 0b11100101u -> unallocated ()
  | c when c &&& 0b11111011u = 0b11101000u ->
    Op.LD4, getVt4SidxMXSn bin, oprSize
  | c when c &&& 0b11111011u = 0b11101010u -> unallocated ()
  | 0b11101001u -> Op.LD4, getVt4DidxMXSn bin, oprSize
  | 0b11101011u -> unallocated ()
  | c when c &&& 0b11111101u = 0b11101101u -> unallocated ()
  | c when c &&& 0b11111100u = 0b11110000u ->
    Op.LD2R, getVt2tMXSn bin resNone, oprSize
  | c when c &&& 0b11111100u = 0b11110100u -> unallocated ()
  | c when c &&& 0b11111100u = 0b11111000u ->
    Op.LD4R, getVt4tMXSn bin resNone, oprSize
  | c when c &&& 0b11111100u = 0b11111100u -> unallocated ()
  | _ -> raise InvalidOpcodeException

/// Advanced SIMD load/store single structure (post-indexed) on page C4-286.
let parseAdvSIMDSinglePostIndexed bin =
  let cond = concat (extract bin 22u 21u) (extract bin 15u 10u) 6
  let isRm11111 = (extract bin 20u 16u) = 0b11111u
  let oprSize = getOprSizeByQ bin
  match cond with (* L:R:opcode:S:size *)
  | c when c &&& 0b10110000u = 0b00110000u -> unallocated ()
  | c when c &&& 0b11111001u = 0b00010001u -> unallocated ()
  | c when c &&& 0b11111001u = 0b00011001u -> unallocated ()
  | c when c &&& 0b11111010u = 0b00100010u -> unallocated ()
  | c when c &&& 0b11111111u = 0b00100101u -> unallocated ()
  | c when c &&& 0b11111011u = 0b00101010u -> unallocated ()
  | c when c &&& 0b11111111u = 0b00101011u -> unallocated ()
  | c when c &&& 0b11111101u = 0b00101101u -> unallocated ()
  | c when c &&& 0b11111000u = 0b00000000u && not isRm11111 ->
    Op.ST1, getVt1BidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111000u = 0b00001000u && not isRm11111 ->
    Op.ST3, getVt3BidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111001u = 0b00010000u && not isRm11111 ->
    Op.ST1, getVt1HidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111001u = 0b00011000u && not isRm11111 ->
    Op.ST3, getVt3HidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111011u = 0b00100000u && not isRm11111 ->
    Op.ST1, getVt1SidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111111u = 0b00100001u && not isRm11111 ->
    Op.ST1, getVt1DidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111011u = 0b00101000u && not isRm11111 ->
    Op.ST3, getVt3SidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111111u = 0b00101001u && not isRm11111 ->
    Op.ST3, getVt3DidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111000u = 0b00000000u && isRm11111 ->
    Op.ST1, getVt1BidxPoXSnI1 bin, oprSize
  | c when c &&& 0b11111000u = 0b00001000u && isRm11111 ->
    Op.ST3, getVt3BidxPoXSnI3 bin, oprSize
  | c when c &&& 0b11111001u = 0b00010000u && isRm11111 ->
    Op.ST1, getVt1HidxPoXSnI2 bin, oprSize
  | c when c &&& 0b11111001u = 0b00011000u && isRm11111 ->
    Op.ST3, getVt3HidxPoXSnI6 bin, oprSize
  | c when c &&& 0b11111011u = 0b00100000u && isRm11111 ->
    Op.ST1, getVt1SidxPoXSnI4 bin, oprSize
  | c when c &&& 0b11111111u = 0b00100001u && isRm11111 ->
    Op.ST1, getVt1DidxPoXSnI8 bin, oprSize
  | c when c &&& 0b11111011u = 0b00101000u && isRm11111 ->
    Op.ST3, getVt3SidxPoXSnI12 bin, oprSize
  | c when c &&& 0b11111111u = 0b00101001u && isRm11111 ->
    Op.ST3, getVt3DidxPoXSnI24 bin, oprSize
  | c when c &&& 0b11111001u = 0b01010001u -> unallocated ()
  | c when c &&& 0b11111001u = 0b01011001u -> unallocated ()
  | c when c &&& 0b11111011u = 0b01100010u -> unallocated ()
  | c when c &&& 0b11111111u = 0b01100011u -> unallocated ()
  | c when c &&& 0b11111101u = 0b01100101u -> unallocated ()
  | c when c &&& 0b11111011u = 0b01101010u -> unallocated ()
  | c when c &&& 0b11111111u = 0b01101011u -> unallocated ()
  | c when c &&& 0b11111101u = 0b01101101u -> unallocated ()
  | c when c &&& 0b11111000u = 0b01000000u && not isRm11111 ->
    Op.ST2, getVt2BidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111000u = 0b01001000u && not isRm11111 ->
    Op.ST4, getVt4BidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111001u = 0b01010000u && not isRm11111 ->
    Op.ST2, getVt2HidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111001u = 0b01011000u && not isRm11111 ->
    Op.ST4, getVt4HidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111011u = 0b01100000u && not isRm11111 ->
    Op.ST2, getVt2SidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111111u = 0b01100001u && not isRm11111 ->
    Op.ST2, getVt2DidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111011u = 0b01101000u && not isRm11111 ->
    Op.ST4, getVt4SidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111111u = 0b01101001u && not isRm11111 ->
    Op.ST4, getVt4DidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111000u = 0b01000000u && isRm11111 ->
    Op.ST2, getVt2BidxPoXSnI2 bin, oprSize
  | c when c &&& 0b11111000u = 0b01001000u && isRm11111 ->
    Op.ST4, getVt4BidxPoXSnI4 bin, oprSize
  | c when c &&& 0b11111001u = 0b01010000u && isRm11111 ->
    Op.ST2, getVt2HidxPoXSnI4 bin, oprSize
  | c when c &&& 0b11111001u = 0b01011000u && isRm11111 ->
    Op.ST4, getVt4HidxPoXSnI8 bin, oprSize
  | c when c &&& 0b11111011u = 0b01100000u && isRm11111 ->
    Op.ST2, getVt2SidxPoXSnI8 bin, oprSize
  | c when c &&& 0b11111111u = 0b01100001u && isRm11111 ->
    Op.ST2, getVt2DidxPoXSnI16 bin, oprSize
  | c when c &&& 0b11111011u = 0b01101000u && isRm11111 ->
    Op.ST4, getVt4SidxPoXSnI16 bin, oprSize
  | c when c &&& 0b11111111u = 0b01101001u && isRm11111 ->
    Op.ST4, getVt4DidxPoXSnI32 bin, oprSize
  | c when c &&& 0b11111001u = 0b10010001u -> unallocated ()
  | c when c &&& 0b11111001u = 0b10011001u -> unallocated ()
  | c when c &&& 0b11111010u = 0b10100010u -> unallocated ()
  | c when c &&& 0b11111111u = 0b10100101u -> unallocated ()
  | c when c &&& 0b11111011u = 0b10101010u -> unallocated ()
  | c when c &&& 0b11111111u = 0b10101011u -> unallocated ()
  | c when c &&& 0b11111101u = 0b10101101u -> unallocated ()
  | c when c &&& 0b11111100u = 0b10110100u -> unallocated ()
  | c when c &&& 0b11111100u = 0b10111100u -> unallocated ()
  | c when c &&& 0b11111000u = 0b10000000u && not isRm11111 ->
    Op.LD1, getVt1BidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111000u = 0b10001000u && not isRm11111 ->
    Op.LD3, getVt3BidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111001u = 0b10010000u && not isRm11111 ->
    Op.LD1, getVt1HidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111001u = 0b10011000u && not isRm11111 ->
    Op.LD3, getVt3HidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111011u = 0b10100000u && not isRm11111 ->
    Op.LD1, getVt1SidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111111u = 0b10100001u && not isRm11111 ->
    Op.LD1, getVt1DidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111011u = 0b10101000u && not isRm11111 ->
    Op.LD3, getVt3SidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111111u = 0b10101001u && not isRm11111 ->
    Op.LD3, getVt3DidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111100u = 0b10110000u && not isRm11111 ->
    Op.LD1R, getVt1tPoXSnXm bin resNone, oprSize
  | c when c &&& 0b11111100u = 0b10111000u && not isRm11111 ->
    Op.LD3R, getVt3tPoXSnXm bin resNone, oprSize
  | c when c &&& 0b11111000u = 0b10000000u && isRm11111 ->
    Op.LD1, getVt1BidxPoXSnI1 bin, oprSize
  | c when c &&& 0b11111000u = 0b10001000u && isRm11111 ->
    Op.LD3, getVt3BidxPoXSnI3 bin, oprSize
  | c when c &&& 0b11111001u = 0b10010000u && isRm11111 ->
    Op.LD1, getVt1HidxPoXSnI2 bin, oprSize
  | c when c &&& 0b11111001u = 0b10011000u && isRm11111 ->
    Op.LD3, getVt3HidxPoXSnI6 bin, oprSize
  | c when c &&& 0b11111011u = 0b10100000u && isRm11111 ->
    Op.LD1, getVt1SidxPoXSnI4 bin, oprSize
  | c when c &&& 0b11111111u = 0b10100001u && isRm11111 ->
    Op.LD1, getVt1DidxPoXSnI8 bin, oprSize
  | c when c &&& 0b11111011u = 0b10101000u && isRm11111 ->
    Op.LD3, getVt3SidxPoXSnI12 bin, oprSize
  | c when c &&& 0b11111111u = 0b10101001u && isRm11111 ->
    Op.LD3, getVt3DidxPoXSnI24 bin, oprSize
  | c when c &&& 0b11111100u = 0b10110000u && isRm11111 ->
    Op.LD1R, getVt1tPoXSnImm2 bin, oprSize
  | c when c &&& 0b11111100u = 0b10111000u && isRm11111 ->
    Op.LD3R, getVt3tPoXSnImm2 bin, oprSize
  | c when c &&& 0b11111001u = 0b11010001u -> unallocated ()
  | c when c &&& 0b11111001u = 0b11011001u -> unallocated ()
  | c when c &&& 0b11111011u = 0b11100010u -> unallocated ()
  | c when c &&& 0b11111111u = 0b11100011u -> unallocated ()
  | c when c &&& 0b11111101u = 0b11100101u -> unallocated ()
  | c when c &&& 0b11111011u = 0b11101010u -> unallocated ()
  | c when c &&& 0b11111111u = 0b11101011u -> unallocated ()
  | c when c &&& 0b11111101u = 0b11101101u -> unallocated ()
  | c when c &&& 0b11111100u = 0b11110100u -> unallocated ()
  | c when c &&& 0b11111100u = 0b11111100u -> unallocated ()
  | c when c &&& 0b11111000u = 0b11000000u && not isRm11111 ->
    Op.LD2, getVt2BidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111000u = 0b11001000u && not isRm11111 ->
    Op.LD4, getVt4BidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111001u = 0b11010000u && not isRm11111 ->
    Op.LD2, getVt2HidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111001u = 0b11011000u && not isRm11111 ->
    Op.LD4, getVt4HidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111011u = 0b11100000u && not isRm11111 ->
    Op.LD2, getVt2SidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111111u = 0b11100001u && not isRm11111 ->
    Op.LD2, getVt2DidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111011u = 0b11101000u && not isRm11111 ->
    Op.LD4, getVt4SidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111111u = 0b11101001u && not isRm11111 ->
    Op.LD4, getVt4DidxPoXSnXm bin, oprSize
  | c when c &&& 0b11111100u = 0b11110000u && not isRm11111 ->
    Op.LD2R, getVt2tPoXSnXm bin resNone, oprSize
  | c when c &&& 0b11111100u = 0b11111000u && not isRm11111 ->
    Op.LD4R, getVt4tPoXSnXm bin resNone, oprSize
  | c when c &&& 0b11111000u = 0b11000000u && isRm11111 ->
    Op.LD2, getVt2BidxPoXSnI2 bin, oprSize
  | c when c &&& 0b11111000u = 0b11001000u && isRm11111 ->
    Op.LD4, getVt4BidxPoXSnI4 bin, oprSize
  | c when c &&& 0b11111001u = 0b11010000u && isRm11111 ->
    Op.LD2, getVt2HidxPoXSnI4 bin, oprSize
  | c when c &&& 0b11111001u = 0b11011000u && isRm11111 ->
    Op.LD4, getVt4HidxPoXSnI8 bin, oprSize
  | c when c &&& 0b11111011u = 0b11100000u && isRm11111 ->
    Op.LD2, getVt2SidxPoXSnI8 bin, oprSize
  | c when c &&& 0b11111111u = 0b11100001u && isRm11111 ->
    Op.LD2, getVt2DidxPoXSnI16 bin, oprSize
  | c when c &&& 0b11111011u = 0b11101000u && isRm11111 ->
    Op.LD4, getVt4SidxPoXSnI16 bin, oprSize
  | c when c &&& 0b11111111u = 0b11101001u && isRm11111 ->
    Op.LD4, getVt4DidxPoXSnI32 bin, oprSize
  | c when c &&& 0b11111100u = 0b11110000u && isRm11111 ->
    Op.LD2R, getVt2tPoXSnImm2 bin, oprSize
  | c when c &&& 0b11111100u = 0b11111000u && isRm11111 ->
    Op.LD4R, getVt4tPoXSnImm2 bin, oprSize
  | _ -> raise InvalidOpcodeException

/// Load register (literal) on page C4-293.
let parseLoadRegLiteral bin =
  let cond = concat (extract bin 31u 30u) (pickBit bin 26u) 1 (* opc:V *)
  match cond with
  | 0b000u -> Op.LDR, getWtLabel bin, 32<rt>
  | 0b001u -> Op.LDR, getStLabel bin, 32<rt>
  | 0b010u -> Op.LDR, getXtLabel bin, 64<rt>
  | 0b011u -> Op.LDR, getDtLabel bin, 64<rt>
  | 0b100u -> Op.LDRSW, getXtLabel bin, 64<rt>
  | 0b101u -> Op.LDR, getQtLabel bin, 128<rt>
  | 0b110u -> Op.PRFM, getPrfopImm5Label bin, 64<rt>
  | 0b111u -> unallocated ()
  | _ -> raise InvalidOpcodeException

let parseLoadStoreExclusive bin =
  let cond = concat (concat (extract bin 31u 30u) (extract bin 23u 21u) 3)
                    (pickBit bin 15u) 1 (* size:o2:L:o1:o0 *)
  let rt2 = extract bin 14u 10u
  match cond with
  | c when c &&& 0b001011u = 0b001000u (* FEAT_LOR *) -> unallocated ()
  | c when c &&& 0b001010u = 0b001010u && rt2 <> 0b11111u -> unallocated ()
  | c when c &&& 0b100010u = 0b000010u && rt2 <> 0b11111u -> unallocated ()
  | 0b000000u -> Op.STXRB, getWsWtMXSn bin, 32<rt>
  | 0b000001u -> Op.STLXRB, getWsWtMXSn bin, 32<rt>
  | 0b000100u -> Op.LDXRB, getWtMXSn bin, 32<rt>
  | 0b000101u -> Op.LDAXRB, getWtMXSn bin, 32<rt>
  | 0b001001u -> Op.STLRB, getWtMXSn bin, 32<rt>
  | 0b001101u -> Op.LDARB, getWtMXSn bin, 32<rt>
  | 0b010000u -> Op.STXRH, getWsWtMXSn bin, 32<rt>
  | 0b010001u -> Op.STLXRH, getWsWtMXSn bin, 32<rt>
  | 0b010100u -> Op.LDXRH, getWtMXSn bin, 32<rt>
  | 0b010101u -> Op.LDAXRH, getWtMXSn bin, 32<rt>
  | 0b011001u -> Op.STLRH, getWtMXSn bin, 32<rt>
  | 0b011101u -> Op.LDARH, getWtMXSn bin, 32<rt>
  | 0b100000u -> Op.STXR, getWsWtMXSn bin, 32<rt>
  | 0b100001u -> Op.STLXR, getWsWtMXSn bin, 32<rt>
  | 0b100010u -> Op.STXP, getWsWt1Wt2MXSn bin, 32<rt>
  | 0b100011u -> Op.STLXP, getWsWt1Wt2MXSn bin, 32<rt>
  | 0b100100u -> Op.LDXR, getWtMXSn bin, 32<rt>
  | 0b100101u -> Op.LDAXR, getWtMXSn bin, 32<rt>
  | 0b100110u -> Op.LDXP, getWt1Wt2MXSn bin, 32<rt>
  | 0b100111u -> Op.LDAXP, getWt1Wt2MXSn bin, 32<rt>
  | 0b101001u -> Op.STLR, getWtMXSn bin, 32<rt>
  | 0b101010u when rt2 = 0b11111u -> Op.CAS, getWsWtMXSn bin, 32<rt>
  | 0b101011u when rt2 = 0b11111u -> Op.CASL, getWsWtMXSn bin, 32<rt>
  | 0b101101u -> Op.LDAR, getWtMXSn bin, 32<rt>
  | 0b101110u when rt2 = 0b11111u -> Op.CASA, getWsWtMXSn bin, 32<rt>
  | 0b101111u when rt2 = 0b11111u -> Op.CASAL, getWsWtMXSn bin, 32<rt>
  | 0b110000u -> Op.STXR, getWsXtMXSn bin, 64<rt>
  | 0b110001u -> Op.STLXR, getWsXtMXSn bin, 64<rt>
  | 0b110010u -> Op.STXP, getWsXt1Xt2MXSn bin, 64<rt>
  | 0b110011u -> Op.STLXP, getWsXt1Xt2MXSn bin, 64<rt>
  | 0b110100u -> Op.LDXR, getXtMXSn bin, 64<rt>
  | 0b110101u -> Op.LDAXR, getXtMXSn bin, 64<rt>
  | 0b110110u -> Op.LDXP, getXt1Xt2MXSn bin, 64<rt>
  | 0b110111u -> Op.LDAXP, getXt1Xt2MXSn bin, 64<rt>
  | 0b111001u -> Op.STLR, getXtMXSn bin, 64<rt>
  | 0b111010u when rt2 = 0b11111u -> Op.CAS, getXsXtMXSn bin, 64<rt>
  | 0b111011u when rt2 = 0b11111u -> Op.CASL, getXsXtMXSn bin, 64<rt>
  | 0b111101u -> Op.LDAR, getXtMXSn bin, 64<rt>
  | 0b111110u when rt2 = 0b11111u -> Op.CASA, getXsXtMXSn bin, 64<rt>
  | 0b111111u when rt2 = 0b11111u -> Op.CASAL, getXsXtMXSn bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let parseLoadStoreNoAllocatePairOffset bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (pickBit bin 22u) 1 (* opc:V:L *)
  match cond with
  | 0b0000u -> Op.STNP, getWt1Wt2BIXSnimm bin 2, 32<rt>
  | 0b0001u -> Op.LDNP, getWt1Wt2BIXSnimm bin 2, 32<rt>
  | 0b0010u -> Op.STNP, getSt1St2BIXSnimm bin 2, 32<rt>
  | 0b0011u -> Op.LDNP, getSt1St2BIXSnimm bin 2, 32<rt>
  | c when c &&& 0b1110u = 0b0100u -> unallocated ()
  | 0b0110u -> Op.STNP, getDt1Dt2BIXSnimm bin 3, 64<rt>
  | 0b0111u -> Op.LDNP, getDt1Dt2BIXSnimm bin 3, 64<rt>
  | 0b1000u -> Op.STNP, getXt1Xt2BIXSnimm bin 3, 64<rt>
  | 0b1001u -> Op.LDNP, getXt1Xt2BIXSnimm bin 3, 64<rt>
  | 0b1010u -> Op.STNP, getQt1Qt2BIXSnimm bin 4, 128<rt>
  | 0b1011u -> Op.LDNP, getQt1Qt2BIXSnimm bin 4, 128<rt>
  | c when c &&& 0b1100u = 0b1100u -> unallocated ()
  | _ -> raise InvalidOpcodeException

let parseLoadStoreRegImmPostIndexed bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (extract bin 23u 22u) 2 (* size:V:opc *)
  match cond with
  | c when c &&& 0b01110u = 0b01110u -> unallocated ()
  | 0b00000u -> Op.STRB, getWtPoXSnsimm bin, 32<rt>
  | 0b00001u -> Op.LDRB, getWtPoXSnsimm bin, 32<rt>
  | 0b00010u -> Op.LDRSB, getXtPoXSnsimm bin, 64<rt>
  | 0b00011u -> Op.LDRSB, getWtPoXSnsimm bin, 32<rt>
  | 0b00100u -> Op.STR, getBtPoXSnsimm bin, 8<rt>
  | 0b00101u -> Op.LDR, getBtPoXSnsimm bin, 8<rt>
  | 0b00110u -> Op.STR, getQtPoXSnsimm bin, 128<rt>
  | 0b00111u -> Op.LDR, getQtPoXSnsimm bin, 128<rt>
  | 0b01000u -> Op.STRH, getWtPoXSnsimm bin, 32<rt>
  | 0b01001u -> Op.LDRH, getWtPoXSnsimm bin, 32<rt>
  | 0b01010u -> Op.LDRSH, getXtPoXSnsimm bin, 64<rt>
  | 0b01011u -> Op.LDRSH, getWtPoXSnsimm bin, 32<rt>
  | 0b01100u -> Op.STR, getHtPoXSnsimm bin, 16<rt>
  | 0b01101u -> Op.LDR, getHtPoXSnsimm bin, 16<rt>
  | c when c &&& 0b10111u = 0b10011u -> unallocated ()
  | c when c &&& 0b10110u = 0b10110u -> unallocated ()
  | 0b10000u -> Op.STR, getWtPoXSnsimm bin, 32<rt>
  | 0b10001u -> Op.LDR, getWtPoXSnsimm bin, 32<rt>
  | 0b10010u -> Op.LDRSW, getXtPoXSnsimm bin, 64<rt>
  | 0b10100u -> Op.STR, getStPoXSnsimm bin, 32<rt>
  | 0b10101u -> Op.LDR, getStPoXSnsimm bin, 32<rt>
  | 0b11000u -> Op.STR, getXtPoXSnsimm bin, 64<rt>
  | 0b11001u -> Op.LDR, getXtPoXSnsimm bin, 64<rt>
  | 0b11010u -> unallocated ()
  | 0b11100u -> Op.STR, getDtPoXSnsimm bin, 64<rt>
  | 0b11101u -> Op.LDR, getDtPoXSnsimm bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let parseLoadStoreRegImmPreIndexed bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (extract bin 23u 22u) 2 (* size:V:opc *)
  match cond with
  | c when c &&& 0b01110u = 0b01110u -> unallocated ()
  | 0b00000u -> Op.STRB, getWtPrXSnsimm bin, 32<rt>
  | 0b00001u -> Op.LDRB, getWtPrXSnsimm bin, 32<rt>
  | 0b00010u -> Op.LDRSB, getXtPrXSnsimm bin, 64<rt>
  | 0b00011u -> Op.LDRSB, getWtPrXSnsimm bin, 32<rt>
  | 0b00100u -> Op.STR, getBtPrXSnsimm bin, 8<rt>
  | 0b00101u -> Op.LDR, getBtPrXSnsimm bin, 8<rt>
  | 0b00110u -> Op.STR, getQtPrXSnsimm bin, 128<rt>
  | 0b00111u -> Op.LDR, getQtPrXSnsimm bin, 128<rt>
  | 0b01000u -> Op.STRH, getWtPrXSnsimm bin, 32<rt>
  | 0b01001u -> Op.LDRH, getWtPrXSnsimm bin, 32<rt>
  | 0b01010u -> Op.LDRSH, getXtPrXSnsimm bin, 64<rt>
  | 0b01011u -> Op.LDRSH, getWtPrXSnsimm bin, 32<rt>
  | 0b01100u -> Op.STR, getHtPrXSnsimm bin, 16<rt>
  | 0b01101u -> Op.LDR, getHtPrXSnsimm bin, 16<rt>
  | c when c &&& 0b10111u = 0b10011u -> unallocated ()
  | c when c &&& 0b10110u = 0b10110u -> unallocated ()
  | 0b10000u -> Op.STR, getWtPrXSnsimm bin, 32<rt>
  | 0b10001u -> Op.LDR, getWtPrXSnsimm bin, 32<rt>
  | 0b10010u -> Op.LDRSW, getXtPrXSnsimm bin, 64<rt>
  | 0b10100u -> Op.STR, getStPrXSnsimm bin, 32<rt>
  | 0b10101u -> Op.LDR, getStPrXSnsimm bin, 32<rt>
  | 0b11100u -> Op.STR, getDtPrXSnsimm bin, 64<rt>
  | 0b11101u -> Op.LDR, getDtPrXSnsimm bin, 64<rt>
  | 0b11010u -> unallocated ()
  | 0b11000u -> Op.STR, getXtPrXSnsimm bin, 64<rt>
  | 0b11001u -> Op.LDR, getXtPrXSnsimm bin, 64<rt>
  | _ -> raise InvalidOpcodeException

/// Load/store register (register offset) on page C4-307.
let parseLoadStoreRegOffset bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (extract bin 23u 22u) 2
  let option = extract bin 15u 13u
  let isOption011 = option = 0b011u
  if option &&& 0b010u = 0b000u then unallocated () else ()
  match cond with (* size:V:opc *)
  | c when c &&& 0b01110u = 0b01110u -> unallocated ()
  | 0b00000u when not isOption011 -> Op.STRB, getWtBEXSnrmamt bin 0L, 32<rt>
  | 0b00000u when isOption011 -> Op.STRB, getWtBRXSnxmamt bin, 32<rt>
  | 0b00001u when not isOption011 -> Op.LDRB, getWtBEXSnrmamt bin 0L, 32<rt>
  | 0b00001u when isOption011 -> Op.LDRB, getWtBRXSnxmamt bin, 32<rt>
  | 0b00010u when not isOption011 ->
    Op.LDRSB, getXtBEXSnrmamt bin 0L, 64<rt>
  | 0b00010u when isOption011 -> Op.LDRSB, getXtBRXSnxmamt bin, 64<rt>
  | 0b00011u when not isOption011 ->
    Op.LDRSB, getWtBEXSnrmamt bin 0L, 32<rt>
  | 0b00011u when isOption011 -> Op.LDRSB, getWtBRXSnxmamt bin, 32<rt>
  | 0b00100u when not isOption011 -> Op.STR, getBtBEXSnrmamt bin, 8<rt>
  | 0b00100u when isOption011 -> Op.STR, getBtBRXSnxmamt bin, 8<rt>
  | 0b00101u when not isOption011 -> Op.LDR, getBtBEXSnrmamt bin, 8<rt>
  | 0b00101u when isOption011 -> Op.LDR, getBtBRXSnxmamt bin, 8<rt>
  | 0b00110u -> Op.STR, getQtBEXSnrmamt bin, 128<rt>
  | 0b00111u -> Op.LDR, getQtBEXSnrmamt bin, 128<rt>
  | 0b01000u -> Op.STRH, getWtBEXSnrmamt bin 1L, 32<rt>
  | 0b01001u -> Op.LDRH, getWtBEXSnrmamt bin 1L, 32<rt>
  | 0b01010u -> Op.LDRSH, getXtBEXSnrmamt bin 1L, 64<rt>
  | 0b01011u -> Op.LDRSH, getWtBEXSnrmamt bin 1L, 32<rt>
  | 0b01100u -> Op.STR, getHtBEXSnrmamt bin, 16<rt>
  | 0b01101u -> Op.LDR, getHtBEXSnrmamt bin, 16<rt>
  | c when c &&& 0b10111u = 0b10011u -> unallocated ()
  | c when c &&& 0b10110u = 0b10110u -> unallocated ()
  | 0b10000u -> Op.STR, getWtBEXSnrmamt bin 2L, 32<rt>
  | 0b10001u -> Op.LDR, getWtBEXSnrmamt bin 2L, 32<rt>
  | 0b10010u -> Op.LDRSW, getXtBEXSnrmamt bin 2L, 64<rt>
  | 0b10100u -> Op.STR, getStBEXSnrmamt bin, 32<rt>
  | 0b10101u -> Op.LDR, getStBEXSnrmamt bin, 32<rt>
  | 0b11000u -> Op.STR, getXtBEXSnrmamt bin 3L, 64<rt>
  | 0b11001u -> Op.LDR, getXtBEXSnrmamt bin 3L, 64<rt>
  | 0b11010u -> Op.PRFM, getPrfopimm5BEXSnrmamt bin, 64<rt>
  | 0b11100u -> Op.STR, getDtBEXSnrmamt bin, 64<rt>
  | 0b11101u -> Op.LDR, getDtBEXSnrmamt bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let parseLoadStoreRegUnprivileged bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (extract bin 23u 22u) 2 (* size:V:opc *)
  match cond with
  | c when c &&& 0b00100u = 0b00100u -> unallocated ()
  | 0b00000u -> Op.STTRB, getWtBIXSnsimm bin, 32<rt>
  | 0b00001u -> Op.LDTRB, getWtBIXSnsimm bin, 32<rt>
  | 0b00010u -> Op.LDTRSB, getXtBIXSnsimm bin, 64<rt>
  | 0b00011u -> Op.LDTRSB, getWtBIXSnsimm bin, 32<rt>
  | 0b01000u -> Op.STTRH, getWtBIXSnsimm bin, 32<rt>
  | 0b01001u -> Op.LDTRH, getWtBIXSnsimm bin, 32<rt>
  | 0b01010u -> Op.LDTRSH, getXtBIXSnsimm bin, 64<rt>
  | 0b01011u -> Op.LDTRSH, getWtBIXSnsimm bin, 32<rt>
  | c when c &&& 0b10111u = 0b10011u -> unallocated ()
  | 0b10000u -> Op.STTR, getWtBIXSnsimm bin, 32<rt>
  | 0b10001u -> Op.LDTR, getWtBIXSnsimm bin, 32<rt>
  | 0b10010u -> Op.LDTRSW, getXtBIXSnsimm bin, 64<rt>
  | 0b11000u -> Op.STTR, getXtBIXSnsimm bin, 64<rt>
  | 0b11001u -> Op.LDTR, getXtBIXSnsimm bin, 64<rt>
  | 0b11010u -> unallocated ()
  | _ -> raise InvalidOpcodeException

/// Load/store register (unscaled immediate) on page C4-296.
let parseLoadStoreRegUnscaledImm bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (extract bin 23u 22u) 2 (* size:V:opc *)
  match cond with
  | c when c &&& 0b01110u = 0b01110u -> unallocated ()
  | 0b00000u -> Op.STURB, getWtBIXSnsimm bin, 32<rt>
  | 0b00001u -> Op.LDURB, getWtBIXSnsimm bin, 32<rt>
  | 0b00010u -> Op.LDURSB, getXtBIXSnsimm bin, 64<rt>
  | 0b00011u -> Op.LDURSB, getWtBIXSnsimm bin, 32<rt>
  | 0b00100u -> Op.STUR, getBtBIXSnsimm bin, 8<rt>
  | 0b00101u -> Op.LDUR, getBtBIXSnsimm bin, 8<rt>
  | 0b00110u -> Op.STUR, getQtBIXSnsimm bin, 128<rt>
  | 0b00111u -> Op.LDUR, getQtBIXSnsimm bin, 128<rt>
  | 0b01000u -> Op.STURH, getWtBIXSnsimm bin, 32<rt>
  | 0b01001u -> Op.LDURH, getWtBIXSnsimm bin, 32<rt>
  | 0b01010u -> Op.LDURSH, getXtBIXSnsimm bin, 64<rt>
  | 0b01011u -> Op.LDURSH, getWtBIXSnsimm bin, 32<rt>
  | 0b01100u -> Op.STUR, getHtBIXSnsimm bin, 16<rt>
  | 0b01101u -> Op.LDUR, getHtBIXSnsimm bin, 16<rt>
  | c when c &&& 0b10111u = 0b10011u -> unallocated ()
  | c when c &&& 0b10110u = 0b10110u -> unallocated ()
  | 0b10000u -> Op.STUR, getWtBIXSnsimm bin, 32<rt>
  | 0b10001u -> Op.LDUR, getWtBIXSnsimm bin, 32<rt>
  | 0b10010u -> Op.LDURSW, getXtBIXSnsimm bin, 64<rt>
  | 0b10100u -> Op.STUR, getStBIXSnsimm bin, 32<rt>
  | 0b10101u -> Op.LDUR, getStBIXSnsimm bin, 32<rt>
  | 0b11000u -> Op.STUR, getXtBIXSnsimm bin, 64<rt>
  | 0b11001u -> Op.LDUR, getXtBIXSnsimm bin, 64<rt>
  | 0b11010u -> Op.PRFUM, getPrfopimm5BIXSnsimm bin, 64<rt>
  | 0b11100u -> Op.STUR, getDtBIXSnsimm bin, 64<rt>
  | 0b11101u -> Op.LDUR, getDtBIXSnsimm bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let parseLoadStoreRegUnsignedImm bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (extract bin 23u 22u) 2 (* size:V:opc *)
  match cond with
  | c when c &&& 0b01110u = 0b01110u -> unallocated ()
  | 0b00000u -> Op.STRB, getWtBIXSnpimm bin 1u, 8<rt>
  | 0b00001u -> Op.LDRB, getWtBIXSnpimm bin 1u, 32<rt>
  | 0b00010u -> Op.LDRSB, getXtBIXSnpimm bin 1u, 64<rt>
  | 0b00011u -> Op.LDRSB, getWtBIXSnpimm bin 1u, 32<rt>
  | 0b00100u -> Op.STR, getBtBIXSnpimm bin, 8<rt>
  | 0b00101u -> Op.LDR, getBtBIXSnpimm bin, 8<rt>
  | 0b00110u -> Op.STR, getQtBIXSnpimm bin, 128<rt>
  | 0b00111u -> Op.LDR, getQtBIXSnpimm bin, 128<rt>
  | 0b01000u -> Op.STRH, getWtBIXSnpimm bin 2u, 32<rt>
  | 0b01001u -> Op.LDRH, getWtBIXSnpimm bin 2u, 32<rt>
  | 0b01010u -> Op.LDRSH, getXtBIXSnpimm bin 2u, 64<rt>
  | 0b01011u -> Op.LDRSH, getWtBIXSnpimm bin 2u, 32<rt>
  | 0b01100u -> Op.STR, getHtBIXSnpimm bin, 16<rt>
  | 0b01101u -> Op.LDR, getHtBIXSnpimm bin, 16<rt>
  | c when c &&& 0b10111u = 0b10011u -> unallocated ()
  | c when c &&& 0b10110u = 0b10110u -> unallocated ()
  | 0b10000u -> Op.STR, getWtBIXSnpimm bin 4u, 32<rt>
  | 0b10001u -> Op.LDR, getWtBIXSnpimm bin 4u, 32<rt>
  | 0b10010u -> Op.LDRSW, getXtBIXSnpimm bin 4u, 64<rt>
  | 0b10100u -> Op.STR, getStBIXSnpimm bin, 32<rt>
  | 0b10101u -> Op.LDR, getStBIXSnpimm bin, 32<rt>
  | 0b11000u -> Op.STR, getXtBIXSnpimm bin 8u, 64<rt>
  | 0b11001u -> Op.LDR, getXtBIXSnpimm bin 8u, 64<rt>
  | 0b11010u -> Op.PRFM, getPrfopimm5BIXSnpimm bin, 64<rt>
  | 0b11100u -> Op.STR, getDtBIXSnpimm bin, 64<rt>
  | 0b11101u -> Op.LDR, getDtBIXSnpimm bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let parseLoadStoreRegPairOffset bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (pickBit bin 22u) 1 (* opc:V:L *)
  match cond with
  | 0b0000u -> Op.STP, getWt1Wt2BIXSnimm bin 2, 32<rt>
  | 0b0001u -> Op.LDP, getWt1Wt2BIXSnimm bin 2, 32<rt>
  | 0b0010u -> Op.STP, getSt1St2BIXSnimm bin 2, 32<rt>
  | 0b0011u -> Op.LDP, getSt1St2BIXSnimm bin 2, 32<rt>
  | 0b0100u -> unallocated ()
  | 0b0101u -> Op.LDPSW, getXt1Xt2BIXSnimm bin 2, 64<rt>
  | 0b0110u -> Op.STP, getDt1Dt2BIXSnimm bin 3, 64<rt>
  | 0b0111u -> Op.LDP, getDt1Dt2BIXSnimm bin 3, 64<rt>
  | 0b1000u -> Op.STP, getXt1Xt2BIXSnimm bin 3, 64<rt>
  | 0b1001u -> Op.LDP, getXt1Xt2BIXSnimm bin 3, 64<rt>
  | 0b1010u -> Op.STP, getQt1Qt2BIXSnimm bin 4, 128<rt>
  | 0b1011u -> Op.LDP, getQt1Qt2BIXSnimm bin 4, 128<rt>
  | c when c &&& 0b1100u = 0b1100u -> unallocated ()
  | _ -> raise InvalidOpcodeException

let parseLoadStoreRegPairPostIndexed bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (pickBit bin 22u) 1 (* opc:V:L *)
  match cond with
  | 0b0000u -> Op.STP, getWt1Wt2PoXSnimm bin, 32<rt>
  | 0b0001u -> Op.LDP, getWt1Wt2PoXSnimm bin, 32<rt>
  | 0b0010u -> Op.STP, getSt1St2PoXSnimm bin, 32<rt>
  | 0b0011u -> Op.LDP, getSt1St2PoXSnimm bin, 32<rt>
  | 0b0100u -> unallocated ()
  | 0b0101u -> Op.LDPSW, getXt1Xt2PoXSnimm bin 2, 64<rt>
  | 0b0110u -> Op.STP, getDt1Dt2PoXSnimm bin, 64<rt>
  | 0b0111u -> Op.LDP, getDt1Dt2PoXSnimm bin, 64<rt>
  | 0b1000u -> Op.STP, getXt1Xt2PoXSnimm bin 3, 64<rt>
  | 0b1001u -> Op.LDP, getXt1Xt2PoXSnimm bin 3, 64<rt>
  | 0b1010u -> Op.STP, getQt1Qt2PoXSnimm bin, 128<rt>
  | 0b1011u -> Op.LDP, getQt1Qt2PoXSnimm bin, 128<rt>
  | c when c &&& 0b1100u = 0b1100u -> unallocated ()
  | _ -> raise InvalidOpcodeException

let parseLoadStoreRegPairPreIndexed bin =
  let cond = concat (concat (extract bin 31u 30u) (pickBit bin 26u) 1)
                    (pickBit bin 22u) 1 (* opc:V:L *)
  match cond with
  | 0b0000u -> Op.STP, getWt1Wt2PrXSnimm bin, 32<rt>
  | 0b0001u -> Op.LDP, getWt1Wt2PrXSnimm bin, 32<rt>
  | 0b0010u -> Op.STP, getSt1St2PrXSnimm bin, 32<rt>
  | 0b0011u -> Op.LDP, getSt1St2PrXSnimm bin, 32<rt>
  | 0b0100u -> unallocated ()
  | 0b0101u -> Op.LDPSW, getXt1Xt2PrXSnimm bin 2, 64<rt>
  | 0b0110u -> Op.STP, getDt1Dt2PrXSnimm bin, 64<rt>
  | 0b0111u -> Op.LDP, getDt1Dt2PrXSnimm bin, 64<rt>
  | 0b1000u -> Op.STP, getXt1Xt2PrXSnimm bin 3, 64<rt>
  | 0b1001u -> Op.LDP, getXt1Xt2PrXSnimm bin 3, 64<rt>
  | 0b1010u -> Op.STP, getQt1Qt2PrXSnimm bin, 128<rt>
  | 0b1011u -> Op.LDP, getQt1Qt2PrXSnimm bin, 128<rt>
  | c when c &&& 0b1100u = 0b1100u -> unallocated ()
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
  | c when c &&& 0b11111010000000u = 0b00010010000000u -> unallocated ()
  | c when c &&& 0b11111101111100u = 0b00011000000000u ->
    parseAdvSIMDSingle bin
  | c when c &&& 0b11111100000000u = 0b00011100000000u ->
    parseAdvSIMDSinglePostIndexed bin
  | c when c &&& 0b11110101000000u = 0b00010001000000u -> unallocated ()
  | c when c &&& 0b11110100100000u = 0b00010000100000u -> unallocated ()
  | c when c &&& 0b11110100010000u = 0b00010000010000u -> unallocated ()
  | c when c &&& 0b11110100001000u = 0b00010000001000u -> unallocated ()
  | c when c &&& 0b11110100000100u = 0b00010000000100u -> unallocated ()
  | c when c &&& 0b11110000000000u = 0b10010000000000u -> unallocated ()
  | c when c &&& 0b01111000000000u = 0b00000000000000u ->
    parseLoadStoreExclusive bin
  | c when c &&& 0b01111000000000u = 0b00001000000000u -> unallocated ()
  | c when c &&& 0b01101000000000u = 0b00100000000000u ->
    parseLoadRegLiteral bin
  | c when c &&& 0b01101000000000u = 0b00101000000000u -> unallocated ()
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
  | c when c &&& 0b01101010000011u = 0b01100010000000u -> unallocated ()
  | c when c &&& 0b01101010000011u = 0b01100010000001u -> unallocated ()
  | c when c &&& 0b01101010000011u = 0b01100010000010u ->
    parseLoadStoreRegOffset bin
  | c when c &&& 0b01101010000011u = 0b01100010000011u -> unallocated ()
  | c when c &&& 0b01101000000000u = 0b01101000000000u ->
    parseLoadStoreRegUnsignedImm bin
  | _ -> raise InvalidOpcodeException

/// The alias is always the preferred disassembly.
let toAliasFromLSLV _ = Op.LSL

let toAliasFromLSRV _ = Op.LSR

let toAliasFromASRV _ = Op.ASR

let parseDataProcessing2Src bin =
  let cond = concat (concat (pickBit bin 31u) (pickBit bin 29u) 1)
                    (extract bin 15u 10u) 6  (* sf:S:opcode *)
  match cond with
  | c when c &&& 0b00111110u = 0b00000000u -> unallocated ()
  | c when c &&& 0b00111000u = 0b00011000u -> unallocated ()
  | c when c &&& 0b00100000u = 0b00100000u -> unallocated ()
  | c when c &&& 0b01111100u = 0b00000100u -> unallocated ()
  | c when c &&& 0b01111100u = 0b00001100u -> unallocated ()
  | c when c &&& 0b01000000u = 0b01000000u -> unallocated ()
  | 0b00000010u -> Op.UDIV, getWdWnWm bin, 32<rt>
  | 0b00000011u -> Op.SDIV, getWdWnWm bin, 32<rt>
  | 0b00001000u -> toAliasFromLSLV Op.LSLV, getWdWnWm bin, 32<rt>
  | 0b00001001u -> toAliasFromLSRV Op.LSRV, getWdWnWm bin, 32<rt>
  | 0b00001010u -> toAliasFromASRV Op.ASRV, getWdWnWm bin, 32<rt>
  | 0b00001011u -> Op.RORV, getWdWnWm bin, 32<rt>
  | c when c &&& 0b11111011u = 0b00010011u -> unallocated ()
  | 0b00010000u -> Op.CRC32B, getWdWnWm bin, 32<rt>
  | 0b00010001u -> Op.CRC32H, getWdWnWm bin, 32<rt>
  | 0b00010010u -> Op.CRC32W, getWdWnWm bin, 32<rt>
  | 0b00010100u -> Op.CRC32CB, getWdWnWm bin, 32<rt>
  | 0b00010101u -> Op.CRC32CH, getWdWnWm bin, 32<rt>
  | 0b00010110u -> Op.CRC32CW, getWdWnWm bin, 32<rt>
  | 0b10000010u -> Op.UDIV, getXdXnXm bin, 64<rt>
  | 0b10000011u -> Op.SDIV, getXdXnXm bin, 64<rt>
  | 0b10001000u -> toAliasFromLSLV Op.LSLV, getXdXnXm bin, 64<rt>
  | 0b10001001u -> toAliasFromLSRV Op.LSRV, getXdXnXm bin, 64<rt>
  | 0b10001010u -> toAliasFromASRV Op.ASRV, getXdXnXm bin, 64<rt>
  | 0b10001011u -> Op.RORV, getXdXnXm bin, 64<rt>
  | c when c &&& 0b11111001u = 0b10010000u -> unallocated ()
  | c when c &&& 0b11111010u = 0b10010000u -> unallocated ()
  | 0b10010011u -> Op.CRC32X, getWdWnXm bin, 32<rt>
  | 0b10010111u -> Op.CRC32CX, getWdWnXm bin, 32<rt>
  | _ -> raise InvalidOpcodeException

/// Data-processing (1 source) on page C4-312.
/// Data-processing (1 source) on page 4554(ID121622).
let parseDataProcessing1Src bin =
  let cond = concat (concat (pickBit bin 31u) (pickBit bin 29u) 1)
                    (extract bin 20u 10u) 11 (* sf:S:opcode2:opcode *)
  match cond with
  | c when c &&& 0b0000000001000u = 0b0000000001000u -> unallocated ()
  | c when c &&& 0b0000000010000u = 0b0000000010000u -> unallocated ()
  | c when c &&& 0b0000000100000u = 0b0000000100000u -> unallocated ()
  | c when c &&& 0b0000001000000u = 0b0000001000000u -> unallocated ()
  | 0b0000000001001u | 0b1000000001001u -> unallocated ()
  | c when c &&& 0b0111111111110u = 0b0000000001010u -> unallocated ()
  | c when c &&& 0b0111111111100u = 0b0000000001100u -> unallocated ()
  | c when c &&& 0b0111111110000u = 0b0000000010000u -> unallocated ()
  | c when c &&& 0b0010000000000u = 0b0010000000000u -> unallocated ()
  | c when c &&& 0b0100000000000u = 0b0100000000000u -> unallocated ()
  | c when c &&& 0b1011111000000u = 0b0000001000000u -> unallocated ()
  | 0b0000000000000u -> Op.RBIT, getWdWn bin, 32<rt>
  | 0b0000000000001u -> Op.REV16, getWdWn bin, 32<rt>
  | 0b0000000000010u -> Op.REV, getWdWn bin, 32<rt>
  | 0b0000000000110u -> Op.CTZ, getWdWn bin, 32<rt> (* FEAT_CSSC *)
  | 0b0000000000100u -> Op.CLZ, getWdWn bin, 32<rt>
  | 0b0000000000101u -> Op.CLS, getWdWn bin, 32<rt>
  | 0b1000000000000u -> Op.RBIT, getXdXn bin, 64<rt>
  | 0b1000000000001u -> Op.REV16, getXdXn bin, 64<rt>
  | 0b1000000000010u -> Op.REV32, getXdXn bin, 64<rt>
  | 0b1000000000011u -> Op.REV, getXdXn bin, 64<rt>
  | 0b1000000000100u -> Op.CLZ, getXdXn bin, 64<rt>
  | 0b1000000000101u -> Op.CLS, getXdXn bin, 64<rt>
  | 0b1000000000110u -> Op.CTZ, getXdXn bin, 64<rt> (* FEAT_CSSC *)
  | _ -> raise InvalidOpcodeException

let changeToAliasOfShiftReg bin instr =
  let isShfZero = (valShift bin) = 0b00u
  let isI6Zero = imm6 bin = 0b000000u
  let isRn11111 = valN bin = 0b11111u
  match instr with
  | Op.ORR, FourOperands(rd, _, rm, _), oprSize
      when isShfZero && isI6Zero && isRn11111 ->
    Op.MOV, TwoOperands(rd, rm), oprSize
  | Op.ORN, FourOperands(rd, _, rm, s), oprSize when isRn11111 ->
    Op.MVN, ThreeOperands(rd, rm, s), oprSize
  | Op.ANDS, FourOperands(_, rn, rm, s), oprSz when valD bin = 0b11111u ->
    Op.TST, ThreeOperands(rn, rm, s), oprSz
  | _ -> instr

let parseLogicalShiftedReg bin =
  let cond = concat (extract bin 31u 29u) (pickBit bin 21u) 1
  let imm6 = extract bin 15u 10u
  match cond with
  | c when c &&& 0b1000u = 0b0000u && imm6 &&& 0b100000u = 0b100000u ->
    unallocated ()
  | 0b0000u -> Op.AND, getWdWnWmShfamt bin, 32<rt>
  | 0b0001u -> Op.BIC, getWdWnWmShfamt bin, 32<rt>
  | 0b0010u -> Op.ORR, getWdWnWmShfamt bin, 32<rt>
  | 0b0011u -> Op.ORN, getWdWnWmShfamt bin, 32<rt>
  | 0b0100u -> Op.EOR, getWdWnWmShfamt bin, 32<rt>
  | 0b0101u -> Op.EON, getWdWnWmShfamt bin, 32<rt>
  | 0b0110u -> Op.ANDS, getWdWnWmShfamt bin, 32<rt>
  | 0b0111u -> Op.BICS, getWdWnWmShfamt bin, 32<rt>
  | 0b1000u -> Op.AND, getXdXnXmShfamt bin, 64<rt>
  | 0b1001u -> Op.BIC, getXdXnXmShfamt bin, 64<rt>
  | 0b1010u -> Op.ORR, getXdXnXmShfamt bin, 64<rt>
  | 0b1011u -> Op.ORN, getXdXnXmShfamt bin, 64<rt>
  | 0b1100u -> Op.EOR, getXdXnXmShfamt bin, 64<rt>
  | 0b1101u -> Op.EON, getXdXnXmShfamt bin, 64<rt>
  | 0b1110u -> Op.ANDS, getXdXnXmShfamt bin, 64<rt>
  | 0b1111u -> Op.BICS, getXdXnXmShfamt bin, 64<rt>
  | _ -> raise InvalidOpcodeException
  |> changeToAliasOfShiftReg bin

let changeToAliasOfAddSubShiftReg bin instr =
  match instr with
  | Op.ADDS, FourOperands(_, rn, rm, shf), oprSize when valD bin = 0b11111u ->
    Op.CMN, ThreeOperands(rn, rm, shf), oprSize
  | Op.SUB, FourOperands(rd, _, rm, shf), oprSize when valN bin = 0b11111u ->
    Op.NEG, ThreeOperands(rd, rm, shf), oprSize
  | Op.SUBS, FourOperands(_, rn, rm, shf), oprSize when valD bin = 0b11111u ->
    Op.CMP, ThreeOperands(rn, rm, shf), oprSize
  | Op.SUBS, FourOperands(rd, _, rm, shf), oprSize when valN bin = 0b11111u ->
    Op.NEGS, ThreeOperands(rd, rm, shf), oprSize
  | _ -> instr

let parseAddSubShiftReg bin =
  if valShift bin = 0b11u then unallocated () else ()
  match extract bin 31u 29u with
  | c when c &&& 0b100u = 0b000u && imm6 bin &&& 0b100000u = 0b100000u ->
    unallocated ()
  | 0b000u -> Op.ADD, getWdWnWmShfamt bin, 32<rt>
  | 0b001u -> Op.ADDS, getWdWnWmShfamt bin, 32<rt>
  | 0b010u -> Op.SUB, getWdWnWmShfamt bin, 32<rt>
  | 0b011u -> Op.SUBS, getWdWnWmShfamt bin, 32<rt>
  | 0b100u -> Op.ADD, getXdXnXmShfamt bin, 64<rt>
  | 0b101u -> Op.ADDS, getXdXnXmShfamt bin, 64<rt>
  | 0b110u -> Op.SUB, getXdXnXmShfamt bin, 64<rt>
  | 0b111u -> Op.SUBS, getXdXnXmShfamt bin, 64<rt>
  | _ -> raise InvalidOpcodeException
  |> changeToAliasOfAddSubShiftReg bin

let changeToAliasOfExtReg bin = function
  | Op.ADDS, FourOperands(_, rn, rm, ext), oprSize when valD bin = 0b11111u ->
    Op.CMN, ThreeOperands(rn, rm, ext), oprSize
  | Op.SUBS, FourOperands(_, rn, rm, ext), oprSize when valD bin = 0b11111u ->
    Op.CMP, ThreeOperands(rn, rm, ext), oprSize
  | instr -> instr

let parseAddSubExtReg bin =
  let imm3 = extract bin 12u 10u
  if imm3 &&& 0b101u = 0b101u || imm3 &&& 0b110u = 0b110u then unallocated ()
  else ()
  let cond = concat (extract bin 31u 29u) (extract bin 23u 22u) 2
  match cond with (* sf:op:S:opt *)
  | c when c &&& 0b00001u = 0b00001u || c &&& 0b00010u = 0b00010u ->
    unallocated ()
  | 0b00000u -> Op.ADD, getWSdWSnWmExtamt bin, 32<rt>
  | 0b00100u -> Op.ADDS, getWSdWSnWmExtamt bin, 32<rt>
  | 0b01000u -> Op.SUB, getWSdWSnWmExtamt bin, 32<rt>
  | 0b01100u -> Op.SUBS, getWSdWSnWmExtamt bin, 32<rt>
  | 0b10000u -> Op.ADD, getXSdXSnRmExtamt bin, 64<rt>
  | 0b10100u -> Op.ADDS, getXSdXSnRmExtamt bin, 64<rt>
  | 0b11000u -> Op.SUB, getXSdXSnRmExtamt bin, 64<rt>
  | 0b11100u -> Op.SUBS, getXSdXSnRmExtamt bin, 64<rt>
  | _ -> raise InvalidOpcodeException
  |> changeToAliasOfExtReg bin

let changeToAliasOfWithCarry = function
  | Op.SBC, ThreeOperands(rd, _, rm), oSz -> Op.NGC, TwoOperands(rd, rm), oSz
  | Op.SBCS, ThreeOperands(rd, _, rm), oSz -> Op.NGCS, TwoOperands(rd, rm), oSz
  | instr -> instr

let parseAddSubWithCarry bin =
  let cond = concat (extract bin 31u 29u) (extract bin 15u 10u) 6
  let instr =
    match cond with  (* sf:op:s:opcode2 *)
    | c when c &&& 0b000111111u = 0b000000001u -> unallocated ()
    | c when c &&& 0b000111111u = 0b000000010u -> unallocated ()
    | c when c &&& 0b000111111u = 0b000000100u -> unallocated ()
    | c when c &&& 0b000111111u = 0b000001000u -> unallocated ()
    | c when c &&& 0b000111111u = 0b000010000u -> unallocated ()
    | c when c &&& 0b000111111u = 0b000100000u -> unallocated ()
    | 0b000000000u -> Op.ADC, getWdWnWm bin, 32<rt>
    | 0b001000000u -> Op.ADCS, getWdWnWm bin, 32<rt>
    | 0b010000000u -> Op.SBC, getWdWnWm bin, 32<rt>
    | 0b011000000u -> Op.SBCS, getWdWnWm bin, 32<rt>
    | 0b100000000u -> Op.ADC, getXdXnXm bin, 64<rt>
    | 0b101000000u -> Op.ADCS, getXdXnXm bin, 64<rt>
    | 0b110000000u -> Op.SBC, getXdXnXm bin, 64<rt>
    | 0b111000000u -> Op.SBCS, getXdXnXm bin, 64<rt>
    | _ -> raise InvalidOpcodeException
  if valN bin <> 0b11111u then instr else changeToAliasOfWithCarry instr

let parseCondCmpReg bin =
  let cond = concat (concat (extract bin 31u 29u) (pickBit bin 10u) 1)
                    (pickBit bin 4u) 1 (* sf:op:S:o2:o3 *)
  match cond with
  | c when c &&& 0b00001u = 0b00001u -> unallocated ()
  | c when c &&& 0b00010u = 0b00010u -> unallocated ()
  | c when c &&& 0b00100u = 0b00000u -> unallocated ()
  | 0b00100u -> Op.CCMN, getWnWmNzcvCond bin, 32<rt>
  | 0b01100u -> Op.CCMP, getWnWmNzcvCond bin, 32<rt>
  | 0b10100u -> Op.CCMN, getXnXmNzcvCond bin, 64<rt>
  | 0b11100u -> Op.CCMP, getXnXmNzcvCond bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let parseCondCmpImm bin =
  let cond = concat (concat (extract bin 31u 29u) (pickBit bin 10u) 1)
                    (pickBit bin 4u) 1 (* sf:op:S:o2:o3 *)
  match cond with
  | c when c &&& 0b00001u = 0b00001u -> unallocated ()
  | c when c &&& 0b00010u = 0b00010u -> unallocated ()
  | c when c &&& 0b00100u = 0b00000u -> unallocated ()
  | 0b00100u -> Op.CCMN, getWnImmNzcvCond bin, 32<rt>
  | 0b01100u -> Op.CCMP, getWnImmNzcvCond bin, 32<rt>
  | 0b10100u -> Op.CCMN, getXnImmNzcvCond bin, 64<rt>
  | 0b11100u -> Op.CCMP, getXnImmNzcvCond bin, 64<rt>
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
  | Op.CSINC, FourOperands(rd, rn, _, _), oprSize when cond1 ->
    Op.CINC, ThreeOperands(rd, rn, cond), oprSize
  | Op.CSINC, FourOperands(rd, _, _, _), oprSize when cond2 ->
    Op.CSET, TwoOperands(rd, cond), oprSize
  | Op.CSINV, FourOperands(rd, rn, _, _), oprSize when cond1 ->
    Op.CINV, ThreeOperands(rd, rn, cond), oprSize
  | Op.CSINV, FourOperands(rd, _, _, _), oprSize when cond2 ->
    Op.CSETM, TwoOperands(rd, cond), oprSize
  | Op.CSNEG, FourOperands(rd, rn, _, _), oprSize when cond3 ->
    Op.CNEG, ThreeOperands(rd, rn, cond), oprSize
  | instr -> instr

let parseCondSelect bin =
  let cond = concat (extract bin 31u 29u) (extract bin 11u 10u) 2
  match cond with  (* sf:op:S:op2 *)
  | c when c &&& 0b00010u = 0b00010u -> unallocated ()
  | c when c &&& 0b00100u = 0b00100u -> unallocated ()
  | 0b00000u -> Op.CSEL, getWdWnWmCond bin, 32<rt>
  | 0b00001u -> Op.CSINC, getWdWnWmCond bin, 32<rt>
  | 0b01000u -> Op.CSINV, getWdWnWmCond bin, 32<rt>
  | 0b01001u -> Op.CSNEG, getWdWnWmCond bin, 32<rt>
  | 0b10000u -> Op.CSEL, getXdXnXmCond bin, 64<rt>
  | 0b10001u -> Op.CSINC, getXdXnXmCond bin, 64<rt>
  | 0b11000u -> Op.CSINV, getXdXnXmCond bin, 64<rt>
  | 0b11001u -> Op.CSNEG, getXdXnXmCond bin, 64<rt>
  | _ -> raise InvalidOpcodeException
  |> changeToAliasOfCondSelect bin

let changeToAliasOfDataProcessing3Src = function
  | Op.MADD, FourOperands(rd, rn, rm, _), oprSize ->
    Op.MUL, ThreeOperands(rd, rn, rm), oprSize
  | Op.MSUB, FourOperands(rd, rn, rm, _), oprSize ->
    Op.MNEG, ThreeOperands(rd, rn, rm), oprSize
  | Op.SMADDL, FourOperands(rd, rn, rm, _), oprSize ->
    Op.SMULL, ThreeOperands(rd, rn, rm), oprSize
  | Op.SMSUBL, FourOperands(rd, rn, rm, _), oprSize ->
    Op.SMNEGL, ThreeOperands(rd, rn, rm), oprSize
  | Op.UMADDL, FourOperands(rd, rn, rm, _), oprSize ->
    Op.UMULL, ThreeOperands(rd, rn, rm), oprSize
  | Op.UMSUBL, FourOperands(rd, rn, rm, _), oprSize ->
    Op.UMNEGL, ThreeOperands(rd, rn, rm), oprSize
  | instr -> instr

let parseDataProcessing3Src bin =
  let cond = concat (concat (extract bin 31u 29u) (extract bin 23u 21u) 3)
                    (pickBit bin 15u) 1
  match cond with
  | c when c &&& 0b0111111u = 0b0000101u -> unallocated ()
  | c when c &&& 0b0111110u = 0b0000110u -> unallocated ()
  | c when c &&& 0b0111110u = 0b0010000u -> unallocated ()
  | c when c &&& 0b0111111u = 0b0001101u -> unallocated ()
  | c when c &&& 0b0111110u = 0b0001110u -> unallocated ()
  | c when c &&& 0b0110000u = 0b0010000u -> unallocated ()
  | c when c &&& 0b0100000u = 0b0100000u -> unallocated ()
  | 0b0000000u -> Op.MADD, getWdWnWmWa bin, 32<rt>
  | 0b0000001u -> Op.MSUB, getWdWnWmWa bin, 32<rt>
  | 0b0000010u -> unallocated ()
  | 0b0000011u -> unallocated ()
  | 0b0000100u -> unallocated ()
  | 0b0001010u -> unallocated ()
  | 0b0001011u -> unallocated ()
  | 0b0001100u -> unallocated ()
  | 0b1000000u -> Op.MADD, getXdXnXmXa bin, 64<rt>
  | 0b1000001u -> Op.MSUB, getXdXnXmXa bin, 64<rt>
  | 0b1000010u -> Op.SMADDL, getXdWnWmXa bin, 64<rt>
  | 0b1000011u -> Op.SMSUBL, getXdWnWmXa bin, 64<rt>
  | 0b1000100u -> Op.SMULH, getXdXnXm bin, 64<rt>
  | 0b1001010u -> Op.UMADDL, getXdWnWmXa bin, 64<rt>
  | 0b1001011u -> Op.UMSUBL, getXdWnWmXa bin, 64<rt>
  | 0b1001100u -> Op.UMULH, getXdXnXm bin, 64<rt>
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
  | c when c &&& 0b11001u = 0b10001u -> unallocated ()
  | c when c &&& 0b11000u = 0b11000u -> parseDataProcessing3Src bin
  | _ -> raise InvalidOpcodeException

/// Cryptographic AES on page C4-323.
let parseCryptAES bin =
  let cond = concat (extract bin 23u 22u) (extract bin 16u 12u) 5
  match cond with (* size:opcode *)
  | c when c &&& 0b0001000u = 0b0001000u -> unallocated ()
  | c when c &&& 0b0011100u = 0b0000000u -> unallocated ()
  | c when c &&& 0b0010000u = 0b0010000u -> unallocated ()
  | c when c &&& 0b0100000u = 0b0100000u -> unallocated ()
  | 0b0000100u -> Op.AESE, getVd16BVn16B bin, 128<rt>
  | 0b0000101u -> Op.AESD, getVd16BVn16B bin, 128<rt>
  | 0b0000110u -> Op.AESMC, getVd16BVn16B bin, 128<rt>
  | 0b0000111u -> Op.AESIMC, getVd16BVn16B bin, 128<rt>
  | c when c &&& 0b1000000u = 0b1000000u -> unallocated ()
  | _ -> raise InvalidOpcodeException

/// Advanced SIMD table lookup on page C4-336.
let parseAdvSIMDTableLookup bin =
  let cond = concat (extract bin 23u 22u) (extract bin 14u 12u) 3
  let oprSize = getOprSizeByQ bin
  match cond with  (* op2:len:op *)
  | c when c &&& 0b01000u = 0b01000u -> unallocated ()
  | 0b00000u -> Op.TBL, getVdtaVn116BVmta bin, oprSize
  | 0b00001u -> Op.TBX, getVdtaVn116BVmta bin, oprSize
  | 0b00010u -> Op.TBL, getVdtaVn216BVmta bin, oprSize
  | 0b00011u -> Op.TBX, getVdtaVn216BVmta bin, oprSize
  | 0b00100u -> Op.TBL, getVdtaVn316BVmta bin, oprSize
  | 0b00101u -> Op.TBX, getVdtaVn316BVmta bin, oprSize
  | 0b00110u -> Op.TBL, getVdtaVn416BVmta bin, oprSize
  | 0b00111u -> Op.TBX, getVdtaVn416BVmta bin, oprSize
  | c when c &&& 0b10000u = 0b10000u -> unallocated ()
  | _ -> raise InvalidOpcodeException

/// Advanced SIMD permute on page C4-337.
let parseAdvSIMDPermute bin =
  let oprSize = getOprSizeByQ bin
  match extract bin 14u 12u with (* opcode *)
  | 0b000u -> unallocated ()
  | 0b001u -> Op.UZP1, getVdtVntVmt bin sizeQ110, oprSize
  | 0b010u -> Op.TRN1, getVdtVntVmt bin sizeQ110, oprSize
  | 0b011u -> Op.ZIP1, getVdtVntVmt bin sizeQ110, oprSize
  | 0b100u -> unallocated ()
  | 0b101u -> Op.UZP2, getVdtVntVmt bin sizeQ110, oprSize
  | 0b110u -> Op.TRN2, getVdtVntVmt bin sizeQ110, oprSize
  | 0b111u -> Op.ZIP2, getVdtVntVmt bin sizeQ110, oprSize
  | _ -> raise InvalidOpcodeException

/// Advanced SIMD extract on page C4-338.
let parseAdvSIMDExtract bin =
  match extract bin 23u 22u with
  | c when c &&& 0b01u = 0b01u -> unallocated ()
  | 0b00u -> Op.EXT, getVdtVntVmtIdx bin, getOprSizeByQ bin
  | c when c &&& 0b10u = 0b10u -> unallocated ()
  | _ -> raise InvalidOpcodeException

let changeToAliasOfAdvSIMDCopy bin =
  let imm5 = valImm5 bin in function
  | Op.UMOV, oprs, oprSize
      when imm5 &&& 0b01111u = 0b01000u || imm5 &&& 0b00111u = 0b00100u ->
    Op.MOV, oprs, oprSize
  | instr -> instr

/// Advanced SIMD copy on page C4-338.
let parseAdvSIMDCopy bin =
  let cond = concat (concat (extract bin 30u 29u) (extract bin 20u 16u) 5)
                    (extract bin 14u 11u) 4 (* Q:op:imm5:imm4 *)
  match cond with
  | c when c &&& 0b00011110000u = 0b00000000000u -> unallocated ()
  | c when c &&& 0b01000001111u = 0b00000000000u ->
    Op.DUP, getVdtVntsidx bin, getOprSizeByQ bin
  | c when c &&& 0b01000001111u = 0b00000000001u ->
    Op.DUP, getVdtRn bin, getOprSizeByQ bin
  | c when c &&& 0b01000001111u = 0b00000000010u -> unallocated ()
  | c when c &&& 0b01000001111u = 0b00000000100u -> unallocated ()
  | c when c &&& 0b01000001111u = 0b00000000110u -> unallocated ()
  | c when c &&& 0b01000001000u = 0b00000001000u -> unallocated ()
  | c when c &&& 0b11000001111u = 0b00000000011u -> unallocated ()
  | c when c &&& 0b11000001111u = 0b00000000101u ->
    Op.SMOV, getWdVntsidx bin imm5xxx00, 32<rt>
  | c when c &&& 0b11000001111u = 0b00000000111u ->
    Op.UMOV, getWdVntsidx bin imm5xx000, 32<rt>
  | c when c &&& 0b11000000000u = 0b01000000000u -> unallocated ()
  | c when c &&& 0b11000001111u = 0b10000000011u ->
    Op.INS, getVdtsidxRn bin, 128<rt>
  | c when c &&& 0b11000001111u = 0b10000000101u ->
    Op.SMOV, getXdVntsidx bin imm5xx000, 64<rt>
  | c when c &&& 0b11011111111u = 0b10010000111u ->
    Op.UMOV, getXdVntsidx bin imm5notx1000, 64<rt>
  | c when c &&& 0b11000000000u = 0b11000000000u ->
    Op.INS, getVdtsidx1Vntsidx2 bin, 128<rt>
  | _ -> raise InvalidOpcodeException
  |> changeToAliasOfAdvSIMDCopy bin

let toAliasFromNOT _ = Op.MVN

/// Advanced SIMD two-register miscellaneous on page C4-343.
let parseAdvSIMDTwoReg bin =
  let cond = concat (concat (pickBit bin 29u) (extract bin 23u 22u) 2)
                    (extract bin 16u 12u) 5 (* U:size:opcode *)
  let oprSize = getOprSizeByQ bin
  match cond with
  | c when c &&& 0b00011110u = 0b00010000u -> unallocated ()
  | c when c &&& 0b00011111u = 0b00010101u -> unallocated ()
  | c when c &&& 0b00011111u = 0b00011110u -> unallocated ()
  | c when c &&& 0b01011100u = 0b00001100u -> unallocated ()
  | c when c &&& 0b01011111u = 0b00011111u -> unallocated ()
  | c when c &&& 0b01011111u = 0b01010110u -> unallocated ()
  | c when c &&& 0b01011111u = 0b01010111u -> unallocated ()
  | c when c &&& 0b10011111u = 0b00000000u ->
    Op.REV64, getVdtVnt bin sizeQ110, oprSize
  | c when c &&& 0b10011111u = 0b00000001u ->
    Op.REV16, getVdtVnt bin sizeQ01x1xx, oprSize
  | c when c &&& 0b10011111u = 0b00000010u ->
    Op.SADDLP, getVdtaVntb bin sizeQ11x, oprSize
  | c when c &&& 0b10011111u = 0b00000011u ->
    Op.SUQADD, getVdtVnt bin sizeQ11x, oprSize
  | c when c &&& 0b10011111u = 0b00000100u ->
    Op.CLS, getVdtVnt bin sizeQ11x, oprSize
  | c when c &&& 0b10011111u = 0b00000101u ->
    Op.CNT, getVdtVnt bin sizeQ01x1xx, oprSize
  | c when c &&& 0b10011111u = 0b00000110u ->
    Op.SADALP, getVdtaVntb bin sizeQ11x, oprSize
  | c when c &&& 0b10011111u = 0b00000111u ->
    Op.SQABS, getVdtVnt bin sizeQ110, oprSize
  | c when c &&& 0b10011111u = 0b00001000u ->
    Op.CMGT, getVdtVntI0 bin sizeQ110, oprSize
  | c when c &&& 0b10011111u = 0b00001001u ->
    Op.CMEQ, getVdtVntI0 bin sizeQ110, oprSize
  | c when c &&& 0b10011111u = 0b00001010u ->
    Op.CMLT, getVdtVntI0 bin sizeQ110, oprSize
  | c when c &&& 0b10011111u = 0b00001011u ->
    Op.ABS, getVdtVnt bin sizeQ110, oprSize
  | c when c &&& 0b10011111u = 0b00010010u ->
    getOpcodeByQ bin Op.XTN Op.XTN2, getVdtbVnta bin sizeQ11x, 64<rt>
  | c when c &&& 0b10011111u = 0b00010011u -> unallocated ()
  | c when c &&& 0b10011111u = 0b00010100u ->
    getOpcodeByQ bin Op.SQXTN Op.SQXTN2, getVdtbVnta bin sizeQ11x, 64<rt>
  | c when c &&& 0b11011111u = 0b00010110u ->
    getOpcodeByQ bin Op.FCVTN Op.FCVTN2, getVdtbVnta2 bin resNone, 64<rt>
  | c when c &&& 0b11011111u = 0b00010111u ->
    getOpcodeByQ bin Op.FCVTL Op.FCVTL2, getVdtaVntb2 bin, 64<rt>
  | c when c &&& 0b11011111u = 0b00011000u ->
    Op.FRINTN, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b00011001u ->
    Op.FRINTM, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b00011010u ->
    Op.FCVTNS, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b00011011u ->
    Op.FCVTMS, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b00011100u ->
    Op.FCVTAS, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b00011101u ->
    Op.SCVTF, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b01001100u ->
    Op.FCMGT, getVdtVntF0 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b01001101u ->
    Op.FCMEQ, getVdtVntF0 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b01001110u ->
    Op.FCMLT, getVdtVntF0 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b01001111u ->
    Op.FABS, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b01011000u ->
    Op.FRINTP, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b01011001u ->
    Op.FRINTZ, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b01011010u ->
    Op.FCVTPS, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b01011011u ->
    Op.FCVTZS, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b01011100u ->
    Op.URECPE, getVdtVnt2 bin szQ1x, oprSize
  | c when c &&& 0b11011111u = 0b01011101u ->
    Op.FRECPE, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b01011111u -> unallocated ()
  | c when c &&& 0b10011111u = 0b10000000u ->
    Op.REV32, getVdtVnt bin sizeQ1xx, oprSize
  | c when c &&& 0b10011111u = 0b10000001u -> unallocated ()
  | c when c &&& 0b10011111u = 0b10000010u ->
    Op.UADDLP, getVdtaVntb bin sizeQ11x, oprSize
  | c when c &&& 0b10011111u = 0b10000011u ->
    Op.USQADD, getVdtVnt bin sizeQ110, oprSize
  | c when c &&& 0b10011111u = 0b10000100u ->
    Op.CLZ, getVdtVnt bin sizeQ11x, oprSize
  | c when c &&& 0b10011111u = 0b10000110u ->
    Op.UADALP, getVdtaVntb bin sizeQ11x, oprSize
  | c when c &&& 0b10011111u = 0b10000111u ->
    Op.SQNEG, getVdtVnt bin sizeQ110, oprSize
  | c when c &&& 0b10011111u = 0b10001000u ->
    Op.CMGE, getVdtVntI0 bin sizeQ110, oprSize
  | c when c &&& 0b10011111u = 0b10001001u ->
    Op.CMLE, getVdtVntI0 bin sizeQ110, oprSize
  | c when c &&& 0b10011111u = 0b10001010u -> unallocated ()
  | c when c &&& 0b10011111u = 0b10001011u ->
    Op.NEG, getVdtVnt bin sizeQ110, oprSize
  | c when c &&& 0b10011111u = 0b10010010u ->
    getOpcodeByQ bin Op.SQXTUN Op.SQXTUN2, getVdtbVnta bin size11, 64<rt>
  | c when c &&& 0b10011111u = 0b10010011u ->
    getOpcodeByQ bin Op.SHLL Op.SHLL2, getVdtaVntbShf2 bin size11, 64<rt>
  | c when c &&& 0b10011111u = 0b10010100u ->
    getOpcodeByQ bin Op.UQXTN Op.UQXTN2, getVdtbVnta bin sizeQ11x, 64<rt>
  | c when c &&& 0b11011111u = 0b10010110u ->
    getOpcodeByQ bin Op.FCVTXN Op.FCVTXN2, getVdtbVnta2 bin szQ0x, 64<rt>
  | c when c &&& 0b11011111u = 0b10010111u -> unallocated ()
  | c when c &&& 0b11011111u = 0b10011000u ->
    Op.FRINTA, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b10011001u ->
    Op.FRINTX, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b10011010u ->
    Op.FCVTNU, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b10011011u ->
    Op.FCVTMU, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b10011100u ->
    Op.FCVTAU, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b10011101u ->
    Op.UCVTF, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11111111u = 0b10000101u ->
    toAliasFromNOT Op.NOT, getVdtVnt3 bin, oprSize
  | c when c &&& 0b11111111u = 0b10100101u ->
    Op.RBIT, getVdtVnt3 bin, oprSize
  | c when c &&& 0b11011111u = 0b11000101u -> unallocated ()
  | c when c &&& 0b11011111u = 0b11001100u ->
    Op.FCMGE, getVdtVntF0 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b11001101u ->
    Op.FCMLE, getVdtVntF0 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b11001110u -> unallocated ()
  | c when c &&& 0b11011111u = 0b11001111u ->
    Op.FNEG, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b11011000u -> unallocated ()
  | c when c &&& 0b11011111u = 0b11011001u ->
    Op.FRINTI, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b11011010u ->
    Op.FCVTPU, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b11011011u ->
    Op.FCVTZU, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b11011100u ->
    Op.URSQRTE, getVdtVnt2 bin szQ1x, oprSize
  | c when c &&& 0b11011111u = 0b11011101u ->
    Op.FRSQRTE, getVdtVnt2 bin szQ10, oprSize
  | c when c &&& 0b11011111u = 0b11011111u ->
    Op.FSQRT, getVdtVnt2 bin szQ10, oprSize
  | _ -> raise InvalidOpcodeException

/// Advanced SIMD across lanes on page C4-345.
let parseAdvSIMDAcrossLanes bin =
  let cond = concat (concat (pickBit bin 29u) (extract bin 23u 22u) 2)
                    (extract bin 16u 12u) 5 (* U:size:opcode *)
  let oprSize = getOprSizeByQ bin
  match cond with
  | c when c &&& 0b00011110u = 0b00000000u -> unallocated ()
  | c when c &&& 0b00011111u = 0b00000010u -> unallocated ()
  | c when c &&& 0b00011100u = 0b00000100u -> unallocated ()
  | c when c &&& 0b00011110u = 0b00001000u -> unallocated ()
  | c when c &&& 0b00011111u = 0b00001011u -> unallocated ()
  | c when c &&& 0b00011111u = 0b00001101u -> unallocated ()
  | c when c &&& 0b00011111u = 0b00001110u -> unallocated ()
  | c when c &&& 0b00011000u = 0b00010000u -> unallocated ()
  | c when c &&& 0b00011110u = 0b00011000u -> unallocated ()
  | c when c &&& 0b00011100u = 0b00011100u -> unallocated ()
  | c when c &&& 0b10011111u = 0b00000011u ->
    Op.SADDLV, getVdVnt1 bin sizeQ10011x, oprSize
  | c when c &&& 0b10011111u = 0b00001010u ->
    Op.SMAXV, getVdVnt2 bin sizeQ10011x, oprSize
  | c when c &&& 0b10011111u = 0b00011010u ->
    Op.SMINV, getVdVnt2 bin sizeQ10011x, oprSize
  | c when c &&& 0b10011111u = 0b00011011u ->
    Op.ADDV, getVdVnt2 bin sizeQ10011x, oprSize
  | c when c &&& 0b10011111u = 0b10000011u ->
    Op.UADDLV, getVdVnt1 bin sizeQ10011x, oprSize
  | c when c &&& 0b10011111u = 0b10001010u ->
    Op.UMAXV, getVdVnt2 bin sizeQ10011x, oprSize
  | c when c &&& 0b10011111u = 0b10011010u ->
    Op.UMINV, getVdVnt2 bin sizeQ10011x, oprSize
  | c when c &&& 0b10011111u = 0b10011011u -> unallocated ()
  | c when c &&& 0b11011111u = 0b10001100u ->
    Op.FMAXNMV, getVdVnt3 bin szQx011, oprSize
  | c when c &&& 0b11011111u = 0b10001111u ->
    Op.FMAXV, getVdVnt3 bin szQx011, oprSize
  | c when c &&& 0b11011111u = 0b11001100u ->
    Op.FMINNMV, getVdVnt3 bin szQx011, oprSize
  | c when c &&& 0b11011111u = 0b11001111u ->
    Op.FMINV, getVdVnt3 bin szQx011, oprSize
  | _ -> raise InvalidOpcodeException

/// Advanced SIMD three different on page C4-347.
let parseAdvSIMDThreeDiff bin =
  let cond = concat (pickBit bin 29u) (extract bin 15u 12u) 4 (* U:opcode *)
  match cond with
  | c when c &&& 0b01111u = 0b01111u -> unallocated ()
  | 0b00000u ->
    getOpcodeByQ bin Op.SADDL Op.SADDL2, getVdtaVntbVmtb bin size11, 64<rt>
  | 0b00001u -> getOpcodeByQ bin Op.SADDW Op.SADDW2,
                getVdtaVntaVmtb bin size11, 64<rt>
  | 0b00010u -> getOpcodeByQ bin Op.SSUBL Op.SSUBL2,
                getVdtaVntbVmtb bin size11, 64<rt>
  | 0b00011u -> getOpcodeByQ bin Op.SSUBW Op.SSUBW2,
                getVdtaVntaVmtb bin size11, 64<rt>
  | 0b00100u -> getOpcodeByQ bin Op.ADDHN Op.ADDHN2,
                getVdtbVntaVmta bin size11, 64<rt>
  | 0b00101u -> getOpcodeByQ bin Op.SABAL Op.SABAL2,
                getVdtaVntbVmtb bin size11, 64<rt>
  | 0b00110u -> getOpcodeByQ bin Op.SUBHN Op.SUBHN2,
                getVdtbVntaVmta bin size11, 64<rt>
  | 0b00111u -> getOpcodeByQ bin Op.SABDL Op.SABDL2,
                getVdtaVntbVmtb bin size11, 64<rt>
  | 0b01000u -> getOpcodeByQ bin Op.SMLAL Op.SMLAL2,
                getVdtaVntbVmtb bin size11, 64<rt>
  | 0b01001u -> getOpcodeByQ bin Op.SQDMLAL Op.SQDMLAL2,
                getVdtaVntbVmtb bin size0011, 64<rt>
  | 0b01010u -> getOpcodeByQ bin Op.SMLSL Op.SMLSL2,
                getVdtaVntbVmtb bin size11, 64<rt>
  | 0b01011u -> getOpcodeByQ bin Op.SQDMLSL Op.SQDMLSL2,
                getVdtaVntbVmtb bin size0011, 64<rt>
  | 0b01100u -> getOpcodeByQ bin Op.SMULL Op.SMULL2,
                getVdtaVntbVmtb bin size11, 64<rt>
  | 0b01101u -> getOpcodeByQ bin Op.SQDMULL Op.SQDMULL2,
                getVdtaVntbVmtb bin size0011, 64<rt>
  | 0b01110u -> getOpcodeByQ bin Op.PMULL Op.PMULL2,
                getVdtaVntbVmtb bin size0110, 64<rt>
  | 0b10000u -> getOpcodeByQ bin Op.UADDL Op.UADDL2,
                getVdtaVntbVmtb bin size11, 64<rt>
  | 0b10001u -> getOpcodeByQ bin Op.UADDW Op.UADDW2,
                getVdtaVntaVmtb bin size11, 64<rt>
  | 0b10010u -> getOpcodeByQ bin Op.USUBL Op.USUBL2,
                getVdtaVntbVmtb bin size11, 64<rt>
  | 0b10011u -> getOpcodeByQ bin Op.USUBW Op.USUBW2,
                getVdtaVntaVmtb bin size11, 64<rt>
  | 0b10100u -> getOpcodeByQ bin Op.RADDHN Op.RADDHN2,
                getVdtbVntaVmta bin size11, 64<rt>
  | 0b10101u -> getOpcodeByQ bin Op.UABAL Op.UABAL2,
                getVdtaVntbVmtb bin size11, 64<rt>
  | 0b10110u -> getOpcodeByQ bin Op.RSUBHN Op.RSUBHN2,
                getVdtbVntaVmta bin size11, 64<rt>
  | 0b10111u -> getOpcodeByQ bin Op.UABDL Op.UABDL2,
                getVdtaVntbVmtb bin size11, 64<rt>
  | 0b11000u -> getOpcodeByQ bin Op.UMLAL Op.UMLAL2,
                getVdtaVntbVmtb bin size11, 64<rt>
  | 0b11001u -> unallocated ()
  | 0b11010u -> getOpcodeByQ bin Op.UMLSL Op.UMLSL2,
                getVdtaVntbVmtb bin size11, 64<rt>
  | 0b11011u -> unallocated ()
  | 0b11100u -> getOpcodeByQ bin Op.UMULL Op.UMULL2,
                getVdtaVntbVmtb bin size11, 64<rt>
  | 0b11101u -> unallocated ()
  | 0b11110u -> unallocated ()
  | _ -> raise InvalidOpcodeException

let changeToAliasOfAdvSIMDThreeSame bin = function
  | Op.ORR, ThreeOperands(vdt, vnt, _) when valM bin = valN bin ->
    Op.MOV, TwoOperands(vdt, vnt)
  | instr -> instr

let parseAdvSIMDThreeSame b =
  let cond = concat (concat (pickBit b 29u) (extract b 23u 22u) 2)
                    (extract b 15u 11u) 5 (* U:size:opcode *)
  match cond with
  | c when c &&& 0b10011111u = 0b00000000u ->
    Op.SHADD, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00000001u ->
    Op.SQADD, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00000010u ->
    Op.SRHADD, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00000100u ->
    Op.SHSUB, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00000101u ->
    Op.SQSUB, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00000110u ->
    Op.CMGT, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00000111u ->
    Op.CMGE, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00001000u ->
    Op.SSHL, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00001001u ->
    Op.SQSHL, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00001010u ->
    Op.SRSHL, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00001011u ->
    Op.SQRSHL, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00001100u ->
    Op.SMAX, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00001101u ->
    Op.SMIN, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00001110u ->
    Op.SABD, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00001111u ->
    Op.SABA, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00010000u ->
    Op.ADD, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00010001u ->
    Op.CMTST, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b00010010u -> Op.MLA, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00010011u -> Op.MUL, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00010100u ->
    Op.SMAXP, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00010101u ->
    Op.SMINP, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b00010110u ->
    Op.SQDMULH, getVdtVntVmt1 b size0011
  | c when c &&& 0b10011111u = 0b00010111u ->
    Op.ADDP, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b11011111u = 0b00011000u ->
    Op.FMAXNM, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b00011001u -> Op.FMLA, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b00011010u -> Op.FADD, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b00011011u ->
    Op.FMULX, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b00011100u ->
    Op.FCMEQ, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b00011101u -> unallocated ()
  | c when c &&& 0b11011111u = 0b00011110u -> Op.FMAX, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b00011111u ->
    Op.FRECPS, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11111111u = 0b00000011u -> Op.AND, getVdtVntVmt3 b
  | c when c &&& 0b11111111u = 0b00100011u -> Op.BIC, getVdtVntVmt3 b
  | c when c &&& 0b11011111u = 0b01011000u ->
    Op.FMINNM, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b01011001u -> Op.FMLS, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b01011010u -> Op.FSUB, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b01011011u -> unallocated ()
  | c when c &&& 0b11011111u = 0b01011100u -> unallocated ()
  | c when c &&& 0b11011111u = 0b01011101u -> unallocated ()
  | c when c &&& 0b11011111u = 0b01011110u -> Op.FMIN, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b01011111u ->
    Op.FRSQRTS, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11111111u = 0b01000011u -> Op.ORR, getVdtVntVmt3 b
  | c when c &&& 0b11111111u = 0b01100011u -> Op.ORN, getVdtVntVmt3 b
  | c when c &&& 0b10011111u = 0b10000000u ->
    Op.UHADD, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10000001u ->
    Op.UQADD, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10000010u ->
    Op.URHADD, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10000100u ->
    Op.UHSUB, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10000101u ->
    Op.UQSUB, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10000110u ->
    Op.CMHI, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10000111u ->
    Op.CMHS, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10001000u ->
    Op.USHL, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10001001u ->
    Op.UQSHL, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10001010u ->
    Op.URSHL, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10001011u ->
    Op.UQRSHL, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10001100u ->
    Op.UMAX, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10001101u ->
    Op.UMIN, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10001110u ->
    Op.UABD, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10001111u ->
    Op.UABA, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10010000u ->
    Op.SUB, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10010001u ->
    Op.CMEQ, getVdtVntVmt1 b sizeQ110
  | c when c &&& 0b10011111u = 0b10010010u -> Op.MLS, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10010011u ->
    Op.PMUL, getVdtVntVmt1 b size011011
  | c when c &&& 0b10011111u = 0b10010100u ->
    Op.UMAXP, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10010101u ->
    Op.UMINP, getVdtVntVmt1 b size11
  | c when c &&& 0b10011111u = 0b10010110u ->
    Op.SQRDMULH, getVdtVntVmt1 b size0011
  | c when c &&& 0b10011111u = 0b10010111u -> unallocated ()
  | c when c &&& 0b11011111u = 0b10011000u ->
    Op.FMAXNMP, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b10011001u -> unallocated ()
  | c when c &&& 0b11011111u = 0b10011010u ->
    Op.FADDP, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b10011011u -> Op.FMUL, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b10011100u ->
    Op.FCMGE, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b10011101u ->
    Op.FACGE, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b10011110u ->
    Op.FMAXP, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b10011111u -> Op.FDIV, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11111111u = 0b10000011u -> Op.EOR, getVdtVntVmt3 b
  | c when c &&& 0b11111111u = 0b10100011u -> Op.BSL, getVdtVntVmt3 b
  | c when c &&& 0b11011111u = 0b11011000u ->
    Op.FMINNMP, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b11011001u -> unallocated ()
  | c when c &&& 0b11011111u = 0b11011010u -> Op.FABD, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b11011011u -> unallocated ()
  | c when c &&& 0b11011111u = 0b11011100u ->
    Op.FCMGT, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b11011101u ->
    Op.FACGT, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b11011110u ->
    Op.FMINP, getVdtVntVmt2 b szQ10
  | c when c &&& 0b11011111u = 0b11011111u -> unallocated ()
  | c when c &&& 0b11111111u = 0b11000011u -> Op.BIT, getVdtVntVmt3 b
  | c when c &&& 0b11111111u = 0b11100011u -> Op.BIF, getVdtVntVmt3 b
  | _ -> raise InvalidOpcodeException
  |> changeToAliasOfAdvSIMDThreeSame b
  |> getSIMDVectorOprSize

/// Advanced SIMD modified immediate on page C4-351.
let parseAdvSIMDModImm bin =
  let cond = concat (extract bin 30u 29u) (extract bin 15u 11u) 5
  let oprSize = getOprSizeByQ bin
  match cond with (* Q:op:cmode:o2 *)
  | c when c &&& 0b0000001u = 0b0000001u -> unallocated ()
  | c when c &&& 0b0110011u = 0b0000000u ->
    Op.MOVI, getVdtImm8LAmt3 bin, oprSize
  | c when c &&& 0b0110011u = 0b0000010u ->
    Op.ORR, getVdtImm8LAmt3 bin, oprSize
  | c when c &&& 0b0111011u = 0b0010000u ->
    Op.MOVI, getVdtImm8LAmt2 bin, oprSize
  | c when c &&& 0b0111011u = 0b0010010u ->
    Op.ORR, getVdtImm8LAmt2 bin, oprSize
  | c when c &&& 0b0111101u = 0b0011000u ->
    Op.MOVI, getVdtImm8MAmt bin, oprSize
  | c when c &&& 0b0111111u = 0b0011100u ->
    Op.MOVI, getVdtImm8LAmt1 bin, oprSize
  | c when c &&& 0b0111111u = 0b0011110u -> Op.FMOV, getVdtFImm bin, oprSize
  | c when c &&& 0b0110011u = 0b0100000u ->
    Op.MVNI, getVdtImm8LAmt3 bin, oprSize
  | c when c &&& 0b0110011u = 0b0100010u ->
    Op.BIC, getVdtImm8LAmt3 bin, oprSize
  | c when c &&& 0b0111011u = 0b0110000u ->
    Op.MVNI, getVdtImm8LAmt2 bin, oprSize
  | c when c &&& 0b0111011u = 0b0110010u ->
    Op.BIC, getVdtImm8LAmt2 bin, oprSize
  | c when c &&& 0b0111101u = 0b0111000u ->
    Op.MVNI, getVdtImm8MAmt bin, oprSize
  | c when c &&& 0b1111111u = 0b0111100u -> Op.MOVI, getDdImm bin, oprSize
  | c when c &&& 0b1111111u = 0b0111110u -> unallocated ()
  | c when c &&& 0b1111111u = 0b1111100u -> Op.MOVI, getVd2DImm bin, oprSize
  | c when c &&& 0b1111111u = 0b1111110u -> Op.FMOV, getVd2DFImm bin, oprSize
  | _ -> raise InvalidOpcodeException

/// Advanced SIMD shift by immediate on page C4-352.
let getAdvSIMDShfByImm b =
  let cond = concat (pickBit b 29u) (extract b 15u 11u) 5 (* U:opcode *)
  let oprSize = getOprSizeByQ b
  match cond with
  | c when c &&& 0b011111u = 0b000001u -> unallocated ()
  | c when c &&& 0b011111u = 0b000011u -> unallocated ()
  | c when c &&& 0b011111u = 0b000101u -> unallocated ()
  | c when c &&& 0b011111u = 0b000111u -> unallocated ()
  | c when c &&& 0b011111u = 0b001001u -> unallocated ()
  | c when c &&& 0b011111u = 0b001011u -> unallocated ()
  | c when c &&& 0b011111u = 0b001101u -> unallocated ()
  | c when c &&& 0b011111u = 0b001111u -> unallocated ()
  | c when c &&& 0b011111u = 0b010101u -> unallocated ()
  | c when c &&& 0b011110u = 0b010110u -> unallocated ()
  | c when c &&& 0b011111u = 0b011101u -> unallocated ()
  | c when c &&& 0b011111u = 0b011110u -> unallocated ()
  | 0b000000u -> Op.SSHR, getVdtVntShf1 b, oprSize
  | 0b000010u -> Op.SSRA, getVdtVntShf1 b, oprSize
  | 0b000100u -> Op.SRSHR, getVdtVntShf1 b, oprSize
  | 0b000110u -> Op.SRSRA, getVdtVntShf1 b, oprSize
  | 0b001000u -> unallocated ()
  | 0b001010u -> Op.SHL, getVdtVntShf2 b, oprSize
  | 0b001100u -> unallocated ()
  | 0b001110u -> Op.SQSHL, getVdtVntShf2 b, oprSize
  | 0b010000u ->
    getOpcodeByQ b Op.SHRN Op.SHRN2, getVdtbVntaShf b immh1xxx, 64<rt>
  | 0b010001u ->
    getOpcodeByQ b Op.RSHRN Op.RSHRN2, getVdtbVntaShf b immh1xxx, 64<rt>
  | 0b010010u ->
    getOpcodeByQ b Op.SQSHRN Op.SQSHRN2, getVdtbVntaShf b immh1xxx, 64<rt>
  | 0b010011u ->
    getOpcodeByQ b Op.SQRSHRN Op.SQRSHRN2, getVdtbVntaShf b immh1xxx, 64<rt>
  | 0b010100u ->
    getOpcodeByQ b Op.SSHLL Op.SSHLL2, getVdtaVntbShf b immh1xxx, 64<rt>
  | 0b011100u -> Op.SCVTF, getVdtVntFbits b immhQ1, oprSize
  | 0b011111u -> Op.FCVTZS, getVdtVntFbits b immhQ1, oprSize
  | 0b100000u -> Op.USHR, getVdtVntShf1 b, oprSize
  | 0b100010u -> Op.USRA, getVdtVntShf1 b, oprSize
  | 0b100100u -> Op.URSHR, getVdtVntShf1 b, oprSize
  | 0b100110u -> Op.URSRA, getVdtVntShf1 b, oprSize
  | 0b101000u -> Op.SRI, getVdtVntShf1 b, oprSize
  | 0b101010u -> Op.SLI, getVdtVntShf2 b, oprSize
  | 0b101100u -> Op.SQSHLU, getVdtVntShf2 b, oprSize
  | 0b101110u -> Op.UQSHL, getVdtVntShf2 b, oprSize
  | 0b110000u ->
    getOpcodeByQ b Op.SQSHRUN Op.SQSHRUN2, getVdtbVntaShf b immh1xxx, 64<rt>
  | 0b110001u ->
    getOpcodeByQ b Op.SQRSHRUN Op.SQRSHRUN2, getVdtbVntaShf b immh1xxx, 64<rt>
  | 0b110010u ->
    getOpcodeByQ b Op.UQSHRN Op.UQSHRN2, getVdtbVntaShf b immh1xxx, 64<rt>
  | 0b110011u ->
    getOpcodeByQ b Op.UQRSHRN Op.UQRSHRN2, getVdtbVntaShf b immh1xxx, 64<rt>
  | 0b110100u ->
    getOpcodeByQ b Op.USHLL Op.USHLL2, getVdtaVntbShf b immh1xxx, 64<rt>
  | 0b111100u -> Op.UCVTF, getVdtVntFbits b immhQ1, oprSize
  | 0b111111u -> Op.FCVTZU, getVdtVntFbits b immhQ1, oprSize
  | _ -> raise InvalidOpcodeException

/// Advanced SIMD vector x indexed element on page C4-354.
let parseAdvSIMDVecXIdxElem bin =
  let cond = concat (concat (pickBit bin 29u) (extract bin 23u 22u) 2)
                    (extract bin 15u 12u) 4 (* U:size:opcode *)
  match cond with
  | c when c &&& 0b0001110u = 0b0001110u -> unallocated ()
  | c when c &&& 0b1001111u = 0b0000000u -> unallocated ()
  | c when c &&& 0b1001111u = 0b0000010u ->
    getOpcodeByQ bin Op.SMLAL Op.SMLAL2, getVdtaVntbVmtsidx bin size0011, 64<rt>
  | c when c &&& 0b1001111u = 0b0000011u ->
    getOpcodeByQ bin Op.SQDMLAL Op.SQDMLAL2,
    getVdtaVntbVmtsidx bin size0011, 64<rt>
  | c when c &&& 0b1001111u = 0b0000100u -> unallocated ()
  | c when c &&& 0b1001111u = 0b0000110u ->
    getOpcodeByQ bin Op.SMLSL Op.SMLSL2, getVdtaVntbVmtsidx bin size0011, 64<rt>
  | c when c &&& 0b1001111u = 0b0000111u ->
    getOpcodeByQ bin Op.SQDMLSL Op.SQDMLSL2,
    getVdtaVntbVmtsidx bin size0011, 64<rt>
  | c when c &&& 0b1001111u = 0b0001000u ->
    Op.MUL, getVdtVntVmtsidx1 bin size0011, getOprSizeByQ bin
  | c when c &&& 0b1001111u = 0b0001010u ->
    getOpcodeByQ bin Op.SMULL Op.SMULL2, getVdtaVntbVmtsidx bin size0011, 64<rt>
  | c when c &&& 0b1001111u = 0b0001011u ->
    getOpcodeByQ bin Op.SQDMULL Op.SQDMULL2,
    getVdtaVntbVmtsidx bin size0011, 64<rt>
  | c when c &&& 0b1001111u = 0b0001100u ->
    Op.SQDMULH, getVdtVntVmtsidx1 bin size0011, getOprSizeByQ bin
  | c when c &&& 0b1001111u = 0b0001101u ->
    Op.SQRDMULH, getVdtVntVmtsidx1 bin size0011, getOprSizeByQ bin
  | c when c &&& 0b1101111u = 0b0100001u ->
    Op.FMLA, getVdtVntVmtsidx2 bin szL11, getOprSizeByQ bin
  | c when c &&& 0b1101111u = 0b0100101u ->
    Op.FMLS, getVdtVntVmtsidx2 bin szL11, getOprSizeByQ bin
  | c when c &&& 0b1101111u = 0b0101001u ->
    Op.FMUL, getVdtVntVmtsidx2 bin szL11, getOprSizeByQ bin
  | c when c &&& 0b1001111u = 0b1000000u ->
    Op.MLA, getVdtVntVmtsidx1 bin size0011, getOprSizeByQ bin
  | c when c &&& 0b1001111u = 0b1000010u ->
    getOpcodeByQ bin Op.UMLAL Op.UMLAL2, getVdtaVntbVmtsidx bin size0011, 64<rt>
  | c when c &&& 0b1001111u = 0b1000011u -> unallocated ()
  | c when c &&& 0b1001111u = 0b1000100u ->
    Op.MLS, getVdtVntVmtsidx1 bin size0011, getOprSizeByQ bin
  | c when c &&& 0b1001111u = 0b1000110u ->
    getOpcodeByQ bin Op.UMLSL Op.UMLSL2, getVdtaVntbVmtsidx bin size0011, 64<rt>
  | c when c &&& 0b1001111u = 0b1000111u -> unallocated ()
  | c when c &&& 0b1001111u = 0b1001000u -> unallocated ()
  | c when c &&& 0b1001111u = 0b1001010u ->
    getOpcodeByQ bin Op.UMULL Op.UMULL2, getVdtaVntbVmtsidx bin size0011, 64<rt>
  | c when c &&& 0b1001111u = 0b1001011u -> unallocated ()
  | c when c &&& 0b1001110u = 0b1001100u -> unallocated ()
  | c when c &&& 0b1101111u = 0b1100001u -> unallocated ()
  | c when c &&& 0b1101111u = 0b1100101u -> unallocated ()
  | c when c &&& 0b1101111u = 0b1101001u ->
    Op.FMULX, getVdtVntVmtsidx2 bin szL11, getOprSizeByQ bin
  | _ -> raise InvalidOpcodeException

/// Data processing - SIMD and FP - 1
let parse64Group5 bin =
  let cond = concat (concat (extract bin 31u 28u) (extract bin 24u 17u) 8)
                    (extract bin 15u 10u) 6 (* op0:op1:op2:op3:op4 *)
  match cond with
  | c when c &&& 0b111110011111000011u = 0b000000010100000010u -> unallocated ()
  | c when c &&& 0b111110011111000011u = 0b001000010100000010u -> unallocated ()
  | c when c &&& 0b111110011111000011u = 0b010000010100000010u ->
    parseCryptAES bin
  | c when c &&& 0b111110011111000011u = 0b011000010100000010u -> unallocated ()
  | c when c &&& 0b101110010000100011u = 0b000000000000000000u ->
    parseAdvSIMDTableLookup bin
  | c when c &&& 0b101110010000100011u = 0b000000000000000010u ->
    parseAdvSIMDPermute bin
  | c when c &&& 0b101110010000100001u = 0b001000000000000000u ->
    parseAdvSIMDExtract bin
  | c when c &&& 0b100111110000100001u = 0b000000000000000001u ->
    parseAdvSIMDCopy bin
  | c when c &&& 0b100111010000100001u = 0b000001000000000001u -> unallocated ()
  | c when c &&& 0b100110111111000011u = 0b000000011100000010u -> unallocated ()
  | c when c &&& 0b100110110000110001u = 0b000000100000010001u -> unallocated ()
  | c when c &&& 0b100110010000100000u = 0b000000000000100000u -> unallocated ()
  | c when c &&& 0b100110011111000011u = 0b000000010000000010u ->
    parseAdvSIMDTwoReg bin
  | c when c &&& 0b100110011111000011u = 0b000000011000000010u ->
    parseAdvSIMDAcrossLanes bin
  | c when c &&& 0b100110010010000011u = 0b000000010010000010u -> unallocated ()
  | c when c &&& 0b100110010001000011u = 0b000000010001000010u -> unallocated ()
  | c when c &&& 0b100110010000000011u = 0b000000010000000000u ->
    parseAdvSIMDThreeDiff bin
  | c when c &&& 0b100110010000000001u = 0b000000010000000001u ->
    parseAdvSIMDThreeSame bin
  | c when c &&& 0b100111111100000001u = 0b000010000000000001u ->
    parseAdvSIMDModImm bin
  | c when c &&& 0b100111000000000001u = 0b000010000000000001u &&
           extract c 11u 8u <> 0b0000u -> getAdvSIMDShfByImm bin
  | c when c &&& 0b100111000000000001u = 0b000011000000000001u -> unallocated ()
  | c when c &&& 0b100110000000000001u = 0b000010000000000000u ->
    parseAdvSIMDVecXIdxElem bin
  | c when c &&& 0b100100000000000000u = 0b100000000000000000u -> unallocated ()
  | _ -> raise InvalidOpcodeException

 /// Cryptographic three-register SHA on page C4-323.
let parseCryptThreeRegSHA bin =
  let cond = concat (extract bin 23u 22u) (extract bin 14u 12u) 3
  match cond with (* size:opcode *)
  | c when c &&& 0b00111u = 0b00111u -> unallocated ()
  | c when c &&& 0b01000u = 0b01000u -> unallocated ()
  | 0b00000u -> Op.SHA1C, getQdSnVm4S bin, 128<rt>
  | 0b00001u -> Op.SHA1P, getQdSnVm4S bin, 128<rt>
  | 0b00010u -> Op.SHA1M, getQdSnVm4S bin, 128<rt>
  | 0b00011u -> Op.SHA1SU0, getVd4SVn4SVm4S bin, 128<rt>
  | 0b00100u -> Op.SHA256H, getQdQnVm4S bin, 128<rt>
  | 0b00101u -> Op.SHA256H2, getQdQnVm4S bin, 128<rt>
  | 0b00110u -> Op.SHA256SU1, getVd4SVn4SVm4S bin, 128<rt>
  | _ -> raise InvalidOpcodeException

/// Cryptographic two-register SHA on page C4-324.
let parseCryptTwoRegSHA bin =
  let cond = concat (extract bin 23u 22u) (extract bin 16u 12u) 5
  match cond with (* size:opcode *)
  | c when c &&& 0b0000100u = 0b0000100u -> unallocated ()
  | c when c &&& 0b0001000u = 0b0001000u -> unallocated ()
  | c when c &&& 0b0010000u = 0b0010000u -> unallocated ()
  | c when c &&& 0b0100000u = 0b0100000u -> unallocated ()
  | 0b0000000u -> Op.SHA1H, getSdSn bin, 32<rt>
  | 0b0000001u -> Op.SHA1SU1, getVd4SVn4S bin, 128<rt>
  | 0b0000010u -> Op.SHA256SU0, getVd4SVn4S bin, 128<rt>
  | 0b0000011u -> unallocated ()
  | c when c &&& 0b1000000u = 0b1000000u -> unallocated ()
  | _ -> raise InvalidOpcodeException

/// This instruction is used by the alias MOV (scalar).
/// The alias is always the preferred disassembly.
let toAliasFromDUP _ = Op.MOV

/// Advanced SIMD scalar copy on page C4-325.
let parseAdvSIMDScalarCopy bin =
  let cond = concat (concat (pickBit bin 29u) (extract bin 20u 16u) 5)
                    (extract bin 14u 11u) 4 (* op:imm5:imm4 *)
  match cond with
  | c when c &&& 0b1000000001u = 0b0000000001u -> unallocated ()
  | c when c &&& 0b1000000010u = 0b0000000010u -> unallocated ()
  | c when c &&& 0b1000000100u = 0b0000000100u -> unallocated ()
  | c when c &&& 0b1000001111u = 0b0000000000u ->
    toAliasFromDUP Op.DUP, getVdVntidx bin, getOprSizeByQ bin
  | c when c &&& 0b1000001000u = 0b0000001000u -> unallocated ()
  | c when c &&& 0b1011111111u = 0b0000000000u -> unallocated ()
  | c when c &&& 0b1000000000u = 0b1000000000u -> unallocated ()
  | _ -> raise InvalidOpcodeException

 /// Advanced SIMD scalar two-register miscellaneous on page C4-328.
let parseAdvSIMDScalarTwoReg bin =
  let cond = concat (concat (extract bin 29u 29u) (extract bin 23u 22u) 2)
                    (extract bin 16u 12u) 5 (* U + size + opcode *)
  match cond with
  | c when c &&& 0b00011110u = 0b00000000u -> unallocated ()
  | c when c &&& 0b00011111u = 0b00000010u -> unallocated ()
  | c when c &&& 0b00011110u = 0b00000100u -> unallocated ()
  | c when c &&& 0b00011111u = 0b00000110u -> unallocated ()
  | c when c &&& 0b00011111u = 0b00001111u -> unallocated ()
  | c when c &&& 0b00011110u = 0b00010000u -> unallocated ()
  | c when c &&& 0b00011111u = 0b00010011u -> unallocated ()
  | c when c &&& 0b00011111u = 0b00010101u -> unallocated ()
  | c when c &&& 0b00011111u = 0b00010111u -> unallocated ()
  | c when c &&& 0b00011110u = 0b00011000u -> unallocated ()
  | c when c &&& 0b00011111u = 0b00011110u -> unallocated ()
  | c when c &&& 0b01011100u = 0b00001100u -> unallocated ()
  | c when c &&& 0b01011111u = 0b00011111u -> unallocated ()
  | c when c &&& 0b01011111u = 0b01010110u -> unallocated ()
  | c when c &&& 0b01011111u = 0b01011100u -> unallocated ()
  | c when c &&& 0b10011111u = 0b00000011u ->
    Op.SUQADD, getVdVn bin resNone, getOprSzBySize bin
  | c when c &&& 0b10011111u = 0b00000111u ->
    Op.SQABS, getVdVn bin resNone, getOprSzBySize bin
  | c when c &&& 0b10011111u = 0b00001000u ->
    Op.CMGT, getVdVnI0 bin size0x10, getOprSzBySize bin
  | c when c &&& 0b10011111u = 0b00001001u ->
    Op.CMEQ, getVdVnI0 bin size0x10, getOprSzBySize bin
  | c when c &&& 0b10011111u = 0b00001010u ->
    Op.CMLT, getVdVnI0 bin size0x10, getOprSzBySize bin
  | c when c &&& 0b10011111u = 0b00001011u ->
    Op.ABS, getVdVn bin size0x10, getOprSzBySize bin
  | c when c &&& 0b10011111u = 0b00010010u -> unallocated ()
  | c when c &&& 0b10011111u = 0b00010100u ->
    Op.SQXTN, getVbdVan bin size11, getOprSzBySize bin
  | c when c &&& 0b11011111u = 0b00010110u -> unallocated ()
  | c when c &&& 0b11011111u = 0b00011010u ->
    Op.FCVTNS, getVdVn2 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b00011011u ->
    Op.FCVTMS, getVdVn2 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b00011100u ->
    Op.FCVTAS, getVdVn2 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b00011101u ->
    Op.SCVTF, getVdVn2 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b01001100u ->
    Op.FCMGT, getVdVnF0 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b01001101u ->
    Op.FCMEQ, getVdVnF0 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b01001110u ->
    Op.FCMLT, getVdVnF0 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b01011010u ->
    Op.FCVTPS, getVdVn2 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b01011011u ->
    Op.FCVTZS, getVdVn2 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b01011101u ->
    Op.FRECPE, getVdVn2 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b01011111u ->
    Op.FRECPX, getVdVn2 bin, getOprSzBySz bin
  | c when c &&& 0b10011111u = 0b10000011u ->
    Op.USQADD, getVdVn bin resNone, getOprSzBySize bin
  | c when c &&& 0b10011111u = 0b10000111u ->
    Op.SQNEG, getVdVn bin resNone, getOprSzBySize bin
  | c when c &&& 0b10011111u = 0b10001000u ->
    Op.CMGE, getVdVnI0 bin size0x10, getOprSzBySize bin
  | c when c &&& 0b10011111u = 0b10001001u ->
    Op.CMLE, getVdVnI0 bin size0x10, getOprSzBySize bin
  | c when c &&& 0b10011111u = 0b10001010u -> unallocated ()
  | c when c &&& 0b10011111u = 0b10001011u ->
    Op.NEG, getVdVn bin size0x10, getOprSzBySize bin
  | c when c &&& 0b10011111u = 0b10010010u ->
    Op.SQXTUN, getVbdVan bin size11, getOprSzBySize bin
  | c when c &&& 0b10011111u = 0b10010100u ->
    Op.UQXTN, getVbdVan bin size11, getOprSzBySize bin
  | c when c &&& 0b11011111u = 0b10010110u ->
    Op.FCVTXN, getVbdVan2 bin sz0, 32<rt>
  | c when c &&& 0b11011111u = 0b10011010u ->
    Op.FCVTNU, getVdVn2 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b10011011u ->
    Op.FCVTMU, getVdVn2 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b10011100u ->
    Op.FCVTAU, getVdVn2 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b10011101u ->
    Op.UCVTF, getVdVn2 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b11001100u ->
    Op.FCMGE, getVdVnF0 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b11001101u ->
    Op.FCMLE, getVdVnF0 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b11001110u -> unallocated ()
  | c when c &&& 0b11011111u = 0b11011010u ->
    Op.FCVTPU, getVdVn2 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b11011011u ->
    Op.FCVTZU, getVdVn2 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b11011101u ->
    Op.FRSQRTE, getVdVn2 bin, getOprSzBySz bin
  | c when c &&& 0b11011111u = 0b11011111u -> unallocated ()
  | _ -> raise InvalidOpcodeException

/// Advanced SIMD scalar pairwise on page C4-330.
let parseAdvSIMDScalarPairwise bin =
  let cond = concat (concat (extract bin 29u 29u) (extract bin 23u 22u) 2)
                    (extract bin 16u 12u) 5 (* U:size:opcode *)
  match cond with
  | c when c &&& 0b00011000u = 0b00000000u -> unallocated ()
  | c when c &&& 0b00011100u = 0b00001000u -> unallocated ()
  | c when c &&& 0b00011111u = 0b00001110u -> unallocated ()
  | c when c &&& 0b00011000u = 0b00010000u -> unallocated ()
  | c when c &&& 0b00011110u = 0b00011000u -> unallocated ()
  | c when c &&& 0b00011111u = 0b00011010u -> unallocated ()
  | c when c &&& 0b00011100u = 0b00011100u -> unallocated ()
  | c when c &&& 0b01011111u = 0b01001101u -> unallocated ()
  | c when c &&& 0b10011111u = 0b00011011u ->
    Op.ADDP, getVdVnt4 bin size0x10, getOprSzBySize bin
  | c when c &&& 0b10011111u = 0b10011011u -> unallocated ()
  | c when c &&& 0b11011111u = 0b10001100u ->
    Op.FMAXNMP, getVdVnt5 bin, 64<rt>
  | c when c &&& 0b11011111u = 0b10001101u -> Op.FADDP, getVdVnt5 bin, 64<rt>
  | c when c &&& 0b11011111u = 0b10001111u -> Op.FMAXP, getVdVnt5 bin, 64<rt>
  | c when c &&& 0b11011111u = 0b11001100u -> Op.FMINNMP, getVdVnt5 bin, 64<rt>
  | c when c &&& 0b11011111u = 0b11001111u -> Op.FMINP, getVdVnt5 bin, 64<rt>
  | _ -> raise InvalidOpcodeException

let parseAdvSIMDScalarThreeDiff bin =
  let cond = concat (extract bin 29u 29u) (extract bin 15u 12u) 4
  match cond with
  | c when c &&& 0b01100u = 0b00000u -> unallocated ()
  | c when c &&& 0b01100u = 0b00100u -> unallocated ()
  | c when c &&& 0b01111u = 0b01000u -> unallocated ()
  | c when c &&& 0b01111u = 0b01010u -> unallocated ()
  | c when c &&& 0b01111u = 0b01100u -> unallocated ()
  | c when c &&& 0b01110u = 0b01110u -> unallocated ()
  | c when c &&& 0b11111u = 0b01001u ->
    Op.SQDMLAL, getVadVbnVbm bin size0011, getOprSzBySize bin
  | c when c &&& 0b11111u = 0b01011u ->
    Op.SQDMLSL, getVadVbnVbm bin size0011, getOprSzBySize bin
  | c when c &&& 0b11111u = 0b01101u ->
    Op.SQDMULL, getVadVbnVbm bin size0011, getOprSzBySize bin
  | c when c &&& 0b11111u = 0b11001u -> unallocated ()
  | c when c &&& 0b11111u = 0b11011u -> unallocated ()
  | c when c &&& 0b11111u = 0b11101u -> unallocated ()
  | _ -> raise InvalidOpcodeException

let parseAdvSIMDScalarThreeSame bin =
  let cond = concat (concat (extract bin 29u 29u) (extract bin 23u 22u) 2)
                    (extract bin 15u 11u) 5 (* U:size:opcode *)
  match cond with
  | c when c &&& 0b00011111u = 0b00000000u -> unallocated ()
  | c when c &&& 0b00011110u = 0b00000010u -> unallocated ()
  | c when c &&& 0b00011111u = 0b00000100u -> unallocated ()
  | c when c &&& 0b00011100u = 0b00001100u -> unallocated ()
  | c when c &&& 0b00011110u = 0b00010010u -> unallocated ()
  | c when c &&& 0b01011111u = 0b01011011u -> unallocated ()
  | c when c &&& 0b10011111u = 0b00000001u ->
    Op.SQADD, getVdVnVm1 bin resNone
  | c when c &&& 0b10011111u = 0b00000101u ->
    Op.SQSUB, getVdVnVm1 bin resNone
  | c when c &&& 0b10011111u = 0b00000110u ->
    Op.CMGT, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b00000111u ->
    Op.CMGE, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b00001000u ->
    Op.SSHL, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b00001001u ->
    Op.SQSHL, getVdVnVm1 bin resNone
  | c when c &&& 0b10011111u = 0b00001010u ->
    Op.SRSHL, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b00001011u ->
    Op.SQRSHL, getVdVnVm1 bin resNone
  | c when c &&& 0b10011111u = 0b00010000u ->
    Op.ADD, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b00010001u ->
    Op.CMTST, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b00010100u -> unallocated ()
  | c when c &&& 0b10011111u = 0b00010101u -> unallocated ()
  | c when c &&& 0b10011111u = 0b00010110u ->
    Op.SQDMULH, getVdVnVm1 bin size0011
  | c when c &&& 0b10011111u = 0b00010111u -> unallocated ()
  | c when c &&& 0b11011111u = 0b00011000u -> unallocated ()
  | c when c &&& 0b11011111u = 0b00011001u -> unallocated ()
  | c when c &&& 0b11011111u = 0b00011010u -> unallocated ()
  | c when c &&& 0b11011111u = 0b00011011u -> Op.FMULX, getVdVnVm2 bin
  | c when c &&& 0b11011111u = 0b00011100u -> Op.FCMEQ, getVdVnVm2 bin
  | c when c &&& 0b11011111u = 0b00011101u -> unallocated ()
  | c when c &&& 0b11011111u = 0b00011110u -> unallocated ()
  | c when c &&& 0b11011111u = 0b00011111u -> Op.FRECPS, getVdVnVm2 bin
  | c when c &&& 0b11011111u = 0b01011000u -> unallocated ()
  | c when c &&& 0b11011111u = 0b01011001u -> unallocated ()
  | c when c &&& 0b11011111u = 0b01011010u -> unallocated ()
  | c when c &&& 0b11011111u = 0b01011100u -> unallocated ()
  | c when c &&& 0b11011111u = 0b01011101u -> unallocated ()
  | c when c &&& 0b11011111u = 0b01011110u -> unallocated ()
  | c when c &&& 0b11011111u = 0b01011111u -> Op.FRSQRTS, getVdVnVm2 bin
  | c when c &&& 0b10011111u = 0b10000001u ->
    Op.UQADD, getVdVnVm1 bin resNone
  | c when c &&& 0b10011111u = 0b10000101u ->
    Op.UQSUB, getVdVnVm1 bin resNone
  | c when c &&& 0b10011111u = 0b10000110u ->
    Op.CMHI, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b10000111u ->
    Op.CMHS, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b10001000u ->
    Op.USHL, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b10001001u ->
    Op.UQSHL, getVdVnVm1 bin resNone
  | c when c &&& 0b10011111u = 0b10001010u ->
    Op.URSHL, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b10001011u ->
    Op.UQRSHL, getVdVnVm1 bin resNone
  | c when c &&& 0b10011111u = 0b10010000u ->
    Op.SUB, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b10010001u ->
    Op.CMEQ, getVdVnVm1 bin size0x10
  | c when c &&& 0b10011111u = 0b10010100u -> unallocated ()
  | c when c &&& 0b10011111u = 0b10010101u -> unallocated ()
  | c when c &&& 0b10011111u = 0b10010110u ->
    Op.SQRDMULH, getVdVnVm1 bin size0011
  | c when c &&& 0b10011111u = 0b10010111u -> unallocated ()
  | c when c &&& 0b11011111u = 0b10011000u -> unallocated ()
  | c when c &&& 0b11011111u = 0b10011001u -> unallocated ()
  | c when c &&& 0b11011111u = 0b10011010u -> unallocated ()
  | c when c &&& 0b11011111u = 0b10011011u -> unallocated ()
  | c when c &&& 0b11011111u = 0b10011100u -> Op.FCMGE, getVdVnVm2 bin
  | c when c &&& 0b11011111u = 0b10011101u -> Op.FACGE, getVdVnVm2 bin
  | c when c &&& 0b11011111u = 0b10011110u -> unallocated ()
  | c when c &&& 0b11011111u = 0b10011111u -> unallocated ()
  | c when c &&& 0b11011111u = 0b11011000u -> unallocated ()
  | c when c &&& 0b11011111u = 0b11011001u -> unallocated ()
  | c when c &&& 0b11011111u = 0b11011010u -> Op.FABD, getVdVnVm2 bin
  | c when c &&& 0b11011111u = 0b11011100u -> Op.FCMGT, getVdVnVm2 bin
  | c when c &&& 0b11011111u = 0b11011101u -> Op.FACGT, getVdVnVm2 bin
  | c when c &&& 0b11011111u = 0b11011110u -> unallocated ()
  | c when c &&& 0b11011111u = 0b11011111u -> unallocated ()
  | _ -> raise InvalidOpcodeException
  |> getSIMDScalarOprSize (extract bin 15u 14u) (valSize1 bin)

/// Advanced SIMD scalar shift by immediate on page C4-333.
let parseAdvSIMDScalarShiftByImm bin =
  let cond = concat (extract bin 29u 29u) (extract bin 15u 11u) 5 (* U:opcode *)
  let isImmhZero = (extract bin 22u 19u) = 0b0000u
  if isImmhZero then unallocated ()
  match cond with
  | c when c &&& 0b011111u = 0b000001u -> unallocated ()
  | c when c &&& 0b011111u = 0b000011u -> unallocated ()
  | c when c &&& 0b011111u = 0b000101u -> unallocated ()
  | c when c &&& 0b011111u = 0b000111u -> unallocated ()
  | c when c &&& 0b011111u = 0b001001u -> unallocated ()
  | c when c &&& 0b011111u = 0b001011u -> unallocated ()
  | c when c &&& 0b011111u = 0b001101u -> unallocated ()
  | c when c &&& 0b011111u = 0b001111u -> unallocated ()
  | c when c &&& 0b011100u = 0b010100u -> unallocated ()
  | c when c &&& 0b011111u = 0b011001u -> unallocated ()
  | c when c &&& 0b011111u = 0b011010u -> unallocated ()
  | c when c &&& 0b011111u = 0b011101u -> unallocated ()
  | c when c &&& 0b011111u = 0b011110u -> unallocated ()
  | 0b000000u -> Op.SSHR, getVdVnShf bin immh0xxx, 64<rt>
  | 0b000010u -> Op.SSRA, getVdVnShf bin immh0xxx, 64<rt>
  | 0b000100u -> Op.SRSHR, getVdVnShf bin immh0xxx, 64<rt>
  | 0b000110u -> Op.SRSRA, getVdVnShf bin immh0xxx, 64<rt>
  | 0b001000u -> unallocated ()
  | 0b001010u -> Op.SHL, getVdVnShf2 bin immh0xxx, 64<rt>
  | 0b001100u -> unallocated ()
  | 0b001110u -> Op.SQSHL, getVdVnShf2 bin immh0000, getOprSzByHSB bin
  | 0b010000u -> unallocated ()
  | 0b010001u -> unallocated ()
  | 0b010010u -> Op.SQSHRN, getVbdVanShf bin immh00001xxx, getOprSzByHSB bin
  | 0b010011u -> Op.SQRSHRN, getVbdVanShf bin immh00001xxx, getOprSzByHSB bin
  | 0b011100u -> Op.SCVTF, getVdVnFbits bin immh00xx, getOprSzByImmh bin
  | 0b011111u -> Op.FCVTZS, getVdVnFbits bin immh00xx, getOprSzByImmh bin
  | 0b100000u -> Op.USHR, getVdVnShf bin immh0xxx, 64<rt>
  | 0b100010u -> Op.USRA, getVdVnShf bin immh0xxx, 64<rt>
  | 0b100100u -> Op.URSHR, getVdVnShf bin immh0xxx, 64<rt>
  | 0b100110u -> Op.URSRA, getVdVnShf bin immh0xxx, 64<rt>
  | 0b101000u -> Op.SRI, getVdVnShf bin immh0xxx, 64<rt>
  | 0b101010u -> Op.SLI, getVdVnShf2 bin immh0xxx, 64<rt>
  | 0b101100u -> Op.SQSHLU, getVdVnShf2 bin immh0000, getOprSzByHSB bin
  | 0b101110u -> Op.UQSHL, getVdVnShf2 bin immh0000, getOprSzByHSB bin
  | 0b110000u -> Op.SQSHRUN, getVbdVanShf bin immh00001xxx, getOprSzByHSB bin
  | 0b110001u -> Op.SQRSHRUN, getVbdVanShf bin immh00001xxx, getOprSzByHSB bin
  | 0b110010u -> Op.UQSHRN, getVbdVanShf bin immh00001xxx, getOprSzByHSB bin
  | 0b110011u -> Op.UQRSHRN, getVbdVanShf bin immh00001xxx, getOprSzByHSB bin
  | 0b111100u -> Op.UCVTF, getVdVnFbits bin immh00xx, getOprSzByImmh bin
  | 0b111111u -> Op.FCVTZU, getVdVnFbits bin immh00xx, getOprSzByImmh bin
  | _ -> raise InvalidOpcodeException

/// Advanced SIMD scalar x indexed element on page C4-335.
let parseAdvSIMDScalarXIdxElem b =
  let cond = concat (concat (extract b 29u 29u) (extract b 23u 22u) 2)
                    (extract b 15u 12u) 4 (* U:size:opcode *)
  match cond with
  | c when c &&& 0b0001111u = 0b0000000u -> unallocated ()
  | c when c &&& 0b0001111u = 0b0000100u -> unallocated ()
  | c when c &&& 0b0001111u = 0b0000100u -> unallocated ()
  | c when c &&& 0b0001111u = 0b0000110u -> unallocated ()
  | c when c &&& 0b0001111u = 0b0001000u -> unallocated ()
  | c when c &&& 0b0001111u = 0b0001010u -> unallocated ()
  | c when c &&& 0b0001110u = 0b0001110u -> unallocated ()
  | c when c &&& 0b1001111u = 0b0000011u ->
    Op.SQDMLAL, getVadVbnVmtsidx b size0011, getOprSzBySize b
  | c when c &&& 0b1001111u = 0b0000111u ->
    Op.SQDMLSL, getVadVbnVmtsidx b size0011, getOprSzBySize b
  | c when c &&& 0b1001111u = 0b0001011u ->
    Op.SQDMULL, getVadVbnVmtsidx b size0011, getOprSzBySize b
  | c when c &&& 0b1001111u = 0b0001100u ->
    Op.SQDMULH, getVdVnVmtsidx1 b size0011, getOprSzBySize b
  | c when c &&& 0b1001111u = 0b0001101u ->
    Op.SQRDMULH, getVdVnVmtsidx1 b size0011, getOprSzBySize b
  | c when c &&& 0b1101111u = 0b0100001u ->
    Op.FMLA, getVdVnVmtsidx2 b szL11, getOprSzBySz b
  | c when c &&& 0b1101111u = 0b0100101u ->
    Op.FMLS, getVdVnVmtsidx2 b szL11, getOprSzBySize b
  | c when c &&& 0b1101111u = 0b0101001u ->
    Op.FMUL, getVdVnVmtsidx2 b szL11, getOprSzBySize b
  | c when c &&& 0b1001111u = 0b1000011u -> unallocated ()
  | c when c &&& 0b1001111u = 0b1000111u -> unallocated ()
  | c when c &&& 0b1001111u = 0b1001011u -> unallocated ()
  | c when c &&& 0b1001110u = 0b1001100u -> unallocated ()
  | c when c &&& 0b1101111u = 0b1100001u -> unallocated ()
  | c when c &&& 0b1101111u = 0b1100101u -> unallocated ()
  | c when c &&& 0b1101111u = 0b1101001u ->
    Op.FMULX, getVdVnVmtsidx2 b szL11, getOprSzBySize b
  | _ -> raise InvalidOpcodeException

let parseConvBetwFPAndFixedPt bin =
  let cond = (* sf:S:type:rmode:opcode *)
    (pickBit bin 31u <<< 8) ||| (pickBit bin 29u <<< 7) |||
    (extract bin 23u 22u <<< 5) ||| (extract bin 20u 16u)
  match cond with
  | c when c &&& 0b000000100u = 0b000000100u -> unallocated ()
  | c when c &&& 0b000001110u = 0b000000000u -> unallocated ()
  | c when c &&& 0b000001110u = 0b000001010u -> unallocated ()
  | c when c &&& 0b000010110u = 0b000000000u -> unallocated ()
  | c when c &&& 0b000010110u = 0b000010010u -> unallocated ()
  | c when c &&& 0b001100000u = 0b001000000u -> unallocated ()
  | c when c &&& 0b010000000u = 0b010000000u -> unallocated ()
  | c when c &&& 0b100000000u = 0b000000000u &&
           (extract bin 15u 10u) >>> 5 = 0b0u -> unallocated ()
  | 0b000000010u -> Op.SCVTF, getSdWnFbits bin, 32<rt>
  | 0b000000011u -> Op.UCVTF, getSdWnFbits bin, 32<rt>
  | 0b000011000u -> Op.FCVTZS, getWdSnFbits bin, 32<rt>
  | 0b000011001u -> Op.FCVTZU, getWdSnFbits bin, 32<rt>
  | 0b000100010u -> Op.SCVTF, getDdWnFbits bin, 64<rt>
  | 0b000100011u -> Op.UCVTF, getDdWnFbits bin, 64<rt>
  | 0b000111000u -> Op.FCVTZS, getWdDnFbits bin, 32<rt>
  | 0b000111001u -> Op.FCVTZU, getWdDnFbits bin, 32<rt>
  | 0b001100010u -> Op.SCVTF, getHdWnFbits bin, 32<rt> (* FEAT_FP16 *)
  | 0b100000010u -> Op.SCVTF, getSdXnFbits bin, 32<rt>
  | 0b100000011u -> Op.UCVTF, getSdXnFbits bin, 32<rt>
  | 0b100011000u -> Op.FCVTZS, getXdSnFbits bin, 64<rt>
  | 0b100011001u -> Op.FCVTZU, getXdSnFbits bin, 64<rt>
  | 0b100100010u -> Op.SCVTF, getDdXnFbits bin, 64<rt>
  | 0b100100011u -> Op.UCVTF, getDdXnFbits bin, 64<rt>
  | 0b100111000u -> Op.FCVTZS, getXdDnFbits bin, 64<rt>
  | 0b100111001u -> Op.FCVTZU, getXdDnFbits bin, 64<rt>
  | 0b101100010u -> Opcode.SCVTF, getHdXnFbits bin, 64<rt> (* FEAT_FP16 *)
  | _ -> raise InvalidOpcodeException

/// Conversion between floating-point and integer on page C4-359.
let parseConvBetwFPAndInt bin =
  let cond = (* sf:S:type:rmode:opcode *)
    (pickBit bin 31u <<< 8) ||| (pickBit bin 29u <<< 7) |||
    (extract bin 23u 22u <<< 5) ||| (extract bin 20u 16u)
  match cond with
  | c when c &&& 0b000001110u = 0b000001010u -> unallocated ()
  | c when c &&& 0b000001110u = 0b000001100u -> unallocated ()
  | c when c &&& 0b000010110u = 0b000010010u -> unallocated ()
  | c when c &&& 0b000010110u = 0b000010100u -> unallocated ()
  | c when c &&& 0b011100100u = 0b001000000u -> unallocated ()
  | c when c &&& 0b011100110u = 0b001000100u -> unallocated ()
  | c when c &&& 0b010000000u = 0b010000000u -> unallocated ()
  | c when c &&& 0b111101110u = 0b000001110u -> unallocated ()
  | 0b000000000u -> Op.FCVTNS, getWdSn bin, 32<rt>
  | 0b000000001u -> Op.FCVTNU, getWdSn bin, 32<rt>
  | 0b000000010u -> Op.SCVTF, getSdWn bin, 32<rt>
  | 0b000000011u -> Op.UCVTF, getSdWn bin, 32<rt>
  | 0b000000100u -> Op.FCVTAS, getWdSn bin, 32<rt>
  | 0b000000101u -> Op.FCVTAU, getWdSn bin, 32<rt>
  | 0b000000110u -> Op.FMOV, getWdSn bin, 32<rt>
  | 0b000000111u -> Op.FMOV, getSdWn bin, 32<rt>
  | 0b000001000u -> Op.FCVTPS, getWdSn bin, 32<rt>
  | 0b000001001u -> Op.FCVTPU, getWdSn bin, 32<rt>
  | c when c &&& 0b111110110u = 0b000010110u -> unallocated ()
  | 0b000010000u -> Op.FCVTMS, getWdSn bin, 32<rt>
  | 0b000010001u -> Op.FCVTMU, getWdSn bin, 32<rt>
  | 0b000011000u -> Op.FCVTZS, getWdSn bin, 32<rt>
  | 0b000011001u -> Op.FCVTZU, getWdSn bin, 32<rt>
  | c when c &&& 0b111100110u = 0b000100110u -> unallocated ()
  | 0b000100000u -> Op.FCVTNS, getWdDn bin, 32<rt>
  | 0b000100001u -> Op.FCVTNU, getWdDn bin, 32<rt>
  | 0b000100010u -> Op.SCVTF, getDdWn bin, 64<rt>
  | 0b000100011u -> Op.UCVTF, getDdWn bin, 64<rt>
  | 0b000100100u -> Op.FCVTAS, getWdDn bin, 32<rt>
  | 0b000100101u -> Op.FCVTAU, getWdDn bin, 32<rt>
  | 0b000101000u -> Op.FCVTPS, getWdDn bin, 32<rt>
  | 0b000101001u -> Op.FCVTPU, getWdDn bin, 32<rt>
  | 0b000110000u -> Op.FCVTMS, getWdDn bin, 32<rt>
  | 0b000110001u -> Op.FCVTMU, getWdDn bin, 32<rt>
  | 0b000111000u -> Op.FCVTZS, getWdDn bin, 32<rt>
  | 0b000111001u -> Op.FCVTZU, getWdDn bin, 32<rt>
  | c when c &&& 0b111100110u = 0b001000110u -> unallocated ()
  | 0b001100010u -> Opcode.SCVTF, getHdWn bin, 32<rt> (* FEAT_FP16 *)
  | c when c &&& 0b111100110u = 0b100000110u -> unallocated ()
  | 0b100000000u -> Op.FCVTNS, getXdSn bin, 64<rt>
  | 0b100000001u -> Op.FCVTNU, getXdSn bin, 64<rt>
  | 0b100000010u -> Op.SCVTF, getSdXn bin, 32<rt>
  | 0b100000011u -> Op.UCVTF, getSdXn bin, 32<rt>
  | 0b100000100u -> Op.FCVTAS, getXdSn bin, 64<rt>
  | 0b100000101u -> Op.FCVTAU, getXdSn bin, 64<rt>
  | 0b100001000u -> Op.FCVTPS, getXdSn bin, 64<rt>
  | 0b100001001u -> Op.FCVTPU, getXdSn bin, 64<rt>
  | 0b100010000u -> Op.FCVTMS, getXdSn bin, 64<rt>
  | 0b100010001u -> Op.FCVTMU, getXdSn bin, 64<rt>
  | 0b100011000u -> Op.FCVTZS, getXdSn bin, 64<rt>
  | 0b100011001u -> Op.FCVTZU, getXdSn bin, 64<rt>
  | c when c &&& 0b111101110u = 0b100101110u -> unallocated ()
  | 0b100100000u -> Op.FCVTNS, getXdDn bin, 64<rt>
  | 0b100100001u -> Op.FCVTNU, getXdDn bin, 64<rt>
  | 0b100100010u -> Op.SCVTF, getDdXn bin, 64<rt>
  | 0b100100011u -> Op.UCVTF, getDdXn bin, 64<rt>
  | 0b100100100u -> Op.FCVTAS, getXdDn bin, 64<rt>
  | 0b100100101u -> Op.FCVTAU, getXdDn bin, 64<rt>
  | 0b100100110u -> Op.FMOV, getXdDn bin, 64<rt>
  | 0b100100111u -> Op.FMOV, getDdXn bin, 64<rt>
  | 0b100101000u -> Op.FCVTPS, getXdDn bin, 64<rt>
  | 0b100101001u -> Op.FCVTPU, getXdDn bin, 64<rt>
  | c when c &&& 0b111110110u = 0b100110110u -> unallocated ()
  | 0b100110000u -> Op.FCVTMS, getXdDn bin, 64<rt>
  | 0b100110001u -> Op.FCVTMU, getXdDn bin, 64<rt>
  | 0b100111000u -> Op.FCVTZS, getXdDn bin, 64<rt>
  | 0b100111001u -> Op.FCVTZU, getXdDn bin, 64<rt>
  | c when c &&& 0b111101110u = 0b101000110u -> unallocated ()
  | 0b101001110u -> Op.FMOV, getXdVnD1 bin, 64<rt>
  | 0b101001111u -> Op.FMOV, getVdD1Xn bin, 128<rt>
  | c when c &&& 0b111110110u = 0b101010110u -> unallocated ()
  | 0b101100010u -> Op.SCVTF, getHdXn bin, 64<rt> (* FEAT_FP16 *)
  | _ -> raise InvalidOpcodeException

/// Floating-point data-processing (1 source) on page C4-362.
let parseFPDP1Src bin =
  let cond = (* M:S:type:opcode *)
    (pickBit bin 31u <<< 9) ||| (pickBit bin 29u <<< 8) |||
    (extract bin 23u 22u <<< 6) ||| (extract bin 20u 15u)
  match cond with
  | c when c &&& 0b0000010000u = 0b0000010000u -> unallocated ()
  | c when c &&& 0b0000100000u = 0b0000100000u -> unallocated ()
  | c when c &&& 0b0100000000u = 0b0100000000u -> unallocated ()
  | 0b0000000000u -> Op.FMOV, getSdSn bin, 32<rt>
  | 0b0000000001u -> Op.FABS, getSdSn bin, 32<rt>
  | 0b0000000010u -> Op.FNEG, getSdSn bin, 32<rt>
  | 0b0000000011u -> Op.FSQRT, getSdSn bin, 32<rt>
  | 0b0000000100u -> unallocated ()
  | 0b0000000101u -> Op.FCVT, getDdSn bin, 64<rt>
  | 0b0000000110u -> unallocated ()
  | 0b0000000111u -> Op.FCVT, getHdSn bin, 16<rt>
  | 0b0000001000u -> Op.FRINTN, getSdSn bin, 32<rt>
  | 0b0000001001u -> Op.FRINTP, getSdSn bin, 32<rt>
  | 0b0000001010u -> Op.FRINTM, getSdSn bin, 32<rt>
  | 0b0000001011u -> Op.FRINTZ, getSdSn bin, 32<rt>
  | 0b0000001100u -> Op.FRINTA, getSdSn bin, 32<rt>
  | 0b0000001101u -> unallocated ()
  | 0b0000001110u -> Op.FRINTX, getSdSn bin, 32<rt>
  | 0b0000001111u -> Op.FRINTI, getSdSn bin, 32<rt>
  | 0b0001000000u -> Op.FMOV, getDdDn bin, 64<rt>
  | 0b0001000001u -> Op.FABS, getDdDn bin, 64<rt>
  | 0b0001000010u -> Op.FNEG, getDdDn bin, 64<rt>
  | 0b0001000011u -> Op.FSQRT, getDdDn bin, 64<rt>
  | 0b0001000100u -> Op.FCVT, getSdDn bin, 32<rt>
  | 0b0001000101u -> unallocated ()
  | 0b0001000110u -> unallocated ()
  | 0b0001000111u -> Op.FCVT, getHdDn bin, 16<rt>
  | 0b0001001000u -> Op.FRINTN, getDdDn bin, 64<rt>
  | 0b0001001001u -> Op.FRINTP, getDdDn bin, 64<rt>
  | 0b0001001010u -> Op.FRINTM, getDdDn bin, 64<rt>
  | 0b0001001011u -> Op.FRINTZ, getDdDn bin, 64<rt>
  | 0b0001001100u -> Op.FRINTA, getDdDn bin, 64<rt>
  | 0b0001001101u -> unallocated ()
  | 0b0001001110u -> Op.FRINTX, getDdDn bin, 64<rt>
  | 0b0001001111u -> Op.FRINTI, getDdDn bin, 64<rt>
  | c when c &&& 0b1111110000u = 0b0010000000u -> unallocated ()
  | 0b0011000100u -> Op.FCVT, getSdHn bin, 32<rt>
  | 0b0011000101u -> Op.FCVT, getDdHn bin, 64<rt>
  | c when c &&& 0b1111111110u = 0b0011000110u -> unallocated ()
  | 0b0011001101u -> unallocated ()
  | c when c &&& 0b1000000000u = 0b1000000000u -> unallocated ()
  | _ -> raise InvalidOpcodeException

/// Floating-point compare on page C4-365.
let parseFPCompare bin =
  let cond = (* M:S:type:op:opcode2 *)
    (pickBit bin 31u <<< 10) ||| (pickBit bin 29u <<< 9) |||
    (extract bin 23u 22u <<< 7) ||| (extract bin 15u 14u <<< 5) |||
    (extract bin 4u 0u)
  match cond with
  | c when c &&& 0b00000000001u = 0b00000000001u -> unallocated ()
  | c when c &&& 0b00000000010u = 0b00000000010u -> unallocated ()
  | c when c &&& 0b00000000100u = 0b00000000100u -> unallocated ()
  | c when c &&& 0b00000100000u = 0b00000100000u -> unallocated ()
  | c when c &&& 0b00001000000u = 0b00001000000u -> unallocated ()
  | c when c &&& 0b00110000000u = 0b00100000000u -> unallocated ()
  | c when c &&& 0b01000000000u = 0b01000000000u -> unallocated ()
  | 0b00000000000u -> Op.FCMP, getSnSm bin, 32<rt>
  | 0b00000001000u -> Op.FCMP, getSnP0 bin, 32<rt>
  | 0b00000010000u -> Op.FCMPE, getSnSm bin, 32<rt>
  | 0b00000011000u -> Op.FCMPE, getSnP0 bin, 32<rt>
  | 0b00010000000u -> Op.FCMP, getDnDm bin, 64<rt>
  | 0b00010001000u -> Op.FCMP, getDnP0 bin, 64<rt>
  | 0b00010010000u -> Op.FCMPE, getDnDm bin, 64<rt>
  | 0b00010011000u -> Op.FCMPE, getDnP0 bin, 64<rt>
  | c when c &&& 0b10000000000u = 0b10000000000u -> unallocated ()
  | _ -> raise InvalidOpcodeException

/// Floating-point immediate on page C4-366.
let parseFPImm bin =
  let cond = (* M:S:type:imm5 *)
    (pickBit bin 31u <<< 8) ||| (pickBit bin 29u <<< 7) |||
    (extract bin 23u 22u <<< 5) ||| (extract bin 9u 5u)
  match cond with
  | c when c &&& 0b000000001u = 0b000000001u -> unallocated ()
  | c when c &&& 0b000000010u = 0b000000010u -> unallocated ()
  | c when c &&& 0b000000100u = 0b000000100u -> unallocated ()
  | c when c &&& 0b000001000u = 0b000001000u -> unallocated ()
  | c when c &&& 0b000010000u = 0b000010000u -> unallocated ()
  | c when c &&& 0b001100000u = 0b001000000u -> unallocated ()
  | c when c &&& 0b010000000u = 0b010000000u -> unallocated ()
  | 0b000000000u -> Op.FMOV, getSdImm8 bin, 32<rt>
  | 0b000100000u -> Op.FMOV, getDdImm8 bin, 64<rt>
  | c when c &&& 0b100000000u = 0b100000000u -> unallocated ()
  | _ -> raise InvalidOpcodeException

/// Floating-point conditional compare on page C4-366.
let parseFPCondComp bin =
  let cond = (* M:S:type:op *)
    (pickBit bin 31u <<< 4) ||| (pickBit bin 29u <<< 3) |||
    (extract bin 23u 22u <<< 1) ||| (pickBit bin 4u)
  match cond with
  | c when c &&& 0b00110u = 0b00100u -> unallocated ()
  | c when c &&& 0b01000u = 0b01000u -> unallocated ()
  | 0b00000u -> Op.FCCMP, getSnSmNZCVCond bin, 32<rt>
  | 0b00001u -> Op.FCCMPE, getSnSmNZCVCond bin, 32<rt>
  | 0b00010u -> Op.FCCMP, getDnDmNZCVCond bin, 64<rt>
  | 0b00011u -> Op.FCCMPE, getDnDmNZCVCond bin, 64<rt>
  | c when c &&& 0b10000u = 0b10000u -> unallocated ()
  | _ -> raise InvalidOpcodeException

/// Floating-point data-processing (2 source) on page C4-367.
let parseFPDP2Src bin =
  let cond = (* M:S:type:opcode *)
    (pickBit bin 31u <<< 7) ||| (pickBit bin 29u <<< 6) |||
    (extract bin 23u 22u <<< 4) ||| (extract bin 15u 12u)
  match cond with
  | c when c &&& 0b00001001u = 0b00001001u -> unallocated ()
  | c when c &&& 0b00001010u = 0b00001010u -> unallocated ()
  | c when c &&& 0b00001100u = 0b00001100u -> unallocated ()
  | c when c &&& 0b00110000u = 0b00100000u -> unallocated ()
  | c when c &&& 0b01000000u = 0b01000000u -> unallocated ()
  | 0b00000000u -> Op.FMUL, getSdSnSm bin, 32<rt>
  | 0b00000001u -> Op.FDIV, getSdSnSm bin, 32<rt>
  | 0b00000010u -> Op.FADD, getSdSnSm bin, 32<rt>
  | 0b00000011u -> Op.FSUB, getSdSnSm bin, 32<rt>
  | 0b00000100u -> Op.FMAX, getSdSnSm bin, 32<rt>
  | 0b00000101u -> Op.FMIN, getSdSnSm bin, 32<rt>
  | 0b00000110u -> Op.FMAXNM, getSdSnSm bin, 32<rt>
  | 0b00000111u -> Op.FMINNM, getSdSnSm bin, 32<rt>
  | 0b00001000u -> Op.FNMUL, getSdSnSm bin, 32<rt>
  | 0b00010000u -> Op.FMUL, getDdDnDm bin, 64<rt>
  | 0b00010001u -> Op.FDIV, getDdDnDm bin, 64<rt>
  | 0b00010010u -> Op.FADD, getDdDnDm bin, 64<rt>
  | 0b00010011u -> Op.FSUB, getDdDnDm bin, 64<rt>
  | 0b00010100u -> Op.FMAX, getDdDnDm bin, 64<rt>
  | 0b00010101u -> Op.FMIN, getDdDnDm bin, 64<rt>
  | 0b00010110u -> Op.FMAXNM, getDdDnDm bin, 64<rt>
  | 0b00010111u -> Op.FMINNM, getDdDnDm bin, 64<rt>
  | 0b00011000u -> Op.FNMUL, getDdDnDm bin, 64<rt>
  | c when c &&& 0b10000000u = 0b10000000u -> unallocated ()
  | _ -> raise InvalidOpcodeException

/// Floating-point conditional select on page C4-368.
let parseFPCondSelect bin =
  let cond = concat (concat (pickBit bin 31u) (pickBit bin 29u) 1)
                    (extract bin 23u 22u) 2 (* M:S:type *)
  match cond with
  | c when c &&& 0b0011u = 0b0010u -> unallocated ()
  | c when c &&& 0b0100u = 0b0100u -> unallocated ()
  | 0b0000u -> Op.FCSEL, getSdSnSmCond bin, 32<rt>
  | 0b0001u -> Op.FCSEL, getDdDnDmCond bin, 64<rt>
  | c when c &&& 0b1000u = 0b1000u -> unallocated ()
  | _ -> raise InvalidOpcodeException

/// Floating-point data-processing (3 source) on page C4-369.
let parseFPDP3Src bin =
  let cond = (* M:S:o1:o0 *)
    (pickBit bin 31u <<< 5) ||| (pickBit bin 29u <<< 4) |||
    (extract bin 23u 21u <<< 1) ||| (pickBit bin 15u)
  match cond with
  | c when c &&& 0b001100u = 0b001000u -> unallocated ()
  | c when c &&& 0b010000u = 0b010000u -> unallocated ()
  | 0b000000u -> Op.FMADD, getSdSnSmSa bin, 32<rt>
  | 0b000001u -> Op.FMSUB, getSdSnSmSa bin, 32<rt>
  | 0b000010u -> Op.FNMADD, getSdSnSmSa bin, 32<rt>
  | 0b000011u -> Op.FNMSUB, getSdSnSmSa bin, 32<rt>
  | 0b000100u -> Op.FMADD, getDdDnDmDa bin, 64<rt>
  | 0b000101u -> Op.FMSUB, getDdDnDmDa bin, 64<rt>
  | 0b000110u -> Op.FNMADD, getDdDnDmDa bin, 64<rt>
  | 0b000111u -> Op.FNMSUB, getDdDnDmDa bin, 64<rt>
  | c when c &&& 0b100000u = 0b100000u -> unallocated ()
  | _ -> raise InvalidOpcodeException

/// Data processing - SIMD and FP - 2
let parse64Group6 bin =
  let cond = concat (concat (extract bin 31u 28u) (extract bin 24u 17u) 8)
                    (extract bin 15u 10u) 6 (* op0:op1:op2:op3:op4 *)
  match cond with
  | c when c &&& 0b111110010000100011u = 0b010100000000000000u ->
    parseCryptThreeRegSHA bin
  | c when c &&& 0b111110010000100011u = 0b010100000000000010u -> unallocated ()
  | c when c &&& 0b111110011111000011u = 0b010100010100000010u ->
    parseCryptTwoRegSHA bin
  | c when c &&& 0b111110010000100001u = 0b011100000000000000u -> unallocated ()
  | c when c &&& 0b111110011111000011u = 0b011100010100000010u -> unallocated ()
  | c when c &&& 0b110111110000100001u = 0b010100000000000001u ->
    parseAdvSIMDScalarCopy bin
  | c when c &&& 0b110111010000100001u = 0b010101000000000001u -> unallocated ()
  | c when c &&& 0b110110111111000011u = 0b010100011100000010u -> unallocated ()
  | c when c &&& 0b110110011111000011u = 0b010100010000000010u ->
    parseAdvSIMDScalarTwoReg bin
  | c when c &&& 0b110110011111000011u = 0b010100011000000010u ->
    parseAdvSIMDScalarPairwise bin
  | c when c &&& 0b110110010010000011u = 0b010100010010000010u -> unallocated ()
  | c when c &&& 0b110110010001000011u = 0b010100010001000010u -> unallocated ()
  | c when c &&& 0b110110010000000011u = 0b010100010000000000u ->
    parseAdvSIMDScalarThreeDiff bin
  | c when c &&& 0b110110010000000001u = 0b010100010000000001u ->
    parseAdvSIMDScalarThreeSame bin
  | c when c &&& 0b110111000000000001u = 0b010110000000000001u ->
    parseAdvSIMDScalarShiftByImm bin
  | c when c &&& 0b110111000000000001u = 0b010111000000000001u -> unallocated ()
  | c when c &&& 0b110110000000000001u = 0b010110000000000000u ->
    parseAdvSIMDScalarXIdxElem bin
  | c when c &&& 0b110100000000000000u = 0b110100000000000000u -> unallocated ()
  | c when c &&& 0b010110010000000000u = 0b000100000000000000u ->
    parseConvBetwFPAndFixedPt bin
  | c when c &&& 0b010110010000111111u = 0b000100010000000000u ->
    parseConvBetwFPAndInt bin
  | c when c &&& 0b010110010000111111u = 0b000100010000100000u -> unallocated ()
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
  | op0 when op0 &&& 0b1100u = 0b0000u -> unallocated ()
  (* Data Processing -- Immediate on page C4-266 *)
  | op0 when op0 &&& 0b1110u = 0b1000u -> parse64Group1 bin
  (* Branches, Exception Generating and System instructions on page C4-271 *)
  | op0 when op0 &&& 0b1110u = 0b1010u -> parse64Group2 bin
  (* Loads and Stores on page C4-279 *)
  | op0 when op0 &&& 0b0101u = 0b0100u -> parse64Group3 bin
  (* Data Processing -- Register on page C4-310 *)
  | op0 when op0 &&& 0b0111u = 0b0101u -> parse64Group4 bin
  (* Data processing - SIMD and floating point *)
  | op0 when op0 &&& 0b1111u = 0b0111u -> parse64Group5 bin
  (* Data processing - SIMD and floating point *)
  | op0 when op0 &&& 0b1111u = 0b1111u -> parse64Group6 bin
  | _ -> raise InvalidOpcodeException

let parse lifter (span: ByteSpan) (reader: IBinReader) addr =
  let bin = reader.ReadUInt32(span, 0)
  let opcode, operands, oprSize = parseByGroupOfB64 bin
  Instruction(addr, 4u, None, opcode, operands, oprSize, lifter)

// vim: set tw=80 sts=2 sw=2:

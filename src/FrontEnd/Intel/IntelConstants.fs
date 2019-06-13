(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Seung Il Jung <sijung@kaist.ac.kr>

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

module internal B2R2.FrontEnd.Intel.Constants

(*
type OperandDesc
ODImmOne
+---------+-------------------------------------+
| 0 0 0 1 |           0 (12bit)                 |
+---------+-------------------------------------+
ODModeSize
+---------+-------------------------------------+
| 0 0 1 0 |    size (6bit)   |   mode (6bit)    |
+---------+-------------------------------------+
ODReg
+---------+-------------------------------------+
| 0 0 1 1 |       Register ID (12bit)           |
+---------+-------------------------------------+
ODRegGrp
+---------+------------+-----------+------------+
| 0 1 0 0 | size(6bit) | grp(3bit) | attr(3bit) |
+---------+------------+-----------+------------+
*)

let [<Literal>] _Ib = 0x208aL
let [<Literal>] _SIb = 0x208bL
let [<Literal>] _SIz = 0x280bL
let [<Literal>] Ap = 0x2381000000000000L
let [<Literal>] Dd = 0x2106000000000000L
let [<Literal>] E0v = 0x26dc000000000000L
let [<Literal>] Eb = 0x2087000000000000L
let [<Literal>] Ep = 0x2387000000000000L
let [<Literal>] Ev = 0x26c7000000000000L
let [<Literal>] Ew = 0x2707000000000000L
let [<Literal>] Ey = 0x27c7000000000000L
let [<Literal>] Gb = 0x2088000000000000L
let [<Literal>] Gd = 0x2108000000000000L
let [<Literal>] Gv = 0x26c8000000000000L
let [<Literal>] Gw = 0x2708000000000000L
let [<Literal>] Gy = 0x27c8000000000000L
let [<Literal>] Gz = 0x2808000000000000L
let [<Literal>] Jb = 0x208c000000000000L
let [<Literal>] Jz = 0x280c000000000000L
let [<Literal>] Ib = 0x208a000000000000L
let [<Literal>] Iv = 0x26ca000000000000L
let [<Literal>] Iw = 0x270a000000000000L
let [<Literal>] Iz = 0x280a000000000000L
let [<Literal>] Ma = 0x204d000000000000L
let [<Literal>] Mdq = 0x218d000000000000L
let [<Literal>] Mp = 0x238d000000000000L
let [<Literal>] Mq = 0x24cd000000000000L
let [<Literal>] Ms = 0x254d000000000000L
let [<Literal>] Mv = 0x26cd000000000000L
let [<Literal>] Mw = 0x270d000000000000L
let [<Literal>] My = 0x27cd000000000000L
let [<Literal>] Mz = 0x280d000000000000L
let [<Literal>] Pd = 0x2111000000000000L
let [<Literal>] Pq = 0x24d1000000000000L
let [<Literal>] Qq = 0x24d2000000000000L
let [<Literal>] Rd = 0x2113000000000000L
let [<Literal>] Rv = 0x26d3000000000000L
let [<Literal>] Ry = 0x27d3000000000000L
let [<Literal>] SIb = 0x208b000000000000L
let [<Literal>] SIv = 0x26cb000000000000L
let [<Literal>] SIw = 0x270b000000000000L
let [<Literal>] SIz = 0x280b000000000000L
let [<Literal>] Sw = 0x2714000000000000L
let [<Literal>] Vdq = 0x2196000000000000L
let [<Literal>] Vx = 0x2756000000000000L
let [<Literal>] Wdq = 0x2198000000000000L
let [<Literal>] Wdqd = 0x21d8000000000000L
let [<Literal>] Wdqq = 0x2258000000000000L
let [<Literal>] Wx = 0x2758000000000000L
let [<Literal>] ALDX = 0x3018301300000000L
let [<Literal>] ALIb = 0x3018208a00000000L
let [<Literal>] ALOb = 0x3018209000000000L
let [<Literal>] BNDRbndBNDRMbnd = 0x20c320c400000000L
let [<Literal>] BNDRMbndBNDRbnd = 0x20c420c300000000L
let [<Literal>] CdRd = 0x2105211300000000L
let [<Literal>] DdRd = 0x2106211300000000L
let [<Literal>] Eb1L = 0x2087100000000000L
let [<Literal>] EbCL = 0x2087301a00000000L
let [<Literal>] EbGb = 0x2087208800000000L
let [<Literal>] EbIb = 0x2087208a00000000L
let [<Literal>] Ev1L = 0x26c7100000000000L
let [<Literal>] EvCL = 0x26c7301a00000000L
let [<Literal>] EvGv = 0x26c726c800000000L
let [<Literal>] EvIb = 0x26c7208a00000000L
let [<Literal>] EvIz = 0x26c7280a00000000L
let [<Literal>] EvSIb = 0x26c7208b00000000L
let [<Literal>] EvSIz = 0x26c7280b00000000L
let [<Literal>] EvSw = 0x26c7271400000000L
let [<Literal>] EwGw = 0x2707270800000000L
let [<Literal>] EyPd = 0x27c7211100000000L
let [<Literal>] EyPq = 0x27c724d100000000L
let [<Literal>] EyVdq = 0x27c7219600000000L
let [<Literal>] GbEb = 0x2088208700000000L
let [<Literal>] GdEb = 0x2108208700000000L
let [<Literal>] GdEw = 0x2108270700000000L
let [<Literal>] GdEy = 0x210827c700000000L
let [<Literal>] GdNq = 0x210824cf00000000L
let [<Literal>] GdUdq = 0x2108219500000000L
let [<Literal>] GdUx = 0x2108275500000000L
let [<Literal>] GvEb = 0x26c8208700000000L
let [<Literal>] GvEd = 0x26c8210700000000L
let [<Literal>] GvEv = 0x26c826c700000000L
let [<Literal>] GvEw = 0x26c8270700000000L
let [<Literal>] GvEy = 0x26c827c700000000L
let [<Literal>] GvMa = 0x26c8204d00000000L
let [<Literal>] GvMp = 0x26c8238d00000000L
let [<Literal>] GvMv = 0x26c826cd00000000L
let [<Literal>] GwMw = 0x2708270d00000000L
let [<Literal>] GyMy = 0x27c827cd00000000L
let [<Literal>] GyUdq = 0x27c8219500000000L
let [<Literal>] GyUpd = 0x27c823d500000000L
let [<Literal>] GyUps = 0x27c8245500000000L
let [<Literal>] GyUx = 0x27c8275500000000L
let [<Literal>] GyWdq = 0x27c8219800000000L
let [<Literal>] GyWsd = 0x27c8259800000000L
let [<Literal>] GyWsdq = 0x27c825d800000000L
let [<Literal>] GyWss = 0x27c8261800000000L
let [<Literal>] GyWssd = 0x27c8265800000000L
let [<Literal>] GzMp = 0x2808238d00000000L
let [<Literal>] IbAL = 0x208a301800000000L
let [<Literal>] IwIb = 0x270a208a00000000L
let [<Literal>] MdqVdq = 0x218d219600000000L
let [<Literal>] MpdVpd = 0x23cd23d600000000L
let [<Literal>] MpsVps = 0x244d245600000000L
let [<Literal>] MqPq = 0x24cd24d100000000L
let [<Literal>] MqVdq = 0x24cd219600000000L
let [<Literal>] MwGw = 0x2708270d00000000L
let [<Literal>] MxVx = 0x274d275600000000L
let [<Literal>] MyGy = 0x27cd27c800000000L
let [<Literal>] MZxzVZxz = 0x278e279700000000L
let [<Literal>] NqIb = 0x24cf208a00000000L
let [<Literal>] ObAL = 0x2090301800000000L
let [<Literal>] PdEy = 0x211127c700000000L
let [<Literal>] PpiWdq = 0x2411219800000000L
let [<Literal>] PpiWdqq = 0x2411225800000000L
let [<Literal>] PpiWpd = 0x241123d800000000L
let [<Literal>] PpiWps = 0x2411245800000000L
let [<Literal>] PpiWpsq = 0x2411249800000000L
let [<Literal>] PqEy = 0x24d127c700000000L
let [<Literal>] PqQd = 0x24d1211200000000L
let [<Literal>] PqQq = 0x24d124d200000000L
let [<Literal>] PqUdq = 0x24d1219500000000L
let [<Literal>] PqWdq = 0x24d1219800000000L
let [<Literal>] QpiWpd = 0x241223d800000000L
let [<Literal>] QqPq = 0x24d224d100000000L
let [<Literal>] RdCd = 0x2113210500000000L
let [<Literal>] RdDd = 0x2113210600000000L
let [<Literal>] SwEw = 0x2714270700000000L
let [<Literal>] UdqIb = 0x2195208a00000000L
let [<Literal>] VdqEdbIb = 0x21962147208a0000L
let [<Literal>] VdqEy = 0x219627c700000000L
let [<Literal>] VdqMdq = 0x2196218d00000000L
let [<Literal>] VdqMq = 0x219624cd00000000L
let [<Literal>] VdqNq = 0x219624cf00000000L
let [<Literal>] VdqQq = 0x219624d200000000L
let [<Literal>] VdqUdq = 0x2196219500000000L
let [<Literal>] VdqWdq = 0x2196219800000000L
let [<Literal>] VdqWdqd = 0x219621d800000000L
let [<Literal>] VdqWdqq = 0x2196225800000000L
let [<Literal>] VdqWdqw = 0x219622d800000000L
let [<Literal>] VpdWpd = 0x23d623d800000000L
let [<Literal>] VpsHpsWpsIb = 0x245624492458208aL
let [<Literal>] VpsWps = 0x2456245800000000L
let [<Literal>] VqqMdq = 0x2516218d00000000L
let [<Literal>] VsdWsd = 0x2596259800000000L
let [<Literal>] VsdWsdq = 0x259625d800000000L
let [<Literal>] VssWss = 0x2616261800000000L
let [<Literal>] VssWssd = 0x2616265800000000L
let [<Literal>] VxMd = 0x2756210d00000000L
let [<Literal>] VxMx = 0x2756274d00000000L
let [<Literal>] VxWdqqdq = 0x2756229800000000L
let [<Literal>] VxWdqdq = 0x2756221800000000L
let [<Literal>] VxWdqwd = 0x2756235800000000L
let [<Literal>] VxWss = 0x2756261800000000L
let [<Literal>] VxWssd = 0x2756265800000000L
let [<Literal>] VxWssq = 0x2756269800000000L
let [<Literal>] VxWx = 0x2756275800000000L
let [<Literal>] VyEy = 0x27d627c700000000L
let [<Literal>] VZxzWdqd = 0x279721d800000000L
let [<Literal>] VZxzWZxz = 0x2797279900000000L
let [<Literal>] WdqVdq = 0x2198219600000000L
let [<Literal>] WdqdVdq = 0x21d8219600000000L
let [<Literal>] WdqqVdq = 0x2258219600000000L
let [<Literal>] WpdVpd = 0x23d823d600000000L
let [<Literal>] WpsVps = 0x2458245600000000L
let [<Literal>] WssVx = 0x2618275600000000L
let [<Literal>] WssdVx = 0x2658275600000000L
let [<Literal>] WxVx = 0x2758275600000000L
let [<Literal>] WZxzVZxz = 0x2799279700000000L
let [<Literal>] XbYb = 0x209a209b00000000L
let [<Literal>] XvYv = 0x26da26db00000000L
let [<Literal>] YbXb = 0x209b209a00000000L
let [<Literal>] YvXv = 0x26db26da00000000L
let [<Literal>] EvGvCL = 0x26c726c8301a0000L
let [<Literal>] EvGvIb = 0x26c726c8208a0000L
let [<Literal>] GdNqIb = 0x210824cf208a0000L
let [<Literal>] GdUdqIb = 0x21082195208a0000L
let [<Literal>] GvEvIb = 0x26c826c7208a0000L
let [<Literal>] GvEvIz = 0x26c826c7280a0000L
let [<Literal>] GvEvSIb = 0x26c826c7208b0000L
let [<Literal>] GvEvSIz = 0x26c826c7280b0000L
let [<Literal>] GyByEy = 0x27c827c227c70000L
let [<Literal>] GyEyBy = 0x27c827c727c20000L
let [<Literal>] GyEyIb = 0x27c827c7208a0000L
let [<Literal>] HxUxIb = 0x27492755208a0000L
let [<Literal>] PqEdwIb = 0x24d12307208a0000L
let [<Literal>] PqQqIb = 0x24d124d2208a0000L
let [<Literal>] VdqHdqMdq = 0x21962189218d0000L
let [<Literal>] VdqHdqMdqd = 0x2196218921cd0000L
let [<Literal>] VdqHdqMq = 0x2196218924cd0000L
let [<Literal>] VdqHdqUdq = 0x2196218921950000L
let [<Literal>] VdqEdwIb = 0x21962307208a0000L
let [<Literal>] VdqWdqIb = 0x21962198208a0000L
let [<Literal>] VsdHsdEy = 0x2596258927c70000L
let [<Literal>] VssHssEy = 0x2616260927c70000L
let [<Literal>] VsdHsdWsd = 0x2596258925980000L
let [<Literal>] VsdHsdWsdq = 0x2596258925d80000L
let [<Literal>] VsdWsdIb = 0x25962598208a0000L
let [<Literal>] VssHssWss = 0x2616260926180000L
let [<Literal>] VssHssWssd = 0x2616260926580000L
let [<Literal>] VpdHpdWpd = 0x23d623c923d80000L
let [<Literal>] VpsHpsWps = 0x2456244924580000L
let [<Literal>] VxHxWdq = 0x2756274921980000L
let [<Literal>] VxHxWsd = 0x2756274925980000L
let [<Literal>] VxHxWss = 0x2756274926180000L
let [<Literal>] VxHxWx = 0x2756274927580000L
let [<Literal>] VxWxIb = 0x27562758208a0000L
let [<Literal>] WsdHxVsd = 0x2598274925960000L
let [<Literal>] WssHxVss = 0x2618274926160000L
let [<Literal>] VdqHdqEdwIb = 0x219621892307208aL
let [<Literal>] VxHxWxIb = 0x275627492758208aL
let [<Literal>] VqqHqqWdqIb = 0x251625092198208aL
let [<Literal>] RGzRGz = 0x4804480200000000L
let [<Literal>] RGvSIz = 0x46c4280b00000000L
let [<Literal>] RGvDX = 0x46c4301300000000L
let [<Literal>] DXRGv = 0x301346c400000000L
let [<Literal>] ORES = 0x3600000000000000L
let [<Literal>] ORCS = 0x3601000000000000L
let [<Literal>] ORSS = 0x3602000000000000L
let [<Literal>] ORDS = 0x3603000000000000L
let [<Literal>] ORFS = 0x3604000000000000L
let [<Literal>] ORGS = 0x3605000000000000L
let [<Literal>] GvG0T = 0x46c2000000000000L
let [<Literal>] GvG1T = 0x46ca000000000000L
let [<Literal>] GvG2T = 0x46d2000000000000L
let [<Literal>] GvG3T = 0x46da000000000000L
let [<Literal>] GvG4T = 0x46e2000000000000L
let [<Literal>] GvG5T = 0x46ea000000000000L
let [<Literal>] GvG6T = 0x46f2000000000000L
let [<Literal>] GvG7T = 0x46fa000000000000L
let [<Literal>] GzG0T = 0x4802000000000000L
let [<Literal>] GzG1T = 0x480a000000000000L
let [<Literal>] GzG2T = 0x4812000000000000L
let [<Literal>] GzG3T = 0x481a000000000000L
let [<Literal>] GzG4T = 0x4822000000000000L
let [<Literal>] GzG5T = 0x482a000000000000L
let [<Literal>] GzG6T = 0x4832000000000000L
let [<Literal>] GzG7T = 0x483a000000000000L
let [<Literal>] GzG0F = 0x4804000000000000L
let [<Literal>] GzG1F = 0x480c000000000000L
let [<Literal>] GzG2F = 0x4814000000000000L
let [<Literal>] GzG3F = 0x481c000000000000L
let [<Literal>] GzG4F = 0x4824000000000000L
let [<Literal>] GzG5F = 0x482c000000000000L
let [<Literal>] GzG6F = 0x4834000000000000L
let [<Literal>] GzG7F = 0x483c000000000000L
let [<Literal>] GvG0TOv = 0x46c226d000000000L
let [<Literal>] GvG1TOv = 0x46ca26d000000000L
let [<Literal>] GvG2TOv = 0x46d226d000000000L
let [<Literal>] GvG3TOv = 0x46da26d000000000L
let [<Literal>] GvG4TOv = 0x46e226d000000000L
let [<Literal>] GvG5TOv = 0x46ea26d000000000L
let [<Literal>] GvG6TOv = 0x46f226d000000000L
let [<Literal>] GvG7TOv = 0x46fa26d000000000L
let [<Literal>] GvG0FOv = 0x46c426d000000000L
let [<Literal>] GvG1FOv = 0x46cc26d000000000L
let [<Literal>] GvG2FOv = 0x46d426d000000000L
let [<Literal>] GvG3FOv = 0x46dc26d000000000L
let [<Literal>] GvG4FOv = 0x46e426d000000000L
let [<Literal>] GvG5FOv = 0x46ec26d000000000L
let [<Literal>] GvG6FOv = 0x46f426d000000000L
let [<Literal>] GvG7FOv = 0x46fc26d000000000L
let [<Literal>] OvGvG0T = 0x26d046c200000000L
let [<Literal>] OvGvG1T = 0x26d046ca00000000L
let [<Literal>] OvGvG2T = 0x26d046d200000000L
let [<Literal>] OvGvG3T = 0x26d046da00000000L
let [<Literal>] OvGvG4T = 0x26d046e200000000L
let [<Literal>] OvGvG5T = 0x26d046ea00000000L
let [<Literal>] OvGvG6T = 0x26d046f200000000L
let [<Literal>] OvGvG7T = 0x26d046fa00000000L
let [<Literal>] OvGvG0F = 0x26d046c400000000L
let [<Literal>] OvGvG1F = 0x26d046cc00000000L
let [<Literal>] OvGvG2F = 0x26d046d400000000L
let [<Literal>] OvGvG3F = 0x26d046dc00000000L
let [<Literal>] OvGvG4F = 0x26d046e400000000L
let [<Literal>] OvGvG5F = 0x26d046ec00000000L
let [<Literal>] OvGvG6F = 0x26d046f400000000L
let [<Literal>] OvGvG7F = 0x26d046fc00000000L
let [<Literal>] GvG0FGvG0T = 0x46c446c200000000L
let [<Literal>] GvG0FGvG1T = 0x46c446ca00000000L
let [<Literal>] GvG0FGvG2T = 0x46c446d200000000L
let [<Literal>] GvG0FGvG3T = 0x46c446da00000000L
let [<Literal>] GvG0FGvG4T = 0x46c446e200000000L
let [<Literal>] GvG0FGvG5T = 0x46c446ea00000000L
let [<Literal>] GvG0FGvG6T = 0x46c446f200000000L
let [<Literal>] GvG0FGvG7T = 0x46c446fa00000000L
let [<Literal>] GvG0TIb = 0x46c2208a00000000L
let [<Literal>] GvG1TIb = 0x46ca208a00000000L
let [<Literal>] GvG2TIb = 0x46d2208a00000000L
let [<Literal>] GvG3TIb = 0x46da208a00000000L
let [<Literal>] GvG4TIb = 0x46e2208a00000000L
let [<Literal>] GvG5TIb = 0x46ea208a00000000L
let [<Literal>] GvG6TIb = 0x46f2208a00000000L
let [<Literal>] GvG7TIb = 0x46fa208a00000000L
let [<Literal>] GvG0FIb = 0x46c4208a00000000L
let [<Literal>] GvG1FIb = 0x46cc208a00000000L
let [<Literal>] GvG2FIb = 0x46d4208a00000000L
let [<Literal>] GvG3FIb = 0x46dc208a00000000L
let [<Literal>] GvG4FIb = 0x46e4208a00000000L
let [<Literal>] GvG5FIb = 0x46ec208a00000000L
let [<Literal>] GvG6FIb = 0x46f4208a00000000L
let [<Literal>] GvG7FIb = 0x46fc208a00000000L
let [<Literal>] IbGvG0T = 0x208a46c200000000L
let [<Literal>] IbGvG1T = 0x208a46ca00000000L
let [<Literal>] IbGvG2T = 0x208a46d200000000L
let [<Literal>] IbGvG3T = 0x208a46da00000000L
let [<Literal>] IbGvG4T = 0x208a46e200000000L
let [<Literal>] IbGvG5T = 0x208a46ea00000000L
let [<Literal>] IbGvG6T = 0x208a46f200000000L
let [<Literal>] IbGvG7T = 0x208a46fa00000000L
let [<Literal>] IbGvG0F = 0x208a46c400000000L
let [<Literal>] IbGvG1F = 0x208a46cc00000000L
let [<Literal>] IbGvG2F = 0x208a46d400000000L
let [<Literal>] IbGvG3F = 0x208a46dc00000000L
let [<Literal>] IbGvG4F = 0x208a46e400000000L
let [<Literal>] IbGvG5F = 0x208a46ec00000000L
let [<Literal>] IbGvG6F = 0x208a46f400000000L
let [<Literal>] IbGvG7F = 0x208a46fc00000000L
let [<Literal>] GvG0TIv = 0x46c226ca00000000L
let [<Literal>] GvG1TIv = 0x46ca26ca00000000L
let [<Literal>] GvG2TIv = 0x46d226ca00000000L
let [<Literal>] GvG3TIv = 0x46da26ca00000000L
let [<Literal>] GvG4TIv = 0x46e226ca00000000L
let [<Literal>] GvG5TIv = 0x46ea26ca00000000L
let [<Literal>] GvG6TIv = 0x46f226ca00000000L
let [<Literal>] GvG7TIv = 0x46fa26ca00000000L
let [<Literal>] GvG0FIv = 0x46c426ca00000000L
let [<Literal>] GvG1FIv = 0x46cc26ca00000000L
let [<Literal>] GvG2FIv = 0x46d426ca00000000L
let [<Literal>] GvG3FIv = 0x46dc26ca00000000L
let [<Literal>] GvG4FIv = 0x46e426ca00000000L
let [<Literal>] GvG5FIv = 0x46ec26ca00000000L
let [<Literal>] GvG6FIv = 0x46f426ca00000000L
let [<Literal>] GvG7FIv = 0x46fc26ca00000000L

(*
type VEXOpcodes
+-----------------+------------------+-----------------+------------------+
| Opcode (16Byte) || Opcode (16Byte) | Opcode (16Byte) || Opcode (16Byte) |
+-----------------+------------------+-----------------+------------------+
*)

let [<Literal>] opNor0F1A = 0x301001003010301L
let [<Literal>] opNor0F1B = 0x301001003010301L
let [<Literal>] opNor0F10 = 0x12a012901250121L
let [<Literal>] opVex0F10Mem = 0x256025502540251L
let [<Literal>] opVex0F10Reg = 0x256025502540251L
let [<Literal>] opNor0F11 = 0x12a012901250121L
let [<Literal>] opVex0F11Mem = 0x256025502540251L
let [<Literal>] opVex0F11Reg = 0x256025502540251L
let [<Literal>] opNor0F12Mem = 0x11601150123010dL
let [<Literal>] opNor0F12Reg = 0x11101150123010dL
let [<Literal>] opVex0F12Mem = 0x24a02490253023eL
let [<Literal>] opVex0F12Reg = 0x24502490253023eL
let [<Literal>] opNor0F13 = 0x116011503010301L
let [<Literal>] opVex0F13 = 0x24a024903010301L
let [<Literal>] opNor0F14 = 0x21c021b03010301L
let [<Literal>] opVex0F14 = 0x2e202e103010301L
let [<Literal>] opNor0F15 = 0x21a021903010301L
let [<Literal>] opVex0F15 = 0x2e002df03010301L
let [<Literal>] opNor0F16Mem = 0x113011201220301L
let [<Literal>] opNor0F16Reg = 0x114011201220301L
let [<Literal>] opVex0F16Mem = 0x247024602520301L
let [<Literal>] opVex0F16Reg = 0x248024602520301L
let [<Literal>] opNor0F17 = 0x113011203010301L
let [<Literal>] opVex0F17 = 0x247024603010301L
let [<Literal>] opNor0F28 = 0x10a010903010301L
let [<Literal>] opVex0F28 = 0x23c023b03010301L
let [<Literal>] opNor0F29 = 0x10a010903010301L
let [<Literal>] opVex0F29 = 0x23c023c03010301L
let [<Literal>] opNor0F2A = 0x480047004f004eL
let [<Literal>] opVex0F2A = 0x3010301022b022aL
let [<Literal>] opNor0F2B = 0x11c011b03010301L
let [<Literal>] opVex0F2B = 0x24f024e03010301L
let [<Literal>] opNor0F2C = 0x55005300570056L
let [<Literal>] opVex0F2C = 0x3010301022e022dL
let [<Literal>] opNor0F2D = 0x4b00450051004cL
let [<Literal>] opVex0F2D = 0x3010301022c0229L
let [<Literal>] opNor0F2E = 0x217021603010301L
let [<Literal>] opVex0F2E = 0x2de02dd03010301L
let [<Literal>] opNor0F2F = 0x3e003d03010301L
let [<Literal>] opVex0F2F = 0x228022703010301L
let [<Literal>] opNor0F50 = 0x118011703010301L
let [<Literal>] opVex0F50 = 0x24c024b03010301L
let [<Literal>] opNor0F51 = 0x1fd01fc01ff01feL
let [<Literal>] opVex0F51 = 0x2d602d502d802d7L
let [<Literal>] opNor0F54 = 0xe000d03010301L
let [<Literal>] opVex0F54 = 0x224022303010301L
let [<Literal>] opNor0F55 = 0xc000b03010301L
let [<Literal>] opVex0F55 = 0x222022103010301L
let [<Literal>] opNor0F56 = 0x138013703010301L
let [<Literal>] opVex0F56 = 0x261026003010301L
let [<Literal>] opNor0F57 = 0x2f502f403010301L
let [<Literal>] opVex0F57 = 0x2e402e303010301L
let [<Literal>] opNor0F58 = 0x7000600090008L
let [<Literal>] opVex0F58 = 0x21e021d0220021fL
let [<Literal>] opNor0F59 = 0x12e012d0130012fL
let [<Literal>] opVex0F59 = 0x25b025a025d025cL
let [<Literal>] opNor0F5A = 0x4a00460050004dL
let [<Literal>] opVex0F5A = 0x301030103010301L
let [<Literal>] opNor0F5B = 0x43004900540301L
let [<Literal>] opVex0F5B = 0x301030103010301L
let [<Literal>] opNor0F5C = 0x20c020b020e020dL
let [<Literal>] opVex0F5C = 0x2da02d902dc02dbL
let [<Literal>] opNor0F5D = 0x104010301060105L
let [<Literal>] opVex0F5D = 0x301030103010301L
let [<Literal>] opNor0F5E = 0x5f005e00610060L
let [<Literal>] opVex0F5E = 0x230022f02320231L
let [<Literal>] opNor0F5F = 0xff00fe01010100L
let [<Literal>] opVex0F5F = 0x301030103010301L
let [<Literal>] opNor0F60 = 0x1b801b803010301L
let [<Literal>] opVex0F60 = 0x30102ce03010301L
let [<Literal>] opNor0F61 = 0x1bb01bb03010301L
let [<Literal>] opVex0F61 = 0x30102d103010301L
let [<Literal>] opNor0F62 = 0x1b901b903010301L
let [<Literal>] opVex0F62 = 0x30102cf03010301L
let [<Literal>] opNor0F63 = 0x142014203010301L
let [<Literal>] opVex0F63 = 0x301026603010301L
let [<Literal>] opNor0F64 = 0x159015903010301L
let [<Literal>] opVex0F64 = 0x301027d03010301L
let [<Literal>] opNor0F65 = 0x15c015c03010301L
let [<Literal>] opVex0F65 = 0x301028003010301L
let [<Literal>] opNor0F66 = 0x15a015a03010301L
let [<Literal>] opVex0F66 = 0x301027e03010301L
let [<Literal>] opNor0F67 = 0x144014403010301L
let [<Literal>] opVex0F67 = 0x301026803010301L
let [<Literal>] opNor0F68 = 0x1b401b403010301L
let [<Literal>] opVex0F68 = 0x30102ca03010301L
let [<Literal>] opNor0F69 = 0x1b701b703010301L
let [<Literal>] opVex0F69 = 0x30102cd03010301L
let [<Literal>] opNor0F6A = 0x1b501b503010301L
let [<Literal>] opVex0F6A = 0x30102cb03010301L
let [<Literal>] opNor0F6B = 0x141014103010301L
let [<Literal>] opVex0F6B = 0x301026503010301L
let [<Literal>] opNor0F6C = 0x30101ba03010301L
let [<Literal>] opVex0F6C = 0x30102d003010301L
let [<Literal>] opNor0F6D = 0x30101b603010301L
let [<Literal>] opVex0F6D = 0x30102cc03010301L
let [<Literal>] opNor0F6EB64 = 0x11e011e03010301L
let [<Literal>] opNor0F6EB32 = 0x10c010c03010301L
let [<Literal>] opVex0F6EB64 = 0x301025003010301L
let [<Literal>] opVex0F6EB32 = 0x301023d03010301L
let [<Literal>] opNor0F6F = 0x11e010f01100301L
let [<Literal>] opVex0F6F = 0x301023f02420301L
let [<Literal>] opEVex0F6FB64 = 0x301024102440301L
let [<Literal>] opEVex0F6FB32 = 0x301024002430301L
let [<Literal>] opNor0F70 = 0x19d019a019b019cL
let [<Literal>] opVex0F70 = 0x30102b102b202b3L
let [<Literal>] opNor0F74 = 0x153015303010301L
let [<Literal>] opVex0F74 = 0x301027703010301L
let [<Literal>] opNor0F75 = 0x156015603010301L
let [<Literal>] opVex0F75 = 0x301027a03010301L
let [<Literal>] opNor0F76 = 0x154015403010301L
let [<Literal>] opVex0F76 = 0x301027803010301L
let [<Literal>] opNor0F77 = 0x301030103010301L
let [<Literal>] opVex0F77 = 0x2e5030103010301L
let [<Literal>] opNor0F7EB64 = 0x11e011e011e0301L
let [<Literal>] opNor0F7EB32 = 0x10c010c011e0301L
let [<Literal>] opVex0F7EB64 = 0x301025002500301L
let [<Literal>] opVex0F7EB32 = 0x301023d02500301L
let [<Literal>] opNor0F7F = 0x11e010f01100301L
let [<Literal>] opVex0F7F = 0x301023f02420301L
let [<Literal>] opEVex0F7FB64 = 0x301024103010301L
let [<Literal>] opEVex0F7FB32 = 0x301024003010301L
let [<Literal>] opNor0FC4 = 0x168016803010301L
let [<Literal>] opVex0FC4 = 0x301028c03010301L
let [<Literal>] opNor0FC5 = 0x15f015f03010301L
let [<Literal>] opVex0FC5 = 0x301028303010301L
let [<Literal>] opNor0FC6 = 0x1f801f703010301L
let [<Literal>] opVex0FC6 = 0x2d402d303010301L
let [<Literal>] opNor0FD1 = 0x1aa01aa03010301L
let [<Literal>] opVex0FD1 = 0x30102c003010301L
let [<Literal>] opNor0FD2 = 0x1a701a703010301L
let [<Literal>] opVex0FD2 = 0x30102bd03010301L
let [<Literal>] opNor0FD3 = 0x1a901a903010301L
let [<Literal>] opVex0FD3 = 0x30102bf03010301L
let [<Literal>] opNor0FD4 = 0x147014703010301L
let [<Literal>] opVex0FD4 = 0x301026b03010301L
let [<Literal>] opNor0FD5 = 0x188018803010301L
let [<Literal>] opVex0FD5 = 0x30102ac03010301L
let [<Literal>] opNor0FD6 = 0x301011e011f010eL
let [<Literal>] opVex0FD6 = 0x301025003010301L
let [<Literal>] opNor0FD7 = 0x176017603010301L
let [<Literal>] opVex0FD7 = 0x301029a03010301L
let [<Literal>] opNor0FD8 = 0x1b001b003010301L
let [<Literal>] opVex0FD8 = 0x30102c603010301L
let [<Literal>] opNor0FD9 = 0x1b101b103010301L
let [<Literal>] opVex0FD9 = 0x30102c703010301L
let [<Literal>] opNor0FDA = 0x173017303010301L
let [<Literal>] opVex0FDA = 0x301029703010301L
let [<Literal>] opNor0FDB = 0x14e014e03010301L
let [<Literal>] opVex0FDB = 0x301027203010301L
let [<Literal>] opNor0FDC = 0x14a014a03010301L
let [<Literal>] opVex0FDC = 0x301026e03010301L
let [<Literal>] opNor0FDD = 0x14b014b03010301L
let [<Literal>] opVex0FDD = 0x301026f03010301L
let [<Literal>] opNor0FDE = 0x16d016d03010301L
let [<Literal>] opVex0FDE = 0x301029103010301L
let [<Literal>] opNor0FDF = 0x14f014f03010301L
let [<Literal>] opVex0FDF = 0x301027303010301L
let [<Literal>] opNor0FE0 = 0x151015103010301L
let [<Literal>] opVex0FE0 = 0x301027403010301L
let [<Literal>] opNor0FE1 = 0x1a601a603010301L
let [<Literal>] opVex0FE1 = 0x30102bc03010301L
let [<Literal>] opNor0FE2 = 0x1a501a503010301L
let [<Literal>] opVex0FE2 = 0x30102bb03010301L
let [<Literal>] opNor0FE3 = 0x152015203010301L
let [<Literal>] opVex0FE3 = 0x301027503010301L
let [<Literal>] opNor0FE4 = 0x185018503010301L
let [<Literal>] opVex0FE4 = 0x30102a903010301L
let [<Literal>] opNor0FE5 = 0x186018603010301L
let [<Literal>] opVex0FE5 = 0x30102aa03010301L
let [<Literal>] opNor0FE6 = 0x301005200420044L
let [<Literal>] opVex0FE6 = 0x301030103010301L
let [<Literal>] opNor0FE7 = 0x11d011903010301L
let [<Literal>] opVex0FE7 = 0x301024d03010301L
let [<Literal>] opEVex0FE7B64 = 0x301030103010301L
let [<Literal>] opEVex0FE7B32 = 0x301024d03010301L
let [<Literal>] opNor0FE8 = 0x1ae01ae03010301L
let [<Literal>] opVex0FE8 = 0x30102c403010301L
let [<Literal>] opNor0FE9 = 0x1af01af03010301L
let [<Literal>] opVex0FE9 = 0x30102c503010301L
let [<Literal>] opNor0FEA = 0x172017203010301L
let [<Literal>] opVex0FEA = 0x301029603010301L
let [<Literal>] opNor0FEB = 0x191019103010301L
let [<Literal>] opVex0FEB = 0x30102ae03010301L
let [<Literal>] opNor0FEC = 0x148014803010301L
let [<Literal>] opVex0FEC = 0x301026c03010301L
let [<Literal>] opNor0FED = 0x149014903010301L
let [<Literal>] opVex0FED = 0x301026d03010301L
let [<Literal>] opNor0FEE = 0x16c016c03010301L
let [<Literal>] opVex0FEE = 0x301029003010301L
let [<Literal>] opNor0FEF = 0x1c201c203010301L
let [<Literal>] opVex0FEF = 0x30102d203010301L
let [<Literal>] opNor0FF0 = 0x3010301030100e6L
let [<Literal>] opVex0FF0 = 0x301030103010236L
let [<Literal>] opNor0FF1 = 0x1a401a403010301L
let [<Literal>] opVex0FF1 = 0x30102ba03010301L
let [<Literal>] opNor0FF2 = 0x1a101a103010301L
let [<Literal>] opVex0FF2 = 0x30102b703010301L
let [<Literal>] opNor0FF3 = 0x1a301a303010301L
let [<Literal>] opVex0FF3 = 0x30102b903010301L
let [<Literal>] opNor0FF4 = 0x189018903010301L
let [<Literal>] opVex0FF4 = 0x30102ad03010301L
let [<Literal>] opNor0FF5 = 0x169016903010301L
let [<Literal>] opVex0FF5 = 0x301028d03010301L
let [<Literal>] opNor0FF6 = 0x198019803010301L
let [<Literal>] opVex0FF6 = 0x30102af03010301L
let [<Literal>] opNor0FF8 = 0x1ab01ab03010301L
let [<Literal>] opVex0FF8 = 0x30102c103010301L
let [<Literal>] opNor0FF9 = 0x1b201b203010301L
let [<Literal>] opVex0FF9 = 0x30102c803010301L
let [<Literal>] opNor0FFA = 0x1ac01ac03010301L
let [<Literal>] opVex0FFA = 0x30102c203010301L
let [<Literal>] opNor0FFB = 0x1ad01ad03010301L
let [<Literal>] opVex0FFB = 0x30102c303010301L
let [<Literal>] opNor0FFC = 0x145014503010301L
let [<Literal>] opVex0FFC = 0x301026903010301L
let [<Literal>] opNor0FFD = 0x14c014c03010301L
let [<Literal>] opVex0FFD = 0x301027003010301L
let [<Literal>] opNor0FFE = 0x146014603010301L
let [<Literal>] opVex0FFE = 0x301026a03010301L
let [<Literal>] opNor0F3800 = 0x199019903010301L
let [<Literal>] opVex0F3800 = 0x30102b003010301L
let [<Literal>] opNor0F3801 = 0x162016203010301L
let [<Literal>] opVex0F3801 = 0x301028603010301L
let [<Literal>] opNor0F3802 = 0x160016003010301L
let [<Literal>] opVex0F3802 = 0x301028403010301L
let [<Literal>] opNor0F3803 = 0x161016103010301L
let [<Literal>] opVex0F3803 = 0x301028503010301L
let [<Literal>] opNor0F3805 = 0x166016603010301L
let [<Literal>] opVex0F3805 = 0x301028a03010301L
let [<Literal>] opNor0F3806 = 0x164016403010301L
let [<Literal>] opVex0F3806 = 0x301028803010301L
let [<Literal>] opNor0F3807 = 0x165016503010301L
let [<Literal>] opVex0F3807 = 0x301028903010301L
let [<Literal>] opNor0F3808 = 0x19e019e03010301L
let [<Literal>] opVex0F3808 = 0x30102b403010301L
let [<Literal>] opNor0F3809 = 0x1a001a003010301L
let [<Literal>] opVex0F3809 = 0x30102b603010301L
let [<Literal>] opNor0F380A = 0x19f019f03010301L
let [<Literal>] opVex0F380A = 0x30102b503010301L
let [<Literal>] opNor0F380B = 0x184018403010301L
let [<Literal>] opVex0F380B = 0x30102a803010301L
let [<Literal>] opNor0F3817 = 0x30101b303010301L
let [<Literal>] opVex0F3817 = 0x30102c903010301L
let [<Literal>] opNor0F3818 = 0x301030103010301L
let [<Literal>] opVex0F3818 = 0x301022603010301L
let [<Literal>] opEVex0F3818 = 0x301022603010301L
let [<Literal>] opNor0F381C = 0x13e013e03010301L
let [<Literal>] opVex0F381C = 0x301026203010301L
let [<Literal>] opNor0F381D = 0x140014003010301L
let [<Literal>] opVex0F381D = 0x301026403010301L
let [<Literal>] opNor0F381E = 0x13f013f03010301L
let [<Literal>] opVex0F381E = 0x301026303010301L
let [<Literal>] opNor0F3820 = 0x301017903010301L
let [<Literal>] opVex0F3820 = 0x301029d03010301L
let [<Literal>] opNor0F3821 = 0x301017703010301L
let [<Literal>] opVex0F3821 = 0x301029b03010301L
let [<Literal>] opNor0F3822 = 0x301017803010301L
let [<Literal>] opVex0F3822 = 0x301029c03010301L
let [<Literal>] opNor0F3823 = 0x301017b03010301L
let [<Literal>] opVex0F3823 = 0x301029f03010301L
let [<Literal>] opNor0F3824 = 0x301017c03010301L
let [<Literal>] opVex0F3824 = 0x30102a003010301L
let [<Literal>] opNor0F3825 = 0x301017a03010301L
let [<Literal>] opVex0F3825 = 0x301029e03010301L
let [<Literal>] opNor0F3828 = 0x301018303010301L
let [<Literal>] opVex0F3828 = 0x30102a703010301L
let [<Literal>] opNor0F3829 = 0x301015503010301L
let [<Literal>] opVex0F3829 = 0x301027903010301L
let [<Literal>] opNor0F382B = 0x301014303010301L
let [<Literal>] opVex0F382B = 0x301026703010301L
let [<Literal>] opNor0F3830 = 0x301017f03010301L
let [<Literal>] opVex0F3830 = 0x30102a303010301L
let [<Literal>] opNor0F3831 = 0x301017d03010301L
let [<Literal>] opVex0F3831 = 0x30102a103010301L
let [<Literal>] opNor0F3832 = 0x301017e03010301L
let [<Literal>] opVex0F3832 = 0x30102a203010301L
let [<Literal>] opNor0F3833 = 0x301018103010301L
let [<Literal>] opVex0F3833 = 0x30102a503010301L
let [<Literal>] opNor0F3834 = 0x301018203010301L
let [<Literal>] opVex0F3834 = 0x30102a603010301L
let [<Literal>] opNor0F3835 = 0x301018003010301L
let [<Literal>] opVex0F3835 = 0x30102a403010301L
let [<Literal>] opNor0F3837 = 0x301015b03010301L
let [<Literal>] opVex0F3837 = 0x301027f03010301L
let [<Literal>] opNor0F3838 = 0x301017003010301L
let [<Literal>] opVex0F3838 = 0x301029403010301L
let [<Literal>] opNor0F3839 = 0x301017103010301L
let [<Literal>] opVex0F3839 = 0x301029503010301L
let [<Literal>] opNor0F383A = 0x301017503010301L
let [<Literal>] opVex0F383A = 0x301029903010301L
let [<Literal>] opNor0F383B = 0x301017403010301L
let [<Literal>] opVex0F383B = 0x301029803010301L
let [<Literal>] opNor0F383C = 0x301016a03010301L
let [<Literal>] opVex0F383C = 0x301028e03010301L
let [<Literal>] opNor0F383D = 0x301016b03010301L
let [<Literal>] opVex0F383D = 0x301028f03010301L
let [<Literal>] opNor0F383E = 0x301016f03010301L
let [<Literal>] opVex0F383E = 0x301029303010301L
let [<Literal>] opNor0F383F = 0x301016e03010301L
let [<Literal>] opVex0F383F = 0x301029203010301L
let [<Literal>] opNor0F3840 = 0x301018703010301L
let [<Literal>] opVex0F3840 = 0x30102ab03010301L
let [<Literal>] opNor0F3841 = 0x301016303010301L
let [<Literal>] opVex0F3841 = 0x301028703010301L
let [<Literal>] opNor0F385A = 0x301030103010301L
let [<Literal>] opVex0F385A = 0x301022503010301L
let [<Literal>] opNor0F3878 = 0x301030103010301L
let [<Literal>] opVex0F3878 = 0x301027603010301L
let [<Literal>] opNor0F38F0 = 0x14b010b03010041L
let [<Literal>] opNor0F38F1 = 0x14b010b03010041L
let [<Literal>] opNor0F38F6 = 0x301030103010301L
let [<Literal>] opVex0F38F6 = 0x301030103010131L
let [<Literal>] opNor0F38F7 = 0x301030103010301L
let [<Literal>] opVex0F38F7 = 0x30101f301d901f6L
let [<Literal>] opNor0F3A0F = 0x14d014d03010301L
let [<Literal>] opVex0F3A0F = 0x301027103010301L
let [<Literal>] opNor0F3A20 = 0x301016703010301L
let [<Literal>] opVex0F3A20 = 0x301030103010301L
let [<Literal>] opNor0F3A38 = 0x301030103010301L
let [<Literal>] opVex0F3A38 = 0x301023503010301L
let [<Literal>] opNor0F3A60 = 0x301015803010301L
let [<Literal>] opVex0F3A60 = 0x301027c03010301L
let [<Literal>] opNor0F3A61 = 0x301015703010301L
let [<Literal>] opVex0F3A61 = 0x301027b03010301L
let [<Literal>] opNor0F3A62 = 0x301015e03010301L
let [<Literal>] opVex0F3A62 = 0x301028203010301L
let [<Literal>] opNor0F3A63 = 0x301015d03010301L
let [<Literal>] opVex0F3A63 = 0x301028103010301L
let [<Literal>] opNor0F3A0B = 0x30101d503010301L
let [<Literal>] opVex0F3A0B = 0x301030103010301L
let [<Literal>] opNor0F3AF0 = 0x301030103010301L
let [<Literal>] opVex0F3AF0 = 0x3010301030101d4L
let [<Literal>] opEmpty = 0x301030103010301L

let inline RegIb r =
  let reg: int64 = LanguagePrimitives.EnumToValue r |> int64
  (3L <<< 12 ||| reg) <<< 48 ||| (_Ib <<< 32)

let getOprMode oprDesc =
  match oprDesc &&& 0x3fL with
  | 0x1L -> OprMode.A
  | 0x2L -> OprMode.B
  | 0x3L -> OprMode.BndR
  | 0x4L -> OprMode.BndM
  | 0x5L -> OprMode.C
  | 0x6L -> OprMode.D
  | 0x7L -> OprMode.E
  | 0x8L -> OprMode.G
  | 0x9L -> OprMode.H
  | 0xaL -> OprMode.I
  | 0xbL -> OprMode.SI
  | 0xcL -> OprMode.J
  | 0xdL -> OprMode.M
  | 0xeL -> OprMode.MZ
  | 0xfL -> OprMode.N
  | 0x10L-> OprMode.O
  | 0x11L -> OprMode.P
  | 0x12L -> OprMode.Q
  | 0x13L -> OprMode.R
  | 0x14L -> OprMode.S
  | 0x15L -> OprMode.U
  | 0x16L -> OprMode.V
  | 0x17L -> OprMode.VZ
  | 0x18L -> OprMode.W
  | 0x19L -> OprMode.WZ
  | 0x1aL -> OprMode.X
  | 0x1bL -> OprMode.Y
  | 0x1cL -> OprMode.E0
  | _ -> failwith "Invalid opr mode"

let getOprSizeKnd oprDesc =
  match oprDesc &&& 0xfc0L with
  | 0x40L -> OprSize.A
  | 0x80L -> OprSize.B
  | 0xc0L -> OprSize.Bnd
  | 0x100L -> OprSize.D
  | 0x140L -> OprSize.DB
  | 0x180L -> OprSize.DQ
  | 0x1c0L -> OprSize.DQD
  | 0x200L -> OprSize.DQQ
  | 0x240L -> OprSize.DQW
  | 0x280L -> OprSize.DW
  | 0x2c0L -> OprSize.P
  | 0x300L -> OprSize.PD
  | 0x340L -> OprSize.PI
  | 0x380L -> OprSize.PS
  | 0x3c0L -> OprSize.PSQ
  | 0x400L -> OprSize.Q
  | 0x440L -> OprSize.QQ
  | 0x480L -> OprSize.S
  | 0x4c0L -> OprSize.SD
  | 0x500L -> OprSize.SDQ
  | 0x540L -> OprSize.SS
  | 0x580L -> OprSize.SSD
  | 0x5c0L -> OprSize.SSQ
  | 0x600L -> OprSize.V
  | 0x640L -> OprSize.W
  | 0x680L -> OprSize.X
  | 0x6c0L -> OprSize.XZ
  | 0x700L -> OprSize.Y
  | 0x740L -> OprSize.Z
  | _ -> failwith "Invalid opr size"

let getRGrpAttr oprDesc =
  match oprDesc &&& 0x7L with
  | 0x0L -> RGrpAttr.ANone
  | 0x1L -> RGrpAttr.AMod11
  | 0x2L -> RGrpAttr.ARegInOpREX
  | 0x4L -> RGrpAttr.ARegInOpNoREX
  | 0x8L -> RGrpAttr.ARegBits
  | 0x10L -> RGrpAttr.ABaseRM
  | 0x20L -> RGrpAttr.ASIBIdx
  | 0x40L -> RGrpAttr.ASIBBase
  | _ -> failwith "Invalid reg grp attr"

let getRegister oprDesc =
  match oprDesc &&& 0xfffL with (* Extract low 12 bits to get the register. *)
  | 0x0L -> R.RAX
  | 0x1L -> R.RBX
  | 0x2L -> R.RCX
  | 0x3L -> R.RDX
  | 0x4L -> R.RSP
  | 0x5L -> R.RBP
  | 0x6L -> R.RSI
  | 0x7L -> R.RDI
  | 0x8L -> R.EAX
  | 0x9L -> R.EBX
  | 0xAL -> R.ECX
  | 0xBL -> R.EDX
  | 0xCL -> R.ESP
  | 0xDL -> R.EBP
  | 0xEL -> R.ESI
  | 0xFL -> R.EDI
  | 0x10L -> R.AX
  | 0x11L -> R.BX
  | 0x12L -> R.CX
  | 0x13L -> R.DX
  | 0x14L -> R.SP
  | 0x15L -> R.BP
  | 0x16L -> R.SI
  | 0x17L -> R.DI
  | 0x18L -> R.AL
  | 0x19L -> R.BL
  | 0x1AL -> R.CL
  | 0x1BL -> R.DL
  | 0x1CL -> R.AH
  | 0x1DL -> R.BH
  | 0x1EL -> R.CH
  | 0x1FL -> R.DH
  | 0x20L -> R.R8
  | 0x21L -> R.R9
  | 0x22L -> R.R10
  | 0x23L -> R.R11
  | 0x24L -> R.R12
  | 0x25L -> R.R13
  | 0x26L -> R.R14
  | 0x27L -> R.R15
  | 0x28L -> R.R8D
  | 0x29L -> R.R9D
  | 0x2AL -> R.R10D
  | 0x2BL -> R.R11D
  | 0x2CL -> R.R12D
  | 0x2DL -> R.R13D
  | 0x2EL -> R.R14D
  | 0x2FL -> R.R15D
  | 0x30L -> R.R8W
  | 0x31L -> R.R9W
  | 0x32L -> R.R10W
  | 0x33L -> R.R11W
  | 0x34L -> R.R12W
  | 0x35L -> R.R13W
  | 0x36L -> R.R14W
  | 0x37L -> R.R15W
  | 0x38L -> R.R8L
  | 0x39L -> R.R9L
  | 0x3AL -> R.R10L
  | 0x3BL -> R.R11L
  | 0x3CL -> R.R12L
  | 0x3DL -> R.R13L
  | 0x3EL -> R.R14L
  | 0x3FL -> R.R15L
  | 0x40L -> R.SPL
  | 0x41L -> R.BPL
  | 0x42L -> R.SIL
  | 0x43L -> R.DIL
  | 0x44L -> R.EIP
  | 0x45L -> R.RIP
  | 0x100L -> R.ST0
  | 0x101L -> R.ST1
  | 0x102L -> R.ST2
  | 0x103L -> R.ST3
  | 0x104L -> R.ST4
  | 0x105L -> R.ST5
  | 0x106L -> R.ST6
  | 0x107L -> R.ST7
  | 0x200L -> R.MM0
  | 0x201L -> R.MM1
  | 0x202L -> R.MM2
  | 0x203L -> R.MM3
  | 0x204L -> R.MM4
  | 0x205L -> R.MM5
  | 0x206L -> R.MM6
  | 0x207L -> R.MM7
  | 0x30FL -> R.XMM0
  | 0x30EL -> R.XMM1
  | 0x30DL -> R.XMM2
  | 0x30CL -> R.XMM3
  | 0x30BL -> R.XMM4
  | 0x30AL -> R.XMM5
  | 0x309L -> R.XMM6
  | 0x308L -> R.XMM7
  | 0x307L -> R.XMM8
  | 0x306L -> R.XMM9
  | 0x305L -> R.XMM10
  | 0x304L -> R.XMM11
  | 0x303L -> R.XMM12
  | 0x302L -> R.XMM13
  | 0x301L -> R.XMM14
  | 0x300L -> R.XMM15
  | 0x40FL -> R.YMM0
  | 0x40EL -> R.YMM1
  | 0x40DL -> R.YMM2
  | 0x40CL -> R.YMM3
  | 0x40BL -> R.YMM4
  | 0x40AL -> R.YMM5
  | 0x409L -> R.YMM6
  | 0x408L -> R.YMM7
  | 0x407L -> R.YMM8
  | 0x406L -> R.YMM9
  | 0x405L -> R.YMM10
  | 0x404L -> R.YMM11
  | 0x403L -> R.YMM12
  | 0x402L -> R.YMM13
  | 0x401L -> R.YMM14
  | 0x400L -> R.YMM15
  | 0x50FL -> R.ZMM0
  | 0x50EL -> R.ZMM1
  | 0x50DL -> R.ZMM2
  | 0x50CL -> R.ZMM3
  | 0x50BL -> R.ZMM4
  | 0x50AL -> R.ZMM5
  | 0x509L -> R.ZMM6
  | 0x508L -> R.ZMM7
  | 0x507L -> R.ZMM8
  | 0x506L -> R.ZMM9
  | 0x505L -> R.ZMM10
  | 0x504L -> R.ZMM11
  | 0x503L -> R.ZMM12
  | 0x502L -> R.ZMM13
  | 0x501L -> R.ZMM14
  | 0x500L -> R.ZMM15
  | 0x600L -> R.ES
  | 0x601L -> R.CS
  | 0x602L -> R.SS
  | 0x603L -> R.DS
  | 0x604L -> R.FS
  | 0x605L -> R.GS
  | 0x700L -> R.ESBase
  | 0x701L -> R.CSBase
  | 0x702L -> R.SSBase
  | 0x703L -> R.DSBase
  | 0x704L -> R.FSBase
  | 0x705L -> R.GSBase
  | 0x800L -> R.CR0
  | 0x802L -> R.CR2
  | 0x803L -> R.CR3
  | 0x804L -> R.CR4
  | 0x900L -> R.DR0
  | 0x901L -> R.DR1
  | 0x902L -> R.DR2
  | 0x903L -> R.DR3
  | 0x906L -> R.DR6
  | 0x907L -> R.DR7
  | 0xA00L -> R.BND0
  | 0xA01L -> R.BND1
  | 0xA02L -> R.BND2
  | 0xA03L -> R.BND3
  | 0xB00L -> R.OF
  | 0xB01L -> R.DF
  | 0xB02L -> R.IF
  | 0xB03L -> R.TF
  | 0xB04L -> R.SF
  | 0xB05L -> R.ZF
  | 0xB06L -> R.AF
  | 0xB07L -> R.PF
  | 0xB08L -> R.CF
  | 0xC00L -> R.FCW
  | 0xC01L -> R.FSW
  | 0xC02L -> R.FTW
  | 0xC03L -> R.FOP
  | 0xC04L -> R.FIP
  | 0xC05L -> R.FCS
  | 0xC06L -> R.FDP
  | 0xC07L -> R.FDS
  | 0xC08L -> R.MXCSR
  | 0xC09L -> R.MXCSRMASK
  | 0xD00L -> R.UnknownReg
  | _ -> failwith "Invalid register"

// vim: set tw=80 sts=2 sw=2:

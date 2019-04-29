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

let [<Literal>] _Ib = 0x2089L
let [<Literal>] _SIb = 0x208aL
let [<Literal>] _SIz = 0x280aL
let [<Literal>] Ap = 0x2381000000000000L
let [<Literal>] Dd = 0x2105000000000000L
let [<Literal>] E0v = 0x26db000000000000L
let [<Literal>] Eb = 0x2086000000000000L
let [<Literal>] Ep = 0x2386000000000000L
let [<Literal>] Ev = 0x26c6000000000000L
let [<Literal>] Ew = 0x2706000000000000L
let [<Literal>] Ey = 0x27c6000000000000L
let [<Literal>] Gb = 0x2087000000000000L
let [<Literal>] Gd = 0x2107000000000000L
let [<Literal>] Gv = 0x26c7000000000000L
let [<Literal>] Gw = 0x2707000000000000L
let [<Literal>] Gy = 0x27c7000000000000L
let [<Literal>] Gz = 0x2807000000000000L
let [<Literal>] Jb = 0x208b000000000000L
let [<Literal>] Jz = 0x280b000000000000L
let [<Literal>] Ib = 0x2089000000000000L
let [<Literal>] Iv = 0x26c9000000000000L
let [<Literal>] Iw = 0x2709000000000000L
let [<Literal>] Iz = 0x2809000000000000L
let [<Literal>] Ma = 0x204c000000000000L
let [<Literal>] Mdq = 0x218c000000000000L
let [<Literal>] Mp = 0x238c000000000000L
let [<Literal>] Mq = 0x24cc000000000000L
let [<Literal>] Ms = 0x254c000000000000L
let [<Literal>] Mv = 0x26cc000000000000L
let [<Literal>] Mw = 0x270c000000000000L
let [<Literal>] My = 0x27cc000000000000L
let [<Literal>] Mz = 0x280c000000000000L
let [<Literal>] Pd = 0x2110000000000000L
let [<Literal>] Pq = 0x24d0000000000000L
let [<Literal>] Qq = 0x24d1000000000000L
let [<Literal>] Rd = 0x2112000000000000L
let [<Literal>] Rv = 0x26d2000000000000L
let [<Literal>] Ry = 0x27d2000000000000L
let [<Literal>] SIb = 0x208a000000000000L
let [<Literal>] SIv = 0x26ca000000000000L
let [<Literal>] SIw = 0x270a000000000000L
let [<Literal>] SIz = 0x280a000000000000L
let [<Literal>] Sw = 0x2713000000000000L
let [<Literal>] Vdq = 0x2195000000000000L
let [<Literal>] Vx = 0x2755000000000000L
let [<Literal>] Wdq = 0x2197000000000000L
let [<Literal>] Wdqd = 0x21d7000000000000L
let [<Literal>] Wdqq = 0x2257000000000000L
let [<Literal>] Wx = 0x2757000000000000L
let [<Literal>] ALDX = 0x3018301300000000L
let [<Literal>] ALIb = 0x3018208900000000L
let [<Literal>] ALOb = 0x3018208f00000000L
let [<Literal>] BNDRbndBNDRMbnd = 0x20c220c300000000L
let [<Literal>] BNDRMbndBNDRbnd = 0x20c320c200000000L
let [<Literal>] CdRd = 0x2104211200000000L
let [<Literal>] DdRd = 0x2105211200000000L
let [<Literal>] Eb1L = 0x2086100000000000L
let [<Literal>] EbCL = 0x2086301a00000000L
let [<Literal>] EbGb = 0x2086208700000000L
let [<Literal>] EbIb = 0x2086208900000000L
let [<Literal>] Ev1L = 0x26c6100000000000L
let [<Literal>] EvCL = 0x26c6301a00000000L
let [<Literal>] EvGv = 0x26c626c700000000L
let [<Literal>] EvIb = 0x26c6208900000000L
let [<Literal>] EvIz = 0x26c6280900000000L
let [<Literal>] EvSIb = 0x26c6208a00000000L
let [<Literal>] EvSIz = 0x26c6280a00000000L
let [<Literal>] EvSw = 0x26c6271300000000L
let [<Literal>] EwGw = 0x2706270700000000L
let [<Literal>] EyPd = 0x27c6211000000000L
let [<Literal>] EyPq = 0x27c624d000000000L
let [<Literal>] EyVdq = 0x27c6219500000000L
let [<Literal>] GbEb = 0x2087208600000000L
let [<Literal>] GdEb = 0x2107208600000000L
let [<Literal>] GdEw = 0x2107270600000000L
let [<Literal>] GdEy = 0x210727c600000000L
let [<Literal>] GdNq = 0x210724ce00000000L
let [<Literal>] GdUdq = 0x2107219400000000L
let [<Literal>] GdUx = 0x2107275400000000L
let [<Literal>] GvEb = 0x26c7208600000000L
let [<Literal>] GvEd = 0x26c7210600000000L
let [<Literal>] GvEv = 0x26c726c600000000L
let [<Literal>] GvEw = 0x26c7270600000000L
let [<Literal>] GvEy = 0x26c727c600000000L
let [<Literal>] GvMa = 0x26c7204c00000000L
let [<Literal>] GvMp = 0x26c7238c00000000L
let [<Literal>] GvMv = 0x26c726cc00000000L
let [<Literal>] GwMw = 0x2707270c00000000L
let [<Literal>] GyMy = 0x27c727cc00000000L
let [<Literal>] GyUdq = 0x27c7219400000000L
let [<Literal>] GyUpd = 0x27c723d400000000L
let [<Literal>] GyUps = 0x27c7245400000000L
let [<Literal>] GyUx = 0x27c7275400000000L
let [<Literal>] GyWdq = 0x27c7219700000000L
let [<Literal>] GyWsd = 0x27c7259700000000L
let [<Literal>] GyWsdq = 0x27c725d700000000L
let [<Literal>] GyWss = 0x27c7261700000000L
let [<Literal>] GyWssd = 0x27c7265700000000L
let [<Literal>] GzMp = 0x2807238c00000000L
let [<Literal>] IbAL = 0x2089301800000000L
let [<Literal>] IwIb = 0x2709208900000000L
let [<Literal>] MdqVdq = 0x218c219500000000L
let [<Literal>] MpdVpd = 0x23cc23d500000000L
let [<Literal>] MpsVps = 0x244c245500000000L
let [<Literal>] MqPq = 0x24cc24d000000000L
let [<Literal>] MqVdq = 0x24cc219500000000L
let [<Literal>] MwGw = 0x2707270c00000000L
let [<Literal>] MxVx = 0x274c275500000000L
let [<Literal>] MyGy = 0x27cc27c700000000L
let [<Literal>] MZxzVZxz = 0x278d279600000000L
let [<Literal>] NqIb = 0x24ce208900000000L
let [<Literal>] ObAL = 0x208f301800000000L
let [<Literal>] PdEy = 0x211027c600000000L
let [<Literal>] PpiWdq = 0x2410219700000000L
let [<Literal>] PpiWdqq = 0x2410225700000000L
let [<Literal>] PpiWpd = 0x241023d700000000L
let [<Literal>] PpiWps = 0x2410245700000000L
let [<Literal>] PpiWpsq = 0x2410249700000000L
let [<Literal>] PqEy = 0x24d027c600000000L
let [<Literal>] PqQd = 0x24d0211100000000L
let [<Literal>] PqQq = 0x24d024d100000000L
let [<Literal>] PqUdq = 0x24d0219400000000L
let [<Literal>] PqWdq = 0x24d0219700000000L
let [<Literal>] QpiWpd = 0x241123d700000000L
let [<Literal>] QqPq = 0x24d124d000000000L
let [<Literal>] RdCd = 0x2112210400000000L
let [<Literal>] RdDd = 0x2112210500000000L
let [<Literal>] SwEw = 0x2713270600000000L
let [<Literal>] UdqIb = 0x2194208900000000L
let [<Literal>] VdqEdbIb = 0x2195214620890000L
let [<Literal>] VdqEy = 0x219527c600000000L
let [<Literal>] VdqMdq = 0x2195218c00000000L
let [<Literal>] VdqMq = 0x219524cc00000000L
let [<Literal>] VdqNq = 0x219524ce00000000L
let [<Literal>] VdqQq = 0x219524d100000000L
let [<Literal>] VdqUdq = 0x2195219400000000L
let [<Literal>] VdqWdq = 0x2195219700000000L
let [<Literal>] VdqWdqd = 0x219521d700000000L
let [<Literal>] VdqWdqq = 0x2195225700000000L
let [<Literal>] VdqWdqw = 0x219522d700000000L
let [<Literal>] VpdWpd = 0x23d523d700000000L
let [<Literal>] VpsHpsWpsIb = 0x2455244824572089L
let [<Literal>] VpsWps = 0x2455245700000000L
let [<Literal>] VqqMdq = 0x2515218c00000000L
let [<Literal>] VsdWsd = 0x2595259700000000L
let [<Literal>] VsdWsdq = 0x259525d700000000L
let [<Literal>] VssWss = 0x2615261700000000L
let [<Literal>] VssWssd = 0x2615265700000000L
let [<Literal>] VxMd = 0x2755210c00000000L
let [<Literal>] VxMx = 0x2755274c00000000L
let [<Literal>] VxWdqqdq = 0x2755229700000000L
let [<Literal>] VxWdqdq = 0x2755221700000000L
let [<Literal>] VxWdqwd = 0x2755235700000000L
let [<Literal>] VxWss = 0x2755261700000000L
let [<Literal>] VxWssd = 0x2755265700000000L
let [<Literal>] VxWssq = 0x2755269700000000L
let [<Literal>] VxWx = 0x2755275700000000L
let [<Literal>] VyEy = 0x27d527c600000000L
let [<Literal>] VZxzWdqd = 0x279621d700000000L
let [<Literal>] VZxzWZxz = 0x2796279800000000L
let [<Literal>] WdqVdq = 0x2197219500000000L
let [<Literal>] WdqdVdq = 0x21d7219500000000L
let [<Literal>] WdqqVdq = 0x2257219500000000L
let [<Literal>] WpdVpd = 0x23d723d500000000L
let [<Literal>] WpsVps = 0x2457245500000000L
let [<Literal>] WssVx = 0x2617275500000000L
let [<Literal>] WssdVx = 0x2657275500000000L
let [<Literal>] WxVx = 0x2757275500000000L
let [<Literal>] WZxzVZxz = 0x2798279600000000L
let [<Literal>] XbYb = 0x2099209a00000000L
let [<Literal>] XvYv = 0x26d926da00000000L
let [<Literal>] YbXb = 0x209a209900000000L
let [<Literal>] YvXv = 0x26da26d900000000L
let [<Literal>] EvGvCL = 0x26c626c7301a0000L
let [<Literal>] EvGvIb = 0x26c626c720890000L
let [<Literal>] GdNqIb = 0x210724ce20890000L
let [<Literal>] GdUdqIb = 0x2107219420890000L
let [<Literal>] GvEvIb = 0x26c726c620890000L
let [<Literal>] GvEvIz = 0x26c726c628090000L
let [<Literal>] GvEvSIb = 0x26c726c6208a0000L
let [<Literal>] GvEvSIz = 0x26c726c6280a0000L
let [<Literal>] HxUxIb = 0x2748275420890000L
let [<Literal>] PqEdwIb = 0x24d0230620890000L
let [<Literal>] PqQqIb = 0x24d024d120890000L
let [<Literal>] VdqHdqMdq = 0x21952188218c0000L
let [<Literal>] VdqHdqMdqd = 0x2195218821cc0000L
let [<Literal>] VdqHdqMq = 0x2195218824cc0000L
let [<Literal>] VdqHdqUdq = 0x2195218821940000L
let [<Literal>] VdqEdwIb = 0x2195230620890000L
let [<Literal>] VdqWdqIb = 0x2195219720890000L
let [<Literal>] VsdHsdEy = 0x2595258827c60000L
let [<Literal>] VssHssEy = 0x2615260827c60000L
let [<Literal>] VsdHsdWsd = 0x2595258825970000L
let [<Literal>] VsdHsdWsdq = 0x2595258825d70000L
let [<Literal>] VsdWsdIb = 0x2595259720890000L
let [<Literal>] VssHssWss = 0x2615260826170000L
let [<Literal>] VssHssWssd = 0x2615260826570000L
let [<Literal>] VpdHpdWpd = 0x23d523c823d70000L
let [<Literal>] VpsHpsWps = 0x2455244824570000L
let [<Literal>] VxHxWdq = 0x2755274821970000L
let [<Literal>] VxHxWsd = 0x2755274825970000L
let [<Literal>] VxHxWss = 0x2755274826170000L
let [<Literal>] VxHxWx = 0x2755274827570000L
let [<Literal>] VxWxIb = 0x2755275720890000L
let [<Literal>] WsdHxVsd = 0x2597274825950000L
let [<Literal>] WssHxVss = 0x2617274826150000L
let [<Literal>] VdqHdqEdwIb = 0x2195218823062089L
let [<Literal>] VxHxWxIb = 0x2755274827572089L
let [<Literal>] VqqHqqWdqIb = 0x2515250821972089L
let [<Literal>] RGzRGz = 0x4804480200000000L
let [<Literal>] RGvSIz = 0x46c4280a00000000L
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
let [<Literal>] GvG0TOv = 0x46c226cf00000000L
let [<Literal>] GvG1TOv = 0x46ca26cf00000000L
let [<Literal>] GvG2TOv = 0x46d226cf00000000L
let [<Literal>] GvG3TOv = 0x46da26cf00000000L
let [<Literal>] GvG4TOv = 0x46e226cf00000000L
let [<Literal>] GvG5TOv = 0x46ea26cf00000000L
let [<Literal>] GvG6TOv = 0x46f226cf00000000L
let [<Literal>] GvG7TOv = 0x46fa26cf00000000L
let [<Literal>] GvG0FOv = 0x46c426cf00000000L
let [<Literal>] GvG1FOv = 0x46cc26cf00000000L
let [<Literal>] GvG2FOv = 0x46d426cf00000000L
let [<Literal>] GvG3FOv = 0x46dc26cf00000000L
let [<Literal>] GvG4FOv = 0x46e426cf00000000L
let [<Literal>] GvG5FOv = 0x46ec26cf00000000L
let [<Literal>] GvG6FOv = 0x46f426cf00000000L
let [<Literal>] GvG7FOv = 0x46fc26cf00000000L
let [<Literal>] OvGvG0T = 0x26cf46c200000000L
let [<Literal>] OvGvG1T = 0x26cf46ca00000000L
let [<Literal>] OvGvG2T = 0x26cf46d200000000L
let [<Literal>] OvGvG3T = 0x26cf46da00000000L
let [<Literal>] OvGvG4T = 0x26cf46e200000000L
let [<Literal>] OvGvG5T = 0x26cf46ea00000000L
let [<Literal>] OvGvG6T = 0x26cf46f200000000L
let [<Literal>] OvGvG7T = 0x26cf46fa00000000L
let [<Literal>] OvGvG0F = 0x26cf46c400000000L
let [<Literal>] OvGvG1F = 0x26cf46cc00000000L
let [<Literal>] OvGvG2F = 0x26cf46d400000000L
let [<Literal>] OvGvG3F = 0x26cf46dc00000000L
let [<Literal>] OvGvG4F = 0x26cf46e400000000L
let [<Literal>] OvGvG5F = 0x26cf46ec00000000L
let [<Literal>] OvGvG6F = 0x26cf46f400000000L
let [<Literal>] OvGvG7F = 0x26cf46fc00000000L
let [<Literal>] GvG0FGvG0T = 0x46c446c200000000L
let [<Literal>] GvG0FGvG1T = 0x46c446ca00000000L
let [<Literal>] GvG0FGvG2T = 0x46c446d200000000L
let [<Literal>] GvG0FGvG3T = 0x46c446da00000000L
let [<Literal>] GvG0FGvG4T = 0x46c446e200000000L
let [<Literal>] GvG0FGvG5T = 0x46c446ea00000000L
let [<Literal>] GvG0FGvG6T = 0x46c446f200000000L
let [<Literal>] GvG0FGvG7T = 0x46c446fa00000000L
let [<Literal>] GvG0TIb = 0x46c2208900000000L
let [<Literal>] GvG1TIb = 0x46ca208900000000L
let [<Literal>] GvG2TIb = 0x46d2208900000000L
let [<Literal>] GvG3TIb = 0x46da208900000000L
let [<Literal>] GvG4TIb = 0x46e2208900000000L
let [<Literal>] GvG5TIb = 0x46ea208900000000L
let [<Literal>] GvG6TIb = 0x46f2208900000000L
let [<Literal>] GvG7TIb = 0x46fa208900000000L
let [<Literal>] GvG0FIb = 0x46c4208900000000L
let [<Literal>] GvG1FIb = 0x46cc208900000000L
let [<Literal>] GvG2FIb = 0x46d4208900000000L
let [<Literal>] GvG3FIb = 0x46dc208900000000L
let [<Literal>] GvG4FIb = 0x46e4208900000000L
let [<Literal>] GvG5FIb = 0x46ec208900000000L
let [<Literal>] GvG6FIb = 0x46f4208900000000L
let [<Literal>] GvG7FIb = 0x46fc208900000000L
let [<Literal>] IbGvG0T = 0x208946c200000000L
let [<Literal>] IbGvG1T = 0x208946ca00000000L
let [<Literal>] IbGvG2T = 0x208946d200000000L
let [<Literal>] IbGvG3T = 0x208946da00000000L
let [<Literal>] IbGvG4T = 0x208946e200000000L
let [<Literal>] IbGvG5T = 0x208946ea00000000L
let [<Literal>] IbGvG6T = 0x208946f200000000L
let [<Literal>] IbGvG7T = 0x208946fa00000000L
let [<Literal>] IbGvG0F = 0x208946c400000000L
let [<Literal>] IbGvG1F = 0x208946cc00000000L
let [<Literal>] IbGvG2F = 0x208946d400000000L
let [<Literal>] IbGvG3F = 0x208946dc00000000L
let [<Literal>] IbGvG4F = 0x208946e400000000L
let [<Literal>] IbGvG5F = 0x208946ec00000000L
let [<Literal>] IbGvG6F = 0x208946f400000000L
let [<Literal>] IbGvG7F = 0x208946fc00000000L
let [<Literal>] GvG0TIv = 0x46c226c900000000L
let [<Literal>] GvG1TIv = 0x46ca26c900000000L
let [<Literal>] GvG2TIv = 0x46d226c900000000L
let [<Literal>] GvG3TIv = 0x46da26c900000000L
let [<Literal>] GvG4TIv = 0x46e226c900000000L
let [<Literal>] GvG5TIv = 0x46ea26c900000000L
let [<Literal>] GvG6TIv = 0x46f226c900000000L
let [<Literal>] GvG7TIv = 0x46fa26c900000000L
let [<Literal>] GvG0FIv = 0x46c426c900000000L
let [<Literal>] GvG1FIv = 0x46cc26c900000000L
let [<Literal>] GvG2FIv = 0x46d426c900000000L
let [<Literal>] GvG3FIv = 0x46dc26c900000000L
let [<Literal>] GvG4FIv = 0x46e426c900000000L
let [<Literal>] GvG5FIv = 0x46ec26c900000000L
let [<Literal>] GvG6FIv = 0x46f426c900000000L
let [<Literal>] GvG7FIv = 0x46fc26c900000000L

(*
type VEXOpcodes
+-----------------+------------------+-----------------+------------------+
| Opcode (16Byte) || Opcode (16Byte) | Opcode (16Byte) || Opcode (16Byte) |
+-----------------+------------------+-----------------+------------------+
*)

let [<Literal>] opNor0F1A = 0x2ee001002ee02eeL
let [<Literal>] opNor0F1B = 0x2ee001002ee02eeL
let [<Literal>] opNor0F10 = 0x12a012901250121L
let [<Literal>] opVex0F10Mem = 0x24d024c024b0248L
let [<Literal>] opVex0F10Reg = 0x24d024c024b0248L
let [<Literal>] opNor0F11 = 0x12a012901250121L
let [<Literal>] opVex0F11Mem = 0x24d024c024b0248L
let [<Literal>] opVex0F11Reg = 0x24d024c024b0248L
let [<Literal>] opNor0F12Mem = 0x11601150123010dL
let [<Literal>] opNor0F12Reg = 0x11101150123010dL
let [<Literal>] opVex0F12Mem = 0x2410240024a0235L
let [<Literal>] opVex0F12Reg = 0x23c0240024a0235L
let [<Literal>] opNor0F13 = 0x116011502ee02eeL
let [<Literal>] opVex0F13 = 0x241024002ee02eeL
let [<Literal>] opNor0F14 = 0x213021202ee02eeL
let [<Literal>] opVex0F14 = 0x2d502d402ee02eeL
let [<Literal>] opNor0F15 = 0x211021002ee02eeL
let [<Literal>] opVex0F15 = 0x2d302d202ee02eeL
let [<Literal>] opNor0F16Mem = 0x1130112012202eeL
let [<Literal>] opNor0F16Reg = 0x1140112012202eeL
let [<Literal>] opVex0F16Mem = 0x23e023d024902eeL
let [<Literal>] opVex0F16Reg = 0x23f023d024902eeL
let [<Literal>] opNor0F17 = 0x113011202ee02eeL
let [<Literal>] opVex0F17 = 0x23e023d02ee02eeL
let [<Literal>] opNor0F28 = 0x10a010902ee02eeL
let [<Literal>] opVex0F28 = 0x233023202ee02eeL
let [<Literal>] opNor0F29 = 0x10a010902ee02eeL
let [<Literal>] opVex0F29 = 0x233023302ee02eeL
let [<Literal>] opNor0F2A = 0x480047004f004eL
let [<Literal>] opVex0F2A = 0x2ee02ee02220221L
let [<Literal>] opNor0F2B = 0x11c011b02ee02eeL
let [<Literal>] opVex0F2B = 0x246024502ee02eeL
let [<Literal>] opNor0F2C = 0x55005300570056L
let [<Literal>] opVex0F2C = 0x2ee02ee02250224L
let [<Literal>] opNor0F2D = 0x4b00450051004cL
let [<Literal>] opVex0F2D = 0x2ee02ee02230220L
let [<Literal>] opNor0F2E = 0x20e020d02ee02eeL
let [<Literal>] opVex0F2E = 0x2d102d002ee02eeL
let [<Literal>] opNor0F2F = 0x3e003d02ee02eeL
let [<Literal>] opVex0F2F = 0x21f021e02ee02eeL
let [<Literal>] opNor0F50 = 0x118011702ee02eeL
let [<Literal>] opVex0F50 = 0x243024202ee02eeL
let [<Literal>] opNor0F54 = 0xe000d02ee02eeL
let [<Literal>] opVex0F54 = 0x21b021a02ee02eeL
let [<Literal>] opNor0F55 = 0xc000b02ee02eeL
let [<Literal>] opVex0F55 = 0x219021802ee02eeL
let [<Literal>] opNor0F56 = 0x137013602ee02eeL
let [<Literal>] opVex0F56 = 0x258025702ee02eeL
let [<Literal>] opNor0F57 = 0x2e802e702ee02eeL
let [<Literal>] opVex0F57 = 0x2d702d602ee02eeL
let [<Literal>] opNor0F58 = 0x7000600090008L
let [<Literal>] opVex0F58 = 0x215021402170216L
let [<Literal>] opNor0F59 = 0x12e012d0130012fL
let [<Literal>] opVex0F59 = 0x252025102540253L
let [<Literal>] opNor0F5A = 0x4a00460050004dL
let [<Literal>] opVex0F5A = 0x2ee02ee02ee02eeL
let [<Literal>] opNor0F5B = 0x430049005402eeL
let [<Literal>] opVex0F5B = 0x2ee02ee02ee02eeL
let [<Literal>] opNor0F5C = 0x203020202050204L
let [<Literal>] opVex0F5C = 0x2cd02cc02cf02ceL
let [<Literal>] opNor0F5D = 0x104010301060105L
let [<Literal>] opVex0F5D = 0x2ee02ee02ee02eeL
let [<Literal>] opNor0F5E = 0x5f005e00610060L
let [<Literal>] opVex0F5E = 0x227022602290228L
let [<Literal>] opNor0F5F = 0xff00fe01010100L
let [<Literal>] opVex0F5F = 0x2ee02ee02ee02eeL
let [<Literal>] opNor0F60 = 0x1b701b702ee02eeL
let [<Literal>] opVex0F60 = 0x2ee02c502ee02eeL
let [<Literal>] opNor0F61 = 0x1ba01ba02ee02eeL
let [<Literal>] opVex0F61 = 0x2ee02c802ee02eeL
let [<Literal>] opNor0F62 = 0x1b801b802ee02eeL
let [<Literal>] opVex0F62 = 0x2ee02c602ee02eeL
let [<Literal>] opNor0F63 = 0x141014102ee02eeL
let [<Literal>] opVex0F63 = 0x2ee025d02ee02eeL
let [<Literal>] opNor0F64 = 0x158015802ee02eeL
let [<Literal>] opVex0F64 = 0x2ee027402ee02eeL
let [<Literal>] opNor0F65 = 0x15b015b02ee02eeL
let [<Literal>] opVex0F65 = 0x2ee027702ee02eeL
let [<Literal>] opNor0F66 = 0x159015902ee02eeL
let [<Literal>] opVex0F66 = 0x2ee027502ee02eeL
let [<Literal>] opNor0F67 = 0x143014302ee02eeL
let [<Literal>] opVex0F67 = 0x2ee025f02ee02eeL
let [<Literal>] opNor0F68 = 0x1b301b302ee02eeL
let [<Literal>] opVex0F68 = 0x2ee02c102ee02eeL
let [<Literal>] opNor0F69 = 0x1b601b602ee02eeL
let [<Literal>] opVex0F69 = 0x2ee02c402ee02eeL
let [<Literal>] opNor0F6A = 0x1b401b402ee02eeL
let [<Literal>] opVex0F6A = 0x2ee02c202ee02eeL
let [<Literal>] opNor0F6B = 0x140014002ee02eeL
let [<Literal>] opVex0F6B = 0x2ee025c02ee02eeL
let [<Literal>] opNor0F6C = 0x2ee01b902ee02eeL
let [<Literal>] opVex0F6C = 0x2ee02c702ee02eeL
let [<Literal>] opNor0F6D = 0x2ee01b502ee02eeL
let [<Literal>] opVex0F6D = 0x2ee02c302ee02eeL
let [<Literal>] opNor0F6EB64 = 0x11e011e02ee02eeL
let [<Literal>] opNor0F6EB32 = 0x10c010c02ee02eeL
let [<Literal>] opVex0F6EB64 = 0x2ee024702ee02eeL
let [<Literal>] opVex0F6EB32 = 0x2ee023402ee02eeL
let [<Literal>] opNor0F6F = 0x11e010f011002eeL
let [<Literal>] opVex0F6F = 0x2ee0236023902eeL
let [<Literal>] opEVex0F6FB64 = 0x2ee0238023b02eeL
let [<Literal>] opEVex0F6FB32 = 0x2ee0237023a02eeL
let [<Literal>] opNor0F70 = 0x19c0199019a019bL
let [<Literal>] opVex0F70 = 0x2ee02a802a902aaL
let [<Literal>] opNor0F74 = 0x152015202ee02eeL
let [<Literal>] opVex0F74 = 0x2ee026e02ee02eeL
let [<Literal>] opNor0F75 = 0x155015502ee02eeL
let [<Literal>] opVex0F75 = 0x2ee027102ee02eeL
let [<Literal>] opNor0F76 = 0x153015302ee02eeL
let [<Literal>] opVex0F76 = 0x2ee026f02ee02eeL
let [<Literal>] opNor0F77 = 0x2ee02ee02ee02eeL
let [<Literal>] opVex0F77 = 0x2d802ee02ee02eeL
let [<Literal>] opNor0F7EB64 = 0x11e011e011e02eeL
let [<Literal>] opNor0F7EB32 = 0x10c010c011e02eeL
let [<Literal>] opVex0F7EB64 = 0x2ee0247024702eeL
let [<Literal>] opVex0F7EB32 = 0x2ee0234024702eeL
let [<Literal>] opNor0F7F = 0x11e010f011002eeL
let [<Literal>] opVex0F7F = 0x2ee0236023902eeL
let [<Literal>] opEVex0F7FB64 = 0x2ee023802ee02eeL
let [<Literal>] opEVex0F7FB32 = 0x2ee023702ee02eeL
let [<Literal>] opNor0FC4 = 0x167016702ee02eeL
let [<Literal>] opVex0FC4 = 0x2ee028302ee02eeL
let [<Literal>] opNor0FC5 = 0x15e015e02ee02eeL
let [<Literal>] opVex0FC5 = 0x2ee027a02ee02eeL
let [<Literal>] opNor0FC6 = 0x1f301f202ee02eeL
let [<Literal>] opVex0FC6 = 0x2cb02ca02ee02eeL
let [<Literal>] opNor0FD1 = 0x1a901a902ee02eeL
let [<Literal>] opVex0FD1 = 0x2ee02b702ee02eeL
let [<Literal>] opNor0FD2 = 0x1a601a602ee02eeL
let [<Literal>] opVex0FD2 = 0x2ee02b402ee02eeL
let [<Literal>] opNor0FD3 = 0x1a801a802ee02eeL
let [<Literal>] opVex0FD3 = 0x2ee02b602ee02eeL
let [<Literal>] opNor0FD4 = 0x146014602ee02eeL
let [<Literal>] opVex0FD4 = 0x2ee026202ee02eeL
let [<Literal>] opNor0FD5 = 0x187018702ee02eeL
let [<Literal>] opVex0FD5 = 0x2ee02a302ee02eeL
let [<Literal>] opNor0FD6 = 0x2ee011e011f010eL
let [<Literal>] opVex0FD6 = 0x2ee024702ee02eeL
let [<Literal>] opNor0FD7 = 0x175017502ee02eeL
let [<Literal>] opVex0FD7 = 0x2ee029102ee02eeL
let [<Literal>] opNor0FD8 = 0x1af01af02ee02eeL
let [<Literal>] opVex0FD8 = 0x2ee02bd02ee02eeL
let [<Literal>] opNor0FD9 = 0x1b001b002ee02eeL
let [<Literal>] opVex0FD9 = 0x2ee02be02ee02eeL
let [<Literal>] opNor0FDA = 0x172017202ee02eeL
let [<Literal>] opVex0FDA = 0x2ee028e02ee02eeL
let [<Literal>] opNor0FDB = 0x14d014d02ee02eeL
let [<Literal>] opVex0FDB = 0x2ee026902ee02eeL
let [<Literal>] opNor0FDC = 0x149014902ee02eeL
let [<Literal>] opVex0FDC = 0x2ee026502ee02eeL
let [<Literal>] opNor0FDD = 0x14a014a02ee02eeL
let [<Literal>] opVex0FDD = 0x2ee026602ee02eeL
let [<Literal>] opNor0FDE = 0x16c016c02ee02eeL
let [<Literal>] opVex0FDE = 0x2ee028802ee02eeL
let [<Literal>] opNor0FDF = 0x14e014e02ee02eeL
let [<Literal>] opVex0FDF = 0x2ee026a02ee02eeL
let [<Literal>] opNor0FE0 = 0x150015002ee02eeL
let [<Literal>] opVex0FE0 = 0x2ee026b02ee02eeL
let [<Literal>] opNor0FE1 = 0x1a501a502ee02eeL
let [<Literal>] opVex0FE1 = 0x2ee02b302ee02eeL
let [<Literal>] opNor0FE2 = 0x1a401a402ee02eeL
let [<Literal>] opVex0FE2 = 0x2ee02b202ee02eeL
let [<Literal>] opNor0FE3 = 0x151015102ee02eeL
let [<Literal>] opVex0FE3 = 0x2ee026c02ee02eeL
let [<Literal>] opNor0FE4 = 0x184018402ee02eeL
let [<Literal>] opVex0FE4 = 0x2ee02a002ee02eeL
let [<Literal>] opNor0FE5 = 0x185018502ee02eeL
let [<Literal>] opVex0FE5 = 0x2ee02a102ee02eeL
let [<Literal>] opNor0FE6 = 0x2ee005200420044L
let [<Literal>] opVex0FE6 = 0x2ee02ee02ee02eeL
let [<Literal>] opNor0FE7 = 0x11d011902ee02eeL
let [<Literal>] opVex0FE7 = 0x2ee024402ee02eeL
let [<Literal>] opEVex0FE7B64 = 0x2ee02ee02ee02eeL
let [<Literal>] opEVex0FE7B32 = 0x2ee024402ee02eeL
let [<Literal>] opNor0FE8 = 0x1ad01ad02ee02eeL
let [<Literal>] opVex0FE8 = 0x2ee02bb02ee02eeL
let [<Literal>] opNor0FE9 = 0x1ae01ae02ee02eeL
let [<Literal>] opVex0FE9 = 0x2ee02bc02ee02eeL
let [<Literal>] opNor0FEA = 0x171017102ee02eeL
let [<Literal>] opVex0FEA = 0x2ee028d02ee02eeL
let [<Literal>] opNor0FEB = 0x190019002ee02eeL
let [<Literal>] opVex0FEB = 0x2ee02a502ee02eeL
let [<Literal>] opNor0FEC = 0x147014702ee02eeL
let [<Literal>] opVex0FEC = 0x2ee026302ee02eeL
let [<Literal>] opNor0FED = 0x148014802ee02eeL
let [<Literal>] opVex0FED = 0x2ee026402ee02eeL
let [<Literal>] opNor0FEE = 0x16b016b02ee02eeL
let [<Literal>] opVex0FEE = 0x2ee028702ee02eeL
let [<Literal>] opNor0FEF = 0x1c101c102ee02eeL
let [<Literal>] opVex0FEF = 0x2ee02c902ee02eeL
let [<Literal>] opNor0FF0 = 0x2ee02ee02ee00e6L
let [<Literal>] opVex0FF0 = 0x2ee02ee02ee022dL
let [<Literal>] opNor0FF1 = 0x1a301a302ee02eeL
let [<Literal>] opVex0FF1 = 0x2ee02b102ee02eeL
let [<Literal>] opNor0FF2 = 0x1a001a002ee02eeL
let [<Literal>] opVex0FF2 = 0x2ee02ae02ee02eeL
let [<Literal>] opNor0FF3 = 0x1a201a202ee02eeL
let [<Literal>] opVex0FF3 = 0x2ee02b002ee02eeL
let [<Literal>] opNor0FF4 = 0x188018802ee02eeL
let [<Literal>] opVex0FF4 = 0x2ee02a402ee02eeL
let [<Literal>] opNor0FF5 = 0x168016802ee02eeL
let [<Literal>] opVex0FF5 = 0x2ee028402ee02eeL
let [<Literal>] opNor0FF6 = 0x197019702ee02eeL
let [<Literal>] opVex0FF6 = 0x2ee02a602ee02eeL
let [<Literal>] opNor0FF8 = 0x1aa01aa02ee02eeL
let [<Literal>] opVex0FF8 = 0x2ee02b802ee02eeL
let [<Literal>] opNor0FF9 = 0x1b101b102ee02eeL
let [<Literal>] opVex0FF9 = 0x2ee02bf02ee02eeL
let [<Literal>] opNor0FFA = 0x1ab01ab02ee02eeL
let [<Literal>] opVex0FFA = 0x2ee02b902ee02eeL
let [<Literal>] opNor0FFB = 0x1ac01ac02ee02eeL
let [<Literal>] opVex0FFB = 0x2ee02ba02ee02eeL
let [<Literal>] opNor0FFC = 0x144014402ee02eeL
let [<Literal>] opVex0FFC = 0x2ee026002ee02eeL
let [<Literal>] opNor0FFD = 0x14b014b02ee02eeL
let [<Literal>] opVex0FFD = 0x2ee026702ee02eeL
let [<Literal>] opNor0FFE = 0x145014502ee02eeL
let [<Literal>] opVex0FFE = 0x2ee026102ee02eeL
let [<Literal>] opNor0F3800 = 0x198019802ee02eeL
let [<Literal>] opVex0F3800 = 0x2ee02a702ee02eeL
let [<Literal>] opNor0F3801 = 0x161016102ee02eeL
let [<Literal>] opVex0F3801 = 0x2ee027d02ee02eeL
let [<Literal>] opNor0F3802 = 0x15f015f02ee02eeL
let [<Literal>] opVex0F3802 = 0x2ee027b02ee02eeL
let [<Literal>] opNor0F3803 = 0x160016002ee02eeL
let [<Literal>] opVex0F3803 = 0x2ee027c02ee02eeL
let [<Literal>] opNor0F3805 = 0x165016502ee02eeL
let [<Literal>] opVex0F3805 = 0x2ee028102ee02eeL
let [<Literal>] opNor0F3806 = 0x163016302ee02eeL
let [<Literal>] opVex0F3806 = 0x2ee027f02ee02eeL
let [<Literal>] opNor0F3807 = 0x164016402ee02eeL
let [<Literal>] opVex0F3807 = 0x2ee028002ee02eeL
let [<Literal>] opNor0F3808 = 0x19d019d02ee02eeL
let [<Literal>] opVex0F3808 = 0x2ee02ab02ee02eeL
let [<Literal>] opNor0F3809 = 0x19f019f02ee02eeL
let [<Literal>] opVex0F3809 = 0x2ee02ad02ee02eeL
let [<Literal>] opNor0F380A = 0x19e019e02ee02eeL
let [<Literal>] opVex0F380A = 0x2ee02ac02ee02eeL
let [<Literal>] opNor0F380B = 0x183018302ee02eeL
let [<Literal>] opVex0F380B = 0x2ee029f02ee02eeL
let [<Literal>] opNor0F3817 = 0x2ee01b202ee02eeL
let [<Literal>] opVex0F3817 = 0x2ee02c002ee02eeL
let [<Literal>] opNor0F3818 = 0x2ee02ee02ee02eeL
let [<Literal>] opVex0F3818 = 0x2ee021d02ee02eeL
let [<Literal>] opEVex0F3818 = 0x2ee021d02ee02eeL
let [<Literal>] opNor0F381C = 0x13d013d02ee02eeL
let [<Literal>] opVex0F381C = 0x2ee025902ee02eeL
let [<Literal>] opNor0F381D = 0x13f013f02ee02eeL
let [<Literal>] opVex0F381D = 0x2ee025b02ee02eeL
let [<Literal>] opNor0F381E = 0x13e013e02ee02eeL
let [<Literal>] opVex0F381E = 0x2ee025a02ee02eeL
let [<Literal>] opNor0F3820 = 0x2ee017802ee02eeL
let [<Literal>] opVex0F3820 = 0x2ee029402ee02eeL
let [<Literal>] opNor0F3821 = 0x2ee017602ee02eeL
let [<Literal>] opVex0F3821 = 0x2ee029202ee02eeL
let [<Literal>] opNor0F3822 = 0x2ee017702ee02eeL
let [<Literal>] opVex0F3822 = 0x2ee029302ee02eeL
let [<Literal>] opNor0F3823 = 0x2ee017a02ee02eeL
let [<Literal>] opVex0F3823 = 0x2ee029602ee02eeL
let [<Literal>] opNor0F3824 = 0x2ee017b02ee02eeL
let [<Literal>] opVex0F3824 = 0x2ee029702ee02eeL
let [<Literal>] opNor0F3825 = 0x2ee017902ee02eeL
let [<Literal>] opVex0F3825 = 0x2ee029502ee02eeL
let [<Literal>] opNor0F3828 = 0x2ee018202ee02eeL
let [<Literal>] opVex0F3828 = 0x2ee029e02ee02eeL
let [<Literal>] opNor0F3829 = 0x2ee015402ee02eeL
let [<Literal>] opVex0F3829 = 0x2ee027002ee02eeL
let [<Literal>] opNor0F382B = 0x2ee014202ee02eeL
let [<Literal>] opVex0F382B = 0x2ee025e02ee02eeL
let [<Literal>] opNor0F3830 = 0x2ee017e02ee02eeL
let [<Literal>] opVex0F3830 = 0x2ee029a02ee02eeL
let [<Literal>] opNor0F3831 = 0x2ee017c02ee02eeL
let [<Literal>] opVex0F3831 = 0x2ee029802ee02eeL
let [<Literal>] opNor0F3832 = 0x2ee017d02ee02eeL
let [<Literal>] opVex0F3832 = 0x2ee029902ee02eeL
let [<Literal>] opNor0F3833 = 0x2ee018002ee02eeL
let [<Literal>] opVex0F3833 = 0x2ee029c02ee02eeL
let [<Literal>] opNor0F3834 = 0x2ee018102ee02eeL
let [<Literal>] opVex0F3834 = 0x2ee029d02ee02eeL
let [<Literal>] opNor0F3835 = 0x2ee017f02ee02eeL
let [<Literal>] opVex0F3835 = 0x2ee029b02ee02eeL
let [<Literal>] opNor0F3837 = 0x2ee015a02ee02eeL
let [<Literal>] opVex0F3837 = 0x2ee027602ee02eeL
let [<Literal>] opNor0F3838 = 0x2ee016f02ee02eeL
let [<Literal>] opVex0F3838 = 0x2ee028b02ee02eeL
let [<Literal>] opNor0F3839 = 0x2ee017002ee02eeL
let [<Literal>] opVex0F3839 = 0x2ee028c02ee02eeL
let [<Literal>] opNor0F383A = 0x2ee017402ee02eeL
let [<Literal>] opVex0F383A = 0x2ee029002ee02eeL
let [<Literal>] opNor0F383B = 0x2ee017302ee02eeL
let [<Literal>] opVex0F383B = 0x2ee028f02ee02eeL
let [<Literal>] opNor0F383C = 0x2ee016902ee02eeL
let [<Literal>] opVex0F383C = 0x2ee028502ee02eeL
let [<Literal>] opNor0F383D = 0x2ee016a02ee02eeL
let [<Literal>] opVex0F383D = 0x2ee028602ee02eeL
let [<Literal>] opNor0F383E = 0x2ee016e02ee02eeL
let [<Literal>] opVex0F383E = 0x2ee028a02ee02eeL
let [<Literal>] opNor0F383F = 0x2ee016d02ee02eeL
let [<Literal>] opVex0F383F = 0x2ee028902ee02eeL
let [<Literal>] opNor0F3840 = 0x2ee018602ee02eeL
let [<Literal>] opVex0F3840 = 0x2ee02a202ee02eeL
let [<Literal>] opNor0F3841 = 0x2ee016202ee02eeL
let [<Literal>] opVex0F3841 = 0x2ee027e02ee02eeL
let [<Literal>] opNor0F385A = 0x2ee02ee02ee02eeL
let [<Literal>] opVex0F385A = 0x2ee021c02ee02eeL
let [<Literal>] opNor0F3878 = 0x2ee02ee02ee02eeL
let [<Literal>] opVex0F3878 = 0x2ee026d02ee02eeL
let [<Literal>] opNor0F38F0 = 0x14b010b02ee0041L
let [<Literal>] opNor0F38F1 = 0x14b010b02ee0041L
let [<Literal>] opNor0F3A0F = 0x14c014c02ee02eeL
let [<Literal>] opVex0F3A0F = 0x2ee026802ee02eeL
let [<Literal>] opNor0F3A20 = 0x2ee016602ee02eeL
let [<Literal>] opVex0F3A20 = 0x2ee02ee02ee02eeL
let [<Literal>] opNor0F3A38 = 0x2ee02ee02ee02eeL
let [<Literal>] opVex0F3A38 = 0x2ee022c02ee02eeL
let [<Literal>] opNor0F3A60 = 0x2ee015702ee02eeL
let [<Literal>] opVex0F3A60 = 0x2ee027302ee02eeL
let [<Literal>] opNor0F3A61 = 0x2ee015602ee02eeL
let [<Literal>] opVex0F3A61 = 0x2ee027202ee02eeL
let [<Literal>] opNor0F3A62 = 0x2ee015d02ee02eeL
let [<Literal>] opVex0F3A62 = 0x2ee027902ee02eeL
let [<Literal>] opNor0F3A63 = 0x2ee015c02ee02eeL
let [<Literal>] opVex0F3A63 = 0x2ee027802ee02eeL
let [<Literal>] opNor0F3A0B = 0x2ee01d302ee02eeL
let [<Literal>] opVex0F3A0B = 0x2ee02ee02ee02eeL
let [<Literal>] opEmpty = 0x2ee02ee02ee02eeL

let inline RegIb r =
  let reg: int64 = LanguagePrimitives.EnumToValue r |> int64
  (3L <<< 12 ||| reg) <<< 48 ||| (_Ib <<< 32)

let getOprMode oprDesc =
  match oprDesc &&& 0x3fL with
  | 0x1L -> OprMode.A
  | 0x2L -> OprMode.BndR
  | 0x3L -> OprMode.BndM
  | 0x4L -> OprMode.C
  | 0x5L -> OprMode.D
  | 0x6L -> OprMode.E
  | 0x7L -> OprMode.G
  | 0x8L -> OprMode.H
  | 0x9L -> OprMode.I
  | 0xaL -> OprMode.SI
  | 0xbL -> OprMode.J
  | 0xcL -> OprMode.M
  | 0xdL -> OprMode.MZ
  | 0xeL -> OprMode.N
  | 0xfL -> OprMode.O
  | 0x10L-> OprMode.P
  | 0x11L -> OprMode.Q
  | 0x12L -> OprMode.R
  | 0x13L -> OprMode.S
  | 0x14L -> OprMode.U
  | 0x15L -> OprMode.V
  | 0x16L -> OprMode.VZ
  | 0x17L -> OprMode.W
  | 0x18L -> OprMode.WZ
  | 0x19L -> OprMode.X
  | 0x1aL -> OprMode.Y
  | 0x1bL -> OprMode.E0
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

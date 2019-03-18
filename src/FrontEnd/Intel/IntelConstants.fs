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
let [<Literal>] _SIz = 0x270aL
let [<Literal>] Ap = 0x2281000000000000L
let [<Literal>] Dd = 0x2105000000000000L
let [<Literal>] E0v = 0x25db000000000000L
let [<Literal>] Eb = 0x2086000000000000L
let [<Literal>] Ep = 0x2286000000000000L
let [<Literal>] Ev = 0x25c6000000000000L
let [<Literal>] Ew = 0x2606000000000000L
let [<Literal>] Ey = 0x26c6000000000000L
let [<Literal>] Gb = 0x2087000000000000L
let [<Literal>] Gd = 0x2107000000000000L
let [<Literal>] Gv = 0x25c7000000000000L
let [<Literal>] Gw = 0x2607000000000000L
let [<Literal>] Gy = 0x26c7000000000000L
let [<Literal>] Gz = 0x2707000000000000L
let [<Literal>] Jb = 0x208b000000000000L
let [<Literal>] Jz = 0x270b000000000000L
let [<Literal>] Ib = 0x2089000000000000L
let [<Literal>] Iv = 0x25c9000000000000L
let [<Literal>] Iw = 0x2609000000000000L
let [<Literal>] Iz = 0x2709000000000000L
let [<Literal>] Ma = 0x204c000000000000L
let [<Literal>] Mdq = 0x218c000000000000L
let [<Literal>] Mp = 0x228c000000000000L
let [<Literal>] Mq = 0x23cc000000000000L
let [<Literal>] Ms = 0x244c000000000000L
let [<Literal>] Mv = 0x25cc000000000000L
let [<Literal>] Mw = 0x260c000000000000L
let [<Literal>] My = 0x26cc000000000000L
let [<Literal>] Mz = 0x270c000000000000L
let [<Literal>] Pd = 0x2110000000000000L
let [<Literal>] Pq = 0x23d0000000000000L
let [<Literal>] Qq = 0x23d1000000000000L
let [<Literal>] Rd = 0x2112000000000000L
let [<Literal>] Rv = 0x25d2000000000000L
let [<Literal>] Ry = 0x26d2000000000000L
let [<Literal>] SIb = 0x208a000000000000L
let [<Literal>] SIv = 0x25ca000000000000L
let [<Literal>] SIw = 0x260a000000000000L
let [<Literal>] SIz = 0x270a000000000000L
let [<Literal>] Sw = 0x2613000000000000L
let [<Literal>] Vdq = 0x2195000000000000L
let [<Literal>] Vx = 0x2655000000000000L
let [<Literal>] Wdq = 0x2197000000000000L
let [<Literal>] Wdqd = 0x21d7000000000000L
let [<Literal>] Wdqq = 0x2217000000000000L
let [<Literal>] Wx = 0x2657000000000000L
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
let [<Literal>] Ev1L = 0x25c6100000000000L
let [<Literal>] EvCL = 0x25c6301a00000000L
let [<Literal>] EvGv = 0x25c625c700000000L
let [<Literal>] EvIb = 0x25c6208900000000L
let [<Literal>] EvIz = 0x25c6270900000000L
let [<Literal>] EvSIb = 0x25c6208a00000000L
let [<Literal>] EvSIz = 0x25c6270a00000000L
let [<Literal>] EvSw = 0x25c6261300000000L
let [<Literal>] EwGw = 0x2606260700000000L
let [<Literal>] EyPd = 0x26c6211000000000L
let [<Literal>] EyPq = 0x26c623d000000000L
let [<Literal>] EyVdq = 0x26c6219500000000L
let [<Literal>] GbEb = 0x2087208600000000L
let [<Literal>] GdEb = 0x2107208600000000L
let [<Literal>] GdEw = 0x2107260600000000L
let [<Literal>] GdEy = 0x210726c600000000L
let [<Literal>] GdNq = 0x210723ce00000000L
let [<Literal>] GdUdq = 0x2107219400000000L
let [<Literal>] GdUx = 0x2107265400000000L
let [<Literal>] GvEb = 0x25c7208600000000L
let [<Literal>] GvEd = 0x25c7210600000000L
let [<Literal>] GvEv = 0x25c725c600000000L
let [<Literal>] GvEw = 0x25c7260600000000L
let [<Literal>] GvEy = 0x25c726c600000000L
let [<Literal>] GvMa = 0x25c7204c00000000L
let [<Literal>] GvMp = 0x25c7228c00000000L
let [<Literal>] GvMv = 0x25c725cc00000000L
let [<Literal>] GwMw = 0x2607260c00000000L
let [<Literal>] GyMy = 0x26c726cc00000000L
let [<Literal>] GyUdq = 0x26c7219400000000L
let [<Literal>] GyUpd = 0x26c722d400000000L
let [<Literal>] GyUps = 0x26c7235400000000L
let [<Literal>] GyUx = 0x26c7265400000000L
let [<Literal>] GyWdq = 0x26c7219700000000L
let [<Literal>] GyWsd = 0x26c7249700000000L
let [<Literal>] GyWsdq = 0x26c724d700000000L
let [<Literal>] GyWss = 0x26c7251700000000L
let [<Literal>] GyWssd = 0x26c7255700000000L
let [<Literal>] GzMp = 0x2707228c00000000L
let [<Literal>] IbAL = 0x2089301800000000L
let [<Literal>] IwIb = 0x2609208900000000L
let [<Literal>] MdqVdq = 0x218c219500000000L
let [<Literal>] MpdVpd = 0x22cc22d500000000L
let [<Literal>] MpsVps = 0x234c235500000000L
let [<Literal>] MqPq = 0x23cc23d000000000L
let [<Literal>] MqVdq = 0x23cc219500000000L
let [<Literal>] MwGw = 0x2607260c00000000L
let [<Literal>] MxVx = 0x264c265500000000L
let [<Literal>] MyGy = 0x26cc26c700000000L
let [<Literal>] MZxzVZxz = 0x268d269600000000L
let [<Literal>] NqIb = 0x23ce208900000000L
let [<Literal>] ObAL = 0x208f301800000000L
let [<Literal>] PdEy = 0x211026c600000000L
let [<Literal>] PpiWdq = 0x2310219700000000L
let [<Literal>] PpiWdqq = 0x2310221700000000L
let [<Literal>] PpiWpd = 0x231022d700000000L
let [<Literal>] PpiWps = 0x2310235700000000L
let [<Literal>] PpiWpsq = 0x2310239700000000L
let [<Literal>] PqEy = 0x23d026c600000000L
let [<Literal>] PqQd = 0x23d0211100000000L
let [<Literal>] PqQq = 0x23d023d100000000L
let [<Literal>] PqUdq = 0x23d0219400000000L
let [<Literal>] PqWdq = 0x23d0219700000000L
let [<Literal>] QpiWpd = 0x231122d700000000L
let [<Literal>] QqPq = 0x23d123d000000000L
let [<Literal>] RdCd = 0x2112210400000000L
let [<Literal>] RdDd = 0x2112210500000000L
let [<Literal>] SwEw = 0x2613260600000000L
let [<Literal>] UdqIb = 0x2194208900000000L
let [<Literal>] VdqEdbIb = 0x2195214620890000L
let [<Literal>] VdqEy = 0x219526c600000000L
let [<Literal>] VdqMdq = 0x2195218c00000000L
let [<Literal>] VdqMq = 0x219523cc00000000L
let [<Literal>] VdqNq = 0x219523ce00000000L
let [<Literal>] VdqQq = 0x219523d100000000L
let [<Literal>] VdqUdq = 0x2195219400000000L
let [<Literal>] VdqWdq = 0x2195219700000000L
let [<Literal>] VdqWdqd = 0x219521d700000000L
let [<Literal>] VdqWdqq = 0x2195221700000000L
let [<Literal>] VpdWpd = 0x22d522d700000000L
let [<Literal>] VpsHpsWpsIb = 0x2355234823572089L
let [<Literal>] VpsWps = 0x2355235700000000L
let [<Literal>] VqqMdq = 0x2415218c00000000L
let [<Literal>] VsdWsd = 0x2495249700000000L
let [<Literal>] VsdWsdq = 0x249524d700000000L
let [<Literal>] VssWss = 0x2515251700000000L
let [<Literal>] VssWssd = 0x2515255700000000L
let [<Literal>] VxMd = 0x2655210c00000000L
let [<Literal>] VxMx = 0x2655264c00000000L
let [<Literal>] VxWss = 0x2655251700000000L
let [<Literal>] VxWssd = 0x2655255700000000L
let [<Literal>] VxWssq = 0x2655259700000000L
let [<Literal>] VxWx = 0x2655265700000000L
let [<Literal>] VyEy = 0x26d526c600000000L
let [<Literal>] VZxzWdqd = 0x269621d700000000L
let [<Literal>] VZxzWZxz = 0x2696269800000000L
let [<Literal>] WdqVdq = 0x2197219500000000L
let [<Literal>] WdqdVdq = 0x21d7219500000000L
let [<Literal>] WdqqVdq = 0x2217219500000000L
let [<Literal>] WpdVpd = 0x22d722d500000000L
let [<Literal>] WpsVps = 0x2357235500000000L
let [<Literal>] WssVx = 0x2517265500000000L
let [<Literal>] WssdVx = 0x2557265500000000L
let [<Literal>] WxVx = 0x2657265500000000L
let [<Literal>] WZxzVZxz = 0x2698269600000000L
let [<Literal>] XbYb = 0x2099209a00000000L
let [<Literal>] XvYv = 0x25d925da00000000L
let [<Literal>] YbXb = 0x209a209900000000L
let [<Literal>] YvXv = 0x25da25d900000000L
let [<Literal>] EvGvCL = 0x25c625c7301a0000L
let [<Literal>] EvGvIb = 0x25c625c720890000L
let [<Literal>] GdNqIb = 0x210723ce20890000L
let [<Literal>] GdUdqIb = 0x2107219420890000L
let [<Literal>] GvEvIb = 0x25c725c620890000L
let [<Literal>] GvEvIz = 0x25c725c627090000L
let [<Literal>] GvEvSIb = 0x25c725c6208a0000L
let [<Literal>] GvEvSIz = 0x25c725c6270a0000L
let [<Literal>] HxUxIb = 0x2648265420890000L
let [<Literal>] PqEdwIb = 0x23d0224620890000L
let [<Literal>] PqQqIb = 0x23d023d120890000L
let [<Literal>] VdqHdqMdq = 0x21952188218c0000L
let [<Literal>] VdqHdqMdqd = 0x2195218821cc0000L
let [<Literal>] VdqHdqMq = 0x2195218823cc0000L
let [<Literal>] VdqHdqUdq = 0x2195218821940000L
let [<Literal>] VdqEdwIb = 0x2195224620890000L
let [<Literal>] VdqWdqIb = 0x2195219720890000L
let [<Literal>] VsdHsdEy = 0x2495248826c60000L
let [<Literal>] VssHssEy = 0x2515250826c60000L
let [<Literal>] VsdHsdWsd = 0x2495248824970000L
let [<Literal>] VsdHsdWsdq = 0x2495248824d70000L
let [<Literal>] VsdWsdIb = 0x2495249720890000L
let [<Literal>] VssHssWss = 0x2515250825170000L
let [<Literal>] VssHssWssd = 0x2515250825570000L
let [<Literal>] VpdHpdWpd = 0x22d522c822d70000L
let [<Literal>] VpsHpsWps = 0x2355234823570000L
let [<Literal>] VxHxWdq = 0x2655264821970000L
let [<Literal>] VxHxWsd = 0x2655264824970000L
let [<Literal>] VxHxWss = 0x2655264825170000L
let [<Literal>] VxHxWx = 0x2655264826570000L
let [<Literal>] VxWxIb = 0x2655265720890000L
let [<Literal>] WsdHxVsd = 0x2497264824950000L
let [<Literal>] WssHxVss = 0x2517264825150000L
let [<Literal>] VdqHdqEdwIb = 0x2195218822462089L
let [<Literal>] VxHxWxIb = 0x2655264826572089L
let [<Literal>] VqqHqqWdqIb = 0x2415240821972089L
let [<Literal>] RGzRGz = 0x4704470200000000L
let [<Literal>] RGvSIz = 0x45c4270a00000000L
let [<Literal>] RGvDX = 0x45c4301300000000L
let [<Literal>] DXRGv = 0x301345c400000000L
let [<Literal>] ORES = 0x3600000000000000L
let [<Literal>] ORCS = 0x3601000000000000L
let [<Literal>] ORSS = 0x3602000000000000L
let [<Literal>] ORDS = 0x3603000000000000L
let [<Literal>] ORFS = 0x3604000000000000L
let [<Literal>] ORGS = 0x3605000000000000L
let [<Literal>] GvG0T = 0x45c2000000000000L
let [<Literal>] GvG1T = 0x45ca000000000000L
let [<Literal>] GvG2T = 0x45d2000000000000L
let [<Literal>] GvG3T = 0x45da000000000000L
let [<Literal>] GvG4T = 0x45e2000000000000L
let [<Literal>] GvG5T = 0x45ea000000000000L
let [<Literal>] GvG6T = 0x45f2000000000000L
let [<Literal>] GvG7T = 0x45fa000000000000L
let [<Literal>] GzG0T = 0x4702000000000000L
let [<Literal>] GzG1T = 0x470a000000000000L
let [<Literal>] GzG2T = 0x4712000000000000L
let [<Literal>] GzG3T = 0x471a000000000000L
let [<Literal>] GzG4T = 0x4722000000000000L
let [<Literal>] GzG5T = 0x472a000000000000L
let [<Literal>] GzG6T = 0x4732000000000000L
let [<Literal>] GzG7T = 0x473a000000000000L
let [<Literal>] GzG0F = 0x4704000000000000L
let [<Literal>] GzG1F = 0x470c000000000000L
let [<Literal>] GzG2F = 0x4714000000000000L
let [<Literal>] GzG3F = 0x471c000000000000L
let [<Literal>] GzG4F = 0x4724000000000000L
let [<Literal>] GzG5F = 0x472c000000000000L
let [<Literal>] GzG6F = 0x4734000000000000L
let [<Literal>] GzG7F = 0x473c000000000000L
let [<Literal>] GvG0TOv = 0x45c225cf00000000L
let [<Literal>] GvG1TOv = 0x45ca25cf00000000L
let [<Literal>] GvG2TOv = 0x45d225cf00000000L
let [<Literal>] GvG3TOv = 0x45da25cf00000000L
let [<Literal>] GvG4TOv = 0x45e225cf00000000L
let [<Literal>] GvG5TOv = 0x45ea25cf00000000L
let [<Literal>] GvG6TOv = 0x45f225cf00000000L
let [<Literal>] GvG7TOv = 0x45fa25cf00000000L
let [<Literal>] GvG0FOv = 0x45c425cf00000000L
let [<Literal>] GvG1FOv = 0x45cc25cf00000000L
let [<Literal>] GvG2FOv = 0x45d425cf00000000L
let [<Literal>] GvG3FOv = 0x45dc25cf00000000L
let [<Literal>] GvG4FOv = 0x45e425cf00000000L
let [<Literal>] GvG5FOv = 0x45ec25cf00000000L
let [<Literal>] GvG6FOv = 0x45f425cf00000000L
let [<Literal>] GvG7FOv = 0x45fc25cf00000000L
let [<Literal>] OvGvG0T = 0x25cf45c200000000L
let [<Literal>] OvGvG1T = 0x25cf45ca00000000L
let [<Literal>] OvGvG2T = 0x25cf45d200000000L
let [<Literal>] OvGvG3T = 0x25cf45da00000000L
let [<Literal>] OvGvG4T = 0x25cf45e200000000L
let [<Literal>] OvGvG5T = 0x25cf45ea00000000L
let [<Literal>] OvGvG6T = 0x25cf45f200000000L
let [<Literal>] OvGvG7T = 0x25cf45fa00000000L
let [<Literal>] OvGvG0F = 0x25cf45c400000000L
let [<Literal>] OvGvG1F = 0x25cf45cc00000000L
let [<Literal>] OvGvG2F = 0x25cf45d400000000L
let [<Literal>] OvGvG3F = 0x25cf45dc00000000L
let [<Literal>] OvGvG4F = 0x25cf45e400000000L
let [<Literal>] OvGvG5F = 0x25cf45ec00000000L
let [<Literal>] OvGvG6F = 0x25cf45f400000000L
let [<Literal>] OvGvG7F = 0x25cf45fc00000000L
let [<Literal>] GvG0FGvG0T = 0x45c445c200000000L
let [<Literal>] GvG0FGvG1T = 0x45c445ca00000000L
let [<Literal>] GvG0FGvG2T = 0x45c445d200000000L
let [<Literal>] GvG0FGvG3T = 0x45c445da00000000L
let [<Literal>] GvG0FGvG4T = 0x45c445e200000000L
let [<Literal>] GvG0FGvG5T = 0x45c445ea00000000L
let [<Literal>] GvG0FGvG6T = 0x45c445f200000000L
let [<Literal>] GvG0FGvG7T = 0x45c445fa00000000L
let [<Literal>] GvG0TIb = 0x45c2208900000000L
let [<Literal>] GvG1TIb = 0x45ca208900000000L
let [<Literal>] GvG2TIb = 0x45d2208900000000L
let [<Literal>] GvG3TIb = 0x45da208900000000L
let [<Literal>] GvG4TIb = 0x45e2208900000000L
let [<Literal>] GvG5TIb = 0x45ea208900000000L
let [<Literal>] GvG6TIb = 0x45f2208900000000L
let [<Literal>] GvG7TIb = 0x45fa208900000000L
let [<Literal>] GvG0FIb = 0x45c4208900000000L
let [<Literal>] GvG1FIb = 0x45cc208900000000L
let [<Literal>] GvG2FIb = 0x45d4208900000000L
let [<Literal>] GvG3FIb = 0x45dc208900000000L
let [<Literal>] GvG4FIb = 0x45e4208900000000L
let [<Literal>] GvG5FIb = 0x45ec208900000000L
let [<Literal>] GvG6FIb = 0x45f4208900000000L
let [<Literal>] GvG7FIb = 0x45fc208900000000L
let [<Literal>] IbGvG0T = 0x208945c200000000L
let [<Literal>] IbGvG1T = 0x208945ca00000000L
let [<Literal>] IbGvG2T = 0x208945d200000000L
let [<Literal>] IbGvG3T = 0x208945da00000000L
let [<Literal>] IbGvG4T = 0x208945e200000000L
let [<Literal>] IbGvG5T = 0x208945ea00000000L
let [<Literal>] IbGvG6T = 0x208945f200000000L
let [<Literal>] IbGvG7T = 0x208945fa00000000L
let [<Literal>] IbGvG0F = 0x208945c400000000L
let [<Literal>] IbGvG1F = 0x208945cc00000000L
let [<Literal>] IbGvG2F = 0x208945d400000000L
let [<Literal>] IbGvG3F = 0x208945dc00000000L
let [<Literal>] IbGvG4F = 0x208945e400000000L
let [<Literal>] IbGvG5F = 0x208945ec00000000L
let [<Literal>] IbGvG6F = 0x208945f400000000L
let [<Literal>] IbGvG7F = 0x208945fc00000000L
let [<Literal>] GvG0TIv = 0x45c225c900000000L
let [<Literal>] GvG1TIv = 0x45ca25c900000000L
let [<Literal>] GvG2TIv = 0x45d225c900000000L
let [<Literal>] GvG3TIv = 0x45da25c900000000L
let [<Literal>] GvG4TIv = 0x45e225c900000000L
let [<Literal>] GvG5TIv = 0x45ea25c900000000L
let [<Literal>] GvG6TIv = 0x45f225c900000000L
let [<Literal>] GvG7TIv = 0x45fa25c900000000L
let [<Literal>] GvG0FIv = 0x45c425c900000000L
let [<Literal>] GvG1FIv = 0x45cc25c900000000L
let [<Literal>] GvG2FIv = 0x45d425c900000000L
let [<Literal>] GvG3FIv = 0x45dc25c900000000L
let [<Literal>] GvG4FIv = 0x45e425c900000000L
let [<Literal>] GvG5FIv = 0x45ec25c900000000L
let [<Literal>] GvG6FIv = 0x45f425c900000000L
let [<Literal>] GvG7FIv = 0x45fc25c900000000L

(*
type VEXOpcodes
+-----------------+------------------+-----------------+------------------+
| Opcode (16Byte) || Opcode (16Byte) | Opcode (16Byte) || Opcode (16Byte) |
+-----------------+------------------+-----------------+------------------+
*)
let [<Literal>] opNor0F1A = 0x2a3001002a302a3L
let [<Literal>] opNor0F1B = 0x2a3001002a302a3L
let [<Literal>] opNor0F10 = 0x12a012901240121L
let [<Literal>] opVex0F10Mem = 0x228022702260223L
let [<Literal>] opVex0F10Reg = 0x228022702260223L
let [<Literal>] opNor0F11 = 0x12a012901240121L
let [<Literal>] opVex0F11Mem = 0x228022702260223L
let [<Literal>] opVex0F11Reg = 0x228022702260223L
let [<Literal>] opNor0F12Mem = 0x11601150123010dL
let [<Literal>] opNor0F12Reg = 0x11101150123010dL
let [<Literal>] opVex0F12Mem = 0x21c021b02250210L
let [<Literal>] opVex0F12Reg = 0x217021b02250210L
let [<Literal>] opNor0F13 = 0x116011502a302a3L
let [<Literal>] opVex0F13 = 0x21c021b02a302a3L
let [<Literal>] opNor0F14 = 0x1ee01ed02a302a3L
let [<Literal>] opVex0F14 = 0x28a028902a302a3L
let [<Literal>] opNor0F15 = 0x1ec01eb02a302a3L
let [<Literal>] opVex0F15 = 0x288028702a302a3L
let [<Literal>] opNor0F16Mem = 0x1130112012202a3L
let [<Literal>] opNor0F16Reg = 0x1140112012202a3L
let [<Literal>] opVex0F16Mem = 0x2190218022402a3L
let [<Literal>] opVex0F16Reg = 0x21a0218022402a3L
let [<Literal>] opNor0F17 = 0x113011202a302a3L
let [<Literal>] opVex0F17 = 0x219021802a302a3L
let [<Literal>] opNor0F28 = 0x10a010902a302a3L
let [<Literal>] opVex0F28 = 0x20e020d02a302a3L
let [<Literal>] opNor0F29 = 0x10a010902a302a3L
let [<Literal>] opVex0F29 = 0x20e020e02a302a3L
let [<Literal>] opNor0F2A = 0x480047004f004eL
let [<Literal>] opVex0F2A = 0x2a302a301fd01fcL
let [<Literal>] opNor0F2B = 0x11c011b02a302a3L
let [<Literal>] opVex0F2B = 0x221022002a302a3L
let [<Literal>] opNor0F2C = 0x55005300570056L
let [<Literal>] opVex0F2C = 0x2a302a3020001ffL
let [<Literal>] opNor0F2D = 0x4b00450051004cL
let [<Literal>] opVex0F2D = 0x2a302a301fe01fbL
let [<Literal>] opNor0F2E = 0x1e901e802a302a3L
let [<Literal>] opVex0F2E = 0x286028502a302a3L
let [<Literal>] opNor0F2F = 0x3e003d02a302a3L
let [<Literal>] opVex0F2F = 0x1fa01f902a302a3L
let [<Literal>] opNor0F50 = 0x118011702a302a3L
let [<Literal>] opVex0F50 = 0x21e021d02a302a3L
let [<Literal>] opNor0F54 = 0xe000d02a302a3L
let [<Literal>] opVex0F54 = 0x1f601f502a302a3L
let [<Literal>] opNor0F55 = 0xc000b02a302a3L
let [<Literal>] opVex0F55 = 0x1f401f302a302a3L
let [<Literal>] opNor0F56 = 0x137013602a302a3L
let [<Literal>] opVex0F56 = 0x233023202a302a3L
let [<Literal>] opNor0F57 = 0x29d029c02a302a3L
let [<Literal>] opVex0F57 = 0x28c028b02a302a3L
let [<Literal>] opNor0F58 = 0x7000600090008L
let [<Literal>] opVex0F58 = 0x1f001ef01f201f1L
let [<Literal>] opNor0F59 = 0x12e012d0130012fL
let [<Literal>] opVex0F59 = 0x22d022c022f022eL
let [<Literal>] opNor0F5A = 0x4a00460050004dL
let [<Literal>] opVex0F5A = 0x2a302a302a302a3L
let [<Literal>] opNor0F5B = 0x430049005402a3L
let [<Literal>] opVex0F5B = 0x2a302a302a302a3L
let [<Literal>] opNor0F5C = 0x1de01dd01e001dfL
let [<Literal>] opVex0F5C = 0x282028102840283L
let [<Literal>] opNor0F5D = 0x104010301060105L
let [<Literal>] opVex0F5D = 0x2a302a302a302a3L
let [<Literal>] opNor0F5E = 0x5f005e00610060L
let [<Literal>] opVex0F5E = 0x202020102040203L
let [<Literal>] opNor0F5F = 0xfe00ff01010100L
let [<Literal>] opVex0F5F = 0x2a302a302a302a3L
let [<Literal>] opNor0F60 = 0x192019202a302a3L
let [<Literal>] opVex0F60 = 0x2a3027a02a302a3L
let [<Literal>] opNor0F61 = 0x195019502a302a3L
let [<Literal>] opVex0F61 = 0x2a3027d02a302a3L
let [<Literal>] opNor0F62 = 0x193019302a302a3L
let [<Literal>] opVex0F62 = 0x2a3027b02a302a3L
let [<Literal>] opNor0F63 = 0x13e013e02a302a3L
let [<Literal>] opVex0F63 = 0x2a3023502a302a3L
let [<Literal>] opNor0F64 = 0x153015302a302a3L
let [<Literal>] opVex0F64 = 0x2a3024a02a302a3L
let [<Literal>] opNor0F65 = 0x155015502a302a3L
let [<Literal>] opVex0F65 = 0x2a3024c02a302a3L
let [<Literal>] opNor0F66 = 0x154015402a302a3L
let [<Literal>] opVex0F66 = 0x2a3024b02a302a3L
let [<Literal>] opNor0F67 = 0x13f013f02a302a3L
let [<Literal>] opVex0F67 = 0x2a3023602a302a3L
let [<Literal>] opNor0F68 = 0x18e018e02a302a3L
let [<Literal>] opVex0F68 = 0x2a3027602a302a3L
let [<Literal>] opNor0F69 = 0x191019102a302a3L
let [<Literal>] opVex0F69 = 0x2a3027902a302a3L
let [<Literal>] opNor0F6A = 0x18f018f02a302a3L
let [<Literal>] opVex0F6A = 0x2a3027702a302a3L
let [<Literal>] opNor0F6B = 0x13d013d02a302a3L
let [<Literal>] opVex0F6B = 0x2a3023402a302a3L
let [<Literal>] opNor0F6C = 0x2a3019402a302a3L
let [<Literal>] opVex0F6C = 0x2a3027c02a302a3L
let [<Literal>] opNor0F6D = 0x2a3019002a302a3L
let [<Literal>] opVex0F6D = 0x2a3027802a302a3L
let [<Literal>] opNor0F6EB64 = 0x11e011e02a302a3L
let [<Literal>] opNor0F6EB32 = 0x10c010c02a302a3L
let [<Literal>] opVex0F6EB64 = 0x2a3022202a302a3L
let [<Literal>] opVex0F6EB32 = 0x2a3020f02a302a3L
let [<Literal>] opNor0F6F = 0x11e010f011002a3L
let [<Literal>] opVex0F6F = 0x2a30211021402a3L
let [<Literal>] opEVex0F6FB64 = 0x2a30213021602a3L
let [<Literal>] opEVex0F6FB32 = 0x2a30212021502a3L
let [<Literal>] opNor0F70 = 0x17a017701780179L
let [<Literal>] opVex0F70 = 0x2a3026002610262L
let [<Literal>] opNor0F74 = 0x14e014e02a302a3L
let [<Literal>] opVex0F74 = 0x2a3024502a302a3L
let [<Literal>] opNor0F76 = 0x14f014f02a302a3L
let [<Literal>] opVex0F76 = 0x2a3024602a302a3L
let [<Literal>] opNor0F77 = 0x2a302a302a302a3L
let [<Literal>] opVex0F77 = 0x28d02a302a302a3L
let [<Literal>] opNor0F7EB64 = 0x11e011e011e02a3L
let [<Literal>] opNor0F7EB32 = 0x10c010c011e02a3L
let [<Literal>] opVex0F7EB64 = 0x2a30222022202a3L
let [<Literal>] opVex0F7EB32 = 0x2a3020f022202a3L
let [<Literal>] opNor0F7F = 0x11e010f011002a3L
let [<Literal>] opVex0F7F = 0x2a30211021402a3L
let [<Literal>] opEVex0F7FB64 = 0x2a3021302a302a3L
let [<Literal>] opEVex0F7FB32 = 0x2a3021202a302a3L
let [<Literal>] opNor0FC4 = 0x15a015a02a302a3L
let [<Literal>] opVex0FC4 = 0x2a3025102a302a3L
let [<Literal>] opNor0FC5 = 0x158015802a302a3L
let [<Literal>] opVex0FC5 = 0x2a3024f02a302a3L
let [<Literal>] opNor0FC6 = 0x1ce01cd02a302a3L
let [<Literal>] opVex0FC6 = 0x280027f02a302a3L
let [<Literal>] opNor0FD1 = 0x184018402a302a3L
let [<Literal>] opVex0FD1 = 0x2a3026c02a302a3L
let [<Literal>] opNor0FD2 = 0x181018102a302a3L
let [<Literal>] opVex0FD2 = 0x2a3026902a302a3L
let [<Literal>] opNor0FD3 = 0x183018302a302a3L
let [<Literal>] opVex0FD3 = 0x2a3026b02a302a3L
let [<Literal>] opNor0FD4 = 0x142014202a302a3L
let [<Literal>] opVex0FD4 = 0x2a3023902a302a3L
let [<Literal>] opNor0FD5 = 0x165016502a302a3L
let [<Literal>] opVex0FD5 = 0x2a3025b02a302a3L
let [<Literal>] opNor0FD6 = 0x2a3011e011f010eL
let [<Literal>] opVex0FD6 = 0x2a3022202a302a3L
let [<Literal>] opNor0FD7 = 0x162016202a302a3L
let [<Literal>] opVex0FD7 = 0x2a3025802a302a3L
let [<Literal>] opNor0FD8 = 0x18a018a02a302a3L
let [<Literal>] opVex0FD8 = 0x2a3027202a302a3L
let [<Literal>] opNor0FD9 = 0x18b018b02a302a3L
let [<Literal>] opVex0FD9 = 0x2a3027302a302a3L
let [<Literal>] opNor0FDA = 0x15f015f02a302a3L
let [<Literal>] opVex0FDA = 0x2a3025602a302a3L
let [<Literal>] opNor0FDB = 0x149014902a302a3L
let [<Literal>] opVex0FDB = 0x2a3024002a302a3L
let [<Literal>] opNor0FDC = 0x145014502a302a3L
let [<Literal>] opVex0FDC = 0x2a3023c02a302a3L
let [<Literal>] opNor0FDD = 0x146014602a302a3L
let [<Literal>] opVex0FDD = 0x2a3023d02a302a3L
let [<Literal>] opNor0FDE = 0x15d015d02a302a3L
let [<Literal>] opVex0FDE = 0x2a3025402a302a3L
let [<Literal>] opNor0FDF = 0x14a014a02a302a3L
let [<Literal>] opVex0FDF = 0x2a3024102a302a3L
let [<Literal>] opNor0FE0 = 0x14b014b02a302a3L
let [<Literal>] opVex0FE0 = 0x2a3024202a302a3L
let [<Literal>] opNor0FE1 = 0x180018002a302a3L
let [<Literal>] opVex0FE1 = 0x2a3026802a302a3L
let [<Literal>] opNor0FE2 = 0x17f017f02a302a3L
let [<Literal>] opVex0FE2 = 0x2a3026702a302a3L
let [<Literal>] opNor0FE3 = 0x14c014c02a302a3L
let [<Literal>] opVex0FE3 = 0x2a3024302a302a3L
let [<Literal>] opNor0FE4 = 0x163016302a302a3L
let [<Literal>] opVex0FE4 = 0x2a3025902a302a3L
let [<Literal>] opNor0FE5 = 0x164016402a302a3L
let [<Literal>] opVex0FE5 = 0x2a3025a02a302a3L
let [<Literal>] opNor0FE6 = 0x2a3005200420044L
let [<Literal>] opVex0FE6 = 0x2a302a302a302a3L
let [<Literal>] opNor0FE7 = 0x11d011902a302a3L
let [<Literal>] opVex0FE7 = 0x2a3021f02a302a3L
let [<Literal>] opEVex0FE7B64 = 0x2a302a302a302a3L
let [<Literal>] opEVex0FE7B32 = 0x2a3021f02a302a3L
let [<Literal>] opNor0FE8 = 0x188018802a302a3L
let [<Literal>] opVex0FE8 = 0x2a3027002a302a3L
let [<Literal>] opNor0FE9 = 0x189018902a302a3L
let [<Literal>] opVex0FE9 = 0x2a3027102a302a3L
let [<Literal>] opNor0FEA = 0x15e015e02a302a3L
let [<Literal>] opVex0FEA = 0x2a3025502a302a3L
let [<Literal>] opNor0FEB = 0x16e016e02a302a3L
let [<Literal>] opVex0FEB = 0x2a3025d02a302a3L
let [<Literal>] opNor0FEC = 0x143014302a302a3L
let [<Literal>] opVex0FEC = 0x2a3023a02a302a3L
let [<Literal>] opNor0FED = 0x144014402a302a3L
let [<Literal>] opVex0FED = 0x2a3023b02a302a3L
let [<Literal>] opNor0FEE = 0x15c015c02a302a3L
let [<Literal>] opVex0FEE = 0x2a3025302a302a3L
let [<Literal>] opNor0FEF = 0x19c019c02a302a3L
let [<Literal>] opVex0FEF = 0x2a3027e02a302a3L
let [<Literal>] opNor0FF0 = 0x2a302a302a300e6L
let [<Literal>] opVex0FF0 = 0x2a302a302a30208L
let [<Literal>] opNor0FF1 = 0x17e017e02a302a3L
let [<Literal>] opVex0FF1 = 0x2a3026602a302a3L
let [<Literal>] opNor0FF2 = 0x17b017b02a302a3L
let [<Literal>] opVex0FF2 = 0x2a3026302a302a3L
let [<Literal>] opNor0FF3 = 0x17d017d02a302a3L
let [<Literal>] opVex0FF3 = 0x2a3026502a302a3L
let [<Literal>] opNor0FF4 = 0x166016602a302a3L
let [<Literal>] opVex0FF4 = 0x2a3025c02a302a3L
let [<Literal>] opNor0FF5 = 0x15b015b02a302a3L
let [<Literal>] opVex0FF5 = 0x2a3025202a302a3L
let [<Literal>] opNor0FF6 = 0x175017502a302a3L
let [<Literal>] opVex0FF6 = 0x2a3025e02a302a3L
let [<Literal>] opNor0FF8 = 0x185018502a302a3L
let [<Literal>] opVex0FF8 = 0x2a3026d02a302a3L
let [<Literal>] opNor0FF9 = 0x18c018c02a302a3L
let [<Literal>] opVex0FF9 = 0x2a3027402a302a3L
let [<Literal>] opNor0FFA = 0x186018602a302a3L
let [<Literal>] opVex0FFA = 0x2a3026e02a302a3L
let [<Literal>] opNor0FFB = 0x187018702a302a3L
let [<Literal>] opVex0FFB = 0x2a3026f02a302a3L
let [<Literal>] opNor0FFC = 0x140014002a302a3L
let [<Literal>] opVex0FFC = 0x2a3023702a302a3L
let [<Literal>] opNor0FFD = 0x147014702a302a3L
let [<Literal>] opVex0FFD = 0x2a3023e02a302a3L
let [<Literal>] opNor0FFE = 0x141014102a302a3L
let [<Literal>] opVex0FFE = 0x2a3023802a302a3L
let [<Literal>] opNor0F3800 = 0x176017602a302a3L
let [<Literal>] opVex0F3800 = 0x2a3025f02a302a3L
let [<Literal>] opNor0F3817 = 0x2a3018d02a302a3L
let [<Literal>] opVex0F3817 = 0x2a3027502a302a3L
let [<Literal>] opNor0F3818 = 0x2a302a302a302a3L
let [<Literal>] opVex0F3818 = 0x2a301f802a302a3L
let [<Literal>] opEVex0F3818 = 0x2a301f802a302a3L
let [<Literal>] opNor0F3829 = 0x2a3015002a302a3L
let [<Literal>] opVex0F3829 = 0x2a3024702a302a3L
let [<Literal>] opNor0F3838 = 0x2a3016102a302a3L
let [<Literal>] opNor0F383B = 0x2a3016002a302a3L
let [<Literal>] opVex0F383B = 0x2a3025702a302a3L
let [<Literal>] opNor0F385A = 0x2a302a302a302a3L
let [<Literal>] opVex0F385A = 0x2a301f702a302a3L
let [<Literal>] opNor0F3878 = 0x2a302a302a302a3L
let [<Literal>] opVex0F3878 = 0x2a3024402a302a3L
let [<Literal>] opNor0F38F0 = 0x14b010b02a30041L
let [<Literal>] opNor0F38F1 = 0x14b010b02a30041L
let [<Literal>] opNor0F3A0F = 0x148014802a302a3L
let [<Literal>] opVex0F3A0F = 0x2a3023f02a302a3L
let [<Literal>] opNor0F3A20 = 0x2a3015902a302a3L
let [<Literal>] opVex0F3A20 = 0x2a302a302a302a3L
let [<Literal>] opNor0F3A38 = 0x2a302a302a302a3L
let [<Literal>] opVex0F3A38 = 0x2a3020702a302a3L
let [<Literal>] opNor0F3A60 = 0x2a3015202a302a3L
let [<Literal>] opVex0F3A60 = 0x2a3024902a302a3L
let [<Literal>] opNor0F3A61 = 0x2a3015102a302a3L
let [<Literal>] opVex0F3A61 = 0x2a3024802a302a3L
let [<Literal>] opNor0F3A62 = 0x2a3015702a302a3L
let [<Literal>] opVex0F3A62 = 0x2a3024e02a302a3L
let [<Literal>] opNor0F3A63 = 0x2a3015602a302a3L
let [<Literal>] opVex0F3A63 = 0x2a3024d02a302a3L
let [<Literal>] opNor0F3A0B = 0x2a301ae02a302a3L
let [<Literal>] opVex0F3A0B = 0x2a302a302a302a3L
let [<Literal>] opEmpty = 0x2a302a302a302a3L

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
  | 0x240L -> OprSize.DW
  | 0x280L -> OprSize.P
  | 0x2c0L -> OprSize.PD
  | 0x300L -> OprSize.PI
  | 0x340L -> OprSize.PS
  | 0x380L -> OprSize.PSQ
  | 0x3c0L -> OprSize.Q
  | 0x400L -> OprSize.QQ
  | 0x440L -> OprSize.S
  | 0x480L -> OprSize.SD
  | 0x4c0L -> OprSize.SDQ
  | 0x500L -> OprSize.SS
  | 0x540L -> OprSize.SSD
  | 0x580L -> OprSize.SSQ
  | 0x5c0L -> OprSize.V
  | 0x600L -> OprSize.W
  | 0x640L -> OprSize.X
  | 0x680L -> OprSize.XZ
  | 0x6c0L -> OprSize.Y
  | 0x700L -> OprSize.Z
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

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

module internal B2R2.FrontEnd.Intel.Constants

type R = Register

let _Ap = ODModeSize (struct (OprMode.A, OprSize.P))
let _BNDRbnd = ODModeSize (struct (OprMode.BndR, OprSize.Bnd))
let _BNDRMbnd = ODModeSize (struct (OprMode.BndM, OprSize.Bnd))
let _By = ODModeSize (struct (OprMode.B, OprSize.Y))
let _Cd = ODModeSize (struct (OprMode.C, OprSize.D))
let _Dd = ODModeSize (struct (OprMode.D, OprSize.D))
let _E0v = ODModeSize (struct (OprMode.E0, OprSize.V)) (* \x0f\x1f *)
let _Eb = ODModeSize (struct (OprMode.E, OprSize.B))
let _Ed = ODModeSize (struct (OprMode.E, OprSize.D))
let _Edb = ODModeSize (struct (OprMode.E, OprSize.DB))
let _Edw = ODModeSize (struct (OprMode.E, OprSize.DW))
let _Ep = ODModeSize (struct (OprMode.E, OprSize.P))
let _Ev = ODModeSize (struct (OprMode.E, OprSize.V))
let _Ew = ODModeSize (struct (OprMode.E, OprSize.W))
let _Ey = ODModeSize (struct (OprMode.E, OprSize.Y))
let _Gb = ODModeSize (struct (OprMode.G, OprSize.B))
let _Gd = ODModeSize (struct (OprMode.G, OprSize.D))
let _Gv = ODModeSize (struct (OprMode.G, OprSize.V))
let _Gw = ODModeSize (struct (OprMode.G, OprSize.W))
let _Gy = ODModeSize (struct (OprMode.G, OprSize.Y))
let _Gz = ODModeSize (struct (OprMode.G, OprSize.Z))
let _Hdq = ODModeSize (struct (OprMode.H, OprSize.DQ))
let _Hpd = ODModeSize (struct (OprMode.H, OprSize.PD))
let _Hps = ODModeSize (struct (OprMode.H, OprSize.PS))
let _Hqq = ODModeSize (struct (OprMode.H, OprSize.QQ))
let _Hsd = ODModeSize (struct (OprMode.H, OprSize.SD))
let _Hss = ODModeSize (struct (OprMode.H, OprSize.SS))
let _Hx = ODModeSize (struct (OprMode.H, OprSize.X))
let _Ib = ODModeSize (struct (OprMode.I, OprSize.B))
let _Iv = ODModeSize (struct (OprMode.I, OprSize.V))
let _Iw = ODModeSize (struct (OprMode.I, OprSize.W))
let _Iz = ODModeSize (struct (OprMode.I, OprSize.Z))
let _Jb = ODModeSize (struct (OprMode.J, OprSize.B))
let _Jz = ODModeSize (struct (OprMode.J, OprSize.Z))
let _Ma = ODModeSize (struct (OprMode.M, OprSize.A))
let _Md = ODModeSize (struct (OprMode.M, OprSize.D))
let _Mdq = ODModeSize (struct (OprMode.M, OprSize.DQ))
let _Mdqd = ODModeSize (struct (OprMode.M, OprSize.DQD))
let _Mp = ODModeSize (struct (OprMode.M, OprSize.P))
let _Mpd = ODModeSize (struct (OprMode.M, OprSize.PD))
let _Mps = ODModeSize (struct (OprMode.M, OprSize.PS))
let _Mq = ODModeSize (struct (OprMode.M, OprSize.Q))
let _Ms = ODModeSize (struct (OprMode.M, OprSize.S))
let _Mv = ODModeSize (struct (OprMode.M, OprSize.V))
let _Mw = ODModeSize (struct (OprMode.M, OprSize.W))
let _Mx = ODModeSize (struct (OprMode.M, OprSize.X))
let _My = ODModeSize (struct (OprMode.M, OprSize.Y))
let _Mz = ODModeSize (struct (OprMode.M, OprSize.Z))
let _MZxz = ODModeSize (struct (OprMode.MZ, OprSize.XZ))
let _Nq = ODModeSize (struct (OprMode.N, OprSize.Q))
let _Ob = ODModeSize (struct (OprMode.O, OprSize.B))
let _Ov = ODModeSize (struct (OprMode.O, OprSize.V))
let _Pd = ODModeSize (struct (OprMode.P, OprSize.D))
let _Ppi = ODModeSize (struct (OprMode.P, OprSize.PI))
let _Pq = ODModeSize (struct (OprMode.P, OprSize.Q))
let _Qd = ODModeSize (struct (OprMode.Q, OprSize.D))
let _Qpi = ODModeSize (struct (OprMode.Q, OprSize.PI))
let _Qq = ODModeSize (struct (OprMode.Q, OprSize.Q))
let _Rd = ODModeSize (struct (OprMode.R, OprSize.D))
let _Rv = ODModeSize (struct (OprMode.R, OprSize.V))
let _Ry = ODModeSize (struct (OprMode.R, OprSize.Y))
let _SIb = ODModeSize (struct (OprMode.SI, OprSize.B))
let _SIv = ODModeSize (struct (OprMode.SI, OprSize.V))
let _SIw = ODModeSize (struct (OprMode.SI, OprSize.W))
let _SIz = ODModeSize (struct (OprMode.SI, OprSize.Z))
let _Sw = ODModeSize (struct (OprMode.S, OprSize.W))
let _Udq = ODModeSize (struct (OprMode.U, OprSize.DQ))
let _Upd = ODModeSize (struct (OprMode.U, OprSize.PD))
let _Ups = ODModeSize (struct (OprMode.U, OprSize.PS))
let _Uq = ODModeSize (struct (OprMode.U, OprSize.Q))
let _Ux = ODModeSize (struct (OprMode.U, OprSize.X))
let _Vdq = ODModeSize (struct (OprMode.V, OprSize.DQ))
let _Vpd = ODModeSize (struct (OprMode.V, OprSize.PD))
let _Vps = ODModeSize (struct (OprMode.V, OprSize.PS))
let _Vq = ODModeSize (struct (OprMode.V, OprSize.Q))
let _Vqq = ODModeSize (struct (OprMode.V, OprSize.QQ))
let _Vsd = ODModeSize (struct (OprMode.V, OprSize.SD))
let _Vss = ODModeSize (struct (OprMode.V, OprSize.SS))
let _Vx = ODModeSize (struct (OprMode.V, OprSize.X))
let _Vy = ODModeSize (struct (OprMode.V, OprSize.Y))
let _VZxz = ODModeSize (struct (OprMode.VZ, OprSize.XZ))
let _Wd = ODModeSize (struct (OprMode.W, OprSize.D))
let _Wdq = ODModeSize (struct (OprMode.W, OprSize.DQ))
let _Wdqd = ODModeSize (struct (OprMode.W, OprSize.DQD))
let _Wdqdq = ODModeSize (struct (OprMode.W, OprSize.DQDQ))
let _Wdqq = ODModeSize (struct (OprMode.W, OprSize.DQQ))
let _Wdqqdq = ODModeSize (struct (OprMode.W, OprSize.DQQDQ))
let _Wdqw = ODModeSize (struct (OprMode.W, OprSize.DQW))
let _Wdqwd = ODModeSize (struct (OprMode.W, OprSize.DQWD))
let _Wpd = ODModeSize (struct (OprMode.W, OprSize.PD))
let _Wps = ODModeSize (struct (OprMode.W, OprSize.PS))
let _Wpsq = ODModeSize (struct (OprMode.W, OprSize.PSQ))
let _Wsd = ODModeSize (struct (OprMode.W, OprSize.SD))
let _Wsdq = ODModeSize (struct (OprMode.W, OprSize.SDQ))
let _Wss = ODModeSize (struct (OprMode.W, OprSize.SS))
let _Wssd = ODModeSize (struct (OprMode.W, OprSize.SSD))
let _Wssq = ODModeSize (struct (OprMode.W, OprSize.SSQ))
let _Wx = ODModeSize (struct (OprMode.W, OprSize.X))
let _WZxz = ODModeSize (struct (OprMode.WZ, OprSize.XZ))
let _Xb = ODModeSize (struct (OprMode.X, OprSize.B))
let _Xv = ODModeSize (struct (OprMode.X, OprSize.V))
let _Yb = ODModeSize (struct (OprMode.Y, OprSize.B))
let _Yv = ODModeSize (struct (OprMode.Y, OprSize.V))

let Ap = [| _Ap |]
let Dd = [| _Dd |]
let E0v = [| _E0v |]
let Eb = [| _Eb |]
let Ep = [| _Ep |]
let Ev = [| _Ev |]
let Ew = [| _Ew |]
let Ey = [| _Ey |]
let Gb = [| _Gb |]
let Gd = [| _Gd |]
let Gv = [| _Gv |]
let Gw = [| _Gw |]
let Gy = [| _Gy |]
let Gz = [| _Gz |]
let Ib = [| _Ib |]
let Iv = [| _Iv |]
let Iw = [| _Iw |]
let Iz = [| _Iz |]
let Jb = [| _Jb |]
let Jz = [| _Jz |]
let Ma = [| _Ma |]
let Mdq = [| _Mdq |]
let Mp = [| _Mp |]
let Mq = [| _Mq |]
let Ms = [| _Ms |]
let Mv = [| _Mv |]
let Mw = [| _Mw |]
let My = [| _My |]
let Mz = [| _Mz |]
let Pd = [| _Pd |]
let Pq = [| _Pq |]
let Qq = [| _Qq |]
let Rd = [| _Rd |]
let Rv = [| _Rv |]
let Ry = [| _Ry |]
let SIb = [| _SIb |]
let SIv = [| _SIv |]
let SIw = [| _SIw |]
let SIz = [| _SIz |]
let Sw = [| _Sw |]
let Vdq = [| _Vdq |]
let Vx = [| _Vx |]
let Wdq = [| _Wdq |]
let Wdqd = [| _Wdqd |]
let Wdqq = [| _Wdqq |]
let Wx = [| _Wx |]

let ORSR sg = [| ODReg sg |]

let ALDX = [| ODReg R.AL; ODReg R.DX |]
let ALIb = [| ODReg R.AL; _Ib |]
let ALOb = [| ODReg R.AL; _Ob |]
let BNDRbndBNDRMbnd = [| _BNDRbnd; _BNDRMbnd |]
let BNDRMbndBNDRbnd = [| _BNDRMbnd; _BNDRbnd |]
let CdRd = [| _Cd; _Rd |]
let DdRd = [| _Dd; _Rd |]
let DXAL = [| ODReg R.DX; ODReg R.AL |]
let Eb1L = [| _Eb; ODImmOne |]
let EbCL = [| _Eb; ODReg R.CL |]
let EbGb = [| _Eb; _Gb |]
let EbIb = [| _Eb; _Ib |]
let Ev1L = [| _Ev; ODImmOne |]
let EvCL = [| _Ev; ODReg R.CL |]
let EvGv = [| _Ev; _Gv |]
let EvIb = [| _Ev; _Ib |]
let EvIz = [| _Ev; _Iz |]
let EvSIb = [| _Ev; _SIb |]
let EvSIz = [| _Ev; _SIz |]
let EvSw = [| _Ev; _Sw |]
let EwGw = [| _Ew; _Gw |]
let EyPd = [| _Ey; _Pd |]
let EyPq = [| _Ey; _Pq |]
let EyVdq = [| _Ey; _Vdq |]
let GbEb = [| _Gb; _Eb |]
let GdEb = [| _Gd; _Eb |]
let GdEw = [| _Gd; _Ew |]
let GdEy = [| _Gd; _Ey |]
let GdNq = [| _Gd; _Nq |]
let GdUdq = [| _Gd; _Udq |]
let GdUx = [| _Gd; _Ux |]
let GvEb = [| _Gv; _Eb |]
let GvEd = [| _Gv; _Ed |]
let GvEv = [| _Gv; _Ev |]
let GvEw = [| _Gv; _Ew |]
let GvEy = [| _Gv; _Ey |]
let GvMa = [| _Gv; _Ma |]
let GvMp = [| _Gv; _Mp |]
let GvMv = [| _Gv; _Mv |]
let GwMw = [| _Gw; _Mw |]
let GyMy = [| _Gy; _My |]
let GyUdq = [| _Gy; _Udq |]
let GyUpd = [| _Gy; _Upd |]
let GyUps = [| _Gy; _Ups |]
let GyUx = [| _Gy; _Ux |]
let GyWdq = [| _Gy; _Wdq |]
let GyWsd = [| _Gy; _Wsd |]
let GyWsdq = [| _Gy; _Wsdq |]
let GyWss = [| _Gy; _Wss |]
let GyWssd = [| _Gy; _Wssd |]
let GzMp = [| _Gz; _Mp |]
let IbAL = [| _Ib; ODReg R.AL |]
let IwIb = [| _Iw; _Ib |]
let MdqVdq = [| _Mdq; _Vdq |]
let MpdVpd = [| _Mpd; _Vpd |]
let MpsVps = [| _Mps; _Vps |]
let MqPq = [| _Mq; _Pq |]
let MqVdq = [| _Mq; _Vdq |]
let MwGw = [| _Gw; _Mw |]
let MxVx = [| _Mx; _Vx |]
let MyGy = [| _My; _Gy |]
let MZxzVZxz = [| _MZxz; _VZxz |]
let NqIb = [| _Nq; _Ib |]
let ObAL = [| _Ob; ODReg R.AL |]
let PdEy = [| _Pd; _Ey |]
let PpiWdq = [| _Ppi; _Wdq |]
let PpiWdqq = [| _Ppi; _Wdqq |]
let PpiWpd = [| _Ppi; _Wpd |]
let PpiWps = [| _Ppi; _Wps |]
let PpiWpsq = [| _Ppi; _Wpsq |]
let PqEy = [| _Pq; _Ey |]
let PqQd = [| _Pq; _Qd |]
let PqQq = [| _Pq; _Qq |]
let PqUdq = [| _Pq; _Udq |]
let PqWdq = [| _Pq; _Wdq |]
let QpiWpd = [| _Qpi; _Wpd |]
let QqPq = [| _Qq; _Pq |]
let RdCd = [| _Rd; _Cd |]
let RdDd = [| _Rd; _Dd |]
let SwEw = [| _Sw; _Ew |]
let UdqIb = [| _Udq; _Ib |]
let VdqEdbIb = [| _Vdq; _Edb; _Ib |]
let VdqEy = [| _Vdq; _Ey |]
let VdqMdq = [| _Vdq; _Mdq |]
let VdqMq = [| _Vdq; _Mq |]
let VdqNq = [| _Vdq; _Nq |]
let VdqQq = [| _Vdq; _Qq |]
let VdqUdq = [| _Vdq; _Udq |]
let VdqWdq = [| _Vdq; _Wdq |]
let VdqWdqd = [| _Vdq; _Wdqd |]
let VdqWdqq = [| _Vdq; _Wdqq |]
let VdqWdqw = [| _Vdq; _Wdqw |]
let VpdWpd = [| _Vpd; _Wpd |]
let VpsWps = [| _Vps; _Wps |]
let VqqMdq = [| _Vqq; _Mdq |]
let VsdWsd = [| _Vsd; _Wsd |]
let VsdWsdq = [| _Vsd; _Wsdq |]
let VssWss = [| _Vss; _Wss |]
let VssWssd = [| _Vss; _Wssd |]
let VxMd = [| _Vx; _Md |]
let VxMx = [| _Vx; _Mx |]
let VxWdqdq = [| _Vx; _Wdqdq |]
let VxWdqqdq = [| _Vx; _Wdqqdq |]
let VxWdqwd = [| _Vx; _Wdqwd |]
let VxWss = [| _Vx; _Wss |]
let VxWssd = [| _Vx; _Wssd |]
let VxWssq = [| _Vx; _Wssq |]
let VxWx = [| _Vx; _Wx |]
let VyEy = [| _Vy; _Ey |]
let VZxzWdqd = [| _VZxz; _Wdqd |]
let VZxzWZxz = [| _VZxz; _WZxz |]
let WdqdVdq = [| _Wdqd; _Vdq |]
let WdqqVdq = [| _Wdqq; _Vdq |]
let WdqVdq = [| _Wdq; _Vdq |]
let WpdVpd = [| _Wpd; _Vpd |]
let WpsVps = [| _Wps; _Vps |]
let WssdVx = [| _Wssd; _Vx |]
let WssqVx = [| _Wssq; _Vx |]
let WssVx = [| _Wss; _Vx |]
let WxVx = [| _Wx; _Vx |]
let WZxzVZxz = [| _WZxz; _VZxz |]
let XbYb = [| _Xb; _Yb |]
let XvYv = [| _Xv; _Yv |]
let YbXb = [| _Yb; _Xb |]
let YvXv = [| _Yv; _Xv |]

let inline RegIb r = [| ODReg r; _Ib |]

let inline private _RGz rg changeable =
  ODRegGrp (rg, OprSize.Z, if changeable then RGrpAttr.ARegInOpREX
                           else RGrpAttr.ARegInOpNoREX)
let inline private _RGv rg changeable =
  ODRegGrp (rg, OprSize.V, if changeable then RGrpAttr.ARegInOpREX
                           else RGrpAttr.ARegInOpNoREX)

let inline RGv rg = [| _RGv rg true |]
let inline RGz rg rexChangeable = [| _RGz rg rexChangeable |]
let inline RGvOv rg rc = [| _RGv rg rc; _Ov |]
let inline OvRGv rg rc = [| _Ov; _RGv rg rc |]
let RGzRGz = [| _RGz RegGrp.RG0 false; _RGz RegGrp.RG0 true |]
let inline RGvRGv rg2 = [| _RGv RegGrp.RG0 false; _RGv rg2 true |]
let inline RGvIb rg rc = [| _RGv rg rc; _Ib |]
let inline IbRGv rg rc = [| _Ib; _RGv rg rc |]
let RGvSIz = [| _RGv RegGrp.RG0 false; _SIz |]
let inline RGvIv rg = [| _RGv rg true; _Iv |]
let RGvDX = [| _RGv RegGrp.RG0 false; ODReg R.DX |]
let DXRGv = [| ODReg R.DX; _RGv RegGrp.RG0 false |]
let RGzDX = [| _RGz RegGrp.RG0 false; ODReg R.DX |]
let DXRGz = [| ODReg R.DX; _RGz RegGrp.RG0 false |]

let EvGvCL = [| _Ev; _Gv; ODReg R.CL |]
let EvGvIb = [| _Ev; _Gv; _Ib |]
let GdNqIb = [| _Gd; _Nq; _Ib |]
let GdUdqIb = [| _Gd; _Udq; _Ib |]
let GvEvIb = [| _Gv; _Ev; _Ib |]
let GvEvIz = [| _Gv; _Ev; _Iz |]
let GvEvSIb = [| _Gv; _Ev; _SIb |]
let GvEvSIz = [| _Gv; _Ev; _SIz |]
let GyByEy = [| _Gy; _By; _Ey |]
let GyEyBy = [| _Gy; _Ey; _By |]
let GyEyIb = [| _Gy; _Ey; _Ib |]
let HxUxIb = [| _Hx; _Ux; _Ib |]
let PqEdwIb = [| _Pq; _Edw; _Ib |]
let PqQqIb = [| _Pq; _Qq; _Ib |]
let VdqEdwIb =  [| _Vdq; _Edw; _Ib |]
let VdqHdqMdq = [| _Vdq; _Hdq; _Mdq |]
let VdqHdqMdqd = [| _Vdq; _Hdq; _Mdqd |]
let VdqHdqMq = [| _Vdq; _Hdq; _Mq |]
let VdqHdqUdq = [| _Vdq; _Hdq; _Udq |]
let VdqWdqIb = [| _Vdq; _Wdq; _Ib |]
let VpdHpdWpd = [| _Vpd; _Hpd; _Wpd |]
let VpsHpsWps = [| _Vps; _Hps; _Wps |]
let VsdHsdEy = [| _Vsd; _Hsd; _Ey |]
let VsdHsdWsd = [| _Vsd; _Hsd; _Wsd |]
let VsdHsdWsdq = [| _Vsd; _Hsd; _Wsdq |]
let VsdWsdIb = [| _Vsd; _Wsd; _Ib |]
let VsdWsdqIb = [| _Vsd; _Wsdq; _Ib |]
let VssHssEy = [| _Vss; _Hss; _Ey |]
let VssHssWss = [| _Vss; _Hss; _Wss |]
let VssHssWssd = [| _Vss; _Hss; _Wssd |]
let VssWssdIb = [| _Vss; _Wssd; _Ib |]
let VxHxWdq = [| _Vx; _Hx; _Wdq |]
let VxHxWsd = [| _Vx; _Hx; _Wsd |]
let VxHxWss = [| _Vx; _Hx; _Wss |]
let VxHxWx = [| _Vx; _Hx; _Wx |]
let VxWxIb = [| _Vx; _Wx; _Ib |]
let WsdHxVsd = [| _Wsd; _Hx; _Vsd |]
let WssHxVss = [| _Wss; _Hx; _Vss |]

let VdqHdqEdwIb = [| _Vdq; _Hdq; _Edw; _Ib |]
let VpsHpsWpsIb = [| _Vps; _Hps; _Wps; _Ib |]
let VqqHqqWdqIb = [| _Vqq; _Hqq; _Wdq; _Ib |]
let VxHxWxIb = [| _Vx; _Hx; _Wx; _Ib |]

let opNor0F1A = [| Opcode.InvalOP; Opcode.BNDMOV;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F1B = [| Opcode.InvalOP; Opcode.BNDMOV;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F10 = [| Opcode.MOVUPS; Opcode.MOVUPD;
                   Opcode.MOVSS; Opcode.MOVSD |]
let opVex0F10Mem = [| Opcode.VMOVUPS; Opcode.VMOVUPD;
                      Opcode.VMOVSS; Opcode.VMOVSD |]
let opVex0F10Reg = [| Opcode.VMOVUPS; Opcode.VMOVUPD;
                      Opcode.VMOVSS; Opcode.VMOVSD |]
let opNor0F11 = [| Opcode.MOVUPS; Opcode.MOVUPD;
                   Opcode.MOVSS; Opcode.MOVSD |]
let opVex0F11Mem = [| Opcode.VMOVUPS; Opcode.VMOVUPD;
                      Opcode.VMOVSS; Opcode.VMOVSD |]
let opVex0F11Reg = [| Opcode.VMOVUPS; Opcode.VMOVUPD;
                      Opcode.VMOVSS; Opcode.VMOVSD |]
let opNor0F12Mem = [| Opcode.MOVLPS; Opcode.MOVLPD;
                      Opcode.MOVSLDUP; Opcode.MOVDDUP |]
let opNor0F12Reg = [| Opcode.MOVHLPS; Opcode.MOVLPD;
                      Opcode.MOVSLDUP; Opcode.MOVDDUP |]
let opVex0F12Mem = [| Opcode.VMOVLPS; Opcode.VMOVLPD;
                      Opcode.VMOVSLDUP; Opcode.VMOVDDUP |]
let opVex0F12Reg = [| Opcode.VMOVHLPS; Opcode.VMOVLPD;
                      Opcode.VMOVSLDUP; Opcode.VMOVDDUP |]
let opNor0F13 = [| Opcode.MOVLPS; Opcode.MOVLPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F13 = [| Opcode.VMOVLPS; Opcode.VMOVLPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F14 = [| Opcode.UNPCKLPS; Opcode.UNPCKLPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F14 = [| Opcode.VUNPCKLPS; Opcode.VUNPCKLPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F15 = [| Opcode.UNPCKHPS; Opcode.UNPCKHPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F15 = [| Opcode.VUNPCKHPS; Opcode.VUNPCKHPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F16Mem = [| Opcode.MOVHPS; Opcode.MOVHPD;
                      Opcode.MOVSHDUP; Opcode.InvalOP |]
let opNor0F16Reg = [| Opcode.MOVLHPS; Opcode.MOVHPD;
                      Opcode.MOVSHDUP; Opcode.InvalOP |]
let opVex0F16Mem = [| Opcode.VMOVHPS; Opcode.VMOVHPD;
                      Opcode.VMOVSHDUP; Opcode.InvalOP |]
let opVex0F16Reg = [| Opcode.VMOVLHPS; Opcode.VMOVHPD;
                      Opcode.VMOVSHDUP; Opcode.InvalOP |]
let opNor0F17 = [| Opcode.MOVHPS; Opcode.MOVHPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F17 = [| Opcode.VMOVHPS; Opcode.VMOVHPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F28 = [| Opcode.MOVAPS; Opcode.MOVAPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F28 = [| Opcode.VMOVAPS; Opcode.VMOVAPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F29 = [| Opcode.MOVAPS; Opcode.MOVAPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F29 = [| Opcode.VMOVAPS; Opcode.VMOVAPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F2A = [| Opcode.CVTPI2PS; Opcode.CVTPI2PD;
                   Opcode.CVTSI2SS; Opcode.CVTSI2SD |]
let opVex0F2A = [| Opcode.InvalOP; Opcode.InvalOP;
                   Opcode.VCVTSI2SS; Opcode.VCVTSI2SD |]
let opNor0F2B = [| Opcode.MOVNTPS; Opcode.MOVNTPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F2B = [| Opcode.VMOVNTPS; Opcode.VMOVNTPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F2C = [| Opcode.CVTTPS2PI; Opcode.CVTTPD2PI;
                   Opcode.CVTTSS2SI; Opcode.CVTTSD2SI |]
let opVex0F2C = [| Opcode.InvalOP; Opcode.InvalOP;
                   Opcode.VCVTTSS2SI; Opcode.VCVTTSD2SI |]
let opNor0F2D = [| Opcode.CVTPS2PI; Opcode.CVTPD2PI;
                   Opcode.CVTSS2SI; Opcode.CVTSD2SI |]
let opVex0F2D = [| Opcode.InvalOP; Opcode.InvalOP;
                   Opcode.VCVTSS2SI; Opcode.VCVTSD2SI |]
let opNor0F2E = [| Opcode.UCOMISS; Opcode.UCOMISD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F2E = [| Opcode.VUCOMISS; Opcode.VUCOMISD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F2F = [| Opcode.COMISS; Opcode.COMISD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F2F = [| Opcode.VCOMISS; Opcode.VCOMISD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F50 = [| Opcode.MOVMSKPS; Opcode.MOVMSKPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F50 = [| Opcode.VMOVMSKPS; Opcode.VMOVMSKPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F51 = [| Opcode.SQRTPS; Opcode.SQRTPD;
                   Opcode.SQRTSS; Opcode.SQRTSD |]
let opVex0F51 = [| Opcode.VSQRTPS; Opcode.VSQRTPD;
                   Opcode.VSQRTSS; Opcode.VSQRTSD |]
let opNor0F54 = [| Opcode.ANDPS; Opcode.ANDPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F54 = [| Opcode.VANDPS; Opcode.VANDPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F55 = [| Opcode.ANDNPS; Opcode.ANDNPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F55 = [| Opcode.VANDNPS; Opcode.VANDNPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F56 = [| Opcode.ORPS; Opcode.ORPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F56 = [| Opcode.VORPS; Opcode.VORPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F57 = [| Opcode.XORPS; Opcode.XORPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F57 = [| Opcode.VXORPS; Opcode.VXORPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F58 = [| Opcode.ADDPS; Opcode.ADDPD;
                   Opcode.ADDSS; Opcode.ADDSD |]
let opVex0F58 = [| Opcode.VADDPS; Opcode.VADDPD;
                   Opcode.VADDSS; Opcode.VADDSD |]
let opNor0F59 = [| Opcode.MULPS; Opcode.MULPD;
                   Opcode.MULSS; Opcode.MULSD |]
let opVex0F59 = [| Opcode.VMULPS; Opcode.VMULPD;
                   Opcode.VMULSS; Opcode.VMULSD |]
let opNor0F5A = [| Opcode.CVTPS2PD; Opcode.CVTPD2PS;
                   Opcode.CVTSS2SD; Opcode.CVTSD2SS |]
let opVex0F5A = [| Opcode.InvalOP; Opcode.InvalOP;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F5B = [| Opcode.CVTDQ2PS; Opcode.CVTPS2DQ;
                   Opcode.CVTTPS2DQ; Opcode.InvalOP |]
let opVex0F5B = [| Opcode.InvalOP; Opcode.InvalOP;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F5C = [| Opcode.SUBPS; Opcode.SUBPD;
                   Opcode.SUBSS; Opcode.SUBSD |]
let opVex0F5C = [| Opcode.VSUBPS; Opcode.VSUBPD;
                   Opcode.VSUBSS; Opcode.VSUBSD |]
let opNor0F5D = [| Opcode.MINPS; Opcode.MINPD;
                   Opcode.MINSS; Opcode.MINSD |]
let opVex0F5D = [| Opcode.InvalOP; Opcode.InvalOP;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F5E = [| Opcode.DIVPS; Opcode.DIVPD;
                   Opcode.DIVSS; Opcode.DIVSD |]
let opVex0F5E = [| Opcode.VDIVPS; Opcode.VDIVPD;
                   Opcode.VDIVSS; Opcode.VDIVSD |]
let opNor0F5F = [| Opcode.MAXPS; Opcode.MAXPD;
                   Opcode.MAXSS; Opcode.MAXSD |]
let opVex0F5F = [| Opcode.InvalOP; Opcode.InvalOP;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F60 = [| Opcode.PUNPCKLBW; Opcode.PUNPCKLBW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F60 = [| Opcode.InvalOP; Opcode.VPUNPCKLBW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F61 = [| Opcode.PUNPCKLWD; Opcode.PUNPCKLWD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F61 = [| Opcode.InvalOP; Opcode.VPUNPCKLWD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F62 = [| Opcode.PUNPCKLDQ; Opcode.PUNPCKLDQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F62 = [| Opcode.InvalOP; Opcode.VPUNPCKLDQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F63 = [| Opcode.PACKSSWB; Opcode.PACKSSWB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F63 = [| Opcode.InvalOP; Opcode.VPACKSSWB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F64 = [| Opcode.PCMPGTB; Opcode.PCMPGTB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F64 = [| Opcode.InvalOP; Opcode.VPCMPGTB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F65 = [| Opcode.PCMPGTW; Opcode.PCMPGTW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F65 = [| Opcode.InvalOP; Opcode.VPCMPGTW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F66 = [| Opcode.PCMPGTD; Opcode.PCMPGTD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F66 = [| Opcode.InvalOP; Opcode.VPCMPGTD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F67 = [| Opcode.PACKUSWB; Opcode.PACKUSWB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F67 = [| Opcode.InvalOP; Opcode.VPACKUSWB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F68 = [| Opcode.PUNPCKHBW; Opcode.PUNPCKHBW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F68 = [| Opcode.InvalOP; Opcode.VPUNPCKHBW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F69 = [| Opcode.PUNPCKHWD; Opcode.PUNPCKHWD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F69 = [| Opcode.InvalOP; Opcode.VPUNPCKHWD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F6A = [| Opcode.PUNPCKHDQ; Opcode.PUNPCKHDQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F6A = [| Opcode.InvalOP; Opcode.VPUNPCKHDQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F6B = [| Opcode.PACKSSDW; Opcode.PACKSSDW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F6B = [| Opcode.InvalOP; Opcode.VPACKSSDW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F6C = [| Opcode.InvalOP; Opcode.PUNPCKLQDQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F6C = [| Opcode.InvalOP; Opcode.VPUNPCKLQDQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F6D = [| Opcode.InvalOP; Opcode.PUNPCKHQDQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F6D = [| Opcode.InvalOP; Opcode.VPUNPCKHQDQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F6EB64 = [| Opcode.MOVQ; Opcode.MOVQ;
                      Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F6EB32 = [| Opcode.MOVD; Opcode.MOVD;
                      Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F6EB64 = [| Opcode.InvalOP; Opcode.VMOVQ;
                      Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F6EB32 = [| Opcode.InvalOP; Opcode.VMOVD;
                      Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F6F = [| Opcode.MOVQ; Opcode.MOVDQA;
                   Opcode.MOVDQU; Opcode.InvalOP |]
let opVex0F6F = [| Opcode.InvalOP; Opcode.VMOVDQA;
                   Opcode.VMOVDQU; Opcode.InvalOP |]
let opEVex0F6FB64 = [| Opcode.InvalOP; Opcode.VMOVDQA64;
                       Opcode.VMOVDQU64; Opcode.InvalOP |]
let opEVex0F6FB32 = [| Opcode.InvalOP; Opcode.VMOVDQA32;
                       Opcode.VMOVDQU32; Opcode.InvalOP |]
let opNor0F70 = [| Opcode.PSHUFW; Opcode.PSHUFD;
                   Opcode.PSHUFHW; Opcode.PSHUFLW |]
let opVex0F70 = [| Opcode.InvalOP; Opcode.VPSHUFD;
                   Opcode.VPSHUFHW; Opcode.VPSHUFLW |]
let opNor0F74 = [| Opcode.PCMPEQB; Opcode.PCMPEQB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F74 = [| Opcode.InvalOP; Opcode.VPCMPEQB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F75 = [| Opcode.PCMPEQW; Opcode.PCMPEQW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F75 = [| Opcode.InvalOP; Opcode.VPCMPEQW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F76 = [| Opcode.PCMPEQD; Opcode.PCMPEQD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F76 = [| Opcode.InvalOP; Opcode.VPCMPEQD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F77 = [| Opcode.EMMS; Opcode.InvalOP;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F77 = [| Opcode.VZEROUPPER; Opcode.InvalOP;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F7EB64 = [| Opcode.MOVQ; Opcode.MOVQ;
                      Opcode.MOVQ; Opcode.InvalOP |]
let opNor0F7EB32 = [| Opcode.MOVD; Opcode.MOVD;
                      Opcode.MOVQ; Opcode.InvalOP |]
let opVex0F7EB64 = [| Opcode.InvalOP; Opcode.VMOVQ;
                      Opcode.VMOVQ; Opcode.InvalOP |]
let opVex0F7EB32 = [| Opcode.InvalOP; Opcode.VMOVD;
                      Opcode.VMOVQ; Opcode.InvalOP |]
let opNor0F7F = [| Opcode.MOVQ; Opcode.MOVDQA;
                   Opcode.MOVDQU; Opcode.InvalOP |]
let opVex0F7F = [| Opcode.InvalOP; Opcode.VMOVDQA;
                   Opcode.VMOVDQU; Opcode.InvalOP |]
let opEVex0F7FB64 = [| Opcode.InvalOP; Opcode.VMOVDQA64;
                       Opcode.InvalOP; Opcode.InvalOP |]
let opEVex0F7FB32 = [| Opcode.InvalOP; Opcode.VMOVDQA32;
                       Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FC2 = [| Opcode.CMPPS; Opcode.CMPPD;
                   Opcode.CMPSS; Opcode.CMPSD |]
let opVex0FC2 = [| Opcode.InvalOP; Opcode.InvalOP;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FC4 = [| Opcode.PINSRW; Opcode.PINSRW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FC4 = [| Opcode.InvalOP; Opcode.VPINSRW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FC5 = [| Opcode.PEXTRW; Opcode.PEXTRW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FC5 = [| Opcode.InvalOP; Opcode.VPEXTRW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FC6 = [| Opcode.SHUFPS; Opcode.SHUFPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FC6 = [| Opcode.VSHUFPS; Opcode.VSHUFPD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FD1 = [| Opcode.PSRLW; Opcode.PSRLW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FD1 = [| Opcode.InvalOP; Opcode.VPSRLW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FD2 = [| Opcode.PSRLD; Opcode.PSRLD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FD2 = [| Opcode.InvalOP; Opcode.VPSRLD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FD3 = [| Opcode.PSRLQ; Opcode.PSRLQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FD3 = [| Opcode.InvalOP; Opcode.VPSRLQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FD4 = [| Opcode.PADDQ; Opcode.PADDQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FD4 = [| Opcode.InvalOP; Opcode.VPADDQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FD5 = [| Opcode.PMULLW; Opcode.PMULLW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FD5 = [| Opcode.InvalOP; Opcode.VPMULLW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FD6 = [| Opcode.InvalOP; Opcode.MOVQ;
                   Opcode.MOVQ2DQ; Opcode.MOVDQ2Q |]
let opVex0FD6 = [| Opcode.InvalOP; Opcode.VMOVQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FD7 = [| Opcode.PMOVMSKB; Opcode.PMOVMSKB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FD7 = [| Opcode.InvalOP; Opcode.VPMOVMSKB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FD8 = [| Opcode.PSUBUSB; Opcode.PSUBUSB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FD8 = [| Opcode.InvalOP; Opcode.VPSUBUSB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FD9 = [| Opcode.PSUBUSW; Opcode.PSUBUSW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FD9 = [| Opcode.InvalOP; Opcode.VPSUBUSW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FDA = [| Opcode.PMINUB; Opcode.PMINUB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FDA = [| Opcode.InvalOP; Opcode.VPMINUB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FDB = [| Opcode.PAND; Opcode.PAND;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FDB = [| Opcode.InvalOP; Opcode.VPAND;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FDC = [| Opcode.PADDUSB; Opcode.PADDUSB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FDC = [| Opcode.InvalOP; Opcode.VPADDUSB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FDD = [| Opcode.PADDUSW; Opcode.PADDUSW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FDD = [| Opcode.InvalOP; Opcode.VPADDUSW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FDE = [| Opcode.PMAXUB; Opcode.PMAXUB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FDE = [| Opcode.InvalOP; Opcode.VPMAXUB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FDF = [| Opcode.PANDN; Opcode.PANDN;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FDF = [| Opcode.InvalOP; Opcode.VPANDN;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FE0 = [| Opcode.PAVGB; Opcode.PAVGB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FE0 = [| Opcode.InvalOP; Opcode.VPAVGB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FE1 = [| Opcode.PSRAW; Opcode.PSRAW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FE1 = [| Opcode.InvalOP; Opcode.VPSRAW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FE2 = [| Opcode.PSRAD; Opcode.PSRAD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FE2 = [| Opcode.InvalOP; Opcode.VPSRAD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FE3 = [| Opcode.PAVGW; Opcode.PAVGW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FE3 = [| Opcode.InvalOP; Opcode.VPAVGW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FE4 = [| Opcode.PMULHUW; Opcode.PMULHUW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FE4 = [| Opcode.InvalOP; Opcode.VPMULHUW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FE5 = [| Opcode.PMULHW; Opcode.PMULHW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FE5 = [| Opcode.InvalOP; Opcode.VPMULHW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FE6 = [| Opcode.InvalOP; Opcode.CVTTPD2DQ;
                   Opcode.CVTDQ2PD; Opcode.CVTPD2DQ |]
let opVex0FE6 = [| Opcode.InvalOP; Opcode.InvalOP;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FE7 = [| Opcode.MOVNTQ; Opcode.MOVNTDQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FE7 = [| Opcode.InvalOP; Opcode.VMOVNTDQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opEVex0FE7B64 = [| Opcode.InvalOP; Opcode.InvalOP;
                       Opcode.InvalOP; Opcode.InvalOP |]
let opEVex0FE7B32 = [| Opcode.InvalOP; Opcode.VMOVNTDQ;
                       Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FE8 = [| Opcode.PSUBSB; Opcode.PSUBSB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FE8 = [| Opcode.InvalOP; Opcode.VPSUBSB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FE9 = [| Opcode.PSUBSW; Opcode.PSUBSW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FE9 = [| Opcode.InvalOP; Opcode.VPSUBSW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FEA = [| Opcode.PMINSW; Opcode.PMINSW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FEA = [| Opcode.InvalOP; Opcode.VPMINSW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FEB = [| Opcode.POR; Opcode.POR;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FEB = [| Opcode.InvalOP; Opcode.VPOR;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FEC = [| Opcode.PADDSB; Opcode.PADDSB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FEC = [| Opcode.InvalOP; Opcode.VPADDSB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FED = [| Opcode.PADDSW; Opcode.PADDSW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FED = [| Opcode.InvalOP; Opcode.VPADDSW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FEE = [| Opcode.PMAXSW; Opcode.PMAXSW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FEE = [| Opcode.InvalOP; Opcode.VPMAXSW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FEF = [| Opcode.PXOR; Opcode.PXOR;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FEF = [| Opcode.InvalOP; Opcode.VPXOR;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FF0 = [| Opcode.InvalOP; Opcode.InvalOP;
                   Opcode.InvalOP; Opcode.LDDQU |]
let opVex0FF0 = [| Opcode.InvalOP; Opcode.InvalOP;
                   Opcode.InvalOP; Opcode.VLDDQU |]
let opNor0FF1 = [| Opcode.PSLLW; Opcode.PSLLW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FF1 = [| Opcode.InvalOP; Opcode.VPSLLW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FF2 = [| Opcode.PSLLD; Opcode.PSLLD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FF2 = [| Opcode.InvalOP; Opcode.VPSLLD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FF3 = [| Opcode.PSLLQ; Opcode.PSLLQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FF3 = [| Opcode.InvalOP; Opcode.VPSLLQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FF4 = [| Opcode.PMULUDQ; Opcode.PMULUDQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FF4 = [| Opcode.InvalOP; Opcode.VPMULUDQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FF5 = [| Opcode.PMADDWD; Opcode.PMADDWD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FF5 = [| Opcode.InvalOP; Opcode.VPMADDWD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FF6 = [| Opcode.PSADBW; Opcode.PSADBW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FF6 = [| Opcode.InvalOP; Opcode.VPSADBW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FF8 = [| Opcode.PSUBB; Opcode.PSUBB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FF8 = [| Opcode.InvalOP; Opcode.VPSUBB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FF9 = [| Opcode.PSUBW; Opcode.PSUBW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FF9 = [| Opcode.InvalOP; Opcode.VPSUBW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FFA = [| Opcode.PSUBD; Opcode.PSUBD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FFA = [| Opcode.InvalOP; Opcode.VPSUBD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FFB = [| Opcode.PSUBQ; Opcode.PSUBQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FFB = [| Opcode.InvalOP; Opcode.VPSUBQ;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FFC = [| Opcode.PADDB; Opcode.PADDB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FFC = [| Opcode.InvalOP; Opcode.VPADDB;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FFD = [| Opcode.PADDW; Opcode.PADDW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FFD = [| Opcode.InvalOP; Opcode.VPADDW;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0FFE = [| Opcode.PADDD; Opcode.PADDD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opVex0FFE = [| Opcode.InvalOP; Opcode.VPADDD;
                   Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3800 = [| Opcode.PSHUFB; Opcode.PSHUFB;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3800 = [| Opcode.InvalOP; Opcode.VPSHUFB;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3801 = [| Opcode.PHADDW; Opcode.PHADDW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3801 = [| Opcode.InvalOP; Opcode.VPHADDW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3802 = [| Opcode.PHADDD; Opcode.PHADDD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3802 = [| Opcode.InvalOP; Opcode.VPHADDD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3803 = [| Opcode.PHADDSW; Opcode.PHADDSW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3803 = [| Opcode.InvalOP; Opcode.VPHADDSW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3805 = [| Opcode.PHSUBW; Opcode.PHSUBW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3805 = [| Opcode.InvalOP; Opcode.VPHSUBW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3806 = [| Opcode.PHSUBD; Opcode.PHSUBD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3806 = [| Opcode.InvalOP; Opcode.VPHSUBD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3807 = [| Opcode.PHSUBSW; Opcode.PHSUBSW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3807 = [| Opcode.InvalOP; Opcode.VPHSUBSW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3808 = [| Opcode.PSIGNB; Opcode.PSIGNB;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3808 = [| Opcode.InvalOP; Opcode.VPSIGNB;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3809 = [| Opcode.PSIGNW; Opcode.PSIGNW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3809 = [| Opcode.InvalOP; Opcode.VPSIGNW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F380A = [| Opcode.PSIGND; Opcode.PSIGND;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F380A = [| Opcode.InvalOP; Opcode.VPSIGND;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F380B = [| Opcode.PMULHRSW; Opcode.PMULHRSW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F380B = [| Opcode.InvalOP; Opcode.VPMULHRSW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3817 = [| Opcode.InvalOP; Opcode.PTEST;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3817 = [| Opcode.InvalOP; Opcode.VPTEST;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3818 = [| Opcode.InvalOP; Opcode.InvalOP;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3818 = [| Opcode.InvalOP; Opcode.VBROADCASTSS;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opEVex0F3818 = [| Opcode.InvalOP; Opcode.VBROADCASTSS;
                      Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F381C = [| Opcode.PABSB; Opcode.PABSB;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F381C = [| Opcode.InvalOP; Opcode.VPABSB;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F381D = [| Opcode.PABSW; Opcode.PABSW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F381D = [| Opcode.InvalOP; Opcode.VPABSW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F381E = [| Opcode.PABSD; Opcode.PABSD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F381E = [| Opcode.InvalOP; Opcode.VPABSD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3820 = [| Opcode.InvalOP; Opcode.PMOVSXBW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3820 = [| Opcode.InvalOP; Opcode.VPMOVSXBW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3821 = [| Opcode.InvalOP; Opcode.PMOVSXBD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3821 = [| Opcode.InvalOP; Opcode.VPMOVSXBD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3822 = [| Opcode.InvalOP; Opcode.PMOVSXBQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3822 = [| Opcode.InvalOP; Opcode.VPMOVSXBQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3823 = [| Opcode.InvalOP; Opcode.PMOVSXWD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3823 = [| Opcode.InvalOP; Opcode.VPMOVSXWD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3824 = [| Opcode.InvalOP; Opcode.PMOVSXWQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3824 = [| Opcode.InvalOP; Opcode.VPMOVSXWQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3825 = [| Opcode.InvalOP; Opcode.PMOVSXDQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3825 = [| Opcode.InvalOP; Opcode.VPMOVSXDQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3828 = [| Opcode.InvalOP; Opcode.PMULDQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3828 = [| Opcode.InvalOP; Opcode.VPMULDQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3829 = [| Opcode.InvalOP; Opcode.PCMPEQQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3829 = [| Opcode.InvalOP; Opcode.VPCMPEQQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F382B = [| Opcode.InvalOP; Opcode.PACKUSDW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F382B = [| Opcode.InvalOP; Opcode.VPACKUSDW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3830 = [| Opcode.InvalOP; Opcode.PMOVZXBW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3830 = [| Opcode.InvalOP; Opcode.VPMOVZXBW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3831 = [| Opcode.InvalOP; Opcode.PMOVZXBD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3831 = [| Opcode.InvalOP; Opcode.VPMOVZXBD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3832 = [| Opcode.InvalOP; Opcode.PMOVZXBQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3832 = [| Opcode.InvalOP; Opcode.VPMOVZXBQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3833 = [| Opcode.InvalOP; Opcode.PMOVZXWD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3833 = [| Opcode.InvalOP; Opcode.VPMOVZXWD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3834 = [| Opcode.InvalOP; Opcode.PMOVZXWQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3834 = [| Opcode.InvalOP; Opcode.VPMOVZXWQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3835 = [| Opcode.InvalOP; Opcode.PMOVZXDQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3835 = [| Opcode.InvalOP; Opcode.VPMOVZXDQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3837 = [| Opcode.InvalOP; Opcode.PCMPGTQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3837 = [| Opcode.InvalOP; Opcode.VPCMPGTQ;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3838 = [| Opcode.InvalOP; Opcode.PMINSB;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3838 = [| Opcode.InvalOP; Opcode.VPMINSB;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3839 = [| Opcode.InvalOP; Opcode.PMINSD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3839 = [| Opcode.InvalOP; Opcode.VPMINSD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F383A = [| Opcode.InvalOP; Opcode.PMINUW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F383A = [| Opcode.InvalOP; Opcode.VPMINUW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F383B = [| Opcode.InvalOP; Opcode.PMINUD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F383B = [| Opcode.InvalOP; Opcode.VPMINUD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F383C = [| Opcode.InvalOP; Opcode.PMAXSB;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F383C = [| Opcode.InvalOP; Opcode.VPMAXSB;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F383D = [| Opcode.InvalOP; Opcode.PMAXSD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F383D = [| Opcode.InvalOP; Opcode.VPMAXSD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F383E = [| Opcode.InvalOP; Opcode.PMAXUW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F383E = [| Opcode.InvalOP; Opcode.VPMAXUW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F383F = [| Opcode.InvalOP; Opcode.PMAXUD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F383F = [| Opcode.InvalOP; Opcode.VPMAXUD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3840 = [| Opcode.InvalOP; Opcode.PMULLD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3840 = [| Opcode.InvalOP; Opcode.VPMULLD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3841 = [| Opcode.InvalOP; Opcode.PHMINPOSUW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3841 = [| Opcode.InvalOP; Opcode.VPHMINPOSUW;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F385A = [| Opcode.InvalOP; Opcode.InvalOP;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F385A = [| Opcode.InvalOP; Opcode.VBROADCASTI128;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3878 = [| Opcode.InvalOP; Opcode.InvalOP;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3878 = [| Opcode.InvalOP; Opcode.VPBROADCASTB;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F38F0 = [| Opcode.MOVBE; Opcode.MOVBE;
                     Opcode.InvalOP; Opcode.CRC32; Opcode.CRC32 |]
let opNor0F38F1 = [| Opcode.MOVBE; Opcode.MOVBE;
                     Opcode.InvalOP; Opcode.CRC32; Opcode.CRC32 |]
let opNor0F38F6 = [| Opcode.InvalOP; Opcode.InvalOP;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F38F6 = [| Opcode.InvalOP; Opcode.InvalOP;
                     Opcode.InvalOP; Opcode.MULX |]
let opNor0F38F7 = [| Opcode.InvalOP; Opcode.InvalOP;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F38F7 = [| Opcode.InvalOP; Opcode.SHLX;
                     Opcode.SARX; Opcode.SHRX |]
let opNor0F3A0F = [| Opcode.PALIGNR; Opcode.PALIGNR;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3A0F = [| Opcode.InvalOP; Opcode.VPALIGNR;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3A20 = [| Opcode.InvalOP; Opcode.PINSRB;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3A20 = [| Opcode.InvalOP; Opcode.InvalOP;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3A38 = [| Opcode.InvalOP; Opcode.InvalOP;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3A38 = [| Opcode.InvalOP; Opcode.VINSERTI128;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3A60 = [| Opcode.InvalOP; Opcode.PCMPESTRM;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3A60 = [| Opcode.InvalOP; Opcode.VPCMPESTRM;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3A61 = [| Opcode.InvalOP; Opcode.PCMPESTRI;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3A61 = [| Opcode.InvalOP; Opcode.VPCMPESTRI;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3A62 = [| Opcode.InvalOP; Opcode.PCMPISTRM;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3A62 = [| Opcode.InvalOP; Opcode.VPCMPISTRM;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3A63 = [| Opcode.InvalOP; Opcode.PCMPISTRI;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3A63 = [| Opcode.InvalOP; Opcode.VPCMPISTRI;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3A0B = [| Opcode.InvalOP; Opcode.ROUNDSD;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3A0B = [| Opcode.InvalOP; Opcode.InvalOP;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opNor0F3AF0 = [| Opcode.InvalOP; Opcode.InvalOP;
                     Opcode.InvalOP; Opcode.InvalOP |]
let opVex0F3AF0 = [| Opcode.InvalOP; Opcode.InvalOP;
                     Opcode.InvalOP; Opcode.RORX |]
let opEmpty = [| Opcode.InvalOP; Opcode.InvalOP;
                 Opcode.InvalOP; Opcode.InvalOP |]


// vim: set tw=80 sts=2 sw=2:

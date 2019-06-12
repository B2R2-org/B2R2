(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          DongYeop Oh <oh51dy@kaist.ac.kr>
          Seung Il Jung <sijung@kaist.ac.kr>
          Minkyu Jung <hestati@kaist.ac.kr>

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

module B2R2.FrontEnd.Intel.Parser

open System
open B2R2
open B2R2.FrontEnd.Intel
open B2R2.FrontEnd.Intel.RegGroup
open B2R2.FrontEnd.Intel.Helper
open B2R2.FrontEnd.Intel.Constants

let private dsNor0F1A     = [| 0L; BNDRbndBNDRMbnd; 0L; 0L |]
let private dsNor0F1B     = [| 0L; BNDRMbndBNDRbnd; 0L; 0L |]
let private dsNor0F10     = [| VdqWdq; VdqWdq; VdqWdqd; VdqWdqq |]
let private dsVex0F10Mem  = [| VpsWps; VpdWpd; VxWssd; VxWssq |]
let private dsVex0F10Reg  = [| VpsWps; VpdWpd; VxHxWss; VxHxWsd |]
let private dsNor0F11     = [| WdqVdq; WdqVdq; WdqdVdq; WdqqVdq |]
let private dsVex0F11Mem  = [| WpsVps; WpdVpd; WssdVx; VxWssq |]
let private dsVex0F11Reg  = [| WpsVps; WpdVpd; WssHxVss; WsdHxVsd |]
let private dsNor0F12Mem  = [| VdqMq; VdqMq; VdqWdq; VdqWdqq |]
let private dsNor0F12Reg  = [| VdqUdq; VdqMq; VdqWdq; VdqWdqq |]
let private dsVex0F12Mem  = [| VdqHdqMq; VdqHdqMdqd; VxWx; VxWx |]
let private dsVex0F12Reg  = [| VdqHdqUdq; VdqHdqMdqd; VxWx; VxWx |]
let private dsNor0F13     = [| MqVdq; MqVdq; 0L; 0L |]
let private dsVex0F13     = [| MqVdq; MqVdq; 0L; 0L |]
let private dsNor0F14     = [| VdqWdq; VdqWdq; 0L; 0L |]
let private dsVex0F14     = [| VxHxWx; VxHxWx; 0L; 0L |]
let private dsNor0F15     = [| VdqWdq; VdqWdq; 0L; 0L |]
let private dsVex0F15     = [| VxHxWx; VxHxWx; 0L; 0L |]
let private dsNor0F16Mem  = [| VdqMq; VdqMq; VdqWdq; 0L |]
let private dsNor0F16Reg  = [| VdqUdq; VdqMq; VdqWdq; 0L |]
let private dsVex0F16Mem  = [| VdqHdqMq; VdqHdqMq; VxWx; 0L |]
let private dsVex0F16Reg  = [| VdqHdqUdq; VdqHdqMq; VxWx; 0L |]
let private dsNor0F17     = [| MqVdq; MqVdq; 0L; 0L |]
let private dsVex0F17     = [| MqVdq; MqVdq; 0L; 0L |]
let private dsNor0F28     = [| VdqWdq; VdqWdq; 0L; 0L |]
let private dsVex0F28     = [| VpsWps; VpdWpd ; 0L; 0L |]
let private dsNor0F29     = [| WdqVdq; WdqVdq; 0L; 0L |]
let private dsVex0F29     = [| WpsVps; WpdVpd; 0L; 0L |]
let private dsNor0F2A     = [| VdqQq; VdqQq; VdqEy; VdqEy |]
let private dsVex0F2A     = [| 0L; 0L; VssHssEy; VsdHsdEy |]
let private dsNor0F2B     = [| MdqVdq; MdqVdq; 0L; 0L |]
let private dsVex0F2B    = [| MpsVps; MpdVpd; 0L; 0L |]
let private dsNor0F2C     = [| PpiWdqq; PpiWdq; GyWssd; GyWsdq |]
let private dsVex0F2C     = [| 0L; 0L; GyWssd; GyWsdq |]
let private dsNor0F2D     = [| PpiWdqq; PpiWdq; GyWssd; GyWsdq |]
let private dsVex0F2D     = [| 0L; 0L; GyWssd; GyWsdq |]
let private dsNor0F2E     = [| VssWssd; VsdWsdq; 0L; 0L |]
let private dsVex0F2E     = [| VssWssd; VsdWsdq; 0L; 0L |]
let private dsNor0F2F     = [| VssWssd; VsdWsdq; 0L; 0L |]
let private dsVex0F2F     = [| VssWssd; VsdWsdq; 0L; 0L |]
let private dsNor0F50     = [| GyUdq; GyUdq; 0L; 0L |]
let private dsVex0F50     = [| GyUps; GyUpd; 0L; 0L |]
let private dsNor0F54     = [| VdqWdq; VdqWdq; 0L; 0L |]
let private dsVex0F54     = [| VpsHpsWps; VpdHpdWpd; 0L; 0L |]
let private dsNor0F55     = [| VdqWdq; VdqWdq; 0L; 0L |]
let private dsVex0F55     = [| VpsHpsWps; VpdHpdWpd; 0L; 0L |]
let private dsNor0F56     = [| VdqWdq; VdqWdq; 0L; 0L |]
let private dsVex0F56     = [| VpsHpsWps; VpdHpdWpd; 0L; 0L |]
let private dsNor0F57     = [| VdqWdq; VdqWdq; 0L; 0L |]
let private dsVex0F57     = [| VpsHpsWps; VpdHpdWpd; 0L; 0L |]
let private dsNor0F58     = [| VdqWdq; VdqWdq; VdqWdqd; VdqWdqq |]
let private dsVex0F58     = [| VpsHpsWps; VpdHpdWpd; VssHssWssd; VsdHsdWsdq |]
let private dsNor0F59     = [| VdqWdq; VdqWdq; VdqWdqd; VdqWdqq |]
let private dsVex0F59     = [| VpsHpsWps; VpdHpdWpd; VssHssWssd; VsdHsdWsdq |]
let private dsNor0F5A     = [| VdqWdqq; VdqWdq; VdqWdqd; VdqWdqq |]
let private dsVex0F5A     = [| 0L; 0L; 0L; 0L |]
let private dsNor0F5B     = [| VdqWdq; VdqWdq; VdqWdq; 0L |]
let private dsVex0F5B     = [| 0L; 0L; 0L; 0L |]
let private dsNor0F5C     = [| VdqWdq; VdqWdq; VdqWdqd; VdqWdqq |]
let private dsVex0F5C     = [| VpsHpsWps; VpdHpdWpd; VssHssWssd; VsdHsdWsdq |]
let private dsNor0F5D     = [| VdqWdq; VdqWdq; VdqWdqd; VdqWdqq |]
let private dsVex0F5D     = [| 0L; 0L; 0L; 0L |]
let private dsNor0F5E     = [| VdqWdq; VdqWdq; VdqWdqd; VdqWdqq |]
let private dsVex0F5E     = [| VpsHpsWps; VpdHpdWpd; VssHssWssd; VsdHsdWsdq |]
let private dsNor0F5F     = [| VdqWdq; VdqWdq; VdqWdqd; VdqWdqq |]
let private dsVex0F5F     = [| 0L; 0L; 0L; 0L |]
let private dsNor0F60     = [| PqQd; VdqWdq; 0L; 0L |]
let private dsVex0F60     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F61     = [| PqQd; VdqWdq; 0L; 0L |]
let private dsVex0F61     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F62     = [| PqQd; VdqWdq; 0L; 0L |]
let private dsVex0F62     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F63     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F63     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F64     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F64     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F65     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F65     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F66     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F66     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F67     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F67     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F68     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F68     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F69     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F69     = [| 0L; VxHxWx; 0L; 0L|]
let private dsNor0F6A     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F6A     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F6B     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F6B     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F6C     = [| 0L; VdqWdq; 0L; 0L |]
let private dsVex0F6C     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F6D     = [| 0L; VdqWdq; 0L; 0L |]
let private dsVex0F6D     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F6EB64  = [| PdEy; VdqEy; 0L; 0L |]
let private dsNor0F6EB32  = [| PdEy; VdqEy; 0L; 0L |]
let private dsVex0F6EB64  = [| 0L; VdqEy; 0L; 0L |]
let private dsVex0F6EB32  = [| 0L; VdqEy; 0L; 0L |]
let private dsNor0F6F     = [| PqQq; VdqWdq; VdqWdq; 0L |]
let private dsVex0F6F     = [| 0L; VxWx; VxWx; 0L |]
let private dsEVex0F6FB64 = [| 0L; VZxzWZxz; VZxzWZxz; 0L |]
let private dsEVex0F6FB32 = [| 0L; VZxzWZxz; VZxzWZxz; 0L |]
let private dsNor0F70     = [| PqQqIb; VdqWdqIb; VdqWdqIb; VdqWdqIb |]
let private dsVex0F70     = [| 0L; VxWxIb; VxWxIb; VxWxIb |]
let private dsNor0F74     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F74     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F75     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F75     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F76     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F76     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F77     = [| 0L; 0L; 0L; 0L |]
let private dsVex0F77     = [| 0L; 0L; 0L; 0L |]
let private dsNor0F7EB64  = [| EyPq; EyVdq; VdqWdqq; 0L |]
let private dsNor0F7EB32  = [| EyPq; EyVdq; VdqWdqq; 0L |]
let private dsVex0F7EB64  = [| 0L; EyVdq; VdqWdqq; 0L |]
let private dsVex0F7EB32  = [| 0L; EyVdq; VdqWdqq; 0L |]
let private dsNor0F7F     = [| QqPq; WdqVdq; WdqVdq; 0L |]
let private dsVex0F7F     = [| 0L; WxVx; WxVx; 0L |]
let private dsEVex0F7FB64 = [| 0L; WZxzVZxz; 0L; 0L |]
let private dsEVex0F7FB32 = [| 0L; WZxzVZxz; 0L; 0L |]
let private dsNor0FC4     = [| PqEdwIb; VdqEdwIb; 0L; 0L |]
let private dsVex0FC4     = [| 0L; VdqHdqEdwIb; 0L; 0L |]
let private dsNor0FC5     = [| GdNqIb; GdUdqIb; 0L; 0L |]
let private dsVex0FC5     = [| 0L; GdUdqIb; 0L; 0L |]
let private dsNor0FC6     = [| VdqWdqIb; VdqWdqIb; 0L; 0L |]
let private dsVex0FC6     = [| VpsHpsWpsIb; VpsHpsWpsIb; 0L; 0L |]
let private dsNor0FD1     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FD1     = [| 0L; VxHxWdq; 0L; 0L |]
let private dsNor0FD2     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FD2     = [| 0L; VxHxWdq; 0L; 0L |]
let private dsNor0FD3     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FD3     = [| 0L; VxHxWdq; 0L; 0L |]
let private dsNor0FD4     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FD4     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FD5     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FD5     = [| 0L; VxHxWx; 0L; 0L|]
let private dsNor0FD6     = [| 0L; WdqqVdq; VdqNq; PqUdq |]
let private dsVex0FD6     = [| 0L; WdqqVdq; 0L; 0L |]
let private dsNor0FD7     = [| GdNq; GdUdq; 0L; 0L |]
let private dsVex0FD7     = [| 0L; GyUx; 0L; 0L |]
let private dsNor0FD8     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FD8     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FD9     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FD9     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FDA     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FDA     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FDB     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FDB     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FDC     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FDC     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FDD     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FDD     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FDE     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FDE     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FDF     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FDF     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FE0     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FE0     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FE1     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FE1     = [| 0L; VxHxWdq; 0L; 0L |]
let private dsNor0FE2     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FE2     = [| 0L; VxHxWdq; 0L; 0L |]
let private dsNor0FE3     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FE3     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FE4     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FE4     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FE5     = [| PqQq; VdqWdq; 0L; 0L|]
let private dsVex0FE5     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FE6     = [| 0L; VdqWdq; VdqWdqq; VdqWdq |]
let private dsVex0FE6     = [| 0L; 0L; 0L; 0L|]
let private dsNor0FE7     = [| MqPq; MdqVdq; 0L; 0L |]
let private dsVex0FE7     = [| 0L; MxVx; 0L; 0L|]
let private dsEVex0FE7B64 = [| 0L; 0L; 0L; 0L |]
let private dsEVex0FE7B32 = [| 0L; MZxzVZxz; 0L; 0L |]
let private dsNor0FE8     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FE8     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FE9     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FE9     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FEA     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FEA     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FEB     = [| PqQq; VdqWdq; 0L; 0L; 0L |]
let private dsVex0FEB     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FEC     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FEC     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FED     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FED     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FEE     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FEE     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FEF     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FEF     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FF0     = [| 0L; 0L; 0L; VdqMdq |]
let private dsVex0FF0     = [| 0L; 0L; 0L; VxMx |]
let private dsNor0FF1     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FF1     = [| 0L; VxHxWdq; 0L; 0L |]
let private dsNor0FF2     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FF2     = [| 0L; VxHxWdq; 0L; 0L |]
let private dsNor0FF3     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FF3     = [| 0L; VxHxWdq; 0L; 0L |]
let private dsNor0FF4     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FF4     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FF5     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FF5     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FF6     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FF6     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FF8     = [| PqQq; VdqWdq; 0L; 0L|]
let private dsVex0FF8     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FF9     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FF9     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FFA     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FFA     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FFB     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FFB     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FFC     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FFC     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FFD     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FFD     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0FFE     = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0FFE     = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F3800   = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F3800   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F3801   = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F3801   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F3802   = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F3802   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F3803   = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F3803   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F3805   = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F3805   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F3806   = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F3806   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F3807   = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F3807   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F3808   = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F3808   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F3809   = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F3809   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F380A   = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F380A   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F380B   = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F380B   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F3817   = [| 0L; VdqWdq; 0L; 0L |]
let private dsVex0F3817   = [| 0L; VxWx; 0L; 0L |]
let private dsNor0F3818   = [| 0L; 0L; 0L; 0L |]
let private dsVex0F3818   = [| 0L; VxMd; 0L; 0L |]
let private dsEVex0F3818  = [| 0L; VZxzWdqd; 0L; 0L |]
let private dsNor0F381C   = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F381C   = [| 0L; VxWx; 0L; 0L |]
let private dsNor0F381D   = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F381D   = [| 0L; VxWx; 0L; 0L |]
let private dsNor0F381E   = [| PqQq; VdqWdq; 0L; 0L |]
let private dsVex0F381E   = [| 0L; VxWx; 0L; 0L |]
let private dsNor0F3820   = [| 0L; VdqWdqq; 0L; 0L |]
let private dsVex0F3820   = [| 0L; VxWdqqdq; 0L; 0L |]
let private dsNor0F3821   = [| 0L; VdqWdqd; 0L; 0L |]
let private dsVex0F3821   = [| 0L; VxWdqdq; 0L; 0L |]
let private dsNor0F3822   = [| 0L; VdqWdqw; 0L; 0L |]
let private dsVex0F3822   = [| 0L; VxWdqwd; 0L; 0L |]
let private dsNor0F3823   = [| 0L; VdqWdqq; 0L; 0L |]
let private dsVex0F3823   = [| 0L; VxWdqqdq; 0L; 0L |]
let private dsNor0F3824   = [| 0L; VdqWdqd; 0L; 0L |]
let private dsVex0F3824   = [| 0L; VxWdqdq; 0L; 0L |]
let private dsNor0F3825   = [| 0L; VdqWdqq; 0L; 0L |]
let private dsVex0F3825   = [| 0L; VxWdqqdq; 0L; 0L |]
let private dsNor0F3828   = [| 0L; VdqWdq; 0L; 0L |]
let private dsVex0F3828   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F3829   = [| 0L; VdqWdq; 0L; 0L |]
let private dsVex0F3829   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F382B   = [| 0L; VdqWdq; 0L; 0L |]
let private dsVex0F382B   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F3830   = [| 0L; VdqWdqq; 0L; 0L |]
let private dsVex0F3830   = [| 0L; VxWdqqdq; 0L; 0L |]
let private dsNor0F3831   = [| 0L; VdqWdqd; 0L; 0L |]
let private dsVex0F3831   = [| 0L; VxWdqdq; 0L; 0L |]
let private dsNor0F3832   = [| 0L; VdqWdqw; 0L; 0L |]
let private dsVex0F3832   = [| 0L; VxWdqwd; 0L; 0L |]
let private dsNor0F3833   = [| 0L; VdqWdqq; 0L; 0L |]
let private dsVex0F3833   = [| 0L; VxWdqqdq; 0L; 0L |]
let private dsNor0F3834   = [| 0L; VdqWdqd; 0L; 0L |]
let private dsVex0F3834   = [| 0L; VxWdqdq; 0L; 0L |]
let private dsNor0F3835   = [| 0L; VdqWdqq; 0L; 0L |]
let private dsVex0F3835   = [| 0L; VxWdqqdq; 0L; 0L |]
let private dsNor0F3837   = [| 0L; VdqWdq; 0L; 0L |]
let private dsVex0F3837   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F3838   = [| 0L; VdqWdq; 0L; 0L |]
let private dsVex0F3838   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F3839   = [| 0L; VdqWdq; 0L; 0L |]
let private dsVex0F3839   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F383A   = [| 0L; VdqWdq; 0L; 0L |]
let private dsVex0F383A   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F383B   = [| 0L; VdqWdq; 0L; 0L |]
let private dsVex0F383B   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F383C   = [| 0L; VdqWdq; 0L; 0L |]
let private dsVex0F383C   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F383D   = [| 0L; VdqWdq; 0L; 0L |]
let private dsVex0F383D   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F383E   = [| 0L; VdqWdq; 0L; 0L |]
let private dsVex0F383E   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F383F   = [| 0L; VdqWdq; 0L; 0L |]
let private dsVex0F383F   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F3840   = [| 0L; VdqWdq; 0L; 0L |]
let private dsVex0F3840   = [| 0L; VxHxWx; 0L; 0L |]
let private dsNor0F3841   = [| 0L; VdqWdq; 0L; 0L |]
let private dsVex0F3841   = [| 0L; VdqWdq; 0L; 0L |]
let private dsNor0F385A   = [| 0L; 0L; 0L; 0L |]
let private dsVex0F385A   = [| 0L; VqqMdq; 0L; 0L |]
let private dsNor0F3878   = [| 0L; 0L; 0L; 0L |]
let private dsVex0F3878   = [| 0L; VxWx; 0L; 0L |]
let private dsNor0F38F0   = [| GyMy; GwMw; 0L; GvEb; GdEb |]
let private dsNor0F38F1   = [| MyGy; MwGw; 0L; GvEy; GdEw |]
let private dsNor0F3A0F   = [| PqQqIb; VdqWdqIb; 0L; 0L |]
let private dsVex0F3A0F   = [| 0L; VxHxWxIb; 0L; 0L |]
let private dsNor0F3A20   = [| 0L; VdqEdbIb; 0L; 0L |]
let private dsVex0F3A20   = [| 0L; 0L; 0L; 0L |]
let private dsNor0F3A38   = [| 0L; 0L; 0L; 0L |]
let private dsVex0F3A38   = [| 0L; VqqHqqWdqIb; 0L; 0L |]
let private dsNor0F3A60   = [| 0L; VdqWdqIb; 0L; 0L |]
let private dsVex0F3A60   = [| 0L; VdqWdqIb; 0L; 0L |]
let private dsNor0F3A61   = [| 0L; VdqWdqIb; 0L; 0L |]
let private dsVex0F3A61   = [| 0L; VdqWdqIb; 0L; 0L |]
let private dsNor0F3A62   = [| 0L; VdqWdqIb; 0L; 0L |]
let private dsVex0F3A62   = [| 0L; VdqWdqIb; 0L; 0L |]
let private dsNor0F3A63   = [| 0L; VdqWdqIb; 0L; 0L |]
let private dsVex0F3A63   = [| 0L; VdqWdqIb; 0L; 0L |]
let private dsNor0F3A0B   = [| 0L; VsdWsdIb; 0L; 0L |]
let private dsVex0F3A0B   = [| 0L; 0L; 0L; 0L |]
let private dsEmpty       = [| 0L; 0L; 0L; 0L |]

let parsePrefix (reader: BinReader) pos =
  let rec loop pos acc =
    let nextPos = pos + 1
    match reader.PeekByte pos with
    | 0xF0uy -> loop nextPos (Prefix.PrxLOCK ||| (clearGrp1PrefMask &&& acc))
    | 0xF2uy -> loop nextPos (Prefix.PrxREPNZ ||| (clearGrp1PrefMask &&& acc))
    | 0xF3uy -> loop nextPos (Prefix.PrxREPZ ||| (clearGrp1PrefMask &&& acc))
    | 0x2Euy -> loop nextPos (Prefix.PrxCS ||| (clearSegMask &&& acc))
    | 0x36uy -> loop nextPos (Prefix.PrxSS ||| (clearSegMask &&& acc))
    | 0x3Euy -> loop nextPos (Prefix.PrxDS ||| (clearSegMask &&& acc))
    | 0x26uy -> loop nextPos (Prefix.PrxES ||| (clearSegMask &&& acc))
    | 0x64uy -> loop nextPos (Prefix.PrxFS ||| (clearSegMask &&& acc))
    | 0x65uy -> loop nextPos (Prefix.PrxGS ||| (clearSegMask &&& acc))
    | 0x66uy -> loop nextPos (Prefix.PrxOPSIZE ||| acc)
    | 0x67uy -> loop nextPos (Prefix.PrxADDRSIZE ||| acc)
    | _opcode -> struct (acc, pos)
  loop pos Prefix.PrxNone

let inline private getREX (reader: BinReader) pos =
  let rb = reader.PeekByte pos |> int |> LanguagePrimitives.EnumOfValue
  if rb >= REXPrefix.REX && rb <= REXPrefix.REXWRXB then
    struct (rb, pos + 1)
  else struct (REXPrefix.NOREX, pos)

let parseREX wordSize reader pos =
  if wordSize = WordSize.Bit32 then struct (REXPrefix.NOREX, pos)
  else getREX reader pos

let inline private getFstDesc oprDescs = (oprDescs >>> 48) &&& 0xFFFFL
let inline private getSndDesc oprDescs = (oprDescs >>> 32) &&& 0xFFFFL
let inline private getTrdDesc oprDescs = (oprDescs >>> 16) &&& 0xFFFFL
let inline private getFthDesc oprDescs = oprDescs &&& 0xFFFFL
let inline private getDescKindFld oprDesc = oprDesc &&& 0xF000L
let inline private getModeFld oprDesc = oprDesc &&& 0x3FL
let inline private getDescAndMode oprDesc = oprDesc &&& 0xF03FL
let inline private getSizeFld oprDesc = oprDesc &&& 0xFC0L

let private isRegMode = function
  | 0x7L  (* OprMode.G *)
  | 0xeL  (* OprMode.N *)
  | 0x10L (* OprMode.P *)
  | 0x12L (* OprMode.R *)
  | 0x15L (* OprMode.V *)
  | 0x16L (* OprMode.VZ *) -> true
  | _ -> false

let inline private isRegOpr oprDesc =
  if oprDesc < 0x2000L then false
  elif oprDesc >= 0x3000L then true
  else getModeFld oprDesc |> isRegMode

let private getOperationSize regSize oprSize opCode oprDescs =
  match opCode with
  | Opcode.PUSH | Opcode.POP -> oprSize
  | Opcode.MOVSB | Opcode.INSB
  | Opcode.STOSB | Opcode.LODSB
  | Opcode.OUTSB | Opcode.SCASB -> 8<rt>
  | Opcode.OUTSW -> 16<rt>
  | Opcode.OUTSD -> 32<rt>
  | _ -> if isRegOpr (getFstDesc oprDescs) then regSize else oprSize

let inline private selectREX vexInfo rexPref =
  match vexInfo with
  | None -> rexPref // t.TREXPrefix
  | Some v -> v.VREXPrefix

let inline private getVecLen t = (Option.get t.TVEXInfo).VectorLength
let inline private is32bit t = t.TWordSize = WordSize.Bit32
let inline private is64bit t = t.TWordSize = WordSize.Bit64
let inline private is64bitWithOprSz t = is64bit t && hasOprSz t.TPrefixes
let inline private is64bitWithAddrSz t = is64bit t && hasAddrSz t.TPrefixes
let inline private hasNoPref t = (int t.TPrefixes) = 0
let inline private hasNoREX t = t.TREXPrefix = REXPrefix.NOREX
let inline private hasNoPrefNoREX t = hasNoPref t && hasNoREX t

/// Returns a tuple (regSize, effOprSize)
let private getSizeBySzDesc t effOprSz szKind =
  match szKind with
  | 0x80L  (* OprSize.B *) -> struct (8<rt>, 8<rt>)
  | 0xc0L  (* OprSize.Bnd *) ->
    struct (effOprSz, if is32bit t then 64<rt> else 128<rt>)
  | 0x700L (* OprSize.W *) -> struct (16<rt>, 16<rt>)
  | 0x100L (* OprSize.D *) -> struct (32<rt>, 32<rt>)
  | 0x140L (* OprSize.DB *) -> struct (32<rt>, 8<rt>)
  | 0x300L (* OprSize.DW *) -> struct (32<rt>, 16<rt>)
  | 0x380L (* OprSize.P *) ->
    if effOprSz = 16<rt> then struct (16<rt>, 32<rt>)
    elif effOprSz = 32<rt> then struct (32<rt>, 48<rt>)
    else struct (64<rt>, 80<rt>)
  | 0x400L (* OprSize.PI *) | 0x4c0L (* OprSize.Q *) -> struct (64<rt>, 64<rt>)
  | 0x2c0L (* OprSize.DQW *) -> struct (128<rt>, 16<rt>)
  | 0x1c0L (* OprSize.DQD *) | 0x640L (* OprSize.SSD *) ->
    struct (128<rt>, 32<rt>)
  | 0x280L (* OprSize.DQQDQ *) ->
    if getVecLen t = 128<rt> then struct (128<rt>, 64<rt>)
    else struct (128<rt>, 128<rt>)
  | 0x200L (* OprSize.DQDQ *) ->
    if getVecLen t = 128<rt> then struct (128<rt>, 32<rt>)
    else struct (128<rt>, 64<rt>)
  | 0x340L (* OprSize.DQWD *) ->
    if getVecLen t = 128<rt> then struct (128<rt>, 16<rt>)
    else struct (128<rt>, 32<rt>)
  | 0x240L (* OprSize.DQQ *)
  | 0x5c0L (* OprSize.SDQ *)
  | 0x680L (* OprSize.SSQ *) -> struct (128<rt>, 64<rt>)
  | 0x180L (* OprSize.DQ *)
  | 0x580L (* OprSize.SD *)
  | 0x600L (* OprSize.SS *) -> struct (128<rt>, 128<rt>)
  | 0x480L (* OprSize.PSQ *) -> struct (getVecLen t, 64<rt>)
  | 0x3c0L (* OprSize.PD *)
  | 0x440L (* OprSize.PS *)
  | 0x740L (* OprSize.X *)
  | 0x780L (* OprSize.XZ *) -> struct (getVecLen t, getVecLen t)
  | 0x500L (* OprSize.QQ *) -> struct (256<rt>, 256<rt>)
  | 0x7c0L (* OprSize.Y *) ->
    if is64bit t && hasREXW (selectREX t.TVEXInfo t.TREXPrefix)
    then struct (64<rt>, 64<rt>)
    else struct (32<rt>, 32<rt>)
  | _ -> struct (effOprSz, effOprSz)

let private convRegSize t effOprSz oprDesc =
  let kind = oprDesc &&& 0xF000L
  if (kind ^^^ 0x3000L) = 0L then Register.toRegType (getRegister oprDesc)
  elif (kind ^^^ 0x4000L) = 0L
    || ((kind ^^^ 0x2000L) = 0L && isRegMode (getModeFld oprDesc)) then
    let (struct (x, _)) = getSizeBySzDesc t effOprSz (getSizeFld oprDesc)
    in x
  else 0<rt>

let rec private findRegSize amount oprDescs t effOprSz ret =
  let oprDesc = (oprDescs >>> amount) &&& 0xffffL
  if oprDesc = 0L then ret
  else
    let v = convRegSize t effOprSz oprDesc
    if v <> 0<rt> then v
    elif amount = 0 then ret
    else findRegSize (amount - 16) oprDescs t effOprSz ret

(* defined in Table 3-4 of the manual Vol. 1. *)
let inline private getRegSize t oprDescs effOprSz =
  findRegSize 48 oprDescs t effOprSz effOprSz

let inline private convMemSize oprDesc =
  match getDescAndMode oprDesc with
  | 0x2003L (* OprMode.BndM *)
  | 0x2006L (* OprMode.E *)
  | 0x200CL (* OprMode.M *)
  | 0x200DL (* OprMode.MZ *)
  | 0x200FL (* OprMode.O *)
  | 0x2011L (* OprMode.Q *)
  | 0x2014L (* OprMode.U *)
  | 0x2017L (* OprMode.W *)
  | 0x2018L (* OprMode.WZ *)
  | 0x2019L (* OprMode.X *)
  | 0x201AL (* OprMode.Y *) -> getSizeFld oprDesc
  | _ -> 0L

let rec private findMemSize amount oprDescs =
  let oprDesc = (oprDescs >>> amount) &&& 0xffffL
  if oprDesc = 0L then 0L
  else
    let s = convMemSize oprDesc
    if s <> 0L then s
    elif amount = 0 then 0L
    else findMemSize (amount - 16) oprDescs

(* Obtain both the effective operand size and the effective address size
   using the rule defined in Table 3-4 of the manual Vol. 1. *)
let getMemSize t oprDescs effOprSz effAddrSz =
  match findMemSize 48 oprDescs with
  | 0L ->
    { EffOprSize = effOprSz; EffAddrSize = effAddrSz; EffRegSize = effOprSz }
  | sz ->
    let struct (rSz, oprSz) = getSizeBySzDesc t effOprSz sz
    { EffOprSize = oprSz; EffAddrSize = effAddrSz; EffRegSize = rSz }

let inline getOprSize size sizeCond =
  if sizeCond = Sz64 then 64<rt>
  elif size = 32<rt> && sizeCond = SzDef64 then 64<rt>
  else size

let inline getSize32 prefs =
  if hasOprSz prefs then
    if hasAddrSz prefs then struct (16<rt>, 16<rt>) else struct (16<rt>, 32<rt>)
  else
    if hasAddrSz prefs then struct (32<rt>, 16<rt>) else struct (32<rt>, 32<rt>)

let inline getSize64 prefs rexPref sizeCond =
  if hasREXW rexPref then
    if hasAddrSz prefs then struct (64<rt>, 32<rt>)
    else struct (64<rt>, 64<rt>)
  else
    if hasOprSz prefs then
      if hasAddrSz prefs then struct (getOprSize 16<rt> sizeCond, 32<rt>)
      else struct (getOprSize 16<rt> sizeCond, 64<rt>)
    else
      if hasAddrSz prefs then
        struct (getOprSize 32<rt> sizeCond, 32<rt>)
      else struct (getOprSize 32<rt> sizeCond, 64<rt>)

let getSize t sizeCond =
  if t.TWordSize = WordSize.Bit32 then getSize32 t.TPrefixes
  else getSize64 t.TPrefixes (selectREX t.TVEXInfo t.TREXPrefix) sizeCond

let newInsSize t sizeCond opCode oprDescs =
  let struct (effOprSize, effAddrSize) = getSize t sizeCond
  let rSize = getRegSize t oprDescs effOprSize
  let mSize = getMemSize t oprDescs effOprSize effAddrSize
  let opSize = getOperationSize rSize mSize.EffOprSize opCode oprDescs
  {
    MemSize = mSize
    RegSize = rSize
    OperationSize = opSize
    SizeCond = sizeCond
  }

let private processOpDescExn oprDescs = function
  | Opcode.CMPSB | Opcode.CMPSW | Opcode.CMPSD | Opcode.CMPSQ -> 0L
  | _ -> oprDescs

let parseOp (t: TemporaryInfo) opCode szCond oprDescs =
  let insSize = newInsSize t szCond opCode oprDescs
  let oprDescs = processOpDescExn oprDescs opCode
  Some (struct (newTemporaryIns opCode NoOperand t insSize, oprDescs))

let private getVLen = function
  | 0b00uy -> 128<rt>
  | 0b01uy -> 256<rt>
  | 0b10uy -> 512<rt>
  | 0b11uy -> raise ParsingFailureException
  | _ -> raise ParsingFailureException

let private getVPrefs b =
  match b &&& 0b00000011uy with
  | 0b01uy -> Prefix.PrxOPSIZE
  | 0b10uy -> Prefix.PrxREPZ
  | 0b11uy -> Prefix.PrxREPNZ
  | _ -> Prefix.PrxNone

let private getVVVV b = (b >>> 3) &&& 0b01111uy

let private getVREXPref (b1: byte) b2 =
  let wmask = if b2 >>> 7 = 0uy then 0b1110111uy else 0b1111111uy
  let mask = (~~~ (b1 >>> 5)) &&& wmask
             |> int |> LanguagePrimitives.EnumOfValue
  match REXPrefix.REXWRXB &&& mask with
  | REXPrefix.REX -> REXPrefix.NOREX
  | v -> v

let private getTwoVEXInfo (reader: BinReader) pos =
  let b = reader.PeekByte pos
  let rexPref = if (b >>> 7) = 0uy then REXPrefix.REXR else REXPrefix.NOREX
  let vLen = if ((b >>> 2) &&& 0b000001uy) = 0uy then 128<rt> else 256<rt>
  { VVVV = getVVVV b; VectorLength = vLen; VEXType = VEXType.VEXTwoByteOp
    VPrefixes = getVPrefs b; VREXPrefix = rexPref; EVEXPrx = None }

let inline private pickVEXType b1 =
  match b1 &&& 0b00011uy with
  | 0b01uy -> VEXType.VEXTwoByteOp
  | 0b10uy -> VEXType.VEXThreeByteOpOne
  | 0b11uy -> VEXType.VEXThreeByteOpTwo
  | _ -> raise ParsingFailureException

let private getThreeVEXInfo (reader: BinReader) pos =
  let b1 = reader.PeekByte pos
  let b2 = reader.PeekByte (pos + 1)
  let vLen = if ((b2 >>> 2) &&& 0b000001uy) = 0uy then 128<rt> else 256<rt>
  { VVVV = getVVVV b2; VectorLength = vLen; VEXType = pickVEXType b1
    VPrefixes = getVPrefs b2; VREXPrefix = getVREXPref b1 b2; EVEXPrx = None }

let private getEVEXInfo (reader: BinReader) pos =
  let b1 = reader.PeekByte pos
  let b2 = reader.PeekByte (pos + 1)
  let l'l = reader.PeekByte (pos + 2) >>> 5 &&& 0b011uy
  let vLen = getVLen l'l
  let z = if (reader.PeekByte (pos + 2) >>> 7 &&& 0b1uy) = 0uy then Zeroing
          else Merging
  let aaa = reader.PeekByte (pos + 2) &&& 0b111uy
  let e = Some { Z = z; AAA = aaa }
  { VVVV = getVVVV b2; VectorLength = vLen;
    VEXType = pickVEXType b1 ||| VEXType.EVEX
    VPrefixes = getVPrefs b2; VREXPrefix = getVREXPref b1 b2; EVEXPrx = e }

let inline private isVEX (reader: BinReader) wordSize pos =
  not (wordSize = WordSize.Bit32 && reader.PeekByte pos < 0xC0uy)

/// Parse the VEX prefix (VEXInfo).
let parseVEXInfo wordSize (reader: BinReader) pos =
  let nextPos = pos + 1
  match reader.PeekByte pos with
  | 0xC5uy when isVEX reader wordSize nextPos ->
    struct (Some <| getTwoVEXInfo reader nextPos, nextPos + 1)
  | 0xC4uy when isVEX reader wordSize nextPos ->
    struct (Some <| getThreeVEXInfo reader nextPos, nextPos + 2)
  | 0x62uy when isVEX reader wordSize nextPos ->
    struct (Some <| getEVEXInfo reader nextPos, nextPos + 3)
  | _ -> struct (None, pos)

let findOpcode opcode pos =
  let amount = 48 - (pos * 16)
  (opcode >>> amount) &&& 0xffffL |> Convert.ToInt32 |> enum<Opcode>

/// Select based on the prefix: None, 66, F3, or F2.
let private selectOpInfo prefs opc (opr: int64 []) =
  if hasOprSz prefs then findOpcode opc 1, opr.[1]
  elif hasREPZ prefs then findOpcode opc 2, opr.[2]
  elif hasREPNZ prefs then findOpcode opc 3, opr.[3]
  else findOpcode opc 0, opr.[0]

let inline private filterPrefs (prefs: Prefix) = prefs &&& clearVEXPrefMask

let inline private selectVEXOpInfo opNorArr opVEXArr dsNorArr dsVEXArr t =
  (* Some instructions use 66/F2/F3 prefix as a mandatory prefix. When both
     VEX.pp and old-style prefix are used, the VEX.pp is used to select the
     opcodes. But if VEX.pp does not exist, then we have to use the old-style
     prefix, and we have to filter out the prefixes because they are not going
     to be used as a normal prefixes. They will only be used as a mandatory
     prefix that decides the opcode. *)
  match t.TVEXInfo with
  | None -> selectOpInfo t.TPrefixes opNorArr dsNorArr,
            { t with TPrefixes = filterPrefs t.TPrefixes }
  | Some vInfo -> selectOpInfo vInfo.VPrefixes opVEXArr dsVEXArr, t

/// Parse VEX instructions.
let private parseVEX t sizeCond opNorArr opVEXArr dsNorArr dsVEXArr =
  let (opCode, descs), t =
    selectVEXOpInfo opNorArr opVEXArr dsNorArr dsVEXArr t
  parseOp t opCode sizeCond descs

let inline private selectNonVEXOt prefs opc (opr: int64 []) =
  if hasOprSz prefs && hasREPNZ prefs then findOpcode opc 4, opr.[4]
  else selectOpInfo prefs opc opr

/// Parse non-VEX instructions.
let private parseNonVEX t sizeCond opNorArr dsNorArr =
  let opCode, descs = selectNonVEXOt t.TPrefixes opNorArr dsNorArr
  parseOp t opCode sizeCond descs

/// Parse EVEX instructions.
let private parseEVEX t sizeCond opNorArr opVEXArr opEVEXArr
                      dsNorArr dsVEXArr dsEVEXArr =
  let opVEXArr, dsVEXArr =
    match t.TVEXInfo with
    | None -> opEmpty, [| 0L; 0L; 0L; 0L |]
    | Some { VEXType = vt } -> if VEXType.isOriginal vt then opVEXArr, dsVEXArr
                               else opEVEXArr, dsEVEXArr
  parseVEX t sizeCond opNorArr opVEXArr dsNorArr dsVEXArr

/// Parse BND-related instructions.
let private parseBND t sizeCond opBNDArr dsBNDArr =
  let opCode, oprDescs = selectOpInfo t.TPrefixes opBNDArr dsBNDArr
  let t = { t with TPrefixes = filterPrefs t.TPrefixes }
  parseOp t opCode sizeCond oprDescs

let private assertVEX128 = function
  | { TVEXInfo = Some vInfo } ->
    if vInfo.VectorLength = 256<rt> then raise ParsingFailureException else ()
  | _ -> ()

let getMod (byte: byte) = (int byte >>> 6) &&& 0b11
let getReg (byte: byte) = (int byte >>> 3) &&& 0b111
let getRM (byte: byte) = (int byte) &&& 0b111

let private getSTReg n =
  Register.make n Register.Kind.FPU |> OprReg

(* Table A-7/15 of Volume 2
   (D8/DC Opcode Map When ModR/M Byte is within 00H to BFH) *)
let private getD8OpWithin00toBF b =
  match getReg b with
  | 0b000 -> Opcode.FADD
  | 0b001 -> Opcode.FMUL
  | 0b010 -> Opcode.FCOM
  | 0b011 -> Opcode.FCOMP
  | 0b100 -> Opcode.FSUB
  | 0b101 -> Opcode.FSUBR
  | 0b110 -> Opcode.FDIV
  | 0b111 -> Opcode.FDIVR
  | _ -> raise ParsingFailureException // failwith "Not a D8/DC Opcode"
let inline private getDCOpWithin00toBF b = getD8OpWithin00toBF b

(* Table A-8 of Volume 2
   (D8 Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
let private getD8OpcodeOutside00toBF = function
  | b when b >= 0xC0uy && b <= 0xC7uy -> Opcode.FADD
  | b when b >= 0xC8uy && b <= 0xCFuy -> Opcode.FMUL
  | b when b >= 0xD0uy && b <= 0xD7uy -> Opcode.FCOM
  | b when b >= 0xD8uy && b <= 0xDFuy -> Opcode.FCOMP
  | b when b >= 0xE0uy && b <= 0xE7uy -> Opcode.FSUB
  | b when b >= 0xE8uy && b <= 0xEFuy -> Opcode.FSUBR
  | b when b >= 0xF0uy && b <= 0xF7uy -> Opcode.FDIV
  | b when b >= 0xF8uy && b <= 0xFFuy -> Opcode.FDIVR
  | _ -> raise ParsingFailureException // failwith "Not a D8 Opcode"

(* Table A-9 of Volume 2
   (D9 Opcode Map When ModR/M Byte is Within 00H to BFH) *)
let private getD9OpWithin00toBF b =
  match getReg b with
  | 0b000 -> Opcode.FLD
  | 0b010 -> Opcode.FST
  | 0b011 -> Opcode.FSTP
  | 0b100 -> Opcode.FLDENV
  | 0b101 -> Opcode.FLDCW
  | 0b110 -> Opcode.FSTENV
  | 0b111 -> Opcode.FSTCW
  | _ -> raise ParsingFailureException // failwith "Not a D9 Opcode"

(* Table A-10 of Volume 2
   (D9 Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
let private getD9OpcodeOutside00toBF = function
  | b when b >= 0xC0uy && b <= 0xC7uy -> Opcode.FLD
  | b when b >= 0xC8uy && b <= 0xCFuy -> Opcode.FXCH
  | 0xD0uy -> Opcode.FNOP
  | 0xE0uy -> Opcode.FCHS
  | 0xE1uy -> Opcode.FABS
  | 0xE5uy -> Opcode.FXAM
  | 0xE8uy -> Opcode.FLD1
  | 0xE9uy -> Opcode.FLDL2T
  | 0xEAuy -> Opcode.FLDL2E
  | 0xEBuy -> Opcode.FLDPI
  | 0xECuy -> Opcode.FLDLG2
  | 0xEDuy -> Opcode.FLDLN2
  | 0xEEuy -> Opcode.FLDZ
  | 0xF0uy -> Opcode.F2XM1
  | 0xF1uy -> Opcode.FYL2X
  | 0xF2uy -> Opcode.FPTAN
  | 0xF3uy -> Opcode.FPATAN
  | 0xF4uy -> Opcode.FXTRACT
  | 0xF5uy -> Opcode.FPREM1
  | 0xF6uy -> Opcode.FDECSTP
  | 0xF7uy -> Opcode.FINCSTP
  | 0xF8uy -> Opcode.FPREM
  | 0xF9uy -> Opcode.FYL2XP1
  | 0xFAuy -> Opcode.FSQRT
  | 0xFBuy -> Opcode.FSINCOS
  | 0xFCuy -> Opcode.FRNDINT
  | 0xFDuy -> Opcode.FSCALE
  | 0xFEuy -> Opcode.FSIN
  | 0xFFuy -> Opcode.FCOS
  | _ -> raise ParsingFailureException // failwith "Not a D9 Opcode"

(* Table A-11/19 of Volume 2
   (DA/DE Opcode Map When ModR/M Byte is Within 00H to BFH) *)
let private getDAOpWithin00toBF b =
  match getReg b with
  | 0b000 -> Opcode.FIADD
  | 0b001 -> Opcode.FIMUL
  | 0b010 -> Opcode.FICOM
  | 0b011 -> Opcode.FICOMP
  | 0b100 -> Opcode.FISUB
  | 0b101 -> Opcode.FISUBR
  | 0b110 -> Opcode.FIDIV
  | 0b111 -> Opcode.FIDIVR
  | _ -> raise ParsingFailureException // failwith "Not a DA/DE Opcode"
let private getDEOpWithin00toBF b = getDAOpWithin00toBF b

(* Table A-12 of Volume 2
   (DA Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
let private getDAOpcodeOutside00toBF = function
  | b when b >= 0xC0uy && b <= 0xC7uy -> Opcode.FCMOVB
  | b when b >= 0xC8uy && b <= 0xCFuy -> Opcode.FCMOVE
  | b when b >= 0xD0uy && b <= 0xD7uy -> Opcode.FCMOVBE
  | b when b >= 0xD8uy && b <= 0xDFuy -> Opcode.FCMOVU
  | 0xE9uy -> Opcode.FUCOMPP
  | _ -> raise ParsingFailureException // failwith "Not a DA Opcode"

(* Table A-13 of Volume 2
   (DB Opcode Map When ModR/M Byte is Within 00H to BFH) *)
let private getDBOpWithin00toBF b =
  match getReg b with
  | 0b000 -> Opcode.FILD
  | 0b001 -> Opcode.FISTTP
  | 0b010 -> Opcode.FIST
  | 0b011 -> Opcode.FISTP
  | 0b101 -> Opcode.FLD
  | 0b111 -> Opcode.FSTP
  | _ -> raise ParsingFailureException // failwith "Not a DB Opcode"

(* Table A-14 of Volume 2
   (DB Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
let private getDBOpcodeOutside00toBF = function
  | b when b >= 0xC0uy && b <= 0xC7uy -> Opcode.FCMOVNB
  | b when b >= 0xC8uy && b <= 0xCFuy -> Opcode.FCMOVNE
  | b when b >= 0xD0uy && b <= 0xD7uy -> Opcode.FCMOVNBE
  | b when b >= 0xD8uy && b <= 0xDFuy -> Opcode.FCMOVNU
  | b when b >= 0xE8uy && b <= 0xEFuy -> Opcode.FUCOMI
  | b when b >= 0xF0uy && b <= 0xF7uy -> Opcode.FCOMI
  | 0xE2uy -> Opcode.FCLEX
  | 0xE3uy -> Opcode.FINIT
  | _ -> raise ParsingFailureException // failwith "Not a DB Opcode"

(* Table A-16 of Volume 2
   (DC Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
let private getDCOpcodeOutside00toBF = function
  | b when b >= 0xC0uy && b <= 0xC7uy -> Opcode.FADD
  | b when b >= 0xC8uy && b <= 0xCFuy -> Opcode.FMUL
  | b when b >= 0xE0uy && b <= 0xE7uy -> Opcode.FSUBR
  | b when b >= 0xE8uy && b <= 0xEFuy -> Opcode.FSUB
  | b when b >= 0xF0uy && b <= 0xF7uy -> Opcode.FDIVR
  | b when b >= 0xF8uy && b <= 0xFFuy -> Opcode.FDIV
  | _ -> raise ParsingFailureException // failwith "Not a DC Opcode"

(* Table A-17 of Volume 2
   (DD Opcode Map When ModR/M Byte is Within 00H to BFH) *)
let private getDDOpWithin00toBF b =
  match getReg b with
  | 0b000 -> Opcode.FLD
  | 0b001 -> Opcode.FISTTP
  | 0b010 -> Opcode.FST
  | 0b011 -> Opcode.FSTP
  | 0b100 -> Opcode.FRSTOR
  | 0b110 -> Opcode.FSAVE
  | 0b111 -> Opcode.FSTSW
  | _ -> raise ParsingFailureException // failwith "Not a DD Opcode"

(* Table A-18 of Volume 2
   (DD Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
let private getDDOpcodeOutside00toBF b =
  match b with
  | b when b >= 0xC0uy && b <= 0xC7uy -> Opcode.FFREE
  | b when b >= 0xD0uy && b <= 0xD7uy -> Opcode.FST
  | b when b >= 0xD8uy && b <= 0xDFuy -> Opcode.FSTP
  | b when b >= 0xE0uy && b <= 0xE7uy -> Opcode.FUCOM
  | b when b >= 0xE8uy && b <= 0xEFuy -> Opcode.FUCOMP
  | _ -> raise ParsingFailureException // failwith "Not a DD Opcode"

(* Table A-20 of Volume 2
   (DE Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
let private getDEOpcodeOutside00toBF = function
  | b when b >= 0xC0uy && b <= 0xC7uy -> Opcode.FADDP
  | b when b >= 0xC8uy && b <= 0xCFuy -> Opcode.FMULP
  | 0xD9uy -> Opcode.FCOMPP
  | b when b >= 0xE0uy && b <= 0xE7uy -> Opcode.FSUBRP
  | b when b >= 0xE8uy && b <= 0xEFuy -> Opcode.FSUBP
  | b when b >= 0xF0uy && b <= 0xF7uy -> Opcode.FDIVRP
  | b when b >= 0xF8uy && b <= 0xFFuy -> Opcode.FDIVP
  | _ -> raise ParsingFailureException // failwith "Not a DE Opcode"

(* Table A-21 of Volume 2
   (DF Opcode Map When ModR/M Byte is Within 00H to BFH) *)
let private getDFOpWithin00toBF b =
  match getReg b with
  | 0b000 -> Opcode.FILD
  | 0b001 -> Opcode.FISTTP
  | 0b010 -> Opcode.FIST
  | 0b011 -> Opcode.FISTP
  | 0b100 -> Opcode.FBLD
  | 0b101 -> Opcode.FILD
  | 0b110 -> Opcode.FBSTP
  | 0b111 -> Opcode.FISTP
  | _ -> raise ParsingFailureException // failwith "Not a DF Opcode"

(* Table A-22 of Volume 2
   (DF Opcode Map When ModR/M Byte is Outside 00H to BFH) *)
let private getDFOpcodeOutside00toBF = function
  | 0xE0uy -> Opcode.FSTSW
  | b when b >= 0xE8uy && b <= 0xEFuy -> Opcode.FUCOMIP
  | b when b >= 0xF0uy && b <= 0xF7uy -> Opcode.FCOMIP
  | _ -> raise ParsingFailureException // failwith "Not a DF Opcode"

let private getD8OverBF b =
  getD8OpcodeOutside00toBF b, TwoOperands (OprReg R.ST0, getRM b |> getSTReg)

let private getD9OverBF b =
  getD9OpcodeOutside00toBF b,
  if b < 0xC0uy || b >= 0xD0uy then NoOperand
  else TwoOperands (OprReg R.ST0, getRM b |> getSTReg)

let private getDAOverBF b =
  getDAOpcodeOutside00toBF b,
  if b = 0xE9uy then NoOperand
  else TwoOperands (OprReg R.ST0, getRM b |> getSTReg)

let private getDBOverBF b =
  getDBOpcodeOutside00toBF b,
  if b = 0xE2uy || b = 0xE3uy then NoOperand
  else TwoOperands (OprReg R.ST0, getRM b |> getSTReg)

let private getDCOverBF b =
  getDCOpcodeOutside00toBF b, TwoOperands (getRM b |> getSTReg, OprReg R.ST0)

let private getDDOverBF b =
  getDDOpcodeOutside00toBF b,
  if b < 0xE0uy || b >= 0xE8uy then getRM b |> getSTReg |> OneOperand
  else TwoOperands (getRM b |> getSTReg, OprReg R.ST0)

let private getDEOverBF b =
  getDEOpcodeOutside00toBF b,
  if b = 0xD9uy then NoOperand
  else TwoOperands (getRM b |> getSTReg, OprReg R.ST0)

let private getDFOverBF b =
  getDFOpcodeOutside00toBF b,
  if b = 0xE0uy then OprReg R.AX |> OneOperand
  else TwoOperands (getRM b |> getSTReg, OprReg R.ST0)

let private getDFEscEffOprSizeByModRM = function
 | 0b000 | 0b001 | 0b010 | 0b011 -> 16<rt>
 | 0b100 -> 80<rt>
 | 0b101 -> 64<rt>
 | 0b110 -> 80<rt>
 | 0b111 -> 64<rt>
 | _ -> raise ParsingFailureException

let private getEscEffOprSizeByESCOp = function
  | 0xD8uy | 0xD9uy | 0xDAuy | 0xDBuy | 0xDCuy | 0xDDuy -> 32<rt>
  | 0xDEuy -> 16<rt>
  | _ -> raise ParsingFailureException

let private parseESCOp t (reader: BinReader) pos escFlag getOpIn getOpOut =
  let b = reader.PeekByte pos // XXX we can optimize this
  if b <= 0xBFuy then
    let opCode = getOpIn b
    let insSize = newInsSize t SzDef32 opCode Mz
    let effOprSize =
      if escFlag = 0xDFuy then getReg b |> getDFEscEffOprSizeByModRM
      else escFlag |> getEscEffOprSizeByESCOp
    let memSize = { insSize.MemSize with EffOprSize = effOprSize }
    let insSize = { insSize with MemSize = memSize }
    Some (struct (newTemporaryIns opCode NoOperand t insSize, Mz)), pos
  else
    let opCode, oprs = getOpOut b
    let insSize = newInsSize t SzDef32 opCode Mz
    Some (struct (newTemporaryIns opCode oprs t insSize, 0L)), pos + 1

// Group Opcodes
let grp1Op   = [| Opcode.ADD; Opcode.OR; Opcode.ADC; Opcode.SBB;
                  Opcode.AND; Opcode.SUB; Opcode.XOR; Opcode.CMP |]
let grp1aOp  = [| Opcode.POP |]
let grp2Op   = [| Opcode.ROL; Opcode.ROR; Opcode.RCL; Opcode.RCR;
                  Opcode.SHL; Opcode.SHR; Opcode.InvalOP; Opcode.SAR |]
let grp4Op   = [| Opcode.INC; Opcode.DEC |]
let grp5Op   = [| Opcode.INC; Opcode.DEC; Opcode.CALLNear; Opcode.CALLFar;
                  Opcode.JMPNear; Opcode.JMPFar; Opcode.PUSH |]
let grp5Desc = [| Ev; Ev; Ev; Ep; Ev; Mp; Ev |]
let grp5SCnd = [| SzDef32; SzDef32; Sz64; SzDef32; Sz64; SzDef32; SzDef64 |]
let grp7Op   = [| Opcode.SGDT; Opcode.SIDT; Opcode.LGDT; Opcode.LIDT;
                  Opcode.SMSW; Opcode.InvalOP; Opcode.LMSW; Opcode.INVLPG |]
let grp7Desc = [| Ms; Ms; Ms; Ms; Mw; 0L; Ew; Ew |]
let grp8Op   = [| Opcode.InvalOP; Opcode.InvalOP; Opcode.InvalOP;
                  Opcode.InvalOP; Opcode.BT; Opcode.BTS; Opcode.BTR;
                  Opcode.BTC |]
let grp16Op  = [| Opcode.PREFETCHNTA; Opcode.PREFETCHT0;
                  Opcode.PREFETCHT1; Opcode.PREFETCHT2 |]

let getOpAndOprKindByOpGrp3 kindFlag regBits oprDesc =
  match regBits, oprDesc with
  | 0b000, k -> Opcode.TEST, k ||| (kindFlag <<< 32), SzDef32
  | 0b010, _ -> Opcode.NOT, oprDesc, SzDef32
  | 0b011, _ -> Opcode.NEG, oprDesc, SzDef32
  | 0b100, _ -> Opcode.MUL, oprDesc, SzDef32
  | 0b101, _ -> Opcode.IMUL, oprDesc, SzDef32
  | 0b110, _ -> Opcode.DIV, oprDesc, SzDef32
  | 0b111, _ -> Opcode.IDIV, oprDesc, SzDef32
  | _ -> raise ParsingFailureException

let private modIsMemory b = (getMod b) <> 0b11

let getOpAndOprKindByOpGrp6 b regBits =
  match modIsMemory b, regBits with
  | true, 0b000 -> Opcode.SLDT, Mv, SzDef32
  | false, 0b000 -> Opcode.SLDT, Rv, SzDef32
  | true, 0b001 -> Opcode.STR, Mv, SzDef32
  | false, 0b001 -> Opcode.STR, Rv, SzDef32
  | _, 0b010 -> Opcode.LLDT, Ew, SzDef32
  | _, 0b011 -> Opcode.LTR, Ew, SzDef32
  | _, 0b100 -> Opcode.VERR, Ew, SzDef32
  | _, 0b101 -> Opcode.VERW, Ew, SzDef32
  | _ -> raise ParsingFailureException

let parseOpAndOprKindByOpGrp7 t pos b regBits =
  let notMemory = function
    | 0b000, 0b001 -> (Opcode.VMCALL, 0L, SzDef32), pos + 1
    | 0b000, 0b010 -> (Opcode.VMLAUNCH, 0L, SzDef32), pos + 1
    | 0b000, 0b011 -> (Opcode.VMRESUME, 0L, SzDef32), pos + 1
    | 0b000, 0b100 -> (Opcode.VMXOFF, 0L, SzDef32), pos + 1
    | 0b001, 0b000 -> (Opcode.MONITOR, 0L, SzDef32), pos + 1
    | 0b001, 0b001 -> (Opcode.MWAIT, 0L, SzDef32), pos + 1
    | 0b001, 0b010 -> (Opcode.CLAC, 0L, SzDef32), pos + 1
    | 0b001, 0b011 -> (Opcode.STAC, 0L, SzDef32), pos + 1
    | 0b010, 0b000 -> (Opcode.XGETBV, 0L, SzDef32), pos + 1
    | 0b010, 0b001 -> (Opcode.XSETBV, 0L, SzDef32), pos + 1
    | 0b010, 0b100 -> (Opcode.VMFUNC, 0L, SzDef32), pos + 1
    | 0b010, 0b101 -> (Opcode.XEND, 0L, SzDef32), pos + 1
    | 0b010, 0b110 -> (Opcode.XTEST, 0L, SzDef32), pos + 1
    | 0b100, _     -> (Opcode.SMSW, Rv, SzDef32), pos
    | 0b101, 0b110 -> (Opcode.RDPKRU, 0L, SzDef32), pos + 1
    | 0b101, 0b111 -> (Opcode.WRPKRU, 0L, SzDef32), pos + 1
    | 0b110, _     -> (Opcode.LMSW, Ew, SzDef32), pos
    | 0b111, 0b000 -> ensure32 t; (Opcode.SWAPGS, 0L, SzOnly64), pos + 1
    | 0b111, 0b001 -> (Opcode.RDTSCP, 0L, SzDef32), pos + 1
    | _ -> raise ParsingFailureException
  if modIsMemory b then (grp7Op.[regBits], grp7Desc.[regBits], SzDef32), pos
  else notMemory (regBits, getRM b)

let getOpAndPorKindByOpGrp9 t b regBits =
  let hasOprSzPref = hasOprSz t.TPrefixes
  let hasREPZPref = hasREPZ t.TPrefixes
  let hasREXWPref = hasREXW t.TREXPrefix
  match modIsMemory b, regBits, hasOprSzPref, hasREPZPref, hasREXWPref with
  | true,  0b001, false, false, true -> Opcode.CMPXCHG16B, Mdq, SzDef32
  | true,  0b001, false, false, _    -> Opcode.CMPXCHG8B, Mq, SzDef32
  | true,  0b100, false, false, true    -> Opcode.XSAVEC64, Mq, SzDef32
  | true,  0b100, false, false, _    -> Opcode.XSAVEC, Mq, SzDef32
  | true,  0b110, false, false, _    -> Opcode.VMPTRLD, Mq, SzDef32
  | true,  0b111, false, false, _    -> Opcode.VMPTRST, Mq, SzDef32
  | true,  0b110, true,  false, _    -> Opcode.VMCLEAR, Mq, SzDef32
  | true,  0b110, false, true,  _    -> Opcode.VMXON, Mq, SzDef32
  | true,  0b111, false, true,  _    -> Opcode.VMPTRST, Mq, SzDef32
  | false, 0b110, false, false, _    -> Opcode.RDRAND, Rv, SzDef32
  | false, 0b111, false, false, _    -> Opcode.RDSEED, Rv, SzDef32
  | _ -> raise ParsingFailureException

let getOpAndOprKindByOpGrp11 opFlag kFlag b reg descs (reader: BinReader) pos =
  match reg with
  | 0b000 -> (Opcode.MOV, descs, SzDef32), pos
  | 0b111 when modIsMemory b -> raise ParsingFailureException
  | 0b111 -> if reader.PeekByte pos <> 0xF8uy then raise ParsingFailureException
             else (opFlag, kFlag, SzDef32), pos + 1
  | _ -> raise ParsingFailureException

let inline private selectPrefix t =
  match t.TVEXInfo with
  | None -> t.TPrefixes
  | Some v -> v.VPrefixes

let getOpAndOprKindByOpGrp12 t b regBits =
  match modIsMemory b, regBits, hasOprSz (selectPrefix t) with
  | false, 0b010, false -> Opcode.PSRLW, NqIb, SzDef32
  | false, 0b010, true  ->
    if t.TVEXInfo = None then Opcode.PSRLW, UdqIb, SzDef32
    else Opcode.VPSRLW, HxUxIb, SzDef32
  | false, 0b100, false -> Opcode.PSRAW, NqIb, SzDef32
  | false, 0b100, true  ->
    if t.TVEXInfo = None then Opcode.PSRAW, UdqIb, SzDef32
    else Opcode.VPSRAW, HxUxIb, SzDef32
  | false, 0b110, false -> Opcode.PSLLW, NqIb, SzDef32
  | false, 0b110, true  ->
    if t.TVEXInfo = None then Opcode.PSLLW, UdqIb, SzDef32
    else Opcode.VPSLLW, HxUxIb, SzDef32
  | _ -> raise ParsingFailureException

let getOpAndOprKindByOpGrp13 t b regBits =
  match modIsMemory b, regBits, hasOprSz (selectPrefix t) with
  | false, 0b010, false -> Opcode.PSRLD, NqIb, SzDef32
  | false, 0b010, true  ->
    if t.TVEXInfo = None then Opcode.PSRLD, UdqIb, SzDef32
    else Opcode.VPSRLD, HxUxIb, SzDef32
  | false, 0b100, false -> Opcode.PSRAD, NqIb, SzDef32
  | false, 0b100, true  ->
    if t.TVEXInfo = None then Opcode.PSRAD, UdqIb, SzDef32
    else Opcode.VPSRAD, HxUxIb, SzDef32
  | false, 0b110, false -> Opcode.PSLLD, NqIb, SzDef32
  | false, 0b110, true  ->
    if t.TVEXInfo = None then Opcode.PSLLD, UdqIb, SzDef32
    else Opcode.VPSLLD, HxUxIb, SzDef32
  | _ -> raise ParsingFailureException

let getOpAndOprKindByOpGrp14 t b regBits =
  match modIsMemory b, regBits, hasOprSz (selectPrefix t) with
  | false, 0b010, false -> Opcode.PSRLQ, NqIb, SzDef32
  | false, 0b010, true  ->
    if t.TVEXInfo = None then Opcode.PSRLQ, UdqIb, SzDef32
    else Opcode.VPSRLQ, HxUxIb, SzDef32
  | false, 0b011, true  ->
    if t.TVEXInfo = None then Opcode.PSRLDQ, UdqIb, SzDef32
    else Opcode.VPSRLDQ, HxUxIb, SzDef32
  | false, 0b110, false -> Opcode.PSLLQ, NqIb, SzDef32
  | false, 0b110, true  ->
    if t.TVEXInfo = None then Opcode.PSLLQ, UdqIb, SzDef32
    else Opcode.VPSLLQ, HxUxIb, SzDef32
  | false, 0b111, true  ->
    if t.TVEXInfo = None then Opcode.PSLLDQ, UdqIb, SzDef32
    else Opcode.VPSLLDQ, HxUxIb, SzDef32
  | _ -> raise ParsingFailureException

let parseOpAndOprKindByOpGrp15 t pos b regBits =
  match modIsMemory b, regBits, hasREPZ t.TPrefixes with
  | true,  0b000, false ->
    let opCode = if hasREXW t.TREXPrefix then Opcode.FXSAVE64 else Opcode.FXSAVE
    (opCode, Ev, SzDef32), pos
  | true,  0b001, false ->
    let opCode =
      if hasREXW t.TREXPrefix then Opcode.FXRSTOR64 else Opcode.FXRSTOR
    (opCode, Ev, SzDef32), pos
  | true,  0b010, false -> (Opcode.LDMXCSR, Ev, SzDef32), pos
  | true,  0b011, false -> (Opcode.STMXCSR, Ev, SzDef32), pos
  | true,  0b100, false -> (Opcode.XSAVE, Ev, SzDef32), pos
  | true,  0b101, false -> (Opcode.XRSTOR, Ev, SzDef32), pos
  | true,  0b110, false -> (Opcode.XSAVEOPT, Ev, SzDef32), pos
  | true,  0b111, false -> (Opcode.CLFLUSH, Ev, SzDef32), pos
  | false, 0b101, false -> (Opcode.LFENCE, 0L, SzDef32), pos + 1
  | false, 0b110, false -> (Opcode.MFENCE, 0L, SzDef32), pos + 1
  | false, 0b111, false -> (Opcode.SFENCE, 0L, SzDef32), pos + 1
  | false, 0b000, true  -> (Opcode.RDFSBASE, Ry, SzDef32), pos
  | false, 0b001, true  -> (Opcode.RDGSBASE, Ry, SzDef32), pos
  | false, 0b010, true  -> (Opcode.WRFSBASE, Ry, SzDef32), pos
  | false, 0b011, true  -> (Opcode.WRGSBASE, Ry, SzDef32), pos
  | _ -> raise ParsingFailureException

let parseOpAndOprKindByGrp t reader pos b oprDescs oprGrp =
  let r = getReg b
  match oprGrp with
  | OpGroup.G1 -> (grp1Op.[r], oprDescs, SzDef32), pos
  | OpGroup.G1Inv64 -> ensure32 t; (grp1Op.[r], oprDescs, SzInv64), pos
  | OpGroup.G1A -> (grp1aOp.[r], oprDescs, SzDef64), pos
  | OpGroup.G2 when r = 0b110 -> raise ParsingFailureException
  | OpGroup.G2 -> (grp2Op.[r], oprDescs, SzDef32), pos
  | OpGroup.G3A -> getOpAndOprKindByOpGrp3 _SIb r oprDescs, pos
  | OpGroup.G3B -> getOpAndOprKindByOpGrp3 _SIz r oprDescs, pos
  | OpGroup.G4 -> (grp4Op.[r], Eb, SzDef32), pos
  | OpGroup.G5 -> (grp5Op.[r], grp5Desc.[r], grp5SCnd.[r]), pos
  | OpGroup.G6 -> getOpAndOprKindByOpGrp6 b r, pos
  | OpGroup.G7 -> parseOpAndOprKindByOpGrp7 t pos b r
  | OpGroup.G8 -> (grp8Op.[r], oprDescs, SzDef32), pos
  | OpGroup.G9 -> getOpAndPorKindByOpGrp9 t b r, pos
  | OpGroup.G11A ->
    getOpAndOprKindByOpGrp11 Opcode.XABORT Ib b r oprDescs reader pos
  | OpGroup.G11B ->
    getOpAndOprKindByOpGrp11 Opcode.XBEGIN Jz b r oprDescs reader pos
  | OpGroup.G12 -> getOpAndOprKindByOpGrp12 t b r, pos
  | OpGroup.G13 -> getOpAndOprKindByOpGrp13 t b r, pos
  | OpGroup.G14 -> getOpAndOprKindByOpGrp14 t b r, pos
  | OpGroup.G15 -> parseOpAndOprKindByOpGrp15 t pos b r
  | OpGroup.G16 -> (grp16Op.[r], oprDescs, SzDef32), pos
  | OpGroup.G10 | OpGroup.G17 | _ ->
    raise ParsingFailureException (* Not implemented yet *)

let parseOpGrpInfo t (reader: BinReader) pos grp oprDescs =
  parseOpAndOprKindByGrp t reader pos (reader.PeekByte pos) oprDescs grp

let parseGrpOpcode t reader pos grp oprDescs =
  let (op, oprDescs, szCond), pos = parseOpGrpInfo t reader pos grp oprDescs
  parseOp t op szCond oprDescs, pos

let private rexb =
  RGrpAttr.ARegInOpREX
  ||| RGrpAttr.ABaseRM
  ||| RGrpAttr.AMod11
  ||| RGrpAttr.ASIBBase

let private rexxb =
  RGrpAttr.ARegInOpREX
  ||| RGrpAttr.ABaseRM
  ||| RGrpAttr.AMod11
  ||| RGrpAttr.ASIBIdx
  ||| RGrpAttr.ASIBBase

let private rexrb =
  RGrpAttr.ARegInOpREX
  ||| RGrpAttr.ABaseRM
  ||| RGrpAttr.AMod11
  ||| RGrpAttr.ARegBits
  ||| RGrpAttr.ASIBBase

let private rexrx = RGrpAttr.ARegBits ||| RGrpAttr.ASIBIdx

let private rexrxb =
  RGrpAttr.ARegInOpREX
  ||| RGrpAttr.ABaseRM
  ||| RGrpAttr.AMod11
  ||| RGrpAttr.ARegBits
  ||| RGrpAttr.ASIBIdx
  ||| RGrpAttr.ASIBBase

let inline private selectRGrp attr g1 g2 rex =
  match rex with
  | REXPrefix.REX -> g2
  | REXPrefix.REXB | REXPrefix.REXWB ->
    if (rexb &&& attr) <> RGrpAttr.ANone then g1 else g2
  | REXPrefix.REXX | REXPrefix.REXWX ->
    if RGrpAttr.ASIBIdx = attr then g1 else g2
  | REXPrefix.REXXB | REXPrefix.REXWXB ->
    if (rexxb &&& attr) <> RGrpAttr.ANone then g1 else g2
  | REXPrefix.REXR | REXPrefix.REXWR ->
    if RGrpAttr.ARegBits = attr then g1 else g2
  | REXPrefix.REXRB | REXPrefix.REXWRB ->
    if (rexrb &&& attr) <> RGrpAttr.ANone then g1 else g2
  | REXPrefix.REXRX | REXPrefix.REXWRX ->
    if (rexrx &&& attr) <> RGrpAttr.ANone then g1 else g2
  | REXPrefix.REXRXB | REXPrefix.REXWRXB ->
    if (rexrxb &&& attr) <> RGrpAttr.ANone then g1 else g2
  | REXPrefix.REXW -> g2
  | _ -> raise ParsingFailureException

let inline private pickReg sz (grp: Register []) =
  match sz with
  | 512<rt> -> grp.[6]
  | 256<rt> -> grp.[5]
  | 128<rt> -> grp.[4]
  | 64<rt> -> grp.[3]
  | 32<rt> -> grp.[2]
  | 16<rt> -> grp.[1]
  | 8<rt> -> grp.[0]
  | _ -> raise ParsingFailureException

let private tblGrpNOREX =
  [| GrpEAX; GrpECX; GrpEDX; GrpEBX; GrpAH; GrpCH; GrpDH; GrpBH |]

let private tblGrp1 =
  [| GrpR8; GrpR9; GrpR10; GrpR11; GrpR12; GrpR13; GrpR14; GrpR15 |]

let private tblGrp2 =
  [| GrpEAX; GrpECX; GrpEDX; GrpEBX; GrpESP; GrpEBP; GrpESI; GrpEDI |]

/// Find an appropriate register symbol from the given RegType, RGrpAttribute,
/// REXPrefix, and RegGrp (int).
let findReg sz oprAttr rex (grp: int) =
  if rex = REXPrefix.NOREX then pickReg sz tblGrpNOREX.[grp]
  else pickReg sz (selectRGrp oprAttr tblGrp1.[grp] tblGrp2.[grp] rex)

let private selectOpInfoByMem (reader: BinReader) pos opNorM opNorR opVEXM
                              opVEXR dsNorM dsNorR dsVEXM dsVEXR =
  if reader.PeekByte pos |> modIsMemory then opNorM, opVEXM, dsNorM, dsVEXM
  else opNorR, opVEXR, dsNorR, dsVEXR

let inline private selectOpInfoByRex t opNorB64 opNorB32 opVEXB64 opVEXB32
                                     dsNorB64 dsNorB32 dsVEXB64 dsVEXB32 =
  if hasREXW (selectREX t.TVEXInfo t.TREXPrefix) then
    opNorB64, opVEXB64, dsNorB64, dsVEXB64
  else opNorB32, opVEXB32, dsNorB32, dsVEXB32

let inline private selectOpInfoByRexEVEX t opB64 opB32 dsB64 dsB32 =
  if hasREXW (selectREX t.TVEXInfo t.TREXPrefix) then opB64, dsB64
  else opB32, dsB32

let private getOpCode0F0D (reader: BinReader) pos =
  let b = reader.PeekByte pos
  match modIsMemory b, getReg b with
  | true, 0b001 -> Opcode.PREFETCHW
  | true, 0b010 -> Opcode.PREFETCHWT1
  | _ -> raise ParsingFailureException

let private ignOpSz t =
  { t with
      TPrefixes = t.TPrefixes &&& LanguagePrimitives.EnumOfValue 0xFDFF }

let inline private parseEVEXByRex t pos opNor opVEX opE64 opE32
                                  dsNor dsVEX dsE64 dsE32 =
  let opEVEX, dsEVEX = selectOpInfoByRexEVEX t opE64 opE32 dsE64 dsE32
  parseEVEX t SzDef32 opNor opVEX opEVEX dsNor dsVEX dsEVEX, pos

let inline private pVEXByMem t reader pos opNorMem opNorReg opVEXMem
                             opVEXReg dsNorMem dsNorReg dsVEXMem dsVEXReg =
  let opNor, opVEX, dsNor, dsVEX =
    selectOpInfoByMem reader pos opNorMem opNorReg opVEXMem opVEXReg
                                 dsNorMem dsNorReg dsVEXMem dsVEXReg
  parseVEX t SzDef32 opNor opVEX dsNor dsVEX, pos

let inline private parseVEXByRex t pos opNorB64 opNorB32 opVEXB64 opVEXB32
                                 dsNorB64 dsNorB32 dsVEXB64 dsVEXB32 =
  let opNor, opVEX, dsNor, dsVEX =
    selectOpInfoByRex t opNorB64 opNorB32 opVEXB64 opVEXB32
                            dsNorB64 dsNorB32 dsVEXB64 dsVEXB32
  parseVEX t SzDef32 opNor opVEX dsNor dsVEX, pos

/// When the first two bytes are 0F38.
/// Table A-4 of Volume 2 (Three-byte Opcode Map : First Two Bytes are 0F 38H)
let private parseThreeByteOp1 t (reader: BinReader) pos =
  match reader.PeekByte pos with
  | 0x00uy -> parseVEX t SzDef32 opNor0F3800 opVex0F3800
                                 dsNor0F3800 dsVex0F3800, pos + 1
  | 0x01uy -> parseVEX t SzDef32 opNor0F3801 opVex0F3801
                                 dsNor0F3801 dsVex0F3801, pos + 1
  | 0x02uy -> parseVEX t SzDef32 opNor0F3802 opVex0F3802
                                 dsNor0F3802 dsVex0F3802, pos + 1
  | 0x03uy -> parseVEX t SzDef32 opNor0F3803 opVex0F3803
                                 dsNor0F3803 dsVex0F3803, pos + 1
  | 0x05uy -> parseVEX t SzDef32 opNor0F3805 opVex0F3805
                                 dsNor0F3805 dsVex0F3805, pos + 1
  | 0x06uy -> parseVEX t SzDef32 opNor0F3806 opVex0F3806
                                 dsNor0F3806 dsVex0F3806, pos + 1
  | 0x07uy -> parseVEX t SzDef32 opNor0F3807 opVex0F3807
                                 dsNor0F3807 dsVex0F3807, pos + 1
  | 0x08uy -> parseVEX t SzDef32 opNor0F3808 opVex0F3808
                                 dsNor0F3808 dsVex0F3808, pos + 1
  | 0x09uy -> parseVEX t SzDef32 opNor0F3809 opVex0F3809
                                 dsNor0F3809 dsVex0F3809, pos + 1
  | 0x0auy -> parseVEX t SzDef32 opNor0F380A opVex0F380A
                                 dsNor0F380A dsVex0F380A, pos + 1
  | 0x0buy -> parseVEX t SzDef32 opNor0F380B opVex0F380B
                                 dsNor0F380B dsVex0F380B, pos + 1
  | 0x17uy -> parseVEX t SzDef32 opNor0F3817 opVex0F3817
                                 dsNor0F3817 dsVex0F3817, pos + 1
  | 0x18uy -> parseEVEXByRex t (pos + 1) opNor0F3818 opVex0F3818 opEmpty
                                         opEVex0F3818 dsNor0F3818
                                         dsVex0F3818 dsEmpty dsEVex0F3818
  | 0x1cuy -> parseVEX t SzDef32 opNor0F381C opVex0F381C
                                 dsNor0F381C dsVex0F381C, pos + 1
  | 0x1duy -> parseVEX t SzDef32 opNor0F381D opVex0F381D
                                 dsNor0F381D dsVex0F381D, pos + 1
  | 0x1euy -> parseVEX t SzDef32 opNor0F381E opVex0F381E
                                 dsNor0F381E dsVex0F381E, pos + 1
  | 0x20uy -> parseVEX t SzDef32 opNor0F3820 opVex0F3820
                                 dsNor0F3820 dsVex0F3820, pos + 1
  | 0x21uy -> parseVEX t SzDef32 opNor0F3821 opVex0F3821
                                 dsNor0F3821 dsVex0F3821, pos + 1
  | 0x22uy -> parseVEX t SzDef32 opNor0F3822 opVex0F3822
                                 dsNor0F3822 dsVex0F3822, pos + 1
  | 0x23uy -> parseVEX t SzDef32 opNor0F3823 opVex0F3823
                                 dsNor0F3823 dsVex0F3823, pos + 1
  | 0x24uy -> parseVEX t SzDef32 opNor0F3824 opVex0F3824
                                 dsNor0F3824 dsVex0F3824, pos + 1
  | 0x25uy -> parseVEX t SzDef32 opNor0F3825 opVex0F3825
                                 dsNor0F3825 dsVex0F3825, pos + 1
  | 0x28uy -> parseVEX t SzDef32 opNor0F3828 opVex0F3828
                                 dsNor0F3828 dsVex0F3828, pos + 1
  | 0x29uy -> parseVEX t SzDef32 opNor0F3829 opVex0F3829
                                 dsNor0F3829 dsVex0F3829, pos + 1
  | 0x2buy -> parseVEX t SzDef32 opNor0F382B opVex0F382B
                                 dsNor0F382B dsVex0F382B, pos + 1
  | 0x30uy -> parseVEX t SzDef32 opNor0F3830 opVex0F3830
                                 dsNor0F3830 dsVex0F3830, pos + 1
  | 0x31uy -> parseVEX t SzDef32 opNor0F3831 opVex0F3831
                                 dsNor0F3831 dsVex0F3831, pos + 1
  | 0x32uy -> parseVEX t SzDef32 opNor0F3832 opVex0F3832
                                 dsNor0F3832 dsVex0F3832, pos + 1
  | 0x33uy -> parseVEX t SzDef32 opNor0F3833 opVex0F3833
                                 dsNor0F3833 dsVex0F3833, pos + 1
  | 0x34uy -> parseVEX t SzDef32 opNor0F3834 opVex0F3834
                                 dsNor0F3834 dsVex0F3834, pos + 1
  | 0x35uy -> parseVEX t SzDef32 opNor0F3835 opVex0F3835
                                 dsNor0F3835 dsVex0F3835, pos + 1
  | 0x37uy -> parseVEX t SzDef32 opNor0F3837 opVex0F3837
                                 dsNor0F3837 dsVex0F3837, pos + 1
  | 0x38uy -> parseVEX t SzDef32 opNor0F3838 opVex0F3838
                                 dsNor0F3838 dsVex0F3838, pos + 1
  | 0x39uy -> parseVEX t SzDef32 opNor0F3839 opVex0F3839
                                 dsNor0F3839 dsVex0F3839, pos + 1
  | 0x3auy -> parseVEX t SzDef32 opNor0F383A opVex0F383A
                                 dsNor0F383A dsVex0F383A, pos + 1
  | 0x3buy -> parseVEX t SzDef32 opNor0F383B opVex0F383B
                                 dsNor0F383B dsVex0F383B, pos + 1
  | 0x3cuy -> parseVEX t SzDef32 opNor0F383C opVex0F383C
                                 dsNor0F383C dsVex0F383C, pos + 1
  | 0x3duy -> parseVEX t SzDef32 opNor0F383D opVex0F383D
                                 dsNor0F383D dsVex0F383D, pos + 1
  | 0x3euy -> parseVEX t SzDef32 opNor0F383E opVex0F383E
                                 dsNor0F383E dsVex0F383E, pos + 1
  | 0x3fuy -> parseVEX t SzDef32 opNor0F383F opVex0F383F
                                 dsNor0F383F dsVex0F383F, pos + 1
  | 0x40uy -> parseVEX t SzDef32 opNor0F3840 opVex0F3840
                                 dsNor0F3840 dsVex0F3840, pos + 1
  | 0x41uy -> parseVEX t SzDef32 opNor0F3841 opVex0F3841
                                 dsNor0F3841 dsVex0F3841, pos + 1
  | 0x5Auy -> parseVEX t SzDef32 opNor0F385A opVex0F385A
                                 dsNor0F385A dsVex0F385A, pos + 1
  | 0x78uy -> parseVEX t SzDef32 opNor0F3878 opVex0F3878
                                 dsNor0F3878 dsVex0F3878, pos + 1
  | 0xF0uy -> parseNonVEX t SzDef32 opNor0F38F0 dsNor0F38F0, pos + 1
  | 0xF1uy -> parseNonVEX t SzDef32 opNor0F38F1 dsNor0F38F1, pos + 1
  | _ -> raise ParsingFailureException

/// When the first two bytes are 0F3A.
/// Table A-5 of Volume 2 (Three-byte Opcode Map : First Two Bytes are 0F 3AH)
let private parseThreeByteOp2 t (reader: BinReader) pos =
  match reader.PeekByte pos with
  | 0x0Fuy -> parseVEX t SzDef32 opNor0F3A0F opVex0F3A0F
                                 dsNor0F3A0F dsVex0F3A0F, pos + 1
  | 0x20uy -> parseVEX t SzDef32 opNor0F3A20 opVex0F3A20
                                 dsNor0F3A20 dsVex0F3A20, pos + 1
  | 0x38uy -> parseVEX t SzDef32 opNor0F3A38 opVex0F3A38
                                 dsNor0F3A38 dsVex0F3A38, pos + 1
  | 0x60uy -> parseVEX t SzDef32 opNor0F3A60 opVex0F3A60
                                 dsNor0F3A60 dsVex0F3A60, pos + 1
  | 0x61uy -> parseVEX t SzDef32 opNor0F3A61 opVex0F3A61
                                 dsNor0F3A61 dsVex0F3A61, pos + 1
  | 0x62uy -> parseVEX t SzDef32 opNor0F3A62 opVex0F3A62
                                 dsNor0F3A62 dsVex0F3A62, pos + 1
  | 0x63uy -> parseVEX t SzDef32 opNor0F3A63 opVex0F3A63
                                 dsNor0F3A63 dsVex0F3A63, pos + 1
  | 0x0Buy -> parseVEX t SzDef32 opNor0F3A0B opVex0F3A0B
                                 dsNor0F3A0B dsVex0F3A0B, pos + 1
  | _ -> raise ParsingFailureException

let private pTwoByteOp t reader pos byte =
  match byte with
  | 0x02uy -> parseOp t Opcode.LAR SzDef32 GvEw, pos
  | 0x03uy -> parseOp t Opcode.LSL SzDef32 GvEw, pos
  | 0x05uy -> ensure64 t; parseOp t Opcode.SYSCALL SzOnly64 0L, pos
  | 0x06uy -> parseOp t Opcode.CLTS SzDef32 0L, pos
  | 0x07uy -> ensure64 t; parseOp t Opcode.SYSRET SzOnly64 0L, pos
  | 0x08uy -> parseOp t Opcode.INVD SzDef32 0L, pos
  | 0x09uy -> parseOp t Opcode.WBINVD SzDef32 0L, pos
  | 0x0Buy -> parseOp t Opcode.UD2 SzDef32 0L, pos
  | 0x0Duy -> parseOp t (getOpCode0F0D reader pos) SzDef32 Ev, pos
  | 0x10uy -> pVEXByMem t reader pos opNor0F10 opNor0F10
                                     opVex0F10Mem opVex0F10Reg
                                     dsNor0F10 dsNor0F10
                                     dsVex0F10Mem dsVex0F10Reg
  | 0x11uy -> pVEXByMem t reader pos opNor0F11 opNor0F11
                                     opVex0F11Mem opVex0F11Reg
                                     dsNor0F11 dsNor0F11
                                     dsVex0F11Mem dsVex0F11Reg
  | 0x12uy -> pVEXByMem t reader pos opNor0F12Mem opNor0F12Reg
                                     opVex0F12Mem opVex0F12Reg
                                     dsNor0F12Mem dsNor0F12Reg
                                     dsVex0F12Mem dsVex0F12Reg
  | 0x13uy -> parseVEX t SzDef32 opNor0F13 opVex0F13 dsNor0F13 dsVex0F13, pos
  | 0x14uy -> parseVEX t SzDef32 opNor0F14 opVex0F14 dsNor0F14 dsVex0F14, pos
  | 0x15uy -> parseVEX t SzDef32 opNor0F15 opVex0F15 dsNor0F15 dsVex0F15, pos
  | 0x16uy -> pVEXByMem t reader pos opNor0F16Mem opNor0F16Reg
                                     opVex0F16Mem opVex0F16Reg
                                     dsNor0F16Mem dsNor0F16Reg
                                     dsVex0F16Mem dsVex0F16Reg
  | 0x17uy -> parseVEX t SzDef32 opNor0F17 opVex0F17 dsNor0F17 dsVex0F17, pos
  | 0x1Auy -> parseBND t SzDef32 opNor0F1A dsNor0F1A, pos
  | 0x1Buy -> parseBND t SzDef32 opNor0F1B dsNor0F1B, pos
  | 0x1Fuy -> parseOp t Opcode.NOP SzDef32 E0v, pos
  | 0x20uy -> parseOp t Opcode.MOV Sz64 RdCd, pos
  | 0x21uy -> parseOp t Opcode.MOV SzDef32 RdDd, pos
  | 0x22uy -> parseOp t Opcode.MOV SzDef32 CdRd, pos
  | 0x23uy -> parseOp t Opcode.MOV SzDef32 DdRd, pos
  | 0x28uy -> parseVEX t SzDef32 opNor0F28 opVex0F28 dsNor0F28 dsVex0F28, pos
  | 0x29uy -> parseVEX t SzDef32 opNor0F29 opVex0F29 dsNor0F29 dsVex0F29, pos
  | 0x2Auy -> parseVEX t SzDef32 opNor0F2A opVex0F2A dsNor0F2A dsVex0F2A, pos
  | 0x2Buy -> parseVEX t SzDef32 opNor0F2B opVex0F2B dsNor0F2B dsVex0F2B, pos
  | 0x2Cuy -> parseVEX t SzDef32 opNor0F2C opVex0F2C dsNor0F2C dsVex0F2C, pos
  | 0x2Duy -> parseVEX t SzDef32 opNor0F2D opVex0F2D dsNor0F2D dsVex0F2D, pos
  | 0x2Euy -> parseVEX t SzDef32 opNor0F2E opVex0F2E dsNor0F2E dsVex0F2E, pos
  | 0x2Fuy -> parseVEX t SzDef32 opNor0F2F opVex0F2F dsNor0F2F dsVex0F2F, pos
  | 0x30uy -> parseOp t Opcode.WRMSR SzDef32 0L, pos
  | 0x31uy -> parseOp t Opcode.RDTSC SzDef32 0L, pos
  | 0x32uy -> parseOp t Opcode.RDMSR SzDef32 0L, pos
  | 0x33uy -> parseOp t Opcode.RDPMC SzDef32 0L, pos
  | 0x34uy -> parseOp t Opcode.SYSENTER SzDef32 0L, pos
  | 0x35uy -> parseOp t Opcode.SYSEXIT SzDef32 0L, pos
  | 0x37uy -> parseOp t Opcode.GETSEC SzDef32 0L, pos
  | 0x40uy -> parseOp t Opcode.CMOVO SzDef32 GvEv, pos
  | 0x41uy -> parseOp t Opcode.CMOVNO SzDef32 GvEv, pos
  | 0x42uy -> parseOp t Opcode.CMOVB SzDef32 GvEv, pos
  | 0x43uy -> parseOp t Opcode.CMOVAE SzDef32 GvEv, pos
  | 0x44uy -> parseOp t Opcode.CMOVZ SzDef32 GvEv, pos
  | 0x45uy -> parseOp t Opcode.CMOVNZ SzDef32 GvEv, pos
  | 0x46uy -> parseOp t Opcode.CMOVBE SzDef32 GvEv, pos
  | 0x47uy -> parseOp t Opcode.CMOVA SzDef32 GvEv, pos
  | 0x48uy -> parseOp t Opcode.CMOVS SzDef32 GvEv, pos
  | 0x49uy -> parseOp t Opcode.CMOVNS SzDef32 GvEv, pos
  | 0x4Auy -> parseOp t Opcode.CMOVP SzDef32 GvEv, pos
  | 0x4Buy -> parseOp t Opcode.CMOVNP SzDef32 GvEv, pos
  | 0x4Cuy -> parseOp t Opcode.CMOVL SzDef32 GvEv, pos
  | 0x4Duy -> parseOp t Opcode.CMOVGE SzDef32 GvEv, pos
  | 0x4Euy -> parseOp t Opcode.CMOVLE SzDef32 GvEv, pos
  | 0x4Fuy -> parseOp t Opcode.CMOVG SzDef32 GvEv, pos
  | 0x50uy -> parseVEX t SzDef32 opNor0F50 opVex0F50 dsNor0F50 dsVex0F50, pos
  | 0x54uy -> parseVEX t SzDef32 opNor0F54 opVex0F54 dsNor0F54 dsVex0F54, pos
  | 0x55uy -> parseVEX t SzDef32 opNor0F55 opVex0F55 dsNor0F55 dsVex0F55, pos
  | 0x56uy -> parseVEX t SzDef32 opNor0F56 opVex0F56 dsNor0F56 dsVex0F56, pos
  | 0x57uy -> parseVEX t SzDef32 opNor0F57 opVex0F57 dsNor0F57 dsVex0F57, pos
  | 0x58uy -> parseVEX t SzDef32 opNor0F58 opVex0F58 dsNor0F58 dsVex0F58, pos
  | 0x59uy -> parseVEX t SzDef32 opNor0F59 opVex0F59 dsNor0F59 dsVex0F59, pos
  | 0x5Auy -> parseVEX t SzDef32 opNor0F5A opVex0F5A dsNor0F5A dsVex0F5A, pos
  | 0x5Buy -> parseVEX t SzDef32 opNor0F5B opVex0F5B dsNor0F5B dsVex0F5B, pos
  | 0x5Cuy -> parseVEX t SzDef32 opNor0F5C opVex0F5C dsNor0F5C dsVex0F5C, pos
  | 0x5Duy -> parseVEX t SzDef32 opNor0F5D opVex0F5D dsNor0F5D dsVex0F5D, pos
  | 0x5Euy -> parseVEX t SzDef32 opNor0F5E opVex0F5E dsNor0F5E dsVex0F5E, pos
  | 0x5Fuy -> parseVEX t SzDef32 opNor0F5F opVex0F5F dsNor0F5F dsVex0F5F, pos
  | 0x60uy -> parseVEX t SzDef32 opNor0F60 opVex0F60 dsNor0F60 dsVex0F60, pos
  | 0x61uy -> parseVEX t SzDef32 opNor0F61 opVex0F61 dsNor0F61 dsVex0F61, pos
  | 0x62uy -> parseVEX t SzDef32 opNor0F62 opVex0F62 dsNor0F62 dsVex0F62, pos
  | 0x63uy -> parseVEX t SzDef32 opNor0F63 opVex0F63 dsNor0F63 dsVex0F63, pos
  | 0x64uy -> parseVEX t SzDef32 opNor0F64 opVex0F64 dsNor0F64 dsVex0F64, pos
  | 0x65uy -> parseVEX t SzDef32 opNor0F65 opVex0F65 dsNor0F65 dsVex0F65, pos
  | 0x66uy -> parseVEX t SzDef32 opNor0F66 opVex0F66 dsNor0F66 dsVex0F66, pos
  | 0x67uy -> parseVEX t SzDef32 opNor0F67 opVex0F67 dsNor0F67 dsVex0F67, pos
  | 0x68uy -> parseVEX t SzDef32 opNor0F68 opVex0F68 dsNor0F68 dsVex0F68, pos
  | 0x69uy -> parseVEX t SzDef32 opNor0F69 opVex0F69 dsNor0F69 dsVex0F69, pos
  | 0x6Auy -> parseVEX t SzDef32 opNor0F6A opVex0F6A dsNor0F6A dsVex0F6A, pos
  | 0x6Buy -> parseVEX t SzDef32 opNor0F6B opVex0F6B dsNor0F6B dsVex0F6B, pos
  | 0x6Cuy -> parseVEX t SzDef32 opNor0F6C opVex0F6C dsNor0F6C dsVex0F6C, pos
  | 0x6Duy -> parseVEX t SzDef32 opNor0F6D opVex0F6D dsNor0F6D dsVex0F6D, pos
  | 0x6Euy -> parseVEXByRex t pos opNor0F6EB64 opNor0F6EB32
                                  opVex0F6EB64 opVex0F6EB32
                                  dsNor0F6EB64 dsNor0F6EB32
                                  dsVex0F6EB64 dsVex0F6EB32
  | 0x6Fuy -> parseEVEXByRex t pos opNor0F6F opVex0F6F
                                   opEVex0F6FB64 opEVex0F6FB32
                                   dsNor0F6F dsVex0F6F
                                   dsEVex0F6FB64 dsEVex0F6FB32
  | 0x70uy -> parseVEX t SzDef32 opNor0F70 opVex0F70 dsNor0F70 dsVex0F70, pos
  | 0x74uy -> parseVEX t SzDef32 opNor0F74 opVex0F74 dsNor0F74 dsVex0F74, pos
  | 0x75uy -> parseVEX t SzDef32 opNor0F75 opVex0F75 dsNor0F75 dsVex0F75, pos
  | 0x76uy -> parseVEX t SzDef32 opNor0F76 opVex0F76 dsNor0F76 dsVex0F76, pos
  | 0x77uy -> parseVEX t SzDef32 opNor0F77 opVex0F77 dsNor0F77 dsVex0F77, pos
  | 0x7Euy -> parseVEXByRex t pos opNor0F7EB64 opNor0F7EB32
                                  opVex0F7EB64 opVex0F7EB32
                                  dsNor0F7EB64 dsNor0F7EB32
                                  dsVex0F7EB64 dsVex0F7EB32
  | 0x7Fuy -> parseEVEXByRex t pos opNor0F7F opVex0F7F
                                   opEVex0F7FB64 opEVex0F7FB32
                                   dsNor0F7F dsVex0F7F
                                   dsEVex0F7FB64 dsEVex0F7FB32
  | 0x80uy -> parseOp t Opcode.JO Sz64 Jz, pos
  | 0x81uy -> parseOp t Opcode.JNO Sz64 Jz, pos
  | 0x82uy -> parseOp t Opcode.JB Sz64 Jz, pos
  | 0x83uy -> parseOp t Opcode.JNB Sz64 Jz, pos
  | 0x84uy -> parseOp t Opcode.JZ Sz64 Jz, pos
  | 0x85uy -> parseOp t Opcode.JNZ Sz64 Jz, pos
  | 0x86uy -> parseOp t Opcode.JBE Sz64 Jz, pos
  | 0x87uy -> parseOp t Opcode.JA Sz64 Jz, pos
  | 0x88uy -> parseOp t Opcode.JS Sz64 Jz, pos
  | 0x89uy -> parseOp t Opcode.JNS Sz64 Jz, pos
  | 0x8Auy -> parseOp t Opcode.JP Sz64 Jz, pos
  | 0x8Buy -> parseOp t Opcode.JNP Sz64 Jz, pos
  | 0x8Cuy -> parseOp t Opcode.JL Sz64 Jz, pos
  | 0x8Duy -> parseOp t Opcode.JNL Sz64 Jz, pos
  | 0x8Euy -> parseOp t Opcode.JLE Sz64 Jz, pos
  | 0x8Fuy -> parseOp t Opcode.JG Sz64 Jz, pos
  | 0x90uy -> parseOp t Opcode.SETO SzDef32 Eb, pos
  | 0x91uy -> parseOp t Opcode.SETNO SzDef32 Eb, pos
  | 0x92uy -> parseOp t Opcode.SETB SzDef32 Eb, pos
  | 0x93uy -> parseOp t Opcode.SETNB SzDef32 Eb, pos
  | 0x94uy -> parseOp t Opcode.SETZ SzDef32 Eb, pos
  | 0x95uy -> parseOp t Opcode.SETNZ SzDef32 Eb, pos
  | 0x96uy -> parseOp t Opcode.SETBE SzDef32 Eb, pos
  | 0x97uy -> parseOp t Opcode.SETA SzDef32 Eb, pos
  | 0x98uy -> parseOp t Opcode.SETS SzDef32 Eb, pos
  | 0x99uy -> parseOp t Opcode.SETNS SzDef32 Eb, pos
  | 0x9Auy -> parseOp t Opcode.SETP SzDef32 Eb, pos
  | 0x9Buy -> parseOp t Opcode.SETNP SzDef32 Eb, pos
  | 0x9Cuy -> parseOp t Opcode.SETL SzDef32 Eb, pos
  | 0x9Duy -> parseOp t Opcode.SETNL SzDef32 Eb, pos
  | 0x9Euy -> parseOp t Opcode.SETLE SzDef32 Eb, pos
  | 0x9Fuy -> parseOp t Opcode.SETG SzDef32 Eb, pos
  | 0xA0uy -> parseOp t Opcode.PUSH SzDef64 ORFS, pos
  | 0xA1uy -> parseOp t Opcode.POP SzDef64 ORFS, pos
  | 0xA2uy -> parseOp t Opcode.CPUID SzDef32 0L, pos
  | 0xA3uy -> parseOp t Opcode.BT SzDef32 EvGv, pos
  | 0xA4uy -> parseOp t Opcode.SHLD SzDef32 EvGvIb, pos
  | 0xA5uy -> parseOp t Opcode.SHLD SzDef32 EvGvCL, pos
  | 0xA8uy -> parseOp t Opcode.PUSH SzDef64 ORGS, pos
  | 0xA9uy -> parseOp t Opcode.POP SzDef64 ORGS, pos
  | 0xAAuy -> parseOp t Opcode.RSM SzDef32 0L, pos
  | 0xABuy -> parseOp t Opcode.BTS SzDef32 EvGv, pos
  | 0xACuy -> parseOp t Opcode.SHRD SzDef32 EvGvIb, pos
  | 0xADuy -> parseOp t Opcode.SHRD SzDef32 EvGvCL, pos
  | 0xAFuy -> parseOp t Opcode.IMUL SzDef32 GvEv, pos
  | 0xB0uy -> parseOp t Opcode.CMPXCHG SzDef32 EbGb, pos
  | 0xB1uy -> parseOp t Opcode.CMPXCHG SzDef32 EvGv, pos
  | 0xB2uy -> parseOp t Opcode.LSS SzDef32 GvMp, pos
  | 0xB3uy -> parseOp t Opcode.BTR SzDef32 EvGv, pos
  | 0xB4uy -> parseOp t Opcode.LFS SzDef32 GvMp, pos
  | 0xB5uy -> parseOp t Opcode.LGS SzDef32 GvMp, pos
  | 0xB6uy -> parseOp t Opcode.MOVZX SzDef32 GvEb, pos
  | 0xB7uy -> parseOp t Opcode.MOVZX SzDef32 GvEw, pos
  | 0xB8uy when not <| hasREPZ t.TPrefixes -> raise ParsingFailureException
  | 0xB8uy -> parseOp t Opcode.POPCNT SzDef32 GvEv, pos
  | 0xBBuy when hasREPZ t.TPrefixes -> raise ParsingFailureException
  | 0xBBuy -> parseOp t Opcode.BTC SzDef32 EvGv, pos
  | 0xBCuy when hasREPZ t.TPrefixes -> parseOp t Opcode.TZCNT SzDef32 GvEv, pos
  | 0xBCuy -> parseOp t Opcode.BSF SzDef32 GvEv, pos
  | 0xBDuy when hasREPZ t.TPrefixes -> parseOp t Opcode.LZCNT SzDef32 GvEv, pos
  | 0xBDuy -> parseOp t Opcode.BSR SzDef32 GvEv, pos
  | 0xBEuy -> parseOp t Opcode.MOVSX SzDef32 GvEb, pos
  | 0xBFuy -> parseOp t Opcode.MOVSX SzDef32 GvEw, pos
  | 0xC0uy -> parseOp t Opcode.XADD SzDef32 EbGb, pos
  | 0xC1uy -> parseOp t Opcode.XADD SzDef32 EvGv, pos
  | 0xC3uy -> parseOp t Opcode.MOVNTI SzDef32 MyGy, pos
  | 0xC4uy -> parseVEX t SzDef32 opNor0FC4 opVex0FC4 dsNor0FC4 dsVex0FC4, pos
  | 0xC5uy -> parseVEX t SzDef32 opNor0FC5 opVex0FC5 dsNor0FC5 dsVex0FC5, pos
  | 0xC6uy -> parseVEX t SzDef32 opNor0FC6 opVex0FC6 dsNor0FC6 dsVex0FC6, pos
  | 0xC8uy -> parseOp (ignOpSz t) Opcode.BSWAP SzDef32 GzG0T, pos
  | 0xC9uy -> parseOp (ignOpSz t) Opcode.BSWAP SzDef32 GzG1T, pos
  | 0xCAuy -> parseOp (ignOpSz t) Opcode.BSWAP SzDef32 GzG2T, pos
  | 0xCBuy -> parseOp (ignOpSz t) Opcode.BSWAP SzDef32 GzG3T, pos
  | 0xCCuy -> parseOp (ignOpSz t) Opcode.BSWAP SzDef32 GzG4T, pos
  | 0xCDuy -> parseOp (ignOpSz t) Opcode.BSWAP SzDef32 GzG5T, pos
  | 0xCEuy -> parseOp (ignOpSz t) Opcode.BSWAP SzDef32 GzG6T, pos
  | 0xCFuy -> parseOp (ignOpSz t) Opcode.BSWAP SzDef32 GzG7T, pos
  | 0xD1uy -> parseVEX t SzDef32 opNor0FD1 opVex0FD1 dsNor0FD1 dsVex0FD1, pos
  | 0xD2uy -> parseVEX t SzDef32 opNor0FD2 opVex0FD2 dsNor0FD2 dsVex0FD2, pos
  | 0xD3uy -> parseVEX t SzDef32 opNor0FD3 opVex0FD3 dsNor0FD3 dsVex0FD3, pos
  | 0xD4uy -> parseVEX t SzDef32 opNor0FD4 opVex0FD4 dsNor0FD4 dsVex0FD4, pos
  | 0xD5uy -> parseVEX t SzDef32 opNor0FD5 opVex0FD5 dsNor0FD5 dsVex0FD5, pos
  | 0xD6uy -> assertVEX128 t
              parseVEX t SzDef32 opNor0FD6 opVex0FD6 dsNor0FD6 dsVex0FD6, pos
  | 0xD7uy -> parseVEX t SzDef32 opNor0FD7 opVex0FD7 dsNor0FD7 dsVex0FD7, pos
  | 0xD8uy -> parseVEX t SzDef32 opNor0FD8 opVex0FD8 dsNor0FD8 dsVex0FD8, pos
  | 0xD9uy -> parseVEX t SzDef32 opNor0FD9 opVex0FD9 dsNor0FD9 dsVex0FD9, pos
  | 0xDAuy -> parseVEX t SzDef32 opNor0FDA opVex0FDA dsNor0FDA dsVex0FDA, pos
  | 0xDBuy -> parseVEX t SzDef32 opNor0FDB opVex0FDB dsNor0FDB dsVex0FDB, pos
  | 0xDCuy -> parseVEX t SzDef32 opNor0FDC opVex0FDC dsNor0FDC dsVex0FDC, pos
  | 0xDDuy -> parseVEX t SzDef32 opNor0FDD opVex0FDD dsNor0FDD dsVex0FDD, pos
  | 0xDEuy -> parseVEX t SzDef32 opNor0FDE opVex0FDE dsNor0FDE dsVex0FDE, pos
  | 0xDFuy -> parseVEX t SzDef32 opNor0FDF opVex0FDF dsNor0FDF dsVex0FDF, pos
  | 0xE0uy -> parseVEX t SzDef32 opNor0FE0 opVex0FE0 dsNor0FE0 dsVex0FE0, pos
  | 0xE1uy -> parseVEX t SzDef32 opNor0FE1 opVex0FE1 dsNor0FE1 dsVex0FE1, pos
  | 0xE2uy -> parseVEX t SzDef32 opNor0FE2 opVex0FE2 dsNor0FE2 dsVex0FE2, pos
  | 0xE3uy -> parseVEX t SzDef32 opNor0FE3 opVex0FE3 dsNor0FE3 dsVex0FE3, pos
  | 0xE4uy -> parseVEX t SzDef32 opNor0FE4 opVex0FE4 dsNor0FE4 dsVex0FE4, pos
  | 0xE5uy -> parseVEX t SzDef32 opNor0FE5 opVex0FE5 dsNor0FE5 dsVex0FE5, pos
  | 0xE6uy -> parseVEX t SzDef32 opNor0FE6 opVex0FE6 dsNor0FE6 dsVex0FE6, pos
  | 0xE7uy -> parseEVEXByRex t pos opNor0FE7 opVex0FE7
                                   opEVex0FE7B64 opEVex0FE7B32
                                   dsNor0FE7 dsVex0FE7
                                   dsEVex0FE7B64 dsEVex0FE7B32
  | 0xE8uy -> parseVEX t SzDef32 opNor0FE8 opVex0FE8 dsNor0FE8 dsVex0FE8, pos
  | 0xE9uy -> parseVEX t SzDef32 opNor0FE9 opVex0FE9 dsNor0FE9 dsVex0FE9, pos
  | 0xEAuy -> parseVEX t SzDef32 opNor0FEA opVex0FEA dsNor0FEA dsVex0FEA, pos
  | 0xEBuy -> parseVEX t SzDef32 opNor0FEB opVex0FEB dsNor0FEB dsVex0FEB, pos
  | 0xECuy -> parseVEX t SzDef32 opNor0FEC opVex0FEC dsNor0FEC dsVex0FEC, pos
  | 0xEDuy -> parseVEX t SzDef32 opNor0FED opVex0FED dsNor0FED dsVex0FED, pos
  | 0xEEuy -> parseVEX t SzDef32 opNor0FEE opVex0FEE dsNor0FEE dsVex0FEE, pos
  | 0xEFuy -> parseVEX t SzDef32 opNor0FEF opVex0FEF dsNor0FEF dsVex0FEF, pos
  | 0xF0uy -> parseVEX t SzDef32 opNor0FF0 opVex0FF0 dsNor0FF0 dsVex0FF0, pos
  | 0xF1uy -> parseVEX t SzDef32 opNor0FF1 opVex0FF1 dsNor0FF1 dsVex0FF1, pos
  | 0xF2uy -> parseVEX t SzDef32 opNor0FF2 opVex0FF2 dsNor0FF2 dsVex0FF2, pos
  | 0xF3uy -> parseVEX t SzDef32 opNor0FF3 opVex0FF3 dsNor0FF3 dsVex0FF3, pos
  | 0xF4uy -> parseVEX t SzDef32 opNor0FF4 opVex0FF4 dsNor0FF4 dsVex0FF4, pos
  | 0xF5uy -> parseVEX t SzDef32 opNor0FF5 opVex0FF5 dsNor0FF5 dsVex0FF5, pos
  | 0xF6uy -> parseVEX t SzDef32 opNor0FF6 opVex0FF6 dsNor0FF6 dsVex0FF6, pos
  | 0xF8uy -> parseVEX t SzDef32 opNor0FF8 opVex0FF8 dsNor0FF8 dsVex0FF8, pos
  | 0xF9uy -> parseVEX t SzDef32 opNor0FF9 opVex0FF9 dsNor0FF9 dsVex0FF9, pos
  | 0xFAuy -> parseVEX t SzDef32 opNor0FFA opVex0FFA dsNor0FFA dsVex0FFA, pos
  | 0xFBuy -> parseVEX t SzDef32 opNor0FFB opVex0FFB dsNor0FFB dsVex0FFB, pos
  | 0xFCuy -> parseVEX t SzDef32 opNor0FFC opVex0FFC dsNor0FFC dsVex0FFC, pos
  | 0xFDuy -> parseVEX t SzDef32 opNor0FFD opVex0FFD dsNor0FFD dsVex0FFD, pos
  | 0xFEuy -> parseVEX t SzDef32 opNor0FFE opVex0FFE dsNor0FFE dsVex0FFE, pos
  (* Group Opcode s: Vol.2C A-19 Table A-6. Opcode Extensions for One- and
     Two-byte Opcodes by Group Number *)
  | 0x00uy -> parseGrpOpcode t reader pos OpGroup.G6 0L
  | 0x01uy -> parseGrpOpcode t reader pos OpGroup.G7 0L
  | 0xBAuy -> parseGrpOpcode t reader pos OpGroup.G8 EvIb
  | 0xC7uy -> parseGrpOpcode t reader pos OpGroup.G9 0L
  | 0x71uy -> parseGrpOpcode t reader pos OpGroup.G12 0L
  | 0x72uy -> parseGrpOpcode t reader pos OpGroup.G13 0L
  | 0x73uy -> parseGrpOpcode t reader pos OpGroup.G14 0L
  | 0xAEuy -> parseGrpOpcode t reader pos OpGroup.G15 0L
  | 0x18uy -> parseGrpOpcode t reader pos OpGroup.G16 Mv
  | 0x38uy -> parseThreeByteOp1 t reader pos
  | 0x3Auy -> parseThreeByteOp2 t reader pos
  | _ -> raise ParsingFailureException

(* Table A-3 of Volume 2 (Two-byte Opcode Map) *)
let private parseTwoByteOpcode t (reader: BinReader) pos =
  reader.PeekByte pos |> pTwoByteOp t reader (pos + 1)

let inline private getDescForRegGrp t regGrp =
  int regGrp |> findReg 8<rt> RGrpAttr.AMod11 t.TREXPrefix |> RegIb

/// The assembler may insert the 16-bit operand-size prefix with this
/// instruction. (Vol. 2A 3-531)
let private addOpSizePref t =
  if not (hasOprSz t.TPrefixes) then
    { t with TPrefixes = Prefix.PrxOPSIZE ||| t.TPrefixes }
  else t

let private pOneByteOpcode t reader pos = function
  | 0x00uy -> parseOp t Opcode.ADD SzDef32 EbGb, pos
  | 0x01uy -> parseOp t Opcode.ADD SzDef32 EvGv, pos
  | 0x02uy -> parseOp t Opcode.ADD SzDef32 GbEb, pos
  | 0x03uy -> parseOp t Opcode.ADD SzDef32 GvEv, pos
  | 0x04uy -> parseOp t Opcode.ADD SzDef32 ALIb, pos
  | 0x05uy -> parseOp t Opcode.ADD SzDef32 RGvSIz, pos
  | 0x06uy -> ensure32 t; parseOp t Opcode.PUSH SzInv64 ORES, pos
  | 0x07uy -> ensure32 t; parseOp t Opcode.POP SzInv64 ORES, pos
  | 0x08uy -> parseOp t Opcode.OR SzDef32 EbGb, pos
  | 0x09uy -> parseOp t Opcode.OR SzDef32 EvGv, pos
  | 0x0Auy -> parseOp t Opcode.OR SzDef32 GbEb, pos
  | 0x0Buy -> parseOp t Opcode.OR SzDef32 GvEv, pos
  | 0x0Cuy -> parseOp t Opcode.OR SzDef32 ALIb, pos
  | 0x0Duy -> parseOp t Opcode.OR SzDef32 RGvSIz, pos
  | 0x0Euy -> ensure32 t; parseOp t Opcode.PUSH SzInv64 ORCS, pos
  | 0x10uy -> parseOp t Opcode.ADC SzDef32 EbGb, pos
  | 0x11uy -> parseOp t Opcode.ADC SzDef32 EvGv, pos
  | 0x12uy -> parseOp t Opcode.ADC SzDef32 GbEb, pos
  | 0x13uy -> parseOp t Opcode.ADC SzDef32 GvEv, pos
  | 0x14uy -> parseOp t Opcode.ADC SzDef32 ALIb, pos
  | 0x15uy -> parseOp t Opcode.ADC SzDef32 RGvSIz, pos
  | 0x16uy -> ensure32 t; parseOp t Opcode.PUSH SzInv64 ORSS, pos
  | 0x17uy -> ensure32 t; parseOp t Opcode.POP SzInv64 ORSS, pos
  | 0x18uy -> parseOp t Opcode.SBB SzDef32 EbGb, pos
  | 0x19uy -> parseOp t Opcode.SBB SzDef32 EvGv, pos
  | 0x1Auy -> parseOp t Opcode.SBB SzDef32 GbEb, pos
  | 0x1Buy -> parseOp t Opcode.SBB SzDef32 GvEv, pos
  | 0x1Cuy -> parseOp t Opcode.SBB SzDef32 ALIb, pos
  | 0x1Duy -> parseOp t Opcode.SBB SzDef32 RGvSIz, pos
  | 0x1Euy -> ensure32 t; parseOp t Opcode.PUSH SzInv64 ORDS, pos
  | 0x1Fuy -> ensure32 t; parseOp t Opcode.POP SzInv64 ORDS, pos
  | 0x20uy -> parseOp t Opcode.AND SzDef32 EbGb, pos
  | 0x21uy -> parseOp t Opcode.AND SzDef32 EvGv, pos
  | 0x22uy -> parseOp t Opcode.AND SzDef32 GbEb, pos
  | 0x23uy -> parseOp t Opcode.AND SzDef32 GvEv, pos
  | 0x24uy -> parseOp t Opcode.AND SzDef32 ALIb, pos
  | 0x25uy -> parseOp t Opcode.AND SzDef32 RGvSIz, pos
  | 0x27uy -> ensure32 t; parseOp t Opcode.DAA SzInv64 0L, pos
  | 0x28uy -> parseOp t Opcode.SUB SzDef32 EbGb, pos
  | 0x29uy -> parseOp t Opcode.SUB SzDef32 EvGv, pos
  | 0x2Auy -> parseOp t Opcode.SUB SzDef32 GbEb, pos
  | 0x2Buy -> parseOp t Opcode.SUB SzDef32 GvEv, pos
  | 0x2Cuy -> parseOp t Opcode.SUB SzDef32 ALIb, pos
  | 0x2Duy -> parseOp t Opcode.SUB SzDef32 RGvSIz, pos
  | 0x2Fuy -> ensure32 t; parseOp t Opcode.DAS SzInv64 0L, pos
  | 0x30uy -> parseOp t Opcode.XOR SzDef32 EbGb, pos
  | 0x31uy -> parseOp t Opcode.XOR SzDef32 EvGv, pos
  | 0x32uy -> parseOp t Opcode.XOR SzDef32 GbEb, pos
  | 0x33uy -> parseOp t Opcode.XOR SzDef32 GvEv, pos
  | 0x34uy -> parseOp t Opcode.XOR SzDef32 ALIb, pos
  | 0x35uy -> parseOp t Opcode.XOR SzDef32 RGvSIz, pos
  | 0x37uy -> ensure32 t; parseOp t Opcode.AAA SzInv64 0L, pos
  | 0x38uy -> parseOp t Opcode.CMP SzDef32 EbGb, pos
  | 0x39uy -> parseOp t Opcode.CMP SzDef32 EvGv, pos
  | 0x3Auy -> parseOp t Opcode.CMP SzDef32 GbEb, pos
  | 0x3Buy -> parseOp t Opcode.CMP SzDef32 GvEv, pos
  | 0x3Cuy -> parseOp t Opcode.CMP SzDef32 ALIb, pos
  | 0x3Duy -> parseOp t Opcode.CMP SzDef32 RGvSIz, pos
  | 0x3Fuy -> ensure32 t; parseOp t Opcode.AAS SzInv64 0L, pos
  | 0x40uy -> ensure32 t; parseOp t Opcode.INC SzInv64 GzG0F, pos
  | 0x41uy -> ensure32 t; parseOp t Opcode.INC SzInv64 GzG1F, pos
  | 0x42uy -> ensure32 t; parseOp t Opcode.INC SzInv64 GzG2F, pos
  | 0x43uy -> ensure32 t; parseOp t Opcode.INC SzInv64 GzG3F, pos
  | 0x44uy -> ensure32 t; parseOp t Opcode.INC SzInv64 GzG4F, pos
  | 0x45uy -> ensure32 t; parseOp t Opcode.INC SzInv64 GzG5F, pos
  | 0x46uy -> ensure32 t; parseOp t Opcode.INC SzInv64 GzG6F, pos
  | 0x47uy -> ensure32 t; parseOp t Opcode.INC SzInv64 GzG7F, pos
  | 0x48uy -> ensure32 t; parseOp t Opcode.DEC SzInv64 GzG0F, pos
  | 0x49uy -> ensure32 t; parseOp t Opcode.DEC SzInv64 GzG1F, pos
  | 0x4Auy -> ensure32 t; parseOp t Opcode.DEC SzInv64 GzG2F, pos
  | 0x4Buy -> ensure32 t; parseOp t Opcode.DEC SzInv64 GzG3F, pos
  | 0x4Cuy -> ensure32 t; parseOp t Opcode.DEC SzInv64 GzG4F, pos
  | 0x4Duy -> ensure32 t; parseOp t Opcode.DEC SzInv64 GzG5F, pos
  | 0x4Euy -> ensure32 t; parseOp t Opcode.DEC SzInv64 GzG6F, pos
  | 0x4Fuy -> ensure32 t; parseOp t Opcode.DEC SzInv64 GzG7F, pos
  | 0x50uy -> parseOp t Opcode.PUSH SzDef64 GvG0T, pos
  | 0x51uy -> parseOp t Opcode.PUSH SzDef64 GvG1T, pos
  | 0x52uy -> parseOp t Opcode.PUSH SzDef64 GvG2T, pos
  | 0x53uy -> parseOp t Opcode.PUSH SzDef64 GvG3T, pos
  | 0x54uy -> parseOp t Opcode.PUSH SzDef64 GvG4T, pos
  | 0x55uy -> parseOp t Opcode.PUSH SzDef64 GvG5T, pos
  | 0x56uy -> parseOp t Opcode.PUSH SzDef64 GvG6T, pos
  | 0x57uy -> parseOp t Opcode.PUSH SzDef64 GvG7T, pos
  | 0x58uy -> parseOp t Opcode.POP SzDef64 GvG0T, pos
  | 0x59uy -> parseOp t Opcode.POP SzDef64 GvG1T, pos
  | 0x5Auy -> parseOp t Opcode.POP SzDef64 GvG2T, pos
  | 0x5Buy -> parseOp t Opcode.POP SzDef64 GvG3T, pos
  | 0x5Cuy -> parseOp t Opcode.POP SzDef64 GvG4T, pos
  | 0x5Duy -> parseOp t Opcode.POP SzDef64 GvG5T, pos
  | 0x5Euy -> parseOp t Opcode.POP SzDef64 GvG6T, pos
  | 0x5Fuy -> parseOp t Opcode.POP SzDef64 GvG7T, pos
  | 0x60uy ->
    ensure32 t
    if hasOprSz t.TPrefixes then parseOp t Opcode.PUSHA SzInv64 0L, pos
    else parseOp t Opcode.PUSHAD SzInv64 0L, pos
  | 0x61uy ->
    ensure32 t
    if hasOprSz t.TPrefixes then parseOp t Opcode.POPA SzInv64 0L, pos
    else parseOp t Opcode.POPAD SzInv64 0L, pos
  | 0x62uy -> ensure32 t; parseOp t Opcode.BOUND SzInv64 GvMa, pos
  | 0x63uy ->
    if is64bit t && not (hasREXW t.TREXPrefix) then
      raise ParsingFailureException
    elif is64bit t then parseOp t Opcode.MOVSXD SzOnly64 GvEd, pos
    else parseOp t Opcode.ARPL SzInv64 EwGw, pos
  | 0x68uy -> parseOp t Opcode.PUSH SzDef64 SIz, pos
  | 0x69uy -> parseOp t Opcode.IMUL SzDef32 GvEvSIz, pos
  | 0x6Auy -> parseOp t Opcode.PUSH SzDef64 SIb, pos
  | 0x6Buy -> parseOp t Opcode.IMUL SzDef32 GvEvSIb, pos
  | 0x6Cuy -> parseOp t Opcode.INSB SzDef32 0L, pos
  | 0x6Duy ->
    if hasOprSz t.TPrefixes then parseOp t Opcode.INSW SzDef32 0L, pos
    else parseOp t Opcode.INSD SzDef32 0L, pos
  | 0x6Euy -> parseOp t Opcode.OUTSB SzDef32 0L, pos
  | 0x6Fuy ->
    if hasOprSz t.TPrefixes then parseOp t Opcode.OUTSW SzDef32 0L, pos
    else parseOp t Opcode.OUTSD SzDef32 0L, pos
  | 0x70uy -> parseOp t Opcode.JO Sz64 Jb, pos
  | 0x71uy -> parseOp t Opcode.JNO Sz64 Jb, pos
  | 0x72uy -> parseOp t Opcode.JB Sz64 Jb, pos
  | 0x73uy -> parseOp t Opcode.JNB Sz64 Jb, pos
  | 0x74uy -> parseOp t Opcode.JZ Sz64 Jb, pos
  | 0x75uy -> parseOp t Opcode.JNZ Sz64 Jb, pos
  | 0x76uy -> parseOp t Opcode.JBE Sz64 Jb, pos
  | 0x77uy -> parseOp t Opcode.JA Sz64 Jb, pos
  | 0x78uy -> parseOp t Opcode.JS Sz64 Jb, pos
  | 0x79uy -> parseOp t Opcode.JNS Sz64 Jb, pos
  | 0x7Auy -> parseOp t Opcode.JP Sz64 Jb, pos
  | 0x7Buy -> parseOp t Opcode.JNP Sz64 Jb, pos
  | 0x7Cuy -> parseOp t Opcode.JL Sz64 Jb, pos
  | 0x7Duy -> parseOp t Opcode.JNL Sz64 Jb, pos
  | 0x7Euy -> parseOp t Opcode.JLE Sz64 Jb, pos
  | 0x7Fuy -> parseOp t Opcode.JG Sz64 Jb, pos
  | 0x84uy -> parseOp t Opcode.TEST SzDef32 EbGb, pos
  | 0x85uy -> parseOp t Opcode.TEST SzDef32 EvGv, pos
  | 0x86uy -> parseOp t Opcode.XCHG SzDef32 EbGb, pos
  | 0x87uy -> parseOp t Opcode.XCHG SzDef32 EvGv, pos
  | 0x88uy -> parseOp t Opcode.MOV SzDef32 EbGb, pos
  | 0x89uy -> parseOp t Opcode.MOV SzDef32 EvGv, pos
  | 0x8Auy -> parseOp t Opcode.MOV SzDef32 GbEb, pos
  | 0x8Buy -> parseOp t Opcode.MOV SzDef32 GvEv, pos
  | 0x8Cuy -> parseOp (addOpSizePref t) Opcode.MOV SzDef32 EvSw, pos
  | 0x8Duy -> parseOp t Opcode.LEA SzDef32 GvMv, pos
  | 0x8Euy -> parseOp (addOpSizePref t) Opcode.MOV SzDef32 SwEw, pos
  | 0x90uy ->
    if hasNoPrefNoREX t then parseOp t Opcode.NOP SzDef32 0L, pos
    elif hasREPZ t.TPrefixes then parseOp t Opcode.PAUSE SzDef32 0L, pos
    else parseOp t Opcode.XCHG SzDef32 RGzRGz, pos
  | 0x91uy -> parseOp t Opcode.XCHG SzDef32 GvG0FGvG1T, pos
  | 0x92uy -> parseOp t Opcode.XCHG SzDef32 GvG0FGvG2T, pos
  | 0x93uy -> parseOp t Opcode.XCHG SzDef32 GvG0FGvG3T, pos
  | 0x94uy -> parseOp t Opcode.XCHG SzDef32 GvG0FGvG4T, pos
  | 0x95uy -> parseOp t Opcode.XCHG SzDef32 GvG0FGvG5T, pos
  | 0x96uy -> parseOp t Opcode.XCHG SzDef32 GvG0FGvG6T, pos
  | 0x97uy -> parseOp t Opcode.XCHG SzDef32 GvG0FGvG7T, pos
  | 0x98uy ->
    if hasOprSz t.TPrefixes then parseOp t Opcode.CBW SzDef32 0L, pos
    elif hasREXW t.TREXPrefix then parseOp t Opcode.CDQE SzDef32 0L, pos
    else parseOp t Opcode.CWDE SzDef32 0L, pos
  | 0x99uy ->
    if hasOprSz t.TPrefixes then parseOp t Opcode.CWD SzDef32 0L, pos
    elif hasREXW t.TREXPrefix then parseOp t Opcode.CQO SzDef32 0L, pos
    else parseOp t Opcode.CDQ SzDef32 0L, pos
  | 0x9Auy -> ensure32 t; parseOp t Opcode.CALLFar SzInv64 Ap, pos
  | 0x9Buy -> parseOp t Opcode.WAIT SzDef32 0L, pos
  | 0x9Cuy ->
    if is64bitWithOprSz t then parseOp t Opcode.PUSHF SzDef64 0L, pos
    elif hasOprSz t.TPrefixes then parseOp t Opcode.PUSHF SzDef32 0L, pos
    elif is64bit t then parseOp t Opcode.PUSHFQ SzDef64 0L, pos
    else parseOp t Opcode.PUSHFD SzDef32 0L, pos
  | 0x9Duy ->
    if is64bitWithOprSz t then parseOp t Opcode.POPF SzDef64 0L, pos
    elif hasOprSz t.TPrefixes then parseOp t Opcode.POPF SzDef32 0L, pos
    elif is64bit t then parseOp t Opcode.POPFQ SzDef64 0L, pos
    else parseOp t Opcode.POPFD SzDef32 0L, pos
  | 0x9Euy -> parseOp t Opcode.SAHF SzDef32 0L, pos
  | 0x9Fuy -> parseOp t Opcode.LAHF SzDef32 0L, pos
  | 0xA0uy -> parseOp t Opcode.MOV SzDef32 ALOb, pos
  | 0xA1uy -> parseOp t Opcode.MOV SzDef32 (GvG0FOv), pos
  | 0xA2uy -> parseOp t Opcode.MOV SzDef32 ObAL, pos
  | 0xA3uy -> parseOp t Opcode.MOV SzDef32 (OvGvG0F), pos
  | 0xA4uy -> parseOp t Opcode.MOVSB SzDef32 0L, pos
  | 0xA5uy ->
    if hasOprSz t.TPrefixes then parseOp t Opcode.MOVSW SzDef32 0L, pos
    elif hasREXW t.TREXPrefix then parseOp t Opcode.MOVSQ SzDef32 0L, pos
    else parseOp t Opcode.MOVSD SzDef32 0L, pos
  | 0xA6uy -> parseOp t Opcode.CMPSB SzDef32 XbYb, pos
  | 0xA7uy ->
    if hasOprSz t.TPrefixes then parseOp t Opcode.CMPSW SzDef32 0L, pos
    elif hasREXW t.TREXPrefix then parseOp t Opcode.CMPSQ SzDef32 0L, pos
    else parseOp t Opcode.CMPSD SzDef32 0L, pos
  | 0xA8uy -> parseOp t Opcode.TEST SzDef32 ALIb, pos
  | 0xA9uy -> parseOp t Opcode.TEST SzDef32 RGvSIz, pos
  | 0xAAuy -> parseOp t Opcode.STOSB SzDef32 0L, pos
  | 0xABuy ->
    if hasOprSz t.TPrefixes then parseOp t Opcode.STOSW SzDef32 0L, pos
    elif hasREXW t.TREXPrefix then parseOp t Opcode.STOSQ SzDef32 0L, pos
    else parseOp t Opcode.STOSD SzDef32 0L, pos
  | 0xACuy -> parseOp t Opcode.LODSB SzDef32 0L, pos
  | 0xADuy ->
    if hasOprSz t.TPrefixes then parseOp t Opcode.LODSW SzDef32 0L, pos
    elif hasREXW t.TREXPrefix then parseOp t Opcode.LODSQ SzDef32 0L, pos
    else parseOp t Opcode.LODSD SzDef32 0L, pos
  | 0xAEuy -> parseOp t Opcode.SCASB SzDef32 0L, pos
  | 0xAFuy ->
    if hasOprSz t.TPrefixes then parseOp t Opcode.SCASW SzDef32 0L, pos
    elif hasREXW t.TREXPrefix then parseOp t Opcode.SCASQ SzDef32 0L, pos
    else parseOp t Opcode.SCASD SzDef32 0L, pos
  | 0xB0uy -> parseOp t Opcode.MOV SzDef32 (getDescForRegGrp t RegGrp.RG0), pos
  | 0xB1uy -> parseOp t Opcode.MOV SzDef32 (getDescForRegGrp t RegGrp.RG1), pos
  | 0xB2uy -> parseOp t Opcode.MOV SzDef32 (getDescForRegGrp t RegGrp.RG2), pos
  | 0xB3uy -> parseOp t Opcode.MOV SzDef32 (getDescForRegGrp t RegGrp.RG3), pos
  | 0xB4uy -> parseOp t Opcode.MOV SzDef32 (getDescForRegGrp t RegGrp.RG4), pos
  | 0xB5uy -> parseOp t Opcode.MOV SzDef32 (getDescForRegGrp t RegGrp.RG5), pos
  | 0xB6uy -> parseOp t Opcode.MOV SzDef32 (getDescForRegGrp t RegGrp.RG6), pos
  | 0xB7uy -> parseOp t Opcode.MOV SzDef32 (getDescForRegGrp t RegGrp.RG7), pos
  | 0xB8uy -> parseOp t Opcode.MOV SzDef32 GvG0TIv, pos
  | 0xB9uy -> parseOp t Opcode.MOV SzDef32 GvG1TIv, pos
  | 0xBAuy -> parseOp t Opcode.MOV SzDef32 GvG2TIv, pos
  | 0xBBuy -> parseOp t Opcode.MOV SzDef32 GvG3TIv, pos
  | 0xBCuy -> parseOp t Opcode.MOV SzDef32 GvG4TIv, pos
  | 0xBDuy -> parseOp t Opcode.MOV SzDef32 GvG5TIv, pos
  | 0xBEuy -> parseOp t Opcode.MOV SzDef32 GvG6TIv, pos
  | 0xBFuy -> parseOp t Opcode.MOV SzDef32 GvG7TIv, pos
  | 0xC2uy -> parseOp t Opcode.RETNearImm Sz64 Iw, pos
  | 0xC3uy -> parseOp t Opcode.RETNear Sz64 0L, pos
  | 0xC4uy -> ensure32 t; parseOp t Opcode.LES SzInv64 GzMp, pos
  | 0xC5uy -> ensure32 t; parseOp t Opcode.LDS SzInv64 GzMp, pos
  | 0xC8uy -> parseOp t Opcode.ENTER SzDef32 IwIb, pos
  | 0xC9uy -> parseOp t Opcode.LEAVE SzDef64 0L, pos
  | 0xCAuy -> parseOp t Opcode.RETFarImm SzDef32 Iw, pos
  | 0xCBuy -> parseOp t Opcode.RETFar SzDef32 0L, pos
  | 0xCCuy -> parseOp t Opcode.INT3 SzDef32 0L, pos
  | 0xCDuy -> parseOp t Opcode.INT SzDef32 Ib, pos
  | 0xCEuy -> ensure32 t; parseOp t Opcode.INTO SzInv64 0L, pos
  | 0xCFuy ->
    if hasOprSz t.TPrefixes then parseOp t Opcode.IRETW SzDef32 0L, pos
    elif hasREXW t.TREXPrefix then parseOp t Opcode.IRETQ SzDef32 0L, pos
    else parseOp t Opcode.IRETD SzDef32 0L, pos
  | 0xD4uy -> ensure32 t; parseOp t Opcode.AAM SzInv64 Ib, pos
  | 0xD5uy -> ensure32 t; parseOp t Opcode.AAD SzInv64 Ib, pos
  | 0xD7uy -> parseOp t Opcode.XLATB SzDef32 0L, pos
  | 0xD8uy -> parseESCOp t reader pos 0xD8uy getD8OpWithin00toBF getD8OverBF
  | 0xD9uy -> parseESCOp t reader pos 0xD9uy getD9OpWithin00toBF getD9OverBF
  | 0xDAuy -> parseESCOp t reader pos 0xDAuy getDAOpWithin00toBF getDAOverBF
  | 0xDBuy -> parseESCOp t reader pos 0xDBuy getDBOpWithin00toBF getDBOverBF
  | 0xDCuy -> parseESCOp t reader pos 0xDCuy getDCOpWithin00toBF getDCOverBF
  | 0xDDuy -> parseESCOp t reader pos 0xDDuy getDDOpWithin00toBF getDDOverBF
  | 0xDEuy -> parseESCOp t reader pos 0xDEuy getDEOpWithin00toBF getDEOverBF
  | 0xDFuy -> parseESCOp t reader pos 0xDFuy getDFOpWithin00toBF getDFOverBF
  | 0xE0uy -> parseOp t Opcode.LOOPNE Sz64 Jb, pos
  | 0xE1uy -> parseOp t Opcode.LOOPE Sz64 Jb, pos
  | 0xE2uy -> parseOp t Opcode.LOOP Sz64 Jb, pos
  | 0xE3uy ->
    if is64bitWithAddrSz t then parseOp t Opcode.JECXZ Sz64 Jb, pos
    elif hasAddrSz t.TPrefixes then parseOp t Opcode.JCXZ Sz64 Jb, pos
    elif is64bit t then parseOp t Opcode.JRCXZ Sz64 Jb, pos
    else parseOp t Opcode.JECXZ Sz64 Jb, pos
  | 0xE4uy -> parseOp t Opcode.IN SzDef32 ALIb, pos
  | 0xE5uy -> parseOp t Opcode.IN SzDef32 GvG0FIb, pos
  | 0xE6uy -> parseOp t Opcode.OUT SzDef32 IbAL, pos
  | 0xE7uy -> parseOp t Opcode.OUT SzDef32 IbGvG0F, pos
  | 0xE8uy -> parseOp t Opcode.CALLNear Sz64 Jz, pos
  | 0xE9uy -> parseOp t Opcode.JMPNear Sz64 Jz, pos
  | 0xEAuy -> ensure32 t; parseOp t Opcode.JMPFar SzInv64 Ap, pos
  | 0xEBuy -> parseOp t Opcode.JMPNear Sz64 Jb, pos
  | 0xECuy -> parseOp t Opcode.IN SzDef32 ALDX, pos
  | 0xEDuy -> parseOp t Opcode.IN SzDef32 RGvDX, pos
  | 0xEEuy -> parseOp t Opcode.OUT SzDef32 ALDX, pos
  | 0xEFuy -> parseOp t Opcode.OUT SzDef32 DXRGv, pos
  | 0xF4uy -> parseOp t Opcode.HLT Sz64 0L, pos
  | 0xF5uy -> parseOp t Opcode.CMC Sz64 0L, pos
  | 0xF8uy -> parseOp t Opcode.CLC Sz64 0L, pos
  | 0xF9uy -> parseOp t Opcode.STC Sz64 0L, pos
  | 0xFAuy -> parseOp t Opcode.CLI Sz64 0L, pos
  | 0xFBuy -> parseOp t Opcode.STI Sz64 0L, pos
  | 0xFCuy -> parseOp t Opcode.CLD Sz64 0L, pos
  | 0xFDuy -> parseOp t Opcode.STD Sz64 0L, pos
  (* Group Opcodes Vol.2C A-19 Table A-6.
     Opcode Extensions for One- and Two-byte Opcodes by Group Number *)
  | 0x80uy -> parseGrpOpcode t reader pos OpGroup.G1 EbIb
  | 0x81uy -> parseGrpOpcode t reader pos OpGroup.G1 EvSIz
  | 0x82uy -> parseGrpOpcode t reader pos OpGroup.G1Inv64 EbIb
  | 0x83uy -> parseGrpOpcode t reader pos OpGroup.G1 EvSIb
  | 0x8Fuy -> parseGrpOpcode t reader pos OpGroup.G1A Ev
  | 0xC0uy -> parseGrpOpcode t reader pos OpGroup.G2 EbIb
  | 0xC1uy -> parseGrpOpcode t reader pos OpGroup.G2 EvIb
  | 0xD0uy -> parseGrpOpcode t reader pos OpGroup.G2 Eb1L
  | 0xD1uy -> parseGrpOpcode t reader pos OpGroup.G2 Ev1L
  | 0xD2uy -> parseGrpOpcode t reader pos OpGroup.G2 EbCL
  | 0xD3uy -> parseGrpOpcode t reader pos OpGroup.G2 EvCL
  | 0xF6uy -> parseGrpOpcode t reader pos OpGroup.G3A Eb
  | 0xF7uy -> parseGrpOpcode t reader pos OpGroup.G3B Ev
  | 0xFEuy -> parseGrpOpcode t reader pos OpGroup.G4 0L
  | 0xFFuy -> parseGrpOpcode t reader pos OpGroup.G5 0L
  | 0xC6uy -> parseGrpOpcode t reader pos OpGroup.G11A EbIb
  | 0xC7uy -> parseGrpOpcode t reader pos OpGroup.G11B EvSIz
  | 0x0Fuy -> parseTwoByteOpcode t reader pos
  | _ -> raise ParsingFailureException

(*
let private memoizeOneByte f t =
  let cache = System.Collections.Generic.Dictionary<_, _> ()
  fun (reader: BinReader) ->
    let b = reader.ReadByte ()
    let key = int t.TPrefixes ||| (int t.TREXPrefix <<< 12)
    let mutable ok = Unchecked.defaultof<_>
    let res = cache.TryGetValue (x, &ok)
    if ok then res
    else let res = f x
         cache.[x] <- res
         res
*)

let private parseRegularOpcode t (reader: BinReader) pos =
  reader.PeekByte pos |> pOneByteOpcode t reader (pos + 1)

let private parseOpcode t (reader: BinReader) pos =
  match t.TVEXInfo with
  | Some { VEXType = vt } ->
    if VEXType.isTwoByteOp vt then parseTwoByteOpcode t reader pos
    elif VEXType.isThreeByteOpOne vt then parseThreeByteOp1 t reader pos
    elif VEXType.isThreeByteOpTwo vt then parseThreeByteOp2 t reader pos
    else raise ParsingFailureException
  | None -> parseRegularOpcode t reader pos

let inline private getOprFromRegGrp rgrp attr insInfo =
  findReg insInfo.InsSize.RegSize attr insInfo.REXPrefix rgrp |> OprReg

let private parseSignedImm (reader: BinReader) pos = function
  | 1 -> reader.PeekInt8 pos |> int64, pos + 1
  | 2 -> reader.PeekInt16 pos |> int64, pos + 2
  | 4 -> reader.PeekInt32 pos |> int64, pos + 4
  | 8 -> reader.PeekInt64 pos, pos + 8
  | _ -> raise ParsingFailureException

let private parseUnsignedImm (reader: BinReader) pos = function
  | 1 -> reader.PeekUInt8 pos |> uint64, pos + 1
  | 2 -> reader.PeekUInt16 pos |> uint64, pos + 2
  | 4 -> reader.PeekUInt32 pos |> uint64, pos + 4
  | 8 -> reader.PeekUInt64 pos, pos + 8
  | _ -> raise ParsingFailureException

let inline private parseOprForDirectJmp insInfo reader pos =
  let addrSz = RegType.toByteWidth insInfo.InsSize.MemSize.EffAddrSize
  let addrValue, nextPos = parseUnsignedImm reader pos addrSz
  let selector = reader.PeekInt16 nextPos
  let absAddr = Absolute (selector, addrValue, RegType.fromByteWidth addrSz)
  struct (OprDirAddr absAddr, nextPos + 2)

let inline private getImmSize effOprSz = function
  | 0x80L (* OprSize.B *) -> 8<rt>
  | 0x6c0L (* OprSize.V *) -> effOprSz
  | 0x700L (* OprSize.W *) -> 16<rt>
  | 0x800L (* OprSize.Z *) ->
    if effOprSz = 64<rt> || effOprSz = 32<rt> then 32<rt> else effOprSz
  | _ -> raise ParsingFailureException

let inline private parseOprForRelJmp insInfo oldPos reader pos sKnd =
  let sz = getImmSize insInfo.InsSize.MemSize.EffOprSize sKnd
  let offset, nextPos = parseSignedImm reader pos (RegType.toByteWidth sz)
  let relOffset = offset + int64 nextPos - int64 oldPos
  struct (OprDirAddr (Relative (relOffset)), nextPos)

/// EVEX uses compressed displacement. See the manual Chap. 15 of Vol. 1.
let compressDisp vInfo disp =
  match vInfo with
  | Some { VectorLength = 128<rt>; VEXType = vt } when VEXType.isEnhanced vt ->
    disp * 16L
  | Some { VectorLength = 256<rt>; VEXType = vt } when VEXType.isEnhanced vt ->
    disp * 32L
  | Some { VectorLength = 512<rt>; VEXType = vt } when VEXType.isEnhanced vt ->
    disp * 64L
  | _ -> disp

let inline private parseOprMem insInfo reader pos baseReg siReg disp =
  let memSz = insInfo.InsSize.MemSize.EffOprSize
  match disp with
  | None -> struct (OprMem (baseReg, siReg, None, memSz), pos)
  | Some dispSz -> let vInfo = insInfo.VEXInfo
                   let disp, nextPos = parseSignedImm reader pos dispSz
                   let disp = compressDisp vInfo disp
                   struct (OprMem (baseReg, siReg, Some disp, memSz), nextPos)

let inline private parseOprImm insInfo reader pos sKnd =
  let sz =
    getImmSize insInfo.InsSize.MemSize.EffOprSize sKnd |> RegType.toByteWidth
  let imm, nextPos = parseUnsignedImm reader pos sz
  struct (OprImm (int64 imm), nextPos)

let inline private getMask sz =
  match sz with
  | 8<rt> -> 0xFFL
  | 16<rt> -> 0xFFFFL
  | 32<rt> -> 0xFFFFFFFFL
  | _ -> 0xFFFFFFFFFFFFFFFFL

let inline private parseOprSImm insInfo reader pos sKnd =
  let sz =
    getImmSize insInfo.InsSize.MemSize.EffOprSize sKnd |> RegType.toByteWidth
  let imm, nextPos = parseSignedImm reader pos sz
  struct (OprImm (imm &&& getMask insInfo.InsSize.OperationSize), nextPos)

/// The first 24 rows of Table 2-1. of the manual Vol. 2A.
/// The index of this tbl is a number that is a concatenation of (mod) and
/// (r/m) field of the ModR/M byte. Each element is a tuple of base register,
/// scaled index register, and the size of the displacement.
let tbl16bitMem = [|
  (* Mod 00b *)
  struct (Some R.BX, Some (R.SI, Scale.X1), None)
  struct (Some R.BX, Some (R.DI, Scale.X1), None)
  struct (Some R.BP, Some (R.SI, Scale.X1), None)
  struct (Some R.BP, Some (R.DI, Scale.X1), None)
  struct (Some R.SI, None, None)
  struct (Some R.DI, None, None)
  struct (None, None, Some 2)
  struct (Some R.BX, None, None)
  (* Mod 01b *)
  struct (Some R.BX, Some (R.SI, Scale.X1), Some 1)
  struct (Some R.BX, Some (R.DI, Scale.X1), Some 1)
  struct (Some R.BP, Some (R.SI, Scale.X1), Some 1)
  struct (Some R.BP, Some (R.DI, Scale.X1), Some 1)
  struct (Some R.SI, None, Some 1)
  struct (Some R.DI, None, Some 1)
  struct (Some R.BP, None, Some 1)
  struct (Some R.BX, None, Some 1)
  (* Mod 10b *)
  struct (Some R.BX, Some (R.SI, Scale.X1), Some 2)
  struct (Some R.BX, Some (R.DI, Scale.X1), Some 2)
  struct (Some R.BP, Some (R.SI, Scale.X1), Some 2)
  struct (Some R.BP, Some (R.DI, Scale.X1), Some 2)
  struct (Some R.SI, None, Some 2)
  struct (Some R.DI, None, Some 2)
  struct (Some R.BP, None, Some 2)
  struct (Some R.BX, None, Some 2)
|]

/// The first 24 rows of Table 2-2. of the manual Vol. 2A.
/// The index of this tbl is a number that is a concatenation of (mod) and
/// (r/m) field of the ModR/M byte. Each element is a tuple of (MemLookupType,
/// and the size of the displacement). If the first value of the tuple (register
/// group) is None, it means we need to look up the SIB tbl (Table 2-3). If
/// not, then it represents the reg group of the base reigster.
let tbl32bitMem = [|
  (* Mod 00b *)
  struct (NOSIB (Some RegGrp.RG0), None)
  struct (NOSIB (Some RegGrp.RG1), None)
  struct (NOSIB (Some RegGrp.RG2), None)
  struct (NOSIB (Some RegGrp.RG3), None)
  struct (SIB,                     None)
  struct (NOSIB (None),            Some 4)
  struct (NOSIB (Some RegGrp.RG6), None)
  struct (NOSIB (Some RegGrp.RG7), None)
  (* Mod 01b *)
  struct (NOSIB (Some RegGrp.RG0), Some 1)
  struct (NOSIB (Some RegGrp.RG1), Some 1)
  struct (NOSIB (Some RegGrp.RG2), Some 1)
  struct (NOSIB (Some RegGrp.RG3), Some 1)
  struct (SIB,                     Some 1)
  struct (NOSIB (Some RegGrp.RG5), Some 1)
  struct (NOSIB (Some RegGrp.RG6), Some 1)
  struct (NOSIB (Some RegGrp.RG7), Some 1)
  (* Mod 10b *)
  struct (NOSIB (Some RegGrp.RG0), Some 4)
  struct (NOSIB (Some RegGrp.RG1), Some 4)
  struct (NOSIB (Some RegGrp.RG2), Some 4)
  struct (NOSIB (Some RegGrp.RG3), Some 4)
  struct (SIB,                     Some 4)
  struct (NOSIB (Some RegGrp.RG5), Some 4)
  struct (NOSIB (Some RegGrp.RG6), Some 4)
  struct (NOSIB (Some RegGrp.RG7), Some 4)
|]

/// Table for register groups. This tbl can be referenced by RM field or REG
/// field of the ModR/M byte.
/// Table for scales (of SIB). This tbl is indexbed by the scale value of SIB.
let tblScale = [| Scale.X1; Scale.X2; Scale.X4; Scale.X8 |]

let private parseMEM16 insInfo reader pos modRM =
  let m = getMod modRM
  let rm = getRM modRM
  let mrm = (m <<< 3) ||| rm (* Concatenation of mod and rm bit *)
  match tbl16bitMem.[mrm] with
  | struct (b, si, disp) -> parseOprMem insInfo reader pos b si disp

let inline private hasREXX rexPref = rexPref &&& REXPrefix.REXX = REXPrefix.REXX

let private getScaledIndex s i insInfo rexPref =
  if i = 0b100 && (not <| hasREXX rexPref) then None
  else let sz = insInfo.InsSize.MemSize.EffAddrSize
       let r = findReg sz RGrpAttr.ASIBIdx rexPref i
       Some (r, tblScale.[s])

let private getBaseReg b insInfo modValue rexPref =
  (* See Notes 1 of Table 2-3 of the manual Vol. 2A *)
  if b = int RegGrp.RG5 && modValue = 0b00 then None
  else let sz = insInfo.InsSize.MemSize.EffAddrSize
       Some (findReg sz RGrpAttr.ASIBBase rexPref b)

let inline private getSIB b =
  struct ((b >>> 6) &&& 0b11, (b >>> 3) &&& 0b111, b &&& 0b111)

let parseSIB insInfo (reader: BinReader) pos modValue =
  let struct (s, i, b) = reader.PeekByte pos |> int |> getSIB
  let rexPref = insInfo.REXPrefix
  let si = getScaledIndex s i insInfo rexPref
  let baseReg = getBaseReg b insInfo modValue rexPref
  struct (si, baseReg, b), pos + 1

let getSIBDisplacement disp bgrp modValue =
  match disp with
  | Some dispSz -> dispSz
  | None when modValue = 0 && bgrp = int RegGrp.RG5 -> 4
  | None when modValue = 1 && bgrp = int RegGrp.RG5 -> 1
  | None when modValue = 2 && bgrp = int RegGrp.RG5 -> 4
  | _ -> 0

let parseOprMemWithSIB insInfo reader pos oprSize modValue disp =
  let struct (si, b, bgrp), nextPos = parseSIB insInfo reader pos modValue
  match getSIBDisplacement disp bgrp modValue with
  | 0 -> struct (OprMem (b, si, None, oprSize), nextPos)
  | dispSz ->
    let vInfo = insInfo.VEXInfo
    let disp, nextPos = parseSignedImm reader nextPos dispSz
    let disp = compressDisp vInfo disp
    struct (OprMem (b, si, Some disp, oprSize), nextPos)

/// RIP-relative addressing (see Section 2.2.1.6. of Vol. 2A).
let parseOprRIPRelativeMem insInfo wordSz reader pos disp =
  if wordSz = WordSize.Bit64 then
    if hasAddrSz insInfo.Prefixes then
      parseOprMem insInfo reader pos (Some R.EIP) None disp
    else parseOprMem insInfo reader pos (Some R.RIP) None disp
  else parseOprMem insInfo reader pos None None disp

let inline private getBaseRMReg insInfo regGrp =
  let rexPref = selectREX insInfo.VEXInfo insInfo.REXPrefix
  let regSz = insInfo.InsSize.MemSize.EffAddrSize
  findReg regSz RGrpAttr.ABaseRM rexPref (int regGrp) |> Some

let inline private parseMEM32 insInfo wordSz reader pos oprSize modRM =
  let m = getMod modRM
  let rm = getRM modRM
  let mrm = (m <<< 3) ||| rm (* Concatenation of mod and rm bit *)
  match tbl32bitMem.[mrm] with
  | struct (NOSIB (None), disp) ->
    parseOprRIPRelativeMem insInfo wordSz reader pos disp
  | struct (NOSIB (Some b), disp) ->
    parseOprMem insInfo reader pos (getBaseRMReg insInfo b) None disp
  | struct (SIB, disp) -> parseOprMemWithSIB insInfo reader pos oprSize m disp

let inline private parseMemory modRM insInfo wordSz reader pos =
  let addrSize = insInfo.InsSize.MemSize.EffAddrSize
  if addrSize = 16<rt> then parseMEM16 insInfo reader pos modRM
  else parseMEM32 insInfo wordSz reader pos insInfo.InsSize.MemSize.EffOprSize
                  modRM

let inline private parseReg rgrp sz attr insInfo pos =
  let rexPref = selectREX insInfo.VEXInfo insInfo.REXPrefix
  struct (findReg sz attr rexPref rgrp |> OprReg, pos)

let inline private parseMemOrReg modRM insInfo wordSz reader pos =
  if getMod modRM = 0b11 then
    let regSize = insInfo.InsSize.MemSize.EffRegSize
    parseReg (getRM modRM) regSize RGrpAttr.AMod11 insInfo pos
  else parseMemory modRM insInfo wordSz reader pos

let inline private parseXMMReg insInfo =
  match insInfo.VEXInfo with
  | None -> raise ParsingFailureException
  | Some vInfo when vInfo.VectorLength = 256<rt> ->
    Register.make (int vInfo.VVVV) Register.Kind.YMM |> OprReg
  | Some vInfo ->
    Register.make (int vInfo.VVVV) Register.Kind.XMM |> OprReg

let inline private parseMMXReg n =
  Register.make n Register.Kind.MMX |> OprReg

let inline private parseSegReg n =
  Register.make n Register.Kind.Segment |> OprReg

let inline private parseBoundRegister n =
  Register.make n Register.Kind.Bound |> OprReg

let inline private parseControlReg n =
  Register.make n Register.Kind.Control |> OprReg

let inline private parseDebugReg n =
  Register.make n Register.Kind.Debug |> OprReg

let parseWithModRM insInfo wordSz reader pos modRM mode =
  match mode with
  | OprMode.M | OprMode.MZ when modIsMemory modRM ->
    parseMemory modRM insInfo wordSz reader pos
  | OprMode.R | OprMode.U ->
    parseReg (getRM modRM)
             insInfo.InsSize.MemSize.EffRegSize RGrpAttr.AMod11 insInfo pos
  | OprMode.E | OprMode.W | OprMode.WZ ->
    parseMemOrReg modRM insInfo wordSz reader pos
  | OprMode.E0 when getReg modRM = 0 ->
    parseMemOrReg modRM insInfo wordSz reader pos
  | OprMode.G | OprMode.V | OprMode.VZ ->
    parseReg (getReg modRM) insInfo.InsSize.RegSize RGrpAttr.ARegBits insInfo
             pos
  | OprMode.C when insInfo.Opcode = Opcode.MOV && hasREXR insInfo.REXPrefix ->
    struct (parseControlReg 0x808, pos) (* CR8 *)
  | OprMode.C -> struct (parseControlReg (getReg modRM), pos)
  | OprMode.D -> struct (parseDebugReg (getReg modRM), pos)
  | OprMode.H -> struct (parseXMMReg insInfo, pos)
  | OprMode.P -> struct (parseMMXReg (getReg modRM), pos)
  | OprMode.S when (getReg modRM) < 6 -> (* 6 means number of Seg registers *)
    struct (parseSegReg (getReg modRM), pos)
  | OprMode.N -> struct (parseMMXReg (getRM modRM), pos)
  | OprMode.Q when modIsMemory modRM ->
    parseMemory modRM insInfo wordSz reader pos
  | OprMode.Q -> struct (parseMMXReg (getRM modRM), pos)
  | OprMode.BndR -> struct (parseBoundRegister (getReg modRM), pos)
  | OprMode.BndM when modIsMemory modRM ->
    parseMemory modRM insInfo wordSz reader pos
  | OprMode.BndM -> struct (parseBoundRegister (getRM modRM), pos)
  | _ -> raise ParsingFailureException

let parseOprOnlyDisp insInfo reader pos =
  let dispSz = RegType.toByteWidth insInfo.InsSize.MemSize.EffAddrSize
  parseOprMem insInfo reader pos None None (Some dispSz)

let parseOperand insInfo wordSz modRM oldPos reader pos oprDesc =
  if oprDesc >= 0x4000L then
    struct (getOprFromRegGrp ((oprDesc >>> 3) &&& 0x7L |> int)
                             (getRGrpAttr oprDesc) insInfo, pos)
  elif oprDesc >= 0x3000L then struct (OprReg (getRegister oprDesc), pos)
  elif oprDesc >= 0x2000L then
    let mode = getModeFld oprDesc
    if mode = 0x1L then (* OprMode.A *)
      parseOprForDirectJmp insInfo reader pos
    elif mode = 0xBL then (* OprMode.J *)
      parseOprForRelJmp insInfo oldPos reader pos (getSizeFld oprDesc)
    elif mode = 0xFL then (* OprMode.O *)
      parseOprOnlyDisp insInfo reader pos
    elif mode = 0x9L then (* OprMode.I *)
      parseOprImm insInfo reader pos (getSizeFld oprDesc)
    elif mode = 0xAL then (* OprMode.SI *)
      parseOprSImm insInfo reader pos (getSizeFld oprDesc)
    else
      parseWithModRM insInfo wordSz reader pos (Option.get modRM)
                     (getOprMode oprDesc)
  else struct (OprImm 1L, pos)

let parseOperands insInfo descs wordSz modRM oldPos reader pos =
  let inline getOprAndNextPos pos desc =
    parseOperand insInfo wordSz modRM oldPos reader pos desc
  if (descs &&& 0xFFFF000000000000L) = 0L then struct (NoOperand, pos)
  elif (descs &&& 0xFFFF00000000L) = 0L then
    let struct (oper, nextPos) = getOprAndNextPos pos (getFstDesc descs)
    struct (OneOperand oper, nextPos)
  elif (descs &&& 0xFFFF0000L) = 0L then
    let struct (oper1, nextPos) = getOprAndNextPos pos (getFstDesc descs)
    let struct (oper2, nextPos) = getOprAndNextPos nextPos (getSndDesc descs)
    struct (TwoOperands (oper1, oper2), nextPos)
  elif (descs &&& 0xFFFFL) = 0L then
    let struct (oper1, nextPos) = getOprAndNextPos pos (getFstDesc descs)
    let struct (oper2, nextPos) = getOprAndNextPos nextPos (getSndDesc descs)
    let struct (oper3, nextPos) = getOprAndNextPos nextPos (getTrdDesc descs)
    struct (ThreeOperands (oper1, oper2, oper3), nextPos)
  else
    let struct (oper1, nextPos) = getOprAndNextPos pos (getFstDesc descs)
    let struct (oper2, nextPos) = getOprAndNextPos nextPos (getSndDesc descs)
    let struct (oper3, nextPos) = getOprAndNextPos nextPos (getTrdDesc descs)
    let struct (oper4, nextPos) = getOprAndNextPos nextPos (getFthDesc descs)
    struct (FourOperands (oper1, oper2, oper3, oper4), nextPos)

let inline private newInsInfo addr parsingInfo instrLen wordSize =
  IntelInstruction (addr, instrLen, parsingInfo, wordSize)

let private isModRMMode = function
  | 1L  (* OprMode.A *)
  | 9L  (* OprMode.I *)
  | 10L (* OprMode.SI *)
  | 11L (* OprMode.J *)
  | 15L (* OprMode.O *) -> true
  | _ -> false

let inline private hasModRM oprDesc =
  match getDescKindFld oprDesc with
  | 0x2000L when isModRMMode (getModeFld oprDesc) -> false
  | 0x2000L -> true
  | _ -> false

let parseModRM oprDescs (reader: BinReader) pos =
  if (oprDescs <> 0L) && (hasModRM (getFstDesc oprDescs)) then
    struct (reader.PeekByte pos |> Some, pos + 1)
  else struct (None, pos)

let parse (reader: BinReader) wordSz addr pos =
  let struct (prefs, nextPos) = parsePrefix reader pos
  let struct (rexPref, nextPos) = parseREX wordSz reader nextPos
  let struct (vInfo, nextPos) = parseVEXInfo wordSz reader nextPos
  let t = newTemporaryInfo prefs rexPref vInfo wordSz
  let ins, nextPos = parseOpcode t reader nextPos
  match ins with
  | None
  | Some (struct ({ Opcode = Opcode.InvalOP }, _) ) ->
    raise ParsingFailureException
  | Some (struct (insInfo, _)) when insInfo.Operands <> NoOperand ->
    let len = nextPos - pos |> uint32
    newInsInfo addr insInfo len wordSz
  | Some (struct (insInfo, oprDescs)) ->
    let struct (modRM, nextPos) = parseModRM oprDescs reader nextPos
    let struct (oprs, nextPos) =
      parseOperands insInfo oprDescs wordSz modRM pos reader nextPos
    let len = nextPos - pos |> uint32
    newInsInfo addr { insInfo with Operands = oprs } len wordSz

// vim: set tw=80 sts=2 sw=2:

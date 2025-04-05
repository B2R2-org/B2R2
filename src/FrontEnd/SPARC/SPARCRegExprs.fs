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

namespace B2R2.FrontEnd.SPARC

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR
open type Register

type RegExprs (wordSize) =
  let var sz t name = AST.var sz t name

  (* SPARC. *)
  let regType = WordSize.toRegType wordSize
  let fRegType = WordSize.toRegType WordSize.Bit32

  member val G0 = var regType (Register.toRegID G0) "g0" with get
  member val G1 = var regType (Register.toRegID G1) "g1" with get
  member val G2 = var regType (Register.toRegID G2) "g2" with get
  member val G3 = var regType (Register.toRegID G3) "g3" with get
  member val G4 = var regType (Register.toRegID G4) "g4" with get
  member val G5 = var regType (Register.toRegID G1) "g5" with get
  member val G6 = var regType (Register.toRegID G6) "g6" with get
  member val G7 = var regType (Register.toRegID G1) "g7" with get
  member val O0 = var regType (Register.toRegID O0) "o0" with get
  member val O1 = var regType (Register.toRegID O1) "o1" with get
  member val O2 = var regType (Register.toRegID O2) "o2" with get
  member val O3 = var regType (Register.toRegID O3) "o3" with get
  member val O4 = var regType (Register.toRegID O4) "o4" with get
  member val O5 = var regType (Register.toRegID O5) "o5" with get
  member val O6 = var regType (Register.toRegID O6) "o6" with get
  member val O7 = var regType (Register.toRegID O7) "o7" with get
  member val L0 = var regType (Register.toRegID L0) "l0" with get
  member val L1 = var regType (Register.toRegID L1) "l1" with get
  member val L2 = var regType (Register.toRegID L2) "l2" with get
  member val L3 = var regType (Register.toRegID L3) "l3" with get
  member val L4 = var regType (Register.toRegID L4) "l4" with get
  member val L5 = var regType (Register.toRegID L5) "l5" with get
  member val L6 = var regType (Register.toRegID L6) "l6" with get
  member val L7 = var regType (Register.toRegID L7) "l7" with get
  member val I0 = var regType (Register.toRegID I0) "i0" with get
  member val I1 = var regType (Register.toRegID I1) "i1" with get
  member val I2 = var regType (Register.toRegID I2) "i2" with get
  member val I3 = var regType (Register.toRegID I3) "i3" with get
  member val I4 = var regType (Register.toRegID I4) "i4" with get
  member val I5 = var regType (Register.toRegID I5) "i5" with get
  member val I6 = var regType (Register.toRegID I6) "i6" with get
  member val I7 = var regType (Register.toRegID I7) "i7" with get
  member val F0 = var fRegType (Register.toRegID F0) "f0" with get
  member val F1 = var fRegType (Register.toRegID F1) "f1" with get
  member val F2 = var fRegType (Register.toRegID F2) "f2" with get
  member val F3 = var fRegType (Register.toRegID F3) "f3" with get
  member val F4 = var fRegType (Register.toRegID F4) "f4" with get
  member val F5 = var fRegType (Register.toRegID F5) "f5" with get
  member val F6 = var fRegType (Register.toRegID F6) "f6" with get
  member val F7 = var fRegType (Register.toRegID F7) "f7" with get
  member val F8 = var fRegType (Register.toRegID F8) "f8" with get
  member val F9 = var fRegType (Register.toRegID F9) "f9" with get
  member val F10 = var fRegType (Register.toRegID F10) "f10" with get
  member val F11 = var fRegType (Register.toRegID F11) "f11" with get
  member val F12 = var fRegType (Register.toRegID F12) "f12" with get
  member val F13 = var fRegType (Register.toRegID F13) "f13" with get
  member val F14 = var fRegType (Register.toRegID F14) "f14" with get
  member val F15 = var fRegType (Register.toRegID F15) "f15" with get
  member val F16 = var fRegType (Register.toRegID F16) "f16" with get
  member val F17 = var fRegType (Register.toRegID F17) "f17" with get
  member val F18 = var fRegType (Register.toRegID F18) "f18" with get
  member val F19 = var fRegType (Register.toRegID F19) "f19" with get
  member val F20 = var fRegType (Register.toRegID F20) "f20" with get
  member val F21 = var fRegType (Register.toRegID F21) "f21" with get
  member val F22 = var fRegType (Register.toRegID F22) "f22" with get
  member val F23 = var fRegType (Register.toRegID F23) "f23" with get
  member val F24 = var fRegType (Register.toRegID F24) "f24" with get
  member val F25 = var fRegType (Register.toRegID F25) "f25" with get
  member val F26 = var fRegType (Register.toRegID F26) "f26" with get
  member val F27 = var fRegType (Register.toRegID F27) "f27" with get
  member val F28 = var fRegType (Register.toRegID F28) "f28" with get
  member val F29 = var fRegType (Register.toRegID F29) "f29" with get
  member val F30 = var fRegType (Register.toRegID F30) "f30" with get
  member val F31 = var fRegType (Register.toRegID F31) "f31" with get
  member val F32 = var regType (Register.toRegID F32) "f32" with get
  member val F34 = var regType (Register.toRegID F34) "f34" with get
  member val F36 = var regType (Register.toRegID F36) "f36" with get
  member val F38 = var regType (Register.toRegID F38) "f38" with get
  member val F40 = var regType (Register.toRegID F40) "f40" with get
  member val F42 = var regType (Register.toRegID F42) "f42" with get
  member val F44 = var regType (Register.toRegID F44) "f44" with get
  member val F46 = var regType (Register.toRegID F46) "f46" with get
  member val F48 = var regType (Register.toRegID F48) "f48" with get
  member val F50 = var regType (Register.toRegID F50) "f50" with get
  member val F52 = var regType (Register.toRegID F52) "f52" with get
  member val F54 = var regType (Register.toRegID F54) "f54" with get
  member val F56 = var regType (Register.toRegID F56) "f56" with get
  member val F58 = var regType (Register.toRegID F58) "f58" with get
  member val F60 = var regType (Register.toRegID F60) "f60" with get
  member val F62 = var regType (Register.toRegID F62) "f62" with get
  member val PC = var regType (Register.toRegID PC) "PC" with get
  member val NPC = var regType (Register.toRegID NPC) "nPC" with get
  member val Y = var regType (Register.toRegID Y) "Y" with get
  member val CCR = var regType (Register.toRegID CCR) "CCR" with get
  member val FSR = var regType (Register.toRegID FSR) "FSR" with get
  member val ASI = var regType (Register.toRegID ASI) "ASI" with get
  member val ASRs = var regType (Register.toRegID ASRs) "ASRs" with get
  member val FPRS = var regType (Register.toRegID FPRS) "FPRS" with get
  member val TICK = var regType (Register.toRegID TICK) "TICK" with get
  member val PSTATE =
    var regType (Register.toRegID PSTATE) "PSTATE" with get
  member val TL = var regType (Register.toRegID TL) "TL" with get
  member val PIL = var regType (Register.toRegID PIL) "PIL" with get
  member val TPC = var regType (Register.toRegID TPC) "TPC" with get
  member val TNPC = var regType (Register.toRegID TNPC) "TNPC" with get
  member val TSTATE =
    var regType (Register.toRegID TSTATE) "TSTATE" with get
  member val TT = var regType (Register.toRegID TT) "TT" with get
  member val TBA = var regType (Register.toRegID TBA) "TBA" with get
  member val VER = var regType (Register.toRegID VER) "VER" with get
  member val CWP = var regType (Register.toRegID CWP) "CWP" with get
  member val CANSAVE =
    var regType (Register.toRegID CANSAVE) "CANSAVE" with get
  member val CANRESTORE =
    var regType (Register.toRegID CANRESTORE) "CANRESTORE" with get
  member val OTHERWIN =
    var regType (Register.toRegID OTHERWIN) "OTHERWIN" with get
  member val WSTATE =
    var regType (Register.toRegID WSTATE) "WSTATE" with get
  member val FQ = var regType (Register.toRegID FQ) "FQ" with get
  member val CLEANWIN =
    var regType (Register.toRegID CLEANWIN) "CLEANWIN" with get

  member this.GetRegVar (name) =
    match name with
    | Register.G0 -> this.G0
    | Register.G1 -> this.G1
    | Register.G2 -> this.G2
    | Register.G3 -> this.G3
    | Register.G4 -> this.G4
    | Register.G5 -> this.G5
    | Register.G6 -> this.G6
    | Register.G7 -> this.G7
    | Register.O0 -> this.O0
    | Register.O1 -> this.O1
    | Register.O2 -> this.O2
    | Register.O3 -> this.O3
    | Register.O4 -> this.O4
    | Register.O5 -> this.O5
    | Register.O6 -> this.O6
    | Register.O7 -> this.O7
    | Register.L0 -> this.L0
    | Register.L1 -> this.L1
    | Register.L2 -> this.L2
    | Register.L3 -> this.L3
    | Register.L4 -> this.L4
    | Register.L5 -> this.L5
    | Register.L6 -> this.L6
    | Register.L7 -> this.L7
    | Register.I0 -> this.I0
    | Register.I1 -> this.I1
    | Register.I2 -> this.I2
    | Register.I3 -> this.I3
    | Register.I4 -> this.I4
    | Register.I5 -> this.I5
    | Register.I6 -> this.I6
    | Register.I7 -> this.I7
    | Register.PC -> this.PC
    | Register.CCR -> this.CCR
    | Register.FSR -> this.FSR
    | Register.Y -> this.Y
    | Register.F0 -> this.F0
    | Register.F1 -> this.F1
    | Register.F2 -> this.F2
    | Register.F3 -> this.F3
    | Register.F4 -> this.F4
    | Register.F5 -> this.F5
    | Register.F6 -> this.F6
    | Register.F7 -> this.F7
    | Register.F8 -> this.F8
    | Register.F9 -> this.F9
    | Register.F10 -> this.F10
    | Register.F11 -> this.F11
    | Register.F12 -> this.F12
    | Register.F13 -> this.F13
    | Register.F14 -> this.F14
    | Register.F15 -> this.F15
    | Register.F16 -> this.F16
    | Register.F17 -> this.F17
    | Register.F18 -> this.F18
    | Register.F19 -> this.F19
    | Register.F20 -> this.F20
    | Register.F21 -> this.F21
    | Register.F22 -> this.F22
    | Register.F23 -> this.F23
    | Register.F24 -> this.F24
    | Register.F25 -> this.F25
    | Register.F26 -> this.F26
    | Register.F27 -> this.F27
    | Register.F28 -> this.F28
    | Register.F29 -> this.F29
    | Register.F30 -> this.F30
    | Register.F31 -> this.F31
    | Register.F32 -> this.F32
    | Register.F34 -> this.F34
    | Register.F36 -> this.F36
    | Register.F38 -> this.F38
    | Register.F40 -> this.F40
    | Register.F42 -> this.F42
    | Register.F44 -> this.F44
    | Register.F46 -> this.F46
    | Register.F48 -> this.F48
    | Register.F50 -> this.F50
    | Register.F52 -> this.F52
    | Register.F54 -> this.F54
    | Register.F56 -> this.F56
    | Register.F58 -> this.F58
    | Register.F60 -> this.F60
    | Register.F62 -> this.F62
    | Register.ASI -> this.ASI
    | Register.ASRs -> this.ASRs
    | Register.FPRS -> this.FPRS
    | Register.TICK -> this.TICK
    | Register.PSTATE -> this.PSTATE
    | Register.TL -> this.TL
    | Register.PIL -> this.PIL
    | Register.TPC -> this.TPC
    | Register.TNPC -> this.TNPC
    | Register.TSTATE -> this.TSTATE
    | Register.TT -> this.TT
    | Register.TBA -> this.TBA
    | Register.VER -> this.VER
    | Register.CWP -> this.CWP
    | Register.CANSAVE -> this.CANSAVE
    | Register.CANRESTORE -> this.CANRESTORE
    | Register.OTHERWIN -> this.OTHERWIN
    | Register.WSTATE -> this.WSTATE
    | Register.FQ -> this.FQ
    | Register.CLEANWIN -> this.CLEANWIN
    | _ -> raise UnhandledRegExprException

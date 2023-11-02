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

namespace B2R2.FrontEnd.BinLifter.SPARC

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

type RegExprs (wordSize) =
  let var sz t name = AST.var sz t name

  (* Registers *)
  let regType = WordSize.toRegType wordSize
  let fRegType = WordSize.toRegType WordSize.Bit32

  member val G0 = var regType (Register.toRegID Register.G0) "g0" with get
  member val G1 = var regType (Register.toRegID Register.G1) "g1" with get
  member val G2 = var regType (Register.toRegID Register.G2) "g2" with get
  member val G3 = var regType (Register.toRegID Register.G3) "g3" with get
  member val G4 = var regType (Register.toRegID Register.G4) "g4" with get
  member val G5 = var regType (Register.toRegID Register.G1) "g5" with get
  member val G6 = var regType (Register.toRegID Register.G6) "g6" with get
  member val G7 = var regType (Register.toRegID Register.G1) "g7" with get
  member val O0 = var regType (Register.toRegID Register.O0) "o0" with get
  member val O1 = var regType (Register.toRegID Register.O1) "o1" with get
  member val O2 = var regType (Register.toRegID Register.O2) "o2" with get
  member val O3 = var regType (Register.toRegID Register.O3) "o3" with get
  member val O4 = var regType (Register.toRegID Register.O4) "o4" with get
  member val O5 = var regType (Register.toRegID Register.O5) "o5" with get
  member val O6 = var regType (Register.toRegID Register.O6) "o6" with get
  member val O7 = var regType (Register.toRegID Register.O7) "o7" with get
  member val L0 = var regType (Register.toRegID Register.L0) "l0" with get
  member val L1 = var regType (Register.toRegID Register.L1) "l1" with get
  member val L2 = var regType (Register.toRegID Register.L2) "l2" with get
  member val L3 = var regType (Register.toRegID Register.L3) "l3" with get
  member val L4 = var regType (Register.toRegID Register.L4) "l4" with get
  member val L5 = var regType (Register.toRegID Register.L5) "l5" with get
  member val L6 = var regType (Register.toRegID Register.L6) "l6" with get
  member val L7 = var regType (Register.toRegID Register.L7) "l7" with get
  member val I0 = var regType (Register.toRegID Register.I0) "i0" with get
  member val I1 = var regType (Register.toRegID Register.I1) "i1" with get
  member val I2 = var regType (Register.toRegID Register.I2) "i2" with get
  member val I3 = var regType (Register.toRegID Register.I3) "i3" with get
  member val I4 = var regType (Register.toRegID Register.I4) "i4" with get
  member val I5 = var regType (Register.toRegID Register.I5) "i5" with get
  member val I6 = var regType (Register.toRegID Register.I6) "i6" with get
  member val I7 = var regType (Register.toRegID Register.I7) "i7" with get
  member val F0 = var fRegType (Register.toRegID Register.F0) "f0" with get
  member val F1 = var fRegType (Register.toRegID Register.F1) "f1" with get
  member val F2 = var fRegType (Register.toRegID Register.F2) "f2" with get
  member val F3 = var fRegType (Register.toRegID Register.F3) "f3" with get
  member val F4 = var fRegType (Register.toRegID Register.F4) "f4" with get
  member val F5 = var fRegType (Register.toRegID Register.F5) "f5" with get
  member val F6 = var fRegType (Register.toRegID Register.F6) "f6" with get
  member val F7 = var fRegType (Register.toRegID Register.F7) "f7" with get
  member val F8 = var fRegType (Register.toRegID Register.F8) "f8" with get
  member val F9 = var fRegType (Register.toRegID Register.F9) "f9" with get
  member val F10 = var fRegType (Register.toRegID Register.F10) "f10" with get
  member val F11 = var fRegType (Register.toRegID Register.F11) "f11" with get
  member val F12 = var fRegType (Register.toRegID Register.F12) "f12" with get
  member val F13 = var fRegType (Register.toRegID Register.F13) "f13" with get
  member val F14 = var fRegType (Register.toRegID Register.F14) "f14" with get
  member val F15 = var fRegType (Register.toRegID Register.F15) "f15" with get
  member val F16 = var fRegType (Register.toRegID Register.F16) "f16" with get
  member val F17 = var fRegType (Register.toRegID Register.F17) "f17" with get
  member val F18 = var fRegType (Register.toRegID Register.F18) "f18" with get
  member val F19 = var fRegType (Register.toRegID Register.F19) "f19" with get
  member val F20 = var fRegType (Register.toRegID Register.F20) "f20" with get
  member val F21 = var fRegType (Register.toRegID Register.F21) "f21" with get
  member val F22 = var fRegType (Register.toRegID Register.F22) "f22" with get
  member val F23 = var fRegType (Register.toRegID Register.F23) "f23" with get
  member val F24 = var fRegType (Register.toRegID Register.F24) "f24" with get
  member val F25 = var fRegType (Register.toRegID Register.F25) "f25" with get
  member val F26 = var fRegType (Register.toRegID Register.F26) "f26" with get
  member val F27 = var fRegType (Register.toRegID Register.F27) "f27" with get
  member val F28 = var fRegType (Register.toRegID Register.F28) "f28" with get
  member val F29 = var fRegType (Register.toRegID Register.F29) "f29" with get
  member val F30 = var fRegType (Register.toRegID Register.F30) "f30" with get
  member val F31 = var fRegType (Register.toRegID Register.F31) "f31" with get
  member val F32 = var regType (Register.toRegID Register.F32) "f32" with get
  member val F34 = var regType (Register.toRegID Register.F34) "f34" with get
  member val F36 = var regType (Register.toRegID Register.F36) "f36" with get
  member val F38 = var regType (Register.toRegID Register.F38) "f38" with get
  member val F40 = var regType (Register.toRegID Register.F40) "f40" with get
  member val F42 = var regType (Register.toRegID Register.F42) "f42" with get
  member val F44 = var regType (Register.toRegID Register.F44) "f44" with get
  member val F46 = var regType (Register.toRegID Register.F46) "f46" with get
  member val F48 = var regType (Register.toRegID Register.F48) "f48" with get
  member val F50 = var regType (Register.toRegID Register.F50) "f50" with get
  member val F52 = var regType (Register.toRegID Register.F52) "f52" with get
  member val F54 = var regType (Register.toRegID Register.F54) "f54" with get
  member val F56 = var regType (Register.toRegID Register.F56) "f56" with get
  member val F58 = var regType (Register.toRegID Register.F58) "f58" with get
  member val F60 = var regType (Register.toRegID Register.F60) "f60" with get
  member val F62 = var regType (Register.toRegID Register.F62) "f62" with get
  member val PC = var regType (Register.toRegID Register.PC) "PC" with get
  member val NPC = var regType (Register.toRegID Register.NPC) "nPC" with get
  member val Y = var regType (Register.toRegID Register.Y) "Y" with get
  member val CCR = var regType (Register.toRegID Register.CCR) "CCR" with get
  member val FSR = var regType (Register.toRegID Register.FSR) "FSR" with get
  member val ASI = var regType (Register.toRegID Register.ASI) "ASI" with get
  member val ASRs = var regType (Register.toRegID Register.ASRs) "ASRs" with get
  member val FPRS = var regType (Register.toRegID Register.FPRS) "FPRS" with get
  member val TICK = var regType (Register.toRegID Register.TICK) "TICK" with get
  member val PSTATE =
    var regType (Register.toRegID Register.PSTATE) "PSTATE" with get
  member val TL = var regType (Register.toRegID Register.TL) "TL" with get
  member val PIL = var regType (Register.toRegID Register.PIL) "PIL" with get
  member val TPC = var regType (Register.toRegID Register.TPC) "TPC" with get
  member val TNPC = var regType (Register.toRegID Register.TNPC) "TNPC" with get
  member val TSTATE =
    var regType (Register.toRegID Register.TSTATE) "TSTATE" with get
  member val TT = var regType (Register.toRegID Register.TT) "TT" with get
  member val TBA = var regType (Register.toRegID Register.TBA) "TBA" with get
  member val VER = var regType (Register.toRegID Register.VER) "VER" with get
  member val CWP = var regType (Register.toRegID Register.CWP) "CWP" with get
  member val CANSAVE =
    var regType (Register.toRegID Register.CANSAVE) "CANSAVE" with get
  member val CANRESTORE =
    var regType (Register.toRegID Register.CANRESTORE) "CANRESTORE" with get
  member val OTHERWIN =
    var regType (Register.toRegID Register.OTHERWIN) "OTHERWIN" with get
  member val WSTATE =
    var regType (Register.toRegID Register.WSTATE) "WSTATE" with get
  member val FQ = var regType (Register.toRegID Register.FQ) "FQ" with get
  member val CLEANWIN =
    var regType (Register.toRegID Register.CLEANWIN) "CLEANWIN" with get

  member __.GetRegVar (name) =
    match name with
    | R.G0 -> __.G0
    | R.G1 -> __.G1
    | R.G2 -> __.G2
    | R.G3 -> __.G3
    | R.G4 -> __.G4
    | R.G5 -> __.G5
    | R.G6 -> __.G6
    | R.G7 -> __.G7
    | R.O0 -> __.O0
    | R.O1 -> __.O1
    | R.O2 -> __.O2
    | R.O3 -> __.O3
    | R.O4 -> __.O4
    | R.O5 -> __.O5
    | R.O6 -> __.O6
    | R.O7 -> __.O7
    | R.L0 -> __.L0
    | R.L1 -> __.L1
    | R.L2 -> __.L2
    | R.L3 -> __.L3
    | R.L4 -> __.L4
    | R.L5 -> __.L5
    | R.L6 -> __.L6
    | R.L7 -> __.L7
    | R.I0 -> __.I0
    | R.I1 -> __.I1
    | R.I2 -> __.I2
    | R.I3 -> __.I3
    | R.I4 -> __.I4
    | R.I5 -> __.I5
    | R.I6 -> __.I6
    | R.I7 -> __.I7
    | R.PC -> __.PC
    | R.CCR -> __.CCR
    | R.FSR -> __.FSR
    | R.Y -> __.Y
    | R.F0 -> __.F0
    | R.F1 -> __.F1
    | R.F2 -> __.F2
    | R.F3 -> __.F3
    | R.F4 -> __.F4
    | R.F5 -> __.F5
    | R.F6 -> __.F6
    | R.F7 -> __.F7
    | R.F8 -> __.F8
    | R.F9 -> __.F9
    | R.F10 -> __.F10
    | R.F11 -> __.F11
    | R.F12 -> __.F12
    | R.F13 -> __.F13
    | R.F14 -> __.F14
    | R.F15 -> __.F15
    | R.F16 -> __.F16
    | R.F17 -> __.F17
    | R.F18 -> __.F18
    | R.F19 -> __.F19
    | R.F20 -> __.F20
    | R.F21 -> __.F21
    | R.F22 -> __.F22
    | R.F23 -> __.F23
    | R.F24 -> __.F24
    | R.F25 -> __.F25
    | R.F26 -> __.F26
    | R.F27 -> __.F27
    | R.F28 -> __.F28
    | R.F29 -> __.F29
    | R.F30 -> __.F30
    | R.F31 -> __.F31
    | R.F32 -> __.F32
    | R.F34 -> __.F34
    | R.F36 -> __.F36
    | R.F38 -> __.F38
    | R.F40 -> __.F40
    | R.F42 -> __.F42
    | R.F44 -> __.F44
    | R.F46 -> __.F46
    | R.F48 -> __.F48
    | R.F50 -> __.F50
    | R.F52 -> __.F52
    | R.F54 -> __.F54
    | R.F56 -> __.F56
    | R.F58 -> __.F58
    | R.F60 -> __.F60
    | R.F62 -> __.F62
    | R.ASI -> __.ASI
    | R.ASRs -> __.ASRs
    | R.FPRS -> __.FPRS
    | R.TICK -> __.TICK
    | R.PSTATE -> __.PSTATE
    | R.TL -> __.TL
    | R.PIL -> __.PIL
    | R.TPC -> __.TPC
    | R.TNPC -> __.TNPC
    | R.TSTATE -> __.TSTATE
    | R.TT -> __.TT
    | R.TBA -> __.TBA
    | R.VER -> __.VER
    | R.CWP -> __.CWP
    | R.CANSAVE -> __.CANSAVE
    | R.CANRESTORE -> __.CANRESTORE
    | R.OTHERWIN -> __.OTHERWIN
    | R.WSTATE -> __.WSTATE
    | R.FQ -> __.FQ
    | R.CLEANWIN -> __.CLEANWIN
    | _ -> raise UnhandledRegExprException

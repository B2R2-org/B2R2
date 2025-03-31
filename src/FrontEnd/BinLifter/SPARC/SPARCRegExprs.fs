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
open B2R2.FrontEnd
open B2R2.FrontEnd.Register
open B2R2.BinIR.LowUIR

type RegExprs (wordSize) =
  let var sz t name = AST.var sz t name

  (* SPARC. *)
  let regType = WordSize.toRegType wordSize
  let fRegType = WordSize.toRegType WordSize.Bit32

  member val G0 = var regType (SPARCRegister.ID SPARC.G0) "g0" with get
  member val G1 = var regType (SPARCRegister.ID SPARC.G1) "g1" with get
  member val G2 = var regType (SPARCRegister.ID SPARC.G2) "g2" with get
  member val G3 = var regType (SPARCRegister.ID SPARC.G3) "g3" with get
  member val G4 = var regType (SPARCRegister.ID SPARC.G4) "g4" with get
  member val G5 = var regType (SPARCRegister.ID SPARC.G1) "g5" with get
  member val G6 = var regType (SPARCRegister.ID SPARC.G6) "g6" with get
  member val G7 = var regType (SPARCRegister.ID SPARC.G1) "g7" with get
  member val O0 = var regType (SPARCRegister.ID SPARC.O0) "o0" with get
  member val O1 = var regType (SPARCRegister.ID SPARC.O1) "o1" with get
  member val O2 = var regType (SPARCRegister.ID SPARC.O2) "o2" with get
  member val O3 = var regType (SPARCRegister.ID SPARC.O3) "o3" with get
  member val O4 = var regType (SPARCRegister.ID SPARC.O4) "o4" with get
  member val O5 = var regType (SPARCRegister.ID SPARC.O5) "o5" with get
  member val O6 = var regType (SPARCRegister.ID SPARC.O6) "o6" with get
  member val O7 = var regType (SPARCRegister.ID SPARC.O7) "o7" with get
  member val L0 = var regType (SPARCRegister.ID SPARC.L0) "l0" with get
  member val L1 = var regType (SPARCRegister.ID SPARC.L1) "l1" with get
  member val L2 = var regType (SPARCRegister.ID SPARC.L2) "l2" with get
  member val L3 = var regType (SPARCRegister.ID SPARC.L3) "l3" with get
  member val L4 = var regType (SPARCRegister.ID SPARC.L4) "l4" with get
  member val L5 = var regType (SPARCRegister.ID SPARC.L5) "l5" with get
  member val L6 = var regType (SPARCRegister.ID SPARC.L6) "l6" with get
  member val L7 = var regType (SPARCRegister.ID SPARC.L7) "l7" with get
  member val I0 = var regType (SPARCRegister.ID SPARC.I0) "i0" with get
  member val I1 = var regType (SPARCRegister.ID SPARC.I1) "i1" with get
  member val I2 = var regType (SPARCRegister.ID SPARC.I2) "i2" with get
  member val I3 = var regType (SPARCRegister.ID SPARC.I3) "i3" with get
  member val I4 = var regType (SPARCRegister.ID SPARC.I4) "i4" with get
  member val I5 = var regType (SPARCRegister.ID SPARC.I5) "i5" with get
  member val I6 = var regType (SPARCRegister.ID SPARC.I6) "i6" with get
  member val I7 = var regType (SPARCRegister.ID SPARC.I7) "i7" with get
  member val F0 = var fRegType (SPARCRegister.ID SPARC.F0) "f0" with get
  member val F1 = var fRegType (SPARCRegister.ID SPARC.F1) "f1" with get
  member val F2 = var fRegType (SPARCRegister.ID SPARC.F2) "f2" with get
  member val F3 = var fRegType (SPARCRegister.ID SPARC.F3) "f3" with get
  member val F4 = var fRegType (SPARCRegister.ID SPARC.F4) "f4" with get
  member val F5 = var fRegType (SPARCRegister.ID SPARC.F5) "f5" with get
  member val F6 = var fRegType (SPARCRegister.ID SPARC.F6) "f6" with get
  member val F7 = var fRegType (SPARCRegister.ID SPARC.F7) "f7" with get
  member val F8 = var fRegType (SPARCRegister.ID SPARC.F8) "f8" with get
  member val F9 = var fRegType (SPARCRegister.ID SPARC.F9) "f9" with get
  member val F10 = var fRegType (SPARCRegister.ID SPARC.F10) "f10" with get
  member val F11 = var fRegType (SPARCRegister.ID SPARC.F11) "f11" with get
  member val F12 = var fRegType (SPARCRegister.ID SPARC.F12) "f12" with get
  member val F13 = var fRegType (SPARCRegister.ID SPARC.F13) "f13" with get
  member val F14 = var fRegType (SPARCRegister.ID SPARC.F14) "f14" with get
  member val F15 = var fRegType (SPARCRegister.ID SPARC.F15) "f15" with get
  member val F16 = var fRegType (SPARCRegister.ID SPARC.F16) "f16" with get
  member val F17 = var fRegType (SPARCRegister.ID SPARC.F17) "f17" with get
  member val F18 = var fRegType (SPARCRegister.ID SPARC.F18) "f18" with get
  member val F19 = var fRegType (SPARCRegister.ID SPARC.F19) "f19" with get
  member val F20 = var fRegType (SPARCRegister.ID SPARC.F20) "f20" with get
  member val F21 = var fRegType (SPARCRegister.ID SPARC.F21) "f21" with get
  member val F22 = var fRegType (SPARCRegister.ID SPARC.F22) "f22" with get
  member val F23 = var fRegType (SPARCRegister.ID SPARC.F23) "f23" with get
  member val F24 = var fRegType (SPARCRegister.ID SPARC.F24) "f24" with get
  member val F25 = var fRegType (SPARCRegister.ID SPARC.F25) "f25" with get
  member val F26 = var fRegType (SPARCRegister.ID SPARC.F26) "f26" with get
  member val F27 = var fRegType (SPARCRegister.ID SPARC.F27) "f27" with get
  member val F28 = var fRegType (SPARCRegister.ID SPARC.F28) "f28" with get
  member val F29 = var fRegType (SPARCRegister.ID SPARC.F29) "f29" with get
  member val F30 = var fRegType (SPARCRegister.ID SPARC.F30) "f30" with get
  member val F31 = var fRegType (SPARCRegister.ID SPARC.F31) "f31" with get
  member val F32 = var regType (SPARCRegister.ID SPARC.F32) "f32" with get
  member val F34 = var regType (SPARCRegister.ID SPARC.F34) "f34" with get
  member val F36 = var regType (SPARCRegister.ID SPARC.F36) "f36" with get
  member val F38 = var regType (SPARCRegister.ID SPARC.F38) "f38" with get
  member val F40 = var regType (SPARCRegister.ID SPARC.F40) "f40" with get
  member val F42 = var regType (SPARCRegister.ID SPARC.F42) "f42" with get
  member val F44 = var regType (SPARCRegister.ID SPARC.F44) "f44" with get
  member val F46 = var regType (SPARCRegister.ID SPARC.F46) "f46" with get
  member val F48 = var regType (SPARCRegister.ID SPARC.F48) "f48" with get
  member val F50 = var regType (SPARCRegister.ID SPARC.F50) "f50" with get
  member val F52 = var regType (SPARCRegister.ID SPARC.F52) "f52" with get
  member val F54 = var regType (SPARCRegister.ID SPARC.F54) "f54" with get
  member val F56 = var regType (SPARCRegister.ID SPARC.F56) "f56" with get
  member val F58 = var regType (SPARCRegister.ID SPARC.F58) "f58" with get
  member val F60 = var regType (SPARCRegister.ID SPARC.F60) "f60" with get
  member val F62 = var regType (SPARCRegister.ID SPARC.F62) "f62" with get
  member val PC = var regType (SPARCRegister.ID SPARC.PC) "PC" with get
  member val NPC = var regType (SPARCRegister.ID SPARC.NPC) "nPC" with get
  member val Y = var regType (SPARCRegister.ID SPARC.Y) "Y" with get
  member val CCR = var regType (SPARCRegister.ID SPARC.CCR) "CCR" with get
  member val FSR = var regType (SPARCRegister.ID SPARC.FSR) "FSR" with get
  member val ASI = var regType (SPARCRegister.ID SPARC.ASI) "ASI" with get
  member val ASRs = var regType (SPARCRegister.ID SPARC.ASRs) "ASRs" with get
  member val FPRS = var regType (SPARCRegister.ID SPARC.FPRS) "FPRS" with get
  member val TICK = var regType (SPARCRegister.ID SPARC.TICK) "TICK" with get
  member val PSTATE =
    var regType (SPARCRegister.ID SPARC.PSTATE) "PSTATE" with get
  member val TL = var regType (SPARCRegister.ID SPARC.TL) "TL" with get
  member val PIL = var regType (SPARCRegister.ID SPARC.PIL) "PIL" with get
  member val TPC = var regType (SPARCRegister.ID SPARC.TPC) "TPC" with get
  member val TNPC = var regType (SPARCRegister.ID SPARC.TNPC) "TNPC" with get
  member val TSTATE =
    var regType (SPARCRegister.ID SPARC.TSTATE) "TSTATE" with get
  member val TT = var regType (SPARCRegister.ID SPARC.TT) "TT" with get
  member val TBA = var regType (SPARCRegister.ID SPARC.TBA) "TBA" with get
  member val VER = var regType (SPARCRegister.ID SPARC.VER) "VER" with get
  member val CWP = var regType (SPARCRegister.ID SPARC.CWP) "CWP" with get
  member val CANSAVE =
    var regType (SPARCRegister.ID SPARC.CANSAVE) "CANSAVE" with get
  member val CANRESTORE =
    var regType (SPARCRegister.ID SPARC.CANRESTORE) "CANRESTORE" with get
  member val OTHERWIN =
    var regType (SPARCRegister.ID SPARC.OTHERWIN) "OTHERWIN" with get
  member val WSTATE =
    var regType (SPARCRegister.ID SPARC.WSTATE) "WSTATE" with get
  member val FQ = var regType (SPARCRegister.ID SPARC.FQ) "FQ" with get
  member val CLEANWIN =
    var regType (SPARCRegister.ID SPARC.CLEANWIN) "CLEANWIN" with get

  member __.GetRegVar (name) =
    match name with
    | SPARC.G0 -> __.G0
    | SPARC.G1 -> __.G1
    | SPARC.G2 -> __.G2
    | SPARC.G3 -> __.G3
    | SPARC.G4 -> __.G4
    | SPARC.G5 -> __.G5
    | SPARC.G6 -> __.G6
    | SPARC.G7 -> __.G7
    | SPARC.O0 -> __.O0
    | SPARC.O1 -> __.O1
    | SPARC.O2 -> __.O2
    | SPARC.O3 -> __.O3
    | SPARC.O4 -> __.O4
    | SPARC.O5 -> __.O5
    | SPARC.O6 -> __.O6
    | SPARC.O7 -> __.O7
    | SPARC.L0 -> __.L0
    | SPARC.L1 -> __.L1
    | SPARC.L2 -> __.L2
    | SPARC.L3 -> __.L3
    | SPARC.L4 -> __.L4
    | SPARC.L5 -> __.L5
    | SPARC.L6 -> __.L6
    | SPARC.L7 -> __.L7
    | SPARC.I0 -> __.I0
    | SPARC.I1 -> __.I1
    | SPARC.I2 -> __.I2
    | SPARC.I3 -> __.I3
    | SPARC.I4 -> __.I4
    | SPARC.I5 -> __.I5
    | SPARC.I6 -> __.I6
    | SPARC.I7 -> __.I7
    | SPARC.PC -> __.PC
    | SPARC.CCR -> __.CCR
    | SPARC.FSR -> __.FSR
    | SPARC.Y -> __.Y
    | SPARC.F0 -> __.F0
    | SPARC.F1 -> __.F1
    | SPARC.F2 -> __.F2
    | SPARC.F3 -> __.F3
    | SPARC.F4 -> __.F4
    | SPARC.F5 -> __.F5
    | SPARC.F6 -> __.F6
    | SPARC.F7 -> __.F7
    | SPARC.F8 -> __.F8
    | SPARC.F9 -> __.F9
    | SPARC.F10 -> __.F10
    | SPARC.F11 -> __.F11
    | SPARC.F12 -> __.F12
    | SPARC.F13 -> __.F13
    | SPARC.F14 -> __.F14
    | SPARC.F15 -> __.F15
    | SPARC.F16 -> __.F16
    | SPARC.F17 -> __.F17
    | SPARC.F18 -> __.F18
    | SPARC.F19 -> __.F19
    | SPARC.F20 -> __.F20
    | SPARC.F21 -> __.F21
    | SPARC.F22 -> __.F22
    | SPARC.F23 -> __.F23
    | SPARC.F24 -> __.F24
    | SPARC.F25 -> __.F25
    | SPARC.F26 -> __.F26
    | SPARC.F27 -> __.F27
    | SPARC.F28 -> __.F28
    | SPARC.F29 -> __.F29
    | SPARC.F30 -> __.F30
    | SPARC.F31 -> __.F31
    | SPARC.F32 -> __.F32
    | SPARC.F34 -> __.F34
    | SPARC.F36 -> __.F36
    | SPARC.F38 -> __.F38
    | SPARC.F40 -> __.F40
    | SPARC.F42 -> __.F42
    | SPARC.F44 -> __.F44
    | SPARC.F46 -> __.F46
    | SPARC.F48 -> __.F48
    | SPARC.F50 -> __.F50
    | SPARC.F52 -> __.F52
    | SPARC.F54 -> __.F54
    | SPARC.F56 -> __.F56
    | SPARC.F58 -> __.F58
    | SPARC.F60 -> __.F60
    | SPARC.F62 -> __.F62
    | SPARC.ASI -> __.ASI
    | SPARC.ASRs -> __.ASRs
    | SPARC.FPRS -> __.FPRS
    | SPARC.TICK -> __.TICK
    | SPARC.PSTATE -> __.PSTATE
    | SPARC.TL -> __.TL
    | SPARC.PIL -> __.PIL
    | SPARC.TPC -> __.TPC
    | SPARC.TNPC -> __.TNPC
    | SPARC.TSTATE -> __.TSTATE
    | SPARC.TT -> __.TT
    | SPARC.TBA -> __.TBA
    | SPARC.VER -> __.VER
    | SPARC.CWP -> __.CWP
    | SPARC.CANSAVE -> __.CANSAVE
    | SPARC.CANRESTORE -> __.CANRESTORE
    | SPARC.OTHERWIN -> __.OTHERWIN
    | SPARC.WSTATE -> __.WSTATE
    | SPARC.FQ -> __.FQ
    | SPARC.CLEANWIN -> __.CLEANWIN
    | _ -> raise UnhandledRegExprException

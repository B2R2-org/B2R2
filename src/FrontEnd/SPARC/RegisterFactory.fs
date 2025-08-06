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

open System.Runtime.CompilerServices
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR
open type Register

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.SPARC.Tests")>]
do ()

/// Represents a factory for accessing various SPARC register variables.
type RegisterFactory(wordSize) =
  let rt = WordSize.toRegType wordSize
  let fRegType = WordSize.toRegType WordSize.Bit32

  let g0 = AST.var rt (Register.toRegID G0) "g0"
  let g1 = AST.var rt (Register.toRegID G1) "g1"
  let g2 = AST.var rt (Register.toRegID G2) "g2"
  let g3 = AST.var rt (Register.toRegID G3) "g3"
  let g4 = AST.var rt (Register.toRegID G4) "g4"
  let g5 = AST.var rt (Register.toRegID G1) "g5"
  let g6 = AST.var rt (Register.toRegID G6) "g6"
  let g7 = AST.var rt (Register.toRegID G1) "g7"
  let o0 = AST.var rt (Register.toRegID O0) "o0"
  let o1 = AST.var rt (Register.toRegID O1) "o1"
  let o2 = AST.var rt (Register.toRegID O2) "o2"
  let o3 = AST.var rt (Register.toRegID O3) "o3"
  let o4 = AST.var rt (Register.toRegID O4) "o4"
  let o5 = AST.var rt (Register.toRegID O5) "o5"
  let o6 = AST.var rt (Register.toRegID O6) "o6"
  let o7 = AST.var rt (Register.toRegID O7) "o7"
  let l0 = AST.var rt (Register.toRegID L0) "l0"
  let l1 = AST.var rt (Register.toRegID L1) "l1"
  let l2 = AST.var rt (Register.toRegID L2) "l2"
  let l3 = AST.var rt (Register.toRegID L3) "l3"
  let l4 = AST.var rt (Register.toRegID L4) "l4"
  let l5 = AST.var rt (Register.toRegID L5) "l5"
  let l6 = AST.var rt (Register.toRegID L6) "l6"
  let l7 = AST.var rt (Register.toRegID L7) "l7"
  let i0 = AST.var rt (Register.toRegID I0) "i0"
  let i1 = AST.var rt (Register.toRegID I1) "i1"
  let i2 = AST.var rt (Register.toRegID I2) "i2"
  let i3 = AST.var rt (Register.toRegID I3) "i3"
  let i4 = AST.var rt (Register.toRegID I4) "i4"
  let i5 = AST.var rt (Register.toRegID I5) "i5"
  let i6 = AST.var rt (Register.toRegID I6) "i6"
  let i7 = AST.var rt (Register.toRegID I7) "i7"
  let f0 = AST.var fRegType (Register.toRegID F0) "f0"
  let f1 = AST.var fRegType (Register.toRegID F1) "f1"
  let f2 = AST.var fRegType (Register.toRegID F2) "f2"
  let f3 = AST.var fRegType (Register.toRegID F3) "f3"
  let f4 = AST.var fRegType (Register.toRegID F4) "f4"
  let f5 = AST.var fRegType (Register.toRegID F5) "f5"
  let f6 = AST.var fRegType (Register.toRegID F6) "f6"
  let f7 = AST.var fRegType (Register.toRegID F7) "f7"
  let f8 = AST.var fRegType (Register.toRegID F8) "f8"
  let f9 = AST.var fRegType (Register.toRegID F9) "f9"
  let f10 = AST.var fRegType (Register.toRegID F10) "f10"
  let f11 = AST.var fRegType (Register.toRegID F11) "f11"
  let f12 = AST.var fRegType (Register.toRegID F12) "f12"
  let f13 = AST.var fRegType (Register.toRegID F13) "f13"
  let f14 = AST.var fRegType (Register.toRegID F14) "f14"
  let f15 = AST.var fRegType (Register.toRegID F15) "f15"
  let f16 = AST.var fRegType (Register.toRegID F16) "f16"
  let f17 = AST.var fRegType (Register.toRegID F17) "f17"
  let f18 = AST.var fRegType (Register.toRegID F18) "f18"
  let f19 = AST.var fRegType (Register.toRegID F19) "f19"
  let f20 = AST.var fRegType (Register.toRegID F20) "f20"
  let f21 = AST.var fRegType (Register.toRegID F21) "f21"
  let f22 = AST.var fRegType (Register.toRegID F22) "f22"
  let f23 = AST.var fRegType (Register.toRegID F23) "f23"
  let f24 = AST.var fRegType (Register.toRegID F24) "f24"
  let f25 = AST.var fRegType (Register.toRegID F25) "f25"
  let f26 = AST.var fRegType (Register.toRegID F26) "f26"
  let f27 = AST.var fRegType (Register.toRegID F27) "f27"
  let f28 = AST.var fRegType (Register.toRegID F28) "f28"
  let f29 = AST.var fRegType (Register.toRegID F29) "f29"
  let f30 = AST.var fRegType (Register.toRegID F30) "f30"
  let f31 = AST.var fRegType (Register.toRegID F31) "f31"
  let f32 = AST.var rt (Register.toRegID F32) "f32"
  let f34 = AST.var rt (Register.toRegID F34) "f34"
  let f36 = AST.var rt (Register.toRegID F36) "f36"
  let f38 = AST.var rt (Register.toRegID F38) "f38"
  let f40 = AST.var rt (Register.toRegID F40) "f40"
  let f42 = AST.var rt (Register.toRegID F42) "f42"
  let f44 = AST.var rt (Register.toRegID F44) "f44"
  let f46 = AST.var rt (Register.toRegID F46) "f46"
  let f48 = AST.var rt (Register.toRegID F48) "f48"
  let f50 = AST.var rt (Register.toRegID F50) "f50"
  let f52 = AST.var rt (Register.toRegID F52) "f52"
  let f54 = AST.var rt (Register.toRegID F54) "f54"
  let f56 = AST.var rt (Register.toRegID F56) "f56"
  let f58 = AST.var rt (Register.toRegID F58) "f58"
  let f60 = AST.var rt (Register.toRegID F60) "f60"
  let f62 = AST.var rt (Register.toRegID F62) "f62"
  let pc = AST.var rt (Register.toRegID PC) "PC"
  let npc = AST.var rt (Register.toRegID NPC) "nPC"
  let y = AST.var rt (Register.toRegID Y) "Y"
  let ccr = AST.var rt (Register.toRegID CCR) "CCR"
  let fsr = AST.var rt (Register.toRegID FSR) "FSR"
  let asi = AST.var rt (Register.toRegID ASI) "ASI"
  let asrs = AST.var rt (Register.toRegID ASRs) "ASRs"
  let fprs = AST.var rt (Register.toRegID FPRS) "FPRS"
  let tick = AST.var rt (Register.toRegID TICK) "TICK"
  let pstate = AST.var rt (Register.toRegID PSTATE) "PSTATE"
  let tl = AST.var rt (Register.toRegID TL) "TL"
  let pil = AST.var rt (Register.toRegID PIL) "PIL"
  let tpc = AST.var rt (Register.toRegID TPC) "TPC"
  let tnpc = AST.var rt (Register.toRegID TNPC) "TNPC"
  let tstate = AST.var rt (Register.toRegID TSTATE) "TSTATE"
  let tt = AST.var rt (Register.toRegID TT) "TT"
  let tba = AST.var rt (Register.toRegID TBA) "TBA"
  let ver = AST.var rt (Register.toRegID VER) "VER"
  let cwp = AST.var rt (Register.toRegID CWP) "CWP"
  let cansave = AST.var rt (Register.toRegID CANSAVE) "CANSAVE"
  let canrestore = AST.var rt (Register.toRegID CANRESTORE) "CANRESTORE"
  let otherwin = AST.var rt (Register.toRegID OTHERWIN) "OTHERWIN"
  let wstate = AST.var rt (Register.toRegID WSTATE) "WSTATE"
  let fq = AST.var rt (Register.toRegID FQ) "FQ"
  let cleanwin = AST.var rt (Register.toRegID CLEANWIN) "CLEANWIN"

  interface IRegisterFactory with
    member _.GetRegVar rid =
      match Register.ofRegID rid with
      | Register.G0 -> g0
      | Register.G1 -> g1
      | Register.G2 -> g2
      | Register.G3 -> g3
      | Register.G4 -> g4
      | Register.G5 -> g5
      | Register.G6 -> g6
      | Register.G7 -> g7
      | Register.O0 -> o0
      | Register.O1 -> o1
      | Register.O2 -> o2
      | Register.O3 -> o3
      | Register.O4 -> o4
      | Register.O5 -> o5
      | Register.O6 -> o6
      | Register.O7 -> o7
      | Register.L0 -> l0
      | Register.L1 -> l1
      | Register.L2 -> l2
      | Register.L3 -> l3
      | Register.L4 -> l4
      | Register.L5 -> l5
      | Register.L6 -> l6
      | Register.L7 -> l7
      | Register.I0 -> i0
      | Register.I1 -> i1
      | Register.I2 -> i2
      | Register.I3 -> i3
      | Register.I4 -> i4
      | Register.I5 -> i5
      | Register.I6 -> i6
      | Register.I7 -> i7
      | Register.PC -> pc
      | Register.CCR -> ccr
      | Register.FSR -> fsr
      | Register.Y -> y
      | Register.F0 -> f0
      | Register.F1 -> f1
      | Register.F2 -> f2
      | Register.F3 -> f3
      | Register.F4 -> f4
      | Register.F5 -> f5
      | Register.F6 -> f6
      | Register.F7 -> f7
      | Register.F8 -> f8
      | Register.F9 -> f9
      | Register.F10 -> f10
      | Register.F11 -> f11
      | Register.F12 -> f12
      | Register.F13 -> f13
      | Register.F14 -> f14
      | Register.F15 -> f15
      | Register.F16 -> f16
      | Register.F17 -> f17
      | Register.F18 -> f18
      | Register.F19 -> f19
      | Register.F20 -> f20
      | Register.F21 -> f21
      | Register.F22 -> f22
      | Register.F23 -> f23
      | Register.F24 -> f24
      | Register.F25 -> f25
      | Register.F26 -> f26
      | Register.F27 -> f27
      | Register.F28 -> f28
      | Register.F29 -> f29
      | Register.F30 -> f30
      | Register.F31 -> f31
      | Register.F32 -> f32
      | Register.F34 -> f34
      | Register.F36 -> f36
      | Register.F38 -> f38
      | Register.F40 -> f40
      | Register.F42 -> f42
      | Register.F44 -> f44
      | Register.F46 -> f46
      | Register.F48 -> f48
      | Register.F50 -> f50
      | Register.F52 -> f52
      | Register.F54 -> f54
      | Register.F56 -> f56
      | Register.F58 -> f58
      | Register.F60 -> f60
      | Register.F62 -> f62
      | Register.ASI -> asi
      | Register.ASRs -> asrs
      | Register.FPRS -> fprs
      | Register.TICK -> tick
      | Register.PSTATE -> pstate
      | Register.TL -> tl
      | Register.PIL -> pil
      | Register.TPC -> tpc
      | Register.TNPC -> tnpc
      | Register.TSTATE -> tstate
      | Register.TT -> tt
      | Register.TBA -> tba
      | Register.VER -> ver
      | Register.CWP -> cwp
      | Register.CANSAVE -> cansave
      | Register.CANRESTORE -> canrestore
      | Register.OTHERWIN -> otherwin
      | Register.WSTATE -> wstate
      | Register.FQ -> fq
      | Register.CLEANWIN -> cleanwin
      | _ -> raise InvalidRegisterException

    member _.GetRegVar(_: string): Expr = Terminator.futureFeature ()

    member _.GetPseudoRegVar(_id, _idx) = Terminator.impossible ()

    member _.GetAllRegVars() = Terminator.futureFeature ()

    member _.GetGeneralRegVars() = Terminator.futureFeature ()

    member _.GetRegisterID expr =
      match expr with
      | Var(_, id, _, _) -> id
      | PCVar _ -> Register.toRegID PC
      | _ -> raise InvalidRegisterException

    member _.GetRegisterID(_: string): RegisterID = Terminator.futureFeature ()

    member _.GetRegisterIDAliases _ = Terminator.futureFeature ()

    member _.GetRegString _ = Terminator.futureFeature ()

    member _.GetAllRegStrings() = Terminator.futureFeature ()

    member _.GetRegType _ = Terminator.futureFeature ()

    member _.ProgramCounter = PC |> Register.toRegID

    member _.StackPointer = O6 |> Register.toRegID |> Some

    member _.FramePointer = I6 |> Register.toRegID |> Some

    member _.IsProgramCounter regid =
      Register.toRegID PC = regid

    member _.IsStackPointer regid =
      Register.toRegID O6 = regid

    member _.IsFramePointer regid =
      Register.toRegID I6 = regid

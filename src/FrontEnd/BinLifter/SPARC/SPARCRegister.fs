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

type Register =
  | G0 = 0x0
  | G1 = 0x1
  | G2 = 0x2
  | G3 = 0x3
  | G4 = 0x4
  | G5 = 0x5
  | G6 = 0x6
  | G7 = 0x7
  | O0 = 0x8
  | O1 = 0x9
  | O2 = 0xA
  | O3 = 0xB
  | O4 = 0xC
  | O5 = 0xD
  | O6 = 0xE
  | O7 = 0xF
  | L0 = 0x10
  | L1 = 0x11
  | L2 = 0x12
  | L3 = 0x13
  | L4 = 0x14
  | L5 = 0x15
  | L6 = 0x16
  | L7 = 0x17
  | I0 = 0x18
  | I1 = 0x19
  | I2 = 0x1A
  | I3 = 0x1B
  | I4 = 0x1C
  | I5 = 0x1D
  | I6 = 0x1E
  | I7 = 0x1F
  | PC = 0x20
  | NPC = 0x21
  | Y = 0x22
  | ASRs = 0x23
  | CCR = 0x24
  | FPRS = 0x25
  | FSR = 0x26
  | ASI = 0x27
  | TICK = 0x28
  | PSTATE = 0x29
  | TL = 0x2A
  | PIL = 0x2B
  | TPC = 0x2C
  | TNPC = 0x2D
  | TSTATE = 0x2E
  | TT = 0x2F
  | TBA = 0x30
  | VER = 0x31
  | CWP = 0x32
  | CANSAVE = 0x33
  | CANRESTORE = 0x34
  | OTHERWIN = 0x35
  | WSTATE = 0x36
  | FQ = 0x37
  | CLEANWIN = 0x38
  | F0 = 0x39
  | F1 = 0x3a
  | F2 = 0x3b
  | F3 = 0x3c
  | F4 = 0x3d
  | F5 = 0x3e
  | F6 = 0x3f
  | F7 = 0x40
  | F8 = 0x41
  | F9 = 0x42
  | F10 = 0x43
  | F11 = 0x44
  | F12 = 0x45
  | F13 = 0x46
  | F14 = 0x47
  | F15 = 0x48
  | F16 = 0x49
  | F17 = 0x4a
  | F18 = 0x4b
  | F19 = 0x4c
  | F20 = 0x4d
  | F21 = 0x4e
  | F22 = 0x4f
  | F23 = 0x50
  | F24 = 0x51
  | F25 = 0x52
  | F26 = 0x53
  | F27 = 0x54
  | F28 = 0x55
  | F29 = 0x56
  | F30 = 0x57
  | F31 = 0x58
  | F32 = 0x59
  | F34 = 0x5a
  | F36 = 0x5b
  | F38 = 0x5c
  | F40 = 0x5d
  | F42 = 0x5e
  | F44 = 0x5f
  | F46 = 0x60
  | F48 = 0x61
  | F50 = 0x62
  | F52 = 0x63
  | F54 = 0x64
  | F56 = 0x65
  | F58 = 0x66
  | F60 = 0x67
  | F62 = 0x68

/// Shortcut for Register type.
type internal R = Register

/// This module exposes several useful functions to handle SPARC
/// registers.
[<RequireQualifiedAccess>]
module Register =
  let inline ofRegID (n: RegisterID): Register =
    int n |> LanguagePrimitives.EnumOfValue

  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  let ofString (str: string) =
    match str.ToLowerInvariant () with
    | "g0" -> R.G0
    | "g1" -> R.G1
    | "g2" -> R.G2
    | "g3" -> R.G3
    | "g4" -> R.G4
    | "g5" -> R.G5
    | "g6" -> R.G6
    | "g7" -> R.G7
    | "O0" -> R.O0
    | "O1" -> R.O1
    | "O2" -> R.O2
    | "O3" -> R.O3
    | "O4" -> R.O4
    | "O5" -> R.O5
    | "O6" -> R.O6
    | "O7" -> R.O7
    | "l0" -> R.L0
    | "l1" -> R.L1
    | "l2" -> R.L2
    | "l3" -> R.L3
    | "l4" -> R.L4
    | "l5" -> R.L5
    | "l6" -> R.L6
    | "l7" -> R.L7
    | "i0" -> R.I0
    | "i1" -> R.I1
    | "i2" -> R.I2
    | "i3" -> R.I3
    | "i4" -> R.I4
    | "i5" -> R.I5
    | "i6" -> R.I6
    | "i7" -> R.I7
    | "pc" -> R.PC
    | "npc" -> R.NPC
    | "y" -> R.Y
    | "asrs" -> R.ASRs
    | "ccr" -> R.CCR
    | "fprs" -> R.FPRS
    | "fsr" -> R.FSR
    | "asi" -> R.ASI
    | "tick" -> R.TICK
    | "pstate" -> R.PSTATE
    | "tl" -> R.TL
    | "pil" -> R.PIL
    | "tpc" -> R.TPC
    | "tnpc" -> R.TNPC
    | "tstate" -> R.TSTATE
    | "tt" -> R.TT
    | "tba" -> R.TBA
    | "ver" -> R.VER
    | "cwp" -> R.CWP
    | "cansave" -> R.CANSAVE
    | "canrestore" -> R.CANRESTORE
    | "otherwin" -> R.OTHERWIN
    | "wstate" -> R.WSTATE
    | "fq" -> R.FQ
    | "cleanwin" -> R.CLEANWIN
    | "f0" -> R.F0
    | "f1" -> R.F1
    | "f2" -> R.F2
    | "f3" -> R.F3
    | "f4" -> R.F4
    | "f5" -> R.F5
    | "f6" -> R.F6
    | "f7" -> R.F7
    | "f8" -> R.F8
    | "f9" -> R.F9
    | "f10" -> R.F10
    | "f11" -> R.F11
    | "f12" -> R.F12
    | "f13" -> R.F13
    | "f14" -> R.F14
    | "f15" -> R.F15
    | "f16" -> R.F16
    | "f17" -> R.F17
    | "f18" -> R.F18
    | "f19" -> R.F19
    | "f20" -> R.F20
    | "f21" -> R.F21
    | "f22" -> R.F22
    | "f23" -> R.F23
    | "f24" -> R.F24
    | "f25" -> R.F25
    | "f26" -> R.F26
    | "f27" -> R.F27
    | "f28" -> R.F28
    | "f29" -> R.F29
    | "f30" -> R.F30
    | "f31" -> R.F31
    | "f32" -> R.F32
    | "f34" -> R.F34
    | "f36" -> R.F36
    | "f38" -> R.F38
    | "f40" -> R.F40
    | "f42" -> R.F42
    | "f44" -> R.F44
    | "f46" -> R.F46
    | "f48" -> R.F48
    | "f50" -> R.F50
    | "f52" -> R.F52
    | "f54" -> R.F54
    | "f56" -> R.F56
    | "f58" -> R.F58
    | "f60" -> R.F60
    | "f62" -> R.F62
    | _ -> Utils.impossible ()

  let toString = function
    | R.G0 -> "%g0"
    | R.G1 -> "%g1"
    | R.G2 -> "%g2"
    | R.G3 -> "%g3"
    | R.G4 -> "%g4"
    | R.G5 -> "%g5"
    | R.G6 -> "%g6"
    | R.G7 -> "%g7"
    | R.O0 -> "%o0"
    | R.O1 -> "%o1"
    | R.O2 -> "%o2"
    | R.O3 -> "%o3"
    | R.O4 -> "%o4"
    | R.O5 -> "%o5"
    | R.O6 -> "%o6"
    | R.O7 -> "%o7"
    | R.L0 -> "%l0"
    | R.L1 -> "%l1"
    | R.L2 -> "%l2"
    | R.L3 -> "%l3"
    | R.L4 -> "%l4"
    | R.L5 -> "%l5"
    | R.L6 -> "%l6"
    | R.L7 -> "%l7"
    | R.I0 -> "%i0"
    | R.I1 -> "%i1"
    | R.I2 -> "%i2"
    | R.I3 -> "%i3"
    | R.I4 -> "%i4"
    | R.I5 -> "%i5"
    | R.I6 -> "%i6"
    | R.I7 -> "%i7"
    | R.PC -> "PC"
    | R.NPC -> "nPC"
    | R.Y -> "Y"
    | R.ASRs -> "ASRs"
    | R.CCR -> "CCR"
    | R.FPRS -> "FPRS"
    | R.FSR -> "%fsr"
    | R.ASI -> "%asi"
    | R.TICK -> "TICK"
    | R.PSTATE -> "PSTATE"
    | R.TL -> "TL"
    | R.PIL -> "PIL"
    | R.TPC -> "TPC"
    | R.TNPC -> "TNPC"
    | R.TSTATE -> "TSTATE"
    | R.TT -> "TT"
    | R.TBA -> "TBA"
    | R.VER -> "VER"
    | R.CWP -> "CWP"
    | R.CANSAVE -> "CANSAVE"
    | R.CANRESTORE -> "CANRESTORE"
    | R.OTHERWIN -> "OTHERWIN"
    | R.WSTATE -> "WSTATE"
    | R.FQ -> "fq"
    | R.CLEANWIN -> "CLEANWIN"
    | R.F0 -> "%f0"
    | R.F1 -> "%f1"
    | R.F2 -> "%f2"
    | R.F3 -> "%f3"
    | R.F4 -> "%f4"
    | R.F5 -> "%f5"
    | R.F6 -> "%f6"
    | R.F7 -> "%f7"
    | R.F8 -> "%f8"
    | R.F9 -> "%f9"
    | R.F10 -> "%f10"
    | R.F11 -> "%f11"
    | R.F12 -> "%f12"
    | R.F13 -> "%f13"
    | R.F14 -> "%f14"
    | R.F15 -> "%f15"
    | R.F16 -> "%f16"
    | R.F17 -> "%f17"
    | R.F18 -> "%f18"
    | R.F19 -> "%f19"
    | R.F20 -> "%f20"
    | R.F21 -> "%f21"
    | R.F22 -> "%f22"
    | R.F23 -> "%f23"
    | R.F24 -> "%f24"
    | R.F25 -> "%f25"
    | R.F26 -> "%f26"
    | R.F27 -> "%f27"
    | R.F28 -> "%f28"
    | R.F29 -> "%f29"
    | R.F30 -> "%f30"
    | R.F31 -> "%f31"
    | R.F32 -> "%f32"
    | R.F34 -> "%f34"
    | R.F36 -> "%f36"
    | R.F38 -> "%f38"
    | R.F40 -> "%f40"
    | R.F42 -> "%f42"
    | R.F44 -> "%f44"
    | R.F46 -> "%f46"
    | R.F48 -> "%f48"
    | R.F50 -> "%f50"
    | R.F52 -> "%f52"
    | R.F54 -> "%f54"
    | R.F56 -> "%f56"
    | R.F58 -> "%f58"
    | R.F60 -> "%f60"
    | R.F62 -> "%f62"
    | _ -> Utils.impossible ()

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

/// <summary>
/// Represents registers for SPARC.<para/>
/// </summary>
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

/// Provides functions to handle SPARC registers.
module Register =
  /// Returns the SPARC register from a register ID.
  [<CompiledName "OfRegID">]
  let inline ofRegID (rid: RegisterID): Register =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Returns the SPARC register from a string representation.
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant () with
    | "g0" -> Register.G0
    | "g1" -> Register.G1
    | "g2" -> Register.G2
    | "g3" -> Register.G3
    | "g4" -> Register.G4
    | "g5" -> Register.G5
    | "g6" -> Register.G6
    | "g7" -> Register.G7
    | "o0" -> Register.O0
    | "o1" -> Register.O1
    | "o2" -> Register.O2
    | "o3" -> Register.O3
    | "o4" -> Register.O4
    | "o5" -> Register.O5
    | "o6" -> Register.O6
    | "o7" -> Register.O7
    | "l0" -> Register.L0
    | "l1" -> Register.L1
    | "l2" -> Register.L2
    | "l3" -> Register.L3
    | "l4" -> Register.L4
    | "l5" -> Register.L5
    | "l6" -> Register.L6
    | "l7" -> Register.L7
    | "i0" -> Register.I0
    | "i1" -> Register.I1
    | "i2" -> Register.I2
    | "i3" -> Register.I3
    | "i4" -> Register.I4
    | "i5" -> Register.I5
    | "i6" -> Register.I6
    | "i7" -> Register.I7
    | "pc" -> Register.PC
    | "npc" -> Register.NPC
    | "y" -> Register.Y
    | "asrs" -> Register.ASRs
    | "ccr" -> Register.CCR
    | "fprs" -> Register.FPRS
    | "fsr" -> Register.FSR
    | "asi" -> Register.ASI
    | "tick" -> Register.TICK
    | "pstate" -> Register.PSTATE
    | "tl" -> Register.TL
    | "pil" -> Register.PIL
    | "tpc" -> Register.TPC
    | "tnpc" -> Register.TNPC
    | "tstate" -> Register.TSTATE
    | "tt" -> Register.TT
    | "tba" -> Register.TBA
    | "ver" -> Register.VER
    | "cwp" -> Register.CWP
    | "cansave" -> Register.CANSAVE
    | "canrestore" -> Register.CANRESTORE
    | "otherwin" -> Register.OTHERWIN
    | "wstate" -> Register.WSTATE
    | "fq" -> Register.FQ
    | "cleanwin" -> Register.CLEANWIN
    | "f0" -> Register.F0
    | "f1" -> Register.F1
    | "f2" -> Register.F2
    | "f3" -> Register.F3
    | "f4" -> Register.F4
    | "f5" -> Register.F5
    | "f6" -> Register.F6
    | "f7" -> Register.F7
    | "f8" -> Register.F8
    | "f9" -> Register.F9
    | "f10" -> Register.F10
    | "f11" -> Register.F11
    | "f12" -> Register.F12
    | "f13" -> Register.F13
    | "f14" -> Register.F14
    | "f15" -> Register.F15
    | "f16" -> Register.F16
    | "f17" -> Register.F17
    | "f18" -> Register.F18
    | "f19" -> Register.F19
    | "f20" -> Register.F20
    | "f21" -> Register.F21
    | "f22" -> Register.F22
    | "f23" -> Register.F23
    | "f24" -> Register.F24
    | "f25" -> Register.F25
    | "f26" -> Register.F26
    | "f27" -> Register.F27
    | "f28" -> Register.F28
    | "f29" -> Register.F29
    | "f30" -> Register.F30
    | "f31" -> Register.F31
    | "f32" -> Register.F32
    | "f34" -> Register.F34
    | "f36" -> Register.F36
    | "f38" -> Register.F38
    | "f40" -> Register.F40
    | "f42" -> Register.F42
    | "f44" -> Register.F44
    | "f46" -> Register.F46
    | "f48" -> Register.F48
    | "f50" -> Register.F50
    | "f52" -> Register.F52
    | "f54" -> Register.F54
    | "f56" -> Register.F56
    | "f58" -> Register.F58
    | "f60" -> Register.F60
    | "f62" -> Register.F62
    | _ -> Terminator.impossible ()

  /// Returns the register ID of a SPARC register.
  [<CompiledName "ToRegID">]
  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  /// Returns the string representation of a SPARC register.
  [<CompiledName "ToString">]
  let toString reg =
    match reg with
    | Register.G0 -> "%g0"
    | Register.G1 -> "%g1"
    | Register.G2 -> "%g2"
    | Register.G3 -> "%g3"
    | Register.G4 -> "%g4"
    | Register.G5 -> "%g5"
    | Register.G6 -> "%g6"
    | Register.G7 -> "%g7"
    | Register.O0 -> "%o0"
    | Register.O1 -> "%o1"
    | Register.O2 -> "%o2"
    | Register.O3 -> "%o3"
    | Register.O4 -> "%o4"
    | Register.O5 -> "%o5"
    | Register.O6 -> "%o6"
    | Register.O7 -> "%o7"
    | Register.L0 -> "%l0"
    | Register.L1 -> "%l1"
    | Register.L2 -> "%l2"
    | Register.L3 -> "%l3"
    | Register.L4 -> "%l4"
    | Register.L5 -> "%l5"
    | Register.L6 -> "%l6"
    | Register.L7 -> "%l7"
    | Register.I0 -> "%i0"
    | Register.I1 -> "%i1"
    | Register.I2 -> "%i2"
    | Register.I3 -> "%i3"
    | Register.I4 -> "%i4"
    | Register.I5 -> "%i5"
    | Register.I6 -> "%i6"
    | Register.I7 -> "%i7"
    | Register.PC -> "pc"
    | Register.NPC -> "npc"
    | Register.Y -> "y"
    | Register.ASRs -> "asrs"
    | Register.CCR -> "ccr"
    | Register.FPRS -> "fprs"
    | Register.FSR -> "%fsr"
    | Register.ASI -> "%asi"
    | Register.TICK -> "%tick"
    | Register.PSTATE -> "%pstate"
    | Register.TL -> "%tl"
    | Register.PIL -> "%pil"
    | Register.TPC -> "%tpc"
    | Register.TNPC -> "%tnpc"
    | Register.TSTATE -> "%tstate"
    | Register.TT -> "%tt"
    | Register.TBA -> "%tba"
    | Register.VER -> "%ver"
    | Register.CWP -> "%cwp"
    | Register.CANSAVE -> "%cansave"
    | Register.CANRESTORE -> "%canrestore"
    | Register.OTHERWIN -> "%otherwin"
    | Register.WSTATE -> "%wstate"
    | Register.FQ -> "%fq"
    | Register.CLEANWIN -> "%cleanwin"
    | Register.F0 -> "%f0"
    | Register.F1 -> "%f1"
    | Register.F2 -> "%f2"
    | Register.F3 -> "%f3"
    | Register.F4 -> "%f4"
    | Register.F5 -> "%f5"
    | Register.F6 -> "%f6"
    | Register.F7 -> "%f7"
    | Register.F8 -> "%f8"
    | Register.F9 -> "%f9"
    | Register.F10 -> "%f10"
    | Register.F11 -> "%f11"
    | Register.F12 -> "%f12"
    | Register.F13 -> "%f13"
    | Register.F14 -> "%f14"
    | Register.F15 -> "%f15"
    | Register.F16 -> "%f16"
    | Register.F17 -> "%f17"
    | Register.F18 -> "%f18"
    | Register.F19 -> "%f19"
    | Register.F20 -> "%f20"
    | Register.F21 -> "%f21"
    | Register.F22 -> "%f22"
    | Register.F23 -> "%f23"
    | Register.F24 -> "%f24"
    | Register.F25 -> "%f25"
    | Register.F26 -> "%f26"
    | Register.F27 -> "%f27"
    | Register.F28 -> "%f28"
    | Register.F29 -> "%f29"
    | Register.F30 -> "%f30"
    | Register.F31 -> "%f31"
    | Register.F32 -> "%f32"
    | Register.F34 -> "%f34"
    | Register.F36 -> "%f36"
    | Register.F38 -> "%f38"
    | Register.F40 -> "%f40"
    | Register.F42 -> "%f42"
    | Register.F44 -> "%f44"
    | Register.F46 -> "%f46"
    | Register.F48 -> "%f48"
    | Register.F50 -> "%f50"
    | Register.F52 -> "%f52"
    | Register.F54 -> "%f54"
    | Register.F56 -> "%f56"
    | Register.F58 -> "%f58"
    | Register.F60 -> "%f60"
    | Register.F62 -> "%f62"
    | _ -> Terminator.impossible ()

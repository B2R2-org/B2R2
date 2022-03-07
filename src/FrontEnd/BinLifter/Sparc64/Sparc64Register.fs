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

namespace B2R2.FrontEnd.BinLifter.Sparc64

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
  | nPC = 0x21
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

/// Shortcut for Register type.
type internal R = Register

/// This module exposes several useful functions to handle Sparc64
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
    | "npc" -> R.nPC
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
    | _ -> Utils.impossible ()

  let toString = function
    | R.G0 -> "G0"
    | R.G1 -> "G1"
    | R.G2 -> "G2"
    | R.G3 -> "G3"
    | R.G4 -> "G4"
    | R.G5 -> "G5"
    | R.G6 -> "G6"
    | R.G7 -> "G7"
    | R.O0 -> "O0"
    | R.O1 -> "O1"
    | R.O2 -> "O2"
    | R.O3 -> "O3"
    | R.O4 -> "O4"
    | R.O5 -> "O5"
    | R.O6 -> "O6"
    | R.O7 -> "O7"
    | R.L0 -> "L0"
    | R.L1 -> "L1"
    | R.L2 -> "L2"
    | R.L3 -> "L3"
    | R.L4 -> "L4"
    | R.L5 -> "L5"
    | R.L6 -> "L6"
    | R.L7 -> "L7"
    | R.I0 -> "I0"
    | R.I1 -> "I1"
    | R.I2 -> "I2"
    | R.I3 -> "I3"
    | R.I4 -> "I4"
    | R.I5 -> "I5"
    | R.I6 -> "I6"
    | R.I7 -> "I7"
    | R.PC -> "PC"
    | R.nPC -> "nPC"
    | R.Y -> "Y"
    | R.ASRs -> "ASRs"
    | R.CCR -> "CCR"
    | R.FPRS -> "FPRS"
    | R.FSR -> "FSR"
    | R.ASI -> "ASI"
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
    | _ -> Utils.impossible ()

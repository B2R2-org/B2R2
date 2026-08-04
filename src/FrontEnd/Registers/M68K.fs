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

namespace B2R2.FrontEnd.M68K

open B2R2

/// <namespacedoc>
///   <summary>
///   Contains types and functions for working with the Motorola 68000 family
///   instructions.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents registers for m68k.<para/>
/// </summary>
type Register =
  /// Data register D0.
  | D0 = 0
  /// Data register D1.
  | D1 = 1
  /// Data register D2.
  | D2 = 2
  /// Data register D3.
  | D3 = 3
  /// Data register D4.
  | D4 = 4
  /// Data register D5.
  | D5 = 5
  /// Data register D6.
  | D6 = 6
  /// Data register D7.
  | D7 = 7
  /// Address register A0.
  | A0 = 8
  /// Address register A1.
  | A1 = 9
  /// Address register A2.
  | A2 = 10
  /// Address register A3.
  | A3 = 11
  /// Address register A4.
  | A4 = 12
  /// Address register A5.
  | A5 = 13
  /// Address register A6.
  | A6 = 14
  /// Address register A7, which is the stack pointer the current privilege
  /// level selects.
  | A7 = 15
  /// Program counter.
  | PC = 16
  /// Condition code register, which is the low byte of the status register.
  | CCR = 17
  /// Status register.
  | SR = 18
  /// User stack pointer.
  | USP = 19
  /// Interrupt stack pointer, also known as the supervisor stack pointer.
  | ISP = 20
  /// Master stack pointer.
  | MSP = 21
  /// Vector base register.
  | VBR = 22
  /// Source function code register.
  | SFC = 23
  /// Destination function code register.
  | DFC = 24
  /// Cache control register.
  | CACR = 25
  /// Cache address register.
  | CAAR = 26
  /// MMU translation control register.
  | TC = 27
  /// Instruction transparent translation register 0.
  | ITT0 = 28
  /// Instruction transparent translation register 1.
  | ITT1 = 29
  /// Data transparent translation register 0.
  | DTT0 = 30
  /// Data transparent translation register 1.
  | DTT1 = 31
  /// MMU status register.
  | MMUSR = 32
  /// User root pointer.
  | URP = 33
  /// Supervisor root pointer.
  | SRP = 34
  /// Floating-point data register FP0.
  | FP0 = 35
  /// Floating-point data register FP1.
  | FP1 = 36
  /// Floating-point data register FP2.
  | FP2 = 37
  /// Floating-point data register FP3.
  | FP3 = 38
  /// Floating-point data register FP4.
  | FP4 = 39
  /// Floating-point data register FP5.
  | FP5 = 40
  /// Floating-point data register FP6.
  | FP6 = 41
  /// Floating-point data register FP7.
  | FP7 = 42
  /// Floating-point control register.
  | FPCR = 43
  /// Floating-point status register.
  | FPSR = 44
  /// Floating-point instruction address register.
  | FPIAR = 45

/// Provides functions to handle m68k registers.
module Register =
  /// Returns the m68k register from a register ID.
  [<CompiledName "OfRegID">]
  let inline ofRegID (rid: RegisterID): Register =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Returns the m68k register from a string representation. The stack pointer
  /// answers to "sp" as well as to "a7", which is how m68k assembly names it.
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant() with
    | "d0" -> Register.D0
    | "d1" -> Register.D1
    | "d2" -> Register.D2
    | "d3" -> Register.D3
    | "d4" -> Register.D4
    | "d5" -> Register.D5
    | "d6" -> Register.D6
    | "d7" -> Register.D7
    | "a0" -> Register.A0
    | "a1" -> Register.A1
    | "a2" -> Register.A2
    | "a3" -> Register.A3
    | "a4" -> Register.A4
    | "a5" -> Register.A5
    | "a6" -> Register.A6
    | "a7" | "sp" -> Register.A7
    | "pc" -> Register.PC
    | "ccr" -> Register.CCR
    | "sr" -> Register.SR
    | "usp" -> Register.USP
    | "isp" | "ssp" -> Register.ISP
    | "msp" -> Register.MSP
    | "vbr" -> Register.VBR
    | "sfc" -> Register.SFC
    | "dfc" -> Register.DFC
    | "cacr" -> Register.CACR
    | "caar" -> Register.CAAR
    | "tc" -> Register.TC
    | "itt0" -> Register.ITT0
    | "itt1" -> Register.ITT1
    | "dtt0" -> Register.DTT0
    | "dtt1" -> Register.DTT1
    | "mmusr" -> Register.MMUSR
    | "urp" -> Register.URP
    | "srp" -> Register.SRP
    | "fp0" -> Register.FP0
    | "fp1" -> Register.FP1
    | "fp2" -> Register.FP2
    | "fp3" -> Register.FP3
    | "fp4" -> Register.FP4
    | "fp5" -> Register.FP5
    | "fp6" -> Register.FP6
    | "fp7" -> Register.FP7
    | "fpcr" -> Register.FPCR
    | "fpsr" -> Register.FPSR
    | "fpiar" -> Register.FPIAR
    | _ -> Terminator.impossible ()

  /// Returns the register ID of an m68k register.
  [<CompiledName "ToRegID">]
  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue reg |> RegisterID.create

  /// Returns the string representation of an m68k register.
  [<CompiledName "ToString">]
  let toString reg =
    match reg with
    | Register.D0 -> "d0"
    | Register.D1 -> "d1"
    | Register.D2 -> "d2"
    | Register.D3 -> "d3"
    | Register.D4 -> "d4"
    | Register.D5 -> "d5"
    | Register.D6 -> "d6"
    | Register.D7 -> "d7"
    | Register.A0 -> "a0"
    | Register.A1 -> "a1"
    | Register.A2 -> "a2"
    | Register.A3 -> "a3"
    | Register.A4 -> "a4"
    | Register.A5 -> "a5"
    | Register.A6 -> "a6"
    | Register.A7 -> "a7"
    | Register.PC -> "pc"
    | Register.CCR -> "ccr"
    | Register.SR -> "sr"
    | Register.USP -> "usp"
    | Register.ISP -> "isp"
    | Register.MSP -> "msp"
    | Register.VBR -> "vbr"
    | Register.SFC -> "sfc"
    | Register.DFC -> "dfc"
    | Register.CACR -> "cacr"
    | Register.CAAR -> "caar"
    | Register.TC -> "tc"
    | Register.ITT0 -> "itt0"
    | Register.ITT1 -> "itt1"
    | Register.DTT0 -> "dtt0"
    | Register.DTT1 -> "dtt1"
    | Register.MMUSR -> "mmusr"
    | Register.URP -> "urp"
    | Register.SRP -> "srp"
    | Register.FP0 -> "fp0"
    | Register.FP1 -> "fp1"
    | Register.FP2 -> "fp2"
    | Register.FP3 -> "fp3"
    | Register.FP4 -> "fp4"
    | Register.FP5 -> "fp5"
    | Register.FP6 -> "fp6"
    | Register.FP7 -> "fp7"
    | Register.FPCR -> "fpcr"
    | Register.FPSR -> "fpsr"
    | Register.FPIAR -> "fpiar"
    | _ -> Terminator.impossible ()

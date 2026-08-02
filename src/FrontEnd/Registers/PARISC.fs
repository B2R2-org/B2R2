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

namespace B2R2.FrontEnd.PARISC

open B2R2

/// <namespacedoc>
///   <summary>
///   Contains types and functions for working with the PA-RISC instructions.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents registers for PA-RISC.<para/>
/// </summary>
type Register =
  | GR0 = 0x0
  | GR1 = 0x1
  | GR2 = 0x2
  | GR3 = 0x3
  | GR4 = 0x4
  | GR5 = 0x5
  | GR6 = 0x6
  | GR7 = 0x7
  | GR8 = 0x8
  | GR9 = 0x9
  | GR10 = 0xA
  | GR11 = 0xB
  | GR12 = 0xC
  | GR13 = 0xD
  | GR14 = 0xE
  | GR15 = 0xF
  | GR16 = 0x10
  | GR17 = 0x11
  | GR18 = 0x12
  | GR19 = 0x13
  | GR20 = 0x14
  | GR21 = 0x15
  | GR22 = 0x16
  | GR23 = 0x17
  | GR24 = 0x18
  | GR25 = 0x19
  | GR26 = 0x1A
  | GR27 = 0x1B
  | GR28 = 0x1C
  | GR29 = 0x1D
  | GR30 = 0x1E
  | GR31 = 0x1F
  | SR0 = 0x20
  | SR1 = 0x21
  | SR2 = 0x22
  | SR3 = 0x23
  | SR4 = 0x24
  | SR5 = 0x25
  | SR6 = 0x26
  | SR7 = 0x27
  | IAOQ_Front = 0x28
  | IAOQ_Back = 0x29
  | IASQ_Front = 0x2A
  | IASQ_Back = 0x2B
  | PSW = 0x2C
  | CR0 = 0x2D
  | CR1 = 0x2E
  | CR2 = 0x2F
  | CR3 = 0x30
  | CR4 = 0x31
  | CR5 = 0x32
  | CR6 = 0x33
  | CR7 = 0x34
  | CR8 = 0x35
  | CR9 = 0x36
  | CR10 = 0x37
  | CR11 = 0x38
  | CR12 = 0x39
  | CR13 = 0x3A
  | CR14 = 0x3B
  | CR15 = 0x3C
  | CR16 = 0x3D
  | CR17 = 0x3E
  | CR18 = 0x3F
  | CR19 = 0x40
  | CR20 = 0x41
  | CR21 = 0x42
  | CR22 = 0x43
  | CR23 = 0x44
  | CR24 = 0x45
  | CR25 = 0x46
  | CR26 = 0x47
  | CR27 = 0x48
  | CR28 = 0x49
  | CR29 = 0x4A
  | CR30 = 0x4B
  | CR31 = 0x4C
  | FPR0L = 0x4D
  | FPR1L = 0x4E
  | FPR2L = 0x4F
  | FPR3L = 0x50
  | FPR4L = 0x51
  | FPR5L = 0x52
  | FPR6L = 0x53
  | FPR7L = 0x54
  | FPR8L = 0x55
  | FPR9L = 0x56
  | FPR10L = 0x57
  | FPR11L = 0x58
  | FPR12L = 0x59
  | FPR13L = 0x5A
  | FPR14L = 0x5B
  | FPR15L = 0x5C
  | FPR16L = 0x5D
  | FPR17L = 0x5E
  | FPR18L = 0x5F
  | FPR19L = 0x60
  | FPR20L = 0x61
  | FPR21L = 0x62
  | FPR22L = 0x63
  | FPR23L = 0x64
  | FPR24L = 0x65
  | FPR25L = 0x66
  | FPR26L = 0x67
  | FPR27L = 0x68
  | FPR28L = 0x69
  | FPR29L = 0x6A
  | FPR30L = 0x6B
  | FPR31L = 0x6C
  | FPR0R = 0x6D
  | FPR1R = 0x6E
  | FPR2R = 0x6F
  | FPR3R = 0x70
  | FPR4R = 0x71
  | FPR5R = 0x72
  | FPR6R = 0x73
  | FPR7R = 0x74
  | FPR8R = 0x75
  | FPR9R = 0x76
  | FPR10R = 0x77
  | FPR11R = 0x78
  | FPR12R = 0x79
  | FPR13R = 0x7A
  | FPR14R = 0x7B
  | FPR15R = 0x7C
  | FPR16R = 0x7D
  | FPR17R = 0x7E
  | FPR18R = 0x7F
  | FPR19R = 0x80
  | FPR20R = 0x81
  | FPR21R = 0x82
  | FPR22R = 0x83
  | FPR23R = 0x84
  | FPR24R = 0x85
  | FPR25R = 0x86
  | FPR26R = 0x87
  | FPR27R = 0x88
  | FPR28R = 0x89
  | FPR29R = 0x8A
  | FPR30R = 0x8B
  | FPR31R = 0x8C

/// Provides functions to handle PARISC registers.
module Register =
  /// Returns the PARISC register from a register ID.
  [<CompiledName "OfRegID">]
  let inline ofRegID (rid: RegisterID): Register =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Returns the PARISC register from a string representation.
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant() with
    | "flags" -> Register.GR0
    | "r1" -> Register.GR1
    | "rp" -> Register.GR2
    | "r3" -> Register.GR3
    | "r4" -> Register.GR4
    | "r5" -> Register.GR5
    | "r6" -> Register.GR6
    | "r7" -> Register.GR7
    | "r8" -> Register.GR8
    | "r9" -> Register.GR9
    | "r10" -> Register.GR10
    | "r11" -> Register.GR11
    | "r12" -> Register.GR12
    | "r13" -> Register.GR13
    | "r14" -> Register.GR14
    | "r15" -> Register.GR15
    | "r16" -> Register.GR16
    | "r17" -> Register.GR17
    | "r18" -> Register.GR18
    | "r19" -> Register.GR19
    | "r20" -> Register.GR20
    | "r21" -> Register.GR21
    | "r22" -> Register.GR22
    | "r23" -> Register.GR23
    | "r24" -> Register.GR24
    | "r25" -> Register.GR25
    | "r26" -> Register.GR26
    | "dp" -> Register.GR27
    | "ret0" -> Register.GR28
    | "ret1" -> Register.GR29
    | "sp" -> Register.GR30
    | "r31" -> Register.GR31
    | "sr0" -> Register.SR0
    | "sr1" -> Register.SR1
    | "sr2" -> Register.SR2
    | "sr3" -> Register.SR3
    | "sr4" -> Register.SR4
    | "sr5" -> Register.SR5
    | "sr6" -> Register.SR6
    | "sr7" -> Register.SR7
    | "iaoq_front" -> Register.IAOQ_Front
    | "iaoq_back" -> Register.IAOQ_Back
    | "iasq_front" -> Register.IASQ_Front
    | "iasq_back" -> Register.IASQ_Back
    | "psw" -> Register.PSW
    | "rctr" -> Register.CR0
    | "cr1" -> Register.CR1
    | "cr2" -> Register.CR2
    | "cr3" -> Register.CR3
    | "cr4" -> Register.CR4
    | "cr5" -> Register.CR5
    | "cr6" -> Register.CR6
    | "cr7" -> Register.CR7
    | "pidr1" -> Register.CR8
    | "pidr2" -> Register.CR9
    | "ccr" -> Register.CR10
    | "sar" -> Register.CR11
    | "pidr3" -> Register.CR12
    | "pidr4" -> Register.CR13
    | "iva" -> Register.CR14
    | "eiem" -> Register.CR15
    | "itmr" -> Register.CR16
    | "pcsq" -> Register.CR17
    | "pcoq" -> Register.CR18
    | "iir" -> Register.CR19
    | "isr" -> Register.CR20
    | "ior" -> Register.CR21
    | "ipsw" -> Register.CR22
    | "eirr" -> Register.CR23
    | "tr0" -> Register.CR24
    | "tr1" -> Register.CR25
    | "tr2" -> Register.CR26
    | "tr3" -> Register.CR27
    | "tr4" -> Register.CR28
    | "tr5" -> Register.CR29
    | "tr6" -> Register.CR30
    | "tr7" -> Register.CR31
    | "fpsr" -> Register.FPR0L
    | "fpe2" -> Register.FPR1L
    | "fpe4" -> Register.FPR2L
    | "fpe6" -> Register.FPR3L
    | "fr4" -> Register.FPR4L
    | "fr5" -> Register.FPR5L
    | "fr6" -> Register.FPR6L
    | "fr7" -> Register.FPR7L
    | "fr8" -> Register.FPR8L
    | "fr9" -> Register.FPR9L
    | "fr10" -> Register.FPR10L
    | "fr11" -> Register.FPR11L
    | "fr12" -> Register.FPR12L
    | "fr13" -> Register.FPR13L
    | "fr14" -> Register.FPR14L
    | "fr15" -> Register.FPR15L
    | "fr16" -> Register.FPR16L
    | "fr17" -> Register.FPR17L
    | "fr18" -> Register.FPR18L
    | "fr19" -> Register.FPR19L
    | "fr20" -> Register.FPR20L
    | "fr21" -> Register.FPR21L
    | "fr22" -> Register.FPR22L
    | "fr23" -> Register.FPR23L
    | "fr24" -> Register.FPR24L
    | "fr25" -> Register.FPR25L
    | "fr26" -> Register.FPR26L
    | "fr27" -> Register.FPR27L
    | "fr28" -> Register.FPR28L
    | "fr29" -> Register.FPR29L
    | "fr30" -> Register.FPR30L
    | "fr31" -> Register.FPR31L
    | "fpsrl" -> Register.FPR0L
    | "fpe2l" -> Register.FPR1L
    | "fpe4l" -> Register.FPR2L
    | "fpe6l" -> Register.FPR3L
    | "fr4l" -> Register.FPR4L
    | "fr5l" -> Register.FPR5L
    | "fr6l" -> Register.FPR6L
    | "fr7l" -> Register.FPR7L
    | "fr8l" -> Register.FPR8L
    | "fr9l" -> Register.FPR9L
    | "fr10l" -> Register.FPR10L
    | "fr11l" -> Register.FPR11L
    | "fr12l" -> Register.FPR12L
    | "fr13l" -> Register.FPR13L
    | "fr14l" -> Register.FPR14L
    | "fr15l" -> Register.FPR15L
    | "fr16l" -> Register.FPR16L
    | "fr17l" -> Register.FPR17L
    | "fr18l" -> Register.FPR18L
    | "fr19l" -> Register.FPR19L
    | "fr20l" -> Register.FPR20L
    | "fr21l" -> Register.FPR21L
    | "fr22l" -> Register.FPR22L
    | "fr23l" -> Register.FPR23L
    | "fr24l" -> Register.FPR24L
    | "fr25l" -> Register.FPR25L
    | "fr26l" -> Register.FPR26L
    | "fr27l" -> Register.FPR27L
    | "fr28l" -> Register.FPR28L
    | "fr29l" -> Register.FPR29L
    | "fr30l" -> Register.FPR30L
    | "fr31l" -> Register.FPR31L
    | "fpe1" -> Register.FPR0R
    | "fpe3" -> Register.FPR1R
    | "fpe5" -> Register.FPR2R
    | "fpe7" -> Register.FPR3R
    | "fr4R" -> Register.FPR4R
    | "fr5R" -> Register.FPR5R
    | "fr6R" -> Register.FPR6R
    | "fr7R" -> Register.FPR7R
    | "fr8R" -> Register.FPR8R
    | "fr9R" -> Register.FPR9R
    | "fr10R" -> Register.FPR10R
    | "fr11R" -> Register.FPR11R
    | "fr12R" -> Register.FPR12R
    | "fr13R" -> Register.FPR13R
    | "fr14R" -> Register.FPR14R
    | "fr15R" -> Register.FPR15R
    | "fr16R" -> Register.FPR16R
    | "fr17R" -> Register.FPR17R
    | "fr18R" -> Register.FPR18R
    | "fr19R" -> Register.FPR19R
    | "fr20R" -> Register.FPR20R
    | "fr21R" -> Register.FPR21R
    | "fr22R" -> Register.FPR22R
    | "fr23R" -> Register.FPR23R
    | "fr24R" -> Register.FPR24R
    | "fr25R" -> Register.FPR25R
    | "fr26R" -> Register.FPR26R
    | "fr27R" -> Register.FPR27R
    | "fr28R" -> Register.FPR28R
    | "fr29R" -> Register.FPR29R
    | "fr30R" -> Register.FPR30R
    | "fr31R" -> Register.FPR31R
    | _ -> Terminator.impossible ()

  /// Returns the register ID of a PARISC register.
  [<CompiledName "ToRegID">]
  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue(reg) |> RegisterID.create

  /// Returns the string representation of a PARISC register.
  [<CompiledName "ToString">]
  let toString reg =
    match reg with
    | Register.GR0 -> "flags"
    | Register.GR1 -> "r1"
    | Register.GR2 -> "rp"
    | Register.GR3 -> "r3"
    | Register.GR4 -> "r4"
    | Register.GR5 -> "r5"
    | Register.GR6 -> "r6"
    | Register.GR7 -> "r7"
    | Register.GR8 -> "r8"
    | Register.GR9 -> "r9"
    | Register.GR10 -> "r10"
    | Register.GR11 -> "r11"
    | Register.GR12 -> "r12"
    | Register.GR13 -> "r13"
    | Register.GR14 -> "r14"
    | Register.GR15 -> "r15"
    | Register.GR16 -> "r16"
    | Register.GR17 -> "r17"
    | Register.GR18 -> "r18"
    | Register.GR19 -> "r19"
    | Register.GR20 -> "r20"
    | Register.GR21 -> "r21"
    | Register.GR22 -> "r22"
    | Register.GR23 -> "r23"
    | Register.GR24 -> "r24"
    | Register.GR25 -> "r25"
    | Register.GR26 -> "r26"
    | Register.GR27 -> "dp"
    | Register.GR28 -> "ret0"
    | Register.GR29 -> "ret1"
    | Register.GR30 -> "sp"
    | Register.GR31 -> "r31"
    | Register.SR0 -> "sr0"
    | Register.SR1 -> "sr1"
    | Register.SR2 -> "sr2"
    | Register.SR3 -> "sr3"
    | Register.SR4 -> "sr4"
    | Register.SR5 -> "sr5"
    | Register.SR6 -> "sr6"
    | Register.SR7 -> "sr7"
    | Register.IAOQ_Front -> "iaoq_front"
    | Register.IAOQ_Back -> "iaoq_back"
    | Register.IASQ_Front -> "iasq_front"
    | Register.IASQ_Back -> "iasq_back"
    | Register.PSW -> "psw"
    | Register.CR0 -> "rctr"
    | Register.CR1 -> "cr1"
    | Register.CR2 -> "cr2"
    | Register.CR3 -> "cr3"
    | Register.CR4 -> "cr4"
    | Register.CR5 -> "cr5"
    | Register.CR6 -> "cr6"
    | Register.CR7 -> "cr7"
    | Register.CR8 -> "pidr1"
    | Register.CR9 -> "pidr2"
    | Register.CR10 -> "ccr"
    | Register.CR11 -> "sar"
    | Register.CR12 -> "pidr3"
    | Register.CR13 -> "pidr4"
    | Register.CR14 -> "iva"
    | Register.CR15 -> "eiem"
    | Register.CR16 -> "itmr"
    | Register.CR17 -> "pcsq"
    | Register.CR18 -> "pcoq"
    | Register.CR19 -> "iir"
    | Register.CR20 -> "isr"
    | Register.CR21 -> "ior"
    | Register.CR22 -> "ipsw"
    | Register.CR23 -> "eirr"
    | Register.CR24 -> "tr0"
    | Register.CR25 -> "tr1"
    | Register.CR26 -> "tr2"
    | Register.CR27 -> "tr3"
    | Register.CR28 -> "tr4"
    | Register.CR29 -> "tr5"
    | Register.CR30 -> "tr6"
    | Register.CR31 -> "tr7"
    | Register.FPR0L -> "fpsr"
    | Register.FPR1L -> "fpe2"
    | Register.FPR2L -> "fpe4"
    | Register.FPR3L -> "fpe6"
    | Register.FPR4L -> "fr4"
    | Register.FPR5L -> "fr5"
    | Register.FPR6L -> "fr6"
    | Register.FPR7L -> "fr7"
    | Register.FPR8L -> "fr8"
    | Register.FPR9L -> "fr9"
    | Register.FPR10L -> "fr10"
    | Register.FPR11L -> "fr11"
    | Register.FPR12L -> "fr12"
    | Register.FPR13L -> "fr13"
    | Register.FPR14L -> "fr14"
    | Register.FPR15L -> "fr15"
    | Register.FPR16L -> "fr16"
    | Register.FPR17L -> "fr17"
    | Register.FPR18L -> "fr18"
    | Register.FPR19L -> "fr19"
    | Register.FPR20L -> "fr20"
    | Register.FPR21L -> "fr21"
    | Register.FPR22L -> "fr22"
    | Register.FPR23L -> "fr23"
    | Register.FPR24L -> "fr24"
    | Register.FPR25L -> "fr25"
    | Register.FPR26L -> "fr26"
    | Register.FPR27L -> "fr27"
    | Register.FPR28L -> "fr28"
    | Register.FPR29L -> "fr29"
    | Register.FPR30L -> "fr30"
    | Register.FPR31L -> "fr31"
    | Register.FPR0R -> "fpe1"
    | Register.FPR1R -> "fpe3"
    | Register.FPR2R -> "fpe5"
    | Register.FPR3R -> "fpe7"
    | Register.FPR4R -> "fr4R"
    | Register.FPR5R -> "fr5R"
    | Register.FPR6R -> "fr6R"
    | Register.FPR7R -> "fr7R"
    | Register.FPR8R -> "fr8R"
    | Register.FPR9R -> "fr9R"
    | Register.FPR10R -> "fr10R"
    | Register.FPR11R -> "fr11R"
    | Register.FPR12R -> "fr12R"
    | Register.FPR13R -> "fr13R"
    | Register.FPR14R -> "fr14R"
    | Register.FPR15R -> "fr15R"
    | Register.FPR16R -> "fr16R"
    | Register.FPR17R -> "fr17R"
    | Register.FPR18R -> "fr18R"
    | Register.FPR19R -> "fr19R"
    | Register.FPR20R -> "fr20R"
    | Register.FPR21R -> "fr21R"
    | Register.FPR22R -> "fr22R"
    | Register.FPR23R -> "fr23R"
    | Register.FPR24R -> "fr24R"
    | Register.FPR25R -> "fr25R"
    | Register.FPR26R -> "fr26R"
    | Register.FPR27R -> "fr27R"
    | Register.FPR28R -> "fr28R"
    | Register.FPR29R -> "fr29R"
    | Register.FPR30R -> "fr30R"
    | Register.FPR31R -> "fr31R"
    | _ -> Terminator.impossible ()

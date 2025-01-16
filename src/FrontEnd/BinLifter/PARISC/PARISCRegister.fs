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

namespace B2R2.FrontEnd.BinLifter.PARISC

open B2R2

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
  | FPR0 = 0x4D
  | FPR1 = 0x4E
  | FPR2 = 0x4F
  | FPR3 = 0x50
  | FPR4 = 0x51
  | FPR5 = 0x52
  | FPR6 = 0x53
  | FPR7 = 0x54
  | FPR8 = 0x55
  | FPR9 = 0x56
  | FPR10 = 0x57
  | FPR11 = 0x58
  | FPR12 = 0x59
  | FPR13 = 0x5A
  | FPR14 = 0x5B
  | FPR15 = 0x5C
  | FPR16 = 0x5D
  | FPR17 = 0x5E
  | FPR18 = 0x5F
  | FPR19 = 0x60
  | FPR20 = 0x61
  | FPR21 = 0x62
  | FPR22 = 0x63
  | FPR23 = 0x64
  | FPR24 = 0x65
  | FPR25 = 0x66
  | FPR26 = 0x67
  | FPR27 = 0x68
  | FPR28 = 0x69
  | FPR29 = 0x6A
  | FPR30 = 0x6B
  | FPR31 = 0x6C

/// Shortcut for Register type.
type internal R = Register

/// This module exposes several useful functions to handle s390/s390x
/// registers.
[<RequireQualifiedAccess>]
module Register =
  let inline ofRegID (n: RegisterID): Register =
    int n |> LanguagePrimitives.EnumOfValue

  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  let ofString (str: string) =
    match str.ToLowerInvariant () with
    | "flags" -> R.GR0
    | "r1" -> R.GR1
    | "rp" -> R.GR2
    | "r3" -> R.GR3
    | "r4" -> R.GR4
    | "r5" -> R.GR5
    | "r6" -> R.GR6
    | "r7" -> R.GR7
    | "r8" -> R.GR8
    | "r9" -> R.GR9
    | "r10" -> R.GR10
    | "r11" -> R.GR11
    | "r12" -> R.GR12
    | "r13" -> R.GR13
    | "r14" -> R.GR14
    | "r15" -> R.GR15
    | "r16" -> R.GR16
    | "r17" -> R.GR17
    | "r18" -> R.GR18
    | "r19" -> R.GR19
    | "r20" -> R.GR20
    | "r21" -> R.GR21
    | "r22" -> R.GR22
    | "r23" -> R.GR23
    | "r24" -> R.GR24
    | "r25" -> R.GR25
    | "r26" -> R.GR26
    | "dp" -> R.GR27
    | "ret0" -> R.GR28
    | "ret1" -> R.GR29
    | "sp" -> R.GR30
    | "r31" -> R.GR31
    | "sr0" -> R.SR0
    | "sr1" -> R.SR1
    | "sr2" -> R.SR2
    | "sr3" -> R.SR3
    | "sr4" -> R.SR4
    | "sr5" -> R.SR5
    | "sr6" -> R.SR6
    | "sr7" -> R.SR7
    | "iaoq_front" -> R.IAOQ_Front
    | "iaoq_back" -> R.IAOQ_Back
    | "iasq_front" -> R.IASQ_Front
    | "iasq_back" -> R.IASQ_Back
    | "psw" -> R.PSW
    | "cr0" -> R.CR0
    | "cr1" -> R.CR1
    | "cr2" -> R.CR2
    | "cr3" -> R.CR3
    | "cr4" -> R.CR4
    | "cr5" -> R.CR5
    | "cr6" -> R.CR6
    | "cr7" -> R.CR7
    | "cr8" -> R.CR8
    | "cr9" -> R.CR9
    | "cr10" -> R.CR10
    | "cr11" -> R.CR11
    | "cr12" -> R.CR12
    | "cr13" -> R.CR13
    | "cr14" -> R.CR14
    | "cr15" -> R.CR15
    | "cr16" -> R.CR16
    | "cr17" -> R.CR17
    | "cr18" -> R.CR18
    | "cr19" -> R.CR19
    | "cr20" -> R.CR20
    | "cr21" -> R.CR21
    | "cr22" -> R.CR22
    | "cr23" -> R.CR23
    | "cr24" -> R.CR24
    | "cr25" -> R.CR25
    | "cr26" -> R.CR26
    | "cr27" -> R.CR27
    | "cr28" -> R.CR28
    | "cr29" -> R.CR29
    | "cr30" -> R.CR30
    | "cr31" -> R.CR31
    | "fpr0" -> R.FPR0
    | "fpr1" -> R.FPR1
    | "fpr2" -> R.FPR2
    | "fpr3" -> R.FPR3
    | "fpr4" -> R.FPR4
    | "fpr5" -> R.FPR5
    | "fpr6" -> R.FPR6
    | "fpr7" -> R.FPR7
    | "fpr8" -> R.FPR8
    | "fpr9" -> R.FPR9
    | "fpr10" -> R.FPR10
    | "fpr11" -> R.FPR11
    | "fpr12" -> R.FPR12
    | "fpr13" -> R.FPR13
    | "fpr14" -> R.FPR14
    | "fpr15" -> R.FPR15
    | "fpr16" -> R.FPR16
    | "fpr17" -> R.FPR17
    | "fpr18" -> R.FPR18
    | "fpr19" -> R.FPR19
    | "fpr20" -> R.FPR20
    | "fpr21" -> R.FPR21
    | "fpr22" -> R.FPR22
    | "fpr23" -> R.FPR23
    | "fpr24" -> R.FPR24
    | "fpr25" -> R.FPR25
    | "fpr26" -> R.FPR26
    | "fpr27" -> R.FPR27
    | "fpr28" -> R.FPR28
    | "fpr29" -> R.FPR29
    | "fpr30" -> R.FPR30
    | "fpr31" -> R.FPR31
    | _ -> Utils.impossible ()

  let toString = function
    | R.GR0 -> "flags"
    | R.GR1 -> "r1"
    | R.GR2 -> "rp"
    | R.GR3 -> "r3"
    | R.GR4 -> "r4"
    | R.GR5 -> "r5"
    | R.GR6 -> "r6"
    | R.GR7 -> "r7"
    | R.GR8 -> "r8"
    | R.GR9 -> "r9"
    | R.GR10 -> "r10"
    | R.GR11 -> "r11"
    | R.GR12 -> "r12"
    | R.GR13 -> "r13"
    | R.GR14 -> "r14"
    | R.GR15 -> "r15"
    | R.GR16 -> "r16"
    | R.GR17 -> "r17"
    | R.GR18 -> "r18"
    | R.GR19 -> "r19"
    | R.GR20 -> "r20"
    | R.GR21 -> "r21"
    | R.GR22 -> "r22"
    | R.GR23 -> "r23"
    | R.GR24 -> "r24"
    | R.GR25 -> "r25"
    | R.GR26 -> "r26"
    | R.GR27 -> "dp"
    | R.GR28 -> "ret0"
    | R.GR29 -> "ret1"
    | R.GR30 -> "sp"
    | R.GR31 -> "r31"
    | R.SR0 -> "sr0"
    | R.SR1 -> "sr1"
    | R.SR2 -> "sr2"
    | R.SR3 -> "sr3"
    | R.SR4 -> "sr4"
    | R.SR5 -> "sr5"
    | R.SR6 -> "sr6"
    | R.SR7 -> "sr7"
    | R.IAOQ_Front -> "iaoq_front"
    | R.IAOQ_Back -> "iaoq_back"
    | R.IASQ_Front -> "iasq_front"
    | R.IASQ_Back -> "iasq_back"
    | R.PSW -> "psw"
    | R.CR0 -> "cr0"
    | R.CR1 -> "cr1"
    | R.CR2 -> "cr2"
    | R.CR3 -> "cr3"
    | R.CR4 -> "cr4"
    | R.CR5 -> "cr5"
    | R.CR6 -> "cr6"
    | R.CR7 -> "cr7"
    | R.CR8 -> "cr8"
    | R.CR9 -> "cr9"
    | R.CR10 -> "cr10"
    | R.CR11 -> "cr11"
    | R.CR12 -> "cr12"
    | R.CR13 -> "cr13"
    | R.CR14 -> "cr14"
    | R.CR15 -> "cr15"
    | R.CR16 -> "cr16"
    | R.CR17 -> "cr17"
    | R.CR18 -> "cr18"
    | R.CR19 -> "cr19"
    | R.CR20 -> "cr20"
    | R.CR21 -> "cr21"
    | R.CR22 -> "cr22"
    | R.CR23 -> "cr23"
    | R.CR24 -> "cr24"
    | R.CR25 -> "cr25"
    | R.CR26 -> "cr26"
    | R.CR27 -> "cr27"
    | R.CR28 -> "cr28"
    | R.CR29 -> "cr29"
    | R.CR30 -> "cr30"
    | R.CR31 -> "cr31"
    | R.FPR0 -> "fpr0"
    | R.FPR1 -> "fpr1"
    | R.FPR2 -> "fpr2"
    | R.FPR3 -> "fpr3"
    | R.FPR4 -> "fpr4"
    | R.FPR5 -> "fpr5"
    | R.FPR6 -> "fpr6"
    | R.FPR7 -> "fpr7"
    | R.FPR8 -> "fpr8"
    | R.FPR9 -> "fpr9"
    | R.FPR10 -> "fpr10"
    | R.FPR11 -> "fpr11"
    | R.FPR12 -> "fpr12"
    | R.FPR13 -> "fpr13"
    | R.FPR14 -> "fpr14"
    | R.FPR15 -> "fpr15"
    | R.FPR16 -> "fpr16"
    | R.FPR17 -> "fpr17"
    | R.FPR18 -> "fpr18"
    | R.FPR19 -> "fpr19"
    | R.FPR20 -> "fpr20"
    | R.FPR21 -> "fpr21"
    | R.FPR22 -> "fpr22"
    | R.FPR23 -> "fpr23"
    | R.FPR24 -> "fpr24"
    | R.FPR25 -> "fpr25"
    | R.FPR26 -> "fpr26"
    | R.FPR27 -> "fpr27"
    | R.FPR28 -> "fpr28"
    | R.FPR29 -> "fpr29"
    | R.FPR30 -> "fpr30"
    | R.FPR31 -> "fpr31"
    | _ -> Utils.impossible ()

  let toRegType wordSize = function
    | R.GR0 | R.GR1 | R.GR2 | R.GR3 | R.GR4 | R.GR5 | R.GR6 | R.GR7
    | R.GR8 | R.GR9 | R.GR10 | R.GR11 | R.GR12 | R.GR13 | R.GR14 | R.GR15
    | R.GR16 | R.GR17 | R.GR18 | R.GR19 | R.GR20 | R.GR21 | R.GR22 | R.GR23
    | R.GR24 | R.GR25 | R.GR26 | R.GR27 | R.GR28 | R.GR29 | R.GR30 | R.GR31
    | R.SR0 | R.SR1 | R.SR2 | R.SR3 | R.SR4 | R.SR5 | R.SR6 | R.SR7
    | R.IAOQ_Front | R.IAOQ_Back | R.IASQ_Front | R.IASQ_Back | R.PSW
    | R.CR0 | R.CR1 | R.CR2 | R.CR3 | R.CR4 | R.CR5 | R.CR6 | R.CR7
    | R.CR8 | R.CR9 | R.CR10 | R.CR11 | R.CR12 | R.CR13 | R.CR14 | R.CR15
    | R.CR16 | R.CR17 | R.CR18 | R.CR19 | R.CR20 | R.CR21 | R.CR22 | R.CR23
    | R.CR24 | R.CR25 | R.CR26 | R.CR27 | R.CR28 | R.CR29 | R.CR30 | R.CR31
    | R.FPR0 | R.FPR1 | R.FPR2 | R.FPR3 | R.FPR4 | R.FPR5 | R.FPR6 | R.FPR7
    | R.FPR8 | R.FPR9 | R.FPR10 | R.FPR11 | R.FPR12 | R.FPR13 | R.FPR14
    | R.FPR15 | R.FPR16 | R.FPR17 | R.FPR18 | R.FPR19 | R.FPR20 | R.FPR21
    | R.FPR22 | R.FPR23 | R.FPR24 | R.FPR25 | R.FPR26 | R.FPR27 | R.FPR28
    | R.FPR29 | R.FPR30 | R.FPR31 -> WordSize.toRegType wordSize
    | _ -> Utils.impossible ()


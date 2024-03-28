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
    | _ -> Utils.impossible ()

  let toRegType wordSize = function
    | _ -> Utils.impossible ()

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

namespace B2R2.FrontEnd.TMS320C6000

open B2R2

/// <namespacedoc>
///   <summary>
///   Contains types and functions for working with the TMS320C6000
///   instructions.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Represents registers for TMS320C6000.<para/>
/// </summary>
type Register =
  | A0 = 0x0
  | A1 = 0x1
  | A2 = 0x2
  | A3 = 0x3
  | A4 = 0x4
  | A5 = 0x5
  | A6 = 0x6
  | A7 = 0x7
  | A8 = 0x8
  | A9 = 0x9
  | A10 = 0xA
  | A11 = 0xB
  | A12 = 0xC
  | A13 = 0xD
  | A14 = 0xE
  | A15 = 0xF
  | A16 = 0x10
  | A17 = 0x11
  | A18 = 0x12
  | A19 = 0x13
  | A20 = 0x14
  | A21 = 0x15
  | A22 = 0x16
  | A23 = 0x17
  | A24 = 0x18
  | A25 = 0x19
  | A26 = 0x1A
  | A27 = 0x1B
  | A28 = 0x1C
  | A29 = 0x1D
  | A30 = 0x1E
  | A31 = 0x1F
  | B0 = 0x20
  | B1 = 0x21
  | B2 = 0x22
  | B3 = 0x23
  | B4 = 0x24
  | B5 = 0x25
  | B6 = 0x26
  | B7 = 0x27
  | B8 = 0x28
  | B9 = 0x29
  | B10 = 0x2A
  | B11 = 0x2B
  | B12 = 0x2C
  | B13 = 0x2D
  | B14 = 0x2E
  | B15 = 0x2F
  | B16 = 0x30
  | B17 = 0x31
  | B18 = 0x32
  | B19 = 0x33
  | B20 = 0x34
  | B21 = 0x35
  | B22 = 0x36
  | B23 = 0x37
  | B24 = 0x38
  | B25 = 0x39
  | B26 = 0x3A
  | B27 = 0x3B
  | B28 = 0x3C
  | B29 = 0x3D
  | B30 = 0x3E
  | B31 = 0x3F
  | AMR = 0x40
  | CSR = 0x41
  | DIER = 0x42
  | DNUM = 0x43
  | ECR = 0x44
  | EFR = 0x45
  | FADCR = 0x46
  | FAUCR = 0x47
  | FMCR = 0x48
  | GFPGFR = 0x49
  | GPLYA = 0x4A
  | GPLYB = 0x4B
  | ICR = 0x4C
  | IER = 0x4D
  | IERR = 0x4E
  | IFR = 0x4F
  | ILC = 0x50
  | IRP = 0x51
  | ISR = 0x52
  | ISTP = 0x53
  | ITSR = 0x54
  | NRP = 0x55
  | NTSR = 0x56
  | PCE1 = 0x57
  | REP = 0x58
  | RILC = 0x59
  | SSR = 0x5A
  | TSCH = 0x5B
  | TSCL = 0x5C
  | TSR = 0x5D

/// Provides functions to handle TMS320C6000 registers.
module Register =
  /// Returns the TMS320C6000 register from a register ID.
  [<CompiledName "OfRegID">]
  let inline ofRegID (rid: RegisterID): Register =
    int rid |> LanguagePrimitives.EnumOfValue

  /// Returns the TMS320C6000 register from a string representation.
  [<CompiledName "OfString">]
  let ofString (str: string) =
    match str.ToLowerInvariant() with
    | "a0" -> Register.A0
    | "a1" -> Register.A1
    | "a2" -> Register.A2
    | "a3" -> Register.A3
    | "a4" -> Register.A4
    | "a5" -> Register.A5
    | "a6" -> Register.A6
    | "a7" -> Register.A7
    | "a8" -> Register.A8
    | "a9" -> Register.A9
    | "a10" -> Register.A10
    | "a11" -> Register.A11
    | "a12" -> Register.A12
    | "a13" -> Register.A13
    | "a14" -> Register.A14
    | "a15" -> Register.A15
    | "a16" -> Register.A16
    | "a17" -> Register.A17
    | "a18" -> Register.A18
    | "a19" -> Register.A19
    | "a20" -> Register.A20
    | "a21" -> Register.A21
    | "a22" -> Register.A22
    | "a23" -> Register.A23
    | "a24" -> Register.A24
    | "a25" -> Register.A25
    | "a26" -> Register.A26
    | "a27" -> Register.A27
    | "a28" -> Register.A28
    | "a29" -> Register.A29
    | "a30" -> Register.A30
    | "a31" -> Register.A31
    | "b0" -> Register.B0
    | "b1" -> Register.B1
    | "b2" -> Register.B2
    | "b3" -> Register.B3
    | "b4" -> Register.B4
    | "b5" -> Register.B5
    | "b6" -> Register.B6
    | "b7" -> Register.B7
    | "b8" -> Register.B8
    | "b9" -> Register.B9
    | "b10" -> Register.B10
    | "b11" -> Register.B11
    | "b12" -> Register.B12
    | "b13" -> Register.B13
    | "b14" -> Register.B14
    | "b15" -> Register.B15
    | "b16" -> Register.B16
    | "b17" -> Register.B17
    | "b18" -> Register.B18
    | "b19" -> Register.B19
    | "b20" -> Register.B20
    | "b21" -> Register.B21
    | "b22" -> Register.B22
    | "b23" -> Register.B23
    | "b24" -> Register.B24
    | "b25" -> Register.B25
    | "b26" -> Register.B26
    | "b27" -> Register.B27
    | "b28" -> Register.B28
    | "b29" -> Register.B29
    | "b30" -> Register.B30
    | "b31" -> Register.B31
    | "amr" -> Register.AMR
    | "csr" -> Register.CSR
    | "dier" -> Register.DIER
    | "dnum" -> Register.DNUM
    | "ecr" -> Register.ECR
    | "efr" -> Register.EFR
    | "fadcr" -> Register.FADCR
    | "faucr" -> Register.FAUCR
    | "fmcr" -> Register.FMCR
    | "gfpgfr" -> Register.GFPGFR
    | "gplya" -> Register.GPLYA
    | "gplyb" -> Register.GPLYB
    | "icr" -> Register.ICR
    | "ier" -> Register.IER
    | "ierr" -> Register.IERR
    | "ifr" -> Register.IFR
    | "ilc" -> Register.ILC
    | "irp" -> Register.IRP
    | "isr" -> Register.ISR
    | "istp" -> Register.ISTP
    | "itsr" -> Register.ITSR
    | "nrp" -> Register.NRP
    | "ntsr" -> Register.NTSR
    | "pce1" -> Register.PCE1
    | "rep" -> Register.REP
    | "rilc" -> Register.RILC
    | "ssr" -> Register.SSR
    | "tsch" -> Register.TSCH
    | "tscl" -> Register.TSCL
    | "tsr" -> Register.TSR
    | _ -> Terminator.impossible ()

  /// Returns the register ID of a TMS320C6000 register.
  [<CompiledName "ToRegID">]
  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue(reg) |> RegisterID.create

  /// Returns the string representation of a TMS320C6000 register.
  [<CompiledName "ToString">]
  let toString reg =
    match reg with
    | Register.A0 -> "A0"
    | Register.A1 -> "A1"
    | Register.A2 -> "A2"
    | Register.A3 -> "A3"
    | Register.A4 -> "A4"
    | Register.A5 -> "A5"
    | Register.A6 -> "A6"
    | Register.A7 -> "A7"
    | Register.A8 -> "A8"
    | Register.A9 -> "A9"
    | Register.A10 -> "A10"
    | Register.A11 -> "A11"
    | Register.A12 -> "A12"
    | Register.A13 -> "A13"
    | Register.A14 -> "A14"
    | Register.A15 -> "A15"
    | Register.A16 -> "A16"
    | Register.A17 -> "A17"
    | Register.A18 -> "A18"
    | Register.A19 -> "A19"
    | Register.A20 -> "A20"
    | Register.A21 -> "A21"
    | Register.A22 -> "A22"
    | Register.A23 -> "A23"
    | Register.A24 -> "A24"
    | Register.A25 -> "A25"
    | Register.A26 -> "A26"
    | Register.A27 -> "A27"
    | Register.A28 -> "A28"
    | Register.A29 -> "A29"
    | Register.A30 -> "A30"
    | Register.A31 -> "A31"
    | Register.B0 -> "B0"
    | Register.B1 -> "B1"
    | Register.B2 -> "B2"
    | Register.B3 -> "B3"
    | Register.B4 -> "B4"
    | Register.B5 -> "B5"
    | Register.B6 -> "B6"
    | Register.B7 -> "B7"
    | Register.B8 -> "B8"
    | Register.B9 -> "B9"
    | Register.B10 -> "B10"
    | Register.B11 -> "B11"
    | Register.B12 -> "B12"
    | Register.B13 -> "B13"
    | Register.B14 -> "B14"
    | Register.B15 -> "B15"
    | Register.B16 -> "B16"
    | Register.B17 -> "B17"
    | Register.B18 -> "B18"
    | Register.B19 -> "B19"
    | Register.B20 -> "B20"
    | Register.B21 -> "B21"
    | Register.B22 -> "B22"
    | Register.B23 -> "B23"
    | Register.B24 -> "B24"
    | Register.B25 -> "B25"
    | Register.B26 -> "B26"
    | Register.B27 -> "B27"
    | Register.B28 -> "B28"
    | Register.B29 -> "B29"
    | Register.B30 -> "B30"
    | Register.B31 -> "B31"
    | Register.AMR -> "AMR"
    | Register.CSR -> "CSR"
    | Register.DIER -> "DIER"
    | Register.DNUM -> "DNUM"
    | Register.ECR -> "ECR"
    | Register.EFR -> "EFR"
    | Register.FADCR -> "FADCR"
    | Register.FAUCR -> "FAUCR"
    | Register.FMCR -> "FMCR"
    | Register.GFPGFR -> "GFPGFR"
    | Register.GPLYA -> "GPLYA"
    | Register.GPLYB -> "GPLYB"
    | Register.ICR -> "ICR"
    | Register.IER -> "IER"
    | Register.IERR -> "IERR"
    | Register.IFR -> "IFR"
    | Register.ILC -> "ILC"
    | Register.IRP -> "IRP"
    | Register.ISR -> "ISR"
    | Register.ISTP -> "ISTP"
    | Register.ITSR -> "ITSR"
    | Register.NRP -> "NRP"
    | Register.NTSR -> "NTSR"
    | Register.PCE1 -> "PCE1"
    | Register.REP -> "REP"
    | Register.RILC -> "RILC"
    | Register.SSR -> "SSR"
    | Register.TSCH -> "TSCH"
    | Register.TSCL -> "TSCL"
    | Register.TSR -> "TSR"
    | _ -> Terminator.impossible ()

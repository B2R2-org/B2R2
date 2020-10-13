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

namespace B2R2.FrontEnd.BinLifter.TMS320C6000

open B2R2

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

/// Shortcut for Register type.
type internal R = Register

/// This module exposes several useful functions to handle TMS320C6000
/// registers.
[<RequireQualifiedAccess>]
module Register =
  let inline ofRegID (n: RegisterID): Register =
    int n |> LanguagePrimitives.EnumOfValue

  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  let ofString (str: string) =
    match str.ToLower () with
    | "a0" -> R.A0
    | "a1" -> R.A1
    | "a2" -> R.A2
    | "a3" -> R.A3
    | "a4" -> R.A4
    | "a5" -> R.A5
    | "a6" -> R.A6
    | "a7" -> R.A7
    | "a8" -> R.A8
    | "a9" -> R.A9
    | "a10" -> R.A10
    | "a11" -> R.A11
    | "a12" -> R.A12
    | "a13" -> R.A13
    | "a14" -> R.A14
    | "a15" -> R.A15
    | "a16" -> R.A16
    | "a17" -> R.A17
    | "a18" -> R.A18
    | "a19" -> R.A19
    | "a20" -> R.A20
    | "a21" -> R.A21
    | "a22" -> R.A22
    | "a23" -> R.A23
    | "a24" -> R.A24
    | "a25" -> R.A25
    | "a26" -> R.A26
    | "a27" -> R.A27
    | "a28" -> R.A28
    | "a29" -> R.A29
    | "a30" -> R.A30
    | "a31" -> R.A31
    | "b0" -> R.B0
    | "b1" -> R.B1
    | "b2" -> R.B2
    | "b3" -> R.B3
    | "b4" -> R.B4
    | "b5" -> R.B5
    | "b6" -> R.B6
    | "b7" -> R.B7
    | "b8" -> R.B8
    | "b9" -> R.B9
    | "b10" -> R.B10
    | "b11" -> R.B11
    | "b12" -> R.B12
    | "b13" -> R.B13
    | "b14" -> R.B14
    | "b15" -> R.B15
    | "b16" -> R.B16
    | "b17" -> R.B17
    | "b18" -> R.B18
    | "b19" -> R.B19
    | "b20" -> R.B20
    | "b21" -> R.B21
    | "b22" -> R.B22
    | "b23" -> R.B23
    | "b24" -> R.B24
    | "b25" -> R.B25
    | "b26" -> R.B26
    | "b27" -> R.B27
    | "b28" -> R.B28
    | "b29" -> R.B29
    | "b30" -> R.B30
    | "b31" -> R.B31
    | "amr" -> R.AMR
    | "csr" -> R.CSR
    | "dier" -> R.DIER
    | "dnum" -> R.DNUM
    | "ecr" -> R.ECR
    | "efr" -> R.EFR
    | "fadcr" -> R.FADCR
    | "faucr" -> R.FAUCR
    | "fmcr" -> R.FMCR
    | "gfpgfr" -> R.GFPGFR
    | "gplya" -> R.GPLYA
    | "gplyb" -> R.GPLYB
    | "icr" -> R.ICR
    | "ier" -> R.IER
    | "ierr" -> R.IERR
    | "ifr" -> R.IFR
    | "ilc" -> R.ILC
    | "irp" -> R.IRP
    | "isr" -> R.ISR
    | "istp" -> R.ISTP
    | "itsr" -> R.ITSR
    | "nrp" -> R.NRP
    | "ntsr" -> R.NTSR
    | "pce1" -> R.PCE1
    | "rep" -> R.REP
    | "rilc" -> R.RILC
    | "ssr" -> R.SSR
    | "tsch" -> R.TSCH
    | "tscl" -> R.TSCL
    | "tsr" -> R.TSR
    | _ -> Utils.impossible ()

  let toString = function
    | R.A0 -> "A0"
    | R.A1 -> "A1"
    | R.A2 -> "A2"
    | R.A3 -> "A3"
    | R.A4 -> "A4"
    | R.A5 -> "A5"
    | R.A6 -> "A6"
    | R.A7 -> "A7"
    | R.A8 -> "A8"
    | R.A9 -> "A9"
    | R.A10 -> "A10"
    | R.A11 -> "A11"
    | R.A12 -> "A12"
    | R.A13 -> "A13"
    | R.A14 -> "A14"
    | R.A15 -> "A15"
    | R.A16 -> "A16"
    | R.A17 -> "A17"
    | R.A18 -> "A18"
    | R.A19 -> "A19"
    | R.A20 -> "A20"
    | R.A21 -> "A21"
    | R.A22 -> "A22"
    | R.A23 -> "A23"
    | R.A24 -> "A24"
    | R.A25 -> "A25"
    | R.A26 -> "A26"
    | R.A27 -> "A27"
    | R.A28 -> "A28"
    | R.A29 -> "A29"
    | R.A30 -> "A30"
    | R.A31 -> "A31"
    | R.B0 -> "B0"
    | R.B1 -> "B1"
    | R.B2 -> "B2"
    | R.B3 -> "B3"
    | R.B4 -> "B4"
    | R.B5 -> "B5"
    | R.B6 -> "B6"
    | R.B7 -> "B7"
    | R.B8 -> "B8"
    | R.B9 -> "B9"
    | R.B10 -> "B10"
    | R.B11 -> "B11"
    | R.B12 -> "B12"
    | R.B13 -> "B13"
    | R.B14 -> "B14"
    | R.B15 -> "B15"
    | R.B16 -> "B16"
    | R.B17 -> "B17"
    | R.B18 -> "B18"
    | R.B19 -> "B19"
    | R.B20 -> "B20"
    | R.B21 -> "B21"
    | R.B22 -> "B22"
    | R.B23 -> "B23"
    | R.B24 -> "B24"
    | R.B25 -> "B25"
    | R.B26 -> "B26"
    | R.B27 -> "B27"
    | R.B28 -> "B28"
    | R.B29 -> "B29"
    | R.B30 -> "B30"
    | R.B31 -> "B31"
    | R.AMR -> "AMR"
    | R.CSR -> "CSR"
    | R.DIER -> "DIER"
    | R.DNUM -> "DNUM"
    | R.ECR -> "ECR"
    | R.EFR -> "EFR"
    | R.FADCR -> "FADCR"
    | R.FAUCR -> "FAUCR"
    | R.FMCR -> "FMCR"
    | R.GFPGFR -> "GFPGFR"
    | R.GPLYA -> "GPLYA"
    | R.GPLYB -> "GPLYB"
    | R.ICR -> "ICR"
    | R.IER -> "IER"
    | R.IERR -> "IERR"
    | R.IFR -> "IFR"
    | R.ILC -> "ILC"
    | R.IRP -> "IRP"
    | R.ISR -> "ISR"
    | R.ISTP -> "ISTP"
    | R.ITSR -> "ITSR"
    | R.NRP -> "NRP"
    | R.NTSR -> "NTSR"
    | R.PCE1 -> "PCE1"
    | R.REP -> "REP"
    | R.RILC -> "RILC"
    | R.SSR -> "SSR"
    | R.TSCH -> "TSCH"
    | R.TSCL -> "TSCL"
    | R.TSR -> "TSR"
    | _ -> Utils.impossible ()


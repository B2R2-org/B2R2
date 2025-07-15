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

namespace B2R2.FrontEnd.Intel

open LanguagePrimitives

/// remove Prx
/// Represents an Instruction prefixes.
[<System.FlagsAttribute>]
type Prefix =
  /// No prefix.
  | PrxNone = 0x0
  /// Lock prefix.
  | PrxLOCK = 0x1
  /// REPNE/REPNZ prefix is encoded using F2H.
  | PrxREPNZ = 0x2
  /// Bound prefix is encoded using F2H.
  | PrxBND = 0x4
  /// REP or REPE/REPZ is encoded using F3H.
  | PrxREPZ = 0x8
  /// CS segment prefix.
  | PrxCS = 0x10
  /// SS segment prefix.
  | PrxSS = 0x20
  /// DS segment prefix.
  | PrxDS = 0x40
  /// ES segment prefix.
  | PrxES = 0x80
  /// FS segment prefix.
  | PrxFS = 0x100
  /// GS segment prefix.
  | PrxGS = 0x200
  /// Operand-size override prefix is encoded using 66H.
  | PrxOPSIZE = 0x400
  /// 67H - Address-size override prefix.
  | PrxADDRSIZE = 0x800

/// Provides functions to access and manipulate instruction prefixes.
[<RequireQualifiedAccess>]
module internal Prefix =
  let inline hasAddrSz p = p &&& Prefix.PrxADDRSIZE = Prefix.PrxADDRSIZE

  let inline hasOprSz p = p &&& Prefix.PrxOPSIZE = Prefix.PrxOPSIZE

  let inline hasREPZ p = p &&& Prefix.PrxREPZ = Prefix.PrxREPZ

  let inline hasREPNZ p = p &&& Prefix.PrxREPNZ = Prefix.PrxREPNZ

  let inline hasLock p = p &&& Prefix.PrxLOCK = Prefix.PrxLOCK

  /// Filter out segment-related prefixes.
  let [<Literal>] ClearSegMask: Prefix = EnumOfValue 0xFC0F

  /// Filter out PrxREPNZ(0x2), PrxREPZ(0x8), and PrxOPSIZE(0x400).
  let [<Literal>] ClearVEXPrefMask: Prefix = EnumOfValue 0xFBF5

  /// Filter out PrxREPZ(0x8)
  let [<Literal>] ClearREPZPrefMask: Prefix = EnumOfValue 0xFFF7

  /// Filter out group 1 prefixes.
  let [<Literal>] ClearGrp1PrefMask: Prefix = EnumOfValue 0xFFF0

  let getSegment pref =
    if (pref &&& Prefix.PrxCS) <> Prefix.PrxNone then Some R.CS
    elif (pref &&& Prefix.PrxDS) <> Prefix.PrxNone then Some R.DS
    elif (pref &&& Prefix.PrxES) <> Prefix.PrxNone then Some R.ES
    elif (pref &&& Prefix.PrxFS) <> Prefix.PrxNone then Some R.FS
    elif (pref &&& Prefix.PrxGS) <> Prefix.PrxNone then Some R.GS
    elif (pref &&& Prefix.PrxSS) <> Prefix.PrxNone then Some R.SS
    else None

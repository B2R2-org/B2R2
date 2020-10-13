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

module internal B2R2.FrontEnd.BinLifter.Intel.Helper

open B2R2
open B2R2.FrontEnd.BinLifter
open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("B2R2.Peripheral.Assembly.Intel")>]
do ()

/// Create a new instruction descriptor.
let newTemporaryIns opcode operands preInfo insSize =
  {
    Prefixes = preInfo.TPrefixes
    REXPrefix = preInfo.TREXPrefix
    VEXInfo = preInfo.TVEXInfo
    Opcode = opcode
    Operands = operands
    InsSize = insSize
  }

let segRegToBase = function
  | R.CS -> R.CSBase
  | R.DS -> R.DSBase
  | R.ES -> R.ESBase
  | R.FS -> R.FSBase
  | R.GS -> R.GSBase
  | R.SS -> R.SSBase
  | _ -> failwith "Unhandled segment."

let inline hasREXW rexPref = rexPref &&& REXPrefix.REXW = REXPrefix.REXW
let inline hasREXR rexPref = rexPref &&& REXPrefix.REXR = REXPrefix.REXR
let inline hasAddrSz prefs = (prefs &&& Prefix.PrxADDRSIZE) <> Prefix.PrxNone
let inline hasOprSz prefs = (prefs &&& Prefix.PrxOPSIZE) <> Prefix.PrxNone
let inline hasREPZ prefs = (prefs &&& Prefix.PrxREPZ) <> Prefix.PrxNone
let inline hasREPNZ prefs = (prefs &&& Prefix.PrxREPNZ) <> Prefix.PrxNone
let inline hasLock prefs = (prefs &&& Prefix.PrxLOCK) <> Prefix.PrxNone

let inline ensure32 t =
  if WordSize.is64 t.TWordSize then raise ParsingFailureException else ()

let inline ensure64 t =
  if WordSize.is32 t.TWordSize then raise ParsingFailureException else ()

/// Filter out segment-related prefixes.
let clearSegMask : Prefix = LanguagePrimitives.EnumOfValue 0xFC0F

/// Filter out PrxREPNZ(0x2), PrxREPZ(0x8), and PrxOPSIZE(0x400).
let clearVEXPrefMask : Prefix = LanguagePrimitives.EnumOfValue 0xFBF5

/// Filter out group 1 prefixes.
let clearGrp1PrefMask : Prefix = LanguagePrimitives.EnumOfValue 0xFFF0

let getSegment pref =
  if (pref &&& Prefix.PrxCS) <> Prefix.PrxNone then Some R.CS
  elif (pref &&& Prefix.PrxDS) <> Prefix.PrxNone then Some R.DS
  elif (pref &&& Prefix.PrxES) <> Prefix.PrxNone then Some R.ES
  elif (pref &&& Prefix.PrxFS) <> Prefix.PrxNone then Some R.FS
  elif (pref &&& Prefix.PrxGS) <> Prefix.PrxNone then Some R.GS
  elif (pref &&& Prefix.PrxSS) <> Prefix.PrxNone then Some R.SS
  else None

let isBranch = function
  | Opcode.CALLFar | Opcode.CALLNear
  | Opcode.JMPFar | Opcode.JMPNear
  | Opcode.RETFar | Opcode.RETFarImm | Opcode.RETNear | Opcode.RETNearImm
  | Opcode.JA | Opcode.JB | Opcode.JBE | Opcode.JCXZ | Opcode.JECXZ
  | Opcode.JG | Opcode.JL | Opcode.JLE | Opcode.JNB | Opcode.JNL | Opcode.JNO
  | Opcode.JNP | Opcode.JNS | Opcode.JNZ | Opcode.JO | Opcode.JP
  | Opcode.JRCXZ | Opcode.JS | Opcode.JZ | Opcode.LOOP | Opcode.LOOPE
  | Opcode.LOOPNE -> true
  | _ -> false

let isCETInstr = function
  | Opcode.INCSSPD | Opcode.INCSSPQ | Opcode.RDSSPD | Opcode.RDSSPQ
  | Opcode.SAVEPREVSSP | Opcode.RSTORSSP | Opcode.WRSSD | Opcode.WRSSQ
  | Opcode.WRUSSD | Opcode.WRUSSQ | Opcode.SETSSBSY | Opcode.CLRSSBSY -> true
  | _ -> false

/// Create a temporary instruction information.
let newTemporaryInfo prefs rexPref vInfo wordSize =
  {
    TPrefixes = prefs
    TREXPrefix = rexPref
    TVEXInfo = vInfo
    TWordSize = wordSize
  }

// vim: set tw=80 sts=2 sw=2:

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
open LanguagePrimitives

[<assembly: InternalsVisibleTo("B2R2.Peripheral.Assembly.Intel")>]
do ()

/// Temporary information needed for parsing the opcode and the operands. This
/// includes prefixes, rexprefix, VEX information, and the word size.
type TemporaryInfo = {
  /// Prefixes.
  TPrefixes: Prefix
  /// REX prefixes.
  TREXPrefix: REXPrefix
  /// VEX information.
  TVEXInfo: VEXInfo option
  /// Current architecture word size.
  TWordSize: WordSize
}

/// Create a new instruction descriptor.
let newTemporaryIns opcode operands (preInfo: TemporaryInfo) insSize =
  { Prefixes = preInfo.TPrefixes
    REXPrefix = preInfo.TREXPrefix
    VEXInfo = preInfo.TVEXInfo
    Opcode = opcode
    Operands = operands
    InsSize = insSize }

type ReadHelper (r, addr, ipos, cpos) =
  let mutable ipos: int = ipos
  let mutable cpos: int = cpos
  member __.BinReader with get(): BinReader = r
  member __.InsAddr with get(): Addr = addr
  member __.InitPos with get() = ipos and set(p) = ipos <- p
  member __.CurrPos with get() = cpos and set(p) = cpos <- p
  member __.IncPos () = cpos <- cpos + 1

  member inline private __.ModCPos i = cpos <- cpos + i
  member inline __.PeekByte () = r.PeekByte cpos
  member inline __.ReadByte () = let v = r.PeekByte cpos in __.ModCPos 1; v
  member inline __.ReadInt8 () = let v = r.PeekInt8 cpos in __.ModCPos 1; v
  member inline __.ReadInt16 () = let v = r.PeekInt16 cpos in __.ModCPos 2; v
  member inline __.ReadInt32 () = let v = r.PeekInt32 cpos in __.ModCPos 4; v
  member inline __.ReadInt64 () = let v = r.PeekInt64 cpos in __.ModCPos 8; v
  member inline __.ReadUInt8 () = let v = r.PeekUInt8 cpos in __.ModCPos 1; v
  member inline __.ReadUInt16 () = let v = r.PeekUInt16 cpos in __.ModCPos 2; v
  member inline __.ReadUInt32 () = let v = r.PeekUInt32 cpos in __.ModCPos 4; v
  member inline __.ReadUInt64 () = let v = r.PeekUInt64 cpos in __.ModCPos 8; v
  member inline __.ParsedLen () = cpos - ipos

#if DEBUG
let inline ensure32 (t: TemporaryInfo) =
  if WordSize.is64 t.TWordSize then raise ParsingFailureException else ()

let inline ensure64 (t: TemporaryInfo) =
  if WordSize.is32 t.TWordSize then raise ParsingFailureException else ()
#endif

let inline hasREXW rexPref = rexPref &&& REXPrefix.REXW = REXPrefix.REXW

let inline hasREXR rexPref = rexPref &&& REXPrefix.REXR = REXPrefix.REXR

let inline hasAddrSz p = p &&& Prefix.PrxADDRSIZE = Prefix.PrxADDRSIZE

let inline hasOprSz p = p &&& Prefix.PrxOPSIZE = Prefix.PrxOPSIZE

let inline hasREPZ p = p &&& Prefix.PrxREPZ = Prefix.PrxREPZ

let inline hasREPNZ p = p &&& Prefix.PrxREPNZ = Prefix.PrxREPNZ

let inline hasLock p = p &&& Prefix.PrxLOCK = Prefix.PrxLOCK

/// Filter out segment-related prefixes.
let [<Literal>] clearSegMask: Prefix = EnumOfValue 0xFC0F

/// Filter out PrxREPNZ(0x2), PrxREPZ(0x8), and PrxOPSIZE(0x400).
let [<Literal>] clearVEXPrefMask: Prefix = EnumOfValue 0xFBF5

/// Filter out group 1 prefixes.
let [<Literal>] clearGrp1PrefMask: Prefix = EnumOfValue 0xFFF0

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
let inline newTemporaryInfo prefs rexPref vInfo wordSize =
  { TPrefixes = prefs
    TREXPrefix = rexPref
    TVEXInfo = vInfo
    TWordSize = wordSize }

/// AHR12LIb ALIb ALOb ALR8LIb BHR15LIb BLR11LIb CHR13LIb CLR9LIb DHR14LIb
/// DLR10LIb Eb Eb1 EbCL EbGb EbIb GbEb IbAL Jb ObAL XbYb
let szByte _ _ effAddrSz =
  { MemEffOprSize = 8<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 8<rt>
    RegSize = 8<rt>
    OperationSize = 8<rt> }

/// GwMw EvSw EwGw MwGw SwEw
let szWord _ _ effAddrSz =
  { MemEffOprSize = 16<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 16<rt>
    RegSize = 16<rt>
    OperationSize = 16<rt> }

/// ALDX DXAL DXEAX EAX EAXDX EAXIb EBP EBX ECX EDI EDX ESI ESP Ev Ev1 EvCL EvGv
/// EvGvCL EvGvIb EvIb EvSIb EvSIz EyGy GvEv GvEvSIb GvEvSIz GvEy GvMa GvMv
/// GyByEy GyEy GyEyBy GyEyIb GyMy Ib IbEAX Iw IwIb Mv MyGy Mz OvRAX RAXIv RAXOv
/// RAXrAX RAXrBP RAXrBX RAXrCX RAXrDI RAXrDX RAXrSI RAXrSP RAXSIz RAXz RBPIv
/// RBPz RBXIv RBXz RCXIv RCXz RDIIv RDIz RDXIv RDXz RSIIv RSIz RSPIv RSPz Rv Ry
/// SIb SIz
let szDef _ effOprSz effAddrSz =
  { MemEffOprSize = effOprSz
    MemEffAddrSize = effAddrSz
    MemEffRegSize = effOprSz
    RegSize = effOprSz
    OperationSize = effOprSz }

/// HxUxIb MpdVpd MpsVps MxVx MZxzVZxz VpdHpdWpd VpdHpdWpdIb VpdWpd VpsHpsWps
/// VpsHpsWpsIb VpsWps VsdHsdWsdIb VssHssWssIb VxHxWsd VxHxWss VxHxWx VxHxWxIb
/// VxMx VxWx VxWxIb VZxzWZxz WpdVpd WpsVps WsdHxVsd WssHxVss WxVx WZxzVZxz
let szVecDef (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  { MemEffOprSize = vLen
    MemEffAddrSize = effAddrSz
    MemEffRegSize = vLen
    RegSize = vLen
    OperationSize = vLen }

/// GvEd Md
let szDV _ effOprSz effAddrSz =
  { MemEffOprSize = 32<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 32<rt>
    RegSize = effOprSz
    OperationSize = effOprSz }

/// Md
let szD _ effOprSz effAddrSz =
  { MemEffOprSize = 32<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 32<rt>
    RegSize = effOprSz
    OperationSize = 32<rt> }

/// Ew Mw
let szMemW _ effOprSz effAddrSz =
  { MemEffOprSize = 16<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 16<rt>
    RegSize = effOprSz
    OperationSize = 16<rt> }

/// CS ES DS FS GS SS
let szRegW _ effOprSz effAddrSz =
  { MemEffOprSize = effOprSz
    MemEffAddrSize = effAddrSz
    MemEffRegSize = effOprSz
    RegSize = 16<rt>
    OperationSize = 16<rt> }

/// GvEw
let szWV _ effOprSz effAddrSz =
  { MemEffOprSize = 16<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 16<rt>
    RegSize = effOprSz
    OperationSize = effOprSz }

/// RAX RCX RDX RBX RSP RBP RSI RDI Jz
let szD64 (t: TemporaryInfo) effOprSz effAddrSz =
  let oprSize = WordSize.toRegType t.TWordSize
  { MemEffOprSize = effOprSz
    MemEffAddrSize = effAddrSz
    MemEffRegSize = effOprSz
    RegSize = oprSize
    OperationSize = oprSize }

/// GzMp
let szPZ (t: TemporaryInfo) effOprSz effAddrSz =
  let oprSize =
    if t.TPrefixes &&& Prefix.PrxOPSIZE = Prefix.PrxOPSIZE then 32<rt>
    else 48<rt>
  { MemEffOprSize = oprSize
    MemEffAddrSize = effAddrSz
    MemEffRegSize = effOprSz
    RegSize = effOprSz
    OperationSize = effOprSz }

/// MdqVdq VdqHdqUdq VdqHdqWdqIb VdqMdq VdqUdq VdqWdq VdqWdqIb WdqVdq
let szDqDq _ _ effAddrSz =
  { MemEffOprSize = 128<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = 128<rt>
    OperationSize = 128<rt> }

/// VdqWdqd VdqMd VdqHdqWdqd VdqWdqdIb MdVdq
let szDqdDq _ _ effAddrSz =
  { MemEffOprSize = 32<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = 128<rt>
    OperationSize = 128<rt> }

/// WdqdVdq MdVdq
let szDqdDqMR _ _ effAddrSz =
  { MemEffOprSize = 32<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = 128<rt>
    OperationSize = 32<rt> }

/// VdqWdqq VdqMq VdqHdqMq VdqHdqWdqq VdqWdqqIb WdqqVdq MqVdq
let szDqqDq _ _ effAddrSz =
  { MemEffOprSize = 64<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = 128<rt>
    OperationSize = 128<rt> }

/// WdqqVdq MqVdq
let szDqqDqMR _ _ effAddrSz =
  { MemEffOprSize = 64<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = 128<rt>
    OperationSize = 64<rt> }

/// VxWxq
let szXqX (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  let struct (mopr, maddr, mreg) =
    match vLen with
    | 128<rt> -> struct (64<rt>, effAddrSz, 128<rt>)
    | 256<rt> -> struct (vLen, effAddrSz, vLen)
    | _ -> Utils.futureFeature () (* EVEX *)
  { MemEffOprSize = mopr
    MemEffAddrSize = maddr
    MemEffRegSize = mreg
    RegSize = vLen
    OperationSize = vLen }

/// BNBNdqq BNdqqBN
let szDqqDqWS (t: TemporaryInfo) effOprSz effAddrSz =
  let struct (mopr, maddr, mreg) =
    match t.TWordSize with
    | WordSize.Bit32 -> struct (64<rt>, effAddrSz, 128<rt>)
    | WordSize.Bit64 -> struct (128<rt>, effAddrSz, 128<rt>)
    | _ -> raise ParsingFailureException
  { MemEffOprSize = mopr
    MemEffAddrSize = maddr
    MemEffRegSize = mreg
    RegSize = 128<rt>
    OperationSize = effOprSz }

/// BNEv BNMv BNMib VdqEy VssHssEy VsdHsdEy
let szVyDq _ effOprSz effAddrSz =
  { MemEffOprSize = effOprSz
    MemEffAddrSize = effAddrSz
    MemEffRegSize = effOprSz
    RegSize = 128<rt>
    OperationSize = 128<rt> }

/// EyVdq MibBN
let szVyDqMR _ effOprSz effAddrSz =
  { MemEffOprSize = effOprSz
    MemEffAddrSize = effAddrSz
    MemEffRegSize = effOprSz
    RegSize = 128<rt>
    OperationSize = effOprSz }

/// RyCd RyDd CdRy DdRy
let szDY (t: TemporaryInfo) effOprSz effAddrSz =
  let effRegSz = WordSize.toRegType t.TWordSize
  { MemEffOprSize = effOprSz
    MemEffAddrSize = effAddrSz
    MemEffRegSize = effRegSz
    RegSize = effOprSz
    OperationSize = effOprSz }

/// VdqQpi VdqNq
let szQDq _ _ effAddrSz =
  { MemEffOprSize = 64<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 64<rt>
    RegSize = 128<rt>
    OperationSize = 128<rt> }

/// PpiWdqq
let szDqqQ _ _ effAddrSz =
  { MemEffOprSize = 64<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = 64<rt>
    OperationSize = 64<rt> }

/// PpiWdq PqUdq
let szDqQ _ _ effAddrSz =
  { MemEffOprSize = 128<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = 64<rt>
    OperationSize = 64<rt> }

/// GyWdqd
let szDqdY _ effOprSz effAddrSz =
  { MemEffOprSize = 32<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = effOprSz
    OperationSize = effOprSz }

/// GyWdqq
let szDqqY _ effOprSz effAddrSz =
  { MemEffOprSize = 64<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = effOprSz
    OperationSize = effOprSz }

/// GyUdq
let szDqY _ effOprSz effAddrSz =
  { MemEffOprSize = 128<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = effOprSz
    OperationSize = effOprSz }

/// UdqIb Mdq
let szDq _ effOprSz effAddrSz =
  { MemEffOprSize = 128<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = effOprSz
    OperationSize = 128<rt> }

/// PqQd
let szDQ _ _ effAddrSz =
  { MemEffOprSize = 32<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 64<rt>
    RegSize = 64<rt>
    OperationSize = 64<rt> }

/// PqQq PqQqIb QqPq MqPq
let szQQ _ _ effAddrSz =
  { MemEffOprSize = 64<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 64<rt>
    RegSize = 64<rt>
    OperationSize = 64<rt> }

/// EyPq
let szYQ _ effOprSz effAddrSz =
  { MemEffOprSize = effOprSz
    MemEffAddrSize = effAddrSz
    MemEffRegSize = effOprSz
    RegSize = 64<rt>
    OperationSize = effOprSz }

/// PqEy
let szYQRM _ effOprSz effAddrSz =
  { MemEffOprSize = effOprSz
    MemEffAddrSize = effAddrSz
    MemEffRegSize = effOprSz
    RegSize = 64<rt>
    OperationSize = 64<rt> }

/// PqEdwIb
let szDwQ _ _ effAddrSz =
  { MemEffOprSize = 16<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 32<rt>
    RegSize = 64<rt>
    OperationSize = 64<rt> }

/// VdqEdwIb VdqHdqEdwIb
let szDwDq _ effOprSz effAddrSz =
  { MemEffOprSize = 16<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 32<rt>
    RegSize = 128<rt>
    OperationSize = effOprSz }

/// EdwVdqIb
let szDwDqMR _ _ effAddrSz =
  { MemEffOprSize = 16<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 32<rt>
    RegSize = 128<rt>
    OperationSize = 16<rt> }

/// GdNqIb GdNq
let szQD _ _ effAddrSz =
  { MemEffOprSize = 64<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 64<rt>
    RegSize = 32<rt>
    OperationSize = 32<rt> }

/// GdUdqIb GdUdq
let szDqd _ _ effAddrSz =
  { MemEffOprSize = 128<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = 32<rt>
    OperationSize = 32<rt> }

/// VxHxWdq
let szDqX (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  { MemEffOprSize = 128<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = vLen
    OperationSize = vLen }

/// GdUx
let szXD (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  { MemEffOprSize = vLen
    MemEffAddrSize = effAddrSz
    MemEffRegSize = vLen
    RegSize = 32<rt>
    OperationSize = 32<rt> }

/// VxWdqqdq
let szDqqdqX (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  let struct (mopr, maddr, mreg) =
    match vLen with
    | 128<rt> -> struct (64<rt>, effAddrSz, 128<rt>)
    | 256<rt> -> struct (128<rt>, effAddrSz, 128<rt>)
    | _ -> Utils.futureFeature () (* EVEX *)
  { MemEffOprSize = mopr
    MemEffAddrSize = maddr
    MemEffRegSize = mreg
    RegSize = vLen
    OperationSize = vLen }

/// VxWdqdq
let szDqddqX (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  let struct (mopr, maddr, mreg) =
    match vLen with
    | 128<rt> -> struct (32<rt>, effAddrSz, 128<rt>)
    | 256<rt> -> struct (64<rt>, effAddrSz, 128<rt>)
    | _ -> Utils.futureFeature () (* EVEX *)
  { MemEffOprSize = mopr
    MemEffAddrSize = maddr
    MemEffRegSize = mreg
    RegSize = vLen
    OperationSize = vLen }

/// VdqWdqw
let szDqwDq _ effOprSz effAddrSz =
  { MemEffOprSize = 16<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = 128<rt>
    OperationSize = 128<rt> }

/// VxWdqwd
let szDqwX (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  let struct (mopr, maddr, mreg) =
    match vLen with
    | 128<rt> -> struct (16<rt>, effAddrSz, 128<rt>)
    | 256<rt> -> struct (32<rt>, effAddrSz, 128<rt>)
    | _ -> Utils.futureFeature () (* EVEX *)
  { MemEffOprSize = mopr
    MemEffAddrSize = maddr
    MemEffRegSize = mreg
    RegSize = vLen
    OperationSize = vLen }

/// VqqMdq VqqHqqWdqIb
let szDqQqq _ _ effAddrSz =
  { MemEffOprSize = 128<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = 256<rt>
    OperationSize = 256<rt> }

/// VxWdqb
let szDqbX (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  { MemEffOprSize = 8<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = vLen
    OperationSize = vLen }

/// VdqEdbIb VdqHdqEdbIb
let szDbDq _ _ effAddrSz =
  { MemEffOprSize = 8<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 32<rt>
    RegSize = 128<rt>
    OperationSize = 128<rt> }

/// GvEb Mb
let szBV _ effOprSz effAddrSz =
  { MemEffOprSize = 8<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 8<rt>
    RegSize = effOprSz
    OperationSize = effOprSz }

/// NqIb Mq
let szQ _ _ effAddrSz =
  { MemEffOprSize = 64<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 64<rt>
    RegSize = 64<rt>
    OperationSize = 64<rt> }

/// Ms
let szS (t: TemporaryInfo) _ effAddrSz =
  let effOprSz = if t.TWordSize = WordSize.Bit32 then 48<rt> else 80<rt>
  { MemEffOprSize = effOprSz
    MemEffAddrSize = effAddrSz
    MemEffRegSize = effOprSz
    RegSize = effOprSz
    OperationSize = effOprSz }

/// VxMd
let szDX (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  { MemEffOprSize = 32<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 32<rt>
    RegSize = vLen
    OperationSize = vLen }

/// VZxzWdqd VxHxWdqd
let szDqdXz (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  { MemEffOprSize = 32<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = vLen
    OperationSize = vLen }

/// VxHxWdqq
let szDqqX (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  { MemEffOprSize = 64<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = vLen
    OperationSize = vLen }

/// Ap Ep Mp
let szP _ effOprSz effAddrSz =
  let struct (regSz, oprSz) =
    if effOprSz = 16<rt> then struct (16<rt>, 32<rt>)
    elif effOprSz = 32<rt> then struct (32<rt>, 48<rt>)
    else struct (64<rt>, 80<rt>)
  { MemEffOprSize = oprSz
    MemEffAddrSize = effAddrSz
    MemEffRegSize = regSz
    RegSize = effOprSz
    OperationSize = oprSz }

/// GvMp
let szPRM _ effOprSz effAddrSz =
  let struct (regSz, oprSz) =
    if effOprSz = 16<rt> then struct (16<rt>, 32<rt>)
    elif effOprSz = 32<rt> then struct (32<rt>, 48<rt>)
    else struct (64<rt>, 80<rt>)
  { MemEffOprSize = oprSz
    MemEffAddrSize = effAddrSz
    MemEffRegSize = regSz
    RegSize = effOprSz
    OperationSize = effOprSz }

/// VZxzWxq
let szXqXz (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  let struct (mopr, maddr, mreg) =
    match vLen with
    | 128<rt> -> struct (64<rt>, effAddrSz, 128<rt>)
    | 256<rt> -> struct (128<rt>, effAddrSz, 128<rt>)
    | 512<rt> -> struct (256<rt>, effAddrSz, 256<rt>)
    | _ -> raise ParsingFailureException
  { MemEffOprSize = mopr
    MemEffAddrSize = maddr
    MemEffRegSize = mreg
    RegSize = vLen
    OperationSize = vLen }

/// VZxzWx
let szXXz (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  let struct (mopr, maddr, mreg) =
    match vLen with
    | 128<rt> -> struct (vLen, effAddrSz, vLen)
    | 256<rt> -> struct (128<rt>, effAddrSz, 128<rt>)
    | 512<rt> -> struct (256<rt>, effAddrSz, 256<rt>)
    | _ -> raise ParsingFailureException
  { MemEffOprSize = mopr
    MemEffAddrSize = maddr
    MemEffRegSize = mreg
    RegSize = vLen
    OperationSize = vLen }

/// VxWZxz
let szXzX (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  let regSize =
    match vLen with
    | 128<rt> -> vLen
    | 256<rt> -> 128<rt>
    | 512<rt> -> 256<rt>
    | _ -> raise ParsingFailureException
  { MemEffOprSize = vLen
    MemEffAddrSize = effAddrSz
    MemEffRegSize = vLen
    RegSize = regSize
    OperationSize = regSize }

/// VZxzHxWZxz VZxzHxWZxzIb
let szXzXz (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  { MemEffOprSize = vLen
    MemEffAddrSize = effAddrSz
    MemEffRegSize = vLen
    RegSize = vLen
    OperationSize = vLen }

/// VqqWdqq
let szDqqQq _ effOprSz effAddrSz =
  { MemEffOprSize = 64<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = 256<rt>
    OperationSize = 256<rt> }

/// VZxzWdqq
let szDqqXz (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  { MemEffOprSize = 64<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = vLen
    OperationSize = vLen }

/// WqqVZxz WZqqVZxzIb WqqVZxzIb
let szQqXz (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  { MemEffOprSize = 256<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 256<rt>
    RegSize = vLen
    OperationSize = 256<rt> }

/// VZxzHxWqqIb
let szQqXzRM (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  { MemEffOprSize = 256<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 256<rt>
    RegSize = vLen
    OperationSize = vLen }

/// VxWdqd
let szDqdX (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  { MemEffOprSize = 32<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = vLen
    OperationSize = vLen }

/// VZxzRd
let szDXz (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  { MemEffOprSize = 32<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 32<rt>
    RegSize = vLen
    OperationSize = vLen }

/// VZxzRq
let szQXz (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  { MemEffOprSize = 64<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 64<rt>
    RegSize = vLen
    OperationSize = vLen }

/// WdqVqqIb
let szDqQq _ effOprSz effAddrSz =
  { MemEffOprSize = 128<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = 256<rt>
    OperationSize = 128<rt> }

/// WdqVZxzIb
let szDqXz (t: TemporaryInfo) _ effAddrSz =
  let vLen = (Option.get t.TVEXInfo).VectorLength
  { MemEffOprSize = 128<rt>
    MemEffAddrSize = effAddrSz
    MemEffRegSize = 128<rt>
    RegSize = vLen
    OperationSize = 128<rt> }

/// VdqHdqEyIb
let szYDq _ effOprSz effAddrSz =
  { MemEffOprSize = effOprSz
    MemEffAddrSize = effAddrSz
    MemEffRegSize = effOprSz
    RegSize = 128<rt>
    OperationSize = 128<rt> }

// vim: set tw=80 sts=2 sw=2:

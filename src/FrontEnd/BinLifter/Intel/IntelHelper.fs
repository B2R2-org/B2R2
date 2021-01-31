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

type [<AbstractClass>] OperandParser () =
  abstract member Render:
    ReadHelper -> InstrSize -> struct (Operands * InstrSize)

and [<AbstractClass>] InsSizeComputer () =
  abstract Render: ReadHelper -> RegType -> RegType -> InstrSize

and ReadHelper (rd, addr, initialPos, cpos, pref, rex, vex, wordSz, ops, szs) =
  let mutable r: BinReader = rd
  let mutable addr: Addr = addr
  let mutable ipos: int = initialPos
  let mutable cpos: int = cpos (* current position *)
  let mutable pref: Prefix = pref
  let mutable rex: REXPrefix = rex
  let mutable vex: VEXInfo option = vex
  let mutable wordSize: WordSize = wordSz
#if LCACHE
  let mutable prefixEnd: int = initialPos
  let mutable hashEnd: int = initialPos
#endif
  new (wordSz, oparsers, szcomputers) =
    ReadHelper (EmptyBinReader () :> BinReader,
                0UL, 0, 0, Prefix.PrxNone, REXPrefix.NOREX, None,
                wordSz, oparsers, szcomputers)
  member __.BinReader with get() = r and set(r') = r <- r'
  member __.InsAddr with get(): Addr = addr and set(a) = addr <- a
  member __.InitialPos with get() = ipos and set(p) = ipos <- p
  member __.CurrPos with get() = cpos and set(p) = cpos <- p
  member __.IncPos () = cpos <- cpos + 1
  member __.Prefixes with get() = pref and set(p) = pref <- p
  member __.REXPrefix with get(): REXPrefix = rex and set(r) = rex <- r
  member __.VEXInfo with get(): VEXInfo option = vex and set(v) = vex <- v
  member __.WordSize with get(): WordSize = wordSize and set(w) = wordSize <- w
  member __.OprParsers with get(): OperandParser [] = ops
  member __.SzComputers with get(): InsSizeComputer [] = szs

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
#if LCACHE
  member inline __.MarkHashEnd () =
    if hashEnd = ipos then hashEnd <- cpos else ()

  member inline __.MarkPrefixEnd (pos) = prefixEnd <- pos

  member inline __.GetInsHash (vinfo: VEXInfo option) =
    let bs = r.PeekBytes (hashEnd - prefixEnd, prefixEnd)
    let n = Array.zeroCreate 8
    Array.blit bs 0 n 0 bs.Length
    let hash = System.BitConverter.ToUInt64 (n, 0)
    if Option.isNone vinfo then (uint64 (cpos - ipos) <<< 52) ||| hash
    else hash
#endif

let inline hasREXW rexPref = rexPref &&& REXPrefix.REXW = REXPrefix.REXW

let inline hasREXR rexPref = rexPref &&& REXPrefix.REXR = REXPrefix.REXR

let inline hasAddrSz p = p &&& Prefix.PrxADDRSIZE = Prefix.PrxADDRSIZE

let inline hasOprSz p = p &&& Prefix.PrxOPSIZE = Prefix.PrxOPSIZE

let inline hasREPZ p = p &&& Prefix.PrxREPZ = Prefix.PrxREPZ

let inline hasREPNZ p = p &&& Prefix.PrxREPNZ = Prefix.PrxREPNZ

let inline hasLock p = p &&& Prefix.PrxLOCK = Prefix.PrxLOCK

let inline is64bit (rhlp: ReadHelper) = rhlp.WordSize = WordSize.Bit64

let inline hasNoPref (rhlp: ReadHelper) = (int rhlp.Prefixes) = 0

let inline hasNoREX (rhlp: ReadHelper) = rhlp.REXPrefix = REXPrefix.NOREX

let inline getMod (byte: byte) = (int byte >>> 6) &&& 0b11

let inline getReg (byte: byte) = (int byte >>> 3) &&& 0b111

let inline getRM (byte: byte) = (int byte) &&& 0b111

let inline getSTReg n = Register.make n Register.Kind.FPU |> OprReg

let inline modIsMemory b = (getMod b) <> 0b11

let inline modIsReg b = (getMod b) = 0b11

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

/// AHR12LIb ALIb ALOb ALR8LIb BHR15LIb BLR11LIb CHR13LIb CLR9LIb DHR14LIb
/// DLR10LIb Eb Eb1 EbCL EbGb EbIb GbEb IbAL Jb ObAL XbYb
type SzByte () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 8<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 8<rt>
      RegSize = 8<rt>
      OperationSize = 8<rt> }

/// GwMw EvSw EwGw MwGw SwEw
type SzWord () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
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
type SzDef () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = effOprSz
      MemEffAddrSize = effAddrSz
      MemEffRegSize = effOprSz
      RegSize = effOprSz
      OperationSize = effOprSz }

/// HxUxIb MpdVpd MpsVps MxVx MZxzVZxz VpdHpdWpd VpdHpdWpdIb VpdWpd VpsHpsWps
/// VpsHpsWpsIb VpsWps VsdHsdWsdIb VssHssWssIb VxHxWsd VxHxWss VxHxWx VxHxWxIb
/// VxMx VxWx VxWxIb VZxzWZxz WpdVpd WpsVps WsdHxVsd WssHxVss WxVx WZxzVZxz
type SzVecDef () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    { MemEffOprSize = vLen
      MemEffAddrSize = effAddrSz
      MemEffRegSize = vLen
      RegSize = vLen
      OperationSize = vLen }

/// GvEd Md
type SzDV () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = 32<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 32<rt>
      RegSize = effOprSz
      OperationSize = effOprSz }

/// Md
type SzD () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = 32<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 32<rt>
      RegSize = effOprSz
      OperationSize = 32<rt> }

/// Ew Mw
type SzMemW () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = 16<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 16<rt>
      RegSize = effOprSz
      OperationSize = 16<rt> }

/// CS ES DS FS GS SS
type SzRegW () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = effOprSz
      MemEffAddrSize = effAddrSz
      MemEffRegSize = effOprSz
      RegSize = 16<rt>
      OperationSize = 16<rt> }

/// GvEw
type SzWV () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = 16<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 16<rt>
      RegSize = effOprSz
      OperationSize = effOprSz }

/// RAX RCX RDX RBX RSP RBP RSI RDI Jz
type SzD64 () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) effOprSz effAddrSz =
    let oprSize = WordSize.toRegType rhlp.WordSize
    { MemEffOprSize = effOprSz
      MemEffAddrSize = effAddrSz
      MemEffRegSize = effOprSz
      RegSize = oprSize
      OperationSize = oprSize }

/// GzMp
type SzPZ () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) effOprSz effAddrSz =
    let oprSize =
      if rhlp.Prefixes &&& Prefix.PrxOPSIZE = Prefix.PrxOPSIZE then 32<rt>
      else 48<rt>
    { MemEffOprSize = oprSize
      MemEffAddrSize = effAddrSz
      MemEffRegSize = effOprSz
      RegSize = effOprSz
      OperationSize = effOprSz }

/// MdqVdq VdqHdqUdq VdqHdqWdqIb VdqMdq VdqUdq VdqWdq VdqWdqIb WdqVdq
type SzDqDq () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 128<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = 128<rt>
      OperationSize = 128<rt> }

/// VdqWdqd VdqMd VdqHdqWdqd VdqWdqdIb MdVdq
type SzDqdDq () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 32<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = 128<rt>
      OperationSize = 128<rt> }

/// WdqdVdq MdVdq
type SzDqdDqMR () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 32<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = 128<rt>
      OperationSize = 32<rt> }

/// VdqWdqq VdqMq VdqHdqMq VdqHdqWdqq VdqWdqqIb WdqqVdq MqVdq
type SzDqqDq () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 64<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = 128<rt>
      OperationSize = 128<rt> }

/// WdqqVdq MqVdq
type SzDqqDqMR () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 64<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = 128<rt>
      OperationSize = 64<rt> }

/// VxWxq
type SzXqX () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
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
type SzDqqDqWS () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) effOprSz effAddrSz =
    let struct (mopr, maddr, mreg) =
      match rhlp.WordSize with
      | WordSize.Bit32 -> struct (64<rt>, effAddrSz, 128<rt>)
      | WordSize.Bit64 -> struct (128<rt>, effAddrSz, 128<rt>)
      | _ -> raise ParsingFailureException
    { MemEffOprSize = mopr
      MemEffAddrSize = maddr
      MemEffRegSize = mreg
      RegSize = 128<rt>
      OperationSize = effOprSz }

/// BNEv BNMv BNMib VdqEy VssHssEy VsdHsdEy
type SzVyDq () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = effOprSz
      MemEffAddrSize = effAddrSz
      MemEffRegSize = effOprSz
      RegSize = 128<rt>
      OperationSize = 128<rt> }

/// EyVdq MibBN
type SzVyDqMR () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = effOprSz
      MemEffAddrSize = effAddrSz
      MemEffRegSize = effOprSz
      RegSize = 128<rt>
      OperationSize = effOprSz }

/// RyCd RyDd CdRy DdRy
type SzDY () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) effOprSz effAddrSz =
    let effRegSz = WordSize.toRegType rhlp.WordSize
    { MemEffOprSize = effOprSz
      MemEffAddrSize = effAddrSz
      MemEffRegSize = effRegSz
      RegSize = effOprSz
      OperationSize = effOprSz }

/// VdqQpi VdqNq
type SzQDq () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 64<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 64<rt>
      RegSize = 128<rt>
      OperationSize = 128<rt> }

/// PpiWdqq
type SzDqqQ () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 64<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = 64<rt>
      OperationSize = 64<rt> }

/// PpiWdq PqUdq
type SzDqQ () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 128<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = 64<rt>
      OperationSize = 64<rt> }

/// GyWdqd
type SzDqdY () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = 32<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = effOprSz
      OperationSize = effOprSz }

/// GyWdqq
type SzDqqY () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = 64<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = effOprSz
      OperationSize = effOprSz }

/// GyUdq
type SzDqY () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = 128<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = effOprSz
      OperationSize = effOprSz }

/// UdqIb Mdq
type SzDq () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = 128<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = effOprSz
      OperationSize = 128<rt> }

/// PqQd
type SzDQ () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 32<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 64<rt>
      RegSize = 64<rt>
      OperationSize = 64<rt> }

/// PqQq PqQqIb QqPq MqPq
type SzQQ () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 64<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 64<rt>
      RegSize = 64<rt>
      OperationSize = 64<rt> }

/// EyPq
type SzYQ () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = effOprSz
      MemEffAddrSize = effAddrSz
      MemEffRegSize = effOprSz
      RegSize = 64<rt>
      OperationSize = effOprSz }

/// PqEy
type SzYQRM () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = effOprSz
      MemEffAddrSize = effAddrSz
      MemEffRegSize = effOprSz
      RegSize = 64<rt>
      OperationSize = 64<rt> }

/// PqEdwIb
type SzDwQ () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 16<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 32<rt>
      RegSize = 64<rt>
      OperationSize = 64<rt> }

/// VdqEdwIb VdqHdqEdwIb
type SzDwDq () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = 16<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 32<rt>
      RegSize = 128<rt>
      OperationSize = effOprSz }

/// EdwVdqIb
type SzDwDqMR () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 16<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 32<rt>
      RegSize = 128<rt>
      OperationSize = 16<rt> }

/// GdNqIb GdNq
type SzQD () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 64<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 64<rt>
      RegSize = 32<rt>
      OperationSize = 32<rt> }

/// GdUdqIb GdUdq
type SzDqd () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 128<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = 32<rt>
      OperationSize = 32<rt> }

/// VxHxWdq
type SzDqX () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    { MemEffOprSize = 128<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = vLen
      OperationSize = vLen }

/// GdUx
type SzXD () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    { MemEffOprSize = vLen
      MemEffAddrSize = effAddrSz
      MemEffRegSize = vLen
      RegSize = 32<rt>
      OperationSize = 32<rt> }

/// VxWdqqdq
type SzDqqdqX () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
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
type SzDqddqX () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
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
type SzDqwDq () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = 16<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = 128<rt>
      OperationSize = 128<rt> }

/// VxWdqwd
type SzDqwX () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
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
type SzDqQqq () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 128<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = 256<rt>
      OperationSize = 256<rt> }

/// VxWdqb
type SzDqbX () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    { MemEffOprSize = 8<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = vLen
      OperationSize = vLen }

/// VdqEdbIb VdqHdqEdbIb
type SzDbDq () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 8<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 32<rt>
      RegSize = 128<rt>
      OperationSize = 128<rt> }

/// GvEb Mb
type SzBV () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = 8<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 8<rt>
      RegSize = effOprSz
      OperationSize = effOprSz }

/// NqIb Mq
type SzQ () =
  inherit InsSizeComputer ()
  override __.Render _ _ effAddrSz =
    { MemEffOprSize = 64<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 64<rt>
      RegSize = 64<rt>
      OperationSize = 64<rt> }

/// Ms
type SzS () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let effOprSz = if rhlp.WordSize = WordSize.Bit32 then 48<rt> else 80<rt>
    { MemEffOprSize = effOprSz
      MemEffAddrSize = effAddrSz
      MemEffRegSize = effOprSz
      RegSize = effOprSz
      OperationSize = effOprSz }

/// VxMd
type SzDX () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    { MemEffOprSize = 32<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 32<rt>
      RegSize = vLen
      OperationSize = vLen }

/// VZxzWdqd VxHxWdqd
type SzDqdXz () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    { MemEffOprSize = 32<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = vLen
      OperationSize = vLen }

/// VxHxWdqq
type SzDqqX () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    { MemEffOprSize = 64<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = vLen
      OperationSize = vLen }

/// Ap Ep Mp
type SzP () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
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
type SzPRM () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
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
type SzXqXz () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
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
type SzXXz () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
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
type SzXzX () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
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
type SzXzXz () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    { MemEffOprSize = vLen
      MemEffAddrSize = effAddrSz
      MemEffRegSize = vLen
      RegSize = vLen
      OperationSize = vLen }

/// VqqWdqq
type SzDqqQq () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = 64<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = 256<rt>
      OperationSize = 256<rt> }

/// VZxzWdqq
type SzDqqXz () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    { MemEffOprSize = 64<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = vLen
      OperationSize = vLen }

/// WqqVZxz WZqqVZxzIb WqqVZxzIb
type SzQqXz () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    { MemEffOprSize = 256<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 256<rt>
      RegSize = vLen
      OperationSize = 256<rt> }

/// VZxzHxWqqIb
type SzQqXzRM () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    { MemEffOprSize = 256<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 256<rt>
      RegSize = vLen
      OperationSize = vLen }

/// VxWdqd
type SzDqdX () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    { MemEffOprSize = 32<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = vLen
      OperationSize = vLen }

/// VZxzRd
type SzDXz () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    { MemEffOprSize = 32<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 32<rt>
      RegSize = vLen
      OperationSize = vLen }

/// VZxzRq
type SzQXz () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    { MemEffOprSize = 64<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 64<rt>
      RegSize = vLen
      OperationSize = vLen }

/// WdqVqqIb
type SzDqQq () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = 128<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = 256<rt>
      OperationSize = 128<rt> }

/// WdqVZxzIb
type SzDqXz () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ effAddrSz =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    { MemEffOprSize = 128<rt>
      MemEffAddrSize = effAddrSz
      MemEffRegSize = 128<rt>
      RegSize = vLen
      OperationSize = 128<rt> }

/// VdqHdqEyIb
type SzYDq () =
  inherit InsSizeComputer ()
  override __.Render _ effOprSz effAddrSz =
    { MemEffOprSize = effOprSz
      MemEffAddrSize = effAddrSz
      MemEffRegSize = effOprSz
      RegSize = 128<rt>
      OperationSize = 128<rt> }

type SizeKind =
  | Byte = 0
  | Word = 1
  | Def = 2
  | VecDef = 3
  | DV = 4
  | D = 5
  | MemW = 6
  | RegW = 7
  | WV = 8
  | D64 = 9
  | PZ = 10
  | DqDq = 11
  | DqdDq = 12
  | DqdDqMR = 13
  | DqqDq = 14
  | DqqDqMR = 15
  | XqX = 16
  | DqqDqWS = 17
  | VyDq = 18
  | VyDqMR = 19
  | DY = 20
  | QDq = 21
  | DqqQ = 22
  | DqQ = 23
  | DqdY = 24
  | DqqY = 25
  | DqY = 26
  | Dq = 27
  | DQ = 28
  | QQ = 29
  | YQ = 30
  | YQRM = 31
  | DwQ = 32
  | DwDq = 33
  | DwDqMR = 34
  | QD = 35
  | Dqd = 36
  | DqX = 37
  | XD = 38
  | DqqdqX = 39
  | DqddqX = 40
  | DqwDq = 41
  | DqwX = 42
  | DqQqq = 43
  | DqbX = 44
  | DbDq = 45
  | BV = 46
  | Q = 47
  | S = 48
  | DX = 49
  | DqdXz = 50
  | DqqX = 51
  | P = 52
  | PRM = 53
  | XqXz = 54
  | XXz = 55
  | XzX = 56
  | XzXz = 57
  | DqqQq = 58
  | DqqXz = 59
  | QqXz = 60
  | QqXzRM = 61
  | DqdX = 62
  | DXz = 63
  | QXz = 64
  | DqQq = 65
  | DqXz = 66
  | YDq = 67

// vim: set tw=80 sts=2 sw=2:

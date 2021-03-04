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
  abstract member Render: ReadHelper -> Operands

and [<AbstractClass>] InsSizeComputer () =
  abstract Render: ReadHelper -> SzCond -> unit

and ReadHelper (rd, addr, initialPos, cpos, pref, rex, vex, wordSz, ops, szs) =
  let mutable r: BinReader = rd
  let mutable addr: Addr = addr
  let mutable ipos: int = initialPos
  let mutable cpos: int = cpos (* current position *)
  let mutable pref: Prefix = pref
  let mutable rex: REXPrefix = rex
  let mutable vex: VEXInfo option = vex
  let mutable wordSize: WordSize = wordSz
  let mutable memOprSz = 0<rt>
  let mutable memAddrSz = 0<rt>
  let mutable memRegSz = 0<rt>
  let mutable regSz = 0<rt>
  let mutable operationSz = 0<rt>
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
  member __.MemEffOprSize with get() = memOprSz and set(s) = memOprSz <- s
  member __.MemEffAddrSize with get() = memAddrSz and set(s) = memAddrSz <- s
  member __.MemEffRegSize with get() = memRegSz and set(s) = memRegSz <- s
  member __.RegSize with get() = regSz and set(s) = regSz <- s
  member __.OperationSize with get() = operationSz and set(s) = operationSz <- s

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
  member inline __.GetInsID () =
    let len = cpos - ipos
    let bs = r.PeekBytes (len, ipos)
    let chars: char [] = Array.zeroCreate (len * sizeof<char>)
    System.Buffer.BlockCopy (bs, 0, chars, 0, bs.Length)
    System.String chars

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

let inline getSTReg n = Register.make n Register.Kind.FPU 80 |> OprReg

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

///////////////////////////////
let getOprSize size sizeCond =
  if sizeCond = SzCond.F64 ||
    (size = 32<rt> && sizeCond = SzCond.D64) then 64<rt>
  else size

let inline getEffOprSize32 prefs =
  if hasOprSz prefs then 16<rt> else 32<rt>

let inline getEffAddrSize32 prefs =
  if hasAddrSz prefs then 16<rt> else 32<rt>

let inline getEffOprSize64 prefs rexPref sizeCond =
  if hasREXW rexPref then 64<rt>
  else
    if hasOprSz prefs then getOprSize 16<rt> sizeCond
    else getOprSize 32<rt> sizeCond

let inline getEffAddrSize64 prefs =
  if hasAddrSz prefs then 32<rt> else 64<rt>

let getEffAddrSize (rhlp: ReadHelper) =
  if rhlp.WordSize = WordSize.Bit32 then getEffAddrSize32 rhlp.Prefixes
  else getEffAddrSize64 rhlp.Prefixes

let getEffOprSize (rhlp: ReadHelper) sizeCond =
  if rhlp.WordSize = WordSize.Bit32 then getEffOprSize32 rhlp.Prefixes
  else getEffOprSize64 rhlp.Prefixes rhlp.REXPrefix sizeCond

/// AHR12LIb ALIb ALOb ALR8LIb BHR15LIb BLR11LIb CHR13LIb CLR9LIb DHR14LIb
/// DLR10LIb Eb Eb1 EbCL EbGb EbIb GbEb IbAL Jb ObAL XbYb
type SzByte () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 8<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 8<rt>
    rhlp.RegSize <- 8<rt>
    rhlp.OperationSize <- 8<rt>

/// GwMw EvSw EwGw MwGw SwEw
type SzWord () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 16<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 16<rt>
    rhlp.RegSize <- 16<rt>
    rhlp.OperationSize <- 16<rt>

/// ALDX DXAL DXEAX EAX EAXDX EAXIb EBP EBX ECX EDI EDX ESI ESP Ev Ev1 EvCL EvGv
/// EvGvCL EvGvIb EvIb EvSIb EvSIz EyGy GvEv GvEvSIb GvEvSIz GvEy GvMa GvMv
/// GyByEy GyEy GyEyBy GyEyIb GyMy Ib IbEAX Iw IwIb Mv MyGy Mz OvRAX RAXIv RAXOv
/// RAXrAX RAXrBP RAXrBX RAXrCX RAXrDI RAXrDX RAXrSI RAXrSP RAXSIz RAXz RBPIv
/// RBPz RBXIv RBXz RCXIv RCXz RDIIv RDIz RDXIv RDXz RSIIv RSIz RSPIv RSPz Rv Ry
/// SIb SIz
type SzDef () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// HxUxIb MpdVpd MpsVps MxVx MZxzVZxz VpdHpdWpd VpdHpdWpdIb VpdWpd VpsHpsWps
/// VpsHpsWpsIb VpsWps VsdHsdWsdIb VssHssWssIb VxHxWsd VxHxWss VxHxWx VxHxWxIb
/// VxMx VxWx VxWxIb VZxzWZxz WpdVpd WpsVps WsdHxVsd WssHxVss WxVx WZxzVZxz
type SzVecDef () =
  inherit InsSizeComputer ()
  override __.Render (rhlp: ReadHelper) _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- vLen
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- vLen
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// GvEd Md
type SzDV () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 32<rt>
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// Md
type SzD () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 32<rt>
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- 32<rt>

/// Ew Mw
type SzMemW () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 16<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 16<rt>
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- 16<rt>

/// CS ES DS FS GS SS
type SzRegW () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- 16<rt>
    rhlp.OperationSize <- 16<rt>

/// GvEw
type SzWV () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 16<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 16<rt>
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// RAX RCX RDX RBX RSP RBP RSI RDI Jz
type SzD64 () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    let oprSize = WordSize.toRegType rhlp.WordSize
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- oprSize
    rhlp.OperationSize <- oprSize

/// GzMp
type SzPZ () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    let oprSize =
      if rhlp.Prefixes &&& Prefix.PrxOPSIZE = Prefix.PrxOPSIZE then 32<rt>
      else 48<rt>
    rhlp.MemEffOprSize <- oprSize
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// MdqVdq VdqHdqUdq VdqHdqWdqIb VdqMdq VdqUdq VdqWdq VdqWdqIb WdqVdq
type SzDqDq () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 128<rt>

/// VdqWdqd VdqMd VdqHdqWdqd VdqWdqdIb MdVdq
type SzDqdDq () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 128<rt>

/// WdqdVdq MdVdq
type SzDqdDqMR () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 32<rt>

/// VdqWdqq VdqMq VdqHdqMq VdqHdqWdqq VdqWdqqIb WdqqVdq MqVdq
type SzDqqDq () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 128<rt>

/// WdqqVdq MqVdq
type SzDqqDqMR () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 64<rt>

/// VxWxq
type SzXqX () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let effAddrSz = getEffAddrSize rhlp
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    let struct (mopr, maddr, mreg) =
      match vLen with
      | 128<rt> -> struct (64<rt>, effAddrSz, 128<rt>)
      | 256<rt> -> struct (vLen, effAddrSz, vLen)
      | _ -> Utils.futureFeature () (* EVEX *)
    rhlp.MemEffOprSize <- mopr
    rhlp.MemEffAddrSize <- maddr
    rhlp.MemEffRegSize <- mreg
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// BNBNdqq BNdqqBN
type SzDqqDqWS () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    let struct (mopr, maddr, mreg) =
      match rhlp.WordSize with
      | WordSize.Bit32 -> struct (64<rt>, effAddrSz, 128<rt>)
      | WordSize.Bit64 -> struct (128<rt>, effAddrSz, 128<rt>)
      | _ -> raise ParsingFailureException
    rhlp.MemEffOprSize <- mopr
    rhlp.MemEffAddrSize <- maddr
    rhlp.MemEffRegSize <- mreg
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- effOprSz

/// BNEv BNMv BNMib VdqEy VssHssEy VsdHsdEy
type SzVyDq () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 128<rt>

/// EyVdq MibBN
type SzVyDqMR () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- effOprSz

/// RyCd RyDd CdRy DdRy
type SzDY () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    let effRegSz = WordSize.toRegType rhlp.WordSize
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effRegSz
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// VdqQpi VdqNq
type SzQDq () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 64<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 128<rt>

/// PpiWdqq
type SzDqqQ () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 64<rt>
    rhlp.OperationSize <- 64<rt>

/// PpiWdq PqUdq
type SzDqQ () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 64<rt>
    rhlp.OperationSize <- 64<rt>

/// GyWdqd
type SzDqdY () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// GyWdqq
type SzDqqY () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// GyUdq
type SzDqY () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// UdqIb Mdq
type SzDq () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- 128<rt>

/// PqQd
type SzDQ () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 64<rt>
    rhlp.RegSize <- 64<rt>
    rhlp.OperationSize <- 64<rt>

/// PqQq PqQqIb QqPq MqPq
type SzQQ () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 64<rt>
    rhlp.RegSize <- 64<rt>
    rhlp.OperationSize <- 64<rt>

/// EyPq
type SzYQ () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- 64<rt>
    rhlp.OperationSize <- effOprSz

/// PqEy
type SzYQRM () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- 64<rt>
    rhlp.OperationSize <- 64<rt>

/// PqEdwIb
type SzDwQ () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 16<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 32<rt>
    rhlp.RegSize <- 64<rt>
    rhlp.OperationSize <- 64<rt>

/// VdqEdwIb VdqHdqEdwIb
type SzDwDq () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 16<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 32<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- effOprSz

/// EdwVdqIb
type SzDwDqMR () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 16<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 32<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 16<rt>

/// GdNqIb GdNq
type SzQD () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 64<rt>
    rhlp.RegSize <- 32<rt>
    rhlp.OperationSize <- 32<rt>

/// GdUdqIb GdUdq
type SzDqd () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 32<rt>
    rhlp.OperationSize <- 32<rt>

/// VxHxWdq
type SzDqX () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// GdUx
type SzXD () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- vLen
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- vLen
    rhlp.RegSize <- 32<rt>
    rhlp.OperationSize <- 32<rt>

/// VxWdqqdq
type SzDqqdqX () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let effAddrSz = getEffAddrSize rhlp
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    let struct (mopr, maddr, mreg) =
      match vLen with
      | 128<rt> -> struct (64<rt>, effAddrSz, 128<rt>)
      | 256<rt> -> struct (128<rt>, effAddrSz, 128<rt>)
      | _ -> Utils.futureFeature () (* EVEX *)
    rhlp.MemEffOprSize <- mopr
    rhlp.MemEffAddrSize <- maddr
    rhlp.MemEffRegSize <- mreg
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VxWdqdq
type SzDqddqX () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let effAddrSz = getEffAddrSize rhlp
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    let struct (mopr, maddr, mreg) =
      match vLen with
      | 128<rt> -> struct (32<rt>, effAddrSz, 128<rt>)
      | 256<rt> -> struct (64<rt>, effAddrSz, 128<rt>)
      | _ -> Utils.futureFeature () (* EVEX *)
    rhlp.MemEffOprSize <- mopr
    rhlp.MemEffAddrSize <- maddr
    rhlp.MemEffRegSize <- mreg
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VdqWdqw
type SzDqwDq () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 16<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 128<rt>

/// VxWdqwd
type SzDqwX () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let effAddrSz = getEffAddrSize rhlp
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    let struct (mopr, maddr, mreg) =
      match vLen with
      | 128<rt> -> struct (16<rt>, effAddrSz, 128<rt>)
      | 256<rt> -> struct (32<rt>, effAddrSz, 128<rt>)
      | _ -> Utils.futureFeature () (* EVEX *)
    rhlp.MemEffOprSize <- mopr
    rhlp.MemEffAddrSize <- maddr
    rhlp.MemEffRegSize <- mreg
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VqqMdq VqqHqqWdqIb
type SzDqQqq () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 256<rt>
    rhlp.OperationSize <- 256<rt>

/// VxWdqb
type SzDqbX () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 8<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VdqEdbIb VdqHdqEdbIb
type SzDbDq () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 8<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 32<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 128<rt>

/// GvEb Mb
type SzBV () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 8<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 8<rt>
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// NqIb Mq
type SzQ () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 64<rt>
    rhlp.RegSize <- 64<rt>
    rhlp.OperationSize <- 64<rt>

/// Ms
type SzS () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let effOprSz = if rhlp.WordSize = WordSize.Bit32 then 48<rt> else 80<rt>
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// VxMd
type SzDX () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 32<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VZxzWdqd VxHxWdqd
type SzDqdXz () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VxHxWdqq
type SzDqqX () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// Ap Ep Mp
type SzP () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    let struct (regSz, oprSz) =
      if effOprSz = 16<rt> then struct (16<rt>, 32<rt>)
      elif effOprSz = 32<rt> then struct (32<rt>, 48<rt>)
      else struct (64<rt>, 80<rt>)
    rhlp.MemEffOprSize <- oprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- regSz
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- oprSz

/// GvMp
type SzPRM () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    let struct (regSz, oprSz) =
      if effOprSz = 16<rt> then struct (16<rt>, 32<rt>)
      elif effOprSz = 32<rt> then struct (32<rt>, 48<rt>)
      else struct (64<rt>, 80<rt>)
    rhlp.MemEffOprSize <- oprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- regSz
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// VZxzWxq
type SzXqXz () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let effAddrSz = getEffAddrSize rhlp
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    let struct (mopr, maddr, mreg) =
      match vLen with
      | 128<rt> -> struct (64<rt>, effAddrSz, 128<rt>)
      | 256<rt> -> struct (128<rt>, effAddrSz, 128<rt>)
      | 512<rt> -> struct (256<rt>, effAddrSz, 256<rt>)
      | _ -> raise ParsingFailureException
    rhlp.MemEffOprSize <- mopr
    rhlp.MemEffAddrSize <- maddr
    rhlp.MemEffRegSize <- mreg
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VZxzWx
type SzXXz () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let effAddrSz = getEffAddrSize rhlp
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    let struct (mopr, maddr, mreg) =
      match vLen with
      | 128<rt> -> struct (vLen, effAddrSz, vLen)
      | 256<rt> -> struct (128<rt>, effAddrSz, 128<rt>)
      | 512<rt> -> struct (256<rt>, effAddrSz, 256<rt>)
      | _ -> raise ParsingFailureException
    rhlp.MemEffOprSize <- mopr
    rhlp.MemEffAddrSize <- maddr
    rhlp.MemEffRegSize <- mreg
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VxWZxz
type SzXzX () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    let regSize =
      match vLen with
      | 128<rt> -> vLen
      | 256<rt> -> 128<rt>
      | 512<rt> -> 256<rt>
      | _ -> raise ParsingFailureException
    rhlp.MemEffOprSize <- vLen
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- vLen
    rhlp.RegSize <- regSize
    rhlp.OperationSize <- regSize

/// VZxzHxWZxz VZxzHxWZxzIb
type SzXzXz () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- vLen
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- vLen
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VqqWdqq
type SzDqqQq () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 256<rt>
    rhlp.OperationSize <- 256<rt>

/// VZxzWdqq
type SzDqqXz () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// WqqVZxz WZqqVZxzIb WqqVZxzIb
type SzQqXz () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 256<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 256<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- 256<rt>

/// VZxzHxWqqIb
type SzQqXzRM () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 256<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 256<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VxWdqd
type SzDqdX () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VZxzRd
type SzDXz () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 32<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VZxzRq
type SzQXz () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 64<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// WdqVqqIb
type SzDqQq () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 256<rt>
    rhlp.OperationSize <- 128<rt>

/// WdqVZxzIb
type SzDqXz () =
  inherit InsSizeComputer ()
  override __.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- getEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- 128<rt>

/// VdqHdqEyIb
type SzYDq () =
  inherit InsSizeComputer ()
  override __.Render rhlp szCond =
    let effAddrSz = getEffAddrSize rhlp
    let effOprSz = getEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 128<rt>

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

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

open B2R2
open B2R2.FrontEnd.BinLifter

/// Specific conditions for determining the size of operands.
/// (See Table A-1, Appendix A.2.5 of Vol. 2D).
type internal SzCond =
  /// (d64) When in 64-bit mode, instruction defaults to 64-bit operand size and
  /// cannot encode 32-bit operand size.
  | D64 = 0
  /// (f64) The operand size is forced to a 64-bit operand size when in 64-bit
  /// mode (prefixes that change operand size, e.g., 66 prefix, are ignored for
  /// this instruction in 64-bit mode).
  | F64 = 1
  /// Normal conditions. This includes all other size conditions in Table A-1.
  | Normal = 2

/// The tupletype will be referenced in the instruction operand encoding table
/// in the reference page of each instruction, providing the cross reference for
/// the scaling factor N to encoding memory addressing operand.
type internal TupleType =
  /// Compressed Displacement (DISP8*N) Affected by Embedded Broadcast.
  | Full = 0
  | Half = 1
  /// EVEX DISP8*N for Instructions Not Affected by Embedded Broadcast.
  | FullMem = 2
  | Tuple1Scalar = 3
  | Tuple1Fixed = 4
  | Tuple2 = 5
  | Tuple4 = 6
  | Tuple8 = 7
  | HalfMem = 8
  | QuarterMem = 9
  | EighthMem = 10
  | Mem128 = 11
  | MOVDDUP = 12
  | NA = 13 (* N/A *)

type internal SizeKind =
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
  | DDq = 11
  | DqDq = 12
  | DqdDq = 13
  | DqdDqMR = 14
  | DqqDq = 15
  | DqqDqMR = 16
  | XqX = 17
  | DqqDqWS = 18
  | VyDq = 19
  | VyDqMR = 20
  | DY = 21
  | QDq = 22
  | DqqQ = 23
  | DqQ = 24
  | DqdY = 25
  | DqqY = 26
  | DqY = 27
  | Dq = 28
  | DQ = 29
  | QQ = 30
  | YQ = 31
  | YQRM = 32
  | DwQ = 33
  | DwDq = 34
  | DwDqMR = 35
  | QD = 36
  | Dqd = 37
  | XDq = 38
  | DqX = 39
  | XD = 40
  | DqqdqX = 41
  | DqddqX = 42
  | DqwDq = 43
  | DqwX = 44
  | DqQqq = 45
  | DqbX = 46
  | DbDq = 47
  | BV = 48
  | Q = 49
  | S = 50
  | DX = 51
  | DqdXz = 52
  | DqqX = 53
  | P = 54
  | PRM = 55
  | XqXz = 56
  | XXz = 57
  | XzX = 58
  | XzXz = 59
  | DqqQq = 60
  | DqqXz = 61
  | QqXz = 62
  | QqXzRM = 63
  | DqdX = 64
  | DXz = 65
  | QXz = 66
  | DqQq = 67
  | DqXz = 68
  | YDq = 69
  | Qq = 70
  | DqwdX = 71
  | Y = 72
  | QQb = 73
  | QQd = 74
  | QQw = 75
  | VecDefRC = 76
  | YP = 77

type [<AbstractClass>] internal OperandParser () =
  abstract Render: ByteSpan * ReadHelper -> Operands

and [<AbstractClass>] internal InsSizeComputer () =
  abstract Render: ReadHelper -> SzCond -> unit
  abstract RenderEVEX: ByteSpan * ReadHelper * SzCond -> unit
  default _.Render (rhlp: ReadHelper) _ =
    rhlp.MemEffOprSize <- 0<rt>
    rhlp.MemEffAddrSize <- 0<rt>
    rhlp.MemEffRegSize <- 0<rt>
    rhlp.RegSize <- 0<rt>
    rhlp.OperationSize <- 0<rt>
  default _.RenderEVEX (_, rhlp: ReadHelper, _) =
    rhlp.MemEffOprSize <- 0<rt>
    rhlp.MemEffAddrSize <- 0<rt>
    rhlp.MemEffRegSize <- 0<rt>
    rhlp.RegSize <- 0<rt>
    rhlp.OperationSize <- 0<rt>

and internal ReadHelper (reader: IBinReader,
                addr, cpos, pref, rex, vex, wordSz, ops, szs, lifter) =
  let mutable addr: Addr = addr
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
  let mutable tupleType = TupleType.NA
  new (reader, wordSz, oparsers, szcomputers, lifter) =
    ReadHelper (reader, 0UL, 0, Prefix.PrxNone, REXPrefix.NOREX, None,
                wordSz, oparsers, szcomputers, lifter)
  member _.InsAddr with get (): Addr = addr and set a = addr <- a
  member _.CurrPos with get () = cpos and set p = cpos <- p
  member _.IncPos () = cpos <- cpos + 1
  member _.Prefixes with get () = pref and set p = pref <- p
  member _.REXPrefix with get (): REXPrefix = rex and set r = rex <- r
  member _.VEXInfo with get (): VEXInfo option = vex and set v = vex <- v
  member _.WordSize with get (): WordSize = wordSize and set w = wordSize <- w
  member _.OprParsers with get (): OperandParser[] = ops
  member _.SzComputers with get (): InsSizeComputer[] = szs
  member _.MemEffOprSize with get () = memOprSz and set s = memOprSz <- s
  member _.MemEffAddrSize with get () = memAddrSz and set s = memAddrSz <- s
  member _.MemEffRegSize with get () = memRegSz and set s = memRegSz <- s
  member _.RegSize with get () = regSz and set(s) = regSz <- s
  member _.OperationSize with get () = operationSz and set s = operationSz <- s
  member _.TupleType
    with get (): TupleType = tupleType and set t = tupleType <- t
  member _.Lifter with get (): ILiftable = lifter

  member inline private _.ModCPos i = cpos <- cpos + i

  member inline _.PeekByte (span: ByteSpan) = span[cpos]

  member inline this.ReadByte (span: ByteSpan) =
    let v = span[cpos]
    this.ModCPos 1
    v

  member inline this.ReadInt8 (span: ByteSpan) =
    let v = reader.ReadInt8 (span, cpos)
    this.ModCPos 1
    v

  member inline this.ReadInt16 (span: ByteSpan) =
    let v = reader.ReadInt16 (span, cpos)
    this.ModCPos 2
    v

  member inline this.ReadInt32 (span: ByteSpan) =
    let v = reader.ReadInt32 (span, cpos)
    this.ModCPos 4
    v

  member inline this.ReadInt64 (span: ByteSpan) =
    let v = reader.ReadInt64 (span, cpos)
    this.ModCPos 8
    v

  member inline this.ReadUInt8 (span: ByteSpan) =
    let v = reader.ReadUInt8 (span, cpos)
    this.ModCPos 1
    v

  member inline this.ReadUInt16 (span: ByteSpan) =
    let v = reader.ReadUInt16 (span, cpos)
    this.ModCPos 2
    v

  member inline this.ReadUInt32 (span: ByteSpan) =
    let v = reader.ReadUInt32 (span, cpos)
    this.ModCPos 4
    v

  member inline this.ReadUInt64 (span: ByteSpan) =
    let v = reader.ReadUInt64 (span, cpos)
    this.ModCPos 8
    v

  member inline _.ParsedLen () = cpos

  static member inline Is64bit (rhlp: ReadHelper) =
    rhlp.WordSize = WordSize.Bit64

  static member inline HasNoPref (rhlp: ReadHelper) = (int rhlp.Prefixes) = 0

  static member inline HasNoREX (rhlp: ReadHelper) =
    rhlp.REXPrefix = REXPrefix.NOREX

  static member inline IsReg001 (span, rhlp: ReadHelper) =
    Operands.getReg (rhlp.PeekByte span) = 1

  static member inline IsReg010 (span, rhlp: ReadHelper) =
    Operands.getReg (rhlp.PeekByte span) = 2

  static member inline IsReg101 (span, rhlp: ReadHelper) =
    Operands.getReg (rhlp.PeekByte span) = 5

  static member inline IsReg110 (span, rhlp: ReadHelper) =
    Operands.getReg (rhlp.PeekByte span) = 6

  static member inline IsReg111 (span, rhlp: ReadHelper) =
    Operands.getReg (rhlp.PeekByte span) = 7

  static member inline IsEVEX (rhlp: ReadHelper) =
    match rhlp.VEXInfo with
    | Some vInfo -> vInfo.VEXType &&& VEXType.EVEX = VEXType.EVEX
    | _ -> false

  static member inline GetOprSize size sizeCond =
    if sizeCond = SzCond.F64 ||
      (size = 32<rt> && sizeCond = SzCond.D64) then 64<rt>
    else size

  static member inline GetEffOprSize32 prefs =
    if Prefix.hasOprSz prefs then 16<rt> else 32<rt>

  static member inline GetEffAddrSize32 prefs =
    if Prefix.hasAddrSz prefs then 16<rt> else 32<rt>

  static member inline GetEffOprSize64 prefs rexPref sizeCond =
    if REXPrefix.hasW rexPref then 64<rt>
    else
      if Prefix.hasOprSz prefs then ReadHelper.GetOprSize 16<rt> sizeCond
      else ReadHelper.GetOprSize 32<rt> sizeCond

  static member inline GetEffAddrSize64 prefs =
    if Prefix.hasAddrSz prefs then 32<rt> else 64<rt>

  static member inline GetEffAddrSize (rhlp: ReadHelper) =
    if rhlp.WordSize = WordSize.Bit32 then
      ReadHelper.GetEffAddrSize32 rhlp.Prefixes
    else ReadHelper.GetEffAddrSize64 rhlp.Prefixes

  static member inline GetEffOprSize (rhlp: ReadHelper) sizeCond =
    if rhlp.WordSize = WordSize.Bit32 then
      ReadHelper.GetEffOprSize32 rhlp.Prefixes
    else ReadHelper.GetEffOprSize64 rhlp.Prefixes rhlp.REXPrefix sizeCond

/// AHR12LIb ALIb ALOb ALR8LIb BHR15LIb BLR11LIb CHR13LIb CLR9LIb DHR14LIb
/// DLR10LIb Eb Eb1 EbCL EbGb EbIb GbEb IbAL Jb ObAL XbYb
type internal SzByte () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 8<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 8<rt>
    rhlp.RegSize <- 8<rt>
    rhlp.OperationSize <- 8<rt>

/// GwMw EvSw EwGw MwGw SwEw
type internal SzWord () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 16<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 16<rt>
    rhlp.RegSize <- 16<rt>
    rhlp.OperationSize <- 16<rt>

/// ALDX DXAL DXEAX EAX EAXDX EAXIb EBP EBX ECX EDI EDX ESI ESP Ev Ev1 EvCL EvGv
/// EvGvCL EvGvIb EvIb EvSIb EvSIz EyGy GvEv GvEvSIb GvEvSIz GvEy GvMa GvMv
/// GyByEy GyEy GyEyBy GyEyIb GyMy Ib IbEAX Iw IwIb Mv MyGy Mz OvRAX RAXIv RAXOv
/// RAXrAX RAXrBP RAXrBX RAXrCX RAXrDI RAXrDX RAXrSI RAXrSP RAXSIz RAXz RBPIv
/// RBPz RBXIv RBXz RCXIv RCXz RDIIv RDIz RDXIv RDXz RSIIv RSIz RSPIv RSPz Rv Ry
/// SIb SIz
type internal SzDef () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// HxUxIb MpdVpd MpsVps MxVx MZxzVZxz VpdHpdWpd VpdHpdWpdIb VpdWpd VpsHpsWps
/// VpsHpsWpsIb VpsWps VsdHsdWsdIb VssHssWssIb VxHxWsd VxHxWss VxHxWx VxHxWxIb
/// VxMx VxWx VxWxIb VZxzWZxz WpdVpd WpsVps WsdHxVsd WssHxVss WxVx WZxzVZxz
type internal SzVecDef () =
  inherit InsSizeComputer ()
  override _.Render (rhlp: ReadHelper) _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- vLen
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- vLen
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

type internal SzVecDefRC () =
  inherit InsSizeComputer ()
  override _.RenderEVEX (span, rhlp: ReadHelper, _) =
    let vInfo = Option.get rhlp.VEXInfo
    let vLen = vInfo.VectorLength
    let modRM = rhlp.PeekByte span
    let evex = Option.get vInfo.EVEXPrx
    if Operands.modIsReg modRM && evex.B = 1uy then
      rhlp.MemEffOprSize <- 512<rt>
      rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
      rhlp.MemEffRegSize <- 512<rt>
      rhlp.RegSize <- 512<rt>
      rhlp.OperationSize <- 512<rt>
    else
      rhlp.MemEffOprSize <- vLen
      rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
      rhlp.MemEffRegSize <- vLen
      rhlp.RegSize <- vLen
      rhlp.OperationSize <- vLen

/// GvEd Md
type internal SzDV () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 32<rt>
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// Md
type internal SzD () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 32<rt>
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- 32<rt>

/// Ew Mw
type internal SzMemW () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 16<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 16<rt>
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- 16<rt>

/// CS ES DS FS GS SS
type internal SzRegW () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- 16<rt>
    rhlp.OperationSize <- 16<rt>

/// GvEw
type internal SzWV () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 16<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 16<rt>
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// RAX RCX RDX RBX RSP RBP RSI RDI Jz
type internal SzD64 () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// GzMp
type internal SzPZ () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    let oprSize =
      if rhlp.Prefixes &&& Prefix.PrxOPSIZE = Prefix.PrxOPSIZE then 32<rt>
      else 48<rt>
    rhlp.MemEffOprSize <- oprSize
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// EdVdqIb
type internal SzDDq () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 32<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 32<rt>

/// MdqVdq VdqHdqUdq VdqHdqWdqIb VdqMdq VdqUdq VdqWdq VdqWdqIb WdqVdq
type internal SzDqDq () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 128<rt>

/// VdqWdqd VdqMd VdqHdqWdqd VdqWdqdIb MdVdq VdqHdqUdqdIb
type internal SzDqdDq () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 128<rt>

/// WdqdVdq MdVdq
type internal SzDqdDqMR () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 32<rt>

/// VdqWdqq VdqMq VdqHdqMq VdqHdqWdqq VdqWdqqIb WdqqVdq MqVdq
type internal SzDqqDq () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 128<rt>

/// WdqqVdq MqVdq
type internal SzDqqDqMR () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 64<rt>

/// VxWxq
type internal SzXqX () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    let struct (mopr, maddr, mreg) =
      match vLen with
      | 128<rt> -> struct (64<rt>, effAddrSz, 128<rt>)
      | 256<rt> -> struct (vLen, effAddrSz, vLen)
      | _ -> Terminator.futureFeature () (* EVEX *)
    rhlp.MemEffOprSize <- mopr
    rhlp.MemEffAddrSize <- maddr
    rhlp.MemEffRegSize <- mreg
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// BNBNdqq BNdqqBN
type internal SzDqqDqWS () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
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
type internal SzVyDq () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 128<rt>

/// EyVdq MibBN
type internal SzVyDqMR () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- effOprSz

/// RyCd RyDd CdRy DdRy
type internal SzDY () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    let effRegSz = WordSize.toRegType rhlp.WordSize
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effRegSz
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// VdqQpi VdqNq
type internal SzQDq () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 64<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 128<rt>

/// PpiWdqq
type internal SzDqqQ () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 64<rt>
    rhlp.OperationSize <- 64<rt>

/// PpiWdq PqUdq
type internal SzDqQ () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 64<rt>
    rhlp.OperationSize <- 64<rt>

/// GyWdqd
type internal SzDqdY () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// GyWdqq
type internal SzDqqY () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// GyUdq
type internal SzDqY () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// UdqIb Mdq
type internal SzDq () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 128<rt>

/// PqQd
type internal SzDQ () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 64<rt>
    rhlp.RegSize <- 64<rt>
    rhlp.OperationSize <- 64<rt>

/// PqQq PqQqIb QqPq MqPq
type internal SzQQ () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 64<rt>
    rhlp.RegSize <- 64<rt>
    rhlp.OperationSize <- 64<rt>

/// EyPq
type internal SzYQ () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- 64<rt>
    rhlp.OperationSize <- effOprSz

/// PqEy
type internal SzYQRM () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- 64<rt>
    rhlp.OperationSize <- 64<rt>

/// PqEdwIb
type internal SzDwQ () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 16<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 32<rt>
    rhlp.RegSize <- 64<rt>
    rhlp.OperationSize <- 64<rt>

/// VdqEdwIb VdqHdqEdwIb
type internal SzDwDq () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 16<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 32<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- effOprSz

/// EdwVdqIb
type internal SzDwDqMR () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 16<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 32<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 16<rt>

/// GdNqIb GdNq
type internal SzQD () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 64<rt>
    rhlp.RegSize <- 32<rt>
    rhlp.OperationSize <- 32<rt>

/// GdUdqIb GdUdq
type internal SzDqd () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 32<rt>
    rhlp.OperationSize <- 32<rt>

/// VxHxWdq
type internal SzXDq () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VdqWx
type internal SzDqX () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- vLen
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- vLen
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- vLen

/// GdUx
type internal SzXD () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- vLen
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- vLen
    rhlp.RegSize <- 32<rt>
    rhlp.OperationSize <- 32<rt>

/// VxWdqqdq
type internal SzDqqdqX () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    let struct (mopr, maddr, mreg) =
      match vLen with
      | 128<rt> -> struct (64<rt>, effAddrSz, 128<rt>)
      | 256<rt> -> struct (128<rt>, effAddrSz, 128<rt>)
      | _ -> Terminator.futureFeature () (* EVEX *)
    rhlp.MemEffOprSize <- mopr
    rhlp.MemEffAddrSize <- maddr
    rhlp.MemEffRegSize <- mreg
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VxWdqdq
type internal SzDqddqX () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    let struct (mopr, maddr, mreg) =
      match vLen with
      | 128<rt> -> struct (32<rt>, effAddrSz, 128<rt>)
      | 256<rt> -> struct (64<rt>, effAddrSz, 128<rt>)
      | _ -> Terminator.futureFeature () (* EVEX *)
    rhlp.MemEffOprSize <- mopr
    rhlp.MemEffAddrSize <- maddr
    rhlp.MemEffRegSize <- mreg
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VdqWdqw
type internal SzDqwDq () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 16<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 128<rt>

/// VxWdqw
type internal SzDqwX () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 16<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VqqMdq VqqHqqWdqIb
type internal SzDqQqq () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 256<rt>
    rhlp.OperationSize <- 256<rt>

/// VxWdqb
type internal SzDqbX () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 8<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VdqEdbIb VdqHdqEdbIb
type internal SzDbDq () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 8<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 32<rt>
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 128<rt>

/// GvEb Mb
type internal SzBV () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 8<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 8<rt>
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// NqIb Mq
type internal SzQ () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 64<rt>
    rhlp.RegSize <- 64<rt>
    rhlp.OperationSize <- 64<rt>

/// Ms
type internal SzS () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let effOprSz = if rhlp.WordSize = WordSize.Bit32 then 48<rt> else 80<rt>
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// VxMd
type internal SzDX () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 32<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VZxzWdqd VxHxWdqd
type internal SzDqdXz () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VxHxWdqq
type internal SzDqqX () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// Ap Ep Mp
type internal SzP () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
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
type internal SzPRM () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
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
type internal SzXqXz () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
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
type internal SzXXz () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
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
type internal SzXzX () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    let regSize =
      match vLen with
      | 128<rt> -> vLen
      | 256<rt> -> 128<rt>
      | 512<rt> -> 256<rt>
      | _ -> raise ParsingFailureException
    rhlp.MemEffOprSize <- vLen
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- vLen
    rhlp.RegSize <- regSize
    rhlp.OperationSize <- regSize

/// VZxzHxWZxz VZxzHxWZxzIb
type internal SzXzXz () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- vLen
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- vLen
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VqqWdqq
type internal SzDqqQq () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 256<rt>
    rhlp.OperationSize <- 256<rt>

/// VZxzWdqq
type internal SzDqqXz () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// WqqVZxz WZqqVZxzIb WqqVZxzIb VqqHqqWqq
type internal SzQqXz () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 256<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 256<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- 256<rt>

/// VZxzHxWqqIb
type internal SzQqXzRM () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 256<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 256<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VxWdqd
type internal SzDqdX () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VZxzRd
type internal SzDXz () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 32<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// VZxzRq
type internal SzQXz () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 64<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 64<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// WdqVqqIb
type internal SzDqQq () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- 256<rt>
    rhlp.OperationSize <- 128<rt>

/// WdqVZxzIb
type internal SzDqXz () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- 128<rt>
    rhlp.MemEffAddrSize <- ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffRegSize <- 128<rt>
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- 128<rt>

/// VdqHdqEyIb
type internal SzYDq () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- 128<rt>
    rhlp.OperationSize <- 128<rt>

/// VdqHdqEyIb
type internal SzQq () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    rhlp.MemEffOprSize <- 256<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- 256<rt>
    rhlp.RegSize <- 256<rt>
    rhlp.OperationSize <- 256<rt>

/// VxWdqwd
type internal SzDqwdX () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    let struct (mopr, maddr, mreg) =
      match vLen with
      | 128<rt> -> struct (16<rt>, effAddrSz, 128<rt>)
      | 256<rt> -> struct (32<rt>, effAddrSz, 128<rt>)
      | _ -> Terminator.futureFeature () (* EVEX *)
    rhlp.MemEffOprSize <- mopr
    rhlp.MemEffAddrSize <- maddr
    rhlp.MemEffRegSize <- mreg
    rhlp.RegSize <- vLen
    rhlp.OperationSize <- vLen

/// EyGy - WordSize
type internal SzY () =
  inherit InsSizeComputer ()
  override _.Render rhlp _ =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = if rhlp.WordSize = WordSize.Bit64 then 64<rt> else 32<rt>
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// GyUps GyUpd
type internal SzYP () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    let vLen = (Option.get rhlp.VEXInfo).VectorLength
    rhlp.MemEffOprSize <- effOprSz
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- vLen
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- effOprSz

/// KnKm MKn
type internal SzQQb () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 8<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- 8<rt>

/// KnKm MKn
type internal SzQQd () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 32<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- 32<rt>

/// KnKm MKn
type internal SzQQw () =
  inherit InsSizeComputer ()
  override _.Render rhlp szCond =
    let effAddrSz = ReadHelper.GetEffAddrSize rhlp
    let effOprSz = ReadHelper.GetEffOprSize rhlp szCond
    rhlp.MemEffOprSize <- 16<rt>
    rhlp.MemEffAddrSize <- effAddrSz
    rhlp.MemEffRegSize <- effOprSz
    rhlp.RegSize <- effOprSz
    rhlp.OperationSize <- 16<rt>

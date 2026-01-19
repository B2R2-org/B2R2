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

type internal ParsingHelper(reader: IBinReader,
                            addr,
                            cpos,
                            pref,
                            rex,
                            vex,
                            wordSz,
                            ops,
                            szs,
                            lifter) =
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

  new(reader, wordSz, oparsers, szcomputers, lifter) =
    ParsingHelper(reader, 0UL, 0, Prefix.None, REXPrefix.NOREX, None,
                  wordSz, oparsers, szcomputers, lifter)

  member _.InsAddr with get(): Addr = addr and set a = addr <- a
  member _.CurrPos with get() = cpos and set p = cpos <- p
  member _.Prefixes with get() = pref and set p = pref <- p
  member _.REXPrefix with get(): REXPrefix = rex and set r = rex <- r
  member _.VEXInfo with get(): VEXInfo option = vex and set v = vex <- v
  member _.WordSize with get(): WordSize = wordSize and set w = wordSize <- w
  member _.OprParsers with get(): OperandParser[] = ops
  member _.SzComputers with get(): InsSizeComputer[] = szs
  member _.MemEffOprSize with get() = memOprSz and set s = memOprSz <- s
  member _.MemEffAddrSize with get() = memAddrSz and set s = memAddrSz <- s
  member _.MemEffRegSize with get() = memRegSz and set s = memRegSz <- s
  member _.RegSize with get() = regSz and set(s) = regSz <- s
  member _.OperationSize with get() = operationSz and set s = operationSz <- s
  member _.TupleType
    with get(): TupleType = tupleType and set t = tupleType <- t
  member _.Lifter with get(): ILiftable = lifter

  static member inline Is64bit(phlp: ParsingHelper) =
    phlp.WordSize = WordSize.Bit64

  static member inline HasNoPref(phlp: ParsingHelper) = (int phlp.Prefixes) = 0

  static member inline HasNoREX(phlp: ParsingHelper) =
    phlp.REXPrefix = REXPrefix.NOREX

  static member inline IsReg001(span: ByteSpan, phlp: ParsingHelper) =
    Operands.getReg span[phlp.CurrPos] = 1

  static member inline IsReg010(span: ByteSpan, phlp: ParsingHelper) =
    Operands.getReg span[phlp.CurrPos] = 2

  static member inline IsReg101(span: ByteSpan, phlp: ParsingHelper) =
    Operands.getReg span[phlp.CurrPos] = 5

  static member inline IsReg110(span: ByteSpan, phlp: ParsingHelper) =
    Operands.getReg span[phlp.CurrPos] = 6

  static member inline IsReg111(span: ByteSpan, phlp: ParsingHelper) =
    Operands.getReg span[phlp.CurrPos] = 7

  static member inline IsEVEX(phlp: ParsingHelper) =
    match phlp.VEXInfo with
    | Some vInfo -> vInfo.VEXType &&& VEXType.EVEX = VEXType.EVEX
    | _ -> false

  static member inline GetOprSize(size, sizeCond) =
    if sizeCond = SzCond.F64 ||
      (size = 32<rt> && sizeCond = SzCond.D64) then 64<rt>
    else size

  static member inline GetEffOprSize32 prefs =
    if Prefix.hasOprSz prefs then 16<rt> else 32<rt>

  static member inline GetEffAddrSize32 prefs =
    if Prefix.hasAddrSz prefs then 16<rt> else 32<rt>

  static member inline GetEffOprSize64(prefs, rexPref, sizeCond) =
    if REXPrefix.hasW rexPref then 64<rt>
    else
      if Prefix.hasOprSz prefs then ParsingHelper.GetOprSize(16<rt>, sizeCond)
      else ParsingHelper.GetOprSize(32<rt>, sizeCond)

  static member inline GetEffAddrSize64 prefs =
    if Prefix.hasAddrSz prefs then 32<rt> else 64<rt>

  static member inline GetEffAddrSize(phlp: ParsingHelper) =
    if phlp.WordSize = WordSize.Bit32 then
      ParsingHelper.GetEffAddrSize32 phlp.Prefixes
    else ParsingHelper.GetEffAddrSize64 phlp.Prefixes

  static member inline GetEffOprSize(phlp: ParsingHelper, sizeCond) =
    if phlp.WordSize = WordSize.Bit32 then
      ParsingHelper.GetEffOprSize32 phlp.Prefixes
    else ParsingHelper.GetEffOprSize64(phlp.Prefixes, phlp.REXPrefix, sizeCond)

  member _.IncPos() = cpos <- cpos + 1

  member inline private _.ModCPos i = cpos <- cpos + i

  member inline _.PeekByte(span: ByteSpan) = span[cpos]

  member inline this.ReadByte(span: ByteSpan) =
    let v = span[cpos]
    this.ModCPos 1
    v

  member inline this.ReadInt8(span: ByteSpan) =
    let v = reader.ReadInt8(span, cpos)
    this.ModCPos 1
    v

  member inline this.ReadInt16(span: ByteSpan) =
    let v = reader.ReadInt16(span, cpos)
    this.ModCPos 2
    v

  member inline this.ReadInt32(span: ByteSpan) =
    let v = reader.ReadInt32(span, cpos)
    this.ModCPos 4
    v

  member inline this.ReadInt64(span: ByteSpan) =
    let v = reader.ReadInt64(span, cpos)
    this.ModCPos 8
    v

  member inline this.ReadUInt8(span: ByteSpan) =
    let v = reader.ReadUInt8(span, cpos)
    this.ModCPos 1
    v

  member inline this.ReadUInt16(span: ByteSpan) =
    let v = reader.ReadUInt16(span, cpos)
    this.ModCPos 2
    v

  member inline this.ReadUInt32(span: ByteSpan) =
    let v = reader.ReadUInt32(span, cpos)
    this.ModCPos 4
    v

  member inline this.ReadUInt64(span: ByteSpan) =
    let v = reader.ReadUInt64(span, cpos)
    this.ModCPos 8
    v

  member inline _.ParsedLen() = cpos

/// Specific conditions for determining the size of operands.
/// (See Table A-1, Appendix A.2.5 of Vol. 2D).
and internal SzCond =
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
and internal TupleType =
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

and internal SizeKind =
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

and [<AbstractClass>] internal OperandParser() =
  abstract Render: ByteSpan * ParsingHelper -> Operands

and [<AbstractClass>] internal InsSizeComputer() =
  abstract Render: ParsingHelper * SzCond -> unit
  abstract RenderEVEX: ByteSpan * ParsingHelper * SzCond -> unit

  default _.Render(phlp: ParsingHelper, _) =
    phlp.MemEffOprSize <- 0<rt>
    phlp.MemEffAddrSize <- 0<rt>
    phlp.MemEffRegSize <- 0<rt>
    phlp.RegSize <- 0<rt>
    phlp.OperationSize <- 0<rt>

  default _.RenderEVEX(_, phlp: ParsingHelper, _) =
    phlp.MemEffOprSize <- 0<rt>
    phlp.MemEffAddrSize <- 0<rt>
    phlp.MemEffRegSize <- 0<rt>
    phlp.RegSize <- 0<rt>
    phlp.OperationSize <- 0<rt>

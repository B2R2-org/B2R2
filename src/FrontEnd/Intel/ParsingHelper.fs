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
  let mutable bcstSz = 0<rt>
  let mutable opcodeClass = OpcodeClass.Normal OpcodeMap.OneByte
  let mutable isFar = false

  new(reader, wordSz, lifter) =
    ParsingHelper(reader, 0UL, 0, Prefix.None, REXPrefix.NOREX, None,
                  wordSz, lifter)

  member _.InsAddr with get(): Addr = addr and set a = addr <- a
  member _.CurrPos with get() = cpos and set p = cpos <- p
  member _.Prefixes with get() = pref and set p = pref <- p
  member _.REXPrefix with get(): REXPrefix = rex and set r = rex <- r
  member _.VEXInfo with get(): VEXInfo option = vex and set v = vex <- v
  member _.WordSize with get(): WordSize = wordSize and set w = wordSize <- w
  member _.MemEffOprSize with get() = memOprSz and set s = memOprSz <- s
  member _.MemEffAddrSize with get() = memAddrSz and set s = memAddrSz <- s
  member _.MemEffRegSize with get() = memRegSz and set s = memRegSz <- s
  member _.RegSize with get() = regSz and set(s) = regSz <- s
  member _.OperationSize with get() = operationSz and set s = operationSz <- s
  member _.TupleType
    with get(): TupleType = tupleType and set t = tupleType <- t
  /// The width of one broadcast element, as declared by the operand being
  /// parsed; 0<rt> when that operand does not support embedded broadcast.
  /// REX.W cannot stand in for this: an FP16 element is 16 bits wide with
  /// either setting of W.
  member _.BroadcastSize with get() = bcstSz and set s = bcstSz <- s
  member _.OpcodeClass
    with get(): OpcodeClass = opcodeClass and set c = opcodeClass <- c
  member _.Lifter with get(): ILiftable = lifter
  member _.IsFar with get() = isFar and set f = isFar <- f

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

// vim: set tw=80 sts=2 sw=2:

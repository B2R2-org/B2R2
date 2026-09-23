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

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Intel.ParsingFunctions
open LanguagePrimitives

/// Represents a parser for Intel (x86 or x86-64) instructions. The prefixes,
/// the REX byte and the VEX or EVEX prefix are read here; the opcode maps are
/// the generated straight-line code of LegacyOpcodeMap and VEXOpcodeMap, which
/// IntelParserGen writes from InstructionTable, so that nothing about an
/// instruction is looked up at parse time.
type IntelParser(wordSz, reader: IBinReader) =
  /// Split a byte value into two fileds (high 3 bits; low 5 bits), and
  /// categorize prefix values into 8 groups based on the high 3 bits (= 2^3).
  /// The below array is a collection of bitmaps that maps the low 5-bit value
  /// to a bit value indicating whether the given byte value is a prefix value
  /// or not.
  let prefixCheck =
    [| 0x0u        (* 000xxxxx = cannot be a prefix value *)
       0x40404040u (* 001xxxxx = 26/2e/36/3e is possible *)
       0x0u        (* 010xxxxx = cannot be a prefix value *)
       0x000000f0u (* 011xxxxx = 64/65/66/67 is possible *)
       0x0u
       0x0u
       0x0u
       0x000d0000u (* 111xxxxx = f0/f2/f3 is possible *) |]

  let is64 = wordSz = WordSize.Bit64

  let mutable disasm = Disasm.Delegate Disasm.IntelSyntax.disasm

  let lifter =
    { new ILiftable with
        member _.Lift(ins, builder) = Lifter.translate ins builder
        member _.Disasm(ins, builder) = disasm.Invoke(builder, ins); builder }

  do ignore reader

  member _.SetDisassemblySyntax syntax =
    match syntax with
    | DefaultSyntax -> disasm <- Disasm.Delegate Disasm.IntelSyntax.disasm
    | ATTSyntax -> disasm <- Disasm.Delegate Disasm.ATTSyntax.disasm

  member inline private _.IsPrefixByte(b: byte) =
    ((prefixCheck[(int b >>> 5)] >>> (int b &&& 0b11111)) &&& 1u) > 0u

  /// In 64-bit mode 40h through 4Fh are REX prefixes; below it they are the
  /// one-byte INC and DEC forms and no prefix at all.
  member inline private _.IsREXByte(b: byte) =
    is64 && (int b &&& 0b11110000) = 0b01000000

  /// Reads the legacy prefixes from startPos on, folding them into pref, and
  /// returns the position of the first byte that is not one.
  member inline private this.ParsePrefix(span: ByteSpan,
                                         startPos,
                                         pref: Prefix byref) =
    let mutable pos = startPos
    let mutable b = span[pos]
    while this.IsPrefixByte b do
      match b with
      | 0xF0uy -> pref <- Prefix.LOCK ||| (Prefix.ClearGrp1PrefMask &&& pref)
      | 0xF2uy -> pref <- Prefix.REPNZ ||| (Prefix.ClearGrp1PrefMask &&& pref)
      | 0xF3uy -> pref <- Prefix.REPZ ||| (Prefix.ClearGrp1PrefMask &&& pref)
      | 0x2Euy -> pref <- Prefix.CS ||| (Prefix.ClearSegMask &&& pref)
      | 0x36uy -> pref <- Prefix.SS ||| (Prefix.ClearSegMask &&& pref)
      | 0x3Euy -> pref <- Prefix.DS ||| (Prefix.ClearSegMask &&& pref)
      | 0x26uy -> pref <- Prefix.ES ||| (Prefix.ClearSegMask &&& pref)
      | 0x64uy -> pref <- Prefix.FS ||| (Prefix.ClearSegMask &&& pref)
      | 0x65uy -> pref <- Prefix.GS ||| (Prefix.ClearSegMask &&& pref)
      | 0x66uy -> pref <- Prefix.OPSIZE ||| pref
      | 0x67uy -> pref <- Prefix.ADDRSIZE ||| pref
      | _ -> pos <- pos - 1
      pos <- pos + 1
      b <- span[pos]
    pos

  member inline private _.ParseREX(bs: ByteSpan, pos, rex: REXPrefix byref) =
    if not is64 then
      pos
    else
      let rb = bs[pos] |> int
      if rb &&& 0b11110000 = 0b01000000 then
        rex <- EnumOfValue rb
        pos + 1
      else
        pos

  /// Reads a VEX or EVEX prefix where one sits, or else the escape bytes that
  /// select a legacy map, whose number is left in map.
  member inline private _.ParseVEX(bs: ByteSpan,
                                   pos,
                                   rex: REXPrefix byref,
                                   vex: VEXInfo option byref,
                                   map: int byref) =
    match bs[pos] with
    | 0x0Fuy ->
      match bs[pos + 1] with
      | 0x38uy ->
        map <- 2
        pos + 2
      | 0x3Auy ->
        map <- 3
        pos + 2
      | _ ->
        map <- 1
        pos + 1
    (* Outside 64-bit mode C5h, C4h and 62h are LDS, LES and BOUND unless the
       ModRM byte that follows names a register. *)
    | 0xC5uy when bs[pos + 1] >= 0xC0uy || is64 ->
      vex <- Some(getTwoVEXInfo bs &rex (pos + 1))
      pos + 2
    | 0xC4uy when bs[pos + 1] >= 0xC0uy || is64 ->
      vex <- Some(getThreeVEXInfo bs &rex (pos + 1))
      pos + 3
    | 0x62uy when bs[pos + 1] >= 0xC0uy || is64 ->
      vex <- Some(getEVEXInfo bs &rex (pos + 1))
      pos + 4
    | _ ->
      pos

  /// The REX state the accept masks and the generated code number: none,
  /// present without W, present with W.
  member inline private _.REXState(rex: REXPrefix) =
    if rex = REXPrefix.NOREX then 0
    elif REXPrefix.hasW rex then 2
    else 1

  member inline private _.AddrSize(pref: Prefix) =
    if is64 then (if Prefix.hasAddrSz pref then 32<rt> else 64<rt>)
    else (if Prefix.hasAddrSz pref then 16<rt> else 32<rt>)

  /// The generated map a VEX or EVEX prefix selects: the VEX maps first, in
  /// the order VEXType numbers them, then the EVEX ones.
  member private _.VexMapIndex(vInfo: VEXInfo) =
    let evex = vInfo.VEXType &&& VEXType.EVEX = VEXType.EVEX
    match vInfo.VEXType &&& (~~~VEXType.EVEX), evex with
    | VEXType.TwoByteOp, false -> 0
    | VEXType.ThreeByteOpOne, false -> 1
    | VEXType.ThreeByteOpTwo, false -> 2
    | VEXType.TwoByteOp, true -> 3
    | VEXType.ThreeByteOpOne, true -> 4
    | VEXType.ThreeByteOpTwo, true -> 5
    | VEXType.Map5, true -> 6
    | VEXType.Map6, true -> 7
    | _ -> raise ParsingFailureException

#if NoOpcodeMaps
  (* Built without the generated maps, for the generator that writes them. *)
  member private _.ParseLegacy(_: ByteSpan,
                               _: Addr,
                               _: Prefix,
                               _: REXPrefix,
                               _: int,
                               _: int): IInstruction =
    raise ParsingFailureException

  member private _.ParseVex(_: ByteSpan,
                            _: Addr,
                            _: Prefix,
                            _: REXPrefix,
                            _: VEXInfo,
                            _: VEXInfo option,
                            _: int): IInstruction =
    raise ParsingFailureException
#else
  /// Parses a legacy (non-VEX) instruction with the generated straight-line
  /// code (LegacyOpcodeMap), the per-instruction state living on this stack
  /// frame.
  member private this.ParseLegacy(span: ByteSpan, addr, pref, rex, map, pos) =
    (* The state is zeroed by the frame; only what a legacy instruction reads
       is written, and the VEX fields stay at their zero. *)
    let mutable st = Unchecked.defaultof<OpcodeMapHelper.ParsingState>
    st.Pos <- pos + 1
    st.Pref <- pref
    st.REX <- rex
    st.Ctx <- this.REXState rex * 8 + MatchContext.prefState pref
              + (if is64 then 24 else 0)
    st.AddrSz <- this.AddrSize pref
    st.Is64 <- is64
    st.NoLock <- not (Prefix.hasLock pref)
    st.Addr <- addr
    st.Lifter <- lifter
    LegacyOpcodeMap.parse span &st map (int span[pos]) :> IInstruction

  /// Parses a VEX or EVEX instruction with the generated code (VEXOpcodeMap).
  member private this.ParseVex(span: ByteSpan,
                               addr,
                               pref,
                               rex,
                               vInfo: VEXInfo,
                               vex,
                               pos) =
    let evexB, aaa, zeroing =
      match vInfo.EVEXPrx with
      | Some e -> e.B = 1uy, int e.AAA, e.Z = Zeroing
      | None -> false, 0, false
    let mutable st: OpcodeMapHelper.ParsingState =
      { Pos = pos + 1
        Pref = pref
        REX = rex
        Ctx = this.REXState rex * 8 + MatchContext.prefState vInfo.VPrefixes
              + (if is64 then 24 else 0)
        AddrSz = this.AddrSize pref
        Is64 = is64
        NoLock = not (Prefix.hasLock pref)
        Addr = addr
        Lifter = lifter
        Vex = vex
        VL = vInfo.VectorLength
        VVVV = int vInfo.VVVV
        IsEVEX = vInfo.EVEXPrx.IsSome
        EvexB = evexB
        AAA = aaa
        Zeroing = zeroing }
    let map = this.VexMapIndex vInfo
    VEXOpcodeMap.parse span &st map (int span[pos]) :> IInstruction
#endif

  interface IInstructionParsable with
    member _.MaxInstructionSize = 15

    member _.InstructionAlignment = 1

    member this.Parse(bs: byte[], addr) =
      (this :> IInstructionParsable).Parse(ReadOnlySpan bs, addr)

    member this.Parse(span: ByteSpan, addr) =
      try
        let mutable pref = Prefix.None
        let mutable rex = REXPrefix.NOREX
        let mutable vex = None
        let mutable map = 0
        let mutable prefEndPos = this.ParsePrefix(span, 0, &pref)
        let mutable rexEndPos = this.ParseREX(span, prefEndPos, &rex)
        (* SDM Vol 2A 2.2.1: a REX prefix has to sit immediately before the
           opcode, so one that another prefix follows is ignored and the scan
           carries on past it. Two REX bytes in a row read the same way: only
           the last one is doing anything. *)
        while rexEndPos > prefEndPos
              && (this.IsPrefixByte(span[rexEndPos])
                  || this.IsREXByte(span[rexEndPos])) do
          rex <- REXPrefix.NOREX
          prefEndPos <- this.ParsePrefix(span, rexEndPos, &pref)
          rexEndPos <- this.ParseREX(span, prefEndPos, &rex)
        let pos = this.ParseVEX(span, rexEndPos, &rex, &vex, &map)
        match vex with
        | None -> this.ParseLegacy(span, addr, pref, rex, map, pos)
        | Some vInfo -> this.ParseVex(span, addr, pref, rex, vInfo, vex, pos)
      with e when not (Terminator.isCritical e) ->
        raise ParsingFailureException

// vim: set tw=80 sts=2 sw=2:

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

namespace B2R2.FrontEnd.BinLifter.Intel

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.FrontEnd.BinLifter.Intel.Helper
open LanguagePrimitives
open type Prefix

/// Parser for Intel (x86 or x86-64) instructions. Parser will return a
/// platform-agnostic instruction type (Instruction).
type IntelParser (wordSz) =
  inherit Parser ()

  let oparsers =
    [| OpRmGpr () :> OperandParser
       OpRmSeg () :> OperandParser
       OpGprCtrl () :> OperandParser
       OpGprDbg () :> OperandParser
       OpRMMmx () :> OperandParser
       OpMmMmx () :> OperandParser
       OpBmBnd () :> OperandParser
       OpRmBnd () :> OperandParser
       OpGprRm () :> OperandParser
       OpGprM () :> OperandParser
       OpMGpr () :> OperandParser
       OpSegRm () :> OperandParser
       OpBndBm () :> OperandParser
       OpBndRm () :> OperandParser
       OpCtrlGpr () :> OperandParser
       OpDbgGpr () :> OperandParser
       OpMmxRm () :> OperandParser
       OpMmxMm () :> OperandParser
       OpGprRMm () :> OperandParser
       OpRegImm8 () :> OperandParser
       OpImm8Reg () :> OperandParser
       OpImm8 () :> OperandParser
       OpImm16 () :> OperandParser
       OpRegImm () :> OperandParser
       OpSImm8 () :> OperandParser
       OpImm () :> OperandParser
       OpEs () :> OperandParser
       OpCs () :> OperandParser
       OpSs () :> OperandParser
       OpDs () :> OperandParser
       OpFs () :> OperandParser
       OpGs () :> OperandParser
       OpALDx () :> OperandParser
       OpEaxDx () :> OperandParser
       OpDxEax () :> OperandParser
       OpDxAL () :> OperandParser
       OpNo () :> OperandParser
       OpEax () :> OperandParser
       OpEcx () :> OperandParser
       OpEdx () :> OperandParser
       OpEbx () :> OperandParser
       OpEsp () :> OperandParser
       OpEbp () :> OperandParser
       OpEsi () :> OperandParser
       OpEdi () :> OperandParser
       OpRax () :> OperandParser
       OpRcx () :> OperandParser
       OpRdx () :> OperandParser
       OpRbx () :> OperandParser
       OpRsp () :> OperandParser
       OpRbp () :> OperandParser
       OpRsi () :> OperandParser
       OpRdi () :> OperandParser
       OpRaxRax () :> OperandParser
       OpRaxRcx () :> OperandParser
       OpRaxRdx () :> OperandParser
       OpRaxRbx () :> OperandParser
       OpRaxRsp () :> OperandParser
       OpRaxRbp () :> OperandParser
       OpRaxRsi () :> OperandParser
       OpRaxRdi () :> OperandParser
       OpGprRmImm8 () :> OperandParser
       OpGprRmImm () :> OperandParser
       OpRel8 () :> OperandParser
       OpRel () :> OperandParser
       OpDir () :> OperandParser
       OpRaxFar () :> OperandParser
       OpFarRax () :> OperandParser
       OpALImm8 () :> OperandParser
       OpCLImm8 () :> OperandParser
       OpDLImm8 () :> OperandParser
       OpBLImm8 () :> OperandParser
       OpAhImm8 () :> OperandParser
       OpChImm8 () :> OperandParser
       OpDhImm8 () :> OperandParser
       OpBhImm8 () :> OperandParser
       OpRaxImm () :> OperandParser
       OpRcxImm () :> OperandParser
       OpRdxImm () :> OperandParser
       OpRbxImm () :> OperandParser
       OpRspImm () :> OperandParser
       OpRbpImm () :> OperandParser
       OpRsiImm () :> OperandParser
       OpRdiImm () :> OperandParser
       OpImmImm () :> OperandParser
       OpRmImm () :> OperandParser
       OpRmImm8 () :> OperandParser
       OpMmxImm8 () :> OperandParser
       OpMem () :> OperandParser
       OpM1 () :> OperandParser
       OpRmCL () :> OperandParser
       OpXmmVvXm () :> OperandParser
       OpGprVvRm () :> OperandParser
       OpXmVvXmm () :> OperandParser
       OpGpr () :> OperandParser
       OpRmXmmImm8 () :> OperandParser
       OpXmmRmImm8 () :> OperandParser
       OpMmxMmImm8 () :> OperandParser
       OpMmxRmImm8 () :> OperandParser
       OpGprMmxImm8 () :> OperandParser
       OpXmmVvXmImm8 () :> OperandParser
       OpXmmVvXmXmm () :> OperandParser
       OpXmRegImm8 () :> OperandParser
       OpGprRmVv () :> OperandParser
       OpVvRmImm8 () :> OperandParser
       OpRmGprCL () :> OperandParser
       OpXmmXmXmm0 () :> OperandParser
       OpXmmXmVv () :> OperandParser
       OpVvRm () :> OperandParser
       OpGprRmImm8Imm8 () :> OperandParser
       OpRmImm8Imm8 () :> OperandParser |]

  let szcomputers =
    [| SzByte () :> InsSizeComputer
       SzWord () :> InsSizeComputer
       SzDef () :> InsSizeComputer
       SzVecDef () :> InsSizeComputer
       SzDV () :> InsSizeComputer
       SzD () :> InsSizeComputer
       SzMemW () :> InsSizeComputer
       SzRegW () :> InsSizeComputer
       SzWV () :> InsSizeComputer
       SzD64 () :> InsSizeComputer
       SzPZ () :> InsSizeComputer
       SzDDq () :> InsSizeComputer
       SzDqDq () :> InsSizeComputer
       SzDqdDq () :> InsSizeComputer
       SzDqdDqMR () :> InsSizeComputer
       SzDqqDq () :> InsSizeComputer
       SzDqqDqMR () :> InsSizeComputer
       SzXqX () :> InsSizeComputer
       SzDqqDqWS () :> InsSizeComputer
       SzVyDq () :> InsSizeComputer
       SzVyDqMR () :> InsSizeComputer
       SzDY () :> InsSizeComputer
       SzQDq () :> InsSizeComputer
       SzDqqQ () :> InsSizeComputer
       SzDqQ () :> InsSizeComputer
       SzDqdY () :> InsSizeComputer
       SzDqqY () :> InsSizeComputer
       SzDqY () :> InsSizeComputer
       SzDq () :> InsSizeComputer
       SzDQ () :> InsSizeComputer
       SzQQ () :> InsSizeComputer
       SzYQ () :> InsSizeComputer
       SzYQRM () :> InsSizeComputer
       SzDwQ () :> InsSizeComputer
       SzDwDq () :> InsSizeComputer
       SzDwDqMR () :> InsSizeComputer
       SzQD () :> InsSizeComputer
       SzDqd () :> InsSizeComputer
       SzXDq () :> InsSizeComputer
       SzDqX () :> InsSizeComputer
       SzXD () :> InsSizeComputer
       SzDqqdqX () :> InsSizeComputer
       SzDqddqX () :> InsSizeComputer
       SzDqwDq () :> InsSizeComputer
       SzDqwX () :> InsSizeComputer
       SzDqQqq () :> InsSizeComputer
       SzDqbX () :> InsSizeComputer
       SzDbDq () :> InsSizeComputer
       SzBV () :> InsSizeComputer
       SzQ () :> InsSizeComputer
       SzS () :> InsSizeComputer
       SzDX () :> InsSizeComputer
       SzDqdXz () :> InsSizeComputer
       SzDqqX () :> InsSizeComputer
       SzP () :> InsSizeComputer
       SzPRM () :> InsSizeComputer
       SzXqXz () :> InsSizeComputer
       SzXXz () :> InsSizeComputer
       SzXzX () :> InsSizeComputer
       SzXzXz () :> InsSizeComputer
       SzDqqQq () :> InsSizeComputer
       SzDqqXz () :> InsSizeComputer
       SzQqXz () :> InsSizeComputer
       SzQqXzRM () :> InsSizeComputer
       SzDqdX () :> InsSizeComputer
       SzDXz () :> InsSizeComputer
       SzQXz () :> InsSizeComputer
       SzDqQq () :> InsSizeComputer
       SzDqXz () :> InsSizeComputer
       SzYDq () :> InsSizeComputer
       SzQq () :> InsSizeComputer
       SzDqwdX () :> InsSizeComputer
       SzY () :> InsSizeComputer |]

  let oneByteParsers =
    [| OneOp00 () :> ParsingJob
       OneOp01 () :> ParsingJob
       OneOp02 () :> ParsingJob
       OneOp03 () :> ParsingJob
       OneOp04 () :> ParsingJob
       OneOp05 () :> ParsingJob
       OneOp06 () :> ParsingJob
       OneOp07 () :> ParsingJob
       OneOp08 () :> ParsingJob
       OneOp09 () :> ParsingJob
       OneOp0A () :> ParsingJob
       OneOp0B () :> ParsingJob
       OneOp0C () :> ParsingJob
       OneOp0D () :> ParsingJob
       OneOp0E () :> ParsingJob
       OneOp0F () :> ParsingJob
       OneOp10 () :> ParsingJob
       OneOp11 () :> ParsingJob
       OneOp12 () :> ParsingJob
       OneOp13 () :> ParsingJob
       OneOp14 () :> ParsingJob
       OneOp15 () :> ParsingJob
       OneOp16 () :> ParsingJob
       OneOp17 () :> ParsingJob
       OneOp18 () :> ParsingJob
       OneOp19 () :> ParsingJob
       OneOp1A () :> ParsingJob
       OneOp1B () :> ParsingJob
       OneOp1C () :> ParsingJob
       OneOp1D () :> ParsingJob
       OneOp1E () :> ParsingJob
       OneOp1F () :> ParsingJob
       OneOp20 () :> ParsingJob
       OneOp21 () :> ParsingJob
       OneOp22 () :> ParsingJob
       OneOp23 () :> ParsingJob
       OneOp24 () :> ParsingJob
       OneOp25 () :> ParsingJob
       OneOp26 () :> ParsingJob
       OneOp27 () :> ParsingJob
       OneOp28 () :> ParsingJob
       OneOp29 () :> ParsingJob
       OneOp2A () :> ParsingJob
       OneOp2B () :> ParsingJob
       OneOp2C () :> ParsingJob
       OneOp2D () :> ParsingJob
       OneOp2E () :> ParsingJob
       OneOp2F () :> ParsingJob
       OneOp30 () :> ParsingJob
       OneOp31 () :> ParsingJob
       OneOp32 () :> ParsingJob
       OneOp33 () :> ParsingJob
       OneOp34 () :> ParsingJob
       OneOp35 () :> ParsingJob
       OneOp36 () :> ParsingJob
       OneOp37 () :> ParsingJob
       OneOp38 () :> ParsingJob
       OneOp39 () :> ParsingJob
       OneOp3A () :> ParsingJob
       OneOp3B () :> ParsingJob
       OneOp3C () :> ParsingJob
       OneOp3D () :> ParsingJob
       OneOp3E () :> ParsingJob
       OneOp3F () :> ParsingJob
       OneOp40 () :> ParsingJob
       OneOp41 () :> ParsingJob
       OneOp42 () :> ParsingJob
       OneOp43 () :> ParsingJob
       OneOp44 () :> ParsingJob
       OneOp45 () :> ParsingJob
       OneOp46 () :> ParsingJob
       OneOp47 () :> ParsingJob
       OneOp48 () :> ParsingJob
       OneOp49 () :> ParsingJob
       OneOp4A () :> ParsingJob
       OneOp4B () :> ParsingJob
       OneOp4C () :> ParsingJob
       OneOp4D () :> ParsingJob
       OneOp4E () :> ParsingJob
       OneOp4F () :> ParsingJob
       OneOp50 () :> ParsingJob
       OneOp51 () :> ParsingJob
       OneOp52 () :> ParsingJob
       OneOp53 () :> ParsingJob
       OneOp54 () :> ParsingJob
       OneOp55 () :> ParsingJob
       OneOp56 () :> ParsingJob
       OneOp57 () :> ParsingJob
       OneOp58 () :> ParsingJob
       OneOp59 () :> ParsingJob
       OneOp5A () :> ParsingJob
       OneOp5B () :> ParsingJob
       OneOp5C () :> ParsingJob
       OneOp5D () :> ParsingJob
       OneOp5E () :> ParsingJob
       OneOp5F () :> ParsingJob
       OneOp60 () :> ParsingJob
       OneOp61 () :> ParsingJob
       OneOp62 () :> ParsingJob
       OneOp63 () :> ParsingJob
       OneOp64 () :> ParsingJob
       OneOp65 () :> ParsingJob
       OneOp66 () :> ParsingJob
       OneOp67 () :> ParsingJob
       OneOp68 () :> ParsingJob
       OneOp69 () :> ParsingJob
       OneOp6A () :> ParsingJob
       OneOp6B () :> ParsingJob
       OneOp6C () :> ParsingJob
       OneOp6D () :> ParsingJob
       OneOp6E () :> ParsingJob
       OneOp6F () :> ParsingJob
       OneOp70 () :> ParsingJob
       OneOp71 () :> ParsingJob
       OneOp72 () :> ParsingJob
       OneOp73 () :> ParsingJob
       OneOp74 () :> ParsingJob
       OneOp75 () :> ParsingJob
       OneOp76 () :> ParsingJob
       OneOp77 () :> ParsingJob
       OneOp78 () :> ParsingJob
       OneOp79 () :> ParsingJob
       OneOp7A () :> ParsingJob
       OneOp7B () :> ParsingJob
       OneOp7C () :> ParsingJob
       OneOp7D () :> ParsingJob
       OneOp7E () :> ParsingJob
       OneOp7F () :> ParsingJob
       OneOp80 () :> ParsingJob
       OneOp81 () :> ParsingJob
       OneOp82 () :> ParsingJob
       OneOp83 () :> ParsingJob
       OneOp84 () :> ParsingJob
       OneOp85 () :> ParsingJob
       OneOp86 () :> ParsingJob
       OneOp87 () :> ParsingJob
       OneOp88 () :> ParsingJob
       OneOp89 () :> ParsingJob
       OneOp8A () :> ParsingJob
       OneOp8B () :> ParsingJob
       OneOp8C () :> ParsingJob
       OneOp8D () :> ParsingJob
       OneOp8E () :> ParsingJob
       OneOp8F () :> ParsingJob
       OneOp90 () :> ParsingJob
       OneOp91 () :> ParsingJob
       OneOp92 () :> ParsingJob
       OneOp93 () :> ParsingJob
       OneOp94 () :> ParsingJob
       OneOp95 () :> ParsingJob
       OneOp96 () :> ParsingJob
       OneOp97 () :> ParsingJob
       OneOp98 () :> ParsingJob
       OneOp99 () :> ParsingJob
       OneOp9A () :> ParsingJob
       OneOp9B () :> ParsingJob
       OneOp9C () :> ParsingJob
       OneOp9D () :> ParsingJob
       OneOp9E () :> ParsingJob
       OneOp9F () :> ParsingJob
       OneOpA0 () :> ParsingJob
       OneOpA1 () :> ParsingJob
       OneOpA2 () :> ParsingJob
       OneOpA3 () :> ParsingJob
       OneOpA4 () :> ParsingJob
       OneOpA5 () :> ParsingJob
       OneOpA6 () :> ParsingJob
       OneOpA7 () :> ParsingJob
       OneOpA8 () :> ParsingJob
       OneOpA9 () :> ParsingJob
       OneOpAA () :> ParsingJob
       OneOpAB () :> ParsingJob
       OneOpAC () :> ParsingJob
       OneOpAD () :> ParsingJob
       OneOpAE () :> ParsingJob
       OneOpAF () :> ParsingJob
       OneOpB0 () :> ParsingJob
       OneOpB1 () :> ParsingJob
       OneOpB2 () :> ParsingJob
       OneOpB3 () :> ParsingJob
       OneOpB4 () :> ParsingJob
       OneOpB5 () :> ParsingJob
       OneOpB6 () :> ParsingJob
       OneOpB7 () :> ParsingJob
       OneOpB8 () :> ParsingJob
       OneOpB9 () :> ParsingJob
       OneOpBA () :> ParsingJob
       OneOpBB () :> ParsingJob
       OneOpBC () :> ParsingJob
       OneOpBD () :> ParsingJob
       OneOpBE () :> ParsingJob
       OneOpBF () :> ParsingJob
       OneOpC0 () :> ParsingJob
       OneOpC1 () :> ParsingJob
       OneOpC2 () :> ParsingJob
       OneOpC3 () :> ParsingJob
       OneOpC4 () :> ParsingJob
       OneOpC5 () :> ParsingJob
       OneOpC6 () :> ParsingJob
       OneOpC7 () :> ParsingJob
       OneOpC8 () :> ParsingJob
       OneOpC9 () :> ParsingJob
       OneOpCA () :> ParsingJob
       OneOpCB () :> ParsingJob
       OneOpCC () :> ParsingJob
       OneOpCD () :> ParsingJob
       OneOpCE () :> ParsingJob
       OneOpCF () :> ParsingJob
       OneOpD0 () :> ParsingJob
       OneOpD1 () :> ParsingJob
       OneOpD2 () :> ParsingJob
       OneOpD3 () :> ParsingJob
       OneOpD4 () :> ParsingJob
       OneOpD5 () :> ParsingJob
       OneOpD6 () :> ParsingJob
       OneOpD7 () :> ParsingJob
       OneOpD8 () :> ParsingJob
       OneOpD9 () :> ParsingJob
       OneOpDA () :> ParsingJob
       OneOpDB () :> ParsingJob
       OneOpDC () :> ParsingJob
       OneOpDD () :> ParsingJob
       OneOpDE () :> ParsingJob
       OneOpDF () :> ParsingJob
       OneOpE0 () :> ParsingJob
       OneOpE1 () :> ParsingJob
       OneOpE2 () :> ParsingJob
       OneOpE3 () :> ParsingJob
       OneOpE4 () :> ParsingJob
       OneOpE5 () :> ParsingJob
       OneOpE6 () :> ParsingJob
       OneOpE7 () :> ParsingJob
       OneOpE8 () :> ParsingJob
       OneOpE9 () :> ParsingJob
       OneOpEA () :> ParsingJob
       OneOpEB () :> ParsingJob
       OneOpEC () :> ParsingJob
       OneOpED () :> ParsingJob
       OneOpEE () :> ParsingJob
       OneOpEF () :> ParsingJob
       OneOpF0 () :> ParsingJob
       OneOpF1 () :> ParsingJob
       OneOpF2 () :> ParsingJob
       OneOpF3 () :> ParsingJob
       OneOpF4 () :> ParsingJob
       OneOpF5 () :> ParsingJob
       OneOpF6 () :> ParsingJob
       OneOpF7 () :> ParsingJob
       OneOpF8 () :> ParsingJob
       OneOpF9 () :> ParsingJob
       OneOpFA () :> ParsingJob
       OneOpFB () :> ParsingJob
       OneOpFC () :> ParsingJob
       OneOpFD () :> ParsingJob
       OneOpFE () :> ParsingJob
       OneOpFF () :> ParsingJob |]

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

  let rhlp = ReadHelper (wordSz, oparsers, szcomputers)

  member inline private __.ParsePrefix (reader, pos: int) =
    let mutable pos = pos
    let mutable pref = PrxNone
    let mutable b = (reader: BinReader).PeekByte pos
    while ((prefixCheck[(int b >>> 5)] >>> (int b &&& 0b11111)) &&& 1u) > 0u do
      match b with
      | 0xF0uy -> pref <- PrxLOCK ||| (clearGrp1PrefMask &&& pref)
      | 0xF2uy -> pref <- PrxREPNZ ||| (clearGrp1PrefMask &&& pref)
      | 0xF3uy -> pref <- PrxREPZ ||| (clearGrp1PrefMask &&& pref)
      | 0x2Euy -> pref <- PrxCS ||| (clearSegMask &&& pref)
      | 0x36uy -> pref <- PrxSS ||| (clearSegMask &&& pref)
      | 0x3Euy -> pref <- PrxDS ||| (clearSegMask &&& pref)
      | 0x26uy -> pref <- PrxES ||| (clearSegMask &&& pref)
      | 0x64uy -> pref <- PrxFS ||| (clearSegMask &&& pref)
      | 0x65uy -> pref <- PrxGS ||| (clearSegMask &&& pref)
      | 0x66uy -> pref <- PrxOPSIZE ||| pref
      | 0x67uy -> pref <- PrxADDRSIZE ||| pref
      | _ -> pos <- pos - 1
      pos <- pos + 1
      b <- reader.PeekByte pos
    rhlp.Prefixes <- pref
    pos

  member inline private __.ParseREX (reader, pos, rex: REXPrefix byref) =
    if wordSz = WordSize.Bit32 then pos
    else
      let rb = (reader: BinReader).PeekByte pos |> int
      if rb &&& 0b11110000 = 0b01000000 then
        rex <- EnumOfValue rb
        pos + 1
      else pos

  override __.Parse reader addr pos =
    let mutable rex = REXPrefix.NOREX
    let prefEndPos = __.ParsePrefix (reader, pos)
    let nextPos = __.ParseREX (reader, prefEndPos, &rex)
    rhlp.VEXInfo <- None
    rhlp.BinReader <- reader
    rhlp.InsAddr <- addr
    rhlp.REXPrefix <- rex
    rhlp.InitialPos <- pos
    rhlp.CurrPos <- nextPos
#if LCACHE
    rhlp.MarkPrefixEnd (prefEndPos)
#endif
    oneByteParsers[int (rhlp.ReadByte ())].Run rhlp :> Instruction

  override __.OperationMode with get() = ArchOperationMode.NoMode and set _ = ()

// vim: set tw=80 sts=2 sw=2:

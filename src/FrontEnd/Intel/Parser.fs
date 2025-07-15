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
open B2R2.FrontEnd.Intel
open LanguagePrimitives
open type Prefix

/// Represents a parser for Intel (x86 or x86-64) instructions, returning a
/// platform-agnostic instruction type.
type IntelParser (wordSz, reader) =
  let oparsers =
    [| OperandParsers.RmGpr () :> OperandParser
       OperandParsers.RmSeg ()
       OperandParsers.GprCtrl ()
       OperandParsers.GprDbg ()
       OperandParsers.RMMmx ()
       OperandParsers.MmMmx ()
       OperandParsers.BmBnd ()
       OperandParsers.RmBnd ()
       OperandParsers.GprRm ()
       OperandParsers.GprM ()
       OperandParsers.MGpr ()
       OperandParsers.SegRm ()
       OperandParsers.BndBm ()
       OperandParsers.BndRm ()
       OperandParsers.CtrlGpr ()
       OperandParsers.DbgGpr ()
       OperandParsers.MmxRm ()
       OperandParsers.MmxMm ()
       OperandParsers.MxMx ()
       OperandParsers.GprRMm ()
       OperandParsers.RegImm8 ()
       OperandParsers.Imm8Reg ()
       OperandParsers.Imm8 ()
       OperandParsers.Imm16 ()
       OperandParsers.RegImm ()
       OperandParsers.SImm8 ()
       OperandParsers.Imm ()
       OperandParsers.Es ()
       OperandParsers.Cs ()
       OperandParsers.Ss ()
       OperandParsers.Ds ()
       OperandParsers.Fs ()
       OperandParsers.Gs ()
       OperandParsers.ALDx ()
       OperandParsers.EaxDx ()
       OperandParsers.DxEax ()
       OperandParsers.DxAL ()
       OperandParsers.No ()
       OperandParsers.Eax ()
       OperandParsers.Ecx ()
       OperandParsers.Edx ()
       OperandParsers.Ebx ()
       OperandParsers.Esp ()
       OperandParsers.Ebp ()
       OperandParsers.Esi ()
       OperandParsers.Edi ()
       OperandParsers.Rax ()
       OperandParsers.Rcx ()
       OperandParsers.Rdx ()
       OperandParsers.Rbx ()
       OperandParsers.Rsp ()
       OperandParsers.Rbp ()
       OperandParsers.Rsi ()
       OperandParsers.Rdi ()
       OperandParsers.RaxRax ()
       OperandParsers.RaxRcx ()
       OperandParsers.RaxRdx ()
       OperandParsers.RaxRbx ()
       OperandParsers.RaxRsp ()
       OperandParsers.RaxRbp ()
       OperandParsers.RaxRsi ()
       OperandParsers.RaxRdi ()
       OperandParsers.GprRmImm8 ()
       OperandParsers.GprRmImm ()
       OperandParsers.Rel8 ()
       OperandParsers.Rel ()
       OperandParsers.Dir ()
       OperandParsers.RaxFar ()
       OperandParsers.FarRax ()
       OperandParsers.ALImm8 ()
       OperandParsers.CLImm8 ()
       OperandParsers.DLImm8 ()
       OperandParsers.BLImm8 ()
       OperandParsers.AhImm8 ()
       OperandParsers.ChImm8 ()
       OperandParsers.DhImm8 ()
       OperandParsers.BhImm8 ()
       OperandParsers.RaxImm ()
       OperandParsers.RcxImm ()
       OperandParsers.RdxImm ()
       OperandParsers.RbxImm ()
       OperandParsers.RspImm ()
       OperandParsers.RbpImm ()
       OperandParsers.RsiImm ()
       OperandParsers.RdiImm ()
       OperandParsers.ImmImm ()
       OperandParsers.RmImm ()
       OperandParsers.RmImm8 ()
       OperandParsers.RmSImm8 ()
       OperandParsers.MmxImm8 ()
       OperandParsers.Mem ()
       OperandParsers.M1 ()
       OperandParsers.RmCL ()
       OperandParsers.XmmVvXm ()
       OperandParsers.GprVvRm ()
       OperandParsers.XmVvXmm ()
       OperandParsers.Gpr ()
       OperandParsers.RmXmmImm8 ()
       OperandParsers.XmmRmImm8 ()
       OperandParsers.MmxMmImm8 ()
       OperandParsers.MmxRmImm8 ()
       OperandParsers.GprMmxImm8 ()
       OperandParsers.XmmVvXmImm8 ()
       OperandParsers.XmmVvXmXmm ()
       OperandParsers.XmRegImm8 ()
       OperandParsers.GprRmVv ()
       OperandParsers.VvRmImm8 ()
       OperandParsers.RmGprCL ()
       OperandParsers.XmmXmXmm0 ()
       OperandParsers.XmmXmVv ()
       OperandParsers.VvRm ()
       OperandParsers.GprRmImm8Imm8 ()
       OperandParsers.RmImm8Imm8 ()
       OperandParsers.KnVvXm ()
       OperandParsers.GprKn ()
       OperandParsers.KnVvXmImm8 ()
       OperandParsers.KnGpr ()
       OperandParsers.XmmVvXmmXm ()
       OperandParsers.KnKm ()
       OperandParsers.MKn ()
       OperandParsers.KKn ()
       OperandParsers.KnKmImm8 ()
       OperandParsers.XmmVsXm ()
       OperandParsers.XmVsXmm () |]

  let szcomputers =
    [| InsSizeComputers.Byte () :> InsSizeComputer
       InsSizeComputers.Word ()
       InsSizeComputers.Def ()
       InsSizeComputers.VecDef ()
       InsSizeComputers.DV ()
       InsSizeComputers.D ()
       InsSizeComputers.MemW ()
       InsSizeComputers.RegW ()
       InsSizeComputers.WV ()
       InsSizeComputers.D64 ()
       InsSizeComputers.PZ ()
       InsSizeComputers.DDq ()
       InsSizeComputers.DqDq ()
       InsSizeComputers.DqdDq ()
       InsSizeComputers.DqdDqMR ()
       InsSizeComputers.DqqDq ()
       InsSizeComputers.DqqDqMR ()
       InsSizeComputers.XqX ()
       InsSizeComputers.DqqDqWS ()
       InsSizeComputers.VyDq ()
       InsSizeComputers.VyDqMR ()
       InsSizeComputers.DY ()
       InsSizeComputers.QDq ()
       InsSizeComputers.DqqQ ()
       InsSizeComputers.DqQ ()
       InsSizeComputers.DqdY ()
       InsSizeComputers.DqqY ()
       InsSizeComputers.DqY ()
       InsSizeComputers.Dq ()
       InsSizeComputers.DQ ()
       InsSizeComputers.QQ ()
       InsSizeComputers.YQ ()
       InsSizeComputers.YQRM ()
       InsSizeComputers.DwQ ()
       InsSizeComputers.DwDq ()
       InsSizeComputers.DwDqMR ()
       InsSizeComputers.QD ()
       InsSizeComputers.Dqd ()
       InsSizeComputers.XDq ()
       InsSizeComputers.DqX ()
       InsSizeComputers.XD ()
       InsSizeComputers.DqqdqX ()
       InsSizeComputers.DqddqX ()
       InsSizeComputers.DqwDq ()
       InsSizeComputers.DqwX ()
       InsSizeComputers.DqQqq ()
       InsSizeComputers.DqbX ()
       InsSizeComputers.DbDq ()
       InsSizeComputers.BV ()
       InsSizeComputers.Q ()
       InsSizeComputers.S ()
       InsSizeComputers.DX ()
       InsSizeComputers.DqdXz ()
       InsSizeComputers.DqqX ()
       InsSizeComputers.P ()
       InsSizeComputers.PRM ()
       InsSizeComputers.XqXz ()
       InsSizeComputers.XXz ()
       InsSizeComputers.XzX ()
       InsSizeComputers.XzXz ()
       InsSizeComputers.DqqQq ()
       InsSizeComputers.DqqXz ()
       InsSizeComputers.QqXz ()
       InsSizeComputers.QqXzRM ()
       InsSizeComputers.DqdX ()
       InsSizeComputers.DXz ()
       InsSizeComputers.QXz ()
       InsSizeComputers.DqQq ()
       InsSizeComputers.DqXz ()
       InsSizeComputers.YDq ()
       InsSizeComputers.Qq ()
       InsSizeComputers.DqwdX ()
       InsSizeComputers.Y ()
       InsSizeComputers.QQb ()
       InsSizeComputers.QQd ()
       InsSizeComputers.QQw ()
       InsSizeComputers.VecDefRC ()
       InsSizeComputers.YP () |]

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

  let mutable disasm = Disasm.Delegate Disasm.IntelSyntax.disasm

  let lifter =
    { new ILiftable with
        member _.Lift ins builder =
          Lifter.translate ins ins.Length builder
        member _.Disasm ins builder =
          disasm.Invoke (builder, ins); builder }

  let phlp = ParsingHelper (reader, wordSz, oparsers, szcomputers, lifter)

  member _.SetDisassemblySyntax syntax =
    match syntax with
    | DefaultSyntax -> disasm <- Disasm.Delegate Disasm.IntelSyntax.disasm
    | ATTSyntax -> disasm <- Disasm.Delegate Disasm.ATTSyntax.disasm

  member inline private _.ParsePrefix (span: ByteSpan) =
    let mutable pos = 0
    let mutable pref = PrxNone
    let mutable b = span[0]
    while ((prefixCheck[(int b >>> 5)] >>> (int b &&& 0b11111)) &&& 1u) > 0u do
      match b with
      | 0xF0uy -> pref <- PrxLOCK ||| (Prefix.ClearGrp1PrefMask &&& pref)
      | 0xF2uy -> pref <- PrxREPNZ ||| (Prefix.ClearGrp1PrefMask &&& pref)
      | 0xF3uy -> pref <- PrxREPZ ||| (Prefix.ClearGrp1PrefMask &&& pref)
      | 0x2Euy -> pref <- PrxCS ||| (Prefix.ClearSegMask &&& pref)
      | 0x36uy -> pref <- PrxSS ||| (Prefix.ClearSegMask &&& pref)
      | 0x3Euy -> pref <- PrxDS ||| (Prefix.ClearSegMask &&& pref)
      | 0x26uy -> pref <- PrxES ||| (Prefix.ClearSegMask &&& pref)
      | 0x64uy -> pref <- PrxFS ||| (Prefix.ClearSegMask &&& pref)
      | 0x65uy -> pref <- PrxGS ||| (Prefix.ClearSegMask &&& pref)
      | 0x66uy -> pref <- PrxOPSIZE ||| pref
      | 0x67uy -> pref <- PrxADDRSIZE ||| pref
      | _ -> pos <- pos - 1
      pos <- pos + 1
      b <- span[pos]
    phlp.Prefixes <- pref
    pos

  member inline private _.ParseREX (bs: ByteSpan, pos, rex: REXPrefix byref) =
    if wordSz = WordSize.Bit32 then pos
    else
      let rb = bs[pos] |> int
      if rb &&& 0b11110000 = 0b01000000 then
        rex <- EnumOfValue rb
        pos + 1
      else pos

  interface IInstructionParsable with
    member this.Parse (bs: byte[], addr) =
      (this :> IInstructionParsable).Parse (ReadOnlySpan bs, addr)

    member this.Parse (span: ByteSpan, addr) =
      let mutable rex = REXPrefix.NOREX
      let prefEndPos = this.ParsePrefix span
      let nextPos = this.ParseREX (span, prefEndPos, &rex)
      phlp.VEXInfo <- None
      phlp.InsAddr <- addr
      phlp.REXPrefix <- rex
      phlp.CurrPos <- nextPos
#if LCACHE
      phlp.MarkPrefixEnd (prefEndPos)
#endif
      oneByteParsers[int (phlp.ReadByte span)].Run (span, phlp) :> IInstruction

    member _.MaxInstructionSize = 15

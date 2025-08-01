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
       OneOp01 ()
       OneOp02 ()
       OneOp03 ()
       OneOp04 ()
       OneOp05 ()
       OneOp06 ()
       OneOp07 ()
       OneOp08 ()
       OneOp09 ()
       OneOp0A ()
       OneOp0B ()
       OneOp0C ()
       OneOp0D ()
       OneOp0E ()
       OneOp0F ()
       OneOp10 ()
       OneOp11 ()
       OneOp12 ()
       OneOp13 ()
       OneOp14 ()
       OneOp15 ()
       OneOp16 ()
       OneOp17 ()
       OneOp18 ()
       OneOp19 ()
       OneOp1A ()
       OneOp1B ()
       OneOp1C ()
       OneOp1D ()
       OneOp1E ()
       OneOp1F ()
       OneOp20 ()
       OneOp21 ()
       OneOp22 ()
       OneOp23 ()
       OneOp24 ()
       OneOp25 ()
       OneOp26 ()
       OneOp27 ()
       OneOp28 ()
       OneOp29 ()
       OneOp2A ()
       OneOp2B ()
       OneOp2C ()
       OneOp2D ()
       OneOp2E ()
       OneOp2F ()
       OneOp30 ()
       OneOp31 ()
       OneOp32 ()
       OneOp33 ()
       OneOp34 ()
       OneOp35 ()
       OneOp36 ()
       OneOp37 ()
       OneOp38 ()
       OneOp39 ()
       OneOp3A ()
       OneOp3B ()
       OneOp3C ()
       OneOp3D ()
       OneOp3E ()
       OneOp3F ()
       OneOp40 ()
       OneOp41 ()
       OneOp42 ()
       OneOp43 ()
       OneOp44 ()
       OneOp45 ()
       OneOp46 ()
       OneOp47 ()
       OneOp48 ()
       OneOp49 ()
       OneOp4A ()
       OneOp4B ()
       OneOp4C ()
       OneOp4D ()
       OneOp4E ()
       OneOp4F ()
       OneOp50 ()
       OneOp51 ()
       OneOp52 ()
       OneOp53 ()
       OneOp54 ()
       OneOp55 ()
       OneOp56 ()
       OneOp57 ()
       OneOp58 ()
       OneOp59 ()
       OneOp5A ()
       OneOp5B ()
       OneOp5C ()
       OneOp5D ()
       OneOp5E ()
       OneOp5F ()
       OneOp60 ()
       OneOp61 ()
       OneOp62 ()
       OneOp63 ()
       OneOp64 ()
       OneOp65 ()
       OneOp66 ()
       OneOp67 ()
       OneOp68 ()
       OneOp69 ()
       OneOp6A ()
       OneOp6B ()
       OneOp6C ()
       OneOp6D ()
       OneOp6E ()
       OneOp6F ()
       OneOp70 ()
       OneOp71 ()
       OneOp72 ()
       OneOp73 ()
       OneOp74 ()
       OneOp75 ()
       OneOp76 ()
       OneOp77 ()
       OneOp78 ()
       OneOp79 ()
       OneOp7A ()
       OneOp7B ()
       OneOp7C ()
       OneOp7D ()
       OneOp7E ()
       OneOp7F ()
       OneOp80 ()
       OneOp81 ()
       OneOp82 ()
       OneOp83 ()
       OneOp84 ()
       OneOp85 ()
       OneOp86 ()
       OneOp87 ()
       OneOp88 ()
       OneOp89 ()
       OneOp8A ()
       OneOp8B ()
       OneOp8C ()
       OneOp8D ()
       OneOp8E ()
       OneOp8F ()
       OneOp90 ()
       OneOp91 ()
       OneOp92 ()
       OneOp93 ()
       OneOp94 ()
       OneOp95 ()
       OneOp96 ()
       OneOp97 ()
       OneOp98 ()
       OneOp99 ()
       OneOp9A ()
       OneOp9B ()
       OneOp9C ()
       OneOp9D ()
       OneOp9E ()
       OneOp9F ()
       OneOpA0 ()
       OneOpA1 ()
       OneOpA2 ()
       OneOpA3 ()
       OneOpA4 ()
       OneOpA5 ()
       OneOpA6 ()
       OneOpA7 ()
       OneOpA8 ()
       OneOpA9 ()
       OneOpAA ()
       OneOpAB ()
       OneOpAC ()
       OneOpAD ()
       OneOpAE ()
       OneOpAF ()
       OneOpB0 ()
       OneOpB1 ()
       OneOpB2 ()
       OneOpB3 ()
       OneOpB4 ()
       OneOpB5 ()
       OneOpB6 ()
       OneOpB7 ()
       OneOpB8 ()
       OneOpB9 ()
       OneOpBA ()
       OneOpBB ()
       OneOpBC ()
       OneOpBD ()
       OneOpBE ()
       OneOpBF ()
       OneOpC0 ()
       OneOpC1 ()
       OneOpC2 ()
       OneOpC3 ()
       OneOpC4 ()
       OneOpC5 ()
       OneOpC6 ()
       OneOpC7 ()
       OneOpC8 ()
       OneOpC9 ()
       OneOpCA ()
       OneOpCB ()
       OneOpCC ()
       OneOpCD ()
       OneOpCE ()
       OneOpCF ()
       OneOpD0 ()
       OneOpD1 ()
       OneOpD2 ()
       OneOpD3 ()
       OneOpD4 ()
       OneOpD5 ()
       OneOpD6 ()
       OneOpD7 ()
       OneOpD8 ()
       OneOpD9 ()
       OneOpDA ()
       OneOpDB ()
       OneOpDC ()
       OneOpDD ()
       OneOpDE ()
       OneOpDF ()
       OneOpE0 ()
       OneOpE1 ()
       OneOpE2 ()
       OneOpE3 ()
       OneOpE4 ()
       OneOpE5 ()
       OneOpE6 ()
       OneOpE7 ()
       OneOpE8 ()
       OneOpE9 ()
       OneOpEA ()
       OneOpEB ()
       OneOpEC ()
       OneOpED ()
       OneOpEE ()
       OneOpEF ()
       OneOpF0 ()
       OneOpF1 ()
       OneOpF2 ()
       OneOpF3 ()
       OneOpF4 ()
       OneOpF5 ()
       OneOpF6 ()
       OneOpF7 ()
       OneOpF8 ()
       OneOpF9 ()
       OneOpFA ()
       OneOpFB ()
       OneOpFC ()
       OneOpFD ()
       OneOpFE ()
       OneOpFF () |]

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
    let mutable pref = Prefix.None
    let mutable b = span[0]
    while ((prefixCheck[(int b >>> 5)] >>> (int b &&& 0b11111)) &&& 1u) > 0u do
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

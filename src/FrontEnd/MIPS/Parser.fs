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

namespace B2R2.FrontEnd.MIPS

open System
open B2R2
open B2R2.FrontEnd.BinLifter

/// <summary>
/// Represents a parser whose encoding a running program can move between.
///
/// MIPS keeps which of its encodings it is reading in a bit of its own, and
/// what moves that bit is the code -- a JALX, or a jump to an address with
/// the low bit set. So a decoder following along has to be told, and the
/// caller doing the telling is not the one that built it.
/// </summary>
type IEncodingSwitchable =
  /// Which encoding this parser is currently reading.
  abstract ISAMode: MIPSISAMode with get, set

/// Represents a parser for MIPS instructions.
and MIPSParser(isa: ISA, reader) =
  let wordSize = isa.WordSize
  let arch = isa.Arch
  let release = isa.MIPSRelease
  let mutable isaMode = isa.MIPSISAMode

  let lifter =
    { new ILiftable with
        member _.Lift(ins, builder) = Lifter.translate ins builder
        member _.Disasm(ins, builder) = Disasm.disasm ins builder; builder }

  /// <summary>
  /// Which encoding this parser reads, which is what the ISA said until
  /// something moves it.
  ///
  /// It is settable because the encoding is not a property of the code but of
  /// the processor reading it: JALX crosses from the 32-bit encoding to the
  /// compressed one and back, and so does a JR or JALR whose target address
  /// carries a one in the bit an instruction address cannot use. Whatever
  /// follows a branch like that is decoded the other way, and nothing in the
  /// word itself says so.
  ///
  /// WHICH compressed encoding is not a choice a running program makes.
  /// MD00076 gives the ISA Mode as one bit, 1 meaning "MIPS16e or microMIPS",
  /// and which of the two it means is a property of the processor -- no
  /// implementation has both. So crossing from the 32-bit encoding returns to
  /// the compressed one this parser started in.
  /// </summary>
  member _.ISAMode with get() = isaMode and set v = isaMode <- v

  interface IEncodingSwitchable with
    member _.ISAMode with get() = isaMode and set v = isaMode <- v

  /// Whether this parser is currently reading microMIPS, which is the one
  /// thing the assembler and the lifter ask of the mode.
  member _.IsMicroMIPS
    with get() = isaMode = MIPSISAMode.MicroMIPS
    and set v =
      isaMode <- if v then MIPSISAMode.MicroMIPS else MIPSISAMode.MIPS

  interface IInstructionParsable with
    member _.MaxInstructionSize = 4

    member _.InstructionAlignment =
      if isaMode = MIPSISAMode.MIPS then 4 else 2

    member this.Parse(bs: byte[], addr) =
      (this :> IInstructionParsable).Parse(ReadOnlySpan bs, addr)

    member _.Parse(span: ByteSpan, addr) =
      try
        match isaMode with
        | MIPSISAMode.MicroMIPS ->
          MicroMIPSParser.parse lifter span reader wordSize release addr
          :> IInstruction
        | MIPSISAMode.MIPS16 ->
          MIPS16Parser.parse lifter span reader wordSize addr
          :> IInstruction
        | _ ->
          ParsingMain.parse lifter span reader arch wordSize release addr
          :> IInstruction
      with e when not (Terminator.isCritical e) ->
        raise ParsingFailureException

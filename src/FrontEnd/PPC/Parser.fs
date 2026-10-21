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

namespace B2R2.FrontEnd.PPC

open System
open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents a parser for PPC instructions. The word size selects the PowerPC
/// variant, which decides both the width of a register and whether the 64-bit
/// forms (ld/std, the rotate-doubleword family, and so on) are recognized; the
/// categories decide how the encodings two categories share are read, and
/// whether the instructions are in Variable Length Encoding at all.
type Parser(wordSize: WordSize, category: Category, reader: IBinReader) =

  let rt = WordSize.toRegType wordSize

  let mutable isVLE = Category.includes Category.VLE category

  let lifter =
    { new ILiftable with
        member _.Lift(ins, builder) = Lifter.translate ins builder
        member _.Disasm(ins, builder) = Disasm.disasm ins builder; builder }

  /// A parser for the server processors' reading of every encoding.
  new(wordSize: WordSize, reader: IBinReader) =
    Parser(wordSize, Category.Server, reader)

  /// A parser for the word size and categories a PowerPC ISA names.
  new(isa: ISA, reader: IBinReader) =
    Parser(isa.WordSize, Category.ofISA isa, reader)

  /// <summary>
  /// Whether this parser reads Variable Length Encoding (VLE), which is what
  /// the categories said until something moves it.
  ///
  /// It is settable because the encoding is a property of the page the code
  /// is in, which the instructions themselves cannot tell a decoder: the
  /// storage attribute that selects VLE is set by the memory management
  /// unit, so a caller that knows where the attribute changes tells the
  /// parser there.
  /// </summary>
  member _.IsVLE with get() = isVLE and set v = isVLE <- v

  interface IInstructionParsable with
    member _.MaxInstructionSize = 4

    member _.InstructionAlignment = if isVLE then 2 else 4

    member this.Parse(bs: byte[], addr) =
      (this :> IInstructionParsable).Parse(ReadOnlySpan bs, addr)

    member _.Parse(span: ByteSpan, addr) =
      try
        if isVLE then
          ParsingVLE.parse lifter category span reader addr rt :> IInstruction
        else
          ParsingMain.parse lifter category span reader addr rt :> IInstruction
      with e when not (Terminator.isCritical e) ->
        raise ParsingFailureException

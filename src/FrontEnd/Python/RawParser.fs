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

namespace B2R2.FrontEnd.Python

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Python
open B2R2.FrontEnd.BinLifter

/// <summary>
/// Parses Python bytecode handed over as bare bytes.
///
/// Every other architecture's parser reads bytes and needs nothing else, so
/// anything holding bytes can ask what they mean. Python's cannot: an
/// argument indexes a table the code object carries, and a name has to be
/// read from somewhere. That left the tools that work in bytes -- the
/// assembler above all, which has to show what it just wrote -- with no way
/// to disassemble Python at all.
///
/// So the bytes get a file built around them. Each Parse wraps what it was
/// given in the smallest `.pyc` that can hold it and reads the instruction
/// back out of that, which costs a marshal per call and is what makes it a
/// parser for tools rather than for a corpus.
/// </summary>
type PythonRawParser(isa: ISA, reader: IBinReader) =
  let version = LanguagePrimitives.EnumOfValue<int, PythonVersion> isa.Flags

  let magic =
    try Builder.magicOf version with _ -> raise InvalidISAException

  let parse (bs: byte[]) =
    let pyc = Builder.build version magic (Builder.codeOf bs)
    let file = PythonBinFile("", pyc, None)
    let parser = PythonParser(file, reader) :> IInstructionParsable
    (* Each call builds a file of its own, so the bytes always begin where
       that file put them. The caller's address names a place in its own
       stream, which this file knows nothing about, and B2R2 addresses a
       Python instruction by where it sits in its file -- so the instruction
       is labelled with that and the caller keeps its own reckoning. *)
    let start =
      match file.CodeObj with
      | PyCode co -> fst co.Code
      | _ -> 0UL
    let span = System.ReadOnlySpan(pyc, int start, bs.Length)
    parser.Parse(span, start)

  interface IInstructionParsable with
    member _.MaxInstructionSize = 8

    member _.InstructionAlignment = 1

    member _.Parse(bs: byte[], _addr: Addr) = parse bs

    member _.Parse(span: ByteSpan, _addr: Addr) = parse (span.ToArray())

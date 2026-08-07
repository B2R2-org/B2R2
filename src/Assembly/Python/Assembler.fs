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

namespace B2R2.Assembly.Python

open B2R2
open B2R2.Assembly.BinLowerer

/// <summary>
/// Represents an assembler for Python bytecode. The syntax it reads is the one
/// B2R2's Python disassembler writes, so a line of disassembly can be handed
/// straight back to it: a mnemonic, and the argument beside it when the
/// instruction takes one.
///
/// Python is the one architecture here whose ISA names a version, and it has
/// to: the same byte is a different instruction on either side of a release,
/// and how wide an instruction is changed at 3.6 and again at 3.11. So the
/// version travels in the ISA's flags and picks the table below, which is the
/// very enum that version's parser decodes with.
///
/// What a line does not carry is what an argument indexes. `load_const 0` says
/// the first constant of a code object; which constant that is belongs to the
/// code object and not to the line, so the note the disassembler prints beside
/// an argument is read and dropped rather than assembled from.
/// </summary>
type Assembler(isa: ISA, _baseAddr: Addr) =

  let spec = Tables.specOf (enum<PythonVersion> isa.Flags)

  interface ILowerable with
    override _.Lower assembly =
      match Encoder.encodeAll spec assembly with
      | Ok instrs -> instrs |> List.map (fun bytes -> isa, bytes) |> Result.Ok
      | Error e -> Result.Error e

// vim: set tw=80 sts=2 sw=2:

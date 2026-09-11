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

namespace B2R2.Assembly.CIL

open B2R2
open B2R2.Assembly.BinLowerer

/// <summary>
/// Represents an assembler for CIL. The syntax it reads is the one B2R2's CIL
/// disassembler writes, so a line of disassembly can be handed straight back
/// to it: a mnemonic, and the one operand the instruction takes beside it,
/// with a branch written by the address it reaches.
///
/// That last is why the assembler has to be told where it is assembling. A
/// branch is encoded as a distance from the instruction after it, so what a
/// line encodes to depends on where the lines above it landed, and the lines
/// are placed one behind another from the address the assembler was built
/// with.
/// </summary>
type Assembler(isa: ISA, baseAddr: Addr) =

  interface ILowerable with
    override _.Lower assembly =
      match Encoder.encodeAll baseAddr assembly with
      | Ok instrs -> instrs |> List.map (fun bytes -> isa, bytes) |> Result.Ok
      | Error e -> Result.Error e

// vim: set tw=80 sts=2 sw=2:

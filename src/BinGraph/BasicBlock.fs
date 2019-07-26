(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.BinGraph

open B2R2

/// The basic term used to describe a line of a basic block (when visualized).
type Term =
  /// Mneomonic, i.e., opcode.
  | Mnemonic of string
  /// Operand.
  | Operand of string
  /// Just a string.
  | String of string
  /// Comment.
  | Comment of string

/// A visual line of a basic block.
type VisualLine = Term list

/// A visual representation of a basic block.
type VisualBlock = VisualLine list

/// The base type for basic block.
[<AbstractClass>]
type BasicBlock () =
  inherit VertexData(VertexData.genID ())
  /// The start position (ProgramPoint) of the basic block.
  abstract Position: ProgramPoint with get
  /// The instruction address range of the basic block.
  abstract Range: AddrRange with get
  /// Convert this basic block to a visual representation.
  abstract ToVisualBlock: unit -> VisualBlock

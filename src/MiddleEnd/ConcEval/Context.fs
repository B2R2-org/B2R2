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

namespace B2R2.MiddleEnd.ConcEval

open B2R2

type Context () =
  /// The current index of the statement to evaluate within the scope of a
  /// machine instruction. This index behaves like a PC for statements of an
  /// instruction.
  member val StmtIdx = 0 with get, set

  /// The current program counter.
  member val PC: Addr = 0UL with get, set

  /// Store named register values.
  member val Registers = Variables<RegisterID>() with get

  /// Store temporary variable values.
  member val Temporaries = Variables<int>() with get

  /// Store labels and their corresponding statement indices.
  member val Labels = Labels () with get

  /// Architecture mode.
  member val Mode = ArchOperationMode.NoMode with get, set

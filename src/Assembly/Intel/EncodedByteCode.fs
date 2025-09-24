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

namespace B2R2.Assembly.Intel

open B2R2
open B2R2.FrontEnd.Intel

/// <summary>
/// Represents encoded bytecode for an Intel instruction.
/// </summary>
type internal EncodedByteCode =
  { Prefix: AsmComponent[]
    REXPrefix: AsmComponent[]
    Opcode: AsmComponent[]
    ModRM: AsmComponent[]
    SIB: AsmComponent[]
    Displacement: AsmComponent[]
    Immediate: AsmComponent[] }

/// Represents basic components for assembling binaries.
and internal AsmComponent =
  /// Normal byte, which is not associated with a label.
  | Normal of byte
  /// This component refers to a label, which we didn't yet concretize. This
  /// will eventually become a concrete number of RegType size.
  | IncompLabel of RegType
  /// Assembled instruction, whose byte values are not yet decided. IncompleteOp
  /// will be transformed into two components: (CompOp, IncompLabel).
  | IncompleteOp of Opcode * Operands
  /// This component refers to an opcode that is now decided (completed) with a
  /// concrete value. It is just that we don't concretize the corresponding
  /// label, i.e., IncompLabel.
  | CompOp of Opcode * Operands * byte[] * byte[] option

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
/// Represents one assembled instruction. An instruction that refers to a label
/// cannot be finished on the first pass, because the distance to that label
/// depends on how long every instruction in between turns out to be.
/// </summary>
type internal Encoded =
  /// Every byte is known.
  | Resolved of byte[]
  /// A branch to a label. Not even the opcode bytes are known yet: a short
  /// branch and a near branch use different opcodes, and which one applies
  /// depends on the distance.
  | PendingBranch of Opcode * label: string
  /// Every byte is known except the displacement standing for the label.
  | PendingFixup of Fixup

/// Represents the one displacement in an instruction that is still unknown,
/// along with the bytes surrounding it. The encoder records which label is
/// meant and how the displacement is measured, so that resolving it later
/// needs no second look at the operands.
and internal Fixup =
  { /// Bytes preceding the displacement.
    Head: byte[]
    /// Width of the displacement itself.
    Width: RegType
    /// Bytes following it, which is an immediate when there is one.
    Tail: byte[]
    /// Label whose position the displacement stands for.
    Label: string
    /// Whether the displacement counts from the end of this instruction. A
    /// branch always measures that way; a data reference measures from the
    /// start of the program, except in 64-bit mode where it is RIP-relative.
    IsBranch: bool }

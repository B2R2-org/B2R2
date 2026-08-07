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

/// <namespacedoc>
///   <summary>
///   Contains Python-specific assembly components and types.
///   </summary>
/// </namespacedoc>
/// <summary>
/// Everything about encoding that belongs to one Python version rather than to
/// Python. Each version's own directory fills one of these in from the enum
/// its parser decodes with, so the assembler and the decoder cannot come to
/// disagree about which byte an instruction is: there is only the one table.
/// </summary>
type VersionSpec =
  { /// The opcode number a mnemonic names, or None when this version has no
    /// such instruction. Case does not matter -- the disassembler writes the
    /// enum case name in lower case, and that is what gets handed back.
    Lookup: string -> int option
    /// Whether the opcode takes an argument at all.
    HasOperand: int -> bool
    /// Inline cache entries following the opcode, each two bytes wide. Zero
    /// before 3.11, which had none.
    CacheCount: int -> int
    /// Whether an argument costs one byte or two. 3.6 replaced the older
    /// encoding, where an instruction with an argument was three bytes, with
    /// wordcode, where every instruction is two.
    IsWordcode: bool
    /// EXTENDED_ARG's own number, which an argument too wide for the
    /// instruction has to be prefixed with.
    ExtendedArg: int }

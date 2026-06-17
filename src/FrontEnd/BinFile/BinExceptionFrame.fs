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

namespace B2R2.FrontEnd.BinFile

open B2R2

/// Represents format-agnostic exception/unwinding information for one function
/// frame, such as a DWARF FDE in ELF/Mach-O or a RUNTIME_FUNCTION in PE x64.
type BinExceptionFrame =
  { /// Start address of the function (inclusive).
    FunctionStart: Addr
    /// End address of the function (inclusive).
    FunctionEnd: Addr
    /// Address of the personality/handler routine that governs this frame, if
    /// any (e.g., an ELF CIE personality or a PE UNWIND_INFO handler). None
    /// when the format records no such routine.
    PersonalityRoutine: Addr option
    /// Guarded regions within this frame, with their handlers resolved.
    Handlers: BinExceptionHandler[] }

/// Represents a guarded code region and the handler it transfers control to on
/// an exception, such as a DWARF call-site/landing-pad pair (ELF/Mach-O) or a
/// PE C++ scope-table entry.
and BinExceptionHandler =
  { /// Start address of the guarded code block.
    BlockStart: Addr
    /// End address (inclusive) of the guarded code block.
    BlockEnd: Addr
    /// Address of the handler that the block transfers to on an exception.
    /// None when the block has no handler in this frame (e.g., a cleanup-only
    /// region or one that propagates the exception up).
    Handler: Addr option }

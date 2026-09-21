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

namespace B2R2.FrontEnd.BinFile.Mach

open B2R2

/// Represents a per-function exception frame descriptor, independent of whether
/// it came from DWARF CFI (`__eh_frame`) or compact unwind (`__unwind_info`).
type internal FrameInfo =
  { /// Start address of the function (inclusive).
    FuncStart: Addr
    /// End address of the function (exclusive).
    FuncEnd: Addr
    /// Address of the LSDA governing this frame, if any.
    LSDAPointer: Addr option
    /// Address at which this frame's personality routine is recorded: the 'P'
    /// augmentation of its DWARF CIE, or the `__unwind_info` personality array
    /// entry its compact encoding indexes. Either way this normally gives the
    /// slot holding the routine rather than the routine itself. None when the
    /// frame names no personality.
    PersonalityRoutine: Addr option }

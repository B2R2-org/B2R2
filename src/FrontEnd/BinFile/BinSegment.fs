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

/// Represents a format-agnostic, memory-mapped segment of a binary, i.e., a
/// consecutive region that is mapped into the virtual memory when the binary
/// is loaded.
type BinSegment =
  { /// Segment name, if the format names its segments. ELF program headers
    /// (segments) are unnamed, so this is None for ELF; Mach-O segments carry
    /// a name (e.g., "__TEXT", "__DATA"), and PE has no real segments so a
    /// synthesized segment borrows its backing section name.
    Name: string option
    /// Virtual address at which the segment is mapped.
    Address: Addr
    /// Size of the segment in the virtual memory.
    Size: uint64
    /// File offset of the segment's contents.
    Offset: uint64
    /// Size of the segment's contents in the file. This can be smaller than
    /// Size when the segment has memory-only contents (e.g., .bss).
    FileSize: uint64
    /// Access permission of the mapped segment.
    Permission: Permission }

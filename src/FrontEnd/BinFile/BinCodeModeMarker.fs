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

/// Represents a marker indicating the instruction-set encoding (or data) that
/// takes effect at a given address, for architectures that interleave
/// encodings within a section (notably ARM and Thumb, marked by the ELF
/// $a/$t/$d mapping symbols).
type BinCodeModeMarker =
  { /// Address at which the marked region begins.
    Address: Addr
    /// Encoding mode effective from this address onward.
    Mode: BinCodeMode }

/// Represents an instruction-set encoding mode, or a data region embedded in
/// code.
and BinCodeMode =
  /// ARM (A32) instruction encoding.
  | ArmMode
  /// Thumb (T32) instruction encoding.
  | ThumbMode
  /// A data region embedded in code (not to be disassembled).
  | DataMode

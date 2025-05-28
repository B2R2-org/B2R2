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

/// Represents the usage of the Mach-O file.
type FileType =
  /// Intermediate object files.
  | MH_OBJECT = 0x1
  /// Standard executable programs.
  | MH_EXECUTE = 0x2
  /// Fixed VM shared library file.
  | MH_FVMLIB = 0x3
  /// Core file.
  | MH_CORE = 0x4
  /// Preloaded executable file.
  | MH_PRELOAD = 0x5
  /// Dynamically bound shared library file.
  | MH_DYLIB = 0x6
  /// Dynamically bound shared library file.
  | MH_DYLINKER = 0x7
  /// Dynamically bound bundle file.
  | MH_BUNDLE = 0x8
  /// Shared library stub for static linking only, no section contents.
  | MH_DYLIB_STUB = 0x9
  /// Companion file with only debug sections.
  | MH_DSYM = 0xa
  /// x86_64 kexts.
  | MH_KEXT_BUNDLE = 0xb

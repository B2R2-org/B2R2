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

/// Represents the high-level kind of a binary file, i.e., what the file is
/// meant to be (a runnable program, a shared library, etc.), independent of the
/// underlying file format.
type BinFileKind =
  /// A runnable program, covering both fixed-base and position-independent
  /// (PIE) executables.
  | Executable
  /// A shared library, such as an ELF shared object (.so), a Mach-O dynamic
  /// library (.dylib), or a PE DLL.
  | SharedLibrary
  /// A relocatable object file, such as an ELF or COFF object (.o).
  | Object
  /// A core dump.
  | Core
  /// The kind is unknown or not applicable, e.g., a raw byte blob or a bytecode
  /// container.
  | Unknown

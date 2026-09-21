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

/// <summary>
/// Represents an interface for accessing binary file metadata, such as its
/// path, and file format.
/// </summary>
type IBinMetadata =
  /// The file path where this file is located.
  abstract Path: string

  /// The format of this file: ELF, PE, Mach-O, or etc.
  abstract Format: FileFormat

  /// The high-level kind of this file: an executable, a shared library, an
  /// object file, etc.
  abstract Kind: BinFileKind

  /// The ISA that this file expects to run on.
  abstract ISA: ISA

  /// <summary>
  /// The OS that this file is built to run on. ELF names it in the OS/ABI byte
  /// of its identification, Mach-O in the platform of its
  /// <c>LC_BUILD_VERSION</c> (or of the <c>LC_VERSION_MIN_*</c> command that
  /// preceded it), and PE by being a PE at all. An image that names no system
  /// at all, as firmware and an embedded ELF do, answers <see
  /// cref='F:B2R2.OS.BareMetal'/>, which is something the file says rather
  /// than something that could not be read. <see
  /// cref='F:B2R2.OS.UnknownOS'/> is the latter: a format that names no OS
  /// (e.g., Wasm, Python) and a raw image, which carries nothing to read.
  /// </summary>
  abstract OS: OS

  /// The entry point of this binary (the start address that this binary runs
  /// at). Note that some binaries (e.g., PE DLL files) do not have a specific
  /// entry point, and EntryPoint will return None in such a case.
  abstract EntryPoint: Addr option

  /// The base address of the associated binary at which it is preferred to be
  /// loaded in memory.
  abstract BaseAddress: Addr

  /// The path to the dynamic loader/interpreter requested by this binary, if
  /// any. ELF exposes it via the PT_INTERP program header and Mach-O via the
  /// LC_LOAD_DYLINKER load command; formats that record no loader path (e.g.,
  /// PE) return None.
  abstract InterpreterPath: string option

  /// <summary>
  /// The legacy runtime library search paths of this binary, taken from the
  /// ELF <c>DT_RPATH</c> dynamic entry (deprecated in favor of <see
  /// cref="RunPath"/>). Returns an empty array for formats that have no such
  /// notion (e.g., PE, Mach-O).
  /// </summary>
  abstract RPath: string[]

  /// <summary>
  /// The runtime library search paths of this binary, taken from the ELF
  /// <c>DT_RUNPATH</c> dynamic entry and the Mach-O <c>LC_RPATH</c> load
  /// commands. Returns an empty array for formats that have no such notion
  /// (e.g., PE).
  /// </summary>
  abstract RunPath: string[]

  /// <summary>
  /// The names of the libraries this binary needs loaded alongside it, taken
  /// from the ELF <c>DT_NEEDED</c> dynamic entries, the Mach-O
  /// <c>LC_LOAD_DYLIB</c> load commands, the PE import directory, and the
  /// module names of Wasm imports. A Mach-O object file carries no
  /// <c>LC_LOAD_DYLIB</c>, so its <c>LC_LINKER_OPTION</c> commands are read
  /// instead, which name a library the way the linker flag does (<c>foo</c>
  /// for <c>-lfoo</c>, <c>Bar</c> for <c>-framework Bar</c>) rather than by
  /// an install path. Returns an empty array for a binary that needs none
  /// and for formats that have no such notion.
  /// </summary>
  abstract DependencyNames: string[]

  /// <summary>
  /// The name this binary announces for itself to whatever links against it,
  /// taken from the ELF <c>DT_SONAME</c> dynamic entry, the Mach-O
  /// <c>LC_ID_DYLIB</c> load command, and the name in the PE export
  /// directory. None for a binary that announces none.
  /// </summary>
  abstract SharedObjectName: string option

  /// <summary>
  /// The build ID that names this particular build of the binary, taken from
  /// the ELF <c>NT_GNU_BUILD_ID</c> note, the Mach-O <c>LC_UUID</c> load
  /// command, and the GUID that the CodeView entry of the PE debug directory
  /// carries. Returns an empty array for a binary that carries none and for
  /// formats that have no such notion (e.g., Wasm).
  /// </summary>
  abstract BuildId: byte[]

  /// Program header table information for SysV-style process initialization.
  /// ELF exposes this through its program header table; formats without an
  /// equivalent runtime contract (e.g., PE, Mach-O, Wasm) return None.
  abstract ProgramHeaderTable: BinProgramHeaderTable option

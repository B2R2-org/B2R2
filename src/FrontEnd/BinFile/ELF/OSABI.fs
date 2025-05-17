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

namespace B2R2.FrontEnd.BinFile.ELF

/// Represents the operating system or ABI used by the ELF file.
type OSABI =
  /// UNIX System V ABI.
  | ELFOSABI_SYSV = 0uy
  /// HP-UX ABI.
  | ELFOSABI_HPUX = 1uy
  /// NetBSD ABI.
  | ELFOSABI_NETBSD = 2uy
  /// Linux ABI.
  | ELFOSABI_GNU = 3uy
  /// Linux ABI.
  | ELFOSABI_LINUX = 3uy
  /// Solaris ABI.
  | ELFOSABI_SOLARIS = 6uy
  /// IBM AIX ABI.
  | ELFOSABI_AIX = 7uy
  /// SGI Irix ABI.
  | ELFOSABI_IRIX = 8uy
  /// FreeBSD ABI.
  | ELFOSABI_FREEBSD = 9uy
  /// Compaq TRU64 UNIX ABI.
  | ELFOSABI_TRU64 = 10uy
  /// Novell Modesto ABI.
  | ELFOSABI_MODESTO = 11uy
  /// OpenBSD ABI.
  | ELFOSABI_OPENBSD = 12uy
  /// ARM EABI.
  | ELFOSABI_ARM_AEABI = 64uy
  /// ARM.
  | ELFOSABI_ARM = 97uy
  /// Standalone (embedded) application.
  | ELFOSABI_STANDALONE = 255uy

/// <summary>
/// Provides helper functions for <see
/// cref='T:B2R2.FrontEnd.BinFile.ELF.OSABI'/>
/// </summary>
[<RequireQualifiedAccess>]
module OSABI =
  /// <summary>
  /// Converts the OSABI to a string representation.
  /// </summary>
  [<CompiledName "ToString">]
  let toString = function
    | OSABI.ELFOSABI_SYSV -> "UNIX System V"
    | OSABI.ELFOSABI_HPUX -> "HP-UX"
    | OSABI.ELFOSABI_NETBSD -> "NetBSD"
    | OSABI.ELFOSABI_GNU | OSABI.ELFOSABI_LINUX -> "Linux"
    | OSABI.ELFOSABI_SOLARIS -> "Solaris"
    | OSABI.ELFOSABI_AIX -> "AIX"
    | OSABI.ELFOSABI_IRIX -> "IRIX"
    | OSABI.ELFOSABI_FREEBSD -> "FreeBSD"
    | OSABI.ELFOSABI_TRU64 -> "TRU64"
    | OSABI.ELFOSABI_MODESTO -> "Modesto"
    | OSABI.ELFOSABI_OPENBSD -> "OpenBSD"
    | OSABI.ELFOSABI_ARM_AEABI -> "ARM EABI"
    | OSABI.ELFOSABI_ARM -> "ARM"
    | OSABI.ELFOSABI_STANDALONE -> "Standalone"
    | _ -> "Unknown"

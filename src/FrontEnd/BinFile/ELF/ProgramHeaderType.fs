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

/// Represents what kind of segment this array element describes or how to
/// interpret the array element's information.
type ProgramHeaderType =
  /// This program header is not used.
  | PT_NULL = 0x00u
  /// This is a loadable segment.
  | PT_LOAD = 0x01u
  /// This segment contains dynamic linking information.
  | PT_DYNAMIC = 0x02u
  /// This segment contains the location and size of a null-terminated path name
  /// to invoke an interpreter. This segment type is meaningful only for
  /// executable files, but not for shared objects. This segment may not occur
  /// more than once in a file. If it is present, it must precede any loadable
  /// segment entry.
  | PT_INTERP = 0x03u
  /// This segment contains the location and size of auxiliary information.
  | PT_NOTE = 0x04u
  /// This segment type is reserved but has unspecified semantics.
  | PT_SHLIB = 0x05u
  /// This segment specifies the location and size of the program header table
  /// itself, It may occur only if the program header table is part of the
  /// memory image of the program. If it is present, it must precede any
  /// loadable segment entry.
  | PT_PHDR = 0x06u
  /// This segment contains the Thread-Local Storage template.
  | PT_TLS = 0x07u
  /// The lower bound of OS-specific program header type.
  | PT_LOOS = 0x60000000u
  /// The upper bound of OS-specific program header type.
  | PT_HIOS = 0x6fffffffu
  /// This segment specifies the location and size of the exception handling
  /// information as defined by the .eh_frame_hdr section.
  | PT_GNU_EH_FRAME = 0x6474e550u
  /// This segment specifies the permissions on the segment containing the stack
  /// and is used to indicate weather the stack should be executable. The
  /// absence of this header indicates that the stack will be executable.
  | PT_GNU_STACK = 0x6474e551u
  /// This segment specifies the location and size of a segment which may be
  /// made read-only after relocations have been processed.
  | PT_GNU_RELRO = 0x6474e552u
  /// This segment contains PAX flags.
  | PT_PAX_FLAGS = 0x65041580u
  /// The lower bound of processor-specific program header type.
  | PT_LOPROC = 0x70000000u
  /// The exception unwind table.
  | PT_ARM_EXIDX = 0x70000001u
  /// MIPS ABI flags.
  | PT_MIPS_ABIFLAGS = 0x70000003u
  /// The upper bound of processor-specific program header type.
  | PT_HIPROC = 0x7fffffffu

/// Provides functions to convert program header type to a string
[<RequireQualifiedAccess>]
module ProgramHeaderType =
  open B2R2

  /// Converts the program header type to a string.
  [<CompiledName "ToString">]
  let toString = function
    | ProgramHeaderType.PT_NULL -> "NULL"
    | ProgramHeaderType.PT_LOAD -> "LOAD"
    | ProgramHeaderType.PT_DYNAMIC -> "DYNAMIC"
    | ProgramHeaderType.PT_INTERP -> "INTERP"
    | ProgramHeaderType.PT_NOTE -> "NOTE"
    | ProgramHeaderType.PT_SHLIB -> "SHLIB"
    | ProgramHeaderType.PT_PHDR -> "PHDR"
    | ProgramHeaderType.PT_TLS -> "TLS"
    | ProgramHeaderType.PT_GNU_EH_FRAME -> "GNU_EH_FRAME"
    | ProgramHeaderType.PT_GNU_STACK -> "GNU_STACK"
    | ProgramHeaderType.PT_GNU_RELRO -> "GNU_RELRO"
    | ProgramHeaderType.PT_PAX_FLAGS -> "PAX_FLAGS"
    | ProgramHeaderType.PT_ARM_EXIDX -> "ARM_EXIDX"
    | ProgramHeaderType.PT_MIPS_ABIFLAGS -> "MIPS_ABIFLAGS"
    | _ -> Terminator.futureFeature ()

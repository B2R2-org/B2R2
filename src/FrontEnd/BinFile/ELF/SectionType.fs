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

/// Represents the ELF section header type.
type SectionType =
  /// This section is inactive.
  | SHT_NULL = 0x00u
  /// This section holds information defined by the program, whose format and
  /// meaning are determined solely by the program.
  | SHT_PROGBITS = 0x01u
  /// This section holds a symbol table.
  | SHT_SYMTAB = 0x02u
  /// This section holds a string table.
  | SHT_STRTAB = 0x03u
  /// This section holds relocation entries with explicit addends.
  | SHT_RELA = 0x04u
  /// This section holds a symbol hash table. All ELF files participating in
  /// dynamic linking must contain a symbol hash table.
  | SHT_HASH = 0x05u
  /// This section holds information for dynamic linking.
  | SHT_DYNAMIC = 0x06u
  /// This section holds a note.
  | SHT_NOTE = 0x07u
  /// This section occupies no space, although SecOffset contains a conceptual
  /// offset to it.
  | SHT_NOBITS = 0x08u
  /// This section holds relocation entries without explicit addends.
  | SHT_REL = 0x09u
  /// This section is reserved (unknown purpose).
  | SHT_SHLIB = 0x0au
  /// This section contains a minimal set of dynamic linking symbols.
  | SHT_DYNSYM = 0x0bu
  /// This section contains initialization function pointers.
  | SHT_INIT_ARRAY = 0x0eu
  /// This section contains termination function pointers.
  | SHT_FINI_ARRAY = 0x0fu
  /// This section contains pre-initialization function pointers.
  | SHT_PREINIT_ARRAY = 0x10u
  /// This section holds section group information.
  | SHT_GROUP = 0x11u
  /// This section holds section indexes.
  | SHT_SYMTAB_SHNDX = 0x12u
  (* The start of processor-specific section type = 0x70000000u *)
  /// ARM unwind section.
  | SHT_ARM_EXIDX = 0x70000001u
  /// Preemption details.
  | SHT_ARM_PREEMPTMAP = 0x70000002u
  /// ARM attributes section.
  | SHT_ARM_ATTRIBUTES = 0x70000003u
  /// Section holds overlay debug info.
  | SHT_ARM_DEBUGOVERLAY = 0x70000004u
  /// Section holds GDB and overlay integration info.
  | SHT_ARM_OVERLAYSECTION = 0x70000005u
  /// Register usage information.
  | SHT_MIPS_REGINFO = 0x70000006u
  /// Miscellaneous options.
  | SHT_MIPS_OPTIONS = 0x7000000du
  /// ABI related flags section.
  | SHT_MIPS_ABIFLAGS = 0x7000002au
  (* The end of processor-specific section type = 0x7fffffffu *)
  (* The lower bound of program-specific section type = 0x80000000u *)
  (* The upper bound of program-specific section type = 0xffffffffu *)
  /// Object attributes.
  | SHT_GNU_ATTRIBUTES = 0x6ffffff5u
  /// GNU-style hash table.
  | SHT_GNU_HASH = 0x6ffffff6u
  /// Prelink library list.
  | SHT_GNU_LIBLIST = 0x6ffffff7u
  /// This section holds Linux-specific version information (Elfxx_VerDef). This
  /// stores version information of functions defined in the binary.
  | SHT_GNU_verdef = 0x6ffffffdu
  /// This section holds Linux-specific version information (Elfxx_VerNeed).
  /// This stores version information of external functions, which is needed by
  /// the caller binary.
  | SHT_GNU_verneed = 0x6ffffffeu
  /// This section holds Linux-specific version information. It specifically
  /// contains an array of elements of type Elfxx_Half. It has as many entries
  /// as the dynamic symbol table.
  | SHT_GNU_versym = 0x6fffffffu

/// Provides functions to convert section types to string representations.
[<RequireQualifiedAccess>]
module SectionType =
  open B2R2

  /// Returns the string representation of the section type.
  [<CompiledName "ToString">]
  let toString = function
    | SectionType.SHT_NULL -> "NULL"
    | SectionType.SHT_PROGBITS -> "PROGBITS"
    | SectionType.SHT_SYMTAB -> "SYMTAB"
    | SectionType.SHT_STRTAB -> "STRTAB"
    | SectionType.SHT_RELA -> "RELA"
    | SectionType.SHT_HASH -> "HASH"
    | SectionType.SHT_DYNAMIC -> "DYNAMIC"
    | SectionType.SHT_NOTE -> "NOTE"
    | SectionType.SHT_NOBITS -> "NOBITS"
    | SectionType.SHT_REL -> "REL"
    | SectionType.SHT_SHLIB -> "SHLIB"
    | SectionType.SHT_DYNSYM -> "DYNSYM"
    | SectionType.SHT_INIT_ARRAY -> "INIT_ARRAY"
    | SectionType.SHT_FINI_ARRAY -> "FINI_ARRAY"
    | SectionType.SHT_PREINIT_ARRAY -> "PREINIT_ARRAY"
    | SectionType.SHT_GROUP -> "GROUP"
    | SectionType.SHT_SYMTAB_SHNDX -> "SYMTAB_SHNDX"
    | SectionType.SHT_ARM_EXIDX -> "ARM_EXIDX"
    | SectionType.SHT_ARM_PREEMPTMAP -> "ARM_PREEMPTMAP"
    | SectionType.SHT_ARM_ATTRIBUTES -> "ARM_ATTRIBUTES"
    | SectionType.SHT_ARM_DEBUGOVERLAY -> "ARM_DEBUGOVERLAY"
    | SectionType.SHT_ARM_OVERLAYSECTION -> "ARM_OVERLAYSECTION"
    | SectionType.SHT_MIPS_REGINFO -> "MIPS_REGINFO"
    | SectionType.SHT_MIPS_OPTIONS -> "MIPS_OPTIONS"
    | SectionType.SHT_MIPS_ABIFLAGS -> "MIPS_ABIFLAGS"
    | SectionType.SHT_GNU_ATTRIBUTES -> "GNU_ATTRIBUTES"
    | SectionType.SHT_GNU_HASH -> "GNU_HASH"
    | SectionType.SHT_GNU_LIBLIST -> "GNU_LIBLIST"
    | SectionType.SHT_GNU_verdef -> "GNU_verdef"
    | SectionType.SHT_GNU_verneed -> "GNU_verneed"
    | SectionType.SHT_GNU_versym -> "GNU_versym"
    | _ -> Terminator.futureFeature ()

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

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.FileHelper

/// This member categorizes the section's contents and semantics.
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
  /// This section marks the start of processor-specific section type.
  | SHT_LOPROC = 0x70000000u
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
  /// This section marks the end of processor-specific section type.
  | SHT_HIPROC = 0x7fffffffu
  /// This section specifies the lower bound of program-specific section type.
  | SHT_LOUSER = 0x80000000u
  /// This section specifies the upper bound of program-specific section type.
  | SHT_HIUSER = 0xffffffffu
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

/// Every symbol table entry is defined in relation to some section.
/// This member holds the relevant section header table index.
type SectionHeaderIdx =
  /// This is the start of the reserved range.
  | SHN_LORESERVE
  /// The symbol is undefined. Linker should update references to this symbol
  /// with the actual definition from another file.
  | SHN_UNDEF
  /// The lower bound of processor-specific section index value.
  | SHN_LOPROC
  /// The upper bound of processor-specific section index value.
  | SHN_HIPROC
  /// The lower bound of OS-specific section index value.
  | SHN_LOOS
  /// The upper bound of OS-specific section index value.
  | SHN_HIOS
  /// The symbol has an absolute value that will not change because of
  /// relocation.
  | SHN_ABS
  /// The symbol labels a common block that has not yet been allocated.
  | SHN_COMMON
  /// An escape value indicating that the actual section header index is too
  /// large to fit in the containing field. The header section index is found in
  /// another location specific to the structure where it appears.
  | SHN_XINDEX
  /// The upper boundary of the range of the reserved range.
  | SHN_HIRESERVE
  /// This symbol index holds an index into the section header table.
  | SectionIndex of int
with
  static member IndexFromInt n =
    match n with
    | 0x00 -> SHN_UNDEF
    | 0xff00 -> SHN_LORESERVE
    | 0xfff1 -> SHN_ABS
    | 0xfff2 -> SHN_COMMON
    | n -> SectionIndex n

/// Sections support 1-bit flags that describe miscellaneous attributes.
[<FlagsAttribute>]
type SectionFlag =
  /// This section contains data that should be writable during process
  /// execution.
  | SHF_WRITE = 0x1UL
  /// This section occupies memory during process execution.
  | SHF_ALLOC = 0x2UL
  /// This section contains executable machine code.
  | SHF_EXECINSTR = 0x4UL
  /// This section may be merged.
  | SHF_MERGE = 0x10UL
  /// This section contains null-terminated strings.
  | SHF_STRINGS = 0x20UL
  /// This section holds section indexes.
  | SHF_INFO_LINK = 0x40UL
  /// This section adds special ordering requirements to the link editor.
  | SHF_LINK_ORDER = 0x80UL
  /// This section requires special OS-specific processing beyond the standard
  /// linking rules to avoid incorrect behavior
  | SHF_OS_NONCONFORMING = 0x100UL
  /// This section is a member, perhaps the only one, of a section group.
  | SHF_GROUP = 0x200UL
  /// This section contains TLS data.
  | SHF_TLS = 0x400UL
  /// This section contains compressed data.
  | SHF_COMPRESSED = 0x800UL
  /// All bits included in this mask are reserved for operating system-specific
  /// semantics.
  | SHF_MASKOS = 0x0ff00000UL
  /// All bits included in this mask are reserved for processor-specific
  /// semantics.
  | SHF_MASKPROC = 0xf0000000UL
  /// This section requires ordering in relation to other sections of the same
  /// type.
  | SHF_ORDERED = 0x40000000UL
  /// This section is excluded from input to the link-edit of an executable or
  /// shared object
  | SHF_EXCLUDE = 0x80000000UL
  /// This section can hold more than 2GB.
  | SHF_X86_64_LARGE = 0x10000000UL

/// ELF Section
type ELFSection = {
  /// Unique section number.
  SecNum: int
  /// The name of the section.
  SecName: string
  /// Categorizes the section's contents and semantics.
  SecType: SectionType
  /// Misc. attributes about the section.
  SecFlags: SectionFlag
  /// The address at which the section's first byte should reside. If this
  /// section will not appear in the process memory, this value is 0.
  SecAddr: Addr
  /// Byte offset from the beginning of the file to the first byte in the
  /// section.
  SecOffset: uint64
  /// The section's size in bytes.
  SecSize: uint64
  /// A section header table index link. The interpretation of this field
  /// depends on the section type.
  SecLink: uint32
  /// Extra information. The interpretation of this info depends on the section
  /// type.
  SecInfo: uint32
  /// Some sections have address alignment constraints.
  SecAlignment: uint64
  /// Some sections hold a table of fixed-size entries, such as a symbol
  /// table. For such a section, this member gives the size in bytes of each
  /// entry.
  SecEntrySize: uint64
}

module internal Section =
  let [<Literal>] SecText = ".text"
  let [<Literal>] SecBSS = ".bss"
  let [<Literal>] SecROData = ".rodata"

  /// Return the section file offset and size, which represents the section
  /// names separated by null character.
  let parseSectionNameTableInfo hdr ({ Reader = reader } as toolBox) =
    let secPtr = hdr.SHdrTblOffset + uint64 (hdr.SHdrStrIdx * hdr.SHdrEntrySize)
    let ptrSize = WordSize.toByteWidth hdr.Class
    let shAddrOffset = 8UL + uint64 (ptrSize * 2)
    let shAddrPtr = secPtr + shAddrOffset (* pointer to sh_offset *)
    let shAddrSize = ptrSize * 2 (* sh_offset, sh_size *)
    let span = ReadOnlySpan (toolBox.Bytes, int shAddrPtr, shAddrSize)
    let offset = readUIntOfType span reader hdr.Class 0
    let size = readUIntOfType span reader hdr.Class (pickNum hdr.Class 4 8)
    ReadOnlySpan (toolBox.Bytes, int offset, int size)

  let peekSecType (span: ByteSpan) (reader: IBinReader) =
    reader.ReadUInt32 (span, 4)
    |> LanguagePrimitives.EnumOfValue: SectionType

  let peekSecFlags span reader cls =
    readUIntOfType span reader cls 8
    |> LanguagePrimitives.EnumOfValue: SectionFlag

  let parseSectionHdr toolBox num nameTbl (secHdr: ByteSpan) =
    let reader = toolBox.Reader
    let nameOffset = reader.ReadInt32 (secHdr, 0)
    let cls = toolBox.Header.Class
    { SecNum = num
      SecName = ByteArray.extractCStringFromSpan nameTbl nameOffset
      SecType = peekSecType secHdr reader
      SecFlags = peekSecFlags secHdr reader cls
      SecAddr = readNative secHdr reader cls 12 16 + toolBox.BaseAddress
      SecOffset = readNative secHdr reader cls 16 24
      SecSize = readNative secHdr reader cls 20 32
      SecLink = reader.ReadUInt32 (secHdr, pickNum cls 24 40)
      SecInfo = reader.ReadUInt32 (secHdr, pickNum cls 28 44)
      SecAlignment = readNative secHdr reader cls 32 48
      SecEntrySize = readNative secHdr reader cls 36 56 }

  let parse ({ Bytes = bytes } as toolBox) =
    let hdr = toolBox.Header
    let nameTbl = parseSectionNameTableInfo hdr toolBox
    let secHdrEntrySize = int hdr.SHdrEntrySize
    let secHdrCount = int hdr.SHdrNum
    let secHeaders = Array.zeroCreate secHdrCount
    let mutable offset = int hdr.SHdrTblOffset
    for i = 0 to secHdrCount - 1 do
      let span = ReadOnlySpan (bytes, offset, secHdrEntrySize)
      let hdr = parseSectionHdr toolBox i nameTbl span
      secHeaders[i] <- hdr
      offset <- offset + secHdrEntrySize
    secHeaders

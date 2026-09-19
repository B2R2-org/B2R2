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

/// Represents the relocation type of ELF.
type internal RelocationKind =
  | RelocationKind of arch: MachineType * relocValue: uint64
with
  /// Creates a generic RelocationKind from a relocation kind of x86
  /// architecture.
  static member Create(reloc: RelocationX86) =
    RelocationKind(MachineType.EM_386, uint64 reloc)

  /// Creates a generic RelocationKind from a relocation kind of x86-64
  static member Create(reloc: RelocationX64) =
    RelocationKind(MachineType.EM_X86_64, uint64 reloc)

  /// Creates a generic RelocationKind from a relocation kind of ARMv7
  static member Create(reloc: RelocationARMv7) =
    RelocationKind(MachineType.EM_ARM, uint64 reloc)

  /// Creates a generic RelocationKind from a relocation kind of ARMv8
  static member Create(reloc: RelocationARMv8) =
    RelocationKind(MachineType.EM_AARCH64, uint64 reloc)

  /// Creates a generic RelocationKind from a relocation kind of MIPS
  static member Create(reloc: RelocationMIPS) =
    RelocationKind(MachineType.EM_MIPS, uint64 reloc)

  /// Creates a generic RelocationKind from a relocation kind of m68k
  static member Create(reloc: RelocationM68K) =
    RelocationKind(MachineType.EM_68K, uint64 reloc)

  /// Creates a generic RelocationKind from a relocation kind of S390
  static member Create(reloc: RelocationS390) =
    RelocationKind(MachineType.EM_S390, uint64 reloc)

  /// Creates a generic RelocationKind from a relocation kind of SH4
  static member Create(reloc: RelocationSH4) =
    RelocationKind(MachineType.EM_SH, uint64 reloc)

  /// Creates a generic RelocationKind from a relocation kind of RISCV
  static member Create(reloc: RelocationRISCV) =
    RelocationKind(MachineType.EM_RISCV, uint64 reloc)

  /// Creates a generic RelocationKind from a relocation kind of PowerPC
  static member Create(reloc: RelocationPPC32) =
    RelocationKind(MachineType.EM_PPC, uint64 reloc)

  /// Creates a generic RelocationKind from a relocation kind of PowerPC64
  static member Create(reloc: RelocationPPC64) =
    RelocationKind(MachineType.EM_PPC64, uint64 reloc)

  /// Creates a generic RelocationKind from a relocation kind of PARISC
  static member Create(reloc: RelocationPARISC) =
    RelocationKind(MachineType.EM_PARISC, uint64 reloc)

  /// Creates a generic RelocationKind from a relocation kind of SPARC
  static member Create(reloc: RelocationSPARC) =
    RelocationKind(MachineType.EM_SPARCV9, uint64 reloc)

  /// Creates a generic RelocationKind from a relocation kind of Alpha
  static member Create(reloc: RelocationAlpha) =
    RelocationKind(MachineType.EM_ALPHA, uint64 reloc)

  /// Creates a generic RelocationKind from a relocation kind of AVR
  static member Create(reloc: RelocationAVR) =
    RelocationKind(MachineType.EM_AVR, uint64 reloc)

  /// Creates a generic RelocationKind from a relocation kind of BPF
  static member Create(reloc: RelocationBPF) =
    RelocationKind(MachineType.EM_BPF, uint64 reloc)

  /// Returns the relative relocation kind of the given architecture, which is
  /// the only kind a RELR table can hold. ValueNone when the architecture
  /// defines no such kind.
  static member TryCreateRelative(arch: MachineType) =
    match arch with
    | MachineType.EM_386 ->
      ValueSome(RelocationKind.Create RelocationX86.R_386_RELATIVE)
    | MachineType.EM_X86_64 ->
      ValueSome(RelocationKind.Create RelocationX64.R_X86_64_RELATIVE)
    | MachineType.EM_ARM ->
      ValueSome(RelocationKind.Create RelocationARMv7.R_ARM_RELATIVE)
    | MachineType.EM_AARCH64 ->
      ValueSome(RelocationKind.Create RelocationARMv8.R_AARCH64_RELATIVE)
    | MachineType.EM_68K ->
      ValueSome(RelocationKind.Create RelocationM68K.R_68K_RELATIVE)
    | MachineType.EM_S390 ->
      ValueSome(RelocationKind.Create RelocationS390.R_390_RELATIVE)
    | MachineType.EM_SH ->
      ValueSome(RelocationKind.Create RelocationSH4.R_SH_RELATIVE)
    | MachineType.EM_RISCV ->
      ValueSome(RelocationKind.Create RelocationRISCV.R_RISCV_RELATIVE)
    | MachineType.EM_PPC ->
      ValueSome(RelocationKind.Create RelocationPPC32.R_PPC_RELATIVE)
    | MachineType.EM_PPC64 ->
      ValueSome(RelocationKind.Create RelocationPPC64.R_PPC64_RELATIVE)
    | MachineType.EM_SPARC
    | MachineType.EM_SPARC32PLUS
    | MachineType.EM_SPARCV9 ->
      ValueSome(RelocationKind.Create RelocationSPARC.R_SPARC_RELATIVE)
    | MachineType.EM_ALPHA
    | MachineType.EM_OLD_ALPHA ->
      ValueSome(RelocationKind.Create RelocationAlpha.R_ALPHA_RELATIVE)
    | _ ->
      ValueNone

  /// Converts a relocation kind to a string representation.
  static member ToString(RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_386 ->
      let kind: RelocationX86 = LanguagePrimitives.EnumOfValue relocValue
      kind.ToString()
    | MachineType.EM_X86_64 ->
      let kind: RelocationX64 = LanguagePrimitives.EnumOfValue relocValue
      kind.ToString()
    | MachineType.EM_ARM ->
      let kind: RelocationARMv7 = LanguagePrimitives.EnumOfValue relocValue
      kind.ToString()
    | MachineType.EM_AARCH64 ->
      let kind: RelocationARMv8 = LanguagePrimitives.EnumOfValue relocValue
      kind.ToString()
    | MachineType.EM_MIPS
    | MachineType.EM_MIPS_RS3_LE ->
      let kind: RelocationMIPS = LanguagePrimitives.EnumOfValue relocValue
      kind.ToString()
    | MachineType.EM_68K ->
      let kind: RelocationM68K = LanguagePrimitives.EnumOfValue relocValue
      kind.ToString()
    | MachineType.EM_S390 ->
      let kind: RelocationS390 = LanguagePrimitives.EnumOfValue relocValue
      kind.ToString()
    | MachineType.EM_SH ->
      let kind: RelocationSH4 = LanguagePrimitives.EnumOfValue relocValue
      kind.ToString()
    | MachineType.EM_RISCV ->
      let kind: RelocationRISCV = LanguagePrimitives.EnumOfValue relocValue
      kind.ToString()
    | MachineType.EM_PPC ->
      let kind: RelocationPPC32 = LanguagePrimitives.EnumOfValue relocValue
      kind.ToString()
    | MachineType.EM_PPC64 ->
      let kind: RelocationPPC64 = LanguagePrimitives.EnumOfValue relocValue
      kind.ToString()
    | MachineType.EM_PARISC ->
      let kind: RelocationPARISC = LanguagePrimitives.EnumOfValue relocValue
      kind.ToString()
    | MachineType.EM_SPARC
    | MachineType.EM_SPARC32PLUS
    | MachineType.EM_SPARCV9 ->
      let kind: RelocationSPARC = LanguagePrimitives.EnumOfValue relocValue
      kind.ToString()
    | MachineType.EM_ALPHA
    | MachineType.EM_OLD_ALPHA ->
      let kind: RelocationAlpha = LanguagePrimitives.EnumOfValue relocValue
      kind.ToString()
    | MachineType.EM_AVR ->
      let kind: RelocationAVR = LanguagePrimitives.EnumOfValue relocValue
      kind.ToString()
    | MachineType.EM_BPF ->
      let kind: RelocationBPF = LanguagePrimitives.EnumOfValue relocValue
      kind.ToString()
    | _ ->
      invalidArg (nameof arch) "Unsupported architecture for relocation."

  /// Returns what the given relocation computes, or ValueNone when the kind is
  /// not one that resolves to an address.
  static member GetSemantics(RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_386 ->
      let kind: RelocationX86 = LanguagePrimitives.EnumOfValue relocValue
      RelocationSemantics.OfX86 kind
    | MachineType.EM_X86_64 ->
      let kind: RelocationX64 = LanguagePrimitives.EnumOfValue relocValue
      RelocationSemantics.OfX64 kind
    | MachineType.EM_ARM ->
      let kind: RelocationARMv7 = LanguagePrimitives.EnumOfValue relocValue
      RelocationSemantics.OfARMv7 kind
    | MachineType.EM_AARCH64 ->
      let kind: RelocationARMv8 = LanguagePrimitives.EnumOfValue relocValue
      RelocationSemantics.OfARMv8 kind
    | MachineType.EM_MIPS
    | MachineType.EM_MIPS_RS3_LE ->
      let kind: RelocationMIPS = LanguagePrimitives.EnumOfValue relocValue
      RelocationSemantics.OfMIPS kind
    | MachineType.EM_68K ->
      let kind: RelocationM68K = LanguagePrimitives.EnumOfValue relocValue
      RelocationSemantics.OfM68K kind
    | MachineType.EM_S390 ->
      let kind: RelocationS390 = LanguagePrimitives.EnumOfValue relocValue
      RelocationSemantics.OfS390 kind
    | MachineType.EM_SH ->
      let kind: RelocationSH4 = LanguagePrimitives.EnumOfValue relocValue
      RelocationSemantics.OfSH4 kind
    | MachineType.EM_RISCV ->
      let kind: RelocationRISCV = LanguagePrimitives.EnumOfValue relocValue
      RelocationSemantics.OfRISCV kind
    | MachineType.EM_PPC ->
      let kind: RelocationPPC32 = LanguagePrimitives.EnumOfValue relocValue
      RelocationSemantics.OfPPC32 kind
    | MachineType.EM_PPC64 ->
      let kind: RelocationPPC64 = LanguagePrimitives.EnumOfValue relocValue
      RelocationSemantics.OfPPC64 kind
    | MachineType.EM_PARISC ->
      let kind: RelocationPARISC = LanguagePrimitives.EnumOfValue relocValue
      RelocationSemantics.OfPARISC kind
    | MachineType.EM_SPARC
    | MachineType.EM_SPARC32PLUS
    | MachineType.EM_SPARCV9 ->
      let kind: RelocationSPARC = LanguagePrimitives.EnumOfValue relocValue
      RelocationSemantics.OfSPARC kind
    | MachineType.EM_ALPHA
    | MachineType.EM_OLD_ALPHA ->
      let kind: RelocationAlpha = LanguagePrimitives.EnumOfValue relocValue
      RelocationSemantics.OfAlpha kind
    | MachineType.EM_AVR ->
      let kind: RelocationAVR = LanguagePrimitives.EnumOfValue relocValue
      RelocationSemantics.OfAVR kind
    | MachineType.EM_BPF ->
      let kind: RelocationBPF = LanguagePrimitives.EnumOfValue relocValue
      RelocationSemantics.OfBPF kind
    | _ ->
      ValueNone

/// Represents a relocation type for x86.
and internal RelocationX86 =
  /// No relocation.
  | R_386_NONE = 0UL
  /// Direct 32-bit (S + A).
  | R_386_32 = 1UL
  /// PC-relative 32-bit (S + A - P).
  | R_386_PC32 = 2UL
  /// 32-bit GOT entry (G + A).
  | R_386_GOT32 = 3UL
  /// 32-bit PLT entry (L + A - P).
  | R_386_PLT32 = 4UL
  /// Copy symbol at runtime.
  | R_386_COPY = 5UL
  /// Create GOT entry (S).
  | R_386_GLOB_DATA = 6UL
  /// Create PLT entry (S).
  | R_386_JUMP_SLOT = 7UL
  /// Adjust by program base (S + A).
  | R_386_RELATIVE = 8UL
  /// 32-bit offset to GOT (S + A - GOT).
  | R_386_GOTOFF = 9UL
  /// PC-relative offset to GOT (GOT + A - P).
  | R_386_GOTPC = 10UL
  /// (L + A).
  | R_386_32PLT = 11UL
  | R_386_TLS_TPOFF = 14UL
  | R_386_TLS_IE = 15UL
  | R_386_TLS_GOTIE = 16UL
  | R_386_TLS_LE = 17UL
  | R_386_TLS_GD = 18UL
  | R_386_TLS_LDM = 19UL
  /// (S + A).
  | R_386_16 = 20UL
  /// (S + A - P).
  | R_386_PC16 = 21UL
  /// (S + A).
  | R_386_8 = 22UL
  /// (S + A - P).
  | R_386_PC8 = 23UL
  | R_386_TLS_GD_32 = 24UL
  | R_386_TLS_GD_PUSH = 25UL
  | R_386_TLS_GD_CALL = 26UL
  | R_386_TLS_GD_POP = 27UL
  | R_386_TLS_LDM_32 = 28UL
  | R_386_TLS_LDM_PUSH = 29UL
  | R_386_TLS_LDM_CALL = 30UL
  | R_386_TLS_LDM_POP = 31UL
  | R_386_TLS_LDO_32 = 32UL
  | R_386_TLS_IE_32 = 33UL
  | R_386_TLS_LE_32 = 34UL
  | R_386_TLS_DTPMOD32 = 35UL
  | R_386_TLS_DTPOFF32 = 36UL
  | R_386_TLS_TPOFF32 = 37UL
  /// (Z + A).
  | R_386_SIZE32 = 38UL
  /// x86 more TLS relocations
  | R_386_TLS_GOTDESC = 39UL
  | R_386_TLS_DESC_CALL = 40UL
  | R_386_TLS_DESC = 41UL
  /// Indirect (B + A).
  | R_386_IRELATIVE = 42UL
  /// (G + A - GOT/G + A)
  | R_386_GOT32X = 43UL
  /// (A + (S >> 4)).
  | R_386_SEG16 = 44UL
  /// (A - S).
  | R_386_SUB16 = 45UL
  /// (A - S).
  | R_386_SUB32 = 46UL

/// Represents a relocation type for x86-64.
and internal RelocationX64 =
  /// No relocation.
  | R_X86_64_None = 0UL
  /// Direct 64-bit.
  | R_X86_64_64 = 1UL
  /// PC-relative 32-bit.
  | R_X86_64_PC32 = 2UL
  /// 32-bit GOT entry.
  | R_X86_64_GOT32 = 3UL
  /// 32-bit PLT entry.
  | R_X86_64_PLT32 = 4UL
  /// Copy symbol at runtime.
  | R_X86_64_COPY = 5UL
  /// Create GOT entry.
  | R_X86_64_GLOB_DATA = 6UL
  /// Create PLT entry.
  | R_X86_64_JUMP_SLOT = 7UL
  /// Adjust by program base.
  | R_X86_64_RELATIVE = 8UL
  /// 32-bit signed PC-relative offset to GOT.
  | R_X86_64_GOTPCREL = 9UL
  /// Direct 32-bit zero extended.
  | R_X86_64_32 = 10UL
  /// Direct 32-bit sign extended.
  | R_X86_64_32S = 11UL
  /// Direct 16-bit zero extended.
  | R_X86_64_16 = 12UL
  /// 16-bit sign extended PC relative.
  | R_X86_64_PC16 = 13UL
  /// Direct 8-bit sign extended.
  | R_X86_64_8 = 14UL
  /// 8-bit sign extended PC relative.
  | R_X86_64_PC8 = 15UL
  /// PC-relative 64 bit.
  | R_X86_64_PC64 = 24UL
  /// 64-bit offset to GOT.
  | R_X86_64_GOTOFF64 = 25UL
  /// 32-bit signed PC-relative offset to GOT.
  | R_X86_64_GOTPC32 = 26UL
  /// 64-bit GOT entry offset.
  | R_X86_64_GOT64 = 27UL
  /// 64-bit PC-relative offset to GOT entry.
  | R_X86_64_GOTPCREL64 = 28UL
  /// 64-bit PC relative offset to GOT.
  | R_X86_64_GOTPC64 = 29UL
  /// 64-bit GOT entry offset requiring PLT.
  | R_X86_64_GOTPLT64 = 30UL
  /// 64-bit GOT relative offset to PLT entry.
  | R_X86_64_PLTOFF64 = 31UL
  /// Size of symbol plus 32-bit addend.
  | R_X86_64_SIZE32 = 32UL
  /// Size of symbol plus 64-bit addend.
  | R_X86_64_SIZE64 = 33UL
  /// Adjust indirectly by program base.
  | R_X86_64_IRELATIVE = 37UL

/// Represents a relocation type for ARMv7.
and internal RelocationARMv7 =
  /// No reloc.
  | R_ARM_None = 0UL
  /// PC-relative 26-bit branch.
  | R_ARM_PC24 = 1UL
  /// Direct 32 bit.
  | R_ARM_ABS32 = 2UL
  /// PC-relative 32 bit.
  | R_ARM_REL32 = 3UL
  /// PC-relative LDR.
  | R_ARM_LDR_PC_G0 = 4UL
  /// Direct 16 bit.
  | R_ARM_ABS16 = 5UL
  /// Direct 12 bit.
  | R_ARM_ABS12 = 6UL
  /// Direct 8 bit.
  | R_ARM_ABS8 = 8UL
  /// Copy symbol at runtime.
  | R_ARM_COPY = 20UL
  /// Create GOT entry.
  | R_ARM_GLOB_DATA = 21UL
  /// Create PLT entry.
  | R_ARM_JUMP_SLOT = 22UL
  /// Adjust by program base.
  | R_ARM_RELATIVE = 23UL
  /// 32-bit offset to GOT.
  | R_ARM_GOTOFF32 = 24UL
  /// 32-bit PC-relative offset to GOT.
  | R_ARM_BASE_PREL = 25UL
  /// 32-bit GOT entry.
  | R_ARM_GOT_BREL = 26UL
  /// 32-bit PLT address.
  | R_ARM_PLT32 = 27UL
  /// Adjust indirectly by program base.
  | R_ARM_IRELATIVE = 160UL

/// Represents a relocation type for ARMv8.
and internal RelocationARMv8 =
  /// No reloc.
  | R_AARCH64_NONE = 0UL
  /// Direct 64 bit.
  | R_AARCH64_ABS64 = 257UL
  /// Direct 32 bit.
  | R_AARCH64_ABS32 = 258UL
  /// Direct 16 bit.
  | R_AARCH64_ABS16 = 259UL
  /// PC-relative 64 bit.
  | R_AARCH64_PREL64 = 260UL
  /// PC-relative 32 bit.
  | R_AARCH64_PREL32 = 261UL
  /// PC-relative 16 bit.
  | R_AARCH64_PREL16 = 262UL
  /// GOT-relative 64 bit.
  | R_AARCH64_GOTREL64 = 307UL
  /// GOT-relative 32 bit.
  | R_AARCH64_GOTREL32 = 308UL
  /// Copy symbol at runtime.
  | R_AARCH64_COPY = 1024UL
  /// Create GOT entry.
  | R_AARCH64_GLOB_DATA = 1025UL
  /// Create PLT entry.
  | R_AARCH64_JUMP_SLOT = 1026UL
  /// Delta(S) + A.
  | R_AARCH64_RELATIVE = 1027UL
  /// Indirect(Delta(S) + A).
  | R_AARCH64_IRELATIVE = 1032UL

/// Represents a relocation type for MIPS.
and internal RelocationMIPS =
  /// No reloc.
  | R_MIPS_NONE = 0UL
  /// Direct 16 bit.
  | R_MIPS_16 = 1UL
  /// Direct 32 bit.
  | R_MIPS_32 = 2UL
  /// PC-relative 32 bit.
  | R_MIPS_REL32 = 3UL
  /// Direct 26 bit shifted.
  | R_MIPS_26 = 4UL
  /// High 16 bit.
  | R_MIPS_HI16 = 5UL
  /// Low 16 bit.
  | R_MIPS_LO16 = 6UL
  /// GP-relative 16 bit.
  | R_MIPS_GPREL16 = 7UL
  /// 16-bit literal entry.
  | R_MIPS_LITERAL = 8UL
  /// 16-bit GOT entry.
  | R_MIPS_GOT16 = 9UL
  /// PC-relative 16 bit.
  | R_MIPS_PC16 = 10UL
  /// 16-bit GOT entry for function.
  | R_MIPS_CALL16 = 11UL
  /// GP-relative 32 bit.
  | R_MIPS_GPREL32 = 12UL
  /// 5-bit shift field.
  | R_MIPS_SHIFT5 = 16UL
  /// 6-bit shift field.
  | R_MIPS_SHIFT6 = 17UL
  /// direct 64 bit.
  | R_MIPS_64 = 18UL
  /// displacement in the GOT.
  | R_MIPS_GOT_DISP = 19UL
  /// displacement to page pointer in the GOT.
  | R_MIPS_GOT_PAGE = 20UL
  /// Offset from page pointer in the GOT.
  | R_MIPS_GOT_OFST = 21UL
  /// HIgh 16 bits of displacement in the GOT.
  | R_MIPS_GOT_HI16 = 22UL
  /// Low 16 bits of displacement in the GOT.
  | R_MIPS_GOT_LO16 = 23UL
  /// 64-bit subtraction.
  | R_MIPS_SUB = 24UL
  /// Insert the addend as an instruction.
  | R_MIPS_INSERT_A = 25UL
  /// Insert the addend as an instruction, and change all relocations to
  /// refer to the old instruction at the address.
  | R_MIPS_INSERT_B = 26UL
  /// Delete a 32 bit instruction.
  | R_MIPS_DELETE = 27UL
  /// Get the higher value of a 64 bit addend.
  | R_MIPS_HIGHER = 28UL
  /// Get the highest value of a 64 bit addend.
  | R_MIPS_HIGHEST = 29UL
  /// High 16 bits of displacement in GOT.
  | R_MIPS_CALL_HI16 = 30UL
  /// Low 16 bits of displacement in GOT.
  | R_MIPS_CALL_LO16 = 31UL
  /// Section displacement, used by an associated event location section.
  | R_MIPS_SCN_DISP = 32UL
  /// PC-relative 16 bit.
  | R_MIPS_REL16 = 33UL
  /// Similiar to R_MIPS__REL32, but used for relocations in a GOT section.
  | R_MIPS_RELGOT = 36UL
  /// Protected jump conversion.
  | R_MIPS_JALR = 37UL
  /// Module number 32 bit.
  | R_MIPS_TLS_DTPMOD32 = 38UL
  /// Module-relative offset 32 bit.
  | R_MIPS_TLS_DTPREL32 = 39UL
  /// Module number 64 bit.
  | R_MIPS_TLS_DTPMOD64 = 40UL
  /// Module-relative offset 64 bit.
  | R_MIPS_TLS_DTPREL64 = 41UL
  /// 16 bit GOT offset for GD.
  | R_MIPS_TLS_GD = 42UL
  /// 16 bit GOT offset for LDM.
  | R_MIPS_TLS_LDM = 43UL
  /// Module-relative offset, high 16 bits.
  | R_MIPS_TLS_DTPREL_HI16 = 44UL
  /// Module-relative offset, low 16 bits.
  | R_MIPS_TLS_DTPREL_LO16 = 45UL
  /// 16 bit GOT offset for IE.
  | R_MIPS_TLS_GOTPREL = 46UL
  /// TP-relative offset, 32 bit.
  | R_MIPS_TLS_TPREL32 = 47UL
  /// TP-relative offset, 64 bit.
  | R_MIPS_TLS_TPREL64 = 48UL
  /// TP-relative offset, high 16 bits.
  | R_MIPS_TLS_TPREL_HI16 = 49UL
  /// TP-relative offset, low 16 bits.
  | R_MIPS_TLS_TPREL_LO16 = 50UL
  /// 32 bit relocation with no addend.
  | R_MIPS_GLOB_DAT = 51UL
  /// Copy symbol at runtime.
  | R_MIPS_COPY = 126UL
  /// Jump slot.
  | R_MIPS_JUMP_SLOT = 127UL
  /// 32-bit PC-relative.
  | R_MIPS_PC32 = 248UL

/// Represents a relocation type for m68k.
and internal RelocationM68K =
  | R_68K_NONE = 0UL
  /// Direct 32-bit.
  | R_68K_32 = 1UL
  /// Direct 16-bit.
  | R_68K_16 = 2UL
  /// Direct 8-bit.
  | R_68K_8 = 3UL
  /// 32-bit PC-relative.
  | R_68K_PC32 = 4UL
  /// 16-bit PC-relative.
  | R_68K_PC16 = 5UL
  /// 8-bit PC-relative.
  | R_68K_PC8 = 6UL
  /// 32-bit PC-relative reference to the GOT entry.
  | R_68K_GOT32 = 7UL
  /// 16-bit PC-relative reference to the GOT entry.
  | R_68K_GOT16 = 8UL
  /// 8-bit PC-relative reference to the GOT entry.
  | R_68K_GOT8 = 9UL
  /// 32-bit offset of the GOT entry from the GOT base.
  | R_68K_GOT32O = 10UL
  /// 16-bit offset of the GOT entry from the GOT base.
  | R_68K_GOT16O = 11UL
  /// 8-bit offset of the GOT entry from the GOT base.
  | R_68K_GOT8O = 12UL
  /// 32-bit PC-relative reference to the PLT entry.
  | R_68K_PLT32 = 13UL
  /// 16-bit PC-relative reference to the PLT entry.
  | R_68K_PLT16 = 14UL
  /// 8-bit PC-relative reference to the PLT entry.
  | R_68K_PLT8 = 15UL
  /// 32-bit offset of the PLT entry from the GOT base.
  | R_68K_PLT32O = 16UL
  /// 16-bit offset of the PLT entry from the GOT base.
  | R_68K_PLT16O = 17UL
  /// 8-bit offset of the PLT entry from the GOT base.
  | R_68K_PLT8O = 18UL
  /// Copy symbol at run time.
  | R_68K_COPY = 19UL
  /// Create a GOT entry.
  | R_68K_GLOB_DAT = 20UL
  /// Create a PLT entry.
  | R_68K_JMP_SLOT = 21UL
  /// Adjust by program base.
  | R_68K_RELATIVE = 22UL
  /// 32-bit offset for the general dynamic thread-local model.
  | R_68K_TLS_GD32 = 25UL
  /// 16-bit offset for the general dynamic thread-local model.
  | R_68K_TLS_GD16 = 26UL
  /// 8-bit offset for the general dynamic thread-local model.
  | R_68K_TLS_GD8 = 27UL
  /// 32-bit offset for the local dynamic thread-local model.
  | R_68K_TLS_LDM32 = 28UL
  /// 16-bit offset for the local dynamic thread-local model.
  | R_68K_TLS_LDM16 = 29UL
  /// 8-bit offset for the local dynamic thread-local model.
  | R_68K_TLS_LDM8 = 30UL
  /// 32-bit offset within a local dynamic thread-local block.
  | R_68K_TLS_LDO32 = 31UL
  /// 16-bit offset within a local dynamic thread-local block.
  | R_68K_TLS_LDO16 = 32UL
  /// 8-bit offset within a local dynamic thread-local block.
  | R_68K_TLS_LDO8 = 33UL
  /// 32-bit offset for the initial exec thread-local model.
  | R_68K_TLS_IE32 = 34UL
  /// 16-bit offset for the initial exec thread-local model.
  | R_68K_TLS_IE16 = 35UL
  /// 8-bit offset for the initial exec thread-local model.
  | R_68K_TLS_IE8 = 36UL
  /// 32-bit offset for the local exec thread-local model.
  | R_68K_TLS_LE32 = 37UL
  /// 16-bit offset for the local exec thread-local model.
  | R_68K_TLS_LE16 = 38UL
  /// 8-bit offset for the local exec thread-local model.
  | R_68K_TLS_LE8 = 39UL
  /// Module index of the thread-local block.
  | R_68K_TLS_DTPMOD32 = 40UL
  /// Offset within the thread-local block.
  | R_68K_TLS_DTPREL32 = 41UL
  /// Offset from the thread pointer.
  | R_68K_TLS_TPREL32 = 42UL

/// Represents a relocation type for S390.
and internal RelocationS390 =
  | R_S390_NONE = 0UL
  | R_390_8 = 1UL
  | R_390_12 = 2UL
  | R_390_16 = 3UL
  | R_390_32 = 4UL
  | R_390_PC32 = 5UL
  | R_390_GOT12 = 6UL
  | R_390_GOT32 = 7UL
  | R_390_PLT32 = 8UL
  | R_390_COPY = 9UL
  | R_390_GLOB_DAT = 10UL
  | R_390_JMP_SLOT = 11UL
  | R_390_RELATIVE = 12UL
  | R_390_GOTOFF = 13UL
  | R_390_GOTPC = 14UL
  | R_390_GOT16 = 15UL
  | R_390_PC16 = 16UL
  | R_390_PC16DBL = 17UL
  | R_390_PLT16DBL = 18UL
  /// Direct 64-bit (S + A).
  | R_390_64 = 22UL
  /// STT_GNU_IFUNC relocation (B + A).
  | R_390_IRELATIVE = 61UL

/// Represents a relocation type for SH4.
and internal RelocationSH4 =
  | R_SH_NONE = 0UL
  | R_SH_DIR32 = 1UL
  | R_SH_REL32 = 2UL
  | R_SH_DIR8WPN = 3UL
  | R_SH_IND12W = 4UL
  | R_SH_DIR8WPL = 5UL
  | R_SH_DIR8WPZ = 6UL
  | R_SH_DIR8BP = 7UL
  | R_SH_DIR8W = 8UL
  | R_SH_DIR8L = 9UL
  | R_SH_LOOP_START = 10UL
  | R_SH_LOOP_END = 11UL
  | R_SH_GNU_VTINHERIT = 22UL
  | R_SH_GNU_VTENTRY = 23UL
  | R_SH_SWITCH8 = 24UL
  | R_SH_SWITCH16 = 25UL
  | R_SH_SWITCH32 = 26UL
  | R_SH_USES = 27UL
  | R_SH_COUNT = 28UL
  | R_SH_ALIGN = 29UL
  | R_SH_CODE = 30UL
  | R_SH_DATA = 31UL
  | R_SH_LABEL = 32UL
  | R_SH_DIR16 = 33UL
  | R_SH_DIR8 = 34UL
  | R_SH_DIR8UL = 35UL
  | R_SH_DIR8UW = 36UL
  | R_SH_DIR8U = 37UL
  | R_SH_DIR8SW = 38UL
  | R_SH_DIR8S = 39UL
  | R_SH_DIR4UL = 40UL
  | R_SH_DIR4UW = 41UL
  | R_SH_DIR4U = 42UL
  | R_SH_PSHA = 43UL
  | R_SH_PSHL = 44UL
  | R_SH_DIR5U = 45UL
  | R_SH_DIR6U = 46UL
  | R_SH_DIR6S = 47UL
  | R_SH_DIR10S = 48UL
  | R_SH_DIR10SW = 49UL
  | R_SH_DIR10SL = 50UL
  | R_SH_DIR10SQ = 51UL
  | R_SH_DIR16S = 53UL
  | R_SH_TLS_GD_32 = 144UL
  | R_SH_TLS_LD_32 = 145UL
  | R_SH_TLS_LDO_32 = 146UL
  | R_SH_TLS_IE_32 = 147UL
  | R_SH_TLS_LE_32 = 148UL
  | R_SH_TLS_DTPMOD32 = 149UL
  | R_SH_TLS_DTPOFF32 = 150UL
  | R_SH_TLS_TPOFF32 = 151UL
  | R_SH_GOT32 = 160UL
  | R_SH_PLT32 = 161UL
  | R_SH_COPY = 162UL
  | R_SH_GLOB_DAT = 163UL
  | R_SH_JMP_SLOT = 164UL
  | R_SH_RELATIVE = 165UL
  | R_SH_GOTOFF = 166UL
  | R_SH_GOTPC = 167UL
  | R_SH_GOTPLT32 = 168UL
  | R_SH_GOT_LOW16 = 169UL
  | R_SH_GOT_MEDLOW16 = 170UL
  | R_SH_GOT_MEDHI16 = 171UL
  | R_SH_GOT_HI16 = 172UL
  | R_SH_GOTPLT_LOW16 = 173UL
  | R_SH_GOTPLT_MEDLOW16 = 174UL
  | R_SH_GOTPLT_MEDHI16 = 175UL
  | R_SH_GOTPLT_HI16 = 176UL
  | R_SH_PLT_LOW16 = 177UL
  | R_SH_PLT_MEDLOW16 = 178UL
  | R_SH_PLT_MEDHI16 = 179UL
  | R_SH_PLT_HI16 = 180UL
  | R_SH_GOTOFF_LOW16 = 181UL
  | R_SH_GOTOFF_MEDLOW16 = 182UL
  | R_SH_GOTOFF_MEDHI16 = 183UL
  | R_SH_GOTOFF_HI16 = 184UL
  | R_SH_GOTPC_LOW16 = 185UL
  | R_SH_GOTPC_MEDLOW16 = 186UL
  | R_SH_GOTPC_MEDHI16 = 187UL
  | R_SH_GOTPC_HI16 = 188UL
  | R_SH_GOT10BY4 = 189UL
  | R_SH_GOTPLT10BY4 = 190UL
  | R_SH_GOT10BY8 = 191UL
  | R_SH_GOTPLT10BY8 = 192UL
  | R_SH_COPY64 = 193UL
  | R_SH_GLOB_DAT64 = 194UL
  | R_SH_JMP_SLOT64 = 195UL
  | R_SH_RELATIVE64 = 196UL
  | R_SH_GOT20 = 201UL
  | R_SH_GOTOFF20 = 202UL
  | R_SH_GOTFUNCDESC = 203UL
  | R_SH_GOTFUNCDESC20 = 204UL
  | R_SH_GOTOFFFUNCDESC = 205UL
  | R_SH_GOTOFFFUNCDESC20 = 206UL
  | R_SH_FUNCDESC = 207UL
  | R_SH_FUNCDESC_VALUE = 208UL
  | R_SH_SHMEDIA_CODE = 242UL
  | R_SH_PT_16 = 243UL
  | R_SH_IMMS16 = 244UL
  | R_SH_IMMU16 = 245UL
  | R_SH_IMM_LOW16 = 246UL
  | R_SH_IMM_LOW16_PCREL = 247UL
  | R_SH_IMM_MEDLOW16 = 248UL
  | R_SH_IMM_MEDLOW16_PCREL = 249UL
  | R_SH_IMM_MEDHI16 = 250UL
  | R_SH_IMM_MEDHI16_PCREL = 251UL
  | R_SH_IMM_HI16 = 252UL
  | R_SH_IMM_HI16_PCREL = 253UL
  | R_SH_64 = 254UL
  | R_SH_64_PCREL = 255UL

/// Represents a relocation type for RISCV.
and internal RelocationRISCV =
  | R_RISCV_NONE = 0UL
  | R_RISCV_32 = 1UL
  | R_RISCV_64 = 2UL
  | R_RISCV_RELATIVE = 3UL
  | R_RISCV_COPY = 4UL
  | R_RISCV_JUMP_SLOT = 5UL
  /// STT_GNU_IFUNC relocation (B + A).
  | R_RISCV_IRELATIVE = 58UL
  | R_RISCV_TLS_DTPMOD32 = 6UL
  | R_RISCV_TLS_DTPMOD64 = 7UL
  | R_RISCV_TLS_DTPREL32 = 8UL
  | R_RISCV_TLS_DTPREL64 = 9UL
  | R_RISCV_TLS_TPREL32 = 10UL
  | R_RISCV_TLS_TPREL64 = 11UL
  | R_RISCV_BRANCH = 16UL
  | R_RISCV_JAL = 17UL
  | R_RISCV_CALL = 18UL
  | R_RISCV_CALL_PLT = 19UL
  | R_RISCV_GOT_HI20 = 20UL
  | R_RISCV_TLS_GOT_HI20 = 21UL
  | R_RISCV_TLS_GD_HI20 = 22UL
  | R_RISCV_PCREL_HI20 = 23UL
  | R_RISCV_PCREL_LO12_I = 24UL
  | R_RISCV_PCREL_LO12_S = 25UL
  | R_RISCV_HI20 = 26UL
  | R_RISCV_LO12_I = 27UL
  | R_RISCV_LO12_S = 28UL
  | R_RISCV_TPREL_HI20 = 29UL
  | R_RISCV_TPREL_LO12_I = 30UL
  | R_RISCV_TPREL_LO12_S = 31UL
  | R_RISCV_TPREL_ADD = 32UL
  | R_RISCV_ADD8 = 33UL
  | R_RISCV_ADD16 = 34UL
  | R_RISCV_ADD32 = 35UL
  | R_RISCV_ADD64 = 36UL
  | R_RISCV_SUB8 = 37UL
  | R_RISCV_SUB16 = 38UL
  | R_RISCV_SUB32 = 39UL
  | R_RISCV_SUB64 = 40UL
  | R_RISCV_GNU_VTINHERIT = 41UL
  | R_RISCV_GNU_VTENTRY = 42UL
  | R_RISCV_ALIGN = 43UL
  | R_RISCV_RVC_BRANCH = 44UL
  | R_RISCV_RVC_JUMP = 45UL
  | R_RISCV_RVC_LUI = 46UL
  | R_RISCV_GPREL_I = 47UL
  | R_RISCV_GPREL_S = 48UL
  | R_RISCV_TPREL_I = 49UL
  | R_RISCV_TPREL_S = 50UL
  | R_RISCV_RELAX = 51UL
  | R_RISCV_SUB6 = 52UL
  | R_RISCV_SET6 = 53UL
  | R_RISCV_SET8 = 54UL
  | R_RISCV_SET16 = 55UL
  | R_RISCV_SET32 = 56UL
  | R_RISCV_32_PCREL = 57UL

/// Represents a relocation type for PPC.
and internal RelocationPPC32 =
  | R_PPC_NONE = 0UL
  | R_PPC_ADDR32 = 1UL
  | R_PPC_ADDR24 = 2UL
  | R_PPC_ADDR16 = 3UL
  | R_PPC_ADDR16_LO = 4UL
  | R_PPC_ADDR16_HI = 5UL
  | R_PPC_ADDR16_HA = 6UL
  | R_PPC_ADDR14 = 7UL
  | R_PPC_ADDR14_BRTAKEN = 8UL
  | R_PPC_ADDR14_BRNTAKEN = 9UL
  | R_PPC_REL24 = 10UL
  | R_PPC_REL14 = 11UL
  | R_PPC_REL14_BRTAKEN = 12UL
  | R_PPC_REL14_BRNTAKEN = 13UL
  | R_PPC_GOT16 = 14UL
  | R_PPC_GOT16_LO = 15UL
  | R_PPC_GOT16_HI = 16UL
  | R_PPC_GOT16_HA = 17UL
  | R_PPC_PLTREL24 = 18UL
  | R_PPC_COPY = 19UL
  | R_PPC_GLOB_DAT = 20UL
  | R_PPC_JMP_SLOT = 21UL
  | R_PPC_RELATIVE = 22UL
  | R_PPC_LOCAL24PC = 23UL
  | R_PPC_UADDR32 = 24UL
  | R_PPC_UADDR16 = 25UL
  | R_PPC_REL32 = 26UL
  | R_PPC_PLT32 = 27UL
  | R_PPC_PLTREL32 = 28UL
  | R_PPC_PLT16_LO = 29UL
  | R_PPC_PLT16_HI = 30UL
  | R_PPC_PLT16_HA = 31UL
  | R_PPC_SDAREL16 = 32UL
  | R_PPC_SECTOFF = 33UL
  | R_PPC_SECTOFF_LO = 34UL
  | R_PPC_SECTOFF_HI = 35UL
  | R_PPC_SECTOFF_HA = 36UL
  | R_PPC_TLS = 67UL
  | R_PPC_DTPMOD32 = 68UL
  | R_PPC_TPREL16 = 69UL
  | R_PPC_TPREL16_LO = 70UL
  | R_PPC_TPREL16_HI = 71UL
  | R_PPC_TPREL16_HA = 72UL
  | R_PPC_TPREL32 = 73UL
  | R_PPC_DTPREL16 = 74UL
  | R_PPC_DTPREL16_LO = 75UL
  | R_PPC_DTPREL16_HI = 76UL
  | R_PPC_DTPREL16_HA = 77UL
  | R_PPC_DTPREL32 = 78UL
  | R_PPC_GOT_TLSGD16 = 79UL
  | R_PPC_GOT_TLSGD16_LO = 80UL
  | R_PPC_GOT_TLSGD16_HI = 81UL
  | R_PPC_GOT_TLSGD16_HA = 82UL
  | R_PPC_GOT_TLSLD16 = 83UL
  | R_PPC_GOT_TLSLD16_LO = 84UL
  | R_PPC_GOT_TLSLD16_HI = 85UL
  | R_PPC_GOT_TLSLD16_HA = 86UL
  | R_PPC_GOT_TPREL16 = 87UL
  | R_PPC_GOT_TPREL16_LO = 88UL
  | R_PPC_GOT_TPREL16_HI = 89UL
  | R_PPC_GOT_TPREL16_HA = 90UL
  | R_PPC_GOT_DTPREL16 = 91UL
  | R_PPC_GOT_DTPREL16_LO = 92UL
  | R_PPC_GOT_DTPREL16_HI = 93UL
  | R_PPC_GOT_DTPREL16_HA = 94UL
  | R_PPC_TLSGD = 95UL
  | R_PPC_TLSLD = 96UL
  | R_PPC_EMB_NADDR32 = 101UL
  | R_PPC_EMB_NADDR16 = 102UL
  | R_PPC_EMB_NADDR16_LO = 103UL
  | R_PPC_EMB_NADDR16_HI = 104UL
  | R_PPC_EMB_NADDR16_HA = 105UL
  | R_PPC_EMB_SDAI16 = 106UL
  | R_PPC_EMB_SDA2I16 = 107UL
  | R_PPC_EMB_SDA2REL = 108UL
  | R_PPC_EMB_SDA21 = 109UL
  | R_PPC_EMB_MRKREF = 110UL
  | R_PPC_EMB_RELSEC16 = 111UL
  | R_PPC_EMB_RELST_LO = 112UL
  | R_PPC_EMB_RELST_HI = 113UL
  | R_PPC_EMB_RELST_HA = 114UL
  | R_PPC_EMB_BIT_FLD = 115UL
  | R_PPC_EMB_RELSDA = 116UL
  | R_PPC_DIAB_SDA21_LO = 180UL
  | R_PPC_DIAB_SDA21_HI = 181UL
  | R_PPC_DIAB_SDA21_HA = 182UL
  | R_PPC_DIAB_RELSDA_LO = 183UL
  | R_PPC_DIAB_RELSDA_HI = 184UL
  | R_PPC_DIAB_RELSDA_HA = 185UL
  | R_PPC_IRELATIVE = 248UL
  | R_PPC_REL16 = 249UL
  | R_PPC_REL16_LO = 250UL
  | R_PPC_REL16_HI = 251UL
  | R_PPC_REL16_HA = 252UL
  | R_PPC_TOC16 = 255UL

/// Represents a relocation type for PARISC.
/// Represents a relocation type for PowerPC64. The ELFv2 ABI reuses the PowerPC
/// numbering for everything it inherits, and adds the doubleword-wide kinds on
/// top; only the kinds a dynamic linker acts on are listed here.
and internal RelocationPPC64 =
  /// No relocation.
  | R_PPC64_NONE = 0UL
  /// Direct 32-bit (S + A).
  | R_PPC64_ADDR32 = 1UL
  /// Copy symbol at runtime.
  | R_PPC64_COPY = 19UL
  /// Create GOT entry (S).
  | R_PPC64_GLOB_DAT = 20UL
  /// Create PLT entry (S).
  | R_PPC64_JMP_SLOT = 21UL
  /// Adjust by program base (B + A).
  | R_PPC64_RELATIVE = 22UL
  /// Direct 64-bit (S + A).
  | R_PPC64_ADDR64 = 38UL
  /// Doubleword holding the TOC pointer.
  | R_PPC64_TOC = 51UL
  /// STT_GNU_IFUNC relocation (B + A).
  | R_PPC64_IRELATIVE = 248UL

and internal RelocationPARISC =
  | R_PARISC_NONE = 0UL
  | R_PARISC_DIR32 = 1UL
  | R_PARISC_DIR21L = 2UL
  | R_PARISC_DIR17R = 3UL
  | R_PARISC_DIR17F = 4UL
  | R_PARISC_DIR14R = 6UL
  | R_PARISC_PCREL21L = 10UL
  | R_PARISC_PCREL17R = 11UL
  | R_PARISC_PCREL17F = 12UL
  | R_PARISC_PCREL17C = 13UL
  | R_PARISC_PCREL14R = 14UL
  | R_PARISC_DPREL21L = 18UL
  | R_PARISC_DPREL14WR = 19UL
  | R_PARISC_DPREL14DR = 20UL
  | R_PARISC_DPREL14R = 22UL
  | R_PARISC_DLTREL21L = 26UL
  | R_PARISC_DLTREL14R = 30UL
  | R_PARISC_DLTIND21L = 34UL
  | R_PARISC_DLTIND14R = 38UL
  | R_PARISC_DLTIND14F = 39UL
  | R_PARISC_SETBASE = 40UL
  | R_PARISC_SECREL32 = 41UL
  | R_PARISC_BASEREL21L = 42UL
  | R_PARISC_BASEREL17R = 43UL
  | R_PARISC_BASEREL14R = 46UL
  | R_PARISC_SEGBASE = 48UL
  | R_PARISC_SEGREL32 = 49UL
  | R_PARISC_PLTOFF21L = 50UL
  | R_PARISC_PLTOFF14R = 54UL
  | R_PARISC_PLTOFF14F = 55UL
  | R_PARISC_PLABEL32 = 65UL
  | R_PARISC_PCREL22C = 73UL
  | R_PARISC_PCREL22F = 74UL
  | R_PARISC_PCREL14WR = 75UL
  | R_PARISC_PCREL14DR = 76UL
  | R_PARISC_DIR14WR = 83UL
  | R_PARISC_DIR14DR = 84UL
  | R_PARISC_DLTREL14WR = 91UL
  | R_PARISC_DLTREL14DR = 92UL
  | R_PARISC_DLTIND14WR = 99UL
  | R_PARISC_DLTIND14DR = 100UL
  | R_PARISC_BASEREL14WR = 107UL
  | R_PARISC_BASEREL14DR = 108UL
  | R_PARISC_PLTOFF14WR = 115UL
  | R_PARISC_PLTOFF14DR = 116UL
  /// 64 bits of effective address (S + A).
  | R_PARISC_DIR64 = 80UL
  /// Copy symbol at runtime.
  | R_PARISC_COPY = 128UL
  /// Dynamic relocation for an imported PLT entry (S + A).
  | R_PARISC_IPLT = 129UL
  /// Dynamic relocation for an exported PLT entry (S + A).
  | R_PARISC_EPLT = 130UL

/// Represents a relocation type for SPARC. The 32-bit and 64-bit variants
/// of the architecture share one numbering.
and internal RelocationSPARC =
  /// No relocation.
  | R_SPARC_NONE = 0UL
  /// Direct 8-bit (S + A).
  | R_SPARC_8 = 1UL
  /// Direct 16-bit (S + A).
  | R_SPARC_16 = 2UL
  /// Direct 32-bit (S + A).
  | R_SPARC_32 = 3UL
  /// PC-relative 8-bit.
  | R_SPARC_DISP8 = 4UL
  /// PC-relative 16-bit.
  | R_SPARC_DISP16 = 5UL
  /// PC-relative 32-bit.
  | R_SPARC_DISP32 = 6UL
  /// PC-relative 30-bit shifted.
  | R_SPARC_WDISP30 = 7UL
  /// PC-relative 22-bit shifted.
  | R_SPARC_WDISP22 = 8UL
  /// High 22 bits.
  | R_SPARC_HI22 = 9UL
  /// Direct 22-bit.
  | R_SPARC_22 = 10UL
  /// Direct 13-bit.
  | R_SPARC_13 = 11UL
  /// Low 10 bits.
  | R_SPARC_LO10 = 12UL
  /// Low 10 bits of a GOT entry.
  | R_SPARC_GOT10 = 13UL
  /// 13-bit GOT entry.
  | R_SPARC_GOT13 = 14UL
  /// High 22 bits of a GOT entry.
  | R_SPARC_GOT22 = 15UL
  /// PC-relative low 10 bits.
  | R_SPARC_PC10 = 16UL
  /// PC-relative high 22 bits.
  | R_SPARC_PC22 = 17UL
  /// PC-relative PLT entry.
  | R_SPARC_WPLT30 = 18UL
  /// Copy symbol at runtime.
  | R_SPARC_COPY = 19UL
  /// Create GOT entry (S).
  | R_SPARC_GLOB_DAT = 20UL
  /// Create PLT entry (S).
  | R_SPARC_JMP_SLOT = 21UL
  /// Adjust by program base (B + A).
  | R_SPARC_RELATIVE = 22UL
  /// Direct unaligned 32-bit (S + A).
  | R_SPARC_UA32 = 23UL
  /// Direct 32-bit PLT entry.
  | R_SPARC_PLT32 = 24UL
  /// Direct 10-bit.
  | R_SPARC_10 = 30UL
  /// Direct 11-bit.
  | R_SPARC_11 = 31UL
  /// Direct 64-bit (S + A).
  | R_SPARC_64 = 32UL
  /// Highest 22 bits.
  | R_SPARC_HH22 = 34UL
  /// High middle 10 bits.
  | R_SPARC_HM10 = 35UL
  /// Low middle 22 bits.
  | R_SPARC_LM22 = 36UL
  /// PC-relative 16-bit shifted.
  | R_SPARC_WDISP16 = 40UL
  /// PC-relative 19-bit shifted.
  | R_SPARC_WDISP19 = 41UL
  /// Direct 7-bit.
  | R_SPARC_7 = 43UL
  /// Direct 5-bit.
  | R_SPARC_5 = 44UL
  /// Direct 6-bit.
  | R_SPARC_6 = 45UL
  /// PC-relative 64-bit.
  | R_SPARC_DISP64 = 46UL
  /// Direct 64-bit PLT entry.
  | R_SPARC_PLT64 = 47UL
  /// High 22 bits, xor-ed.
  | R_SPARC_HIX22 = 48UL
  /// Low 10 bits, xor-ed.
  | R_SPARC_LOX10 = 49UL
  /// Top 22 bits of a 44-bit address.
  | R_SPARC_H44 = 50UL
  /// Middle 10 bits of a 44-bit address.
  | R_SPARC_M44 = 51UL
  /// Low 12 bits of a 44-bit address.
  | R_SPARC_L44 = 52UL
  /// Global register usage.
  | R_SPARC_REGISTER = 53UL
  /// Direct unaligned 64-bit (S + A).
  | R_SPARC_UA64 = 54UL
  /// Direct unaligned 16-bit (S + A).
  | R_SPARC_UA16 = 55UL
  /// STT_GNU_IFUNC relocation (B + A).
  | R_SPARC_IRELATIVE = 249UL

/// Represents a relocation type for Alpha.
and internal RelocationAlpha =
  /// No relocation.
  | R_ALPHA_NONE = 0UL
  /// Direct 32-bit (S + A).
  | R_ALPHA_REFLONG = 1UL
  /// Direct 64-bit (S + A).
  | R_ALPHA_REFQUAD = 2UL
  /// GP-relative 32-bit.
  | R_ALPHA_GPREL32 = 3UL
  /// Reference to a literal in the GOT.
  | R_ALPHA_LITERAL = 4UL
  /// Use of a literal.
  | R_ALPHA_LITUSE = 5UL
  /// Displacement that loads GP.
  | R_ALPHA_GPDISP = 6UL
  /// PC+4 relative 23-bit shifted.
  | R_ALPHA_BRADDR = 7UL
  /// Branch prediction hint.
  | R_ALPHA_HINT = 8UL
  /// PC-relative 16-bit.
  | R_ALPHA_SREL16 = 9UL
  /// PC-relative 32-bit.
  | R_ALPHA_SREL32 = 10UL
  /// PC-relative 64-bit.
  | R_ALPHA_SREL64 = 11UL
  /// High 16 bits of a GP-relative address.
  | R_ALPHA_GPRELHIGH = 17UL
  /// Low 16 bits of a GP-relative address.
  | R_ALPHA_GPRELLOW = 18UL
  /// GP-relative 16-bit.
  | R_ALPHA_GPREL16 = 19UL
  /// Copy symbol at runtime.
  | R_ALPHA_COPY = 24UL
  /// Create GOT entry (S).
  | R_ALPHA_GLOB_DAT = 25UL
  /// Create PLT entry (S).
  | R_ALPHA_JMP_SLOT = 26UL
  /// Adjust by program base (B + A).
  | R_ALPHA_RELATIVE = 27UL
  /// High bits of a general-dynamic TLS offset.
  | R_ALPHA_TLS_GD_HI = 28UL
  /// General-dynamic TLS.
  | R_ALPHA_TLSGD = 29UL
  /// Local-dynamic TLS.
  | R_ALPHA_TLS_LDM = 30UL
  /// TLS module ID.
  | R_ALPHA_DTPMOD64 = 31UL
  /// GOT entry for a TLS offset.
  | R_ALPHA_GOTDTPREL = 32UL
  /// Offset within a TLS block.
  | R_ALPHA_DTPREL64 = 33UL
  /// High bits of a TLS block offset.
  | R_ALPHA_DTPRELHI = 34UL
  /// Low bits of a TLS block offset.
  | R_ALPHA_DTPRELLO = 35UL
  /// 16-bit TLS block offset.
  | R_ALPHA_DTPREL16 = 36UL
  /// GOT entry for an initial-exec TLS offset.
  | R_ALPHA_GOTTPREL = 37UL
  /// Thread-pointer-relative 64-bit.
  | R_ALPHA_TPREL64 = 38UL
  /// High bits of a thread-pointer-relative offset.
  | R_ALPHA_TPRELHI = 39UL
  /// Low bits of a thread-pointer-relative offset.
  | R_ALPHA_TPRELLO = 40UL
  /// Thread-pointer-relative 16-bit.
  | R_ALPHA_TPREL16 = 41UL

/// Represents a relocation type for AVR. Most kinds name a field inside an
/// instruction rather than a whole address, AVR having no room for one.
and internal RelocationAVR =
  /// No relocation.
  | R_AVR_NONE = 0UL
  /// Direct 32-bit (S + A).
  | R_AVR_32 = 1UL
  /// PC-relative 7-bit.
  | R_AVR_7_PCREL = 2UL
  /// PC-relative 13-bit.
  | R_AVR_13_PCREL = 3UL
  /// Direct 16-bit (S + A).
  | R_AVR_16 = 4UL
  /// Direct 16-bit program-memory word.
  | R_AVR_16_PM = 5UL
  /// Low byte, for LDI.
  | R_AVR_LO8_LDI = 6UL
  /// High byte, for LDI.
  | R_AVR_HI8_LDI = 7UL
  /// Higher byte, for LDI.
  | R_AVR_HH8_LDI = 8UL
  /// Low byte negated, for LDI.
  | R_AVR_LO8_LDI_NEG = 9UL
  /// High byte negated, for LDI.
  | R_AVR_HI8_LDI_NEG = 10UL
  /// Higher byte negated, for LDI.
  | R_AVR_HH8_LDI_NEG = 11UL
  /// Low byte of a program-memory word, for LDI.
  | R_AVR_LO8_LDI_PM = 12UL
  /// High byte of a program-memory word, for LDI.
  | R_AVR_HI8_LDI_PM = 13UL
  /// Higher byte of a program-memory word, for LDI.
  | R_AVR_HH8_LDI_PM = 14UL
  /// Low byte of a negated program-memory word.
  | R_AVR_LO8_LDI_PM_NEG = 15UL
  /// High byte of a negated program-memory word.
  | R_AVR_HI8_LDI_PM_NEG = 16UL
  /// Higher byte of a negated program-memory word.
  | R_AVR_HH8_LDI_PM_NEG = 17UL
  /// Program-memory address of a CALL or JMP.
  | R_AVR_CALL = 18UL
  /// Direct 16-bit, for LDI.
  | R_AVR_LDI = 19UL
  /// Direct 6-bit.
  | R_AVR_6 = 20UL
  /// Direct 6-bit, for ADIW and SBIW.
  | R_AVR_6_ADIW = 21UL
  /// Most significant byte, for LDI.
  | R_AVR_MS8_LDI = 22UL
  /// Most significant byte negated, for LDI.
  | R_AVR_MS8_LDI_NEG = 23UL
  /// Low byte of a function descriptor, for LDI.
  | R_AVR_LO8_LDI_GS = 24UL
  /// High byte of a function descriptor, for LDI.
  | R_AVR_HI8_LDI_GS = 25UL
  /// Direct 8-bit (S + A).
  | R_AVR_8 = 26UL
  /// Low byte of a direct 8-bit.
  | R_AVR_8_LO8 = 27UL
  /// High byte of a direct 8-bit.
  | R_AVR_8_HI8 = 28UL
  /// Higher byte of a direct 8-bit.
  | R_AVR_8_HLO8 = 29UL
  /// 8-bit difference between two symbols.
  | R_AVR_DIFF8 = 30UL
  /// 16-bit difference between two symbols.
  | R_AVR_DIFF16 = 31UL
  /// 32-bit difference between two symbols.
  | R_AVR_DIFF32 = 32UL
  /// Direct 7-bit, for LDS and STS.
  | R_AVR_LDS_STS_16 = 33UL
  /// Direct 6-bit port address.
  | R_AVR_PORT6 = 34UL
  /// Direct 5-bit port address.
  | R_AVR_PORT5 = 35UL

/// Represents a relocation type for BPF.
and internal RelocationBPF =
  /// No relocation.
  | R_BPF_NONE = 0UL
  /// Symbol address split across a wide instruction.
  | R_BPF_64_64 = 1UL
  /// Direct 64-bit (S + A).
  | R_BPF_64_ABS64 = 2UL
  /// Direct 32-bit (S + A).
  | R_BPF_64_ABS32 = 3UL
  /// Direct 32-bit that the loader leaves alone.
  | R_BPF_64_NODYLD32 = 4UL
  /// Symbol address in the immediate field of a call.
  | R_BPF_64_32 = 10UL

/// Represents what a relocation computes, regardless of the architecture that
/// defines it. Only the kinds resolving to an address are classified; S is the
/// address of the symbol, A the addend, and B the base address of the image.
and internal RelocationSemantics =
  /// S + A. An entry naming no symbol takes S as zero, so it resolves against
  /// the base alone, which is what a local relocation in a PIC image wants.
  | SymbolPlusAddend
  /// S.
  | SymbolOnly
  /// B + A.
  | BasePlusAddend
  /// B + A, where what the sum names is an ifunc resolver: a function the
  /// loader calls to learn the address, rather than that address itself.
  | IFuncResolver
with
  /// Classifies a relocation kind of x86.
  static member OfX86(reloc: RelocationX86) =
    match reloc with
    | RelocationX86.R_386_32 -> ValueSome SymbolPlusAddend
    | RelocationX86.R_386_GLOB_DATA
    | RelocationX86.R_386_JUMP_SLOT -> ValueSome SymbolOnly
    | RelocationX86.R_386_RELATIVE -> ValueSome BasePlusAddend
    | RelocationX86.R_386_IRELATIVE -> ValueSome IFuncResolver
    | _ -> ValueNone

  /// Classifies a relocation kind of x86-64.
  static member OfX64(reloc: RelocationX64) =
    match reloc with
    | RelocationX64.R_X86_64_64 -> ValueSome SymbolPlusAddend
    | RelocationX64.R_X86_64_GLOB_DATA
    | RelocationX64.R_X86_64_JUMP_SLOT -> ValueSome SymbolOnly
    | RelocationX64.R_X86_64_RELATIVE -> ValueSome BasePlusAddend
    | RelocationX64.R_X86_64_IRELATIVE -> ValueSome IFuncResolver
    | _ -> ValueNone

  /// Classifies a relocation kind of ARMv7.
  static member OfARMv7(reloc: RelocationARMv7) =
    match reloc with
    | RelocationARMv7.R_ARM_ABS32 -> ValueSome SymbolPlusAddend
    | RelocationARMv7.R_ARM_GLOB_DATA
    | RelocationARMv7.R_ARM_JUMP_SLOT -> ValueSome SymbolOnly
    | RelocationARMv7.R_ARM_RELATIVE -> ValueSome BasePlusAddend
    | RelocationARMv7.R_ARM_IRELATIVE -> ValueSome IFuncResolver
    | _ -> ValueNone

  /// Classifies a relocation kind of ARMv8.
  static member OfARMv8(reloc: RelocationARMv8) =
    match reloc with
    | RelocationARMv8.R_AARCH64_ABS64 -> ValueSome SymbolPlusAddend
    | RelocationARMv8.R_AARCH64_GLOB_DATA
    | RelocationARMv8.R_AARCH64_JUMP_SLOT -> ValueSome SymbolOnly
    | RelocationARMv8.R_AARCH64_RELATIVE -> ValueSome BasePlusAddend
    | RelocationARMv8.R_AARCH64_IRELATIVE -> ValueSome IFuncResolver
    | _ -> ValueNone

  /// Classifies a relocation kind of MIPS.
  static member OfMIPS(reloc: RelocationMIPS) =
    match reloc with
    | RelocationMIPS.R_MIPS_32
    | RelocationMIPS.R_MIPS_64
    | RelocationMIPS.R_MIPS_REL32 -> ValueSome SymbolPlusAddend
    | RelocationMIPS.R_MIPS_GLOB_DAT
    | RelocationMIPS.R_MIPS_JUMP_SLOT -> ValueSome SymbolOnly
    | _ -> ValueNone

  /// Classifies a relocation kind of m68k.
  static member OfM68K(reloc: RelocationM68K) =
    match reloc with
    | RelocationM68K.R_68K_32 -> ValueSome SymbolPlusAddend
    | RelocationM68K.R_68K_GLOB_DAT
    | RelocationM68K.R_68K_JMP_SLOT -> ValueSome SymbolOnly
    | RelocationM68K.R_68K_RELATIVE -> ValueSome BasePlusAddend
    | _ -> ValueNone

  /// Classifies a relocation kind of S390.
  static member OfS390(reloc: RelocationS390) =
    match reloc with
    | RelocationS390.R_390_32
    | RelocationS390.R_390_64 -> ValueSome SymbolPlusAddend
    | RelocationS390.R_390_GLOB_DAT
    | RelocationS390.R_390_JMP_SLOT -> ValueSome SymbolOnly
    | RelocationS390.R_390_RELATIVE -> ValueSome BasePlusAddend
    | RelocationS390.R_390_IRELATIVE -> ValueSome IFuncResolver
    | _ -> ValueNone

  /// Classifies a relocation kind of SH4.
  static member OfSH4(reloc: RelocationSH4) =
    match reloc with
    | RelocationSH4.R_SH_DIR32 -> ValueSome SymbolPlusAddend
    | RelocationSH4.R_SH_GLOB_DAT
    | RelocationSH4.R_SH_JMP_SLOT -> ValueSome SymbolOnly
    | RelocationSH4.R_SH_RELATIVE -> ValueSome BasePlusAddend
    | _ -> ValueNone

  /// Classifies a relocation kind of RISCV.
  static member OfRISCV(reloc: RelocationRISCV) =
    match reloc with
    | RelocationRISCV.R_RISCV_32
    | RelocationRISCV.R_RISCV_64 -> ValueSome SymbolPlusAddend
    | RelocationRISCV.R_RISCV_JUMP_SLOT -> ValueSome SymbolOnly
    | RelocationRISCV.R_RISCV_RELATIVE -> ValueSome BasePlusAddend
    | RelocationRISCV.R_RISCV_IRELATIVE -> ValueSome IFuncResolver
    | _ -> ValueNone

  /// Classifies a relocation kind of PowerPC.
  static member OfPPC32(reloc: RelocationPPC32) =
    match reloc with
    | RelocationPPC32.R_PPC_ADDR32 -> ValueSome SymbolPlusAddend
    | RelocationPPC32.R_PPC_GLOB_DAT
    | RelocationPPC32.R_PPC_JMP_SLOT -> ValueSome SymbolOnly
    | RelocationPPC32.R_PPC_RELATIVE -> ValueSome BasePlusAddend
    | RelocationPPC32.R_PPC_IRELATIVE -> ValueSome IFuncResolver
    | _ -> ValueNone

  /// Classifies a relocation kind of PowerPC64.
  static member OfPPC64(reloc: RelocationPPC64) =
    match reloc with
    | RelocationPPC64.R_PPC64_ADDR32
    | RelocationPPC64.R_PPC64_ADDR64 -> ValueSome SymbolPlusAddend
    | RelocationPPC64.R_PPC64_GLOB_DAT
    | RelocationPPC64.R_PPC64_JMP_SLOT -> ValueSome SymbolOnly
    | RelocationPPC64.R_PPC64_RELATIVE -> ValueSome BasePlusAddend
    | RelocationPPC64.R_PPC64_IRELATIVE -> ValueSome IFuncResolver
    | _ -> ValueNone

  (* R_PARISC_PLABEL32 is deliberately absent: it yields the address of a
     function descriptor rather than that of the symbol itself. *)
  /// Classifies a relocation kind of PARISC.
  static member OfPARISC(reloc: RelocationPARISC) =
    match reloc with
    | RelocationPARISC.R_PARISC_DIR32
    | RelocationPARISC.R_PARISC_DIR64
    | RelocationPARISC.R_PARISC_IPLT
    | RelocationPARISC.R_PARISC_EPLT -> ValueSome SymbolPlusAddend
    | _ -> ValueNone

  /// Classifies a relocation kind of SPARC.
  static member OfSPARC(reloc: RelocationSPARC) =
    match reloc with
    | RelocationSPARC.R_SPARC_8
    | RelocationSPARC.R_SPARC_16
    | RelocationSPARC.R_SPARC_32
    | RelocationSPARC.R_SPARC_64
    | RelocationSPARC.R_SPARC_UA16
    | RelocationSPARC.R_SPARC_UA32
    | RelocationSPARC.R_SPARC_UA64 -> ValueSome SymbolPlusAddend
    | RelocationSPARC.R_SPARC_GLOB_DAT
    | RelocationSPARC.R_SPARC_JMP_SLOT -> ValueSome SymbolOnly
    | RelocationSPARC.R_SPARC_RELATIVE -> ValueSome BasePlusAddend
    | RelocationSPARC.R_SPARC_IRELATIVE -> ValueSome IFuncResolver
    | _ -> ValueNone

  /// Classifies a relocation kind of Alpha.
  static member OfAlpha(reloc: RelocationAlpha) =
    match reloc with
    | RelocationAlpha.R_ALPHA_REFLONG
    | RelocationAlpha.R_ALPHA_REFQUAD -> ValueSome SymbolPlusAddend
    | RelocationAlpha.R_ALPHA_GLOB_DAT
    | RelocationAlpha.R_ALPHA_JMP_SLOT -> ValueSome SymbolOnly
    | RelocationAlpha.R_ALPHA_RELATIVE -> ValueSome BasePlusAddend
    | _ -> ValueNone

  (* The LDI, PM and CALL kinds are left out: each names a byte or a word of an
     address inside an instruction, not a slot holding the address itself. *)
  /// Classifies a relocation kind of AVR.
  static member OfAVR(reloc: RelocationAVR) =
    match reloc with
    | RelocationAVR.R_AVR_8
    | RelocationAVR.R_AVR_16
    | RelocationAVR.R_AVR_32 -> ValueSome SymbolPlusAddend
    | _ -> ValueNone

  (* R_BPF_64_64 and R_BPF_64_32 are left out, both naming an immediate field
     inside an instruction rather than a slot holding an address. *)
  /// Classifies a relocation kind of BPF.
  static member OfBPF(reloc: RelocationBPF) =
    match reloc with
    | RelocationBPF.R_BPF_64_ABS32
    | RelocationBPF.R_BPF_64_ABS64 -> ValueSome SymbolPlusAddend
    | _ -> ValueNone

/// Provides active patterns for matching against architecture-specific
/// relocation kinds.
[<AutoOpen>]
module internal RelocationKind =
  [<return: Struct>]
  let (|RelocationKindX86|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_386 ->
      let reloc: RelocationX86 = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ ->
      ValueNone

  [<return: Struct>]
  let (|RelocationKindX64|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_X86_64 ->
      let reloc: RelocationX64 = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ ->
      ValueNone

  [<return: Struct>]
  let (|RelocationKindARMv7|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_ARM ->
      let reloc: RelocationARMv7 = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ ->
      ValueNone

  [<return: Struct>]
  let (|RelocationKindARMv8|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_AARCH64 ->
      let reloc: RelocationARMv8 = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ ->
      ValueNone

  [<return: Struct>]
  let (|RelocationKindMIPS|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_MIPS ->
      let reloc: RelocationMIPS = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ ->
      ValueNone

  [<return: Struct>]
  let (|RelocationKindM68K|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_68K ->
      let reloc: RelocationM68K = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ ->
      ValueNone

  [<return: Struct>]
  let (|RelocationKindS390|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_S390 ->
      let reloc: RelocationS390 = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ ->
      ValueNone

  [<return: Struct>]
  let (|RelocationKindSH4|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_SH ->
      let reloc: RelocationSH4 = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ ->
      ValueNone

  [<return: Struct>]
  let (|RelocationKindRISCV|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_RISCV ->
      let reloc: RelocationRISCV = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ ->
      ValueNone

  [<return: Struct>]
  let (|RelocationKindPPC32|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_PPC ->
      let reloc: RelocationPPC32 = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ ->
      ValueNone

  [<return: Struct>]
  let (|RelocationKindPPC64|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_PPC64 ->
      let reloc: RelocationPPC64 = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ ->
      ValueNone

  [<return: Struct>]
  let (|RelocationKindPARISC|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_PARISC ->
      let reloc: RelocationPARISC = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ ->
      ValueNone

  [<return: Struct>]
  let (|RelocationKindSPARC|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_SPARC
    | MachineType.EM_SPARC32PLUS
    | MachineType.EM_SPARCV9 ->
      let reloc: RelocationSPARC = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ ->
      ValueNone

  [<return: Struct>]
  let (|RelocationKindAlpha|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_ALPHA
    | MachineType.EM_OLD_ALPHA ->
      let reloc: RelocationAlpha = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ ->
      ValueNone

  [<return: Struct>]
  let (|RelocationKindAVR|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_AVR ->
      let reloc: RelocationAVR = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ ->
      ValueNone

  [<return: Struct>]
  let (|RelocationKindBPF|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_BPF ->
      let reloc: RelocationBPF = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ ->
      ValueNone

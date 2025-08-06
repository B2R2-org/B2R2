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
type RelocationKind = RelocationKind of arch: MachineType * relocValue: uint64
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

  /// Creates a generic RelocationKind from a relocation kind of PARISC
  static member Create(reloc: RelocationPARISC) =
    RelocationKind(MachineType.EM_PARISC, uint64 reloc)

  /// Converts a relocation kind to a string representation.
  static member ToString(RelocationKind(arch, relocValue))=
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
    | MachineType.EM_PARISC ->
      let kind: RelocationPARISC = LanguagePrimitives.EnumOfValue relocValue
      kind.ToString()
    | _ -> invalidArg (nameof arch) "Unsupported architecture for relocation."

/// Represents a relocation type for x86.
and RelocationX86 =
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
and RelocationX64 =
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
and RelocationARMv7 =
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

/// Represents a relocation type for ARMv8.
and RelocationARMv8 =
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

/// Represents a relocation type for MIPS.
and RelocationMIPS =
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

/// Represents a relocation type for S390.
and RelocationS390 =
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

/// Represents a relocation type for SH4.
and RelocationSH4 =
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
and RelocationRISCV =
  | R_RISCV_NONE = 0UL
  | R_RISCV_32 = 1UL
  | R_RISCV_64 = 2UL
  | R_RISCV_RELATIVE = 3UL
  | R_RISCV_COPY = 4UL
  | R_RISCV_JUMP_SLOT = 5UL
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
and RelocationPPC32 =
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
and RelocationPARISC =
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
  | R_PARISC_LORESERVE = 128UL
  | R_PARISC_HIRESERVE = 255UL

/// Provides active patterns for matching against architecture-specific
/// relocation kinds.
[<AutoOpen>]
module RelocationKind =
  [<return: Struct>]
  let (|RelocationKindX86|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_386 ->
      let reloc: RelocationX86 = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ -> ValueNone

  [<return: Struct>]
  let (|RelocationKindX64|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_X86_64 ->
      let reloc: RelocationX64 = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ -> ValueNone

  [<return: Struct>]
  let (|RelocationKindARMv7|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_ARM ->
      let reloc: RelocationARMv7 = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ -> ValueNone

  [<return: Struct>]
  let (|RelocationKindARMv8|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_AARCH64 ->
      let reloc: RelocationARMv8 = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ -> ValueNone

  [<return: Struct>]
  let (|RelocationKindMIPS|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_MIPS ->
      let reloc: RelocationMIPS = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ -> ValueNone

  [<return: Struct>]
  let (|RelocationKindS390|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_S390 ->
      let reloc: RelocationS390 = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ -> ValueNone

  [<return: Struct>]
  let (|RelocationKindSH4|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_SH ->
      let reloc: RelocationSH4 = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ -> ValueNone

  [<return: Struct>]
  let (|RelocationKindRISCV|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_RISCV ->
      let reloc: RelocationRISCV = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ -> ValueNone

  [<return: Struct>]
  let (|RelocationKindPPC32|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_PPC ->
      let reloc: RelocationPPC32 = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ -> ValueNone

  [<return: Struct>]
  let (|RelocationKindPARISC|_|) (RelocationKind(arch, relocValue)) =
    match arch with
    | MachineType.EM_PARISC ->
      let reloc: RelocationPARISC = LanguagePrimitives.EnumOfValue relocValue
      ValueSome reloc
    | _ -> ValueNone

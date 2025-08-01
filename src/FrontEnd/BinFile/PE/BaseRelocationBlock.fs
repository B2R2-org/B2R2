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

namespace B2R2.FrontEnd.BinFile.PE

/// <namespacedoc>
///   <summary>
///   Contains types and functions for working with PE file types.
///   </summary>
/// </namespacedoc>
///
/// <summary>
/// Represents a base relocation block in a PE file. The .reloc section
/// contains a series of base relocation blocks, each of which describes a
/// set of relocations that need to be applied to the image when it is loaded
/// into memory.
/// </summary>
type BaseRelocationBlock =
  { /// The relative virtual address of the block.
    PageRVA: uint32
    /// The size of the block in bytes.
    BlockSize: int32
    /// The entries in the block, which contain the relocation information.
    Entries: RelocBlockEntry[] }

/// Represents an entry in the base relocation block.
and RelocBlockEntry =
  { /// The type of the base relocation.
    Type: BaseRelocType
    /// The offset from the starting address that was specified in the PageRVA
    /// field for the block.
    Offset: uint16 }

/// Represents the base relocation type.
and BaseRelocType =
  /// The base relocation is skipped. This type can be used to pad a block.
  | IMAGE_REL_BASED_ABSOLUTE = 0
  /// The base relocation adds the high 16 bits of the difference to the 16-bit
  /// field at offset. The 16-bit field represents the high value of a 32-bit
  /// word.
  | IMAGE_REL_BASED_HIGH = 1
  /// The base relocation adds the low 16 bits of the difference to the 16-bit
  /// field at offset. The 16-bit field represents the low half of a 32-bit
  /// word.
  | IMAGE_REL_BASED_LOW = 2
  /// The base relocation applies all 32 bits of the difference to the 32-bit
  /// field at offset.
  | IMAGE_REL_BASED_HIGHLOW = 3
  /// The base relocation adds the high 16 bits of the difference to the 16-bit
  /// field at offset. The 16-bit field represents the high value of a 32-bit
  /// word. The low 16 bits of the 32-bit value are stored in the 16-bit word
  /// that follows this base relocation. This means that this base relocation
  /// occupies two slots.
  | IMAGE_REL_BASED_HIGHADJ = 4
  /// The relocation interpretation is dependent on the machine type. When the
  /// machine type is MIPS, the base relocation applies to a MIPS jump
  /// instruction
  | IMAGE_REL_BASED_MIPS_JMPADDR = 5
  /// This relocation is meaningful only when the machine type is ARM or Thumb.
  /// The base relocation applies the 32-bit address of a symbol across a
  /// consecutive MOVW/MOVT instruction pair.
  | IMAGE_REL_BASED_ARM_MOV32 = 5
  /// This relocation is only meaningful when the machine type is RISC-V. The
  /// base relocation applies to the high 20 bits of a 32-bit absolute address.
  | IMAGE_REL_BASED_RISCV_HIGH20 = 5
  /// This relocation is meaningful only when the machine type is Thumb. The
  /// base relocation applies the 32-bit address of a symbol to a consecutive
  /// MOVW/MOVT instruction pair.
  | IMAGE_REL_BASED_THUMB_MOV32 = 7
  /// This relocation is only meaningful when the machine type is RISC-V. The
  /// base relocation applies to the low 12 bits of a 32-bit absolute address
  /// formed in RISC-V I-type instruction format.
  | IMAGE_REL_BASED_RISCV_LOW12I =  7
  /// This relocation is only meaningful when the machine type is RISC-V. The
  /// base relocation applies to the low 12 bits of a 32-bit absolute address
  /// formed in RISC-V S-type instruction format.
  | IMAGE_REL_BASED_RISCV_LOW12S = 8
  /// This relocation is only meaningful when the machine type is LoongArch
  /// 32-bit. The base relocation applies to a 32-bit absolute address formed in
  /// two consecutive instructions.
  | IMAGE_REL_BASED_LOONGARCH32_MARK_LA = 8
  /// This relocation is only meaningful when the machine type is LoongArch
  /// 64-bit. The base relocation applies to a 64-bit absolute address formed in
  /// four consecutive instructions.
  | IMAGE_REL_BASED_LOONGARCH64_MARK_LA = 8
  /// The relocation is only meaningful when the machine type is MIPS. The base
  /// relocation applies to a MIPS16 jump instruction.
  | IMAGE_REL_BASED_MIPS_JMPADDR16 = 9
  /// The base relocation applies the difference to the 64-bit field at offset.
  | IMAGE_REL_BASED_DIR64 = 10

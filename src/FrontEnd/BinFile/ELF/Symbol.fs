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

open B2R2

/// Represents the symbol type of ELF.
type Symbol = {
  /// Address of the symbol.
  Addr: Addr
  /// Symbol's name.
  SymName: string
  /// Size of the symbol (e.g., size of the data object).
  Size: uint64
  /// Symbol binding.
  Bind: SymbolBind
  /// Symbol type.
  SymType: SymbolType
  /// Symbol visibility.
  Vis: SymbolVisibility
  /// The index of the relevant section with regard to this symbol.
  SecHeaderIndex: SectionHeaderIdx
  /// Parent section of this section.
  ParentSection: SectionHeader option
  /// Version information.
  VerInfo: SymVerInfo option
  /// ARM32-specific linker symbol type.
  ARMLinkerSymbol: ARMLinkerSymbol
}
with
  /// Checks if the given symbol is a function symbol.
  static member inline IsFunction (s: Symbol) =
    s.SymType = SymbolType.STT_FUNC || s.SymType = SymbolType.STT_GNU_IFUNC

  /// Checks if the given symbol is defined. A symbol is defined if it has a
  /// section header index that is not SHN_UNDEF.
  static member inline IsDefined (s: Symbol) =
    s.SecHeaderIndex <> SHN_UNDEF

  /// Returns the library name of the symbol. This is only valid if the symbol
  /// has version information.
  member this.LibName with get () =
    match this.VerInfo with
    | Some version -> version.VerName
    | None -> ""

/// Represents the relevant section header index of a symbol. Every symbol table
/// entry is defined in relation to some section.
and SectionHeaderIdx =
  /// The symbol is undefined. Linker should update references to this symbol
  /// with the actual definition from another file.
  | SHN_UNDEF
  /// The symbol has an absolute value that will not change because of
  /// relocation.
  | SHN_ABS
  /// The symbol labels a common block that has not yet been allocated.
  | SHN_COMMON
  /// An escape value indicating that the actual section header index is too
  /// large to fit in the containing field. The header section index is found in
  /// another location specific to the structure where it appears.
  | SHN_XINDEX
  /// This symbol index holds an index into the section header table.
  | SectionIndex of int
with
  /// Converts an integer to a section header index.
  static member IndexFromInt n =
    match n with
    | 0x00 -> SHN_UNDEF
    | 0xfff1 -> SHN_ABS
    | 0xfff2 -> SHN_COMMON
    | n -> SectionIndex n

  /// Converts the section header index to a string.
  static member ToString idx =
    match idx with
    | SHN_UNDEF -> "UNDEF"
    | SHN_ABS -> "ABS"
    | SHN_COMMON -> "COMMON"
    | SHN_XINDEX -> "XINDEX"
    | SectionIndex n -> $"{n}"

/// Represents the version information of a symbol.
and SymVerInfo = {
  /// Is this a hidden symbol? This is a GNU-specific extension indicated as
  /// VERSYM_HIDDEN.
  IsHidden: bool
  /// Version string.
  VerName: string
}

/// Represents an ARM-specific symbol type for ELF binaries, which are used to
/// distinguish between ARM and Thumb instructions. For other CPU architectures,
/// this will be set to None.
and ARMLinkerSymbol =
  | ARM = 1
  | Thumb = 2
  | None = 3

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

/// Represents a section object defined in a file-format-agnostic way. A Section
/// in B2R2 should be located inside a segment.
type Section = {
  /// Address of the section.
  Address: Addr
  /// File offset of the section.
  FileOffset: uint32
  /// Section kind.
  Kind: SectionKind
  /// Size of the section.
  Size: uint32
  /// Name of the section.
  Name: string
}
with
  /// Convert the section into an AddrRange based on its starting address and
  /// the size.
  member this.ToAddrRange () =
    AddrRange (this.Address, this.Address + uint64 this.Size - 1UL)

  override this.ToString () =
    $"Section [{this.Name}] ({this.Kind}) \
      @ {this.Address:x}-{(this.Address + uint64 this.Size):x} \
      @ {this.FileOffset:x}"

/// Represents the kind of a section, which is used to classify sections in a
/// binary file in a file-format-agnostic way.
and SectionKind =
  /// Executable code section.
  | CodeSection = 1
  /// Linkage table, such as PLT, section.
  | LinkageTableSection = 2
  /// Data section that contains initialized data, e.g., .data section.
  | InitializedDataSection = 3
  /// Data section that contains uninitialized data, e.g., .bss section.
  | UninitializedDataSection = 4
  /// Read-only data section, e.g., .rodata section.
  | ReadOnlyDataSection = 5
  /// Extra section that does not fit into the above categories.
  | ExtraSection = 6

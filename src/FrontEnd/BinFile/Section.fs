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

/// Kinds of sections.
type SectionKind =
  /// Executable section.
  | ExecutableSection = 1
  /// Writable section.
  | WritableSection = 2
  /// Linkage table, such as PLT, section.
  | LinkageTableSection = 3
  /// Extra section.
  | ExtraSection = 4

/// A section object defined in a file-format-agnostic way. A Section in B2R2
/// should be located inside a segment.
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
  member __.ToAddrRange () =
    AddrRange (__.Address, __.Address + uint64 __.Size - 1UL)

  override __.ToString () =
    $"Section [{__.Name}] ({__.Kind}) \
      @ {__.Address:x}-{(__.Address + uint64 __.Size):x} \
      @ {__.FileOffset:x}"

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

/// Represents miscellaneous attributes of a section.
[<FlagsAttribute>]
type SectionFlags =
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

/// Provides functions to convert section flags to string.
[<RequireQualifiedAccess>]
module SectionFlags =
  /// Returns the string representation of the section flags.
  [<CompiledName "ToString">]
  let toString (flags: SectionFlags) =
    [ if flags.HasFlag SectionFlags.SHF_WRITE then "WRITE"
      if flags.HasFlag SectionFlags.SHF_ALLOC then "ALLOC"
      if flags.HasFlag SectionFlags.SHF_EXECINSTR then "EXECINSTR"
      if flags.HasFlag SectionFlags.SHF_MERGE then "MERGE"
      if flags.HasFlag SectionFlags.SHF_STRINGS then "STRINGS"
      if flags.HasFlag SectionFlags.SHF_INFO_LINK then "INFO_LINK"
      if flags.HasFlag SectionFlags.SHF_LINK_ORDER then "LINK_ORDER"
      if flags.HasFlag SectionFlags.SHF_OS_NONCONFORMING then "OS_NONCONFORMING"
      if flags.HasFlag SectionFlags.SHF_GROUP then "GROUP"
      if flags.HasFlag SectionFlags.SHF_TLS then "TLS"
      if flags.HasFlag SectionFlags.SHF_COMPRESSED then "COMPRESSED"
      if flags.HasFlag SectionFlags.SHF_MASKOS then "MASKOS"
      if flags.HasFlag SectionFlags.SHF_MASKPROC then "MASKPROC"
      if flags.HasFlag SectionFlags.SHF_ORDERED then "ORDERED"
      if flags.HasFlag SectionFlags.SHF_EXCLUDE then "EXCLUDE"
      if flags.HasFlag SectionFlags.SHF_X86_64_LARGE then "X86_64_LARGE" ]
    |> String.concat ","

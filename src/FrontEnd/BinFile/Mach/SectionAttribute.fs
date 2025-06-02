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

namespace B2R2.FrontEnd.BinFile.Mach

open System

/// Represents the attributes of Mach-O section.
[<FlagsAttribute>]
type SectionAttribute =
  /// Section contains only true machine instructions.
  | S_ATTR_PURE_INSTRUCTIONS = 0x80000000
  /// Section contains coalesced symbols that are not to be in a ranlib table of
  /// contents.
  | S_ATTR_NO_TOC = 0x40000000
  /// OK to strip static symbols in this section in files with the MH_DYLDLINK
  /// flag.
  | S_ATTR_STRIP_STATIC_SYMS = 0x20000000
  /// No dead stripping.
  | S_ATTR_NO_DEAD_STRIP = 0x10000000
  /// Blocks are live if they reference live blocks.
  | S_ATTR_LIVE_SUPPORT = 0x08000000
  /// Used with i386 code stubs written on by dyld.
  | S_ATTR_SELF_MODIFYING_CODE = 0x04000000
  /// Debug section.
  | S_ATTR_DEBUG = 0x02000000
  /// Section has external relocation entries.
  | S_ATTR_EXT_RELOC = 0x00000200
  /// Section has local relocation entries.
  | S_ATTR_LOC_RELOC = 0x00000100

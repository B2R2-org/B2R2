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
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile.FileHelper

/// Section type.
type SectionType =
  /// Regular section.
  | S_REGULAR = 0x0
  /// Zero fill on demand section.
  | S_ZEROFILL = 0x1
  /// Section with only literal C strings.
  | S_CSTRING_LITERALS = 0x2
  /// Section with only 4 byte literals.
  | S_4BYTE_LITERALS = 0x3
  /// Section with only 8 byte literals.
  | S_8BYTE_LITERALS = 0x4
  /// section with only pointers to literals.
  | S_LITERAL_POINTERS = 0x5
  /// Section with only non-lazy symbol pointers .
  | S_NON_LAZY_SYMBOL_POINTERS = 0x6
  /// Section with only lazy symbol pointers.
  | S_LAZY_SYMBOL_POINTERS = 0x7
  /// Section with only symbol stubs, byte size of stub in the reserved2 field.
  | S_SYMBOL_STUBS = 0x8
  /// Section with only function pointers for initialization.
  | S_MOD_INIT_FUNC_POINTERS = 0x9
  /// Section with only function pointers for termination.
  | S_MOD_TERM_FUNC_POINTERS = 0xa
  /// Section contains symbols that are to be coalesced.
  | S_COALESCED = 0xb
  /// Zero fill on demand section (this can be larger than 4 gigabytes).
  | S_GB_ZEROFILL = 0xc
  /// Section with only pairs of function pointers for interposing.
  | S_INTERPOSING = 0xd
  /// Section with only 16 byte literals.
  | S_16BYTE_LITERALS = 0xe
  /// Section contains DTrace Object Format.
  | S_DTRACE_DOF = 0xf
  /// Section with only lazy symbol pointers to lazy loaded dylibs.
  | S_LAZY_DYLIB_SYMBOL_POINTERS = 0x10
  /// Template of initial values for TLVs.
  | S_THREAD_LOCAL_REGULAR = 0x11
  /// Template of initial values for TLVs.
  | S_THREAD_LOCAL_ZEROFILL = 0x12
  /// TLV descriptors.
  | S_THREAD_LOCAL_VARIABLES = 0x13
  /// Pointers to TLV descriptors.
  | S_THREAD_LOCAL_VARIABLE_POINTERS = 0x14
  /// Functions to call to initialize TLV values .
  | S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15

/// Section attribute.
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

/// Mach-O section.
type MachSection = {
  /// Section name.
  SecName: string
  /// The name of the segment that should eventually contain this section.
  SegName: string
  /// The virtual memory address of this section.
  SecAddr: Addr
  /// The size of this section.
  SecSize: uint64
  /// The offset to this section in the file.
  SecOffset: uint32
  /// The section's byte alignment.
  SecAlignment: uint32
  /// The file offset of the first relocation entry for this section.
  SecRelOff: uint32
  /// The number of relocation entries located at SecRelOff for this section.
  SecNumOfReloc: int
  /// Section type.
  SecType: SectionType
  /// Section attributes.
  SecAttrib: SectionAttribute
  /// Reserved field 1.
  SecReserved1: int
  /// Reserved field 2.
  SecReserved2: int
}

module internal Section =
  let [<Literal>] SecText = "__text"

  let private parseSection toolBox (span: ByteSpan) offset =
    let cls = toolBox.Header.Class
    let reader = toolBox.Reader
    let span = span.Slice offset
    let secFlag = reader.ReadInt32 (span, pickNum cls 56 64)
    { SecName = readCString span 0
      SegName = readCString span 16
      SecAddr = readUIntOfType span reader cls 32 + toolBox.BaseAddress
      SecSize = readNative span reader cls 36 40
      SecOffset = reader.ReadUInt32 (span, pickNum cls 40 48)
      SecAlignment = reader.ReadUInt32 (span, pickNum cls 44 52)
      SecRelOff = reader.ReadUInt32 (span, pickNum cls 48 56)
      SecNumOfReloc = reader.ReadInt32 (span, pickNum cls 52 60)
      SecType = secFlag &&& 0xFF |> LanguagePrimitives.EnumOfValue
      SecAttrib = secFlag &&& 0xFFFFFF00 |> LanguagePrimitives.EnumOfValue
      SecReserved1 = reader.ReadInt32 (span, pickNum cls 60 68)
      SecReserved2 = reader.ReadInt32 (span, pickNum cls 64 72) }

  let private countSections segCmds =
    segCmds
    |> Array.fold (fun cnt seg -> cnt + int seg.NumSecs) 0

  let parse ({ Bytes = bytes; Header = hdr } as toolBox) segCmds =
    let numSections = countSections segCmds
    let sections = Array.zeroCreate numSections
    let mutable idx = 0
    for seg in segCmds do
      let entrySize = pickNum hdr.Class 68 80
      let sectionSize = entrySize * int seg.NumSecs
      let sectionOffset = int toolBox.MachOffset + seg.SecOff
      let sectionSpan = ReadOnlySpan (bytes, sectionOffset, sectionSize)
      for i = 0 to int seg.NumSecs - 1 do
        let offset = i * entrySize
        sections[idx] <- parseSection toolBox sectionSpan offset
        idx <- idx + 1
    sections

  let getTextSectionIndex secs =
    secs |> Array.findIndex (fun s -> s.SecName = SecText)

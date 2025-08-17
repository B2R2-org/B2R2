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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.FileHelper

/// Represents a Mach-O section.
type Section =
  { /// Section name.
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
    SecReserved2: int }

module internal Section =
  let [<Literal>] SecText = "__text"

  let private parseSection toolBox (span: ByteSpan) offset =
    let cls = toolBox.Header.Class
    let reader = toolBox.Reader
    let span = span.Slice offset
    let secFlag = reader.ReadInt32(span, selectByWordSize cls 56 64)
    { SecName = readCString span 0
      SegName = readCString span 16
      SecAddr = readUIntByWordSize span reader cls 32 + toolBox.BaseAddress
      SecSize = readUIntByWordSizeAndOffset span reader cls 36 40
      SecOffset = reader.ReadUInt32(span, selectByWordSize cls 40 48)
      SecAlignment = reader.ReadUInt32(span, selectByWordSize cls 44 52)
      SecRelOff = reader.ReadUInt32(span, selectByWordSize cls 48 56)
      SecNumOfReloc = reader.ReadInt32(span, selectByWordSize cls 52 60)
      SecType = secFlag &&& 0xFF |> LanguagePrimitives.EnumOfValue
      SecAttrib = secFlag &&& 0xFFFFFF00 |> LanguagePrimitives.EnumOfValue
      SecReserved1 = reader.ReadInt32(span, selectByWordSize cls 60 68)
      SecReserved2 = reader.ReadInt32(span, selectByWordSize cls 64 72) }

  let private countSections segCmds =
    segCmds
    |> Array.fold (fun cnt seg -> cnt + int seg.NumSecs) 0

  let parse ({ Bytes = bytes; Header = hdr } as toolBox) segCmds =
    let numSections = countSections segCmds
    let sections = Array.zeroCreate numSections
    let mutable idx = 0
    for seg in segCmds do
      let entrySize = selectByWordSize hdr.Class 68 80
      let sectionSize = entrySize * int seg.NumSecs
      let sectionOffset = seg.SecOff
      let sectionSpan = ReadOnlySpan(bytes, sectionOffset, sectionSize)
      for i = 0 to int seg.NumSecs - 1 do
        let offset = i * entrySize
        sections[idx] <- parseSection toolBox sectionSpan offset
        idx <- idx + 1
    sections

  let getTextSectionIndex secs =
    secs |> Array.findIndex (fun s -> s.SecName = SecText)

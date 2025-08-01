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
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

/// Represents a program header in ELF. A program header describes a segment of
/// the program.
type ProgramHeader =
  { /// Program header type.
    PHType: ProgramHeaderType
    /// Flags relevant to the segment.
    PHFlags: int
    /// An offset from the beginning of the file at which the first byte of the
    /// segment resides in memory.
    PHOffset: uint64
    /// The virtual address at which the first byte of the segment resides in
    /// memory.
    PHAddr: Addr
    /// The physical address of the segment. This is reserved for systems using
    /// physical addresses.
    PHPhyAddr: Addr
    /// The number of bytes in the file image of the segment.
    PHFileSize: uint64
    /// The number of bytes in the memory image of the segment. This can be
    /// greater than PHFileSize as some sections (w/ SHTNoBits type) occupy
    /// nothing in the binary file, but can be mapped in the segment at runtime.
    PHMemSize: uint64
    /// The value to which the segments are aligned in memory and in the file.
    PHAlignment: uint64 }
with
  /// Converts the PHFlags field of a program header to a Permission value.
  static member inline FlagsToPerm(flag: int): Permission =
    flag &&& 7 |> LanguagePrimitives.EnumOfValue

[<RequireQualifiedAccess>]
module internal ProgramHeaders =
  let parseProgHeader toolBox (span: ByteSpan) =
    let reader, cls = toolBox.Reader, toolBox.Header.Class
    let phType = reader.ReadUInt32(span, 0)
    let baseAddr = toolBox.BaseAddress
    { PHType = LanguagePrimitives.EnumOfValue phType
      PHFlags = reader.ReadInt32(span, selectByWordSize cls 24 4)
      PHOffset = readUIntByWordSizeAndOffset span reader cls 4 8
      PHAddr = readUIntByWordSizeAndOffset span reader cls 8 16 + baseAddr
      PHPhyAddr = readUIntByWordSizeAndOffset span reader cls 12 24
      PHFileSize = readUIntByWordSizeAndOffset span reader cls 16 32
      PHMemSize = readUIntByWordSizeAndOffset span reader cls 20 40
      PHAlignment = readUIntByWordSizeAndOffset span reader cls 28 48 }

  /// Parse program headers and returns them as an array.
  let parse ({ Bytes = bytes; Header = hdr } as toolBox) =
    let entrySize = selectByWordSize hdr.Class 32 56
    let numEntries = int hdr.PHdrNum
    let progHeaders = Array.zeroCreate numEntries
    for i = 0 to numEntries - 1 do
      let offset = int hdr.PHdrTblOffset + i * entrySize
      let span = ReadOnlySpan(bytes, offset, entrySize)
      progHeaders[i] <- parseProgHeader toolBox span
    progHeaders

  let filterLoadables (progHeaders: ProgramHeader[]) =
    progHeaders
    |> Array.filter (fun ph -> ph.PHType = ProgramHeaderType.PT_LOAD)

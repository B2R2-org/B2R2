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
open System.IO
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

/// This member tells what kind of segment this array element describes or
/// how to interpret the array element's information. A segment is also known as
/// a 'program header'.
type ProgramHeaderType =
  /// This program header is not used.
  | PT_NULL = 0x00u
  /// This is a loadable segment.
  | PT_LOAD = 0x01u
  /// This segment contains dynamic linking information.
  | PT_DYNAMIC = 0x02u
  /// This segment contains the location and size of a null-terminated path name
  /// to invoke an interpreter. This segment type is meaningful only for
  /// executable files, but not for shared objects. This segment may not occur
  /// more than once in a file. If it is present, it must precede any loadable
  /// segment entry.
  | PT_INTERP = 0x03u
  /// This segment contains the location and size of auxiliary information.
  | PT_NOTE = 0x04u
  /// This segment type is reserved but has unspecified semantics.
  | PT_SHLIB = 0x05u
  /// This segment specifies the location and size of the program header table
  /// itself, It may occur only if the program header table is part of the
  /// memory image of the program. If it is present, it must precede any
  /// loadable segment entry.
  | PT_PHDR = 0x06u
  /// This segment contains the Thread-Local Storage template.
  | PT_TLS = 0x07u
  /// The lower bound of OS-specific program header type.
  | PT_LOOS = 0x60000000u
  /// The upper bound of OS-specific program header type.
  | PT_HIOS = 0x6fffffffu
  /// This segment specifies the location and size of the exception handling
  /// information as defined by the .eh_frame_hdr section.
  | PT_GNU_EH_FRAME = 0x6474e550u
  /// This segment specifies the permissions on the segment containing the stack
  /// and is used to indicate weather the stack should be executable. The
  /// absence of this header indicates that the stack will be executable.
  | PT_GNU_STACK = 0x6474e551u
  /// This segment specifies the location and size of a segment which may be
  /// made read-only after relocations have been processed.
  | PT_GNU_RELRO = 0x6474e552u
  /// This segment contains PAX flags.
  | PT_PAX_FLAGS = 0x65041580u
  /// The lower bound of processor-specific program header type.
  | PT_LOPROC = 0x70000000u
  /// The exception unwind table.
  | PT_ARM_EXIDX = 0x70000001u
  /// MIPS ABI flags.
  | PT_MIPS_ABIFLAGS = 0x70000003u
  /// The upper bound of processor-specific program header type.
  | PT_HIPROC = 0x7fffffffu

/// An executable or shared object file's program header table is an array of
/// structures, each of which describes a segment or the other information a
/// system needs to prepare for execution. An object file segment contains one
/// or more sections. Program headers are meaningful only for executable and
/// shared object files. A file specifies its own program header size with
/// the ELF header's members.
type ProgramHeader = {
  /// Program header type.
  PHType: ProgramHeaderType
  /// Flags relevant to the segment.
  PHFlags: Permission
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
  PHAlignment: uint64
}

module ProgramHeader =
  let peekPHdrFlags (span: ByteSpan) (reader: IBinReader) cls =
    reader.ReadInt32 (span, pickNum cls 24 4)
    |> LanguagePrimitives.EnumOfValue

  let parseProgHeader toolBox (span: ByteSpan) =
    let reader, cls = toolBox.Reader, toolBox.Header.Class
    let phType = reader.ReadUInt32 (span, 0)
    { PHType = LanguagePrimitives.EnumOfValue phType
      PHFlags = peekPHdrFlags span reader cls
      PHOffset = readNative span reader cls 4 8
      PHAddr = readNative span reader cls 8 16 + toolBox.BaseAddress
      PHPhyAddr = readNative span reader cls 12 24
      PHFileSize = readNative span reader cls 16 32
      PHMemSize = readNative span reader cls 20 40
      PHAlignment = readNative span reader cls 28 48 }

  /// Parse program headers and returns them as an array.
  let parse toolBox =
    let stream = toolBox.Stream
    let hdr = toolBox.Header
    let buf = Array.zeroCreate (pickNum hdr.Class 32 56)
    let numEntries = int hdr.PHdrNum
    let progHeaders = Array.zeroCreate numEntries
    stream.Seek (int64 hdr.PHdrTblOffset, SeekOrigin.Begin) |> ignore
    let rec parseLoop count =
      if count = numEntries then progHeaders
      else
        readOrDie stream buf
        let phdr = parseProgHeader toolBox (ReadOnlySpan buf)
        progHeaders[count] <- phdr
        parseLoop (count + 1)
    parseLoop 0

  let getLoadableProgHeaders (progHeaders: ProgramHeader[]) =
    progHeaders
    |> Array.filter (fun ph -> ph.PHType = ProgramHeaderType.PT_LOAD)

  let toSegment phdr =
    { Address = phdr.PHAddr
      Offset = uint32 phdr.PHOffset
      Size = uint32 phdr.PHMemSize
      SizeInFile = uint32 phdr.PHFileSize
      Permission = phdr.PHFlags }

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

module internal B2R2.BinFile.ELF.Header

open B2R2
open B2R2.BinFile.FileHelper

let private elfMagicNumber = [| 0x7fuy; 0x45uy; 0x4cuy; 0x46uy |]

/// Check if the file has a valid ELF header.
let isELF (reader: BinReader) offset =
  reader.Length() > offset + sizeof<uint32> &&
  reader.PeekBytes (4, offset) = elfMagicNumber

let peekClass (reader: BinReader) offset =
  match offset + 4 |> reader.PeekByte with
  | 0x1uy -> WordSize.Bit32
  | 0x2uy -> WordSize.Bit64
  | _ -> raise InvalidWordSizeException

let peekEndianness (reader: BinReader) offset =
  match offset + 5 |> reader.PeekByte with
  | 0x1uy -> Endian.Little
  | 0x2uy -> Endian.Big
  | _ -> raise InvalidEndianException


let peekELFFileType (reader: BinReader) offset: ELFFileType =
  offset + 16 |> reader.PeekUInt16 |> LanguagePrimitives.EnumOfValue

let peekELFFlags reader cls offset =
  peekHeaderU32 reader cls offset 36 48

let getMIPSISA (reader: BinReader) cls offset =
  match peekELFFlags reader cls offset &&& 0xf0000000u with
  | 0x00000000u -> Arch.MIPS1
  | 0x10000000u -> Arch.MIPS2
  | 0x20000000u -> Arch.MIPS3
  | 0x30000000u -> Arch.MIPS4
  | 0x40000000u -> Arch.MIPS5
  | 0x50000000u -> Arch.MIPS32
  | 0x60000000u -> Arch.MIPS64
  | 0x70000000u -> Arch.MIPS32R2
  | 0x80000000u -> Arch.MIPS64R2
  | 0x90000000u -> Arch.MIPS32R6
  | 0xa0000000u -> Arch.MIPS64R6
  | c -> failwithf "invalid MIPS arch (%02x)" c

let peekArch (reader: BinReader) cls offset =
  match offset + 18 |> reader.PeekInt16 with
  | 0x03s -> Arch.IntelX86
  | 0x3es -> Arch.IntelX64
  | 0x28s -> Arch.ARMv7
  | 0xB7s -> Arch.AARCH64
  | 0x08s
  | 0x0as -> getMIPSISA reader cls offset
  | _ -> Arch.UnknownISA

let parse baseAddr offset (reader: BinReader) =
  let cls = peekClass reader offset
  {
    Class = cls
    Endian = peekEndianness reader offset
    Version = peekHeaderU32 reader cls offset 6 6
    OSABI = offset + 7 |> reader.PeekByte |> LanguagePrimitives.EnumOfValue
    OSABIVersion = offset + 8 |> reader.PeekByte |> uint32
    ELFFileType = peekELFFileType reader offset
    MachineType = peekArch reader cls offset
    EntryPoint = peekHeaderNative reader cls offset 24 24 + baseAddr
    PHdrTblOffset = peekHeaderNative reader cls offset 28 32
    SHdrTblOffset = peekHeaderNative reader cls offset 32 40
    ELFFlags = peekELFFlags reader cls offset
    HeaderSize = peekHeaderU16 reader cls offset 40 52
    PHdrEntrySize = peekHeaderU16 reader cls offset 42 54
    PHdrNum = peekHeaderU16 reader cls offset 44 56
    SHdrEntrySize = peekHeaderU16 reader cls offset 46 58
    SHdrNum = peekHeaderU16 reader cls offset 48 60
    SHdrStrIdx = peekHeaderU16 reader cls offset 50 62
  }

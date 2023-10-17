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
open B2R2.FrontEnd.BinFile.FileHelper

module internal Header =
  let private elfMagicNumber = [| 0x7fuy; 0x45uy; 0x4cuy; 0x46uy |]

  /// Check if the file has a valid ELF header.
  let isELF (span: ByteSpan) =
    span.Length > 4
    && span.Slice(0, 4).SequenceEqual (ReadOnlySpan elfMagicNumber)

  let peekClass (span: ByteSpan) =
    match span[4] with
    | 0x1uy -> WordSize.Bit32
    | 0x2uy -> WordSize.Bit64
    | _ -> raise InvalidWordSizeException

  let peekEndianness (span: ByteSpan) =
    match span[5] with
    | 0x1uy -> Endian.Little
    | 0x2uy -> Endian.Big
    | _ -> raise InvalidEndianException

  let peekELFFileType (span: ByteSpan) (reader: IBinReader) =
    reader.ReadUInt16 (span, 16)
    |> LanguagePrimitives.EnumOfValue: ELFFileType

  let peekELFFlags span reader cls =
    peekHeaderU32 span reader cls 36 48

  let getMIPSISA span reader cls =
    match peekELFFlags span reader cls &&& 0xf0000000u with
    | 0x00000000u
    | 0x10000000u
    | 0x20000000u
    | 0x30000000u
    | 0x40000000u
    | 0x50000000u
    | 0x70000000u
    | 0x90000000u -> Arch.MIPS32
    | 0x60000000u
    | 0x80000000u
    | 0xa0000000u -> Arch.MIPS64
    | c -> failwithf "invalid MIPS arch (%02x)" c

  let peekArch (span: ByteSpan) (reader: IBinReader) cls =
    match reader.ReadInt16 (span, 18) with
    | 0x03s -> Arch.IntelX86
    | 0x3es -> Arch.IntelX64
    | 0x28s -> Arch.ARMv7
    | 0xb7s -> Arch.AARCH64
    | 0x08s | 0x0as -> getMIPSISA span reader cls
    | 0x53s -> Arch.AVR
    | 0x2as -> Arch.SH4
    | 0x14s -> Arch.PPC32
    | 0x2bs -> Arch.SPARC
    | 0xf3s -> Arch.RISCV64 (* FIXME: RISCV *)
    | _ -> Arch.UnknownISA

  let computeNewBaseAddr ftype baseAddr =
    match ftype with
    | ELFFileType.Executable -> 0UL (* Non-PIEs must have zero base. *)
    | _ -> defaultArg baseAddr 0UL

  let parse span (reader: IBinReader) baseAddrOpt =
    let cls = peekClass span
    let ftype = peekELFFileType span reader
    let baseAddr = computeNewBaseAddr ftype baseAddrOpt
    let hdr =
      { Class = cls
        Endian = peekEndianness span
        Version = peekHeaderU32 span reader cls 6 6
        OSABI = span[7] |> LanguagePrimitives.EnumOfValue
        OSABIVersion = span[8] |> uint32
        ELFFileType = ftype
        MachineType = peekArch span reader cls
        EntryPoint = peekHeaderNative span reader cls 24 24 + baseAddr
        PHdrTblOffset = peekHeaderNative span reader cls 28 32
        SHdrTblOffset = peekHeaderNative span reader cls 32 40
        ELFFlags = peekELFFlags span reader cls
        HeaderSize = peekHeaderU16 span reader cls 40 52
        PHdrEntrySize = peekHeaderU16 span reader cls 42 54
        PHdrNum = peekHeaderU16 span reader cls 44 56
        SHdrEntrySize = peekHeaderU16 span reader cls 46 58
        SHdrNum = peekHeaderU16 span reader cls 48 60
        SHdrStrIdx = peekHeaderU16 span reader cls 50 62 }
    struct (hdr, baseAddr)

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

module B2R2.FrontEnd.BinFile.Mach.Header

open B2R2
open B2R2.FrontEnd.BinFile

let internal peekMagic (span: ByteSpan) reader =
  if span.Length > 4
  then (reader: IBinReader).ReadUInt32 (span, 0)
  else 0ul
  |> LanguagePrimitives.EnumOfValue

let isFat span reader =
  match peekMagic span reader with
  | Magic.FATCigam | Magic.FATMagic -> true
  | _ -> false

let isMach span =
  let reader = BinReader.binReaderLE
  match peekMagic span reader with
  | Magic.MHCigam | Magic.MHCigam64 | Magic.MHMagic | Magic.MHMagic64 -> true
  | _ -> isFat span reader

let internal peekCPUType (span: ByteSpan) (reader: IBinReader) =
  reader.ReadInt32 (span, 4) |> LanguagePrimitives.EnumOfValue

let internal peekCPUSubType (span: ByteSpan) (reader: IBinReader) =
  reader.ReadInt32 (span, 8) |> LanguagePrimitives.EnumOfValue

let internal getMIPSArch = function
  | CPUSubType.MIPSAll
  | CPUSubType.MIPSR2300
  | CPUSubType.MIPSR2600
  | CPUSubType.MIPSR2800
  | CPUSubType.MIPSR2000A -> Arch.MIPS32 (* MIPS32R2 *)
  | _ -> raise InvalidISAException

let cpuTypeToArch cputype subtype =
  match cputype with
  | CPUType.I386 -> Arch.IntelX86
  | CPUType.X64 -> Arch.IntelX64
  | CPUType.ARM -> Arch.ARMv7
  | CPUType.ARM64 -> Arch.AARCH64
  | CPUType.MIPS -> getMIPSArch subtype
  | _ -> Arch.UnknownISA

let internal peekArch span reader =
  let cputype = peekCPUType span reader
  let subtype = peekCPUSubType span reader
  cpuTypeToArch cputype subtype

let internal peekClass span reader =
  match peekMagic span reader with
  | Magic.MHMagic | Magic.MHCigam -> WordSize.Bit32
  | Magic.MHMagic64 | Magic.MHCigam64 -> WordSize.Bit64
  | _ -> raise FileFormatMismatchException

let internal magicToEndian = function
  | Magic.MHMagic | Magic.MHMagic64 | Magic.FATMagic -> Endian.Little
  | Magic.MHCigam | Magic.MHCigam64 | Magic.FATCigam -> Endian.Big
  | _ -> raise FileFormatMismatchException

let internal peekEndianness span reader =
  peekMagic span reader
  |> magicToEndian

/// Detect the endianness and return an appropriate IBinReader.
let internal getMachBinReader span =
  match peekEndianness span BinReader.binReaderLE with
  | Endian.Little -> BinReader.binReaderLE
  | Endian.Big -> BinReader.binReaderBE
  | _ -> Utils.impossible ()

let internal parse span reader =
  { Magic = peekMagic span reader
    Class = peekClass span reader
    CPUType = peekCPUType span reader
    CPUSubType = peekCPUSubType span reader
    FileType = reader.ReadInt32 (span, 12) |> LanguagePrimitives.EnumOfValue
    NumCmds = reader.ReadUInt32 (span, 16)
    SizeOfCmds = reader.ReadUInt32 (span, 20)
    Flags = reader.ReadInt32 (span, 24) |> LanguagePrimitives.EnumOfValue }
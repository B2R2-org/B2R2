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

let internal peekMagic (reader: BinReader) offset =
  if reader.Length() > offset + sizeof<uint32>
  then reader.PeekUInt32 offset
  else 0ul
  |> LanguagePrimitives.EnumOfValue

let isFat reader offset =
  match peekMagic reader offset with
  | Magic.FATCigam | Magic.FATMagic -> true
  | _ -> false

let isMach reader offset =
  match peekMagic reader offset with
  | Magic.MHCigam | Magic.MHCigam64 | Magic.MHMagic | Magic.MHMagic64 -> true
  | _ -> isFat reader offset

let internal peekCPUType (reader: BinReader) offset =
  offset + 4 |> reader.PeekInt32 |> LanguagePrimitives.EnumOfValue

let internal peekCPUSubType (reader: BinReader) offset =
  offset + 8 |> reader.PeekInt32 |> LanguagePrimitives.EnumOfValue

let internal getMIPSArch = function
  | CPUSubType.MIPSAll
  | CPUSubType.MIPSR2300
  | CPUSubType.MIPSR2600
  | CPUSubType.MIPSR2800
  | CPUSubType.MIPSR2000A -> Arch.MIPS32R2
  | _ -> raise InvalidISAException

let cpuTypeToArch cputype subtype =
  match cputype with
  | CPUType.I386 -> Arch.IntelX86
  | CPUType.X64 -> Arch.IntelX64
  | CPUType.ARM -> Arch.ARMv7
  | CPUType.ARM64 -> Arch.AARCH64
  | CPUType.MIPS -> getMIPSArch subtype
  | _ -> Arch.UnknownISA

let internal peekArch reader offset =
  let cputype = peekCPUType reader offset
  let subtype = peekCPUSubType reader offset
  cpuTypeToArch cputype subtype

let internal peekClass reader offset =
  match peekMagic reader offset with
  | Magic.MHMagic | Magic.MHCigam -> WordSize.Bit32
  | Magic.MHMagic64 | Magic.MHCigam64 -> WordSize.Bit64
  | _ -> raise FileFormatMismatchException

let internal magicToEndian = function
  | Magic.MHMagic | Magic.MHMagic64 -> Endian.Little
  | Magic.MHCigam | Magic.MHCigam64 -> Endian.Big
  | _ -> raise FileFormatMismatchException

let internal peekEndianness reader offset =
  peekMagic reader offset |> magicToEndian

let internal parse reader offset =
  { Magic = peekMagic reader offset
    Class = peekClass reader offset
    CPUType = peekCPUType reader offset
    CPUSubType = peekCPUSubType reader offset
    FileType = offset + 12 |> reader.PeekInt32 |> LanguagePrimitives.EnumOfValue
    NumCmds = offset + 16 |> reader.PeekUInt32
    SizeOfCmds = offset + 20 |> reader.PeekUInt32
    Flags = offset + 24 |> reader.PeekInt32 |> LanguagePrimitives.EnumOfValue }
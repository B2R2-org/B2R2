(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

module B2R2.BinFile.Mach.Header

open B2R2
open B2R2.BinFile

let peekMagic (reader : BinReader) offset =
  reader.PeekUInt32 offset |> LanguagePrimitives.EnumOfValue

let isMach (reader : BinReader) offset =
  match peekMagic reader offset with
  | Magic.MHCigam | Magic.MHCigam64 | Magic.MHMagic | Magic.MHMagic64 -> true
  | _ -> false

let peekCPUType (reader: BinReader) offset =
  offset + 4 |> reader.PeekInt32 |> LanguagePrimitives.EnumOfValue

let peekCPUSubType (reader: BinReader) offset =
  offset + 8 |> reader.PeekInt32 |> LanguagePrimitives.EnumOfValue

let getMIPSISA (reader: BinReader) offset =
  match peekCPUSubType reader offset with
  | CPUSubType.MIPSAll
  | CPUSubType.MIPSR2300
  | CPUSubType.MIPSR2600
  | CPUSubType.MIPSR2800
  | CPUSubType.MIPSR2000A -> Arch.MIPS32R2
  | _ -> raise InvalidISAException

let peekArch reader offset =
  match peekCPUType reader offset with
  | CPUType.I386 -> Arch.IntelX86
  | CPUType.X64 -> Arch.IntelX64
  | CPUType.ARM -> Arch.ARMv7
  | CPUType.ARM64 -> Arch.AARCH64
  | CPUType.MIPS -> getMIPSISA reader offset
  | _ -> Arch.UnknownISA

let peekClass reader offset =
  match peekMagic reader offset with
  | Magic.MHMagic | Magic.MHCigam -> WordSize.Bit32
  | Magic.MHMagic64 | Magic.MHCigam64 -> WordSize.Bit64
  | _ -> raise FileFormatMismatchException

let peekEndianness reader offset =
  match peekMagic reader offset with
  | Magic.MHMagic | Magic.MHMagic64 -> Endian.Little
  | Magic.MHCigam | Magic.MHCigam64 -> Endian.Big
  | _ -> raise FileFormatMismatchException

let parse reader offset =
  { Magic = peekMagic reader offset
    Class = peekClass reader offset
    CPUType = peekCPUType reader offset
    CPUSubType = peekCPUSubType reader offset
    FileType = offset + 12 |> reader.PeekInt32 |> LanguagePrimitives.EnumOfValue
    NumCmds = offset + 16 |> reader.PeekUInt32
    SizeOfCmds = offset + 20 |> reader.PeekUInt32
    Flags = offset + 24 |> reader.PeekInt32 |> LanguagePrimitives.EnumOfValue }

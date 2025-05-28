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

/// Provides functions to parse Mach-O FAT binary headers.
[<RequireQualifiedAccess>]
module B2R2.FrontEnd.BinFile.Mach.Fat

open System
open B2R2
open B2R2.FrontEnd.BinLifter

let private readFatArch (span: ByteSpan) (reader: IBinReader) offset =
  let cpuType = reader.ReadInt32 (span, offset)
  let cpuSubType = reader.ReadInt32 (span, offset + 4)
  { CPUType = cpuType |> LanguagePrimitives.EnumOfValue
    CPUSubType = cpuSubType |> LanguagePrimitives.EnumOfValue
    Offset = reader.ReadInt32 (span, offset + 8)
    Size = reader.ReadInt32 (span, offset + 12)
    Align = reader.ReadInt32 (span, offset + 16) }

/// Parses the FAT binary header and returns an array of `FatArch` records.
let parseArchs (bytes: byte[]) =
  let reader = BinReader.Init Endian.Big
  let magic = reader.ReadUInt32 (bytes, 0)
  let nArch = reader.ReadInt32 (bytes, 4)
  assert (LanguagePrimitives.EnumOfValue magic = Magic.FAT_MAGIC)
  let span = ReadOnlySpan (bytes, 8, 20 * nArch)
  let archs = Array.zeroCreate nArch
  for i = 0 to nArch - 1 do
    archs[i] <- readFatArch span reader (i * 20)
  archs

let private matchingISA (isa: ISA) fatArch =
  let arch, wordSize =
    CPUType.toArchWordSizeTuple fatArch.CPUType fatArch.CPUSubType
  isa.Arch = arch && isa.WordSize = wordSize

/// Parses the FAT binary header and returns the `FatArch` record that matches
/// the given ISA.
let parseArch bytes isa =
  parseArchs bytes
  |> Array.tryFind (matchingISA isa)
  |> function Some arch -> arch | None -> raise InvalidISAException

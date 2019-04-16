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

module internal B2R2.BinFile.Mach.Fat

open B2R2

type FatArch = {
  CPUType: CPUType
  CPUSubType: CPUSubType
  Offset: int
  Size: int
  Align: int
}

let readFatArch (reader: BinReader) pos =
  { CPUType = reader.PeekInt32 pos |> LanguagePrimitives.EnumOfValue
    CPUSubType = reader.PeekInt32 (pos + 4) |> LanguagePrimitives.EnumOfValue
    Offset = reader.PeekInt32 (pos + 8)
    Size = reader.PeekInt32 (pos + 12)
    Align = reader.PeekInt32 (pos + 16) }

let rec loadFat acc reader pos cnt =
  if cnt = 0 then acc
  else let arch = readFatArch reader pos
       loadFat (arch :: acc) reader (pos + 20) (cnt - 1)

/// Convert FatArch to a tuple of (Architecture, Offset), where Offset is the
/// offset to the binary object of the corresponding architecture.
let toTuple arch =
  Header.cpuTypeToArch arch.CPUType arch.CPUSubType, arch.Offset

let loadFormats (reader: BinReader) =
  let nArch = reader.PeekInt32 4
  loadFat [] reader 0 nArch
  |> List.map toTuple

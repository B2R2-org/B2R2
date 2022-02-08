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

module B2R2.FrontEnd.BinFile.Mach.Fat

open System
open B2R2

type FatArch = {
  CPUType: CPUType
  CPUSubType: CPUSubType
  Offset: int
  Size: int
  Align: int
}

let private readFatArch (span: ByteSpan) (r: IBinReader) pos =
  { CPUType = r.ReadInt32 (span, pos) |> LanguagePrimitives.EnumOfValue
    CPUSubType = r.ReadInt32 (span, pos + 4) |> LanguagePrimitives.EnumOfValue
    Offset = r.ReadInt32 (span, pos + 8)
    Size = r.ReadInt32 (span, pos + 12)
    Align = r.ReadInt32 (span, pos + 16) }

let rec private loadFatAux acc span reader pos cnt =
  if cnt = 0 then acc
  else
    let arch = readFatArch span reader pos
    loadFatAux (arch :: acc) span reader (pos + 20) (cnt - 1)

let loadFats (span: ByteSpan) (reader: IBinReader) =
  let nArch = reader.ReadInt32 (span, 4)
  loadFatAux [] span reader 8 nArch

let private matchISA isa fatArch =
  let arch = Header.cpuTypeToArch fatArch.CPUType fatArch.CPUSubType
  isa.Arch = arch

let rec findMatchingFatRecord isa fats =
  match fats with
  | fatArch :: tl ->
    if matchISA isa fatArch then fatArch
    else findMatchingFatRecord isa tl
  | [] -> raise InvalidISAException
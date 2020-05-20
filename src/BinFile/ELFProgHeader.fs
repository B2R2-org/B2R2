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

module internal B2R2.BinFile.ELF.ProgHeader

open System
open B2R2
open B2R2.BinFile
open B2R2.BinFile.FileHelper

let peekPHdrFlags (reader: BinReader) cls offset =
  let pHdrPHdrFlagsOffset = if cls = WordSize.Bit32 then 24 else 4
  offset + pHdrPHdrFlagsOffset |> reader.PeekInt32

let parseProgHeader baseAddr cls (reader: BinReader) offset =
  {
    PHType = reader.PeekUInt32 offset |> LanguagePrimitives.EnumOfValue
    PHFlags = peekPHdrFlags reader cls offset |> LanguagePrimitives.EnumOfValue
    PHOffset = peekHeaderNative reader cls offset 4 8
    PHAddr = peekHeaderNative reader cls offset 8 16 + baseAddr
    PHPhyAddr = peekHeaderNative reader cls offset 12 24
    PHFileSize = peekHeaderNative reader cls offset 16 32
    PHMemSize = peekHeaderNative reader cls offset 20 40
    PHAlignment = peekHeaderNative reader cls offset 28 48
  }

/// Parse and associate program headers with section headers to return the list
/// of segments.
let parse baseAddr eHdr reader =
  let nextPHdrOffset = if eHdr.Class = WordSize.Bit32 then 32 else 56
  let nextPHdr offset = offset + nextPHdrOffset
  let rec parseLoop pNum acc offset =
    if pNum = 0us then List.rev acc
    else
      let phdr = parseProgHeader baseAddr eHdr.Class reader offset
      parseLoop (pNum - 1us) (phdr :: acc) (nextPHdr offset)
  Convert.ToInt32 eHdr.PHdrTblOffset
  |> parseLoop eHdr.PHdrNum []

let getLoadableProgHeaders pHdrs =
  pHdrs |> List.filter (fun ph -> ph.PHType = ProgramHeaderType.PTLoad)

let gatherLoadlabeSecNums pHdr secs =
  let foldSHdr acc sec =
    let lb = pHdr.PHOffset
    let ub = lb + pHdr.PHFileSize
    if sec.SecOffset >= lb && sec.SecOffset < ub then sec.SecNum :: acc else acc
  ARMap.fold (fun acc _ s -> foldSHdr acc s) [] secs.SecByAddr

let getLoadableSecNums secs segs =
  let loop set seg =
    gatherLoadlabeSecNums seg secs
    |> List.fold (fun set n -> Set.add n set) set
  segs |> List.fold loop Set.empty

let toSegment phdr =
  {
    Address = phdr.PHAddr
    Size = phdr.PHFileSize
    Permission = phdr.PHFlags
  }

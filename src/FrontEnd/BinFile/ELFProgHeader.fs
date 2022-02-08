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

module internal B2R2.FrontEnd.BinFile.ELF.ProgHeader

open System
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

let peekPHdrFlags (span: ByteSpan) (reader: IBinReader) cls offset =
  let pHdrPHdrFlagsOffset = if cls = WordSize.Bit32 then 24 else 4
  reader.ReadInt32 (span, offset + pHdrPHdrFlagsOffset)
  |> LanguagePrimitives.EnumOfValue

let parseProgHeader baseAddr cls (span: ByteSpan) reader offset =
  let phType = (reader: IBinReader).ReadUInt32 (span, offset)
  { PHType = LanguagePrimitives.EnumOfValue phType
    PHFlags = peekPHdrFlags span reader cls offset
    PHOffset = peekHeaderNative span reader cls offset 4 8
    PHAddr = peekHeaderNative span reader cls offset 8 16 + baseAddr
    PHPhyAddr = peekHeaderNative span reader cls offset 12 24
    PHFileSize = peekHeaderNative span reader cls offset 16 32
    PHMemSize = peekHeaderNative span reader cls offset 20 40
    PHAlignment = peekHeaderNative span reader cls offset 28 48 }

let rec private parseLoop span reader pNum baseAddr eHdr acc delta offset =
  if pNum = 0us then List.rev acc
  else
    let phdr = parseProgHeader baseAddr eHdr.Class span reader offset
    parseLoop span reader (pNum - 1us) baseAddr eHdr (phdr :: acc)
              delta (offset + delta)

/// Parse and associate program headers with section headers to return the list
/// of segments.
let parse baseAddr eHdr span reader =
  let nextPHdrOffset = if eHdr.Class = WordSize.Bit32 then 32 else 56
  parseLoop span reader eHdr.PHdrNum baseAddr eHdr []
            nextPHdrOffset (Convert.ToInt32 eHdr.PHdrTblOffset)

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
  { Address = phdr.PHAddr
    Offset = phdr.PHOffset
    Size = phdr.PHMemSize
    SizeInFile = phdr.PHFileSize
    Permission = phdr.PHFlags }

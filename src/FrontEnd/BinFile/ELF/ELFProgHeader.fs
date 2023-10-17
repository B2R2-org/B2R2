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
open System.IO
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.FileHelper

let peekPHdrFlags (span: ByteSpan) (reader: IBinReader) cls =
  let pHdrPHdrFlagsOffset = if cls = WordSize.Bit32 then 24 else 4
  reader.ReadInt32 (span, pHdrPHdrFlagsOffset)
  |> LanguagePrimitives.EnumOfValue

let parseProgHeader baseAddr cls (span: ByteSpan) reader =
  let phType = (reader: IBinReader).ReadUInt32 (span, 0)
  { PHType = LanguagePrimitives.EnumOfValue phType
    PHFlags = peekPHdrFlags span reader cls
    PHOffset = peekHeaderNative span reader cls 4 8
    PHAddr = peekHeaderNative span reader cls 8 16 + baseAddr
    PHPhyAddr = peekHeaderNative span reader cls 12 24
    PHFileSize = peekHeaderNative span reader cls 16 32
    PHMemSize = peekHeaderNative span reader cls 20 40
    PHAlignment = peekHeaderNative span reader cls 28 48 }

/// Parse program headers and returns them as an array.
let parse (stream: Stream) reader hdr baseAddr =
  let cls = hdr.Class
  let fieldLength = if cls = WordSize.Bit32 then 32 else 56
  let buf = Array.zeroCreate fieldLength
  let numEntries = int hdr.PHdrNum
  let progHeaders = Array.zeroCreate numEntries
  stream.Seek (int64 hdr.PHdrTblOffset, SeekOrigin.Begin) |> ignore
  let rec parseLoop count =
    if count = numEntries then progHeaders
    else
      readOrDie stream buf
      let phdr = parseProgHeader baseAddr cls (ReadOnlySpan buf) reader
      progHeaders[count] <- phdr
      parseLoop (count + 1)
  parseLoop 0

let getLoadableProgHeaders (progHeaders: Lazy<ProgramHeader[]>) =
  progHeaders.Value
  |> Array.filter (fun ph -> ph.PHType = ProgramHeaderType.PTLoad)

let toSegment phdr =
  { Address = phdr.PHAddr
    Offset = uint32 phdr.PHOffset
    Size = uint32 phdr.PHMemSize
    SizeInFile = uint32 phdr.PHFileSize
    Permission = phdr.PHFlags }

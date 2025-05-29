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

[<RequireQualifiedAccess>]
module internal B2R2.FrontEnd.BinFile.PE.BaseRelocationTable

open System.Reflection.PortableExecutable
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.PE.PEUtils

let private buildRelocBlock (bytes: byte[]) (reader: IBinReader) headerOffset =
  let blockSize = reader.ReadInt32 (bytes, headerOffset + 4)
  let upperBound = headerOffset + blockSize
  let rec parseBlock offset entries =
    if offset < upperBound then
      let buffer = reader.ReadUInt16 (bytes, offset)
      { Type = buffer >>> 12 |> int32 |> LanguagePrimitives.EnumOfValue;
        Offset = buffer &&& 0xFFFus }::entries
      |> parseBlock (offset + 2)
    else
      entries |> List.toArray
  { PageRVA = reader.ReadUInt32 (bytes, headerOffset)
    BlockSize = blockSize
    Entries = parseBlock (headerOffset + 8) List.empty }

let parse bytes (reader: IBinReader) (headers: PEHeaders) secs =
  let peHdr = headers.PEHeader
  match peHdr.BaseRelocationTableDirectory.RelativeVirtualAddress with
  | 0 -> List.empty
  | rva ->
    let hdrOffset = getRawOffset secs rva
    let upperBound = hdrOffset + peHdr.BaseRelocationTableDirectory.Size
    let rec parseRelocDirectory offset blks =
      if offset < upperBound then
        let relocBlk = buildRelocBlock bytes reader offset
        parseRelocDirectory (offset + relocBlk.BlockSize) (relocBlk :: blks)
      else blks
    parseRelocDirectory hdrOffset List.empty


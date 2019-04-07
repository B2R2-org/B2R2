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

module internal B2R2.BinFile.PE.PDB

open System
open B2R2

let private magicBytes =
  [| 'M'; 'i'; 'c'; 'r'; 'o'; 's'; 'o'; 'f';
     't'; ' '; 'C'; '/'; 'C'; '+'; '+'; ' ';
     'M'; 'S'; 'F'; ' '; '7'; '.'; '0'; '0';
     '\013'; '\010'; '\026'; 'D'; 'S'; '\000'; '\000'; '\000' |]

let isPDBHeader (reader: BinReader) offset =
  reader.PeekChars (32, offset) = magicBytes

let parseSuperBlock (reader: BinReader) offset =
  {
    BlockSize = offset + 32 |> reader.PeekInt32
    FreeBlockMapIdx = offset + 36 |> reader.PeekInt32
    NumBlocks = offset + 40 |> reader.PeekInt32
    NumDirectoryBytes = offset + 44 |> reader.PeekInt32
    BlockMapAddr = offset + 52 |> reader.PeekInt32
  }

let inline getNumBlocks numBytes blockSize =
  (numBytes + blockSize - 1) / blockSize

let rec readIntValues (reader: BinReader) cnt acc pos =
  if cnt = 0 then List.rev acc
  else readIntValues reader (cnt - 1) (reader.PeekInt32 pos :: acc) (pos + 4)

let readStream (reader: BinReader) (blockSize: int) blockMapAddrs =
  let size = List.length blockMapAddrs * blockSize
  let buf: byte [] = Array.zeroCreate size
  let folder idx blockMapAddr =
    let offset = blockMapAddr * blockSize
    let blk = reader.PeekBytes (blockSize, offset)
    Array.blit blk 0 buf (idx * blockSize) blockSize
  blockMapAddrs |> List.iteri folder
  buf

let parseStreamBlks (reader: BinReader) sb streamSizes offset =
  let rec loop idx acc offset =
    if idx = Array.length streamSizes then List.rev acc |> List.toArray
    else
      let numBlks = getNumBlocks streamSizes.[idx] sb.BlockSize
      let blocks = readIntValues reader numBlks [] offset |> List.toArray
      let nextOffset = offset + numBlks * 4
      loop (idx + 1) (blocks :: acc) nextOffset
  loop 0 [] offset

let buildStreamDirectory sb (reader: BinReader) =
  let numStream = reader.PeekInt32 0
  let streamSizes = readIntValues reader numStream [] 4 |> List.toArray
  let streamBlks = parseStreamBlks reader sb streamSizes (numStream * 4 + 4)
  {
    NumStreams = numStream
    StreamSizes = streamSizes
    StreamBlocks = streamBlks
  }

let parseStreamDirectory reader sb =
  let numBlks = getNumBlocks sb.NumDirectoryBytes sb.BlockSize
  let blockMapOffset = sb.BlockMapAddr * sb.BlockSize
  Convert.ToInt32 blockMapOffset
  |> readIntValues reader numBlks []
  |> readStream reader sb.BlockSize
  |> BinReader.Init
  |> buildStreamDirectory sb

let readSymName (reader: BinReader) (size: int) offset =
  let bs = reader.PeekBytes (size, offset)
  ByteArray.extractCString bs 0

let parseSym (reader: BinReader) streamSize =
  let rec loop acc cnt offset =
    let size = reader.PeekUInt16 offset |> int
    if offset >= int streamSize || size = 0 then acc
    else
      let typ = reader.PeekUInt16 (offset + 2) |> LanguagePrimitives.EnumOfValue
      let flg = reader.PeekInt32 (offset + 4) |> LanguagePrimitives.EnumOfValue
      match typ with
      | SymType.SPUB32 -> (* PUBSYM32 *)
        let sym =
          { Flags = flg
            Address = reader.PeekUInt32 (offset + 8) |> uint64
            Segment = reader.PeekUInt16 (offset + 12)
            Name = readSymName reader (size - 12) (offset + 14) }
        loop (sym :: acc) (cnt + 1) (offset + size + 2)
      | _ -> loop acc (cnt + 1) (offset + size + 2)
  loop [] 0 0

let getDBIStreamOffset sb streamDir =
  let dbiBlkIndices = streamDir.StreamBlocks.[3]
  dbiBlkIndices.[0] * sb.BlockSize

let parseDBIStream (reader: BinReader) superBlock streamDir =
  let offset = getDBIStreamOffset superBlock streamDir
  { VersionHeader = offset |> reader.PeekInt32 |> LanguagePrimitives.EnumOfValue
    GlobalStreamIndex = offset + 12 |> reader.PeekUInt16 |> int
    PublicStreamIndex = offset + 16 |> reader.PeekUInt16 |> int
    SymRecordStreamIndex = offset + 20 |> reader.PeekUInt16 |> int }

let parseSymbolStream reader superBlock streamDir dbi =
  let blks = streamDir.StreamBlocks.[dbi.SymRecordStreamIndex] |> Array.toList
  let size = streamDir.StreamSizes.[dbi.SymRecordStreamIndex]
  let stream = readStream reader superBlock.BlockSize blks
  let symReader = BinReader.Init (stream)
  parseSym symReader size

let parse reader offset =
  let superBlock = parseSuperBlock reader offset
  let streamDir = parseStreamDirectory reader superBlock
  let dbi = parseDBIStream reader superBlock streamDir
  parseSymbolStream reader superBlock streamDir dbi

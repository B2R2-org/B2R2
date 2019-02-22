(*
  B2R2 - the Next-Generation Reversing Platform

  Author: DongYeop Oh <oh51dy@kaist.ac.kr>

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

module internal B2R2.BinFile.PDB

open System
open B2R2
open B2R2.BinFile.FileHelper

type SuperBlock = {
  BlockSize         : uint32
  FreeBlockMapIdx   : uint32
  NumBlocks         : uint32
  NumDirectoryBytes : uint32
  BlockMapAddr      : uint32
}

type StreamDir = {
  NumStreams  : Num
  StreamSizes : StreamSizes
  StreamMap   : Map<Num, Block>
}
and StreamSizes = uint32 list
and Num = uint32
and Block = uint32 list

type SymFlags =
  | None = 0b0000
  | Code = 0b0001
  | Function = 0b0010
  | Managed = 0b0100
  | MSIL = 0b1000

type Sym = {
  Size    : uint16
  Type    : uint16
  Flags   : SymFlags
  Offset  : uint32
  Addr    : Addr
  Segment : uint16
  Name    : string
}

type PDBSymbols = {
  PDBAddrMap  : Map<Addr, Sym>
  PDBNameMap  : Map<String, Sym>
  PDBSymArr   : Sym []
}

type PDBSymNumMap = Map<int, Sym>


let StreamDBI = 3u

let emptyPDB = Map.empty

let private magicBytes =
  [| 'M'; 'i'; 'c'; 'r'; 'o'; 's'; 'o'; 'f';
     't'; ' '; 'C'; '/'; 'C'; '+'; '+'; ' ';
     'M'; 'S'; 'F'; ' '; '7'; '.'; '0'; '0';
     '\013'; '\010'; '\026'; 'D'; 'S'; '\000'; '\000'; '\000' |]

let readMagic (reader: BinReader) offset =
  let magicOffset = 0
  reader.PeekChars (32, offset + magicOffset)

let readBlockSize (reader: BinReader) offset =
  let blockSizeOffset = 32
  offset + blockSizeOffset |> reader.PeekUInt32

let readFreeBlockMapIdx (reader: BinReader) offset =
  let freeBlockMapIdxOffset = 36
  offset + freeBlockMapIdxOffset |> reader.PeekUInt32

let readNumBlocks (reader: BinReader) offset =
  let numBlocksOffset = 40
  offset + numBlocksOffset |> reader.PeekUInt32

let readNumDirectoryBytes (reader: BinReader) offset =
  let numDirectoryBytesOffset = 44
  offset + numDirectoryBytesOffset |> reader.PeekUInt32

let readBlockMapAddr (reader: BinReader) offset =
  let blockMapAddrOffset = 52
  offset + blockMapAddrOffset |> reader.PeekUInt32

let isPDBHeader reader offset = readMagic reader offset = magicBytes

let parseSuperBlock reader offset =
  {
    BlockSize = readBlockSize reader offset
    FreeBlockMapIdx = readFreeBlockMapIdx reader offset
    NumBlocks = readNumBlocks reader offset
    NumDirectoryBytes = readNumDirectoryBytes reader offset
    BlockMapAddr = readBlockMapAddr reader offset
  }

let alignTo value align = (value + align - 1u) / align * align

let bytesToBlock numBytes blockSize = alignTo numBytes blockSize / blockSize

let getBlockMapOffset (sb: SuperBlock) = sb.BlockMapAddr * sb.BlockSize

let getDBIStreamOffset (sb: SuperBlock) (streamsDir: StreamDir) =
  let block = Map.find StreamDBI streamsDir.StreamMap
  block.[0] * sb.BlockSize

let getGlobalStreamOffset sb streamsDir =
  getDBIStreamOffset sb streamsDir

let getSymRecordStreamIdx (reader: BinReader) dbiOff =
  let symRecordStreamIdx = 20u
  dbiOff + symRecordStreamIdx |> Convert.ToInt32 |> reader.PeekUInt16 |> uint32

let getPubSymRecordStreamIdx (reader: BinReader) dbiOff =
  let symRecordStreamIdx = 16u
  dbiOff + symRecordStreamIdx |> Convert.ToInt32 |> reader.PeekUInt16 |> uint32

let getNumDirectoryBlocks (sb: SuperBlock) =
   bytesToBlock sb.NumDirectoryBytes sb.BlockSize

let rec readUInt32Loop (reader : BinReader) cnt acc offset =
  if cnt = 0u then struct (List.rev acc, offset)
  else
    let struct (v, nextOff) = reader.ReadUInt32 offset
    readUInt32Loop reader (cnt - 1u) (v :: acc) nextOff

let getDirectoryBlocks reader (sb: SuperBlock) =
  let dirNum = getNumDirectoryBlocks sb
  let blockMapOffset = getBlockMapOffset sb
  Convert.ToInt32 blockMapOffset |> readUInt32Loop reader dirNum []

let parseStream (reader: BinReader) sb (streamSizes: StreamSizes) offset =
  let rec loop idx acc offset =
    if idx = streamSizes.Length then acc
    else
      let bNum = bytesToBlock streamSizes.[idx] sb.BlockSize
      let struct (block, nextOff) = readUInt32Loop reader bNum [] offset
      loop (idx + 1) (Map.add (uint32 idx) block acc) nextOff
  loop 0 Map.empty offset

let parseStreamDir (reader: BinReader) (sb: SuperBlock) =
  let struct (numStream, nextOff) = reader.ReadUInt32 0
  let struct (streamSizes, nextOff) = readUInt32Loop reader numStream [] nextOff
  let streamMap = parseStream reader sb streamSizes nextOff
  {
    NumStreams = numStream
    StreamSizes = streamSizes
    StreamMap = streamMap
  }

let readSymName (reader: BinReader) size offset =
  let len = size - 14us |> int
  let name = String (reader.PeekChars (len, offset))
  Array.get (name.Split('\000')) 0

let makeSym size typ flags off segment name =
  {
    Size = size
    Type = typ
    Flags = flags |> int |> enum<SymFlags>
    Offset = off
    Addr = 0UL
    Segment = segment
    Name = name
  }

let parseSym (reader: BinReader) streamSize =
  let rec loop acc cnt offset =
    let struct (size, nextOff) = reader.ReadUInt16 offset
    if offset >= int streamSize || size = 0us then acc
    else
      let size = size + 2us
      let struct (typ, nextOff) = reader.ReadUInt16 nextOff
      if typ = 0x110eus then
        let struct (flags, nextOff) = reader.ReadUInt32 nextOff
        let struct (off, nextOff) = reader.ReadUInt32 nextOff
        let struct (segment, nextOff) = reader.ReadUInt16 nextOff
        let name = readSymName reader size nextOff
        let sym = makeSym size typ flags off segment name
        loop (Map.add cnt sym acc) (cnt + 1) (offset + int sym.Size)
      else loop acc (cnt + 1) (offset + int size)
  loop Map.empty 0 0

let getPubSymStream reader superBlock streamsDir =
  let dbiOffset = getDBIStreamOffset superBlock streamsDir
  let symRecordStreamIdx = getPubSymRecordStreamIdx reader dbiOffset
  if symRecordStreamIdx < streamsDir.NumStreams then ()
  else failwith "Public stream not present"
  Map.find symRecordStreamIdx streamsDir.StreamMap

let getSymStream reader superBlock streamsDir =
  let dbiOffset = getDBIStreamOffset superBlock streamsDir
  let symRecordStreamIdx = getSymRecordStreamIdx reader dbiOffset
  Map.find symRecordStreamIdx streamsDir.StreamMap,
  streamsDir.StreamSizes.[symRecordStreamIdx |> int]

let genStream (reader: BinReader) blocks blockSize =
  let loop acc (block: uint32) =
    let offset = block * blockSize |> Convert.ToInt32
    let size = blockSize |> Convert.ToInt32
    Array.append acc (reader.PeekBytes (size, offset))
  List.fold loop [||] blocks

let parse reader offset =
  let superBlock = parseSuperBlock reader offset
  let struct (dirBlocks, _) = getDirectoryBlocks reader superBlock
  let dirStream = genStream reader dirBlocks superBlock.BlockSize
  let dirReader = BinReader.Init (dirStream)
  let streamsDir = parseStreamDir dirReader superBlock
  let symblocks, symStreamSize = getSymStream reader superBlock streamsDir
  let symStream = genStream reader symblocks superBlock.BlockSize
  let symReader = BinReader.Init (symStream)
  parseSym symReader symStreamSize

let parsePDB pdbBytes =
  let reader = BinReader.Init (pdbBytes)
  if isPDBHeader reader startOffset then ()
  else raise FileFormatMismatchException
  parse reader startOffset

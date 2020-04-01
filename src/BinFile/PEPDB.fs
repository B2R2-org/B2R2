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

module internal B2R2.BinFile.PE.PDB

open System
open B2R2
open B2R2.BinFile.FileHelper

/// Hold an MSF stream.
type MSFStream = {
  Reader: BinReader
  ByteSize: int
}

let private magicBytes =
  [| 'M'; 'i'; 'c'; 'r'; 'o'; 's'; 'o'; 'f';
     't'; ' '; 'C'; '/'; 'C'; '+'; '+'; ' ';
     'M'; 'S'; 'F'; ' '; '7'; '.'; '0'; '0';
     '\013'; '\010'; '\026'; 'D'; 'S'; '\000'; '\000'; '\000' |]

let isPDBHeader (reader: BinReader) offset =
  reader.PeekChars (32, offset) = magicBytes

let parseSuperBlock (reader: BinReader) offset =
  { BlockSize = offset + 32 |> reader.PeekInt32
    FreeBlockMapIdx = offset + 36 |> reader.PeekInt32
    NumBlocks = offset + 40 |> reader.PeekInt32
    NumDirectoryBytes = offset + 44 |> reader.PeekInt32
    BlockMapAddr = offset + 52 |> reader.PeekInt32 }

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
  { NumStreams = numStream
    StreamSizes = streamSizes
    StreamBlocks = streamBlks }

let parseStreamDirectory reader sb =
  let numBlks = getNumBlocks sb.NumDirectoryBytes sb.BlockSize
  let blockMapOffset = sb.BlockMapAddr * sb.BlockSize
  Convert.ToInt32 blockMapOffset
  |> readIntValues reader numBlks []
  |> readStream reader sb.BlockSize
  |> BinReader.Init
  |> buildStreamDirectory sb

let parseStream reader superBlock streamDir idx =
  let blks = streamDir.StreamBlocks.[idx] |> Array.toList
  let size = streamDir.StreamSizes.[idx]
  let stream = readStream reader superBlock.BlockSize blks
  { Reader = BinReader.Init (stream); ByteSize = size }

let buildStreamMap reader superBlock streamDir =
  let rec builder acc idx =
    if idx >= streamDir.NumStreams then List.rev acc |> List.toArray
    else
      let stream = lazy (parseStream reader superBlock streamDir idx)
      builder (stream :: acc) (idx + 1)
  builder [] 0

let getStream (streamMap: Lazy<MSFStream> []) idx =
  let s = streamMap.[idx]
  s.Force ()

let parseDBIHeader dbiStream =
  let reader = dbiStream.Reader
  { DBIVersion = 4 |> reader.PeekInt32 |> LanguagePrimitives.EnumOfValue
    GlobalStreamIdx = 12 |> reader.PeekUInt16 |> int
    PublicStreamIdx = 16 |> reader.PeekUInt16 |> int
    SymRecordStreamIdx = 20 |> reader.PeekUInt16 |> int
    ModInfoSize = 24 |> reader.PeekInt32 }

let rec parseSymbolRecord stream offset modules streamMap =
  let reader = stream.Reader
  let size = reader.PeekUInt16 offset |> int
  let typ = reader.PeekUInt16 (offset + 2) |> LanguagePrimitives.EnumOfValue
  let flg = reader.PeekInt32 (offset + 4) |> LanguagePrimitives.EnumOfValue
  match typ with
  | SymType.SPUB32 -> (* PUBSYM32 *)
    { Flags = flg
      Address = reader.PeekUInt32 (offset + 8) |> uint64
      Segment = reader.PeekUInt16 (offset + 12)
      Name = peekCStringOfSize reader (offset + 14) (size - 12) } |> Some
  | SymType.SLPROC32
  | SymType.SGPROC32 -> (* PROCSYM32 *)
    { Flags = SymFlags.Function
      Address = reader.PeekUInt32 (offset + 32) |> uint64
      Segment = reader.PeekUInt16 (offset + 36)
      Name = peekCStringOfSize reader (offset + 39) (size - 36) } |> Some
  | SymType.SPROCREF
  | SymType.SLPROCREF -> (* REFSYM2 *)
    let modnum = reader.PeekUInt16 (offset + 12) |> int
    let refOffset = reader.PeekInt32 (offset + 8)
    let m = Array.get modules (modnum - 1)
    let stream = getStream streamMap m.SymStreamIndex
    parseSymbolRecord stream refOffset modules streamMap
  | _ -> None

let parseSymRecordStream modules streamMap stream =
  let rec loop acc cnt offset =
    let size = stream.Reader.PeekUInt16 offset |> int
    if offset >= int stream.ByteSize || size = 0 then acc
    else
      match parseSymbolRecord stream offset modules streamMap with
      | Some sym -> loop (sym :: acc) (cnt + 1) (offset + size + 2)
      | None -> loop acc (cnt + 1) (offset + size + 2)
  loop [] 0 0

let readStr (reader: BinReader) pos =
  let rec loop acc pos =
    let byte = reader.PeekByte pos
    if byte = 0uy then List.rev acc |> List.toArray, pos + 1
    else loop (byte :: acc) (pos + 1)
  let bs, nextPos = loop [] pos
  Text.Encoding.ASCII.GetString bs, nextPos

let align offset n =
  if offset &&& (n - 1) > 0 then (offset &&& (~~~ (n - 1))) + n
  else offset

let parseModuleInfo dbi dbiStream =
  let maxOffset = dbi.ModInfoSize + 64
  let reader = dbiStream.Reader
  let rec loop acc pos =
    if pos >= maxOffset then acc
    else
      let modName, nextOffset = readStr reader (pos + 64)
      let objName, nextOffset = readStr reader nextOffset
      let acc =
        { SectionIndex = reader.PeekUInt16 (pos + 4) |> int
          SymStreamIndex = reader.PeekUInt16 (pos + 34) |> int
          ModuleName = modName
          ObjFileName = objName } :: acc
      loop acc (align nextOffset 4)
  loop [] 64 |> List.rev |> List.toArray

let rec readHashRecords acc (reader: BinReader) offset numEntries =
  if numEntries = 0u then List.rev acc
  else
    let r = { HROffset = reader.PeekInt32 offset
              HRCRef = reader.PeekInt32 (offset + 4) }
    readHashRecords (r :: acc) reader (offset + 8) (numEntries - 1u)

let parseGSIHeader (reader: BinReader) =
  { VersionSignature = reader.PeekUInt32 0
    VersionHeader = reader.PeekUInt32 4
    HashRecordSize = reader.PeekUInt32 8
    NumBuckets = reader.PeekUInt32 12 }

let parseGSIHashRecord reader gsiHeader =
  if gsiHeader.VersionSignature = 0xFFFFFFFFu
    && gsiHeader.VersionHeader = 0xF12F091Au
  then readHashRecords [] reader 16 (gsiHeader.HashRecordSize / 8u)
  else []

let parseGlobalSymbolInfo glStream =
  let gsiHeader = parseGSIHeader glStream.Reader
  parseGSIHashRecord glStream.Reader gsiHeader

let parse reader offset =
  let superBlock = parseSuperBlock reader offset
  let streamDir = parseStreamDirectory reader superBlock
  let streamMap = buildStreamMap reader superBlock streamDir
  let dbiStream = getStream streamMap 3
  let dbi = parseDBIHeader dbiStream
  let modules = parseModuleInfo dbi dbiStream
  let _gsi = getStream streamMap dbi.GlobalStreamIdx |> parseGlobalSymbolInfo
  getStream streamMap dbi.SymRecordStreamIdx
  |> parseSymRecordStream modules streamMap

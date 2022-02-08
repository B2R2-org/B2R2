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

module internal B2R2.FrontEnd.BinFile.PE.PDB

open System
open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinFile.FileHelper

let private getMagicBytes () =
  [| 'M'; 'i'; 'c'; 'r'; 'o'; 's'; 'o'; 'f';
     't'; ' '; 'C'; '/'; 'C'; '+'; '+'; ' ';
     'M'; 'S'; 'F'; ' '; '7'; '.'; '0'; '0';
     '\013'; '\010'; '\026'; 'D'; 'S'; '\000'; '\000'; '\000' |]

let isPDBHeader (span: ByteSpan) (reader: IBinReader) =
  reader.ReadChars (span, 0, 32) = getMagicBytes ()

let parseSuperBlock (span: ByteSpan) (reader: IBinReader) =
  { BlockSize = reader.ReadInt32 (span, 32)
    FreeBlockMapIdx = reader.ReadInt32 (span, 36)
    NumBlocks = reader.ReadInt32 (span, 40)
    NumDirectoryBytes = reader.ReadInt32 (span, 44)
    BlockMapAddr = reader.ReadInt32 (span, 52) }

let inline getNumBlocks numBytes blockSize =
  (numBytes + blockSize - 1) / blockSize

let rec readIntValues (span: ByteSpan) reader cnt acc pos =
  if cnt = 0 then List.rev acc
  else
    let v = (reader: IBinReader).ReadInt32 (span, pos)
    readIntValues span reader (cnt - 1) (v :: acc) (pos + 4)

let readStream (span: ByteSpan) reader blockSize blockMapAddrs =
  let size = List.length blockMapAddrs * blockSize
  let buf: byte [] = Array.zeroCreate size
  let mutable idx = 0
  for blockMapAddr in blockMapAddrs do
    let offset = blockMapAddr * blockSize
    let blk = (reader: IBinReader).ReadBytes (span, offset, blockSize)
    Array.blit blk 0 buf (idx * blockSize) blockSize
    idx <- idx + 1
  buf

let parseStreamBlks span reader sb streamSizes offset =
  let lst = List<int[]> ()
  let mutable offset = offset
  for idx = 0 to Array.length streamSizes - 1 do
    let numBlks = getNumBlocks streamSizes[idx] sb.BlockSize
    let blocks = readIntValues span reader numBlks [] offset |> List.toArray
    offset <- offset + numBlks * 4
    lst.Add blocks
  lst |> Seq.toArray

let buildStreamDirectory sb (span: ByteSpan) reader =
  let numStream = (reader: IBinReader).ReadInt32 (span, 0)
  let streamSizes = readIntValues span reader numStream [] 4 |> List.toArray
  let streamBlks =
    parseStreamBlks span reader sb streamSizes (numStream * 4 + 4)
  { NumStreams = numStream
    StreamSizes = streamSizes
    StreamBlocks = streamBlks }

let parseStreamDirectory span reader sb =
  let numBlks = getNumBlocks sb.NumDirectoryBytes sb.BlockSize
  let blockMapOffset = sb.BlockMapAddr * sb.BlockSize
  let intVals =
    readIntValues span reader numBlks [] (Convert.ToInt32 blockMapOffset)
  let bs = readStream span reader sb.BlockSize intVals
  buildStreamDirectory sb (ReadOnlySpan bs) reader

let parseStream span reader superBlock streamDir idx =
  let blks = streamDir.StreamBlocks[idx] |> Array.toList
  let size = streamDir.StreamSizes[idx]
  readStream span reader superBlock.BlockSize blks, size

let buildStreamMap span reader superBlock streamDir =
  let lst = List<byte[] * int> ()
  for idx = 0 to streamDir.NumStreams - 1 do
    let stream = parseStream span reader superBlock streamDir idx
    lst.Add stream
  lst |> Seq.toArray

let inline getStream (streamMap: (byte[] * int) []) idx =
  streamMap[idx]

let parseDBIHeader (reader: IBinReader) (dbiStream: byte[]) =
  let span = ReadOnlySpan dbiStream
  { DBIVersion = reader.ReadInt32 (span, 4) |> LanguagePrimitives.EnumOfValue
    GlobalStreamIdx = reader.ReadUInt16 (span, 12) |> int
    PublicStreamIdx = reader.ReadUInt16 (span, 16) |> int
    SymRecordStreamIdx = reader.ReadUInt16 (span, 20) |> int
    ModInfoSize = reader.ReadInt32 (span, 24) }

let rec parseSymbolRecord (bs: byte[]) reader offset modules streamMap =
  let sp = ReadOnlySpan bs
  let size = (reader: IBinReader).ReadUInt16 (sp, offset) |> int
  let typ = reader.ReadUInt16 (sp, offset + 2) |> LanguagePrimitives.EnumOfValue
  let flg = reader.ReadInt32 (sp, offset + 4) |> LanguagePrimitives.EnumOfValue
  match typ with
  | SymType.SPUB32 -> (* PUBSYM32 *)
    { Flags = flg
      Address = reader.ReadUInt32 (sp, offset + 8) |> uint64
      Segment = reader.ReadUInt16 (sp, offset + 12)
      Name = peekCString sp (offset + 14) } |> Some
  | SymType.SLPROC32
  | SymType.SGPROC32 -> (* PROCSYM32 *)
    { Flags = SymFlags.Function
      Address = reader.ReadUInt32 (sp, offset + 32) |> uint64
      Segment = reader.ReadUInt16 (sp, offset + 36)
      Name = peekCString sp (offset + 39) } |> Some
  | SymType.SPROCREF
  | SymType.SLPROCREF -> (* REFSYM2 *)
    let modnum = reader.ReadUInt16 (sp, offset + 12) |> int
    let refOffset = reader.ReadInt32 (sp, offset + 8)
    let m = Array.get modules (modnum - 1)
    let stream, _ = getStream streamMap m.SymStreamIndex
    parseSymbolRecord stream reader refOffset modules streamMap
  | _ -> None

let parseSymRecordStream reader modules streamMap (stream: byte[], streamSize) =
  let rec loop acc cnt offset =
    let size = (reader: IBinReader).ReadUInt16 (stream, offset) |> int
    if offset >= streamSize || size = 0 then acc
    else
      match parseSymbolRecord stream reader offset modules streamMap with
      | Some sym -> loop (sym :: acc) (cnt + 1) (offset + size + 2)
      | None -> loop acc (cnt + 1) (offset + size + 2)
  loop [] 0 0

let readStr (bs: byte[]) pos =
  let rec loop acc pos =
    let byte = bs[pos]
    if byte = 0uy then List.rev acc |> List.toArray, pos + 1
    else loop (byte :: acc) (pos + 1)
  let bs, nextPos = loop [] pos
  Text.Encoding.ASCII.GetString bs, nextPos

let align offset n =
  if offset &&& (n - 1) > 0 then (offset &&& (~~~ (n - 1))) + n
  else offset

let parseModuleInfo (reader: IBinReader) dbi (bs: byte[]) =
  let maxOffset = dbi.ModInfoSize + 64
  let rec loop acc pos =
    if pos >= maxOffset then acc
    else
      let modName, nextOffset = readStr bs (pos + 64)
      let objName, nextOffset = readStr bs nextOffset
      let acc =
        { SectionIndex = reader.ReadUInt16 (bs, pos + 4) |> int
          SymStreamIndex = reader.ReadUInt16 (bs, pos + 34) |> int
          ModuleName = modName
          ObjFileName = objName } :: acc
      loop acc (align nextOffset 4)
  loop [] 64 |> List.rev |> List.toArray

let rec readHashRecords acc (span: ByteSpan) (reader: IBinReader)
                        offset numEntries =
  if numEntries = 0u then List.rev acc
  else
    let r = { HROffset = reader.ReadInt32 (span, offset)
              HRCRef = reader.ReadInt32 (span, offset + 4) }
    readHashRecords (r :: acc) span reader (offset + 8) (numEntries - 1u)

let parseGSIHeader (span: ByteSpan) (reader: IBinReader) =
  { VersionSignature = reader.ReadUInt32 (span, 0)
    VersionHeader = reader.ReadUInt32 (span, 4)
    HashRecordSize = reader.ReadUInt32 (span, 8)
    NumBuckets = reader.ReadUInt32 (span, 12) }

let parseGSIHashRecord span reader gsiHeader =
  if gsiHeader.VersionSignature = 0xFFFFFFFFu
    && gsiHeader.VersionHeader = 0xF12F091Au
  then readHashRecords [] span reader 16 (gsiHeader.HashRecordSize / 8u)
  else []

let parseGlobalSymb reader (glStream: byte[], _glSize) =
  let span = ReadOnlySpan glStream
  let gsiHeader = parseGSIHeader span reader
  parseGSIHashRecord span reader gsiHeader

let parse span reader =
  let superBlock = parseSuperBlock span reader
  let streamDir = parseStreamDirectory span reader superBlock
  let streamMap = buildStreamMap span reader superBlock streamDir
  let dbiStream, _ = getStream streamMap 3
  let dbi = parseDBIHeader reader dbiStream
  let modules = parseModuleInfo reader dbi dbiStream
  let _gsi = getStream streamMap dbi.GlobalStreamIdx |> parseGlobalSymb reader
  getStream streamMap dbi.SymRecordStreamIdx
  |> parseSymRecordStream reader modules streamMap

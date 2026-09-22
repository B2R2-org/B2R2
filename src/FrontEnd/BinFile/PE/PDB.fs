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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile

/// SuperBlock forms the header of a PDB file.
type internal SuperBlock =
  { /// The block size of the internal file system. PDB can be considered as a
    /// file system within the file.
    BlockSize: int
    /// The index of a block within the file, at which begins a bit field
    /// representing the set of all blocks within the file, which are free.
    FreeBlockMapIdx: int
    /// The total number of blocks in the file.
    NumBlocks: int
    /// The size of the stream directory, in bytes. The stream directory
    /// contains information about each stream's size and the set of blocks
    /// that it occupies.
    NumDirectoryBytes: int
    /// The index of a block within the MSF file.
    BlockMapAddr: int }

/// The Stream Directory contains information about the other streams in an MSF
/// file. MSF is a file system internally used in a PDB file, and a file in MSF
/// is often called as a stream.
type internal StreamDirectory =
  { /// Number of streams.
    NumStreams: int
    /// The sizes of streams.
    StreamSizes: int[]
    /// The block indices for streams.
    StreamBlocks: int[][] }

/// DBI stream version.
type internal DBIStreamVersion =
  | VC41 = 930803
  | V50 = 19960307
  | V60 = 19970606
  | V70 = 19990903
  | V110 = 20091201

/// DBI stream header.
type internal DBIStreamHeader =
  { /// Compiler version
    DBIVersion: DBIStreamVersion
    /// The index to the global stream.
    GlobalStreamIdx: int
    /// The index to the public stream.
    PublicStreamIdx: int
    /// The index to the stream containing all CodeView symbol records used
    /// by the program.
    SymRecordStreamIdx: int
    /// Size of the module info substream.
    ModInfoSize: int }

/// Module information follows immediately after the DBI stream header (struct
/// ModInfo).
type internal ModuleInfo =
  { /// The section in the binary which contains the code/data from this module.
    SectionIndex: int
    /// The index of the stream that contains symbol information for
    /// this module.
    SymStreamIndex: int
    /// Module name
    ModuleName: string
    /// Object file name.
    ObjFileName: string }

/// GSI (Global Symbol Information) hash header.
type internal GSIHashHeader =
  { VersionSignature: uint32
    VersionHeader: uint32
    HashRecordSize: uint32
    NumBuckets: uint32 }

/// GSI (Global Symbol Information) hash record.
type internal GSIHashRecord =
  { /// An offset.
    HROffset: int
    /// A cross reference.
    HRCRef: int }

/// The stream holding what a PDB says about itself, which is the second one.
let [<Literal>] InfoStreamIndex = 1

/// DBI stream is the fourth stream in the MSF file, which contains
/// information about the debug information.
let [<Literal>] DBIStreamIndex = 3

/// The size of the part of the info stream that names the build, which the
/// named stream map follows.
let [<Literal>] InfoHeaderSize = 28

/// The version of the info stream that first carried a GUID, which every
/// toolchain since VC7 writes. The versions are dates, so a later one reads
/// as a greater number.
let [<Literal>] InfoVersionVC70 = 20000404

/// The size of the DBI stream header, which every field the module info
/// substream holds sits past.
let [<Literal>] DBIHeaderSize = 64

/// The signature every DBI stream leads with.
let [<Literal>] DBISignature = -1

/// The flag a public symbol carries when it names a function, which the
/// specification calls CVPSF_function.
let [<Literal>] PublicSymbolIsFunction = 0x2u

/// The block sizes the internal file system of a PDB is allowed to use.
let validBlockSizes = [| 512; 1024; 2048; 4096 |]

/// Raises when the given condition does not hold. Every check on the shape of
/// a PDB reports a file this reader cannot follow the same way.
let checkFormat cond =
  if cond then () else raise InvalidFileFormatException

/// Checks if the given span is a valid PDB header. The header is expected to
/// start with a specific magic number.
let isValidHeader (span: ByteSpan) (reader: IBinReader) =
  let magicBytes =
    [| 'M'
       'i'
       'c'
       'r'
       'o'
       's'
       'o'
       'f'
       't'
       ' '
       'C'
       '/'
       'C'
       '+'
       '+'
       ' '
       'M'
       'S'
       'F'
       ' '
       '7'
       '.'
       '0'
       '0'
       '\013'
       '\010'
       '\026'
       'D'
       'S'
       '\000'
       '\000'
       '\000' |]
  span.Length >= 32 && reader.ReadChars(span, 0, 32) = magicBytes

let parseSuperBlock (span: ByteSpan) (reader: IBinReader) =
  { BlockSize = reader.ReadInt32(span, 32)
    FreeBlockMapIdx = reader.ReadInt32(span, 36)
    NumBlocks = reader.ReadInt32(span, 40)
    NumDirectoryBytes = reader.ReadInt32(span, 44)
    BlockMapAddr = reader.ReadInt32(span, 52) }

/// Checks that the super block describes a file this reader can follow: the
/// block size is one of the four the format allows, and every block it counts
/// is in the file, as is the one its stream directory is mapped from. A file
/// failing any of these is one to give up on rather than read blocks out of.
let isValidSuperBlock (span: ByteSpan) sb =
  Array.contains sb.BlockSize validBlockSizes
  && sb.NumBlocks > 0
  && sb.BlockMapAddr > 0
  && sb.BlockMapAddr < sb.NumBlocks
  && int64 sb.NumBlocks * int64 sb.BlockSize <= int64 span.Length
  && sb.NumDirectoryBytes > 0
  && int64 sb.NumDirectoryBytes <= int64 sb.NumBlocks * int64 sb.BlockSize

let inline getNumBlocks numBytes blockSize =
  (numBytes + blockSize - 1) / blockSize

let rec readIntValues (span: ByteSpan) reader cnt acc pos =
  if cnt = 0 then
    List.rev acc
  else
    let v = (reader: IBinReader).ReadInt32(span, pos)
    readIntValues span reader (cnt - 1) (v :: acc) (pos + 4)

/// Copies the blocks the given stream occupies into one buffer. A block index
/// reaching outside the file is one no stream of a readable PDB carries.
let readStream (span: ByteSpan) blockSize blockMapAddrs =
  let size = List.length blockMapAddrs * blockSize
  let buf: byte[] = Array.zeroCreate size
  let mutable idx = 0
  for blockMapAddr in blockMapAddrs do
    let offset = int64 blockMapAddr * int64 blockSize
    checkFormat (offset >= 0L && offset + int64 blockSize <= int64 span.Length)
    span.Slice(int offset, blockSize).CopyTo(buf.AsSpan(idx * blockSize))
    idx <- idx + 1
  buf

/// Returns the size of a stream as a count of bytes to read. A stream a PDB
/// has dropped carries a size of -1, which is no bytes at all, and one that
/// claims more bytes than the whole file holds is a file to give up on.
let normalizeStreamSize limit size =
  checkFormat (int64 size <= limit)
  if size < 0 then 0 else size

let parseStreamBlks span reader sb streamSizes offset =
  let lst = List<int[]>()
  let mutable offset = offset
  for idx = 0 to Array.length streamSizes - 1 do
    let numBlks = getNumBlocks streamSizes[idx] sb.BlockSize
    checkFormat (offset + numBlks * 4 <= (span: ByteSpan).Length)
    let blocks = readIntValues span reader numBlks [] offset |> List.toArray
    offset <- offset + numBlks * 4
    lst.Add blocks
  lst |> Seq.toArray

let buildStreamDirectory sb (span: ByteSpan) reader =
  let numStream = (reader: IBinReader).ReadInt32(span, 0)
  checkFormat (numStream >= 0)
  checkFormat (int64 numStream * 4L + 4L <= int64 span.Length)
  let limit = int64 sb.NumBlocks * int64 sb.BlockSize
  let sizes = readIntValues span reader numStream [] 4 |> List.toArray
  let streamSizes = Array.map (normalizeStreamSize limit) sizes
  let streamBlks =
    parseStreamBlks span reader sb streamSizes (numStream * 4 + 4)
  { NumStreams = numStream
    StreamSizes = streamSizes
    StreamBlocks = streamBlks }

let parseStreamDirectory (span: ByteSpan) reader sb =
  let numBlks = getNumBlocks sb.NumDirectoryBytes sb.BlockSize
  let blockMapOffset = sb.BlockMapAddr * sb.BlockSize
  checkFormat (blockMapOffset + numBlks * 4 <= span.Length)
  let intVals = readIntValues span reader numBlks [] blockMapOffset
  let bs = readStream span sb.BlockSize intVals
  buildStreamDirectory sb (ReadOnlySpan bs) reader

let parseStream span superBlock streamDir idx =
  let blks = streamDir.StreamBlocks[idx] |> Array.toList
  let size = streamDir.StreamSizes[idx]
  readStream span superBlock.BlockSize blks, size

let buildStreamMap span superBlock streamDir =
  let lst = List<byte[] * int>()
  for idx = 0 to streamDir.NumStreams - 1 do
    let stream = parseStream span superBlock streamDir idx
    lst.Add stream
  lst |> Seq.toArray

let inline getStream (streamMap: (byte[] * int) array) idx = streamMap[idx]

/// Checks whether the given index names a stream the directory holds. An
/// index a PDB leaves unset reads as 0xFFFF, which names no stream at all.
let isValidStreamIndex streamMap idx =
  idx >= 0 && idx < Array.length streamMap

/// Checks that the DBI stream is one this reader can follow. It leads with a
/// fixed signature and names the layout it uses, and only the VC7.0 layout --
/// the one every toolchain since has written -- puts the fields where this
/// reader looks for them. Its module list has to be there whole, since every
/// symbol reached by reference is reached through it.
let isValidDBIStream (reader: IBinReader) (bs: byte[]) =
  bs.Length >= DBIHeaderSize
  && reader.ReadInt32(bs, 0) = DBISignature
  && reader.ReadInt32(bs, 4) = int DBIStreamVersion.V70
  && reader.ReadInt32(bs, 24) >= 0
  && reader.ReadInt32(bs, 24) <= bs.Length - DBIHeaderSize

let parseDBIHeader (reader: IBinReader) (dbiStream: byte[]) =
  let span = ReadOnlySpan dbiStream
  { DBIVersion = reader.ReadInt32(span, 4) |> LanguagePrimitives.EnumOfValue
    GlobalStreamIdx = reader.ReadUInt16(span, 12) |> int
    PublicStreamIdx = reader.ReadUInt16(span, 16) |> int
    SymRecordStreamIdx = reader.ReadUInt16(span, 20) |> int
    ModInfoSize = reader.ReadInt32(span, 24) }

let align offset n =
  if offset &&& (n - 1) > 0 then (offset &&& (~~~(n - 1))) + n else offset

/// Reads the name at the given offset, and returns it along with the offset
/// right past the terminator ending it. A name running past the limit is one
/// the substream holding it does not hold whole.
let readName (bs: byte[]) limit pos =
  checkFormat (pos >= 0 && pos <= limit)
  let idx = Array.IndexOf(bs, 0uy, pos, limit - pos)
  checkFormat (idx >= 0)
  Text.Encoding.Latin1.GetString(bs, pos, idx - pos), idx + 1

let parseModuleInfo (reader: IBinReader) dbi (bs: byte[]) =
  let limit = dbi.ModInfoSize + DBIHeaderSize
  let rec loop acc pos =
    if pos + DBIHeaderSize >= limit then
      acc
    else
      let modName, next = readName bs limit (pos + DBIHeaderSize)
      let objName, next = readName bs limit next
      let acc =
        { SectionIndex = reader.ReadUInt16(bs, pos + 4) |> int
          SymStreamIndex = reader.ReadUInt16(bs, pos + 34) |> int
          ModuleName = modName
          ObjFileName = objName } :: acc
      loop acc (align next 4)
  loop [] DBIHeaderSize |> List.rev |> List.toArray

/// Returns the whole length of the symbol record at the given offset, or none
/// when no whole record sits there. A record leads with a length counting
/// every byte of it but that field itself. A stream is allocated in whole
/// blocks, so its size, not the length of the array holding it, is where its
/// records end: past that lies whatever the blocks held before.
let tryGetRecordLength (reader: IBinReader) (bs: byte[]) size offset =
  let size = min size bs.Length
  if offset < 0 || offset + 4 > size then
    None
  else
    let len = (reader.ReadUInt16(bs, offset) |> int) + 2
    if len < 4 || offset + len > size then None else Some len

/// Returns the name a symbol record ends with, or none when the record holds
/// no terminator for it. Every record this reader knows puts its name last.
let tryReadName (sp: ByteSpan) offset =
  if offset >= sp.Length then
    None
  else
    let tail = sp.Slice offset
    let len = tail.IndexOf 0uy
    if len < 0 then
      None
    else
      Text.Encoding.Latin1.GetString(tail.Slice(0, len)) |> Some

/// Parses a public symbol record (PUBSYM32). Its flags are the only thing a
/// public PDB -- one stripped of every symbol but these -- says about whether
/// the symbol names a function.
let parsePublicSymbol (reader: IBinReader) (sp: ByteSpan) =
  match tryReadName sp 14 with
  | None ->
    None
  | Some name ->
    let flags = reader.ReadUInt32(sp, 4)
    { Address = reader.ReadUInt32(sp, 8) |> uint64
      Segment = reader.ReadUInt16(sp, 12)
      Name = name
      IsFunction = (flags &&& PublicSymbolIsFunction) <> 0u } |> Some

/// Parses a procedure symbol record (PROCSYM32), which a PDB holds for every
/// function it keeps private symbols for.
let parseProcedureSymbol (reader: IBinReader) (sp: ByteSpan) =
  match tryReadName sp 39 with
  | None ->
    None
  | Some name ->
    { Address = reader.ReadUInt32(sp, 32) |> uint64
      Segment = reader.ReadUInt16(sp, 36)
      Name = name
      IsFunction = true } |> Some

/// Returns the symbol stream of the module the given number names, or none
/// when there is no such module or it was built without symbols of its own.
/// The numbers a reference carries are one-based, and a module with nothing
/// to point at leaves its stream index unset.
let tryGetModuleStream modules streamMap n =
  match Array.tryItem (n - 1) modules with
  | Some m when isValidStreamIndex streamMap m.SymStreamIndex ->
    Array.get streamMap m.SymStreamIndex |> Some
  | _ ->
    None

/// Parses the symbol record the given span holds, unless it is a reference to
/// one held elsewhere, which only a stream of global symbols carries.
let parseDirectRecord (reader: IBinReader) (sp: ByteSpan) =
  let typ = reader.ReadUInt16(sp, 2) |> LanguagePrimitives.EnumOfValue
  match typ with
  | PDBSymbolKind.S_PUB32 -> (* PUBSYM32 *)
    parsePublicSymbol reader sp
  | PDBSymbolKind.S_LPROC32
  | PDBSymbolKind.S_GPROC32 -> (* PROCSYM32 *)
    parseProcedureSymbol reader sp
  | _ ->
    None

/// Follows a reference (REFSYM2) to the record it names, which sits in the
/// symbol stream of the module it points at. What is reached that way is
/// read as a record in its own right and never as another reference, so a
/// PDB whose references point at each other is read once and not forever.
let followSymbolRef (reader: IBinReader) (sp: ByteSpan) modules streamMap =
  let refOffset = reader.ReadInt32(sp, 8)
  let modnum = reader.ReadUInt16(sp, 12) |> int
  match tryGetModuleStream modules streamMap modnum with
  | None ->
    None
  | Some(bs, size) ->
    match tryGetRecordLength reader bs size refOffset with
    | None -> None
    | Some len -> parseDirectRecord reader (ReadOnlySpan(bs, refOffset, len))

let parseSymbolRecord reader (bs: byte[], size) offset modules streamMap =
  match tryGetRecordLength reader bs size offset with
  | None ->
    None
  | Some len ->
    let sp = ReadOnlySpan(bs, offset, len)
    let typ = reader.ReadUInt16(sp, 2) |> LanguagePrimitives.EnumOfValue
    match typ with
    | PDBSymbolKind.S_PROCREF
    | PDBSymbolKind.S_LPROCREF when len >= 14 -> (* REFSYM2 *)
      followSymbolRef reader sp modules streamMap
    | _ ->
      parseDirectRecord reader sp

/// Reads every symbol record the given stream holds, from its first byte to
/// the last one its size covers.
let parseSymRecordStream reader modules streamMap stream =
  let bs, size = stream
  let rec loop acc offset =
    match tryGetRecordLength reader bs size offset with
    | None ->
      acc
    | Some len ->
      let sym = parseSymbolRecord reader stream offset modules streamMap
      let acc = Option.fold (fun acc sym -> sym :: acc) acc sym
      loop acc (offset + len)
  loop [] 0

let rec readHashRecords acc
                        (span: ByteSpan)
                        (reader: IBinReader)
                        offset
                        numEntries =
  if numEntries = 0u then
    List.rev acc
  else
    let r = { HROffset = reader.ReadInt32(span, offset)
              HRCRef = reader.ReadInt32(span, offset + 4) }
    readHashRecords (r :: acc) span reader (offset + 8) (numEntries - 1u)

let parseGSIHeader (span: ByteSpan) (reader: IBinReader) =
  { VersionSignature = reader.ReadUInt32(span, 0)
    VersionHeader = reader.ReadUInt32(span, 4)
    HashRecordSize = reader.ReadUInt32(span, 8)
    NumBuckets = reader.ReadUInt32(span, 12) }

let parseGSIHashRecord span reader gsiHeader =
  if gsiHeader.VersionSignature = 0xFFFFFFFFu
    && gsiHeader.VersionHeader = 0xF12F091Au
  then readHashRecords [] span reader 16 (gsiHeader.HashRecordSize / 8u)
  else []

let parseGlobalSymb reader (glStream: byte[], _glSize) =
  let span = ReadOnlySpan glStream
  let gsiHeader = parseGSIHeader span reader
  parseGSIHashRecord span reader gsiHeader

/// Checks that the PDB is the one the image was built with. An image names
/// its PDB by a GUID and an age, and the PDB written by that build repeats
/// both, so a PDB whose own pair differs was written for another build: the
/// addresses it names are not the addresses of this image. An image that
/// says nothing about a PDB leaves nothing to check, and what a caller hands
/// over is then read as it is.
let isMatchingPDB (reader: IBinReader) (bs: byte[]) expected =
  match expected with
  | None ->
    true
  | Some cv ->
    bs.Length >= InfoHeaderSize
    && reader.ReadInt32(bs, 0) >= InfoVersionVC70
    && reader.ReadInt32(bs, 8) = cv.Age
    && Array.sub bs 12 16 = cv.Guid

/// Reads every symbol the given streams hold, which is what a PDB is read
/// for. They are reached through the DBI stream, which names the stream of
/// symbol records and the modules those records reach into.
let parseSymbols reader streamMap =
  checkFormat (isValidStreamIndex streamMap DBIStreamIndex)
  let dbiStream, _ = getStream streamMap DBIStreamIndex
  checkFormat (isValidDBIStream reader dbiStream)
  let dbi = parseDBIHeader reader dbiStream
  let modules = parseModuleInfo reader dbi dbiStream
  checkFormat (isValidStreamIndex streamMap dbi.SymRecordStreamIdx)
  getStream streamMap dbi.SymRecordStreamIdx
  |> parseSymRecordStream reader modules streamMap

let parse span reader expected =
  let sb = parseSuperBlock span reader
  checkFormat (isValidSuperBlock span sb)
  let streamDir = parseStreamDirectory span reader sb
  let streamMap = buildStreamMap span sb streamDir
  checkFormat (isValidStreamIndex streamMap InfoStreamIndex)
  let infoStream, _ = getStream streamMap InfoStreamIndex
  if isMatchingPDB reader infoStream expected then parseSymbols reader streamMap
  else []

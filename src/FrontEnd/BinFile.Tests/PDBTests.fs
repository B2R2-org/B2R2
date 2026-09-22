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

namespace B2R2.FrontEnd.BinFile.Tests

open System
open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.PE
open B2R2.FrontEnd.BinFile.PE.PDB
open Microsoft.VisualStudio.TestTools.UnitTesting
open type FileFormat

/// Tests the reader of the CodeView records a PDB holds. Every record here is
/// built by hand, since what these tests are about -- a stream ending where
/// its size says it does, a reference pointing at nothing -- is the shape of
/// a record rather than anything a compiler can be asked to emit.
[<TestClass>]
type PDBTests() =
  static let reader = BinReader.Init Endian.Little

  /// Builds a symbol record: a length covering every byte but itself, the
  /// kind, and the body that kind calls for.
  static let symbolRecord (kind: PDBSymbolKind) (body: byte[]) =
    [| BitConverter.GetBytes(uint16 (body.Length + 2))
       BitConverter.GetBytes(uint16 kind)
       body |]
    |> Array.concat

  /// Builds a public symbol record (PUBSYM32).
  static let publicSymbol flags addr seg (name: string) =
    [| BitConverter.GetBytes(uint32 flags)
       BitConverter.GetBytes(uint32 addr)
       BitConverter.GetBytes(uint16 seg)
       Text.Encoding.ASCII.GetBytes name
       [| 0uy |] |]
    |> Array.concat
    |> symbolRecord PDBSymbolKind.S_PUB32

  /// Builds a procedure symbol record (PROCSYM32) of the given kind.
  static let procedureSymbol kind len addr seg (name: string) =
    [| Array.zeroCreate 12
       BitConverter.GetBytes(uint32 len)
       Array.zeroCreate 12
       BitConverter.GetBytes(uint32 addr)
       BitConverter.GetBytes(uint16 seg)
       [| 0uy |]
       Text.Encoding.ASCII.GetBytes name
       [| 0uy |] |]
    |> Array.concat
    |> symbolRecord kind

  /// Builds a data symbol record (DATASYM32).
  static let dataSymbol addr seg (name: string) =
    [| BitConverter.GetBytes 0u
       BitConverter.GetBytes(uint32 addr)
       BitConverter.GetBytes(uint16 seg)
       Text.Encoding.ASCII.GetBytes name
       [| 0uy |] |]
    |> Array.concat
    |> symbolRecord PDBSymbolKind.S_GDATA32

  /// Builds a reference to a procedure in another module's stream (REFSYM2).
  static let procedureRef modnum symOffset (name: string) =
    [| BitConverter.GetBytes 0u
       BitConverter.GetBytes(uint32 symOffset)
       BitConverter.GetBytes(uint16 modnum)
       Text.Encoding.ASCII.GetBytes name
       [| 0uy |] |]
    |> Array.concat
    |> symbolRecord PDBSymbolKind.S_PROCREF

  /// Builds the entry the module list holds for a module carrying the given
  /// symbol stream.
  static let moduleInfo symStreamIdx =
    { SectionIndex = 1
      SymStreamIndex = symStreamIdx
      ModuleName = "a.obj"
      ObjFileName = "a.obj" }

  /// The header of a PDB holding nothing, which is every PDB whose records
  /// are handed over rather than read out of its blocks.
  static let emptySuperBlock =
    { BlockSize = 4096
      FreeBlockMapIdx = 1
      NumBlocks = 0
      NumDirectoryBytes = 0
      BlockMapAddr = 0 }

  /// A store holding no stream, which is all a record naming no other one
  /// ever reaches into.
  static let noStreams =
    { PDBBytes = [||]
      SuperBlock = emptySuperBlock
      Directory = { NumStreams = 0; StreamSizes = [||]; StreamBlocks = [||] }
      ReadStreams = Dictionary() }

  static let readRecords modules stream =
    parseSymRecordStream reader modules noStreams stream

  /// Builds the info stream of a PDB naming the given build.
  static let infoStream version age (guid: byte[]) =
    [| BitConverter.GetBytes(uint32 version)
       BitConverter.GetBytes 0u
       BitConverter.GetBytes(uint32 age)
       guid |]
    |> Array.concat

  static let guidA = Array.create 16 0xAAuy

  static let guidB = Array.create 16 0xBBuy

  static let codeView age guid =
    { Guid = guid; Age = age; PDBPath = @"D:\build\out\prog.pdb" }

  /// A stream is allocated in whole blocks, so the array holding one can be
  /// longer than the stream is. Records running to the last byte the size
  /// covers are records to read, and the end of the stream is not a reason to
  /// read one byte further.
  [<TestMethod>]
  member _.``[PDB] symbol records ending on the stream size test``() =
    let bs = publicSymbol 2 0x20 1 "helper"
    Assert.AreEqual<int>(1, readRecords [||] (bs, bs.Length) |> List.length)

  /// The bytes past a stream's size are whatever the blocks held before it,
  /// so a record reaching into them is no record of this stream.
  [<TestMethod>]
  member _.``[PDB] symbol records stopping at the stream size test``() =
    let first = publicSymbol 2 0x20 1 "helper"
    let stale = publicSymbol 2 0x40 1 "stale"
    let bs = Array.append first stale
    let syms = readRecords [||] (bs, first.Length + 6)
    Assert.AreEqual<int>(1, List.length syms)

  /// A public PDB -- one stripped of every symbol but these -- says a symbol
  /// names a function only through the flags its record carries.
  [<TestMethod>]
  member _.``[PDB] public symbol naming a function test``() =
    let bs = publicSymbol 2 0x20 1 "helper"
    match readRecords [||] (bs, bs.Length) with
    | [ sym ] ->
      Assert.AreEqual<string>("helper", sym.Name)
      Assert.AreEqual<bool>(true, sym.IsFunction)
    | _ ->
      Assert.Fail()

  /// The same flags are what says a public symbol names something other than
  /// a function, which is every public symbol a data object has.
  [<TestMethod>]
  member _.``[PDB] public symbol naming no function test``() =
    let bs = publicSymbol 0 0x20 1 "counter"
    match readRecords [||] (bs, bs.Length) with
    | [ sym ] ->
      Assert.AreEqual<string>("counter", sym.Name)
      Assert.AreEqual<bool>(false, sym.IsFunction)
    | _ ->
      Assert.Fail()

  /// A module built without symbols of its own leaves its stream index unset,
  /// which reads as 0xFFFF and names no stream to follow the reference into.
  [<TestMethod>]
  member _.``[PDB] reference into a module with no stream test``() =
    let bs = procedureRef 1 0 "helper"
    let syms = readRecords [| moduleInfo 0xFFFF |] (bs, bs.Length)
    Assert.AreEqual<int>(0, List.length syms)

  /// Module numbers a reference carries are one-based, so a zero names no
  /// module, and neither does a number past the end of the list.
  [<TestMethod>]
  member _.``[PDB] reference to a module outside the list test``() =
    let modules = [| moduleInfo 1 |]
    let zero = procedureRef 0 0 "helper"
    let past = procedureRef 9 0 "helper"
    let byZero = readRecords modules (zero, zero.Length)
    let byPast = readRecords modules (past, past.Length)
    Assert.AreEqual<int>(0, List.length byZero)
    Assert.AreEqual<int>(0, List.length byPast)

  /// A PDB repeating the GUID and age its image names is that image's.
  [<TestMethod>]
  member _.``[PDB] info stream naming the same build test``() =
    let info = infoStream 20000404 7 guidA
    let expected = Some(codeView 7 guidA)
    Assert.AreEqual<bool>(true, isMatchingPDB reader info expected)

  /// A GUID of its own is what a PDB written for another image carries, and
  /// the addresses such a PDB names are not the addresses of this one.
  [<TestMethod>]
  member _.``[PDB] info stream naming another build test``() =
    let info = infoStream 20000404 7 guidB
    let expected = Some(codeView 7 guidA)
    Assert.AreEqual<bool>(false, isMatchingPDB reader info expected)

  /// An incremental link writes the PDB again under the same GUID and raises
  /// the age instead, so the age tells one such write from another.
  [<TestMethod>]
  member _.``[PDB] info stream naming another age test``() =
    let info = infoStream 20000404 8 guidA
    let expected = Some(codeView 7 guidA)
    Assert.AreEqual<bool>(false, isMatchingPDB reader info expected)

  /// Only VC7.0 and later carry a GUID at all, so what reads as one in an
  /// older info stream is some other field and names no build.
  [<TestMethod>]
  member _.``[PDB] info stream older than a GUID test``() =
    let info = infoStream 19990604 7 guidA
    let expected = Some(codeView 7 guidA)
    Assert.AreEqual<bool>(false, isMatchingPDB reader info expected)

  /// An image saying nothing about a PDB leaves nothing to check, and what a
  /// caller hands over is read as it is.
  [<TestMethod>]
  member _.``[PDB] info stream with nothing to match test``() =
    let info = infoStream 20000404 7 guidA
    Assert.AreEqual<bool>(true, isMatchingPDB reader info None)

  /// An image names the PDB the linker wrote, which is not always the image's
  /// own name: /PDBSTRIPPED and /PDB both give it one of their own. The name
  /// at the end of the recorded path is looked for beside the image, ahead of
  /// the image's own name; the recorded path itself is the build machine's
  /// and is never followed.
  [<TestMethod>]
  member _.``[PDB] search paths name the recorded PDB first test``() =
    let cv = { Guid = guidA; Age = 1; PDBPath = @"D:\build\out\full.pdb" }
    let exe = IO.Path.Combine("bin", "prog.exe")
    let paths = Parser.getPDBSearchPaths exe cv
    Assert.AreEqual<int>(2, List.length paths)
    Assert.AreEqual<string>(IO.Path.Combine("bin", "full.pdb"), paths[0])
    Assert.AreEqual<string>(IO.Path.Combine("bin", "prog.pdb"), paths[1])

  /// A procedure record says how far the function reaches as well as where it
  /// begins, which is the one size any record in a PDB carries.
  [<TestMethod>]
  member _.``[PDB] procedure symbol carrying its length test``() =
    let bs = procedureSymbol PDBSymbolKind.S_GPROC32 0x2a 0x20 1 "helper"
    match readRecords [||] (bs, bs.Length) with
    | [ sym ] ->
      Assert.AreEqual<string>("helper", sym.Name)
      Assert.AreEqual<bool>(true, sym.IsFunction)
      Assert.AreEqual<uint64 option>(Some 0x2aUL, sym.Size)
    | _ ->
      Assert.Fail()

  /// A compiler that keeps ID records names a procedure's type by an ID index
  /// and writes S_GPROC32_ID for it, which lays out as S_GPROC32 does.
  [<TestMethod>]
  member _.``[PDB] procedure symbol of the ID kind test``() =
    let bs = procedureSymbol PDBSymbolKind.S_GPROC32_ID 0x2a 0x20 1 "helper"
    match readRecords [||] (bs, bs.Length) with
    | [ sym ] ->
      Assert.AreEqual<string>("helper", sym.Name)
      Assert.AreEqual<bool>(true, sym.IsFunction)
    | _ ->
      Assert.Fail()

  /// A data record lays its address out where a public symbol does, but what
  /// sits where that one keeps its flags is a type index, so nothing in a
  /// data record ever makes it a function.
  [<TestMethod>]
  member _.``[PDB] data symbol test``() =
    let bs = dataSymbol 0x3000 2 "counter"
    match readRecords [||] (bs, bs.Length) with
    | [ sym ] ->
      Assert.AreEqual<string>("counter", sym.Name)
      Assert.AreEqual<bool>(false, sym.IsFunction)
      Assert.AreEqual<uint64 option>(None, sym.Size)
    | _ ->
      Assert.Fail()

  /// A PDB cut short holds a file system naming more blocks than are there.
  /// Whichever read finds that out, what reaches the caller says the one
  /// thing it can act on: this is not a PDB to read symbols out of.
  [<TestMethod>]
  member _.``[PDB] truncated PDB test``() =
    let bytes = ZIPReader.readBytes PEBinary "pe_x64_pdb.zip" "pe_x64_pdb.pdb"
    let half = Array.sub bytes 0 (bytes.Length / 2)
    let thrown =
      try
        Parser.parsePDB reader None half |> ignore
        false
      with InvalidFileFormatException ->
        true
    Assert.AreEqual<bool>(true, thrown)

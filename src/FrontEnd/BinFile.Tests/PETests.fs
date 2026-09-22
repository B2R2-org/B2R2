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
open System.IO
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.PE
open Microsoft.VisualStudio.TestTools.UnitTesting
open type FileFormat

[<TestClass>]
type PETests() =
  static let isStripped (file: IBinFile) = file.SymbolTable.Value.IsStripped

  static let parseFile fileName =
    let zipFile = fileName + ".zip"
    let fileNameInZip = fileName + ".exe"
    let bytes = ZIPReader.readBytes PEBinary zipFile fileNameInZip
    PEBinFile(fileNameInZip, bytes, None, [||])

  static let parseFileWithPdb fileName =
    let zipFile = fileName + ".zip"
    let exeName = fileName + ".exe"
    let bytes = ZIPReader.readBytes PEBinary zipFile exeName
    let pdbBytes = ZIPReader.readBytes PEBinary zipFile (fileName + ".pdb")
    PEBinFile(exeName, bytes, None, pdbBytes)

  static let parseObjFile fileName =
    let objName = fileName + ".obj"
    let bytes = ZIPReader.readBytes PEBinary (fileName + ".zip") objName
    PEBinFile(objName, bytes, None, [||])

  static let parseDllFile fileName =
    let dllName = fileName + ".dll"
    let bytes = ZIPReader.readBytes PEBinary (fileName + ".zip") dllName
    PEBinFile(dllName, bytes, None, [||])

  /// This test assembly is itself a managed PE -- pure IL, marked AnyCPU --
  /// which is the shape nearly every .NET assembly has. Reading it back costs
  /// no fixture and cannot drift from what a loader has to handle.
  static let managedBytes =
    Reflection.Assembly.GetExecutingAssembly().Location |> File.ReadAllBytes

  /// Rewrites the COR header's flags field, which sits 16 bytes into that
  /// header, so that one assembly can stand for every combination of them.
  static let withCorFlags (flags: CorFlags) =
    let bytes = Array.copy managedBytes
    let hdr = Header.parse bytes (BinReader.Init Endian.Little)
    BitConverter.GetBytes(int flags).CopyTo(bytes, hdr.CorHeaderOffset + 16)
    bytes

  /// Reads back the ISA of this assembly rewritten to carry the given flags.
  static let managedISA flags =
    (PEBinFile("", withCorFlags flags, None, [||]) :> IBinFile).ISA

  /// A minimal x64 console executable (no PDB), used as the canonical fixture
  /// for metadata, section, and address-space tests.
  static let x64File = parseFile "pe_x64"

  /// A minimal x86 (32-bit) console executable (no PDB), exercising the PE32
  /// header and 32-bit ISA decoding.
  static let x86File = parseFile "pe_x86"

  /// The x64 executable bundled with its PDB, exercising the PDB-based symbol
  /// path (PE images carry no symbols of their own).
  static let x64PdbFile = parseFileWithPdb "pe_x64_pdb"

  /// The same source built with /PDBSTRIPPED, whose PDB is the public one a
  /// symbol server hands out: every private symbol is gone, so each function
  /// is named by a public symbol record and by nothing else.
  static let x64PdbStrippedFile = parseFileWithPdb "pe_x64_pdb_stripped"

  /// A COFF object file (.obj), exercising the COFF-only path: no entry point,
  /// an object kind, and a COFF symbol table (no PDB needed).
  static let x64ObjFile = parseObjFile "pe_x64_obj"

  /// A DLL exporting a single function, exercising the shared-library kind and
  /// export-table name resolution (no PDB needed).
  static let x64DllFile = parseDllFile "pe_x64_dll"

  /// A C++/SEH binary (try/catch plus __try/__except): its UNWIND_INFO carries
  /// a personality routine, the SEH frame carries a C scope table, and the C++
  /// try uses the compressed (FH4) FuncInfo format.
  static let x64ExcFile = parseFile "pe_x64_exc"

  /// The same source built with /d2FH4-, so the C++ try/catch uses the classic
  /// (FH3) FuncInfo format instead of the compressed FH4 one.
  static let x64ExcFh3File = parseFile "pe_x64_exc_fh3"

  /// A /guard:cf build, whose load configuration lists every function the
  /// loader will let an indirect call reach.
  static let x64GuardCFFile = parseFile "pe_x64_guardcf"

  /// A build with two TLS callbacks, which the loader runs as a thread
  /// starts and ends and which nothing else in the image names.
  static let x64TLSFile = parseFile "pe_x64_tls"

  /// Rewrites the RVA of one data directory, which is how a file naming a
  /// directory that lands nowhere is made out of a sound one. The directories
  /// follow the optional header, whose PE32+ form runs 112 bytes.
  static let withDirectoryRVA index rva (bytes: byte[]) =
    let bytes = Array.copy bytes
    let hdr = Header.parse bytes (BinReader.Init Endian.Little)
    let offset = hdr.OptionalHeaderOffset + 112 + index * 8
    BitConverter.GetBytes(rva: int).CopyTo(bytes, offset)
    bytes

  /// Renames every section whose name starts with ".text", leaving an object
  /// that names no code section at all, which is what a data-only object and
  /// an LTCG one are. A section header runs 40 bytes.
  static let withoutTextSections (bytes: byte[]) =
    let bytes = Array.copy bytes
    let hdrs = Header.parse bytes (BinReader.Init Endian.Little)
    let table = hdrs.SectionHeaderTblOffset
    let secs = hdrs.SectionHeaders
    for i in 0 .. secs.Length - 1 do
      if secs[i].Name.StartsWith ".text" then
        ".zzzz"B.CopyTo(bytes, table + i * 40)
      else
        ()
    bytes

  /// Points the sole export at the string naming it, which sits inside the
  /// export directory and so reads as a forwarder, and which carries no dot
  /// to part a library name from a function name.
  static let withDotlessForwarder (bytes: byte[]) =
    let bytes = Array.copy bytes
    let hdrs = Header.parse bytes (BinReader.Init Endian.Little)
    let secs = hdrs.SectionHeaders
    let toOffset rva =
      let sec = secs[PEUtils.findContainingSectionIndex secs rva]
      rva - sec.VirtualAddress + sec.PointerToRawData
    let opt = Option.get hdrs.OptionalHeader
    let dir = opt.Directory DirectoryKind.ExportTable
    let dirOffset = PEUtils.tryGetDirectoryOffset secs dir |> Option.get
    let eatRVA = BitConverter.ToInt32(bytes, dirOffset + 28)
    let enptRVA = BitConverter.ToInt32(bytes, dirOffset + 32)
    let nameRVA = BitConverter.ToInt32(bytes, toOffset enptRVA)
    BitConverter.GetBytes(nameRVA).CopyTo(bytes, toOffset eatRVA)
    bytes

  /// The names the aliased export goes under, in the order the export name
  /// pointer table lists them.
  static let aliasNames = [| "alias_first"; "alias_second" |]

  /// Gives the sole export both of those names, each naming the same ordinal,
  /// which is what an alias export is. The two tables and the names go in the
  /// room the section holds past what it maps, the export directory itself
  /// having none to spare. Each name is given sixteen bytes of its own, which
  /// is more than either of them takes.
  static let withAliasedExport (bytes: byte[]) =
    let bytes = Array.copy bytes
    let hdrs = Header.parse bytes (BinReader.Init Endian.Little)
    let secs = hdrs.SectionHeaders
    let opt = Option.get hdrs.OptionalHeader
    let dir = opt.Directory DirectoryKind.ExportTable
    let dirOffset = PEUtils.tryGetDirectoryOffset secs dir |> Option.get
    let sec = secs[PEUtils.findContainingSectionIndex secs dir.RVA]
    let tblRVA = sec.VirtualAddress + PEUtils.alignUp sec.VirtualSize 16
    let tblOffset = tblRVA - sec.VirtualAddress + sec.PointerToRawData
    let putInt (v: int) (offset: int) =
      BitConverter.GetBytes(v).CopyTo(bytes, offset)
    let putOrd (v: uint16) (offset: int) =
      BitConverter.GetBytes(v).CopyTo(bytes, offset)
    putInt 2 (dirOffset + 24)
    putInt tblRVA (dirOffset + 32)
    putInt (tblRVA + 8) (dirOffset + 36)
    for i in 0 .. aliasNames.Length - 1 do
      putInt (tblRVA + 16 + i * 16) (tblOffset + i * 4)
      putOrd 0us (tblOffset + 8 + i * 2)
      Text.Encoding.Latin1.GetBytes(aliasNames[i])
        .CopyTo(bytes, tblOffset + 16 + i * 16)
    bytes

  /// Every fixture of a format other than PE, read out of its archive. The
  /// entry inside is named after the archive itself, but for the two formats
  /// that give it an extension of its own.
  static let otherFormatBytes =
    let extensionOf = function
      | FileFormat.WasmBinary -> ".wasm"
      | FileFormat.PythonBinary -> ".pyc"
      | _ -> ""
    [| for fmt in [| ELFBinary; MachBinary; WasmBinary; PythonBinary |] do
         for name in ZIPReader.listFixtureNames fmt do
           let entry = name + extensionOf fmt
           name, ZIPReader.readBytes fmt (name + ".zip") entry |]

  let assertExistenceOfRelocBlock (file: PEBinFile) pageRVA blockSize =
    file.RelocBlocks
    |> List.map (fun b -> b.PageRVA, b.BlockSize)
    |> assertExistenceOfPair (pageRVA, blockSize)

  [<TestMethod>]
  member _.``[PE] X64 PDB build ID test``() =
    (* PE names a build by the GUID of the PDB it was built with, which the
       CodeView entry of its debug directory carries. *)
    let hex = "590d440e92d5dc4294c27ae9b2c70ae2"
    let expected = ByteArray.ofHexString hex
    CollectionAssert.AreEqual(expected, (x64PdbFile :> IBinFile).BuildId)

  [<TestMethod>]
  member _.``[PE] X64 without CodeView has no build ID test``() =
    (* The debug directory of this one holds only a POGO entry, which names
       no PDB and so names no build. *)
    CollectionAssert.AreEqual([||], (x64File :> IBinFile).BuildId)

  [<TestMethod>]
  member _.``[PE] X64 object file has no build ID test``() =
    (* An object file has no optional header, so no debug directory either. *)
    CollectionAssert.AreEqual([||], (x64ObjFile :> IBinFile).BuildId)

  [<TestMethod>]
  member _.``[PE] x64 ISA test``() =
    let isa = (x64File :> IBinFile).ISA
    Assert.AreEqual(Architecture.Intel, isa.Arch)
    Assert.AreEqual(WordSize.Bit64, isa.WordSize)
    Assert.AreEqual(Endian.Little, isa.Endian)

  [<TestMethod>]
  member _.``[PE] OS test``() =
    Assert.AreEqual<OS>(OS.Windows, (x64File :> IBinFile).OS)

  [<TestMethod>]
  member _.``[PE] x64 entry point test``() =
    Assert.AreEqual(Some 0x140001290UL, (x64File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[PE] x64 file type test``() =
    let flg = Characteristics.ExecutableImage
    Assert.AreEqual
      (true, x64File.Header.CoffHeader.Characteristics.HasFlag flg)

  [<TestMethod>]
  member _.``[PE] x64 dependencies test``() =
    (* The import directory names one entry per DLL, and an image with no
       export directory announces no name of its own. *)
    let file = x64File :> IBinFile
    let expected =
      [| "KERNEL32.dll"
         "VCRUNTIME140.dll"
         "api-ms-win-crt-heap-l1-1-0.dll"
         "api-ms-win-crt-locale-l1-1-0.dll"
         "api-ms-win-crt-math-l1-1-0.dll"
         "api-ms-win-crt-runtime-l1-1-0.dll"
         "api-ms-win-crt-stdio-l1-1-0.dll" |]
    CollectionAssert.AreEqual(expected, Array.sort file.DependencyNames)
    Assert.AreEqual<string option>(None, file.SharedObjectName)

  [<TestMethod>]
  member _.``[PE] x64 dll announces its own name test``() =
    let file = x64DllFile :> IBinFile
    let expected = Some "pe_x64_dll.dll"
    Assert.AreEqual<string option>(expected, file.SharedObjectName)

  [<TestMethod>]
  member _.``[PE] x64 kind test``() =
    Assert.AreEqual<BinFileKind>(Executable, (x64File :> IBinFile).Kind)

  [<TestMethod>]
  member _.``[PE] x64 is PIE test``() =
    Assert.AreEqual<bool>(true, (x64File :> IBinFile).IsPIE)

  [<TestMethod>]
  member _.``[PE] x64 is base-relative test``() =
    Assert.AreEqual<bool>(true, (x64File :> IBinFile).IsBaseRelative)

  [<TestMethod>]
  member _.``[PE] x64 has no Relro test``() =
    Assert.AreEqual<Relro option>(None, (x64File :> IBinFile).Relro)

  [<TestMethod>]
  member _.``[PE] x64 has no rpath test``() =
    let file = x64File :> IBinFile
    CollectionAssert.AreEqual([||], file.RPath)
    CollectionAssert.AreEqual([||], file.RunPath)

  [<TestMethod>]
  member _.``[PE] x64 has no program header table info test``() =
    let file = x64File :> IBinFile
    Assert.AreEqual(None, file.ProgramHeaderTable)

  [<TestMethod>]
  member _.``[PE] x64 base address test``() =
    Assert.AreEqual<uint64>(0x140000000UL, (x64File :> IBinFile).BaseAddress)

  [<TestMethod>]
  member _.``[PE] x64 IsNXEnabled test``() =
    Assert.AreEqual<bool>(true, (x64File :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[PE] x64 IsStripped test``() =
    Assert.AreEqual<bool>(true, isStripped (x64File :> IBinFile))

  [<TestMethod>]
  member _.``[PE] x64 text section address test``() =
    Assert.AreEqual<uint64>(0x140001000UL, getTextSectionAddr x64File)

  [<TestMethod>]
  member _.``[PE] x64 sections length test``() =
    Assert.AreEqual<int>(5, x64File.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[PE] x86 ISA test``() =
    let isa = (x86File :> IBinFile).ISA
    Assert.AreEqual(Architecture.Intel, isa.Arch)
    Assert.AreEqual(WordSize.Bit32, isa.WordSize)
    Assert.AreEqual(Endian.Little, isa.Endian)

  [<TestMethod>]
  member _.``[PE] pure IL assembly ISA test``() =
    let isa = managedISA CorFlags.ILOnly
    Assert.AreEqual(Architecture.CIL, isa.Arch)
    Assert.AreEqual<string>("cil", isa.ToString())

  /// Strong-name signing says nothing about whether an assembly holds native
  /// code, and most assemblies shipped through NuGet carry the flag. Reading
  /// the COR flags as a whole value rather than testing the one bit made every
  /// one of them look like a mixed-mode binary.
  [<TestMethod>]
  member _.``[PE] signed pure IL assembly ISA test``() =
    let isa = managedISA (CorFlags.ILOnly ||| CorFlags.StrongNameSigned)
    Assert.AreEqual(Architecture.CIL, isa.Arch)
    Assert.AreEqual<string>("cil", isa.ToString())

  /// A mixed-mode assembly holds native code and is entered through it, so the
  /// ISA that describes it is the one that code is in. Whatever IL it also
  /// holds is a fact about the file rather than about its instruction set.
  [<TestMethod>]
  member _.``[PE] mixed-mode assembly ISA test``() =
    let isa = managedISA CorFlags.StrongNameSigned
    Assert.AreEqual(Architecture.Intel, isa.Arch)
    Assert.AreEqual(WordSize.Bit32, isa.WordSize)

  /// A PDB sitting beside an image that this parser cannot read is not a
  /// reason to fail to load the image, since nothing asked for that file in
  /// the first place. Every .NET assembly built today ships a portable PDB,
  /// which is not the format this parser reads, and this test assembly is one
  /// such assembly with one such PDB next to it.
  [<TestMethod>]
  member _.``[PE] unreadable PDB beside the image test``() =
    let path = Reflection.Assembly.GetExecutingAssembly().Location
    let file = PEBinFile(path, managedBytes, None, [||]) :> IBinFile
    Assert.AreEqual(PEBinary, file.Format)
    Assert.AreEqual(Architecture.CIL, file.ISA.Arch)

  [<TestMethod>]
  member _.``[PE] x86 entry point test``() =
    Assert.AreEqual(Some 0x4012F0UL, (x86File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[PE] x86 file type test``() =
    let flg = Characteristics.ExecutableImage
    Assert.AreEqual
      (true, x86File.Header.CoffHeader.Characteristics.HasFlag flg)

  [<TestMethod>]
  member _.``[PE] x86 text section address test``() =
    Assert.AreEqual<uint64>(0x401000UL, getTextSectionAddr x86File)

  [<TestMethod>]
  member _.``[PE] x86 sections length test``() =
    Assert.AreEqual<int>(4, x86File.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[PE] x86 IsStripped test``() =
    Assert.AreEqual<bool>(true, isStripped (x86File :> IBinFile))

  [<TestMethod>]
  member _.``[PE] x64 pdb IsStripped test``() =
    Assert.AreEqual<bool>(false, isStripped (x64PdbFile :> IBinFile))

  [<TestMethod>]
  member _.``[PE] x64 pdb function symbol test (1)``() =
    assertFuncSymbolExistence x64PdbFile 0x140001040UL "main"

  [<TestMethod>]
  member _.``[PE] x64 pdb function symbol test (2)``() =
    assertFuncSymbolExistence x64PdbFile 0x140001020UL "helper"

  /// A PDB keeping private symbols says how far each function reaches, which
  /// is the one size a PE names anywhere. helper is the 11 bytes its four
  /// instructions take, and main the 16 of its five.
  [<TestMethod>]
  member _.``[PE] x64 pdb function size test``() =
    let tbl = (x64PdbFile :> IBinFile).SymbolTable.Value
    match tbl.TryFindSymbolByAddr 0x140001020UL with
    | Ok s -> Assert.AreEqual<uint64 option>(Some 11UL, s.Size)
    | Error _ -> Assert.Fail()

  /// A public symbol says only where a function begins, so a PDB stripped of
  /// every other record says nothing about how far one reaches.
  [<TestMethod>]
  member _.``[PE] x64 stripped pdb has no function size test``() =
    let tbl = (x64PdbStrippedFile :> IBinFile).SymbolTable.Value
    match tbl.TryFindSymbolByAddr 0x140001020UL with
    | Ok s -> Assert.AreEqual<uint64 option>(None, s.Size)
    | Error _ -> Assert.Fail()

  [<TestMethod>]
  member _.``[PE] x64 stripped pdb function symbol test (1)``() =
    assertFuncSymbolExistence x64PdbStrippedFile 0x140001040UL "main"

  [<TestMethod>]
  member _.``[PE] x64 stripped pdb function symbol test (2)``() =
    assertFuncSymbolExistence x64PdbStrippedFile 0x140001020UL "helper"

  /// A public symbol record says whether it names a function, and in a PDB
  /// stripped of private symbols it is the only record that says so at all.
  [<TestMethod>]
  member _.``[PE] x64 stripped pdb symbol kind test``() =
    let tbl = (x64PdbStrippedFile :> IBinFile).SymbolTable.Value
    match tbl.TryFindSymbolByAddr 0x140001020UL with
    | Ok s ->
      Assert.AreEqual<string>("helper", s.Name)
      Assert.AreEqual<BinSymbolKind>(FunctionSymbol, s.Kind)
    | Error _ ->
      Assert.Fail()

  /// A leaf function needs no unwinding, so .pdata names main and nothing
  /// else here. What makes helper a function the image knows about is the
  /// flag its public symbol carries, and there is no other trace of it.
  /// An image names its PDB by more than the GUID that is its build ID: the
  /// age tells one write of that PDB from the next, and the path says what
  /// the linker called it.
  [<TestMethod>]
  member _.``[PE] x64 pdb code view record test``() =
    let bytes = ZIPReader.readPEFixture "pe_x64_pdb"
    let hdrs = Header.parse bytes (BinReader.Init Endian.Little)
    let reader = BinReader.Init Endian.Little
    match hdrs.OptionalHeader with
    | Some hdr ->
      match CodeViewInfo.tryFind bytes reader hdrs.SectionHeaders hdr with
      | Some cv ->
        Assert.AreEqual<int>(1, cv.Age)
        Assert.AreEqual<int>(16, cv.Guid.Length)
        Assert.AreEqual<bool>(true, cv.PDBPath.EndsWith "pe_x64_pdb.pdb")
      | None ->
        Assert.Fail()
    | None ->
      Assert.Fail()

  /// A PDB written for another build names another GUID, and the addresses it
  /// holds are that build's rather than this one's. Reading it would put one
  /// image's names on another image's addresses, so it yields no symbols at
  /// all -- here the PDB of the full build, handed to the stripped image.
  [<TestMethod>]
  member _.``[PE] x64 pdb built for another image test``() =
    let name = "pe_x64_pdb_stripped"
    let exe = ZIPReader.readBytes PEBinary (name + ".zip") (name + ".exe")
    let pdb = ZIPReader.readBytes PEBinary "pe_x64_pdb.zip" "pe_x64_pdb.pdb"
    let file = PEBinFile(name + ".exe", exe, None, pdb) :> IBinFile
    Assert.AreEqual<int>(0, file.SymbolTable.Value.Symbols.Length)

  [<TestMethod>]
  member _.``[PE] x64 stripped pdb function addresses test``() =
    let file = x64PdbStrippedFile :> IBinFile
    let addrs = file.Structure.Value.FunctionAddresses
    Assert.AreEqual<bool>(true, Array.contains 0x140001040UL addrs)
    Assert.AreEqual<bool>(true, Array.contains 0x140001020UL addrs)

  [<TestMethod>]
  member _.``[PE] x64 obj has no entry point test``() =
    Assert.AreEqual<uint64 option>(None, (x64ObjFile :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[PE] x64 obj kind test``() =
    Assert.AreEqual<BinFileKind>(Object, (x64ObjFile :> IBinFile).Kind)

  [<TestMethod>]
  member _.``[PE] x64 obj is base-relative test``() =
    Assert.AreEqual<bool>(true, (x64ObjFile :> IBinFile).IsBaseRelative)

  [<TestMethod>]
  member _.``[PE] x64 obj IsNXEnabled test``() =
    Assert.AreEqual<bool>(false, (x64ObjFile :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[PE] x64 obj IsStripped test``() =
    Assert.AreEqual<bool>(false, isStripped (x64ObjFile :> IBinFile))

  [<TestMethod>]
  member _.``[PE] x64 obj COFF symbols include functions test``() =
    (* COMDAT puts each function at offset 0 of its own section, so we check the
       COFF symbol table by name rather than by address. *)
    let names =
      (x64ObjFile :> IBinFile).SymbolTable.Value.Symbols
      |> Array.map (fun s -> s.Name)
      |> Set.ofArray
    Assert.AreEqual<bool>(true, names.Contains "main")
    Assert.AreEqual<bool>(true, names.Contains "helper")

  [<TestMethod>]
  member _.``[PE] x64 dll kind test``() =
    Assert.AreEqual<BinFileKind>(SharedLibrary, (x64DllFile :> IBinFile).Kind)

  [<TestMethod>]
  member _.``[PE] x64 dll is not PIE test``() =
    Assert.AreEqual<bool>(false, (x64DllFile :> IBinFile).IsPIE)

  [<TestMethod>]
  member _.``[PE] x64 dll is base-relative test``() =
    Assert.AreEqual<bool>(true, (x64DllFile :> IBinFile).IsBaseRelative)

  [<TestMethod>]
  member _.``[PE] x64 dll IsStripped test``() =
    Assert.AreEqual<bool>(true, isStripped (x64DllFile :> IBinFile))

  [<TestMethod>]
  member _.``[PE] x64 dll export name resolution test``() =
    assertFuncSymbolExistence x64DllFile 0x180001000UL "exported_func"

  [<TestMethod>]
  member _.``[PE] x64 dll aliased export takes one name test``() =
    (* Two names of one ordinal name one entry of the export address table,
       and so one address, which leaves one of them as the name that address
       goes under. The last of the names the table lists is the one, which is
       as good as either and is what reading the table has always given back. *)
    let bytes = ZIPReader.readBytes PEBinary "pe_x64_dll.zip" "pe_x64_dll.dll"
    let file = PEBinFile("pe_x64_dll.dll", withAliasedExport bytes, None, [||])
    let tbl = (file :> IBinFile).SymbolTable.Value
    match tbl.TryFindSymbolByAddr 0x180001000UL with
    | Ok s -> Assert.AreEqual<string>("alias_second", s.Name)
    | Error _ -> Assert.Fail()

  [<TestMethod>]
  member _.``[PE] x64 relocation block test``() =
    assertExistenceOfRelocBlock x64File 0x2000u 0x2C

  [<TestMethod>]
  member _.``[PE] x64 IsRelocationAddr test``() =
    let relocs = (x64File :> IBinFile).Relocations.Value
    Assert.AreEqual<bool>(true, relocs.IsRelocationAddr 0x140002150UL)
    Assert.AreEqual<bool>(false, relocs.IsRelocationAddr 0x140001290UL)

  [<TestMethod>]
  member _.``[PE] x64 TryGetRelocatedAddr test``() =
    let relocs = (x64File :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x140001630UL, relocs.TryGetRelocatedAddr 0x140002150UL)
    Assert.AreEqual(Error ErrorCase.ItemNotFound,
                    relocs.TryGetRelocatedAddr 0x140001290UL)

  [<TestMethod>]
  member _.``[PE] x64 exception table is parsed from .pdata``() =
    let frames = (x64File :> IBinFile).ExceptionTable.Value.Frames
    Assert.AreEqual<bool>(true, frames.Length > 0)

  [<TestMethod>]
  member _.``[PE] x64 exception frames have sane ranges``() =
    let frames = (x64File :> IBinFile).ExceptionTable.Value.Frames
    let sane =
      frames |> Array.forall (fun f -> f.FunctionEnd >= f.FunctionStart)
    Assert.AreEqual<bool>(true, sane)

  [<TestMethod>]
  member _.``[PE] x86 has no exception table entries``() =
    let frames = (x86File :> IBinFile).ExceptionTable.Value.Frames
    Assert.AreEqual<int>(0, frames.Length)

  [<TestMethod>]
  member _.``[PE] x64 exception frame has a personality routine``() =
    let frames = (x64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    let hasPersonality =
      frames |> Array.exists (fun f -> f.PersonalityRoutine.IsSome)
    Assert.AreEqual<bool>(true, hasPersonality)

  [<TestMethod>]
  member _.``[PE] x64 exception handler is resolved``() =
    let frames = (x64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    let hasHandler =
      frames |> Array.exists (fun f ->
        f.Handlers |> Array.exists (fun h -> h.Handler.IsSome))
    Assert.AreEqual<bool>(true, hasHandler)

  [<TestMethod>]
  member _.``[PE] x64 FH4 C++ catch handlers are parsed``() =
    let frames = (x64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    let multiCatch =
      frames
      |> Array.collect (fun f -> f.Handlers)
      |> Array.filter (fun h -> h.Handler.IsSome)
      |> Array.groupBy (fun h -> h.BlockStart, h.BlockEnd)
      |> Array.exists (fun (_, hs) -> hs.Length >= 2)
    Assert.AreEqual<bool>(true, multiCatch)

  [<TestMethod>]
  member _.``[PE] x64 FH3 C++ catch handlers are parsed``() =
    let frames = (x64ExcFh3File :> IBinFile).ExceptionTable.Value.Frames
    let multiCatch =
      frames
      |> Array.collect (fun f -> f.Handlers)
      |> Array.filter (fun h -> h.Handler.IsSome)
      |> Array.groupBy (fun h -> h.BlockStart, h.BlockEnd)
      |> Array.exists (fun (_, hs) -> hs.Length >= 2)
    Assert.AreEqual<bool>(true, multiCatch)

  [<TestMethod>]
  member _.``[PE] x64 valid address test``() =
    let f = x64File :> IBinFile
    Assert.AreEqual<bool>(true, f.IsValidAddr 0x140001000UL) (* .text *)
    Assert.AreEqual<bool>(true, f.IsValidAddr 0x140003220UL) (* .data tail *)
    Assert.AreEqual<bool>(false, f.IsValidAddr 0x140030000UL) (* unmapped *)

  [<TestMethod>]
  member _.``[PE] x64 address mapped to file test``() =
    (* .text is file-backed, but the tail of .data (virtual size > raw size) is
       not. *)
    let f = x64File :> IBinFile
    Assert.AreEqual<bool>(true, f.IsAddrMappedToFile 0x140001000UL)
    Assert.AreEqual<bool>(false, f.IsAddrMappedToFile 0x140003220UL)

  [<TestMethod>]
  member _.``[PE] x64 valid range test``() =
    (* .text reaches as far as its virtual size says, which leaves the rest of
       the page it ends in a gap before .rdata begins. A range with both ends
       mapped still crosses that gap, so checking the ends is not enough. *)
    let f = x64File :> IBinFile
    let inside: AddrRange = { Min = 0x140001000UL; Max = 0x140001100UL }
    let crossing: AddrRange = { Min = 0x140001000UL; Max = 0x140002000UL }
    let past: AddrRange = { Min = 0x140006000UL; Max = 0x140006100UL }
    Assert.AreEqual<bool>(true, f.IsValidRange inside)
    Assert.AreEqual<bool>(false, f.IsValidRange crossing)
    Assert.AreEqual<bool>(false, f.IsValidRange past)

  [<TestMethod>]
  member _.``[PE] x64 valid range boundary test``() =
    (* .text spans 0x140001000-0x140001c27, and one past its end is the gap. *)
    let f = x64File :> IBinFile
    let first: AddrRange = { Min = 0x140001000UL; Max = 0x140001000UL }
    let last: AddrRange = { Min = 0x140001c27UL; Max = 0x140001c27UL }
    let onePast: AddrRange = { Min = 0x140001c28UL; Max = 0x140001c28UL }
    let whole: AddrRange = { Min = 0x140001000UL; Max = 0x140001c27UL }
    Assert.AreEqual<bool>(true, f.IsValidRange first)
    Assert.AreEqual<bool>(true, f.IsValidRange last)
    Assert.AreEqual<bool>(false, f.IsValidRange onePast)
    Assert.AreEqual<bool>(true, f.IsValidRange whole)

  [<TestMethod>]
  member _.``[PE] x64 range mapped to file test``() =
    (* .data takes more room in memory than the file gives it, so its tail is
       an address of the image that reads no byte of the file. Where the file
       gives a section more room than memory does, as it does .text, the two
       questions part the other way: what is past the end of .text in memory
       is no address of the image, though the file holds bytes there. *)
    let f = x64File :> IBinFile
    let backed: AddrRange = { Min = 0x140003000UL; Max = 0x1400031ffUL }
    let tail: AddrRange = { Min = 0x140003200UL; Max = 0x14000322fUL }
    let onePast: AddrRange = { Min = 0x140001c28UL; Max = 0x140001c28UL }
    Assert.AreEqual<bool>(true, f.IsRangeMappedToFile backed)
    Assert.AreEqual<bool>(true, f.IsValidRange tail)
    Assert.AreEqual<bool>(false, f.IsRangeMappedToFile tail)
    Assert.AreEqual<bool>(false, f.IsValidRange onePast)
    Assert.AreEqual<bool>(true, f.IsRangeMappedToFile onePast)

  [<TestMethod>]
  member _.``[PE] x64 executable address test``() =
    let f = x64File :> IBinFile
    Assert.AreEqual<bool>(true, f.IsExecutableAddr 0x140001000UL) (* .text *)
    Assert.AreEqual<bool>(false, f.IsExecutableAddr 0x140002000UL) (* .rdata *)

  [<TestMethod>]
  member _.``[PE] x64 slice maps address to file content test``() =
    let f = x64File :> IBinFile
    let viaSlice = f.Slice(0x140001000UL, 8).ToArray()
    let viaRaw = f.RawBytes.Span.Slice(0x400, 8).ToArray()
    CollectionAssert.AreEqual(viaRaw, viaSlice)

  [<TestMethod>]
  member _.``[PE] x64 bounded pointer test``() =
    let f = x64File :> IBinFile
    let p = f.GetBoundedPointer 0x140001000UL
    Assert.AreEqual<bool>(false, p.IsNull)
    Assert.AreEqual<bool>(true, p.CanReadFileBytes)

  [<TestMethod>]
  member _.``[PE] no file of another format is identified as PE``() =
    (* PE is tried before Mach, Wasm and Python, and an object file carries no
       signature to know it by, so what keeps a file of another format out is
       the machine its COFF header would be read as naming. *)
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    Assert.AreNotEqual<int>(0, otherFormatBytes.Length, "No fixture swept.")
    for name, bytes in otherFormatBytes do
      let struct (fmt, _) = FormatDetector.identify bytes isa
      Assert.AreNotEqual<FileFormat>(PEBinary, fmt, name)

  [<TestMethod>]
  member _.``[PE] format detector identifies PE test``() =
    let bytes = ZIPReader.readBytes PEBinary "pe_x64.zip" "pe_x64.exe"
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    let struct (fmt, _) = FormatDetector.identify bytes isa
    Assert.AreEqual(PEBinary, fmt)

  [<TestMethod>]
  member _.``[PE] file factory loadPE test``() =
    let bytes = ZIPReader.readBytes PEBinary "pe_x64.zip" "pe_x64.exe"
    let f = FileFactory.loadPE "" bytes None [||] :> IBinFile
    Assert.AreEqual(PEBinary, f.Format)

  [<TestMethod>]
  member _.``[PE] x64 an RVA no section maps reads nowhere``() =
    (* Asking whether an RVA reads anywhere and asking where it reads are the
       one question, and -1 is the answer to both where no section holds bytes
       for it. Raising is what a caller with nowhere else to go gets instead. *)
    let secs = x64File.SectionHeaders
    let unmapped = 0x7f000000
    Assert.AreEqual(-1, PEUtils.findMappedSectionIndex secs unmapped)
    Assert.AreEqual(-1, PEUtils.tryGetRawOffset secs unmapped)
    Assert.ThrowsExactly<InvalidFileFormatException>(fun () ->
      PEUtils.getRawOffset secs unmapped |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``[PE] x64 a mapped RVA reads where its section does``() =
    (* The first byte of a section reads at the offset the section names, and
       the two ways of asking for it agree wherever there is an answer. *)
    let secs = x64File.SectionHeaders
    let sec = secs |> Array.find (fun s -> s.Name = ".text")
    let expected = sec.PointerToRawData
    Assert.AreEqual(expected, PEUtils.tryGetRawOffset secs sec.VirtualAddress)
    Assert.AreEqual(expected, PEUtils.getRawOffset secs sec.VirtualAddress)

  [<TestMethod>]
  member _.``[PE] an import directory landing nowhere is a format error``() =
    (* An RVA no section maps names no byte of the file, which is a fact about
       the file rather than an index to read on with. A table is read where it
       is asked for rather than where the file is opened, so that is where the
       file says so, and everything the table is no part of still reads. *)
    let bytes =
      ZIPReader.readBytes PEBinary "pe_x64.zip" "pe_x64.exe"
      |> withDirectoryRVA 1 0x7f000000
    let file = PEBinFile("pe_x64.exe", bytes, None, [||]) :> IBinFile
    Assert.AreEqual(Some 0x140001290UL, file.EntryPoint)
    Assert.ThrowsExactly<InvalidFileFormatException>(fun () ->
      file.ImportTable.Value.Imports |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``[PE] an object naming no code section still loads``() =
    (* A data-only object, and one built with LTCG, carries no .text at all. *)
    let bytes =
      ZIPReader.readBytes PEBinary "pe_x64_obj.zip" "pe_x64_obj.obj"
      |> withoutTextSections
    let file = PEBinFile("pe_x64_obj.obj", bytes, None, [||]) :> IBinFile
    Assert.AreEqual<BinFileKind>(Object, file.Kind)

  [<TestMethod>]
  member _.``[PE] a forwarder naming no library is passed over``() =
    (* A forwarder reads "LIB.func"; one with no dot names no library, so it
       forwards nowhere and is no export of this file either. *)
    let bytes =
      ZIPReader.readBytes PEBinary "pe_x64_dll.zip" "pe_x64_dll.dll"
      |> withDotlessForwarder
    let file = PEBinFile("pe_x64_dll.dll", bytes, None, [||]) :> IBinFile
    Assert.AreEqual<BinFileKind>(SharedLibrary, file.Kind)
    let names =
      file.SymbolTable.Value.Symbols |> Array.map (fun s -> s.Name)
    Assert.AreEqual<bool>(false, Array.contains "exported_func" names)

  [<TestMethod>]
  member _.``[PE] x64 function addresses include .pdata starts``() =
    (* An image carrying neither a PDB nor exports names its functions
       nowhere but in the table it unwinds them by. *)
    let addrs = (x64File :> IBinFile).Structure.Value.FunctionAddresses
    Assert.AreEqual<bool>(true, Array.contains 0x140001840UL addrs)
    Assert.AreEqual<bool>(true, Array.contains 0x140001000UL addrs)

  [<TestMethod>]
  member _.``[PE] x64 a chained .pdata range is no function``() =
    (* 0x14000184b carries on the range 0x140001840 opens, which is what its
       UNWIND_INFO chaining back to that one says, so it starts nothing. *)
    let addrs = (x64File :> IBinFile).Structure.Value.FunctionAddresses
    Assert.AreEqual<bool>(false, Array.contains 0x14000184bUL addrs)

  [<TestMethod>]
  member _.``[PE] x64 dll exports are symbols``() =
    (* An image keeps no symbol table of its own, so what it exports is the
       only name it gives an address inside it. *)
    let names =
      (x64DllFile :> IBinFile).SymbolTable.Value.Symbols
      |> Array.map (fun s -> s.Name)
    Assert.AreEqual<bool>(true, Array.contains "exported_func" names)

  [<TestMethod>]
  member _.``[PE] x64 dll export is found by address``() =
    let tbl = (x64DllFile :> IBinFile).SymbolTable.Value
    match tbl.TryFindSymbolByAddr 0x180001000UL with
    | Ok s ->
      Assert.AreEqual<string>("exported_func", s.Name)
      Assert.AreEqual<BinSymbolKind>(FunctionSymbol, s.Kind)
    | Error _ ->
      Assert.Fail()

  [<TestMethod>]
  member _.``[PE] x64 every relocation is a relocation address``() =
    (* What the table lists and what a lookup in it answers are one thing,
       which is what indexing the lookup has to leave true. *)
    let relocs = (x64File :> IBinFile).Relocations.Value
    let all = relocs.Relocations
    Assert.AreEqual<bool>(true, all.Length > 0)
    let found = all |> Array.forall (fun r -> relocs.IsRelocationAddr r.Address)
    Assert.AreEqual<bool>(true, found)

  [<TestMethod>]
  member _.``[PE] x64 obj section relocations name their symbols``() =
    let relocs = (x64ObjFile :> IBinFile).Relocations.Value.Relocations
    let names = relocs |> Array.choose (fun r -> r.SymbolName) |> Set.ofArray
    Assert.AreEqual<bool>(true, names.Contains "puts")
    Assert.AreEqual<bool>(true, names.Contains "msg")
    Assert.AreEqual<bool>(true, names.Contains "g_buf")

  [<TestMethod>]
  member _.``[PE] x64 obj relocation count``() =
    (* Three in .text$mn and three in .pdata, which is every one the object
       carries. *)
    let relocs = (x64ObjFile :> IBinFile).Relocations.Value.Relocations
    Assert.AreEqual<int>(6, relocs.Length)

  [<TestMethod>]
  member _.``[PE] x86 SafeSEH handlers are functions``() =
    (* The load configuration of the x86 fixture names one exception handler,
       and a handler is a function nothing else in the file names. *)
    let addrs = (x86File :> IBinFile).Structure.Value.FunctionAddresses
    Assert.AreEqual<bool>(true, Array.contains 0x4018f0UL addrs)

  [<TestMethod>]
  member _.``[PE] x64 guard CF table entries are functions``() =
    (* Of the eleven the table lists, these are three no .pdata range opens
       at, so only the table names them. They are its first entry, one in
       the middle and its last, which no reading of it at the wrong stride
       or for the wrong count gets all three of. *)
    let addrs = (x64GuardCFFile :> IBinFile).Structure.Value.FunctionAddresses
    Assert.AreEqual<bool>(true, Array.contains 0x140001000UL addrs)
    Assert.AreEqual<bool>(true, Array.contains 0x140001040UL addrs)
    Assert.AreEqual<bool>(true, Array.contains 0x140001bc0UL addrs)

  [<TestMethod>]
  member _.``[PE] x64 TLS callbacks are functions``() =
    (* Neither opens a .pdata range, and this image lists no guard function
       table, so the callback array is the only thing naming them. Taking
       both tells reading it through from stopping at its first entry. *)
    let addrs = (x64TLSFile :> IBinFile).Structure.Value.FunctionAddresses
    Assert.AreEqual<bool>(true, Array.contains 0x140001000UL addrs)
    Assert.AreEqual<bool>(true, Array.contains 0x140001010UL addrs)

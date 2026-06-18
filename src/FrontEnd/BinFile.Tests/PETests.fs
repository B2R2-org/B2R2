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

open System.Reflection.PortableExecutable
open B2R2
open B2R2.FrontEnd.BinFile
open Microsoft.VisualStudio.TestTools.UnitTesting
open type FileFormat

[<TestClass>]
type PETests() =
  static let isStripped (file: IBinFile) =
    file.SymbolTable.Value.IsStripped

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

  /// A minimal x64 console executable (no PDB), used as the canonical fixture
  /// for metadata, section, and address-space tests.
  static let x64File = parseFile "pe_x64"

  /// A minimal x86 (32-bit) console executable (no PDB), exercising the PE32
  /// header and 32-bit ISA decoding.
  static let x86File = parseFile "pe_x86"

  /// The x64 executable bundled with its PDB, exercising the PDB-based symbol
  /// path (PE images carry no symbols of their own).
  static let x64PdbFile = parseFileWithPdb "pe_x64_pdb"

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

  let assertExistenceOfRelocBlock (file: PEBinFile) pageRVA blockSize =
    file.RelocBlocks
    |> List.map (fun b -> b.PageRVA, b.BlockSize)
    |> assertExistenceOfPair (pageRVA, blockSize)

  [<TestMethod>]
  member _.``[PE] x64 ISA test``() =
    let isa = (x64File :> IBinFile).ISA
    Assert.AreEqual(Architecture.Intel, isa.Arch)
    Assert.AreEqual(WordSize.Bit64, isa.WordSize)
    Assert.AreEqual(Endian.Little, isa.Endian)

  [<TestMethod>]
  member _.``[PE] x64 entry point test``() =
    Assert.AreEqual(Some 0x140001290UL, (x64File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[PE] x64 file type test``() =
    let flg = Characteristics.ExecutableImage
    Assert.AreEqual
      (true, x64File.PEHeaders.CoffHeader.Characteristics.HasFlag flg)

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
  member _.``[PE] x86 entry point test``() =
    Assert.AreEqual(Some 0x4012F0UL, (x86File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[PE] x86 file type test``() =
    let flg = Characteristics.ExecutableImage
    Assert.AreEqual
      (true, x86File.PEHeaders.CoffHeader.Characteristics.HasFlag flg)

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

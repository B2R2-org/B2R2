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
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinFile
open type FileFormat

[<TestClass>]
type PETests() =
  static let isStripped (file: IBinFile) =
    file.SymbolTable.Value.IsStripped

  static let parseFile fileName (pdbFileName: string) =
    let zipFile = fileName + ".zip"
    let fileNameInZip = fileName + ".exe"
    let bytes = ZIPReader.readBytes PEBinary zipFile fileNameInZip
    let pdbBytes =
      if pdbFileName.Length = 0 then [||]
      else ZIPReader.readBytes PEBinary zipFile pdbFileName
    PEBinFile(fileNameInZip, bytes, None, pdbBytes)

  let assertExistenceOfRelocBlock (file: IBinFile) pageRVA blockSize =
    (file :?> PEBinFile).RelocBlocks
    |> List.map (fun pair -> pair.PageRVA, pair.BlockSize)
    |> Seq.ofList
    |> assertExistenceOfPair (pageRVA, blockSize)

  let assertExistenceOfSectionHeader (file: IBinFile) address headerName =
    (file :?> PEBinFile).SectionHeaders
    |> Array.map (fun record -> record.VirtualAddress, record.Name)
    |> assertExistenceOfPair (address, headerName)

  static let x86File = parseFile "pe_x86" "pe_x86.pdb"

  static let x64File = parseFile "pe_x64" "pe_x64.pdb"

  /// A C++/SEH binary (try/catch plus __try/__except), so its UNWIND_INFO
  /// carries exception handlers and the SEH frames carry a C scope table.
  static let x64ExcFile = parseFile "pe_x64_exc" ""

  /// Same source built with /d2FH4- so the C++ try/catch uses the classic
  /// (FH3) FuncInfo format rather than the compressed FH4 one.
  static let x64ExcFh3File = parseFile "pe_x64_exc_fh3" ""

  [<TestMethod>]
  member _.``[PE] X86 EntryPoint test``() =
    Assert.AreEqual(Some 0x0040140cUL, (x86File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[PE] X86 file type test``() =
    let flg = Characteristics.ExecutableImage
    Assert.AreEqual
      (true, x86File.PEHeaders.CoffHeader.Characteristics.HasFlag flg)

  [<TestMethod>]
  member _.``[PE] X86 IsStripped test``() =
    Assert.AreEqual(false, isStripped (x86File :> IBinFile))

  [<TestMethod>]
  member _.``[PE] X86 IsNXEnabled test``() =
    Assert.AreEqual(true, (x86File :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[PE] X86 sections length test``() =
    Assert.AreEqual<int>(5, x86File.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[PE] X86 static symbols length test``() =
    Assert.AreEqual<int>(239, x86File.Symbols.SymbolArray.Length)

  [<TestMethod>]
  member _.``[PE] X86 dynamic symbols length test``() =
    Assert.AreEqual<int>(41, x86File.ImportedSymbols.Count)
    Assert.AreEqual<int>(0, x86File.ExportedSymbols.Count)

  [<TestMethod>]
  member _.``[PE] X86 text section address test``() =
    Assert.AreEqual<uint64>(0x00401000UL, getTextSectionAddr x86File)

  [<TestMethod>]
  member _.``[PE] X86 isa wordSize test``() =
    Assert.AreEqual(WordSize.Bit32, (x86File :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[PE] X86 function symbol test (1)``() =
    assertFuncSymbolExistence x86File 0x00401090UL "_add"

  [<TestMethod>]
  member _.``[PE] X86 function symbol test (2)``() =
    assertFuncSymbolExistence x86File 0x004010d0UL "_mul"

  [<TestMethod>]
  member _.``[PE] X86 function symbol test (3)``() =
    assertFuncSymbolExistence x86File 0x004010e0UL "_main"

  [<TestMethod>]
  member _.``[PE] X86 Reloc section test (1)``() =
    assertExistenceOfRelocBlock x86File 8192u 36

  [<TestMethod>]
  member _.``[PE] X86 Reloc section test (2)``() =
    assertExistenceOfRelocBlock x86File 4096u 320

  [<TestMethod>]
  member _.``[PE] X86 IsRelocationAddr test``() =
    let relocs = (x86File :> IBinFile).Relocations.Value
    Assert.AreEqual(true, relocs.IsRelocationAddr 0x00401001UL)
    Assert.AreEqual(false, relocs.IsRelocationAddr 0x00401000UL)

  [<TestMethod>]
  member _.``[PE] X86 TryGetRelocatedAddr test``() =
    let relocs = (x86File :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x00403380UL,
                    relocs.TryGetRelocatedAddr 0x00401001UL)
    Assert.AreEqual(Error ErrorCase.ItemNotFound,
                    relocs.TryGetRelocatedAddr 0x00401000UL)

  [<TestMethod>]
  member _.``[PE] X86 section header test (1)``() =
    assertExistenceOfSectionHeader x86File 4096 ".text"

  [<TestMethod>]
  member _.``[PE] X86 section header test (2)``() =
    assertExistenceOfSectionHeader x86File 8192 ".rdata"

  [<TestMethod>]
  member _.``[PE] X86 section header test (3)``() =
    assertExistenceOfSectionHeader x86File 12288 ".data"

  [<TestMethod>]
  member _.``[PE] X86 section header test (4)``() =
    assertExistenceOfSectionHeader x86File 16384 ".rsrc"

  [<TestMethod>]
  member _.``[PE] X86 section header test (5)``() =
    assertExistenceOfSectionHeader x86File 20480 ".reloc"

  [<TestMethod>]
  member _.``[PE] X64 EntryPoint test``() =
    Assert.AreEqual(Some 0x1400014b4UL, (x64File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[PE] X64 file type test``() =
    let flg = Characteristics.ExecutableImage
    Assert.AreEqual
      (true, x64File.PEHeaders.CoffHeader.Characteristics.HasFlag flg)

  [<TestMethod>]
  member _.``[PE] X64 IsStripped test``() =
    Assert.AreEqual(false, isStripped (x64File :> IBinFile))

  [<TestMethod>]
  member _.``[PE] X64 IsNXEnabled test``() =
    Assert.AreEqual(true, (x64File :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[PE] X64 sections length test``() =
    Assert.AreEqual<int>(6, x64File.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[PE] X64 static symbols length test``() =
    Assert.AreEqual<int>(240, x64File.Symbols.SymbolArray.Length)

  [<TestMethod>]
  member _.``[PE] X64 dynamic symbols length test``() =
    Assert.AreEqual<int>(43, x64File.ImportedSymbols.Count)
    Assert.AreEqual<int>(0, x64File.ExportedSymbols.Count)

  [<TestMethod>]
  member _.``[PE] X64 text section address test``() =
    Assert.AreEqual<uint64>(0x140001000UL, getTextSectionAddr x64File)

  [<TestMethod>]
  member _.``[PE] X64 isa wordSize test``() =
    Assert.AreEqual(WordSize.Bit64, (x64File :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[PE] X64 function symbol test (1)``() =
    assertFuncSymbolExistence x64File 0x1400010e0UL "add"

  [<TestMethod>]
  member _.``[PE] X64 function symbol test (2)``() =
    assertFuncSymbolExistence x64File 0x140001110UL "mul"

  [<TestMethod>]
  member _.``[PE] X64 function symbol test (3)``() =
    assertFuncSymbolExistence x64File 0x140001130UL "main"

  [<TestMethod>]
  member _.``[PE] X64 Reloc section test``() =
    assertExistenceOfRelocBlock x64File 8192u 28

  [<TestMethod>]
  member _.``[PE] X64 IsRelocationAddr test``() =
    let relocs = (x64File :> IBinFile).Relocations.Value
    Assert.AreEqual(true, relocs.IsRelocationAddr 0x140002190UL)
    Assert.AreEqual(false, relocs.IsRelocationAddr 0x140002194UL)

  [<TestMethod>]
  member _.``[PE] X64 TryGetRelocatedAddr test``() =
    let relocs = (x64File :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x1400019ccUL,
                    relocs.TryGetRelocatedAddr 0x140002190UL)
    Assert.AreEqual(Error ErrorCase.ItemNotFound,
                    relocs.TryGetRelocatedAddr 0x140002194UL)

  [<TestMethod>]
  member _.``[PE] X64 section header test (1)``() =
    assertExistenceOfSectionHeader x64File 4096 ".text"

  [<TestMethod>]
  member _.``[PE] X64 section header test (2)``() =
    assertExistenceOfSectionHeader x64File 8192 ".rdata"

  [<TestMethod>]
  member _.``[PE] X64 section header test (3)``() =
    assertExistenceOfSectionHeader x64File 12288 ".data"

  [<TestMethod>]
  member _.``[PE] X64 section header test (4)``() =
    assertExistenceOfSectionHeader x64File 16384 ".pdata"

  [<TestMethod>]
  member _.``[PE] X64 section header test (5)``() =
    assertExistenceOfSectionHeader x64File 20480 ".rsrc"

  [<TestMethod>]
  member _.``[PE] X64 section header test (6)``() =
    assertExistenceOfSectionHeader x64File 24576 ".reloc"

  [<TestMethod>]
  member _.``[PE] X64 exception table is parsed from .pdata``() =
    let frames = (x64File :> IBinFile).ExceptionTable.Value.Frames
    Assert.AreEqual<bool>(true, frames.Length > 0)

  [<TestMethod>]
  member _.``[PE] X64 exception frames have sane ranges``() =
    let frames = (x64File :> IBinFile).ExceptionTable.Value.Frames
    let sane = frames |> Array.forall (fun f -> f.FunctionEnd > f.FunctionStart)
    Assert.AreEqual<bool>(true, sane)

  [<TestMethod>]
  member _.``[PE] X86 has no exception table entries``() =
    let frames = (x86File :> IBinFile).ExceptionTable.Value.Frames
    Assert.AreEqual<int>(0, frames.Length)

  [<TestMethod>]
  member _.``[PE] X64 exception frame has a personality routine``() =
    let frames = (x64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    let hasPersonality =
      frames |> Array.exists (fun f -> f.PersonalityRoutine.IsSome)
    Assert.AreEqual<bool>(true, hasPersonality)

  [<TestMethod>]
  member _.``[PE] X64 SEH scope table handler is resolved``() =
    let frames = (x64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    let hasHandler =
      frames |> Array.exists (fun f ->
        f.Handlers |> Array.exists (fun h -> h.Handler.IsSome))
    Assert.AreEqual<bool>(true, hasHandler)

  [<TestMethod>]
  member _.``[PE] X64 FH3 C++ catch handlers are parsed``() =
    let frames = (x64ExcFh3File :> IBinFile).ExceptionTable.Value.Frames
    // A C++ try with multiple catch clauses yields several handlers sharing the
    // same guarded range; SEH scope records never do, so this pins the FH3
    // path.
    let multiCatch =
      frames
      |> Array.collect (fun f -> f.Handlers)
      |> Array.filter (fun h -> h.Handler.IsSome)
      |> Array.groupBy (fun h -> h.BlockStart, h.BlockEnd)
      |> Array.exists (fun (_, hs) -> hs.Length >= 2)
    Assert.AreEqual<bool>(true, multiCatch)

  [<TestMethod>]
  member _.``[PE] X64 FH4 C++ catch handlers are parsed``() =
    let frames = (x64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    let multiCatch =
      frames
      |> Array.collect (fun f -> f.Handlers)
      |> Array.filter (fun h -> h.Handler.IsSome)
      |> Array.groupBy (fun h -> h.BlockStart, h.BlockEnd)
      |> Array.exists (fun (_, hs) -> hs.Length >= 2)
    Assert.AreEqual<bool>(true, multiCatch)

  [<TestMethod>]
  member _.``[PE] X64 FH4 catch handler addresses match dumpbin``() =
    // dumpbin /unwindinfo reports cppGuarded's two catch handlers at RVAs
    // 0x91FE0 and 0x9200D (image base 0x140000000).
    let frames = (x64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    let targets =
      frames
      |> Array.collect (fun f -> f.Handlers)
      |> Array.choose (fun h -> h.Handler)
    Assert.AreEqual<bool>(true, Array.contains 0x140091FE0UL targets)
    Assert.AreEqual<bool>(true, Array.contains 0x14009200DUL targets)

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
type PETests () =
  static let parseFile fileName (pdbFileName: string) =
    let zipFile = fileName + ".zip"
    let fileNameInZip = fileName + ".exe"
    let bytes = ZIPReader.readBytes PEBinary zipFile fileNameInZip
    let pdbBytes =
      if pdbFileName.Length = 0 then [||]
      else ZIPReader.readBytes PEBinary zipFile pdbFileName
    PEBinFile (fileNameInZip, bytes, None, pdbBytes)

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

  [<TestMethod>]
  member _.``[PE] X86 EntryPoint test`` () =
    Assert.AreEqual (Some 0x0040140cUL, (x86File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[PE] X86 file type test`` () =
    let flg = Characteristics.ExecutableImage
    Assert.IsTrue (x86File.PEHeaders.CoffHeader.Characteristics.HasFlag flg)

  [<TestMethod>]
  member _.``[PE] X86 IsStripped test`` () =
    Assert.AreEqual<bool> (false, (x86File :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[PE] X86 IsNXEnabled test`` () =
    Assert.AreEqual<bool> (true, (x86File :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[PE] X86 sections length test`` () =
    Assert.AreEqual<int> (5, x86File.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[PE] X86 static symbols length test`` () =
    Assert.AreEqual<int> (239, x86File.Symbols.SymbolArray.Length)

  [<TestMethod>]
  member _.``[PE] X86 dynamic symbols length test`` () =
    Assert.AreEqual<int> (41, x86File.ImportedSymbols.Count)
    Assert.AreEqual<int> (0, x86File.ExportedSymbols.Count)

  [<TestMethod>]
  member _.``[PE] X86 text section address test`` () =
    Assert.AreEqual<uint64> (0x00401000UL, getTextSectionAddr x86File)

  [<TestMethod>]
  member _.``[PE] X86 isa wordSize test`` () =
    Assert.AreEqual (WordSize.Bit32, (x86File :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[PE] X86 function symbol test (1)`` () =
    assertFuncSymbolExistence x86File 0x00401090UL "_add"

  [<TestMethod>]
  member _.``[PE] X86 function symbol test (2)`` () =
    assertFuncSymbolExistence x86File 0x004010d0UL "_mul"

  [<TestMethod>]
  member _.``[PE] X86 function symbol test (3)`` () =
    assertFuncSymbolExistence x86File 0x004010e0UL "_main"

  [<TestMethod>]
  member _.``[PE] X86 Reloc section test (1)`` () =
    assertExistenceOfRelocBlock x86File 8192u 36

  [<TestMethod>]
  member _.``[PE] X86 Reloc section test (2)`` () =
    assertExistenceOfRelocBlock x86File 4096u 320

  [<TestMethod>]
  member _.``[PE] X86 section header test (1)`` () =
    assertExistenceOfSectionHeader x86File 4096 ".text"

  [<TestMethod>]
  member _.``[PE] X86 section header test (2)`` () =
    assertExistenceOfSectionHeader x86File 8192 ".rdata"

  [<TestMethod>]
  member _.``[PE] X86 section header test (3)`` () =
    assertExistenceOfSectionHeader x86File 12288 ".data"

  [<TestMethod>]
  member _.``[PE] X86 section header test (4)`` () =
    assertExistenceOfSectionHeader x86File 16384 ".rsrc"

  [<TestMethod>]
  member _.``[PE] X86 section header test (5)`` () =
    assertExistenceOfSectionHeader x86File 20480 ".reloc"

  [<TestMethod>]
  member _.``[PE] X64 EntryPoint test`` () =
    Assert.AreEqual (Some 0x1400014b4UL, (x64File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[PE] X64 file type test`` () =
    let flg = Characteristics.ExecutableImage
    Assert.IsTrue (x64File.PEHeaders.CoffHeader.Characteristics.HasFlag flg)

  [<TestMethod>]
  member _.``[PE] X64 IsStripped test`` () =
    Assert.AreEqual<bool> (false, (x64File :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[PE] X64 IsNXEnabled test`` () =
    Assert.AreEqual<bool> (true, (x64File :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[PE] X64 sections length test`` () =
    Assert.AreEqual<int> (6, x64File.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[PE] X64 static symbols length test`` () =
    Assert.AreEqual<int> (240, x64File.Symbols.SymbolArray.Length)

  [<TestMethod>]
  member _.``[PE] X64 dynamic symbols length test`` () =
    Assert.AreEqual<int> (43, x64File.ImportedSymbols.Count)
    Assert.AreEqual<int> (0, x64File.ExportedSymbols.Count)

  [<TestMethod>]
  member _.``[PE] X64 text section address test`` () =
    Assert.AreEqual<uint64> (0x140001000UL, getTextSectionAddr x64File)

  [<TestMethod>]
  member _.``[PE] X64 isa wordSize test`` () =
    Assert.AreEqual (WordSize.Bit64, (x64File :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[PE] X64 function symbol test (1)`` () =
    assertFuncSymbolExistence x64File 0x1400010e0UL "add"

  [<TestMethod>]
  member _.``[PE] X64 function symbol test (2)`` () =
    assertFuncSymbolExistence x64File 0x140001110UL "mul"

  [<TestMethod>]
  member _.``[PE] X64 function symbol test (3)`` () =
    assertFuncSymbolExistence x64File 0x140001130UL "main"

  [<TestMethod>]
  member _.``[PE] X64 Reloc section test`` () =
    assertExistenceOfRelocBlock x64File 8192u 28

  [<TestMethod>]
  member _.``[PE] X64 section header test (1)`` () =
    assertExistenceOfSectionHeader x64File 4096 ".text"

  [<TestMethod>]
  member _.``[PE] X64 section header test (2)`` () =
    assertExistenceOfSectionHeader x64File 8192 ".rdata"

  [<TestMethod>]
  member _.``[PE] X64 section header test (3)`` () =
    assertExistenceOfSectionHeader x64File 12288 ".data"

  [<TestMethod>]
  member _.``[PE] X64 section header test (4)`` () =
    assertExistenceOfSectionHeader x64File 16384 ".pdata"

  [<TestMethod>]
  member _.``[PE] X64 section header test (5)`` () =
    assertExistenceOfSectionHeader x64File 20480 ".rsrc"

  [<TestMethod>]
  member _.``[PE] X64 section header test (6)`` () =
    assertExistenceOfSectionHeader x64File 24576 ".reloc"

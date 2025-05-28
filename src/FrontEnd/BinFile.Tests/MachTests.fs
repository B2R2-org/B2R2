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

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Mach
open type FileFormat

[<TestClass>]
type MachTests () =
  static let parseFile fileName arch wsz =
    let zipFile = fileName + ".zip"
    let bytes = ZIPReader.readBytes MachBinary zipFile fileName
    let isa = ISA (arch, Endian.Little, wsz)
    MachBinFile (fileName, bytes, isa, None)

  let assertExistenceOfFlag (file: IBinFile) flags =
    (file :?> MachBinFile).Header.Flags.ToString () = flags
    |> Assert.IsTrue

  let assertExistenceOfSectionHeader (file: IBinFile) address sectionName =
    (file :?> MachBinFile).Sections
    |> Seq.map (fun record -> record.SecAddr, record.SecName)
    |> assertExistenceOfPair (address, sectionName)

  static let x86File =
    parseFile "mach_x86_rm_stripped" Architecture.Intel WordSize.Bit32

  static let x64File =
    parseFile "mach_x64_wc" Architecture.Intel WordSize.Bit64

  static let x64SFile =
    parseFile "mach_x64_wc_stripped" Architecture.Intel WordSize.Bit64

  [<TestMethod>]
  member _.``[Mach] X86_Stripped EntryPoint test`` () =
    Assert.AreEqual (Some 0x00002050UL, (x86File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped file type test`` () =
    Assert.AreEqual (MachFileType.MH_EXECUTE, x86File.Header.FileType)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped IsStripped test`` () =
    Assert.AreEqual<bool> (true, (x86File :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped IsNXEnabled test`` () =
    Assert.AreEqual<bool> (true, (x86File :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped sections length test`` () =
    Assert.AreEqual<int> (9, x86File.Sections.Length)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped static symbols length test`` () =
    Assert.AreEqual<int> (0, x86File.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped dynamic symbols length test`` () =
    Assert.AreEqual<int> (59, x86File.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped linkageTableEntries length test`` () =
    let f = x86File :> IBinFile
    Assert.AreEqual<int> (45, f.GetLinkageTableEntries().Length)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped text section address test`` () =
    Assert.AreEqual<uint64> (0x00002050UL, getTextSectionAddr x86File)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped isa wordSize test`` () =
    Assert.AreEqual (WordSize.Bit32, (x86File :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped function symbol test (1)`` () =
    assertFuncSymbolExistence x86File 0x00003b28UL "___error"

  [<TestMethod>]
  member _.``[Mach] X86_Stripped function symbol test (2)`` () =
    assertFuncSymbolExistence x86File 0x00003b70UL "_fflush"

  [<TestMethod>]
  member _.``[Mach] X86_Stripped section header test (1)`` () =
    assertExistenceOfSectionHeader x86File 8272UL "__text"

  [<TestMethod>]
  member _.``[Mach] X86_Stripped section header test (2)`` () =
    assertExistenceOfSectionHeader x86File 16620UL "__common"

  [<TestMethod>]
  member _.``[Mach] X86_Stripped flags test`` () =
    let flags =
      "MH_NOUNDEFS, MH_DYLDLINK, MH_TWOLEVEL, MH_PIE, MH_NO_HEAP_EXECUTION"
    assertExistenceOfFlag x86File flags

  [<TestMethod>]
  member _.``[Mach] X64 EntryPoint test`` () =
    Assert.AreEqual (Some 0x100000E90UL, (x64File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[Mach] X64 file type test`` () =
    Assert.AreEqual (MachFileType.MH_EXECUTE, x64File.Header.FileType)

  [<TestMethod>]
  member _.``[Mach] X64 IsStripped test`` () =
    Assert.AreEqual<bool> (false, (x64File :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[Mach] X64 IsNXEnabled test`` () =
    Assert.AreEqual<bool> (true, (x64File :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[Mach] X64 sections length test`` () =
    Assert.AreEqual<int> (13, x64File.Sections.Length)

  [<TestMethod>]
  member _.``[Mach] X64 static symbols length test`` () =
    Assert.AreEqual<int> (885, x64File.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[Mach] X64 dynamic symbols length test`` () =
    Assert.AreEqual<int> (190, x64File.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[Mach] X64 linkageTableEntries length test`` () =
    let f = x64File :> IBinFile
    Assert.AreEqual<int> (72, f.GetLinkageTableEntries().Length)

  [<TestMethod>]
  member _.``[Mach] X64 text section address test`` () =
    Assert.AreEqual<uint64> (0x100000D30UL, getTextSectionAddr x64File)

  [<TestMethod>]
  member _.``[Mach] X64 isa wordSize test`` () =
    Assert.AreEqual (WordSize.Bit64, (x64File :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[Mach] X64 function symbol test (1)`` () =
    assertFuncSymbolExistence x64File 0x100000D30UL "_usage"

  [<TestMethod>]
  member _.``[Mach] X64 function symbol test (2)`` () =
    assertFuncSymbolExistence x64File 0x100005F90UL "_error"

  [<TestMethod>]
  member _.``[Mach] X64 section header test (1)`` () =
    assertExistenceOfSectionHeader x64File 0x100000D30UL "__text"

  [<TestMethod>]
  member _.``[Mach] X64 section header test (2)`` () =
    assertExistenceOfSectionHeader x64File 0x10000d680UL "__common"

  [<TestMethod>]
  member _.``[Mach] X64 flags test`` () =
    let flags = "MH_NOUNDEFS, MH_DYLDLINK, MH_TWOLEVEL, MH_PIE"
    assertExistenceOfFlag x64File flags

  [<TestMethod>]
  member _.``[Mach] X64_Stripped EntryPoint test`` () =
    Assert.AreEqual (Some 0x100000E90UL, (x64SFile :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped file type test`` () =
    Assert.AreEqual (MachFileType.MH_EXECUTE, x64SFile.Header.FileType)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped IsStripped test`` () =
    Assert.AreEqual<bool> (true, (x64SFile :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped IsNXEnabled test`` () =
    Assert.AreEqual<bool> (true, (x64SFile :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped sections length test`` () =
    Assert.AreEqual<int> (13, x64SFile.Sections.Length)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped static symbols length test`` () =
    Assert.AreEqual<int> (0, x64SFile.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped dynamic symbols length test`` () =
    Assert.AreEqual<int> (190, x64SFile.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped linkageTableEntries length test`` () =
    let f = x64SFile :> IBinFile
    Assert.AreEqual<int> (72, f.GetLinkageTableEntries().Length)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped text section address test`` () =
    Assert.AreEqual<uint64> (0x100000D30UL, getTextSectionAddr x64SFile)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped isa wordSize test`` () =
    Assert.AreEqual (WordSize.Bit64, (x64SFile :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped function symbol test (1)`` () =
    assertFuncSymbolExistence x64SFile 0x10000B076UL "___error"

  [<TestMethod>]
  member _.``[Mach] X64_Stripped function symbol test (2)`` () =
    assertFuncSymbolExistence x64SFile 0x10000B0D0UL "_fflush"

  [<TestMethod>]
  member _.``[Mach] X64_Stripped section header test (1)`` () =
    assertExistenceOfSectionHeader x64SFile 0x100000D30UL "__text"

  [<TestMethod>]
  member _.``[Mach] X64_Stripped section header test (2)`` () =
    assertExistenceOfSectionHeader x64SFile 0x10000d680UL "__common"

  [<TestMethod>]
  member _.``[Mach] X64_Stripped flags test`` () =
    let flags = "MH_NOUNDEFS, MH_DYLDLINK, MH_TWOLEVEL, MH_PIE"
    assertExistenceOfFlag x64SFile flags


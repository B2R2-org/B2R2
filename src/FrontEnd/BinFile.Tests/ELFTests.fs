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

open B2R2
open B2R2.FrontEnd.BinFile
open Microsoft.VisualStudio.TestTools.UnitTesting
open type FileFormat

[<TestClass>]
type ELFTests () =
  static let parseFile fileName =
    let zipFile = fileName + ".zip"
    let bytes = ZIPReader.readBytes ELFBinary zipFile fileName
    ELFBinFile (fileName, bytes, None, None)

  let assertExistenceOfRelocation (file: IBinFile) offset symbolName =
    (file :?> ELFBinFile).RelocationInfo.Entries
    |> Seq.map (fun reloc -> reloc.RelOffset, reloc.RelSymbol.Value.SymName)
    |> assertExistenceOfPair (offset, symbolName)

  let assertExistenceOfSectionHeader (file: IBinFile) sectionNum sectionName =
    (file :?> ELFBinFile).SectionHeaders
    |> Seq.map (fun record -> record.SecNum, record.SecName)
    |> assertExistenceOfPair (sectionNum, sectionName)

  static let x86File = parseFile "elf_x86_ls"
  static let x86SFile = parseFile "elf_x86_ls_stripped"
  static let x64File = parseFile "elf_x64_ls"
  static let x64SFile = parseFile "elf_x64_ls_stripped"
  static let arm32File = parseFile "elf_arm32_ls"
  static let arm32SFile = parseFile "elf_arm32_ls_stripped"
  static let thumbFile = parseFile "elf_thumb_ls"
  static let thumbSFile = parseFile "elf_thumb_ls_stripped"
  static let aarch64File = parseFile "elf_aarch64_ls"
  static let aarch64SFile = parseFile "elf_aarch64_ls_stripped"
  static let mips32File = parseFile "elf_mips32_ls_stripped"
  static let mips32leFile = parseFile "elf_mips32_ls_stripped_le"
  static let mips64File = parseFile "elf_mips64_ls_stripped"

  [<TestMethod>]
  member _.``[ELF] X86 EntryPoint test`` () =
    Assert.AreEqual<uint64> (0x8049CD0UL, x86File.Header.EntryPoint)

  [<TestMethod>]
  member _.``[ELF] X86 file type test`` () =
    Assert.AreEqual (ELF.ELFType.ET_EXEC, (x86File.Header.ELFType))

  [<TestMethod>]
  member _.``[ELF] X86 IsStripped test`` () =
    Assert.AreEqual<bool> (false, (x86File :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[ELF] X86 IsNXEnabled test`` () =
    Assert.AreEqual<bool> (true, (x86File :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[ELF] X86 sections length test`` () =
    Assert.AreEqual<int> (31, x86File.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] X86 static symbols length test`` () =
    Assert.AreEqual<int> (793, x86File.Symbols.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] X86 dynamic symbols length test`` () =
    Assert.AreEqual<int> (131, x86File.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] X86 linkageTableEntries length test`` () =
    let f = x86File :> IBinFile
    Assert.AreEqual<int> (114, f.GetLinkageTableEntries().Length)

  [<TestMethod>]
  member _.``[ELF] X86 text section address test`` () =
    Assert.AreEqual<uint64> (0x8049CD0UL, getTextSectionAddr x86File)

  [<TestMethod>]
  member _.``[ELF] X86 isa wordSize test`` () =
    let f = x86File :> IBinFile
    Assert.AreEqual (WordSize.Bit32, f.ISA.WordSize)

  [<TestMethod>]
  member _.``[ELF] X86 function symbol test (1)`` () =
    assertFuncSymbolExistence x86File 0x080495B0UL "unsetenv"

  [<TestMethod>]
  member _.``[ELF] X86 function symbol test (2)`` () =
    assertFuncSymbolExistence x86File 0x080495B0UL "unsetenv"

  [<TestMethod>]
  member _.``[ELF] X86 Reloc section Dyn test (1)`` () =
    assertExistenceOfRelocation x86File 0x08069FFCUL "__gmon_start__"

  [<TestMethod>]
  member _.``[ELF] X86 Reloc section Dyn test (2)`` () =
    assertExistenceOfRelocation x86File 0x0806A3C0UL "optarg"

  [<TestMethod>]
  member _.``[ELF] X86 Reloc section PLT test (1)`` () =
    assertExistenceOfRelocation x86File 0x0806A00CUL "unsetenv"

  [<TestMethod>]
  member _.``[ELF] X86 Reloc section PLT test (2)`` () =
    assertExistenceOfRelocation x86File 0x0806A1CCUL "putchar_unlocked"

  [<TestMethod>]
  member _.``[ELF] X86 section header test (1)`` () =
    assertExistenceOfSectionHeader x86File 0 ""

  [<TestMethod>]
  member _.``[ELF] X86 section header test (2)`` () =
    assertExistenceOfSectionHeader x86File 30 ".strtab"

  [<TestMethod>]
  member _.``[ELF] X86_Stripped EntryPoint test`` () =
    Assert.AreEqual<uint64> (0x8049CD0UL, x86SFile.Header.EntryPoint)

  [<TestMethod>]
  member _.``[ELF] X86_Stripped file type test`` () =
    Assert.AreEqual (ELF.ELFType.ET_EXEC, x86SFile.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] X86_Stripped IsStripped test`` () =
    Assert.AreEqual<bool> (true, (x86SFile :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[ELF] X86_Stripped IsNXEnabled test`` () =
    Assert.AreEqual<bool> (true, (x86SFile :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[ELF] X86_Stripped sections length test`` () =
    Assert.AreEqual<int> (29, x86SFile.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] X86_Stripped static symbols length test`` () =
    Assert.AreEqual<int> (0, x86SFile.Symbols.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] X86_Stripped dynamic symbols length test`` () =
    Assert.AreEqual<int> (131, x86SFile.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] X86_Stripped linkageTableEntries length test`` () =
    let f = x86SFile :> IBinFile
    Assert.AreEqual<int> (114, f.GetLinkageTableEntries().Length)

  [<TestMethod>]
  member _.``[ELF] X86_Stripped text section address test`` () =
    Assert.AreEqual<uint64> (0x8049CD0UL, getTextSectionAddr x86SFile)

  [<TestMethod>]
  member _.``[ELF] X86_Stripped isa wordSize test`` () =
    Assert.AreEqual (WordSize.Bit32, (x86SFile :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[ELF] X86_Stripped function symbol test (1)`` () =
    assertFuncSymbolExistence x86SFile 0x080495B0UL "unsetenv"

  [<TestMethod>]
  member _.``[ELF] X86_Stripped function symbol test (2)`` () =
    assertFuncSymbolExistence x86SFile 0x08049CB0UL "putchar_unlocked"

  [<TestMethod>]
  member _.``[ELF] X86_Stripped Reloc section Dyn test (1)`` () =
    assertExistenceOfRelocation x86SFile 0x08069FFCUL "__gmon_start__"

  [<TestMethod>]
  member _.``[ELF] X86_Stripped Reloc section Dyn test (2)`` () =
    assertExistenceOfRelocation x86SFile 0x0806A3C0UL "optarg"

  [<TestMethod>]
  member _.``[ELF] X86_Stripped Reloc section PLT test (1)`` () =
    assertExistenceOfRelocation x86SFile 0x0806A00CUL "unsetenv"

  [<TestMethod>]
  member _.``[ELF] X86_Stripped Reloc section PLT test (2)`` () =
    assertExistenceOfRelocation x86SFile 0x0806A1CCUL "putchar_unlocked"

  [<TestMethod>]
  member _.``[ELF] X86_Stripped section header test (1)`` () =
    assertExistenceOfSectionHeader x86SFile 0 ""

  [<TestMethod>]
  member _.``[ELF] X86_Stripped section header test (2)`` () =
    assertExistenceOfSectionHeader x86SFile 28 ".shstrtab"

  [<TestMethod>]
  member _.``[ELF] X64 EntryPoint test`` () =
    Assert.AreEqual<uint64> (0x404050UL, x64File.Header.EntryPoint)

  [<TestMethod>]
  member _.``[ELF] X64 file type test`` () =
    Assert.AreEqual (ELF.ELFType.ET_EXEC, x64File.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] X64 IsStripped test`` () =
    Assert.AreEqual<bool> (false, (x64File :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[ELF] X64 IsNXEnabled test`` () =
    Assert.AreEqual<bool> (true, (x64File :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[ELF] X64 sections length test`` () =
    Assert.AreEqual<int> (38, x64File.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] X64 static symbols length test`` () =
    Assert.AreEqual<int> (635, x64File.Symbols.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] X64 dynamic symbols length test`` () =
    Assert.AreEqual<int> (126, x64File.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] X64 linkageTableEntries length test`` () =
    let f = x64File :> IBinFile
    Assert.AreEqual<int> (110, f.GetLinkageTableEntries().Length)

  [<TestMethod>]
  member _.``[ELF] X64 text section address test`` () =
    Assert.AreEqual<uint64> (0x4027C0UL, getTextSectionAddr x64File)

  [<TestMethod>]
  member _.``[ELF] X64 isa wordSize test`` () =
    Assert.AreEqual (WordSize.Bit64, (x64File :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[ELF] X64 function symbol test (1)`` () =
    assertFuncSymbolExistence x64File 0x004020E0UL "__ctype_toupper_loc"

  [<TestMethod>]
  member _.``[ELF] X64 function symbol test (2)`` () =
    assertFuncSymbolExistence x64File 0x004027A0UL "__sprintf_chk"

  [<TestMethod>]
  member _.``[ELF] X64 Reloc section Dyn test (1)`` () =
    assertExistenceOfRelocation x64File 0x0061Eff8UL "__gmon_start__"

  [<TestMethod>]
  member _.``[ELF] X64 Reloc section Dyn test (2)`` () =
    assertExistenceOfRelocation x64File 0x0061F620UL "stderr"

  [<TestMethod>]
  member _.``[ELF] X64 Reloc section PLT test (1)`` () =
    assertExistenceOfRelocation x64File 0x0061F018UL "__ctype_toupper_loc"

  [<TestMethod>]
  member _.``[ELF] X64 Reloc section PLT test (2)`` () =
    assertExistenceOfRelocation x64File 0x0061F378UL "__sprintf_chk"

  [<TestMethod>]
  member _.``[ELF] X64 section header test (1)`` () =
    assertExistenceOfSectionHeader x64File 0 ""

  [<TestMethod>]
  member _.``[ELF] X64 section header test (2)`` () =
    assertExistenceOfSectionHeader x64File 37 ".strtab"

  [<TestMethod>]
  member _.``[ELF] X64_Stripped EntryPoint test`` () =
    Assert.AreEqual<uint64> (0x404050UL, x64SFile.Header.EntryPoint)

  [<TestMethod>]
  member _.``[ELF] X64_Stripped file type test`` () =
    Assert.AreEqual (ELF.ELFType.ET_EXEC, x64SFile.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] X64_Stripped IsStripped test`` () =
    Assert.AreEqual<bool> (true, (x64SFile :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[ELF] X64_Stripped IsNXEnabled test`` () =
    Assert.AreEqual<bool> (true, (x64SFile :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[ELF] X64_Stripped sections length test`` () =
    Assert.AreEqual<int> (29, x64SFile.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] X64_Stripped static symbols length test`` () =
    Assert.AreEqual<int> (0, x64SFile.Symbols.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] X64_Stripped dynamic symbols length test`` () =
    Assert.AreEqual<int> (126, x64SFile.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] X64_Stripped linkageTableEntries length test`` () =
    let f = x64SFile :> IBinFile
    Assert.AreEqual<int> (110, f.GetLinkageTableEntries().Length)

  [<TestMethod>]
  member _.``[ELF] X64_Stripped text section address test`` () =
    Assert.AreEqual<uint64> (0x4027C0UL, getTextSectionAddr x64SFile)

  [<TestMethod>]
  member _.``[ELF] X64_Stripped isa wordSize test`` () =
    Assert.AreEqual (WordSize.Bit64, (x64SFile :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[ELF] X64_Stripped function symbol test (1)`` () =
    assertFuncSymbolExistence x64SFile 0x004020E0UL "__ctype_toupper_loc"

  [<TestMethod>]
  member _.``[ELF] X64_Stripped function symbol test (2)`` () =
    assertFuncSymbolExistence x64SFile 0x004027A0UL "__sprintf_chk"

  [<TestMethod>]
  member _.``[ELF] X64_Stripped Reloc section Dyn test (1)`` () =
    assertExistenceOfRelocation x64SFile 0x0061EFF8UL "__gmon_start__"

  [<TestMethod>]
  member _.``[ELF] X64_Stripped Reloc section Dyn test (2)`` () =
    assertExistenceOfRelocation x64SFile 0x0061F620UL "stderr"

  [<TestMethod>]
  member _.``[ELF] X64_Stripped Reloc section PLT test (1)`` () =
    assertExistenceOfRelocation x64SFile 0x0061F018UL "__ctype_toupper_loc"

  [<TestMethod>]
  member _.``[ELF] X64_Stripped Reloc section PLT test (2)`` () =
    assertExistenceOfRelocation x64SFile 0x0061F378UL "__sprintf_chk"

  [<TestMethod>]
  member _.``[ELF] X64_Stripped section header test (1)`` () =
    assertExistenceOfSectionHeader x64SFile 0 ""

  [<TestMethod>]
  member _.``[ELF] X64_Stripped section header test (2)`` () =
    assertExistenceOfSectionHeader x64SFile 28 ".shstrtab"

  [<TestMethod>]
  member _.``[ELF] arm32 EntryPoint test`` () =
    Assert.AreEqual<uint64> (0x00013D0CUL, arm32File.Header.EntryPoint)

  [<TestMethod>]
  member _.``[ELF] arm32 file type test`` () =
    Assert.AreEqual (ELF.ELFType.ET_EXEC, arm32File.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] arm32 IsStripped test`` () =
    Assert.AreEqual<bool> (false, (arm32File :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[ELF] arm32 IsNXEnabled test`` () =
    Assert.AreEqual<bool> (true, (arm32File :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[ELF] arm32 sections length test`` () =
    Assert.AreEqual<int> (38, arm32File.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] arm32 static symbols length test`` () =
    Assert.AreEqual<int> (1299, arm32File.Symbols.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] arm32 dynamic symbols length test`` () =
    Assert.AreEqual<int> (136, arm32File.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] arm32 linkageTableEntries length test`` () =
    let f = arm32File :> IBinFile
    Assert.AreEqual<int> (121, f.GetLinkageTableEntries().Length)

  [<TestMethod>]
  member _.``[ELF] arm32 text section address test`` () =
    Assert.AreEqual<uint64> (0x00011F98UL, getTextSectionAddr arm32File)

  [<TestMethod>]
  member _.``[ELF] arm32 isa wordSize test`` () =
    Assert.AreEqual (WordSize.Bit32, (arm32File :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[ELF] arm32 function symbol test (1)`` () =
    assertFuncSymbolExistence arm32File 0x000119ECUL "fdopen"

  [<TestMethod>]
  member _.``[ELF] arm32 function symbol test (2)`` () =
    assertFuncSymbolExistence arm32File 0x00011F8CUL "__assert_fail"

  [<TestMethod>]
  member _.``[ELF] arm32 Reloc section Dyn test (1)`` () =
    assertExistenceOfRelocation arm32File 0x0003F1F0UL "__gmon_start__"

  [<TestMethod>]
  member _.``[ELF] arm32 Reloc section Dyn test (2)`` () =
    assertExistenceOfRelocation arm32File 0x0003F35CUL "stdout"

  [<TestMethod>]
  member _.``[ELF] arm32 Reloc section PLT test (1)`` () =
    assertExistenceOfRelocation arm32File 0x0003F00CUL "fdopen"

  [<TestMethod>]
  member _.``[ELF] arm32 Reloc section PLT test (2)`` () =
    assertExistenceOfRelocation arm32File 0x0003F1eCUL "__assert_fail"

  [<TestMethod>]
  member _.``[ELF] arm32 section header test (1)`` () =
    assertExistenceOfSectionHeader arm32File 0 ""

  [<TestMethod>]
  member _.``[ELF] arm32 section header test (2)`` () =
    assertExistenceOfSectionHeader arm32File 37 ".strtab"

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped EntryPoint test`` () =
    Assert.AreEqual<uint64> (0x00013D0CUL, arm32SFile.Header.EntryPoint)

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped file type test`` () =
    Assert.AreEqual (ELF.ELFType.ET_EXEC, arm32SFile.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped IsStripped test`` () =
    Assert.AreEqual<bool> (true, (arm32SFile :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped IsNXEnabled test`` () =
    Assert.AreEqual<bool> (true, (arm32SFile :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped sections length test`` () =
    Assert.AreEqual<int> (28, arm32SFile.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped static symbols length test`` () =
    Assert.AreEqual<int> (0, arm32SFile.Symbols.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped dynamic symbols length test`` () =
    Assert.AreEqual<int> (136, arm32SFile.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped linkageTableEntries length test`` () =
    let f = arm32SFile :> IBinFile
    Assert.AreEqual<int> (121, f.GetLinkageTableEntries().Length)

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped text section address test`` () =
    Assert.AreEqual<uint64> (0x00011F98UL, getTextSectionAddr arm32SFile)

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped isa wordSize test`` () =
    Assert.AreEqual (WordSize.Bit32, (arm32SFile :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped function symbol test (1)`` () =
    assertFuncSymbolExistence arm32SFile 0x000119ECUL "fdopen"

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped function symbol test (2)`` () =
    assertFuncSymbolExistence arm32SFile 0x00011F8CUL "__assert_fail"

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped Reloc section Dyn test (1)`` () =
    assertExistenceOfRelocation arm32SFile 0x0003F1F0UL "__gmon_start__"

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped Reloc section Dyn test (2)`` () =
    assertExistenceOfRelocation arm32SFile 0x0003F35CUL "stdout"

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped Reloc section PLT test (1)`` () =
    assertExistenceOfRelocation arm32SFile 0x0003F00CUL "fdopen"

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped Reloc section PLT test (2)`` () =
    assertExistenceOfRelocation arm32SFile 0x0003F1ECUL "__assert_fail"

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped section header test (1)`` () =
    assertExistenceOfSectionHeader arm32SFile 0 ""

  [<TestMethod>]
  member _.``[ELF] arm32_Stripped section header test (2)`` () =
    assertExistenceOfSectionHeader arm32SFile 27 ".shstrtab"

  [<TestMethod>]
  member _.``[ELF] thumb EntryPoint test`` () =
    Assert.AreEqual<uint64> (0x00013605UL, thumbFile.Header.EntryPoint)

  [<TestMethod>]
  member _.``[ELF] thumb file type test`` () =
    Assert.AreEqual (ELF.ELFType.ET_EXEC, thumbFile.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] thumb IsStripped test`` () =
    Assert.AreEqual<bool> (false, (thumbFile :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[ELF] thumb IsNXEnabled test`` () =
    Assert.AreEqual<bool> (true, (thumbFile :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[ELF] thumb sections length test`` () =
    Assert.AreEqual<int> (38, thumbFile.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] thumb static symbols length test`` () =
    Assert.AreEqual<int> (1088, thumbFile.Symbols.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] thumb dynamic symbols length test`` () =
    Assert.AreEqual<int> (136, thumbFile.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] thumb linkageTableEntries length test`` () =
    let f = thumbFile :> IBinFile
    Assert.AreEqual<int> (121, f.GetLinkageTableEntries().Length)

  [<TestMethod>]
  member _.``[ELF] thumb text section address test`` () =
    Assert.AreEqual<uint64> (0x00011FE0UL, getTextSectionAddr thumbFile)

  [<TestMethod>]
  member _.``[ELF] thumb isa wordSize test`` () =
    Assert.AreEqual (WordSize.Bit32, (thumbFile :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[ELF] thumb function symbol test (1)`` () =
    assertFuncSymbolExistence thumbFile 0x000119FCUL "fdopen"

  [<TestMethod>]
  member _.``[ELF] thumb function symbol test (2)`` () =
    assertFuncSymbolExistence thumbFile 0x00011FD0UL "__assert_fail"

  [<TestMethod>]
  member _.``[ELF] thumb Reloc section Dyn test (1)`` () =
    assertExistenceOfRelocation thumbFile 0x000371F0UL "__gmon_start__"

  [<TestMethod>]
  member _.``[ELF] thumb Reloc section Dyn test (2)`` () =
    assertExistenceOfRelocation thumbFile 0x0003735CUL "stdout"

  [<TestMethod>]
  member _.``[ELF] thumb Reloc section PLT test (1)`` () =
    assertExistenceOfRelocation thumbFile 0x0003700CUL "fdopen"

  [<TestMethod>]
  member _.``[ELF] thumb Reloc section PLT test (2)`` () =
    assertExistenceOfRelocation thumbFile 0x000371ECUL "__assert_fail"

  [<TestMethod>]
  member _.``[ELF] thumb section header test (1)`` () =
    assertExistenceOfSectionHeader thumbFile 0 ""

  [<TestMethod>]
  member _.``[ELF] thumb section header test (2)`` () =
    assertExistenceOfSectionHeader thumbFile 37 ".strtab"

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped EntryPoint test`` () =
    Assert.AreEqual<uint64> (0x00013605UL, thumbSFile.Header.EntryPoint)

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped file type test`` () =
    Assert.AreEqual (ELF.ELFType.ET_EXEC, thumbSFile.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped IsStripped test`` () =
    Assert.AreEqual<bool> (true, (thumbSFile :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped IsNXEnabled test`` () =
    Assert.AreEqual<bool> (true, (thumbSFile :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped sections length test`` () =
    Assert.AreEqual<int> (28, thumbSFile.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped static symbols length test`` () =
    Assert.AreEqual<int> (0, thumbSFile.Symbols.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped dynamic symbols length test`` () =
    Assert.AreEqual<int> (136, thumbSFile.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped linkageTableEntries length test`` () =
    let f = thumbSFile :> IBinFile
    Assert.AreEqual<int> (121, f.GetLinkageTableEntries().Length)

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped text section address test`` () =
    Assert.AreEqual<uint64> (0x00011FE0UL, getTextSectionAddr thumbSFile)

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped isa wordSize test`` () =
    Assert.AreEqual (WordSize.Bit32, (thumbSFile :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped function symbol test (1)`` () =
    assertFuncSymbolExistence thumbSFile 0x000119FCUL "fdopen"

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped function symbol test (2)`` () =
    assertFuncSymbolExistence thumbSFile 0x00011FD0UL "__assert_fail"

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped Reloc section Dyn test (1)`` () =
    assertExistenceOfRelocation thumbSFile 0x000371F0UL "__gmon_start__"

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped Reloc section Dyn test (2)`` () =
    assertExistenceOfRelocation thumbSFile 0x0003735CUL "stdout"

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped Reloc section PLT test (1)`` () =
    assertExistenceOfRelocation thumbSFile 0x0003700CUL "fdopen"

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped Reloc section PLT test (2)`` () =
    assertExistenceOfRelocation thumbSFile 0x000371ECUL "__assert_fail"

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped section header test (1)`` () =
    assertExistenceOfSectionHeader thumbSFile 0 ""

  [<TestMethod>]
  member _.``[ELF] thumb_Stripped section header test (2)`` () =
    assertExistenceOfSectionHeader thumbSFile 27 ".shstrtab"

  [<TestMethod>]
  member _.``[ELF] aarch64 EntryPoint test`` () =
    Assert.AreEqual<uint64> (0x00404788UL, aarch64File.Header.EntryPoint)

  [<TestMethod>]
  member _.``[ELF] aarch64 file type test`` () =
    Assert.AreEqual (ELF.ELFType.ET_EXEC, aarch64File.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] aarch64 IsStripped test`` () =
    Assert.AreEqual<bool> (false, (aarch64File :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[ELF] aarch64 IsNXEnabled test`` () =
    Assert.AreEqual<bool> (true, (aarch64File :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[ELF] aarch64 sections length test`` () =
    Assert.AreEqual<int> (37, aarch64File.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] aarch64 static symbols length test`` () =
    Assert.AreEqual<int> (935, aarch64File.Symbols.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] aarch64 dynamic symbols length test`` () =
    Assert.AreEqual<int> (136, aarch64File.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] aarch64 linkageTableEntries length test`` () =
    let f = aarch64File :> IBinFile
    Assert.AreEqual<int> (121, f.GetLinkageTableEntries().Length)

  [<TestMethod>]
  member _.``[ELF] aarch64 text section address test`` () =
    Assert.AreEqual<uint64> (0x00402E60UL, getTextSectionAddr aarch64File)

  [<TestMethod>]
  member _.``[ELF] aarch64 isa wordSize test`` () =
    Assert.AreEqual (WordSize.Bit64, (aarch64File :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[ELF] aarch64 function symbol test (1)`` () =
    assertFuncSymbolExistence aarch64File 0x004026D0UL "mbrtowc"

  [<TestMethod>]
  member _.``[ELF] aarch64 function symbol test (2)`` () =
    assertFuncSymbolExistence aarch64File 0x00402E50UL "__fxstatat"

  [<TestMethod>]
  member _.``[ELF] aarch64 Reloc section Dyn test (1)`` () =
    assertExistenceOfRelocation aarch64File 0x0042FFD8UL "__gmon_start__"

  [<TestMethod>]
  member _.``[ELF] aarch64 Reloc section Dyn test (2)`` () =
    assertExistenceOfRelocation aarch64File 0x00430630UL "__progname"

  [<TestMethod>]
  member _.``[ELF] aarch64 Reloc section PLT test (1)`` () =
    assertExistenceOfRelocation aarch64File 0x00430000UL "mbrtowc"

  [<TestMethod>]
  member _.``[ELF] aarch64 Reloc section PLT test (2)`` () =
    assertExistenceOfRelocation aarch64File 0x004303C0UL "__fxstatat"

  [<TestMethod>]
  member _.``[ELF] aarch64 section header test (1)`` () =
    assertExistenceOfSectionHeader aarch64File 0 ""

  [<TestMethod>]
  member _.``[ELF] aarch64 section header test (2)`` () =
    assertExistenceOfSectionHeader aarch64File 36 ".strtab"

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped EntryPoint test`` () =
    Assert.AreEqual<uint64> (0x00404788UL, aarch64SFile.Header.EntryPoint)

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped file type test`` () =
    Assert.AreEqual (ELF.ELFType.ET_EXEC, aarch64SFile.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped IsStripped test`` () =
    Assert.AreEqual<bool> (true, (aarch64SFile :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped IsNXEnabled test`` () =
    Assert.AreEqual<bool> (true, (aarch64SFile :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped sections length test`` () =
    Assert.AreEqual<int> (27, aarch64SFile.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped static symbols length test`` () =
    Assert.AreEqual<int> (0, aarch64SFile.Symbols.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped dynamic symbols length test`` () =
    Assert.AreEqual<int> (136, aarch64SFile.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped linkageTableEntries length test`` () =
    let f = aarch64SFile :> IBinFile
    Assert.AreEqual<int> (121, f.GetLinkageTableEntries().Length)

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped text section address test`` () =
    Assert.AreEqual<uint64> (0x00402E60UL, getTextSectionAddr aarch64SFile)

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped isa wordSize test`` () =
    Assert.AreEqual (WordSize.Bit64, (aarch64SFile :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped function symbol test (1)`` () =
    assertFuncSymbolExistence aarch64SFile 0x004026D0UL "mbrtowc"

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped function symbol test (2)`` () =
    assertFuncSymbolExistence aarch64SFile 0x00402E50UL "__fxstatat"

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped Reloc section Dyn test (1)`` () =
    assertExistenceOfRelocation aarch64SFile 0x0042FFD8UL "__gmon_start__"

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped Reloc section Dyn test (2)`` () =
    assertExistenceOfRelocation aarch64SFile 0x00430630UL "__progname"

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped Reloc section PLT test (1)`` () =
    assertExistenceOfRelocation aarch64SFile 0x00430000UL "mbrtowc"

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped Reloc section PLT test (2)`` () =
    assertExistenceOfRelocation aarch64SFile 0x004303C0UL "__fxstatat"

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped section header test (1)`` () =
    assertExistenceOfSectionHeader aarch64SFile 0 ""

  [<TestMethod>]
  member _.``[ELF] aarch64_Stripped section header test (2)`` () =
    assertExistenceOfSectionHeader aarch64SFile 26 ".shstrtab"

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped EntryPoint test`` () =
    Assert.AreEqual<uint64> (0x00004C80UL, mips32File.Header.EntryPoint)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped file type test`` () =
    Assert.AreEqual (ELF.ELFType.ET_DYN, mips32File.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped IsStripped test`` () =
    Assert.AreEqual<bool> (true, (mips32File :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped IsNXEnabled test`` () =
    Assert.AreEqual<bool> (false, (mips32File :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped sections length test`` () =
    Assert.AreEqual<int> (34, mips32File.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped static symbols length test`` () =
    Assert.AreEqual<int> (0, mips32File.Symbols.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped dynamic symbols length test`` () =
    Assert.AreEqual<int> (232, mips32File.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped linkageTableEntries length test`` () =
    let f = mips32File :> IBinFile
    Assert.AreEqual<int> (106, f.GetLinkageTableEntries().Length)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped text section address test`` () =
    Assert.AreEqual<uint64> (0x00002C50UL, getTextSectionAddr mips32File)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped isa wordSize test`` () =
    Assert.AreEqual (WordSize.Bit32, (mips32File :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped function symbol test (1)`` () =
    assertFuncSymbolExistence mips32File 0x0001C280UL "strcmp"

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped function symbol test (2)`` () =
    assertFuncSymbolExistence mips32File 0x0001C240UL "getpwnam"

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped Reloc section Dyn test (1)`` () =
    assertExistenceOfRelocation mips32File 0x00032B28UL ""

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped Reloc section Dyn test (2)`` () =
    assertExistenceOfRelocation mips32File 0x00033588UL ""

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped section header test (1)`` () =
    assertExistenceOfSectionHeader mips32File 0 ""

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped section header test (2)`` () =
    assertExistenceOfSectionHeader mips32File 33 ".shstrtab"

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped_le EntryPoint test`` () =
    Assert.AreEqual<uint64> (0x00004C80UL, mips32leFile.Header.EntryPoint)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped_le file type test`` () =
    Assert.AreEqual (ELF.ELFType.ET_DYN, mips32leFile.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped_le IsStripped test`` () =
    Assert.AreEqual<bool> (true, (mips32leFile :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped_le IsNXEnabled test`` () =
    Assert.AreEqual<bool> (false, (mips32leFile :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped_le sections length test`` () =
    Assert.AreEqual<int> (34, mips32leFile.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped_le static symbols length test`` () =
    Assert.AreEqual<int> (0, mips32leFile.Symbols.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped_le dynamic symbols length test`` () =
    Assert.AreEqual<int> (232, mips32leFile.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped_le linkageTableEntries length test`` () =
    let f = mips32leFile :> IBinFile
    Assert.AreEqual<int> (106, f.GetLinkageTableEntries().Length)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped_le text section address test`` () =
    Assert.AreEqual<uint64> (0x00002C50UL, getTextSectionAddr mips32leFile)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped_le isa wordSize test`` () =
    Assert.AreEqual (WordSize.Bit32, (mips32leFile :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped_le function symbol test (1)`` () =
    assertFuncSymbolExistence mips32leFile 0x0001C280UL "__snprintf_chk"

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped_le function symbol test (2)`` () =
    assertFuncSymbolExistence mips32leFile 0x0001C240UL "unsetenv"

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped_le Reloc section Dyn test (1)`` () =
    assertExistenceOfRelocation mips32leFile 0x00032B28UL ""

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped_le Reloc section Dyn test (2)`` () =
    assertExistenceOfRelocation mips32leFile 0x00033588UL ""

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped_le section header test (1)`` () =
    assertExistenceOfSectionHeader mips32leFile 0 ""

  [<TestMethod>]
  member _.``[ELF] mips32_Stripped_le section header test (2)`` () =
    assertExistenceOfSectionHeader mips32leFile 33 ".shstrtab"

  [<TestMethod>]
  member _.``[ELF] mips64_Stripped EntryPoint test`` () =
    Assert.AreEqual<uint64> (0x0000ADE0UL, mips64File.Header.EntryPoint)

  [<TestMethod>]
  member _.``[ELF] mips64_Stripped file type test`` () =
    Assert.AreEqual (ELF.ELFType.ET_DYN, mips64File.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] mips64_Stripped IsStripped test`` () =
    Assert.AreEqual<bool> (true, (mips64File :> IBinFile).IsStripped)

  [<TestMethod>]
  member _.``[ELF] mips64_Stripped IsNXEnabled test`` () =
    Assert.AreEqual<bool> (false, (mips64File :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[ELF] mips64_Stripped sections length test`` () =
    Assert.AreEqual<int> (32, mips64File.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] mips64_Stripped static symbols length test`` () =
    Assert.AreEqual<int> (0, mips64File.Symbols.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] mips64_Stripped dynamic symbols length test`` () =
    Assert.AreEqual<int> (232, mips64File.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] mips64_Stripped linkageTableEntries length test`` () =
    let f = mips64File :> IBinFile
    Assert.AreEqual<int> (106, f.GetLinkageTableEntries().Length)

  [<TestMethod>]
  member _.``[ELF] mips64_Stripped text section address test`` () =
    Assert.AreEqual<uint64> (0x00008F90UL, getTextSectionAddr mips64File)

  [<TestMethod>]
  member _.``[ELF] mips64_Stripped isa wordSize test`` () =
    Assert.AreEqual (WordSize.Bit64, (mips64File :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[ELF] mips64_Stripped function symbol test (1)`` () =
    assertFuncSymbolExistence mips64File 0x00022380UL "strcmp"

  [<TestMethod>]
  member _.``[ELF] mips64_Stripped function symbol test (2)`` () =
    assertFuncSymbolExistence mips64File 0x00022320UL "unsetenv"

  [<TestMethod>]
  member _.``[ELF] mips64_Stripped Reloc section Dyn test (1)`` () =
    assertExistenceOfRelocation mips64File 0x00039650UL ""

  [<TestMethod>]
  member _.``[ELF] mips64_Stripped Reloc section Dyn test (2)`` () =
    assertExistenceOfRelocation mips64File 0x0003AA50UL ""

  [<TestMethod>]
  member _.``[ELF] mips64_Stripped section header test (1)`` () =
    assertExistenceOfSectionHeader mips64File 0 ""

  [<TestMethod>]
  member _.``[ELF] mips64_Stripped section header test (2)`` () =
    assertExistenceOfSectionHeader mips64File 31 ".shstrtab"

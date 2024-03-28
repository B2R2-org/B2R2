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

namespace B2R2.BinFile.Tests

open B2R2
open B2R2.FrontEnd.BinFile
open Microsoft.VisualStudio.TestTools.UnitTesting
open System.IO
open System.IO.Compression
open type FileFormat

exception TestFileNotFoundException

[<AutoOpen>]
module ZIPReader =
  let baseDir = System.AppDomain.CurrentDomain.BaseDirectory

  let zipFileSrcDir = baseDir + "../../../"

  let getFileDir = function
    | FileFormat.PEBinary -> "PE/"
    | FileFormat.ELFBinary -> "ELF/"
    | FileFormat.MachBinary -> "Mach/"
    | FileFormat.WasmBinary -> "Wasm/"
    | _ -> failwith "Invalid file format"

  let readBytesFromZipFile fileFormat zipFileName inZipFileName =
    let zipDirectory = zipFileSrcDir + getFileDir fileFormat
    let archive = ZipFile.Open (zipDirectory + zipFileName, ZipArchiveMode.Read)
    let entry = archive.GetEntry (inZipFileName)
    let stream = entry.Open ()
    use ms = new MemoryStream ()
    stream.CopyTo (ms)
    ms.ToArray ()

[<AutoOpen>]
module TestHelper =
  let assertFuncSymbolExistence (file: IBinFile) address symbolName =
    match file.TryFindFunctionName address with
    | Ok n -> Assert.AreEqual (n, symbolName)
    | Error _ -> Assert.Fail ()

  let getTextSectionAddr (file: IBinFile) =
    let sec = file.GetTextSection ()
    sec.Address

  let assertExistenceOfPair pair pairSequence =
    pairSequence
    |> Seq.tryFind ((=) pair)
    |> Option.isSome
    |> Assert.IsTrue

module PE =
  let x64FileName = "pe_x64"
  let x86FileName = "pe_x86"
  let x64PDBFileName = "pe_x64.pdb"
  let x86PDBFileName = "pe_x86.pdb"

  let parseFile fileName (pdbFileName: string) =
    let zipFile = fileName + ".zip"
    let fileNameInZip = fileName + ".exe"
    let bytes = readBytesFromZipFile PEBinary zipFile fileNameInZip
    let pdbBytes =
      if pdbFileName.Length = 0 then [||]
      else readBytesFromZipFile PEBinary zipFile pdbFileName
    PEBinFile (fileNameInZip, bytes, None, pdbBytes) :> IBinFile

  let assertExistenceOfRelocBlock (file: IBinFile) pageRVA blockSize =
    (file :?> PEBinFile).PE.RelocBlocks
    |> List.map (fun pair -> pair.PageRVA, pair.BlockSize)
    |> Seq.ofList
    |> assertExistenceOfPair (pageRVA, blockSize)

  let assertExistenceOfSectionHeader (file: IBinFile) address headerName =
    (file :?> PEBinFile).PE.SectionHeaders
    |> Array.map (fun record -> record.VirtualAddress, record.Name)
    |> assertExistenceOfPair (address, headerName)

  [<TestClass>]
  type X86TestClass () =
    static let file = parseFile x86FileName x86PDBFileName

    [<TestMethod>]
    member __.``[PE] X86 EntryPoint test`` () =
      Assert.AreEqual (Some 0x0040140cUL, file.EntryPoint)

    [<TestMethod>]
    member __.``[PE] X86 file type test`` () =
      Assert.AreEqual (FileType.ExecutableFile, file.Type)

    [<TestMethod>]
    member __.``[PE] X86 IsStripped test`` () =
      Assert.AreEqual (false, file.IsStripped)

    [<TestMethod>]
    member __.``[PE] X86 IsNXEnabled test`` () =
      Assert.AreEqual (true, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[PE] X86 sections length test`` () =
      Assert.AreEqual (5, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[PE] X86 static symbols length test`` () =
      Assert.AreEqual (239, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[PE] X86 dynamic symbols length test`` () =
      Assert.AreEqual (41, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[PE] X86 text section address test`` () =
      Assert.AreEqual (0x00401000UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[PE] X86 isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[PE] X86 function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x00401090UL "_add"

    [<TestMethod>]
    member __.``[PE] X86 function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x004010d0UL "_mul"

    [<TestMethod>]
    member __.``[PE] X86 function symbol test (3)`` () =
      assertFuncSymbolExistence file 0x004010e0UL "_main"

    [<TestMethod>]
    member __.``[PE] X86 Reloc section test (1)`` () =
      assertExistenceOfRelocBlock file 8192u 36

    [<TestMethod>]
    member __.``[PE] X86 Reloc section test (2)`` () =
      assertExistenceOfRelocBlock file 4096u 320

    [<TestMethod>]
    member __.``[PE] X86 section header test (1)`` () =
      assertExistenceOfSectionHeader file 4096 ".text"

    [<TestMethod>]
    member __.``[PE] X86 section header test (2)`` () =
      assertExistenceOfSectionHeader file 8192 ".rdata"

    [<TestMethod>]
    member __.``[PE] X86 section header test (3)`` () =
      assertExistenceOfSectionHeader file 12288 ".data"

    [<TestMethod>]
    member __.``[PE] X86 section header test (4)`` () =
      assertExistenceOfSectionHeader file 16384 ".rsrc"

    [<TestMethod>]
    member __.``[PE] X86 section header test (5)`` () =
      assertExistenceOfSectionHeader file 20480 ".reloc"

  [<TestClass>]
  type X64TestClass () =
    static let file = parseFile x64FileName x64PDBFileName

    [<TestMethod>]
    member __.``[PE] X64 EntryPoint test`` () =
      Assert.AreEqual (Some 0x1400014b4UL, file.EntryPoint)

    [<TestMethod>]
    member __.``[PE] X64 file type test`` () =
      Assert.AreEqual (FileType.ExecutableFile, file.Type)

    [<TestMethod>]
    member __.``[PE] X64 IsStripped test`` () =
      Assert.AreEqual (false, file.IsStripped)

    [<TestMethod>]
    member __.``[PE] X64 IsNXEnabled test`` () =
      Assert.AreEqual (true, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[PE] X64 sections length test`` () =
      Assert.AreEqual (6, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[PE] X64 static symbols length test`` () =
      Assert.AreEqual (240, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[PE] X64 dynamic symbols length test`` () =
      Assert.AreEqual (43, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[PE] X64 text section address test`` () =
      Assert.AreEqual (0x140001000UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[PE] X64 isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit64, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[PE] X64 function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x1400010e0UL "add"

    [<TestMethod>]
    member __.``[PE] X64 function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x140001110UL "mul"

    [<TestMethod>]
    member __.``[PE] X64 function symbol test (3)`` () =
      assertFuncSymbolExistence file 0x140001130UL "main"

    [<TestMethod>]
    member __.``[PE] X64 Reloc section test`` () =
      assertExistenceOfRelocBlock file 8192u 28

    [<TestMethod>]
    member __.``[PE] X64 section header test (1)`` () =
      assertExistenceOfSectionHeader file 4096 ".text"

    [<TestMethod>]
    member __.``[PE] X64 section header test (2)`` () =
      assertExistenceOfSectionHeader file 8192 ".rdata"

    [<TestMethod>]
    member __.``[PE] X64 section header test (3)`` () =
      assertExistenceOfSectionHeader file 12288 ".data"

    [<TestMethod>]
    member __.``[PE] X64 section header test (4)`` () =
      assertExistenceOfSectionHeader file 16384 ".pdata"

    [<TestMethod>]
    member __.``[PE] X64 section header test (5)`` () =
      assertExistenceOfSectionHeader file 20480 ".rsrc"

    [<TestMethod>]
    member __.``[PE] X64 section header test (6)`` () =
      assertExistenceOfSectionHeader file 24576 ".reloc"

module Mach =
  let parseFile fileName arch =
    let zipFile = fileName + ".zip"
    let bytes = readBytesFromZipFile MachBinary zipFile fileName
    let isa = ISA.Init arch Endian.Little
    MachBinFile (fileName, bytes, isa, None) :> IBinFile

  let assertExistenceOfFlag (file: IBinFile) flags =
    (file :?> MachBinFile).Header.Flags.ToString () = flags
    |> Assert.IsTrue

  let assertExistenceOfSectionHeader (file: IBinFile) address sectionName =
    (file :?> MachBinFile).Sections
    |> Seq.map (fun record -> record.SecAddr, record.SecName)
    |> assertExistenceOfPair (address, sectionName)

  [<TestClass>]
  type X86StrippedTestClass () =
    static let file = parseFile "mach_x86_rm_stripped" Architecture.IntelX86

    [<TestMethod>]
    member __.``[Mach] X86_Stripped EntryPoint test`` () =
      Assert.AreEqual (Some 0x00002050UL, file.EntryPoint)

    [<TestMethod>]
    member __.``[Mach] X86_Stripped file type test`` () =
      Assert.AreEqual (FileType.ExecutableFile, file.Type)

    [<TestMethod>]
    member __.``[Mach] X86_Stripped IsStripped test`` () =
      Assert.AreEqual (true, file.IsStripped)

    [<TestMethod>]
    member __.``[Mach] X86_Stripped IsNXEnabled test`` () =
      Assert.AreEqual (true, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[Mach] X86_Stripped sections length test`` () =
      Assert.AreEqual (9, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[Mach] X86_Stripped static symbols length test`` () =
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[Mach] X86_Stripped dynamic symbols length test`` () =
      Assert.AreEqual (59, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[Mach] X86_Stripped linkageTableEntries length test`` () =
      Assert.AreEqual (45, file.GetLinkageTableEntries () |> Seq.length)

    [<TestMethod>]
    member __.``[Mach] X86_Stripped text section address test`` () =
      Assert.AreEqual (0x00002050UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[Mach] X86_Stripped isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[Mach] X86_Stripped function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x00003b28UL "___error"

    [<TestMethod>]
    member __.``[Mach] X86_Stripped function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x00003b70UL "_fflush"

    [<TestMethod>]
    member __.``[Mach] X86_Stripped section header test (1)`` () =
      assertExistenceOfSectionHeader file 8272UL "__text"

    [<TestMethod>]
    member __.``[Mach] X86_Stripped section header test (2)`` () =
      assertExistenceOfSectionHeader file 16620UL "__common"

    [<TestMethod>]
    member __.``[Mach] X86_Stripped flags test`` () =
      let flags =
        "MH_NOUNDEFS, MH_DYLDLINK, MH_TWOLEVEL, MH_PIE, MH_NO_HEAP_EXECUTION"
      assertExistenceOfFlag file flags

  [<TestClass>]
  type X64TestClass () =
    static let file = parseFile "mach_x64_wc" Architecture.IntelX64

    [<TestMethod>]
    member __.``[Mach] X64 EntryPoint test`` () =
      Assert.AreEqual (Some 0x100000E90UL, file.EntryPoint)

    [<TestMethod>]
    member __.``[Mach] X64 file type test`` () =
      Assert.AreEqual (FileType.ExecutableFile, file.Type)

    [<TestMethod>]
    member __.``[Mach] X64 IsStripped test`` () =
      Assert.AreEqual (false, file.IsStripped)

    [<TestMethod>]
    member __.``[Mach] X64 IsNXEnabled test`` () =
      Assert.AreEqual (true, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[Mach] X64 sections length test`` () =
      Assert.AreEqual (13, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[Mach] X64 static symbols length test`` () =
      Assert.AreEqual (885, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[Mach] X64 dynamic symbols length test`` () =
      Assert.AreEqual (190, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[Mach] X64 linkageTableEntries length test`` () =
      Assert.AreEqual (72, file.GetLinkageTableEntries () |> Seq.length)

    [<TestMethod>]
    member __.``[Mach] X64 text section address test`` () =
      Assert.AreEqual (0x100000D30UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[Mach] X64 isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit64, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[Mach] X64 function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x100000D30UL "_usage"

    [<TestMethod>]
    member __.``[Mach] X64 function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x100005F90UL "_error"

    [<TestMethod>]
    member __.``[Mach] X64 section header test (1)`` () =
      assertExistenceOfSectionHeader file 0x100000D30UL "__text"

    [<TestMethod>]
    member __.``[Mach] X64 section header test (2)`` () =
      assertExistenceOfSectionHeader file 0x10000d680UL "__common"

    [<TestMethod>]
    member __.``[Mach] X64 flags test`` () =
      let flags = "MH_NOUNDEFS, MH_DYLDLINK, MH_TWOLEVEL, MH_PIE"
      assertExistenceOfFlag file flags

  [<TestClass>]
  type X64StrippedTestClass () =
    static let file = parseFile "mach_x64_wc_stripped" Architecture.IntelX64

    [<TestMethod>]
    member __.``[Mach] X64_Stripped EntryPoint test`` () =
      Assert.AreEqual (Some 0x100000E90UL, file.EntryPoint)

    [<TestMethod>]
    member __.``[Mach] X64_Stripped file type test`` () =
      Assert.AreEqual (FileType.ExecutableFile, file.Type)

    [<TestMethod>]
    member __.``[Mach] X64_Stripped IsStripped test`` () =
      Assert.AreEqual (true, file.IsStripped)

    [<TestMethod>]
    member __.``[Mach] X64_Stripped IsNXEnabled test`` () =
      Assert.AreEqual (true, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[Mach] X64_Stripped sections length test`` () =
      Assert.AreEqual (13, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[Mach] X64_Stripped static symbols length test`` () =
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[Mach] X64_Stripped dynamic symbols length test`` () =
      Assert.AreEqual (190, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[Mach] X64_Stripped linkageTableEntries length test`` () =
      Assert.AreEqual (72, file.GetLinkageTableEntries () |> Seq.length)

    [<TestMethod>]
    member __.``[Mach] X64_Stripped text section address test`` () =
      Assert.AreEqual (0x100000D30UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[Mach] X64_Stripped isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit64, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[Mach] X64_Stripped function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x10000B076UL "___error"

    [<TestMethod>]
    member __.``[Mach] X64_Stripped function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x10000B0D0UL "_fflush"

    [<TestMethod>]
    member __.``[Mach] X64_Stripped section header test (1)`` () =
      assertExistenceOfSectionHeader file 0x100000D30UL "__text"

    [<TestMethod>]
    member __.``[Mach] X64_Stripped section header test (2)`` () =
      assertExistenceOfSectionHeader file 0x10000d680UL "__common"

    [<TestMethod>]
    member __.``[Mach] X64_Stripped flags test`` () =
      let flags = "MH_NOUNDEFS, MH_DYLDLINK, MH_TWOLEVEL, MH_PIE"
      assertExistenceOfFlag file flags

module ELF =
  let x64FileName = "elf_x64_ls"
  let x86FileName = "elf_x86_ls"
  let x64StrippedFileName = "elf_x64_ls_stripped"
  let x86StrippedFileName = "elf_x86_ls_stripped"
  let arm32FileName = "elf_arm32_ls"
  let thumbFileName = "elf_thumb_ls"
  let aarch64FileName = "elf_aarch64_ls"
  let arm32StrippedFileName = "elf_arm32_ls_stripped"
  let thumbStrippedFileName = "elf_thumb_ls_stripped"
  let aarch64StrippedFileName = "elf_aarch64_ls_stripped"
  let mips32StrippedFileName = "elf_mips32_ls_stripped"
  let mips32LEStrippedFileName = "elf_mips32_ls_stripped_le"
  let mips64StrippedFileName = "elf_mips64_ls_stripped"

  let parseFile fileName =
    let zipFile = fileName + ".zip"
    let bytes = readBytesFromZipFile ELFBinary zipFile fileName
    ELFBinFile (fileName, bytes, None, None) :> IBinFile

  let assertExistenceOfRelocation (file: IBinFile) offset symbolName =
    (file :?> ELFBinFile).RelocationInfo.RelocByAddr
    |> Seq.map (fun pair -> pair.Key, pair.Value.RelSymbol.Value.SymName)
    |> assertExistenceOfPair (offset, symbolName)

  let assertExistenceOfSectionHeader (file: IBinFile) sectionNum sectionName =
    (file :?> ELFBinFile).SectionHeaders
    |> Seq.map (fun record -> record.SecNum, record.SecName)
    |> assertExistenceOfPair (sectionNum, sectionName)

  [<TestClass>]
  type X86TestClass () =
    static let file = parseFile x86FileName

    [<TestMethod>]
    member __.``[ELF] X86 EntryPoint test`` () =
      Assert.AreEqual (Some 0x8049CD0UL, file.EntryPoint)

    [<TestMethod>]
    member __.``[ELF] X86 file type test`` () =
      Assert.AreEqual (FileType.ExecutableFile, file.Type)

    [<TestMethod>]
    member __.``[ELF] X86 IsStripped test`` () =
      Assert.AreEqual (false, file.IsStripped)

    [<TestMethod>]
    member __.``[ELF] X86 IsNXEnabled test`` () =
      Assert.AreEqual (true, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[ELF] X86 sections length test`` () =
      Assert.AreEqual (31, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] X86 static symbols length test`` () =
      Assert.AreEqual (793, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] X86 dynamic symbols length test`` () =
      Assert.AreEqual (131, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] X86 linkageTableEntries length test`` () =
      Assert.AreEqual (114, file.GetLinkageTableEntries () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] X86 text section address test`` () =
      Assert.AreEqual (0x8049CD0UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[ELF] X86 isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[ELF] X86 function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x080495B0UL "unsetenv"

    [<TestMethod>]
    member __.``[ELF] X86 function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x080495B0UL "unsetenv"

    [<TestMethod>]
    member __.``[ELF] X86 Reloc section Dyn test (1)`` () =
      assertExistenceOfRelocation file 0x08069FFCUL "__gmon_start__"

    [<TestMethod>]
    member __.``[ELF] X86 Reloc section Dyn test (2)`` () =
      assertExistenceOfRelocation file 0x0806A3C0UL "optarg"

    [<TestMethod>]
    member __.``[ELF] X86 Reloc section PLT test (1)`` () =
      assertExistenceOfRelocation file 0x0806A00CUL "unsetenv"

    [<TestMethod>]
    member __.``[ELF] X86 Reloc section PLT test (2)`` () =
      assertExistenceOfRelocation file 0x0806A1CCUL "putchar_unlocked"

    [<TestMethod>]
    member __.``[ELF] X86 section header test (1)`` () =
      assertExistenceOfSectionHeader file 0 ""

    [<TestMethod>]
    member __.``[ELF] X86 section header test (2)`` () =
      assertExistenceOfSectionHeader file 30 ".strtab"

  [<TestClass>]
  type X86StrippedTestClass () =
    static let file = parseFile x86StrippedFileName

    [<TestMethod>]
    member __.``[ELF] X86_Stripped EntryPoint test`` () =
      Assert.AreEqual (Some 0x8049CD0UL, file.EntryPoint)

    [<TestMethod>]
    member __.``[ELF] X86_Stripped file type test`` () =
      Assert.AreEqual (FileType.ExecutableFile, file.Type)

    [<TestMethod>]
    member __.``[ELF] X86_Stripped IsStripped test`` () =
      Assert.AreEqual (true, file.IsStripped)

    [<TestMethod>]
    member __.``[ELF] X86_Stripped IsNXEnabled test`` () =
      Assert.AreEqual (true, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[ELF] X86_Stripped sections length test`` () =
      Assert.AreEqual (29, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] X86_Stripped static symbols length test`` () =
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] X86_Stripped dynamic symbols length test`` () =
      Assert.AreEqual (131, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] X86_Stripped linkageTableEntries length test`` () =
      Assert.AreEqual (114, file.GetLinkageTableEntries () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] X86_Stripped text section address test`` () =
      Assert.AreEqual (0x8049CD0UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[ELF] X86_Stripped isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[ELF] X86_Stripped function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x080495B0UL "unsetenv"

    [<TestMethod>]
    member __.``[ELF] X86_Stripped function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x08049CB0UL "putchar_unlocked"

    [<TestMethod>]
    member __.``[ELF] X86_Stripped Reloc section Dyn test (1)`` () =
      assertExistenceOfRelocation file 0x08069FFCUL "__gmon_start__"

    [<TestMethod>]
    member __.``[ELF] X86_Stripped Reloc section Dyn test (2)`` () =
      assertExistenceOfRelocation file 0x0806A3C0UL "optarg"

    [<TestMethod>]
    member __.``[ELF] X86_Stripped Reloc section PLT test (1)`` () =
      assertExistenceOfRelocation file 0x0806A00CUL "unsetenv"

    [<TestMethod>]
    member __.``[ELF] X86_Stripped Reloc section PLT test (2)`` () =
      assertExistenceOfRelocation file 0x0806A1CCUL "putchar_unlocked"

    [<TestMethod>]
    member __.``[ELF] X86_Stripped section header test (1)`` () =
      assertExistenceOfSectionHeader file 0 ""

    [<TestMethod>]
    member __.``[ELF] X86_Stripped section header test (2)`` () =
      assertExistenceOfSectionHeader file 28 ".shstrtab"

  [<TestClass>]
  type X64TestClass () =
    static let file = parseFile x64FileName

    [<TestMethod>]
    member __.``[ELF] X64 EntryPoint test`` () =
      Assert.AreEqual (Some 0x404050UL, file.EntryPoint)

    [<TestMethod>]
    member __.``[ELF] X64 file type test`` () =
      Assert.AreEqual (FileType.ExecutableFile, file.Type)

    [<TestMethod>]
    member __.``[ELF] X64 IsStripped test`` () =
      Assert.AreEqual (false, file.IsStripped)

    [<TestMethod>]
    member __.``[ELF] X64 IsNXEnabled test`` () =
      Assert.AreEqual (true, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[ELF] X64 sections length test`` () =
      Assert.AreEqual (38, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] X64 static symbols length test`` () =
      Assert.AreEqual (635, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] X64 dynamic symbols length test`` () =
      Assert.AreEqual (126, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] X64 linkageTableEntries length test`` () =
      Assert.AreEqual (110, file.GetLinkageTableEntries () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] X64 text section address test`` () =
      Assert.AreEqual (0x4027C0UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[ELF] X64 isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit64, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[ELF] X64 function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x004020E0UL "__ctype_toupper_loc"

    [<TestMethod>]
    member __.``[ELF] X64 function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x004027A0UL "__sprintf_chk"

    [<TestMethod>]
    member __.``[ELF] X64 Reloc section Dyn test (1)`` () =
      assertExistenceOfRelocation file 0x0061Eff8UL "__gmon_start__"

    [<TestMethod>]
    member __.``[ELF] X64 Reloc section Dyn test (2)`` () =
      assertExistenceOfRelocation file 0x0061F620UL "stderr"

    [<TestMethod>]
    member __.``[ELF] X64 Reloc section PLT test (1)`` () =
      assertExistenceOfRelocation file 0x0061F018UL "__ctype_toupper_loc"

    [<TestMethod>]
    member __.``[ELF] X64 Reloc section PLT test (2)`` () =
      assertExistenceOfRelocation file 0x0061F378UL "__sprintf_chk"

    [<TestMethod>]
    member __.``[ELF] X64 section header test (1)`` () =
      assertExistenceOfSectionHeader file 0 ""

    [<TestMethod>]
    member __.``[ELF] X64 section header test (2)`` () =
      assertExistenceOfSectionHeader file 37 ".strtab"

  [<TestClass>]
  type X64StrippedTestClass () =
    static let file = parseFile x64StrippedFileName

    [<TestMethod>]
    member __.``[ELF] X64_Stripped EntryPoint test`` () =
      Assert.AreEqual (Some 0x404050UL, file.EntryPoint)

    [<TestMethod>]
    member __.``[ELF] X64_Stripped file type test`` () =
      Assert.AreEqual (FileType.ExecutableFile, file.Type)

    [<TestMethod>]
    member __.``[ELF] X64_Stripped IsStripped test`` () =
      Assert.AreEqual (true, file.IsStripped)

    [<TestMethod>]
    member __.``[ELF] X64_Stripped IsNXEnabled test`` () =
      Assert.AreEqual (true, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[ELF] X64_Stripped sections length test`` () =
      Assert.AreEqual (29, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] X64_Stripped static symbols length test`` () =
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] X64_Stripped dynamic symbols length test`` () =
      Assert.AreEqual (126, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] X64_Stripped linkageTableEntries length test`` () =
      Assert.AreEqual (110, file.GetLinkageTableEntries () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] X64_Stripped text section address test`` () =
      Assert.AreEqual (0x4027C0UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[ELF] X64_Stripped isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit64, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[ELF] X64_Stripped function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x004020E0UL "__ctype_toupper_loc"

    [<TestMethod>]
    member __.``[ELF] X64_Stripped function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x004027A0UL "__sprintf_chk"

    [<TestMethod>]
    member __.``[ELF] X64_Stripped Reloc section Dyn test (1)`` () =
      assertExistenceOfRelocation file 0x0061EFF8UL "__gmon_start__"

    [<TestMethod>]
    member __.``[ELF] X64_Stripped Reloc section Dyn test (2)`` () =
      assertExistenceOfRelocation file 0x0061F620UL "stderr"

    [<TestMethod>]
    member __.``[ELF] X64_Stripped Reloc section PLT test (1)`` () =
      assertExistenceOfRelocation file 0x0061F018UL "__ctype_toupper_loc"

    [<TestMethod>]
    member __.``[ELF] X64_Stripped Reloc section PLT test (2)`` () =
      assertExistenceOfRelocation file 0x0061F378UL "__sprintf_chk"

    [<TestMethod>]
    member __.``[ELF] X64_Stripped section header test (1)`` () =
      assertExistenceOfSectionHeader file 0 ""

    [<TestMethod>]
    member __.``[ELF] X64_Stripped section header test (2)`` () =
      assertExistenceOfSectionHeader file 28 ".shstrtab"

  [<TestClass>]
  type ARM32TestClass () =
    static let file = parseFile arm32FileName

    [<TestMethod>]
    member __.``[ELF] arm32 EntryPoint test`` () =
      Assert.AreEqual (Some 0x00013D0CUL, file.EntryPoint)

    [<TestMethod>]
    member __.``[ELF] arm32 file type test`` () =
      Assert.AreEqual (FileType.ExecutableFile, file.Type)

    [<TestMethod>]
    member __.``[ELF] arm32 IsStripped test`` () =
      Assert.AreEqual (false, file.IsStripped)

    [<TestMethod>]
    member __.``[ELF] arm32 IsNXEnabled test`` () =
      Assert.AreEqual (true, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[ELF] arm32 sections length test`` () =
      Assert.AreEqual (38, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] arm32 static symbols length test`` () =
      Assert.AreEqual (1299, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] arm32 dynamic symbols length test`` () =
      Assert.AreEqual (136, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] arm32 linkageTableEntries length test`` () =
      Assert.AreEqual (121, file.GetLinkageTableEntries () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] arm32 text section address test`` () =
      Assert.AreEqual (0x00011F98UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[ELF] arm32 isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[ELF] arm32 function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x000119ECUL "fdopen"

    [<TestMethod>]
    member __.``[ELF] arm32 function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x00011F8CUL "__assert_fail"

    [<TestMethod>]
    member __.``[ELF] arm32 Reloc section Dyn test (1)`` () =
      assertExistenceOfRelocation file 0x0003F1F0UL "__gmon_start__"

    [<TestMethod>]
    member __.``[ELF] arm32 Reloc section Dyn test (2)`` () =
      assertExistenceOfRelocation file 0x0003F35CUL "stdout"

    [<TestMethod>]
    member __.``[ELF] arm32 Reloc section PLT test (1)`` () =
      assertExistenceOfRelocation file 0x0003F00CUL "fdopen"

    [<TestMethod>]
    member __.``[ELF] arm32 Reloc section PLT test (2)`` () =
      assertExistenceOfRelocation file 0x0003F1eCUL "__assert_fail"

    [<TestMethod>]
    member __.``[ELF] arm32 section header test (1)`` () =
      assertExistenceOfSectionHeader file 0 ""

    [<TestMethod>]
    member __.``[ELF] arm32 section header test (2)`` () =
      assertExistenceOfSectionHeader file 37 ".strtab"

  [<TestClass>]
  type ARM32StrippedTestClass () =
    static let file = parseFile arm32StrippedFileName

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped EntryPoint test`` () =
      Assert.AreEqual (Some 0x00013D0CUL, file.EntryPoint)

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped file type test`` () =
      Assert.AreEqual (FileType.ExecutableFile, file.Type)

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped IsStripped test`` () =
      Assert.AreEqual (true, file.IsStripped)

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped IsNXEnabled test`` () =
      Assert.AreEqual (true, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped sections length test`` () =
      Assert.AreEqual (28, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped static symbols length test`` () =
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped dynamic symbols length test`` () =
      Assert.AreEqual (136, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped linkageTableEntries length test`` () =
      Assert.AreEqual (121, file.GetLinkageTableEntries () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped text section address test`` () =
      Assert.AreEqual (0x00011F98UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x000119ECUL "fdopen"

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x00011F8CUL "__assert_fail"

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped Reloc section Dyn test (1)`` () =
      assertExistenceOfRelocation file 0x0003F1F0UL "__gmon_start__"

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped Reloc section Dyn test (2)`` () =
      assertExistenceOfRelocation file 0x0003F35CUL "stdout"

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped Reloc section PLT test (1)`` () =
      assertExistenceOfRelocation file 0x0003F00CUL "fdopen"

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped Reloc section PLT test (2)`` () =
      assertExistenceOfRelocation file 0x0003F1ECUL "__assert_fail"

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped section header test (1)`` () =
      assertExistenceOfSectionHeader file 0 ""

    [<TestMethod>]
    member __.``[ELF] arm32_Stripped section header test (2)`` () =
      assertExistenceOfSectionHeader file 27 ".shstrtab"

  [<TestClass>]
  type ThumbTestClass () =
    static let file = parseFile thumbFileName

    [<TestMethod>]
    member __.``[ELF] thumb EntryPoint test`` () =
      Assert.AreEqual (Some 0x00013605UL, file.EntryPoint)

    [<TestMethod>]
    member __.``[ELF] thumb file type test`` () =
      Assert.AreEqual (FileType.ExecutableFile, file.Type)

    [<TestMethod>]
    member __.``[ELF] thumb IsStripped test`` () =
      Assert.AreEqual (false, file.IsStripped)

    [<TestMethod>]
    member __.``[ELF] thumb IsNXEnabled test`` () =
      Assert.AreEqual (true, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[ELF] thumb sections length test`` () =
      Assert.AreEqual (38, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] thumb static symbols length test`` () =
      Assert.AreEqual (1088, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] thumb dynamic symbols length test`` () =
      Assert.AreEqual (136, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] thumb linkageTableEntries length test`` () =
      Assert.AreEqual (121, file.GetLinkageTableEntries () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] thumb text section address test`` () =
      Assert.AreEqual (0x00011FE0UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[ELF] thumb isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[ELF] thumb function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x000119FCUL "fdopen"

    [<TestMethod>]
    member __.``[ELF] thumb function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x00011FD0UL "__assert_fail"

    [<TestMethod>]
    member __.``[ELF] thumb Reloc section Dyn test (1)`` () =
      assertExistenceOfRelocation file 0x000371F0UL "__gmon_start__"

    [<TestMethod>]
    member __.``[ELF] thumb Reloc section Dyn test (2)`` () =
      assertExistenceOfRelocation file 0x0003735CUL "stdout"

    [<TestMethod>]
    member __.``[ELF] thumb Reloc section PLT test (1)`` () =
      assertExistenceOfRelocation file 0x0003700CUL "fdopen"

    [<TestMethod>]
    member __.``[ELF] thumb Reloc section PLT test (2)`` () =
      assertExistenceOfRelocation file 0x000371ECUL "__assert_fail"

    [<TestMethod>]
    member __.``[ELF] thumb section header test (1)`` () =
      assertExistenceOfSectionHeader file 0 ""

    [<TestMethod>]
    member __.``[ELF] thumb section header test (2)`` () =
      assertExistenceOfSectionHeader file 37 ".strtab"

  [<TestClass>]
  type ThumbStrippedTestClass () =
    static let file = parseFile thumbStrippedFileName

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped EntryPoint test`` () =
      Assert.AreEqual (Some 0x00013605UL, file.EntryPoint)

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped file type test`` () =
      Assert.AreEqual (FileType.ExecutableFile, file.Type)

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped IsStripped test`` () =
      Assert.AreEqual (true, file.IsStripped)

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped IsNXEnabled test`` () =
      Assert.AreEqual (true, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped sections length test`` () =
      Assert.AreEqual (28, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped static symbols length test`` () =
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped dynamic symbols length test`` () =
      Assert.AreEqual (136, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped linkageTableEntries length test`` () =
      Assert.AreEqual (121, file.GetLinkageTableEntries () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped text section address test`` () =
      Assert.AreEqual (0x00011FE0UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x000119FCUL "fdopen"

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x00011FD0UL "__assert_fail"

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped Reloc section Dyn test (1)`` () =
      assertExistenceOfRelocation file 0x000371F0UL "__gmon_start__"

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped Reloc section Dyn test (2)`` () =
      assertExistenceOfRelocation file 0x0003735CUL "stdout"

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped Reloc section PLT test (1)`` () =
      assertExistenceOfRelocation file 0x0003700CUL "fdopen"

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped Reloc section PLT test (2)`` () =
      assertExistenceOfRelocation file 0x000371ECUL "__assert_fail"

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped section header test (1)`` () =
      assertExistenceOfSectionHeader file 0 ""

    [<TestMethod>]
    member __.``[ELF] thumb_Stripped section header test (2)`` () =
      assertExistenceOfSectionHeader file 27 ".shstrtab"

  [<TestClass>]
  type AArch64TestClass () =
    static let file = parseFile aarch64FileName

    [<TestMethod>]
    member __.``[ELF] aarch64 EntryPoint test`` () =
      Assert.AreEqual (Some 0x00404788UL, file.EntryPoint)

    [<TestMethod>]
    member __.``[ELF] aarch64 file type test`` () =
      Assert.AreEqual (FileType.ExecutableFile, file.Type)

    [<TestMethod>]
    member __.``[ELF] aarch64 IsStripped test`` () =
      Assert.AreEqual (false, file.IsStripped)

    [<TestMethod>]
    member __.``[ELF] aarch64 IsNXEnabled test`` () =
      Assert.AreEqual (true, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[ELF] aarch64 sections length test`` () =
      Assert.AreEqual (37, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] aarch64 static symbols length test`` () =
      Assert.AreEqual (935, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] aarch64 dynamic symbols length test`` () =
      Assert.AreEqual (136, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] aarch64 linkageTableEntries length test`` () =
      Assert.AreEqual (121, file.GetLinkageTableEntries () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] aarch64 text section address test`` () =
      Assert.AreEqual (0x00402E60UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[ELF] aarch64 isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit64, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[ELF] aarch64 function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x004026D0UL "mbrtowc"

    [<TestMethod>]
    member __.``[ELF] aarch64 function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x00402E50UL "__fxstatat"

    [<TestMethod>]
    member __.``[ELF] aarch64 Reloc section Dyn test (1)`` () =
      assertExistenceOfRelocation file 0x0042FFD8UL "__gmon_start__"

    [<TestMethod>]
    member __.``[ELF] aarch64 Reloc section Dyn test (2)`` () =
      assertExistenceOfRelocation file 0x00430630UL "__progname"

    [<TestMethod>]
    member __.``[ELF] aarch64 Reloc section PLT test (1)`` () =
      assertExistenceOfRelocation file 0x00430000UL "mbrtowc"

    [<TestMethod>]
    member __.``[ELF] aarch64 Reloc section PLT test (2)`` () =
      assertExistenceOfRelocation file 0x004303C0UL "__fxstatat"

    [<TestMethod>]
    member __.``[ELF] aarch64 section header test (1)`` () =
      assertExistenceOfSectionHeader file 0 ""

    [<TestMethod>]
    member __.``[ELF] aarch64 section header test (2)`` () =
      assertExistenceOfSectionHeader file 36 ".strtab"

  [<TestClass>]
  type AArch64StrippedTestClass () =
    static let file = parseFile aarch64StrippedFileName

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped EntryPoint test`` () =
      Assert.AreEqual (Some 0x00404788UL, file.EntryPoint)

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped file type test`` () =
      Assert.AreEqual (FileType.ExecutableFile, file.Type)

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped IsStripped test`` () =
      Assert.AreEqual (true, file.IsStripped)

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped IsNXEnabled test`` () =
      Assert.AreEqual (true, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped sections length test`` () =
      Assert.AreEqual (27, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped static symbols length test`` () =
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped dynamic symbols length test`` () =
      Assert.AreEqual (136, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped linkageTableEntries length test`` () =
      Assert.AreEqual (121, file.GetLinkageTableEntries () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped text section address test`` () =
      Assert.AreEqual (0x00402E60UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit64, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x004026D0UL "mbrtowc"

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x00402E50UL "__fxstatat"

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped Reloc section Dyn test (1)`` () =
      assertExistenceOfRelocation file 0x0042FFD8UL "__gmon_start__"

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped Reloc section Dyn test (2)`` () =
      assertExistenceOfRelocation file 0x00430630UL "__progname"

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped Reloc section PLT test (1)`` () =
      assertExistenceOfRelocation file 0x00430000UL "mbrtowc"

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped Reloc section PLT test (2)`` () =
      assertExistenceOfRelocation file 0x004303C0UL "__fxstatat"

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped section header test (1)`` () =
      assertExistenceOfSectionHeader file 0 ""

    [<TestMethod>]
    member __.``[ELF] aarch64_Stripped section header test (2)`` () =
      assertExistenceOfSectionHeader file 26 ".shstrtab"

  [<TestClass>]
  type MIPS32StrippedTestClass () =
    static let file = parseFile mips32StrippedFileName

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped EntryPoint test`` () =
      Assert.AreEqual (Some 0x00004C80UL, file.EntryPoint)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped file type test`` () =
      Assert.AreEqual (FileType.LibFile, file.Type)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped IsStripped test`` () =
      Assert.AreEqual (true, file.IsStripped)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped IsNXEnabled test`` () =
      Assert.AreEqual (false, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped sections length test`` () =
      Assert.AreEqual (34, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped static symbols length test`` () =
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped dynamic symbols length test`` () =
      Assert.AreEqual (232, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped linkageTableEntries length test`` () =
      Assert.AreEqual (106, file.GetLinkageTableEntries () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped text section address test`` () =
      Assert.AreEqual (0x00002C50UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x0001C280UL "strcmp"

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x0001C240UL "getpwnam"

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped Reloc section Dyn test (1)`` () =
      assertExistenceOfRelocation file 0x00032B28UL ""

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped Reloc section Dyn test (2)`` () =
      assertExistenceOfRelocation file 0x00033588UL ""

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped section header test (1)`` () =
      assertExistenceOfSectionHeader file 0 ""

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped section header test (2)`` () =
      assertExistenceOfSectionHeader file 33 ".shstrtab"

  [<TestClass>]
  type MIPS32StrippedLETestClass () =
    static let file = parseFile mips32LEStrippedFileName

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped_le EntryPoint test`` () =
      Assert.AreEqual (Some 0x00004C80UL, file.EntryPoint)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped_le file type test`` () =
      Assert.AreEqual (FileType.LibFile, file.Type)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped_le IsStripped test`` () =
      Assert.AreEqual (true, file.IsStripped)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped_le IsNXEnabled test`` () =
      Assert.AreEqual (false, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped_le sections length test`` () =
      Assert.AreEqual (34, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped_le static symbols length test`` () =
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped_le dynamic symbols length test`` () =
      Assert.AreEqual (232, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped_le linkageTableEntries length test`` () =
      Assert.AreEqual (106, file.GetLinkageTableEntries () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped_le text section address test`` () =
      Assert.AreEqual (0x00002C50UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped_le isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped_le function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x0001C280UL "__snprintf_chk"

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped_le function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x0001C240UL "unsetenv"

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped_le Reloc section Dyn test (1)`` () =
      assertExistenceOfRelocation file 0x00032B28UL ""

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped_le Reloc section Dyn test (2)`` () =
      assertExistenceOfRelocation file 0x00033588UL ""

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped_le section header test (1)`` () =
      assertExistenceOfSectionHeader file 0 ""

    [<TestMethod>]
    member __.``[ELF] mips32_Stripped_le section header test (2)`` () =
      assertExistenceOfSectionHeader file 33 ".shstrtab"

  [<TestClass>]
  type MIPS64StrippedTestClass () =
    static let file = parseFile mips64StrippedFileName

    [<TestMethod>]
    member __.``[ELF] mips64_Stripped EntryPoint test`` () =
      Assert.AreEqual (file.EntryPoint, Some 0x0000ADE0UL)

    [<TestMethod>]
    member __.``[ELF] mips64_Stripped file type test`` () =
      Assert.AreEqual (FileType.LibFile, file.Type)

    [<TestMethod>]
    member __.``[ELF] mips64_Stripped IsStripped test`` () =
      Assert.AreEqual (true, file.IsStripped)

    [<TestMethod>]
    member __.``[ELF] mips64_Stripped IsNXEnabled test`` () =
      Assert.AreEqual (false, file.IsNXEnabled)

    [<TestMethod>]
    member __.``[ELF] mips64_Stripped sections length test`` () =
      Assert.AreEqual (32, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] mips64_Stripped static symbols length test`` () =
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] mips64_Stripped dynamic symbols length test`` () =
      Assert.AreEqual (232, file.GetDynamicSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] mips64_Stripped linkageTableEntries length test`` () =
      Assert.AreEqual (106, file.GetLinkageTableEntries () |> Seq.length)

    [<TestMethod>]
    member __.``[ELF] mips64_Stripped text section address test`` () =
      Assert.AreEqual (0x00008F90UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[ELF] mips64_Stripped isa wordSize test`` () =
      Assert.AreEqual (WordSize.Bit64, file.ISA.WordSize)

    [<TestMethod>]
    member __.``[ELF] mips64_Stripped function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x00022380UL "strcmp"

    [<TestMethod>]
    member __.``[ELF] mips64_Stripped function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x00022320UL "unsetenv"

    [<TestMethod>]
    member __.``[ELF] mips64_Stripped Reloc section Dyn test (1)`` () =
      assertExistenceOfRelocation file 0x00039650UL ""

    [<TestMethod>]
    member __.``[ELF] mips64_Stripped Reloc section Dyn test (2)`` () =
      assertExistenceOfRelocation file 0x0003AA50UL ""

    [<TestMethod>]
    member __.``[ELF] mips64_Stripped section header test (1)`` () =
      assertExistenceOfSectionHeader file 0 ""

    [<TestMethod>]
    member __.``[ELF] mips64_Stripped section header test (2)`` () =
      assertExistenceOfSectionHeader file 31 ".shstrtab"

module Wasm =
  let wasmBasicFileName = "wasm_basic"

  let parseFile fileName =
    let zipFile = fileName + ".zip"
    let fileNameInZip = fileName + ".wasm"
    let bytes = readBytesFromZipFile WasmBinary zipFile fileNameInZip
    WasmBinFile ("", bytes) :> IBinFile

  [<TestClass>]
  type TestClass () =
    static let file = parseFile wasmBasicFileName

    [<TestMethod>]
    member __.``[Wasm] EntryPoint test`` () =
      Assert.AreEqual (Some 0x15AUL, file.EntryPoint)

    [<TestMethod>]
    member __.``[Wasm] file type test`` () =
      Assert.AreEqual (FileType.ExecutableFile, file.Type)

    [<TestMethod>]
    member __.``[Wasm] IsStripped test`` () =
      Assert.IsFalse (file.IsStripped)

    [<TestMethod>]
    member __.``[Wasm] text section address test`` () =
      Assert.AreEqual (0x154UL, getTextSectionAddr file)

    [<TestMethod>]
    member __.``[Wasm] symbols length test`` () =
      Assert.AreEqual (9, file.GetSymbols () |> Seq.length)

    [<TestMethod>]
    member __.``[Wasm] sections length test`` () =
      Assert.AreEqual (12, file.GetSections () |> Seq.length)

    [<TestMethod>]
    member __.``[Wasm] linkageTableEntries length test`` () =
      Assert.AreEqual (4, file.GetLinkageTableEntries () |> Seq.length)

    [<TestMethod>]
    member __.``[Wasm] function symbol test (1)`` () =
      assertFuncSymbolExistence file 0x0000007AUL "putc_js"

    [<TestMethod>]
    member __.``[Wasm] function symbol test (2)`` () =
      assertFuncSymbolExistence file 0x00000116UL "writev_c"

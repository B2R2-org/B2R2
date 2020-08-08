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
open B2R2.BinFile
open Microsoft.VisualStudio.TestTools.UnitTesting
open System.IO
open System.IO.Compression

exception TestFileNotFoundException

module ZIPReader =

  let baseDir = System.AppDomain.CurrentDomain.BaseDirectory
  let zipFileSrcDir = baseDir + "../../../"
  let getFileDir = function
    | FileFormat.PEBinary -> "PE/"
    | FileFormat.ELFBinary -> "ELF/"
    | FileFormat.MachBinary -> "Mach/"
    | FileFormat.WasmBinary -> "Wasm/"
    | _ -> failwith "Invalid file format"

  let readFileFromZipFile fmt zName fName =
    let zDir = zipFileSrcDir + getFileDir fmt
    let archive = ZipFile.Open(zDir + zName, ZipArchiveMode.Read)
    let entry = archive.GetEntry(fName)
    let stream = entry.Open ()
    use ms = new MemoryStream()
    stream.CopyTo(ms)
    ms.ToArray()

module PE =
  let x64FileName = "pe_x64"
  let x86FileName = "pe_x86"
  let x64PDBFileName = "pe_x64.pdb"
  let x86PDBFileName = "pe_x86.pdb"
  let x64StrippedFileName = "pe_x64_without_pdb"
  let x86StrippedFileName = "pe_x86_without_pdb"

  let parseFile fileName (pdbFileName: string) =
    let zip = fileName + ".zip"
    let file = fileName + ".exe"
    let bytes = ZIPReader.readFileFromZipFile FileFormat.PEBinary zip file
    let pdbBytes =
      if pdbFileName.Length = 0 then [||]
      else ZIPReader.readFileFromZipFile FileFormat.PEBinary zip pdbFileName
    new PEFileInfo (bytes, file, pdbBytes)

  let checkSymbol (fileInfo : PEFileInfo) addr symName =
    let found, n = fileInfo.TryFindFunctionSymbolName addr
    Assert.IsTrue (found)
    Assert.AreEqual(n, symName)

  [<TestClass>]
  type TestClass () =

    [<TestMethod>]
    member __.``[BinFile] PE File Parse Test (X86)`` () =
      let fi = parseFile x86FileName x86PDBFileName
      Assert.AreEqual (Some 0x0040140cUL, fi.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, fi.FileType)
      Assert.AreEqual (false, fi.IsStripped)
      Assert.AreEqual (true, fi.IsNXEnabled)
      Assert.AreEqual (5, fi.GetSections () |> Seq.length)
      Assert.AreEqual (239, fi.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (41, fi.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (0x00401000UL, fi.TextStartAddr)
      Assert.AreEqual (WordSize.Bit32, fi.WordSize)
      checkSymbol fi 0x00401090UL "_add"
      checkSymbol fi 0x004010d0UL "_mul"
      checkSymbol fi 0x004010e0UL "_main"

    [<TestMethod>]
    member __.``[BinFile] PE File Parse Test (X64)`` () =
      let fi = parseFile x64FileName x64PDBFileName
      Assert.AreEqual (Some 0x1400014b4UL, fi.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, fi.FileType)
      Assert.AreEqual (false, fi.IsStripped)
      Assert.AreEqual (true, fi.IsNXEnabled)
      Assert.AreEqual (6, fi.GetSections () |> Seq.length)
      Assert.AreEqual (240, fi.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (43, fi.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (0x140001000UL, fi.TextStartAddr)
      Assert.AreEqual (WordSize.Bit64, fi.WordSize)
      checkSymbol fi 0x1400010e0UL "add"
      checkSymbol fi 0x140001110UL "mul"
      checkSymbol fi 0x140001130UL "main"

module Mach =
  let parseFile fileName arch =
    let zip = fileName + ".zip"
    let bytes = ZIPReader.readFileFromZipFile FileFormat.MachBinary zip fileName
    let isa = ISA.Init arch Endian.Little
    new MachFileInfo (bytes, fileName, isa)

  let checkSymbol (fileInfo : MachFileInfo) addr symName =
    let found, n = fileInfo.TryFindFunctionSymbolName addr
    Assert.IsTrue (found)
    Assert.AreEqual(symName, n)

  [<TestClass>]
  type TestClass () =

    [<TestMethod>]
    member __.``[BinFile] Mach File Parse Test (X86_Stripped)`` () =
      let fi = parseFile "mach_x86_rm_stripped" Architecture.IntelX86
      Assert.AreEqual (Some 0x00002050UL, fi.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, fi.FileType)
      Assert.AreEqual (true, fi.IsStripped)
      Assert.AreEqual (true, fi.IsNXEnabled)
      Assert.AreEqual (9, fi.GetSections () |> Seq.length)
      Assert.AreEqual (0, fi.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (59, fi.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (45, fi.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x00002050UL, fi.TextStartAddr)
      Assert.AreEqual (WordSize.Bit32, fi.WordSize)
      checkSymbol fi 0x00003b28UL "___error"
      checkSymbol fi 0x00003b70UL "_fflush"

    [<TestMethod>]
    member __.``[BinFile] Mach File Parse Test (X64)`` () =
      let fi = parseFile "mach_x64_wc" Architecture.IntelX64
      Assert.AreEqual (Some 0x100000E90UL, fi.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, fi.FileType)
      Assert.AreEqual (false, fi.IsStripped)
      Assert.AreEqual (true, fi.IsNXEnabled)
      Assert.AreEqual (13, fi.GetSections () |> Seq.length)
      Assert.AreEqual (885, fi.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (190, fi.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (72, fi.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x100000D30UL, fi.TextStartAddr)
      Assert.AreEqual (WordSize.Bit64, fi.WordSize)
      checkSymbol fi 0x100000D30UL "_usage"
      checkSymbol fi 0x100005F90UL "_error"

    [<TestMethod>]
    member __.``[BinFile] Mach File Parse Test (X64_Stripped)`` () =
      let fi = parseFile "mach_x64_wc_stripped" Architecture.IntelX64
      Assert.AreEqual (Some 0x100000E90UL, fi.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, fi.FileType)
      Assert.AreEqual (true, fi.IsStripped)
      Assert.AreEqual (true, fi.IsNXEnabled)
      Assert.AreEqual (13, fi.GetSections () |> Seq.length)
      Assert.AreEqual (0, fi.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (190, fi.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (72, fi.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x100000D30UL, fi.TextStartAddr)
      Assert.AreEqual (WordSize.Bit64, fi.WordSize)
      checkSymbol fi 0x10000B076UL "___error"
      checkSymbol fi 0x10000B0D0UL "_fflush"

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
    let zip = fileName + ".zip"
    let bytes = ZIPReader.readFileFromZipFile FileFormat.ELFBinary zip fileName
    new ELFFileInfo (bytes, fileName)

  let checkSymbol (fileInfo : ELFFileInfo) addr symName =
    let found, n = fileInfo.TryFindFunctionSymbolName addr
    Assert.IsTrue (found)
    Assert.AreEqual(n, symName)

  [<TestClass>]
  type TestClass () =

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (X86)`` () =
      let fi = parseFile x86FileName
      Assert.AreEqual (Some 0x8049CD0UL, fi.EntryPoint)
      Assert.AreEqual (fi.FileType, FileType.ExecutableFile)
      Assert.AreEqual (fi.IsStripped, false)
      Assert.AreEqual (fi.IsNXEnabled, true)
      Assert.AreEqual (fi.GetSections () |> Seq.length, 31)
      Assert.AreEqual (fi.GetStaticSymbols () |> Seq.length, 793)
      Assert.AreEqual (fi.GetDynamicSymbols () |> Seq.length, 131)
      Assert.AreEqual (fi.GetLinkageTableEntries () |> Seq.length, 113)
      Assert.AreEqual (fi.TextStartAddr, 0x8049CD0UL)
      Assert.AreEqual (fi.WordSize, WordSize.Bit32)
      checkSymbol fi 0x080495b0UL "unsetenv"
      checkSymbol fi 0x08049cb0UL "putchar_unlocked"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (X86_Stripped)`` () =
      let fi = parseFile x86StrippedFileName
      Assert.AreEqual (Some 0x8049CD0UL, fi.EntryPoint)
      Assert.AreEqual (fi.FileType, FileType.ExecutableFile)
      Assert.AreEqual (fi.IsStripped, true)
      Assert.AreEqual (fi.IsNXEnabled, true)
      Assert.AreEqual (fi.GetSections () |> Seq.length, 29)
      Assert.AreEqual (fi.GetStaticSymbols () |> Seq.length, 0)
      Assert.AreEqual (fi.GetDynamicSymbols () |> Seq.length, 131)
      Assert.AreEqual (fi.GetLinkageTableEntries () |> Seq.length, 113)
      Assert.AreEqual (fi.TextStartAddr, 0x8049CD0UL)
      Assert.AreEqual (fi.WordSize, WordSize.Bit32)
      checkSymbol fi 0x080495b0UL "unsetenv"
      checkSymbol fi 0x08049cb0UL "putchar_unlocked"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (X64)`` () =
      let fi = parseFile x64FileName
      Assert.AreEqual (Some 0x404050UL, fi.EntryPoint)
      Assert.AreEqual (fi.FileType, FileType.ExecutableFile)
      Assert.AreEqual (fi.IsStripped, false)
      Assert.AreEqual (fi.IsNXEnabled, true)
      Assert.AreEqual (fi.GetSections () |> Seq.length, 38)
      Assert.AreEqual (fi.GetStaticSymbols () |> Seq.length, 635)
      Assert.AreEqual (fi.GetDynamicSymbols () |> Seq.length, 126)
      Assert.AreEqual (fi.GetLinkageTableEntries () |> Seq.length, 109)
      Assert.AreEqual (fi.TextStartAddr, 0x4027C0UL)
      Assert.AreEqual (fi.WordSize, WordSize.Bit64)
      checkSymbol fi 0x004020e0UL "__ctype_toupper_loc"
      checkSymbol fi 0x004027a0UL "__sprintf_chk"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (X64_Stripped)`` () =
      let fi = parseFile x64StrippedFileName
      Assert.AreEqual (Some 0x404050UL, fi.EntryPoint)
      Assert.AreEqual (fi.FileType, FileType.ExecutableFile)
      Assert.AreEqual (fi.IsStripped, true)
      Assert.AreEqual (fi.IsNXEnabled, true)
      Assert.AreEqual (fi.GetSections () |> Seq.length, 29)
      Assert.AreEqual (fi.GetStaticSymbols () |> Seq.length, 0)
      Assert.AreEqual (fi.GetDynamicSymbols () |> Seq.length, 126)
      Assert.AreEqual (fi.GetLinkageTableEntries () |> Seq.length, 109)
      Assert.AreEqual (fi.TextStartAddr, 0x4027C0UL)
      Assert.AreEqual (fi.WordSize, WordSize.Bit64)
      checkSymbol fi 0x004020e0UL "__ctype_toupper_loc"
      checkSymbol fi 0x004027a0UL "__sprintf_chk"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (arm32)`` () =
      let fi = parseFile arm32FileName
      Assert.AreEqual (Some 0x00013d0cUL, fi.EntryPoint)
      Assert.AreEqual (fi.FileType, FileType.ExecutableFile)
      Assert.AreEqual (fi.IsStripped, false)
      Assert.AreEqual (fi.IsNXEnabled, true)
      Assert.AreEqual (fi.GetSections () |> Seq.length, 38)
      Assert.AreEqual (fi.GetStaticSymbols () |> Seq.length, 1299)
      Assert.AreEqual (fi.GetDynamicSymbols () |> Seq.length, 136)
      Assert.AreEqual (fi.GetLinkageTableEntries () |> Seq.length, 121)
      Assert.AreEqual (fi.TextStartAddr, 0x00011f98UL)
      Assert.AreEqual (fi.WordSize, WordSize.Bit32)
      checkSymbol fi 0x000119ecUL "fdopen"
      checkSymbol fi 0x00011f8cUL "__assert_fail"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (arm32_Stripped)`` () =
      let fi = parseFile arm32StrippedFileName
      Assert.AreEqual (Some 0x00013d0cUL, fi.EntryPoint)
      Assert.AreEqual (fi.FileType, FileType.ExecutableFile)
      Assert.AreEqual (fi.IsStripped, true)
      Assert.AreEqual (fi.IsNXEnabled, true)
      Assert.AreEqual (fi.GetSections () |> Seq.length, 28)
      Assert.AreEqual (fi.GetStaticSymbols () |> Seq.length, 0)
      Assert.AreEqual (fi.GetDynamicSymbols () |> Seq.length, 136)
      Assert.AreEqual (fi.GetLinkageTableEntries () |> Seq.length, 121)
      Assert.AreEqual (fi.TextStartAddr, 0x00011f98UL)
      Assert.AreEqual (fi.WordSize, WordSize.Bit32)
      checkSymbol fi 0x000119ecUL "fdopen"
      checkSymbol fi 0x00011f8cUL "__assert_fail"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (thumb)`` () =
      let fi = parseFile thumbFileName
      Assert.AreEqual (Some 0x00013605UL, fi.EntryPoint)
      Assert.AreEqual (fi.FileType, FileType.ExecutableFile)
      Assert.AreEqual (fi.IsStripped, false)
      Assert.AreEqual (fi.IsNXEnabled, true)
      Assert.AreEqual (fi.GetSections () |> Seq.length, 38)
      Assert.AreEqual (fi.GetStaticSymbols () |> Seq.length, 1088)
      Assert.AreEqual (fi.GetDynamicSymbols () |> Seq.length, 136)
      Assert.AreEqual (fi.GetLinkageTableEntries () |> Seq.length, 121)
      Assert.AreEqual (fi.TextStartAddr, 0x00011fe0UL)
      Assert.AreEqual (fi.WordSize, WordSize.Bit32)
      checkSymbol fi 0x000119fcUL "fdopen"
      checkSymbol fi 0x00011fd0UL "__assert_fail"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (thumb_Stripped)`` () =
      let fi = parseFile thumbStrippedFileName
      Assert.AreEqual (Some 0x00013605UL, fi.EntryPoint)
      Assert.AreEqual (fi.FileType, FileType.ExecutableFile)
      Assert.AreEqual (fi.IsStripped, true)
      Assert.AreEqual (fi.IsNXEnabled, true)
      Assert.AreEqual (fi.GetSections () |> Seq.length, 28)
      Assert.AreEqual (fi.GetStaticSymbols () |> Seq.length, 0)
      Assert.AreEqual (fi.GetDynamicSymbols () |> Seq.length, 136)
      Assert.AreEqual (fi.GetLinkageTableEntries () |> Seq.length, 121)
      Assert.AreEqual (fi.TextStartAddr, 0x00011fe0UL)
      Assert.AreEqual (fi.WordSize, WordSize.Bit32)
      checkSymbol fi 0x000119fcUL "fdopen"
      checkSymbol fi 0x00011fd0UL "__assert_fail"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (aarch64)`` () =
      let fi = parseFile aarch64FileName
      Assert.AreEqual (Some 0x00404788UL, fi.EntryPoint)
      Assert.AreEqual (fi.FileType, FileType.ExecutableFile)
      Assert.AreEqual (fi.IsStripped, false)
      Assert.AreEqual (fi.IsNXEnabled, true)
      Assert.AreEqual (fi.GetSections () |> Seq.length, 37)
      Assert.AreEqual (fi.GetStaticSymbols () |> Seq.length, 935)
      Assert.AreEqual (fi.GetDynamicSymbols () |> Seq.length, 136)
      Assert.AreEqual (fi.GetLinkageTableEntries () |> Seq.length, 121)
      Assert.AreEqual (fi.TextStartAddr, 0x00402e60UL)
      Assert.AreEqual (fi.WordSize, WordSize.Bit64)
      checkSymbol fi 0x004026d0UL "mbrtowc"
      checkSymbol fi 0x00402e50UL "__fxstatat"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (aarch64_Stripped)`` () =
      let fi = parseFile aarch64StrippedFileName
      Assert.AreEqual (Some 0x00404788UL, fi.EntryPoint)
      Assert.AreEqual (fi.FileType, FileType.ExecutableFile)
      Assert.AreEqual (fi.IsStripped, true)
      Assert.AreEqual (fi.IsNXEnabled, true)
      Assert.AreEqual (fi.GetSections () |> Seq.length, 27)
      Assert.AreEqual (fi.GetStaticSymbols () |> Seq.length, 0)
      Assert.AreEqual (fi.GetDynamicSymbols () |> Seq.length, 136)
      Assert.AreEqual (fi.GetLinkageTableEntries () |> Seq.length, 121)
      Assert.AreEqual (fi.TextStartAddr, 0x00402e60UL)
      Assert.AreEqual (fi.WordSize, WordSize.Bit64)
      checkSymbol fi 0x004026d0UL "mbrtowc"
      checkSymbol fi 0x00402e50UL "__fxstatat"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (mips32_Stripped)`` () =
      let fi = parseFile mips32StrippedFileName
      Assert.AreEqual (Some 0x00004c80UL, fi.EntryPoint)
      Assert.AreEqual (fi.FileType, FileType.LibFile)
      Assert.AreEqual (fi.IsStripped, true)
      Assert.AreEqual (fi.IsNXEnabled, false)
      Assert.AreEqual (fi.GetSections () |> Seq.length, 34)
      Assert.AreEqual (fi.GetStaticSymbols () |> Seq.length, 0)
      Assert.AreEqual (fi.GetDynamicSymbols () |> Seq.length, 232)
      Assert.AreEqual (fi.GetLinkageTableEntries () |> Seq.length, 0)
      Assert.AreEqual (fi.TextStartAddr, 0x00002c50UL)
      Assert.AreEqual (fi.WordSize, WordSize.Bit32)
      checkSymbol fi 0x0001c280UL "strcmp"
      checkSymbol fi 0x0001c240UL "getpwnam"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (mips32_Stripped_le)`` () =
      let fi = parseFile mips32LEStrippedFileName
      Assert.AreEqual (Some 0x00004c80UL, fi.EntryPoint)
      Assert.AreEqual (fi.FileType, FileType.LibFile)
      Assert.AreEqual (fi.IsStripped, true)
      Assert.AreEqual (fi.IsNXEnabled, false)
      Assert.AreEqual (fi.GetSections () |> Seq.length, 34)
      Assert.AreEqual (fi.GetStaticSymbols () |> Seq.length, 0)
      Assert.AreEqual (fi.GetDynamicSymbols () |> Seq.length, 232)
      Assert.AreEqual (fi.GetLinkageTableEntries () |> Seq.length, 0)
      Assert.AreEqual (fi.TextStartAddr, 0x00002c50UL)
      Assert.AreEqual (fi.WordSize, WordSize.Bit32)
      checkSymbol fi 0x0001c280UL "__snprintf_chk"
      checkSymbol fi 0x0001c240UL "unsetenv"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (mips64_Stripped)`` () =
      let fi = parseFile mips64StrippedFileName
      Assert.AreEqual (Some 0x0000ade0UL, fi.EntryPoint)
      Assert.AreEqual (fi.FileType, FileType.LibFile)
      Assert.AreEqual (fi.IsStripped, true)
      Assert.AreEqual (fi.IsNXEnabled, false)
      Assert.AreEqual (fi.GetSections () |> Seq.length, 32)
      Assert.AreEqual (fi.GetStaticSymbols () |> Seq.length, 0)
      Assert.AreEqual (fi.GetDynamicSymbols () |> Seq.length, 232)
      Assert.AreEqual (fi.GetLinkageTableEntries () |> Seq.length, 0)
      Assert.AreEqual (fi.TextStartAddr, 0x00008f90UL)
      Assert.AreEqual (fi.WordSize, WordSize.Bit64)
      checkSymbol fi 0x00022380UL "strcmp"
      checkSymbol fi 0x00022320UL "unsetenv"

module Wasm =
  let wasmBasicFileName = "wasm_basic"

  let parseFile fileName =
    let zip = fileName + ".zip"
    let file = fileName + ".wasm"
    let bytes =
      ZIPReader.readFileFromZipFile FileFormat.WasmBinary zip file
    new WasmFileInfo (bytes, "")

  [<TestClass>]
  type TestClass () =
    [<TestMethod>]
    member __.``[BinFile] Wasm Module Parse Test`` () =
      let fi = parseFile wasmBasicFileName
      Assert.AreEqual (FileType.ExecutableFile, fi.FileType)
      Assert.IsFalse (fi.IsStripped)
      Assert.AreEqual (Some 0x15AUL, fi.EntryPoint)
      Assert.AreEqual (0x154UL, fi.TextStartAddr)
      Assert.AreEqual (9, fi.GetSymbols () |> Seq.length)
      Assert.AreEqual (12, fi.GetSections () |> Seq.length)
      Assert.AreEqual (4, fi.GetLinkageTableEntries () |> Seq.length)
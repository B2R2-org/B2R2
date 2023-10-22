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
    let archive = ZipFile.Open (zDir + zName, ZipArchiveMode.Read)
    let entry = archive.GetEntry (fName)
    let stream = entry.Open ()
    use ms = new MemoryStream ()
    stream.CopyTo (ms)
    ms.ToArray ()

[<AutoOpen>]
module TestHelper =
  let checkSymbol (fileInfo: IBinFile) addr symName =
    match fileInfo.TryFindFunctionSymbolName addr with
    | Ok n -> Assert.AreEqual (n, symName)
    | Error _ -> Assert.Fail ()

  let getTextSectionAddr (fileInfo: IBinFile) =
    let sec = fileInfo.GetTextSection ()
    sec.Address

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
    PEBinFile (file, bytes, None, pdbBytes) :> IBinFile

  [<TestClass>]
  type TestClass () =

    [<TestMethod>]
    member __.``[BinFile] PE File Parse Test (X86)`` () =
      let file = parseFile x86FileName x86PDBFileName
      Assert.AreEqual (Some 0x0040140cUL, file.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, file.Type)
      Assert.AreEqual (false, file.IsStripped)
      Assert.AreEqual (true, file.IsNXEnabled)
      Assert.AreEqual (5, file.GetSections () |> Seq.length)
      Assert.AreEqual (239, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (41, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (0x00401000UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)
      checkSymbol file 0x00401090UL "_add"
      checkSymbol file 0x004010d0UL "_mul"
      checkSymbol file 0x004010e0UL "_main"

    [<TestMethod>]
    member __.``[BinFile] PE File Parse Test (X64)`` () =
      let file = parseFile x64FileName x64PDBFileName
      Assert.AreEqual (Some 0x1400014b4UL, file.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, file.Type)
      Assert.AreEqual (false, file.IsStripped)
      Assert.AreEqual (true, file.IsNXEnabled)
      Assert.AreEqual (6, file.GetSections () |> Seq.length)
      Assert.AreEqual (240, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (43, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (0x140001000UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit64, file.ISA.WordSize)
      checkSymbol file 0x1400010e0UL "add"
      checkSymbol file 0x140001110UL "mul"
      checkSymbol file 0x140001130UL "main"

module Mach =
  let parseFile fileName arch =
    let zip = fileName + ".zip"
    let bytes = ZIPReader.readFileFromZipFile FileFormat.MachBinary zip fileName
    let isa = ISA.Init arch Endian.Little
    MachBinFile (fileName, bytes, isa, None) :> IBinFile

  [<TestClass>]
  type TestClass () =

    [<TestMethod>]
    member __.``[BinFile] Mach File Parse Test (X86_Stripped)`` () =
      let file = parseFile "mach_x86_rm_stripped" Architecture.IntelX86
      Assert.AreEqual (Some 0x00002050UL, file.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, file.Type)
      Assert.AreEqual (true, file.IsStripped)
      Assert.AreEqual (true, file.IsNXEnabled)
      Assert.AreEqual (9, file.GetSections () |> Seq.length)
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (59, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (45, file.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x00002050UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)
      checkSymbol file 0x00003b28UL "___error"
      checkSymbol file 0x00003b70UL "_fflush"

    [<TestMethod>]
    member __.``[BinFile] Mach File Parse Test (X64)`` () =
      let file = parseFile "mach_x64_wc" Architecture.IntelX64
      Assert.AreEqual (Some 0x100000E90UL, file.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, file.Type)
      Assert.AreEqual (false, file.IsStripped)
      Assert.AreEqual (true, file.IsNXEnabled)
      Assert.AreEqual (13, file.GetSections () |> Seq.length)
      Assert.AreEqual (885, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (190, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (72, file.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x100000D30UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit64, file.ISA.WordSize)
      checkSymbol file 0x100000D30UL "_usage"
      checkSymbol file 0x100005F90UL "_error"

    [<TestMethod>]
    member __.``[BinFile] Mach File Parse Test (X64_Stripped)`` () =
      let file = parseFile "mach_x64_wc_stripped" Architecture.IntelX64
      Assert.AreEqual (Some 0x100000E90UL, file.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, file.Type)
      Assert.AreEqual (true, file.IsStripped)
      Assert.AreEqual (true, file.IsNXEnabled)
      Assert.AreEqual (13, file.GetSections () |> Seq.length)
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (190, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (72, file.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x100000D30UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit64, file.ISA.WordSize)
      checkSymbol file 0x10000B076UL "___error"
      checkSymbol file 0x10000B0D0UL "_fflush"

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
    ELFBinFile (fileName, bytes, None, None) :> IBinFile

  [<TestClass>]
  type TestClass () =

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (X86)`` () =
      let file = parseFile x86FileName
      Assert.AreEqual (Some 0x8049CD0UL, file.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, file.Type)
      Assert.AreEqual (false, file.IsStripped)
      Assert.AreEqual (true, file.IsNXEnabled)
      Assert.AreEqual (31, file.GetSections () |> Seq.length)
      Assert.AreEqual (793, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (131, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (114, file.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x8049CD0UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)
      checkSymbol file 0x080495b0UL "unsetenv"
      checkSymbol file 0x08049cb0UL "putchar_unlocked"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (X86_Stripped)`` () =
      let file = parseFile x86StrippedFileName
      Assert.AreEqual (Some 0x8049CD0UL, file.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, file.Type)
      Assert.AreEqual (true, file.IsStripped)
      Assert.AreEqual (true, file.IsNXEnabled)
      Assert.AreEqual (29, file.GetSections () |> Seq.length)
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (131, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (114, file.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x8049CD0UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)
      checkSymbol file 0x080495b0UL "unsetenv"
      checkSymbol file 0x08049cb0UL "putchar_unlocked"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (X64)`` () =
      let file = parseFile x64FileName
      Assert.AreEqual (Some 0x404050UL, file.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, file.Type)
      Assert.AreEqual (false, file.IsStripped)
      Assert.AreEqual (true, file.IsNXEnabled)
      Assert.AreEqual (38, file.GetSections () |> Seq.length)
      Assert.AreEqual (635, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (126, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (110, file.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x4027C0UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit64, file.ISA.WordSize)
      checkSymbol file 0x004020e0UL "__ctype_toupper_loc"
      checkSymbol file 0x004027a0UL "__sprintf_chk"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (X64_Stripped)`` () =
      let file = parseFile x64StrippedFileName
      Assert.AreEqual (Some 0x404050UL, file.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, file.Type)
      Assert.AreEqual (true, file.IsStripped)
      Assert.AreEqual (true, file.IsNXEnabled)
      Assert.AreEqual (29, file.GetSections () |> Seq.length)
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (126, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (110, file.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x4027C0UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit64, file.ISA.WordSize)
      checkSymbol file 0x004020e0UL "__ctype_toupper_loc"
      checkSymbol file 0x004027a0UL "__sprintf_chk"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (arm32)`` () =
      let file = parseFile arm32FileName
      Assert.AreEqual (Some 0x00013d0cUL, file.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, file.Type)
      Assert.AreEqual (false, file.IsStripped)
      Assert.AreEqual (true, file.IsNXEnabled)
      Assert.AreEqual (38, file.GetSections () |> Seq.length)
      Assert.AreEqual (1299, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (136, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (121, file.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x00011f98UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)
      checkSymbol file 0x000119ecUL "fdopen"
      checkSymbol file 0x00011f8cUL "__assert_fail"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (arm32_Stripped)`` () =
      let file = parseFile arm32StrippedFileName
      Assert.AreEqual (Some 0x00013d0cUL, file.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, file.Type)
      Assert.AreEqual (true, file.IsStripped)
      Assert.AreEqual (true, file.IsNXEnabled)
      Assert.AreEqual (28, file.GetSections () |> Seq.length)
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (136, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (121, file.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x00011f98UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)
      checkSymbol file 0x000119ecUL "fdopen"
      checkSymbol file 0x00011f8cUL "__assert_fail"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (thumb)`` () =
      let file = parseFile thumbFileName
      Assert.AreEqual (Some 0x00013605UL, file.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, file.Type)
      Assert.AreEqual (false, file.IsStripped)
      Assert.AreEqual (true, file.IsNXEnabled)
      Assert.AreEqual (38, file.GetSections () |> Seq.length)
      Assert.AreEqual (1088, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (136, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (121, file.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x00011fe0UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)
      checkSymbol file 0x000119fcUL "fdopen"
      checkSymbol file 0x00011fd0UL "__assert_fail"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (thumb_Stripped)`` () =
      let file = parseFile thumbStrippedFileName
      Assert.AreEqual (Some 0x00013605UL, file.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, file.Type)
      Assert.AreEqual (true, file.IsStripped)
      Assert.AreEqual (true, file.IsNXEnabled)
      Assert.AreEqual (28, file.GetSections () |> Seq.length)
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (136, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (121, file.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x00011fe0UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)
      checkSymbol file 0x000119fcUL "fdopen"
      checkSymbol file 0x00011fd0UL "__assert_fail"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (aarch64)`` () =
      let file = parseFile aarch64FileName
      Assert.AreEqual (Some 0x00404788UL, file.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, file.Type)
      Assert.AreEqual (false, file.IsStripped)
      Assert.AreEqual (true, file.IsNXEnabled)
      Assert.AreEqual (37, file.GetSections () |> Seq.length)
      Assert.AreEqual (935, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (136, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (121, file.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x00402e60UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit64, file.ISA.WordSize)
      checkSymbol file 0x004026d0UL "mbrtowc"
      checkSymbol file 0x00402e50UL "__fxstatat"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (aarch64_Stripped)`` () =
      let file = parseFile aarch64StrippedFileName
      Assert.AreEqual (Some 0x00404788UL, file.EntryPoint)
      Assert.AreEqual (FileType.ExecutableFile, file.Type)
      Assert.AreEqual (true, file.IsStripped)
      Assert.AreEqual (true, file.IsNXEnabled)
      Assert.AreEqual (27, file.GetSections () |> Seq.length)
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (136, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (121, file.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x00402e60UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit64, file.ISA.WordSize)
      checkSymbol file 0x004026d0UL "mbrtowc"
      checkSymbol file 0x00402e50UL "__fxstatat"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (mips32_Stripped)`` () =
      let file = parseFile mips32StrippedFileName
      Assert.AreEqual (Some 0x00004c80UL, file.EntryPoint)
      Assert.AreEqual (FileType.LibFile, file.Type)
      Assert.AreEqual (true, file.IsStripped)
      Assert.AreEqual (false, file.IsNXEnabled)
      Assert.AreEqual (34, file.GetSections () |> Seq.length)
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (232, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (106, file.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x00002c50UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)
      checkSymbol file 0x0001c280UL "strcmp"
      checkSymbol file 0x0001c240UL "getpwnam"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (mips32_Stripped_le)`` () =
      let file = parseFile mips32LEStrippedFileName
      Assert.AreEqual (Some 0x00004c80UL, file.EntryPoint)
      Assert.AreEqual (FileType.LibFile, file.Type)
      Assert.AreEqual (true, file.IsStripped)
      Assert.AreEqual (false, file.IsNXEnabled)
      Assert.AreEqual (34, file.GetSections () |> Seq.length)
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (232, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (106, file.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x00002c50UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit32, file.ISA.WordSize)
      checkSymbol file 0x0001c280UL "__snprintf_chk"
      checkSymbol file 0x0001c240UL "unsetenv"

    [<TestMethod>]
    member __.``[BinFile] ELF File Parse Test (mips64_Stripped)`` () =
      let file = parseFile mips64StrippedFileName
      Assert.AreEqual (file.EntryPoint, Some 0x0000ade0UL)
      Assert.AreEqual (FileType.LibFile, file.Type)
      Assert.AreEqual (true, file.IsStripped)
      Assert.AreEqual (false, file.IsNXEnabled)
      Assert.AreEqual (32, file.GetSections () |> Seq.length)
      Assert.AreEqual (0, file.GetStaticSymbols () |> Seq.length)
      Assert.AreEqual (232, file.GetDynamicSymbols () |> Seq.length)
      Assert.AreEqual (106, file.GetLinkageTableEntries () |> Seq.length)
      Assert.AreEqual (0x00008f90UL, getTextSectionAddr file)
      Assert.AreEqual (WordSize.Bit64, file.ISA.WordSize)
      checkSymbol file 0x00022380UL "strcmp"
      checkSymbol file 0x00022320UL "unsetenv"

module Wasm =
  let wasmBasicFileName = "wasm_basic"

  let parseFile fileName =
    let zip = fileName + ".zip"
    let file = fileName + ".wasm"
    let bytes =
      ZIPReader.readFileFromZipFile FileFormat.WasmBinary zip file
    WasmBinFile (bytes, "") :> IBinFile

  [<TestClass>]
  type TestClass () =
    [<TestMethod>]
    member __.``[BinFile] Wasm Module Parse Test`` () =
      let file = parseFile wasmBasicFileName
      Assert.AreEqual (FileType.ExecutableFile, file.Type)
      Assert.IsFalse (file.IsStripped)
      Assert.AreEqual (Some 0x15AUL, file.EntryPoint)
      Assert.AreEqual (0x154UL, getTextSectionAddr file)
      Assert.AreEqual (9, file.GetSymbols () |> Seq.length)
      Assert.AreEqual (12, file.GetSections () |> Seq.length)
      Assert.AreEqual (4, file.GetLinkageTableEntries () |> Seq.length)

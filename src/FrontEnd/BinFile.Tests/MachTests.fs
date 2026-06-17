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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Mach
open type FileFormat

[<TestClass>]
type MachTests() =
  static let isStripped (file: IBinFile) =
    file.SymbolTable.Value.IsStripped

  static let parseFile fileName arch wsz =
    let zipFile = fileName + ".zip"
    let bytes = ZIPReader.readBytes MachBinary zipFile fileName
    let isa = ISA(arch, Endian.Little, wsz)
    MachBinFile(fileName, bytes, isa, None, None)

  let assertExistenceOfFlag (file: IBinFile) flags =
    Assert.AreEqual
      (true, (file :?> MachBinFile).Header.Flags.ToString() = flags)

  let assertExistenceOfSectionHeader (file: IBinFile) address sectionName =
    (file :?> MachBinFile).Sections
    |> Seq.map (fun record -> record.SecAddr, record.SecName)
    |> assertExistenceOfPair (address, sectionName)

  static let x86File =
    parseFile "mach_x86_rm_stripped" Architecture.Intel WordSize.Bit32

  static let x64File = parseFile "mach_x64_wc" Architecture.Intel WordSize.Bit64

  static let x64SFile =
    parseFile "mach_x64_wc_stripped" Architecture.Intel WordSize.Bit64

  static let x64RelocFile =
    parseFile "mach_x64_reloc" Architecture.Intel WordSize.Bit64

  static let x64ChainedFile =
    parseFile "mach_x64_chained" Architecture.Intel WordSize.Bit64

  static let x64DyldInfoFile =
    parseFile "mach_x64_dyldinfo" Architecture.Intel WordSize.Bit64

  static let x64WeakBindFile =
    parseFile "mach_x64_weakbind" Architecture.Intel WordSize.Bit64

  static let x64TwoLevelFile =
    parseFile "mach_x64_twolevel" Architecture.Intel WordSize.Bit64

  static let arm64eChainedFile =
    parseFile "mach_arm64e_chained" Architecture.ARMv8 WordSize.Bit64

  /// A C++ binary with try/catch, so it carries DWARF CFI in __eh_frame and an
  /// LSDA table in __gcc_except_tab. Exception parsing needs a register
  /// factory.
  static let x64ExcFile =
    let bytes = ZIPReader.readBytes MachBinary "mach_x64_exc.zip" "mach_x64_exc"
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    let regFactory = FrontEnd.Intel.RegisterFactory isa :> IRegisterFactory
    MachBinFile("mach_x64_exc", bytes, isa, None, Some regFactory)

  /// An arm64 C++ binary built normally, so unwinding lives in Apple compact
  /// unwind (__unwind_info) rather than __eh_frame, with the LSDA still in
  /// __gcc_except_tab. Compact unwind needs no register factory.
  static let arm64ExcFile =
    parseFile "mach_arm64_exc" Architecture.ARMv8 WordSize.Bit64

  [<TestMethod>]
  member _.``[Mach] X86_Stripped EntryPoint test``() =
    Assert.AreEqual(Some 0x00002050UL, (x86File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped file type test``() =
    Assert.AreEqual(FileType.MH_EXECUTE, x86File.Header.FileType)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped IsStripped test``() =
    Assert.AreEqual(true, isStripped (x86File :> IBinFile))

  [<TestMethod>]
  member _.``[Mach] X86_Stripped IsNXEnabled test``() =
    Assert.AreEqual(true, (x86File :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped sections length test``() =
    Assert.AreEqual<int>(9, x86File.Sections.Length)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped static symbols length test``() =
    Assert.AreEqual<int>(0, x86File.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped dynamic symbols length test``() =
    Assert.AreEqual<int>(59, x86File.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[Mach] X64 ContainsRelocation test``() =
    let reloc = (x64RelocFile :> IBinFile).Relocations.Value
    Assert.AreEqual(true, reloc.ContainsRelocation 0x0UL)
    Assert.AreEqual(true, reloc.ContainsRelocation 0x8UL)
    Assert.AreEqual(true, reloc.ContainsRelocation 0x10UL)
    Assert.AreEqual(false, reloc.ContainsRelocation 0x4UL)

  [<TestMethod>]
  member _.``[Mach] X64 TryGetRelocatedAddr external symbol test``() =
    let reloc = (x64RelocFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x10UL, reloc.TryGetRelocatedAddr 0x0UL)
    Assert.AreEqual(Ok 0x38UL, reloc.TryGetRelocatedAddr 0x8UL)

  [<TestMethod>]
  member _.``[Mach] X64 TryGetRelocatedAddr section test``() =
    let reloc = (x64RelocFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x18UL, reloc.TryGetRelocatedAddr 0x10UL)

  [<TestMethod>]
  member _.``[Mach] X64 TryGetRelocatedAddr not found test``() =
    let reloc = (x64RelocFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Error ErrorCase.ItemNotFound,
                    reloc.TryGetRelocatedAddr 0x4UL)

  [<TestMethod>]
  member _.``[Mach] X64 chained fixups ContainsRelocation test``() =
    let reloc = (x64ChainedFile :> IBinFile).Relocations.Value
    Assert.AreEqual(true, reloc.ContainsRelocation 0x1000UL)
    Assert.AreEqual(true, reloc.ContainsRelocation 0x1010UL)
    Assert.AreEqual(false, reloc.ContainsRelocation 0x1008UL)

  [<TestMethod>]
  member _.``[Mach] X64 chained fixups rebase test``() =
    let reloc = (x64ChainedFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x1008UL, reloc.TryGetRelocatedAddr 0x1010UL)

  [<TestMethod>]
  member _.``[Mach] X64 chained fixups bind test``() =
    let reloc = (x64ChainedFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Error ErrorCase.ItemNotFound,
                    reloc.TryGetRelocatedAddr 0x1000UL)

  [<TestMethod>]
  member _.``[Mach] X64 chained fixups linkage entries test``() =
    let linkage = (x64ChainedFile :> IBinFile).ImportTable.Value
    let entries = linkage.Imports
    Assert.AreEqual<int>(1, entries.Length)
    Assert.AreEqual<string>("_ext_symbol", entries[0].Name)
    Assert.AreEqual(0x1000UL, entries[0].TableAddress)

  [<TestMethod>]
  member _.``[Mach] X64 chained fixups IsInImportTable test``() =
    let linkage = (x64ChainedFile :> IBinFile).ImportTable.Value
    Assert.AreEqual(true, linkage.IsInImportTable 0x1000UL)
    Assert.AreEqual(false, linkage.IsInImportTable 0x1010UL)

  [<TestMethod>]
  member _.``[Mach] X64 dyld info ContainsRelocation test``() =
    let reloc = (x64DyldInfoFile :> IBinFile).Relocations.Value
    Assert.AreEqual(true, reloc.ContainsRelocation 0x1000UL)
    Assert.AreEqual(true, reloc.ContainsRelocation 0x1010UL)
    Assert.AreEqual(false, reloc.ContainsRelocation 0x1008UL)

  [<TestMethod>]
  member _.``[Mach] X64 dyld info rebase test``() =
    let reloc = (x64DyldInfoFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x1008UL, reloc.TryGetRelocatedAddr 0x1010UL)

  [<TestMethod>]
  member _.``[Mach] X64 dyld info bind linkage test``() =
    let linkage = (x64DyldInfoFile :> IBinFile).ImportTable.Value
    let entries = linkage.Imports
    Assert.AreEqual<int>(1, entries.Length)
    Assert.AreEqual<string>("_ext_symbol", entries[0].Name)
    Assert.AreEqual(0x1000UL, entries[0].TableAddress)
    Assert.AreEqual(true, linkage.IsInImportTable 0x1000UL)

  [<TestMethod>]
  member _.``[Mach] X64 weak bind linkage test``() =
    let linkage = (x64WeakBindFile :> IBinFile).ImportTable.Value
    let entries = linkage.Imports
    Assert.AreEqual<int>(1, entries.Length)
    Assert.AreEqual<string>("_weak_sym", entries[0].Name)
    Assert.AreEqual(0x1008UL, entries[0].TableAddress)
    Assert.AreEqual(true, linkage.IsInImportTable 0x1008UL)

  [<TestMethod>]
  member _.``[Mach] X64 weak bind ContainsRelocation test``() =
    let reloc = (x64WeakBindFile :> IBinFile).Relocations.Value
    Assert.AreEqual(true, reloc.ContainsRelocation 0x1008UL)
    Assert.AreEqual(false, reloc.ContainsRelocation 0x1000UL)

  [<TestMethod>]
  member _.``[Mach] X64 two-level bind library name test``() =
    let linkage = (x64TwoLevelFile :> IBinFile).ImportTable.Value
    let entries = linkage.Imports
    Assert.AreEqual<int>(1, entries.Length)
    Assert.AreEqual<string>("_foo_data", entries[0].Name)
    Assert.AreEqual<string>("/usr/lib/libfoo.dylib", entries[0].LibraryName)
    Assert.AreEqual(0x1000UL, entries[0].TableAddress)

  [<TestMethod>]
  member _.``[Mach] arm64e chained fixups ContainsRelocation test``() =
    let reloc = (arm64eChainedFile :> IBinFile).Relocations.Value
    Assert.AreEqual(true, reloc.ContainsRelocation 0x4000UL)
    Assert.AreEqual(true, reloc.ContainsRelocation 0x4008UL)
    Assert.AreEqual(true, reloc.ContainsRelocation 0x4018UL)
    Assert.AreEqual(true, reloc.ContainsRelocation 0x4020UL)
    Assert.AreEqual(false, reloc.ContainsRelocation 0x4010UL)

  [<TestMethod>]
  member _.``[Mach] arm64e chained fixups rebase test``() =
    let reloc = (arm64eChainedFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x4010UL, reloc.TryGetRelocatedAddr 0x4018UL)
    Assert.AreEqual(Ok 0x370UL, reloc.TryGetRelocatedAddr 0x4020UL)

  [<TestMethod>]
  member _.``[Mach] arm64e chained fixups bind linkage test``() =
    let linkage = (arm64eChainedFile :> IBinFile).ImportTable.Value
    let entries = linkage.Imports
    Assert.AreEqual<int>(2, entries.Length)
    Assert.AreEqual<string>("_ext_func", entries[0].Name)
    Assert.AreEqual(0x4000UL, entries[0].TableAddress)
    Assert.AreEqual<string>("_ext_data", entries[1].Name)
    Assert.AreEqual(0x4008UL, entries[1].TableAddress)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped linkageTableEntries length test``() =
    let f = x86File :> IBinFile
    Assert.AreEqual<int>(45, (getLinkageTableEntries f).Length)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped text section address test``() =
    Assert.AreEqual<uint64>(0x00002050UL, getTextSectionAddr x86File)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped isa wordSize test``() =
    Assert.AreEqual(WordSize.Bit32, (x86File :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[Mach] X86_Stripped function symbol test (1)``() =
    assertFuncSymbolExistence x86File 0x00003b28UL "___error"

  [<TestMethod>]
  member _.``[Mach] X86_Stripped function symbol test (2)``() =
    assertFuncSymbolExistence x86File 0x00003b70UL "_fflush"

  [<TestMethod>]
  member _.``[Mach] X86_Stripped section header test (1)``() =
    assertExistenceOfSectionHeader x86File 8272UL "__text"

  [<TestMethod>]
  member _.``[Mach] X86_Stripped section header test (2)``() =
    assertExistenceOfSectionHeader x86File 16620UL "__common"

  [<TestMethod>]
  member _.``[Mach] X86_Stripped flags test``() =
    let flags =
      "MH_NOUNDEFS, MH_DYLDLINK, MH_TWOLEVEL, MH_PIE, MH_NO_HEAP_EXECUTION"
    assertExistenceOfFlag x86File flags

  [<TestMethod>]
  member _.``[Mach] X64 EntryPoint test``() =
    Assert.AreEqual(Some 0x100000E90UL, (x64File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[Mach] X64 file type test``() =
    Assert.AreEqual(FileType.MH_EXECUTE, x64File.Header.FileType)

  [<TestMethod>]
  member _.``[Mach] X64 IsStripped test``() =
    Assert.AreEqual(false, isStripped (x64File :> IBinFile))

  [<TestMethod>]
  member _.``[Mach] X64 IsNXEnabled test``() =
    Assert.AreEqual(true, (x64File :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[Mach] X64 InterpreterPath test``() =
    let actual = (x64File :> IBinFile).InterpreterPath
    Assert.AreEqual<string option>(Some "/usr/lib/dyld", actual)

  [<TestMethod>]
  member _.``[Mach] X64 sections length test``() =
    Assert.AreEqual<int>(13, x64File.Sections.Length)

  [<TestMethod>]
  member _.``[Mach] X64 static symbols length test``() =
    Assert.AreEqual<int>(885, x64File.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[Mach] X64 dynamic symbols length test``() =
    Assert.AreEqual<int>(190, x64File.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[Mach] X64 linkageTableEntries length test``() =
    let f = x64File :> IBinFile
    Assert.AreEqual<int>(72, (getLinkageTableEntries f).Length)

  [<TestMethod>]
  member _.``[Mach] X64 text section address test``() =
    Assert.AreEqual<uint64>(0x100000D30UL, getTextSectionAddr x64File)

  [<TestMethod>]
  member _.``[Mach] X64 isa wordSize test``() =
    Assert.AreEqual(WordSize.Bit64, (x64File :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[Mach] X64 function symbol test (1)``() =
    assertFuncSymbolExistence x64File 0x100000D30UL "_usage"

  [<TestMethod>]
  member _.``[Mach] X64 function symbol test (2)``() =
    assertFuncSymbolExistence x64File 0x100005F90UL "_error"

  [<TestMethod>]
  member _.``[Mach] X64 section header test (1)``() =
    assertExistenceOfSectionHeader x64File 0x100000D30UL "__text"

  [<TestMethod>]
  member _.``[Mach] X64 section header test (2)``() =
    assertExistenceOfSectionHeader x64File 0x10000d680UL "__common"

  [<TestMethod>]
  member _.``[Mach] X64 flags test``() =
    let flags = "MH_NOUNDEFS, MH_DYLDLINK, MH_TWOLEVEL, MH_PIE"
    assertExistenceOfFlag x64File flags

  [<TestMethod>]
  member _.``[Mach] X64_Stripped EntryPoint test``() =
    Assert.AreEqual(Some 0x100000E90UL, (x64SFile :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped file type test``() =
    Assert.AreEqual(FileType.MH_EXECUTE, x64SFile.Header.FileType)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped IsStripped test``() =
    Assert.AreEqual(true, isStripped (x64SFile :> IBinFile))

  [<TestMethod>]
  member _.``[Mach] X64_Stripped IsNXEnabled test``() =
    Assert.AreEqual(true, (x64SFile :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped sections length test``() =
    Assert.AreEqual<int>(13, x64SFile.Sections.Length)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped static symbols length test``() =
    Assert.AreEqual<int>(0, x64SFile.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped dynamic symbols length test``() =
    Assert.AreEqual<int>(190, x64SFile.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped linkageTableEntries length test``() =
    let f = x64SFile :> IBinFile
    Assert.AreEqual<int>(72, (getLinkageTableEntries f).Length)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped text section address test``() =
    Assert.AreEqual<uint64>(0x100000D30UL, getTextSectionAddr x64SFile)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped isa wordSize test``() =
    Assert.AreEqual(WordSize.Bit64, (x64SFile :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[Mach] X64_Stripped function symbol test (1)``() =
    assertFuncSymbolExistence x64SFile 0x10000B076UL "___error"

  [<TestMethod>]
  member _.``[Mach] X64_Stripped function symbol test (2)``() =
    assertFuncSymbolExistence x64SFile 0x10000B0D0UL "_fflush"

  [<TestMethod>]
  member _.``[Mach] X64_Stripped section header test (1)``() =
    assertExistenceOfSectionHeader x64SFile 0x100000D30UL "__text"

  [<TestMethod>]
  member _.``[Mach] X64_Stripped section header test (2)``() =
    assertExistenceOfSectionHeader x64SFile 0x10000d680UL "__common"

  [<TestMethod>]
  member _.``[Mach] X64_Stripped flags test``() =
    let flags = "MH_NOUNDEFS, MH_DYLDLINK, MH_TWOLEVEL, MH_PIE"
    assertExistenceOfFlag x64SFile flags

  [<TestMethod>]
  member _.``[Mach] X64 exception table is parsed``() =
    let frames = (x64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    Assert.AreEqual<bool>(true, frames.Length > 0)

  [<TestMethod>]
  member _.``[Mach] X64 exception frames have sane ranges``() =
    let frames = (x64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    let sane = frames |> Array.forall (fun f -> f.FunctionEnd > f.FunctionStart)
    Assert.AreEqual<bool>(true, sane)

  [<TestMethod>]
  member _.``[Mach] X64 exception handler landing pad is resolved``() =
    let frames = (x64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    let hasHandler =
      frames |> Array.exists (fun f ->
        f.Handlers |> Array.exists (fun h -> h.Handler.IsSome))
    Assert.AreEqual<bool>(true, hasHandler)

  [<TestMethod>]
  member _.``[Mach] ARM64 compact unwind table is parsed``() =
    let frames = (arm64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    Assert.AreEqual<bool>(true, frames.Length > 0)

  [<TestMethod>]
  member _.``[Mach] ARM64 compact unwind frames have sane ranges``() =
    let frames = (arm64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    let sane = frames |> Array.forall (fun f -> f.FunctionEnd > f.FunctionStart)
    Assert.AreEqual<bool>(true, sane)

  [<TestMethod>]
  member _.``[Mach] ARM64 compact unwind handler landing pad is resolved``() =
    let frames = (arm64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    let hasHandler =
      frames |> Array.exists (fun f ->
        f.Handlers |> Array.exists (fun h -> h.Handler.IsSome))
    Assert.AreEqual<bool>(true, hasHandler)

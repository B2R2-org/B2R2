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

  /// A minimal x86-64 Mach-O executable; the canonical x64 fixture used for
  /// metadata, section, and address-space tests.
  static let x64File = parseFile "mach_x64" Architecture.Intel WordSize.Bit64

  /// mach_x64 with its symbols stripped: the defined function symbols are gone.
  static let x64SFile =
    parseFile "mach_x64_stripped" Architecture.Intel WordSize.Bit64

  /// A minimal arm64 Mach-O executable, exercising the ARM64 cpu type.
  static let arm64File =
    parseFile "mach_arm64" Architecture.ARMv8 WordSize.Bit64

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
  member _.``[Mach] X64 ISA test``() =
    let isa = (x64File :> IBinFile).ISA
    Assert.AreEqual(Architecture.Intel, isa.Arch)
    Assert.AreEqual(WordSize.Bit64, isa.WordSize)
    Assert.AreEqual(Endian.Little, isa.Endian)

  [<TestMethod>]
  member _.``[Mach] X64 EntryPoint test``() =
    Assert.AreEqual(Some 0x100000480UL, (x64File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[Mach] X64 file type test``() =
    Assert.AreEqual(FileType.MH_EXECUTE, x64File.Header.FileType)

  [<TestMethod>]
  member _.``[Mach] X64 kind test``() =
    Assert.AreEqual<BinFileKind>(Executable, (x64File :> IBinFile).Kind)

  [<TestMethod>]
  member _.``[Mach] X64 is PIE test``() =
    Assert.AreEqual<bool>(true, (x64File :> IBinFile).IsPIE)

  [<TestMethod>]
  member _.``[Mach] X64 is base-relative test``() =
    Assert.AreEqual<bool>(true, (x64File :> IBinFile).IsBaseRelative)

  [<TestMethod>]
  member _.``[Mach] X64 has no Relro test``() =
    Assert.AreEqual<Relro option>(None, (x64File :> IBinFile).Relro)

  [<TestMethod>]
  member _.``[Mach] X64 base address test``() =
    Assert.AreEqual<uint64>(0UL, (x64File :> IBinFile).BaseAddress)

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
  member _.``[Mach] X64 text section address test``() =
    Assert.AreEqual<uint64>(0x100000470UL, getTextSectionAddr x64File)

  [<TestMethod>]
  member _.``[Mach] X64 isa wordSize test``() =
    Assert.AreEqual(WordSize.Bit64, (x64File :> IBinFile).ISA.WordSize)

  [<TestMethod>]
  member _.``[Mach] X64 function symbol test (1)``() =
    assertFuncSymbolExistence x64File 0x100000480UL "_main"

  [<TestMethod>]
  member _.``[Mach] X64 function symbol test (2)``() =
    assertFuncSymbolExistence x64File 0x100000470UL "_helper"

  [<TestMethod>]
  member _.``[Mach] X64 section header test``() =
    assertExistenceOfSectionHeader x64File 0x100000470UL "__text"

  [<TestMethod>]
  member _.``[Mach] X64 flags test``() =
    let flags = "MH_NOUNDEFS, MH_DYLDLINK, MH_TWOLEVEL, MH_PIE"
    assertExistenceOfFlag x64File flags

  [<TestMethod>]
  member _.``[Mach] X64_Stripped IsStripped test``() =
    Assert.AreEqual(true, isStripped (x64SFile :> IBinFile))

  [<TestMethod>]
  member _.``[Mach] X64_Stripped function symbol removed test``() =
    match BinFileOps.tryResolveName x64SFile 0x100000480UL with
    | Error _ -> ()
    | Ok _ -> Assert.Fail "_main should not resolve after stripping"

  [<TestMethod>]
  member _.``[Mach] ARM64 ISA test``() =
    let isa = (arm64File :> IBinFile).ISA
    Assert.AreEqual(Architecture.ARMv8, isa.Arch)
    Assert.AreEqual(WordSize.Bit64, isa.WordSize)
    Assert.AreEqual(Endian.Little, isa.Endian)

  [<TestMethod>]
  member _.``[Mach] ARM64 EntryPoint test``() =
    Assert.AreEqual(Some 0x100000478UL, (arm64File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[Mach] ARM64 file type test``() =
    Assert.AreEqual(FileType.MH_EXECUTE, arm64File.Header.FileType)

  [<TestMethod>]
  member _.``[Mach] ARM64 text section address test``() =
    Assert.AreEqual<uint64>(0x100000460UL, getTextSectionAddr arm64File)

  [<TestMethod>]
  member _.``[Mach] ARM64 function symbol test``() =
    assertFuncSymbolExistence arm64File 0x100000478UL "_main"

  [<TestMethod>]
  member _.``[Mach] ARM64 flags test``() =
    let flags = "MH_NOUNDEFS, MH_DYLDLINK, MH_TWOLEVEL, MH_PIE"
    assertExistenceOfFlag arm64File flags

  [<TestMethod>]
  member _.``[Mach] X64 IsRelocationAddr test``() =
    let reloc = (x64RelocFile :> IBinFile).Relocations.Value
    Assert.AreEqual(true, reloc.IsRelocationAddr 0x0UL)
    Assert.AreEqual(true, reloc.IsRelocationAddr 0x8UL)
    Assert.AreEqual(true, reloc.IsRelocationAddr 0x10UL)
    Assert.AreEqual(false, reloc.IsRelocationAddr 0x4UL)

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
  member _.``[Mach] X64 chained fixups IsRelocationAddr test``() =
    let reloc = (x64ChainedFile :> IBinFile).Relocations.Value
    Assert.AreEqual(true, reloc.IsRelocationAddr 0x1000UL)
    Assert.AreEqual(true, reloc.IsRelocationAddr 0x1010UL)
    Assert.AreEqual(false, reloc.IsRelocationAddr 0x1008UL)

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
  member _.``[Mach] X64 dyld info IsRelocationAddr test``() =
    let reloc = (x64DyldInfoFile :> IBinFile).Relocations.Value
    Assert.AreEqual(true, reloc.IsRelocationAddr 0x1000UL)
    Assert.AreEqual(true, reloc.IsRelocationAddr 0x1010UL)
    Assert.AreEqual(false, reloc.IsRelocationAddr 0x1008UL)

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
  member _.``[Mach] X64 weak bind IsRelocationAddr test``() =
    let reloc = (x64WeakBindFile :> IBinFile).Relocations.Value
    Assert.AreEqual(true, reloc.IsRelocationAddr 0x1008UL)
    Assert.AreEqual(false, reloc.IsRelocationAddr 0x1000UL)

  [<TestMethod>]
  member _.``[Mach] X64 two-level bind library name test``() =
    let linkage = (x64TwoLevelFile :> IBinFile).ImportTable.Value
    let entries = linkage.Imports
    Assert.AreEqual<int>(1, entries.Length)
    Assert.AreEqual<string>("_foo_data", entries[0].Name)
    Assert.AreEqual<string>("/usr/lib/libfoo.dylib", entries[0].LibraryName)
    Assert.AreEqual(0x1000UL, entries[0].TableAddress)

  [<TestMethod>]
  member _.``[Mach] arm64e chained fixups IsRelocationAddr test``() =
    let reloc = (arm64eChainedFile :> IBinFile).Relocations.Value
    Assert.AreEqual(true, reloc.IsRelocationAddr 0x4000UL)
    Assert.AreEqual(true, reloc.IsRelocationAddr 0x4008UL)
    Assert.AreEqual(true, reloc.IsRelocationAddr 0x4018UL)
    Assert.AreEqual(true, reloc.IsRelocationAddr 0x4020UL)
    Assert.AreEqual(false, reloc.IsRelocationAddr 0x4010UL)

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
  member _.``[Mach] X64 exception table is parsed``() =
    let frames = (x64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    Assert.AreEqual<bool>(true, frames.Length > 0)

  [<TestMethod>]
  member _.``[Mach] X64 exception frames have sane ranges``() =
    let frames = (x64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    let sane =
      frames |> Array.forall (fun f -> f.FunctionEnd >= f.FunctionStart)
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
    let sane =
      frames |> Array.forall (fun f -> f.FunctionEnd >= f.FunctionStart)
    Assert.AreEqual<bool>(true, sane)

  [<TestMethod>]
  member _.``[Mach] ARM64 compact unwind handler landing pad is resolved``() =
    let frames = (arm64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    let hasHandler =
      frames |> Array.exists (fun f ->
        f.Handlers |> Array.exists (fun h -> h.Handler.IsSome))
    Assert.AreEqual<bool>(true, hasHandler)

  [<TestMethod>]
  member _.``[Mach] X64 valid address test``() =
    let f = x64File :> IBinFile
    Assert.AreEqual<bool>(true, f.IsValidAddr 0x100000470UL) (* __text *)
    Assert.AreEqual<bool>(true, f.IsValidAddr 0x100002200UL) (* __LINKEDIT *)
    Assert.AreEqual<bool>(false, f.IsValidAddr 0x200000000UL) (* unmapped *)

  [<TestMethod>]
  member _.``[Mach] X64 address mapped to file test``() =
    (* __text is file-backed, but the tail of __LINKEDIT (vmsize > filesize) is
       not. *)
    let f = x64File :> IBinFile
    Assert.AreEqual<bool>(true, f.IsAddrMappedToFile 0x100000470UL)
    Assert.AreEqual<bool>(false, f.IsAddrMappedToFile 0x100002200UL)

  [<TestMethod>]
  member _.``[Mach] X64 executable address test``() =
    let f = x64File :> IBinFile
    Assert.AreEqual<bool>(true, f.IsExecutableAddr 0x100000470UL) (* __text *)
    Assert.AreEqual<bool>(false, f.IsExecutableAddr 0x100001000UL) (* __DATA *)

  [<TestMethod>]
  member _.``[Mach] X64 slice maps address to file content test``() =
    let f = x64File :> IBinFile
    let viaSlice = f.Slice(0x100000470UL, 8).ToArray()
    let viaRaw = f.RawBytes.Span.Slice(0x470, 8).ToArray()
    CollectionAssert.AreEqual(viaRaw, viaSlice)

  [<TestMethod>]
  member _.``[Mach] X64 bounded pointer test``() =
    let f = x64File :> IBinFile
    let p = f.GetBoundedPointer 0x100000470UL
    Assert.AreEqual<bool>(false, p.IsNull)
    Assert.AreEqual<bool>(true, p.CanReadFileBytes)

  [<TestMethod>]
  member _.``[Mach] format detector identifies Mach test``() =
    let bytes = ZIPReader.readBytes MachBinary "mach_x64.zip" "mach_x64"
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    let struct (fmt, _) = FormatDetector.identify bytes isa
    Assert.AreEqual(MachBinary, fmt)

  [<TestMethod>]
  member _.``[Mach] file factory loadMach test``() =
    let bytes = ZIPReader.readBytes MachBinary "mach_x64.zip" "mach_x64"
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    let rf = FrontEnd.Intel.RegisterFactory isa :> IRegisterFactory
    let f = FileFactory.loadMach "" bytes isa rf None :> IBinFile
    Assert.AreEqual(MachBinary, f.Format)

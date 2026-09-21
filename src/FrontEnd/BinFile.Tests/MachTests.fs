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
  static let isStripped (file: IBinFile) = file.SymbolTable.Value.IsStripped

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

  /// An x86-64 Mach-O executable carrying two LC_RPATH load commands, used to
  /// exercise runtime search-path (@rpath) parsing.
  static let x64RPathFile =
    parseFile "mach_x64_rpath" Architecture.Intel WordSize.Bit64

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

  /// A dylib exporting _foo, _foobar and _foobarbaz, so its export trie has
  /// nodes that are terminal and a parent at once.
  static let x64TriePrefixFile =
    parseFile "mach_x64_trie_prefix" Architecture.Intel WordSize.Bit64

  /// An executable that loads liba weakly before it loads libb normally, so a
  /// dylib ordinal only lands on the right library when the weak load counts.
  static let x64WeakDyLibFile =
    parseFile "mach_x64_weakdylib" Architecture.Intel WordSize.Bit64

  /// A universal binary holding an x86-64 slice and an arm64 one, parsed as
  /// each of the two.
  static let fatX64File =
    parseFile "mach_fat_x64_arm64" Architecture.Intel WordSize.Bit64

  static let fatArm64File =
    parseFile "mach_fat_x64_arm64" Architecture.ARMv8 WordSize.Bit64

  /// The same two slices behind a 64-bit FAT header (FAT_MAGIC_64), whose
  /// architecture table uses 64-bit offsets and sizes.
  static let fat64X64File =
    parseFile "mach_fat64_x64_arm64" Architecture.Intel WordSize.Bit64

  /// A relocatable object holding only a __DATA,__data section, so the file
  /// has no __text section for the parser to key on.
  static let x64NoTextFile =
    parseFile "mach_x64_notext" Architecture.Intel WordSize.Bit64

  /// Executables naming their entry point through LC_UNIXTHREAD, as binaries
  /// older than LC_MAIN and kernel images do.
  static let x64UnixThreadFile =
    parseFile "mach_x64_unixthread" Architecture.Intel WordSize.Bit64

  static let arm64UnixThreadFile =
    parseFile "mach_arm64_unixthread" Architecture.ARMv8 WordSize.Bit64

  /// A 32-bit i386 dylib carrying LC_DYLD_INFO_ONLY, where every pointer the
  /// opcode streams touch is four bytes wide rather than eight.
  static let i386DyldInfoFile =
    parseFile "mach_i386_dyldinfo" Architecture.Intel WordSize.Bit32

  /// A 32-bit i386 object carrying the relocation shapes x86-64 never
  /// produces: a scattered entry, a PC-relative one, and a plain external one.
  static let i386RelocFile =
    parseFile "mach_i386_reloc" Architecture.Intel WordSize.Bit32

  /// An ARMv7 executable mixing A32 and T32 code, with a data range embedded
  /// in __text that LC_DATA_IN_CODE names.
  static let arm32ThumbFile =
    parseFile "mach_arm32_thumb" Architecture.ARMv7 WordSize.Bit32

  /// A non-PIE dylib whose relocations live in the external and local tables
  /// of LC_DYSYMTAB rather than hanging off its sections.
  static let x64ExtRelocFile =
    parseFile "mach_x64_extreloc" Architecture.Intel WordSize.Bit64

  /// A dylib whose one fixup page holds two chains, so its page_start indexes
  /// an overflow list rather than naming an offset into the page.
  static let x64MultiChainFile =
    parseFile "mach_x64_multichain" Architecture.Intel WordSize.Bit64

  /// An MH_FILESET container holding two images, the way a kernel collection
  /// holds the kernel and its kexts. Both share one __LINKEDIT.
  static let x64FilesetFile =
    parseFile "mach_x64_fileset" Architecture.Intel WordSize.Bit64

  /// An MH_OBJECT naming what it needs linked with LC_LINKER_OPTION, the way
  /// clang's autolinking writes it, rather than with LC_LOAD_DYLIB.
  static let x64LinkerOptFile =
    parseFile "mach_x64_linkeropt" Architecture.Intel WordSize.Bit64

  /// A non-PIE dylib naming its initializers with __mod_init_func, its
  /// terminators with __mod_term_func and one more routine with LC_ROUTINES64.
  static let x64InitFuncFile =
    parseFile "mach_x64_initfunc" Architecture.Intel WordSize.Bit64

  /// A PIE dylib whose __mod_init_func slots hold a chain of rebase entries
  /// rather than the addresses of the initializers themselves.
  static let x64InitChainFile =
    parseFile "mach_x64_initchain" Architecture.Intel WordSize.Bit64

  /// A dylib carrying an ad-hoc code signature: a hand-written superblob with
  /// a code directory, an entitlements plist and a CMS blob.
  static let x64CodeSignFile =
    parseFile "mach_x64_codesign" Architecture.Intel WordSize.Bit64

  /// An arm64 executable naming its platform with LC_VERSION_MIN_IPHONEOS,
  /// the way everything built before LC_BUILD_VERSION took the job over does.
  static let arm64VersionMinFile =
    parseFile "mach_arm64_versionmin" Architecture.ARMv8 WordSize.Bit64

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
  member _.``[Mach] X64 entry point follows the base address test``() =
    (* LC_MAIN names an offset from the Mach-O header, and the __TEXT vmaddr it
       is added to already carries the load address, so a slid image moves its
       entry point exactly once. *)
    let bytes = ZIPReader.readBytes MachBinary "mach_x64.zip" "mach_x64"
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    let f = MachBinFile("mach_x64", bytes, isa, Some 0x200000000UL, None)
    Assert.AreEqual(Some 0x300000480UL, (f :> IBinFile).EntryPoint)

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
  member _.``[Mach] X64 has no encrypted range test``() =
    (* Only a re-signed image carries LC_ENCRYPTION_INFO with a cryptid set;
       what a linker builds names no encrypted range. *)
    let file = x64File :> IBinFile
    CollectionAssert.AreEqual([||], file.EncryptedRanges)

  [<TestMethod>]
  member _.``[Mach] X64 has no rpath test``() =
    let file = x64File :> IBinFile
    CollectionAssert.AreEqual([||], file.RPath)
    CollectionAssert.AreEqual([||], file.RunPath)

  [<TestMethod>]
  member _.``[Mach] X64 rpath test``() =
    let file = x64RPathFile :> IBinFile
    CollectionAssert.AreEqual([||], file.RPath)
    CollectionAssert.AreEqual([| "/opt/lib"; "/usr/local/lib" |], file.RunPath)

  [<TestMethod>]
  member _.``[Mach] X64 dependencies test``() =
    (* LC_LOAD_DYLIB names what the image needs, and LC_ID_DYLIB the name it
       answers to; an executable carries only the former. *)
    let file = x64File :> IBinFile
    let expected = [| "/usr/lib/libSystem.B.dylib" |]
    CollectionAssert.AreEqual(expected, file.DependencyNames)
    Assert.AreEqual<string option>(None, file.SharedObjectName)

  [<TestMethod>]
  member _.``[Mach] X64 initializer function test``() =
    (* The pointer arrays and LC_ROUTINES name functions the symbol table
       does not, and they join the symbols in one sorted list. *)
    let file = x64InitFuncFile :> IBinFile
    let addrs = file.Structure.Value.FunctionAddresses
    let expected = [| 0x700UL; 0x800UL; 0x810UL; 0x820UL; 0x900UL |]
    CollectionAssert.AreEqual(expected, addrs)

  [<TestMethod>]
  member _.``[Mach] X64 chained initializer function test``() =
    (* dyld writes what a chained slot holds, so the initializer is named by
       the rebase fixup; the file bytes hold the chain entry instead. *)
    let file = x64InitChainFile :> IBinFile
    let addrs = file.Structure.Value.FunctionAddresses
    CollectionAssert.AreEqual([| 0x800UL; 0x810UL |], addrs)

  [<TestMethod>]
  member _.``[Mach] X64 has no initializer function test``() =
    (* A binary carrying neither the pointer arrays nor LC_ROUTINES names its
       functions by symbol alone, and names each of them once. *)
    let addrs = (x64File :> IBinFile).Structure.Value.FunctionAddresses
    Assert.AreEqual<int>(Array.length (Array.distinct addrs), addrs.Length)
    CollectionAssert.AreEqual(Array.sort addrs, addrs)

  [<TestMethod>]
  member _.``[Mach] X64 code signature test``() =
    (* Everything a code signing structure holds is big-endian, whichever way
       round the Mach-O around it is, so a signature read with the file's own
       reader would come out byte-swapped throughout. *)
    let sign = x64CodeSignFile.CodeSignature.Value
    Assert.AreEqual<int>(0x1000, sign.SignOffset)
    Assert.AreEqual<uint32>(337u, sign.SignSize)
    let dir = sign.CodeDirectory
    Assert.AreEqual<string>("com.example.signed", dir.Identifier)
    Assert.AreEqual<string>("ABCDE12345", dir.TeamIdentifier)
    Assert.AreEqual<CodeHashType>(CodeHashType.SHA256, dir.HashType)
    Assert.AreEqual<uint64>(0x1000UL, dir.CodeLimit)
    Assert.AreEqual<int>(4096, dir.PageSize)
    Assert.AreEqual<bool>(true, dir.SignFlags.HasFlag CodeSignFlag.CS_ADHOC)
    let linkerSigned = CodeSignFlag.CS_LINKER_SIGNED
    Assert.AreEqual<bool>(true, dir.SignFlags.HasFlag linkerSigned)

  [<TestMethod>]
  member _.``[Mach] X64 code directory hash test``() =
    (* A cdhash is the code directory hashed whole by the algorithm it names
       and cut to twenty bytes, which is what every tool prints one at. *)
    let dir = x64CodeSignFile.CodeSignature.Value.CodeDirectory
    let hex = "b41ae28e90e9e76123f77eb021f4a535e5a5d15c"
    CollectionAssert.AreEqual(ByteArray.ofHexString hex, dir.CDHash)

  [<TestMethod>]
  member _.``[Mach] X64 entitlements test``() =
    (* The entitlements slot carries the plist as it stands, after the magic
       and the length that every blob of a superblob begins with. *)
    let ents = x64CodeSignFile.CodeSignature.Value.Entitlements
    Assert.AreEqual<int>(131, ents.Length)
    let head = System.Text.Encoding.ASCII.GetString(ents, 0, 5)
    Assert.AreEqual<string>("<?xml", head)

  [<TestMethod>]
  member _.``[Mach] X64 has no code signature test``() =
    Assert.AreEqual<bool>(true, x64File.CodeSignature.IsNone)

  [<TestMethod>]
  member _.``[Mach] X64 build version test``() =
    (* A version is packed with its major part in the upper sixteen bits and
       its minor and patch parts in a byte each below that, which is how every
       version a Mach-O records reads. *)
    let ver = x64File.BuildVersion.Value
    Assert.AreEqual<Platform>(Platform.MACOS, ver.Platform)
    Assert.AreEqual<uint32>(0x1a0000u, ver.MinOSVersion)
    Assert.AreEqual<uint32>(0x1a0500u, ver.SDKVersion)
    Assert.AreEqual<int>(1, ver.BuildTools.Length)
    let tool = ver.BuildTools[0]
    Assert.AreEqual<BuildToolKind>(BuildToolKind.TOOL_LD, tool.Tool)
    Assert.AreEqual<uint32>(0x4f30000u, tool.ToolVersion)

  [<TestMethod>]
  member _.``[Mach] ARM64 version min test``() =
    (* An LC_VERSION_MIN_* command names its platform by being the command it
       is, and names no tool at all, so the two versions are all it carries. *)
    let ver = arm64VersionMinFile.BuildVersion.Value
    Assert.AreEqual<Platform>(Platform.IOS, ver.Platform)
    Assert.AreEqual<uint32>(0xc0100u, ver.MinOSVersion)
    Assert.AreEqual<uint32>(0xc0300u, ver.SDKVersion)
    CollectionAssert.AreEqual([||], ver.BuildTools)

  [<TestMethod>]
  member _.``[Mach] X64 without build version test``() =
    Assert.AreEqual<bool>(true, x64CodeSignFile.BuildVersion.IsNone)

  [<TestMethod>]
  member _.``[Mach] OS test``() =
    (* Every Apple platform shares the ABI that macOS stands for here, and a
       Mach-O naming no platform is one built for macOS before any command
       said so. *)
    Assert.AreEqual<OS>(OS.MacOSX, (x64File :> IBinFile).OS)
    Assert.AreEqual<OS>(OS.MacOSX, (arm64VersionMinFile :> IBinFile).OS)
    Assert.AreEqual<OS>(OS.MacOSX, (x64CodeSignFile :> IBinFile).OS)

  [<TestMethod>]
  member _.``[Mach] bare metal platform test``() =
    (* Firmware and the Secure Enclave run under no system, which is a thing
       the image says rather than a thing this parser could not read. No
       toolchain here builds one, so the mapping alone is what pins it. *)
    Assert.AreEqual<OS>(OS.BareMetal, Platform.toOS Platform.FIRMWARE)
    Assert.AreEqual<OS>(OS.BareMetal, Platform.toOS Platform.SEPOS)
    Assert.AreEqual<OS>(OS.MacOSX, Platform.toOS Platform.IOSSIMULATOR)

  [<TestMethod>]
  member _.``[Mach] X64 linker option dependencies test``() =
    (* An object file carries no LC_LOAD_DYLIB, so its LC_LINKER_OPTION
       commands are what name the libraries it needs linked. Every form that
       names one is read, a directive repeated for each translation unit
       names its library once, and an option naming none is dropped. *)
    let file = x64LinkerOptFile :> IBinFile
    Assert.AreEqual<BinFileKind>(BinFileKind.Object, file.Kind)
    let expected =
      [| "foo"; "Bar"; "baz"; "Qux"; "quux"; "corge"; "Grault" |]
    CollectionAssert.AreEqual(expected, file.DependencyNames)
    Assert.AreEqual<string option>(None, file.SharedObjectName)

  [<TestMethod>]
  member _.``[Mach] X64 raw linker option test``() =
    let opts = x64LinkerOptFile.LinkerOptions
    Assert.AreEqual<int>(9, opts.Length)
    CollectionAssert.AreEqual([| "-lfoo" |], opts[0])
    CollectionAssert.AreEqual([| "-framework"; "Bar" |], opts[1])
    CollectionAssert.AreEqual([| "-random_flag" |], opts[8])
    CollectionAssert.AreEqual([||], x64File.LinkerOptions)

  [<TestMethod>]
  member _.``[Mach] X64 object without linker option test``() =
    (* An object file that names no library keeps an empty dependency list;
       reading the linker options is not a fallback onto anything else. *)
    let file = x64NoTextFile :> IBinFile
    CollectionAssert.AreEqual([||], file.DependencyNames)

  [<TestMethod>]
  member _.``[Mach] X64 two-level install name test``() =
    let file = x64TwoLevelFile :> IBinFile
    let expected = [| "/usr/lib/libfoo.dylib" |]
    CollectionAssert.AreEqual(expected, file.DependencyNames)
    let name = Some "mach_x64_twoleve"
    Assert.AreEqual<string option>(name, file.SharedObjectName)

  [<TestMethod>]
  member _.``[Mach] X64 build ID test``() =
    (* LC_UUID is what Mach-O names a build by, the counterpart of the GNU
       build-ID note of ELF. *)
    let hex = "4345cc36ef4d304b831aa9b624070e20"
    let expected = ByteArray.ofHexString hex
    CollectionAssert.AreEqual(expected, (x64File :> IBinFile).BuildId)

  [<TestMethod>]
  member _.``[Mach] ARM64 build ID test``() =
    let hex = "1411857880883b2199a52b90d50d8635"
    let expected = ByteArray.ofHexString hex
    CollectionAssert.AreEqual(expected, (arm64File :> IBinFile).BuildId)

  [<TestMethod>]
  member _.``[Mach] build ID array is not shared test``() =
    let file = x64File :> IBinFile
    let buildId = file.BuildId
    buildId[0] <- 0uy
    Assert.AreEqual<byte>(0x43uy, file.BuildId[0])

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
  member _.``[Mach] X64 has no program header table info test``() =
    let file = x64File :> IBinFile
    Assert.AreEqual(None, file.ProgramHeaderTable)

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
  member _.``[Mach] STAB symbol is not section function test``() =
    let sym =
      { SymName = "stab"
        SymType = SymbolType.N_BNSYM
        IsExternal = false
        SecNum = 1
        SymDesc = 0s
        VerInfo = None
        SymAddr = 0x100000470UL }
    Assert.AreEqual<bool>(false, Symbol.IsFunc(0, sym))

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
  member _.``[Mach] X64 exports trie test``() =
    (* A modern binary carries its export trie in LC_DYLD_EXPORTS_TRIE, and the
       addresses in it are relative to the image base. *)
    let exports =
      x64File.ExportedSymbols
      |> Array.map (fun e -> e.ExportSymName, e.ExportAddr)
      |> Array.sortBy fst
    let expected =
      [| "__mh_execute_header", 0x100000000UL
         "_helper", 0x100000470UL
         "_main", 0x100000480UL |]
    CollectionAssert.AreEqual(expected, exports)

  [<TestMethod>]
  member _.``[Mach] X64 legacy dyld info exports trie test``() =
    (* An older binary embeds the same trie in LC_DYLD_INFO instead. *)
    let exports =
      x64DyldInfoFile.ExportedSymbols
      |> Array.map (fun e -> e.ExportSymName, e.ExportAddr)
      |> Array.sortBy fst
    let expected = [| "_p_bind", 0x1000UL; "_p_rebase", 0x1010UL |]
    CollectionAssert.AreEqual(expected, exports)

  [<TestMethod>]
  member _.``[Mach] X64 exports trie with shared prefixes test``() =
    (* _foo is terminal and still the parent of _foobar, which is in turn the
       parent of _foobarbaz, so a terminal node has to be descended into. *)
    let exports =
      x64TriePrefixFile.ExportedSymbols
      |> Array.map (fun e -> e.ExportSymName, e.ExportAddr)
      |> Array.sortBy fst
    let expected =
      [| "_foo", 0x300UL; "_foobar", 0x310UL; "_foobarbaz", 0x320UL |]
    CollectionAssert.AreEqual(expected, exports)

  [<TestMethod>]
  member _.``[Mach] X64 undefined external symbol is not defined test``() =
    (* An undefined import has N_EXT set alongside N_UNDF, so only the N_TYPE
       field of n_type tells the two apart. *)
    let symbols = (x64File :> IBinFile).SymbolTable.Value.Symbols
    let isDefined name =
      symbols
      |> Array.tryFind (fun s -> s.Name = name)
      |> Option.map (fun s -> s.IsDefined)
    Assert.AreEqual(Some false, isDefined "_write")
    Assert.AreEqual(Some true, isDefined "_main")

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
  member _.``[Mach] ARM64 chained fixups image-relative rebase test``() =
    (* DYLD_CHAINED_PTR_64_OFFSET names its rebase target as an offset from the
       image base rather than as an unslid address, so the __TEXT vmaddr has to
       be added back. The second entry also sets high8, which the ARM64 C++ ABI
       uses to mark a unique type_info name. *)
    let reloc = (arm64ExcFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x100004048UL, reloc.TryGetRelocatedAddr 0x100004040UL)
    Assert.AreEqual(Ok 0x80000001000007e0UL,
                    reloc.TryGetRelocatedAddr 0x100004050UL)

  [<TestMethod>]
  member _.``[Mach] X64 weak dylib counts toward library ordinals test``() =
    (* LC_LOAD_WEAK_DYLIB takes an ordinal just as LC_LOAD_DYLIB does, so the
       weakly loaded liba is ordinal 1 and libb is ordinal 2. *)
    let linkage = (x64WeakDyLibFile :> IBinFile).ImportTable.Value
    let entries =
      linkage.Imports
      |> Array.map (fun e -> e.Name, e.LibraryName)
      |> Array.sortBy fst
    let expected =
      [| "_a_sym", "/usr/lib/liba.dylib"
         "_b_sym", "/usr/lib/libb.dylib" |]
    CollectionAssert.AreEqual(expected, entries)

  [<TestMethod>]
  member _.``[Mach] X64 weak dylib is a dependency test``() =
    let deps = (x64WeakDyLibFile :> IBinFile).DependencyNames |> Array.sort
    let expected =
      [| "/usr/lib/liba.dylib"
         "/usr/lib/libSystem.B.dylib"
         "/usr/lib/libb.dylib" |] |> Array.sort
    CollectionAssert.AreEqual(expected, deps)

  [<TestMethod>]
  member _.``[Mach] X64 symbol library name follows the ordinal test``() =
    let symbols = (x64WeakDyLibFile :> IBinFile).SymbolTable.Value.Symbols
    let libOf name =
      symbols
      |> Array.tryFind (fun s -> s.Name = name)
      |> Option.bind (fun s -> s.LibraryName)
    Assert.AreEqual(Some "/usr/lib/liba.dylib", libOf "_a_sym")
    Assert.AreEqual(Some "/usr/lib/libb.dylib", libOf "_b_sym")

  [<TestMethod>]
  member _.``[Mach] FAT binary selects the slice matching the ISA test``() =
    let x64 = (fatX64File :> IBinFile).ISA
    let arm64 = (fatArm64File :> IBinFile).ISA
    Assert.AreEqual(Architecture.Intel, x64.Arch)
    Assert.AreEqual(Architecture.ARMv8, arm64.Arch)

  [<TestMethod>]
  member _.``[Mach] FAT binary length is the slice length test``() =
    (* The image ends where its slice does, not where the whole file does. *)
    let f = fatX64File :> IBinFile
    let arch =
      fatX64File.FatArchs
      |> Array.find (fun a -> a.CPUType = CPUType.X64)
    Assert.AreEqual<int>(int arch.Size, f.Length)

  [<TestMethod>]
  member _.``[Mach] FAT binary file offsets are slice-relative test``() =
    (* A section offset counts from the Mach-O header, which in a universal
       binary sits at the slice offset rather than at the start of the file.
       The whole archive is read again here so that the expected bytes do not
       come back through the same address space under test. *)
    let name = "mach_fat_x64_arm64"
    let whole = ZIPReader.readBytes MachBinary (name + ".zip") name
    let arch =
      fatX64File.FatArchs |> Array.find (fun a -> a.CPUType = CPUType.X64)
    let f = fatX64File :> IBinFile
    let text = f.Structure.Value.CodeSectionPointer
    let start = int arch.Offset + text.Offset
    let expected = whole[start..start + 7]
    CollectionAssert.AreEqual(expected, f.Slice(text.Addr, 8).ToArray())

  [<TestMethod>]
  member _.``[Mach] FAT binary entry point is in the slice test``() =
    let entry = (fatX64File :> IBinFile).EntryPoint
    Assert.AreEqual<bool>(true, Option.isSome entry)
    let f = fatX64File :> IBinFile
    Assert.AreEqual<bool>(true, f.IsExecutableAddr entry.Value)

  [<TestMethod>]
  member _.``[Mach] FAT64 binary is recognized test``() =
    (* FAT_MAGIC_64 widens the architecture table to 64-bit offsets. *)
    let f = fat64X64File :> IBinFile
    Assert.AreEqual(Architecture.Intel, f.ISA.Arch)
    Assert.AreEqual<int>(2, fat64X64File.FatArchs.Length)

  [<TestMethod>]
  member _.``[Mach] FAT64 binary matches the FAT32 slice test``() =
    (* lipo wrote the same two slices either way, so the images agree. *)
    let fat = (fatX64File :> IBinFile).RawBytes.ToArray()
    let fat64 = (fat64X64File :> IBinFile).RawBytes.ToArray()
    CollectionAssert.AreEqual(fat, fat64)

  [<TestMethod>]
  member _.``[Mach] X64 file without a text section parses test``() =
    let f = x64NoTextFile :> IBinFile
    Assert.AreEqual<BinFileKind>(Object, f.Kind)
    let names = f.Structure.Value.Sections |> Array.map (fun s -> s.Name)
    CollectionAssert.AreEqual([| "__data" |], names)

  [<TestMethod>]
  member _.``[Mach] X64 file without a text section has symbols test``() =
    let symbols = (x64NoTextFile :> IBinFile).SymbolTable.Value.Symbols
    let names = symbols |> Array.map (fun s -> s.Name)
    CollectionAssert.AreEqual([| "_g_table" |], names)

  [<TestMethod>]
  member _.``[Mach] X64 file without a text section has no code test``() =
    let ptr = (x64NoTextFile :> IBinFile).Structure.Value.CodeSectionPointer
    Assert.AreEqual<bool>(true, ptr.IsNull)

  [<TestMethod>]
  member _.``[Mach] X64 LC_UNIXTHREAD entry point test``() =
    (* The thread state spells out an unslid address, not an offset. *)
    let entry = (x64UnixThreadFile :> IBinFile).EntryPoint
    Assert.AreEqual(Some 0x100000170UL, entry)

  [<TestMethod>]
  member _.``[Mach] ARM64 LC_UNIXTHREAD entry point test``() =
    let entry = (arm64UnixThreadFile :> IBinFile).EntryPoint
    Assert.AreEqual(Some 0x1000001d8UL, entry)

  [<TestMethod>]
  member _.``[Mach] I386 dyld info rebase reads a 32-bit pointer test``() =
    (* The slot at 0x1004 holds 0x1008, and the word behind it is non-zero, so
       reading the slot eight bytes wide would drag that word into the
       target. *)
    let reloc = (i386DyldInfoFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x1008UL, reloc.TryGetRelocatedAddr 0x1004UL)

  [<TestMethod>]
  member _.``[Mach] I386 dyld info bind linkage test``() =
    let linkage = (i386DyldInfoFile :> IBinFile).ImportTable.Value
    let entries = linkage.Imports
    Assert.AreEqual<int>(1, entries.Length)
    Assert.AreEqual<string>("_ext_symbol", entries[0].Name)
    Assert.AreEqual(0x1000UL, entries[0].TableAddress)

  [<TestMethod>]
  member _.``[Mach] I386 word size test``() =
    let isa = (i386DyldInfoFile :> IBinFile).ISA
    Assert.AreEqual(WordSize.Bit32, isa.WordSize)
    Assert.AreEqual(Architecture.Intel, isa.Arch)

  [<TestMethod>]
  member _.``[Mach] I386 scattered relocation test``() =
    (* A scattered entry packs every field into its first word, so reading it
       as the ordinary two-word layout lands on a nonsense section ordinal.
       Its field holds the absolute target, 0x10 past the 0x2000 the entry
       measures from. *)
    let reloc = (i386RelocFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x2010UL, reloc.TryGetRelocatedAddr 0x0UL)

  [<TestMethod>]
  member _.``[Mach] I386 PC-relative relocation has no target test``() =
    (* The field is measured from the end of the instruction it sits in, and
       the entry records neither that length nor where the instruction starts,
       so no absolute target can be named. *)
    let reloc = (i386RelocFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Error ErrorCase.ItemNotFound,
                    reloc.TryGetRelocatedAddr 0x4UL)

  [<TestMethod>]
  member _.``[Mach] I386 external relocation addend test``() =
    let reloc = (i386RelocFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x30UL, reloc.TryGetRelocatedAddr 0x8UL)

  [<TestMethod>]
  member _.``[Mach] I386 relocation symbol names test``() =
    (* A scattered entry names an address rather than a symbol. *)
    let relocs = (i386RelocFile :> IBinFile).Relocations.Value.Relocations
    let named =
      relocs |> Array.map (fun r -> r.Address, r.SymbolName) |> Array.sortBy fst
    let expected =
      [| 0x0UL, None
         0x4UL, Some "_pcrel_target"
         0x8UL, Some "_plain_target" |]
    CollectionAssert.AreEqual(expected, named)

  [<TestMethod>]
  member _.``[Mach] ARM32 code mode markers test``() =
    (* N_ARM_THUMB_DEF marks the T32 function, and the LC_DATA_IN_CODE range
       interrupts the A32 one, which resumes where the range ends. *)
    let markers = (arm32ThumbFile :> IBinFile).SymbolTable.Value.CodeModeMarkers
    let actual = markers |> Array.map (fun m -> m.Address, m.Mode)
    let expected =
      [| 0x10c0UL, ArmMode
         0x10d0UL, DataMode
         0x10d8UL, ArmMode
         0x10e0UL, ThumbMode |]
    CollectionAssert.AreEqual(expected, actual)

  [<TestMethod>]
  member _.``[Mach] X64 has no code mode markers test``() =
    (* x86 has one encoding and no value in the model to name it with, so a
       data range there could be opened but never closed. *)
    let markers = (x64File :> IBinFile).SymbolTable.Value.CodeModeMarkers
    Assert.AreEqual<int>(0, markers.Length)

  [<TestMethod>]
  member _.``[Mach] ARM32 absolute symbol ignores the base address test``() =
    (* An absolute symbol names a value rather than a location, so the load
       address moves the section-defined symbols around it but not it. *)
    let name = "mach_arm32_thumb"
    let bytes = ZIPReader.readBytes MachBinary (name + ".zip") name
    let isa = ISA(Architecture.ARMv7, Endian.Little, WordSize.Bit32)
    let f = MachBinFile(name, bytes, isa, Some 0x10000UL, None)
    let symbols = (f :> IBinFile).SymbolTable.Value.Symbols
    let addrOf n =
      symbols |> Array.tryFind (fun s -> s.Name = n) |> Option.map _.Address
    Assert.AreEqual(Some 0x1234UL, addrOf "_abs_sym")
    Assert.AreEqual(Some 0x110c0UL, addrOf "_arm_fn")

  [<TestMethod>]
  member _.``[Mach] truncated load commands are rejected test``() =
    (* A command running past the end of the file is a bad file, not a span
       that could not be cut. *)
    let bytes = ZIPReader.readBytes MachBinary "mach_x64.zip" "mach_x64"
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    let truncated = Array.sub bytes 0 64
    let f = MachBinFile("truncated", truncated, isa, None, None)
    Assert.ThrowsExactly<InvalidFileFormatException>(fun () ->
      (f :> IBinFile).EntryPoint |> ignore) |> ignore

  [<TestMethod>]
  member _.``[Mach] X64 external relocation table test``() =
    (* The r_address of an image relocation counts from the image base, here
       the __TEXT vmaddr of 0x1000, so the entry at 0x1000 relocates 0x2000.
       It names _data_base, at 0x2000, and its field holds an addend of 0x10. *)
    let reloc = (x64ExtRelocFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x2010UL, reloc.TryGetRelocatedAddr 0x2000UL)

  [<TestMethod>]
  member _.``[Mach] X64 local relocation table test``() =
    (* A local entry keeps its unslid target in place. *)
    let reloc = (x64ExtRelocFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x2000UL, reloc.TryGetRelocatedAddr 0x2008UL)

  [<TestMethod>]
  member _.``[Mach] X64 image relocation addresses test``() =
    let reloc = (x64ExtRelocFile :> IBinFile).Relocations.Value
    let named =
      reloc.Relocations
      |> Array.map (fun r -> r.Address, r.SymbolName)
      |> Array.sortBy fst
    let expected = [| 0x2000UL, Some "_data_base"; 0x2008UL, None |]
    CollectionAssert.AreEqual(expected, named)
    Assert.AreEqual<bool>(true, reloc.IsRelocationAddr 0x2000UL)
    Assert.AreEqual<bool>(false, reloc.IsRelocationAddr 0x2004UL)

  [<TestMethod>]
  member _.``[Mach] X64 multi-chain fixup page test``() =
    (* DYLD_CHAINED_PTR_START_MULTI turns page_start into an index into the
       overflow list that follows the array, whose entries start one chain
       each up to the one marked last. Reading the index as an offset would
       find neither chain. *)
    let reloc = (x64MultiChainFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x1008UL, reloc.TryGetRelocatedAddr 0x1000UL)
    Assert.AreEqual(Ok 0x1018UL, reloc.TryGetRelocatedAddr 0x1010UL)

  [<TestMethod>]
  member _.``[Mach] X64 multi-chain page marks both chains test``() =
    let reloc = (x64MultiChainFile :> IBinFile).Relocations.Value
    Assert.AreEqual<bool>(true, reloc.IsRelocationAddr 0x1000UL)
    Assert.AreEqual<bool>(true, reloc.IsRelocationAddr 0x1010UL)
    Assert.AreEqual<bool>(false, reloc.IsRelocationAddr 0x1008UL)

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
  member _.``[Mach] X64 exception frame personality routine is resolved``() =
    (* The zPLR CIE encodes its personality pointer as indirect|pcrel|sdata4,
       so it resolves to the __DATA_CONST,__got slot that binds
       ___gxx_personality_v0, not to the routine itself. *)
    let frames = (x64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    let personalities =
      frames
      |> Array.choose (fun f -> f.PersonalityRoutine)
      |> Array.distinct
    CollectionAssert.AreEqual([| 0x100001000UL |], personalities)

  [<TestMethod>]
  member _.``[Mach] ARM64 compact unwind personality routine is resolved``() =
    (* Only the frame with a landing pad names a personality, by an index into
       the __unwind_info personality array, whose entry points at the
       __DATA_CONST,__got slot binding ___gxx_personality_v0. *)
    let frames = (arm64ExcFile :> IBinFile).ExceptionTable.Value.Frames
    let named =
      frames
      |> Array.choose (fun f ->
        f.PersonalityRoutine |> Option.map (fun p -> f.FunctionStart, p))
    CollectionAssert.AreEqual([| 0x100000608UL, 0x100004028UL |], named)

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
  member _.``[Mach] X64 holds no fileset entries test``() =
    CollectionAssert.AreEqual([||], x64File.FilesetEntries)

  [<TestMethod>]
  member _.``[Mach] fileset entries test``() =
    let file = x64FilesetFile :> IBinFile
    Assert.AreEqual<BinFileKind>(BinFileKind.Executable, file.Kind)
    let entries = x64FilesetFile.FilesetEntries
    let names = entries |> Array.map (fun e -> e.EntryName)
    let expected = [| "com.example.kext.a"; "com.example.kext.b" |]
    CollectionAssert.AreEqual(expected, names)
    Assert.AreEqual<Addr>(0x100001000UL, entries[0].EntryVMAddr)
    Assert.AreEqual<uint64>(0x1000UL, entries[0].EntryFileOffset)
    Assert.AreEqual<Addr>(0x100002000UL, entries[1].EntryVMAddr)
    Assert.AreEqual<uint64>(0x2000UL, entries[1].EntryFileOffset)

  [<TestMethod>]
  member _.``[Mach] fileset entry opening test``() =
    (* Each image is read in place: its __LINKEDIT and symbol table are the
       container's, so the second image's symbol sits past the end of its own
       page and only whole-container bytes reach it. *)
    let entry = (x64FilesetFile.TryOpenFilesetEntry "com.example.kext.b").Value
    let file = entry :> IBinFile
    Assert.AreEqual<BinFileKind>(BinFileKind.SharedLibrary, file.Kind)
    let symbols = file.SymbolTable.Value.Symbols
    Assert.AreEqual<int>(1, symbols.Length)
    Assert.AreEqual<string>("_b_func", symbols[0].Name)
    Assert.AreEqual<Addr>(0x100002800UL, symbols[0].Address)
    let ptr = BinFileOps.getCodeSectionPointer file
    Assert.AreEqual<Addr>(0x100002800UL, ptr.Addr)
    Assert.AreEqual<int>(0x2800, ptr.Offset)
    Assert.AreEqual<byte>(0xC3uy, (file.Slice(ptr.Addr, 1)).ToArray()[0])

  [<TestMethod>]
  member _.``[Mach] fileset unknown entry test``() =
    let opened = x64FilesetFile.TryOpenFilesetEntry "nosuch"
    Assert.AreEqual<bool>(true, opened.IsNone)

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

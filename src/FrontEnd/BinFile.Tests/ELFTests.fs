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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.DWARF
open Microsoft.VisualStudio.TestTools.UnitTesting
open type FileFormat

/// Names the relocation-kind type, which the ELF prefix alone cannot reach:
/// an auto-opened module of active patterns shares the name and shadows the
/// type wherever that namespace is not open.
type internal RelocKind = ELF.RelocationKind

[<TestClass>]
type ELFTests() =
  static let isStripped (file: IBinFile) = file.SymbolTable.Value.IsStripped

  /// The code mode markers of the given file, keyed by the address each marks.
  static let markersOf (file: ELFBinFile) =
    (file :> IBinFile).SymbolTable.Value.CodeModeMarkers
    |> Array.map (fun m -> m.Address, m.Mode)
    |> Map.ofArray

  static let tryResolveName (file: ELFBinFile) addr =
    (file :> IBinFile).NameResolver.Value.TryResolveName addr

  static let coreLayoutOf machine cls flags =
    ELF.CoreRegisters.tryFindLayout machine cls flags

  static let coreLayout machine cls =
    match coreLayoutOf machine cls 0u with
    | Some layout -> layout
    | None -> Assert.Fail $"No core register layout for {machine}."; [||]

  static let parseFile fileName =
    let bytes = ZIPReader.readBytes ELFBinary (fileName + ".zip") fileName
    ELFBinFile(fileName, bytes, None, None)

  /// A non-PIE, dynamically-linked x86-64 executable (ET_EXEC). It is the
  /// canonical x64 fixture and is reused by the address-space tests, so it
  /// carries an executable .text, a read-only .rodata, and a NOBITS .bss.
  static let x64ExecFile = parseFile "elf_x64_exec"

  /// A position-independent x86-64 executable (ET_DYN carrying DT_DEBUG), the
  /// counterpart to the fixed-base elf_x64_exec.
  static let x64PieFile = parseFile "elf_x64_pie"

  /// elf_x64_pie loaded at an explicit base address, so that base-relative
  /// relocations must account for the load base rather than assume zero.
  static let x64PieRebasedFile =
    let fileName = "elf_x64_pie"
    let bytes = ZIPReader.readBytes ELFBinary (fileName + ".zip") fileName
    ELFBinFile(fileName, bytes, Some 0x400000UL, None)

  /// An x86-64 shared library (ET_DYN without DT_DEBUG and without a
  /// PT_INTERP), exporting a single defined function symbol.
  static let x64SoFile = parseFile "elf_x64_so"

  /// An x86-64 relocatable object file (ET_REL): no program headers, and the
  /// relocation against the external symbol is still present.
  static let x64ObjFile = parseFile "elf_x64_obj"

  /// elf_x64_obj parsed with a register factory, which is what makes its CFI
  /// readable. Being a relocatable object, the begin address of each of its
  /// FDEs comes from a relocation rather than from the section bytes.
  static let x64ObjCFIFile =
    let fileName = "elf_x64_obj"
    let bytes = ZIPReader.readBytes ELFBinary (fileName + ".zip") fileName
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    let regFactory = FrontEnd.Intel.RegisterFactory isa :> IRegisterFactory
    ELFBinFile(fileName, bytes, None, Some regFactory)

  /// elf_x64_exec with its .symtab stripped: the .dynsym (imports) survives but
  /// static symbols are gone.
  static let x64StrippedFile = parseFile "elf_x64_stripped"

  /// A non-PIE x86-64 executable carrying a variety of dynamic relocations: a
  /// JUMP_SLOT (write), GLOB_DAT entries, and a COPY (__environ).
  static let x64RelocFile = parseFile "elf_x64_reloc"

  /// A PIE x86-64 executable linked with -z pack-relative-relocs, so every
  /// relative relocation is packed into a .relr.dyn bitmap and .rela.dyn holds
  /// none. Its three RELR entries cover all the encodings: a leading address,
  /// a bitmap, and a second bitmap reached only after the cursor skips a full
  /// word of bits.
  static let x64RelrFile = parseFile "elf_x64_relr"

  /// elf_x64_relr loaded at an explicit base address, so that the addends RELR
  /// leaves in the slots it relocates must be taken relative to the load base.
  static let x64RelrRebasedFile =
    let fileName = "elf_x64_relr"
    let bytes = ZIPReader.readBytes ELFBinary (fileName + ".zip") fileName
    ELFBinFile(fileName, bytes, Some 0x400000UL, None)

  /// elf_x64_relr with its section header table removed, leaving PT_DYNAMIC
  /// as the only route to the relocation tables and PT_LOAD as the only route
  /// to the bytes they relocate.
  static let x64NoSecFile = parseFile "elf_x64_nosec"

  /// A section-header-stripped binary linked with --hash-style=sysv, so it
  /// carries DT_HASH rather than DT_GNU_HASH and its nchain word is what
  /// gives the size of the dynamic symbol table.
  static let x64SysvHashFile = parseFile "elf_x64_sysvhash"

  /// An x86-64 executable built with an executable stack (GNU_STACK = RWX), so
  /// NX is reported as disabled.
  static let x64NonXFile = parseFile "elf_x64_nonx"

  /// A statically linked x86-64 executable built around two ifuncs, whose PLT
  /// entries lld puts in .iplt rather than in .plt. Its IRELATIVE relocations
  /// live in .rela.dyn, there being no .rela.plt without a dynamic linker.
  static let x64IpltFile = parseFile "elf_x64_iplt"

  /// elf_x64_exec rewritten to use the extended numbering: e_shnum, e_phnum
  /// and e_shstrndx all carry their escape value, and the initial section
  /// header holds the real ones in sh_size, sh_link and sh_info.
  static let x64XIndexFile = parseFile "elf_x64_xindex"

  /// A relocatable object of 65282 sections, one more than st_shndx can name.
  /// Its high_fn is defined in the last of them, so its symbol carries
  /// SHN_XINDEX and a .symtab_shndx entry holds the number itself.
  static let x64ShndxFile = parseFile "elf_x64_shndx"

  /// An x86-64 executable carrying a colon-separated DT_RUNPATH (the modern
  /// runtime search-path tag, emitted with --enable-new-dtags).
  static let x64RunPathFile = parseFile "elf_x64_runpath"

  /// An x86-64 executable carrying a colon-separated legacy DT_RPATH instead of
  /// DT_RUNPATH (emitted with --disable-new-dtags).
  static let x64RPathFile = parseFile "elf_x64_rpath"

  /// An x86-64 shared library carrying a DT_SONAME, the name it announces to
  /// whatever links against it, beside the DT_NEEDED naming the one library
  /// it needs of its own.
  static let x64SonameFile = parseFile "elf_x64_soname"

  /// Parses a C++ binary with try/catch, so it carries DWARF CFI in .eh_frame
  /// and an LSDA table in .gcc_except_table. Exception parsing needs a register
  /// factory. This returns a fresh instance every time, as the laziness tests
  /// must not observe an instance that another test has already forced.
  static let parseEhFrameFile () =
    let fileName = "elf_x64_eh_frame"
    let bytes = ZIPReader.readBytes ELFBinary (fileName + ".zip") fileName
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    let regFactory = FrontEnd.Intel.RegisterFactory isa :> IRegisterFactory
    ELFBinFile(fileName, bytes, None, Some regFactory)

  /// The shared instance of the .eh_frame fixture, for tests that do not care
  /// about which parts of it have already been evaluated.
  static let x64EhFrameFile = parseEhFrameFile ()

  /// A 32-bit Intel (i386) dynamically-linked executable, exercising the ELF32
  /// header and the R_386_* relocation decoding.
  static let x86File = parseFile "elf_x86"

  /// A 32-bit ARM (ARM mode) dynamically-linked executable, exercising the
  /// EM_ARM machine type and the R_ARM_* relocation decoding.
  static let arm32File = parseFile "elf_arm32"

  /// A 32-bit ARM executable compiled in Thumb mode, so its function symbols
  /// carry the Thumb bit (LSB set) in their addresses.
  static let thumbFile = parseFile "elf_thumb"

  /// A C++ ARM binary using try/catch, so its unwinding lives in the
  /// ARM-specific .ARM.exidx/.ARM.extab tables rather than in .eh_frame.
  static let arm32ExidxFile = parseFile "elf_arm32_exidx"

  /// A 64-bit ARM (AArch64) dynamically-linked executable, exercising the
  /// EM_AARCH64 machine type and the R_AARCH64_* relocation decoding.
  static let aarch64File = parseFile "elf_aarch64"

  /// A 32-bit big-endian MIPS executable, exercising big-endian ELF32 decoding
  /// and the MIPS machine type.
  static let mips32File = parseFile "elf_mips32"

  /// The little-endian counterpart of elf_mips32 (mipsel), exercising
  /// little-endian decoding of the same machine type.
  static let mips32leFile = parseFile "elf_mips32_le"

  /// A MIPS32 executable built for the MIPS PLT ABI (-mno-shared -mplt), so it
  /// carries a real .rel.plt with JUMP_SLOT entries instead of the classic
  /// .MIPS.stubs and GOT scheme that the other MIPS fixtures use.
  static let mips32PltFile = parseFile "elf_mips32_plt"

  /// A MIPS32 shared library, whose .rel.dyn holds local R_MIPS_REL32 entries.
  /// Being REL rather than RELA, each addend lives in the slot it relocates.
  static let mips32SoFile = parseFile "elf_mips32_so"

  /// The MIPS64 counterpart of elf_mips32_so. Its n64 r_info packs three
  /// relocation types, R_MIPS_REL32 first, so the primary type is 8 bits wide
  /// rather than the 32 bits an ELF64 file would otherwise use.
  static let mips64SoFile = parseFile "elf_mips64_so"

  /// A RISCV64 PIE, carrying all three dynamic relocation families at once:
  /// RELATIVE, the 64-bit absolute kind, and JUMP_SLOT.
  static let riscv64File = parseFile "elf_riscv64"

  /// A RISCV64 PIE built around an ifunc, so its .rela.plt carries an
  /// R_RISCV_IRELATIVE next to the ordinary JUMP_SLOT. It is the only fixture
  /// whose relocation names a resolver rather than a symbol or a datum.
  static let riscv64IfuncFile = parseFile "elf_riscv64_ifunc"

  /// A PowerPC (32-bit) shared library: RELATIVE, ADDR32, GLOB_DAT, JMP_SLOT.
  static let ppc32SoFile = parseFile "elf_ppc32_so"

  /// A PowerPC64 shared library. EM_PPC64 numbers the kinds it inherits as
  /// PowerPC does, and adds the doubleword ADDR64 on top.
  static let ppc64SoFile = parseFile "elf_ppc64_so"

  /// The ppc64le counterpart of elf_ppc64_so, built for ELFv2. It has no .opd,
  /// and its glink stubs are the branch alone, where the ELFv1 ones above
  /// carry the PLT index with them.
  static let ppc64leSoFile = parseFile "elf_ppc64le_so"

  /// An SH4 shared library: RELATIVE, GLOB_DAT, JMP_SLOT.
  static let sh4SoFile = parseFile "elf_sh4_so"

  /// An S390x PIE: RELATIVE, GLOB_DAT, JMP_SLOT.
  static let s390xFile = parseFile "elf_s390x"

  /// An m68k shared library: RELATIVE, GLOB_DAT, JMP_SLOT.
  static let m68kSoFile = parseFile "elf_m68k_so"

  /// A PA-RISC executable, whose PLT entries are function descriptors filled
  /// by R_PARISC_IPLT rather than by the JUMP_SLOT other targets use.
  static let pariscFile = parseFile "elf_parisc"

  /// A PA-RISC shared library, holding the one relocation across every fixture
  /// whose symbol and addend are both non-zero, plus the PLABEL32 kind that
  /// names a function descriptor instead of the function.
  static let pariscSoFile = parseFile "elf_parisc_so"

  /// A SPARC V9 shared library: RELATIVE, GLOB_DAT, JMP_SLOT. Linked with a
  /// smaller max-page-size, the default one padding it out to a megabyte.
  static let sparc64SoFile = parseFile "elf_sparc64_so"

  /// A 32-bit SPARC shared library, whose machine type is EM_SPARC32PLUS: the
  /// V9 instruction set addressing a 32-bit word. Built without libc, so `ext`
  /// is the whole of its PLT.
  static let sparc32SoFile = parseFile "elf_sparc32_so"

  /// An Alpha shared library: RELATIVE, GLOB_DAT, JMP_SLOT.
  static let alphaSoFile = parseFile "elf_alpha_so"

  /// An AVR relocatable object. AVR is linked statically into firmware, so an
  /// object file is the only place its relocations survive.
  static let avrObjFile = parseFile "elf_avr_obj"

  /// A BPF relocatable object, for the same reason as the AVR one.
  static let bpfObjFile = parseFile "elf_bpf_obj"

  /// A 64-bit big-endian MIPS executable, exercising MIPS/Bit64 decoding.
  static let mips64File = parseFile "elf_mips64"

  /// A core dump of a tiny x86-64 program that ran itself into SIGILL. Its
  /// notes are the only ones reachable through a PT_NOTE segment alone, since
  /// the section headers a core dump carries name none of them.
  static let x64CoreFile = parseFile "elf_x64_core"

  /// Returns the header offsets of every section of a 64-bit little-endian ELF
  /// image.
  static let sectionHeaderOffsets (bytes: byte[]) =
    let shoff = int (System.BitConverter.ToUInt64(bytes, 0x28))
    let shentsize = int (System.BitConverter.ToUInt16(bytes, 0x3a))
    let shnum = int (System.BitConverter.ToUInt16(bytes, 0x3c))
    Array.init shnum (fun i -> shoff + i * shentsize)

  /// Returns the type of the section at the given header offset.
  static let sectionType (bytes: byte[]) hdr =
    System.BitConverter.ToUInt32(bytes, hdr + 4)

  /// Returns the header offsets of every REL/RELA section of a 64-bit
  /// little-endian ELF image.
  static let relocSectionHeaders bytes =
    let isReloc hdr =
      sectionType bytes hdr = 4u (* SHT_RELA *)
      || sectionType bytes hdr = 9u (* SHT_REL *)
    sectionHeaderOffsets bytes |> Array.filter isReloc

  /// Returns the header offset of the first section of the given type.
  static let sectionHeaderOfType bytes typ =
    let hasType hdr = sectionType bytes hdr = typ
    sectionHeaderOffsets bytes |> Array.find hasType

  /// Returns the entry size of the REL/RELA section at the given header.
  static let relocEntrySize bytes hdr =
    if sectionType bytes hdr = 4u then 24 else 16

  static let writeUInt16 (bytes: byte[]) offset (v: uint16) =
    Array.blit (System.BitConverter.GetBytes v) 0 bytes offset 2

  static let writeUInt32 (bytes: byte[]) offset (v: uint32) =
    Array.blit (System.BitConverter.GetBytes v) 0 bytes offset 4

  static let writeUInt64 (bytes: byte[]) offset (v: uint64) =
    Array.blit (System.BitConverter.GetBytes v) 0 bytes offset 8

  static let parsePatchedObjFile patch =
    let bytes = ZIPReader.readBytes ELFBinary "elf_x64_obj.zip" "elf_x64_obj"
    for hdr in relocSectionHeaders bytes do patch bytes hdr
    ELFBinFile("elf_x64_obj", bytes, None, None)

  static let relocFileBytes () =
    ZIPReader.readBytes ELFBinary "elf_x64_reloc.zip" "elf_x64_reloc"

  /// Returns the version info of the dynamic symbol of the given name.
  static let verInfoOf (file: ELFBinFile) name =
    let hasName (s: ELF.Symbol) = s.SymName = name
    (file.Symbols.DynamicSymbols |> Array.find hasName).VerInfo

  /// Returns the index of the dynamic symbol of the given name, which is also
  /// the index of its entry in the symbol version section.
  static let dynamicSymbolIndex (file: ELFBinFile) name =
    let hasName (s: ELF.Symbol) = s.SymName = name
    file.Symbols.DynamicSymbols |> Array.findIndex hasName

  /// Parses elf_x64_reloc after rewriting the raw version value of the
  /// dynamic symbol at the given index.
  static let parseWithPatchedVersion idx patch =
    let bytes = relocFileBytes ()
    let versym = sectionHeaderOfType bytes 0x6fffffffu (* SHT_GNU_versym *)
    let off = int (System.BitConverter.ToUInt64(bytes, versym + 24)) + idx * 2
    writeUInt16 bytes off (patch (System.BitConverter.ToUInt16(bytes, off)))
    ELFBinFile("elf_x64_reloc", bytes, None, None)

  /// Parses the given fixture after moving the first section of the given type
  /// out of the file, so that reading that section fails.
  static let parseWithBrokenSection fileName typ =
    let bytes = ZIPReader.readBytes ELFBinary (fileName + ".zip") fileName
    let sec = sectionHeaderOfType bytes typ
    writeUInt64 bytes (sec + 24) 0xffffffffUL (* sh_offset *)
    ELFBinFile(fileName, bytes, None, None)

  /// Returns the first symbol of the first dynamic symbol table.
  static let firstDynamicSymbol (file: ELFBinFile) =
    file.Symbols.DynamicSymbols[0]

  /// Returns the first static symbol that the address map keeps.
  static let firstMappedSymbol (file: ELFBinFile) =
    file.Symbols.StaticSymbols |> Array.find (fun s -> s.Addr > 0UL)

  /// Asserts that the symbol found at the given address is the added one.
  static let assertAddedName (file: ELFBinFile) addr =
    let name = file.Symbols.TryFindSymbol addr |> Result.map _.SymName
    Assert.AreEqual(Ok "added", name)

  static let glibc225: ELF.SymVerInfo option =
    Some { IsHidden = false; VerName = "GLIBC_2.2.5" }

  /// The one kind a RELR table can hold on x86-64.
  static let x64Relative =
    let value = uint64 ELF.RelocationX64.R_X86_64_RELATIVE
    ELF.RelocationKind(ELF.MachineType.EM_X86_64, value)

  static let x64GlobDat =
    let value = uint64 ELF.RelocationX64.R_X86_64_GLOB_DATA
    ELF.RelocationKind(ELF.MachineType.EM_X86_64, value)

  static let x64JumpSlot =
    let value = uint64 ELF.RelocationX64.R_X86_64_JUMP_SLOT
    ELF.RelocationKind(ELF.MachineType.EM_X86_64, value)

  /// Assembles the ELF32 header of an image of the given machine type, which
  /// is the whole of what the ISA is read from. It stands in wherever no
  /// toolchain to hand builds the machine type in question.
  static let elf32Header endian (machineType: uint16) =
    let bytes = Array.zeroCreate<byte> 0x34
    let isLittle = endian = Endian.Little
    Array.blit [| 0x7fuy; byte 'E'; byte 'L'; byte 'F' |] 0 bytes 0 4
    bytes[4] <- 1uy (* ELFCLASS32 *)
    bytes[5] <- if isLittle then 1uy else 2uy
    bytes[18] <- if isLittle then byte machineType else byte (machineType >>> 8)
    bytes[19] <- if isLittle then byte (machineType >>> 8) else byte machineType
    bytes

  /// No TI toolchain comes with the cross-compilers the fixtures are built
  /// with, so EM_TI_C6000 has to be stated rather than built.
  static let tic6xHeader = elf32Header Endian.Little 0x8cus

  /// A toolchain asked for 32-bit SPARC emits EM_SPARC32PLUS, which the
  /// fixture below carries, so the plain EM_SPARC is stated the same way.
  static let sparcV8Header = elf32Header Endian.Big 0x02us

  let assertExistenceOfReloc (file: ELFBinFile) offset symbolName =
    file.RelocationInfo.Entries
    |> Seq.map (fun reloc -> reloc.RelOffset, reloc.RelSymbol.Value.SymName)
    |> assertExistenceOfPair (offset, symbolName)

  [<TestMethod>]
  member _.``[ELF] x64 exec ISA test``() =
    let isa = (x64ExecFile :> IBinFile).ISA
    Assert.AreEqual(Architecture.Intel, isa.Arch)
    Assert.AreEqual(WordSize.Bit64, isa.WordSize)
    Assert.AreEqual(Endian.Little, isa.Endian)

  [<TestMethod>]
  member _.``[ELF] OS test``() =
    (* The OS/ABI byte of the identification is what names the OS, and every
       System V derivative it can name follows the ABI that Linux stands for
       here. An embedded image names the bare machine instead, which no fixture
       is, so one is made by rewriting that byte alone. *)
    Assert.AreEqual<OS>(OS.Linux, (x64ExecFile :> IBinFile).OS)
    let name = "elf_x64_exec"
    let bytes = ZIPReader.readBytes ELFBinary (name + ".zip") name
    bytes[7] <- byte ELF.OSABI.ELFOSABI_STANDALONE
    let standalone = ELFBinFile(name, bytes, None, None) :> IBinFile
    Assert.AreEqual<OS>(OS.BareMetal, standalone.OS)

  [<TestMethod>]
  member _.``[ELF] x64 exec entry point test``() =
    Assert.AreEqual(Some 0x401080UL, (x64ExecFile :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[ELF] x64 exec file type test``() =
    Assert.AreEqual(ELF.ELFType.ET_EXEC, x64ExecFile.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] x64 exec kind test``() =
    Assert.AreEqual<BinFileKind>(Executable, (x64ExecFile :> IBinFile).Kind)

  [<TestMethod>]
  member _.``[ELF] x64 exec is not PIE test``() =
    Assert.AreEqual<bool>(false, (x64ExecFile :> IBinFile).IsPIE)

  [<TestMethod>]
  member _.``[ELF] x64 exec is not base-relative test``() =
    Assert.AreEqual<bool>(false, (x64ExecFile :> IBinFile).IsBaseRelative)

  [<TestMethod>]
  member _.``[ELF] x64 exec Relro test``() =
    Assert.AreEqual<Relro option>(Some PartialRelro,
                                  (x64ExecFile :> IBinFile).Relro)

  [<TestMethod>]
  member _.``[ELF] x64 exec has no rpath test``() =
    let file = x64ExecFile :> IBinFile
    CollectionAssert.AreEqual([||], file.RPath)
    CollectionAssert.AreEqual([||], file.RunPath)

  [<TestMethod>]
  member _.``[ELF] x64 runpath test``() =
    let file = x64RunPathFile :> IBinFile
    CollectionAssert.AreEqual([| "/opt/lib"; "/usr/local/lib" |], file.RunPath)
    CollectionAssert.AreEqual([||], file.RPath)

  [<TestMethod>]
  member _.``[ELF] x64 rpath test``() =
    let file = x64RPathFile :> IBinFile
    CollectionAssert.AreEqual([| "/opt/lib"; "/usr/local/lib" |], file.RPath)
    CollectionAssert.AreEqual([||], file.RunPath)

  [<TestMethod>]
  member _.``[ELF] x64 rpath array is not shared test``() =
    let file = parseFile "elf_x64_rpath" :> IBinFile
    let rpath = file.RPath
    rpath[0] <- "/mutated"
    CollectionAssert.AreEqual([| "/opt/lib"; "/usr/local/lib" |], file.RPath)
    CollectionAssert.AreEqual([||], file.RunPath)

  [<TestMethod>]
  member _.``[ELF] x64 runpath array is not shared test``() =
    let file = parseFile "elf_x64_runpath" :> IBinFile
    let runpath = file.RunPath
    runpath[0] <- "/mutated"
    CollectionAssert.AreEqual([| "/opt/lib"; "/usr/local/lib" |], file.RunPath)
    CollectionAssert.AreEqual([||], file.RPath)

  [<TestMethod>]
  member _.``[ELF] x64 soname test``() =
    let file = x64SonameFile :> IBinFile
    CollectionAssert.AreEqual([| "libc.so.6" |], file.DependencyNames)
    Assert.AreEqual<string option>(Some "libfoo.so.1", file.SharedObjectName)

  [<TestMethod>]
  member _.``[ELF] x64 exec announces no soname test``() =
    let file = x64ExecFile :> IBinFile
    CollectionAssert.AreEqual([| "libc.so.6" |], file.DependencyNames)
    Assert.AreEqual<string option>(None, file.SharedObjectName)

  [<TestMethod>]
  member _.``[ELF] x64 dependency array is not shared test``() =
    let file = parseFile "elf_x64_soname" :> IBinFile
    let deps = file.DependencyNames
    deps[0] <- "/mutated"
    CollectionAssert.AreEqual([| "libc.so.6" |], file.DependencyNames)

  [<TestMethod>]
  member _.``[ELF] x64 nosec dependencies test``() =
    (* The dynamic string table is the one DT_STRTAB points at, and a file
       whose section headers are gone still says where that is. *)
    let file = x64NoSecFile :> IBinFile
    CollectionAssert.AreEqual([| "libc.so.6" |], file.DependencyNames)

  [<TestMethod>]
  member _.``[ELF] x64 rpath without section headers test``() =
    (* The same route is what the search paths were read by all along, and
       through the section headers they were lost with them. *)
    let fileName = "elf_x64_rpath"
    let bytes = ZIPReader.readBytes ELFBinary (fileName + ".zip") fileName
    for i in 0x28 .. 0x2f do bytes[i] <- 0uy (* e_shoff = 0 *)
    for i in 0x3c .. 0x3f do bytes[i] <- 0uy (* e_shnum, e_shstrndx = 0 *)
    let file = ELFBinFile(fileName, bytes, None, None) :> IBinFile
    CollectionAssert.AreEqual([| "/opt/lib"; "/usr/local/lib" |], file.RPath)

  [<TestMethod>]
  member _.``[ELF] x64 exec notes test``() =
    (* Both a PT_NOTE segment and an SHT_NOTE section name each of these, so
       reading the two without care would report every note twice. *)
    let owners = x64ExecFile.Notes |> Array.map _.NoteOwner
    let types = x64ExecFile.Notes |> Array.map _.NoteType
    CollectionAssert.AreEqual([| "GNU"; "GNU"; "GNU" |], owners)
    CollectionAssert.AreEqual([| 5u; 3u; 1u |], types)

  [<TestMethod>]
  member _.``[ELF] note segment padding test``() =
    (* Alignment can leave zeros between two notes, and a whole note header
       of them reads as a note that names nothing. The second PT_NOTE of the
       fixture is grown by twelve zeroed bytes to put one there. *)
    let fileName = "elf_x64_exec"
    let bytes = ZIPReader.readBytes ELFBinary (fileName + ".zip") fileName
    for i in 0x3ac .. 0x3b7 do bytes[i] <- 0uy
    bytes[0x220] <- 0x50uy (* p_filesz of the second PT_NOTE: 0x44 -> 0x50 *)
    let file = ELFBinFile(fileName, bytes, None, None)
    let types = file.Notes |> Array.map _.NoteType
    CollectionAssert.AreEqual([| 5u; 3u; 1u |], types)

  [<TestMethod>]
  member _.``[ELF] x64 exec build ID test``() =
    let hex = "d231f2fa07d818f5cac8f0ee509cbe73dba57e63"
    let expected = ByteArray.ofHexString hex
    CollectionAssert.AreEqual(expected, (x64ExecFile :> IBinFile).BuildId)

  [<TestMethod>]
  member _.``[ELF] aarch64 build ID test``() =
    let hex = "76cb2d19459e0634717883574e4fe8aa76ecfaa7"
    let expected = ByteArray.ofHexString hex
    CollectionAssert.AreEqual(expected, (aarch64File :> IBinFile).BuildId)

  [<TestMethod>]
  member _.``[ELF] x64 nosec build ID test``() =
    (* A file whose section headers are gone still carries its notes in a
       PT_NOTE segment, which is the route a core dump leaves too. *)
    let hex = "b46382ea0a3a829917d626a31d0ce072d0c36d74"
    let expected = ByteArray.ofHexString hex
    CollectionAssert.AreEqual(expected, (x64NoSecFile :> IBinFile).BuildId)

  [<TestMethod>]
  member _.``[ELF] x64 obj notes test``() =
    (* A relocatable object has no program headers at all, so its one note is
       reachable only through the SHT_NOTE section that holds it. *)
    let types = x64ObjFile.Notes |> Array.map _.NoteType
    CollectionAssert.AreEqual([| 5u |], types)
    CollectionAssert.AreEqual([||], (x64ObjFile :> IBinFile).BuildId)

  [<TestMethod>]
  member _.``[ELF] build ID array is not shared test``() =
    let file = parseFile "elf_x64_exec" :> IBinFile
    let buildId = file.BuildId
    buildId[0] <- 0uy
    Assert.AreEqual<byte>(0xd2uy, file.BuildId[0])

  [<TestMethod>]
  member _.``[ELF] x64 exec GNU property test``() =
    (* The property note records two properties: the x86 feature word, whose
       IBT and SHSTK bits are both set, and the ISA the binary needs. *)
    let props = x64ExecFile.GNUProperties
    let types = props |> Array.map _.PropertyType
    CollectionAssert.AreEqual([| 0xc0000002u; 0xc0008002u |], types)
    Assert.AreEqual<bool>(true, ELF.GNUProperties.hasIBT props)
    Assert.AreEqual<bool>(true, ELF.GNUProperties.hasShadowStack props)
    Assert.AreEqual<bool>(false, ELF.GNUProperties.hasBTI props)
    Assert.AreEqual<bool>(false, ELF.GNUProperties.hasPointerAuth props)

  [<TestMethod>]
  member _.``[ELF] aarch64 has no GNU property test``() =
    let props = aarch64File.GNUProperties
    CollectionAssert.AreEqual([||], props)
    Assert.AreEqual<bool>(false, ELF.GNUProperties.hasBTI props)

  [<TestMethod>]
  member _.``[ELF] x64 core kind test``() =
    Assert.AreEqual<BinFileKind>(Core, (x64CoreFile :> IBinFile).Kind)

  [<TestMethod>]
  member _.``[ELF] x64 core notes test``() =
    (* The dump carries eight notes from three vendors, and the two of them
       that no vendor numbers alike are told apart by their owner. *)
    let owners = x64CoreFile.Notes |> Array.map _.NoteOwner |> Array.distinct
    Assert.AreEqual<int>(8, x64CoreFile.Notes.Length)
    CollectionAssert.AreEqual([| "CORE"; "LINUX"; "GDB" |], owners)

  [<TestMethod>]
  member _.``[ELF] x64 core process status test``() =
    match x64CoreFile.ProcessStatuses with
    | [| status |] ->
      Assert.AreEqual<int>(4, status.CurrentSignal) (* SIGILL *)
      Assert.AreEqual<int>(3405619, status.ProcessID)
      Assert.AreEqual<int>(224, status.RegisterBlock.Length)
    | statuses ->
      Assert.Fail $"Expected one thread state, got {statuses.Length}."

  [<TestMethod>]
  member _.``[ELF] x64 core registers test``() =
    (* Every value here is what gdb reads out of the very same dump, so the
       slot order of the x86-64 layout is checked against a second reader
       rather than against itself. *)
    let status = x64CoreFile.ProcessStatuses[0]
    let regs = status.GeneralRegisters |> Map.ofArray
    Assert.AreEqual<int>(27, status.GeneralRegisters.Length)
    Assert.AreEqual<uint64>(0x555555555044UL, regs["RIP"])
    Assert.AreEqual<uint64>(0x7fffffffd378UL, regs["RSP"])
    Assert.AreEqual<uint64>(0x7fffffffd410UL, regs["RBP"])
    Assert.AreEqual<uint64>(0x555555555040UL, regs["RAX"])
    Assert.AreEqual<uint64>(1UL, regs["RDI"])
    Assert.AreEqual<uint64>(0x203UL, regs["R11"])
    Assert.AreEqual<uint64>(0x33UL, regs["CS"])
    Assert.AreEqual<uint64>(0x2bUL, regs["SS"])
    Assert.AreEqual<uint64>(0x10246UL, regs["EFLAGS"])

  [<TestMethod>]
  member _.``[ELF] core register layout shapes test``() =
    (* One slot count and the program counter of each architecture, taken
       from a dump of that machine that gdb read the same registers out of,
       so that an edit to a table cannot quietly shift a whole machine. *)
    let x86 = coreLayout ELF.MachineType.EM_386 WordSize.Bit32
    let aarch64 = coreLayout ELF.MachineType.EM_AARCH64 WordSize.Bit64
    let arm32 = coreLayout ELF.MachineType.EM_ARM WordSize.Bit32
    let riscv64 = coreLayout ELF.MachineType.EM_RISCV WordSize.Bit64
    Assert.AreEqual<int * string>((17, "EIP"), (x86.Length, fst x86[12]))
    Assert.AreEqual<int * string>((34, "pc"), (aarch64.Length, fst aarch64[32]))
    Assert.AreEqual<int * string>((18, "pc"), (arm32.Length, fst arm32[15]))
    Assert.AreEqual<int * string>((32, "pc"), (riscv64.Length, fst riscv64[0]))

  [<TestMethod>]
  member _.``[ELF] PowerPC core register layout test``() =
    (* Both classes lay the same slots out, the width of a word apart: the
       thirty-two general registers, then pt_regs with the instruction
       address first, then four slots of padding. *)
    let ppc32 = coreLayout ELF.MachineType.EM_PPC WordSize.Bit32
    let ppc64 = coreLayout ELF.MachineType.EM_PPC64 WordSize.Bit64
    Assert.AreEqual<int * string>((48, "iar"), (ppc32.Length, fst ppc32[32]))
    Assert.AreEqual<string>("lr", fst ppc32[36])
    CollectionAssert.AreEqual(Array.map fst ppc32, Array.map fst ppc64)
    Assert.AreEqual<int>(4, snd ppc32[0])
    Assert.AreEqual<int>(8, snd ppc64[0])

  [<TestMethod>]
  member _.``[ELF] s390x core register layout test``() =
    (* The one layout whose slots differ in width: the PSW and the general
       registers are words, the access registers half that. *)
    let s390x = coreLayout ELF.MachineType.EM_S390 WordSize.Bit64
    Assert.AreEqual<int>(35, s390x.Length)
    Assert.AreEqual<string * int>(("PSWAddr", 8), s390x[1])
    Assert.AreEqual<string * int>(("R0", 8), s390x[2])
    Assert.AreEqual<string * int>(("ACR0", 4), s390x[18])
    Assert.AreEqual<string * int>(("OrigR2", 8), s390x[34])

  [<TestMethod>]
  member _.``[ELF] MIPS core register layout test``() =
    (* o32 opens its block with six slots the kernel never sets, so the
       general registers start at six there and at zero under n64. Both
       blocks hold forty-five slots all the same. *)
    let mips32 = coreLayout ELF.MachineType.EM_MIPS WordSize.Bit32
    let mips64 = coreLayout ELF.MachineType.EM_MIPS WordSize.Bit64
    Assert.AreEqual<int * int>((45, 45), (mips32.Length, mips64.Length))
    Assert.AreEqual<string>("", fst mips32[5])
    let starts = fst mips32[6], fst mips64[0]
    let pcs = fst mips32[40], fst mips64[34]
    Assert.AreEqual<string * string>(("r0", "r0"), starts)
    Assert.AreEqual<string * string>(("pc", "pc"), pcs)

  [<TestMethod>]
  member _.``[ELF] SuperH and PA-RISC core register layouts test``() =
    let sh4 = coreLayout ELF.MachineType.EM_SH WordSize.Bit32
    let hppa = coreLayout ELF.MachineType.EM_PARISC WordSize.Bit32
    Assert.AreEqual<int * string>((23, "pc"), (sh4.Length, fst sh4[16]))
    Assert.AreEqual<string>("tra", fst sh4[22])
    Assert.AreEqual<int * string>((80, "flags"), (hppa.Length, fst hppa[0]))
    let spaces = fst hppa[32], fst hppa[40]
    Assert.AreEqual<string * string>(("sr0", "iaoq0"), spaces)

  [<TestMethod>]
  member _.``[ELF] m68k core register layout test``() =
    (* Its data registers open the block with d0 held back to the middle of
       it, and two of the twenty slots are each shared by a pair of
       half-width fields, which is what makes twenty-two entries of eighty
       bytes. *)
    let m68k = coreLayout ELF.MachineType.EM_68K WordSize.Bit32
    let width = m68k |> Array.sumBy snd
    Assert.AreEqual<int * int>((22, 80), (m68k.Length, width))
    Assert.AreEqual<string * int>(("d1", 4), m68k[0])
    Assert.AreEqual<string * int>(("d0", 4), m68k[14])
    Assert.AreEqual<string * int>(("sr", 2), m68k[18])
    Assert.AreEqual<string * int>(("pc", 4), m68k[19])

  [<TestMethod>]
  member _.``[ELF] core register layout widths test``() =
    (* Every layout has to be exactly as wide as the elf_gregset_t of its
       machine, which is what the kernel writes. The sizes here were taken
       from the cross-toolchain headers of each machine, by compiling
       sizeof(elf_gregset_t) rather than by reading a dump. *)
    let widthOf machine cls = coreLayout machine cls |> Array.sumBy snd
    let expected =
      [| ELF.MachineType.EM_X86_64, WordSize.Bit64, 216
         ELF.MachineType.EM_386, WordSize.Bit32, 68
         ELF.MachineType.EM_AARCH64, WordSize.Bit64, 272
         ELF.MachineType.EM_ARM, WordSize.Bit32, 72
         ELF.MachineType.EM_RISCV, WordSize.Bit64, 256
         ELF.MachineType.EM_PPC, WordSize.Bit32, 192
         ELF.MachineType.EM_PPC64, WordSize.Bit64, 384
         ELF.MachineType.EM_S390, WordSize.Bit64, 216
         ELF.MachineType.EM_MIPS, WordSize.Bit32, 180
         ELF.MachineType.EM_MIPS, WordSize.Bit64, 360
         ELF.MachineType.EM_SH, WordSize.Bit32, 92
         ELF.MachineType.EM_PARISC, WordSize.Bit32, 320
         ELF.MachineType.EM_68K, WordSize.Bit32, 80
         ELF.MachineType.EM_ALPHA, WordSize.Bit64, 264
         ELF.MachineType.EM_SPARCV9, WordSize.Bit64, 288 |]
    for machine, cls, width in expected do
      let actual = widthOf machine cls
      Assert.AreEqual<int>(width, actual, $"{machine} gregset width")

  [<TestMethod>]
  member _.``[ELF] Alpha and SPARC core register layouts test``() =
    (* Neither follows the pt_regs order that its ptrace header gives. Alpha
       is rearranged into the numbering order of the ISA before it is
       written, and SPARC writes the four register windows of the trap
       before the trap state. gdb reads both the same way. *)
    let alpha = coreLayout ELF.MachineType.EM_ALPHA WordSize.Bit64
    let sparc = coreLayout ELF.MachineType.EM_SPARCV9 WordSize.Bit64
    let generals = fst alpha[0], fst alpha[30]
    let tail = fst alpha[31], fst alpha[32]
    let globals = fst sparc[0], fst sparc[8]
    let windows = fst sparc[16], fst sparc[24]
    Assert.AreEqual<int>(33, alpha.Length)
    Assert.AreEqual<string * string>(("r0", "r30"), generals)
    Assert.AreEqual<string * string>(("pc", "uniq"), tail)
    Assert.AreEqual<int>(36, sparc.Length)
    Assert.AreEqual<string * string>(("%g0", "%o0"), globals)
    Assert.AreEqual<string * string>(("%l0", "%i0"), windows)
    Assert.AreEqual<string>("pc", fst sparc[33])

  [<TestMethod>]
  member _.``[ELF] prstatus prefix shape test``() =
    (* The fixed prefix of a prstatus note is 112 bytes wide on an ELF64
       machine and 72 on an ELF32 one, except on m68k, which aligns to two
       bytes and so pads none of the fields that the others pad. *)
    let shape machine cls =
      let struct (prefix, pid) = ELF.CoreNotes.prstatusShape machine cls
      prefix, pid
    let x64 = shape ELF.MachineType.EM_X86_64 WordSize.Bit64
    let arm = shape ELF.MachineType.EM_ARM WordSize.Bit32
    let m68k = shape ELF.MachineType.EM_68K WordSize.Bit32
    Assert.AreEqual<int * int>((112, 32), x64)
    Assert.AreEqual<int * int>((72, 24), arm)
    Assert.AreEqual<int * int>((70, 22), m68k)

  [<TestMethod>]
  member _.``[ELF] core register layout is machine specific test``() =
    (* The class has to agree with the machine, an x32 dump being an ELF32
       file of x86-64 registers, and so does the ABI, MIPS n32 putting n64
       registers in an ELF32 file. A machine no layout is known for, 32-bit
       SPARC among them, leaves the raw block as the only record. *)
    let x64 = coreLayoutOf ELF.MachineType.EM_X86_64
    Assert.AreEqual<bool>(true, (x64 WordSize.Bit64 0u).IsSome)
    Assert.AreEqual<bool>(false, (x64 WordSize.Bit32 0u).IsSome)
    let mips = coreLayoutOf ELF.MachineType.EM_MIPS
    Assert.AreEqual<bool>(true, (mips WordSize.Bit32 0u).IsSome)
    Assert.AreEqual<bool>(false, (mips WordSize.Bit32 0x20u).IsSome)
    let sparc32 = coreLayoutOf ELF.MachineType.EM_SPARC
    Assert.AreEqual<bool>(false, (sparc32 WordSize.Bit32 0u).IsSome)

  [<TestMethod>]
  member _.``[ELF] x64 core mappings test``() =
    let mappings = x64CoreFile.CoreMappings
    let paths = mappings |> Array.map _.MappingPath |> Array.distinct
    let expected =
      [| "/home/sangkilc/Develop/B2R2/corevictim"
         "/usr/lib/x86_64-linux-gnu/libc.so.6"
         "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" |]
    Assert.AreEqual<int>(15, mappings.Length)
    CollectionAssert.AreEqual(expected, paths)
    Assert.AreEqual<Addr>(0x555555554000UL, mappings[0].MappingStart)
    Assert.AreEqual<Addr>(0x555555555000UL, mappings[0].MappingEnd)
    Assert.AreEqual<uint64>(0x1000UL, mappings[1].MappingFileOffset)

  [<TestMethod>]
  member _.``[ELF] x64 exec has no core notes test``() =
    CollectionAssert.AreEqual([||], x64ExecFile.CoreMappings)
    CollectionAssert.AreEqual([||], x64ExecFile.ProcessStatuses)

  [<TestMethod>]
  member _.``[ELF] x64 exec base address test``() =
    Assert.AreEqual<uint64>(0UL, (x64ExecFile :> IBinFile).BaseAddress)

  [<TestMethod>]
  member _.``[ELF] x64 exec interpreter path test``() =
    let actual = (x64ExecFile :> IBinFile).InterpreterPath
    Assert.AreEqual<string option>(Some "/lib64/ld-linux-x86-64.so.2", actual)

  [<TestMethod>]
  member _.``[ELF] x64 exec program header table info test``() =
    let file = x64ExecFile :> IBinFile
    let phdr =
      x64ExecFile.ProgramHeaders
      |> Array.find (fun ph -> ph.PHType = ELF.ProgramHeaderType.PT_PHDR)
    match file.ProgramHeaderTable with
    | Some info ->
      Assert.AreEqual<Addr>(phdr.PHAddr, info.Address)
      Assert.AreEqual<int>(int x64ExecFile.Header.PHdrEntrySize, info.EntrySize)
      Assert.AreEqual<int>(x64ExecFile.ProgramHeaders.Length, info.Count)
    | None ->
      Assert.Fail "Expected ELF program header table information."

  [<TestMethod>]
  member _.``[ELF] x64 exec IsNXEnabled test``() =
    Assert.AreEqual<bool>(true, (x64ExecFile :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[ELF] x64 exec IsStripped test``() =
    Assert.AreEqual<bool>(false, isStripped (x64ExecFile :> IBinFile))

  [<TestMethod>]
  member _.``[ELF] x64 exec text section address test``() =
    Assert.AreEqual<uint64>(0x401050UL, getTextSectionAddr x64ExecFile)

  [<TestMethod>]
  member _.``[ELF] x64 exec sections length test``() =
    Assert.AreEqual<int>(31, x64ExecFile.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] x64 exec static symbols length test``() =
    Assert.AreEqual<int>(37, x64ExecFile.Symbols.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] x64 exec dynamic symbols length test``() =
    Assert.AreEqual<int>(4, x64ExecFile.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] x64 exec function symbol test (1)``() =
    assertFuncSymbolExistence x64ExecFile 0x401050UL "main"

  [<TestMethod>]
  member _.``[ELF] x64 exec function symbol test (2)``() =
    assertFuncSymbolExistence x64ExecFile 0x401170UL "helper"

  [<TestMethod>]
  member _.``[ELF] x64 pie entry point test``() =
    Assert.AreEqual(Some 0x1090UL, (x64PieFile :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[ELF] x64 pie file type test``() =
    Assert.AreEqual(ELF.ELFType.ET_DYN, x64PieFile.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] x64 pie kind test``() =
    Assert.AreEqual<BinFileKind>(Executable, (x64PieFile :> IBinFile).Kind)

  [<TestMethod>]
  member _.``[ELF] x64 pie is PIE test``() =
    Assert.AreEqual<bool>(true, (x64PieFile :> IBinFile).IsPIE)

  [<TestMethod>]
  member _.``[ELF] x64 pie is base-relative test``() =
    Assert.AreEqual<bool>(true, (x64PieFile :> IBinFile).IsBaseRelative)

  [<TestMethod>]
  member _.``[ELF] x64 pie Relro test``() =
    Assert.AreEqual<Relro option>(Some FullRelro,
                                  (x64PieFile :> IBinFile).Relro)

  [<TestMethod>]
  member _.``[ELF] x64 so file type test``() =
    Assert.AreEqual(ELF.ELFType.ET_DYN, x64SoFile.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] x64 so kind test``() =
    Assert.AreEqual<BinFileKind>(SharedLibrary, (x64SoFile :> IBinFile).Kind)

  [<TestMethod>]
  member _.``[ELF] x64 so is not PIE test``() =
    Assert.AreEqual<bool>(false, (x64SoFile :> IBinFile).IsPIE)

  [<TestMethod>]
  member _.``[ELF] x64 so is base-relative test``() =
    Assert.AreEqual<bool>(true, (x64SoFile :> IBinFile).IsBaseRelative)

  [<TestMethod>]
  member _.``[ELF] x64 so has no interpreter test``() =
    let actual = (x64SoFile :> IBinFile).InterpreterPath
    Assert.AreEqual<string option>(None, actual)

  [<TestMethod>]
  member _.``[ELF] x64 so exported symbol test``() =
    assertFuncSymbolExistence x64SoFile 0x1100UL "exported_func"

  [<TestMethod>]
  member _.``[ELF] x64 obj file type test``() =
    Assert.AreEqual(ELF.ELFType.ET_REL, x64ObjFile.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] x64 obj kind test``() =
    Assert.AreEqual<BinFileKind>(Object, (x64ObjFile :> IBinFile).Kind)

  [<TestMethod>]
  member _.``[ELF] x64 obj is base-relative test``() =
    Assert.AreEqual<bool>(true, (x64ObjFile :> IBinFile).IsBaseRelative)

  [<TestMethod>]
  member _.``[ELF] x64 obj is not PIE test``() =
    Assert.AreEqual<bool>(false, (x64ObjFile :> IBinFile).IsPIE)

  [<TestMethod>]
  member _.``[ELF] x64 obj Relro test``() =
    Assert.AreEqual<Relro option>(Some NoRelro, (x64ObjFile :> IBinFile).Relro)

  [<TestMethod>]
  member _.``[ELF] x64 obj has no program headers test``() =
    Assert.AreEqual<int>(0, x64ObjFile.ProgramHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] x64 obj has no program header table info test``() =
    let file = x64ObjFile :> IBinFile
    Assert.AreEqual(None, file.ProgramHeaderTable)

  [<TestMethod>]
  member _.``[ELF] x64 exec segments are loadable headers test``() =
    let expected =
      x64ExecFile.ProgramHeaders
      |> Array.filter (fun ph ->
        ph.PHType = ELF.ProgramHeaderType.PT_LOAD && ph.PHMemSize > 0UL)
      |> Array.length
    let actual = (x64ExecFile :> IBinFile).MemoryLayout.Value.Segments.Length
    Assert.AreEqual<int>(expected, actual)

  [<TestMethod>]
  member _.``[ELF] x64 extended numbering counts its tables test``() =
    (* Both counts escape into the initial section header, which is the only
       place the file states them. *)
    let sections = x64ExecFile.SectionHeaders.Length
    let segments = x64ExecFile.ProgramHeaders.Length
    Assert.AreEqual<int>(sections, x64XIndexFile.SectionHeaders.Length)
    Assert.AreEqual<int>(segments, x64XIndexFile.ProgramHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] x64 extended numbering names its sections test``() =
    (* e_shstrndx escapes as well, so the name table is reachable only through
       sh_link of that same header. *)
    let names = x64XIndexFile.SectionHeaders |> Array.map _.SecName
    Assert.AreEqual(true, Array.contains ELF.Section.Text names)

  [<TestMethod>]
  member _.``[ELF] x64 segment count past the file end test``() =
    (* PN_XNUM says the real count sits in the initial section header, and a
       file with no section header table has none to hold it. What is left is
       a count the file has no room for, and no table to be read from. *)
    let fileName = "elf_x64_exec"
    let bytes = ZIPReader.readBytes ELFBinary (fileName + ".zip") fileName
    for i in 0x28 .. 0x2f do bytes[i] <- 0uy (* e_shoff = 0 *)
    for i in 0x3c .. 0x3f do bytes[i] <- 0uy (* e_shnum, e_shstrndx = 0 *)
    bytes[0x38] <- 0xffuy (* e_phnum = PN_XNUM *)
    bytes[0x39] <- 0xffuy
    let file = ELFBinFile(fileName, bytes, None, None)
    Assert.AreEqual<int>(0, file.ProgramHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] x64 extended symbol index test``() =
    (* st_shndx is sixteen bits wide, so a symbol of a section numbered past
       SHN_LORESERVE carries SHN_XINDEX there and leaves the number itself to
       the extended table. A symbol of any other section is unaffected. *)
    let symbols = x64ShndxFile.Symbols.StaticSymbols
    let indexOf name =
      symbols |> Array.find (fun s -> s.SymName = name) |> _.SecHeaderIndex
    Assert.AreEqual(ELF.SectionIndex 0xff01, indexOf "high_fn")
    Assert.AreEqual(ELF.SectionIndex 1, indexOf "low_fn")

  [<TestMethod>]
  member _.``[ELF] x64 extended symbol index names its section test``() =
    (* That index is also what pairs a symbol with the section defining it,
       which is where a relocatable object gets its addresses from. *)
    let symbols = x64ShndxFile.Symbols.StaticSymbols
    let high = symbols |> Array.find (fun s -> s.SymName = "high_fn")
    let name = high.ParentSection |> Option.map _.SecName
    Assert.AreEqual<string option>(Some ".text.high", name)

  [<TestMethod>]
  member _.``[ELF] x64 obj relocation test``() =
    assertExistenceOfReloc x64ObjFile 0x6UL "ext"

  [<TestMethod>]
  member _.``[ELF] bpf obj keeps relocations of equal offset test``() =
    (* .rel.text and .rel.rodata each relocate their own offset zero, which an
       index by offset alone collapses into one entry. *)
    let entries = bpfObjFile.RelocationInfo.Entries
    let atZero =
      entries
      |> Seq.filter (fun r -> r.RelOffset = 0UL)
      |> Seq.map _.RelTargetSecNumber
      |> Seq.toArray
      |> Array.sort
    Assert.AreEqual<int>(5, Seq.length entries)
    CollectionAssert.AreEqual([| 1; 5 |], atZero)

  [<TestMethod>]
  member _.``[ELF] x64 obj relocation lookup is section scoped test``() =
    let secNumOf name =
      x64ObjFile.SectionHeaders
      |> Array.find (fun s -> s.SecName = name)
      |> _.SecNum
    let reloc = x64ObjFile.RelocationInfo
    let ehFrame, text = secNumOf ".eh_frame", secNumOf ".text"
    let notFound = Error ErrorCase.ItemNotFound
    let found secNum offset =
      reloc.TryFindInSection(secNum, offset)
      |> Result.map (fun r -> r.RelTargetSecNumber)
    Assert.AreEqual(Ok ehFrame, found ehFrame 0x20UL)
    Assert.AreEqual(Ok text, found text 0x6UL)
    (* The .text entry sits at an offset the frame section has no entry at. *)
    Assert.AreEqual(notFound, found ehFrame 0x6UL)

  [<TestMethod>]
  member _.``[ELF] x64 obj FDE begins where its relocation says test``() =
    (* .rela.eh_frame relocates the begin address of the sole FDE to .text + 0,
       so leaving it unresolved would leave the offset of the FDE itself. *)
    let fdes =
      x64ObjCFIFile.ExceptionFrame
      |> List.collect (fun cfi -> List.ofArray cfi.FDEs)
    Assert.AreEqual<Addr list>([ 0UL ], fdes |> List.map _.PCBegin)

  [<TestMethod>]
  member _.``[ELF] x64 stripped IsStripped test``() =
    Assert.AreEqual<bool>(true, isStripped (x64StrippedFile :> IBinFile))

  [<TestMethod>]
  member _.``[ELF] x64 stripped static symbols length test``() =
    Assert.AreEqual<int>(0, x64StrippedFile.Symbols.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] x64 stripped dynamic symbols length test``() =
    Assert.AreEqual<int>(4, x64StrippedFile.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] x64 stripped imports are preserved test``() =
    let f = x64StrippedFile :> IBinFile
    let hasWrite =
      getLinkageTableEntries f |> Seq.exists (fun i -> i.Name = "write")
    Assert.AreEqual<bool>(true, hasWrite)

  [<TestMethod>]
  member _.``[ELF] x64 reloc entries test``() =
    assertExistenceOfReloc x64RelocFile 0x404000UL "write"
    assertExistenceOfReloc x64RelocFile 0x404020UL "__environ"

  [<TestMethod>]
  member _.``[ELF] x64 reloc symbol versions test``() =
    (* write, environ and __environ share one version index. *)
    Assert.AreEqual(glibc225, verInfoOf x64RelocFile "write")
    Assert.AreEqual(glibc225, verInfoOf x64RelocFile "environ")
    Assert.AreEqual(glibc225, verInfoOf x64RelocFile "__environ")
    let glibc234: ELF.SymVerInfo option =
      Some { IsHidden = false; VerName = "GLIBC_2.34" }
    Assert.AreEqual(glibc234, verInfoOf x64RelocFile "__libc_start_main")
    let gmon = verInfoOf x64RelocFile "__gmon_start__"
    Assert.AreEqual<ELF.SymVerInfo option>(None, gmon)
    Assert.AreEqual<ELF.SymVerInfo option>(None, verInfoOf x64RelocFile "")

  [<TestMethod>]
  member _.``[ELF] x64 reloc hidden symbol version test``() =
    (* The hidden flag is part of the version value, so hiding one symbol's
       version leaves the other symbols of the same index visible. *)
    let idx = dynamicSymbolIndex x64RelocFile "write"
    let file = parseWithPatchedVersion idx (fun v -> v ||| 0x8000us)
    let hidden: ELF.SymVerInfo option =
      Some { IsHidden = true; VerName = "GLIBC_2.2.5" }
    Assert.AreEqual(hidden, verInfoOf file "write")
    Assert.AreEqual(glibc225, verInfoOf file "environ")

  [<TestMethod>]
  member _.``[ELF] x64 reloc unnamed symbol version test``() =
    let idx = dynamicSymbolIndex x64RelocFile "write"
    let file = parseWithPatchedVersion idx (fun _ -> 0x7ffeus)
    Assert.AreEqual<ELF.SymVerInfo option>(None, verInfoOf file "write")
    Assert.AreEqual(glibc225, verInfoOf file "environ")

  [<TestMethod>]
  member _.``[ELF] x64 reloc reserved symbol versions test``() =
    (* 0 (local) and 1 (global) carry no version. 0x8000 and 0x8001 are not
       excluded by that rule, but their index names no version either. *)
    let idx = dynamicSymbolIndex x64RelocFile "write"
    for raw in [| 0us; 1us; 0x8000us; 0x8001us |] do
      let file = parseWithPatchedVersion idx (fun _ -> raw)
      Assert.AreEqual<ELF.SymVerInfo option>(None, verInfoOf file "write")
      Assert.AreEqual(glibc225, verInfoOf file "environ")

  [<TestMethod>]
  member _.``[ELF] x64 relr section type test``() =
    let isRelr (s: ELF.SectionHeader) =
      s.SecType = ELF.SectionType.SHT_RELR
    let sec = x64RelrFile.SectionHeaders |> Array.find isRelr
    Assert.AreEqual<string>(".relr.dyn", sec.SecName)
    Assert.AreEqual<string>("RELR", ELF.SectionType.toString sec.SecType)

  [<TestMethod>]
  member _.``[ELF] x64 relr dynamic tags test``() =
    let valueOf tag =
      x64RelrFile.DynamicArrayEntries
      |> Array.tryFind (fun e -> e.DTag = tag)
      |> Option.map _.DVal
    Assert.AreEqual(Some 0x600UL, valueOf ELF.DTag.DT_RELR)
    Assert.AreEqual(Some 24UL, valueOf ELF.DTag.DT_RELRSZ)
    Assert.AreEqual(Some 8UL, valueOf ELF.DTag.DT_RELRENT)

  [<TestMethod>]
  member _.``[ELF] x64 relr entries test``() =
    (* Packing moves every relative relocation out of .rela.dyn, so all 39 of
       them can only come from the .relr.dyn bitmap. None names a symbol. *)
    let entries = x64RelrFile.RelocationInfo.Entries |> Seq.toArray
    let relatives = entries |> Array.filter (fun r -> r.RelKind = x64Relative)
    Assert.AreEqual<int>(39, relatives.Length)
    let anonymous = relatives |> Array.forall (fun r -> r.RelSymbol.IsNone)
    Assert.AreEqual<bool>(true, anonymous)

  [<TestMethod>]
  member _.``[ELF] x64 relr implicit addend test``() =
    (* RELR has no addend field: the link-time address already in the slot is
       the addend. These three sites come from the leading address entry, from
       the first bitmap, and from the second bitmap, which the cursor reaches
       only after skipping a whole word of bits. *)
    let addendAt addr =
      x64RelrFile.RelocationInfo.TryFind addr |> Result.map _.RelAddend
    Assert.AreEqual(Ok 0x1140UL, addendAt 0x3c50UL)
    Assert.AreEqual(Ok 0x2012UL, addendAt 0x3d78UL)
    Assert.AreEqual(Ok 0x4008UL, addendAt 0x4008UL)

  [<TestMethod>]
  member _.``[ELF] x64 relr relocated addr test``() =
    let relocs = (x64RelrFile :> IBinFile).Relocations.Value
    Assert.AreEqual<bool>(true, relocs.IsRelocationAddr 0x3c50UL)
    (* A bitmap marks whole words, so the middle of one is not a site. *)
    Assert.AreEqual<bool>(false, relocs.IsRelocationAddr 0x3c54UL)
    Assert.AreEqual(Ok 0x1140UL, relocs.TryGetRelocatedAddr 0x3c50UL)
    Assert.AreEqual(Ok 0x4008UL, relocs.TryGetRelocatedAddr 0x4008UL)

  [<TestMethod>]
  member _.``[ELF] x64 relr rebased test``() =
    (* Both the site and the value it resolves to shift with the load base. *)
    let relocs = (x64RelrRebasedFile :> IBinFile).Relocations.Value
    Assert.AreEqual<bool>(true, relocs.IsRelocationAddr 0x403c50UL)
    Assert.AreEqual(Ok 0x401140UL, relocs.TryGetRelocatedAddr 0x403c50UL)

  [<TestMethod>]
  member _.``[ELF] x64 nosec has no section headers test``() =
    Assert.AreEqual<int>(0, x64NoSecFile.SectionHeaders.Length)

  [<TestMethod>]
  member _.``[ELF] x64 nosec dynamic array test``() =
    (* The .dynamic section is gone, so these come from PT_DYNAMIC. *)
    let entries = x64NoSecFile.DynamicArrayEntries
    let valueOf tag =
      entries |> Array.tryFind (fun e -> e.DTag = tag) |> Option.map _.DVal
    Assert.AreEqual(Some 0x600UL, valueOf ELF.DTag.DT_RELR)
    Assert.AreEqual(Some 0x570UL, valueOf ELF.DTag.DT_RELA)
    Assert.AreEqual(Some 0x5e8UL, valueOf ELF.DTag.DT_JMPREL)
    Assert.AreEqual(Some 24UL, valueOf ELF.DTag.DT_PLTRELSZ)

  [<TestMethod>]
  member _.``[ELF] x64 nosec relocation entries test``() =
    (* DT_RELA, DT_JMPREL and DT_RELR between them name every table the
       section headers named, so stripping them loses no entry. *)
    let stripped = x64NoSecFile.RelocationInfo.Entries |> Seq.length
    let kept = x64RelrFile.RelocationInfo.Entries |> Seq.length
    Assert.AreEqual<int>(45, kept)
    Assert.AreEqual<int>(kept, stripped)

  [<TestMethod>]
  member _.``[ELF] x64 nosec implicit addend test``() =
    (* Without section headers the slot a RELR entry relocates can only be
       found through the loadable segments. *)
    let addendAt addr =
      x64NoSecFile.RelocationInfo.TryFind addr |> Result.map _.RelAddend
    Assert.AreEqual(Ok 0x1140UL, addendAt 0x3c50UL)
    Assert.AreEqual(Ok 0x2012UL, addendAt 0x3d78UL)
    Assert.AreEqual(Ok 0x4008UL, addendAt 0x4008UL)

  [<TestMethod>]
  member _.``[ELF] x64 nosec explicit addend test``() =
    (* DT_PLTREL says whether DT_JMPREL is REL or RELA, and this one is RELA,
       so the JUMP_SLOT below carries its addend in the entry itself. *)
    let kindAt addr =
      x64NoSecFile.RelocationInfo.TryFind addr |> Result.map _.RelKind
    Assert.AreEqual(Ok x64GlobDat, kindAt 0x3fc0UL)
    Assert.AreEqual(Ok x64JumpSlot, kindAt 0x3fb8UL)

  [<TestMethod>]
  member _.``[ELF] x64 nosec dynamic symbols test``() =
    (* DT_SYMTAB and DT_STRTAB name the tables, and the distance between them
       is what bounds the symbol table, as no tag gives its size. *)
    let names = x64NoSecFile.Symbols.DynamicSymbols |> Array.map _.SymName
    let kept = x64RelrFile.Symbols.DynamicSymbols |> Array.map _.SymName
    Assert.AreEqual<int>(7, kept.Length)
    CollectionAssert.AreEqual(kept, names)

  [<TestMethod>]
  member _.``[ELF] x64 nosec relocation symbols test``() =
    let nameAt addr =
      x64NoSecFile.RelocationInfo.TryFind addr
      |> Result.map (fun r -> r.RelSymbol |> Option.map _.SymName)
    Assert.AreEqual(Ok(Some "printf"), nameAt 0x3fb8UL)
    Assert.AreEqual(Ok(Some "__libc_start_main"), nameAt 0x3fc0UL)
    (* A relative relocation names no symbol whichever way it was found. *)
    Assert.AreEqual(Ok None, nameAt 0x3c50UL)

  [<TestMethod>]
  member _.``[ELF] x64 nosec symbol versions test``() =
    (* The version indices come from DT_VERSYM and the names they stand for
       from DT_VERNEED, neither of which a section header has to name. *)
    Assert.AreEqual(glibc225, verInfoOf x64NoSecFile "printf")
    let glibc234: ELF.SymVerInfo option =
      Some { IsHidden = false; VerName = "GLIBC_2.34" }
    Assert.AreEqual(glibc234, verInfoOf x64NoSecFile "__libc_start_main")
    let gmon = verInfoOf x64NoSecFile "__gmon_start__"
    Assert.AreEqual<ELF.SymVerInfo option>(None, gmon)

  [<TestMethod>]
  member _.``[ELF] x64 sysvhash dynamic symbols test``() =
    (* With no DT_GNU_HASH, DT_HASH gives the count in its nchain word. *)
    let symbols = x64SysvHashFile.Symbols.DynamicSymbols
    Assert.AreEqual<int>(7, symbols.Length)
    let names = symbols |> Array.map _.SymName
    Assert.AreEqual<bool>(true, Array.contains "printf" names)

  [<TestMethod>]
  member _.``[ELF] symbol version names are per file test``() =
    (* The same version index names a different version in each file. *)
    Assert.AreEqual(glibc225, verInfoOf x64ExecFile "write")
    let glibc20: ELF.SymVerInfo option =
      Some { IsHidden = false; VerName = "GLIBC_2.0" }
    Assert.AreEqual(glibc20, verInfoOf x86File "write")
    let glibc217: ELF.SymVerInfo option =
      Some { IsHidden = false; VerName = "GLIBC_2.17" }
    Assert.AreEqual(glibc217, verInfoOf aarch64File "write")

  [<TestMethod>]
  member _.``[ELF] x64 obj symbols have no version test``() =
    let versioned =
      x64ObjFile.Symbols.StaticSymbols
      |> Array.exists (fun s -> s.VerInfo.IsSome)
    Assert.AreEqual<bool>(false, versioned)
    Assert.AreEqual<int>(0, x64ObjFile.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] empty symbol table reads no version test``() =
    (* With no symbol to read a version for, the version section is never
       touched, even when its header points outside the file. *)
    let bytes = relocFileBytes ()
    let versym = sectionHeaderOfType bytes 0x6fffffffu (* SHT_GNU_versym *)
    let dynsym = sectionHeaderOfType bytes 11u (* SHT_DYNSYM *)
    writeUInt64 bytes (versym + 24) 0xffffffffUL (* sh_offset *)
    writeUInt64 bytes (dynsym + 32) 0UL (* sh_size *)
    let file = ELFBinFile("elf_x64_reloc", bytes, None, None)
    Assert.AreEqual<int>(0, file.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] broken symtab keeps dynsym readable test``() =
    let file = parseWithBrokenSection "elf_x64_exec" 2u (* SHT_SYMTAB *)
    Assert.AreEqual<int>(4, file.Symbols.DynamicSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] broken dynsym keeps symtab readable test``() =
    let file = parseWithBrokenSection "elf_x64_exec" 11u (* SHT_DYNSYM *)
    Assert.AreEqual<int>(37, file.Symbols.StaticSymbols.Length)

  [<TestMethod>]
  member _.``[ELF] unknown symbol table lookup reads nothing test``() =
    let file = parseWithBrokenSection "elf_x64_exec" 2u (* SHT_SYMTAB *)
    let found = file.Symbols.TryFindSymbolTable 0xffff
    Assert.AreEqual(Error ErrorCase.ItemNotFound, found)

  [<TestMethod>]
  member _.``[ELF] symbol map ignores the evaluation order test``() =
    let resolveAll (file: ELFBinFile) =
      Array.append file.Symbols.StaticSymbols file.Symbols.DynamicSymbols
      |> Array.map (fun s -> s.Addr)
      |> Array.distinct
      |> Array.map (fun addr ->
        let name = file.Symbols.TryFindSymbol addr |> Result.map _.SymName
        addr, name)
    let staticFirst = parseFile "elf_x64_exec"
    staticFirst.Symbols.StaticSymbols |> ignore
    staticFirst.Symbols.DynamicSymbols |> ignore
    let dynamicFirst = parseFile "elf_x64_exec"
    dynamicFirst.Symbols.DynamicSymbols |> ignore
    dynamicFirst.Symbols.StaticSymbols |> ignore
    CollectionAssert.AreEqual(resolveAll staticFirst, resolveAll dynamicFirst)

  [<TestMethod>]
  member _.``[ELF] arm32 mapping symbols mark the encoding test``() =
    let markers = markersOf arm32File
    Assert.AreEqual(Some ArmMode, Map.tryFind 0x10388UL markers)
    Assert.AreEqual(Some ThumbMode, Map.tryFind 0x10354UL markers)
    Assert.AreEqual(Some DataMode, Map.tryFind 0x10194UL markers)

  [<TestMethod>]
  member _.``[ELF] aarch64 mapping symbols mark the encoding test``() =
    let markers = markersOf aarch64File
    Assert.AreEqual(Some A64Mode, Map.tryFind 0x4005c0UL markers)
    Assert.AreEqual(Some DataMode, Map.tryFind 0x400278UL markers)

  [<TestMethod>]
  member _.``[ELF] x64 carries no mapping symbols test``() =
    Assert.AreEqual<int>(0, (markersOf x64ExecFile).Count)

  [<TestMethod>]
  member _.``[ELF] suffixed mapping symbols are read test``() =
    (* A producer may name each region distinctly, as LLVM does. *)
    let parse = ELF.MappingSymbol.parse ELF.MachineType.EM_AARCH64
    Assert.AreEqual(ELF.MappingSymbol.A64, parse "$x.2")
    Assert.AreEqual(ELF.MappingSymbol.Data, parse "$d.realdata")
    Assert.AreEqual(ELF.MappingSymbol.None, parse "$data")
    Assert.AreEqual(ELF.MappingSymbol.None, parse "$t")

  [<TestMethod>]
  member _.``[ELF] adding a symbol reads no symbol table test``() =
    let file = parseWithBrokenSection "elf_x64_exec" 2u (* SHT_SYMTAB *)
    let sym = { firstDynamicSymbol file with SymName = "added" }
    file.Symbols.AddSymbol(0x1234UL, sym)
    assertAddedName file 0x1234UL

  [<TestMethod>]
  member _.``[ELF] added symbol wins over the original symbol test``() =
    let before = parseFile "elf_x64_exec"
    let orig = firstMappedSymbol before
    before.Symbols.AddSymbol(orig.Addr, { orig with SymName = "added" })
    assertAddedName before orig.Addr
    let after = parseFile "elf_x64_exec"
    after.Symbols.TryFindSymbol orig.Addr |> ignore (* builds the map *)
    after.Symbols.AddSymbol(orig.Addr, { orig with SymName = "added" })
    assertAddedName after orig.Addr

  [<TestMethod>]
  member _.``[ELF] the last added symbol wins test``() =
    let file = parseFile "elf_x64_exec"
    let orig = firstMappedSymbol file
    file.Symbols.AddSymbol(orig.Addr, { orig with SymName = "first" })
    file.Symbols.AddSymbol(orig.Addr, { orig with SymName = "added" })
    assertAddedName file orig.Addr

  [<TestMethod>]
  member _.``[ELF] added symbol at address zero is kept test``() =
    let file = parseFile "elf_x64_exec"
    let orig = firstMappedSymbol file
    file.Symbols.AddSymbol(0UL, { orig with SymName = "added" })
    assertAddedName file 0UL

  [<TestMethod>]
  member _.``[ELF] added symbol stays out of the symbol tables test``() =
    let file = parseFile "elf_x64_exec"
    let orig = firstMappedSymbol file
    file.Symbols.AddSymbol(orig.Addr, { orig with SymName = "added" })
    let inTables =
      Array.append file.Symbols.StaticSymbols file.Symbols.DynamicSymbols
      |> Array.exists (fun s -> s.SymName = "added")
    Assert.AreEqual<bool>(false, inTables)

  [<TestMethod>]
  member _.``[ELF] broken symtab keeps the PLT readable test``() =
    let file = parseWithBrokenSection "elf_x64_exec" 2u (* SHT_SYMTAB *)
    let entries = getLinkageTableEntries (file :> IBinFile)
    let hasWrite = entries |> Seq.exists (fun i -> i.Name = "write")
    Assert.AreEqual<bool>(true, hasWrite)

  [<TestMethod>]
  member _.``[ELF] x64 obj reloc without a symbol table test``() =
    (* sh_link now names SHT_NULL, so the section has no symbol table. *)
    let patch bytes hdr = writeUInt32 bytes (hdr + 40) 0u
    let file = parsePatchedObjFile patch
    let entries = file.RelocationInfo.Entries |> Seq.toArray
    Assert.AreEqual<bool>(true, entries.Length > 0)
    let unresolved = entries |> Array.forall (fun r -> r.RelSymbol.IsNone)
    Assert.AreEqual<bool>(true, unresolved)

  [<TestMethod>]
  member _.``[ELF] x64 obj reloc with an out-of-range symbol test``() =
    (* The symbol index sits in the upper half of r_info on 64-bit ELF. *)
    let patch bytes hdr =
      let secOff = int (System.BitConverter.ToUInt64(bytes, hdr + 24))
      let secSize = int (System.BitConverter.ToUInt64(bytes, hdr + 32))
      let entSize = relocEntrySize bytes hdr
      for i in 0 .. secSize / entSize - 1 do
        writeUInt32 bytes (secOff + i * entSize + 12) 0xffffffu
    let file = parsePatchedObjFile patch
    let entries = file.RelocationInfo.Entries |> Seq.toArray
    Assert.AreEqual<bool>(true, entries.Length > 0)
    let unresolved = entries |> Array.forall (fun r -> r.RelSymbol.IsNone)
    Assert.AreEqual<bool>(true, unresolved)

  [<TestMethod>]
  member _.``[ELF] x64 reloc IsRelocationAddr test``() =
    let relocs = (x64RelocFile :> IBinFile).Relocations.Value
    Assert.AreEqual<bool>(true, relocs.IsRelocationAddr 0x404000UL)
    Assert.AreEqual<bool>(true, relocs.IsRelocationAddr 0x404020UL)
    Assert.AreEqual<bool>(false, relocs.IsRelocationAddr 0x404008UL)

  [<TestMethod>]
  member _.``[ELF] x64 reloc JUMP_SLOT resolves to symbol address test``() =
    (* write is an undefined import, so its symbol address resolves to 0. *)
    let relocs = (x64RelocFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x404000UL)

  [<TestMethod>]
  member _.``[ELF] x64 reloc GLOB_DAT resolves to symbol address test``() =
    (* __libc_start_main is an undefined import, so it resolves to 0. *)
    let relocs = (x64RelocFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x403fd8UL)

  [<TestMethod>]
  member _.``[ELF] x64 pie RELATIVE resolves to base plus addend test``() =
    let relocs = (x64PieFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x1170UL, relocs.TryGetRelocatedAddr 0x3db8UL)
    Assert.AreEqual(Ok 0x1130UL, relocs.TryGetRelocatedAddr 0x3dc0UL)
    Assert.AreEqual(Ok 0x4008UL, relocs.TryGetRelocatedAddr 0x4008UL)

  [<TestMethod>]
  member _.``[ELF] x64 pie RELATIVE honors the load base test``() =
    (* The addend is a link-time address, so a non-zero load base must shift
       the resolved target along with it. *)
    let relocs = (x64PieRebasedFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x401170UL, relocs.TryGetRelocatedAddr 0x403db8UL)

  [<TestMethod>]
  member _.``[ELF] aarch64 JUMP_SLOT and GLOB_DAT resolve test``() =
    let relocs = (aarch64File :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x420010UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x41ffd0UL)

  [<TestMethod>]
  member _.``[ELF] mips32 JUMP_SLOT resolves to symbol address test``() =
    (* write and abort are undefined imports, so they resolve to 0. *)
    let relocs = (mips32PltFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x420008UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x42000cUL)

  [<TestMethod>]
  member _.``[ELF] mips32 COPY is not an address relocation test``() =
    let relocs = (mips32PltFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Error ErrorCase.ItemNotFound,
                    relocs.TryGetRelocatedAddr 0x420050UL)

  [<TestMethod>]
  member _.``[ELF] mips32 local REL32 resolves to base plus addend test``() =
    (* A local REL32 names no symbol, so it resolves against the load base,
       taking its addend from the slot it relocates. *)
    let relocs = (mips32SoFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x510UL, relocs.TryGetRelocatedAddr 0x1fff0UL)
    Assert.AreEqual(Ok 0x4a4UL, relocs.TryGetRelocatedAddr 0x1fff4UL)
    Assert.AreEqual(Ok 0x20000UL, relocs.TryGetRelocatedAddr 0x1fff8UL)
    Assert.AreEqual(Ok 0x20004UL, relocs.TryGetRelocatedAddr 0x1fffcUL)
    Assert.AreEqual(Ok 0x20044UL, relocs.TryGetRelocatedAddr 0x20044UL)

  [<TestMethod>]
  member _.``[ELF] mips32 REL entries expose the implicit addend test``() =
    let relocs = (mips32SoFile :> IBinFile).Relocations.Value
    let addends =
      relocs.Relocations
      |> Array.filter (fun r -> r.Address = 0x1fff0UL || r.Address = 0x1fff4UL)
      |> Array.sortBy (fun r -> r.Address)
      |> Array.map (fun r -> r.Addend)
    CollectionAssert.AreEqual([| Some 0x510L; Some 0x4a4L |], addends)

  [<TestMethod>]
  member _.``[ELF] mips64 n64 packed REL32 resolves test``() =
    (* The n64 r_info carries R_MIPS_REL32 alongside R_MIPS_64; reading the
       whole 32-bit type field of a generic ELF64 file would yield neither. *)
    let relocs = (mips64SoFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x7d8UL, relocs.TryGetRelocatedAddr 0x1ffe0UL)
    Assert.AreEqual(Ok 0x768UL, relocs.TryGetRelocatedAddr 0x1ffe8UL)

  [<TestMethod>]
  member _.``[ELF] mips32 REL32 honors the load base test``() =
    let fileName = "elf_mips32_so"
    let bytes = ZIPReader.readBytes ELFBinary (fileName + ".zip") fileName
    let file = ELFBinFile(fileName, bytes, Some 0x400000UL, None)
    let relocs = (file :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x400510UL, relocs.TryGetRelocatedAddr 0x41fff0UL)

  [<TestMethod>]
  member _.``[ELF] riscv64 resolves every relocation family test``() =
    let relocs = (riscv64File :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x672UL, relocs.TryGetRelocatedAddr 0x1da0UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x1fd8UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x1fb8UL)

  [<TestMethod>]
  member _.``[ELF] riscv64 preinit_array names a function test``() =
    (* .preinit_array holds one relocated pointer, to load_gp, which the symbol
       table marks NOTYPE and so reaches the function list by no other path. *)
    let addrs = (riscv64File :> IBinFile).Structure.Value.FunctionAddresses
    Assert.AreEqual(true, Array.contains 0x672UL addrs)

  [<TestMethod>]
  member _.``[ELF] riscv64 imports test``() =
    (* .plt is 0x50 from 0x600, a 32-byte header and three 16-byte stubs. *)
    let expected =
      [ "__libc_start_main", Some 0x620UL
        "abort", Some 0x630UL
        "write", Some 0x640UL ]
    let entries =
      getLinkageTableEntries riscv64File
      |> Seq.map (fun i -> i.Name, i.TrampolineAddress)
      |> Seq.toList
    Assert.AreEqual<(string * Addr option) list>(expected, entries)

  [<TestMethod>]
  member _.``[ELF] s390x imports test``() =
    (* .plt is 0xa0 from 0x638, a 32-byte header and four 32-byte stubs. *)
    let expected =
      [ "__cxa_finalize", Some 0x658UL
        "__libc_start_main", Some 0x678UL
        "write", Some 0x698UL
        "abort", Some 0x6b8UL ]
    let entries =
      getLinkageTableEntries s390xFile
      |> Seq.map (fun i -> i.Name, i.TrampolineAddress)
      |> Seq.toList
    Assert.AreEqual<(string * Addr option) list>(expected, entries)

  [<TestMethod>]
  member _.``[ELF] m68k imports test``() =
    (* .plt is 0x50 from 0x384, a 20-byte header and three 20-byte stubs. *)
    let expected =
      [ "ext", Some 0x398UL
        "__cxa_finalize", Some 0x3acUL
        "__gmon_start__", Some 0x3c0UL ]
    let entries =
      getLinkageTableEntries m68kSoFile
      |> Seq.map (fun i -> i.Name, i.TrampolineAddress)
      |> Seq.toList
    Assert.AreEqual<(string * Addr option) list>(expected, entries)

  [<TestMethod>]
  member _.``[ELF] riscv64 ifunc resolves to its resolver test``() =
    (* resolve_f sits at 0x686, and that is the addend of the IRELATIVE entry
       the loader fills 0x1fd0 with. *)
    let relocs = (riscv64IfuncFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x686UL, relocs.TryGetRelocatedAddr 0x1fd0UL)

  [<TestMethod>]
  member _.``[ELF] riscv64 ifunc is an internal function test``() =
    (* An ifunc names no symbol, so the resolver it points at is reachable
       only through the kind of the relocation itself. *)
    let relocs = (riscv64IfuncFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x686UL, relocs.TryGetInternalFunctionAddr 0x1fd0UL)

  [<TestMethod>]
  member _.``[ELF] riscv64 imported function is not internal test``() =
    (* The JUMP_SLOT beside it names __libc_start_main, which this file does
       not define. *)
    let relocs = (riscv64IfuncFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Error ErrorCase.SymbolNotFound,
                    relocs.TryGetInternalFunctionAddr 0x1fc8UL)

  [<TestMethod>]
  member _.``[ELF] riscv64 ifunc takes a PLT entry of its own test``() =
    (* The PLT has an entry per entry of .rela.plt, the ifunc among them, and
       the import table is how the middle end reaches the resolver behind it.
       Naming no symbol, that entry carries an empty name. *)
    let imports = getLinkageTableEntries riscv64IfuncFile
    let names = imports |> Seq.map _.Name |> Seq.toList
    Assert.AreEqual<string list>([ "__libc_start_main"; "" ], names)
    Assert.AreEqual<uint64>(0x1fd0UL, (Seq.item 1 imports).TableAddress)

  [<TestMethod>]
  member _.``[ELF] x64 iplt entries are imports test``() =
    (* A static ifunc takes its PLT entry in .iplt, which is a PLT section by
       another name, and the slot it relocates is what identifies it. *)
    let expected = [ 0x201340UL, 0x202360UL; 0x201350UL, 0x202368UL ]
    let entries =
      getLinkageTableEntries x64IpltFile
      |> Seq.map (fun i -> Option.get i.TrampolineAddress, i.TableAddress)
      |> Seq.toList
    Assert.AreEqual<(Addr * Addr) list>(expected, entries)

  [<TestMethod>]
  member _.``[ELF] x64 iplt entry spans the whole stub test``() =
    (* An .iplt stub is the 16-byte lazy form, a jump through the slot with a
       push and a branch behind it, and carries no PLT0 header to say so. *)
    let linkage = (x64IpltFile :> IBinFile).ImportTable.Value
    Assert.AreEqual(true, linkage.IsInImportTable 0x20134fUL)
    Assert.AreEqual(false, linkage.IsInImportTable 0x201360UL)

  [<TestMethod>]
  member _.``[ELF] ARM ifunc kinds name a resolver test``() =
    (* No ARM cross-toolchain builds these fixtures, so what can be checked is
       the classification the resolver lookup turns on. *)
    let resolver = ValueSome ELF.RelocationSemantics.IFuncResolver
    let ofARMv7 = ELF.RelocationSemantics.OfARMv7
    let ofARMv8 = ELF.RelocationSemantics.OfARMv8
    Assert.AreEqual(resolver, ofARMv7 ELF.RelocationARMv7.R_ARM_IRELATIVE)
    Assert.AreEqual(resolver, ofARMv8 ELF.RelocationARMv8.R_AARCH64_IRELATIVE)

  [<TestMethod>]
  member _.``[ELF] unsupported relocation arch still names its kind test``() =
    (* The entry parsed; only the name for it is missing, which is no reason
       to fail the file. *)
    let kind = ELF.RelocationKind(ELF.MachineType.EM_TI_C6000, 4UL)
    Assert.AreEqual<string>("RELOC_0x4", RelocKind.ToString kind)

  [<TestMethod>]
  member _.``[ELF] TI C6000 ISA test``() =
    match ELF.Header.getISA tic6xHeader with
    | Ok isa ->
      Assert.AreEqual(Architecture.TMS320C6000, isa.Arch)
      Assert.AreEqual(WordSize.Bit32, isa.WordSize)
    | Error _ ->
      Assert.Fail()

  [<TestMethod>]
  member _.``[ELF] ppc32 resolves every relocation family test``() =
    let relocs = (ppc32SoFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x4d0UL, relocs.TryGetRelocatedAddr 0x1fefcUL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x1ff08UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x1fff0UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x20000UL)

  [<TestMethod>]
  member _.``[ELF] ppc64 resolves RELATIVE and ADDR64 test``() =
    let relocs = (ppc64SoFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x1fed0UL, relocs.TryGetRelocatedAddr 0x1fca8UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x1ff08UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x20018UL)

  [<TestMethod>]
  member _.``[ELF] ppc64 ELFv1 imports test``() =
    (* .plt is NOBITS, so the stubs are the glink ones at DT_PPC64_GLINK + 32,
       eight bytes apart: an index into r0 and a branch to the resolver. *)
    let expected =
      [ "ext", Some 0x85cUL
        "__cxa_finalize", Some 0x864UL
        "__gmon_start__", Some 0x86cUL ]
    let entries =
      getLinkageTableEntries ppc64SoFile
      |> Seq.map (fun i -> i.Name, i.TrampolineAddress)
      |> Seq.toList
    Assert.AreEqual<(string * Addr option) list>(expected, entries)

  [<TestMethod>]
  member _.``[ELF] ppc64 ELFv2 imports test``() =
    (* The same layout, but each stub is the branch alone, so they sit four
       bytes apart and the resolver works the index out for itself. *)
    let expected =
      [ "ext", Some 0x6ccUL
        "__cxa_finalize", Some 0x6d0UL
        "__gmon_start__", Some 0x6d4UL ]
    let entries =
      getLinkageTableEntries ppc64leSoFile
      |> Seq.map (fun i -> i.Name, i.TrampolineAddress)
      |> Seq.toList
    Assert.AreEqual<(string * Addr option) list>(expected, entries)

  [<TestMethod>]
  member _.``[ELF] ppc64 imports name their PLT slots test``() =
    (* The slot an import resolves through is the one its JMP_SLOT relocates,
       which under ELFv1 is 24 bytes wide and under ELFv2 only 8. *)
    let slotsOf f =
      getLinkageTableEntries f |> Seq.map _.TableAddress |> Seq.toList
    Assert.AreEqual<Addr list>([ 0x20018UL; 0x20030UL; 0x20048UL ],
                               slotsOf ppc64SoFile)
    Assert.AreEqual<Addr list>([ 0x20010UL; 0x20018UL; 0x20020UL ],
                               slotsOf ppc64leSoFile)

  [<TestMethod>]
  member _.``[ELF] ppc64le ISA test``() =
    let isa = (ppc64leSoFile :> IBinFile).ISA
    Assert.AreEqual(Architecture.PPC, isa.Arch)
    Assert.AreEqual(WordSize.Bit64, isa.WordSize)
    Assert.AreEqual(Endian.Little, isa.Endian)

  [<TestMethod>]
  member _.``[ELF] sh4 resolves every relocation family test``() =
    let relocs = (sh4SoFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x490UL, relocs.TryGetRelocatedAddr 0x1ff28UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x20024UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x20018UL)

  [<TestMethod>]
  member _.``[ELF] s390x resolves every relocation family test``() =
    let relocs = (s390xFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x800UL, relocs.TryGetRelocatedAddr 0x1d98UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x1fd0UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x1fb0UL)

  [<TestMethod>]
  member _.``[ELF] m68k resolves every relocation family test``() =
    let relocs = (m68kSoFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x494UL, relocs.TryGetRelocatedAddr 0x3f28UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x4018UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x400cUL)

  [<TestMethod>]
  member _.``[ELF] parisc IPLT resolves and COPY does not test``() =
    let relocs = (pariscFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x12028UL)
    Assert.AreEqual(Error ErrorCase.ItemNotFound,
                    relocs.TryGetRelocatedAddr 0x12088UL)

  [<TestMethod>]
  member _.``[ELF] parisc imports test``() =
    (* The stubs sit ahead of _start in .text, and they are in no particular
       order: each names its own descriptor as a GP-relative offset, and only
       the imports that are actually called get one, three of the six here. *)
    let expected =
      [ "abort", Some 0x103e8UL
        "__libc_start_main", Some 0x103fcUL
        "write", Some 0x10410UL ]
    let entries =
      getLinkageTableEntries pariscFile
      |> Seq.map (fun i -> i.Name, i.TrampolineAddress)
      |> Seq.toList
    Assert.AreEqual<(string * Addr option) list>(expected, entries)

  [<TestMethod>]
  member _.``[ELF] parisc imports name their descriptors test``() =
    (* The slot an import goes through is the one its IPLT relocates, which on
       PA-RISC is an eight-byte descriptor rather than a stub of its own. *)
    let slots =
      getLinkageTableEntries pariscFile |> Seq.map _.TableAddress |> Seq.toList
    Assert.AreEqual<Addr list>([ 0x12050UL; 0x12028UL; 0x12040UL ], slots)

  [<TestMethod>]
  member _.``[ELF] parisc so imports test``() =
    (* A position-independent image reaches its GP through r19 rather than the
       r27 of the plain one above, so the stub head reads differently. *)
    let expected =
      [ "__cxa_finalize", Some 0x438UL
        "ext", Some 0x44cUL ]
    let entries =
      getLinkageTableEntries pariscSoFile
      |> Seq.map (fun i -> i.Name, i.TrampolineAddress)
      |> Seq.toList
    Assert.AreEqual<(string * Addr option) list>(expected, entries)

  [<TestMethod>]
  member _.``[ELF] parisc local descriptors are not imports test``() =
    (* Three of the eight IPLT entries name local functions, which are called
       directly and so have no stub for the scan to find. *)
    let names = getLinkageTableEntries pariscSoFile |> Seq.map _.Name
    Assert.AreEqual<bool>(false, Seq.contains "" names)

  [<TestMethod>]
  member _.``[ELF] parisc DIR32 adds the symbol and the addend test``() =
    (* .init sits at 0x41c and the addend is 0x1be8, so this is the one case
       across the fixtures where both halves of S + A are non-zero. *)
    let relocs = (pariscSoFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x2004UL, relocs.TryGetRelocatedAddr 0x1f20UL)

  [<TestMethod>]
  member _.``[ELF] parisc local DIR32 falls back to the base test``() =
    let relocs = (pariscSoFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x1f28UL, relocs.TryGetRelocatedAddr 0x2074UL)

  [<TestMethod>]
  member _.``[ELF] parisc PLABEL32 is not an address relocation test``() =
    let relocs = (pariscSoFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Error ErrorCase.ItemNotFound,
                    relocs.TryGetRelocatedAddr 0x1f14UL)

  [<TestMethod>]
  member _.``[ELF] sparc64 imports test``() =
    (* A SPARC PLT entry is relocated where it stands, so the address a call
       reaches and the one the relocation names are the same. *)
    let expected =
      [ "ext", Some 0x4180UL
        "__cxa_finalize", Some 0x41a0UL
        "__gmon_start__", Some 0x41c0UL ]
    let entries =
      getLinkageTableEntries sparc64SoFile
      |> Seq.map (fun i -> i.Name, i.TrampolineAddress)
      |> Seq.toList
    Assert.AreEqual<(string * Addr option) list>(expected, entries)
    let slots =
      getLinkageTableEntries sparc64SoFile
      |> Seq.map _.TableAddress
      |> Seq.toList
    Assert.AreEqual<Addr list>([ 0x4180UL; 0x41a0UL; 0x41c0UL ], slots)

  [<TestMethod>]
  member _.``[ELF] sparc32 imports test``() =
    (* The 32-bit PLT is laid out the same way, only with shorter entries, and
       this one was linked without a libc so it holds the one import. *)
    let entries =
      getLinkageTableEntries sparc32SoFile
      |> Seq.map (fun i -> i.Name, i.TrampolineAddress)
      |> Seq.toList
    Assert.AreEqual<(string * Addr option) list>([ "ext", Some 0x20034UL ],
                                                 entries)

  [<TestMethod>]
  member _.``[ELF] aliased machine types name one kind test``() =
    (* This header says EM_SPARC32PLUS where elf_sparc64_so says EM_SPARCV9,
       and the two share one set of relocation kinds. Naming every kind by a
       single machine type is what lets one be compared against another. *)
    let jmpSlot = RelocKind.Create ELF.RelocationSPARC.R_SPARC_JMP_SLOT
    let kindsOf (f: ELFBinFile) = f.RelocationInfo.Entries |> Seq.map _.RelKind
    Assert.AreEqual<bool>(true, Seq.contains jmpSlot (kindsOf sparc32SoFile))
    Assert.AreEqual<bool>(true, Seq.contains jmpSlot (kindsOf sparc64SoFile))

  [<TestMethod>]
  member _.``[ELF] sparc32 ISA test``() =
    let isa = (sparc32SoFile :> IBinFile).ISA
    Assert.AreEqual(Architecture.SPARC, isa.Arch)
    Assert.AreEqual(WordSize.Bit32, isa.WordSize)
    Assert.AreEqual(Endian.Big, isa.Endian)

  [<TestMethod>]
  member _.``[ELF] sparc v8 machine type is 32-bit test``() =
    match ELF.Header.getISA sparcV8Header with
    | Ok isa ->
      Assert.AreEqual(Architecture.SPARC, isa.Arch)
      Assert.AreEqual(WordSize.Bit32, isa.WordSize)
    | Error _ ->
      Assert.Fail()

  [<TestMethod>]
  member _.``[ELF] sparc64 resolves every relocation family test``() =
    let relocs = (sparc64SoFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x69cUL, relocs.TryGetRelocatedAddr 0x3e30UL)
    Assert.AreEqual(Ok 0x41e8UL, relocs.TryGetRelocatedAddr 0x3e40UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x4010UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x4180UL)

  [<TestMethod>]
  member _.``[ELF] alpha resolves every relocation family test``() =
    let relocs = (alphaSoFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x5e0UL, relocs.TryGetRelocatedAddr 0x1fe60UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x20018UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x20010UL)

  [<TestMethod>]
  member _.``[ELF] avr resolves the direct kinds only test``() =
    (* Both entries target the .data section symbol, two bytes apart, so the
       gap between the two results is the addend being added to it. *)
    let relocs = (avrObjFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0x38UL, relocs.TryGetRelocatedAddr 0x0UL)
    Assert.AreEqual(Ok 0x3aUL, relocs.TryGetRelocatedAddr 0x2UL)

  [<TestMethod>]
  member _.``[ELF] avr instruction field kinds are unresolved test``() =
    let relocs = (avrObjFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Error ErrorCase.ItemNotFound,
                    relocs.TryGetRelocatedAddr 0xcUL)
    Assert.AreEqual(Error ErrorCase.ItemNotFound,
                    relocs.TryGetRelocatedAddr 0x26UL)

  [<TestMethod>]
  member _.``[ELF] bpf resolves ABS64 only test``() =
    let relocs = (bpfObjFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0xc0UL, relocs.TryGetRelocatedAddr 0x8UL)
    Assert.AreEqual(Error ErrorCase.ItemNotFound,
                    relocs.TryGetRelocatedAddr 0x30UL)
    Assert.AreEqual(Error ErrorCase.ItemNotFound,
                    relocs.TryGetRelocatedAddr 0x78UL)

  [<TestMethod>]
  member _.``[ELF] arm32 JUMP_SLOT and GLOB_DAT resolve test``() =
    let relocs = (arm32File :> IBinFile).Relocations.Value
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x12014UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x1201cUL)

  [<TestMethod>]
  member _.``[ELF] x64 reloc undefined internal function test``() =
    let relocs = (x64RelocFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Error ErrorCase.SymbolNotFound,
                    relocs.TryGetInternalFunctionAddr 0x404000UL)

  [<TestMethod>]
  member _.``[ELF] x64 reloc relocation list test``() =
    let relocs = (parseFile "elf_x64_reloc" :> IBinFile).Relocations.Value
    let toTuple (r: BinRelocation) = r.Address, r.SymbolName, r.Addend
    let expected =
      [| 0x403fd8UL, Some "__libc_start_main", Some 0L
         0x403fe0UL, Some "__gmon_start__", Some 0L
         0x404000UL, Some "write", Some 0L
         0x404020UL, Some "__environ", Some 0L |]
    let first = relocs.Relocations
    let byAddr = first |> Array.map toTuple |> Array.sortBy (fun (a, _, _) -> a)
    CollectionAssert.AreEqual(expected, byAddr)
    CollectionAssert.AreEqual(first, relocs.Relocations)

  [<TestMethod>]
  member _.``[ELF] x64 reloc relocation array is not shared test``() =
    let relocs = (parseFile "elf_x64_reloc" :> IBinFile).Relocations.Value
    let entries = relocs.Relocations
    let expected = Array.copy entries
    entries[0] <- { Address = 0UL; SymbolName = None; Addend = None }
    CollectionAssert.AreEqual(expected, relocs.Relocations)
    Assert.AreEqual<bool>(true, relocs.IsRelocationAddr 0x404000UL)
    Assert.AreEqual(Ok 0UL, relocs.TryGetRelocatedAddr 0x404000UL)

  [<TestMethod>]
  member _.``[ELF] x64 nonx IsNXEnabled test``() =
    Assert.AreEqual<bool>(false, (x64NonXFile :> IBinFile).IsNXEnabled)

  [<TestMethod>]
  member _.``[ELF] x64 exception table is parsed``() =
    let frames = (x64EhFrameFile :> IBinFile).ExceptionTable.Value.Frames
    Assert.AreEqual<bool>(true, frames.Length > 0)

  [<TestMethod>]
  member _.``[ELF] x64 exception frames have sane ranges``() =
    let frames = (x64EhFrameFile :> IBinFile).ExceptionTable.Value.Frames
    let sane =
      frames |> Array.forall (fun f -> f.FunctionEnd >= f.FunctionStart)
    Assert.AreEqual<bool>(true, sane)

  [<TestMethod>]
  member _.``[ELF] x64 exception handler landing pad is resolved``() =
    let frames = (x64EhFrameFile :> IBinFile).ExceptionTable.Value.Frames
    let hasHandler =
      frames |> Array.exists (fun f ->
        f.Handlers |> Array.exists (fun h -> h.Handler.IsSome))
    Assert.AreEqual<bool>(true, hasHandler)

  [<TestMethod>]
  member _.``[ELF] x64 exception frame personality routine is resolved``() =
    (* The zPLR CIE encodes its personality pointer as indirect|pcrel|sdata4,
       so it resolves to the slot that R_X86_64_64 binds to
       __gxx_personality_v0, not to the routine itself. *)
    let frames = (x64EhFrameFile :> IBinFile).ExceptionTable.Value.Frames
    let personalities =
      frames
      |> Array.choose (fun f -> f.PersonalityRoutine)
      |> Array.distinct
    CollectionAssert.AreEqual([| 0x4018UL |], personalities)

  [<TestMethod>]
  member _.``[ELF] x64 frame lookup keeps unwinding unevaluated``() =
    (* An unevaluated FDE also proves that the unified unwinding table stayed
       unevaluated, as building it forces every FDE of the file. *)
    let file = parseEhFrameFile ()
    (file :> IBinFile).ExceptionTable.Value.Frames |> ignore
    let fdes =
      file.ExceptionFrame |> List.collect (fun c -> List.ofArray c.FDEs)
    let forced =
      file.ExceptionFrame
      |> List.exists (fun c -> c.CIE.InitialUnwinding.IsValueCreated)
      || fdes |> List.exists (fun f -> f.UnwindingInfo.IsValueCreated)
    Assert.AreEqual<bool>(false, forced)

  [<TestMethod>]
  member _.``[ELF] x64 forcing one FDE leaves the others unevaluated``() =
    let file = parseEhFrameFile ()
    let cfi = List.head file.ExceptionFrame
    let fdes = cfi.FDEs
    let idx =
      fdes
      |> Array.findIndex (fun f -> not (List.isEmpty f.UnwindingInfo.Value))
    Assert.AreEqual<bool>(true, fdes.Length > idx + 1)
    Assert.AreEqual<bool>(true, cfi.CIE.InitialUnwinding.IsValueCreated)
    let untouched =
      fdes[idx + 1..]
      |> Array.forall (fun f -> not f.UnwindingInfo.IsValueCreated)
    Assert.AreEqual<bool>(true, untouched)

  [<TestMethod>]
  member _.``[ELF] x64 unwinding results are cached``() =
    let file = parseEhFrameFile ()
    let fde = (List.head file.ExceptionFrame).FDEs[0]
    let first = fde.UnwindingInfo.Value
    let second = fde.UnwindingInfo.Value
    Assert.AreEqual<bool>(true, obj.ReferenceEquals(first, second))
    let tbl = file.UnwindingTable
    Assert.AreEqual<bool>(true, obj.ReferenceEquals(tbl, file.UnwindingTable))

  [<TestMethod>]
  member _.``[ELF] x64 unwinding table does not depend on the FDE order``() =
    let file = parseEhFrameFile ()
    for cfi in file.ExceptionFrame do
      for fde in Array.rev cfi.FDEs do
        fde.UnwindingInfo.Value |> ignore
    let expected = x64EhFrameFile.UnwindingTable
    Assert.AreEqual<bool>(true, file.UnwindingTable = expected)

  [<TestMethod>]
  member _.``[ELF] x64 CIE initial unwinding matches the ABI``() =
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    let rsp = DWRegister.toRegID isa 7uy
    let states =
      x64EhFrameFile.ExceptionFrame
      |> List.map (fun cfi -> cfi.CIE.InitialUnwinding.Value)
    Assert.AreEqual<bool>(true, not states.IsEmpty)
    let sane =
      states |> List.forall (fun s ->
        s.CFARegister = 7uy
        && s.CFA = RegPlusOffset(rsp, 8)
        && Map.tryFind ReturnAddress s.Rule = Some(Offset -8L))
    Assert.AreEqual<bool>(true, sane)

  [<TestMethod>]
  member _.``[ELF] x64 unwinding entries start at the function entry``() =
    let starts =
      x64EhFrameFile.ExceptionFrame
      |> List.collect (fun cfi -> List.ofArray cfi.FDEs)
      |> List.choose (fun fde ->
        List.tryHead fde.UnwindingInfo.Value
        |> Option.map (fun e -> fde.PCBegin, e.Location))
    Assert.AreEqual<bool>(true, not starts.IsEmpty)
    Assert.AreEqual<bool>(true, starts |> List.forall (fun (b, l) -> b = l))

  [<TestMethod>]
  member _.``[ELF] arm32 exidx exception table is parsed``() =
    let frames = (arm32ExidxFile :> IBinFile).ExceptionTable.Value.Frames
    Assert.AreEqual<bool>(true, frames.Length > 0)

  [<TestMethod>]
  member _.``[ELF] arm32 exidx frames have sane ranges``() =
    let frames = (arm32ExidxFile :> IBinFile).ExceptionTable.Value.Frames
    let sane =
      frames |> Array.forall (fun f -> f.FunctionEnd >= f.FunctionStart)
    Assert.AreEqual<bool>(true, sane)

  [<TestMethod>]
  member _.``[ELF] arm32 exidx handler landing pad is resolved``() =
    let frames = (arm32ExidxFile :> IBinFile).ExceptionTable.Value.Frames
    let hasHandler =
      frames |> Array.exists (fun f ->
        f.Handlers |> Array.exists (fun h -> h.Handler.IsSome))
    Assert.AreEqual<bool>(true, hasHandler)

  [<TestMethod>]
  member _.``[ELF] arm32 exidx carries no unwinding entries``() =
    let fdes =
      arm32ExidxFile.ExceptionFrame
      |> List.collect (fun cfi -> List.ofArray cfi.FDEs)
    let empty =
      fdes |> List.forall (fun f -> List.isEmpty f.UnwindingInfo.Value)
    Assert.AreEqual<bool>(true, empty)
    Assert.AreEqual<int>(0, Map.count arm32ExidxFile.UnwindingTable)

  [<TestMethod>]
  member _.``[ELF] x86 ISA test``() =
    let isa = (x86File :> IBinFile).ISA
    Assert.AreEqual(Architecture.Intel, isa.Arch)
    Assert.AreEqual(WordSize.Bit32, isa.WordSize)
    Assert.AreEqual(Endian.Little, isa.Endian)

  [<TestMethod>]
  member _.``[ELF] x86 entry point test``() =
    Assert.AreEqual(Some 0x8049090UL, (x86File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[ELF] x86 file type test``() =
    Assert.AreEqual(ELF.ELFType.ET_EXEC, x86File.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] x86 text section address test``() =
    Assert.AreEqual<uint64>(0x8049050UL, getTextSectionAddr x86File)

  [<TestMethod>]
  member _.``[ELF] x86 function symbol test``() =
    assertFuncSymbolExistence x86File 0x8049050UL "main"

  [<TestMethod>]
  member _.``[ELF] x86 relocation test``() =
    assertExistenceOfReloc x86File 0x804c004UL "write"

  [<TestMethod>]
  member _.``[ELF] arm32 ISA test``() =
    let isa = (arm32File :> IBinFile).ISA
    Assert.AreEqual(Architecture.ARMv7, isa.Arch)
    Assert.AreEqual(WordSize.Bit32, isa.WordSize)
    Assert.AreEqual(Endian.Little, isa.Endian)

  [<TestMethod>]
  member _.``[ELF] arm32 entry point test``() =
    Assert.AreEqual(Some 0x10355UL, (arm32File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[ELF] arm32 file type test``() =
    Assert.AreEqual(ELF.ELFType.ET_EXEC, arm32File.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] arm32 text section address test``() =
    Assert.AreEqual<uint64>(0x10330UL, getTextSectionAddr arm32File)

  [<TestMethod>]
  member _.``[ELF] arm32 function symbol test``() =
    assertFuncSymbolExistence arm32File 0x10330UL "main"

  [<TestMethod>]
  member _.``[ELF] arm32 relocation test``() =
    assertExistenceOfReloc arm32File 0x12014UL "write"

  [<TestMethod>]
  member _.``[ELF] thumb ISA test``() =
    let isa = (thumbFile :> IBinFile).ISA
    Assert.AreEqual(Architecture.ARMv7, isa.Arch)
    Assert.AreEqual(WordSize.Bit32, isa.WordSize)
    Assert.AreEqual(Endian.Little, isa.Endian)

  [<TestMethod>]
  member _.``[ELF] thumb entry point test``() =
    Assert.AreEqual(Some 0x10349UL, (thumbFile :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[ELF] thumb file type test``() =
    Assert.AreEqual(ELF.ELFType.ET_EXEC, thumbFile.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] thumb text section address test``() =
    Assert.AreEqual<uint64>(0x10330UL, getTextSectionAddr thumbFile)

  [<TestMethod>]
  member _.``[ELF] thumb function symbol test``() =
    (* Thumb function symbols keep the Thumb bit (LSB) in their value, matching
       the raw ELF symbol, so main resolves at 0x10331. *)
    assertFuncSymbolExistence thumbFile 0x10331UL "main"

  [<TestMethod>]
  member _.``[ELF] thumb relocation test``() =
    assertExistenceOfReloc thumbFile 0x12014UL "write"

  [<TestMethod>]
  member _.``[ELF] aarch64 ISA test``() =
    let isa = (aarch64File :> IBinFile).ISA
    Assert.AreEqual(Architecture.ARMv8, isa.Arch)
    Assert.AreEqual(WordSize.Bit64, isa.WordSize)
    Assert.AreEqual(Endian.Little, isa.Endian)

  [<TestMethod>]
  member _.``[ELF] aarch64 entry point test``() =
    Assert.AreEqual(Some 0x4005c0UL, (aarch64File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[ELF] aarch64 file type test``() =
    Assert.AreEqual(ELF.ELFType.ET_EXEC, aarch64File.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] aarch64 text section address test``() =
    Assert.AreEqual<uint64>(0x400580UL, getTextSectionAddr aarch64File)

  [<TestMethod>]
  member _.``[ELF] aarch64 function symbol test``() =
    assertFuncSymbolExistence aarch64File 0x400580UL "main"

  [<TestMethod>]
  member _.``[ELF] aarch64 relocation test``() =
    assertExistenceOfReloc aarch64File 0x420010UL "write"

  [<TestMethod>]
  member _.``[ELF] mips32 ISA test``() =
    let isa = (mips32File :> IBinFile).ISA
    Assert.AreEqual(Architecture.MIPS, isa.Arch)
    Assert.AreEqual(WordSize.Bit32, isa.WordSize)
    Assert.AreEqual(Endian.Big, isa.Endian)

  [<TestMethod>]
  member _.``[ELF] mips32 unknown ISA flags test``() =
    (* EF_MIPS_ARCH names no architecture above MIPS64R6, and a file claiming
       one is refused the way an unknown machine type is. *)
    let fileName = "elf_mips32"
    let bytes = ZIPReader.readBytes ELFBinary (fileName + ".zip") fileName
    bytes[0x24] <- 0xb0uy (* the top nibble of e_flags, which is big endian *)
    Assert.ThrowsExactly<InvalidISAException>(fun () ->
      ELFBinFile(fileName, bytes, None, None) |> ignore) |> ignore

  [<TestMethod>]
  member _.``[ELF] mips32 entry point test``() =
    Assert.AreEqual(Some 0x400560UL, (mips32File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[ELF] mips32 file type test``() =
    Assert.AreEqual(ELF.ELFType.ET_EXEC, mips32File.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] mips32 text section address test``() =
    Assert.AreEqual<uint64>(0x400520UL, getTextSectionAddr mips32File)

  [<TestMethod>]
  member _.``[ELF] mips32 function symbol test``() =
    assertFuncSymbolExistence mips32File 0x400520UL "main"

  [<TestMethod>]
  member _.``[ELF] mips32_le ISA test``() =
    let isa = (mips32leFile :> IBinFile).ISA
    Assert.AreEqual(Architecture.MIPS, isa.Arch)
    Assert.AreEqual(WordSize.Bit32, isa.WordSize)
    Assert.AreEqual(Endian.Little, isa.Endian)

  [<TestMethod>]
  member _.``[ELF] mips32_le entry point test``() =
    Assert.AreEqual(Some 0x400560UL, (mips32leFile :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[ELF] mips32_le file type test``() =
    Assert.AreEqual(ELF.ELFType.ET_EXEC, mips32leFile.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] mips32_le text section address test``() =
    Assert.AreEqual<uint64>(0x400520UL, getTextSectionAddr mips32leFile)

  [<TestMethod>]
  member _.``[ELF] mips32_le function symbol test``() =
    assertFuncSymbolExistence mips32leFile 0x400520UL "main"

  [<TestMethod>]
  member _.``[ELF] mips64 ISA test``() =
    let isa = (mips64File :> IBinFile).ISA
    Assert.AreEqual(Architecture.MIPS, isa.Arch)
    Assert.AreEqual(WordSize.Bit64, isa.WordSize)
    Assert.AreEqual(Endian.Big, isa.Endian)

  [<TestMethod>]
  member _.``[ELF] mips64 entry point test``() =
    Assert.AreEqual(Some 0x120000900UL, (mips64File :> IBinFile).EntryPoint)

  [<TestMethod>]
  member _.``[ELF] mips64 file type test``() =
    Assert.AreEqual(ELF.ELFType.ET_EXEC, mips64File.Header.ELFType)

  [<TestMethod>]
  member _.``[ELF] mips64 text section address test``() =
    Assert.AreEqual<uint64>(0x1200008b0UL, getTextSectionAddr mips64File)

  [<TestMethod>]
  member _.``[ELF] mips64 function symbol test``() =
    assertFuncSymbolExistence mips64File 0x1200008b0UL "main"

  [<TestMethod>]
  member _.``[ELF] x64 exec valid address test``() =
    let f = x64ExecFile :> IBinFile
    Assert.AreEqual<bool>(true, f.IsValidAddr 0x401050UL) (* .text *)
    Assert.AreEqual<bool>(true, f.IsValidAddr 0x404100UL) (* .bss *)
    Assert.AreEqual<bool>(false, f.IsValidAddr 0x500000UL) (* unmapped *)

  [<TestMethod>]
  member _.``[ELF] x64 exec valid range test``() =
    let f = x64ExecFile :> IBinFile
    let valid: AddrRange = { Min = 0x401050UL; Max = 0x401080UL }
    let invalid: AddrRange = { Min = 0x401050UL; Max = 0x500000UL }
    Assert.AreEqual<bool>(true, f.IsValidRange valid)
    Assert.AreEqual<bool>(false, f.IsValidRange invalid)

  [<TestMethod>]
  member _.``[ELF] x64 exec valid range boundary test``() =
    (* The executable segment spans 0x401000-0x401184, and one past its end
       falls into the gap before the next segment at 0x402000. *)
    let f = x64ExecFile :> IBinFile
    let first: AddrRange = { Min = 0x401000UL; Max = 0x401000UL }
    let last: AddrRange = { Min = 0x401184UL; Max = 0x401184UL }
    let past: AddrRange = { Min = 0x401185UL; Max = 0x401185UL }
    let whole: AddrRange = { Min = 0x401000UL; Max = 0x401184UL }
    Assert.AreEqual<bool>(true, f.IsValidRange first)
    Assert.AreEqual<bool>(true, f.IsValidRange last)
    Assert.AreEqual<bool>(false, f.IsValidRange past)
    Assert.AreEqual<bool>(true, f.IsValidRange whole)

  [<TestMethod>]
  member _.``[ELF] x64 exec valid range across memory gaps test``() =
    (* Both ends are mapped, but the 0x401185-0x401fff gap in between is not,
       so checking only the two end addresses would not be enough. *)
    let f = x64ExecFile :> IBinFile
    let oneGap: AddrRange = { Min = 0x401050UL; Max = 0x402050UL }
    let twoGaps: AddrRange = { Min = 0x400100UL; Max = 0x402050UL }
    Assert.AreEqual<bool>(true, f.IsValidAddr 0x401050UL)
    Assert.AreEqual<bool>(true, f.IsValidAddr 0x402050UL)
    Assert.AreEqual<bool>(false, f.IsValidRange oneGap)
    Assert.AreEqual<bool>(false, f.IsValidRange twoGaps)

  [<TestMethod>]
  member _.``[ELF] x64 exec address mapped to file test``() =
    (* .text is file-backed, but .bss has memsize > filesize, so it is not. *)
    let f = x64ExecFile :> IBinFile
    Assert.AreEqual<bool>(true, f.IsAddrMappedToFile 0x401050UL)
    Assert.AreEqual<bool>(false, f.IsAddrMappedToFile 0x404100UL)

  [<TestMethod>]
  member _.``[ELF] x64 exec range mapped to file test``() =
    (* The last segment carries file data up to 0x404017, and its .bss tail
       (0x404018-0x40413f) exists in memory only. *)
    let f = x64ExecFile :> IBinFile
    let text: AddrRange = { Min = 0x401050UL; Max = 0x401080UL }
    let bss: AddrRange = { Min = 0x404100UL; Max = 0x404120UL }
    let crossing: AddrRange = { Min = 0x404000UL; Max = 0x404100UL }
    Assert.AreEqual<bool>(true, f.IsRangeMappedToFile text)
    Assert.AreEqual<bool>(true, f.IsValidRange bss)
    Assert.AreEqual<bool>(false, f.IsRangeMappedToFile bss)
    Assert.AreEqual<bool>(true, f.IsValidRange crossing)
    Assert.AreEqual<bool>(false, f.IsRangeMappedToFile crossing)

  [<TestMethod>]
  member _.``[ELF] x64 exec name resolution test``() =
    let name addr = tryResolveName x64ExecFile addr
    Assert.AreEqual<Result<string, ErrorCase>>(Ok "main", name 0x401050UL)
    Assert.AreEqual<Result<string, ErrorCase>>(Ok "_start", name 0x401080UL)
    Assert.AreEqual<Result<string, ErrorCase>>(Ok "helper", name 0x401170UL)
    Assert.AreEqual<Result<string, ErrorCase>>(Ok "g_buf", name 0x404040UL)

  [<TestMethod>]
  member _.``[ELF] x64 exec name resolution failure test``() =
    (* An unmapped address, and an address inside a function but not at its
       entry, both resolve to nothing. *)
    let name addr = tryResolveName x64ExecFile addr
    let notFound: Result<string, ErrorCase> = Error ErrorCase.ItemNotFound
    Assert.AreEqual<Result<string, ErrorCase>>(notFound, name 0x500000UL)
    Assert.AreEqual<Result<string, ErrorCase>>(notFound, name 0x401051UL)

  [<TestMethod>]
  member _.``[ELF] x64 exec name resolution via PLT parsing test``() =
    (* The PLT is parsed only after a symbol lookup has missed, and parsing it
       registers the imported symbol at its trampoline address. The entry's
       table address is the GOT slot, not the trampoline, so the first lookup
       still fails while the next one finds the freshly added symbol. This
       starts from a fresh instance, as a shared one may have forced the PLT
       already. *)
    let file = parseFile "elf_x64_exec"
    let notFound: Result<string, ErrorCase> = Error ErrorCase.ItemNotFound
    Assert.AreEqual<Result<string, ErrorCase>>(notFound,
                                               tryResolveName file 0x401040UL)
    Assert.AreEqual<Result<string, ErrorCase>>(Ok "write",
                                               tryResolveName file 0x401040UL)

  [<TestMethod>]
  member _.``[ELF] x64 exec executable address test``() =
    let f = x64ExecFile :> IBinFile
    Assert.AreEqual<bool>(true, f.IsExecutableAddr 0x401050UL) (* .text *)
    Assert.AreEqual<bool>(false, f.IsExecutableAddr 0x402000UL) (* .rodata *)

  [<TestMethod>]
  member _.``[ELF] x64 exec slice maps address to file content test``() =
    let f = x64ExecFile :> IBinFile
    let viaSlice = f.Slice(0x401050UL, 8).ToArray()
    let viaRaw = f.RawBytes.Span.Slice(0x1050, 8).ToArray()
    CollectionAssert.AreEqual(viaRaw, viaSlice)

  [<TestMethod>]
  member _.``[ELF] x64 exec bounded pointer test``() =
    let f = x64ExecFile :> IBinFile
    let p = f.GetBoundedPointer 0x401050UL
    Assert.AreEqual<bool>(false, p.IsNull)
    Assert.AreEqual<bool>(true, p.CanReadFileBytes)

  [<TestMethod>]
  member _.``[ELF] x64 core reads dumped memory test``() =
    (* A core dump maps its memory through PT_LOAD like any other file, so
       what it captured is readable by address. The vDSO is the one mapping
       the dump keeps whole, being anonymous rather than file-backed. *)
    let f = x64CoreFile :> IBinFile
    let magic = f.Slice(0x7ffff7fc3000UL, 4).ToArray()
    CollectionAssert.AreEqual([| 0x7fuy; 0x45uy; 0x4cuy; 0x46uy |], magic)
    Assert.AreEqual<bool>(true, f.IsValidAddr 0x7ffff7fc3000UL)

  [<TestMethod>]
  member _.``[ELF] format detector identifies ELF test``() =
    let bytes = ZIPReader.readBytes ELFBinary "elf_x64_exec.zip" "elf_x64_exec"
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    let struct (fmt, _) = FormatDetector.identify bytes isa
    Assert.AreEqual(ELFBinary, fmt)

  [<TestMethod>]
  member _.``[ELF] format detector falls back to raw test``() =
    let bytes = [| 0uy; 1uy; 2uy; 3uy; 4uy; 5uy; 6uy; 7uy |]
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    let struct (fmt, _) = FormatDetector.identify bytes isa
    Assert.AreEqual(RawBinary, fmt)

  [<TestMethod>]
  member _.``[ELF] file factory load test``() =
    let bytes = ZIPReader.readBytes ELFBinary "elf_x64_exec.zip" "elf_x64_exec"
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    let rf = FrontEnd.Intel.RegisterFactory isa :> IRegisterFactory
    let f = FileFactory.load "" bytes ELFBinary isa rf None
    Assert.AreEqual(ELFBinary, f.Format)
    Assert.AreEqual(WordSize.Bit64, f.ISA.WordSize)

  [<TestMethod>]
  member _.``[ELF] file factory loadELF test``() =
    let bytes = ZIPReader.readBytes ELFBinary "elf_x64_exec.zip" "elf_x64_exec"
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    let rf = FrontEnd.Intel.RegisterFactory isa :> IRegisterFactory
    let f = FileFactory.loadELF "" bytes rf None :> IBinFile
    Assert.AreEqual(ELFBinary, f.Format)

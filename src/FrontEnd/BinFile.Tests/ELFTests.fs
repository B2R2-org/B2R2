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

[<TestClass>]
type ELFTests() =
  static let isStripped (file: IBinFile) = file.SymbolTable.Value.IsStripped

  static let tryResolveName (file: ELFBinFile) addr =
    (file :> IBinFile).NameResolver.Value.TryResolveName addr

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

  /// An x86-64 executable carrying a colon-separated DT_RUNPATH (the modern
  /// runtime search-path tag, emitted with --enable-new-dtags).
  static let x64RunPathFile = parseFile "elf_x64_runpath"

  /// An x86-64 executable carrying a colon-separated legacy DT_RPATH instead of
  /// DT_RUNPATH (emitted with --disable-new-dtags).
  static let x64RPathFile = parseFile "elf_x64_rpath"

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

  /// A PowerPC (32-bit) shared library: RELATIVE, ADDR32, GLOB_DAT, JMP_SLOT.
  static let ppc32SoFile = parseFile "elf_ppc32_so"

  /// A PowerPC64 shared library. EM_PPC64 numbers the kinds it inherits as
  /// PowerPC does, and adds the doubleword ADDR64 on top.
  static let ppc64SoFile = parseFile "elf_ppc64_so"

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

  /// An Alpha shared library: RELATIVE, GLOB_DAT, JMP_SLOT.
  static let alphaSoFile = parseFile "elf_alpha_so"

  /// An AVR relocatable object. AVR is linked statically into firmware, so an
  /// object file is the only place its relocations survive.
  static let avrObjFile = parseFile "elf_avr_obj"

  /// A BPF relocatable object, for the same reason as the AVR one.
  static let bpfObjFile = parseFile "elf_bpf_obj"

  /// A 64-bit big-endian MIPS executable, exercising MIPS/Bit64 decoding.
  static let mips64File = parseFile "elf_mips64"

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
  member _.``[ELF] x64 obj relocation test``() =
    assertExistenceOfReloc x64ObjFile 0x6UL "ext"

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

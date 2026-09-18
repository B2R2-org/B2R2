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

  /// A 64-bit big-endian MIPS executable, exercising MIPS/Bit64 decoding.
  static let mips64File = parseFile "elf_mips64"

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
  member _.``[ELF] x64 reloc GLOB_DAT is unhandled test``() =
    let relocs = (x64RelocFile :> IBinFile).Relocations.Value
    Assert.AreEqual(Error ErrorCase.ItemNotFound,
                    relocs.TryGetRelocatedAddr 0x403fd8UL)

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

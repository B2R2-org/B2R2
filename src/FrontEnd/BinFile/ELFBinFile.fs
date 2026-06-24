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

namespace B2R2.FrontEnd.BinFile

open B2R2
open B2R2.Collections
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.FileHelper
open B2R2.FrontEnd.BinFile.DWARF
open B2R2.FrontEnd.BinFile.ELF
open B2R2.FrontEnd.BinFile.ELF.Helper

/// Represents an ELF binary file.
type ELFBinFile(path, bytes: byte[], baseAddrOpt, rfOpt) =
  let toolBox = Toolbox.Init(bytes, Header.parse baseAddrOpt bytes)
  let hdr = toolBox.Header
  let phdrs = lazy ProgramHeaders.parse toolBox
  let shdrs = lazy SectionHeaders.parse toolBox
  let loadables = lazy ProgramHeaders.filterLoadables phdrs.Value
  let symbs = lazy SymbolStore(toolBox, shdrs.Value)
  let relocs = lazy RelocationInfo(toolBox, shdrs.Value, symbs.Value)
  let plt = lazy PLT.parse toolBox shdrs.Value symbs.Value relocs.Value
  let exn = lazy ExceptionData.parse toolBox shdrs.Value rfOpt relocs.Value
  let notInMemRanges = lazy invalidRangesByVM hdr loadables.Value
  let notInFileRanges = lazy invalidRangesByFileBounds hdr loadables.Value
  let executableRanges = lazy executableRanges shdrs.Value loadables.Value
  let dbginfo = lazy DebugInformation.parse toolBox rfOpt shdrs.Value
  let dynamicArray = lazy DynamicArray.parse toolBox shdrs.Value

  let symKindOf (s: Symbol) =
    match s.SymType with
    | SymbolType.STT_FUNC
    | SymbolType.STT_GNU_IFUNC -> FunctionSymbol
    | SymbolType.STT_OBJECT
    | SymbolType.STT_COMMON
    | SymbolType.STT_TLS -> DataSymbol
    | SymbolType.STT_SECTION -> SectionSymbol
    | SymbolType.STT_FILE -> FileSymbol
    | _ -> OtherSymbol

  let symBindingOf (s: Symbol) =
    match s.Bind with
    | SymbolBind.STB_LOCAL -> LocalBinding
    | SymbolBind.STB_GLOBAL -> GlobalBinding
    | SymbolBind.STB_WEAK -> WeakBinding
    | _ -> UnknownBinding

  let isBindNow dynArr =
    dynArr
    |> Array.exists (fun e ->
      match e.DTag with
      | DTag.DT_BIND_NOW -> true
      | DTag.DT_FLAGS -> e.DVal &&& 0x8UL <> 0UL (* DF_BIND_NOW *)
      | DTag.DT_FLAGS_1 -> e.DVal &&& 0x1UL <> 0UL (* DF_1_NOW *)
      | _ -> false)

  let toBinSymbol (s: Symbol) =
    { Name = s.SymName
      Address = s.Addr
      Kind = symKindOf s
      Binding = symBindingOf s
      IsDefined = Symbol.IsDefined s
      Size = Some s.Size
      LibraryName = s.VerInfo |> Option.map (fun v -> v.VerName) }

  let codeModeMarkers =
    lazy
      symbs.Value.StaticSymbols
      |> Array.choose (fun s ->
        match s.ARMLinkerSymbol with
        | ARMLinkerSymbol.ARM -> Some { Address = s.Addr; Mode = ArmMode }
        | ARMLinkerSymbol.Thumb -> Some { Address = s.Addr; Mode = ThumbMode }
        | ARMLinkerSymbol.Data -> Some { Address = s.Addr; Mode = DataMode }
        | _ -> None)

  let binSymbols =
    lazy
      Array.append symbs.Value.StaticSymbols symbs.Value.DynamicSymbols
      |> Array.map toBinSymbol

  let symbolTableObj =
    { new ISymbolTable with
        member _.IsStripped with get() =
          shdrs.Value |> Array.exists (fun s -> s.SecName = ".symtab") |> not

        member _.Symbols with get() = binSymbols.Value

        member _.TryFindSymbolByAddr addr =
          symbs.Value.TryFindSymbol addr |> Result.map toBinSymbol

        member _.CodeModeMarkers = codeModeMarkers.Value }

  let symbolTable = Some symbolTableObj

  let nameResolver =
    let onSymbols = NameResolver.ofSymbolTable symbolTableObj
    Some { new INameResolvable with
      member _.TryResolveName addr =
        match onSymbols.TryResolveName addr with
        | Ok name -> Ok name
        | Error e ->
          match NoOverlapIntervalMap.tryFindByAddr addr plt.Value with
          | Some entry when entry.TableAddress = addr -> Ok entry.Name
          | _ -> Error e }

  let functionAddrs =
    lazy
      let staticFuncs =
        [| for s in symbs.Value.StaticSymbols do
              if Symbol.IsFunction s && Symbol.IsDefined s then s.Addr
              else () |]
      let dynamicFuncs =
        [| for s in symbs.Value.DynamicSymbols do
              if Symbol.IsFunction s && Symbol.IsDefined s then s.Addr
              else () |]
      let extraFuncs =
        findExtraFnAddrs toolBox shdrs.Value relocs.Value
      Array.concat [| staticFuncs; dynamicFuncs; extraFuncs |]
      |> Array.distinct
      |> Array.sort

  let secFileSize (sec: SectionHeader) =
    if sec.SecType = SectionType.SHT_NOBITS then 0UL else sec.SecSize

  let isDebugSection (sec: SectionHeader) =
    sec.SecName.StartsWith Section.Debug
    || sec.SecName.StartsWith Section.ZDebug

  let secKind (sec: SectionHeader) =
    if PLT.isPLTSectionName sec.SecName then
      DynamicLinkageSection
    elif sec.SecFlags.HasFlag SectionFlags.SHF_EXECINSTR then
      CodeSection
    elif sec.SecFlags.HasFlag SectionFlags.SHF_TLS then
      ThreadLocalStorageSection
    elif sec.SecType = SectionType.SHT_NOBITS then
      UninitializedDataSection
    elif isDebugSection sec then
      DebugSection
    else
      match sec.SecType with
      | SectionType.SHT_PROGBITS
      | SectionType.SHT_INIT_ARRAY
      | SectionType.SHT_FINI_ARRAY
      | SectionType.SHT_PREINIT_ARRAY -> DataSection
      | SectionType.SHT_SYMTAB
      | SectionType.SHT_STRTAB
      | SectionType.SHT_RELA
      | SectionType.SHT_REL
      | SectionType.SHT_HASH
      | SectionType.SHT_DYNAMIC
      | SectionType.SHT_DYNSYM
      | SectionType.SHT_GROUP
      | SectionType.SHT_SYMTAB_SHNDX
      | SectionType.SHT_GNU_ATTRIBUTES
      | SectionType.SHT_GNU_HASH
      | SectionType.SHT_GNU_LIBLIST
      | SectionType.SHT_GNU_verdef
      | SectionType.SHT_GNU_verneed
      | SectionType.SHT_GNU_versym -> MetadataSection
      | _ -> UnknownSection

  let secPermission (sec: SectionHeader) =
    let r = if sec.SecFlags.HasFlag SectionFlags.SHF_ALLOC then 4 else 0
    let w = if sec.SecFlags.HasFlag SectionFlags.SHF_WRITE then 2 else 0
    let x = if sec.SecFlags.HasFlag SectionFlags.SHF_EXECINSTR then 1 else 0
    r ||| w ||| x |> LanguagePrimitives.EnumOfValue

  let toBinSection (sec: SectionHeader) =
    { Name = sec.SecName
      Address = sec.SecAddr
      Size = sec.SecSize
      (* ELF records a nominal file offset even for SHT_NOBITS sections, so we
         keep it; FileSize = 0 indicates the section has no file-backed data. *)
      Offset = Some sec.SecOffset
      FileSize = secFileSize sec
      Permission = secPermission sec
      Kind = secKind sec }

  let tryFindSectionByAddr addr =
    shdrs.Value
    |> Array.tryFind (fun sec ->
      addr >= sec.SecAddr && addr < sec.SecAddr + sec.SecSize)

  let tryFindSectionByOffset (offset: uint32) =
    shdrs.Value
    |> Array.tryFind (fun sec ->
      let fileSize = secFileSize sec
      fileSize > 0UL && uint64 offset >= sec.SecOffset
      && uint64 offset < sec.SecOffset + fileSize)

  let binSections = lazy (shdrs.Value |> Array.map toBinSection)

  let structure =
    Some { new IBinStructure with
      member _.Sections with get() = binSections.Value

      member _.CodeSectionPointer =
        shdrs.Value
        |> Array.tryFind (fun sec -> sec.SecName = Section.Text)
        |> function
          | Some s ->
            BinFilePointer.CreateFileBacked(
              s.SecAddr,
              s.SecAddr + s.SecSize - 1UL,
              int s.SecOffset,
              int s.SecOffset + int s.SecSize - 1)
          | None ->
            BinFilePointer.Null

      member _.GetSectionPointer name =
        shdrs.Value
        |> Array.tryFind (fun sec -> sec.SecName = name)
        |> function
          | Some sec ->
            BinFilePointer.CreateFileBacked(
              sec.SecAddr,
              sec.SecAddr + sec.SecSize - 1UL,
              int sec.SecOffset,
              int sec.SecOffset + int sec.SecSize - 1)
          | None ->
            BinFilePointer.Null

      member _.TryFindSectionByName name =
        shdrs.Value
        |> Array.tryFind (fun sec -> sec.SecName = name)
        |> function
          | Some sec -> Ok(toBinSection sec)
          | None -> Error ErrorCase.ItemNotFound

      member _.TryFindSectionByAddr addr =
        match tryFindSectionByAddr addr with
        | Some sec -> Ok(toBinSection sec)
        | None -> Error ErrorCase.ItemNotFound

      member _.TryFindSectionByOffset offset =
        match tryFindSectionByOffset offset with
        | Some sec -> Ok(toBinSection sec)
        | None -> Error ErrorCase.ItemNotFound

      member _.TryFindSectionNameByAddr addr =
        tryFindSectionByAddr addr
        |> function
          | Some sec -> Ok sec.SecName
          | None -> Error ErrorCase.ItemNotFound

      member _.TryFindSectionNameByOffset offset =
        tryFindSectionByOffset offset
        |> function
          | Some sec -> Ok sec.SecName
          | None -> Error ErrorCase.ItemNotFound

      member _.FunctionAddresses =
        functionAddrs.Value
    }

  let relocations =
    Some { new IRelocationTable with
      member _.Relocations =
        relocs.Value.Entries
        |> Seq.map (fun r ->
          { Address = r.RelOffset
            SymbolName = r.RelSymbol |> Option.map (fun s -> s.SymName)
            Addend = Some(int64 r.RelAddend) })
        |> Seq.toArray

      member _.IsRelocationAddr addr =
        relocs.Value.Contains addr

      member _.TryGetRelocatedAddr relocAddr =
        getRelocatedAddr relocs.Value relocAddr

      member _.TryGetInternalFunctionAddr relocAddr =
        match relocs.Value.TryFind relocAddr with
        | Ok reloc -> tryGetInternalFuncAddr reloc
        | Error e -> Error e
    }

  let toExceptionHandlers (fde: FDE) =
    match fde.LSDAPointer with
    | None -> [||]
    | Some p ->
      match Map.tryFind p exn.Value.LSDATable with
      | None -> [||]
      | Some lsda ->
        lsda.CallSiteTable
        |> List.map (fun cs ->
          { BlockStart = fde.PCBegin + cs.Position
            BlockEnd = fde.PCBegin + cs.Position + cs.Length - 1UL
            Handler =
              if cs.LandingPad = 0UL then None
              else Some(fde.PCBegin + cs.LandingPad) })
        |> List.toArray

  let exceptionFrames =
    lazy
      [| for cfi in exn.Value.ExceptionFrame do
           for fde in cfi.FDEs do
             { FunctionStart = fde.PCBegin
               FunctionEnd = fde.PCEnd - 1UL
               PersonalityRoutine = None
               Handlers = toExceptionHandlers fde } |]

  let exceptionTable =
    Some { new IExceptionTable with
      member _.Frames = exceptionFrames.Value
    }

  let importEntries =
    lazy
      plt.Value
      |> NoOverlapIntervalMap.fold (fun acc _ entry -> entry :: acc) []
      |> List.sortBy (fun entry -> entry.TrampolineAddress)
      |> List.toArray

  let importTable =
    Some { new IImportTable with
      member _.Imports =
        importEntries.Value

      member _.IsInImportTable addr =
        NoOverlapIntervalMap.containsAddr addr plt.Value
    }

  let segments =
    lazy
      phdrs.Value
      |> Array.filter (fun ph ->
        ph.PHType = ProgramHeaderType.PT_LOAD && ph.PHMemSize > 0UL)
      |> Array.map (fun ph ->
        { Name = None
          Address = ph.PHAddr
          Size = ph.PHMemSize
          Offset = ph.PHOffset
          FileSize = ph.PHFileSize
          Permission = ProgramHeader.FlagsToPerm ph.PHFlags })

  let memoryLayout =
    Some { new IMemoryLayout with
      member _.Segments = segments.Value }

  let interpreterPath =
    lazy
      phdrs.Value
      |> Array.tryFind (fun ph -> ph.PHType = ProgramHeaderType.PT_INTERP)
      |> Option.map (fun ph ->
        readCString (System.ReadOnlySpan bytes) (int ph.PHOffset))

  let dynamicPaths tag =
    let isDyn s = s.SecType = SectionType.SHT_DYNAMIC
    match Array.tryFind isDyn shdrs.Value with
    | None -> [||]
    | Some sec ->
      let strOff = int shdrs.Value[int sec.SecLink].SecOffset
      let span = System.ReadOnlySpan bytes
      let offsets =
        dynamicArray.Value
        |> Array.choose (fun e ->
          if e.DTag = tag then Some(strOff + int e.DVal) else None)
      let acc = ResizeArray()
      for off in offsets do
        acc.AddRange((readCString span off).Split(':'))
      acc.ToArray() |> Array.filter (fun s -> s <> "")

  let programHeaderTableAddr =
    lazy
      let phs = phdrs.Value
      let isPhdr p = p.PHType = ProgramHeaderType.PT_PHDR
      match Array.tryFind isPhdr phs with
      | Some p ->
        Some p.PHAddr
      | None ->
        let phoff = hdr.PHdrTblOffset
        let phsize = uint64 hdr.PHdrEntrySize * uint64 hdr.PHdrNum
        let phend = phoff + phsize
        let covers p =
          p.PHType = ProgramHeaderType.PT_LOAD
          && phoff >= p.PHOffset && phend <= p.PHOffset + p.PHFileSize
        Array.tryFind covers phs
        |> Option.map (fun p -> p.PHAddr + (phoff - p.PHOffset))

  let programHeaderTable =
    lazy
      if hdr.PHdrNum = 0us then None
      else
        programHeaderTableAddr.Value
        |> Option.map (fun addr ->
          { Address = addr
            EntrySize = int hdr.PHdrEntrySize
            Count = int hdr.PHdrNum })

  /// ELF Header information.
  member internal _.Header with get() = hdr

  /// List of dynamic section entries.
  member internal _.DynamicArrayEntries with get() = dynamicArray.Value

  /// ELF program headers.
  member internal _.ProgramHeaders with get() = phdrs.Value

  /// ELF section headers.
  member internal _.SectionHeaders with get() = shdrs.Value

  /// Exception information.
  member internal _.ExceptionFrame with get() = exn.Value.ExceptionFrame

  /// LSDA table.
  member internal _.LSDATable with get() = exn.Value.LSDATable

  /// Unwinding table.
  member internal _.UnwindingTable with get() = exn.Value.UnwindingTbl

  /// ELF symbol information.
  member internal _.Symbols with get() = symbs.Value

  /// Relocation information.
  member internal _.RelocationInfo with get() = relocs.Value

  /// Debug information.
  member internal _.DebugInfo with get() = dbginfo.Value

  /// Returns Global Pointer (GP) value when it is known. This is only available
  /// in MIPS binaries.
  member internal _.GlobalPointer with get() =
    match hdr.MachineType with
    | MachineType.EM_MIPS ->
      shdrs.Value
      |> Array.tryFind (fun s -> s.SecName = Section.GOT)
      |> Option.map (fun s -> s.SecAddr + 0x7ff0UL)
    | _ -> None

  /// Try to find a section by its name.
  member internal _.TryFindSection(name: string) =
    shdrs.Value |> Array.tryFind (fun s -> s.SecName = name)

  /// Find a section by its index.
  member internal _.FindSection(idx: int) = shdrs.Value[idx]

  interface IBinFile with
    member _.Reader with get() = toolBox.Reader

    member _.RawBytes with get() = System.ReadOnlyMemory bytes

    member _.Length with get() = bytes.Length

    member _.Path with get() = path

    member _.Format with get() = FileFormat.ELFBinary

    member _.Kind with get() =
      match hdr.ELFType with
      | ELFType.ET_REL -> BinFileKind.Object
      | ELFType.ET_EXEC -> BinFileKind.Executable
      | ELFType.ET_CORE -> BinFileKind.Core
      | ELFType.ET_DYN ->
        let pred e = e.DTag = DTag.DT_DEBUG
        if Array.exists pred dynamicArray.Value then BinFileKind.Executable
        else BinFileKind.SharedLibrary
      | _ -> BinFileKind.Unknown

    member _.ISA with get() = toolBox.ISA

    member _.EntryPoint with get() = Some hdr.EntryPoint

    member _.BaseAddress with get() = toolBox.BaseAddress

    member _.InterpreterPath with get() = interpreterPath.Value

    member _.RPath with get() = dynamicPaths DTag.DT_RPATH

    member _.RunPath with get() = dynamicPaths DTag.DT_RUNPATH

    member _.ProgramHeaderTable with get() =
      programHeaderTable.Value

    member _.IsNXEnabled with get() =
      let predicate e = e.PHType = ProgramHeaderType.PT_GNU_STACK
      match Array.tryFind predicate phdrs.Value with
      | Some s ->
        let perm = ProgramHeader.FlagsToPerm s.PHFlags
        perm.HasFlag Permission.Executable |> not
      | _ -> false

    member _.IsPIE with get() =
      let pred e = e.DTag = DTag.DT_DEBUG
      toolBox.Header.ELFType = ELFType.ET_DYN
      && dynamicArray.Value |> Array.exists pred

    member _.IsBaseRelative with get() =
      let ty = toolBox.Header.ELFType
      ty = ELFType.ET_DYN || ty = ELFType.ET_REL

    member _.Relro with get() =
      let pred e = e.PHType = ProgramHeaderType.PT_GNU_RELRO
      if phdrs.Value |> Array.exists pred then
        if isBindNow dynamicArray.Value then Some FullRelro
        else Some PartialRelro
      else Some NoRelro

    member _.NameResolver with get() = nameResolver

    member _.SymbolTable with get() = symbolTable

    member _.Structure with get() = structure

    member _.Relocations with get() = relocations

    member _.ExceptionTable with get() = exceptionTable

    member _.ImportTable with get() = importTable

    member _.MemoryLayout with get() = memoryLayout

    member this.Slice(addr, len) =
      let ptr = (this :> IAddressSpace).GetBoundedPointer addr
      sliceByPointer bytes ptr len

    member _.IsValidAddr addr =
      IntervalSet.containsAddr addr notInMemRanges.Value |> not

    member _.IsValidRange range =
      IntervalSet.findAll range notInMemRanges.Value |> List.isEmpty

    member _.IsAddrMappedToFile addr =
      IntervalSet.containsAddr addr notInFileRanges.Value |> not

    member _.IsRangeMappedToFile range =
      IntervalSet.findAll range notInFileRanges.Value |> List.isEmpty

    member _.IsExecutableAddr addr =
      IntervalSet.containsAddr addr executableRanges.Value

    member _.GetBoundedPointer addr =
      if Array.isEmpty loadables.Value then
        getBoundedPtrBySections shdrs.Value addr
      else
        let phdrs = phdrs.Value
        let mutable found = false
        let mutable idx = 0
        let mutable maxAddr = 0UL
        let mutable offset = 0
        let mutable maxOffset = 0
        while not found && idx < phdrs.Length do
          let ph = phdrs[idx]
          if addr >= ph.PHAddr && addr < ph.PHAddr + ph.PHMemSize then
            found <- true
            maxOffset <- int ph.PHOffset + int ph.PHFileSize - 1
            if addr < ph.PHAddr + ph.PHFileSize then
              offset <- int ph.PHOffset + int (addr - ph.PHAddr)
              maxAddr <- ph.PHAddr + ph.PHFileSize - 1UL
            else
              offset <- maxOffset + 1
              maxAddr <- ph.PHAddr + ph.PHMemSize - 1UL
          else idx <- idx + 1
        if found then
          if offset > maxOffset then BinFilePointer.CreateVirtual(addr, maxAddr)
          else BinFilePointer.CreateFileBacked(addr, maxAddr, offset, maxOffset)
        else
          BinFilePointer.Null

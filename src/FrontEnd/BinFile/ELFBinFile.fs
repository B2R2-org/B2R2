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

  let nameResolver =
    Some { new INameResolvable with
      member _.TryFindName addr =
        symbs.Value.TryFindSymbol addr
        |> Result.map (fun s -> s.SymName)
        |> function
          | Ok name -> Ok name
          | Error e ->
            match NoOverlapIntervalMap.tryFindByAddr addr plt.Value with
            | Some entry when entry.TableAddress = addr -> Ok entry.FuncName
            | _ -> Error e
    }

  let symbolMetadata =
    Some { new ISymbolMetadata with
      member _.IsStripped with get() =
        shdrs.Value |> Array.exists (fun s -> s.SecName = ".symtab") |> not
    }

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
      |> Set.ofArray
      |> Set.toArray

  let secFileSize (sec: SectionHeader) =
    if sec.SecType = SectionType.SHT_NOBITS then 0UL else sec.SecSize

  let isDebugSection (sec: SectionHeader) =
    sec.SecName.StartsWith Section.Debug
    || sec.SecName.StartsWith Section.ZDebug

  let secKind (sec: SectionHeader) =
    if sec.SecFlags.HasFlag SectionFlags.SHF_EXECINSTR then
      BinSectionKind.Code
    elif sec.SecFlags.HasFlag SectionFlags.SHF_TLS then
      BinSectionKind.ThreadLocalStorage
    elif sec.SecType = SectionType.SHT_NOBITS then
      BinSectionKind.UninitializedData
    elif isDebugSection sec then
      BinSectionKind.Debug
    else
      match sec.SecType with
      | SectionType.SHT_PROGBITS
      | SectionType.SHT_INIT_ARRAY
      | SectionType.SHT_FINI_ARRAY
      | SectionType.SHT_PREINIT_ARRAY -> BinSectionKind.Data
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
      | SectionType.SHT_GNU_versym -> BinSectionKind.Metadata
      | _ -> BinSectionKind.Unknown

  let secPermission (sec: SectionHeader) =
    let r = if sec.SecFlags.HasFlag SectionFlags.SHF_ALLOC then 4 else 0
    let w = if sec.SecFlags.HasFlag SectionFlags.SHF_WRITE then 2 else 0
    let x = if sec.SecFlags.HasFlag SectionFlags.SHF_EXECINSTR then 1 else 0
    r ||| w ||| x |> LanguagePrimitives.EnumOfValue

  let toBinSection (sec: SectionHeader) =
    { Name = sec.SecName
      Address = sec.SecAddr
      Size = sec.SecSize
      Offset =
        if sec.SecType = SectionType.SHT_NOBITS then None
        else Some sec.SecOffset
      FileSize = secFileSize sec
      Permission = secPermission sec
      Kind = secKind sec }

  let tryFindSectionByAddr addr =
    shdrs.Value
    |> Array.tryFind (fun sec ->
      addr >= sec.SecAddr && addr < sec.SecAddr + sec.SecSize)

  let tryFindSectionByOffset offset =
    shdrs.Value
    |> Array.tryFind (fun sec ->
      let fileSize = secFileSize sec
      fileSize > 0UL && offset >= sec.SecOffset
      && offset < sec.SecOffset + fileSize)

  let structure =
    Some { new IBinStructure with
      member _.Sections with get() =
        shdrs.Value |> Array.map toBinSection

      member _.GetCodeSectionPointer() =
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

      member _.TryFindSectionNameByOffset(offset: uint32) =
        tryFindSectionByOffset (uint64 offset)
        |> function
          | Some sec -> Ok sec.SecName
          | None -> Error ErrorCase.ItemNotFound

      member _.GetFunctionAddresses() =
        functionAddrs.Value
    }

  let relocations =
    Some { new IRelocationTable with
      member _.ContainsRelocation addr =
        relocs.Value.Contains addr

      member _.TryGetRelocatedAddr relocAddr =
        getRelocatedAddr relocs.Value relocAddr
    }

  let linkageEntries =
    lazy
      plt.Value
      |> NoOverlapIntervalMap.fold (fun acc _ entry -> entry :: acc) []
      |> List.sortBy (fun entry -> entry.TrampolineAddress)
      |> List.toArray

  let linkage =
    Some { new ILinkageTable with
      member _.GetLinkageEntries() =
        linkageEntries.Value

      member _.IsInLinkageTable addr =
        NoOverlapIntervalMap.containsAddr addr plt.Value
    }

  let segments =
    lazy
      phdrs.Value
      |> Array.filter (fun ph ->
        ph.PHType.HasFlag ProgramHeaderType.PT_LOAD && ph.PHMemSize > 0UL)
      |> Array.map (fun ph ->
        { Name = None
          Address = ph.PHAddr
          Size = ph.PHMemSize
          Offset = ph.PHOffset
          FileSize = ph.PHFileSize
          Permission = ProgramHeader.FlagsToPerm ph.PHFlags })

  let memoryLayout =
    Some { new IMemoryLayout with
      member _.GetSegments() = segments.Value }

  /// ELF Header information.
  member _.Header with get() = hdr

  /// List of dynamic section entries.
  member _.DynamicArrayEntries with get() = dynamicArray.Value

  /// ELF program headers.
  member _.ProgramHeaders with get() = phdrs.Value

  /// ELF section headers.
  member _.SectionHeaders with get() = shdrs.Value

  /// PLT.
  member _.PLT with get() = plt.Value

  /// Exception information.
  member _.ExceptionFrame with get() = exn.Value.ExceptionFrame

  /// LSDA table.
  member _.LSDATable with get() = exn.Value.LSDATable

  /// Unwinding table.
  member _.UnwindingTable with get() = exn.Value.UnwindingTbl

  /// ELF symbol information.
  member _.Symbols with get() = symbs.Value

  /// Relocation information.
  member _.RelocationInfo with get() = relocs.Value

  /// Debug information.
  member _.DebugInfo with get() = dbginfo.Value

  /// Returns Global Pointer (GP) value when it is known. This is only available
  /// in MIPS binaries.
  member _.GlobalPointer with get() =
    match hdr.MachineType with
    | MachineType.EM_MIPS ->
      shdrs.Value
      |> Array.tryFind (fun s -> s.SecName = Section.GOT)
      |> Option.map (fun s -> s.SecAddr + 0x7ff0UL)
    | _ -> None

  /// Try to find a section by its name.
  member _.TryFindSection(name: string) =
    shdrs.Value |> Array.tryFind (fun s -> s.SecName = name)

  /// Find a section by its index.
  member _.FindSection(idx: int) = shdrs.Value[idx]

  /// Is this a PLT section?
  member _.IsPLT sec = PLT.isPLTSectionName sec.SecName

  /// Is this section contains executable code?
  member _.HasCode sec =
    sec.SecFlags.HasFlag SectionFlags.SHF_EXECINSTR
    && not (PLT.isPLTSectionName sec.SecName)

  interface IBinFile with
    member _.Reader with get() = toolBox.Reader

    member _.RawBytes with get() = System.ReadOnlyMemory bytes

    member _.Length with get() = bytes.Length

    member _.Path with get() = path

    member _.Format with get() = FileFormat.ELFBinary

    member _.ISA with get() = toolBox.ISA

    member _.EntryPoint with get() = Some hdr.EntryPoint

    member _.BaseAddress with get() = toolBox.BaseAddress

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

    member _.NameResolver with get() = nameResolver

    member _.SymbolMetadata with get() = symbolMetadata

    member _.Structure with get() = structure

    member _.Relocations with get() = relocations

    member _.Linkage with get() = linkage

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

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
open B2R2.FrontEnd.BinFile.Mach
open B2R2.FrontEnd.BinFile.Mach.Helper

/// Represents a Mach-O binary file.
type MachBinFile(path, bytes: byte[], isa, baseAddrOpt) =
  let toolBox = Toolbox.Init(bytes, Header.parse bytes baseAddrOpt isa)
  let cmds = lazy LoadCommands.parse toolBox
  let segCmds = lazy Segment.extract cmds.Value
  let segMap = lazy Segment.buildMap segCmds.Value
  let secs = lazy Section.parse toolBox segCmds.Value
  let syms = lazy SymbolStore.parse toolBox cmds.Value secs.Value
  let exports = lazy ExportedSymbols.parse toolBox cmds.Value
  let relocs = lazy Reloc.parse toolBox secs.Value
  let relocMap = lazy Reloc.buildMap relocs.Value
  let fixups =
    lazy
      Array.append
        (ChainedFixup.parse toolBox cmds.Value segCmds.Value)
        (DyldInfo.parse toolBox cmds.Value segCmds.Value)
  let fixupMap = lazy Fixup.buildMap fixups.Value
  let notInMemRanges = lazy invalidRangesByVM toolBox segCmds.Value
  let notInFileRanges = lazy invalidRangesByFileBounds toolBox segCmds.Value
  let executableRanges = lazy executableRanges segCmds.Value
  let enumSymbols =
    lazy (syms.Value.SymbolArray
          |> Array.filter (fun s -> s.SymType <> SymbolType.N_OPT))
  let staticSymbols = lazy (enumSymbols.Value |> Array.filter Symbol.IsStatic)
  let dynamicSymbols =
    lazy (enumSymbols.Value |> Array.filter (Symbol.IsStatic >> not))
  let entryPoint = lazy computeEntryPoint segCmds.Value cmds.Value

  let nameResolver =
    Some { new INameResolvable with
      member _.TryFindName(addr) =
        match Map.tryFind addr syms.Value.SymbolMap with
        | Some s -> Ok s.SymName
        | None -> Error ErrorCase.SymbolNotFound
    }

  let symbolMetadata =
    Some { new ISymbolMetadata with
      member _.IsStripped with get() = isStripped secs.Value syms.Value
    }

  let functionAddrs =
    lazy
      let secText = Section.getTextSectionIndex secs.Value
      [| for s in syms.Value.SymbolArray do
           if Symbol.IsFunc(secText, s) && s.SymAddr > 0UL then s.SymAddr
           else () |]

  let isZeroFillSection (sec: Section) =
    sec.SecType = SectionType.S_ZEROFILL
    || sec.SecType = SectionType.S_GB_ZEROFILL
    || sec.SecType = SectionType.S_THREAD_LOCAL_ZEROFILL

  let isTLSSection (sec: Section) =
    sec.SecType = SectionType.S_THREAD_LOCAL_REGULAR
    || sec.SecType = SectionType.S_THREAD_LOCAL_ZEROFILL
    || sec.SecType = SectionType.S_THREAD_LOCAL_VARIABLES
    || sec.SecType = SectionType.S_THREAD_LOCAL_VARIABLE_POINTERS
    || sec.SecType = SectionType.S_THREAD_LOCAL_INIT_FUNCTION_POINTERS

  let isMetadataSection (sec: Section) =
    sec.SecType = SectionType.S_NON_LAZY_SYMBOL_POINTERS
    || sec.SecType = SectionType.S_LAZY_SYMBOL_POINTERS
    || sec.SecType = SectionType.S_MOD_INIT_FUNC_POINTERS
    || sec.SecType = SectionType.S_MOD_TERM_FUNC_POINTERS
    || sec.SecType = SectionType.S_INTERPOSING
    || sec.SecType = SectionType.S_LAZY_DYLIB_SYMBOL_POINTERS

  let secPermission (sec: Section) =
    match NoOverlapIntervalMap.tryFindByAddr sec.SecAddr segMap.Value with
    | Some seg -> LanguagePrimitives.EnumOfValue seg.InitProt
    | None -> LanguagePrimitives.EnumOfValue 0

  let secKind (sec: Section) =
    if sec.SecAttrib.HasFlag SectionAttribute.S_ATTR_DEBUG then
      BinSectionKind.Debug
    elif isTLSSection sec then BinSectionKind.ThreadLocalStorage
    elif isZeroFillSection sec then BinSectionKind.UninitializedData
    elif sec.SecAttrib.HasFlag SectionAttribute.S_ATTR_PURE_INSTRUCTIONS then
      BinSectionKind.Code
    elif sec.SecName = Section.Text then BinSectionKind.Code
    elif isMetadataSection sec then BinSectionKind.Metadata
    elif sec.SecType = SectionType.S_REGULAR then BinSectionKind.Data
    else BinSectionKind.Unknown

  let toBinSection (sec: Section) =
    { Name = sec.SecName
      Address = sec.SecAddr
      Size = sec.SecSize
      Offset =
        if isZeroFillSection sec then None
        else Some(uint64 sec.SecOffset)
      FileSize = if isZeroFillSection sec then 0UL else sec.SecSize
      Permission = secPermission sec
      Kind = secKind sec }

  let tryFindSectionByAddr addr =
    secs.Value
    |> Array.tryFind (fun sec ->
      addr >= sec.SecAddr && addr < sec.SecAddr + sec.SecSize)

  let tryFindSectionByOffset offset =
    secs.Value
    |> Array.tryFind (fun sec ->
      let fileSize = if isZeroFillSection sec then 0UL else sec.SecSize
      let secOffset = uint64 sec.SecOffset
      fileSize > 0UL && offset >= secOffset && offset < secOffset + fileSize)

  let structure =
    Some { new IBinStructure with
      member _.Sections with get() =
        secs.Value |> Array.map toBinSection

      member _.GetCodeSectionPointer() =
        let secs = secs.Value
        let secText = Section.getTextSectionIndex secs
        let sec = secs[secText]
        BinFilePointer.CreateFileBacked(
          sec.SecAddr,
          sec.SecAddr + sec.SecSize - 1UL,
          int sec.SecOffset,
          int sec.SecOffset + int sec.SecSize - 1)

      member _.GetSectionPointer name =
        secs.Value
        |> Array.tryFind (fun sec -> sec.SecName = name)
        |> function
          | Some sec ->
            BinFilePointer.CreateFileBacked(
              sec.SecAddr,
              sec.SecAddr + sec.SecSize - 1UL,
              int sec.SecOffset,
              int sec.SecOffset + int sec.SecSize - 1)
          | None -> BinFilePointer.Null

      member _.TryFindSectionByName name =
        secs.Value
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

      member _.TryFindSectionNameByAddr(addr: Addr) =
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
        Map.containsKey addr relocMap.Value
        || Map.containsKey addr fixupMap.Value

      member _.TryGetRelocatedAddr relocAddr =
        match Map.tryFind relocAddr fixupMap.Value with
        | Some fixup ->
          match fixup.FixupTarget with
          | Rebase target -> Ok target
          | Bind _ -> Error ErrorCase.ItemNotFound
        | None ->
          Reloc.getRelocatedAddr toolBox relocMap.Value syms.Value relocAddr
    }

  let fixupLinkage =
    lazy
      fixups.Value
      |> Array.choose (fun fixup ->
        match fixup.FixupTarget with
        | Bind(name, library, _) ->
          Some { FuncName = name
                 LibraryName = library
                 TrampolineAddress = 0UL
                 TableAddress = fixup.FixupAddr }
        | Rebase _ -> None)

  (* Stub-based binaries already describe imports via the symbol store; only
     fall back to dyld fixup binds when there is no classic linkage table (e.g.
     chained-fixups or dyld-info dylibs without __stubs). *)
  let linkageEntries =
    lazy
      let classic = getPLT syms.Value
      if Array.isEmpty classic then fixupLinkage.Value else classic

  let linkage =
    Some { new ILinkageTable with
      member _.GetLinkageEntries() = linkageEntries.Value

      member _.IsInLinkageTable addr =
        isPLT syms.Value addr
        || (List.isEmpty syms.Value.LinkageTable
            && Fixup.isBindAt fixupMap.Value addr)
    }

  let segments =
    lazy
      segCmds.Value
      |> Array.filter (fun seg -> seg.VMSize > 0UL)
      |> Array.map (fun seg ->
        { Name = Some seg.SegCmdName
          Address = seg.VMAddr
          Size = seg.VMSize
          Offset = seg.FileOff
          FileSize = seg.FileSize
          Permission = LanguagePrimitives.EnumOfValue seg.InitProt })

  let memoryLayout =
    Some { new IMemoryLayout with
      member _.GetSegments() = segments.Value }

  member _.Header with get() = toolBox.Header

  member _.Commands with get() = cmds.Value

  member _.Sections with get() = secs.Value

  member _.Symbols with get() = syms.Value

  member _.StaticSymbols with get() = staticSymbols.Value

  member _.DynamicSymbols with get() = dynamicSymbols.Value

  member _.ExportedSymbols with get() = exports.Value

  member _.Relocations with get() = relocs.Value

  member _.IsPLT(sec: Section) =
    match sec.SecType with
    | SectionType.S_NON_LAZY_SYMBOL_POINTERS
    | SectionType.S_LAZY_SYMBOL_POINTERS
    | SectionType.S_SYMBOL_STUBS -> true
    | _ -> false

  member _.HasCode(sec: Section) =
    match sec.SecType with
    | SectionType.S_NON_LAZY_SYMBOL_POINTERS
    | SectionType.S_LAZY_SYMBOL_POINTERS
    | SectionType.S_SYMBOL_STUBS -> false
    | _ ->
      let seg = NoOverlapIntervalMap.findByAddr sec.SecAddr segMap.Value
      seg.InitProt &&& int MachVMProt.Executable > 0

  interface IBinFile with
    member _.Reader with get() = toolBox.Reader

    member _.RawBytes with get() = System.ReadOnlyMemory bytes

    member _.Length with get() = bytes.Length

    member _.Path with get() = path

    member _.Format with get() = FileFormat.MachBinary

    member _.ISA with get() = toolBox.ISA

    member _.EntryPoint with get() = entryPoint.Value

    member _.BaseAddress with get() = toolBox.BaseAddress

    member _.IsNXEnabled with get() = isNXEnabled toolBox.Header

    member _.IsPIE with get() =
      toolBox.Header.Flags.HasFlag MachFlag.MH_PIE

    member _.IsBaseRelative with get() =
      let hdr = toolBox.Header
      hdr.Flags.HasFlag MachFlag.MH_PIE
      || hdr.FileType <> FileType.MH_EXECUTE

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
      let segCmds = segCmds.Value
      let mutable found = false
      let mutable idx = 0
      let mutable maxAddr = 0UL
      let mutable offset = 0
      let mutable maxOffset = 0
      while not found && idx < segCmds.Length do
        let seg = segCmds[idx]
        if addr >= seg.VMAddr && addr < seg.VMAddr + seg.VMSize then
          found <- true
          maxOffset <- int seg.FileOff + int seg.FileSize - 1
          if addr < seg.VMAddr + seg.FileSize then
            offset <- int seg.FileOff + int (addr - seg.VMAddr)
            maxAddr <- seg.VMAddr + seg.FileSize - 1UL
          else
            offset <- maxOffset + 1
            maxAddr <- seg.VMAddr + seg.VMSize - 1UL
        else idx <- idx + 1
      if found then
        if offset > maxOffset then BinFilePointer.CreateVirtual(addr, maxAddr)
        else BinFilePointer.CreateFileBacked(addr, maxAddr, offset, maxOffset)
      else
        BinFilePointer.Null

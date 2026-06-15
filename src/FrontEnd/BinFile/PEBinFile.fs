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

open System.Reflection.PortableExecutable
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.FileHelper
open B2R2.FrontEnd.BinFile.PE
open B2R2.FrontEnd.BinFile.PE.Helper

/// Represents a PE binary file.
type PEBinFile(path, bytes: byte[], baseAddrOpt, rawpdb) =
  let pe = Parser.parse path bytes baseAddrOpt rawpdb
  let isa = peHeadersToISA pe.PEHeaders

  let nameResolver =
    Some { new INameResolvable with
      member _.TryFindName(addr) =
        if pe.Symbols.SymbolArray.Length = 0 then
          tryFindSymbolFromBinary pe addr
        else tryFindSymbolFromPDB pe addr
    }

  let symbolMetadata =
    Some { new ISymbolMetadata with
      member _.IsStripped with get() = Array.isEmpty pe.Symbols.SymbolArray
    }

  let functionAddrs =
    lazy
      let staticAddrs =
        [| for s in pe.Symbols.SymbolArray do
             if s.IsFunction then s.Address else () |]
      let dynamicAddrs =
        [| for addr in pe.ExportedSymbols.Addresses do
             let idx = pe.FindSectionIdxFromRVA(int (addr - pe.BaseAddr))
             if idx <> -1 && isSectionExecutableByIndex pe idx then addr
             else () |]
      Array.concat [| staticAddrs; dynamicAddrs |]
      |> Set.ofArray
      |> Set.toArray

  let isPEMetadataSection name =
    name = Section.Reloc || name = Section.IData || name = Section.EData
    || name = Section.PData || name = Section.XData
    || name = Section.ResourceData

  let secKind (sec: SectionHeader) =
    let ch = sec.SectionCharacteristics
    if sec.Name = Section.Resource then
      BinSectionKind.Resource
    elif sec.Name.StartsWith Section.DebugPrefix then
      BinSectionKind.Debug
    elif sec.Name = Section.TLS then
      BinSectionKind.ThreadLocalStorage
    elif ch.HasFlag SectionCharacteristics.MemExecute
      || ch.HasFlag SectionCharacteristics.ContainsCode then
      BinSectionKind.Code
    elif ch.HasFlag SectionCharacteristics.ContainsUninitializedData then
      BinSectionKind.UninitializedData
    elif ch.HasFlag SectionCharacteristics.ContainsInitializedData then
      BinSectionKind.Data
    elif isPEMetadataSection sec.Name then
      BinSectionKind.Metadata
    else
      BinSectionKind.Unknown

  let secFileOffset (sec: SectionHeader) =
    if sec.SizeOfRawData = 0 then None
    else Some(uint64 sec.PointerToRawData)

  let toBinSection (sec: SectionHeader) =
    { Name = sec.Name
      Address = PEUtils.addrFromRVA pe.BaseAddr sec.VirtualAddress
      Size = uint64 (getVirtualSectionSize sec)
      Offset = secFileOffset sec
      FileSize = uint64 sec.SizeOfRawData
      Permission = getSecPermission sec.SectionCharacteristics
      Kind = secKind sec }

  let tryFindSectionByAddr addr =
    let rva = int (addr - pe.BaseAddr)
    match pe.FindSectionIdxFromRVA rva with
    | -1 -> None
    | idx -> Some pe.SectionHeaders[idx]

  let tryFindSectionByOffset offset =
    pe.SectionHeaders
    |> Array.tryFind (fun sec ->
      let secStart = uint64 sec.PointerToRawData
      let secEnd = secStart + uint64 sec.SizeOfRawData
      sec.SizeOfRawData > 0 && offset >= secStart && offset < secEnd)

  let structure =
    Some { new IBinStructure with
      member _.Sections with get() =
        pe.SectionHeaders |> Array.map toBinSection

      member _.GetCodeSectionPointer() =
        pe.SectionHeaders
        |> Array.tryFind (fun sec -> sec.Name = SecText)
        |> function
          | Some sec ->
            let addr = PEUtils.addrFromRVA pe.BaseAddr sec.VirtualAddress
            let size = sec.SizeOfRawData
            BinFilePointer.CreateFileBacked(
              addr,
              addr + uint64 size - 1UL,
              sec.PointerToRawData,
              sec.PointerToRawData + size - 1)
          | None -> BinFilePointer.Null

      member _.GetSectionPointer name =
        pe.SectionHeaders
        |> Array.tryFind (fun sec -> sec.Name = name)
        |> function
          | Some sec ->
            let addr = PEUtils.addrFromRVA pe.BaseAddr sec.VirtualAddress
            let size = sec.SizeOfRawData
            BinFilePointer.CreateFileBacked(
              addr,
              addr + uint64 size - 1UL,
              sec.PointerToRawData,
              sec.PointerToRawData + size - 1)
          | None -> BinFilePointer.Null

      member _.TryFindSectionByName name =
        pe.SectionHeaders
        |> Array.tryFind (fun sec -> sec.Name = name)
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
        match tryFindSectionByAddr addr with
        | Some sec -> Ok sec.Name
        | None -> Error ErrorCase.ItemNotFound

      member _.TryFindSectionNameByOffset(offset: uint32) =
        tryFindSectionByOffset (uint64 offset)
        |> function
          | Some sec -> Ok sec.Name
          | None -> Error ErrorCase.ItemNotFound

      member _.GetFunctionAddresses() =
        functionAddrs.Value
    }

  let relocations =
    Some { new IRelocationTable with
      member _.ContainsRelocation addr = Relocation.contains pe addr

      member _.TryGetRelocatedAddr relocAddr =
        Relocation.tryGetRelocatedAddr bytes pe relocAddr
    }

  let linkageEntries =
    lazy getImportTable pe

  let linkage =
    Some { new ILinkageTable with
      member _.GetLinkageEntries() = linkageEntries.Value

      member _.IsInLinkageTable addr = isImportTable pe addr
    }

  let memoryMappedRegions =
    lazy
      pe.SectionHeaders
      |> Array.choose (fun sec ->
        let secSize = getVirtualSectionSize sec
        if secSize > 0 then
          let addr = uint64 sec.VirtualAddress + pe.BaseAddr
          let range = AddrRange.create addr (addr + uint64 secSize - 1UL)
          Some(range, getSecPermission sec.SectionCharacteristics)
        else None)

  let memoryLayout =
    Some { new IMemoryLayout with
      member _.GetMemoryMappedRegions() =
        memoryMappedRegions.Value |> Array.map fst

      member _.GetMemoryMappedRegions(perm) =
        memoryMappedRegions.Value
        |> Array.choose (fun (range, secPerm) ->
          if secPerm &&& perm = perm then Some range else None) }

  new(path, bytes) = PEBinFile(path, bytes, None, [||])

  new(path, bytes, rawpdb) = PEBinFile(path, bytes, None, rawpdb)

  /// Returns the base address.
  member _.BaseAddress with get() = pe.BaseAddr

  /// Returns the PEHeaders.
  member _.PEHeaders with get() = pe.PEHeaders

  /// Returns the section headers.
  member _.SectionHeaders with get() = pe.SectionHeaders

  /// Returns the list of relocation blocks.
  member _.RelocBlocks with get() = pe.RelocBlocks

  /// Returns the symbol store.
  member _.Symbols with get() = pe.Symbols

  /// Returns the imported symbols.
  member _.ImportedSymbols with get() = pe.ImportedSymbols

  /// Returns the exported symbols.
  member _.ExportedSymbols with get() = pe.ExportedSymbols

  member _.RawPDB with get() = rawpdb

  /// Finds the section index from the given RVA.
  member _.FindSectionIdxFromRVA rva = pe.FindSectionIdxFromRVA rva

  member _.HasCode(sec: SectionHeader) =
    sec.SectionCharacteristics.HasFlag SectionCharacteristics.MemExecute

  interface IBinFile with
    member _.Reader with get() = pe.BinReader

    member _.RawBytes with get() = System.ReadOnlyMemory bytes

    member _.Length with get() = bytes.Length

    member _.Path with get() = path

    member _.Format with get() = FileFormat.PEBinary

    member _.ISA with get() = isa

    member _.EntryPoint with get() = getEntryPoint pe

    member _.BaseAddress with get() = pe.BaseAddr

    member _.IsNXEnabled with get() = isNXEnabled pe

    member _.IsPIE with get() = isPIE pe

    member _.IsBaseRelative with get() = isBaseRelative pe

    member _.NameResolver with get() = nameResolver

    member _.SymbolMetadata with get() = symbolMetadata

    member _.Structure with get() = structure

    member _.Relocations with get() = relocations

    member _.Linkage with get() = linkage

    member _.MemoryLayout with get() = memoryLayout

    member this.Slice(addr, len) =
      let ptr = (this :> IAddressSpace).GetBoundedPointer addr
      sliceByPointer bytes ptr len

    member _.IsValidAddr addr = isValidAddr pe addr

    member _.IsValidRange range = isValidRange pe range

    member _.IsAddrMappedToFile addr = isAddrMappedToFile pe addr

    member _.IsRangeMappedToFile range = isRangeMappedToFile pe range

    member _.IsExecutableAddr addr = isExecutableAddr pe addr

    member _.GetBoundedPointer addr =
      let hdrs = pe.SectionHeaders
      let mutable found = false
      let mutable idx = 0
      let mutable maxAddr = 0UL
      let mutable offset = 0
      let mutable maxOffset = 0
      while not found && idx < hdrs.Length do
        let sec = hdrs[idx]
        let vma = uint64 sec.VirtualAddress + pe.BaseAddr
        let vmaSize = getVirtualSectionSize sec
        if addr >= vma && addr < vma + uint64 vmaSize then
          found <- true
          maxOffset <- sec.PointerToRawData + sec.SizeOfRawData - 1
          if addr < vma + uint64 sec.SizeOfRawData then
            offset <- sec.PointerToRawData + int (addr - vma)
            maxAddr <- vma + uint64 sec.SizeOfRawData - 1UL
          else
            offset <- maxOffset + 1
            maxAddr <- vma + uint64 vmaSize - 1UL
        else idx <- idx + 1
      if found then
        if offset > maxOffset then BinFilePointer.CreateVirtual(addr, maxAddr)
        else BinFilePointer.CreateFileBacked(addr, maxAddr, offset, maxOffset)
      else
        BinFilePointer.Null

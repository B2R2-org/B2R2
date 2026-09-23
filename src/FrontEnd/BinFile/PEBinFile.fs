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

open System.Collections.Immutable
open B2R2
open B2R2.Collections
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.FileHelper
open B2R2.FrontEnd.BinFile.PE
open B2R2.FrontEnd.BinFile.PE.Helper
open B2R2.FrontEnd.BinFile.PE.PEUtils

/// Represents a PE binary file.
type PEBinFile private(path, bytes: byte[], baseAddrOpt, pdb) =
  let rawBytes = System.ReadOnlyMemory bytes

  let pe = Parser.parse path bytes baseAddrOpt pdb

  let isa = headerToISA pe.Header

  let nameResolver =
    Some { new INameResolvable with
      member _.TryResolveName(addr) =
        if pe.Symbols.Value.SymbolArray.Length = 0 then
          tryFindSymbolFromBinary pe addr
        else
          tryFindSymbolFromPDB pe addr
    }

  let isExecutableAddress addr =
    let idx = pe.FindSectionIdxFromRVA(int (addr - pe.BaseAddr))
    idx <> -1 && isSectionExecutableByIndex pe idx

  let toBinSymbol (s: Symbol) =
    { Name = s.Name
      Address = s.Address
      Kind = if s.IsFunction then FunctionSymbol else OtherSymbol
      Binding = UnknownBinding
      IsDefined = true
      Size = s.Size
      LibraryName = None }

  let toExportedSymbol addr name =
    { Name = name
      Address = addr
      Kind = if isExecutableAddress addr then FunctionSymbol else DataSymbol
      Binding = GlobalBinding
      IsDefined = true
      Size = None
      LibraryName = None }

  (* An image keeps no symbol table of its own, so what it exports is the only
     name it gives an address inside it. These are names a linker reads rather
     than ones a debugger does, which is why an image holding nothing besides
     them is stripped all the same. *)
  let exportedSymbols =
    lazy
      [| for KeyValue(addr, names) in pe.ExportedSymbols.Value.Exports do
           for name in names -> toExportedSymbol addr name |]

  let binSymbols =
    lazy
      Array.append
        (pe.Symbols.Value.SymbolArray |> Array.map toBinSymbol)
        exportedSymbols.Value
      |> ImmutableArray.ofArray

  let tryFindExportedSymbol addr =
    match pe.ExportedSymbols.Value.TryFind addr with
    | Some(name :: _) -> Ok(toExportedSymbol addr name)
    | _ -> Error ErrorCase.SymbolNotFound

  let symbolTable =
    Some { new ISymbolTable with
      member _.IsStripped with get() =
        Array.isEmpty pe.Symbols.Value.SymbolArray

      member _.Symbols with get() = binSymbols.Value

      member _.TryFindSymbolByAddr addr =
        match pe.Symbols.Value.SymbolByAddr.TryGetValue addr with
        | true, s ->
          Ok(toBinSymbol s)
        | false, _ ->
          tryFindExportedSymbol addr

      member _.CodeModeMarkers = ImmutableArray.Empty
    }

  let unwindFrames = lazy (ExceptionData.parse pe bytes)

  let functionAddrs =
    lazy
      let staticAddrs =
        [| for s in pe.Symbols.Value.SymbolArray do
             if s.IsFunction then s.Address else () |]
      let dynamicAddrs =
        [| for addr in pe.ExportedSymbols.Value.Addresses do
             if isExecutableAddress addr then addr else () |]
      (* Every range .pdata unwinds opens a function, barring one that chains
         back to the range before it and so only carries that one on. *)
      let unwindAddrs =
        [| for f in unwindFrames.Value do
             if f.IsChained then () else f.FuncStart |]
      (* What the loader is handed as a function is one, so long as it lands
         where the file keeps code. *)
      let vouchedAddrs =
        [| yield! LoadConfig.getFunctionAddresses bytes pe
           yield! TLSDirectory.getCallbackAddresses bytes pe |]
        |> Array.filter isExecutableAddress
      Array.concat
        [| staticAddrs; dynamicAddrs; unwindAddrs; vouchedAddrs |]
      |> Array.distinct
      |> Array.sort
      |> ImmutableArray.ofArray

  let isPEMetadataSection name =
    name = Section.Reloc || name = Section.EData
    || name = Section.PData || name = Section.XData
    || name = Section.ResourceData

  let secKind (sec: SectionHeader) =
    let ch = sec.SectionCharacteristics
    if sec.Name = Section.Resource then
      ResourceSection
    elif sec.Name.StartsWith Section.DebugPrefix then
      DebugSection
    elif sec.Name = Section.TLS then
      ThreadLocalStorageSection
    elif sec.Name = Section.IData then
      DynamicLinkageSection
    elif ch.HasFlag SectionCharacteristics.MemExecute
      || ch.HasFlag SectionCharacteristics.ContainsCode then
      CodeSection
    elif ch.HasFlag SectionCharacteristics.ContainsUninitializedData then
      UninitializedDataSection
    elif ch.HasFlag SectionCharacteristics.ContainsInitializedData then
      DataSection
    elif isPEMetadataSection sec.Name then
      MetadataSection
    else
      UnknownSection

  let secFileOffset (sec: SectionHeader) =
    if sec.SizeOfRawData = 0 then None else Some(uint64 sec.PointerToRawData)

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

  let tryFindSectionByOffset (offset: uint32) =
    pe.SectionHeaders
    |> Array.tryFind (fun sec ->
      let secStart = uint64 sec.PointerToRawData
      let secEnd = secStart + uint64 sec.SizeOfRawData
      sec.SizeOfRawData > 0
      && uint64 offset >= secStart
      && uint64 offset < secEnd)

  let binSections =
    lazy
      (pe.SectionHeaders |> Array.map toBinSection |> ImmutableArray.ofArray)

  /// Returns a pointer to the file bytes of the given section, or a null
  /// pointer when the section holds no raw data at all.
  let toSectionPointer (sec: SectionHeader) =
    if sec.SizeOfRawData = 0 then
      BinFilePointer.Null
    else
      let addr = PEUtils.addrFromRVA pe.BaseAddr sec.VirtualAddress
      let size = sec.SizeOfRawData
      BinFilePointer.CreateFileBacked(
        addr,
        addr + uint64 size - 1UL,
        sec.PointerToRawData,
        sec.PointerToRawData + size - 1
      )

  let structure =
    Some { new IBinStructure with
      member _.Sections with get() = binSections.Value

      member _.CodeSectionPointer =
        pe.SectionHeaders
        |> Array.tryFind (fun sec -> sec.Name = SecText)
        |> function
          | Some sec -> toSectionPointer sec
          | None -> BinFilePointer.Null

      member _.GetSectionPointer name =
        pe.SectionHeaders
        |> Array.tryFind (fun sec -> sec.Name = name)
        |> function
          | Some sec -> toSectionPointer sec
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

      member _.TryFindSectionNameByOffset offset =
        tryFindSectionByOffset offset
        |> function
          | Some sec -> Ok sec.Name
          | None -> Error ErrorCase.ItemNotFound

      member _.FunctionAddresses = functionAddrs.Value
    }

  let relocIndex = lazy (Relocation.build bytes pe)

  let relocations =
    Some { new IRelocationTable with
      member _.Relocations = relocIndex.Value.Relocations

      member _.IsRelocationAddr addr =
        relocIndex.Value.Addresses.Contains addr

      member _.TryGetRelocatedAddr relocAddr =
        Relocation.tryGetRelocatedAddr bytes pe relocIndex.Value relocAddr

      member _.TryGetInternalFunctionAddr _relocAddr =
        Error ErrorCase.SymbolNotFound
    }

  let importEntries = lazy (getImportTable pe |> ImmutableArray.ofArray)

  (* One entry of the import directory per library, which is what every import
     of it names, so the names of the libraries are its names made distinct. *)
  let dependencies =
    lazy
      importEntries.Value
      |> ImmutableArray.map _.LibraryName
      |> Array.filter (fun name -> name <> "")
      |> Array.distinct
      |> ImmutableArray.ofArray

  let exportName =
    lazy
      match pe.ExportedSymbols.Value.DLLName with
      | "" -> None
      | name -> Some name

  let buildId = lazy (getBuildId bytes pe |> ImmutableArray.ofArray)

  let importTable =
    Some { new IImportTable with
      member _.Imports = importEntries.Value

      member _.IsInImportTable addr = isImportTable pe addr
    }

  let segments =
    lazy
      pe.SectionHeaders
      |> Array.choose (fun sec ->
        let secSize = getVirtualSectionSize sec
        if secSize > 0 then
          Some { Name = Some sec.Name
                 Address = uint64 sec.VirtualAddress + pe.BaseAddr
                 PhysAddr = uint64 sec.VirtualAddress + pe.BaseAddr
                 Size = uint64 secSize
                 Offset = uint64 sec.PointerToRawData
                 FileSize = uint64 sec.SizeOfRawData
                 Permission = getSecPermission sec.SectionCharacteristics }
        else
          None)
      |> ImmutableArray.ofArray

  let memoryLayout =
    Some { new IMemoryLayout with
      member _.Segments = segments.Value }

  let exceptionFrames =
    lazy
      [| for f in unwindFrames.Value do
           { FunctionStart = f.FuncStart
             FunctionEnd = f.FuncEnd - 1UL
             PersonalityRoutine = f.Personality
             Handlers =
               f.Handlers
               |> List.map (fun (s, e, h) ->
                 { BlockStart = s; BlockEnd = e; Handler = h })
               |> List.toArray } |]
      |> ImmutableArray.ofArray

  let exceptionTable =
    Some { new IExceptionTable with
      member _.Frames = exceptionFrames.Value
    }

  new(path, bytes) = PEBinFile(path, bytes, None, NoPDBGiven)

  /// Reads the image with the PDB whose bytes are given. An empty array names
  /// no PDB, and one is then looked for beside the image.
  new(path, bytes, rawpdb: byte[]) =
    PEBinFile(path, bytes, None, PDBSource.ofBytes rawpdb)

  /// Reads the image with the PDB at the given path, which is opened and read
  /// a block at a time. It is the way to name a PDB too large to hold in an
  /// array, which the biggest of them are.
  new(path, bytes, pdbPath: string) =
    PEBinFile(path, bytes, None, PDBPath pdbPath)

  /// Reads the image at the given base address with the PDB whose bytes are
  /// given. An empty array names no PDB.
  new(path, bytes, baseAddrOpt, rawpdb: byte[]) =
    PEBinFile(path, bytes, baseAddrOpt, PDBSource.ofBytes rawpdb)

  /// Reads the image at the given base address with the PDB at the given
  /// path, which is opened and read a block at a time.
  new(path, bytes, baseAddrOpt, pdbPath: string) =
    PEBinFile(path, bytes, baseAddrOpt, PDBPath pdbPath)

  /// Returns the base address.
  member internal _.BaseAddress with get() = pe.BaseAddr

  /// Returns the contents of the file.
  member internal _.Bytes with get() = bytes

  /// Returns every header of the file.
  member internal _.Header with get() = pe.Header

  /// Returns the section headers.
  member internal _.SectionHeaders with get() = pe.SectionHeaders

  /// Returns the list of relocation blocks.
  member internal _.RelocBlocks with get() = pe.RelocBlocks.Value

  /// Returns the symbol store.
  member internal _.Symbols with get() = pe.Symbols.Value

  /// Returns the imported symbols.
  member internal _.ImportedSymbols with get() = pe.ImportedSymbols.Value

  /// Returns the exported symbols.
  member internal _.ExportedSymbols with get() = pe.ExportedSymbols.Value

  member internal _.RawPDB with get() =
    match pdb with
    | PDBBytes bs -> bs
    | _ -> [||]

  /// Finds the section index from the given RVA.
  member internal _.FindSectionIdxFromRVA rva = pe.FindSectionIdxFromRVA rva

  interface IBinFile with
    member _.Reader with get() = pe.BinReader

    member _.RawBytes with get() = rawBytes

    member _.Length with get() = bytes.Length

    member _.Path with get() = path

    member _.Format with get() = FileFormat.PEBinary

    member _.Kind with get() =
      let chr = pe.Header.CoffHeader.Characteristics
      if chr.HasFlag Characteristics.Dll then
        BinFileKind.SharedLibrary
      elif chr.HasFlag Characteristics.ExecutableImage then
        BinFileKind.Executable
      else
        BinFileKind.Object

    member _.ISA with get() = isa

    member _.OS with get() = OS.Windows

    member _.EntryPoint with get() = getEntryPoint pe

    member _.BaseAddress with get() = pe.BaseAddr

    member _.InterpreterPath with get() = None

    member _.RPath with get() = ImmutableArray.Empty

    member _.RunPath with get() = ImmutableArray.Empty

    member _.DependencyNames with get() = dependencies.Value

    member _.SharedObjectName with get() = exportName.Value

    member _.BuildId with get() = buildId.Value

    member _.ProgramHeaderTable with get() = None

    member _.IsNXEnabled with get() = isNXEnabled pe

    member _.IsPIE with get() = isPIE pe

    member _.IsBaseRelative with get() = isBaseRelative pe

    member _.Relro with get() = None

    member _.EncryptedRanges with get() = ImmutableArray.Empty

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

    member _.IsValidAddr addr = isValidAddr pe addr

    member _.IsValidRange range = isValidRange pe range

    member _.IsAddrMappedToFile addr = isAddrMappedToFile pe addr

    member _.IsRangeMappedToFile range = isRangeMappedToFile pe range

    member _.IsExecutableAddr addr = isExecutableAddr pe addr

    member _.GetBoundedPointer addr = boundedPointerOf pe addr

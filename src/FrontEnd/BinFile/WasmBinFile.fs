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
open B2R2.FrontEnd.BinFile.Wasm
open B2R2.FrontEnd.BinFile.Wasm.Helper

/// Represents a Web Assembly (Wasm) binary file.
type WasmBinFile(path, bytes, baseAddrOpt) =
  let wm = Parser.parse bytes
  let baseAddr = defaultArg baseAddrOpt 0UL
  let reader = BinReader.Init Endian.Little
  let isa = ISA Architecture.WASM

  let sectionSummaryToPointer (sec: SectionSummary) =
    let addr = uint64 sec.Offset
    let size = sec.HeaderSize + sec.ContentsSize
    BinFilePointer.CreateFileBacked(
      addr,
      addr + uint64 size - 1UL,
      sec.Offset,
      sec.Offset + int size - 1)

  let tryFindSectionByOffset offset =
    wm.SectionsInfo.SecArray
    |> Array.tryFind (fun sec ->
      offset >= uint32 sec.Offset
      && offset < uint32 sec.Offset + sec.HeaderSize + sec.ContentsSize)

  let secKind (sec: SectionSummary) =
    match sec.Id with
    | SectionId.Code -> BinSectionKind.Code
    | SectionId.Data -> BinSectionKind.Data
    | SectionId.Custom when sec.Name = Section.CustomName ->
      BinSectionKind.Debug
    | SectionId.Custom -> BinSectionKind.Unknown
    | _ -> BinSectionKind.Metadata

  let secPermission sec =
    match secKind sec with
    | BinSectionKind.Code ->
      int Permission.Readable ||| int Permission.Executable
    | BinSectionKind.Data ->
      int Permission.Readable ||| int Permission.Writable
    | BinSectionKind.Debug
    | BinSectionKind.Metadata
    | BinSectionKind.Unknown -> int Permission.Readable
    | _ -> 0
    |> LanguagePrimitives.EnumOfValue

  let toBinSection (sec: SectionSummary) =
    { Name = sec.Name
      Address = uint64 sec.Offset
      Size = uint64 (sec.HeaderSize + sec.ContentsSize)
      Offset = Some(uint64 sec.Offset)
      FileSize = uint64 (sec.HeaderSize + sec.ContentsSize)
      Permission = secPermission sec
      Kind = secKind sec }

  let functionAddrs =
    lazy
      wm.IndexMap
      |> Array.choose (fun idx ->
        if idx.Kind = IndexKind.Function
           && NoOverlapIntervalMap.containsAddr
                (uint64 idx.ElemOffset) wm.SectionsInfo.SecByAddr then
          match NoOverlapIntervalMap.findByAddr
                  (uint64 idx.ElemOffset) wm.SectionsInfo.SecByAddr with
          | sec when sec.Id = SectionId.Code -> Some(uint64 idx.ElemOffset)
          | _ -> None
        else None)

  let importEntries =
    lazy getImports wm

  let symbolMap =
    lazy getFunctionNameMap wm

  let nameResolver =
    Some { new INameResolvable with
      member _.TryResolveName addr =
        match Map.tryFind addr symbolMap.Value with
        | Some name -> Ok name
        | None -> Error ErrorCase.SymbolNotFound
    }

  let structure =
    Some { new IBinStructure with
      member _.Sections with get() =
        wm.SectionsInfo.SecArray |> Array.map toBinSection

      member _.GetCodeSectionPointer() =
        match wm.CodeSection with
        | Some sec ->
          let headerSize =
            wm.SectionsInfo.SecArray
            |> Array.tryFind (fun sm -> sm.Id = SectionId.Code)
            |> Option.map (fun sm -> sm.HeaderSize)
            |> Option.defaultValue 0u
          let addr = uint64 sec.Offset
          let size = headerSize + sec.Size
          BinFilePointer.CreateFileBacked(
            addr,
            addr + uint64 size - 1UL,
            sec.Offset,
            sec.Offset + int size - 1)
        | None ->
          BinFilePointer.Null

      member _.GetSectionPointer name =
        match Map.tryFind name wm.SectionsInfo.SecByName with
        | Some sec -> sectionSummaryToPointer sec
        | None -> BinFilePointer.Null

      member _.TryFindSectionByName name =
        Map.tryFind name wm.SectionsInfo.SecByName
        |> function
          | Some sec -> Ok(toBinSection sec)
          | None -> Error ErrorCase.ItemNotFound

      member _.TryFindSectionByAddr addr =
        NoOverlapIntervalMap.tryFindByAddr addr wm.SectionsInfo.SecByAddr
        |> function
          | Some sec -> Ok(toBinSection sec)
          | None -> Error ErrorCase.ItemNotFound

      member _.TryFindSectionByOffset offset =
        if offset > 0xffffffffUL then Error ErrorCase.ItemNotFound
        else
          match tryFindSectionByOffset (uint32 offset) with
          | Some sec -> Ok(toBinSection sec)
          | None -> Error ErrorCase.ItemNotFound

      member _.TryFindSectionNameByAddr addr =
        NoOverlapIntervalMap.tryFindByAddr addr wm.SectionsInfo.SecByAddr
        |> function
          | Some sec -> Ok sec.Name
          | None -> Error ErrorCase.ItemNotFound

      member _.TryFindSectionNameByOffset offset =
        match tryFindSectionByOffset offset with
        | Some sec -> Ok sec.Name
        | None -> Error ErrorCase.ItemNotFound

      member _.GetFunctionAddresses() =
        functionAddrs.Value
    }

  let importTable =
    Some { new IImportTable with
      member _.GetImports() = importEntries.Value

      member _.IsInImportTable addr =
        importEntries.Value
        |> Array.exists (fun entry -> entry.TableAddress = addr)
    }

  new(path, bytes) = WasmBinFile(path, bytes, None)

  member _.WASM with get() = wm

  member _.Sections with get() = wm.SectionsInfo.SecArray

  interface IBinFile with
    member _.Reader with get() = reader

    member _.RawBytes with get() = System.ReadOnlyMemory bytes

    member _.Length with get() = bytes.Length

    member _.Path with get() = path

    member _.Format with get() = FileFormat.WasmBinary

    member _.ISA with get() = isa

    member _.EntryPoint with get() = entryPointOf wm

    member _.BaseAddress with get() = baseAddr

    member _.IsNXEnabled with get() = true

    member _.IsPIE with get() = false

    member _.IsBaseRelative with get() = false

    member _.NameResolver with get() = nameResolver

    member _.SymbolTable with get() = None

    member _.Structure with get() = structure

    member _.Relocations with get() = None

    member _.ImportTable with get() = importTable

    member _.MemoryLayout with get() = None

    member _.Slice(addr, len) = sliceBySafeOffset bytes addr len

    member _.IsValidAddr(addr) = addr >= 0UL && addr < (uint64 bytes.LongLength)

    member this.IsValidRange range =
      (this :> IAddressSpace).IsValidAddr range.Min
      && (this :> IAddressSpace).IsValidAddr range.Max

    member this.IsAddrMappedToFile addr =
      (this :> IAddressSpace).IsValidAddr addr

    member this.IsRangeMappedToFile range =
      (this :> IAddressSpace).IsValidRange range

    member this.IsExecutableAddr addr =
      (this :> IAddressSpace).IsValidAddr addr

    member _.GetBoundedPointer addr =
      NoOverlapIntervalMap.tryFindByAddr addr wm.SectionsInfo.SecByAddr
      |> function
        | Some s ->
          let size = s.HeaderSize + s.ContentsSize
          let maxAddr = uint64 s.Offset + uint64 size - 1UL
          BinFilePointer.CreateFileBacked(addr, maxAddr, int addr, int maxAddr)
        | None -> BinFilePointer.Null

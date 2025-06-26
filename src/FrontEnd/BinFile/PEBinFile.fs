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
open B2R2.FrontEnd.BinFile.PE
open B2R2.FrontEnd.BinFile.PE.Helper

/// Represents a PE binary file.
type PEBinFile (path, bytes: byte[], baseAddrOpt, rawpdb) =
  let pe = Parser.parse path bytes baseAddrOpt rawpdb
  let isa = peHeadersToISA pe.PEHeaders

  new (path, bytes) = PEBinFile (path, bytes, None, [||])

  new (path, bytes, rawpdb) = PEBinFile (path, bytes, None, rawpdb)

  /// Returns the base address.
  member _.BaseAddress with get () = pe.BaseAddr

  /// Returns the PEHeaders.
  member _.PEHeaders with get () = pe.PEHeaders

  /// Returns the section headers.
  member _.SectionHeaders with get () = pe.SectionHeaders

  /// Returns the list of relocation blocks.
  member _.RelocBlocks with get () = pe.RelocBlocks

  /// Returns the symbol store.
  member _.Symbols with get () = pe.Symbols

  /// Returns the imported symbols.
  member _.ImportedSymbols with get () = pe.ImportedSymbols

  /// Returns the exported symbols.
  member _.ExportedSymbols with get () = pe.ExportedSymbols

  member _.RawPDB with get () = rawpdb

  /// Finds the section index from the given RVA.
  member _.FindSectionIdxFromRVA rva =
    pe.FindSectionIdxFromRVA rva

  member _.HasCode (sec: SectionHeader) =
    sec.SectionCharacteristics.HasFlag SectionCharacteristics.MemExecute

  interface IBinFile with
    member _.Reader with get() = pe.BinReader

    member _.RawBytes = bytes

    member _.Length = bytes.Length

    member _.Path with get() = path

    member _.Format with get() = FileFormat.PEBinary

    member _.ISA with get() = isa

    member _.EntryPoint = getEntryPoint pe

    member _.BaseAddress with get() = pe.BaseAddr

    member _.IsStripped = Array.isEmpty pe.Symbols.SymbolArray

    member _.IsNXEnabled = isNXEnabled pe

    member _.IsRelocatable = isRelocatable pe

    member _.Slice (addr, len) =
      System.ReadOnlySpan (bytes, translateAddr pe addr, len)

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
            offset <- maxOffset
            maxAddr <- vma + uint64 vmaSize - 1UL
        else idx <- idx + 1
      BinFilePointer (addr, maxAddr, offset, maxOffset)

    member _.GetVMMappedRegions () =
      pe.SectionHeaders
      |> Array.choose (fun sec ->
        let secSize = getVirtualSectionSize sec
        if secSize > 0 then
          let addr = uint64 sec.VirtualAddress + pe.BaseAddr
          Some <| AddrRange (addr, addr + uint64 secSize - 1UL)
        else None)

    member _.GetVMMappedRegions perm =
      pe.SectionHeaders
      |> Array.choose (fun sec ->
        let secPerm = getSecPermission sec.SectionCharacteristics
        let secSize = getVirtualSectionSize sec
        if (secPerm &&& perm = perm) && secSize > 0 then
          let addr = uint64 sec.VirtualAddress + pe.BaseAddr
          Some <| AddrRange (addr, addr + uint64 secSize - 1UL)
        else None)

    member _.TryFindName (addr) =
      if pe.Symbols.SymbolArray.Length = 0 then tryFindSymbolFromBinary pe addr
      else tryFindSymbolFromPDB pe addr

    member _.GetTextSectionPointer () =
      pe.SectionHeaders
      |> Array.tryFind (fun sec -> sec.Name = SecText)
      |> function
        | Some sec ->
          let addr = PEUtils.addrFromRVA pe.BaseAddr sec.VirtualAddress
          let size = sec.SizeOfRawData
          BinFilePointer (addr, addr + uint64 size - 1UL,
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
          BinFilePointer (addr, addr + uint64 size - 1UL,
                          sec.PointerToRawData,
                          sec.PointerToRawData + size - 1)
        | None -> BinFilePointer.Null

    member _.IsInTextOrDataOnlySection addr =
      let rva = int (addr - pe.BaseAddr)
      match pe.FindSectionIdxFromRVA rva with
      | -1 -> false
      | idx -> pe.SectionHeaders[idx].Name = SecText

    member _.GetFunctionAddresses () =
      let staticAddrs =
        [| for s in pe.Symbols.SymbolArray do
             if s.IsFunction then s.Address |]
      let dynamicAddrs =
        [| for addr in pe.ExportedSymbols.Addresses do
             let idx = pe.FindSectionIdxFromRVA (int (addr - pe.BaseAddr))
             if idx <> -1 && isSectionExecutableByIndex pe idx then addr |]
      Array.concat [| staticAddrs; dynamicAddrs |]

    member _.HasRelocationInfo addr = hasRelocationSymbols pe addr

    member _.GetRelocatedAddr _relocAddr = Terminator.futureFeature ()

    member _.GetLinkageTableEntries () = getImportTable pe

    member _.IsLinkageTable addr = isImportTable pe addr

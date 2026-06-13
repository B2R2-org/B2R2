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

  let structure =
    Some { new IBinStructure with
      member _.GetTextSectionPointer() =
        match wm.CodeSection with
        | Some sec ->
          BinFilePointer(uint64 sec.Offset,
                         uint64 sec.Offset + uint64 sec.Size - 1UL,
                         int sec.Offset,
                         int sec.Offset + int sec.Size - 1)
        | None ->
          BinFilePointer.Null

      member _.GetSectionPointer _ =
        Terminator.futureFeature ()

      member _.IsInTextOrDataOnlySection _ =
        Terminator.futureFeature ()

      member _.TryFindSectionNameByAddr(_: Addr) =
        Terminator.futureFeature ()

      member _.TryFindSectionNameByOffset(_: uint32) =
        Terminator.futureFeature ()

      member _.GetFunctionAddresses() =
        Terminator.futureFeature ()
    }

  let linkage =
    Some { new ILinkageTable with
      member _.GetLinkageTableEntries() = getImports wm

      member _.IsLinkageTable _addr = Terminator.futureFeature ()
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

    member _.IsStripped with get() = List.isEmpty wm.CustomSections

    member _.IsNXEnabled with get() = true

    member _.IsRelocatable with get() = false

    member _.NameResolver with get() = None

    member _.Structure with get() = structure

    member _.Relocations with get() = None

    member _.Linkage with get() = linkage

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
          BinFilePointer(addr, maxAddr, int addr, int maxAddr)
        | None -> BinFilePointer.Null

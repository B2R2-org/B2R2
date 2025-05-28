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
open B2R2.FrontEnd.BinFile.Wasm
open B2R2.FrontEnd.BinFile.Wasm.Helper

/// Represents a Web Assembly (Wasm) binary file.
type WasmBinFile (path, bytes, baseAddrOpt) =
  let wm = Parser.parse bytes
  let baseAddr = defaultArg baseAddrOpt 0UL
  let reader = BinReader.Init Endian.Little
  let isa = ISA Architecture.WASM

  new (path, bytes) = WasmBinFile (path, bytes, None)

  member _.WASM with get() = wm

  member _.Sections with get () = wm.SectionsInfo.SecArray

  interface IBinFile with
    member _.Reader with get() = reader

    member _.RawBytes = bytes

    member _.Length = bytes.Length

    member _.Path with get() = path

    member _.Format with get() = FileFormat.WasmBinary

    member _.ISA with get() = isa

    member _.Type with get() = fileTypeOf wm

    member _.EntryPoint = entryPointOf wm

    member _.BaseAddress with get() = baseAddr

    member _.IsStripped = List.isEmpty wm.CustomSections

    member _.IsNXEnabled = true

    member _.IsRelocatable = false

    member _.Slice (addr, len) =
      System.ReadOnlySpan (bytes, int addr, len)

    member _.IsValidAddr (addr) =
      addr >= 0UL && addr < (uint64 bytes.LongLength)

    member this.IsValidRange range =
      (this :> IContentAddressable).IsValidAddr range.Min
      && (this :> IContentAddressable).IsValidAddr range.Max

    member this.IsAddrMappedToFile addr =
      (this :> IContentAddressable).IsValidAddr addr

    member this.IsRangeMappedToFile range =
      (this :> IContentAddressable).IsValidRange range

    member _.IsExecutableAddr _addr = Terminator.futureFeature ()

    member _.GetBoundedPointer addr =
      NoOverlapIntervalMap.tryFindByAddr addr wm.SectionsInfo.SecByAddr
      |> function
        | Some s ->
          let size = s.HeaderSize + s.ContentsSize
          let maxAddr = uint64 s.Offset + uint64 size - 1UL
          BinFilePointer (addr, maxAddr, int addr, int maxAddr)
        | None -> BinFilePointer.Null

    member _.GetVMMappedRegions () = [||]

    member _.GetVMMappedRegions _permission = [||]

    member _.TryFindFunctionName _addr =
      Terminator.futureFeature ()

    member _.GetTextSectionPointer () =
      match wm.CodeSection with
      | Some sec ->
        BinFilePointer (uint64 sec.Offset,
                        uint64 sec.Offset + uint64 sec.Size - 1UL,
                        int sec.Offset,
                        int sec.Offset + int sec.Size - 1)
      | None -> BinFilePointer.Null

    member _.GetSectionPointer _addr = Terminator.futureFeature ()

    member _.IsInTextOrDataOnlySection _ = Terminator.futureFeature ()

    member _.GetFunctionAddresses () = Terminator.futureFeature ()

    member _.GetFunctionAddresses (_) = Terminator.futureFeature ()

    member _.HasRelocationInfo _addr = false

    member _.GetRelocatedAddr _relocAddr = Terminator.futureFeature ()

    member _.GetLinkageTableEntries () = getImports wm

    member _.IsLinkageTable _addr = Terminator.futureFeature ()

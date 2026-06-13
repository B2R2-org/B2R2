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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.FileHelper

/// <summary>
/// Represents a raw binary file (containing only binary code and data without
/// file format).
/// </summary>
type RawBinFile(path, bytes: byte[], isa: ISA, baseAddrOpt) =
  let size = bytes.Length
  let baseAddr = defaultArg baseAddrOpt 0UL
  let reader = BinReader.Init isa.Endian

  (* Raw files expose the whole image as a single rwx region, so we ignore the
     requested permission. *)
  let memoryLayout =
    let region = [| AddrRange.create baseAddr (baseAddr + uint64 size - 1UL) |]
    Some { new IMemoryLayout with
      member _.GetMemoryMappedRegions() = region
      member _.GetMemoryMappedRegions _perm = region }

  interface IBinFile with
    member _.Reader with get() = reader

    member _.RawBytes with get() = System.ReadOnlyMemory bytes

    member _.Length with get() = bytes.Length

    member _.Path with get() = path

    member _.Format with get() = FileFormat.RawBinary

    member _.ISA with get() = isa

    member _.EntryPoint with get() = Some baseAddr

    member _.BaseAddress with get() = baseAddr

    member _.IsStripped with get() = false

    member _.IsNXEnabled with get() = false

    member _.IsPIE with get() = false

    member _.IsBaseRelative with get() = false

    member _.NameResolver with get() = None

    member _.Structure with get() = None

    member _.Relocations with get() = None

    member _.Linkage with get() = None

    member _.MemoryLayout with get() = memoryLayout

    member _.Slice(addr, len) =
      sliceBySafeOffset bytes (addr - baseAddr) len

    member _.IsValidAddr addr =
      addr >= baseAddr && addr < (baseAddr + uint64 size)

    member this.IsValidRange range =
      (this :> IAddressSpace).IsValidAddr range.Min
      && (this :> IAddressSpace).IsValidAddr range.Max

    member this.IsAddrMappedToFile addr =
      (this :> IAddressSpace).IsValidAddr addr

    member this.IsRangeMappedToFile range =
      (this :> IAddressSpace).IsValidRange range

    member this.IsExecutableAddr addr =
      (this :> IAddressSpace).IsValidAddr addr

    member _.GetBoundedPointer(addr) =
      if addr >= baseAddr && addr < (baseAddr + uint64 size) then
        let maxAddr = baseAddr + uint64 size - 1UL
        let offset = addr - baseAddr
        BinFilePointer(addr, maxAddr, int offset, size - 1)
      else BinFilePointer.Null

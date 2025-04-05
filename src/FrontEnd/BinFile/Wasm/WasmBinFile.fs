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

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinFile.Wasm
open B2R2.FrontEnd.BinFile.Wasm.Helper

/// This class represents a Web Assembly (Wasm Module) binary file.
type WasmBinFile (path, bytes, baseAddrOpt) =
  let wm = Parser.parse bytes
  let baseAddr = defaultArg baseAddrOpt 0UL
  let reader = BinReader.Init Endian.Little

  new (path, bytes) = WasmBinFile (path, bytes, None)

  member _.WASM with get() = wm

  interface IBinFile with
    member _.Reader with get() = reader

    member _.RawBytes = bytes

    member _.Length = bytes.Length

    member _.Path with get() = path

    member _.Format with get() = FileFormat.WasmBinary

    member _.ISA with get() = defaultISA

    member _.Type with get() = fileTypeOf wm

    member _.EntryPoint = entryPointOf wm

    member _.BaseAddress with get() = baseAddr

    member _.IsStripped = List.isEmpty wm.CustomSections

    member _.IsNXEnabled = true

    member _.IsRelocatable = false

    member _.GetOffset addr = int addr

    member _.Slice (addr: Addr, size) =
      let span = ReadOnlySpan bytes
      span.Slice (int addr, size)

    member _.Slice (addr: Addr) =
      let span = ReadOnlySpan bytes
      span.Slice (int addr)

    member _.Slice (offset: int, size) =
      let span = ReadOnlySpan bytes
      span.Slice (offset, size)

    member _.Slice (offset: int) =
      let span = ReadOnlySpan bytes
      span.Slice offset

    member _.Slice (ptr: BinFilePointer, size) =
      let span = ReadOnlySpan bytes
      span.Slice (ptr.Offset, size)

    member _.Slice (ptr: BinFilePointer) =
      let span = ReadOnlySpan bytes
      span.Slice ptr.Offset

    member this.ReadByte (addr: Addr) =
      let offset = (this :> IContentAddressable).GetOffset addr
      bytes[offset]

    member _.ReadByte (offset: int) =
      bytes[offset]

    member _.ReadByte (ptr: BinFilePointer) =
      bytes[ptr.Offset]

    member _.IsValidAddr (addr) =
      addr >= 0UL && addr < (uint64 bytes.LongLength)

    member this.IsValidRange range =
      (this :> IContentAddressable).IsValidAddr range.Min
      && (this :> IContentAddressable).IsValidAddr range.Max

    member this.IsInFileAddr addr =
      (this :> IContentAddressable).IsValidAddr addr

    member this.IsInFileRange range =
      (this :> IContentAddressable).IsValidRange range

    member _.IsExecutableAddr _addr = Terminator.futureFeature ()

    member _.GetNotInFileIntervals range =
      FileHelper.getNotInFileIntervals 0UL (uint64 bytes.LongLength) range

    member _.ToBinFilePointer addr =
      BinFilePointer.OfSectionOpt (getSectionsByAddr wm addr |> Seq.tryHead)

    member _.ToBinFilePointer name =
      BinFilePointer.OfSectionOpt (getSectionsByName wm name |> Seq.tryHead)

    member _.TryFindFunctionName (addr) = tryFindFunSymName wm addr

    member _.GetSymbols () = getSymbols wm

    member _.GetStaticSymbols () = [||]

    member _.GetFunctionSymbols () = Terminator.futureFeature ()

    member _.GetDynamicSymbols (?exc) = getDynamicSymbols wm exc

    member _.AddSymbol _addr _symbol = Terminator.futureFeature ()

    member _.GetSections () = getSections wm

    member _.GetSections (addr) = getSectionsByAddr wm addr

    member _.GetSections (name) = getSectionsByName wm name

    member _.GetTextSection () =
      wm.CodeSection
      |> Option.map (fun sec ->
        { Address = uint64 sec.Offset
          FileOffset = uint32 sec.Offset
          Kind = sectionIdToKind SectionId.Code
          Size = sec.Size
          Name = "" })
      |> function Some s -> s | None -> raise SectionNotFoundException

    member _.GetSegments (_isLoadable: bool): Segment[] = [||]

    member _.GetSegments (_addr: Addr): Segment[] = [||]

    member _.GetSegments (_perm: Permission): Segment[] = [||]

    member _.GetFunctionAddresses () = Terminator.futureFeature ()

    member _.GetFunctionAddresses (_) = Terminator.futureFeature ()

    member _.GetRelocationInfos () = [||]

    member _.HasRelocationInfo _addr = false

    member _.GetRelocatedAddr _relocAddr = Terminator.futureFeature ()

    member _.GetLinkageTableEntries () = getImports wm

    member _.IsLinkageTable _addr = Terminator.futureFeature ()

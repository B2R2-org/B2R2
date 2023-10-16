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
open B2R2.FrontEnd.BinFile.Wasm
open B2R2.FrontEnd.BinFile.Wasm.Helper

/// This class represents a Web Assembly (Wasm Module) binary file.
type WasmBinFile (bytes, path, baseAddrOpt) =
  let wm = Parser.parse bytes
  let baseAddr = defaultArg baseAddrOpt 0UL

  new (bytes, path) = WasmBinFile (bytes, path, None)

  member __.WASM with get() = wm

  interface IBinFile with
    member __.FilePath with get() = path

    member __.FileFormat with get() = FileFormat.WasmBinary

    member __.ISA with get() = defaultISA

    member __.FileType with get() = fileTypeOf wm

    member __.EntryPoint = entryPointOf wm

    member __.BaseAddress with get() = baseAddr

    member __.IsStripped = List.isEmpty wm.CustomSections

    member __.IsNXEnabled = true

    member __.IsRelocatable = false

    member __.Length = bytes.Length

    member __.RawBytes = bytes

    member __.Span = ReadOnlySpan bytes

    member __.GetOffset addr = int addr

    member __.Slice (addr: Addr, size) =
      let span = ReadOnlySpan bytes
      span.Slice (int addr, size)

    member __.Slice (addr: Addr) =
      let span = ReadOnlySpan bytes
      span.Slice (int addr)

    member __.Slice (offset: int, size) =
      let span = ReadOnlySpan bytes
      span.Slice (offset, size)

    member __.Slice (offset: int) =
      let span = ReadOnlySpan bytes
      span.Slice offset

    member __.Slice (ptr: BinFilePointer, size) =
      let span = ReadOnlySpan bytes
      span.Slice (ptr.Offset, size)

    member __.Slice (ptr: BinFilePointer) =
      let span = ReadOnlySpan bytes
      span.Slice ptr.Offset

    member __.IsValidAddr (addr) =
      addr >= 0UL && addr < (uint64 bytes.LongLength)

    member __.IsValidRange range =
      (__ :> IContentAddressable).IsValidAddr range.Min
      && (__ :> IContentAddressable).IsValidAddr range.Max

    member __.IsInFileAddr addr =
      (__ :> IContentAddressable).IsValidAddr addr

    member __.IsInFileRange range =
      (__ :> IContentAddressable).IsValidRange range

    member __.IsExecutableAddr _addr = Utils.futureFeature ()

    member __.GetNotInFileIntervals range =
      FileHelper.getNotInFileIntervals 0UL (uint64 bytes.LongLength) range

    member __.ToBinFilePointer addr =
      BinFilePointer.OfSectionOpt (getSectionsByAddr wm addr |> Seq.tryHead)

    member __.ToBinFilePointer name =
      BinFilePointer.OfSectionOpt (getSectionsByName wm name |> Seq.tryHead)

    member __.GetRelocatedAddr _relocAddr = Utils.futureFeature ()

    member __.GetSymbols () = getSymbols wm

    member __.GetStaticSymbols () = Seq.empty

    member __.GetFunctionSymbols () = Utils.futureFeature ()

    member __.GetDynamicSymbols (?exc) = getDynamicSymbols wm exc

    member __.GetRelocationSymbols () = Seq.empty

    member __.AddSymbol _addr _symbol = Utils.futureFeature ()

    member __.TryFindFunctionSymbolName (addr) = tryFindFunSymName wm addr

    member __.GetSections () = getSections wm

    member __.GetSections (addr) = getSectionsByAddr wm addr

    member __.GetSections (name) = getSectionsByName wm name

    member __.GetTextSection () =
      wm.CodeSection
      |> Option.map (fun sec ->
        { Address = uint64 sec.Offset
          FileOffset = uint32 sec.Offset
          Kind = sectionIdToKind SectionId.Code
          Size = sec.Size
          Name = "" })
      |> function Some s -> s | None -> raise SectionNotFoundException

    member __.GetSegments (_isLoadable: bool): seq<Segment> = Seq.empty

    member __.GetSegments (_addr: Addr): seq<Segment> = Seq.empty

    member __.GetSegments (_perm: Permission): seq<Segment> = Seq.empty

    member __.GetLinkageTableEntries () = getImports wm

    member __.IsLinkageTable _addr = Utils.futureFeature ()

    member __.GetFunctionAddresses () = Utils.futureFeature ()

    member __.GetFunctionAddresses (_) = Utils.futureFeature ()

    member __.NewBinFile bs = WasmBinFile (bs, path, Some baseAddr)

    member __.NewBinFile (bs, baseAddr) = WasmBinFile (bs, path, Some baseAddr)


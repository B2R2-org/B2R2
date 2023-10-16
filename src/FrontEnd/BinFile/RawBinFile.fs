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
open System.Collections.Generic
open B2R2

/// This class represents a raw binary file (containing only binary code and
/// data without file format).
type RawBinFile (bytes: byte[], path, isa, baseAddrOpt) =
  let size = bytes.Length
  let baseAddr = defaultArg baseAddrOpt 0UL
  let symbolMap = Dictionary<Addr, Symbol> ()
  let mutable position = 0

  member inline private __.AdjustPosition () =
    if position > bytes.Length then position <- bytes.Length
    else ()

  interface IBinFile with
    member __.FilePath with get() = path

    member __.FileFormat with get() = FileFormat.RawBinary

    member __.ISA with get() = isa

    member __.FileType with get() = FileType.UnknownFile

    member __.EntryPoint = Some baseAddr

    member __.BaseAddress with get() = baseAddr

    member __.IsStripped = false

    member __.IsNXEnabled = false

    member __.IsRelocatable = false

    member __.Length = bytes.Length

    member __.RawBytes = bytes

    member __.Span = ReadOnlySpan bytes

    member __.GetOffset addr = Convert.ToInt32 (addr - baseAddr)

    member __.Slice (addr, size) =
      let offset = (__ :> IContentAddressable).GetOffset addr
      let span = ReadOnlySpan bytes
      span.Slice (offset, size)

    member __.Slice (addr) =
      let offset = (__ :> IContentAddressable).GetOffset addr
      let span = ReadOnlySpan bytes
      span.Slice offset

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

    member __.Read (buffer, offset, size) =
      Array.blit bytes position buffer offset size
      position <- position + size
      __.AdjustPosition ()

    member __.ReadByte () =
      let res = bytes[position]
      position <- position + 1
      __.AdjustPosition ()
      res

    member __.Seek (addr: Addr) =
      position <- (__ :> IContentAddressable).GetOffset addr
      __.AdjustPosition ()

    member __.Seek (offset: int) =
      position <- offset
      __.AdjustPosition ()

    member __.IsValidAddr addr =
      addr >= baseAddr && addr < (baseAddr + uint64 size)

    member __.IsValidRange range =
      (__ :> IContentAddressable).IsValidAddr range.Min
      && (__ :> IContentAddressable).IsValidAddr range.Max

    member __.IsInFileAddr addr =
      (__ :> IContentAddressable).IsValidAddr addr

    member __.IsInFileRange range =
      (__ :> IContentAddressable).IsValidRange range

    member __.IsExecutableAddr addr =
      (__ :> IContentAddressable).IsValidAddr addr

    member __.GetNotInFileIntervals range =
      FileHelper.getNotInFileIntervals baseAddr (uint64 size) range

    member __.ToBinFilePointer addr =
      if addr = baseAddr then BinFilePointer (baseAddr, 0, size - 1)
      else BinFilePointer.Null

    member __.ToBinFilePointer (_name: string) = BinFilePointer.Null

    member __.GetRelocatedAddr _relocAddr = Utils.impossible ()

    member __.GetSymbols () =
      Seq.map (fun (KeyValue(k, v)) -> v) symbolMap

    member __.GetStaticSymbols () = (__ :> IBinFile).GetSymbols ()

    member __.GetFunctionSymbols () = (__ :> IBinFile).GetStaticSymbols ()

    member __.GetDynamicSymbols (?_excludeImported) = Seq.empty

    member __.GetRelocationSymbols () = Seq.empty

    member __.AddSymbol addr symbol = symbolMap[addr] <- symbol

    member __.TryFindFunctionSymbolName (_addr) =
      if symbolMap.ContainsKey(_addr) then Ok symbolMap[_addr].Name
      else Error ErrorCase.SymbolNotFound

    member __.GetSections () =
      Seq.singleton { Address = baseAddr
                      FileOffset = 0u
                      Kind = SectionKind.ExecutableSection
                      Size = uint32 size
                      Name = "" }

    member __.GetSections (addr: Addr) =
      if addr >= baseAddr && addr < (baseAddr + uint64 size) then
        (__ :> IBinFile).GetSections ()
      else
        Seq.empty

    member __.GetSections (_: string): seq<Section> = Seq.empty

    member __.GetTextSection () = raise SectionNotFoundException

    member __.GetSegments (_isLoadable: bool) =
      Seq.singleton { Address = baseAddr
                      Offset = 0u
                      Size = uint32 size
                      SizeInFile = uint32 size
                      Permission = Permission.Readable
                                   ||| Permission.Executable }

    member __.GetSegments (addr: Addr) =
      (__ :> IBinFile).GetSegments ()
      |> Seq.filter (fun s -> (addr >= s.Address)
                              && (addr < s.Address + uint64 s.Size))

    member __.GetSegments (perm: Permission) =
      (__ :> IBinFile).GetSegments ()
      |> Seq.filter (fun s -> (s.Permission &&& perm = perm) && s.Size > 0u)

    member __.GetLinkageTableEntries () = Seq.empty

    member __.IsLinkageTable _ = false

    member __.GetFunctionAddresses () =
      (__ :> IBinFile).GetFunctionSymbols ()
      |> Seq.filter (fun s -> s.Kind = SymFunctionType)
      |> Seq.map (fun s -> s.Address)

    member __.GetFunctionAddresses (_) =
      (__ :> IBinFile).GetFunctionAddresses ()

    member __.NewBinFile bs =
      RawBinFile (bs, path, isa, Some baseAddr)

    member __.NewBinFile (bs, baseAddr) =
      RawBinFile (bs, path, isa, Some baseAddr)


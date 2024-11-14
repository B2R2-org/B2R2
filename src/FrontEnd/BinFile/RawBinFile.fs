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
type RawBinFile (path, bytes: byte[], isa, baseAddrOpt) =
  let size = bytes.Length
  let baseAddr = defaultArg baseAddrOpt 0UL
  let symbolMap = Dictionary<Addr, Symbol> ()
  let reader = BinReader.Init isa.Endian

  interface IBinFile with
    member __.Reader with get() = reader

    member __.RawBytes = bytes

    member __.Length = bytes.Length

    member __.Path with get() = path

    member __.Format with get() = FileFormat.RawBinary

    member __.ISA with get() = isa

    member __.Type with get() = FileType.UnknownFile

    member __.EntryPoint = Some baseAddr

    member __.BaseAddress with get() = baseAddr

    member __.IsStripped = false

    member __.IsNXEnabled = false

    member __.IsRelocatable = false

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

    member __.ReadByte (addr: Addr) =
      let offset = (__ :> IContentAddressable).GetOffset addr
      bytes[offset]

    member __.ReadByte (offset: int) =
      bytes[offset]

    member __.ReadByte (ptr: BinFilePointer) =
      bytes[ptr.Offset]

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

    member __.TryFindFunctionName (_addr) =
      if symbolMap.ContainsKey(_addr) then Ok symbolMap[_addr].Name
      else Error ErrorCase.SymbolNotFound

    member __.GetSymbols () =
      Seq.map (fun (KeyValue(k, v)) -> v) symbolMap |> Seq.toArray

    member __.GetStaticSymbols () = (__ :> IBinFile).GetSymbols ()

    member __.GetFunctionSymbols () = (__ :> IBinFile).GetStaticSymbols ()

    member __.GetDynamicSymbols (?_excludeImported) = [||]

    member __.AddSymbol addr symbol = symbolMap[addr] <- symbol

    member __.GetSections () =
      [| { Address = baseAddr
           FileOffset = 0u
           Kind = SectionKind.ExecutableSection
           Size = uint32 size
           Name = "" } |]

    member __.GetSections (addr: Addr) =
      if addr >= baseAddr && addr < (baseAddr + uint64 size) then
        (__ :> IBinFile).GetSections ()
      else [||]

    member __.GetSections (_: string): Section[] = [||]

    member __.GetTextSection () = raise SectionNotFoundException

    member __.GetSegments (_isLoadable: bool) =
      [| { Address = baseAddr
           Offset = 0u
           Size = uint32 size
           SizeInFile = uint32 size
           Permission = Permission.Readable ||| Permission.Executable } |]

    member __.GetSegments (addr: Addr) =
      (__ :> IBinFile).GetSegments ()
      |> Array.filter (fun s -> (addr >= s.Address)
                             && (addr < s.Address + uint64 s.Size))

    member __.GetSegments (perm: Permission) =
      (__ :> IBinFile).GetSegments ()
      |> Array.filter (fun s -> (s.Permission &&& perm = perm) && s.Size > 0u)

    member __.GetFunctionAddresses () =
      (__ :> IBinFile).GetFunctionSymbols ()
      |> Array.filter (fun s -> s.Kind = SymFunctionType)
      |> Array.map (fun s -> s.Address)

    member __.GetFunctionAddresses (_) =
      (__ :> IBinFile).GetFunctionAddresses ()

    member __.GetRelocationInfos () = [||]

    member __.HasRelocationInfo _ = false

    member __.GetRelocatedAddr _relocAddr = Utils.impossible ()

    member __.GetLinkageTableEntries () = [||]

    member __.IsLinkageTable _ = false
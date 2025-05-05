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
open B2R2.FrontEnd.BinLifter

/// This class represents a raw binary file (containing only binary code and
/// data without file format).
type RawBinFile (path, bytes: byte[], isa: ISA, baseAddrOpt) =
  let size = bytes.Length
  let baseAddr = defaultArg baseAddrOpt 0UL
  let symbolMap = Dictionary<Addr, Symbol> ()
  let reader = BinReader.Init isa.Endian

  interface IBinFile with
    member _.Reader with get() = reader

    member _.RawBytes = bytes

    member _.Length = bytes.Length

    member _.Path with get() = path

    member _.Format with get() = FileFormat.RawBinary

    member _.ISA with get() = isa

    member _.Type with get() = FileType.UnknownFile

    member _.EntryPoint = Some baseAddr

    member _.BaseAddress with get() = baseAddr

    member _.IsStripped = false

    member _.IsNXEnabled = false

    member _.IsRelocatable = false

    member _.GetOffset addr = Convert.ToInt32 (addr - baseAddr)

    member this.Slice (addr, size) =
      let offset = (this :> IContentAddressable).GetOffset addr
      let span = ReadOnlySpan bytes
      span.Slice (offset, size)

    member this.Slice (addr) =
      let offset = (this :> IContentAddressable).GetOffset addr
      let span = ReadOnlySpan bytes
      span.Slice offset

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

    member _.IsValidAddr addr =
      addr >= baseAddr && addr < (baseAddr + uint64 size)

    member this.IsValidRange range =
      (this :> IContentAddressable).IsValidAddr range.Min
      && (this :> IContentAddressable).IsValidAddr range.Max

    member this.IsInFileAddr addr =
      (this :> IContentAddressable).IsValidAddr addr

    member this.IsInFileRange range =
      (this :> IContentAddressable).IsValidRange range

    member this.IsExecutableAddr addr =
      (this :> IContentAddressable).IsValidAddr addr

    member _.GetNotInFileIntervals range =
      FileHelper.getNotInFileIntervals baseAddr (uint64 size) range

    member _.ToBinFilePointer addr =
      if addr = baseAddr then BinFilePointer (baseAddr, 0, size - 1)
      else BinFilePointer.Null

    member _.ToBinFilePointer (_name: string) = BinFilePointer.Null

    member _.TryFindFunctionName (_addr) =
      if symbolMap.ContainsKey(_addr) then Ok symbolMap[_addr].Name
      else Error ErrorCase.SymbolNotFound

    member _.GetSymbols () =
      Seq.map (fun (KeyValue(k, v)) -> v) symbolMap |> Seq.toArray

    member this.GetStaticSymbols () = (this :> IBinFile).GetSymbols ()

    member this.GetFunctionSymbols () = (this :> IBinFile).GetStaticSymbols ()

    member _.GetDynamicSymbols (?_excludeImported) = [||]

    member _.AddSymbol addr symbol = symbolMap[addr] <- symbol

    member _.GetSections () =
      [| { Address = baseAddr
           FileOffset = 0u
           Kind = SectionKind.CodeSection
           Size = uint32 size
           Name = "" } |]

    member this.GetSections (addr: Addr) =
      if addr >= baseAddr && addr < (baseAddr + uint64 size) then
        (this :> IBinFile).GetSections ()
      else [||]

    member _.GetSections (_: string): Section[] = [||]

    member _.GetTextSection () = raise SectionNotFoundException

    member _.GetSegments (_isLoadable: bool) =
      [| { Address = baseAddr
           Offset = 0u
           Size = uint32 size
           SizeInFile = uint32 size
           Permission = Permission.Readable ||| Permission.Executable } |]

    member this.GetSegments (addr: Addr) =
      (this :> IBinFile).GetSegments ()
      |> Array.filter (fun s -> (addr >= s.Address)
                             && (addr < s.Address + uint64 s.Size))

    member this.GetSegments (perm: Permission) =
      (this :> IBinFile).GetSegments ()
      |> Array.filter (fun s -> (s.Permission &&& perm = perm) && s.Size > 0u)

    member this.GetFunctionAddresses () =
      (this :> IBinFile).GetFunctionSymbols ()
      |> Array.filter (fun s -> s.Kind = SymFunctionType)
      |> Array.map (fun s -> s.Address)

    member this.GetFunctionAddresses (_) =
      (this :> IBinFile).GetFunctionAddresses ()

    member _.GetRelocationInfos () = [||]

    member _.HasRelocationInfo _ = false

    member _.GetRelocatedAddr _relocAddr = Terminator.impossible ()

    member _.GetLinkageTableEntries () = [||]

    member _.IsLinkageTable _ = false

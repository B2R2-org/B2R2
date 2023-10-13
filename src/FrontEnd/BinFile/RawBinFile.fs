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
/// data without file format)
type RawBinFile private (bytes: byte[], path, isa, ftype, content, baseAddr) =
  inherit BinFile (path, FileFormat.RawBinary, isa, ftype, content)
  let size = bytes.Length
  let usize = uint64 size
  let symbolMap = Dictionary<Addr, Symbol> ()

  new (bytes, path, isa, baseOpt) =
    let ftype = FileType.UnknownFile
    let baseAddr = defaultArg baseOpt 0UL
    let content = RawBinaryContent (bytes, baseAddr)
    RawBinFile (bytes, path, isa, ftype, content, baseAddr)

  override __.BaseAddress with get() = baseAddr

  override __.IsStripped = false

  override __.IsNXEnabled = false

  override __.IsRelocatable = false

  override __.EntryPoint = Some baseAddr

  override __.TextStartAddr = baseAddr

  override __.GetRelocatedAddr _relocAddr = Utils.impossible ()

  override __.AddSymbol addr symbol =
    symbolMap[addr] <- symbol

  override __.GetSymbols () =
    Seq.map (fun (KeyValue(k, v)) -> v) symbolMap

  override __.GetStaticSymbols () = __.GetSymbols ()

  override __.GetDynamicSymbols (?_excludeImported) = Seq.empty

  override __.GetRelocationSymbols () = Seq.empty

  override __.GetSections () =
    Seq.singleton { Address = baseAddr
                    FileOffset = 0UL
                    Kind = SectionKind.ExecutableSection
                    Size = usize
                    Name = "" }

  override __.GetSections (addr: Addr) =
    if addr >= baseAddr && addr < (baseAddr + usize) then
      __.GetSections ()
    else
      Seq.empty

  override __.GetSections (_: string): seq<Section> = Seq.empty

  override __.GetTextSections () = Seq.empty

  override __.GetSegments (_isLoadable) =
    Seq.singleton { Address = baseAddr
                    Offset = 0UL
                    Size = usize
                    SizeInFile = usize
                    Permission = Permission.Readable ||| Permission.Executable }

  override __.GetLinkageTableEntries () = Seq.empty

  override __.IsLinkageTable _ = false

  override __.TryFindFunctionSymbolName (_addr) =
    if symbolMap.ContainsKey(_addr) then Ok symbolMap[_addr].Name
    else Error ErrorCase.SymbolNotFound

  override __.ToBinFilePointer addr =
    if addr = baseAddr then BinFilePointer (baseAddr, 0, size - 1)
    else BinFilePointer.Null

  override __.ToBinFilePointer (_name: string) = BinFilePointer.Null

  override __.NewBinFile bs =
    RawBinFile (bs, path, isa, Some baseAddr)

  override __.NewBinFile (bs, baseAddr) =
    RawBinFile (bs, path, isa, Some baseAddr)

and RawBinaryContent (bytes, baseAddr) =
  let usize = uint64 bytes.Length
  interface IContentAddressable with
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

    member __.IsValidAddr addr =
      addr >= baseAddr && addr < (baseAddr + usize)

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
      FileHelper.getNotInFileIntervals baseAddr usize range

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
open B2R2.FrontEnd.BinFile.ELF
open B2R2.FrontEnd.BinFile.ELF.Helper

/// <summary>
///   This class represents an ELF binary file.
/// </summary>
type ELFBinFile
  private (elf, path, isa, ftype, baseAddr, content, regbay, forEmu) =
  inherit BinFile (path, FileFormat.ELFBinary, isa, ftype, content)

  new (bytes, path) =
    ELFBinFile (bytes, path, None, None, false)

  new (bytes, path, baseAddr, regbay) =
    ELFBinFile (bytes, path, baseAddr, regbay, false)

  new (bytes, path, baseAddr, regbay, forEmu) =
    let elf = Parser.parse bytes baseAddr regbay forEmu
    let isa = elf.ISA
    let ftype = convFileType elf.ELFHdr.ELFFileType
    let content = ELFBinaryContent (elf, bytes) :> IContentAddressable
    ELFBinFile (elf, path, isa, ftype, baseAddr, content, regbay, forEmu)

  override __.BaseAddress with get() = elf.BaseAddr

  override __.IsStripped = not (Map.containsKey ".symtab" elf.SecInfo.SecByName)

  override __.IsNXEnabled = isNXEnabled elf

  override __.IsRelocatable = isRelocatable content.Span elf

  override __.EntryPoint = Some elf.ELFHdr.EntryPoint

  override __.TextStartAddr = getTextStartAddr elf

  override __.GetRelocatedAddr relocAddr = getRelocatedAddr elf relocAddr

  override __.AddSymbol addr symbol = Utils.futureFeature ()

  override __.GetSymbols () = getSymbols elf

  override __.GetStaticSymbols () = getStaticSymbols elf

  override __.GetDynamicSymbols (?exc) = getDynamicSymbols exc elf

  override __.GetRelocationSymbols () = getRelocSymbols elf

  override __.GetSections () = getSections elf

  override __.GetSections (addr) = getSectionsByAddr elf addr

  override __.GetSections (name) = getSectionsByName elf name

  override __.GetTextSections () = getTextSections elf

  override __.GetSegments (isLoadable) = getSegments elf isLoadable

  override __.GetLinkageTableEntries () = getPLT elf

  override __.IsLinkageTable addr = isInPLT elf addr

  override __.TryFindFunctionSymbolName (addr) = tryFindFuncSymb elf addr

  override __.ToBinFilePointer addr =
    BinFilePointer.OfSectionOpt (getSectionsByAddr elf addr |> Seq.tryHead)

  override __.ToBinFilePointer name =
    BinFilePointer.OfSectionOpt (getSectionsByName elf name |> Seq.tryHead)

  override __.GetFunctionAddresses () =
    base.GetFunctionAddresses ()
    |> addExtraFunctionAddrs content.Span elf false

  override __.GetFunctionAddresses (useExcInfo) =
    base.GetFunctionAddresses ()
    |> addExtraFunctionAddrs content.Span elf useExcInfo

  override __.NewBinFile bs =
    ELFBinFile (bs, path, baseAddr, regbay, forEmu)

  override __.NewBinFile (bs, baseAddr) =
    ELFBinFile (bs, path, Some baseAddr, regbay, forEmu)

  member __.ELF with get() = elf

  /// List of dynamic section entries.
  member __.DynamicSectionEntries with get() =
    Section.getDynamicSectionEntries content.Span elf.BinReader elf.SecInfo

and ELFBinaryContent (elf, bytes) =
  interface IContentAddressable with
    member __.Length = bytes.Length

    member __.RawBytes = bytes

    member __.Span = ReadOnlySpan bytes

    member __.GetOffset addr =
      translateAddrToOffset addr elf |> Convert.ToInt32

    member __.Slice (addr, size) =
      let offset = translateAddrToOffset addr elf |> Convert.ToInt32
      let span = ReadOnlySpan bytes
      span.Slice (offset, size)

    member __.Slice (addr) =
      let offset = translateAddrToOffset addr elf |> Convert.ToInt32
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

    member __.IsValidAddr addr = isValidAddr elf addr

    member __.IsValidRange range = isValidRange elf range

    member __.IsInFileAddr addr = isInFileAddr elf addr

    member __.IsInFileRange range = isInFileRange elf range

    member __.IsExecutableAddr addr = isExecutableAddr elf addr

    member __.GetNotInFileIntervals range = getNotInFileIntervals elf range


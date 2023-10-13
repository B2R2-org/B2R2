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
open B2R2.FrontEnd.BinFile.PE.Helper

/// This class represents a PE binary file.
type PEBinFile private (pe, path, isa, ftype, content, baseAddr, rawpdb) =
  inherit BinFile (path, FileFormat.PEBinary, isa, ftype, content)

  new (bytes, path) = PEBinFile (bytes, path, None, [||])

  new (bytes, path, baseAddr) = PEBinFile (bytes, path, baseAddr, [||])

  new (bytes, path, rawpdb) = PEBinFile (bytes, path, None, rawpdb)

  new (bytes, path, baseAddr, rawpdb) =
    let pe = PE.Parser.parse bytes path baseAddr rawpdb
    let isa = getISA pe
    let ftype = getFileType pe
    let content = PEBinaryContent (pe, bytes)
    PEBinFile (pe, path, isa, ftype, content, baseAddr, rawpdb)

  override __.BaseAddress with get() = pe.BaseAddr
  override __.IsStripped = Array.isEmpty pe.SymbolInfo.SymbolArray
  override __.IsNXEnabled = isNXEnabled pe
  override __.IsRelocatable = isRelocatable pe
  override __.EntryPoint = getEntryPoint pe
  override __.TextStartAddr = getTextStartAddr pe
  override __.GetRelocatedAddr _relocAddr = Utils.futureFeature ()
  override __.AddSymbol _addr _symbol = Utils.futureFeature ()
  override __.GetSymbols () = getSymbols pe
  override __.GetStaticSymbols () = getStaticSymbols pe
  override __.GetDynamicSymbols (?exc) = getDynamicSymbols pe exc
  override __.GetRelocationSymbols () = getRelocationSymbols pe
  override __.GetSections () = getSections pe
  override __.GetSections (addr) = getSectionsByAddr pe addr
  override __.GetSections (name) = getSectionsByName pe name
  override __.GetTextSections () = getTextSections pe
  override __.GetSegments (_isLoadable) = getSegments pe
  override __.GetLinkageTableEntries () = getImportTable pe
  override __.IsLinkageTable addr = isImportTable pe addr
  override __.TryFindFunctionSymbolName (addr) = tryFindFuncSymb pe addr
  override __.ToBinFilePointer addr =
    BinFilePointer.OfSectionOpt (getSectionsByAddr pe addr |> Seq.tryHead)
  override __.ToBinFilePointer name =
    BinFilePointer.OfSectionOpt (getSectionsByName pe name |> Seq.tryHead)
  override __.NewBinFile bs = PEBinFile (bs, path, baseAddr, rawpdb)
  override __.NewBinFile (bs, baseAddr) =
    PEBinFile (bs, path, Some baseAddr, rawpdb)
  member __.PE with get() = pe
  member __.RawPDB = rawpdb

and PEBinaryContent (pe, bytes) =
  interface IContentAddressable with
    member __.Length = bytes.Length

    member __.RawBytes = bytes

    member __.Span = ReadOnlySpan bytes

    member __.GetOffset addr = translateAddr pe addr

    member __.Slice (addr, size) =
      let offset = translateAddr pe addr |> Convert.ToInt32
      let span = ReadOnlySpan bytes
      span.Slice (offset, size)

    member __.Slice (addr) =
      let offset = translateAddr pe addr |> Convert.ToInt32
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

    member __.IsValidAddr addr = isValidAddr pe addr

    member __.IsValidRange range = isValidRange pe range

    member __.IsInFileAddr addr = isInFileAddr pe addr

    member __.IsInFileRange range = isInFileRange pe range

    member __.IsExecutableAddr addr = isExecutableAddr pe addr

    member __.GetNotInFileIntervals range = getNotInFileIntervals pe range


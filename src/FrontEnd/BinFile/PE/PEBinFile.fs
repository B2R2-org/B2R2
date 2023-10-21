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
open System.IO
open B2R2
open B2R2.FrontEnd.BinFile.PE.Helper

/// This class represents a PE binary file.
type PEBinFile (path, stream: Stream, baseAddrOpt, rawpdb) =
  let pe = PE.Parser.parse path stream baseAddrOpt rawpdb

  new (path, stream) = PEBinFile (path, stream, None, [||])

  new (path, stream, rawpdb) = PEBinFile (path, stream, None, rawpdb)

  member __.PE with get() = pe

  member __.RawPDB = rawpdb

  interface IBinFile with
    member __.FilePath with get() = path

    member __.FileFormat with get() = FileFormat.PEBinary

    member __.ISA with get() = getISA pe

    member __.FileType with get() = getFileType pe

    member __.EntryPoint = getEntryPoint pe

    member __.BaseAddress with get() = pe.BaseAddr

    member __.IsStripped = Array.isEmpty pe.SymbolInfo.SymbolArray

    member __.IsNXEnabled = isNXEnabled pe

    member __.IsRelocatable = isRelocatable pe

    member __.Length = int stream.Length

    member __.RawBytes = Utils.futureFeature () // XXX

    member __.Span = Utils.futureFeature (); ReadOnlySpan [||]

    member __.GetOffset addr = translateAddr pe addr

    member __.Slice (addr, size) =
      let offset = translateAddr pe addr |> Convert.ToInt32
      (__ :> IBinFile).Slice (offset=offset, size=size)

    member __.Slice (addr) =
      let offset = translateAddr pe addr |> Convert.ToInt32
      let size = int stream.Length - offset
      (__ :> IBinFile).Slice (offset=offset, size=size)

    member __.Slice (offset: int, size) =
      let buf = FileHelper.readChunk stream (uint64 offset) size
      ReadOnlySpan buf

    member __.Slice (offset: int) =
      let size = int stream.Length - offset
      (__ :> IBinFile).Slice (offset=offset, size=size)

    member __.Slice (ptr: BinFilePointer, size) =
      (__ :> IBinFile).Slice (offset=ptr.Offset, size=size)

    member __.Slice (ptr: BinFilePointer) =
      (__ :> IBinFile).Slice (offset=ptr.Offset)

    member __.Read (_buffer, _offset, _size) = Utils.futureFeature ()

    member __.ReadByte () = Utils.futureFeature ()

    member __.Seek (_addr: Addr): unit = Utils.futureFeature ()

    member __.Seek (_offset: int): unit = Utils.futureFeature ()

    member __.IsValidAddr addr = isValidAddr pe addr

    member __.IsValidRange range = isValidRange pe range

    member __.IsInFileAddr addr = isInFileAddr pe addr

    member __.IsInFileRange range = isInFileRange pe range

    member __.IsExecutableAddr addr = isExecutableAddr pe addr

    member __.GetNotInFileIntervals range = getNotInFileIntervals pe range

    member __.ToBinFilePointer addr =
      BinFilePointer.OfSectionOpt (getSectionsByAddr pe addr |> Seq.tryHead)

    member __.ToBinFilePointer name =
      BinFilePointer.OfSectionOpt (getSectionsByName pe name |> Seq.tryHead)

    member __.GetRelocatedAddr _relocAddr = Utils.futureFeature ()

    member __.GetSymbols () = getSymbols pe

    member __.GetStaticSymbols () = getStaticSymbols pe

    member __.GetFunctionSymbols () =
      let self = __ :> IBinFile
      let staticSymbols =
        self.GetStaticSymbols ()
        |> Seq.filter (fun s -> s.Kind = SymFunctionType)
      let dynamicSymbols =
        self.GetDynamicSymbols (true)
        |> Seq.filter (fun s -> s.Kind = SymFunctionType)
      Seq.append staticSymbols dynamicSymbols

    member __.GetDynamicSymbols (?exc) = getDynamicSymbols pe exc

    member __.GetRelocationSymbols () = getRelocationSymbols pe

    member __.AddSymbol _addr _symbol = Utils.futureFeature ()

    member __.TryFindFunctionSymbolName (addr) = tryFindFuncSymb pe addr

    member __.GetSections () = getSections pe

    member __.GetSections (addr) = getSectionsByAddr pe addr

    member __.GetSections (name) = getSectionsByName pe name

    member __.GetTextSection () = getTextSection pe

    member __.GetSegments (_isLoadable: bool) = getSegments pe

    member __.GetSegments (addr) =
      (__ :> IBinFile).GetSegments ()
      |> Seq.filter (fun s -> (addr >= s.Address)
                              && (addr < s.Address + uint64 s.Size))

    member __.GetSegments (perm) =
      (__ :> IBinFile).GetSegments ()
      |> Seq.filter (fun s -> (s.Permission &&& perm = perm) && s.Size > 0u)

    member __.GetLinkageTableEntries () = getImportTable pe

    member __.IsLinkageTable addr = isImportTable pe addr

    member __.GetFunctionAddresses () =
      (__ :> IBinFile).GetFunctionSymbols ()
      |> Seq.map (fun s -> s.Address)

    member __.GetFunctionAddresses (_) =
      (__ :> IBinFile).GetFunctionAddresses ()

    member __.NewBinFile bs = Utils.futureFeature ()

    member __.NewBinFile (bs, baseAddr) = Utils.futureFeature ()

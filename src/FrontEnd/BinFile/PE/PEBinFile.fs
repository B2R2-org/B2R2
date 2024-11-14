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
open B2R2.FrontEnd.BinFile.PE
open B2R2.FrontEnd.BinFile.PE.Helper

/// This class represents a PE binary file.
type PEBinFile (path, bytes: byte[], baseAddrOpt, rawpdb) =
  let pe = Parser.parse path bytes baseAddrOpt rawpdb

  new (path, bytes) = PEBinFile (path, bytes, None, [||])

  new (path, bytes, rawpdb) = PEBinFile (path, bytes, None, rawpdb)

  member __.PE with get() = pe

  member __.RawPDB = rawpdb

  interface IBinFile with
    member __.Reader with get() = pe.BinReader

    member __.RawBytes = bytes

    member __.Length = bytes.Length

    member __.Path with get() = path

    member __.Format with get() = FileFormat.PEBinary

    member __.ISA with get() = getISA pe

    member __.Type with get() = getFileType pe

    member __.EntryPoint = getEntryPoint pe

    member __.BaseAddress with get() = pe.BaseAddr

    member __.IsStripped = Array.isEmpty pe.SymbolInfo.SymbolArray

    member __.IsNXEnabled = isNXEnabled pe

    member __.IsRelocatable = isRelocatable pe

    member __.GetOffset addr = translateAddr pe addr

    member __.Slice (addr, size) =
      let offset = translateAddr pe addr |> Convert.ToInt32
      (__ :> IBinFile).Slice (offset=offset, size=size)

    member __.Slice (addr) =
      let offset = translateAddr pe addr |> Convert.ToInt32
      (__ :> IBinFile).Slice (offset=offset)

    member __.Slice (offset: int, size) =
      ReadOnlySpan (bytes, offset, size)

    member __.Slice (offset: int) =
      ReadOnlySpan(bytes).Slice offset

    member __.Slice (ptr: BinFilePointer, size) =
      ReadOnlySpan (bytes, ptr.Offset, size)

    member __.Slice (ptr: BinFilePointer) =
      ReadOnlySpan(bytes).Slice ptr.Offset

    member __.ReadByte (addr: Addr) =
      let offset = translateAddr pe addr |> Convert.ToInt32
      bytes[offset]

    member __.ReadByte (offset: int) =
      bytes[offset]

    member __.ReadByte (ptr: BinFilePointer) =
      bytes[ptr.Offset]

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

    member __.TryFindFunctionName (addr) = tryFindFuncSymb pe addr

    member __.GetSymbols () = getSymbols pe

    member __.GetStaticSymbols () = getStaticSymbols pe

    member __.GetFunctionSymbols () =
      let self = __ :> IBinFile
      let staticSymbols =
        self.GetStaticSymbols ()
        |> Array.filter (fun s -> s.Kind = SymFunctionType)
      let dynamicSymbols =
        self.GetDynamicSymbols (true)
        |> Array.filter (fun s -> s.Kind = SymFunctionType)
      Array.append staticSymbols dynamicSymbols

    member __.GetDynamicSymbols (?exc) = getDynamicSymbols pe exc

    member __.AddSymbol _addr _symbol = Utils.futureFeature ()

    member __.GetSections () = getSections pe

    member __.GetSections (addr) = getSectionsByAddr pe addr

    member __.GetSections (name) = getSectionsByName pe name

    member __.GetTextSection () = getTextSection pe

    member __.GetSegments (_isLoadable: bool) = getSegments pe

    member __.GetSegments (addr) =
      (__ :> IBinFile).GetSegments ()
      |> Array.filter (fun s -> (addr >= s.Address)
                             && (addr < s.Address + uint64 s.Size))

    member __.GetSegments (perm) =
      (__ :> IBinFile).GetSegments ()
      |> Array.filter (fun s -> (s.Permission &&& perm = perm) && s.Size > 0u)

    member __.GetFunctionAddresses () =
      (__ :> IBinFile).GetFunctionSymbols ()
      |> Array.map (fun s -> s.Address)

    member __.GetFunctionAddresses (_) =
      (__ :> IBinFile).GetFunctionAddresses ()

    member __.GetRelocationInfos () = getRelocationSymbols pe

    member __.HasRelocationInfo addr = hasRelocationSymbols pe addr

    member __.GetRelocatedAddr _relocAddr = Utils.futureFeature ()

    member __.GetLinkageTableEntries () = getImportTable pe

    member __.IsLinkageTable addr = isImportTable pe addr
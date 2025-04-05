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

  member _.PE with get() = pe

  member _.RawPDB = rawpdb

  interface IBinFile with
    member _.Reader with get() = pe.BinReader

    member _.RawBytes = bytes

    member _.Length = bytes.Length

    member _.Path with get() = path

    member _.Format with get() = FileFormat.PEBinary

    member _.ISA with get() = getISA pe

    member _.Type with get() = getFileType pe

    member _.EntryPoint = getEntryPoint pe

    member _.BaseAddress with get() = pe.BaseAddr

    member _.IsStripped = Array.isEmpty pe.SymbolInfo.SymbolArray

    member _.IsNXEnabled = isNXEnabled pe

    member _.IsRelocatable = isRelocatable pe

    member _.GetOffset addr = translateAddr pe addr

    member this.Slice (addr, size) =
      let offset = translateAddr pe addr |> Convert.ToInt32
      (this :> IBinFile).Slice (offset=offset, size=size)

    member this.Slice (addr) =
      let offset = translateAddr pe addr |> Convert.ToInt32
      (this :> IBinFile).Slice (offset=offset)

    member _.Slice (offset: int, size) =
      ReadOnlySpan (bytes, offset, size)

    member _.Slice (offset: int) =
      ReadOnlySpan(bytes).Slice offset

    member _.Slice (ptr: BinFilePointer, size) =
      ReadOnlySpan (bytes, ptr.Offset, size)

    member _.Slice (ptr: BinFilePointer) =
      ReadOnlySpan(bytes).Slice ptr.Offset

    member _.ReadByte (addr: Addr) =
      let offset = translateAddr pe addr |> Convert.ToInt32
      bytes[offset]

    member _.ReadByte (offset: int) =
      bytes[offset]

    member _.ReadByte (ptr: BinFilePointer) =
      bytes[ptr.Offset]

    member _.IsValidAddr addr = isValidAddr pe addr

    member _.IsValidRange range = isValidRange pe range

    member _.IsInFileAddr addr = isInFileAddr pe addr

    member _.IsInFileRange range = isInFileRange pe range

    member _.IsExecutableAddr addr = isExecutableAddr pe addr

    member _.GetNotInFileIntervals range = getNotInFileIntervals pe range

    member _.ToBinFilePointer addr =
      BinFilePointer.OfSectionOpt (getSectionsByAddr pe addr |> Seq.tryHead)

    member _.ToBinFilePointer name =
      BinFilePointer.OfSectionOpt (getSectionsByName pe name |> Seq.tryHead)

    member _.TryFindFunctionName (addr) = tryFindFuncSymb pe addr

    member _.GetSymbols () = getSymbols pe

    member _.GetStaticSymbols () = getStaticSymbols pe

    member this.GetFunctionSymbols () =
      let self = this :> IBinFile
      let staticSymbols =
        self.GetStaticSymbols ()
        |> Array.filter (fun s -> s.Kind = SymFunctionType)
      let dynamicSymbols =
        self.GetDynamicSymbols (true)
        |> Array.filter (fun s -> s.Kind = SymFunctionType)
      Array.append staticSymbols dynamicSymbols

    member _.GetDynamicSymbols (?exc) = getDynamicSymbols pe exc

    member _.AddSymbol _addr _symbol = Terminator.futureFeature ()

    member _.GetSections () = getSections pe

    member _.GetSections (addr) = getSectionsByAddr pe addr

    member _.GetSections (name) = getSectionsByName pe name

    member _.GetTextSection () = getTextSection pe

    member _.GetSegments (_isLoadable: bool) = getSegments pe

    member this.GetSegments (addr) =
      (this :> IBinFile).GetSegments ()
      |> Array.filter (fun s -> (addr >= s.Address)
                             && (addr < s.Address + uint64 s.Size))

    member this.GetSegments (perm) =
      (this :> IBinFile).GetSegments ()
      |> Array.filter (fun s -> (s.Permission &&& perm = perm) && s.Size > 0u)

    member this.GetFunctionAddresses () =
      (this :> IBinFile).GetFunctionSymbols ()
      |> Array.map (fun s -> s.Address)

    member this.GetFunctionAddresses (_) =
      (this :> IBinFile).GetFunctionAddresses ()

    member _.GetRelocationInfos () = getRelocationSymbols pe

    member _.HasRelocationInfo addr = hasRelocationSymbols pe addr

    member _.GetRelocatedAddr _relocAddr = Terminator.futureFeature ()

    member _.GetLinkageTableEntries () = getImportTable pe

    member _.IsLinkageTable addr = isImportTable pe addr

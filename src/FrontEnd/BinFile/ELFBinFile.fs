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
type ELFBinFile (bytes, path, baseAddr, regbay, forEmu) =
  let elf = Parser.parse bytes baseAddr regbay forEmu

  new (bytes, path) =
    ELFBinFile (bytes, path, None, None, false)

  new (bytes, path, baseAddr, regbay) =
    ELFBinFile (bytes, path, baseAddr, regbay, false)

  member __.ELF with get() = elf

  /// List of dynamic section entries.
  member __.DynamicSectionEntries with get() =
    let span = ReadOnlySpan bytes
    Section.getDynamicSectionEntries span elf.BinReader elf.SecInfo

  interface IBinFile with
    member __.FilePath with get() = path

    member __.FileFormat with get() = FileFormat.ELFBinary

    member __.ISA with get() = elf.ISA

    member __.FileType with get() = convFileType elf.ELFHdr.ELFFileType

    member __.EntryPoint = Some elf.ELFHdr.EntryPoint

    member __.BaseAddress with get() = elf.BaseAddr

    member __.IsStripped = not (Map.containsKey ".symtab" elf.SecInfo.SecByName)

    member __.IsNXEnabled = isNXEnabled elf

    member __.IsRelocatable = isRelocatable (ReadOnlySpan bytes) elf

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

    member __.ToBinFilePointer addr =
      BinFilePointer.OfSectionOpt (getSectionsByAddr elf addr |> Seq.tryHead)

    member __.ToBinFilePointer name =
      BinFilePointer.OfSectionOpt (getSectionsByName elf name |> Seq.tryHead)

    member __.GetRelocatedAddr relocAddr = getRelocatedAddr elf relocAddr

    member __.GetSymbols () = getSymbols elf

    member __.GetStaticSymbols () = getStaticSymbols elf

    member __.GetFunctionSymbols () =
      let dict = Collections.Generic.Dictionary<Addr, Symbol> ()
      let self = __ :> IBinFile
      self.GetStaticSymbols ()
      |> Seq.iter (fun s ->
        if s.Kind = SymFunctionType then dict[s.Address] <- s
        elif s.Kind = SymNoType (* This is to handle ppc's PLT symbols. *)
          && s.Address > 0UL && s.Name.Contains "pic32."
        then dict[s.Address] <- s
        else ())
      self.GetDynamicSymbols (true) |> Seq.iter (fun s ->
        if dict.ContainsKey s.Address then ()
        elif s.Kind = SymFunctionType then dict[s.Address] <- s
        else ())
      dict.Values

    member __.GetDynamicSymbols (?exc) = getDynamicSymbols exc elf

    member __.GetRelocationSymbols () = getRelocSymbols elf

    member __.AddSymbol addr symbol = Utils.futureFeature ()

    member __.TryFindFunctionSymbolName (addr) = tryFindFuncSymb elf addr

    member __.GetSections () = getSections elf

    member __.GetSections (addr) = getSectionsByAddr elf addr

    member __.GetSections (name) = getSectionsByName elf name

    member __.GetTextSection () = getTextSection elf

    member __.GetSegments (isLoadable) = getSegments elf isLoadable

    member __.GetSegments (addr) =
      (__ :> IBinFile).GetSegments ()
      |> Seq.filter (fun s -> (addr >= s.Address)
                              && (addr < s.Address + s.Size))

    member __.GetSegments (perm) =
      (__ :> IBinFile).GetSegments ()
      |> Seq.filter (fun s -> (s.Permission &&& perm = perm) && s.Size > 0UL)

    member __.GetLinkageTableEntries () = getPLT elf

    member __.IsLinkageTable addr = isInPLT elf addr

    member __.GetFunctionAddresses () =
      (__ :> IBinFile).GetFunctionSymbols ()
      |> Seq.map (fun s -> s.Address)
      |> addExtraFunctionAddrs (ReadOnlySpan bytes) elf false

    member __.GetFunctionAddresses (useExcInfo) =
      (__ :> IBinFile).GetFunctionSymbols ()
      |> Seq.map (fun s -> s.Address)
      |> addExtraFunctionAddrs (ReadOnlySpan bytes) elf useExcInfo

    member __.NewBinFile bs =
      ELFBinFile (bs, path, baseAddr, regbay, forEmu)

    member __.NewBinFile (bs, baseAddr) =
      ELFBinFile (bs, path, Some baseAddr, regbay, forEmu)


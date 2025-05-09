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
open B2R2.Collections
open B2R2.FrontEnd.BinFile.ELF
open B2R2.FrontEnd.BinFile.ELF.Helper

/// Represents an ELF binary file.
type ELFBinFile (path, bytes: byte[], baseAddrOpt, rfOpt) =
  let toolBox = Header.parse baseAddrOpt bytes
  let hdr = toolBox.Header
  let phdrs = lazy ProgramHeader.parse toolBox
  let shdrs = lazy Section.parse toolBox
  let loadables = lazy ProgramHeader.getLoadableProgHeaders phdrs.Value
  let symbInfo = lazy Symbol.parse toolBox shdrs.Value
  let relocs = lazy RelocationInfo.parse toolBox shdrs.Value symbInfo.Value
  let plt = lazy PLT.parse toolBox shdrs.Value symbInfo.Value relocs.Value
  let exnInfo = lazy ExceptionInfo.parse toolBox shdrs.Value rfOpt relocs.Value
  let notInMemRanges = lazy invalidRangesByVM hdr loadables.Value
  let notInFileRanges = lazy invalidRangesByFileBounds hdr loadables.Value
  let executableRanges = lazy executableRanges shdrs.Value loadables.Value

  /// ELF Header information.
  member _.Header with get() = hdr

  /// List of dynamic section entries.
  member _.DynamicSectionEntries with get() =
    DynamicSection.readEntries toolBox shdrs.Value

  /// Try to find a section by its name.
  member _.TryFindSection (name: string) =
    shdrs.Value |> Array.tryFind (fun s -> s.SecName = name)

  /// Find a section by its index.
  member _.FindSection (idx: int) =
    shdrs.Value[idx]

  /// ELF program headers.
  member _.ProgramHeaders with get() = phdrs.Value

  /// ELF section headers.
  member _.SectionHeaders with get() = shdrs.Value

  /// PLT.
  member _.PLT with get() = plt.Value

  /// Exception information.
  member _.ExceptionInfo with get() = exnInfo.Value

  /// ELF symbol information.
  member _.SymbolInfo with get() = symbInfo.Value

  /// Relocation information.
  member _.RelocationInfo with get() = relocs.Value

  interface IBinFile with
    member _.Reader with get() = toolBox.Reader

    member _.RawBytes = bytes

    member _.Length = bytes.Length

    member _.Path with get() = path

    member _.Format with get() = FileFormat.ELFBinary

    member _.ISA with get() = toolBox.ISA

    member _.Type with get() = toFileType hdr.ELFFileType

    member _.EntryPoint = Some hdr.EntryPoint

    member _.BaseAddress with get() = toolBox.BaseAddress

    member _.IsStripped =
      shdrs.Value |> Array.exists (fun s -> s.SecName = ".symtab") |> not

    member _.IsNXEnabled = isNXEnabled phdrs.Value

    member _.IsRelocatable = isRelocatable toolBox shdrs.Value

    member _.GetOffset addr =
      translateAddrToOffset loadables.Value shdrs.Value addr |> Convert.ToInt32

    member this.Slice (addr, size) =
      let offset = (this :> IContentAddressable).GetOffset addr
      (this :> IContentAddressable).Slice (offset=offset, size=size)

    member this.Slice (addr) =
      let offset = (this :> IContentAddressable).GetOffset addr
      (this :> IContentAddressable).Slice (offset=offset)

    member _.Slice (offset: int, size) =
      ReadOnlySpan (bytes, offset, size)

    member _.Slice (offset: int) =
      ReadOnlySpan(bytes).Slice offset

    member _.Slice (ptr: BinFilePointer, size) =
      ReadOnlySpan (bytes, ptr.Offset, size)

    member _.Slice (ptr: BinFilePointer) =
      ReadOnlySpan(bytes).Slice ptr.Offset

    member this.ReadByte (addr: Addr) =
      let offset = (this :> IContentAddressable).GetOffset addr
      bytes[offset]

    member _.ReadByte (offset: int) =
      bytes[offset]

    member _.ReadByte (ptr: BinFilePointer) =
      bytes[ptr.Offset]

    member _.IsValidAddr addr =
      IntervalSet.containsAddr addr notInMemRanges.Value |> not

    member _.IsValidRange range =
      IntervalSet.findAll range notInMemRanges.Value |> List.isEmpty

    member _.IsInFileAddr addr =
      IntervalSet.containsAddr addr notInFileRanges.Value |> not

    member _.IsInFileRange range =
      IntervalSet.findAll range notInFileRanges.Value |> List.isEmpty

    member _.IsExecutableAddr addr =
      IntervalSet.containsAddr addr executableRanges.Value

    member _.GetNotInFileIntervals range =
      IntervalSet.findAll range notInFileRanges.Value
      |> List.toArray
      |> Array.map range.Slice

    member _.ToBinFilePointer addr =
      getSectionsByAddr shdrs.Value addr
      |> Seq.tryHead
      |> BinFilePointer.OfSection

    member _.ToBinFilePointer name =
      getSectionsByName shdrs.Value name
      |> Seq.tryHead
      |> BinFilePointer.OfSection

    member _.TryFindFunctionName (addr) =
      tryFindFuncSymb symbInfo.Value addr

    member _.GetSymbols () = getSymbols shdrs.Value symbInfo.Value

    member _.GetStaticSymbols () = getStaticSymbols shdrs.Value symbInfo.Value

    member this.GetFunctionSymbols () =
      let dict = Collections.Generic.Dictionary<Addr, Symbol> ()
      let f = this :> IBinFile
      f.GetStaticSymbols ()
      |> Seq.iter (fun s ->
        if s.Kind = SymFunctionType then dict[s.Address] <- s
        elif s.Kind = SymNoType (* This is to handle ppc's PLT symbols. *)
          && s.Address > 0UL && s.Name.Contains "pic32."
        then dict[s.Address] <- s
        else ())
      f.GetDynamicSymbols (true) |> Seq.iter (fun s ->
        if dict.ContainsKey s.Address then ()
        elif s.Kind = SymFunctionType then dict[s.Address] <- s
        else ())
      dict.Values |> Seq.toArray

    member _.GetDynamicSymbols (?exc) =
      getDynamicSymbols exc shdrs.Value symbInfo.Value

    member _.AddSymbol _addr _symbol = Terminator.futureFeature ()

    member _.GetSections () = getSections shdrs.Value

    member _.GetSections (addr) = getSectionsByAddr shdrs.Value addr

    member _.GetSections (name) = getSectionsByName shdrs.Value name

    member _.GetTextSection () = getTextSection shdrs.Value

    member _.GetSegments (isLoadable) =
      if isLoadable then getSegments loadables.Value
      else getSegments phdrs.Value

    member this.GetSegments (addr) =
      (this :> IBinFile).GetSegments ()
      |> Array.filter (fun s -> (addr >= s.Address)
                             && (addr < s.Address + uint64 s.Size))

    member this.GetSegments (perm) =
      (this :> IBinFile).GetSegments ()
      |> Array.filter (fun s -> (s.Permission &&& perm = perm) && s.Size > 0u)

    member this.GetFunctionAddresses () =
      (this :> IBinFile).GetFunctionSymbols ()
      |> Seq.map (fun s -> s.Address)
      |> addExtraFunctionAddrs toolBox shdrs.Value loadables.Value
                               relocs.Value None

    member this.GetFunctionAddresses (useExcInfo) =
      let exnInfo = if useExcInfo then Some exnInfo.Value else None
      (this :> IBinFile).GetFunctionSymbols ()
      |> Seq.map (fun s -> s.Address)
      |> addExtraFunctionAddrs toolBox shdrs.Value loadables.Value
                               relocs.Value exnInfo

    member _.GetRelocationInfos () = getRelocSymbols relocs.Value

    member _.HasRelocationInfo addr =
      relocs.Value.RelocByAddr.ContainsKey addr

    member _.GetRelocatedAddr relocAddr =
      getRelocatedAddr relocs.Value relocAddr

    member _.GetLinkageTableEntries () =
      plt.Value
      |> NoOverlapIntervalMap.fold (fun acc _ entry -> entry :: acc) []
      |> List.sortBy (fun entry -> entry.TrampolineAddress)
      |> List.toArray

    member _.IsLinkageTable addr =
      NoOverlapIntervalMap.containsAddr addr plt.Value

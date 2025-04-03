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
  member __.Header with get() = hdr

  /// List of dynamic section entries.
  member __.DynamicSectionEntries with get() =
    DynamicSection.readEntries toolBox shdrs.Value

  /// Try to find a section by its name.
  member __.TryFindSection (name: string) =
    shdrs.Value |> Array.tryFind (fun s -> s.SecName = name)

  /// Find a section by its index.
  member __.FindSection (idx: int) =
    shdrs.Value[idx]

  /// ELF program headers.
  member __.ProgramHeaders with get() = phdrs.Value

  /// ELF section headers.
  member __.SectionHeaders with get() = shdrs.Value

  /// PLT.
  member __.PLT with get() = plt.Value

  /// Exception information.
  member __.ExceptionInfo with get() = exnInfo.Value

  /// ELF symbol information.
  member __.SymbolInfo with get() = symbInfo.Value

  /// Relocation information.
  member __.RelocationInfo with get() = relocs.Value

  interface IBinFile with
    member __.Reader with get() = toolBox.Reader

    member __.RawBytes = bytes

    member __.Length = bytes.Length

    member __.Path with get() = path

    member __.Format with get() = FileFormat.ELFBinary

    member __.ISA with get() = ISA.Init hdr.MachineType hdr.Endian

    member __.Type with get() = toFileType hdr.ELFFileType

    member __.EntryPoint = Some hdr.EntryPoint

    member __.BaseAddress with get() = toolBox.BaseAddress

    member __.IsStripped =
      shdrs.Value |> Array.exists (fun s -> s.SecName = ".symtab") |> not

    member __.IsNXEnabled = isNXEnabled phdrs.Value

    member __.IsRelocatable = isRelocatable toolBox shdrs.Value

    member __.GetOffset addr =
      translateAddrToOffset loadables.Value shdrs.Value addr |> Convert.ToInt32

    member __.Slice (addr, size) =
      let offset = (__ :> IContentAddressable).GetOffset addr
      (__ :> IContentAddressable).Slice (offset=offset, size=size)

    member __.Slice (addr) =
      let offset = (__ :> IContentAddressable).GetOffset addr
      (__ :> IContentAddressable).Slice (offset=offset)

    member __.Slice (offset: int, size) =
      ReadOnlySpan (bytes, offset, size)

    member __.Slice (offset: int) =
      ReadOnlySpan(bytes).Slice offset

    member __.Slice (ptr: BinFilePointer, size) =
      ReadOnlySpan (bytes, ptr.Offset, size)

    member __.Slice (ptr: BinFilePointer) =
      ReadOnlySpan(bytes).Slice ptr.Offset

    member __.ReadByte (addr: Addr) =
      let offset = (__ :> IContentAddressable).GetOffset addr
      bytes[offset]

    member __.ReadByte (offset: int) =
      bytes[offset]

    member __.ReadByte (ptr: BinFilePointer) =
      bytes[ptr.Offset]

    member __.IsValidAddr addr =
      IntervalSet.containsAddr addr notInMemRanges.Value |> not

    member __.IsValidRange range =
      IntervalSet.findAll range notInMemRanges.Value |> List.isEmpty

    member __.IsInFileAddr addr =
      IntervalSet.containsAddr addr notInFileRanges.Value |> not

    member __.IsInFileRange range =
      IntervalSet.findAll range notInFileRanges.Value |> List.isEmpty

    member __.IsExecutableAddr addr =
      IntervalSet.containsAddr addr executableRanges.Value

    member __.GetNotInFileIntervals range =
      IntervalSet.findAll range notInFileRanges.Value
      |> List.toArray
      |> Array.map range.Slice

    member __.ToBinFilePointer addr =
      getSectionsByAddr shdrs.Value addr
      |> Seq.tryHead
      |> BinFilePointer.OfSectionOpt

    member __.ToBinFilePointer name =
      getSectionsByName shdrs.Value name
      |> Seq.tryHead
      |> BinFilePointer.OfSectionOpt

    member __.TryFindFunctionName (addr) =
      tryFindFuncSymb symbInfo.Value addr

    member __.GetSymbols () = getSymbols shdrs.Value symbInfo.Value

    member __.GetStaticSymbols () = getStaticSymbols shdrs.Value symbInfo.Value

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
      dict.Values |> Seq.toArray

    member __.GetDynamicSymbols (?exc) =
      getDynamicSymbols exc shdrs.Value symbInfo.Value

    member __.AddSymbol _addr _symbol = Terminator.futureFeature ()

    member __.GetSections () = getSections shdrs.Value

    member __.GetSections (addr) = getSectionsByAddr shdrs.Value addr

    member __.GetSections (name) = getSectionsByName shdrs.Value name

    member __.GetTextSection () = getTextSection shdrs.Value

    member __.GetSegments (isLoadable) =
      if isLoadable then getSegments loadables.Value
      else getSegments phdrs.Value

    member __.GetSegments (addr) =
      (__ :> IBinFile).GetSegments ()
      |> Array.filter (fun s -> (addr >= s.Address)
                             && (addr < s.Address + uint64 s.Size))

    member __.GetSegments (perm) =
      (__ :> IBinFile).GetSegments ()
      |> Array.filter (fun s -> (s.Permission &&& perm = perm) && s.Size > 0u)

    member __.GetFunctionAddresses () =
      (__ :> IBinFile).GetFunctionSymbols ()
      |> Seq.map (fun s -> s.Address)
      |> addExtraFunctionAddrs toolBox shdrs.Value loadables.Value
                               relocs.Value None

    member __.GetFunctionAddresses (useExcInfo) =
      let exnInfo = if useExcInfo then Some exnInfo.Value else None
      (__ :> IBinFile).GetFunctionSymbols ()
      |> Seq.map (fun s -> s.Address)
      |> addExtraFunctionAddrs toolBox shdrs.Value loadables.Value
                               relocs.Value exnInfo

    member __.GetRelocationInfos () = getRelocSymbols relocs.Value

    member __.HasRelocationInfo addr =
      relocs.Value.RelocByAddr.ContainsKey addr

    member __.GetRelocatedAddr relocAddr =
      getRelocatedAddr relocs.Value relocAddr

    member __.GetLinkageTableEntries () =
      plt.Value
      |> ARMap.fold (fun acc _ entry -> entry :: acc) []
      |> List.sortBy (fun entry -> entry.TrampolineAddress)
      |> List.toArray

    member __.IsLinkageTable addr = ARMap.containsAddr addr plt.Value

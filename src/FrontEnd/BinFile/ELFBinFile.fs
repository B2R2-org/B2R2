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

  /// Try to find a section by its name.
  member _.TryFindSection (name: string) =
    shdrs.Value |> Array.tryFind (fun s -> s.SecName = name)

  /// Find a section by its index.
  member _.FindSection (idx: int) =
    shdrs.Value[idx]

  /// Is this a PLT section?
  member _.IsPLT (sec: Section) =
    PLT.isPLTSectionName sec.SecName

  /// Is this section contains executable code?
  member _.HasCode (sec: Section) =
    sec.SecFlags.HasFlag SectionFlag.SHF_EXECINSTR
    && not (PLT.isPLTSectionName sec.SecName)

  interface IBinFile with
    member _.Reader with get() = toolBox.Reader

    member _.RawBytes = bytes

    member _.Length = bytes.Length

    member _.Path with get() = path

    member _.Format with get() = FileFormat.ELFBinary

    member _.ISA with get() = toolBox.ISA

    member _.Type with get() = toFileType hdr.ELFType

    member _.EntryPoint = Some hdr.EntryPoint

    member _.BaseAddress with get() = toolBox.BaseAddress

    member _.IsStripped =
      shdrs.Value |> Array.exists (fun s -> s.SecName = ".symtab") |> not

    member _.IsNXEnabled = isNXEnabled phdrs.Value

    member _.IsRelocatable = isRelocatable toolBox shdrs.Value

    member _.GetOffset addr =
      translateAddrToOffset loadables.Value shdrs.Value addr |> Convert.ToInt32

    member _.IsValidAddr addr =
      IntervalSet.containsAddr addr notInMemRanges.Value |> not

    member _.IsValidRange range =
      IntervalSet.findAll range notInMemRanges.Value |> List.isEmpty

    member _.IsAddrMappedToFile addr =
      IntervalSet.containsAddr addr notInFileRanges.Value |> not

    member _.IsRangeMappedToFile range =
      IntervalSet.findAll range notInFileRanges.Value |> List.isEmpty

    member _.IsExecutableAddr addr =
      IntervalSet.containsAddr addr executableRanges.Value

    member _.GetBoundedPointer addr =
      let phdrs = phdrs.Value
      let mutable found = false
      let mutable idx = 0
      let mutable maxAddr = 0UL
      let mutable offset = 0
      let mutable maxOffset = 0
      while not found && idx < phdrs.Length do
        let ph = phdrs[idx]
        if addr >= ph.PHAddr && addr < ph.PHAddr + ph.PHMemSize then
          found <- true
          if addr < ph.PHAddr + ph.PHFileSize then
            offset <- int ph.PHOffset + int (addr - ph.PHAddr)
            maxOffset <- int ph.PHOffset + int ph.PHFileSize - 1
            maxAddr <- ph.PHAddr + ph.PHFileSize - 1UL
          else
            offset <- int ph.PHOffset + int (addr - ph.PHAddr)
            maxOffset <- int ph.PHOffset + int ph.PHMemSize - 1
            maxAddr <- ph.PHAddr + ph.PHMemSize - 1UL
        else idx <- idx + 1
      BinFilePointer (addr, maxAddr, offset, maxOffset)

    member _.GetVMMappedRegions () =
      phdrs.Value
      |> Array.choose (fun ph ->
        if ph.PHMemSize > 0UL then
          Some <| AddrRange (ph.PHAddr, ph.PHAddr + ph.PHMemSize - 1UL)
        else None)

    member _.GetVMMappedRegions (perm) =
      phdrs.Value
      |> Array.choose (fun ph ->
        let phPerm = ProgramHeader.flagsToPerm ph.PHFlags
        if (phPerm &&& perm = perm) && ph.PHMemSize > 0UL then
          Some <| AddrRange (ph.PHAddr, ph.PHAddr + ph.PHMemSize - 1UL)
        else None)

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

    member _.GetTextSectionPointer () =
      shdrs.Value
      |> Array.tryFind (fun sec -> sec.SecName = Section.SecText)
      |> function
        | Some s ->
          BinFilePointer (s.SecAddr, s.SecAddr + uint64 s.SecSize - 1UL,
                          int s.SecOffset, int s.SecOffset + int s.SecSize - 1)
        | None -> BinFilePointer.Null

    member _.GetSectionPointer name =
      shdrs.Value
      |> Array.tryFind (fun sec -> sec.SecName = name)
      |> function
        | Some sec ->
          BinFilePointer (sec.SecAddr,
                          sec.SecAddr + uint64 sec.SecSize - 1UL,
                          int sec.SecOffset,
                          int sec.SecOffset + int sec.SecSize - 1)
        | None -> BinFilePointer.Null

    member _.IsInTextOrDataOnlySection addr =
      shdrs.Value
      |> Array.tryFind (fun sec ->
        addr >= sec.SecAddr && addr < sec.SecAddr + uint64 sec.SecSize)
      |> function
        | Some sec ->
          sec.SecName = Section.SecText || sec.SecName = Section.SecROData
        | None -> false

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

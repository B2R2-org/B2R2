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
  let toolBox = Header.parse baseAddrOpt bytes |> Toolbox.Init bytes
  let hdr = toolBox.Header
  let phdrs = lazy ProgramHeaders.parse toolBox
  let shdrs = lazy SectionHeaders.parse toolBox
  let loadables = lazy ProgramHeaders.filterLoadables phdrs.Value
  let symbs = lazy SymbolStore (toolBox, shdrs.Value)
  let relocs = lazy RelocationInfo (toolBox, shdrs.Value, symbs.Value)
  let plt = lazy PLT.parse toolBox shdrs.Value symbs.Value relocs.Value
  let exn = lazy ExceptionData.parse toolBox shdrs.Value rfOpt relocs.Value
  let notInMemRanges = lazy invalidRangesByVM hdr loadables.Value
  let notInFileRanges = lazy invalidRangesByFileBounds hdr loadables.Value
  let executableRanges = lazy executableRanges shdrs.Value loadables.Value

  /// ELF Header information.
  member _.Header with get () = hdr

  /// List of dynamic section entries.
  member _.DynamicArrayEntries with get () =
    DynamicArray.parse toolBox shdrs.Value

  /// ELF program headers.
  member _.ProgramHeaders with get () = phdrs.Value

  /// ELF section headers.
  member _.SectionHeaders with get () = shdrs.Value

  /// PLT.
  member _.PLT with get () = plt.Value

  /// Exception information.
  member _.ExceptionFrame with get () = exn.Value.ExceptionFrame

  /// LSDA table.
  member _.LSDATable with get () = exn.Value.LSDATable

  /// Unwinding table.
  member _.UnwindingTable with get () = exn.Value.UnwindingTbl

  /// ELF symbol information.
  member _.Symbols with get () = symbs.Value

  /// Relocation information.
  member _.RelocationInfo with get () = relocs.Value

  /// Try to find a section by its name.
  member _.TryFindSection (name: string) =
    shdrs.Value |> Array.tryFind (fun s -> s.SecName = name)

  /// Find a section by its index.
  member _.FindSection (idx: int) =
    shdrs.Value[idx]

  /// Is this a PLT section?
  member _.IsPLT sec =
    PLT.isPLTSectionName sec.SecName

  /// Is this section contains executable code?
  member _.HasCode sec =
    sec.SecFlags.HasFlag SectionFlags.SHF_EXECINSTR
    && not (PLT.isPLTSectionName sec.SecName)

  interface IBinFile with
    member _.Reader with get () = toolBox.Reader

    member _.RawBytes = bytes

    member _.Length = bytes.Length

    member _.Path with get () = path

    member _.Format with get () = FileFormat.ELFBinary

    member _.ISA with get () = toolBox.ISA

    member _.EntryPoint = Some hdr.EntryPoint

    member _.BaseAddress with get () = toolBox.BaseAddress

    member _.IsStripped =
      shdrs.Value |> Array.exists (fun s -> s.SecName = ".symtab") |> not

    member _.IsNXEnabled =
      let predicate e = e.PHType = ProgramHeaderType.PT_GNU_STACK
      match Array.tryFind predicate phdrs.Value with
      | Some s ->
        let perm = ProgramHeader.FlagsToPerm s.PHFlags
        perm.HasFlag Permission.Executable |> not
      | _ -> false

    member _.IsRelocatable =
      let pred e = e.DTag = DTag.DT_DEBUG
      toolBox.Header.ELFType = ELFType.ET_DYN
      && DynamicArray.parse toolBox shdrs.Value |> Array.exists pred

    member _.Slice (addr, len) =
      let offset =
        translateAddrToOffset loadables.Value shdrs.Value addr
        |> Convert.ToInt32
      ReadOnlySpan (bytes, offset, len)

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
        let phPerm = ProgramHeader.FlagsToPerm ph.PHFlags
        if (phPerm &&& perm = perm) && ph.PHMemSize > 0UL then
          Some <| AddrRange (ph.PHAddr, ph.PHAddr + ph.PHMemSize - 1UL)
        else None)

    member _.TryFindName (addr) =
      symbs.Value.TryFindSymbol addr
      |> Result.map (fun s -> s.SymName)

    member _.GetTextSectionPointer () =
      shdrs.Value
      |> Array.tryFind (fun sec -> sec.SecName = Section.Text)
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
        | Some sec -> sec.SecName = Section.Text || sec.SecName = Section.ROData
        | None -> false

    member _.GetFunctionAddresses () =
      let staticFuncs =
        [| for s in symbs.Value.StaticSymbols do
             if Symbol.IsFunction s && Symbol.IsDefined s then s.Addr |]
      let dynamicFuncs =
        [| for s in symbs.Value.DynamicSymbols do
             if Symbol.IsFunction s && Symbol.IsDefined s then s.Addr |]
      let extraFuncs =
        findExtraFnAddrs toolBox shdrs.Value loadables.Value relocs.Value
      Array.concat [| staticFuncs; dynamicFuncs; extraFuncs |]
      |> Set.ofArray
      |> Set.toArray

    member _.HasRelocationInfo addr =
      relocs.Value.Contains addr

    member _.GetRelocatedAddr relocAddr =
      getRelocatedAddr relocs.Value relocAddr

    member _.GetLinkageTableEntries () =
      plt.Value
      |> NoOverlapIntervalMap.fold (fun acc _ entry -> entry :: acc) []
      |> List.sortBy (fun entry -> entry.TrampolineAddress)
      |> List.toArray

    member _.IsLinkageTable addr =
      NoOverlapIntervalMap.containsAddr addr plt.Value

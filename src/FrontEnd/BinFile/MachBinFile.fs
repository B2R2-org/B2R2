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

open B2R2
open B2R2.Collections
open B2R2.FrontEnd.BinFile.Mach
open B2R2.FrontEnd.BinFile.Mach.Helper

/// Represents a Mach-O binary file.
type MachBinFile (path, bytes: byte[], isa, baseAddrOpt) =
  let toolBox = Header.parse bytes baseAddrOpt isa
  let cmds = lazy LoadCommand.parse toolBox
  let segCmds = lazy Segment.extract cmds.Value
  let segMap = lazy Segment.buildMap segCmds.Value
  let secs = lazy Section.parse toolBox segCmds.Value
  let symInfo = lazy Symbol.parse toolBox cmds.Value secs.Value
  let relocs = lazy Reloc.parse toolBox secs.Value
  let notInMemRanges = lazy invalidRangesByVM toolBox segCmds.Value
  let notInFileRanges = lazy invalidRangesByFileBounds toolBox segCmds.Value
  let executableRanges = lazy executableRanges segCmds.Value

  member _.Header with get () = toolBox.Header

  member _.Commands with get () = cmds.Value

  member _.Sections with get () = secs.Value

  member _.SymbolInfo with get () = symInfo.Value

  member _.StaticSymbols with get () =
    symInfo.Value.Symbols
    |> Array.filter Symbol.isStatic

  member _.DynamicSymbols with get () =
    symInfo.Value.Symbols
    |> Array.filter (Symbol.isStatic >> not)

  member _.Relocations with get () = relocs.Value

  member _.IsPLT (sec: MachSection) =
    match sec.SecType with
    | SectionType.S_NON_LAZY_SYMBOL_POINTERS
    | SectionType.S_LAZY_SYMBOL_POINTERS
    | SectionType.S_SYMBOL_STUBS -> true
    | _ -> false

  member _.HasCode (sec: MachSection) =
    match sec.SecType with
    | SectionType.S_NON_LAZY_SYMBOL_POINTERS
    | SectionType.S_LAZY_SYMBOL_POINTERS
    | SectionType.S_SYMBOL_STUBS -> false
    | _ ->
      let seg = NoOverlapIntervalMap.findByAddr sec.SecAddr segMap.Value
      seg.InitProt &&& int MachVMProt.Executable > 0

  interface IBinFile with
    member _.Reader with get() = toolBox.Reader

    member _.RawBytes = bytes

    member _.Length = bytes.Length

    member _.Path with get() = path

    member _.Format with get() = FileFormat.MachBinary

    member _.ISA with get() = getISA toolBox.Header

    member _.Type with get() = convFileType toolBox.Header.FileType

    member _.EntryPoint = computeEntryPoint segCmds.Value cmds.Value

    member _.BaseAddress with get() = toolBox.BaseAddress

    member _.IsStripped = isStripped secs.Value symInfo.Value

    member _.IsNXEnabled = isNXEnabled toolBox.Header

    member _.IsRelocatable = toolBox.Header.Flags.HasFlag MachFlag.MH_PIE

    member _.Slice (addr, len) =
      let offset = translateAddr segMap.Value addr
      System.ReadOnlySpan (bytes, offset, len)

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
      let segCmds = segCmds.Value
      let mutable found = false
      let mutable idx = 0
      let mutable maxAddr = 0UL
      let mutable offset = 0
      let mutable maxOffset = 0
      while not found && idx < segCmds.Length do
        let seg = segCmds[idx]
        if addr >= seg.VMAddr && addr < seg.VMAddr + seg.VMSize then
          found <- true
          if addr < seg.VMAddr + seg.FileSize then
            offset <- int seg.FileOff + int (addr - seg.VMAddr)
            maxOffset <- int seg.FileOff + int seg.FileSize - 1
            maxAddr <- seg.VMAddr + seg.FileSize - 1UL
          else
            offset <- int seg.FileOff + int (addr - seg.VMAddr)
            maxOffset <- int seg.FileOff + int seg.VMSize - 1
            maxAddr <- seg.VMAddr + seg.VMSize - 1UL
        else idx <- idx + 1
      BinFilePointer (addr, maxAddr, offset, maxOffset)

    member _.GetVMMappedRegions () =
      segCmds.Value
      |> Array.choose (fun seg ->
        if seg.VMSize > 0UL then
          Some <| AddrRange (seg.VMAddr, seg.VMAddr + seg.VMSize - 1UL)
        else None)

    member _.GetVMMappedRegions perm =
      segCmds.Value
      |> Array.choose (fun seg ->
        let segPerm: Permission = LanguagePrimitives.EnumOfValue seg.MaxProt
        if (segPerm &&& perm = perm) && seg.VMSize > 0UL then
          Some <| AddrRange (seg.VMAddr, seg.VMAddr + seg.VMSize - 1UL)
        else None)

    member _.TryFindFunctionName (addr) =
      tryFindFuncSymb symInfo.Value addr

    member _.GetTextSectionPointer () =
      let secs = secs.Value
      let secText = Section.getTextSectionIndex secs
      let sec = secs[secText]
      BinFilePointer (sec.SecAddr,
                      sec.SecAddr + sec.SecSize - 1UL,
                      int sec.SecOffset,
                      int sec.SecOffset + int sec.SecSize - 1)

    member _.GetSectionPointer name =
      secs.Value
      |> Array.tryFind (fun sec -> sec.SecName = name)
      |> function
        | Some sec ->
          BinFilePointer (sec.SecAddr,
                          sec.SecAddr + sec.SecSize - 1UL,
                          int sec.SecOffset,
                          int sec.SecOffset + int sec.SecSize - 1)
        | None -> BinFilePointer.Null

    member _.IsInTextOrDataOnlySection addr =
      secs.Value
      |> Array.tryFind (fun sec ->
        addr >= sec.SecAddr && addr < sec.SecAddr + sec.SecSize)
      |> function
        | Some sec -> sec.SecName = Section.SecText
        | None -> false

    member _.GetFunctionAddresses () =
      let secText = Section.getTextSectionIndex secs.Value
      [| for s in symInfo.Value.Symbols do
           if Symbol.isFunc secText s && s.SymAddr > 0UL then s.SymAddr |]

    member this.GetFunctionAddresses (_) =
      (this :> IBinFile).GetFunctionAddresses ()

    member _.HasRelocationInfo addr =
      relocs.Value
      |> Array.exists (fun r ->
        (r.RelocSection.SecAddr + uint64 r.RelocAddr) = addr)

    member _.GetRelocatedAddr _relocAddr = Terminator.futureFeature ()

    member _.GetLinkageTableEntries () = getPLT symInfo.Value

    member _.IsLinkageTable addr = isPLT symInfo.Value addr

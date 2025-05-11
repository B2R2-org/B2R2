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
  let relocs = lazy Reloc.parse toolBox symInfo.Value secs.Value
  let notInMemRanges = lazy invalidRangesByVM toolBox segCmds.Value
  let notInFileRanges = lazy invalidRangesByFileBounds toolBox segCmds.Value
  let executableRanges = lazy executableRanges segCmds.Value

  member _.Header with get() = toolBox.Header

  member _.Commands with get() = cmds.Value

  member _.Sections with get() = secs.Value

  member _.SymbolInfo with get() = symInfo.Value

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

    member _.GetOffset addr = translateAddr segMap.Value addr

    member this.Slice (addr, size) =
      let offset = translateAddr segMap.Value addr |> Convert.ToInt32
      (this :> IBinFile).Slice (offset=offset, size=size)

    member this.Slice (addr) =
      let offset = translateAddr segMap.Value addr |> Convert.ToInt32
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
      let offset = translateAddr segMap.Value addr |> Convert.ToInt32
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
      getSectionsByAddr secs.Value segMap.Value addr
      |> Seq.tryHead
      |> BinFilePointer.OfSection

    member _.ToBinFilePointer name =
      getSectionsByName secs.Value segMap.Value name
      |> Seq.tryHead
      |> BinFilePointer.OfSection

    member _.TryFindFunctionName (addr) =
      tryFindFuncSymb symInfo.Value addr

    member _.GetSymbols () = getSymbols secs.Value symInfo.Value

    member _.GetStaticSymbols () =
      getStaticSymbols secs.Value symInfo.Value

    member this.GetFunctionSymbols () =
      let f = this :> IBinFile
      let staticSymbols =
        f.GetStaticSymbols ()
        |> Array.filter (fun s -> s.Kind = SymFunctionType)
      let dynamicSymbols =
        f.GetDynamicSymbols (true)
        |> Array.filter (fun s -> s.Kind = SymFunctionType)
      Array.append staticSymbols dynamicSymbols

    member _.GetDynamicSymbols (?e) =
      getDynamicSymbols e secs.Value symInfo.Value

    member _.AddSymbol _addr _symbol = Terminator.futureFeature ()

    member _.GetSections () = getSections secs.Value segMap.Value

    member _.GetSections (addr) =
      getSectionsByAddr secs.Value segMap.Value addr

    member _.GetSections (name) =
      getSectionsByName secs.Value segMap.Value name

    member _.GetTextSection () = getTextSection secs.Value segMap.Value

    member _.GetSegments (isLoadable) =
      Segment.toArray segCmds.Value isLoadable

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

    member _.GetRelocationInfos () = relocs.Value

    member _.HasRelocationInfo addr =
      relocs.Value
      |> Array.exists (fun r -> r.Address = addr)

    member _.GetRelocatedAddr _relocAddr = Terminator.futureFeature ()

    member _.GetLinkageTableEntries () = getPLT symInfo.Value

    member _.IsLinkageTable addr = isPLT symInfo.Value addr

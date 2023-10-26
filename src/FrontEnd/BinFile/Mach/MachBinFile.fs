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
open B2R2.FrontEnd.BinFile.Mach
open B2R2.FrontEnd.BinFile.Mach.Helper

/// <summary>
///   This class represents a Mach-O binary file.
/// </summary>
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

  member __.Header with get() = toolBox.Header

  member __.Commands with get() = cmds.Value

  member __.Sections with get() = secs.Value

  member __.SymbolInfo with get() = symInfo.Value

  interface IBinFile with
    member __.Path with get() = path

    member __.Format with get() = FileFormat.MachBinary

    member __.ISA with get() = getISA toolBox.Header

    member __.Type with get() = convFileType toolBox.Header.FileType

    member __.EntryPoint = computeEntryPoint segCmds.Value cmds.Value

    member __.BaseAddress with get() = toolBox.BaseAddress

    member __.IsStripped = isStripped secs.Value symInfo.Value

    member __.IsNXEnabled = isNXEnabled toolBox.Header

    member __.IsRelocatable = toolBox.Header.Flags.HasFlag MachFlag.MH_PIE

    member __.GetOffset addr = translateAddr segMap.Value addr

    member __.Slice (addr, size) =
      let offset = translateAddr segMap.Value addr |> Convert.ToInt32
      (__ :> IBinFile).Slice (offset=offset, size=size)

    member __.Slice (addr) =
      let offset = translateAddr segMap.Value addr |> Convert.ToInt32
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
      let offset = translateAddr segMap.Value addr |> Convert.ToInt32
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
      |> List.map range.Slice
      |> List.toSeq

    member __.ToBinFilePointer addr =
      getSectionsByAddr secs.Value segMap.Value addr
      |> Seq.tryHead
      |> BinFilePointer.OfSectionOpt

    member __.ToBinFilePointer name =
      getSectionsByName secs.Value segMap.Value name
      |> Seq.tryHead
      |> BinFilePointer.OfSectionOpt

    member __.GetRelocatedAddr _relocAddr = Utils.futureFeature ()

    member __.TryFindFunctionName (addr) =
      tryFindFuncSymb symInfo.Value addr

    member __.GetSymbols () = getSymbols secs.Value symInfo.Value

    member __.GetStaticSymbols () =
      getStaticSymbols secs.Value symInfo.Value |> Array.toSeq

    member __.GetFunctionSymbols () =
      let self = __ :> IBinFile
      let staticSymbols =
        self.GetStaticSymbols ()
        |> Seq.filter (fun s -> s.Kind = SymFunctionType)
      let dynamicSymbols =
        self.GetDynamicSymbols (true)
        |> Seq.filter (fun s -> s.Kind = SymFunctionType)
      Seq.append staticSymbols dynamicSymbols

    member __.GetDynamicSymbols (?e) =
      getDynamicSymbols e secs.Value symInfo.Value |> Array.toSeq

    member __.GetRelocationSymbols () = relocs.Value |> Array.toSeq

    member __.AddSymbol _addr _symbol = Utils.futureFeature ()

    member __.GetSections () = getSections secs.Value segMap.Value

    member __.GetSections (addr) =
      getSectionsByAddr secs.Value segMap.Value addr

    member __.GetSections (name) =
      getSectionsByName secs.Value segMap.Value name

    member __.GetTextSection () = getTextSection secs.Value segMap.Value

    member __.GetSegments (isLoadable) = Segment.toSeq segCmds.Value isLoadable

    member __.GetSegments (addr) =
      (__ :> IBinFile).GetSegments ()
      |> Seq.filter (fun s -> (addr >= s.Address)
                              && (addr < s.Address + uint64 s.Size))

    member __.GetSegments (perm) =
      (__ :> IBinFile).GetSegments ()
      |> Seq.filter (fun s -> (s.Permission &&& perm = perm) && s.Size > 0u)

    member __.GetLinkageTableEntries () = getPLT symInfo.Value

    member __.IsLinkageTable addr = isPLT symInfo.Value addr

    member __.GetFunctionAddresses () =
      (__ :> IBinFile).GetFunctionSymbols ()
      |> Seq.map (fun s -> s.Address)

    member __.GetFunctionAddresses (_) =
      (__ :> IBinFile).GetFunctionAddresses ()

    member __.Reader with get() = toolBox.Reader

    member __.RawBytes = bytes

    member __.Length = bytes.Length
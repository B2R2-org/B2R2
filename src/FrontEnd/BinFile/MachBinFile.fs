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
type MachBinFile (bytes, path, isa, baseAddr) =
  let mach = Parser.parse baseAddr bytes isa

  new (bytes: byte[], path, isa: ISA) =
    MachBinFile (bytes, path, isa, None)

  member __.Mach with get() = mach

  interface IBinFile with
    member __.FilePath with get() = path

    member __.FileFormat with get() = FileFormat.MachBinary

    member __.ISA with get() = getISA mach

    member __.FileType with get() = convFileType mach.MachHdr.FileType

    member __.EntryPoint = mach.EntryPoint

    member __.BaseAddress with get() = mach.BaseAddr

    member __.IsStripped = isStripped mach

    member __.IsNXEnabled = isNXEnabled mach

    member __.IsRelocatable = mach.MachHdr.Flags.HasFlag MachFlag.MHPIE

    member __.Length = bytes.Length

    member __.RawBytes = bytes

    member __.Span = ReadOnlySpan bytes

    member __.GetOffset addr = translateAddr mach addr

    member __.Slice (addr, size) =
      let offset = translateAddr mach addr |> Convert.ToInt32
      let span = ReadOnlySpan bytes
      span.Slice (offset, size)

    member __.Slice (addr) =
      let offset = translateAddr mach addr |> Convert.ToInt32
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

    member __.IsValidAddr addr = isValidAddr mach addr

    member __.IsValidRange range = isValidRange mach range

    member __.IsInFileAddr addr = isInFileAddr mach addr

    member __.IsInFileRange range = isInFileRange mach range

    member __.IsExecutableAddr addr = isExecutableAddr mach addr

    member __.GetNotInFileIntervals range = getNotInFileIntervals mach range

    member __.ToBinFilePointer addr =
      BinFilePointer.OfSectionOpt (getSectionsByAddr mach addr |> Seq.tryHead)

    member __.ToBinFilePointer name =
      BinFilePointer.OfSectionOpt (getSectionsByName mach name |> Seq.tryHead)

    member __.GetRelocatedAddr _relocAddr = Utils.futureFeature ()

    member __.GetSymbols () = getSymbols mach

    member __.GetStaticSymbols () = getStaticSymbols mach |> Array.toSeq

    member __.GetFunctionSymbols () =
      let self = __ :> IBinFile
      let staticSymbols =
        self.GetStaticSymbols ()
        |> Seq.filter (fun s -> s.Kind = SymFunctionType)
      let dynamicSymbols =
        self.GetDynamicSymbols (true)
        |> Seq.filter (fun s -> s.Kind = SymFunctionType)
      Seq.append staticSymbols dynamicSymbols

    member __.GetDynamicSymbols (?e) = getDynamicSymbols e mach |> Array.toSeq

    member __.GetRelocationSymbols () = mach.Relocations |> Array.toSeq

    member __.AddSymbol _addr _symbol = Utils.futureFeature ()

    member __.TryFindFunctionSymbolName (addr) = tryFindFuncSymb mach addr

    member __.GetSections () = getSections mach

    member __.GetSections (addr) = getSectionsByAddr mach addr

    member __.GetSections (name) = getSectionsByName mach name

    member __.GetTextSection () = getTextSection mach

    member __.GetSegments (isLoadable) = Segment.getSegments mach isLoadable

    member __.GetSegments (addr) =
      (__ :> IBinFile).GetSegments ()
      |> Seq.filter (fun s -> (addr >= s.Address)
                              && (addr < s.Address + s.Size))

    member __.GetSegments (perm) =
      (__ :> IBinFile).GetSegments ()
      |> Seq.filter (fun s -> (s.Permission &&& perm = perm) && s.Size > 0UL)

    member __.GetLinkageTableEntries () = getPLT mach

    member __.IsLinkageTable addr = isPLT mach addr

    member __.GetFunctionAddresses () =
      (__ :> IBinFile).GetFunctionSymbols ()
      |> Seq.map (fun s -> s.Address)

    member __.GetFunctionAddresses (_) =
      (__ :> IBinFile).GetFunctionAddresses ()

    member __.NewBinFile bs = MachBinFile (bs, path, isa, baseAddr)

    member __.NewBinFile (bs, baseAddr) =
      MachBinFile (bs, path, isa, Some baseAddr)


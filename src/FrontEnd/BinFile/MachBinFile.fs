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
type MachBinFile private (mach, path, isa, ftype, content, baseAddr) =
  inherit BinFile (path, FileFormat.MachBinary, isa, ftype, content)

  new (bytes: byte[], path, isa: ISA) =
    MachBinFile (bytes, path, isa, None)

  new (bytes, path, isa, baseAddr) =
    let mach = Parser.parse baseAddr bytes isa
    let isa = getISA mach
    let ftype = convFileType mach.MachHdr.FileType
    let content = MachBinaryContent (mach, bytes)
    MachBinFile (mach, path, isa, ftype, content, baseAddr)

  override __.BaseAddress with get() = mach.BaseAddr
  override __.IsStripped = isStripped mach
  override __.IsNXEnabled = isNXEnabled mach
  override __.IsRelocatable = mach.MachHdr.Flags.HasFlag MachFlag.MHPIE
  override __.EntryPoint = mach.EntryPoint
  override __.TextStartAddr = getTextStartAddr mach
  override __.GetRelocatedAddr relocAddr = Utils.futureFeature ()
  override __.AddSymbol addr symbol = Utils.futureFeature ()
  override __.GetSymbols () = getSymbols mach
  override __.GetStaticSymbols () = getStaticSymbols mach |> Array.toSeq
  override __.GetDynamicSymbols (?e) = getDynamicSymbols e mach |> Array.toSeq
  override __.GetRelocationSymbols () = mach.Relocations |> Array.toSeq
  override __.GetSections () = getSections mach
  override __.GetSections (addr) = getSectionsByAddr mach addr
  override __.GetSections (name) = getSectionsByName mach name
  override __.GetTextSections () = getTextSections mach
  override __.GetSegments (isLoadable) = Segment.getSegments mach isLoadable
  override __.GetLinkageTableEntries () = getPLT mach
  override __.IsLinkageTable addr = isPLT mach addr
  override __.TryFindFunctionSymbolName (addr) = tryFindFuncSymb mach addr
  override __.ToBinFilePointer addr =
    BinFilePointer.OfSectionOpt (getSectionsByAddr mach addr |> Seq.tryHead)
  override __.ToBinFilePointer name =
    BinFilePointer.OfSectionOpt (getSectionsByName mach name |> Seq.tryHead)
  override __.NewBinFile bs = MachBinFile (bs, path, isa, baseAddr)
  override __.NewBinFile (bs, baseAddr) =
    MachBinFile (bs, path, isa, Some baseAddr)
  member __.Mach with get() = mach

and MachBinaryContent (mach, bytes) =
  interface IContentAddressable with
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


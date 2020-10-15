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

/// <summary>
///   This class represents a raw binary file (containing only binary code and
///   data without file format)
/// </summary>
type RawFileInfo (bytes: byte [], isa, baseAddr) =
  inherit FileInfo (baseAddr)

  override __.BinReader = BinReader.Init (bytes, isa.Endian)

  override __.FileFormat = FileFormat.RawBinary

  override __.ISA = isa

  override __.FileType = FileType.UnknownFile

  override __.FilePath = ""

  override __.WordSize = isa.WordSize

  override __.IsStripped = false

  override __.IsNXEnabled = false

  override __.IsRelocatable = false

  override __.BaseAddress = baseAddr

  override __.EntryPoint = Some baseAddr

  override __.TextStartAddr = baseAddr

  override __.TranslateAddress addr = System.Convert.ToInt32 (addr - baseAddr)

  override __.GetSymbols () = Seq.empty

  override __.GetStaticSymbols () = Seq.empty

  override __.GetDynamicSymbols (?_excludeImported) = Seq.empty

  override __.GetRelocationSymbols () = Seq.empty

  override __.GetSections () =
    Seq.singleton { Address = baseAddr
                    Kind = SectionKind.ExecutableSection
                    Size = uint64 bytes.LongLength
                    Name = "" }

  override __.GetSections (addr: Addr) =
    if addr >= baseAddr && addr < (baseAddr + uint64 bytes.LongLength) then
      __.GetSections ()
    else
      Seq.empty

  override __.GetSections (_: string): seq<Section> = Seq.empty

  override __.GetTextSections () = Seq.empty

  override __.GetSegments (_isLoadable) =
    Seq.singleton { Address = baseAddr
                    Size = uint64 bytes.LongLength
                    Permission = Permission.Readable ||| Permission.Executable }

  override __.GetLinkageTableEntries () = Seq.empty

  override __.IsLinkageTable _ = false

  override __.TryFindFunctionSymbolName (_addr) = Error ErrorCase.SymbolNotFound

  override __.ExceptionTable = Map.empty

  override __.IsValidAddr (addr) =
    addr >= baseAddr && addr < (baseAddr + uint64 bytes.LongLength)

  override __.IsValidRange (range) =
    __.IsValidAddr range.Min && __.IsValidAddr (range.Max - 1UL)

  override __.IsInFileAddr (addr) = __.IsValidAddr (addr)

  override __.IsInFileRange range = __.IsValidRange range

  override __.IsExecutableAddr addr = __.IsValidAddr addr

  override __.GetNotInFileIntervals range =
    let lastAddr = baseAddr + uint64 bytes.LongLength
    if range.Max <= baseAddr then Seq.singleton range
    elif range.Max <= lastAddr && range.Min < baseAddr then
      Seq.singleton (AddrRange (range.Min, baseAddr))
    elif range.Max > lastAddr && range.Min < baseAddr then
      [ AddrRange (range.Min, baseAddr); AddrRange (lastAddr, range.Max) ]
      |> List.toSeq
    elif range.Max > lastAddr && range.Min <= lastAddr then
      Seq.singleton (AddrRange (lastAddr, range.Max))
    elif range.Max > lastAddr && range.Min > lastAddr then Seq.singleton range
    else Seq.empty

// vim: set tw=80 sts=2 sw=2:

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
type ELFFileInfo (bytes, path, baseAddr, regbay) =
  inherit FileInfo ()
  let elf = Parser.parse bytes baseAddr regbay

  new (bytes, path) = ELFFileInfo (bytes, path, None, None)

  override __.Span = ReadOnlySpan bytes

  override __.FileFormat = FileFormat.ELFBinary

  override __.ISA = elf.ISA

  override __.FileType = convFileType elf.ELFHdr.ELFFileType

  override __.FilePath = path

  override __.WordSize = elf.ELFHdr.Class

  override __.IsStripped = not (Map.containsKey ".symtab" elf.SecInfo.SecByName)

  override __.IsNXEnabled = isNXEnabled elf

  override __.IsRelocatable = isRelocatable (ReadOnlySpan bytes) elf

  override __.BaseAddress = elf.BaseAddr

  override __.EntryPoint = Some elf.ELFHdr.EntryPoint

  override __.TextStartAddr = getTextStartAddr elf

  override __.TranslateAddress addr = translateAddrToOffset addr elf

  override __.GetRelocatedAddr relocAddr = getRelocatedAddr elf relocAddr

  override __.AddSymbol addr symbol = Utils.futureFeature ()

  override __.GetSymbols () = getSymbols elf

  override __.GetStaticSymbols () = getStaticSymbols elf

  override __.GetDynamicSymbols (?exc) = getDynamicSymbols exc elf

  override __.GetRelocationSymbols () = getRelocSymbols elf

  override __.GetSections () = getSections elf

  override __.GetSections (addr) = getSectionsByAddr elf addr

  override __.GetSections (name) = getSectionsByName elf name

  override __.GetTextSections () = getTextSections elf

  override __.GetSegments (isLoadable) = getSegments elf isLoadable

  override __.GetLinkageTableEntries () = getPLT elf

  override __.IsLinkageTable addr = isInPLT elf addr

  override __.TryFindFunctionSymbolName (addr) = tryFindFuncSymb elf addr

  override __.ToBinaryPointer addr =
    BinaryPointer.OfSectionOpt (getSectionsByAddr elf addr |> Seq.tryHead)

  override __.ToBinaryPointer name =
    BinaryPointer.OfSectionOpt (getSectionsByName elf name |> Seq.tryHead)

  override __.IsValidAddr addr = isValidAddr elf addr

  override __.IsValidRange range = isValidRange elf range

  override __.IsInFileAddr addr = isInFileAddr elf addr

  override __.IsInFileRange range = isInFileRange elf range

  override __.IsExecutableAddr addr = isExecutableAddr elf addr

  override __.GetNotInFileIntervals range = getNotInFileIntervals elf range

  override __.GetFunctionAddresses () =
    base.GetFunctionAddresses ()
    |> addExtraFunctionAddrs (ReadOnlySpan bytes) elf false

  override __.GetFunctionAddresses (useExcInfo) =
    base.GetFunctionAddresses ()
    |> addExtraFunctionAddrs (ReadOnlySpan bytes) elf useExcInfo

  member __.ELF with get() = elf

  member __.RegisterBay = regbay

// vim: set tw=80 sts=2 sw=2:

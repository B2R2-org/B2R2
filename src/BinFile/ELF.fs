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

namespace B2R2.BinFile

open B2R2
open B2R2.BinFile.ELF
open B2R2.BinFile.ELF.Helper

/// <summary>
///   This class represents an ELF binary file.
/// </summary>
type ELFFileInfo (bytes, path) =
  inherit FileInfo ()
  let elf = Parser.parse bytes

  override __.BinReader = elf.BinReader
  override __.FileFormat = FileFormat.ELFBinary
  override __.ISA = ISA.Init elf.ELFHdr.MachineType elf.ELFHdr.Endian
  override __.FileType = convFileType elf.ELFHdr.ELFFileType
  override __.FilePath = path
  override __.WordSize = elf.ELFHdr.Class
  override __.IsStripped = not (Map.containsKey ".symtab" elf.SecInfo.SecByName)
  override __.IsNXEnabled = isNXEnabled elf
  override __.IsRelocatable = isRelocatable elf
  override __.EntryPoint = Some elf.ELFHdr.EntryPoint
  override __.TextStartAddr = getTextStartAddr elf
  override __.TranslateAddress addr = translateAddr addr elf.LoadableSegments
  override __.GetSymbols () = getSymbols elf
  override __.GetStaticSymbols () = getStaticSymbols elf
  override __.GetDynamicSymbols (?exc) = getDynamicSymbols exc elf
  override __.GetRelocationSymbols () = getRelocSymbols elf
  override __.GetSections () = getSections elf
  override __.GetSections (addr) = getSectionsByAddr elf addr
  override __.GetSections (name) = getSectionsByName elf name
  override __.GetSegments (isLoadable) = getSegments elf isLoadable
  override __.GetLinkageTableEntries () = getPLT elf
  override __.TryFindFunctionSymbolName (addr, n) = tryFindFuncSymb elf addr &n
  override __.IsValidAddr addr = isValidAddr elf addr
  override __.IsValidRange range = isValidRange elf range
  override __.IsInFileAddr addr = isInFileAddr elf addr
  override __.IsInFileRange range = isInFileRange elf range
  override __.GetNotInFileIntervals range = getNotInFileIntervals elf range

// vim: set tw=80 sts=2 sw=2:

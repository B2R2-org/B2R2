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
open B2R2.FrontEnd.BinFile.Mach
open B2R2.FrontEnd.BinFile.Mach.Helper

/// <summary>
///   This class represents a Mach-O binary file.
/// </summary>
type MachFileInfo (bytes, path, isa, baseAddr) =
  inherit FileInfo (baseAddr)
  let mach = Parser.parse baseAddr bytes isa
  let regbay = FileHelper.initRegisterBay isa

  new (bytes, path, isa) = MachFileInfo (bytes, path, isa, 0UL)
  override __.BinReader = mach.BinReader
  override __.FileFormat = FileFormat.MachBinary
  override __.ISA = getISA mach
  override __.RegisterBay = regbay
  override __.FileType = convFileType mach.MachHdr.FileType
  override __.FilePath = path
  override __.WordSize = mach.MachHdr.Class
  override __.IsStripped = isStripped mach
  override __.IsNXEnabled = isNXEnabled mach
  override __.IsRelocatable = mach.MachHdr.Flags.HasFlag MachFlag.MHPIE
  override __.BaseAddress = getBaseAddr mach
  override __.EntryPoint = mach.EntryPoint
  override __.TextStartAddr = getTextStartAddr mach
  override __.TranslateAddress addr = translateAddr mach addr
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
  override __.ExceptionTable = Map.empty
  override __.IsValidAddr addr = isValidAddr mach addr
  override __.IsValidRange range = isValidRange mach range
  override __.IsInFileAddr addr = isInFileAddr mach addr
  override __.IsInFileRange range = isInFileRange mach range
  override __.IsExecutableAddr addr = isExecutableAddr mach addr
  override __.GetNotInFileIntervals range = getNotInFileIntervals mach range

// vim: set tw=80 sts=2 sw=2:

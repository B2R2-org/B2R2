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
open B2R2.FrontEnd.BinFile.Wasm
open B2R2.FrontEnd.BinFile.Wasm.Helper

/// <summary>
///   This class represents a Web Assembly
///   (Wasm Module) binary file.
/// </summary>
type WasmFileInfo (bytes, path, baseAddr) =
  inherit FileInfo ()
  let wm = Parser.parse bytes
  let baseAddr = defaultArg baseAddr 0UL

  new (bytes, path) = WasmFileInfo (bytes, path, None)
  override __.Span = ReadOnlySpan bytes
  override __.FileFormat = FileFormat.WasmBinary
  override __.ISA = defaultISA
  override __.FileType = fileTypeOf wm
  override __.FilePath = path
  override __.WordSize = WordSize.Bit32
  override __.IsStripped = List.isEmpty wm.CustomSections
  override __.IsNXEnabled = true
  override __.IsRelocatable = false
  override __.BaseAddress = baseAddr
  override __.EntryPoint = entryPointOf wm
  override __.TextStartAddr = textStartAddrOf wm
  override __.TranslateAddress addr = int addr
  override __.GetRelocatedAddr relocAddr = Utils.futureFeature ()
  override __.AddSymbol addr symbol = Utils.futureFeature ()
  override __.GetSymbols () = getSymbols wm
  override __.GetStaticSymbols () = Seq.empty
  override __.GetDynamicSymbols (?exc) = getDynamicSymbols wm exc
  override __.GetRelocationSymbols () = Seq.empty
  override __.GetSections () = getSections wm
  override __.GetSections (addr) = getSectionsByAddr wm addr
  override __.GetSections (name) = getSectionsByName wm name
  override __.GetTextSections () = Utils.futureFeature () // FIXME
  override __.GetSegments (_isLoadable) = Seq.empty
  override __.GetLinkageTableEntries () = getImports wm
  override __.IsLinkageTable _addr = Utils.futureFeature () // FIXME
  override __.TryFindFunctionSymbolName (addr) = tryFindFunSymName wm addr
  override __.ExceptionTable = ARMap.empty
  override __.ToBinaryPointer addr =
    BinaryPointer.OfSectionOpt (getSectionsByAddr wm addr |> Seq.tryHead)
  override __.ToBinaryPointer name =
    BinaryPointer.OfSectionOpt (getSectionsByName wm name |> Seq.tryHead)
  override __.IsValidAddr (addr) =
    addr >= 0UL && addr < (uint64 bytes.LongLength)
  override __.IsValidRange range =
    __.IsValidAddr range.Min && __.IsValidAddr range.Max
  override __.IsInFileAddr addr = __.IsValidAddr addr
  override __.IsInFileRange range = __.IsValidRange range
  override __.IsExecutableAddr _addr = Utils.futureFeature () // FIXME
  override __.GetNotInFileIntervals range =
    FileHelper.getNotInFileIntervals 0UL (uint64 bytes.LongLength) range
  member __.WASM with get() = wm

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

namespace B2R2.FrontEnd.BinInterface

open System
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinInterface.Helper

type BinHandle = {
  ISA: ISA
  FileInfo: FileInfo
  DisasmHelper: DisasmHelper
  DefaultParsingContext: ParsingContext
  TranslationContext: TranslationContext
  Parser: Parser
  RegisterBay: RegisterBay
}
with
  static member private Init (isa, mode, autoDetect, baseAddr, bytes, path) =
    let fmt, isa = identifyFormatAndISA bytes isa autoDetect
    let struct (ctxt, parser, regbay) = initBasis isa
    let fi = newFileInfo bytes baseAddr path fmt isa regbay
    assert (isa = fi.ISA)
    let needCheckThumb = mode = ArchOperationMode.NoMode && isARM isa
    let mode = if needCheckThumb then detectThumb fi.EntryPoint isa else mode
    { ISA = isa
      FileInfo = fi
      DisasmHelper = DisasmHelper (fi.TryFindFunctionSymbolName)
      DefaultParsingContext = ParsingContext.Init (mode)
      TranslationContext = ctxt
      Parser = parser
      RegisterBay = regbay }

  static member Init (isa, archMode, autoDetect, baseAddr, bytes) =
    BinHandle.Init (isa, archMode, autoDetect, baseAddr, bytes, "")

  static member Init (isa, archMode, autoDetect, baseAddr, fileName) =
    let bytes = IO.File.ReadAllBytes fileName
    let fileName = IO.Path.GetFullPath fileName
    BinHandle.Init (isa, archMode, autoDetect, baseAddr, bytes, fileName)

  static member Init (isa, baseAddr, fileName) =
    let bytes = IO.File.ReadAllBytes fileName
    let fileName = IO.Path.GetFullPath fileName
    let defaultMode = ArchOperationMode.NoMode
    BinHandle.Init (isa, defaultMode, true, baseAddr, bytes, fileName)

  static member Init (isa, fileName) =
    BinHandle.Init (isa=isa, baseAddr=None, fileName=fileName)

  static member Init (isa, baseAddr, bytes) =
    let defaultMode = ArchOperationMode.NoMode
    BinHandle.Init (isa, defaultMode, false, baseAddr, bytes, "")

  static member Init (isa, bytes) =
    BinHandle.Init (isa=isa, baseAddr=None, bytes=bytes)

  static member Init (isa, archMode) =
    BinHandle.Init (isa, archMode, false, None, [||], "")

  static member Init (isa) = BinHandle.Init (isa, [||])

  static member UpdateCode h addr bs =
    { h with FileInfo = RawFileInfo (bs, "", h.ISA, Some addr) :> FileInfo }

  static member private UpdateFileInfo h fi =
    { h with FileInfo = fi }

  static member PatchCode h addr (bs: byte []) =
    let fi = h.FileInfo
    let reader = fi.BinReader
    let idx = int <| addr - fi.BaseAddress
    let lastIdx = idx + bs.Length - 1
    if reader.IsOutOfRange idx || reader.IsOutOfRange lastIdx then
      Error ErrorCase.InvalidMemoryRead
    else
      let bs =
        reader.Bytes.[ idx + Array.length bs .. ]
        |> Array.append bs
        |> Array.append reader.Bytes.[ .. idx - 1 ]
      match fi with
      | :? RawFileInfo ->
        RawFileInfo (bs, fi.FilePath, fi.ISA, Some fi.BaseAddress) :> FileInfo
        |> BinHandle.UpdateFileInfo h
        |> Ok
      | :? ELFFileInfo as fi ->
        ELFFileInfo (bs, fi.FilePath, Some fi.BaseAddress, fi.RegisterBay)
        :> FileInfo
        |> BinHandle.UpdateFileInfo h
        |> Ok
      | :? MachFileInfo ->
        MachFileInfo (bs, fi.FilePath, fi.ISA, Some fi.BaseAddress) :> FileInfo
        |> BinHandle.UpdateFileInfo h
        |> Ok
      | :? PEFileInfo as fi ->
        PEFileInfo (bs, fi.FilePath, Some fi.BaseAddress, fi.RawPDB) :> FileInfo
        |> BinHandle.UpdateFileInfo h
        |> Ok
      | :? WasmFileInfo ->
        WasmFileInfo (bs, fi.FilePath, Some fi.BaseAddress) :> FileInfo
        |> BinHandle.UpdateFileInfo h
        |> Ok
      | _ -> Error ErrorCase.InvalidFileFormat

  member __.ReadBytes (addr: Addr, nBytes) =
    BinHandle.ReadBytes (__, addr, nBytes)

  member __.ReadBytes (bp: BinaryPointer, nBytes) =
    BinHandle.ReadBytes (__, bp, nBytes)

  static member TryReadBytes ({ FileInfo = fi }, addr, nBytes) =
    let range = AddrRange (addr, addr + uint64 nBytes)
    if fi.IsInFileRange range then
      fi.BinReader.PeekBytes (nBytes, fi.TranslateAddress addr) |> Ok
    elif fi.IsValidRange range then
      fi.GetNotInFileIntervals range
      |> classifyRanges range
      |> List.fold (fun bs (range, isInFile) ->
           let len = range.Max - range.Min |> int
           if isInFile then
             let addr = fi.TranslateAddress range.Min
             fi.BinReader.PeekBytes (len, addr)
             |> Array.append bs
           else Array.create len 0uy |> Array.append bs
         ) [||]
      |> Ok
    else Error ErrorCase.InvalidMemoryRead

  static member TryReadBytes ({ FileInfo = fi }, bp, nBytes) =
    if BinaryPointer.IsValidAccess bp nBytes then
      fi.BinReader.PeekBytes (nBytes, bp.Offset) |> Ok
    else Error ErrorCase.InvalidMemoryRead

  static member ReadBytes (hdl, addr: Addr, nBytes) =
    match BinHandle.TryReadBytes (hdl, addr, nBytes) with
    | Ok bs -> bs
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  static member ReadBytes (hdl, bp: BinaryPointer, nBytes) =
    match BinHandle.TryReadBytes (hdl, bp, nBytes) with
    | Ok bs -> bs
    | Error e -> invalidArg (nameof bp) (ErrorCase.toString e)

  member __.ReadInt (addr: Addr, nBytes) =
    BinHandle.ReadInt (__, addr, nBytes)

  member __.ReadInt (bp: BinaryPointer, nBytes) =
    BinHandle.ReadInt (__, bp, nBytes)

  static member TryReadInt ({ FileInfo = fi }, addr, nBytes) =
    let pos = fi.TranslateAddress addr
    if pos >= fi.BinReader.Bytes.Length || pos < 0 then
      Error ErrorCase.InvalidMemoryRead
    else readIntBySize fi pos nBytes

  static member TryReadInt ({ FileInfo = fi }, bp, nBytes) =
    if BinaryPointer.IsValidAccess bp nBytes then
      readIntBySize fi bp.Offset nBytes
    else Error ErrorCase.InvalidMemoryRead

  static member ReadInt (hdl, addr: Addr, nBytes) =
    match BinHandle.TryReadInt (hdl, addr, nBytes) with
    | Ok i -> i
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  static member ReadInt (hdl, bp: BinaryPointer, nBytes) =
    match BinHandle.TryReadInt (hdl, bp, nBytes) with
    | Ok i -> i
    | Error e -> invalidArg (nameof bp) (ErrorCase.toString e)

  member __.ReadUInt (addr: Addr, nBytes) =
    BinHandle.ReadUInt (__, addr, nBytes)

  member __.ReadUInt (bp: BinaryPointer, nBytes) =
    BinHandle.ReadUInt (__, bp, nBytes)

  static member TryReadUInt ({ FileInfo = fi }, addr, nBytes) =
    let pos = fi.TranslateAddress addr
    if pos >= fi.BinReader.Bytes.Length || pos < 0 then
      Error ErrorCase.InvalidMemoryRead
    else readUIntBySize fi pos nBytes

  static member TryReadUInt ({ FileInfo = fi }, bp, nBytes) =
    if BinaryPointer.IsValidAccess bp nBytes then
      readUIntBySize fi bp.Offset nBytes
    else Error ErrorCase.InvalidMemoryRead

  static member ReadUInt (hdl, addr: Addr, nBytes) =
    match BinHandle.TryReadUInt (hdl, addr, nBytes) with
    | Ok i -> i
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  static member ReadUInt (hdl, bp: BinaryPointer, nBytes) =
    match BinHandle.TryReadUInt (hdl, bp, nBytes) with
    | Ok i -> i
    | Error e -> invalidArg (nameof bp) (ErrorCase.toString e)

  member __.ReadASCII (addr: Addr) =
    BinHandle.ReadASCII (__, addr)

  member __.ReadASCII (bp: BinaryPointer) =
    BinHandle.ReadASCII (__, bp)

  static member ReadASCII ({ FileInfo = fi }, addr) =
    let bs = fi.TranslateAddress addr |> readASCII fi
    ByteArray.extractCString bs 0

  static member ReadASCII ({ FileInfo = fi }, bp: BinaryPointer) =
    let bs = readASCII fi bp.Offset
    ByteArray.extractCString bs 0

  static member ParseInstr (hdl: BinHandle, ctxt, addr) =
    parseInstrFromAddr hdl.FileInfo hdl.Parser ctxt addr

  static member ParseInstr (hdl: BinHandle, ctxt, bp: BinaryPointer) =
    parseInstrFromBinPtr hdl.FileInfo hdl.Parser ctxt bp

  static member TryParseInstr (hdl, ctxt, addr) =
    tryParseInstrFromAddr hdl.FileInfo hdl.Parser ctxt addr

  static member TryParseInstr (hdl, ctxt, bp: BinaryPointer) =
    tryParseInstrFromBinPtr hdl.FileInfo hdl.Parser ctxt bp

  static member ParseBBlock (hdl, ctxt, addr) =
    parseBBLFromAddr hdl.FileInfo hdl.Parser ctxt addr

  static member ParseBBlock (hdl, ctxt, bp) =
    parseBBLFromBinPtr hdl.FileInfo hdl.Parser ctxt bp

  static member inline LiftInstr (hdl: BinHandle) (ins: Instruction) =
    ins.Translate hdl.TranslationContext

  static member LiftOptimizedInstr hdl (ins: Instruction) =
    BinHandle.LiftInstr hdl ins |> LocalOptimizer.Optimize

  static member LiftBBlock (hdl: BinHandle, ctxt, addr: Addr) =
    liftBBLFromAddr hdl.FileInfo hdl.Parser hdl.TranslationContext ctxt addr

  static member LiftBBlock (hdl: BinHandle, ctxt, bp: BinaryPointer) =
    liftBBLFromBinPtr hdl.FileInfo hdl.Parser hdl.TranslationContext ctxt bp

  static member inline DisasmInstr hdl showAddr resolve (ins: Instruction) =
    ins.Disasm (showAddr, resolve, hdl.DisasmHelper)

  static member inline DisasmInstrSimple (ins: Instruction) =
    ins.Disasm ()

  static member DisasmBBlock (hdl, ctxt, showAddr, resolve, addr) =
    disasmBBLFromAddr
      hdl.FileInfo hdl.Parser hdl.DisasmHelper showAddr resolve ctxt addr

  static member DisasmBBlock (hdl, ctxt, showAddr, resolve, bp) =
    disasmBBLFromBinPtr
      hdl.FileInfo hdl.Parser hdl.DisasmHelper showAddr resolve ctxt bp

  static member Optimize stmts = LocalOptimizer.Optimize stmts

// vim: set tw=80 sts=2 sw=2:

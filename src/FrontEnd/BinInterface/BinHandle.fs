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
  BinFile: BinFile
  DisasmHelper: DisasmHelper
  TranslationContext: TranslationContext
  Parser: Parser
  RegisterBay: RegisterBay
  BinReader: IBinReader
  OS: OS
}
with
  static member private Init (isa, mode, autoDetect, baseAddr, bs, path, os) =
    let struct (fmt, isa, os) = identifyFormatAndISAAndOS bs isa os autoDetect
    let struct (ctxt, regbay) = Basis.init isa
    let file = newFileInfo bs baseAddr path fmt isa regbay
    assert (isa = file.ISA)
    let parser = Parser.init isa mode file.EntryPoint
    { ISA = isa
      BinFile = file
      DisasmHelper = DisasmHelper (file.TryFindFunctionSymbolName)
      TranslationContext = ctxt
      Parser = parser
      RegisterBay = regbay
      BinReader = BinReader.Init isa.Endian
      OS = os }

  static member Init (isa, archMode, autoDetect, baseAddr, bytes) =
    BinHandle.Init (isa, archMode, autoDetect, baseAddr, bytes, "", None)

  static member Init (isa, archMode, autoDetect, baseAddr, fileName) =
    let bytes = IO.File.ReadAllBytes fileName
    let fileName = IO.Path.GetFullPath fileName
    BinHandle.Init (isa, archMode, autoDetect, baseAddr, bytes, fileName, None)

  static member Init (isa, baseAddr, fileName) =
    let bytes = IO.File.ReadAllBytes fileName
    let fileName = IO.Path.GetFullPath fileName
    let defaultMode = ArchOperationMode.NoMode
    BinHandle.Init (isa, defaultMode, true, baseAddr, bytes, fileName, None)

  static member Init (isa, fileName) =
    BinHandle.Init (isa=isa, baseAddr=None, fileName=fileName)

  static member Init (isa, baseAddr, bytes) =
    let defaultMode = ArchOperationMode.NoMode
    BinHandle.Init (isa, defaultMode, false, baseAddr, bytes, "", None)

  static member Init (isa, bytes) =
    BinHandle.Init (isa=isa, baseAddr=None, bytes=bytes)

  static member Init (isa, archMode) =
    BinHandle.Init (isa, archMode, false, None, [||], "", None)

  static member Init (isa, os) =
    let defaultMode = ArchOperationMode.NoMode
    BinHandle.Init (isa, defaultMode, false, None, [||], "", Some os)

  static member Init (isa: ISA) = BinHandle.Init (isa, ([||]: byte []))

  static member NewBinHandle (hdl, bs) =
    { hdl with BinFile = hdl.BinFile.NewBinFile bs }

  static member NewBinHandle (hdl, addr, bs) =
    { hdl with BinFile = hdl.BinFile.NewBinFile (bs, addr) }

  member __.ReadBytes (addr: Addr, nBytes) =
    BinHandle.ReadBytes (__, addr, nBytes)

  member __.ReadBytes (bp: BinaryPointer, nBytes) =
    BinHandle.ReadBytes (__, bp, nBytes)

  static member TryReadBytes ({ BinFile = file }, addr, nBytes) =
    let range = AddrRange (addr, addr + uint64 nBytes - 1UL)
    if file.IsInFileRange range then
      let slice = file.Span.Slice (file.TranslateAddress addr, nBytes)
      slice.ToArray () |> Ok
    elif file.IsValidRange range then
      file.GetNotInFileIntervals range
      |> classifyRanges range
      |> List.fold (fun bs (range, isInFile) ->
           let len = (range.Max - range.Min |> int) + 1
           if isInFile then
             let offset = file.TranslateAddress range.Min
             let slice = file.Span.Slice (offset, len)
             Array.append bs (slice.ToArray ())
           else Array.create len 0uy |> Array.append bs
         ) [||]
      |> Ok
    else Error ErrorCase.InvalidMemoryRead

  static member TryReadBytes ({ BinFile = file }, bp, nBytes) =
    if BinaryPointer.IsValidAccess bp nBytes then
      let slice = file.Span.Slice (bp.Offset, nBytes)
      slice.ToArray () |> Ok
    else Error ErrorCase.InvalidMemoryRead

  static member ReadBytes (hdl, addr: Addr, nBytes) =
    match BinHandle.TryReadBytes (hdl, addr, nBytes) with
    | Ok bs -> bs
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  static member ReadBytes (hdl, bp: BinaryPointer, nBytes) =
    match BinHandle.TryReadBytes (hdl, bp, nBytes) with
    | Ok bs -> bs
    | Error e -> invalidArg (nameof bp) (ErrorCase.toString e)

  member __.ReadInt (addr: Addr, size) =
    BinHandle.ReadInt (__, addr, size)

  member __.ReadInt (bp: BinaryPointer, size) =
    BinHandle.ReadInt (__, bp, size)

  static member TryReadInt ({ BinFile = file; BinReader = r }, addr, size) =
    let pos = file.TranslateAddress addr
    if (pos + size) > file.Span.Length || (pos < 0) then
      Error ErrorCase.InvalidMemoryRead
    else readIntBySize r file pos size

  static member TryReadInt ({ BinFile = file; BinReader = r }, bp, size) =
    if BinaryPointer.IsValidAccess bp size then
      readIntBySize r file bp.Offset size
    else Error ErrorCase.InvalidMemoryRead

  static member ReadInt (hdl, addr: Addr, size) =
    match BinHandle.TryReadInt (hdl, addr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  static member ReadInt (hdl, bp: BinaryPointer, size) =
    match BinHandle.TryReadInt (hdl, bp, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof bp) (ErrorCase.toString e)

  member __.ReadUInt (addr: Addr, size) =
    BinHandle.ReadUInt (__, addr, size)

  member __.ReadUInt (bp: BinaryPointer, size) =
    BinHandle.ReadUInt (__, bp, size)

  static member TryReadUInt ({ BinFile = file; BinReader = r }, addr, size) =
    let pos = file.TranslateAddress addr
    if (pos + size) > file.Span.Length || (pos < 0) then
      Error ErrorCase.InvalidMemoryRead
    else readUIntBySize r file pos size

  static member TryReadUInt ({ BinFile = file; BinReader = r }, bp, size) =
    if BinaryPointer.IsValidAccess bp size then
      readUIntBySize r file bp.Offset size
    else Error ErrorCase.InvalidMemoryRead

  static member ReadUInt (hdl, addr: Addr, size) =
    match BinHandle.TryReadUInt (hdl, addr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  static member ReadUInt (hdl, bp: BinaryPointer, size) =
    match BinHandle.TryReadUInt (hdl, bp, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof bp) (ErrorCase.toString e)

  member __.ReadASCII (addr: Addr) =
    BinHandle.ReadASCII (__, addr)

  member __.ReadASCII (bp: BinaryPointer) =
    BinHandle.ReadASCII (__, bp)

  static member ReadASCII ({ BinFile = file }, addr) =
    let bs = file.TranslateAddress addr |> readASCII file
    ByteArray.extractCString bs 0

  static member ReadASCII ({ BinFile = file }, bp: BinaryPointer) =
    let bs = readASCII file bp.Offset
    ByteArray.extractCString bs 0

  static member ParseInstr (hdl: BinHandle, addr) =
    parseInstrFromAddr hdl.BinFile hdl.Parser addr

  static member ParseInstr (hdl: BinHandle, bp: BinaryPointer) =
    parseInstrFromBinPtr hdl.BinFile hdl.Parser bp

  static member TryParseInstr (hdl, addr) =
    tryParseInstrFromAddr hdl.BinFile hdl.Parser addr

  static member TryParseInstr (hdl, bp: BinaryPointer) =
    tryParseInstrFromBinPtr hdl.BinFile hdl.Parser bp

  static member ParseBBlock (hdl, addr) =
    parseBBLFromAddr hdl.BinFile hdl.Parser addr

  static member ParseBBlock (hdl, bp) =
    parseBBLFromBinPtr hdl.BinFile hdl.Parser bp

  static member inline LiftInstr (hdl: BinHandle) (ins: Instruction) =
    ins.Translate hdl.TranslationContext

  static member LiftOptimizedInstr hdl (ins: Instruction) =
    BinHandle.LiftInstr hdl ins |> LocalOptimizer.Optimize

  static member LiftBBlock (hdl: BinHandle, addr: Addr) =
    liftBBLFromAddr hdl.BinFile hdl.Parser hdl.TranslationContext addr

  static member LiftBBlock (hdl: BinHandle, bp: BinaryPointer) =
    liftBBLFromBinPtr hdl.BinFile hdl.Parser hdl.TranslationContext bp

  static member inline DisasmInstr hdl showAddr resolveSymbol ins =
    (ins: Instruction).Disasm (showAddr, resolveSymbol, hdl.DisasmHelper)

  static member inline DisasmInstrSimple (ins: Instruction) =
    ins.Disasm ()

  static member DisasmBBlock (hdl, showAddr, resolveSymbol, addr) =
    disasmBBLFromAddr
      hdl.BinFile hdl.Parser hdl.DisasmHelper showAddr resolveSymbol addr

  static member DisasmBBlock (hdl, showAddr, resolveSymbol, bp) =
    disasmBBLFromBinPtr
      hdl.BinFile hdl.Parser hdl.DisasmHelper showAddr resolveSymbol bp

  static member Optimize stmts = LocalOptimizer.Optimize stmts

// vim: set tw=80 sts=2 sw=2:

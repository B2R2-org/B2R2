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
    { BinFile = file
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

  member __.ReadBytes (ptr: BinFilePointer, nBytes) =
    BinHandle.ReadBytes (__, ptr, nBytes)

  static member TryReadBytes ({ BinFile = file }, addr, nBytes) =
    let range = AddrRange (addr, addr + uint64 nBytes - 1UL)
    if file.Content.IsInFileRange range then
      let slice = file.Content.Slice (addr, nBytes)
      slice.ToArray () |> Ok
    elif file.Content.IsValidRange range then
      file.Content.GetNotInFileIntervals range
      |> classifyRanges range
      |> List.fold (fun bs (range, isInFile) ->
           let len = (range.Max - range.Min |> int) + 1
           if isInFile then
             let slice = file.Content.Slice (range.Min, len)
             Array.append bs (slice.ToArray ())
           else Array.create len 0uy |> Array.append bs
         ) [||]
      |> Ok
    else Error ErrorCase.InvalidMemoryRead

  static member TryReadBytes ({ BinFile = file }, ptr, nBytes) =
    if BinFilePointer.IsValidAccess ptr nBytes then
      let slice = file.Content.Slice (ptr, nBytes)
      slice.ToArray () |> Ok
    else Error ErrorCase.InvalidMemoryRead

  static member ReadBytes (hdl, addr: Addr, nBytes) =
    match BinHandle.TryReadBytes (hdl, addr, nBytes) with
    | Ok bs -> bs
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  static member ReadBytes (hdl, ptr: BinFilePointer, nBytes) =
    match BinHandle.TryReadBytes (hdl, ptr, nBytes) with
    | Ok bs -> bs
    | Error e -> invalidArg (nameof ptr) (ErrorCase.toString e)

  member __.ReadInt (addr: Addr, size) =
    BinHandle.ReadInt (__, addr, size)

  member __.ReadInt (ptr: BinFilePointer, size) =
    BinHandle.ReadInt (__, ptr, size)

  static member TryReadInt ({ BinFile = file; BinReader = r }, addr, size) =
    let pos = file.Content.GetOffset addr
    if (pos + size) > file.Content.Length || (pos < 0) then
      Error ErrorCase.InvalidMemoryRead
    else
      let span = file.Content.Slice (offset=pos)
      readIntBySize r span size

  static member TryReadInt ({ BinFile = file; BinReader = r }, ptr, size) =
    if BinFilePointer.IsValidAccess ptr size then
      let span = file.Content.Slice (offset=ptr.Offset)
      readIntBySize r span size
    else Error ErrorCase.InvalidMemoryRead

  static member ReadInt (hdl, addr: Addr, size) =
    match BinHandle.TryReadInt (hdl, addr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  static member ReadInt (hdl, ptr: BinFilePointer, size) =
    match BinHandle.TryReadInt (hdl, ptr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof ptr) (ErrorCase.toString e)

  member __.ReadUInt (addr: Addr, size) =
    BinHandle.ReadUInt (__, addr, size)

  member __.ReadUInt (ptr: BinFilePointer, size) =
    BinHandle.ReadUInt (__, ptr, size)

  static member TryReadUInt ({ BinFile = file; BinReader = r }, addr, size) =
    let pos = file.Content.GetOffset addr
    if (pos + size) > file.Content.Length || (pos < 0) then
      Error ErrorCase.InvalidMemoryRead
    else
      let span = file.Content.Slice (offset=pos)
      readUIntBySize r span size

  static member TryReadUInt ({ BinFile = file; BinReader = r }, ptr, size) =
    if BinFilePointer.IsValidAccess ptr size then
      let span = file.Content.Slice (offset=ptr.Offset)
      readUIntBySize r span size
    else Error ErrorCase.InvalidMemoryRead

  static member ReadUInt (hdl, addr: Addr, size) =
    match BinHandle.TryReadUInt (hdl, addr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  static member ReadUInt (hdl, ptr: BinFilePointer, size) =
    match BinHandle.TryReadUInt (hdl, ptr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof ptr) (ErrorCase.toString e)

  member __.ReadASCII (addr: Addr) =
    BinHandle.ReadASCII (__, addr)

  member __.ReadASCII (ptr: BinFilePointer) =
    BinHandle.ReadASCII (__, ptr)

  static member ReadASCII ({ BinFile = file }, addr) =
    let bs = file.Content.GetOffset addr |> readASCII file
    ByteArray.extractCString bs 0

  static member ReadASCII ({ BinFile = file }, ptr: BinFilePointer) =
    let bs = readASCII file ptr.Offset
    ByteArray.extractCString bs 0

  static member ParseInstr (hdl: BinHandle, addr: Addr) =
    hdl.Parser.Parse (hdl.BinFile.Content.Slice addr, addr)

  static member ParseInstr (hdl: BinHandle, ptr: BinFilePointer) =
    parseInstrFromBinPtr hdl.BinFile hdl.Parser ptr

  static member TryParseInstr (hdl, addr) =
    tryParseInstrFromAddr hdl.BinFile hdl.Parser addr

  static member TryParseInstr (hdl, ptr: BinFilePointer) =
    tryParseInstrFromBinPtr hdl.BinFile hdl.Parser ptr

  static member ParseBBlock (hdl, addr) =
    parseBBLFromAddr hdl.BinFile hdl.Parser addr

  static member ParseBBlock (hdl, ptr) =
    parseBBLFromBinPtr hdl.BinFile hdl.Parser ptr

  static member inline LiftInstr (hdl: BinHandle) (ins: Instruction) =
    ins.Translate hdl.TranslationContext

  static member LiftOptimizedInstr hdl (ins: Instruction) =
    BinHandle.LiftInstr hdl ins |> LocalOptimizer.Optimize

  static member LiftBBlock (hdl: BinHandle, addr: Addr) =
    liftBBLFromAddr hdl.BinFile hdl.Parser hdl.TranslationContext addr

  static member LiftBBlock (hdl: BinHandle, ptr: BinFilePointer) =
    liftBBLFromBinPtr hdl.BinFile hdl.Parser hdl.TranslationContext ptr

  static member inline DisasmInstr hdl showAddr resolveSymbol ins =
    (ins: Instruction).Disasm (showAddr, resolveSymbol, hdl.DisasmHelper)

  static member inline DisasmInstrSimple (ins: Instruction) =
    ins.Disasm ()

  static member DisasmBBlock (hdl, showAddr, resolveSymbol, addr) =
    disasmBBLFromAddr
      hdl.BinFile hdl.Parser hdl.DisasmHelper showAddr resolveSymbol addr

  static member DisasmBBlock (hdl, showAddr, resolveSymbol, ptr) =
    disasmBBLFromBinPtr
      hdl.BinFile hdl.Parser hdl.DisasmHelper showAddr resolveSymbol ptr

  static member Optimize stmts = LocalOptimizer.Optimize stmts

// vim: set tw=80 sts=2 sw=2:

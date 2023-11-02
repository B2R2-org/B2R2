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

namespace B2R2.FrontEnd

open System.IO
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Helper
open type B2R2.FileFormat
open type B2R2.ArchOperationMode

type BinHandle private (path, bytes, fmt, isa, baseAddrOpt, mode) =
  let binFile = FileFactory.load path bytes fmt isa baseAddrOpt
  let struct (ctxt, regFactory) = Basis.init binFile.ISA
  let parser = Parser.init binFile.ISA mode binFile.EntryPoint

  new (path, isa, baseAddrOpt, mode) =
    let bytes = File.ReadAllBytes path
    let struct (fmt, isa) = FormatDetector.identify bytes isa
    BinHandle (path, bytes, fmt, isa, baseAddrOpt, mode)

  new (path, isa, baseAddrOpt) =
    BinHandle (path=path, isa=isa, baseAddrOpt=baseAddrOpt, mode=NoMode)

  new (path, isa) =
    BinHandle (path=path, isa=isa, baseAddrOpt=None, mode=NoMode)

  new (bytes, isa, baseAddrOpt, detectFormat) =
    if detectFormat then
      let struct (fmt, isa) = FormatDetector.identify bytes isa
      BinHandle ("", bytes, fmt, isa, baseAddrOpt, NoMode)
    else
      BinHandle ("", bytes, RawBinary, isa, baseAddrOpt, NoMode)

  new (isa) =
    BinHandle ([||], isa, None, false)

  /// Return the `IBinFile` object.
  member __.File with get(): IBinFile = binFile

  /// ISA that this binary file is compiled for.
  member __.ISA with get() = binFile.ISA

  member __.TranslationContext with get(): TranslationContext = ctxt

  member __.Parser with get(): IInstructionParsable = parser

  member __.RegisterFactory with get(): RegisterFactory = regFactory

  member __.TryReadBytes (addr: Addr, nBytes) =
    let range = AddrRange (addr, addr + uint64 nBytes - 1UL)
    if binFile.IsInFileRange range then
      let slice = binFile.Slice (addr, nBytes)
      slice.ToArray () |> Ok
    elif binFile.IsValidRange range then
      binFile.GetNotInFileIntervals range
      |> classifyRanges range
      |> List.fold (fun bs (range, isInFile) ->
           let len = (range.Max - range.Min |> int) + 1
           if isInFile then
             let slice = binFile.Slice (range.Min, len)
             Array.append bs (slice.ToArray ())
           else Array.create len 0uy |> Array.append bs
         ) [||]
      |> Ok
    else Error ErrorCase.InvalidMemoryRead

  member __.TryReadBytes (ptr: BinFilePointer, nBytes) =
    if BinFilePointer.IsValidAccess ptr nBytes then
      let slice = binFile.Slice (ptr, nBytes)
      slice.ToArray () |> Ok
    else Error ErrorCase.InvalidMemoryRead

  member __.ReadBytes (addr: Addr, nBytes) =
    match __.TryReadBytes (addr, nBytes) with
    | Ok bs -> bs
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  member __.ReadBytes (ptr: BinFilePointer, nBytes) =
    match __.TryReadBytes (ptr, nBytes) with
    | Ok bs -> bs
    | Error e -> invalidArg (nameof ptr) (ErrorCase.toString e)

  member __.TryReadInt (addr: Addr, size) =
    let pos = binFile.GetOffset addr
    if (pos + size) > binFile.Length || (pos < 0) then
      Error ErrorCase.InvalidMemoryRead
    else
      let span = binFile.Slice (offset=pos)
      readIntBySize binFile.Reader span size

  member __.TryReadInt (ptr: BinFilePointer, size) =
    if BinFilePointer.IsValidAccess ptr size then
      let span = binFile.Slice (offset=ptr.Offset)
      readIntBySize binFile.Reader span size
    else Error ErrorCase.InvalidMemoryRead

  member __.ReadInt (addr: Addr, size) =
    match __.TryReadInt (addr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  member __.ReadInt (ptr: BinFilePointer, size) =
    match __.TryReadInt (ptr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof ptr) (ErrorCase.toString e)

  member __.TryReadUInt (addr: Addr, size) =
    let pos = binFile.GetOffset addr
    if (pos + size) > binFile.Length || (pos < 0) then
      Error ErrorCase.InvalidMemoryRead
    else
      let span = binFile.Slice (offset=pos)
      readUIntBySize binFile.Reader span size

  member __.TryReadUInt (ptr: BinFilePointer, size) =
    if BinFilePointer.IsValidAccess ptr size then
      let span = binFile.Slice (offset=ptr.Offset)
      readUIntBySize binFile.Reader span size
    else Error ErrorCase.InvalidMemoryRead

  member __.ReadUInt (addr: Addr, size) =
    match __.TryReadUInt (addr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof addr) (ErrorCase.toString e)

  member __.ReadUInt (ptr: BinFilePointer, size) =
    match __.TryReadUInt (ptr, size) with
    | Ok i -> i
    | Error e -> invalidArg (nameof ptr) (ErrorCase.toString e)

  member __.ReadASCII (addr: Addr) =
    let bs = binFile.GetOffset addr |> readASCII binFile
    ByteArray.extractCString bs 0

  member __.ReadASCII (ptr: BinFilePointer) =
    let bs = readASCII binFile ptr.Offset
    ByteArray.extractCString bs 0

  member __.ParseInstr (addr: Addr) =
    parser.Parse (binFile.Slice (addr), addr)

  member __.ParseInstr (ptr: BinFilePointer) =
    parseInstrFromBinPtr binFile parser ptr

  member __.TryParseInstr (addr) =
    tryParseInstrFromAddr binFile parser addr

  member __.TryParseInstr (ptr: BinFilePointer) =
    tryParseInstrFromBinPtr binFile parser ptr

  member __.ParseBBlock (addr) =
    parseBBLFromAddr binFile parser addr

  member __.ParseBBlock (ptr) =
    parseBBLFromBinPtr binFile parser ptr

  member __.LiftInstr (addr: Addr) =
    let ins = parser.Parse (binFile.Slice addr, addr)
    ins.Translate ctxt

  member __.LiftInstr (ptr: BinFilePointer) =
    let ins = parseInstrFromBinPtr binFile parser ptr
    ins.Translate ctxt

  member __.LiftInstr (ins: Instruction) =
    ins.Translate ctxt

  member __.LiftOptimizedInstr (addr: Addr) =
    __.LiftInstr addr |> LocalOptimizer.Optimize

  member __.LiftOptimizedInstr (ptr: BinFilePointer) =
    __.LiftInstr ptr |> LocalOptimizer.Optimize

  member __.LiftOptimizedInstr (ins: Instruction) =
    ins.Translate ctxt |> LocalOptimizer.Optimize

  member __.LiftBBlock (addr: Addr) =
    liftBBLFromAddr binFile parser ctxt addr

  member __.LiftBBlock (ptr: BinFilePointer) =
    liftBBLFromBinPtr binFile parser ctxt ptr

  member __.DisasmInstr (addr: Addr, showAddr, resolveSymbol) =
    let ins = parser.Parse (binFile.Slice addr, addr)
    let reader = if resolveSymbol then binFile :> INameReadable else null
    ins.Disasm (showAddr, reader)

  member __.DisasmInstr (ptr: BinFilePointer, showAddr, resolveSymbol) =
    let ins = parseInstrFromBinPtr binFile parser ptr
    let reader = if resolveSymbol then binFile :> INameReadable else null
    ins.Disasm (showAddr, reader)

  member __.DisasmInstr (ins: Instruction, showAddr, resolveSymbol) =
    let reader = if resolveSymbol then binFile :> INameReadable else null
    ins.Disasm (showAddr, reader)

  member __.DisasmInstr (addr: Addr) =
    let ins = parser.Parse (binFile.Slice addr, addr)
    ins.Disasm ()

  member __.DisasmInstr (ptr: BinFilePointer) =
    let ins = parseInstrFromBinPtr binFile parser ptr
    ins.Disasm ()

  member inline __.DisasmInstr (ins: Instruction) =
    ins.Disasm ()

  member __.DisasmBBlock (addr, showAddr, resolveSymbol) =
    disasmBBLFromAddr binFile parser showAddr resolveSymbol addr

  member __.DisasmBBlock (ptr, showAddr, resolveSymbol) =
    disasmBBLFromBinPtr binFile parser showAddr resolveSymbol ptr

// vim: set tw=80 sts=2 sw=2:

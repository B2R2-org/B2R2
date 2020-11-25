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
    let path = try IO.Path.GetFullPath path with _ -> ""
    let fmt, isa = identifyFormatAndISA bytes path isa autoDetect
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
    BinHandle.Init (isa, archMode, autoDetect, baseAddr, bytes, fileName)

  static member Init (isa, baseAddr, fileName) =
    let bytes = IO.File.ReadAllBytes fileName
    let defaultMode = ArchOperationMode.NoMode
    BinHandle.Init (isa, defaultMode, true, baseAddr, bytes, fileName)

  static member Init (isa, fileName) =
    BinHandle.Init (isa=isa, baseAddr=0UL, fileName=fileName)

  static member Init (isa, baseAddr, bytes) =
    let defaultMode = ArchOperationMode.NoMode
    BinHandle.Init (isa, defaultMode, false, baseAddr, bytes, "")

  static member Init (isa, bytes) =
    BinHandle.Init (isa=isa, baseAddr=0UL, bytes=bytes)

  static member Init (isa, archMode) =
    BinHandle.Init (isa, archMode, false, 0UL, [||], "")

  static member Init (isa) = BinHandle.Init (isa, [||])

  static member UpdateCode h addr bs =
    { h with FileInfo = RawFileInfo (bs, "", h.ISA, addr) :> FileInfo }

  member __.ReadBytes (addr, nBytes) =
    BinHandle.ReadBytes (__, addr, nBytes)

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

  static member ReadBytes (hdl, addr, nBytes) =
    match BinHandle.TryReadBytes (hdl, addr, nBytes) with
    | Ok bs -> bs
    | Error _ -> invalidArg "ReadBytes" "Invalid size given."

  member __.ReadInt (addr, nBytes) =
    BinHandle.ReadInt (__, addr, nBytes)

  static member TryReadInt ({ FileInfo = fi }, addr, nBytes) =
    let pos = fi.TranslateAddress addr
    if pos >= fi.BinReader.Bytes.Length || pos < 0 then
      Error ErrorCase.InvalidMemoryRead
    else
      match nBytes with
      | 1 -> fi.BinReader.PeekInt8 pos |> int64 |> Ok
      | 2 -> fi.BinReader.PeekInt16 pos |> int64 |> Ok
      | 4 -> fi.BinReader.PeekInt32 pos |> int64 |> Ok
      | 8 -> fi.BinReader.PeekInt64 pos |> Ok
      | _ -> Error ErrorCase.InvalidMemoryRead

  static member ReadInt (hdl, addr, nBytes) =
    match BinHandle.TryReadInt (hdl, addr, nBytes) with
    | Ok i -> i
    | Error _ -> invalidArg "ReadInt" "Invalid size given."

  member __.ReadUInt (addr, nBytes) =
    BinHandle.ReadUInt (__, addr, nBytes)

  static member TryReadUInt ({ FileInfo = fi }, addr, nBytes) =
    let pos = fi.TranslateAddress addr
    match nBytes with
    | 1 -> fi.BinReader.PeekUInt8 pos |> uint64 |> Ok
    | 2 -> fi.BinReader.PeekUInt16 pos |> uint64 |> Ok
    | 4 -> fi.BinReader.PeekUInt32 pos |> uint64 |> Ok
    | 8 -> fi.BinReader.PeekUInt64 pos |> Ok
    | _ -> Error ErrorCase.InvalidMemoryRead

  static member ReadUInt (hdl, addr, nBytes) =
    match BinHandle.TryReadUInt (hdl, addr, nBytes) with
    | Ok i -> i
    | Error _ -> invalidArg "ReadUInt" "Invalid size given."

  member __.ReadASCII (addr) =
    BinHandle.ReadASCII (__, addr)

  static member ReadASCII ({ FileInfo = fi }, addr) =
    let rec loop acc pos =
      let b = fi.BinReader.PeekByte pos
      if b = 0uy then List.rev (b :: acc) |> List.toArray
      else loop (b :: acc) (pos + 1)
    let bs = fi.TranslateAddress addr |> loop []
    ByteArray.extractCString bs 0

  static member ParseInstr (hdl: BinHandle) ctxt addr =
    hdl.FileInfo.TranslateAddress addr
    |> hdl.Parser.Parse hdl.FileInfo.BinReader ctxt addr

  static member TryParseInstr hdl ctxt addr =
    try BinHandle.ParseInstr hdl ctxt addr |> Ok
    with _ -> Error ErrorCase.ParsingFailure

  static member ParseBBlock handle ctxt addr =
    let rec parseLoop ctxt acc pc =
      match BinHandle.TryParseInstr handle ctxt pc with
      | Ok ins ->
        let ctxt = ins.NextParsingContext
        if ins.IsExit () then Ok (List.rev (ins :: acc), ctxt)
        else parseLoop ctxt (ins :: acc) (pc + uint64 ins.Length)
      | Error _ -> Error <| List.rev acc
    parseLoop ctxt [] addr

  static member inline LiftInstr (handle: BinHandle) (ins: Instruction) =
    ins.Translate handle.TranslationContext

  static member LiftBBlock (hdl: BinHandle) ctxt addr =
    match BinHandle.ParseBBlock hdl ctxt addr with
    | Ok (bbl, ctxt) ->
      let struct (stmts, addr) = lift hdl.TranslationContext addr bbl
      Ok (stmts, addr, ctxt)
    | Error bbl ->
      let struct (stmts, addr) = lift hdl.TranslationContext addr bbl
      Error (stmts, addr)

  static member LiftIRBBlock (hdl: BinHandle) ctxt addr =
    let rec liftLoop ctxt acc pc =
      match BinHandle.TryParseInstr hdl ctxt pc with
      | Ok ins ->
        let stmts = ins.Translate hdl.TranslationContext
        let acc = (ins, stmts) :: acc
        let pc = pc + uint64 ins.Length
        let lastStmt = stmts.[stmts.Length - 1]
        if BinIR.Utils.isBBEnd lastStmt then
          Ok (List.rev acc, ctxt, pc)
        else liftLoop ins.NextParsingContext acc pc
      | Error _ -> Error []
    liftLoop ctxt [] addr

  static member inline DisasmInstr hdl showAddr resolve (ins: Instruction) =
    ins.Disasm (showAddr, resolve, hdl.DisasmHelper)

  static member inline DisasmInstrSimple (ins: Instruction) =
    ins.Disasm ()

  static member DisasmBBlock hdl ctxt showAddr resolve addr =
    match BinHandle.ParseBBlock hdl ctxt addr with
    | Ok (bbl, ctxt) ->
      let struct (str, addr) = disasm showAddr resolve hdl.DisasmHelper addr bbl
      Ok (str, addr, ctxt)
    | Error bbl ->
      let struct (str, addr) = disasm showAddr resolve hdl.DisasmHelper addr bbl
      Error (str, addr)

  static member Optimize stmts = LocalOptimizer.Optimize stmts

// vim: set tw=80 sts=2 sw=2:

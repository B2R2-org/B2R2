(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Minkyu Jung <hestati@kaist.ac.kr>

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

open System
open System.Runtime.InteropServices
open System.Threading.Tasks
open B2R2
open B2R2.BinFile
open B2R2.FrontEnd
open B2R2.FrontEnd.BinHandlerHelper

type BinHandler = {
  ISA: ISA
  FileInfo: FileInfo
  ParsingContext: ParsingContext
  TranslationContext: TranslationContext
  Parser: Parser
}
with
  static member private Init (isa, mode, autoDetect, baseAddr, bytes, path) =
    let path = try IO.Path.GetFullPath path with _ -> ""
    let fi = newFileInfo bytes baseAddr path isa autoDetect
    let isa = fi.ISA
    let needCheckThumb = mode = ArchOperationMode.NoMode && isARM isa
    let mode = if needCheckThumb then detectThumb fi.EntryPoint isa else mode
    let ctxt, parser = initHelpers isa
    { ISA = isa
      FileInfo = fi
      ParsingContext = ParsingContext (mode)
      TranslationContext = ctxt
      Parser = parser }

  static member Init (isa, archMode, autoDetect, baseAddr, bytes) =
    BinHandler.Init (isa, archMode, autoDetect, baseAddr, bytes, "")

  static member Init (isa, archMode, autoDetect, baseAddr, fileName) =
    let bytes = IO.File.ReadAllBytes fileName
    BinHandler.Init (isa, archMode, autoDetect, baseAddr, bytes, fileName)

  static member Init (isa, fileName) =
    let bytes = IO.File.ReadAllBytes fileName
    let defaultMode = ArchOperationMode.NoMode
    BinHandler.Init (isa, defaultMode, true, 0UL, bytes, fileName)

  static member Init (isa, bytes) =
    let defaultMode = ArchOperationMode.NoMode
    BinHandler.Init (isa, defaultMode, false, 0UL, bytes, "")

  static member Init (isa, archMode) =
    BinHandler.Init (isa, archMode, false, 0UL, [||], "")

  static member Init (isa) = BinHandler.Init (isa, [||])

  static member UpdateCode h addr bs =
    { h with FileInfo = new RawFileInfo (bs, addr, h.ISA) :> FileInfo }

  member __.ReadBytes (addr, nBytes) =
    BinHandler.ReadBytes (__, addr, nBytes)

  static member ReadBytes ({ FileInfo = fi }, addr, nBytes) =
    if fi.IsValidAddr (addr + uint64 nBytes - 1UL) then
      fi.BinReader.PeekBytes (nBytes, fi.TranslateAddress addr)
    else invalidArg "ReadBytes" "Invalid address or size is given."

  member __.ReadInt (addr, nBytes) =
    BinHandler.ReadInt (__, addr, nBytes)

  static member ReadInt ({ FileInfo = fi }, addr, nBytes) =
    let pos = fi.TranslateAddress addr
    match nBytes with
    | 1 -> fi.BinReader.PeekInt8 pos |> int64
    | 2 -> fi.BinReader.PeekInt16 pos |> int64
    | 4 -> fi.BinReader.PeekInt32 pos |> int64
    | 8 -> fi.BinReader.PeekInt64 pos
    | _ -> invalidArg "ReadInt" "Invalid size given."

  member __.ReadUInt (addr, nBytes) =
    BinHandler.ReadUInt (__, addr, nBytes)

  static member ReadUInt ({ FileInfo = fi }, addr, nBytes) =
    let pos = fi.TranslateAddress addr
    match nBytes with
    | 1 -> fi.BinReader.PeekUInt8 pos |> uint64
    | 2 -> fi.BinReader.PeekUInt16 pos |> uint64
    | 4 -> fi.BinReader.PeekUInt32 pos |> uint64
    | 8 -> fi.BinReader.PeekUInt64 pos
    | _ -> invalidArg "ReadUInt" "Invalid size given."

  member __.ReadASCII (addr) =
    BinHandler.ReadASCII (__, addr)

  static member ReadASCII ({ FileInfo = fi }, addr) =
    let rec loop acc pos =
      let b = fi.BinReader.PeekByte pos
      if b = 0uy then List.rev (b :: acc) |> List.toArray
      else loop (b :: acc) (pos + 1)
    let bs = fi.TranslateAddress addr |> loop []
    ByteArray.extractCString bs 0

  static member ParseInstr (hdl: BinHandler) addr =
    hdl.FileInfo.TranslateAddress addr
    |> hdl.Parser.Parse hdl.FileInfo.BinReader hdl.ParsingContext addr

  static member TryParseInstr handler addr =
    try BinHandler.ParseInstr handler addr |> Some
    with _ -> None

  static member ParseBBlock handle addr =
    let rec parseLoop acc pc =
      match BinHandler.TryParseInstr handle pc with
      | Some ins ->
        if ins.IsExit () then Ok <| List.rev (ins :: acc)
        else parseLoop (ins :: acc) (pc + uint64 ins.Length)
      | None -> Error <| List.rev acc
    parseLoop [] addr

  static member ParseBBlockWithAddr (handle, addr) =
    let rec parseLoop acc pc =
      match BinHandler.TryParseInstr handle pc with
      | Some ins ->
        if ins.IsExit () then Ok (List.rev (ins :: acc)), pc + uint64 ins.Length
        else parseLoop (ins :: acc) (pc + uint64 ins.Length)
      | None -> Error (List.rev acc), pc
    parseLoop [] addr

  static member inline LiftInstr (handle: BinHandler) (ins: Instruction) =
    ins.Translate handle.TranslationContext

  static member LiftBBlock (handler: BinHandler) addr =
    match BinHandler.ParseBBlock handler addr with
    | Ok bbl -> lift handler.TranslationContext addr bbl |> Ok
    | Error bbl -> lift handler.TranslationContext addr bbl |> Error

  static member LiftIRBBlock (handler: BinHandler) addr =
    let rec liftLoop acc pc =
      match BinHandler.TryParseInstr handler pc with
      | Some ins ->
        let stmts = ins.Translate handler.TranslationContext
        let acc = (ins, stmts) :: acc
        let pc = pc + uint64 ins.Length
        let lastStmt = stmts.[stmts.Length - 1]
        if BinIR.Utils.isBBEnd lastStmt then Ok (List.rev acc, pc)
        else liftLoop acc pc
      | None -> Error []
    liftLoop [] addr

  static member inline DisasmInstr handler showAddr resolve (ins: Instruction) =
    ins.Disasm (showAddr, resolve, handler.FileInfo)

  static member inline DisasmInstrSimple (ins: Instruction) =
    ins.Disasm ()

  static member DisasmBBlock handler showAddr resolve addr =
    match BinHandler.ParseBBlock handler addr with
    | Ok bbl -> disasm showAddr resolve handler.FileInfo addr bbl |> Ok
    | Error bbl -> disasm showAddr resolve handler.FileInfo addr bbl |> Error

  static member Optimize stmts = LocalOptimizer.Optimize stmts

  static member LiftInstList (handler: BinHandler) insts success =
    List.map (fun (ins: Instruction) ->
                ins.Translate handler.TranslationContext) insts |> Array.concat,
    success

  static member LiftOptInstList (handler: BinHandler) insts success =
    List.map (fun (ins: Instruction) ->
                ins.Translate handler.TranslationContext) insts |> Array.concat
    |> LocalOptimizer.Optimize, success

  static member BuildTask func = new Task<BinIR.LowUIR.Stmt [] * bool> (func)

  static member CreateLiftBBlockTask
    (handler, addr, [<Optional;DefaultParameterValue(true)>] optimize: bool,
     [<Out>] nxt: byref<Addr>) =
    match BinHandler.ParseBBlockWithAddr (handler, addr) with
    | Ok (is), next ->
      nxt <- next
      if optimize then (fun () -> BinHandler.LiftOptInstList handler is true)
                  else (fun () -> BinHandler.LiftInstList handler is true)
      |> BinHandler.BuildTask
    | Error (is), stop ->
      nxt <- stop + 1UL // FIXME: next address, its Intel
      if optimize then (fun () -> BinHandler.LiftOptInstList handler is false)
                  else (fun () -> BinHandler.LiftInstList handler is false)
      |> BinHandler.BuildTask

// vim: set tw=80 sts=2 sw=2:

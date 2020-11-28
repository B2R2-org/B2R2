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

module internal B2R2.FrontEnd.BinInterface.Helper

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open System.Text

let initBasis isa =
  match isa.Arch with
  | Arch.IntelX64
  | Arch.IntelX86 -> Intel.Basis.init isa
  | Arch.ARMv7 -> ARM32.Basis.init isa
  | Arch.AARCH64 -> ARM64.Basis.init isa
  | Arch.MIPS1 | Arch.MIPS2 | Arch.MIPS3 | Arch.MIPS4 | Arch.MIPS5
  | Arch.MIPS32 | Arch.MIPS32R2 | Arch.MIPS32R6
  | Arch.MIPS64 | Arch.MIPS64R2 | Arch.MIPS64R6 -> MIPS.Basis.init isa
  | Arch.EVM -> EVM.Basis.init isa
  | Arch.TMS320C6000 -> TMS320C6000.Basis.init isa
  | _ -> Utils.futureFeature ()

let identifyFormatAndISA bytes path isa autoDetect =
  if autoDetect then
    if System.IO.File.Exists path then FormatDetector.identifyFromFile path isa
    else FormatDetector.identifyFromBuffer bytes isa
  else FileFormat.RawBinary, isa

let newFileInfo bytes (baddr: Addr) path fmt isa regbay =
  match fmt with
  | FileFormat.ELFBinary ->
    ELFFileInfo (bytes, path, baddr, Some regbay) :> FileInfo
  | FileFormat.PEBinary ->
    PEFileInfo (bytes, path, baddr) :> FileInfo
  | FileFormat.MachBinary ->
    MachFileInfo (bytes, path, isa, baddr) :> FileInfo
  | _ -> new RawFileInfo (bytes, path, isa, baddr) :> FileInfo

let detectThumb entryPoint (isa: ISA) =
  match entryPoint, isa.Arch with
  | Some entry, Arch.ARMv7 when entry % 2UL <> 0UL -> (* XXX: LIbraries? *)
    ArchOperationMode.ThumbMode
  | _ -> ArchOperationMode.ARMMode

let isARM (isa: ISA) =
  match isa.Arch with
  | Arch.ARMv7 | Arch.AARCH32 | Arch.AARCH64 -> true
  | _ -> false

/// Classify ranges to be either in-file or not-in-file. The second parameter
/// (notinfiles) is a sequence of (exclusive) ranges within the myrange, which
/// represent the not-in-file ranges. This function will simply divide the
/// myrange into subranges where each subrange is labeled with either true or
/// false, where true means in-file, and false means not-in-file.
let classifyRanges myrange notinfiles =
  notinfiles
  |> Seq.fold (fun (infiles, saddr) r ->
       let l = AddrRange.GetMin r
       let h = AddrRange.GetMax r
       if saddr = l then (r, false) :: infiles, h
       else (r, false) :: ((AddrRange (saddr, l), true) :: infiles), h
     ) ([], AddrRange.GetMin myrange)
  |> (fun (infiles, saddr) ->
       if saddr = myrange.Max then infiles
       else ((AddrRange (saddr, myrange.Max), true) :: infiles))
  |> List.rev

let inline readIntBySize (fi: FileInfo) pos size =
  match size with
  | 1 -> fi.BinReader.PeekInt8 pos |> int64 |> Ok
  | 2 -> fi.BinReader.PeekInt16 pos |> int64 |> Ok
  | 4 -> fi.BinReader.PeekInt32 pos |> int64 |> Ok
  | 8 -> fi.BinReader.PeekInt64 pos |> Ok
  | _ -> Error ErrorCase.InvalidMemoryRead

let inline readUIntBySize (fi: FileInfo) pos size =
  match size with
  | 1 -> fi.BinReader.PeekUInt8 pos |> uint64 |> Ok
  | 2 -> fi.BinReader.PeekUInt16 pos |> uint64 |> Ok
  | 4 -> fi.BinReader.PeekUInt32 pos |> uint64 |> Ok
  | 8 -> fi.BinReader.PeekUInt64 pos |> Ok
  | _ -> Error ErrorCase.InvalidMemoryRead

let inline readASCII (fi: FileInfo) pos =
  let rec loop acc pos =
    let b = fi.BinReader.PeekByte pos
    if b = 0uy then List.rev (b :: acc) |> List.toArray
    else loop (b :: acc) (pos + 1)
  loop [] pos

let inline parseInstrFromAddr (fi: FileInfo) (parser: Parser) ctxt addr =
  fi.TranslateAddress addr
  |> parser.Parse fi.BinReader ctxt addr

let inline tryParseInstrFromAddr (fi: FileInfo) (parser: Parser) ctxt addr =
  try parseInstrFromAddr fi parser ctxt addr |> Ok
  with _ -> Error ErrorCase.ParsingFailure

let inline parseInstrFromBinPtr (fi: FileInfo) parser ctxt (bp: BinaryPointer) =
  (parser: Parser).Parse fi.BinReader ctxt bp.Addr bp.Offset

let inline tryParseInstrFromBinPtr (fi: FileInfo) (parser: Parser) ctxt bp =
  try parseInstrFromBinPtr fi parser ctxt bp |> Ok
  with _ -> Error ErrorCase.ParsingFailure

let advanceAddr addr len =
  addr + uint64 len

let rec parseBBLAux fi parser ctxt tryParseFn advanceFn pos acc =
  match tryParseFn fi parser ctxt pos with
  | Ok (ins: Instruction) ->
    let ctxt = ins.NextParsingContext
    if ins.IsExit () then Ok (List.rev (ins :: acc), ctxt)
    else
      let pos = advanceFn pos (int ins.Length)
      parseBBLAux fi parser ctxt tryParseFn advanceFn pos (ins :: acc)
  | Error _ -> Error <| List.rev acc

let inline parseBBLFromAddr (fi: FileInfo) (parser: Parser) ctxt addr =
  parseBBLAux fi parser ctxt tryParseInstrFromAddr advanceAddr addr []

let inline parseBBLFromBinPtr (fi: FileInfo) (parser: Parser) ctxt bp =
  parseBBLAux fi parser ctxt tryParseInstrFromBinPtr BinaryPointer.Advance bp []

let rec liftBBLAux acc advanceFn trctxt pos = function
  | (ins: Instruction) :: rest ->
    let pos = advanceFn pos (int ins.Length)
    liftBBLAux (ins.Translate trctxt :: acc) advanceFn trctxt pos rest
  | [] -> struct (List.rev acc |> Array.concat, pos)

let inline liftBBLFromAddr fi parser trctxt pctxt addr =
  match parseBBLFromAddr fi parser pctxt addr with
  | Ok (bbl, ctxt) ->
    let struct (stmts, addr) = liftBBLAux [] advanceAddr trctxt addr bbl
    Ok (stmts, addr, ctxt)
  | Error bbl ->
    let struct (stmts, addr) = liftBBLAux [] advanceAddr trctxt addr bbl
    Error (stmts, addr)

let inline liftBBLFromBinPtr fi parser trctxt pctxt bp =
  match parseBBLFromBinPtr fi parser pctxt bp with
  | Ok (bbl, ctxt) ->
    let struct (stmts, bp) = liftBBLAux [] BinaryPointer.Advance trctxt bp bbl
    Ok (stmts, bp, ctxt)
  | Error bbl ->
    let struct (stmts, bp) = liftBBLAux [] BinaryPointer.Advance trctxt bp bbl
    Error (stmts, bp)

let rec disasmBBLAux sb advanceFn showAddr resolve hlp pos = function
  | (ins: Instruction) :: rest ->
    let s = ins.Disasm (showAddr, resolve, hlp)
    let s =
      if (sb: StringBuilder).Length = 0 then s
      else System.Environment.NewLine + s
    let pos = advanceFn pos (int ins.Length)
    disasmBBLAux (sb.Append (s)) advanceFn showAddr resolve hlp pos rest
  | [] -> struct (sb.ToString (), pos)

let disasmBBLFromAddr fi parser hlp showAddr resolve ctxt addr =
  match parseBBLFromAddr fi parser ctxt addr with
  | Ok (bbl, ctxt) ->
    let struct (str, addr) =
      disasmBBLAux (StringBuilder ()) advanceAddr showAddr resolve hlp addr bbl
    Ok (str, addr, ctxt)
  | Error bbl ->
    let struct (str, addr) =
      disasmBBLAux (StringBuilder ()) advanceAddr showAddr resolve hlp addr bbl
    Error (str, addr)

let disasmBBLFromBinPtr fi parser hlp showAddr resolve ctxt bp =
  match parseBBLFromBinPtr fi parser ctxt bp with
  | Ok (bbl, ctxt) ->
    let struct (str, addr) =
      disasmBBLAux (StringBuilder ())
        BinaryPointer.Advance showAddr resolve hlp bp bbl
    Ok (str, addr, ctxt)
  | Error bbl ->
    let struct (str, addr) =
      disasmBBLAux (StringBuilder ())
        BinaryPointer.Advance showAddr resolve hlp bp bbl
    Error (str, addr)

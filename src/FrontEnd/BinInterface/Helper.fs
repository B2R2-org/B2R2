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

open System.Text
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter

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
  | Arch.CILOnly -> CIL.Basis.init isa
  | Arch.AVR -> AVR.Basis.init isa
  | Arch.SH4 -> SH4.Basis.init isa
  | _ -> Utils.futureFeature ()

let private appendOSInfo fmt isa =
  match fmt with
  | FileFormat.ELFBinary -> struct (fmt, isa, OS.Linux)
  | FileFormat.PEBinary -> struct (fmt, isa, OS.Windows)
  | FileFormat.MachBinary -> struct (fmt, isa, OS.MacOSX)
  | _ -> Utils.impossible ()

let identifyFormatAndISAAndOS bytes isa os autoDetect =
  if autoDetect then FormatDetector.identify bytes isa ||> appendOSInfo
  else struct (FileFormat.RawBinary, isa, Option.defaultValue OS.UnknownOS os)

let newFileInfo bytes (baddr: Addr option) path fmt isa regbay =
  match fmt with
  | FileFormat.ELFBinary ->
    ELFFileInfo (bytes, path, baddr, Some regbay) :> FileInfo
  | FileFormat.PEBinary ->
    PEFileInfo (bytes, path, baddr) :> FileInfo
  | FileFormat.MachBinary ->
    MachFileInfo (bytes, path, isa, baddr) :> FileInfo
  | _ -> RawFileInfo (bytes, path, isa, baddr) :> FileInfo

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

let inline parseInstrFromAddr (fi: FileInfo) (parser: Parser) addr =
  fi.TranslateAddress addr
  |> parser.Parse fi.BinReader addr

let inline tryParseInstrFromAddr (fi: FileInfo) (parser: Parser) addr =
  try parseInstrFromAddr fi parser addr |> Ok
  with _ -> Error ErrorCase.ParsingFailure

let inline tryParseInstrFromBinPtr fi (p: Parser) (bp: BinaryPointer) =
  try
    let ins = p.Parse (fi: FileInfo).BinReader bp.Addr bp.Offset
    if BinaryPointer.IsValidAccess bp (int ins.Length) then Ok ins
    else Error ErrorCase.ParsingFailure
  with _ ->
    Error ErrorCase.ParsingFailure

let inline parseInstrFromBinPtr (fi: FileInfo) parser (bp: BinaryPointer) =
  match tryParseInstrFromBinPtr fi parser bp with
  | Ok ins -> ins
  | Error _ -> raise ParsingFailureException

let advanceAddr addr len =
  addr + uint64 len

let rec parseLoopByAddr fi parser addr acc =
  match tryParseInstrFromAddr fi parser addr with
  | Ok ins ->
    if ins.IsBBLEnd () then Ok (List.rev (ins :: acc))
    else
      let addr = addr + (uint64 ins.Length)
      parseLoopByAddr fi parser addr (ins :: acc)
  | Error _ -> Error <| List.rev acc

let inline parseBBLFromAddr (fi: FileInfo) (parser: Parser) addr =
  parseLoopByAddr fi parser addr []

let rec parseLoopByPtr fi parser bp acc =
  match tryParseInstrFromBinPtr fi parser bp with
  | Ok (ins: Instruction) ->
    if ins.IsBBLEnd () then Ok (List.rev (ins :: acc))
    else
      let bp = BinaryPointer.Advance bp (int ins.Length)
      parseLoopByPtr fi parser bp (ins :: acc)
  | Error _ -> Error <| List.rev acc

let inline parseBBLFromBinPtr (fi: FileInfo) (parser: Parser) bp =
  parseLoopByPtr fi parser bp []

let rec liftBBLAux acc advanceFn trctxt pos = function
  | (ins: Instruction) :: rest ->
    let pos = advanceFn pos (int ins.Length)
    liftBBLAux (ins.Translate trctxt :: acc) advanceFn trctxt pos rest
  | [] -> struct (List.rev acc |> Array.concat, pos)

let inline liftBBLFromAddr fi parser trctxt addr =
  match parseBBLFromAddr fi parser addr with
  | Ok bbl ->
    let struct (stmts, addr) = liftBBLAux [] advanceAddr trctxt addr bbl
    Ok (stmts, addr)
  | Error bbl ->
    let struct (stmts, addr) = liftBBLAux [] advanceAddr trctxt addr bbl
    Error (stmts, addr)

let inline liftBBLFromBinPtr fi parser trctxt bp =
  match parseBBLFromBinPtr fi parser bp with
  | Ok bbl ->
    let struct (stmts, bp) = liftBBLAux [] BinaryPointer.Advance trctxt bp bbl
    Ok (stmts, bp)
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

let disasmBBLFromAddr fi parser hlp showAddr resolve addr =
  match parseBBLFromAddr fi parser addr with
  | Ok bbl ->
    let struct (str, addr) =
      disasmBBLAux (StringBuilder ()) advanceAddr showAddr resolve hlp addr bbl
    Ok (str, addr)
  | Error bbl ->
    let struct (str, addr) =
      disasmBBLAux (StringBuilder ()) advanceAddr showAddr resolve hlp addr bbl
    Error (str, addr)

let disasmBBLFromBinPtr fi parser hlp showAddr resolve bp =
  match parseBBLFromBinPtr fi parser bp with
  | Ok bbl ->
    let struct (str, addr) =
      disasmBBLAux (StringBuilder ())
        BinaryPointer.Advance showAddr resolve hlp bp bbl
    Ok (str, addr)
  | Error bbl ->
    let struct (str, addr) =
      disasmBBLAux (StringBuilder ())
        BinaryPointer.Advance showAddr resolve hlp bp bbl
    Error (str, addr)

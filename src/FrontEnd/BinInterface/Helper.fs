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

let private appendOSInfo fmt isa =
  match fmt with
  | FileFormat.ELFBinary -> struct (fmt, isa, OS.Linux)
  | FileFormat.PEBinary -> struct (fmt, isa, OS.Windows)
  | FileFormat.MachBinary -> struct (fmt, isa, OS.MacOSX)
  | FileFormat.WasmBinary -> struct (fmt, isa, OS.UnknownOS)
  | FileFormat.RawBinary -> struct (fmt, isa, OS.UnknownOS)
  | _ -> Utils.impossible ()

let identifyFormatAndISAAndOS bytes isa os autoDetect =
  if autoDetect then FormatDetector.identify bytes isa ||> appendOSInfo
  else struct (FileFormat.RawBinary, isa, Option.defaultValue OS.UnknownOS os)

let newFileInfo bytes (baddr: Addr option) path fmt isa regbay =
  match fmt with
  | FileFormat.ELFBinary ->
    ELFBinFile (bytes, path, baddr, Some regbay) :> IBinFile
  | FileFormat.PEBinary ->
    PEBinFile (bytes, path, baddr) :> IBinFile
  | FileFormat.MachBinary ->
    MachBinFile (bytes, path, isa, baddr) :> IBinFile
  | FileFormat.WasmBinary ->
    WasmBinFile (bytes, path, baddr) :> IBinFile
  | _ -> RawBinFile (bytes, path, isa, baddr) :> IBinFile

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

let inline readIntBySize (r: IBinReader) (span: ByteSpan) size =
  match size with
  | 1 -> r.ReadInt8 (span, 0) |> int64 |> Ok
  | 2 -> r.ReadInt16 (span, 0) |> int64 |> Ok
  | 4 -> r.ReadInt32 (span, 0) |> int64 |> Ok
  | 8 -> r.ReadInt64 (span, 0) |> Ok
  | _ -> Error ErrorCase.InvalidMemoryRead

let inline readUIntBySize (r: IBinReader) (span: ByteSpan) size =
  match size with
  | 1 -> r.ReadUInt8 (span, 0) |> uint64 |> Ok
  | 2 -> r.ReadUInt16 (span, 0) |> uint64 |> Ok
  | 4 -> r.ReadUInt32 (span, 0) |> uint64 |> Ok
  | 8 -> r.ReadUInt64 (span, 0) |> Ok
  | _ -> Error ErrorCase.InvalidMemoryRead

let inline readASCII (file: IBinFile) pos =
  let rec loop acc pos =
    let b = file.RawBytes[pos]
    if b = 0uy then List.rev (b :: acc) |> List.toArray
    else loop (b :: acc) (pos + 1)
  loop [] pos

let inline tryParseInstrFromAddr (file: IBinFile) (parser: Parser) addr =
  try parser.Parse (file.Slice (addr=addr), addr) |> Ok
  with _ -> Error ErrorCase.ParsingFailure

let inline tryParseInstrFromBinPtr file (p: Parser) (ptr: BinFilePointer) =
  try
    let ins = p.Parse ((file: IBinFile).Slice ptr.Offset, ptr.Addr)
    if BinFilePointer.IsValidAccess ptr (int ins.Length) then Ok ins
    else Error ErrorCase.ParsingFailure
  with _ ->
    Error ErrorCase.ParsingFailure

let inline parseInstrFromBinPtr (file: IBinFile) parser (ptr: BinFilePointer) =
  match tryParseInstrFromBinPtr file parser ptr with
  | Ok ins -> ins
  | Error _ -> raise ParsingFailureException

let advanceAddr addr len =
  addr + uint64 len

let rec parseLoopByAddr file parser addr acc =
  match tryParseInstrFromAddr file parser addr with
  | Ok ins ->
    if ins.IsBBLEnd () then Ok (List.rev (ins :: acc))
    else
      let addr = addr + (uint64 ins.Length)
      parseLoopByAddr file parser addr (ins :: acc)
  | Error _ -> Error <| List.rev acc

let inline parseBBLFromAddr (file: IBinFile) (parser: Parser) addr =
  parseLoopByAddr file parser addr []

let rec parseLoopByPtr file parser ptr acc =
  match tryParseInstrFromBinPtr file parser ptr with
  | Ok (ins: Instruction) ->
    if ins.IsBBLEnd () then Ok (List.rev (ins :: acc))
    else
      let ptr = BinFilePointer.Advance ptr (int ins.Length)
      parseLoopByPtr file parser ptr (ins :: acc)
  | Error _ -> Error <| List.rev acc

let inline parseBBLFromBinPtr (file: IBinFile) (parser: Parser) ptr =
  parseLoopByPtr file parser ptr []

let rec liftBBLAux acc advanceFn trctxt pos = function
  | (ins: Instruction) :: rest ->
    let pos = advanceFn pos (int ins.Length)
    liftBBLAux (ins.Translate trctxt :: acc) advanceFn trctxt pos rest
  | [] -> struct (List.rev acc |> Array.concat, pos)

let inline liftBBLFromAddr file parser trctxt addr =
  match parseBBLFromAddr file parser addr with
  | Ok bbl ->
    let struct (stmts, addr) = liftBBLAux [] advanceAddr trctxt addr bbl
    Ok (stmts, addr)
  | Error bbl ->
    let struct (stmts, addr) = liftBBLAux [] advanceAddr trctxt addr bbl
    Error (stmts, addr)

let inline liftBBLFromBinPtr file parser trctxt ptr =
  match parseBBLFromBinPtr file parser ptr with
  | Ok bbl ->
    let struct (stmts, ptr) =
      liftBBLAux [] BinFilePointer.Advance trctxt ptr bbl
    Ok (stmts, ptr)
  | Error bbl ->
    let struct (stmts, ptr) =
      liftBBLAux [] BinFilePointer.Advance trctxt ptr bbl
    Error (stmts, ptr)

let rec disasmBBLAux sb advanceFn showAddr resolve hlp pos = function
  | (ins: Instruction) :: rest ->
    let s = ins.Disasm (showAddr, resolve, hlp)
    let s =
      if (sb: StringBuilder).Length = 0 then s
      else System.Environment.NewLine + s
    let pos = advanceFn pos (int ins.Length)
    disasmBBLAux (sb.Append (s)) advanceFn showAddr resolve hlp pos rest
  | [] -> struct (sb.ToString (), pos)

let disasmBBLFromAddr file parser hlp showAddr resolve addr =
  match parseBBLFromAddr file parser addr with
  | Ok bbl ->
    let struct (str, addr) =
      disasmBBLAux (StringBuilder ()) advanceAddr showAddr resolve hlp addr bbl
    Ok (str, addr)
  | Error bbl ->
    let struct (str, addr) =
      disasmBBLAux (StringBuilder ()) advanceAddr showAddr resolve hlp addr bbl
    Error (str, addr)

let disasmBBLFromBinPtr file parser hlp showAddr resolve ptr =
  match parseBBLFromBinPtr file parser ptr with
  | Ok bbl ->
    let struct (str, addr) =
      disasmBBLAux (StringBuilder ())
        BinFilePointer.Advance showAddr resolve hlp ptr bbl
    Ok (str, addr)
  | Error bbl ->
    let struct (str, addr) =
      disasmBBLAux (StringBuilder ())
        BinFilePointer.Advance showAddr resolve hlp ptr bbl
    Error (str, addr)

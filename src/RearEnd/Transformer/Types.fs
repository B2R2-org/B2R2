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

namespace B2R2.RearEnd.Transformer

open System
open System.Text
open B2R2
open B2R2.FrontEnd.BinInterface

/// Binary is the main data object representing a byte sequence tagged with
/// some useful information.
type Binary = Binary of BinHandle * annotation: string
with
  static member Init annot hdl = Binary (hdl, annot)

  static member PlainInit hdl = Binary (hdl, "")

  static member Handle bin =
    match bin with
    | Binary (hdl, _) -> hdl

  static member Annotation bin =
    match bin with
    | Binary (_, annot) -> annot

  override __.ToString () =
    match __ with
    | Binary (hdl, annot) when hdl.BinFile.FileFormat = FileFormat.RawBinary ->
      let s = Utils.makeSpanSummary hdl.BinFile.Span
      $"Binary(Raw) | 0x{hdl.BinFile.BaseAddress:x8} | {s}{annot}"
    | Binary (hdl, annot) ->
      let s = Utils.makeSpanSummary hdl.BinFile.Span
      let fmt = FileFormat.toString hdl.BinFile.FileFormat
      let path = hdl.BinFile.FilePath
      let finfo = if String.IsNullOrEmpty path then "" else $", {path}"
      $"Binary({fmt}{finfo}) | 0x{hdl.BinFile.BaseAddress:x8} | {s}{annot}"

/// Instruction tagged with its corresponding bytes.
type Instruction =
  | ValidInstruction of FrontEnd.BinLifter.Instruction * byte[]
  | BadInstruction of Addr * byte[]
with
  override __.ToString () =
    match __ with
    | ValidInstruction (ins, bs) ->
      let bs = Utils.makeByteArraySummary bs
      $"{ins.Address:x16} | {bs.PadRight 32} | {ins.Disasm ()}"
    | BadInstruction (addr, bs) ->
      let bs = Utils.makeByteArraySummary bs
      $"{addr:x16} | {bs.PadRight 32} | (bad)"

/// Fingerprint of a binary, which is a list of (hash * byte position) tuple.
type Fingerprint = {
  Patterns: (int * int) list
  NGramSize: int
  WindowSize: int
}
with
  override __.ToString () =
    let sb = StringBuilder ()
    __.Patterns
    |> List.iter (fun (b, p) ->
      sb.Append $"{b:x2}@{p}{Environment.NewLine}" |> ignore)
    sb.ToString ()

/// Collection of objects.
type ObjCollection = {
  Values: obj array
}

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

module B2R2.RearEnd.FileViewer.Helper

open B2R2
open B2R2.RearEnd
open B2R2.FrontEnd.BinFile

let addrToString size addr = Addr.toString size addr

let normalizeEmpty s =
  if System.String.IsNullOrEmpty s then "(n/a)" else s

let toHexString (v: uint64) =
  "0x" + v.ToString ("x")

let toHexString32 (v: uint32) =
  "0x" + v.ToString ("x")

let toNBytes (v: uint64) =
  v.ToString () + " bytes"

let columnWidthOfAddr (fi: FileInfo) =
  match fi with
  | :? ELFFileInfo as fi ->
    if fi.ELF.ELFHdr.Class = WordSize.Bit32 then 8 else 16
  | :? PEFileInfo as fi ->
    if fi.PE.WordSize = WordSize.Bit32 then 8 else 16
  | :? MachFileInfo as fi ->
    if fi.Mach.MachHdr.Class = WordSize.Bit32 then 8 else 16
  | _ -> Utils.futureFeature ()

let targetString s =
  match s.Target with
  | TargetKind.StaticSymbol -> "(s)"
  | TargetKind.DynamicSymbol -> "(d)"
  | _ -> Utils.impossible ()

let toLibString s =
  if System.String.IsNullOrEmpty s then s else "@" + s

let wrapParen s =
  "(" + s + ")"

let wrapSqrdBrac s =
  "[" + s + "]"

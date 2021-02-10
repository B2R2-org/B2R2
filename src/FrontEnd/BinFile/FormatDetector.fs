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

/// Binary file format detector.
[<RequireQualifiedAccess>]
module B2R2.FrontEnd.BinFile.FormatDetector

open System.IO
open B2R2

let private identifyELF reader =
  if ELF.Header.isELF reader 0 then
    let cls = ELF.Header.peekClass reader 0
    let arch = ELF.Header.peekArch reader cls 0
    let endian = ELF.Header.peekEndianness reader 0
    let isa = ISA.Init arch endian
    Some (FileFormat.ELFBinary, isa)
  else None

let private identifyPE bytes =
  match PE.Helper.getPEArch bytes 0 with
  | Ok arch ->
    let isa = ISA.Init arch Endian.Little
    Some (FileFormat.PEBinary, isa)
  | Error _ -> None

let private identifyMach reader isa =
  if Mach.Header.isMach reader 0 then
    if Mach.Header.isFat reader 0 then
      Some (FileFormat.MachBinary, isa)
    else
      let arch = Mach.Header.peekArch reader 0
      let endian = Mach.Header.peekEndianness reader 0
      let isa = ISA.Init arch endian
      Some (FileFormat.MachBinary, isa)
  else None

let private identifyWASM reader isa =
  if Wasm.Header.isWasm reader 0 then
    Some (FileFormat.WasmBinary, isa)
  else None

/// <summary>
///   Given a byte array, identify its binary file format and return
///   B2R2.FileFormat and B2R2.ISA.
/// </summary>
[<CompiledName("Identify")>]
let identify bytes isa =
  let reader = BinReader.Init (bytes)
  Monads.OrElse.orElse {
    yield! identifyELF reader
    yield! identifyPE bytes
    yield! identifyMach reader isa
    yield! identifyWASM reader isa
    yield! Some (FileFormat.RawBinary, isa)
  } |> Option.get

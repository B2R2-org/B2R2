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

/// Provides a function to detect the file format of a binary.
[<RequireQualifiedAccess>]
module B2R2.FrontEnd.BinFile.FormatDetector

open B2R2
open B2R2.FrontEnd.BinLifter

let private identifyELF bytes =
  match ELF.Header.getISA bytes with
  | Ok isa -> Some struct (FileFormat.ELFBinary, isa)
  | _ -> None

let private identifyPE bytes =
  match PE.Helper.getISA bytes with
  | Ok isa -> Some struct (FileFormat.PEBinary, isa)
  | Error _ -> None

let private identifyMach bytes isa =
  if Mach.Header.isMach bytes 0UL then
    let toolBox = Mach.Header.parse bytes None isa
    let isa = Mach.Helper.getISA toolBox.Header
    Some struct (FileFormat.MachBinary, isa)
  else None

let private identifyWASM bytes isa =
  let reader = BinReader.Init Endian.Little
  if Wasm.Header.isWasm bytes reader then
    Some struct (FileFormat.WasmBinary, isa)
  else None

/// <summary>
/// Given an array of bytes, identify its binary file format (<see
/// cref='T:B2R2.FrontEnd.BinFile.FileFormat'/>) and its underlying ISA
/// (<see cref='T:B2R2.ISA'/>). For FAT binaries, this function will select an
/// ISA only when there is a match with the given input ISA. Otherwise, this
/// function will raise InvalidISAException.
/// </summary>
[<CompiledName("Identify")>]
let identify bytes isa =
  Monads.OrElse.orElse {
    yield! identifyELF bytes
    yield! identifyPE bytes
    yield! identifyMach bytes isa
    yield! identifyWASM bytes isa
    yield! Some (FileFormat.RawBinary, isa)
  } |> Option.get

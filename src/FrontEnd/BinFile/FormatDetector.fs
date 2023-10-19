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

open System
open B2R2

let private identifyELF span =
  match ELF.Header.getISA span with
  | Ok isa -> Some (FileFormat.ELFBinary, isa)
  | _ -> None

let private identifyPE bytes =
  match PE.Helper.getPEArch bytes 0 with
  | Ok arch ->
    let isa = ISA.Init arch Endian.Little
    Some (FileFormat.PEBinary, isa)
  | Error _ -> None

let private identifyMach span isa =
  if Mach.Header.isMach span then
    let reader = Mach.Header.getMachBinReader span
    if Mach.Header.isFat span reader then
      let fat =
        Mach.Fat.loadFats span reader
        |> Mach.Fat.findMatchingFatRecord isa
      let arch = Mach.Header.cpuTypeToArch fat.CPUType fat.CPUSubType
      let endian = Mach.Header.peekEndianness (span.Slice fat.Offset) reader
      let isa = ISA.Init arch endian
      Some (FileFormat.MachBinary, isa)
    else
      let arch = Mach.Header.peekArch span reader
      let endian = Mach.Header.peekEndianness span reader
      let isa = ISA.Init arch endian
      Some (FileFormat.MachBinary, isa)
  else None

let private identifyWASM span isa =
  let reader = BinReader.Init Endian.Little
  if Wasm.Header.isWasm span reader then Some (FileFormat.WasmBinary, isa)
  else None

/// <summary>
///   Given a binary (byte array), identify its binary file format
///   (B2R2.FileFormat) and its underlying ISA (B2R2.ISA). For FAT binaries,
///   this function will select an ISA only when there is a match with the given
///   input ISA. Otherwise, this function will raise InvalidISAException.
/// </summary>
[<CompiledName("Identify")>]
let identify (bytes: byte[]) isa =
  Monads.OrElse.orElse {
    yield! identifyELF (ReadOnlySpan bytes)
    yield! identifyPE bytes
    yield! identifyMach (ReadOnlySpan bytes) isa
    yield! identifyWASM (ReadOnlySpan bytes) isa
    yield! Some (FileFormat.RawBinary, isa)
  } |> Option.get

(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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
module B2R2.BinFile.FormatDetector

open System.IO
open B2R2

let private checkELF reader =
  if ELF.Header.isELF reader 0 then
    let cls = ELF.Header.peekClass reader 0
    let e = ELF.Header.peekEndianness reader 0
    let reader = BinReader.RenewReader reader e
    Some (FileFormat.ELFBinary, ISA.Init (ELF.Header.peekArch reader cls 0) e)
  else None

let private checkPE bytes =
  try Some (FileFormat.PEBinary, PE.Helper.parseFormat bytes 0)
  with _ -> None

let private checkMach reader =
  if Mach.Header.isMach reader 0 then
    let e = Mach.Header.peekEndianness reader 0
    let reader = BinReader.RenewReader reader e
    Some (FileFormat.MachBinary, ISA.Init (Mach.Header.peekArch reader 0) e)
  else None

/// <summary>
/// Given a binary file, identify file format and return a tuple of
/// (B2R2.FileFormat and B2R2.ISA).
/// </summary>
[<CompiledName("Detect")>]
let detect file =
  use f = File.OpenRead (file)
  let maxBytes = 2048 (* This is more than enough for all three file formats. *)
  let bytes = Array.create maxBytes 0uy
  f.Read (bytes, 0, maxBytes) |> ignore
  let reader = BinReader.Init (bytes)
  Monads.OrElse.orElse {
    yield! checkELF reader
    yield! checkPE bytes
    yield! checkMach reader
    yield! Some (FileFormat.RawBinary, ISA.Init (Arch.IntelX86) Endian.Little)
  } |> Option.get

// vim: set tw=80 sts=2 sw=2:

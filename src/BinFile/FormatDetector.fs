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
open B2R2.BinFile.FileHelper

let private checkELF reader offset =
  if ELF.isELFHeader reader offset then
    let cls = ELF.readClass reader offset
    let e = ELF.readEndianness reader offset
    let reader = BinReader.RenewReader reader e
    Some (FileFormat.ELFBinary, ISA.Init (ELF.readArch reader cls offset) e)
  else None

let private checkPE reader offset =
  if PE.isPEHeader reader offset then
    Some (FileFormat.PEBinary,
          ISA.Init (PE.parsePEArch reader offset) Endian.Little)
  else None

let private checkMach reader offset =
  if Mach.isMachHeader reader offset then
    let e = Mach.readEndianness reader offset
    let reader = BinReader.RenewReader reader e
    Some (FileFormat.MachBinary, ISA.Init (Mach.readArch reader offset) e)
  else None

/// <summary>
/// Given a binary file, identify file format and return a tuple of (<see
/// cref="B2R2.FileFormat"/> , and <see cref="B2R2.ISA"/>).
/// </summary>
[<CompiledName("Detect")>]
let detect file =
  use f = File.OpenRead (file)
  let maxBytes = 2000 (* This is more than enough for all three file formats. *)
  let bytes = Array.create maxBytes 0uy
  f.Read (bytes, 0, maxBytes) |> ignore
  let reader = BinReader.Init (bytes)
  Monads.OrElse.orElse {
    yield! checkELF reader startOffset
    yield! checkPE reader startOffset
    yield! checkMach reader startOffset
    yield! Some (FileFormat.RawBinary, ISA.Init (Arch.IntelX86) Endian.Little)
  } |> Option.get

// vim: set tw=80 sts=2 sw=2:

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
module B2R2.BinFile.FormatDetector

open System.IO
open B2R2

let private elfBinary reader =
  if ELF.Header.isELF reader 0 then Some FileFormat.ELFBinary
  else None

let private peBinary bytes =
  if PE.Helper.isPE bytes 0 then Some FileFormat.PEBinary
  else None

let private machBinary reader =
  if Mach.Header.isMach reader 0 then Some FileFormat.MachBinary
  else None

/// <summary>
///   Given a byte array, identify its file format and return B2R2.FileFormat.
/// </summary>
[<CompiledName("Detect")>]
let detectBuffer bytes =
  let reader = BinReader.Init (bytes)
  Monads.OrElse.orElse {
    yield! elfBinary reader
    yield! peBinary bytes
    yield! machBinary reader
    yield! Some FileFormat.RawBinary
  } |> Option.get

/// <summary>
///   Given a binary file path, identify its file format and return
///   B2R2.FileFormat.
/// </summary>
[<CompiledName("Detect")>]
let detect file =
  use f = File.OpenRead (file)
  let maxBytes = 2048 (* This is more than enough for all the file formats. *)
  let bytes = Array.create maxBytes 0uy
  f.Read (bytes, 0, maxBytes) |> ignore
  detectBuffer bytes

// vim: set tw=80 sts=2 sw=2:

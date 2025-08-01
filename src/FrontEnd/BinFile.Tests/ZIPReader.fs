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

module B2R2.FrontEnd.BinFile.Tests.ZIPReader

open System.IO
open System.IO.Compression
open B2R2.FrontEnd.BinFile
open type FileFormat

let private baseDir = System.AppDomain.CurrentDomain.BaseDirectory

let private zipFileSrcDir = baseDir + "../../../"

let private getFileDir = function
  | FileFormat.PEBinary -> "PE/"
  | FileFormat.ELFBinary -> "ELF/"
  | FileFormat.MachBinary -> "Mach/"
  | FileFormat.WasmBinary -> "Wasm/"
  | _ -> failwith "Invalid file format"

let readBytes fileFormat zipFileName inZipFileName =
  let zipDirectory = zipFileSrcDir + getFileDir fileFormat
  let archive = ZipFile.Open(zipDirectory + zipFileName, ZipArchiveMode.Read)
  let entry = archive.GetEntry(inZipFileName)
  let stream = entry.Open()
  use ms = new MemoryStream()
  stream.CopyTo(ms)
  ms.ToArray()


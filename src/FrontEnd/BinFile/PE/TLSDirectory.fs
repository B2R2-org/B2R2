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

module internal B2R2.FrontEnd.BinFile.PE.TLSDirectory

open B2R2
open B2R2.FrontEnd.BinFile.FileHelper
open B2R2.FrontEnd.BinFile.PE.Helper
open B2R2.FrontEnd.BinFile.PE.PEUtils

/// How far into the thread-local storage directory its callback array is
/// named, which is after three pointer-sized fields in either of its forms.
let private callbackArrayOffset wordSize =
  WordSize.toByteWidth wordSize * 3

/// The most callbacks a directory is read for. A real one holds a handful;
/// a bound is what keeps a file naming nonsense from being walked forever.
let [<Literal>] private MaxCallbacks = 4096

/// Returns where the thread-local storage directory sits in the file, or
/// none where the file names none or names one landing nowhere.
let private tryFindDirectory pe =
  match pe.Header.OptionalHeader with
  | None ->
    None
  | Some hdr ->
    let dir = hdr.Directory DirectoryKind.ThreadLocalStorageTable
    let rva = dir.RVA
    if dir.Size = 0 || findMappedSectionIndex pe.SectionHeaders rva = -1 then
      None
    else
      Some(getRawOffset pe.SectionHeaders rva)

/// Reads the null-terminated array of addresses the directory points at.
/// They are addresses the image would load at, so it is the preferred base
/// that turns one back into an RVA, not the base the file was opened with.
let private readCallbacks (bytes: byte[]) pe arrayVA =
  let imageBase = getImageBase pe
  let secs = pe.SectionHeaders
  if arrayVA <= imageBase then
    [||]
  else
    let rva = int (arrayVA - imageBase)
    if findMappedSectionIndex secs rva = -1 then
      [||]
    else
      let width = WordSize.toByteWidth pe.WordSize
      let start = getRawOffset secs rva
      let span = System.ReadOnlySpan bytes
      let addrs = ResizeArray()
      let mutable i = 0
      let mutable go = true
      while go && i < MaxCallbacks && start + (i + 1) * width <= bytes.Length do
        let at = start + i * width
        let va = readUIntByWordSize span pe.BinReader pe.WordSize at
        if va <= imageBase then go <- false
        else addrs.Add(va - imageBase + pe.BaseAddr)
        i <- i + 1
      addrs.ToArray()

/// Returns the addresses of the callbacks the thread-local storage directory
/// names. The loader runs each of them as a thread starts and ends, so every
/// one of them starts a function, and a file that has them names them
/// nowhere else.
let getCallbackAddresses (bytes: byte[]) pe =
  match tryFindDirectory pe with
  | None ->
    [||]
  | Some offset ->
    let span = System.ReadOnlySpan bytes
    let at = offset + callbackArrayOffset pe.WordSize
    let arrayVA = readUIntByWordSize span pe.BinReader pe.WordSize at
    readCallbacks bytes pe arrayVA

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

namespace B2R2.FrontEnd.BinFile.Tests

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Python
open Microsoft.VisualStudio.TestTools.UnitTesting
open type FileFormat

[<TestClass>]
type PythonExceptionTableTests() =
  (* Entries byte for byte the way CPython writes them: six value bits per
     byte, 0x40 for "one more byte follows", 0x80 on an entry's first byte.
     Start 2, length 3, target 10, depth 1 and lasti set (2 * 1 + 1 = 3),
     every field fitting a byte of its own. *)
  static let shortEntry = [| 0x82uy; 0x03uy; 0x0Auy; 0x03uy |]

  (* Start 64 and target 100, which need two bytes apiece, with length 1,
     depth 2 and lasti clear. *)
  static let wideEntry = [| 0xC1uy; 0x00uy; 0x01uy; 0x41uy; 0x24uy; 0x04uy |]

  static let tableBytes = Array.append shortEntry wideEntry

  static let codeLength = 16

  static let pycOf version =
    let co = Builder.codeOf (Array.zeroCreate codeLength)
    let co =
      if int version >= 311 then { co with ExceptionTable = tableBytes } else co
    Builder.build version (Builder.magicOf version) co

  static let file = PythonBinFile("", pycOf PythonVersion.Python312, None)

  static let legacy = PythonBinFile("", pycOf PythonVersion.Python310, None)

  static let codeAddr =
    match file.CodeObj with
    | PyCode co -> fst co.Code
    | _ -> 0UL

  static let framesOf (f: PythonBinFile) =
    match (f :> IBinFile).ExceptionTable with
    | Some tbl -> tbl.Frames
    | None -> [||]

  (* A real CPython 3.12 file, so that the decoder is held to what an
     interpreter actually wrote rather than only to what this test writes.
     Its `f` is the one function with guarded ranges; the module around it
     has none. See Python/README.md for the source it was compiled from. *)
  static let realBytes =
    ZIPReader.readBytes PythonBinary
                        "python_exception.zip"
                        "python_exception.pyc"

  static let realFile = PythonBinFile("", realBytes, None)

  static let guarded =
    PyExceptionTable.collect realFile.CodeObj
    |> Array.find (fun (co, _) -> co.Name = "f")

  static let guardedAddr = fst (fst guarded).Code

  (* What CPython's own `dis` reports for `f`, as (start, end, target, depth,
     lasti). Its end is exclusive, so an entry's own End is one less. *)
  static let expected =
    [| 4UL, 14UL, 40UL, 0, false
       40UL, 62UL, 68UL, 1, true
       62UL, 66UL, 74UL, 0, false
       66UL, 68UL, 68UL, 1, true
       68UL, 74UL, 74UL, 0, false
       74UL, 100UL, 100UL, 1, true |]

  [<TestMethod>]
  member _.``[Python] exception table entries are decoded test``() =
    let entries = PyExceptionTable.decode 0x1000UL tableBytes
    Assert.AreEqual<int>(2, entries.Length)
    Assert.AreEqual<Addr>(0x1004UL, entries[0].Start)
    Assert.AreEqual<Addr>(0x1009UL, entries[0].End)
    Assert.AreEqual<Addr>(0x1014UL, entries[0].Target)
    Assert.AreEqual<int>(1, entries[0].Depth)
    Assert.AreEqual<bool>(true, entries[0].PushLasti)

  [<TestMethod>]
  member _.``[Python] multi-byte varints are decoded test``() =
    let entries = PyExceptionTable.decode 0x1000UL tableBytes
    Assert.AreEqual<Addr>(0x1080UL, entries[1].Start)
    Assert.AreEqual<Addr>(0x1081UL, entries[1].End)
    Assert.AreEqual<Addr>(0x10C8UL, entries[1].Target)
    Assert.AreEqual<int>(2, entries[1].Depth)
    Assert.AreEqual<bool>(false, entries[1].PushLasti)

  [<TestMethod>]
  member _.``[Python] a table without entries decodes to nothing test``() =
    Assert.AreEqual<int>(0, (PyExceptionTable.decode 0UL [||]).Length)

  [<TestMethod>]
  member _.``[Python] entries are addressed from the code object test``() =
    let entries = file.ExceptionEntries
    Assert.AreEqual<int>(2, entries.Length)
    Assert.AreEqual<Addr>(codeAddr + 4UL, entries[0].Start)
    Assert.AreEqual<Addr>(codeAddr + 20UL, entries[0].Target)
    Assert.AreEqual<Addr>(codeAddr + 128UL, entries[1].Start)

  [<TestMethod>]
  member _.``[Python] the covering entry is found test``() =
    let entries = file.ExceptionEntries
    let covered = PyExceptionTable.tryFindEntry (codeAddr + 6UL) entries
    let uncovered = PyExceptionTable.tryFindEntry codeAddr entries
    Assert.AreEqual(Some entries[0], covered)
    Assert.AreEqual<bool>(true, uncovered.IsNone)

  [<TestMethod>]
  member _.``[Python] entries become exception frames test``() =
    let frames = framesOf file
    Assert.AreEqual<int>(1, frames.Length)
    Assert.AreEqual<Addr>(codeAddr, frames[0].FunctionStart)
    Assert.AreEqual<Addr>(codeAddr + uint64 codeLength - 1UL,
                          frames[0].FunctionEnd)
    Assert.AreEqual<bool>(true, frames[0].PersonalityRoutine.IsNone)
    Assert.AreEqual<int>(2, frames[0].Handlers.Length)
    Assert.AreEqual<Addr>(codeAddr + 4UL, frames[0].Handlers[0].BlockStart)
    Assert.AreEqual<Addr>(codeAddr + 9UL, frames[0].Handlers[0].BlockEnd)
    Assert.AreEqual(Some(codeAddr + 20UL), frames[0].Handlers[0].Handler)

  [<TestMethod>]
  member _.``[Python] a real table matches what dis reports test``() =
    let entries = snd guarded
    Assert.AreEqual<int>(expected.Length, entries.Length)
    for i in 0 .. expected.Length - 1 do
      let start, endOff, target, depth, lasti = expected[i]
      Assert.AreEqual<Addr>(guardedAddr + start, entries[i].Start)
      Assert.AreEqual<Addr>(guardedAddr + endOff - 1UL, entries[i].End)
      Assert.AreEqual<Addr>(guardedAddr + target, entries[i].Target)
      Assert.AreEqual<int>(depth, entries[i].Depth)
      Assert.AreEqual<bool>(lasti, entries[i].PushLasti)

  [<TestMethod>]
  member _.``[Python] a nested code object is reached test``() =
    (* The module holding `f` guards nothing itself, so a decoder that only
       looked at the outermost code object would report an empty file. *)
    Assert.AreEqual<int>(2, (framesOf realFile).Length)
    Assert.AreEqual<int>(expected.Length, realFile.ExceptionEntries.Length)

  [<TestMethod>]
  member _.``[Python] legacy files have no entries test``() =
    Assert.AreEqual<int>(0, legacy.ExceptionEntries.Length)

  [<TestMethod>]
  member _.``[Python] a legacy code object still gets a frame test``() =
    let frames = framesOf legacy
    Assert.AreEqual<int>(1, frames.Length)
    Assert.AreEqual<int>(0, frames[0].Handlers.Length)

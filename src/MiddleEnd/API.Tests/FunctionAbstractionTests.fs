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

namespace B2R2.MiddleEnd.Tests

open System.IO
open System.IO.Compression
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowGraph

/// Tests the function abstractions that summarize calls to external functions.
/// The x86-64 float return register is XMM0, which no single variable holds, so
/// these make sure that such a register is defined chunk by chunk.
[<TestClass>]
type FunctionAbstractionTests() =
  (* We reuse the ELF fixtures that live next to the BinFile tests. *)
  let elfDir =
    System.AppDomain.CurrentDomain.BaseDirectory
    + "../../../../../FrontEnd/BinFile.Tests/ELF/"

  let readZippedBinary name =
    let path = elfDir + name + ".zip"
    let archive = ZipFile.Open(path, ZipArchiveMode.Read)
    let stream = archive.GetEntry(name).Open()
    use ms = new MemoryStream()
    stream.CopyTo ms
    ms.ToArray()

  let definedVars (blk: ILowUIRBasicBlock) =
    if blk.IsAbstract then
      [| for stmt in blk.AbstractContent.Rundown do
           match stmt with
           | Put(dst, _, _) -> dst
           | _ -> () |]
    else
      [||]

  let abstractionDefs =
    let bytes = readZippedBinary "elf_x64_exec"
    let hdl = BinHandle.LoadFileBytes(bytes, ISA "x64")
    [| for fn in BinaryBrew(hdl).Functions.Sequence do
         for v in fn.CFG.Vertices do
           yield! definedVars v.VData.Internals |]

  [<TestMethod>]
  member _.``External calls define registers through plain variables``() =
    Assert.AreNotEqual<int>(0, abstractionDefs.Length)
    for dst in abstractionDefs do
      match dst with
      | Var _ | TempVar _ | PCVar _ -> ()
      | _ -> Assert.Fail(PrettyPrinter.ToString dst)

  [<TestMethod>]
  member _.``Float return register is defined chunk by chunk``() =
    let names =
      abstractionDefs
      |> Array.choose (fun dst ->
        match dst with
        | Var(_, _, name, _) -> Some name
        | _ -> None)
    CollectionAssert.Contains(names, "ZMM0A")
    CollectionAssert.Contains(names, "ZMM0B")

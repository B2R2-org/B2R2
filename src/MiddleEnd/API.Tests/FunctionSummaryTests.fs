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

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowGraph

/// Tests the function summaries that stand for calls. The x86-64 float return
/// register is XMM0, which no single variable holds, so these make sure that
/// such a register is defined chunk by chunk.
[<TestClass>]
type FunctionSummaryTests() =
  let definedVars (blk: ILowUIRBasicBlock) =
    if blk.IsAbstract then
      [| for stmt in blk.AbstractContent.Rundown do
           match stmt with
           | Put(Dst = dst) -> dst
           | _ -> () |]
    else
      [||]

  let summaryDefsOf hdl =
    [| for fn in BinaryBrew(hdl: BinHandle).Functions.Sequence do
         for v in fn.CFG.Vertices do
           yield! definedVars v.VData.Internals |]

  let namesOf defs =
    defs
    |> Array.choose (fun dst ->
      match dst with
      | Var(Name = name) -> Some name
      | _ -> None)

  let summaryDefs =
    let bytes = readZippedBinary "elf_x64_exec"
    BinHandle.LoadFileBytes(bytes, ISA "x64") |> summaryDefsOf

  [<TestMethod>]
  member _.``External calls define registers through plain variables``() =
    Assert.AreNotEqual<int>(0, summaryDefs.Length)
    for dst in summaryDefs do
      match dst with
      | Var _ | TempVar _ | PCVar _ -> ()
      | _ -> Assert.Fail(PrettyPrinter.ToString dst)

  [<TestMethod>]
  member _.``Float return register is defined chunk by chunk``() =
    let names = namesOf summaryDefs
    CollectionAssert.Contains(names, "ZMM0A")
    CollectionAssert.Contains(names, "ZMM0B")

  [<TestMethod>]
  member _.``A call on ARM leaves the stack pointer where it was``() =
    (* BL leaves the return address in LR rather than on the stack, so the
       callee returns with the stack it was called with. *)
    let code =
      [ "10402de9" (* push {r4, lr} *)
        "010000eb" (* bl 0x10 *)
        "1080bde8" (* pop {r4, pc} *)
        "00f020e3" (* nop *)
        "1eff2fe1" (* bx lr *) ]
      |> String.concat ""
      |> ByteArray.ofHexString
    let hdl = BinHandle.LoadRawImage(code, ISA "armv7")
    let names = summaryDefsOf hdl |> namesOf
    CollectionAssert.Contains(names, "R0")
    CollectionAssert.DoesNotContain(names, "SP")

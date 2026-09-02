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

namespace B2R2.MiddleEnd.ConcEval.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.ConcEval

[<TestClass>]
type ConcExecutorTests() =
  (* syscall; nop; nop *)
  let bytes = [| 0x0fuy; 0x05uy; 0x90uy; 0x90uy |]

  let newExecutor () =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    BinHandle.LoadRawImage(bytes, isa, OS.Linux) |> ConcExecutor

  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``Run makes progress past a side-effect instruction``() =
    let exec = newExecutor ()
    let st = exec.CreateState()
    let res = exec.Run(0UL, st, ConcRunOptions.Default(StopAfterAddress 0x3UL))
    Assert.AreEqual<Addr>(0x4UL, res.FinalAddress)
    Assert.AreEqual<int>(3, res.InstructionCount)

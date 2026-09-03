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

namespace B2R2.MiddleEnd.Executor.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.Executor

[<TestClass>]
type CallContextTests() =
  let newHandle arch (ws: WordSize) =
    BinHandle.LoadRawImage([| 0x90uy |], ISA(arch, ws), OS.Linux)

  let newContext arch ws =
    CallContext.Create(newHandle arch ws, 0x1000UL, 0x2000UL, 0x1005UL)

  [<TestMethod>]
  member _.``The context carries the call site it stands in for``() =
    let ctx = newContext Architecture.Intel WordSize.Bit64
    Assert.AreEqual<Addr>(0x1000UL, ctx.CallSite)
    Assert.AreEqual<Addr>(0x2000UL, ctx.Target)
    Assert.AreEqual<Addr>(0x1005UL, ctx.ReturnAddress)
    Assert.AreEqual<RegType>(64<rt>, ctx.WordType)
    Assert.AreEqual<Endian>(Endian.Little, ctx.Endian)

  [<TestMethod>]
  member _.``A register-passing ABI contributes its argument registers``() =
    let ctx = newContext Architecture.Intel WordSize.Bit64
    Assert.AreEqual<int>(6, Array.length ctx.ArgumentRegisters)

  [<TestMethod>]
  member _.``A stack-passing ABI contributes no argument register``() =
    let ctx = newContext Architecture.Intel WordSize.Bit32
    Assert.AreEqual<int>(0, Array.length ctx.ArgumentRegisters)

  [<TestMethod>]
  member _.``An ABI with fewer than six of them contributes them all``() =
    let ctx = newContext Architecture.SH4 WordSize.Bit32
    Assert.AreEqual<int>(4, Array.length ctx.ArgumentRegisters)

  [<TestMethod>]
  member _.``An ABI with more than six of them contributes them all``() =
    let ctx = newContext Architecture.RISCV WordSize.Bit64
    Assert.AreEqual<int>(8, Array.length ctx.ArgumentRegisters)

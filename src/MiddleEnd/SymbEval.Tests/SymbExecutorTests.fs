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

namespace B2R2.MiddleEnd.SymbEval.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.Executor
open B2R2.MiddleEnd.SymbEval

[<TestClass>]
type SymbExecutorTests() =
  (* call rel32 1 (target 0x6) ; nop ; ret *)
  let hookedCall = [| 0xe8uy; 0x01uy; 0x00uy; 0x00uy; 0x00uy; 0x90uy; 0xc3uy |]

  let loadRawImage (bytes: byte[]) arch (ws: WordSize) =
    BinHandle.LoadRawImage(bytes, ISA(arch, ws), OS.Linux)

  let runHookedCall hdl hook =
    let exec = SymbExecutor hdl
    let st = exec.CreateState()
    SymbStateAccessor(hdl, st).InitializeDefaultStack()
    let opts =
      SymbRunOptions.Default(ReachAddress 0x5UL).RegisterCallHook(0x6UL, hook)
    exec.Run(0UL, st, opts)

  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A hook sees no argument register under a stack-passing ABI``() =
    let hdl = loadRawImage hookedCall Architecture.Intel WordSize.Bit32
    let seen = ResizeArray()
    let hook (ctx: CallContext) (st: SymbState) =
      seen.Add ctx.ArgumentRegisters
      Ok [ st ]
    match runHookedCall hdl hook with
    | Reachable _ ->
      Assert.AreEqual<int>(1, seen.Count)
      Assert.AreEqual<int>(0, Array.length seen[0])
    | result ->
      Assert.Fail $"The hooked call did not reach the return address: {result}."

  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``A hook sees the argument registers of a register ABI``() =
    let hdl = loadRawImage hookedCall Architecture.Intel WordSize.Bit64
    let seen = ResizeArray()
    let hook (ctx: CallContext) (st: SymbState) =
      seen.Add ctx.ArgumentRegisters
      Ok [ st ]
    match runHookedCall hdl hook with
    | Reachable _ ->
      Assert.AreEqual<int>(1, seen.Count)
      Assert.AreEqual<int>(6, Array.length seen[0])
    | result ->
      Assert.Fail $"The hooked call did not reach the return address: {result}."

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
type SymbStateAccessorTests() =
  let addr = 0x1000UL

  let newAccessor arch (ws: WordSize) =
    let hdl = BinHandle.LoadRawImage([| 0x90uy |], ISA(arch, ws), OS.Linux)
    SymbStateAccessor(hdl, SymbState())

  let newInterface arch ws =
    newAccessor arch ws :> IStateAccessor<SymbState, SymbExpr, SymbEvalError>

  [<TestMethod>]
  member _.``The default stack top is what a 64-bit stack starts at``() =
    let accessor = newAccessor Architecture.Intel WordSize.Bit64
    accessor.InitializeDefaultStack()
    Assert.AreEqual<Addr>(accessor.DefaultStackTop, accessor.StackPointer)

  [<TestMethod>]
  member _.``The default stack top is what a 32-bit stack starts at``() =
    let accessor = newAccessor Architecture.Intel WordSize.Bit32
    accessor.InitializeDefaultStack()
    Assert.AreEqual<Addr>(accessor.DefaultStackTop, accessor.StackPointer)

  [<TestMethod>]
  member _.``The interface alone can read back a written value``() =
    let iface = newInterface Architecture.Intel WordSize.Bit64
    let value = iface.WordValue 0x1234UL
    iface.WriteValue(addr, value)
    Assert.AreEqual<SymbExpr>(value, iface.ReadValue(addr, iface.WordType))

  [<TestMethod>]
  member _.``The interface alone can round-trip the stack``() =
    let iface = newInterface Architecture.Intel WordSize.Bit64
    iface.InitializeDefaultStack()
    Assert.AreEqual<Addr>(iface.DefaultStackTop, iface.StackPointer)
    let value = iface.WordValue 0x1234UL
    match iface.TryPushToStack value with
    | Ok _ ->
      let expected = Ok value
      Assert.AreEqual<Result<SymbExpr, SymbEvalError>>(expected,
                                                       iface.TryPopFromStack())
    | Error e ->
      Assert.Fail $"Failed to push to the stack: {e}"

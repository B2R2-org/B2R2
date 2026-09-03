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

open System
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.Executor
open B2R2.MiddleEnd.ConcEval

[<TestClass>]
type ConcStateAccessorTests() =
  let strAddr = 0x1000UL

  let newAccessor arch (ws: WordSize) =
    let hdl = BinHandle.LoadRawImage([| 0x90uy |], ISA(arch, ws), OS.Linux)
    ConcStateAccessor(hdl, EvalState())

  let newInterface arch ws =
    newAccessor arch ws :> IStateAccessor<EvalState, BitVector, ErrorCase>

  let accessorWith arch ws bytes =
    let accessor = newAccessor arch ws
    accessor.WriteBytes(strAddr, bytes)
    accessor

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
  member _.``A 32-bit default stack top fits in a 32-bit word``() =
    let accessor = newAccessor Architecture.Intel WordSize.Bit32
    Assert.AreEqual<bool>(true, accessor.DefaultStackTop <= 0xffffffffUL)

  [<TestMethod>]
  member _.``A terminated string reads back as itself``() =
    let bytes = [| 0x41uy; 0x42uy; 0x00uy |]
    let accessor = accessorWith Architecture.Intel WordSize.Bit64 bytes
    Assert.AreEqual<string>("AB", accessor.ReadCString(strAddr, 8))

  [<TestMethod>]
  member _.``An unterminated string is a failure, not a truncation``() =
    let bytes = [| 0x41uy; 0x42uy; 0x43uy |]
    let accessor = accessorWith Architecture.Intel WordSize.Bit64 bytes
    Assert.ThrowsExactly<InvalidOperationException>(fun () ->
      accessor.ReadCString(strAddr, 3) |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``TryReadCString reports an unterminated string``() =
    let bytes = [| 0x41uy; 0x42uy; 0x43uy |]
    let accessor = accessorWith Architecture.Intel WordSize.Bit64 bytes
    let expected = Error ErrorCase.InvalidFormat
    let actual = accessor.TryReadCString(strAddr, 3)
    Assert.AreEqual<Result<string, ErrorCase>>(expected, actual)

  [<TestMethod>]
  member _.``TryReadCString reads a terminated string``() =
    let bytes = [| 0x41uy; 0x42uy; 0x00uy |]
    let accessor = accessorWith Architecture.Intel WordSize.Bit64 bytes
    let actual = accessor.TryReadCString(strAddr, 8)
    Assert.AreEqual<Result<string, ErrorCase>>(Ok "AB", actual)

  [<TestMethod>]
  member _.``The interface alone can read back a written value``() =
    let iface = newInterface Architecture.Intel WordSize.Bit64
    let value = iface.WordValue 0x1234UL
    iface.WriteValue(strAddr, value)
    Assert.AreEqual<BitVector>(value, iface.ReadValue(strAddr, iface.WordType))

  [<TestMethod>]
  member _.``The interface alone can move the stack pointer``() =
    let iface = newInterface Architecture.Intel WordSize.Bit64
    match iface.TrySetStackPointer 0x2000UL with
    | Ok() ->
      let expected = Ok 0x2000UL
      Assert.AreEqual<Result<Addr, ErrorCase>>(expected,
                                               iface.TryGetStackPointer())
    | Error e ->
      Assert.Fail $"Failed to set the stack pointer: {e}"

  [<TestMethod>]
  member _.``The interface alone can round-trip the stack``() =
    let iface = newInterface Architecture.Intel WordSize.Bit64
    iface.InitializeDefaultStack()
    Assert.AreEqual<Addr>(iface.DefaultStackTop, iface.StackPointer)
    let value = iface.WordValue 0x1234UL
    match iface.TryPushToStack value with
    | Ok _ ->
      let expected = Ok value
      Assert.AreEqual<Result<BitVector, ErrorCase>>(expected,
                                                    iface.TryPopFromStack())
    | Error e ->
      Assert.Fail $"Failed to push to the stack: {e}"

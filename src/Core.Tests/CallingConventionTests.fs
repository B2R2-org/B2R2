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

namespace B2R2.Core.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2

[<TestClass>]
type CallingConventionTests() =

  let r n = RegisterID.create n

  let sampleCC =
    { Args =
        [| ArgLocation.Reg(r 1)
           ArgLocation.Reg(r 2)
           ArgLocation.Stack { FirstOffset = 8; SlotSize = 8 } |]
      ReturnLocation = ArgLocation.Reg(r 0)
      CalleeSavedRegisters = set [ r 10; r 11 ]
      CallerSavedRegisters = set [ r 1; r 2 ] }

  [<TestMethod>]
  member _.``GetArgLocation returns register arguments``() =
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Reg(r 1), sampleCC.GetArgLocation(0))
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Reg(r 2), sampleCC.GetArgLocation(1))

  [<TestMethod>]
  member _.``GetArgLocation resolves stack spill offsets``() =
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Stack { FirstOffset = 8; SlotSize = 8 },
      sampleCC.GetArgLocation(2))
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Stack { FirstOffset = 16; SlotSize = 8 },
      sampleCC.GetArgLocation(3))
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Stack { FirstOffset = 24; SlotSize = 8 },
      sampleCC.GetArgLocation(4))

  [<TestMethod>]
  member _.``GetArgLocation handles all-stack ABI``() =
    let cc =
      { sampleCC with
          Args = [| ArgLocation.Stack { FirstOffset = 4; SlotSize = 4 } |] }
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Stack { FirstOffset = 4; SlotSize = 4 }, cc.GetArgLocation(0))
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Stack { FirstOffset = 8; SlotSize = 4 }, cc.GetArgLocation(1))

  [<TestMethod>]
  member _.``ReturnRegister extracts the return register``() =
    Assert.AreEqual<RegisterID>(r 0, sampleCC.ReturnRegister)

  [<TestMethod>]
  member _.``ArgRegister extracts register arguments``() =
    Assert.AreEqual<RegisterID>(r 1, sampleCC.ArgRegister(0))
    Assert.AreEqual<RegisterID>(r 2, sampleCC.ArgRegister(1))

  [<TestMethod>]
  member _.``IsCalleeSaved and IsCallerSaved membership``() =
    Assert.AreEqual<bool>(true, sampleCC.IsCalleeSaved(r 10))
    Assert.AreEqual<bool>(false, sampleCC.IsCalleeSaved(r 1))
    Assert.AreEqual<bool>(true, sampleCC.IsCallerSaved(r 1))
    Assert.AreEqual<bool>(false, sampleCC.IsCallerSaved(r 10))

  [<TestMethod>]
  member _.``GetArgLocation rejects negative index``() =
    Assert.ThrowsExactly<System.ArgumentException>(fun () ->
      sampleCC.GetArgLocation(-1) |> ignore) |> ignore

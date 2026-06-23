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
type SyscallConventionTests() =

  let r n = RegisterID.create n

  let sample =
    { NumberRegister = r 0
      ReturnRegister = r 0
      Args =
        [| ArgLocation.Reg(r 1)
           ArgLocation.Reg(r 2)
           ArgLocation.Stack { FirstOffset = 8; SlotSize = 8 } |] }

  [<TestMethod>]
  member _.``ArgRegister extracts register arguments``() =
    Assert.AreEqual<RegisterID>(r 1, sample.ArgRegister(0))
    Assert.AreEqual<RegisterID>(r 2, sample.ArgRegister(1))

  [<TestMethod>]
  member _.``GetArgLocation resolves spilled stack arguments``() =
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Stack { FirstOffset = 8; SlotSize = 8 },
      sample.GetArgLocation(2))
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Stack { FirstOffset = 16; SlotSize = 8 },
      sample.GetArgLocation(3))

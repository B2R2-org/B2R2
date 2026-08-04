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

namespace B2R2.ABI.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.ABI
open B2R2.FrontEnd

[<TestClass>]
type SyscallConventionTests() =

  let r n = RegisterID.create n

  let sample =
    { NumberRegister = r 0
      ReturnRegister = r 0
      Error = SyscallError.NegatedErrno
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

  (* Linux on m68k enters the kernel with a TRAP #0, taking the call number in
     D0 and the arguments in D1 through D5 and then A0, which is the one place
     the sequence leaves the data registers. *)
  [<TestMethod>]
  member _.``m68k takes its last syscall argument in an address register``() =
    let conv = SyscallConvention.create OS.Linux (ISA Architecture.M68K)
    let d0 = M68K.Register.toRegID M68K.Register.D0
    Assert.AreEqual<RegisterID>(d0, conv.NumberRegister)
    Assert.AreEqual<RegisterID>(d0, conv.ReturnRegister)
    let d1 = M68K.Register.toRegID M68K.Register.D1
    Assert.AreEqual<ArgLocation>(ArgLocation.Reg d1, conv.GetArgLocation 0)
    let a0 = M68K.Register.toRegID M68K.Register.A0
    Assert.AreEqual<ArgLocation>(ArgLocation.Reg a0, conv.GetArgLocation 5)

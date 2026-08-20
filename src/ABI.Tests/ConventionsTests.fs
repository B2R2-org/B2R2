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

[<TestClass>]
type ConventionsTests() =

  [<TestMethod>]
  member _.``create bundles the per-OS/ISA conventions``() =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let conv = Conventions.create OS.Linux isa
    Assert.AreEqual<RegisterID>(
      (CallingConvention.create OS.Linux isa).IntReturnRegister,
      conv.Calling.IntReturnRegister
    )
    Assert.AreEqual<int>(
      (StackConvention.create OS.Linux isa).RedZoneSize,
      conv.Stack.RedZoneSize
    )
    Assert.AreEqual<RegisterID>(
      (SyscallConvention.create OS.Linux isa).NumberRegister,
      conv.Syscall.NumberRegister
    )

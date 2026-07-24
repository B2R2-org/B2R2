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
type MacosSyscallTests() =

  let x64 = ISA(Architecture.Intel, WordSize.Bit64)

  let arm64 = ISA(Architecture.ARMv8, WordSize.Bit64)

  [<TestMethod>]
  member _.``BSD numbers match the XNU table``() =
    Assert.AreEqual<int>(1, MacosSyscall.toNumber arm64 MacosSyscall.Exit)
    Assert.AreEqual<int>(3, MacosSyscall.toNumber arm64 MacosSyscall.Read)
    Assert.AreEqual<int>(4, MacosSyscall.toNumber arm64 MacosSyscall.Write)
    Assert.AreEqual<int>(6, MacosSyscall.toNumber arm64 MacosSyscall.Close)

  [<TestMethod>]
  member _.``x86_64 encodes the BSD syscall class in the high bits``() =
    let n = MacosSyscall.toNumber x64 MacosSyscall.Write
    Assert.AreEqual<int>(0x2000004, n)

  [<TestMethod>]
  member _.``ofNumber inverts toNumber on both ISAs``() =
    let x64Num = MacosSyscall.toNumber x64 MacosSyscall.Write
    let armNum = MacosSyscall.toNumber arm64 MacosSyscall.Write
    Assert.AreEqual<MacosSyscall>(
      MacosSyscall.Write, MacosSyscall.ofNumber x64 x64Num)
    Assert.AreEqual<MacosSyscall>(
      MacosSyscall.Write, MacosSyscall.ofNumber arm64 armNum)

  [<TestMethod>]
  member _.``toString and ofString round-trip``() =
    Assert.AreEqual<string>("close", MacosSyscall.toString MacosSyscall.Close)
    Assert.AreEqual<MacosSyscall>(
      MacosSyscall.Close, MacosSyscall.ofString "close")

  [<TestMethod>]
  member _.``Unsupported ISA raises UnhandledSyscallException``() =
    let x86 = ISA(Architecture.Intel, WordSize.Bit32)
    Assert.ThrowsExactly<UnhandledSyscallException>(fun () ->
      MacosSyscall.toNumber x86 MacosSyscall.Exit |> ignore)
    |> ignore

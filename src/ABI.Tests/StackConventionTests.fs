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
type StackConventionTests() =

  let x64 = ISA(Architecture.Intel, WordSize.Bit64)

  [<TestMethod>]
  member _.``x64 System V has a 128-byte red zone and 16-byte align``() =
    let sc = StackConvention.create OS.Linux x64
    Assert.AreEqual<int>(16, sc.Alignment)
    Assert.AreEqual<int>(128, sc.RedZoneSize)
    Assert.AreEqual<int>(0, sc.ShadowSpaceSize)

  [<TestMethod>]
  member _.``Windows x64 has 32-byte shadow space and no red zone``() =
    let sc = StackConvention.create OS.Windows x64
    Assert.AreEqual<int>(16, sc.Alignment)
    Assert.AreEqual<int>(0, sc.RedZoneSize)
    Assert.AreEqual<int>(32, sc.ShadowSpaceSize)

  [<TestMethod>]
  member _.``macOS x64 shares the System V red zone``() =
    let sc = StackConvention.create OS.MacOSX x64
    Assert.AreEqual<int>(128, sc.RedZoneSize)
    Assert.AreEqual<int>(0, sc.ShadowSpaceSize)

  [<TestMethod>]
  member _.``AArch64 has no red zone or shadow space``() =
    let sc = StackConvention.create OS.Linux (ISA Architecture.ARMv8)
    Assert.AreEqual<int>(16, sc.Alignment)
    Assert.AreEqual<int>(0, sc.RedZoneSize)
    Assert.AreEqual<int>(0, sc.ShadowSpaceSize)

  [<TestMethod>]
  member _.``Windows x86 uses 4-byte stack alignment``() =
    let x86 = ISA(Architecture.Intel, WordSize.Bit32)
    let sc = StackConvention.create OS.Windows x86
    Assert.AreEqual<int>(4, sc.Alignment)

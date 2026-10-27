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

namespace B2R2.MiddleEnd.Tests

open System
open System.Runtime.CompilerServices
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd

[<TestClass>]
type BinaryBrewTests() =
  /// Brews a one-instruction binary and drops the brew, handing back only a
  /// weak reference to the binary. Inlining it would let a local of the caller
  /// keep the binary alive.
  [<MethodImpl(MethodImplOptions.NoInlining)>]
  static member private BrewAndDrop() =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let hdl = BinHandle.LoadRawImage([| 0xc3uy |], isa)
    BinaryBrew hdl |> ignore
    WeakReference hdl

  [<TestMethod>]
  member _.``BinaryBrew lets go of its binary once it is dropped``() =
    let binary = BinaryBrewTests.BrewAndDrop()
    GC.Collect()
    GC.WaitForPendingFinalizers()
    GC.Collect()
    Assert.AreEqual<bool>(false, binary.IsAlive)

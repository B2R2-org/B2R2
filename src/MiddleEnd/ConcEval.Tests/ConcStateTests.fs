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

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.MiddleEnd.ConcEval

[<TestClass>]
type ConcStateTests() =
  let value n = BitVector(uint64 n, 32<rt>)

  [<TestMethod>]
  member _.``Aborting an instruction can advance the PC``() =
    let st = ConcState()
    st.CurrentInsLen <- 4u
    st.AbortInstr true
    Assert.AreEqual<Addr>(4UL, st.PC)
    Assert.AreEqual<bool>(true, st.IsInstrTerminated)

  [<TestMethod>]
  member _.``Aborting an instruction leaves the PC alone by default``() =
    let st = ConcState()
    st.CurrentInsLen <- 4u
    st.AbortInstr()
    Assert.AreEqual<Addr>(0UL, st.PC)
    Assert.AreEqual<bool>(true, st.IsInstrTerminated)

  [<TestMethod>]
  member _.``An undefined register reads as Undef``() =
    let st = ConcState()
    Assert.AreEqual<ConcEvalValue>(Undef, st.TryGetReg(RegisterID.create 3))

  [<TestMethod>]
  member _.``A defined register reads back as Def``() =
    let st = ConcState()
    let rid = RegisterID.create 3
    st.SetReg(rid, value 1)
    Assert.AreEqual<ConcEvalValue>(Def(value 1), st.TryGetReg rid)

  [<TestMethod>]
  member _.``An undefined temporary reads as Undef``() =
    let st = ConcState()
    Assert.AreEqual<ConcEvalValue>(Undef, st.TryGetTmp 0)

  [<TestMethod>]
  member _.``A defined temporary reads back as Def``() =
    let st = ConcState()
    st.SetTmp(0, value 1)
    Assert.AreEqual<ConcEvalValue>(Def(value 1), st.TryGetTmp 0)

  [<TestMethod>]
  member _.``Registers come out of ToArray keyed by RegisterID``() =
    let st = ConcState()
    let rid = RegisterID.create 3
    st.SetReg(rid, value 7)
    let arr: (RegisterID * BitVector)[] = st.Registers.ToArray()
    Assert.AreEqual<int>(1, arr.Length)
    Assert.AreEqual<RegisterID * BitVector>((rid, value 7), arr[0])

  [<TestMethod>]
  member _.``Temporaries come out of ToArray keyed by their number``() =
    let st = ConcState()
    st.SetTmp(3, value 7)
    let arr: (int * BitVector)[] = st.Temporaries.ToArray()
    Assert.AreEqual<int>(1, arr.Length)
    Assert.AreEqual<int * BitVector>((3, value 7), arr[0])

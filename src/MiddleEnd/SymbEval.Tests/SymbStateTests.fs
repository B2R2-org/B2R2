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
open B2R2.MiddleEnd.SymbEval

[<TestClass>]
type SymbStateTests() =
  [<TestMethod>]
  member _.``Aborting an instruction can advance the PC``() =
    let st = SymbState()
    st.CurrentInsLen <- 4u
    st.AbortInstr true
    Assert.AreEqual<Addr>(4UL, st.PC)
    Assert.AreEqual<bool>(true, st.IsInstrTerminated)

  [<TestMethod>]
  member _.``Aborting an instruction leaves the PC alone by default``() =
    let st = SymbState()
    st.CurrentInsLen <- 4u
    st.AbortInstr()
    Assert.AreEqual<Addr>(0UL, st.PC)
    Assert.AreEqual<bool>(true, st.IsInstrTerminated)

  [<TestMethod>]
  member _.``An undefined register reads as ValueNone``() =
    let st = SymbState()
    let v = st.TryGetReg(RegisterID.create 3)
    Assert.AreEqual<SymbExpr voption>(ValueNone, v)

  [<TestMethod>]
  member _.``A defined register reads back as itself``() =
    let st = SymbState()
    let rid = RegisterID.create 3
    let v = SymbExpr.Const(BitVector(1UL, 32<rt>))
    st.SetReg(rid, v)
    Assert.AreEqual<SymbExpr voption>(ValueSome v, st.TryGetReg rid)

  [<TestMethod>]
  member _.``Registers come out of ToArray keyed by RegisterID``() =
    let st = SymbState()
    let rid = RegisterID.create 3
    let v = SymbExpr.Const(BitVector(7UL, 32<rt>))
    st.SetReg(rid, v)
    let arr: (RegisterID * SymbExpr)[] = st.Registers.ToArray()
    Assert.AreEqual<int>(1, arr.Length)
    Assert.AreEqual<RegisterID * SymbExpr>((rid, v), arr[0])

  [<TestMethod>]
  member _.``Temporaries come out of ToArray keyed by their number``() =
    let st = SymbState()
    let v = SymbExpr.Const(BitVector(7UL, 32<rt>))
    st.SetTmp(3, v)
    let arr: (int * SymbExpr)[] = st.Temporaries.ToArray()
    Assert.AreEqual<int>(1, arr.Length)
    Assert.AreEqual<int * SymbExpr>((3, v), arr[0])

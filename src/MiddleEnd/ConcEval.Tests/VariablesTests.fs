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
type VariablesTests() =
  let value n = BitVector(uint64 n, 32<rt>)

  [<TestMethod>]
  member _.``An undefined variable reads as Undef``() =
    let vars = Variables<int>()
    Assert.AreEqual<ConcEvalValue>(Undef, vars.TryGet 0)

  [<TestMethod>]
  member _.``A defined variable reads back as itself``() =
    let vars = Variables<int>()
    vars.Set(0, value 1)
    Assert.AreEqual<ConcEvalValue>(Def(value 1), vars.TryGet 0)

  [<TestMethod>]
  member _.``Unsetting a variable makes it undefined again``() =
    let vars = Variables<int>()
    vars.Set(0, value 1)
    vars.Unset 0
    Assert.AreEqual<ConcEvalValue>(Undef, vars.TryGet 0)
    Assert.AreEqual<int>(0, vars.Count)

  [<TestMethod>]
  member _.``A clone does not share its updates with the origin``() =
    let vars = Variables<int>()
    vars.Set(0, value 1)
    let clone = vars.Clone()
    clone.Set(0, value 2)
    clone.Set(1, value 3)
    Assert.AreEqual<ConcEvalValue>(Def(value 1), vars.TryGet 0)
    Assert.AreEqual<int>(1, vars.Count)

  [<TestMethod>]
  member _.``Registers come out of ToArray keyed by RegisterID``() =
    let st = EvalState()
    let rid = RegisterID.create 3
    st.SetReg(rid, value 7)
    let arr: (RegisterID * BitVector)[] = st.Registers.ToArray()
    Assert.AreEqual<int>(1, arr.Length)
    Assert.AreEqual<RegisterID * BitVector>((rid, value 7), arr[0])

  [<TestMethod>]
  member _.``Temporaries come out of ToArray keyed by their number``() =
    let st = EvalState()
    st.SetTmp(3, value 7)
    let arr: (int * BitVector)[] = st.Temporaries.ToArray()
    Assert.AreEqual<int>(1, arr.Length)
    Assert.AreEqual<int * BitVector>((3, value 7), arr[0])

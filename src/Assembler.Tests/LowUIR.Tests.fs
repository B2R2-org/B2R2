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

namespace B2R2.Assembler.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd

[<TestClass>]
type LowUIRTests () =
  let regfactory = Intel.RegFactory WordSize.Bit64 :> RegisterFactory
  let p = LowUIRParser (ISA.DefaultISA, regfactory)
  let size1Num = BitVector.T
  let size64Num = BitVector.cast size1Num 64<rt>

  [<TestMethod>]
  member __.``[IntelAssemblerLowUIR] Test Register Assignment ``() =
    let result = p.Run "RAX := 0x1:I64" |> Option.get
    let regID = Intel.Register.toRegID (Intel.Register.RAX)
    let answer =
      Put (Var(64<rt>, regID, "RAX", EmptyRegisterSet ()),Num size64Num)
    Assert.AreEqual (answer, result)

  [<TestMethod>]
  member __.``[IntelAssemblerLowUIR] Test IEMark ``() =
    let result = p.Run "=== IEMark (pc := 1)" |> Option.get
    let answer = IEMark 1UL
    Assert.AreEqual (answer, result)

  [<TestMethod>]
  member __.``[IntelAssemblerLowUIR] Test Temporary Registers``() =
    let result = p.Run "T_2:I1 := 1" |> Option.get
    let answer = Put (TempVar(1<rt>,2), Num size1Num)
    Assert.AreEqual (answer, result)

  [<TestMethod>]
  member __.``[IntelAssemblerLowUIR] Test Operation in Expression``() =
    let result = p.Run "RAX := (0x1:I64 - 0x1:I64)" |> Option.get
    let regID = Intel.Register.toRegID (Intel.Register.RAX)
    let answer =
      Put (Var (64<rt>, regID, "RAX", RegisterSet.empty),
           Num (BitVector.cast BitVector.F 64<rt>))
    Assert.AreEqual (answer, result)


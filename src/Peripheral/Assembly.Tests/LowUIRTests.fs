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

namespace B2R2.Peripheral.Assembly.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.BinIR.LowUIR
open B2R2.Peripheral.Assembly.LowUIR

[<TestClass>]
type LowUIRTests() =
  let regFactory = Intel.RegisterFactory WordSize.Bit64
  let p = LowUIRParser(ISA Architecture.Intel, regFactory)
  let size1Num = BitVector.T
  let size64Num = BitVector.Cast(size1Num, 64<rt>)
  let get = function Ok v -> v | Error _ -> failwith "Bad value"

  [<TestMethod>]
  member _.``[IntelAssemblerLowUIR] Test Register Assignment ``() =
    let result = p.Parse "RAX := 0x1:I64" |> get |> Array.head
    let regID = Intel.Register.toRegID Intel.Register.RAX
    let answer = AST.put (AST.var 64<rt> regID "RAX") (AST.num size64Num)
    Assert.AreEqual<Stmt>(answer, result)

  [<TestMethod>]
  member _.``[IntelAssemblerLowUIR] Test IEMark ``() =
    let result = p.Parse "} // 1" |> get |> Array.head
    let answer = AST.iemark 1u
    Assert.AreEqual<Stmt>(answer, result)

  [<TestMethod>]
  member _.``[IntelAssemblerLowUIR] Test Temporary Registers``() =
    let result = p.Parse "T_2:I1 := 1" |> get |> Array.head
    let answer = AST.put (AST.tmpvar 1<rt> 2) (AST.num size1Num)
    Assert.AreEqual<Stmt>(answer, result)

  [<TestMethod>]
  member _.``[IntelAssemblerLowUIR] Test Operation in Expression``() =
    let result =
      p.Parse "RAX := (0x1:I64 - 0x1:I64)" |> get |> Array.head
    let regID = Intel.Register.toRegID Intel.Register.RAX
    let answer =
      AST.put (AST.var 64<rt> regID "RAX")
              (AST.num (BitVector.Cast(BitVector.F, 64<rt>)))
    Assert.AreEqual<Stmt>(answer, result)

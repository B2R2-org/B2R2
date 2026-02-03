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

namespace B2R2.BinIR.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.LowUIR

[<TestClass>]
type ParserTests() =
  let regNameAccessor =
    { new IRegisterNameAccessor with
        member _.GetRegisterName _ = "R"
        member _.GetAllRegisterNames() = [| "R" |] }
  let regID = RegisterID.create 0
  let regVarAccessor =
    { new IRegisterVarAccessor with
        member _.GetRegVar(_: RegisterID) = AST.var 64<rt> regID "R"
        member _.GetRegVar(_: string) = AST.var 64<rt> regID "R"
        member _.GetPseudoRegVar(_, _) = Terminator.impossible ()
        member _.GetAllRegVars() = [||]
        member _.GetGeneralRegVars() = [||] }
  let p = Parser(ISA Architecture.Intel, regNameAccessor, regVarAccessor)
  let size1Num = BitVector.T
  let size64Num = BitVector.Cast(size1Num, 64<rt>)
  let get = function Ok v -> v | Error e -> printfn "%s" e; failwith "Bad value"

  [<TestMethod>]
  member _.``[LowUIRParser] Test Register Assignment ``() =
    let result = p.Parse "R := 0x1:I64" |> get |> Array.head
    let answer = AST.put (AST.var 64<rt> regID "R") (AST.num size64Num)
    Assert.AreEqual<Stmt>(answer, result)

  [<TestMethod>]
  member _.``[LowUIRParser] Test IEMark ``() =
    let result = p.Parse "} // 1" |> get |> Array.head
    let answer = AST.iemark 1u
    Assert.AreEqual<Stmt>(answer, result)

  [<TestMethod>]
  member _.``[LowUIRParser] Test Temporary Registers``() =
    let result = p.Parse "T_2:I1 := 1" |> get |> Array.head
    let answer = AST.put (AST.tmpvar 1<rt> 2) (AST.num size1Num)
    Assert.AreEqual<Stmt>(answer, result)

  [<TestMethod>]
  member _.``[LowUIRParser] Test Operation in Expression``() =
    let result = p.Parse "R := (0x1:I64 - 0x1:I64)" |> get |> Array.head
    let answer =
      AST.put (AST.var 64<rt> regID "R")
              (AST.num (BitVector.Cast(BitVector.F, 64<rt>)))
    Assert.AreEqual<Stmt>(answer, result)

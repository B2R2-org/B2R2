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

namespace B2R2.FrontEnd.PPC.Tests

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.PPC
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type RegisterFactoryTests() =
  static let factoryOf wordSize =
    let isa = ISA(Architecture.PPC, Endian.Big, wordSize)
    RegisterFactory isa :> IRegisterFactory

  static let wordSizes = [ WordSize.Bit32; WordSize.Bit64 ]

  (* The data flow names a register by its ID and asks the factory how wide
     it is, which has to be what the variable of the register says. *)
  [<TestMethod>]
  member _.``[PPC] a register is as wide as its variable``() =
    for wordSize in wordSizes do
      let factory = factoryOf wordSize
      for var in factory.GetAllRegVars() do
        let rid = factory.GetRegisterID var
        let case = $"{var} {wordSize}"
        Assert.AreEqual<RegType>(Expr.typeOf var, factory.GetRegType rid, case)

  [<TestMethod>]
  member _.``[PPC] a register is found by its name``() =
    for wordSize in wordSizes do
      let factory = factoryOf wordSize
      for var in factory.GetAllRegVars() do
        let rid = factory.GetRegisterID var
        let name = factory.GetRegisterName rid
        Assert.AreEqual<RegisterID>(rid, factory.GetRegisterID name, name)
        Assert.AreEqual<Expr>(var, factory.GetRegVar name, name)

  (* LR and CTR hold addresses, the bits of CR are bits, and a floating-point
     register holds a double on every processor. *)
  [<TestMethod>]
  member _.``[PPC] the registers of branches are as wide as they hold``() =
    for wordSize in wordSizes do
      let factory = factoryOf wordSize
      let typeOf reg = factory.GetRegType(Register.toRegID reg)
      let word = WordSize.toRegType wordSize
      Assert.AreEqual<RegType>(word, typeOf Register.LR)
      Assert.AreEqual<RegType>(word, typeOf Register.CTR)
      Assert.AreEqual<RegType>(1<rt>, typeOf Register.CR0_2)
      Assert.AreEqual<RegType>(4<rt>, typeOf Register.CR7)
      Assert.AreEqual<RegType>(64<rt>, typeOf Register.F1)

  [<TestMethod>]
  member _.``[PPC] every bit of CR is a register of its own``() =
    let factory = factoryOf WordSize.Bit32
    let rids = factory.GetAllRegVars() |> Array.map factory.GetRegisterID
    for n in 0u .. 31u do
      let rid = OperandHelper.getCRbitRegister n |> Register.toRegID
      let count = rids |> Array.filter ((=) rid) |> Array.length
      Assert.AreEqual<int>(1, count, string n)

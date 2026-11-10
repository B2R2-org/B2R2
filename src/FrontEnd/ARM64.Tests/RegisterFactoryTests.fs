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

namespace B2R2.FrontEnd.ARM64.Tests

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM64
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type RegisterFactoryTests() =
  static let factory =
    RegisterFactory(ISA Architecture.ARMv8) :> IRegisterFactory

  static let regVar reg = factory.GetRegVar(Register.toRegID reg)

  static let half reg pos = factory.GetPseudoRegVar(Register.toRegID reg, pos)

  static let halves reg = AST.concat (half reg 2) (half reg 1)

  (* AAPCS64 passes and returns floating-point values in V0 to V7, and a caller
     who reads one as a whole register sees all 128 bits, which the lifter
     keeps as two 64-bit halves. *)
  [<TestMethod>]
  member _.``[ARM64] a V register reads as both of its halves test``() =
    let v0 = regVar Register.V0
    let v31 = regVar Register.V31
    Assert.AreEqual<Expr>(halves Register.V0, v0)
    Assert.AreEqual<RegType>(128<rt>, Expr.typeOf v0)
    Assert.AreEqual<Expr>(halves Register.V31, v31)

  (* The ID of a half that a statement writes leads back to the half, and D0
     is the low half. *)
  [<TestMethod>]
  member _.``[ARM64] a half of a V register is a register of its own test``() =
    let idOf e = Register.ofRegID (factory.GetRegisterID(e: Expr))
    let v0a = regVar Register.V0A
    Assert.AreEqual<Expr>(half Register.V0 1, v0a)
    Assert.AreEqual<Register>(Register.V0A, idOf v0a)
    Assert.AreEqual<Register>(Register.V31B, idOf (regVar Register.V31B))
    Assert.AreEqual<Expr>(v0a, regVar Register.D0)

  (* AAPCS64 makes X29 the frame pointer, through which code built without
     optimization reads its locals. *)
  [<TestMethod>]
  member _.``[ARM64] X29 is the frame pointer test``() =
    let fp = Register.toRegID Register.X29
    let x0 = Register.toRegID Register.X0
    Assert.AreEqual<RegisterID option>(Some fp, factory.FramePointer)
    Assert.AreEqual<bool>(true, factory.IsFramePointer fp)
    Assert.AreEqual<bool>(false, factory.IsFramePointer x0)

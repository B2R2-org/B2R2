(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*)


namespace B2R2.FrontEnd.BinLifter.Tests

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.S390
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type RegisterFactoryTests() =
  static let regType wordSize reg =
    let isa = ISA(Architecture.S390, Endian.Big, wordSize)
    let factory = RegisterFactory isa :> IRegisterFactory
    factory.GetRegType(Register.toRegID reg)

  (* A 32-bit S390 target runs ESA/390, whose general and control registers are
     32 bits wide; z/Architecture widened both to 64. Reporting 64 either way
     would tell the IR that a 31-bit program has doubleword registers. *)
  [<TestMethod>]
  member _.``[S390] a general register is 32 bits in 32-bit mode test``() =
    Assert.AreEqual<RegType>(32<rt>, regType WordSize.Bit32 Register.R1)

  [<TestMethod>]
  member _.``[S390] a general register is 64 bits in 64-bit mode test``() =
    Assert.AreEqual<RegType>(64<rt>, regType WordSize.Bit64 Register.R1)

  [<TestMethod>]
  member _.``[S390] a control register follows the word size test``() =
    Assert.AreEqual<RegType>(32<rt>, regType WordSize.Bit32 Register.CR0)
    Assert.AreEqual<RegType>(64<rt>, regType WordSize.Bit64 Register.CR0)

  (* The floating-point registers were 64 bits in ESA/390 already, and the
     access registers stayed at 32, so neither moves with the word size. *)
  [<TestMethod>]
  member _.``[S390] a floating-point register is 64 bits either way test``() =
    Assert.AreEqual<RegType>(64<rt>, regType WordSize.Bit32 Register.FPR0)
    Assert.AreEqual<RegType>(64<rt>, regType WordSize.Bit64 Register.FPR0)

  [<TestMethod>]
  member _.``[S390] an access register is 32 bits either way test``() =
    Assert.AreEqual<RegType>(32<rt>, regType WordSize.Bit32 Register.AR0)
    Assert.AreEqual<RegType>(32<rt>, regType WordSize.Bit64 Register.AR0)

  (* ESA/390 has a 64-bit PSW and z/Architecture a 128-bit one. *)
  [<TestMethod>]
  member _.``[S390] the PSW follows the word size test``() =
    Assert.AreEqual<RegType>(64<rt>, regType WordSize.Bit32 Register.PSW)
    Assert.AreEqual<RegType>(128<rt>, regType WordSize.Bit64 Register.PSW)

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

namespace B2R2.FrontEnd.BinLifter.Tests

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.M68K
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type RegisterFactoryTests() =
  static let factory =
    RegisterFactory(ISA Architecture.M68K) :> IRegisterFactory

  static let regType reg = factory.GetRegType(Register.toRegID reg)

  (* Every general and control register of the family is 32 bits, and MOVEC
     transfers a control register as a long word however few bits the register
     itself is implemented with. *)
  [<TestMethod>]
  member _.``[M68K] the general registers are 32 bits test``() =
    Assert.AreEqual<RegType>(32<rt>, regType Register.D0)
    Assert.AreEqual<RegType>(32<rt>, regType Register.A7)
    Assert.AreEqual<RegType>(32<rt>, regType Register.PC)
    Assert.AreEqual<RegType>(32<rt>, regType Register.VBR)

  (* The condition code register is the low byte of the status register, and a
     floating-point data register always holds an extended-precision value. *)
  [<TestMethod>]
  member _.``[M68K] the odd widths test``() =
    Assert.AreEqual<RegType>(8<rt>, regType Register.CCR)
    Assert.AreEqual<RegType>(16<rt>, regType Register.SR)
    Assert.AreEqual<RegType>(80<rt>, regType Register.FP0)

  (* A7 is the stack pointer at whatever privilege level is current, and the
     ELF ABI makes A6 the frame pointer. *)
  [<TestMethod>]
  member _.``[M68K] the pointer registers test``() =
    Assert.AreEqual<RegisterID>(Register.toRegID Register.PC,
                                factory.ProgramCounter)
    Assert.AreEqual<RegisterID option>(Some(Register.toRegID Register.A7),
                                       factory.StackPointer)
    Assert.AreEqual<RegisterID option>(Some(Register.toRegID Register.A6),
                                       factory.FramePointer)

  (* An m68k assembler names the stack pointer "sp" as readily as "a7", and the
     supervisor stack pointer answers to both of its names too. *)
  [<TestMethod>]
  member _.``[M68K] the stack pointer answers to both names test``() =
    Assert.AreEqual<Register>(Register.A7, Register.ofString "sp")
    Assert.AreEqual<Register>(Register.A7, Register.ofString "A7")
    Assert.AreEqual<Register>(Register.ISP, Register.ofString "ssp")

  (* Every register the factory hands out has to name itself back, or a caller
     that reads a register out of the IR cannot say which one it got. *)
  [<TestMethod>]
  member _.``[M68K] every register round-trips through its name test``() =
    for name in factory.GetAllRegisterNames() do
      let rid = factory.GetRegisterID name
      Assert.AreEqual<string>(name, factory.GetRegisterName rid)

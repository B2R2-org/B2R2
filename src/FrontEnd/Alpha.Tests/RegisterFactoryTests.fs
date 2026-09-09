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
open B2R2.FrontEnd.Alpha
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type RegisterFactoryTests() =
  static let factory =
    RegisterFactory(ISA Architecture.Alpha) :> IRegisterFactory

  static let regType reg = factory.GetRegType(Register.toRegID reg)

  (* Every register is a quadword wide, the floating-point ones included: what
     one of those holds is the sixty-four bits of a T_floating number whatever
     format an instruction reads it in. *)
  [<TestMethod>]
  member _.``[Alpha] every register is 64 bits test``() =
    Assert.AreEqual<RegType>(64<rt>, regType Register.R0)
    Assert.AreEqual<RegType>(64<rt>, regType Register.R31)
    Assert.AreEqual<RegType>(64<rt>, regType Register.F0)
    Assert.AreEqual<RegType>(64<rt>, regType Register.PC)
    Assert.AreEqual<RegType>(64<rt>, regType Register.FPCR)

  (* The calling standard makes r30 the stack pointer and r15 the frame
     pointer. *)
  [<TestMethod>]
  member _.``[Alpha] the pointer registers test``() =
    Assert.AreEqual<RegisterID>(Register.toRegID Register.PC,
                                factory.ProgramCounter)
    Assert.AreEqual<RegisterID option>(Some(Register.toRegID Register.R30),
                                       factory.StackPointer)
    Assert.AreEqual<RegisterID option>(Some(Register.toRegID Register.R15),
                                       factory.FramePointer)

  (* The general registers are named by their numbers and the floating-point
     ones by the same numbers under another letter, so nothing but the letter
     tells the two files apart. *)
  [<TestMethod>]
  member _.``[Alpha] a register is named by its number test``() =
    Assert.AreEqual<Register>(Register.R0, Register.ofString "r0")
    Assert.AreEqual<Register>(Register.R31, Register.ofString "R31")
    Assert.AreEqual<Register>(Register.F0, Register.ofString "f0")
    Assert.AreEqual<string>("r30", Register.toString Register.R30)
    Assert.AreEqual<string>("f30", Register.toString Register.F30)

  (* The general registers are what a caller reading the state of a machine
     wants, and neither the two the architecture keeps for itself nor the three
     the lifter keeps -- the process unique value and the pair modeling a
     reservation -- are among them. *)
  [<TestMethod>]
  member _.``[Alpha] the general registers are the numbered ones test``() =
    Assert.AreEqual<int>(32, factory.GetGeneralRegVars().Length)
    Assert.AreEqual<int>(69, factory.GetAllRegVars().Length)

  (* Every register the factory hands out has to name itself back, or a caller
     that reads a register out of the IR cannot say which one it got. *)
  [<TestMethod>]
  member _.``[Alpha] every register round-trips through its name test``() =
    for name in factory.GetAllRegisterNames() do
      let rid = factory.GetRegisterID name
      Assert.AreEqual<string>(name, factory.GetRegisterName rid)

// vim: set tw=80 sts=2 sw=2:

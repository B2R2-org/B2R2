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
open B2R2.FrontEnd.BPF
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type RegisterFactoryTests() =
  static let factory = RegisterFactory(ISA Architecture.BPF) :> IRegisterFactory

  static let regType reg = factory.GetRegType(Register.toRegID reg)

  (* Every register is a quadword wide, an instruction of the thirty-two bit
     class reading the lower half of one and clearing the upper half when it
     writes. *)
  [<TestMethod>]
  member _.``[BPF] every register is 64 bits test``() =
    Assert.AreEqual<RegType>(64<rt>, regType Register.R0)
    Assert.AreEqual<RegType>(64<rt>, regType Register.R10)
    Assert.AreEqual<RegType>(64<rt>, regType Register.PC)

  (* What a program reaches its own frame through is a register it may read and
     never write, and there is no stack pointer beside it. *)
  [<TestMethod>]
  member _.``[BPF] the frame pointer stands alone test``() =
    Assert.AreEqual<RegisterID>(Register.toRegID Register.PC,
                                factory.ProgramCounter)
    Assert.AreEqual<RegisterID option>(None, factory.StackPointer)
    Assert.AreEqual<RegisterID option>(Some(Register.toRegID Register.R10),
                                       factory.FramePointer)

  (* The registers are named by their numbers, and the one holding where the
     frame begins goes by a name of its own as well. *)
  [<TestMethod>]
  member _.``[BPF] a register is named by its number test``() =
    Assert.AreEqual<Register>(Register.R0, Register.ofString "r0")
    Assert.AreEqual<Register>(Register.R10, Register.ofString "R10")
    Assert.AreEqual<Register>(Register.R10, Register.ofString "fp")
    Assert.AreEqual<string>("r10", Register.toString Register.R10)

  (* The machine keeps eleven registers and no more, and the program counter is
     not one a program may name. *)
  [<TestMethod>]
  member _.``[BPF] there are eleven registers test``() =
    Assert.AreEqual<int>(11, factory.GetGeneralRegVars().Length)
    Assert.AreEqual<int>(12, factory.GetAllRegVars().Length)

  (* Every register the factory hands out has to name itself back, or a caller
     that reads a register out of the IR cannot say which one it got. *)
  [<TestMethod>]
  member _.``[BPF] every register round-trips through its name test``() =
    for name in factory.GetAllRegisterNames() do
      let rid = factory.GetRegisterID name
      Assert.AreEqual<string>(name, factory.GetRegisterName rid)

// vim: set tw=80 sts=2 sw=2:

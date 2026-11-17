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


namespace B2R2.FrontEnd.RISCV.Tests

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.RISCV
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type RegisterFactoryTests() =
  static let factoryOf wordSize =
    let isa = ISA(Architecture.RISCV, Endian.Little, wordSize)
    RegisterFactory isa :> IRegisterFactory

  static let rid reg = Register.toRegID reg

  (* The psABI makes x2 the stack pointer and x8 the frame pointer, and a
     factory that names one register as either has to tell the same register
     apart when asked. *)
  [<TestMethod>]
  member _.``[RISCV] sp and s0 are the stack and frame pointers``() =
    for wordSize in [ WordSize.Bit32; WordSize.Bit64 ] do
      let factory = factoryOf wordSize
      let sp, fp = rid Register.X2, rid Register.X8
      Assert.AreEqual<RegisterID option>(Some sp, factory.StackPointer)
      Assert.AreEqual<RegisterID option>(Some fp, factory.FramePointer)
      Assert.AreEqual<bool>(true, factory.IsStackPointer sp)
      Assert.AreEqual<bool>(true, factory.IsFramePointer fp)
      for other in [ Register.X29; Register.X30 ] do
        Assert.AreEqual<bool>(false, factory.IsStackPointer(rid other))
        Assert.AreEqual<bool>(false, factory.IsFramePointer(rid other))

  (* FCSR holds FFLAGS and FRM side by side, so a write to either changes it,
     and a write to it changes both. *)
  [<TestMethod>]
  member _.``[RISCV] fcsr shares its bits with fflags and frm``() =
    let factory = factoryOf WordSize.Bit64
    let aliases reg = factory.GetRegisterIDAliases(rid reg) |> Set.ofArray
    let set regs = regs |> List.map rid |> Set.ofList
    let fcsr = set [ Register.FCSR; Register.FFLAGS; Register.FRM ]
    Assert.AreEqual<Set<RegisterID>>(fcsr, aliases Register.FCSR)
    let fflags = set [ Register.FFLAGS; Register.FCSR ]
    Assert.AreEqual<Set<RegisterID>>(fflags, aliases Register.FFLAGS)
    let frm = set [ Register.FRM; Register.FCSR ]
    Assert.AreEqual<Set<RegisterID>>(frm, aliases Register.FRM)

  [<TestMethod>]
  member _.``[RISCV] a general register shares its bits with no other``() =
    let factory = factoryOf WordSize.Bit32
    for reg in [ Register.X0; Register.X10; Register.F10 ] do
      let aliases = factory.GetRegisterIDAliases(rid reg)
      CollectionAssert.AreEqual([| rid reg |], aliases, string reg)

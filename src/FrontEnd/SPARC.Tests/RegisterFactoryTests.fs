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

namespace B2R2.FrontEnd.SPARC.Tests

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.SPARC
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type RegisterFactoryTests() =
  static let factoryOf wordSize =
    let isa = ISA(Architecture.SPARC, Endian.Big, wordSize)
    RegisterFactory isa :> IRegisterFactory

  static let wordSizes = [ WordSize.Bit32; WordSize.Bit64 ]

  (* The data flow names a register by its ID and asks the factory how wide
     it is, which has to be what the variable of the register says. *)
  [<TestMethod>]
  member _.``[SPARC] A Register Is As Wide As Its Variable Test``() =
    for wordSize in wordSizes do
      let factory = factoryOf wordSize
      for var in factory.GetAllRegVars() do
        let rid = factory.GetRegisterID var
        let case = $"{var} {wordSize}"
        Assert.AreEqual<RegType>(Expr.typeOf var, factory.GetRegType rid, case)

  (* The disassembly writes a register with a %, which the name may leave
     out. *)
  [<TestMethod>]
  member _.``[SPARC] A Register Is Found By Its Name Test``() =
    let factory = factoryOf WordSize.Bit64
    for var in factory.GetAllRegVars() do
      let rid = factory.GetRegisterID var
      let name = factory.GetRegisterName rid
      Assert.AreEqual<RegisterID>(rid, factory.GetRegisterID name, name)
      Assert.AreEqual<Expr>(var, factory.GetRegVar name, name)
      let bare = name.TrimStart '%'
      Assert.AreEqual<RegisterID>(rid, factory.GetRegisterID bare, bare)

  [<TestMethod>]
  member _.``[SPARC] Every Register Comes Once Test``() =
    let factory = factoryOf WordSize.Bit64
    let rids = factory.GetAllRegVars() |> Array.map factory.GetRegisterID
    Assert.AreEqual<int>(rids.Length, Array.distinct rids |> Array.length)
    let general = factory.GetGeneralRegVars()
    Assert.AreEqual<int>(32, general.Length)
    let sp = factory.StackPointer |> Option.get |> factory.GetRegVar
    CollectionAssert.Contains(general, sp)

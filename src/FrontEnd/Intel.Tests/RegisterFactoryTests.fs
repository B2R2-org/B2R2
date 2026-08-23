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

namespace B2R2.FrontEnd.Intel.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Intel

[<TestClass>]
type RegisterFactoryTests() =
  let regFactory =
    RegisterFactory(ISA(Architecture.Intel, WordSize.Bit64))
    :> IRegisterFactory

  let regVar (reg: Register): Expr =
    Register.toRegID reg |> regFactory.GetRegVar

  let regType (reg: Register) = Register.toRegID reg |> regFactory.GetRegType

  let regs (first: Register) count =
    [| for n in 0 .. count - 1 ->
         LanguagePrimitives.EnumOfValue(int first + n) |]

  let compositeRegs =
    [| yield! regs Register.ST0 8
       yield! regs Register.XMM0 16
       yield! regs Register.YMM0 16
       yield! regs Register.ZMM0 16
       yield! regs Register.BND0 4 |]

  [<TestMethod>]
  member _.``Composite registers have their full width``() =
    for reg in compositeRegs do
      Assert.AreEqual<RegType>(regType reg, Expr.typeOf (regVar reg))

  [<TestMethod>]
  member _.``Composite registers concatenate their chunks in order``() =
    Assert.AreEqual<string>("(ZMM0B ++ ZMM0A)",
                            regVar Register.XMM0 |> PrettyPrinter.ToString)
    Assert.AreEqual<string>("((ZMM1D ++ ZMM1C) ++ (ZMM1B ++ ZMM1A))",
                            regVar Register.YMM1 |> PrettyPrinter.ToString)
    Assert.AreEqual<string>("(BND2B ++ BND2A)",
                            regVar Register.BND2 |> PrettyPrinter.ToString)

  [<TestMethod>]
  member _.``Composite registers are reachable by their name``() =
    for reg in compositeRegs do
      let byName: Expr = Register.toString reg |> regFactory.GetRegVar
      Assert.AreEqual<string>(regVar reg |> PrettyPrinter.ToString,
                              byName |> PrettyPrinter.ToString)

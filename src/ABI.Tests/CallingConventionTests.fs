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

namespace B2R2.ABI.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.ABI
open B2R2.FrontEnd

[<TestClass>]
type CallingConventionTests() =

  let r n = RegisterID.create n

  let sampleCC =
    { IntArgs =
        [| ArgLocation.Reg(r 1)
           ArgLocation.Reg(r 2)
           ArgLocation.Stack { FirstOffset = 8; SlotSize = 8 } |]
      FloatArgs = [| ArgLocation.Reg(r 5); ArgLocation.Reg(r 6) |]
      IntReturnLocation = ArgLocation.Reg(r 0)
      FloatReturnLocation = ArgLocation.Reg(r 7)
      ArgClassification = Independent
      CalleeSavedRegisters = set [ r 10; r 11 ]
      CallerSavedRegisters = set [ r 1; r 2 ]
      ReturnAddressLocation = OnStack }

  [<TestMethod>]
  member _.``GetIntArgLocation returns register arguments``() =
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Reg(r 1), sampleCC.GetIntArgLocation(0)
    )
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Reg(r 2), sampleCC.GetIntArgLocation(1)
    )

  [<TestMethod>]
  member _.``GetIntArgLocation resolves stack spill offsets``() =
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Stack { FirstOffset = 8; SlotSize = 8 },
      sampleCC.GetIntArgLocation(2)
    )
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Stack { FirstOffset = 16; SlotSize = 8 },
      sampleCC.GetIntArgLocation(3)
    )
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Stack { FirstOffset = 24; SlotSize = 8 },
      sampleCC.GetIntArgLocation(4)
    )

  [<TestMethod>]
  member _.``GetIntArgLocation handles all-stack ABI``() =
    let cc =
      { sampleCC with
          IntArgs = [| ArgLocation.Stack { FirstOffset = 4; SlotSize = 4 } |] }
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Stack { FirstOffset = 4; SlotSize = 4 },
      cc.GetIntArgLocation(0)
    )
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Stack { FirstOffset = 8; SlotSize = 4 },
      cc.GetIntArgLocation(1)
    )

  [<TestMethod>]
  member _.``IntReturnRegister extracts the return register``() =
    Assert.AreEqual<RegisterID>(r 0, sampleCC.IntReturnRegister)

  [<TestMethod>]
  member _.``IntArgRegister extracts register arguments``() =
    Assert.AreEqual<RegisterID>(r 1, sampleCC.IntArgRegister(0))
    Assert.AreEqual<RegisterID>(r 2, sampleCC.IntArgRegister(1))

  [<TestMethod>]
  member _.``GetFloatArgLocation returns float register arguments``() =
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Reg(r 5), sampleCC.GetFloatArgLocation(0)
    )
    Assert.AreEqual<ArgLocation>(
      ArgLocation.Reg(r 6), sampleCC.GetFloatArgLocation(1)
    )

  [<TestMethod>]
  member _.``FloatArgRegister and FloatReturnRegister extract registers``() =
    Assert.AreEqual<RegisterID>(r 5, sampleCC.FloatArgRegister(0))
    Assert.AreEqual<RegisterID>(r 7, sampleCC.FloatReturnRegister)

  [<TestMethod>]
  member _.``IsCalleeSaved and IsCallerSaved membership``() =
    Assert.AreEqual<bool>(true, sampleCC.IsCalleeSaved(r 10))
    Assert.AreEqual<bool>(false, sampleCC.IsCalleeSaved(r 1))
    Assert.AreEqual<bool>(true, sampleCC.IsCallerSaved(r 1))
    Assert.AreEqual<bool>(false, sampleCC.IsCallerSaved(r 10))

  [<TestMethod>]
  member _.``GetIntArgLocation rejects negative index``() =
    Assert.ThrowsExactly<System.ArgumentException>(fun () ->
      sampleCC.GetIntArgLocation(-1) |> ignore) |> ignore

  [<TestMethod>]
  member _.``x64 keeps the return address on the stack``() =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let cc = CallingConvention.create OS.Linux isa
    Assert.AreEqual<ReturnAddressLocation>(OnStack, cc.ReturnAddressLocation)

  [<TestMethod>]
  member _.``AArch64 holds the return address in the link register``() =
    let cc = CallingConvention.create OS.Linux (ISA Architecture.ARMv8)
    let lr = ARM64.Register.toRegID ARM64.Register.X30
    Assert.AreEqual<ReturnAddressLocation>(
      InRegister lr, cc.ReturnAddressLocation
    )

  [<TestMethod>]
  member _.``x64 System V passes floats in XMM independently``() =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let cc = CallingConvention.create OS.Linux isa
    let xmm0 = Intel.Register.toRegID Intel.Register.XMM0
    Assert.AreEqual<RegisterID>(xmm0, cc.FloatArgRegister(0))
    Assert.AreEqual<RegisterID>(xmm0, cc.FloatReturnRegister)
    Assert.AreEqual<ArgClassification>(Independent, cc.ArgClassification)

  [<TestMethod>]
  member _.``Windows x64 classifies arguments positionally``() =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let cc = CallingConvention.create OS.Windows isa
    let xmm0 = Intel.Register.toRegID Intel.Register.XMM0
    Assert.AreEqual<ArgClassification>(Positional, cc.ArgClassification)
    Assert.AreEqual<RegisterID>(xmm0, cc.FloatArgRegister(0))

  (* The System V m68k psABI passes every argument on the stack, so there is no
     register argument to resolve and the return value alone comes back in one.
     A6 is the frame pointer, which makes it callee-saved. *)
  [<TestMethod>]
  member _.``m68k passes every argument on the stack``() =
    let cc = CallingConvention.create OS.Linux (ISA Architecture.M68K)
    let d0 = M68K.Register.toRegID M68K.Register.D0
    let slot = ArgLocation.Stack { FirstOffset = 4; SlotSize = 4 }
    Assert.AreEqual<ArgLocation>(slot, cc.GetIntArgLocation 0)
    Assert.AreEqual<ArgLocation>(ArgLocation.Reg d0, cc.IntReturnLocation)
    Assert.AreEqual<ReturnAddressLocation>(OnStack, cc.ReturnAddressLocation)
    let a6 = M68K.Register.toRegID M68K.Register.A6
    Assert.AreEqual<bool>(true, cc.CalleeSavedRegisters.Contains a6)
    Assert.AreEqual<bool>(true, cc.CallerSavedRegisters.Contains d0)

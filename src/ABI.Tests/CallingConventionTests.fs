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

  (* AAPCS64 passes the first eight words in X0 to X7 and the rest on the
     stack, the first of them right at the stack pointer, as BL pushes
     nothing. *)
  [<TestMethod>]
  member _.``AAPCS64 passes eight words in registers and then on the stack``() =
    let cc = CallingConvention.create OS.Linux (ISA Architecture.ARMv8)
    let x7 = ARM64.Register.toRegID ARM64.Register.X7
    let slot = ArgLocation.Stack { FirstOffset = 0; SlotSize = 8 }
    Assert.AreEqual<ArgLocation>(ArgLocation.Reg x7, cc.GetIntArgLocation 7)
    Assert.AreEqual<ArgLocation>(slot, cc.GetIntArgLocation 8)

  (* IP0 and IP1 are free for the veneers and PLT entries that a linker puts in
     front of a callee, X18 is a temporary on GNU/Linux, and X30 takes the
     return address, so none of them survives a call, while X19 to X29 and the
     stack pointer do. *)
  [<TestMethod>]
  member _.``AAPCS64 clobbers X0 to X18 and LR and keeps X19 to X29``() =
    let cc = CallingConvention.create OS.Linux (ISA Architecture.ARMv8)
    let arm64 r = ARM64.Register.toRegID r
    Assert.AreEqual<bool>(true, cc.IsCallerSaved(arm64 ARM64.Register.X9))
    Assert.AreEqual<bool>(true, cc.IsCallerSaved(arm64 ARM64.Register.X16))
    Assert.AreEqual<bool>(true, cc.IsCallerSaved(arm64 ARM64.Register.X18))
    Assert.AreEqual<bool>(true, cc.IsCallerSaved(arm64 ARM64.Register.X30))
    Assert.AreEqual<bool>(true, cc.IsCalleeSaved(arm64 ARM64.Register.X19))
    Assert.AreEqual<bool>(true, cc.IsCalleeSaved(arm64 ARM64.Register.X29))
    Assert.AreEqual<bool>(true, cc.IsCalleeSaved(arm64 ARM64.Register.SP))

  (* AAPCS64 has a callee keep only the low halves of V8 to V15, which are D8
     to D15, and the lifter keeps every SIMD register in two halves, which are
     what a statement writes; every other half is lost across a call. *)
  [<TestMethod>]
  member _.``AAPCS64 keeps the low halves of V8 to V15 across a call``() =
    let cc = CallingConvention.create OS.Linux (ISA Architecture.ARMv8)
    let arm64 r = ARM64.Register.toRegID r
    Assert.AreEqual<bool>(true, cc.IsCalleeSaved(arm64 ARM64.Register.V8A))
    Assert.AreEqual<bool>(true, cc.IsCalleeSaved(arm64 ARM64.Register.V15A))
    Assert.AreEqual<bool>(true, cc.IsCallerSaved(arm64 ARM64.Register.V8B))
    Assert.AreEqual<bool>(true, cc.IsCallerSaved(arm64 ARM64.Register.V0A))
    Assert.AreEqual<bool>(true, cc.IsCallerSaved(arm64 ARM64.Register.V7B))
    Assert.AreEqual<bool>(true, cc.IsCallerSaved(arm64 ARM64.Register.V16A))
    Assert.AreEqual<bool>(true, cc.IsCallerSaved(arm64 ARM64.Register.V31B))
    Assert.AreEqual<bool>(false, cc.IsCallerSaved(arm64 ARM64.Register.V8A))

  (* AAPCS passes the first four words in R0 to R3 and the rest on the stack,
     the first of them right at the stack pointer, as BL pushes nothing. *)
  [<TestMethod>]
  member _.``AAPCS passes four words in registers and then on the stack``() =
    let cc = CallingConvention.create OS.Linux (ISA Architecture.ARMv7)
    let r3 = ARM32.Register.toRegID ARM32.Register.R3
    let slot = ArgLocation.Stack { FirstOffset = 0; SlotSize = 4 }
    Assert.AreEqual<ArgLocation>(ArgLocation.Reg r3, cc.GetIntArgLocation 3)
    Assert.AreEqual<ArgLocation>(slot, cc.GetIntArgLocation 4)

  (* IP is free for the veneers and PLT entries that a linker puts in front of
     a callee, and LR takes the return address, so neither survives a call. R9
     is a platform register, which GNU/Linux has the callee keep. *)
  [<TestMethod>]
  member _.``AAPCS clobbers IP and LR across a call and keeps R9``() =
    let cc = CallingConvention.create OS.Linux (ISA Architecture.ARMv7)
    let arm r = ARM32.Register.toRegID r
    Assert.AreEqual<bool>(true, cc.IsCallerSaved(arm ARM32.Register.IP))
    Assert.AreEqual<bool>(true, cc.IsCallerSaved(arm ARM32.Register.LR))
    Assert.AreEqual<bool>(true, cc.IsCalleeSaved(arm ARM32.Register.SB))

  (* AAPCS sorts the VFP registers alike whichever variant passes the floats:
     D8 to D15 survive a call, and the rest do not, D16 to D31 included on the
     units that have them. *)
  [<TestMethod>]
  member _.``AAPCS keeps D8 to D15 across a call and clobbers the rest``() =
    let cc = CallingConvention.create OS.Linux (ISA Architecture.ARMv7)
    let arm r = ARM32.Register.toRegID r
    Assert.AreEqual<bool>(true, cc.IsCalleeSaved(arm ARM32.Register.D8))
    Assert.AreEqual<bool>(true, cc.IsCalleeSaved(arm ARM32.Register.D15))
    Assert.AreEqual<bool>(true, cc.IsCallerSaved(arm ARM32.Register.D0))
    Assert.AreEqual<bool>(true, cc.IsCallerSaved(arm ARM32.Register.D7))
    Assert.AreEqual<bool>(true, cc.IsCallerSaved(arm ARM32.Register.D16))
    Assert.AreEqual<bool>(true, cc.IsCallerSaved(arm ARM32.Register.D31))

  (* The VFP variant of AAPCS passes floats in D0 to D7 and returns one in D0,
     whose low half is S0; the base standard leaves them to the core
     registers. *)
  [<TestMethod>]
  member _.``AAPCS passes floats in VFP registers only when hard-float``() =
    let arm r = ARM32.Register.toRegID r
    let d0, d7 = arm ARM32.Register.D0, arm ARM32.Register.D7
    let hard = CallingConvention.create OS.Linux (ISA "armhf")
    let soft = CallingConvention.create OS.Linux (ISA "armel")
    Assert.AreEqual<RegisterID>(d0, hard.FloatArgRegister 0)
    Assert.AreEqual<RegisterID>(d7, hard.FloatArgRegister 7)
    Assert.AreEqual<RegisterID>(d0, hard.FloatReturnRegister)
    Assert.AreEqual<int>(0, soft.FloatArgs.Length)
    Assert.AreEqual<RegisterID>(arm ARM32.Register.R0, soft.FloatReturnRegister)

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
  (* Alpha numbers one sequence of argument slots and reads each from whichever
     file the argument's type names, so the third argument is a2 when it is a
     word and $f18 when it is a number -- and a leading number does not move a
     following word down to a1, which is what Positional means and what tells
     this ABI from the RISC ones counting the two kinds apart. *)
  [<TestMethod>]
  member _.``Alpha numbers its argument slots across both files``() =
    let cc = CallingConvention.create OS.Linux (ISA Architecture.Alpha)
    Assert.AreEqual<ArgClassification>(Positional, cc.ArgClassification)
    let a2 = Alpha.Register.toRegID Alpha.Register.R18
    Assert.AreEqual<ArgLocation>(ArgLocation.Reg a2, cc.GetIntArgLocation 2)
    let f18 = Alpha.Register.toRegID Alpha.Register.F18
    Assert.AreEqual<ArgLocation>(ArgLocation.Reg f18, cc.GetFloatArgLocation 2)
    let v0 = Alpha.Register.toRegID Alpha.Register.R0
    Assert.AreEqual<ArgLocation>(ArgLocation.Reg v0, cc.IntReturnLocation)
    let ra = Alpha.Register.toRegID Alpha.Register.R26
    Assert.AreEqual<ReturnAddressLocation>(InRegister ra,
                                           cc.ReturnAddressLocation)
    let s0 = Alpha.Register.toRegID Alpha.Register.R9
    Assert.AreEqual<bool>(true, cc.CalleeSavedRegisters.Contains s0)
    Assert.AreEqual<bool>(true, cc.CallerSavedRegisters.Contains v0)

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

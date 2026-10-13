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

namespace B2R2.FrontEnd.ARM32.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2.BinIR
open B2R2.FrontEnd.ARM32
open B2R2.FrontEnd.ARM32.Tests.ManualLifting

/// <summary>
/// One test for each instruction DDI0406C and DDI0487F.c describe, A8.8.1 ADC
/// to A8.8.176 SMC in the order of their sections. A value test runs a word's
/// lifting with IRRunner over inputs QEMU ran the word on (qemu-arm -cpu max)
/// and asserts what QEMU left. A structural test is for a word a user-mode run
/// cannot execute alone; its doc comment says what it checks, and its
/// expectation is the manual's.
/// </summary>
[<TestClass>]
type ManualLifterTests1() =
  /// <summary>
  /// A8.8.1 ADC: adc r0, r1, #0x0. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.1 ADC``() =
    let inputs =
      [ [ Gpr(0, 0xe0c8cefdu); Gpr(1, 0x1bab4a35u); CPSR 0x20000010u ]
        [ Gpr(0, 0x69eee27au); Gpr(1, 0x31d527aeu); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu); CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x1bab4a36u) ]
        [ Gpr(0, 0x31d527aeu) ]
        [ Gpr(0, 0x0000ffffu) ] ]
    check false "e2a10000" inputs outputs

  /// <summary>
  /// A8.8.4 ADD: add r0, r1, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.4 ADD``() =
    let inputs =
      [ [ Gpr(0, 0x1b448276u); Gpr(1, 0x696f80c2u); Gpr(2, 0xf5999afcu) ]
        [ Gpr(0, 0x24229f4cu); Gpr(1, 0x37ba9a16u); Gpr(2, 0xa5f85e88u) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x5f091bbeu) ]
        [ Gpr(0, 0xddb2f89eu) ]
        [ Gpr(0, 0x00017fffu) ] ]
    check false "e0810002" inputs outputs

  /// <summary>
  /// A8.8.12 ADR: add r0, pc, #8. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.12 ADR``() =
    let inputs =
      [ [ Gpr(0, 0xa7d5b5a1u) ]
        [ Gpr(0, 0x8d61377au) ]
        [ Gpr(0, 0x00000001u) ] ]
    let outputs =
      [ [ Gpr(0, 0x30000010u) ]
        [ Gpr(0, 0x30000010u) ]
        [ Gpr(0, 0x30000010u) ] ]
    check false "e28f0008" inputs outputs

  /// <summary>
  /// A8.8.13 AND: and r0, r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.13 AND``() =
    let inputs =
      [ [ Gpr(0, 0xedab0028u); Gpr(2, 0x36ce21b5u) ]
        [ Gpr(0, 0x062f47bdu); Gpr(2, 0x383a6503u) ]
        [ Gpr(0, 0x00000001u); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x248a0020u) ]
        [ Gpr(0, 0x002a4501u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e0000002" inputs outputs

  /// <summary>
  /// A8.8.16 ASR: asr r0, r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.16 ASR``() =
    let inputs =
      [ [ Gpr(0, 0xe648e16au); Gpr(2, 0x33101e1fu) ]
        [ Gpr(0, 0xe95c9fd9u); Gpr(2, 0x41f03d3fu) ]
        [ Gpr(0, 0x00000001u); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xffffffffu) ]
        [ Gpr(0, 0xffffffffu) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1a00250" inputs outputs

  /// <summary>
  /// A8.8.18 B: b 0x4 ; . This checks where it goes, PC + 8 + imm24:00
  /// (CodeAddr + 4 for an offset of -4), by a plain jump. It is not a value
  /// test because it branches, and a run inside one instruction cannot follow
  /// it to what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.18 B``() =
    let run = runWith false "eaffffff" [] []
    Assert.AreEqual(Some(CodeAddr + 4UL), run.Target)
    let kinds = kindsOf false "eaffffff"
    CollectionAssert.AreEqual([| InterJmpKind.Base |], kinds)

  /// <summary>
  /// A8.8.19 BFC: bfc r0, #0x3, #0x5. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.19 BFC``() =
    let inputs =
      [ [ Gpr(0, 0xdf25423bu) ]
        [ Gpr(0, 0x03202094u) ]
        [ Gpr(0, 0x00000001u) ] ]
    let outputs =
      [ [ Gpr(0, 0xdf254203u) ]
        [ Gpr(0, 0x03202004u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e7c7019f" inputs outputs

  /// <summary>
  /// A8.8.20 BFI: bfi r0, r1, #0x3, #0x5. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.20 BFI``() =
    let inputs =
      [ [ Gpr(0, 0x8805ae92u); Gpr(1, 0xc177b71cu) ]
        [ Gpr(0, 0xdfba69f1u); Gpr(1, 0xa5a3bec0u) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x8805aee2u) ]
        [ Gpr(0, 0xdfba6901u) ]
        [ Gpr(0, 0x000000f9u) ] ]
    check false "e7c70191" inputs outputs

  /// <summary>
  /// A8.8.21 BIC: bic r0, r1, #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.21 BIC``() =
    let inputs =
      [ [ Gpr(0, 0xce0bf691u); Gpr(1, 0x6b5d0b4eu) ]
        [ Gpr(0, 0xf6843868u); Gpr(1, 0xd0cc89c7u) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x6b5d0b4eu) ]
        [ Gpr(0, 0xd0cc89c7u) ]
        [ Gpr(0, 0x0000ffffu) ] ]
    check false "e3c10000" inputs outputs

  /// <summary>
  /// A8.8.24 BKPT: bkpt #0x3. This checks that it takes a breakpoint. It is not
  /// a value test because it takes an exception, which a user-mode run cannot
  /// return from.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.24 BKPT``() =
    let run = runWith false "e1200073" [ CPSR 0x10u ] []
    Assert.AreEqual(Some SideEffect.Breakpoint, run.Effect)

  /// <summary>
  /// A8.8.25 BL: bl 0x4 ; . This checks that it goes to PC + 8 - 4, puts the
  /// address of the next instruction in LR and stays in A32, and that the jump
  /// is a call. It is not a value test because it branches, and a run inside
  /// one instruction cannot follow it to what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.25 BL``() =
    let run = runWith false "ebffffff" [ CPSR 0x10u ] []
    Assert.AreEqual(Some(CodeAddr + 4UL), run.Target)
    Assert.AreEqual(uint32 CodeAddr + 4u, run.Reg Register.LR)
    Assert.AreEqual(CPSR 0x10u, run.After(CPSR 0u))
    let kinds = kindsOf false "ebffffff"
    CollectionAssert.AreEqual([| InterJmpKind.IsCall |], kinds)

  /// <summary>
  /// A8.8.25 BLX: blx 0x4 ; . This checks that it goes to Align(PC, 4) - 4,
  /// puts the address of the next instruction in LR and selects T32. It is not
  /// a value test because it branches, and a run inside one instruction cannot
  /// follow it to what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.25 BLX``() =
    let run = runWith false "faffffff" [ CPSR 0x10u ] []
    Assert.AreEqual(Some(CodeAddr + 4UL), run.Target)
    Assert.AreEqual(uint32 CodeAddr + 4u, run.Reg Register.LR)
    Assert.AreEqual(CPSR 0x30u, run.After(CPSR 0u))

  /// <summary>
  /// A8.8.27 BX: bx r1. This checks that it goes to Rm with bit 0 cleared,
  /// selecting T32 where bit 0 is set and A32 where it is clear. It is not a
  /// value test because it branches, and a run inside one instruction cannot
  /// follow it to what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.27 BX``() =
    let thumb = [ Gpr(1, 0x30001001u); CPSR 0x10u ]
    let arm = [ Gpr(1, 0x30001000u); CPSR 0x30u ]
    let toThumb = runWith false "e12fff11" thumb []
    let toArm = runWith false "e12fff11" arm []
    Assert.AreEqual(Some 0x30001000UL, toThumb.Target)
    Assert.AreEqual(CPSR 0x30u, toThumb.After(CPSR 0u))
    Assert.AreEqual(Some 0x30001000UL, toArm.Target)
    Assert.AreEqual(CPSR 0x10u, toArm.After(CPSR 0u))

  /// <summary>
  /// A8.8.28 BXJ: bxj r1. This checks that it goes to Rm with bit 0 cleared,
  /// selecting T32 where bit 0 is set and A32 where it is clear: with no
  /// Jazelle state BXJ is BX. It is not a value test because it branches, and a
  /// run inside one instruction cannot follow it to what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.28 BXJ``() =
    let thumb = [ Gpr(1, 0x30001001u); CPSR 0x10u ]
    let arm = [ Gpr(1, 0x30001000u); CPSR 0x30u ]
    let toThumb = runWith false "e12fff21" thumb []
    let toArm = runWith false "e12fff21" arm []
    Assert.AreEqual(Some 0x30001000UL, toThumb.Target)
    Assert.AreEqual(CPSR 0x30u, toThumb.After(CPSR 0u))
    Assert.AreEqual(Some 0x30001000UL, toArm.Target)
    Assert.AreEqual(CPSR 0x10u, toArm.After(CPSR 0u))

  /// <summary>
  /// A8.8.29 CBNZ: cbnz r0, 0x4 ; . This checks that it goes to PC + imm
  /// (CodeAddr + 4) when Rn is not zero and to the next instruction when it is.
  /// It is not a value test because it branches, and a run inside one
  /// instruction cannot follow it to what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.29 CBNZ``() =
    let taken = runWith true "b900" [ Gpr(0, 5u) ] []
    let fallen = runWith true "b900" [ Gpr(0, 0u) ] []
    Assert.AreEqual(Some(CodeAddr + 4UL), taken.Target)
    Assert.AreEqual(Some(CodeAddr + 2UL), fallen.Target)

  /// <summary>
  /// A8.8.29 CBZ: cbz r0, 0x4 ; . This checks that it goes to PC + imm
  /// (CodeAddr + 4) when Rn is zero and to the next instruction when it is not.
  /// It is not a value test because it branches, and a run inside one
  /// instruction cannot follow it to what QEMU would show.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.29 CBZ``() =
    let taken = runWith true "b100" [ Gpr(0, 0u) ] []
    let fallen = runWith true "b100" [ Gpr(0, 5u) ] []
    Assert.AreEqual(Some(CodeAddr + 4UL), taken.Target)
    Assert.AreEqual(Some(CodeAddr + 2UL), fallen.Target)

  /// <summary>
  /// A8.8.30 CDP: cdp 7, 1, cr1, cr2, cr3, {4}. This checks that the lift says
  /// the instruction is unsupported: coprocessor 7 is none this front end
  /// models. It is not a value test because it reaches a coprocessor, which a
  /// user-mode run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.30 CDP``() =
    let run = runWith false "ee121783" [ CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.30 CDP2: cdp2 7, 1, cr1, cr2, cr3, {4}. This checks that the lift
  /// says the instruction is unsupported: coprocessor 7 is none this front end
  /// models. It is not a value test because it reaches a coprocessor, which a
  /// user-mode run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.30 CDP2``() =
    let run = runWith false "fe121783" [ CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.32 CLREX: clrex. This checks that it clears a reservation: STREX
  /// succeeds while one is held and fails after CLREX. It is not a value test
  /// because what it clears is a reservation no register shows.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.32 CLREX``() =
    let w = uint32 Window
    let held =
      [ Register.ExMonAddr, w + 16u; Register.ExMonVal, 0x1234u ]
    let cells = [ Gpr(1, w + 16u); Gpr(2, 0x5678u); M(16, 0x1234UL) ]
    let cleared = runWith false "f57ff01f" [] held
    let after = [ for r, _ in held -> r, cleared.Reg r ]
    let strex = "e1810f92"
    let holds = runWith false strex cells held
    let fails = runWith false strex cells after
    Assert.AreEqual(Gpr(0, 0u), holds.After(Gpr(0, 0u)))
    Assert.AreEqual(M(16, 0x5678UL), holds.After(M(16, 0UL)))
    Assert.AreEqual(Gpr(0, 1u), fails.After(Gpr(0, 0u)))
    Assert.AreEqual(M(16, 0x1234UL), fails.After(M(16, 0UL)))

  /// <summary>
  /// A8.8.33 CLZ: clz r0, r1. The outputs are what QEMU left after running it
  /// on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.33 CLZ``() =
    let inputs =
      [ [ Gpr(0, 0x58e22cb5u); Gpr(1, 0x0db78ed1u) ]
        [ Gpr(0, 0x3d880c9fu); Gpr(1, 0xb298e20eu) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000004u) ]
        [ Gpr(0, 0x00000000u) ]
        [ Gpr(0, 0x00000010u) ] ]
    check false "e16f0f11" inputs outputs

  /// <summary>
  /// A8.8.34 CMN: cmn r1, r2. The outputs are what QEMU left after running it
  /// on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.34 CMN``() =
    let inputs =
      [ [ Gpr(1, 0x693a999du); Gpr(2, 0xd5edf592u); CPSR 0x20000010u ]
        [ Gpr(1, 0x71e55c4eu); Gpr(2, 0xa50e2e7du); CPSR 0x900a0010u ]
        [ Gpr(1, 0x0000ffffu); Gpr(2, 0x00008000u); CPSR 0x48050010u ] ]
    let outputs =
      [ [ CPSR 0x20000010u ]
        [ CPSR 0x200a0010u ]
        [ CPSR 0x08050010u ] ]
    check false "e1710002" inputs outputs

  /// <summary>
  /// A8.8.37 CMP: cmp r1, #0x3. The outputs are what QEMU left after running it
  /// on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.37 CMP``() =
    let inputs =
      [ [ Gpr(1, 0x27db8b8au); CPSR 0x20000010u ]
        [ Gpr(1, 0x490867b1u); CPSR 0x900a0010u ]
        [ Gpr(1, 0x0000ffffu); CPSR 0x48050010u ] ]
    let outputs =
      [ [ CPSR 0x20000010u ]
        [ CPSR 0x200a0010u ]
        [ CPSR 0x28050010u ] ]
    check false "e3510003" inputs outputs

  /// <summary>
  /// A8.8.40 CPS: cps #0x13. This checks that it changes System mode to
  /// Supervisor mode and that in User mode it changes nothing. It is not a
  /// value test because it needs a privileged mode, which a user-mode run does
  /// not have.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.40 CPS``() =
    let user = runWith false "f1020013" [ CPSR 0x10u ] []
    let system = runWith false "f1020013" [ CPSR 0x1fu ] []
    Assert.AreEqual(CPSR 0x10u, user.After(CPSR 0u))
    Assert.AreEqual(CPSR 0x13u, system.After(CPSR 0u))

  /// <summary>
  /// A8.8.41 CPY: mov r0, r1. The outputs are what QEMU left after running it
  /// on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.41 CPY``() =
    let inputs =
      [ [ Gpr(0, 0x7d6ea74bu); Gpr(1, 0x8a4a883du) ]
        [ Gpr(0, 0x3310184fu); Gpr(1, 0xbd451676u) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x8a4a883du) ]
        [ Gpr(0, 0xbd451676u) ]
        [ Gpr(0, 0x0000ffffu) ] ]
    check false "e1a00001" inputs outputs

  /// <summary>
  /// A8.8.42 CSDB: csdb. It lifts to no statements: what it does is a hint or
  /// an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.42 CSDB``() =
    Assert.AreEqual(0, (lift false "e320f014").Length)

  /// <summary>
  /// A8.8.43 DBG: dbg #0x4. It lifts to no statements: what it does is a hint
  /// or an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.43 DBG``() =
    Assert.AreEqual(0, (lift false "e320f0f4").Length)

  /// <summary>
  /// A8.8.44 DMB: dmb sy. It lifts to no statements: what it does is a hint or
  /// an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.44 DMB``() =
    Assert.AreEqual(0, (lift false "f57ff05f").Length)

  /// <summary>
  /// A8.8.45 DSB: dsb sy. It lifts to no statements: what it does is a hint or
  /// an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.45 DSB``() =
    Assert.AreEqual(0, (lift false "f57ff04f").Length)

  /// <summary>
  /// A8.8.46 ENTERX: .inst 0xf3bf8f1f. This checks that it takes the Undefined
  /// Instruction exception. It is not a value test because it belongs to
  /// ThumbEE, which no QEMU model implements.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.46 ENTERX``() =
    let run = runWith true "f3bf8f1f" [ CPSR 0x10u ] []
    Assert.AreEqual(Some SideEffect.UndefinedInstruction, run.Effect)

  /// <summary>
  /// A8.8.47 EOR: eor r0, r1, #0xff00000. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.47 EOR``() =
    let inputs =
      [ [ Gpr(0, 0xc40db144u); Gpr(1, 0x357dcb85u) ]
        [ Gpr(0, 0xd7dff138u); Gpr(1, 0x78730531u) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x3a8dcb85u) ]
        [ Gpr(0, 0x77830531u) ]
        [ Gpr(0, 0x0ff0ffffu) ] ]
    check false "e22106ff" inputs outputs

  /// <summary>
  /// A8.8.50 ERET: eret. This checks that User mode refuses it, and that from
  /// Supervisor mode it returns to LR with CPSR taken from SPSR. It is not a
  /// value test because it needs a privileged mode, which a user-mode run does
  /// not have.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.50 ERET``() =
    let others =
      [ Register.SPSR, 0x80000010u; Register.LR, 0x30002000u ]
    let run = runWith false "e160006e" [ CPSR 0x13u ] others
    let refused = refusedModes false "e160006e" [] others
    CollectionAssert.AreEqual([| 0x10u |], refused)
    Assert.AreEqual(Some 0x30002000UL, run.Target)
    Assert.AreEqual(CPSR 0x80000010u, run.After(CPSR 0u))

  /// <summary>
  /// A8.8.53 HVC: hvc 1. This checks that User mode refuses it and that every
  /// other mode reaches a call the lift does not model. It is not a value test
  /// because it takes an exception, which a user-mode run cannot return from.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.53 HVC``() =
    let run = runWith false "e1400071" [ CPSR 0x13u ] []
    let refused = refusedModes false "e1400071" [] []
    CollectionAssert.AreEqual([| 0x10u |], refused)
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.54 ISB: isb sy. It lifts to no statements: what it does is a hint or
  /// an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.54 ISB``() =
    Assert.AreEqual(0, (lift false "f57ff06f").Length)

  /// <summary>
  /// A8.8.55 IT: it eq. This checks that IT EQ sets ITSTATE to 0x08: firstcond
  /// 0000 and mask 1000, ITSTATE&lt;7:2&gt; in CPSR&lt;15:10&gt;. It is not a
  /// value test because it only conditions the instructions after it, and its
  /// state is none MRS shows.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.55 IT``() =
    let run = runWith true "bf08" [ CPSR 0x30u ] []
    Assert.AreEqual(CPSR 0x830u, run.After(CPSR 0u))

  /// <summary>
  /// A8.8.56 LDC: ldc 7, cr1, [r1, #8]. This checks that the lift says the
  /// instruction is unsupported: coprocessor 7 is none this front end models.
  /// It is not a value test because it reaches a coprocessor, which a user-mode
  /// run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.56 LDC``() =
    let run = runWith false "ed911702" [ CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.56 LDC2: ldc2 7, cr1, [r1, #8]. This checks that the lift says the
  /// instruction is unsupported: coprocessor 7 is none this front end models.
  /// It is not a value test because it reaches a coprocessor, which a user-mode
  /// run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.56 LDC2``() =
    let run = runWith false "fd911702" [ CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.58 LDM: ldm r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.58 LDM``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          Gpr(2, 0xd24a816fu)
          Gpr(3, 0x6be77da5u)
          M(0, 0x2cd339e848e68bc1UL)
          M(8, 0xd53f4c3c6778110bUL)
          M(16, 0xf3d4c4a053822300UL)
          M(24, 0x9420bb3b8537e308UL)
          M(32, 0xe17559e0263abd6aUL)
          M(40, 0x5fd3109124a1b109UL)
          M(48, 0x72ff09ed5f2d1a46UL)
          M(56, 0xc8505b3d50a96beeUL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x54ca4cf8u)
          Gpr(3, 0x65a5d067u)
          M(0, 0x78b17a43de12b5bfUL)
          M(8, 0xb76a29481d2c7e0cUL)
          M(16, 0xe21a8e9e682d8e44UL)
          M(24, 0x7e25f38febe799d5UL)
          M(32, 0xccb1e1f072c4732fUL)
          M(40, 0x8a06041236dd11e4UL)
          M(48, 0xf0168d4a83e87ff7UL)
          M(56, 0xa820166edc82280dUL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x00008000u)
          Gpr(3, 0x7fff8000u)
          M(0, 0x47ae094c18ae62f2UL)
          M(8, 0x2df60ad976519323UL)
          M(16, 0xafd4b7e54da726d3UL)
          M(24, 0x87998130450b401fUL)
          M(32, 0xb32b6b3e7b785829UL)
          M(40, 0x79516c8f1d9bf382UL)
          M(48, 0x92404ee3d00df791UL)
          M(56, 0x6186b929b530673bUL) ] ]
    let outputs =
      [ [ Gpr(2, 0x8537e308u); Gpr(3, 0x9420bb3bu) ]
        [ Gpr(2, 0xebe799d5u); Gpr(3, 0x7e25f38fu) ]
        [ Gpr(2, 0x450b401fu); Gpr(3, 0x87998130u) ] ]
    check false "e891000c" inputs outputs

  /// <summary>
  /// A8.8.58 LDMFD: ldm r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.58 LDMFD``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          Gpr(2, 0x124d92f3u)
          Gpr(3, 0x4a9abec4u)
          M(0, 0x75cb864c08686fabUL)
          M(8, 0xc27abc98673f7f06UL)
          M(16, 0x0e4a46cd8a6a6adaUL)
          M(24, 0x390f9714617c45c6UL)
          M(32, 0x81f83c29133b627fUL)
          M(40, 0xef515b4a037cbf27UL)
          M(48, 0x80d968b669720aa4UL)
          M(56, 0xafd2aa5b47de6220UL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0xd4c16d3cu)
          Gpr(3, 0xad5a68fbu)
          M(0, 0x693ef7414799c979UL)
          M(8, 0x25e1bfdc0c2871f1UL)
          M(16, 0x36ed4db66488d611UL)
          M(24, 0xd46d7315b49a5808UL)
          M(32, 0x240842e25342c78bUL)
          M(40, 0xc1ecd028ae3609cfUL)
          M(48, 0x9443130721bd98deUL)
          M(56, 0xf36c491ae5995590UL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x48ba9e83608a3710UL)
          M(8, 0xe8e1981cc9731b8cUL)
          M(16, 0xa6fd0ee28bc4976fUL)
          M(24, 0xc4c6e415c9842addUL)
          M(32, 0xb476528cc233fad3UL)
          M(40, 0xc1b4ce0afdab871bUL)
          M(48, 0x8e323d87d3a586cbUL)
          M(56, 0x7b3199c86d5a9206UL) ] ]
    let outputs =
      [ [ Gpr(2, 0x617c45c6u); Gpr(3, 0x390f9714u) ]
        [ Gpr(2, 0xb49a5808u); Gpr(3, 0xd46d7315u) ]
        [ Gpr(2, 0xc9842addu); Gpr(3, 0xc4c6e415u) ] ]
    check false "e891000c" inputs outputs

  /// <summary>
  /// A8.8.58 LDMIA: ldm r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.58 LDMIA``() =
    let inputs =
      [ [ Gpr(1, 0x20000818u)
          Gpr(2, 0x79a0344fu)
          Gpr(3, 0x5472203du)
          M(0, 0xc6643cb493abf870UL)
          M(8, 0x0fae0a19dfffbcdbUL)
          M(16, 0xf7a5a1c760a9fd09UL)
          M(24, 0x3cdb2970f00b501bUL)
          M(32, 0xb9218517cca38865UL)
          M(40, 0x4748099dca94f92bUL)
          M(48, 0x5bc83ffc61db8e27UL)
          M(56, 0x9e042615945c4816UL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x3f554437u)
          Gpr(3, 0x34c945b9u)
          M(0, 0x70583fdc3a4efdc3UL)
          M(8, 0xbbbd6ba4962ac2f6UL)
          M(16, 0x5658cab48888051aUL)
          M(24, 0xbb4de7b6d461577bUL)
          M(32, 0x387aa9bac491745fUL)
          M(40, 0x5dbbc0b75cfc06eeUL)
          M(48, 0x9899d07392cbfdf1UL)
          M(56, 0x457196a944390b8dUL) ]
        [ Gpr(1, 0x20000818u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0xd7845906e43b5653UL)
          M(8, 0x9cc5c6ba40b5bfb8UL)
          M(16, 0x5754af4d470cdcb4UL)
          M(24, 0x594902ab0cbc0f0bUL)
          M(32, 0x5f1f6b1931ca72a7UL)
          M(40, 0xb34c6e5e855579cdUL)
          M(48, 0x83547cec7f51db32UL)
          M(56, 0x07289a99ef902212UL) ] ]
    let outputs =
      [ [ Gpr(2, 0xf00b501bu); Gpr(3, 0x3cdb2970u) ]
        [ Gpr(2, 0xd461577bu); Gpr(3, 0xbb4de7b6u) ]
        [ Gpr(2, 0x0cbc0f0bu); Gpr(3, 0x594902abu) ] ]
    check false "e891000c" inputs outputs

  /// <summary>
  /// A8.8.60 LDMDA: ldmda r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.60 LDMDA``() =
    let inputs =
      [ [ Gpr(1, 0x2000081cu)
          Gpr(2, 0xcd6c990cu)
          Gpr(3, 0xfb0c1475u)
          M(0, 0xa90df2360216823fUL)
          M(8, 0x9ff10eb6de06545fUL)
          M(16, 0xf38ecf80ded00e54UL)
          M(24, 0x568684f98fdd238aUL)
          M(32, 0x9c1204e4006ae531UL)
          M(40, 0xec476a400ab72d3fUL)
          M(48, 0x93bf397e46b8df8dUL)
          M(56, 0xfc3620ec7f40980fUL) ]
        [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x74c85b15u)
          Gpr(3, 0x284bc57cu)
          M(0, 0xe4e83ae7ac34f1aaUL)
          M(8, 0x561d580594b8ba89UL)
          M(16, 0x293911e78458c9e0UL)
          M(24, 0x8cae4207f888e286UL)
          M(32, 0xa73a01030f658c38UL)
          M(40, 0x74d796418f75e775UL)
          M(48, 0xd059577ffc4b8bbfUL)
          M(56, 0x0392db73d8ab5298UL) ]
        [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x3998b24fc4176732UL)
          M(8, 0x5ce4fc8548aa948dUL)
          M(16, 0xdf702025d16dbf6fUL)
          M(24, 0xd6ca3b98c3dd80ccUL)
          M(32, 0xbef4fc1b826307dbUL)
          M(40, 0x3f68bad5a175b1f9UL)
          M(48, 0xc35d3f314f09f4e2UL)
          M(56, 0x2f424440e715f707UL) ] ]
    let outputs =
      [ [ Gpr(2, 0x8fdd238au); Gpr(3, 0x568684f9u) ]
        [ Gpr(2, 0xf888e286u); Gpr(3, 0x8cae4207u) ]
        [ Gpr(2, 0xc3dd80ccu); Gpr(3, 0xd6ca3b98u) ] ]
    check false "e811000c" inputs outputs

  /// <summary>
  /// A8.8.60 LDMFA: ldmda r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.60 LDMFA``() =
    let inputs =
      [ [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x3344dda3u)
          Gpr(3, 0xda7c9e92u)
          M(0, 0xb51b9bb75bfc34f4UL)
          M(8, 0x9849a6f5141c5845UL)
          M(16, 0xc0fd8e6d31bd275dUL)
          M(24, 0x06ae0646b8e5b3c6UL)
          M(32, 0x81f7c668efaaaf7cUL)
          M(40, 0x070d099b98c4f1f3UL)
          M(48, 0x75f6fd6e5937e35bUL)
          M(56, 0xe732a8ac9e6d03e9UL) ]
        [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x1ff68a97u)
          Gpr(3, 0x37eecf5fu)
          M(0, 0x33ef4651063c1e7aUL)
          M(8, 0x81dcce4b10848bd7UL)
          M(16, 0x2f768baf2bfc6e5dUL)
          M(24, 0x0420b47c0b102ad0UL)
          M(32, 0xd5d3465fb33d3145UL)
          M(40, 0x05e689b0408c9704UL)
          M(48, 0x7a593ad163389912UL)
          M(56, 0xda468af198b5b17eUL) ]
        [ Gpr(1, 0x2000081cu)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x7d9a997fb642030bUL)
          M(8, 0x322d765c46db1c7eUL)
          M(16, 0x3386c48440a316e3UL)
          M(24, 0x5195d90cf96f7e4aUL)
          M(32, 0x2363d2ffa30f2e57UL)
          M(40, 0x1f695b76393a254eUL)
          M(48, 0x83fc8a2224faff09UL)
          M(56, 0xb315e6816322063cUL) ] ]
    let outputs =
      [ [ Gpr(2, 0xb8e5b3c6u); Gpr(3, 0x06ae0646u) ]
        [ Gpr(2, 0x0b102ad0u); Gpr(3, 0x0420b47cu) ]
        [ Gpr(2, 0xf96f7e4au); Gpr(3, 0x5195d90cu) ] ]
    check false "e811000c" inputs outputs

  /// <summary>
  /// A8.8.61 LDMDB: ldmdb r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.61 LDMDB``() =
    let inputs =
      [ [ Gpr(1, 0x20000820u)
          Gpr(2, 0xe796a698u)
          Gpr(3, 0x28340f56u)
          M(0, 0x9960477f3280cef1UL)
          M(8, 0xef68c8e1ea560eb1UL)
          M(16, 0x6f1e9f493991fdf6UL)
          M(24, 0x55e48fcec851ebdfUL)
          M(32, 0x0df14a1be35d1ceeUL)
          M(40, 0x3bad1ae401c23ec1UL)
          M(48, 0xd7338cf7847dd0aaUL)
          M(56, 0x1d56f7f36b9c9797UL) ]
        [ Gpr(1, 0x20000820u)
          Gpr(2, 0x4c497544u)
          Gpr(3, 0x3d65d360u)
          M(0, 0x97160615553fa5d7UL)
          M(8, 0x41f9f230dde24fffUL)
          M(16, 0xad931d77c2d5ec1eUL)
          M(24, 0xfbd32aa0102392b7UL)
          M(32, 0xec43f6f90f439eb9UL)
          M(40, 0x65f9035e0d1f8ca1UL)
          M(48, 0x8eaa5bfaadbe1c9eUL)
          M(56, 0xce2f381f68c781feUL) ]
        [ Gpr(1, 0x20000820u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0xbdaeab6467b18b4cUL)
          M(8, 0xe0742fc49a7c1acdUL)
          M(16, 0xed3329abd5a4b5d3UL)
          M(24, 0x7e9e8993f8c05ceeUL)
          M(32, 0x0f871c588d6036e2UL)
          M(40, 0x73c28e4da420c6f5UL)
          M(48, 0xfb4ebc724af97956UL)
          M(56, 0x62ffe685a4bfcb11UL) ] ]
    let outputs =
      [ [ Gpr(2, 0xc851ebdfu); Gpr(3, 0x55e48fceu) ]
        [ Gpr(2, 0x102392b7u); Gpr(3, 0xfbd32aa0u) ]
        [ Gpr(2, 0xf8c05ceeu); Gpr(3, 0x7e9e8993u) ] ]
    check false "e911000c" inputs outputs

  /// <summary>
  /// A8.8.61 LDMEA: ldmdb r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.61 LDMEA``() =
    let inputs =
      [ [ Gpr(1, 0x20000820u)
          Gpr(2, 0x31a686acu)
          Gpr(3, 0xa390e527u)
          M(0, 0x1518d869360e7c83UL)
          M(8, 0x401652cebe12d0b0UL)
          M(16, 0x740eb761058f2e5dUL)
          M(24, 0x1376537667476efdUL)
          M(32, 0x28c2a7f0f09ea2a3UL)
          M(40, 0x6f63e35379257423UL)
          M(48, 0x10b1489dcabfe1dfUL)
          M(56, 0xf13ece45389af25fUL) ]
        [ Gpr(1, 0x20000820u)
          Gpr(2, 0xbe07b4a8u)
          Gpr(3, 0x1d561767u)
          M(0, 0x90b21a0a2f4e2cd6UL)
          M(8, 0x322b5e2aa94b1c1dUL)
          M(16, 0xffae00b86cf00b7bUL)
          M(24, 0xe0dc0c3289703abfUL)
          M(32, 0x44cea8662326dcf4UL)
          M(40, 0xd278a57cb7d87f30UL)
          M(48, 0x48469aa0b82a2316UL)
          M(56, 0x81fea5e4ee777e19UL) ]
        [ Gpr(1, 0x20000820u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x3d70f58985e724f9UL)
          M(8, 0xf51c4919039ef43eUL)
          M(16, 0x50f65e5df3670fb3UL)
          M(24, 0x7827d75d8080d297UL)
          M(32, 0x95f4a98bd188e081UL)
          M(40, 0xa048e1217047a98aUL)
          M(48, 0x62f4c17b079fd4b1UL)
          M(56, 0x4697d017bab24d67UL) ] ]
    let outputs =
      [ [ Gpr(2, 0x67476efdu); Gpr(3, 0x13765376u) ]
        [ Gpr(2, 0x89703abfu); Gpr(3, 0xe0dc0c32u) ]
        [ Gpr(2, 0x8080d297u); Gpr(3, 0x7827d75du) ] ]
    check false "e911000c" inputs outputs

  /// <summary>
  /// A8.8.62 LDMED: ldmib r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.62 LDMED``() =
    let inputs =
      [ [ Gpr(1, 0x20000814u)
          Gpr(2, 0x0aa9bf99u)
          Gpr(3, 0x90aafb50u)
          M(0, 0xd6cb60d98f94dd7fUL)
          M(8, 0x77d96f44f9593d6aUL)
          M(16, 0x20701e2fd8f6f590UL)
          M(24, 0xa22dc6205bdc0cc7UL)
          M(32, 0xfff09d722b69b794UL)
          M(40, 0x85fb9d9d49665d45UL)
          M(48, 0xe901d37398ca5f13UL)
          M(56, 0x41416cda4a8726bdUL) ]
        [ Gpr(1, 0x20000814u)
          Gpr(2, 0x2290a5fau)
          Gpr(3, 0x9bec9711u)
          M(0, 0xf1a62f558b13cec4UL)
          M(8, 0x6cd4c75c1899a470UL)
          M(16, 0x9c95fb2821dccd96UL)
          M(24, 0x2bd3cf2dc674750cUL)
          M(32, 0xd99927734cade9e9UL)
          M(40, 0xfae580895e65413cUL)
          M(48, 0xfe1c3848d96bbf74UL)
          M(56, 0xf863637441095337UL) ]
        [ Gpr(1, 0x20000814u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0xa5ab364b71874969UL)
          M(8, 0x41546f8808b418f9UL)
          M(16, 0x7db3eb3478c17746UL)
          M(24, 0x8c762c95a4b0c643UL)
          M(32, 0xc67c2821c1ec6ee5UL)
          M(40, 0x2923d62839e57ab7UL)
          M(48, 0xdef4915103e86e46UL)
          M(56, 0xac28315b5bf85459UL) ] ]
    let outputs =
      [ [ Gpr(2, 0x5bdc0cc7u); Gpr(3, 0xa22dc620u) ]
        [ Gpr(2, 0xc674750cu); Gpr(3, 0x2bd3cf2du) ]
        [ Gpr(2, 0xa4b0c643u); Gpr(3, 0x8c762c95u) ] ]
    check false "e991000c" inputs outputs

  /// <summary>
  /// A8.8.62 LDMIB: ldmib r1, {r2, r3}. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.62 LDMIB``() =
    let inputs =
      [ [ Gpr(1, 0x20000814u)
          Gpr(2, 0x2fec3e87u)
          Gpr(3, 0xff3a144fu)
          M(0, 0x3126ac99e85f7c06UL)
          M(8, 0xc37e96ca504ffd8cUL)
          M(16, 0x4bea083d8d0c8212UL)
          M(24, 0x586d75fd201cabb7UL)
          M(32, 0x8aa3f093b3770661UL)
          M(40, 0x07c6acaa0549a9edUL)
          M(48, 0x272bfb4058ea97c3UL)
          M(56, 0x954f6e08b5d4addaUL) ]
        [ Gpr(1, 0x20000814u)
          Gpr(2, 0xc0d348c2u)
          Gpr(3, 0x5fd921bdu)
          M(0, 0x3900e8215fdfa943UL)
          M(8, 0x7bc5cd08a9876666UL)
          M(16, 0x1ee5fddad9c654bfUL)
          M(24, 0xd7913351a7de87b1UL)
          M(32, 0xe3ad285f7232e362UL)
          M(40, 0x943ad20628a8d4acUL)
          M(48, 0xd1f40e4979af5396UL)
          M(56, 0x0cf2f16e5a32f5fdUL) ]
        [ Gpr(1, 0x20000814u)
          Gpr(2, 0x00000000u)
          Gpr(3, 0x80007fffu)
          M(0, 0x6bad15c9586d7073UL)
          M(8, 0x21fa406cac0bcedcUL)
          M(16, 0x87107521624b8671UL)
          M(24, 0x84a97f3bfb5bfea3UL)
          M(32, 0x331901464f18b4deUL)
          M(40, 0xa832f34d6e4d7770UL)
          M(48, 0x941b9e416547bb42UL)
          M(56, 0xbf4487ca7675e946UL) ] ]
    let outputs =
      [ [ Gpr(2, 0x201cabb7u); Gpr(3, 0x586d75fdu) ]
        [ Gpr(2, 0xa7de87b1u); Gpr(3, 0xd7913351u) ]
        [ Gpr(2, 0xfb5bfea3u); Gpr(3, 0x84a97f3bu) ] ]
    check false "e991000c" inputs outputs

  /// <summary>
  /// A8.8.63 LDR: ldr r0, [r1, #16]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.63 LDR``() =
    let inputs =
      [ [ Gpr(0, 0x04bd2e00u)
          Gpr(1, 0x20000800u)
          M(0, 0x8689c7c835fbd53dUL)
          M(8, 0x21fb1579ff1e6a54UL)
          M(16, 0xf921a829847e8183UL)
          M(24, 0x907df7bd430037b6UL)
          M(32, 0x23316a10c3edf8fdUL)
          M(40, 0xa414d6162d701b0aUL)
          M(48, 0xce7589bd84a086ffUL)
          M(56, 0x77ccdc9460479ffdUL) ]
        [ Gpr(0, 0x5ea4f477u)
          Gpr(1, 0x20000800u)
          M(0, 0x933ffeb11b4b5d5bUL)
          M(8, 0x047dc1c73cc753bdUL)
          M(16, 0x3b738ed706309ebbUL)
          M(24, 0x0555c461fc76f264UL)
          M(32, 0x3cb545c5eb3f8dcdUL)
          M(40, 0xa950d2a2eec57dc4UL)
          M(48, 0x1e8584f1743e0597UL)
          M(56, 0x55dbd2eaeeac5a74UL) ]
        [ Gpr(0, 0x00000001u)
          Gpr(1, 0x20000800u)
          M(0, 0xf13e828cb5dc1ba9UL)
          M(8, 0xc5bd485e85bec730UL)
          M(16, 0xc17dcd59b04e3a25UL)
          M(24, 0x32de44a2e51b247cUL)
          M(32, 0xa4a71a5877e06a80UL)
          M(40, 0x76dbba6404b63589UL)
          M(48, 0xffd7d33ec1889273UL)
          M(56, 0x1dbbff83afed1af7UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x847e8183u) ]
        [ Gpr(0, 0x06309ebbu) ]
        [ Gpr(0, 0xb04e3a25u) ] ]
    check false "e5910010" inputs outputs

  /// <summary>
  /// A8.8.68 LDRB: ldrb r0, [r1, #3]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.68 LDRB``() =
    let inputs =
      [ [ Gpr(0, 0x1cccd6e0u)
          Gpr(1, 0x2000080du)
          M(0, 0xf4d54c7bff247718UL)
          M(8, 0x624c1a7a4d3187bbUL)
          M(16, 0xce7d3d9d9a1f76e8UL)
          M(24, 0x812bcb1587ef5c1cUL)
          M(32, 0xf83e8aea900ac0f3UL)
          M(40, 0x8f5da4549ee3529dUL)
          M(48, 0xa3136681e097aa10UL)
          M(56, 0x840789a98e1cdd7cUL) ]
        [ Gpr(0, 0xe9f96710u)
          Gpr(1, 0x2000080du)
          M(0, 0x87be41d9aee6a283UL)
          M(8, 0xb0039419601899a9UL)
          M(16, 0xac108e274ee6c2b0UL)
          M(24, 0x4697ac42bedc66d2UL)
          M(32, 0x41fbe5c5b562028dUL)
          M(40, 0x85e956ab8d3198fcUL)
          M(48, 0x09ae4fd7dbd832a6UL)
          M(56, 0x6afdc9a714610ce2UL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x2000080du)
          M(0, 0x70d57d8fe0cad224UL)
          M(8, 0xf2cabb38356c6730UL)
          M(16, 0x63f21f9654753738UL)
          M(24, 0x9f58cc9a8946a1a0UL)
          M(32, 0xb52170f6ef06f063UL)
          M(40, 0xe98db227d68d1b5eUL)
          M(48, 0x217ca53fcdaae8f5UL)
          M(56, 0x702b529a3cf512fdUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x000000e8u) ]
        [ Gpr(0, 0x000000b0u) ]
        [ Gpr(0, 0x00000038u) ] ]
    check false "e5d10003" inputs outputs

  /// <summary>
  /// A8.8.72 LDRBT: ldrbt r0, [r1], #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.72 LDRBT``() =
    let inputs =
      [ [ Gpr(0, 0x3999396eu)
          Gpr(1, 0x20000810u)
          M(0, 0x88d3d2693a5d1f51UL)
          M(8, 0xe1e70c3a2ce2121fUL)
          M(16, 0x195ef490da4a1496UL)
          M(24, 0x04724b9327eaeb4bUL)
          M(32, 0x14bad4c91a3f4270UL)
          M(40, 0x6fa532b2bf7d772aUL)
          M(48, 0x9085a979c94bb7e6UL)
          M(56, 0x3d8c2ea07b7d9067UL) ]
        [ Gpr(0, 0x657aa484u)
          Gpr(1, 0x20000810u)
          M(0, 0x10d07e559025ef7aUL)
          M(8, 0xd2e7a19903831534UL)
          M(16, 0xde6736f480835285UL)
          M(24, 0xdccc5bb678e14446UL)
          M(32, 0x11a1f67ee6a95e5dUL)
          M(40, 0x954f66df5d181b61UL)
          M(48, 0x3f8ea2eb6aab3701UL)
          M(56, 0xe6668c4cd1cc1df5UL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000810u)
          M(0, 0x5423f3028f380715UL)
          M(8, 0x12de2bddb40a9721UL)
          M(16, 0xf61840217466f4e4UL)
          M(24, 0x2b0cb0001e13d205UL)
          M(32, 0xde42d5d2ff19e263UL)
          M(40, 0xe2a4d290b795c6f5UL)
          M(48, 0xde3ee721511c61a5UL)
          M(56, 0x94119308b89d8c99UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000096u); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0x00000085u); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0x000000e4u); Gpr(1, 0x20000810u) ] ]
    check false "e4f10000" inputs outputs

  /// <summary>
  /// A8.8.73 LDRD: ldrd r2, [r1, #8]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.73 LDRD``() =
    let inputs =
      [ [ Gpr(1, 0x20000808u)
          Gpr(2, 0x4984ac2du)
          Gpr(3, 0xff49f626u)
          M(0, 0x610ae07dc1483933UL)
          M(8, 0x52a5b2f270622f94UL)
          M(16, 0xa3ffa68170b501dfUL)
          M(24, 0xae0b65c20768c1daUL)
          M(32, 0x5a5f91d827e8a1e4UL)
          M(40, 0xe9b2c3b3ae6e3997UL)
          M(48, 0x96c4d41237b92d27UL)
          M(56, 0x4ada33b99512f8b8UL) ]
        [ Gpr(1, 0x20000808u)
          Gpr(2, 0x9a4df448u)
          Gpr(3, 0x998d863au)
          M(0, 0x3e7e241972643271UL)
          M(8, 0x7576aac7f4391a56UL)
          M(16, 0x078448a1f6810c56UL)
          M(24, 0x942c196cb6cd21aaUL)
          M(32, 0x598fa67639bec77aUL)
          M(40, 0xa071082451bc6449UL)
          M(48, 0x053014e749f1d92cUL)
          M(56, 0x327e6a3433969ebdUL) ]
        [ Gpr(1, 0x20000808u)
          Gpr(2, 0x7fff8000u)
          Gpr(3, 0x00000000u)
          M(0, 0x6eca43b10d2766c0UL)
          M(8, 0x785904bc24b28df1UL)
          M(16, 0xd72d918d81383fecUL)
          M(24, 0x162167fe720fe1ccUL)
          M(32, 0xac28432f6e00ed3fUL)
          M(40, 0x01d790a5bdfdf325UL)
          M(48, 0x74d5dcc2e751dd87UL)
          M(56, 0x19e2436052be505fUL) ] ]
    let outputs =
      [ [ Gpr(2, 0x70b501dfu); Gpr(3, 0xa3ffa681u) ]
        [ Gpr(2, 0xf6810c56u); Gpr(3, 0x078448a1u) ]
        [ Gpr(2, 0x81383fecu); Gpr(3, 0xd72d918du) ] ]
    check false "e1c120d8" inputs outputs

  /// <summary>
  /// A8.8.76 LDREX: ldrex r0, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.76 LDREX``() =
    let inputs =
      [ [ Gpr(0, 0x86a0ff5du)
          Gpr(1, 0x20000810u)
          M(0, 0xa49f9c2a7378cba7UL)
          M(8, 0x4418aefe37907debUL)
          M(16, 0xc62ec65fff5727c7UL)
          M(24, 0x9c0bdeb95ec4f3a6UL)
          M(32, 0x9b058465748808edUL)
          M(40, 0x9c9e90360bd3e22eUL)
          M(48, 0x57c37ac7b9fb3cfaUL)
          M(56, 0xb4598f41d2839c94UL) ]
        [ Gpr(0, 0x436d2684u)
          Gpr(1, 0x20000810u)
          M(0, 0x6efcffae455c9da8UL)
          M(8, 0x4bd4525bdee03ce6UL)
          M(16, 0xdfe8e00a80fea8faUL)
          M(24, 0xff610aacdc24eabbUL)
          M(32, 0x16602b15dbfb83b6UL)
          M(40, 0x5356ea201b4dbfc8UL)
          M(48, 0x071e459d06bd7c9dUL)
          M(56, 0x5dc17afa270b58d3UL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000810u)
          M(0, 0xddddddd82d003151UL)
          M(8, 0x4fb0eed07e7b3c2eUL)
          M(16, 0x1fc0d2a6c1c66032UL)
          M(24, 0x3c3811ff2aa6c78fUL)
          M(32, 0xd80fe55aa3edbc82UL)
          M(40, 0xf99dfe5b6c2c9dc9UL)
          M(48, 0x1501b6e8eaf8355cUL)
          M(56, 0x692a16ffd70afee3UL) ] ]
    let outputs =
      [ [ Gpr(0, 0xff5727c7u) ]
        [ Gpr(0, 0x80fea8fau) ]
        [ Gpr(0, 0xc1c66032u) ] ]
    check false "e1910f9f" inputs outputs

  /// <summary>
  /// A8.8.77 LDREXB: ldrexb r0, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.77 LDREXB``() =
    let inputs =
      [ [ Gpr(0, 0x2f1241e4u)
          Gpr(1, 0x20000810u)
          M(0, 0xfdfe8c9b3166df0cUL)
          M(8, 0xa319c63ed1d4c115UL)
          M(16, 0x1a6170a6fabf85d7UL)
          M(24, 0x7a38e76b550b1adeUL)
          M(32, 0xe9c04654e4fcb76fUL)
          M(40, 0x45de861b496a492cUL)
          M(48, 0x844e11d0be70f405UL)
          M(56, 0x86ab9dbc32b6ba08UL) ]
        [ Gpr(0, 0x896c2345u)
          Gpr(1, 0x20000810u)
          M(0, 0x5fc42983fd7341c5UL)
          M(8, 0x412185914cd13ae8UL)
          M(16, 0x3e5289f451595979UL)
          M(24, 0xc6f8f739d2037661UL)
          M(32, 0xf72d85aee5c584ffUL)
          M(40, 0x6d7a4c7fb913bd0cUL)
          M(48, 0xd23f641a92a250a0UL)
          M(56, 0xb7f8a02a4f677b5bUL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          M(0, 0xc14906c5e513f6d5UL)
          M(8, 0x993a86dc74434eccUL)
          M(16, 0xaba83205a57a7603UL)
          M(24, 0x12f5a3863658f9ddUL)
          M(32, 0x9e5e60eebad8e0b0UL)
          M(40, 0xaaca678119f6ac18UL)
          M(48, 0x6ab16a14fedc6b75UL)
          M(56, 0x5df040510bee62e6UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x000000d7u) ]
        [ Gpr(0, 0x00000079u) ]
        [ Gpr(0, 0x00000003u) ] ]
    check false "e1d10f9f" inputs outputs

  /// <summary>
  /// A8.8.78 LDREXD: ldrexd r0, r1, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.78 LDREXD``() =
    let inputs =
      [ [ Gpr(0, 0x03c3746cu)
          Gpr(1, 0x20000810u)
          M(0, 0x0ea25c347938ff83UL)
          M(8, 0x73d9e8adab118f1dUL)
          M(16, 0xe195001548643fe1UL)
          M(24, 0x98c2260e2afd08c7UL)
          M(32, 0xf62eb49d49de2eaaUL)
          M(40, 0xd937716b09ffb51aUL)
          M(48, 0x804ae97321ede4fdUL)
          M(56, 0xf21acad8b58d57f6UL) ]
        [ Gpr(0, 0x991abe20u)
          Gpr(1, 0x20000810u)
          M(0, 0xf5ebb1f73cdb6872UL)
          M(8, 0x4a09021b81cabb73UL)
          M(16, 0x12118163298b861bUL)
          M(24, 0xbea786f6de51993dUL)
          M(32, 0x3a34e0cce850457eUL)
          M(40, 0x188a6781fa0e0d38UL)
          M(48, 0x1a39527d9c225ea9UL)
          M(56, 0x929cb001941f147cUL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          M(0, 0x763e7a3a463458e4UL)
          M(8, 0xe1cb9153b3f43e4dUL)
          M(16, 0xc4a96013cb774e4bUL)
          M(24, 0xd4fb436cc92da1aeUL)
          M(32, 0x4ab4ae2db1325d29UL)
          M(40, 0x82f28d761fe8864dUL)
          M(48, 0x5b0a3bc48f31640fUL)
          M(56, 0xc02fbd4faa7e405fUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x48643fe1u); Gpr(1, 0xe1950015u) ]
        [ Gpr(0, 0x298b861bu); Gpr(1, 0x12118163u) ]
        [ Gpr(0, 0xcb774e4bu); Gpr(1, 0xc4a96013u) ] ]
    check false "e1b10f9f" inputs outputs

  /// <summary>
  /// A8.8.79 LDREXH: ldrexh r0, [r1]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.79 LDREXH``() =
    let inputs =
      [ [ Gpr(0, 0x4031bf2eu)
          Gpr(1, 0x20000810u)
          M(0, 0x0e221378efa81fe7UL)
          M(8, 0x864fc5ee6404e96fUL)
          M(16, 0x59be87309e963537UL)
          M(24, 0x62dcec3e9ea4d644UL)
          M(32, 0xec7e2e3c096fb341UL)
          M(40, 0x9bff0fd4297dc0a6UL)
          M(48, 0x75aaa9df2143a29bUL)
          M(56, 0xc5f13c38d6070ddbUL) ]
        [ Gpr(0, 0xbe48ff61u)
          Gpr(1, 0x20000810u)
          M(0, 0x6f29321612335bf2UL)
          M(8, 0xc186dd79666b6b5dUL)
          M(16, 0x8c848a2a76de5a97UL)
          M(24, 0xd4fd9a2119235d88UL)
          M(32, 0x5065f4cad5d0355bUL)
          M(40, 0xd02529b1ffb1c241UL)
          M(48, 0x09992f7f5c1e310aUL)
          M(56, 0xf8e31e87ab096925UL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          M(0, 0xed1d1ee57dbd279dUL)
          M(8, 0xc9846d213a41ba64UL)
          M(16, 0x8c33f28f4790f36eUL)
          M(24, 0xc686bd39bc957846UL)
          M(32, 0x96bf00e41f4f94a5UL)
          M(40, 0x55762c519a6f44a1UL)
          M(48, 0x873c4d499d10b72dUL)
          M(56, 0xb5485ada73066d54UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00003537u) ]
        [ Gpr(0, 0x00005a97u) ]
        [ Gpr(0, 0x0000f36eu) ] ]
    check false "e1f10f9f" inputs outputs

  /// <summary>
  /// A8.8.80 LDRH: ldrh r0, [r1, #16]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.80 LDRH``() =
    let inputs =
      [ [ Gpr(0, 0xbf9c9227u)
          Gpr(1, 0x20000800u)
          M(0, 0x6f45c34ade7c3dfcUL)
          M(8, 0x68c7303c1a4330a9UL)
          M(16, 0xfe1f52bbcc51f04aUL)
          M(24, 0x13388208ad91a066UL)
          M(32, 0x257c9ee9c05fd720UL)
          M(40, 0xe6b9ce50b1a61470UL)
          M(48, 0xe731074be8c3793cUL)
          M(56, 0x2114da5021b1a3eeUL) ]
        [ Gpr(0, 0xd228a9a1u)
          Gpr(1, 0x20000800u)
          M(0, 0x86ec73d85e2fc15bUL)
          M(8, 0x7629d89e9fbe0dccUL)
          M(16, 0xcccbb18ce743c6ffUL)
          M(24, 0x1ebd517f73d2676fUL)
          M(32, 0x750bb0a033c6e495UL)
          M(40, 0x3302be62c0164731UL)
          M(48, 0x094c9e75b7384de9UL)
          M(56, 0x76eaa254ac5cef7bUL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000800u)
          M(0, 0x02345517d452bda5UL)
          M(8, 0x3bb56cb123cc198fUL)
          M(16, 0x631429e53103683fUL)
          M(24, 0x49bfd15f982ac691UL)
          M(32, 0xe2a93fddef792cdbUL)
          M(40, 0x3c1c101535fa8aebUL)
          M(48, 0x4643071eae19014eUL)
          M(56, 0x4ecd2f380ae21dbdUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x0000f04au) ]
        [ Gpr(0, 0x0000c6ffu) ]
        [ Gpr(0, 0x0000683fu) ] ]
    check false "e1d101b0" inputs outputs

  /// <summary>
  /// A8.8.84 LDRHT: ldrht r0, [r1], #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.84 LDRHT``() =
    let inputs =
      [ [ Gpr(0, 0x569a327bu)
          Gpr(1, 0x20000810u)
          M(0, 0x9bb11245c0227cd2UL)
          M(8, 0x65e3423a28c3e341UL)
          M(16, 0x5b97015d4b17224dUL)
          M(24, 0x3170c5b768dce70fUL)
          M(32, 0xb1756625089fbdacUL)
          M(40, 0xeccb741318be5520UL)
          M(48, 0xa5097fc31de95b0fUL)
          M(56, 0x5dfd287430d273f3UL) ]
        [ Gpr(0, 0x139054e3u)
          Gpr(1, 0x20000810u)
          M(0, 0x778dcd5ae0ca0b4bUL)
          M(8, 0x888430fbae22e14dUL)
          M(16, 0x0d3d8d6c97e20ad7UL)
          M(24, 0x315134998e13fc8eUL)
          M(32, 0x30388ad657005a24UL)
          M(40, 0x20ef8383c631e87bUL)
          M(48, 0x9a8d8bcb8968df79UL)
          M(56, 0xe2b6f8b5c6208c53UL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000810u)
          M(0, 0xf33a0d586fe00b63UL)
          M(8, 0x8b1fda7042a32b7aUL)
          M(16, 0xc926a0dc0e7afe71UL)
          M(24, 0x739a669833cc61cdUL)
          M(32, 0x60f6a49f692cd89eUL)
          M(40, 0x1574a6430b62bfc8UL)
          M(48, 0xd1f0c4a4591da64fUL)
          M(56, 0x192c0433ab006eddUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x0000224du); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0x00000ad7u); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0x0000fe71u); Gpr(1, 0x20000810u) ] ]
    check false "e0f100b0" inputs outputs

  /// <summary>
  /// A8.8.85 LDRSB: ldrsb r0, [r1, #7]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.85 LDRSB``() =
    let inputs =
      [ [ Gpr(0, 0xc056ea76u)
          Gpr(1, 0x20000809u)
          M(0, 0x6c3e384f7e82e617UL)
          M(8, 0x89528d2cc01e9544UL)
          M(16, 0x6bf3d1be88d36dc4UL)
          M(24, 0x44ce3b61646e6e3cUL)
          M(32, 0x438b52a4d241b5ecUL)
          M(40, 0xc99a8062506cceb5UL)
          M(48, 0x53e6e32da13a6ce3UL)
          M(56, 0xe075d1f9aabafdceUL) ]
        [ Gpr(0, 0xf2b1faa1u)
          Gpr(1, 0x20000809u)
          M(0, 0xc929cd2131c4cbe1UL)
          M(8, 0xd38fc3ff35cc6356UL)
          M(16, 0x1d0057ea83646cc0UL)
          M(24, 0xb0b59d8800786f6fUL)
          M(32, 0x641c521994b39e82UL)
          M(40, 0x82b23b24c804e88dUL)
          M(48, 0xa555f0aa7d3a4bf0UL)
          M(56, 0xc1c20b8eb5b2a73aUL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x20000809u)
          M(0, 0xde9630c43abeb143UL)
          M(8, 0xf2ec2235eadbb148UL)
          M(16, 0x0de10dba99c28fe1UL)
          M(24, 0xc0216afa16183631UL)
          M(32, 0x4271cb09ca4f2d3fUL)
          M(40, 0x284279c1af2cc434UL)
          M(48, 0x28542e008ee1f1b8UL)
          M(56, 0xbf9a2ff4df575f37UL) ] ]
    let outputs =
      [ [ Gpr(0, 0xffffffc4u) ]
        [ Gpr(0, 0xffffffc0u) ]
        [ Gpr(0, 0xffffffe1u) ] ]
    check false "e1d100d7" inputs outputs

  /// <summary>
  /// A8.8.88 LDRSBT: ldrsbt r0, [r1], #0x0. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.88 LDRSBT``() =
    let inputs =
      [ [ Gpr(0, 0x21791b37u)
          Gpr(1, 0x20000810u)
          M(0, 0x97e6e0b267adfc3bUL)
          M(8, 0x40357af517e786f4UL)
          M(16, 0x067ccdc517fa9861UL)
          M(24, 0x42c4a0c9815f6868UL)
          M(32, 0x5b83c7364f28d313UL)
          M(40, 0x6b30a308beaa916dUL)
          M(48, 0xb05b7212e727c7c0UL)
          M(56, 0x20c85bb0bc3d8f3bUL) ]
        [ Gpr(0, 0xa6de0565u)
          Gpr(1, 0x20000810u)
          M(0, 0xaac502aa14708f8cUL)
          M(8, 0x3c628e865aebca1cUL)
          M(16, 0x97b414b2ce641ccaUL)
          M(24, 0xd8205218aa89f54aUL)
          M(32, 0x2601aec6b7201fe5UL)
          M(40, 0x29cfb830720a8570UL)
          M(48, 0xebea3f4426e00329UL)
          M(56, 0x18d0179347426f97UL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          M(0, 0x3476575a353364adUL)
          M(8, 0x71e3ac63ed214c7fUL)
          M(16, 0x4bae8c97c3e1f48bUL)
          M(24, 0x9c7cd85182080b63UL)
          M(32, 0xfe60a2a891bbe896UL)
          M(40, 0x0561267058e6bfbaUL)
          M(48, 0x17974e14ee44b736UL)
          M(56, 0x22b935599f77365fUL) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000061u); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0xffffffcau); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0xffffff8bu); Gpr(1, 0x20000810u) ] ]
    check false "e0f100d0" inputs outputs

  /// <summary>
  /// A8.8.89 LDRSH: ldrsh r0, [r1, #6]. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.89 LDRSH``() =
    let inputs =
      [ [ Gpr(0, 0xb16b483cu)
          Gpr(1, 0x2000080au)
          M(0, 0x72719f501cded2ffUL)
          M(8, 0xee8b0a754406e09eUL)
          M(16, 0x4efba9562174c884UL)
          M(24, 0xcf1bd535af83342dUL)
          M(32, 0x33cf2e5d47f57600UL)
          M(40, 0x10db5e643dba5662UL)
          M(48, 0x1f8a645e307a1290UL)
          M(56, 0xf4a007288a1688adUL) ]
        [ Gpr(0, 0x1fb3c91eu)
          Gpr(1, 0x2000080au)
          M(0, 0x5b1743d665468afaUL)
          M(8, 0xcadd6a5e6533ea08UL)
          M(16, 0x742ebfc86efe9345UL)
          M(24, 0x3f512b95fed3af5aUL)
          M(32, 0x9987dd55155505c4UL)
          M(40, 0xe9c1e1101fac69c8UL)
          M(48, 0x4a77170f76983eb3UL)
          M(56, 0x02fc96b8fc26b394UL) ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x2000080au)
          M(0, 0x2329339ce06b1041UL)
          M(8, 0x9b73ea764f8e6923UL)
          M(16, 0x2d81b18782861de7UL)
          M(24, 0xb9377ede6678d0c8UL)
          M(32, 0x47985e0714ffd7a7UL)
          M(40, 0xb287143925cdb829UL)
          M(48, 0xac01365a5259a05cUL)
          M(56, 0x6c6dc8c76749b757UL) ] ]
    let outputs =
      [ [ Gpr(0, 0xffffc884u) ]
        [ Gpr(0, 0xffff9345u) ]
        [ Gpr(0, 0x00001de7u) ] ]
    check false "e1d100f6" inputs outputs

  /// <summary>
  /// A8.8.92 LDRSHT: ldrsht r0, [r1], #0x0. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.92 LDRSHT``() =
    let inputs =
      [ [ Gpr(0, 0xdf9b2810u)
          Gpr(1, 0x20000810u)
          M(0, 0xae49ef172f0d67acUL)
          M(8, 0xbf54ea3255ae5e12UL)
          M(16, 0x99f291ee1e6a28c2UL)
          M(24, 0xb929c74f35b3774fUL)
          M(32, 0xd711f6d302838b94UL)
          M(40, 0xf6867e1fd5289454UL)
          M(48, 0xbd9dbb83ad9aec5bUL)
          M(56, 0xef528ac443b07b09UL) ]
        [ Gpr(0, 0xa2a5c122u)
          Gpr(1, 0x20000810u)
          M(0, 0x1fe3782f79937bacUL)
          M(8, 0x0a0207782760ab07UL)
          M(16, 0xf01811283f759d81UL)
          M(24, 0x0b74a2b629db1b2eUL)
          M(32, 0x96dc13bae138241bUL)
          M(40, 0xe2baf4c24c0ebc6eUL)
          M(48, 0xce875e9be0fa700aUL)
          M(56, 0x7c4c0eaeed832bf0UL) ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x20000810u)
          M(0, 0x43ba1eed34c2eed2UL)
          M(8, 0x92f4f5d7c4f6f6f8UL)
          M(16, 0x0b718f49ad20c910UL)
          M(24, 0x289c7df50d1414f8UL)
          M(32, 0xef117f0c5e6e8221UL)
          M(40, 0xb4a7f85d78a2651aUL)
          M(48, 0xeb3a5f47b86970afUL)
          M(56, 0xa7d6b159cdfa4c46UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x000028c2u); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0xffff9d81u); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0xffffc910u); Gpr(1, 0x20000810u) ] ]
    check false "e0f100f0" inputs outputs

  /// <summary>
  /// A8.8.93 LDRT: ldrt r0, [r1], #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.93 LDRT``() =
    let inputs =
      [ [ Gpr(0, 0x6cb2eb70u)
          Gpr(1, 0x20000810u)
          M(0, 0x91ec17dbbd487959UL)
          M(8, 0x7a9981c9fc36fe68UL)
          M(16, 0x718f6265837fb45dUL)
          M(24, 0x0795f46c47771214UL)
          M(32, 0x69da38b53a0a72b9UL)
          M(40, 0x0d926178c0c4f5c5UL)
          M(48, 0xea1504481c2874e5UL)
          M(56, 0x0dfc288c835698bfUL) ]
        [ Gpr(0, 0xc4c28f98u)
          Gpr(1, 0x20000810u)
          M(0, 0x26d40126f3a17251UL)
          M(8, 0xab0aa646fadb1efbUL)
          M(16, 0x5b4c03c3c3a61a0fUL)
          M(24, 0xafaaec3f28d0ca73UL)
          M(32, 0xe89af24157eb37c3UL)
          M(40, 0x2ced84f80cb93fc8UL)
          M(48, 0xf1bba0724b8ee208UL)
          M(56, 0xf0f4a9ed718fe7e3UL) ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x20000810u)
          M(0, 0xa0fcd111e85cf69dUL)
          M(8, 0x206ffcd1d6e15be2UL)
          M(16, 0xb9e3b4ca08c77b68UL)
          M(24, 0x955b393e7d223ccdUL)
          M(32, 0x44461d87ec744b91UL)
          M(40, 0x858a3114f1e0b480UL)
          M(48, 0x11ffc6f20ac97ac8UL)
          M(56, 0xab217bd0fb01dfc5UL) ] ]
    let outputs =
      [ [ Gpr(0, 0x837fb45du); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0xc3a61a0fu); Gpr(1, 0x20000810u) ]
        [ Gpr(0, 0x08c77b68u); Gpr(1, 0x20000810u) ] ]
    check false "e4b10000" inputs outputs

  /// <summary>
  /// A8.8.94 LEAVEX: .inst 0xf3bf8f0f. This checks that it takes the Undefined
  /// Instruction exception. It is not a value test because it belongs to
  /// ThumbEE, which no QEMU model implements.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.94 LEAVEX``() =
    let run = runWith true "f3bf8f0f" [ CPSR 0x10u ] []
    Assert.AreEqual(Some SideEffect.UndefinedInstruction, run.Effect)

  /// <summary>
  /// A8.8.95 LSL: lsl r0, r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.95 LSL``() =
    let inputs =
      [ [ Gpr(0, 0xb6b64876u); Gpr(2, 0xdbcf9404u) ]
        [ Gpr(0, 0xf1800aa7u); Gpr(2, 0xa6861ff0u) ]
        [ Gpr(0, 0x00000001u); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x6b648760u) ]
        [ Gpr(0, 0x00000000u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1a00210" inputs outputs

  /// <summary>
  /// A8.8.97 LSR: lsr r0, r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.97 LSR``() =
    let inputs =
      [ [ Gpr(0, 0x0e1478a8u); Gpr(2, 0x6c56ce6au) ]
        [ Gpr(0, 0xf49bc22bu); Gpr(2, 0x8c85c5bdu) ]
        [ Gpr(0, 0x00000001u); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000000u) ]
        [ Gpr(0, 0x00000000u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1a00230" inputs outputs

  /// <summary>
  /// A8.8.99 MCR: mcr p15, #0x0, r0, c1, c0, #0x0. This checks that User mode
  /// refuses it and that Supervisor mode writes Rt to SCTLR. It is not a value
  /// test because it reaches a coprocessor, which a user-mode run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.99 MCR``() =
    let cells = [ Gpr(0, 0x00c5187du); CPSR 0x13u ]
    let run = runWith false "ee010f10" cells []
    let refused = refusedModes false "ee010f10" [] []
    CollectionAssert.AreEqual([| 0x10u |], refused)
    Assert.AreEqual(0x00c5187du, run.Reg Register.SCTLR)

  /// <summary>
  /// A8.8.99 MCR2: mcr2 7, 1, r0, cr1, cr2, {4}. This checks that the lift says
  /// the instruction is unsupported: coprocessor 7 is none this front end
  /// models. It is not a value test because it reaches a coprocessor, which a
  /// user-mode run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.99 MCR2``() =
    let run = runWith false "fe210792" [ CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.100 MCRR: mcrr 7, 1, r0, r1, cr2. This checks that the lift says the
  /// instruction is unsupported: coprocessor 7 is none this front end models.
  /// It is not a value test because it reaches a coprocessor, which a user-mode
  /// run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.100 MCRR``() =
    let run = runWith false "ec410712" [ CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.100 MCRR2: mcrr2 7, 1, r0, r1, cr2. This checks that the lift says
  /// the instruction is unsupported: coprocessor 7 is none this front end
  /// models. It is not a value test because it reaches a coprocessor, which a
  /// user-mode run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.100 MCRR2``() =
    let run = runWith false "fc410712" [ CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.101 MLA: mla r0, r1, r2, r3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.101 MLA``() =
    let inputs =
      [ [ Gpr(0, 0x8fd94f76u)
          Gpr(1, 0x90733e54u)
          Gpr(2, 0x70cfced5u)
          Gpr(3, 0xb118c1b4u) ]
        [ Gpr(0, 0x8ae29ec9u)
          Gpr(1, 0x7b522254u)
          Gpr(2, 0xa7beace8u)
          Gpr(3, 0xa80fdc3cu) ]
        [ Gpr(0, 0x00000001u)
          Gpr(1, 0x0000ffffu)
          Gpr(2, 0x00008000u)
          Gpr(3, 0x7fff8000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xc30f3598u) ]
        [ Gpr(0, 0xdfe7685cu) ]
        [ Gpr(0, 0xffff0000u) ] ]
    check false "e0203291" inputs outputs

  /// <summary>
  /// A8.8.102 MLS: mls r0, r1, r2, r3. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.102 MLS``() =
    let inputs =
      [ [ Gpr(0, 0x74663e7cu)
          Gpr(1, 0xa2023a81u)
          Gpr(2, 0xd721b901u)
          Gpr(3, 0x91937feeu) ]
        [ Gpr(0, 0x566bf270u)
          Gpr(1, 0x96c6816eu)
          Gpr(2, 0xfcd6a92du)
          Gpr(3, 0x2244405eu) ]
        [ Gpr(0, 0x00000001u)
          Gpr(1, 0x0000ffffu)
          Gpr(2, 0x00008000u)
          Gpr(3, 0x7fff8000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x71a90c6du) ]
        [ Gpr(0, 0x1bf9e208u) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e0603291" inputs outputs

  /// <summary>
  /// A8.8.103 MOV: mov r0, #0x3. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.103 MOV``() =
    let inputs =
      [ [ Gpr(0, 0x7f469402u) ]
        [ Gpr(0, 0xa97e757eu) ]
        [ Gpr(0, 0x00000001u) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000003u) ]
        [ Gpr(0, 0x00000003u) ]
        [ Gpr(0, 0x00000003u) ] ]
    check false "e3a00003" inputs outputs

  /// <summary>
  /// A8.8.107 MOVT: movt r0, #0x7. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.107 MOVT``() =
    let inputs =
      [ [ Gpr(0, 0x8871760du) ]
        [ Gpr(0, 0x2bd0ad71u) ]
        [ Gpr(0, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x0007760du) ]
        [ Gpr(0, 0x0007ad71u) ]
        [ Gpr(0, 0x0007ffffu) ] ]
    check false "e3400007" inputs outputs

  /// <summary>
  /// A8.8.108 MRC: mrc p15, #0x0, r0, c1, c0, #0x0. This checks that User mode
  /// refuses it and that Supervisor mode reads SCTLR into Rt. It is not a value
  /// test because it reaches a coprocessor, which a user-mode run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.108 MRC``() =
    let sctlr = [ Register.SCTLR, 0x00c5187du ]
    let run = runWith false "ee110f10" [ CPSR 0x13u ] sctlr
    let refused = refusedModes false "ee110f10" [] sctlr
    CollectionAssert.AreEqual([| 0x10u |], refused)
    Assert.AreEqual(Gpr(0, 0x00c5187du), run.After(Gpr(0, 0u)))

  /// <summary>
  /// A8.8.108 MRC2: mrc2 7, 1, r0, cr1, cr2, {4}. This checks that the lift
  /// says the instruction is unsupported: coprocessor 7 is none this front end
  /// models. It is not a value test because it reaches a coprocessor, which a
  /// user-mode run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.108 MRC2``() =
    let run = runWith false "fe310792" [ CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.109 MRRC: mrrc 7, 1, r0, r1, cr2. This checks that the lift says the
  /// instruction is unsupported: coprocessor 7 is none this front end models.
  /// It is not a value test because it reaches a coprocessor, which a user-mode
  /// run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.109 MRRC``() =
    let run = runWith false "ec510712" [ CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.109 MRRC2: mrrc2 7, 1, r0, r1, cr2. This checks that the lift says
  /// the instruction is unsupported: coprocessor 7 is none this front end
  /// models. It is not a value test because it reaches a coprocessor, which a
  /// user-mode run cannot.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.109 MRRC2``() =
    let run = runWith false "fc510712" [ CPSR 0x13u ] []
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

  /// <summary>
  /// A8.8.110 MRS: mrs r0, CPSR. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.110 MRS``() =
    let inputs =
      [ [ Gpr(0, 0xbc54ed89u); CPSR 0x20000010u ]
        [ Gpr(0, 0xfc686becu); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000001u); CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x20000010u) ]
        [ Gpr(0, 0x900a0010u) ]
        [ Gpr(0, 0x48050010u) ] ]
    check false "e10f0000" inputs outputs

  /// <summary>
  /// A8.8.112 MSR: msr CPSR_fs, r1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.112 MSR``() =
    let inputs =
      [ [ Gpr(1, 0x7f398e31u); CPSR 0x20000010u ]
        [ Gpr(1, 0x5023c4f0u); CPSR 0x900a0010u ]
        [ Gpr(1, 0x0000ffffu); CPSR 0x48050010u ] ]
    let outputs =
      [ [ CPSR 0x78090010u ]
        [ CPSR 0x50030010u ]
        [ CPSR 0x00000010u ] ]
    check false "e12cf001" inputs outputs

  /// <summary>
  /// A8.8.115 MUL: mul r0, r1, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.115 MUL``() =
    let inputs =
      [ [ Gpr(0, 0xdd744c85u); Gpr(1, 0x01daa50fu); Gpr(2, 0xac890f40u) ]
        [ Gpr(0, 0x59dfda8du); Gpr(1, 0xc5758aa0u); Gpr(2, 0x4ab943bdu) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xaf5c24c0u) ]
        [ Gpr(0, 0xf8af3820u) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e0000291" inputs outputs

  /// <summary>
  /// A8.8.116 MVN: mvn r0, #0x3fc. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.116 MVN``() =
    let inputs =
      [ [ Gpr(0, 0xd3fc2658u) ]
        [ Gpr(0, 0xd8849ca5u) ]
        [ Gpr(0, 0x00000001u) ] ]
    let outputs =
      [ [ Gpr(0, 0xfffffc03u) ]
        [ Gpr(0, 0xfffffc03u) ]
        [ Gpr(0, 0xfffffc03u) ] ]
    check false "e3e00fff" inputs outputs

  /// <summary>
  /// A8.8.119 NEG: rsb r0, r1, #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.119 NEG``() =
    let inputs =
      [ [ Gpr(0, 0x606650d9u); Gpr(1, 0x9eed76e8u) ]
        [ Gpr(0, 0xc129b95eu); Gpr(1, 0xedc4897bu) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x61128918u) ]
        [ Gpr(0, 0x123b7685u) ]
        [ Gpr(0, 0xffff0001u) ] ]
    check false "e2610000" inputs outputs

  /// <summary>
  /// A8.8.120 NOP: nop {0}. It lifts to no statements: what it does is a hint
  /// or an ordering of memory accesses that one run cannot observe, and QEMU's
  /// runs of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.120 NOP``() =
    Assert.AreEqual(0, (lift false "e320f000").Length)

  /// <summary>
  /// A8.8.121 ORN: orn r0, r1, #0x1. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.121 ORN``() =
    let inputs =
      [ [ Gpr(0, 0x7f6f1011u); Gpr(1, 0xc7baf5a6u) ]
        [ Gpr(0, 0x6b938619u); Gpr(1, 0x753d35aeu) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0xfffffffeu) ]
        [ Gpr(0, 0xfffffffeu) ]
        [ Gpr(0, 0xffffffffu) ] ]
    check true "f0610001" inputs outputs

  /// <summary>
  /// A8.8.123 ORR: orr r0, r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.123 ORR``() =
    let inputs =
      [ [ Gpr(0, 0xfba8736fu); Gpr(2, 0x5e059d95u) ]
        [ Gpr(0, 0xbe74fc54u); Gpr(2, 0x48dce66eu) ]
        [ Gpr(0, 0x00000001u); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xffadffffu) ]
        [ Gpr(0, 0xfefcfe7eu) ]
        [ Gpr(0, 0x00008001u) ] ]
    check false "e1800002" inputs outputs

  /// <summary>
  /// A8.8.126 PKH: pkhbt r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.126 PKH``() =
    let inputs =
      [ [ Gpr(0, 0x2fdd0430u); Gpr(1, 0x23ff1b3au); Gpr(2, 0x95f20b0au) ]
        [ Gpr(0, 0x62e2cf6du); Gpr(1, 0xea167f72u); Gpr(2, 0x56e1a4b2u) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x95f21b3au) ]
        [ Gpr(0, 0x56e17f72u) ]
        [ Gpr(0, 0x0000ffffu) ] ]
    check false "e6810012" inputs outputs

  /// <summary>
  /// A8.8.127 PLD: pld [r1, #7]. It lifts to no statements: what it does is a
  /// hint or an ordering of memory accesses that one run cannot observe, and
  /// QEMU's runs of it changed no register and no byte, so a value test would
  /// assert nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.127 PLD``() =
    Assert.AreEqual(0, (lift false "f5d1f007").Length)

  /// <summary>
  /// A8.8.127 PLDW: pldw [r1]. It lifts to no statements: what it does is a
  /// hint or an ordering of memory accesses that one run cannot observe, and
  /// QEMU's runs of it changed no register and no byte, so a value test would
  /// assert nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.127 PLDW``() =
    Assert.AreEqual(0, (lift false "f591f000").Length)

  /// <summary>
  /// A8.8.130 PLI: pli [r1, #7]. It lifts to no statements: what it does is a
  /// hint or an ordering of memory accesses that one run cannot observe, and
  /// QEMU's runs of it changed no register and no byte, so a value test would
  /// assert nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.130 PLI``() =
    Assert.AreEqual(0, (lift false "f4d1f007").Length)

  /// <summary>
  /// A8.8.132 POP: pop {r2, r3}. This checks that it loads R2 then R3 from SP
  /// and moves SP up by eight. It is not a value test because it moves SP,
  /// which the run itself stands on.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.132 POP``() =
    let w = uint32 Window
    let cells = [ M(16, 0x3333333322222222UL) ]
    let run = runWith false "e8bd000c" cells [ Register.SP, w + 16u ]
    Assert.AreEqual(Gpr(2, 0x22222222u), run.After(Gpr(2, 0u)))
    Assert.AreEqual(Gpr(3, 0x33333333u), run.After(Gpr(3, 0u)))
    Assert.AreEqual(w + 24u, run.Reg Register.SP)

  /// <summary>
  /// A8.8.134 PUSH: push {r2, r3}. This checks that it stores R2 then R3 below
  /// SP and moves SP down by eight. It is not a value test because it moves SP,
  /// which the run itself stands on.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.134 PUSH``() =
    let w = uint32 Window
    let cells = [ Gpr(2, 0x22222222u); Gpr(3, 0x33333333u); M(24, 0UL) ]
    let run = runWith false "e92d000c" cells [ Register.SP, w + 32u ]
    Assert.AreEqual(M(24, 0x3333333322222222UL), run.After(M(24, 0UL)))
    Assert.AreEqual(w + 24u, run.Reg Register.SP)

  /// <summary>
  /// A8.8.135 QADD: qadd r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.135 QADD``() =
    let inputs =
      [ [ Gpr(0, 0x95e3e24bu)
          Gpr(1, 0xe4ede70du)
          Gpr(2, 0x7db134deu)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x634ad02du)
          Gpr(1, 0x413a0e10u)
          Gpr(2, 0xdab58cbbu)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x629f1bebu); CPSR 0x20000010u ]
        [ Gpr(0, 0x1bef9acbu); CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fffffffu); CPSR 0x48050010u ] ]
    check false "e1020051" inputs outputs

  /// <summary>
  /// A8.8.136 QADD16: qadd16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.136 QADD16``() =
    let inputs =
      [ [ Gpr(0, 0x738cc871u); Gpr(1, 0xbea259a9u); Gpr(2, 0x95ee682au) ]
        [ Gpr(0, 0x1e30cb0bu); Gpr(1, 0x55fb2443u); Gpr(2, 0x5c39f1c0u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x80007fffu) ]
        [ Gpr(0, 0x7fff1603u) ]
        [ Gpr(0, 0x80007fffu) ] ]
    check false "e6210f12" inputs outputs

  /// <summary>
  /// A8.8.137 QADD8: qadd8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.137 QADD8``() =
    let inputs =
      [ [ Gpr(0, 0x6b3f9d24u); Gpr(1, 0xee69105bu); Gpr(2, 0x40522619u) ]
        [ Gpr(0, 0xdacacb05u); Gpr(1, 0x1eded8eeu); Gpr(2, 0xe8dfbca8u) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x2e7f3674u) ]
        [ Gpr(0, 0x06bd9496u) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e6210f92" inputs outputs

  /// <summary>
  /// A8.8.138 QASX: qasx r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.138 QASX``() =
    let inputs =
      [ [ Gpr(0, 0x32874adfu); Gpr(1, 0xee9dcaa7u); Gpr(2, 0xf3ae3443u) ]
        [ Gpr(0, 0x8821a092u); Gpr(1, 0x770c7135u); Gpr(2, 0xd6b6210cu) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); Gpr(2, 0x7fff8000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x22e0d6f9u) ]
        [ Gpr(0, 0x7fff7fffu) ]
        [ Gpr(0, 0x80008000u) ] ]
    check false "e6210f32" inputs outputs

  /// <summary>
  /// A8.8.139 QDADD: qdadd r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.139 QDADD``() =
    let inputs =
      [ [ Gpr(0, 0x68ff03f5u)
          Gpr(1, 0xd1da6683u)
          Gpr(2, 0x66e98107u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x62f18a4au)
          Gpr(1, 0x65243a93u)
          Gpr(2, 0xf26e6de3u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x51da6682u); CPSR 0x28000010u ]
        [ Gpr(0, 0x4a011659u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u); CPSR 0x48050010u ] ]
    check false "e1420051" inputs outputs

  /// <summary>
  /// A8.8.140 QDSUB: qdsub r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.140 QDSUB``() =
    let inputs =
      [ [ Gpr(0, 0x8096d00eu)
          Gpr(1, 0x121622cfu)
          Gpr(2, 0xac5a31ffu)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x413b8117u)
          Gpr(1, 0x16d4400cu)
          Gpr(2, 0x658004f3u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x7fffffffu); CPSR 0x28000010u ]
        [ Gpr(0, 0x96d4400du); CPSR 0x980a0010u ]
        [ Gpr(0, 0x7fff8000u); CPSR 0x48050010u ] ]
    check false "e1620051" inputs outputs

  /// <summary>
  /// A8.8.141 QSAX: qsax r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.141 QSAX``() =
    let inputs =
      [ [ Gpr(0, 0x24d437c1u); Gpr(1, 0x1eebe6b0u); Gpr(2, 0x61e06aedu) ]
        [ Gpr(0, 0x112434afu); Gpr(1, 0x81593ee7u); Gpr(2, 0x5549ad48u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); Gpr(2, 0x7fff8000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xb3fe4890u) ]
        [ Gpr(0, 0xd4117fffu) ]
        [ Gpr(0, 0x7fffffffu) ] ]
    check false "e6210f52" inputs outputs

  /// <summary>
  /// A8.8.142 QSUB: qsub r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.142 QSUB``() =
    let inputs =
      [ [ Gpr(0, 0x51534be8u)
          Gpr(1, 0x923d850fu)
          Gpr(2, 0xbf7d6334u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x73d852cau)
          Gpr(1, 0xeaf5ef3cu)
          Gpr(2, 0x62acccbau)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xd2c021dbu); CPSR 0x20000010u ]
        [ Gpr(0, 0x88492282u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x80010000u); CPSR 0x48050010u ] ]
    check false "e1220051" inputs outputs

  /// <summary>
  /// A8.8.143 QSUB16: qsub16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.143 QSUB16``() =
    let inputs =
      [ [ Gpr(0, 0xa5785c29u); Gpr(1, 0xe156bb86u); Gpr(2, 0x2489fc2du) ]
        [ Gpr(0, 0x804b2b20u); Gpr(1, 0xe84ba678u); Gpr(2, 0x1d82fef9u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0xbccdbf59u) ]
        [ Gpr(0, 0xcac9a77fu) ]
        [ Gpr(0, 0x7fff8001u) ] ]
    check false "e6210f72" inputs outputs

  /// <summary>
  /// A8.8.144 QSUB8: qsub8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.144 QSUB8``() =
    let inputs =
      [ [ Gpr(0, 0x1d6433c7u); Gpr(1, 0x8f27a4d7u); Gpr(2, 0x3e9595a2u) ]
        [ Gpr(0, 0x76302c9au); Gpr(1, 0x8857fb1eu); Gpr(2, 0xdb2d599eu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x807f0f35u) ]
        [ Gpr(0, 0xad2aa27fu) ]
        [ Gpr(0, 0x7fff8000u) ] ]
    check false "e6210ff2" inputs outputs

  /// <summary>
  /// A8.8.145 RBIT: rbit r0, r1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.145 RBIT``() =
    let inputs =
      [ [ Gpr(0, 0xb4078668u); Gpr(1, 0xb5fb8056u) ]
        [ Gpr(0, 0xab4ca879u); Gpr(1, 0xf0b38fa3u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x6a01dfadu) ]
        [ Gpr(0, 0xc5f1cd0fu) ]
        [ Gpr(0, 0x00010000u) ] ]
    check false "e6ff0f31" inputs outputs

  /// <summary>
  /// A8.8.146 REV: rev r0, r1. The outputs are what QEMU left after running it
  /// on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.146 REV``() =
    let inputs =
      [ [ Gpr(0, 0x1a284233u); Gpr(1, 0x05b26339u) ]
        [ Gpr(0, 0x535b0313u); Gpr(1, 0xe04de60cu) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x3963b205u) ]
        [ Gpr(0, 0x0ce64de0u) ]
        [ Gpr(0, 0xffff0000u) ] ]
    check false "e6bf0f31" inputs outputs

  /// <summary>
  /// A8.8.147 REV16: rev16 r0, r1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.147 REV16``() =
    let inputs =
      [ [ Gpr(0, 0x606ec9dcu); Gpr(1, 0x86db9f95u) ]
        [ Gpr(0, 0xefcf8eb7u); Gpr(1, 0x636fe20fu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xdb86959fu) ]
        [ Gpr(0, 0x6f630fe2u) ]
        [ Gpr(0, 0xff7f0080u) ] ]
    check false "e6bf0fb1" inputs outputs

  /// <summary>
  /// A8.8.148 REVSH: revsh r0, r1. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.148 REVSH``() =
    let inputs =
      [ [ Gpr(0, 0xb5b79a81u); Gpr(1, 0xb331f549u) ]
        [ Gpr(0, 0x1324fba3u); Gpr(1, 0xbdff79beu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x000049f5u) ]
        [ Gpr(0, 0xffffbe79u) ]
        [ Gpr(0, 0x00000080u) ] ]
    check false "e6ff0fb1" inputs outputs

  /// <summary>
  /// A8.8.149 RFE: rfeia r1. This checks, in Supervisor mode with Rn pointing
  /// at a return address of 0x30003000 and a saved CPSR of 0x20000010, that it
  /// returns there with that CPSR and leaves Rn, and that User and Hyp mode
  /// refuse it. It is not a value test because it needs a privileged mode,
  /// which a user-mode run does not have.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.149 RFE``() =
    let w = uint32 Window
    let cells = [ Gpr(1, w + 16u); M(16, 0x2000001030003000UL) ]
    let run = runWith false "f8910a00" (CPSR 0x13u :: cells) []
    let refused = refusedModes false "f8910a00" cells []
    CollectionAssert.AreEqual([| 0x10u; 0x1au |], refused)
    Assert.AreEqual(Some 0x30003000UL, run.Target)
    Assert.AreEqual(CPSR 0x20000010u, run.After(CPSR 0u))
    Assert.AreEqual(Gpr(1, w + 16u), run.After(Gpr(1, 0u)))

  /// <summary>
  /// A8.8.150 ROR: ror r0, r0, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.150 ROR``() =
    let inputs =
      [ [ Gpr(0, 0x61c3ad38u); Gpr(2, 0x5ce0c57cu) ]
        [ Gpr(0, 0x4250725fu); Gpr(2, 0xfb5f0424u) ]
        [ Gpr(0, 0x00000001u); Gpr(2, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x1c3ad386u) ]
        [ Gpr(0, 0xf4250725u) ]
        [ Gpr(0, 0x00000001u) ] ]
    check false "e1a00270" inputs outputs

  /// <summary>
  /// A8.8.152 RRX: rrx r0, r2. The outputs are what QEMU left after running it
  /// on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.152 RRX``() =
    let inputs =
      [ [ Gpr(0, 0xf7e27f49u); Gpr(2, 0x0feae58eu); CPSR 0x20000010u ]
        [ Gpr(0, 0xb34a13cbu); Gpr(2, 0xc98d547du); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000001u); Gpr(2, 0x00008000u); CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x87f572c7u) ]
        [ Gpr(0, 0x64c6aa3eu) ]
        [ Gpr(0, 0x00004000u) ] ]
    check false "e1a00062" inputs outputs

  /// <summary>
  /// A8.8.153 RSB: rsb r0, r1, #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.153 RSB``() =
    let inputs =
      [ [ Gpr(0, 0x7cda3cb2u); Gpr(1, 0xa8ad7298u) ]
        [ Gpr(0, 0x4015a117u); Gpr(1, 0x5e597e75u) ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu) ] ]
    let outputs =
      [ [ Gpr(0, 0x57528d68u) ]
        [ Gpr(0, 0xa1a6818bu) ]
        [ Gpr(0, 0xffff0001u) ] ]
    check false "e2610000" inputs outputs

  /// <summary>
  /// A8.8.156 RSC: rsc r0, r1, #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.156 RSC``() =
    let inputs =
      [ [ Gpr(0, 0xb65d6c93u); Gpr(1, 0xe665d0b7u); CPSR 0x20000010u ]
        [ Gpr(0, 0xc175b69du); Gpr(1, 0x4315ed7au); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu); CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x199a2f49u) ]
        [ Gpr(0, 0xbcea1285u) ]
        [ Gpr(0, 0xffff0000u) ] ]
    check false "e2e10000" inputs outputs

  /// <summary>
  /// A8.8.159 SADD16: sadd16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.159 SADD16``() =
    let inputs =
      [ [ Gpr(0, 0x41ed877bu)
          Gpr(1, 0xfd9f6f38u)
          Gpr(2, 0xbbb7fb23u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xaa869e8du)
          Gpr(1, 0x1db9f2e5u)
          Gpr(2, 0x13c3777eu)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u)
          Gpr(1, 0x00000000u)
          Gpr(2, 0x80007fffu)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xb9566a5bu); CPSR 0x20030010u ]
        [ Gpr(0, 0x317c6a63u); CPSR 0x900f0010u ]
        [ Gpr(0, 0x80007fffu); CPSR 0x48030010u ] ]
    check false "e6110f12" inputs outputs

  /// <summary>
  /// A8.8.160 SADD8: sadd8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.160 SADD8``() =
    let inputs =
      [ [ Gpr(0, 0x5825e689u)
          Gpr(1, 0xe9e737f1u)
          Gpr(2, 0xa2f2b72cu)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xf73b7188u)
          Gpr(1, 0x7683e0c6u)
          Gpr(2, 0x782c6a95u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x00008000u)
          Gpr(1, 0x7fff8000u)
          Gpr(2, 0x00000000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0x8bd9ee1du); CPSR 0x20010010u ]
        [ Gpr(0, 0xeeaf4a5bu); CPSR 0x900a0010u ]
        [ Gpr(0, 0x7fff8000u); CPSR 0x48090010u ] ]
    check false "e6110f92" inputs outputs

  /// <summary>
  /// A8.8.161 SASX: sasx r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.161 SASX``() =
    let inputs =
      [ [ Gpr(0, 0xaf045024u)
          Gpr(1, 0xbcbc46bdu)
          Gpr(2, 0xfd43f0ecu)
          CPSR 0x20000010u ]
        [ Gpr(0, 0x6e2015d6u)
          Gpr(1, 0x7611b8c6u)
          Gpr(2, 0x8855ced6u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x0000ffffu)
          Gpr(1, 0x00008000u)
          Gpr(2, 0x7fff8000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xada8497au); CPSR 0x20030010u ]
        [ Gpr(0, 0x44e73071u); CPSR 0x900f0010u ]
        [ Gpr(0, 0x80000001u); CPSR 0x48000010u ] ]
    check false "e6110f32" inputs outputs

  /// <summary>
  /// A8.8.162 SBC: sbc r0, r1, #0x0. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.162 SBC``() =
    let inputs =
      [ [ Gpr(0, 0x2fbe1e65u); Gpr(1, 0xfd33ad5eu); CPSR 0x20000010u ]
        [ Gpr(0, 0xee17e647u); Gpr(1, 0x38e43f81u); CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000001u); Gpr(1, 0x0000ffffu); CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xfd33ad5eu) ]
        [ Gpr(0, 0x38e43f80u) ]
        [ Gpr(0, 0x0000fffeu) ] ]
    check false "e2c10000" inputs outputs

  /// <summary>
  /// A8.8.165 SBFX: sbfx r0, r1, #0x3, #0x5. The outputs are what QEMU left
  /// after running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.165 SBFX``() =
    let inputs =
      [ [ Gpr(0, 0x446600e8u); Gpr(1, 0x0dd6491du) ]
        [ Gpr(0, 0x3486b9ffu); Gpr(1, 0xfc82b7f7u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000003u) ]
        [ Gpr(0, 0xfffffffeu) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e7a401d1" inputs outputs

  /// <summary>
  /// A8.8.166 SDIV: sdiv r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.166 SDIV``() =
    let inputs =
      [ [ Gpr(0, 0xbf1746c3u); Gpr(1, 0xb35859beu); Gpr(2, 0xb3a1fb4bu) ]
        [ Gpr(0, 0x79f03877u); Gpr(1, 0xb2845ac3u); Gpr(2, 0x258ac730u) ]
        [ Gpr(0, 0x0000ffffu); Gpr(1, 0x00008000u); Gpr(2, 0x7fff8000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x00000001u) ]
        [ Gpr(0, 0xfffffffeu) ]
        [ Gpr(0, 0x00000000u) ] ]
    check false "e710f211" inputs outputs

  /// <summary>
  /// A8.8.167 SEL: sel r0, r1, r2. The outputs are what QEMU left after running
  /// it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.167 SEL``() =
    let inputs =
      [ [ Gpr(0, 0xf739cd68u)
          Gpr(1, 0x5092acf3u)
          Gpr(2, 0xfef48850u)
          CPSR 0x20000010u ]
        [ Gpr(0, 0xbe5a627cu)
          Gpr(1, 0xbad07c2du)
          Gpr(2, 0xec84a171u)
          CPSR 0x900a0010u ]
        [ Gpr(0, 0x00000001u)
          Gpr(1, 0x0000ffffu)
          Gpr(2, 0x00008000u)
          CPSR 0x48050010u ] ]
    let outputs =
      [ [ Gpr(0, 0xfef48850u) ]
        [ Gpr(0, 0xba847c71u) ]
        [ Gpr(0, 0x000080ffu) ] ]
    check false "e6810fb2" inputs outputs

  /// <summary>
  /// A8.8.168 SETEND: setend be. This checks that it sets E, CPSR bit 9, and
  /// goes on to the next instruction by a jump, so that what follows is lifted
  /// again. It is not a value test because it changes the byte order of every
  /// access after it, the run's own included.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.168 SETEND``() =
    let run = runWith false "f1010200" [ CPSR 0x10u ] []
    Assert.AreEqual(CPSR 0x210u, run.After(CPSR 0u))
    Assert.AreEqual(Some(CodeAddr + 4UL), run.Target)

  /// <summary>
  /// A8.8.169 SEV: sev. It lifts to no statements: what it does is a hint or an
  /// ordering of memory accesses that one run cannot observe, and QEMU's runs
  /// of it changed no register and no byte, so a value test would assert
  /// nothing.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.169 SEV``() =
    Assert.AreEqual(0, (lift false "e320f004").Length)

  /// <summary>
  /// A8.8.170 SHADD16: shadd16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.170 SHADD16``() =
    let inputs =
      [ [ Gpr(0, 0x47419e4eu); Gpr(1, 0x2d149c95u); Gpr(2, 0xc2a883d6u) ]
        [ Gpr(0, 0xffe59b75u); Gpr(1, 0x893245beu); Gpr(2, 0xeb1d2abcu) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0xf7de9035u) ]
        [ Gpr(0, 0xba27383du) ]
        [ Gpr(0, 0xc0004001u) ] ]
    check false "e6310f12" inputs outputs

  /// <summary>
  /// A8.8.171 SHADD8: shadd8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.171 SHADD8``() =
    let inputs =
      [ [ Gpr(0, 0xbd09fe41u); Gpr(1, 0xc93c0ffeu); Gpr(2, 0x060064c1u) ]
        [ Gpr(0, 0xeab044e6u); Gpr(1, 0x1d536558u); Gpr(2, 0x6d36aa94u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0xe71e39dfu) ]
        [ Gpr(0, 0x454407f6u) ]
        [ Gpr(0, 0xc0003fffu) ] ]
    check false "e6310f92" inputs outputs

  /// <summary>
  /// A8.8.172 SHASX: shasx r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.172 SHASX``() =
    let inputs =
      [ [ Gpr(0, 0x1aabd766u); Gpr(1, 0xb01c465au); Gpr(2, 0x153632e2u) ]
        [ Gpr(0, 0xea5a08f8u); Gpr(1, 0xdc5691e5u); Gpr(2, 0xcda161cdu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0xf17f1892u) ]
        [ Gpr(0, 0x1f11e222u) ]
        [ Gpr(0, 0x3fffc000u) ] ]
    check false "e6310f32" inputs outputs

  /// <summary>
  /// A8.8.173 SHSAX: shsax r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.173 SHSAX``() =
    let inputs =
      [ [ Gpr(0, 0x5747f428u); Gpr(1, 0xc183c385u); Gpr(2, 0xa70bab64u) ]
        [ Gpr(0, 0x5a55ce37u); Gpr(1, 0x655447beu); Gpr(2, 0x2b1d711eu) ]
        [ Gpr(0, 0x00008000u); Gpr(1, 0x7fff8000u); Gpr(2, 0x00000000u) ] ]
    let outputs =
      [ [ Gpr(0, 0x0b0fb548u) ]
        [ Gpr(0, 0xfa1b396du) ]
        [ Gpr(0, 0x3fffc000u) ] ]
    check false "e6310f52" inputs outputs

  /// <summary>
  /// A8.8.174 SHSUB16: shsub16 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.174 SHSUB16``() =
    let inputs =
      [ [ Gpr(0, 0x264626fdu); Gpr(1, 0x489d7220u); Gpr(2, 0xf2ff8ce1u) ]
        [ Gpr(0, 0xada90877u); Gpr(1, 0xcc378f63u); Gpr(2, 0x2ad43612u) ]
        [ Gpr(0, 0x00000000u); Gpr(1, 0x80007fffu); Gpr(2, 0x00000003u) ] ]
    let outputs =
      [ [ Gpr(0, 0x2acf729fu) ]
        [ Gpr(0, 0xd0b1aca8u) ]
        [ Gpr(0, 0xc0003ffeu) ] ]
    check false "e6310f72" inputs outputs

  /// <summary>
  /// A8.8.175 SHSUB8: shsub8 r0, r1, r2. The outputs are what QEMU left after
  /// running it on the inputs, three runs paired by position.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.175 SHSUB8``() =
    let inputs =
      [ [ Gpr(0, 0x269c11e4u); Gpr(1, 0x1749554du); Gpr(2, 0x2b8f2aa5u) ]
        [ Gpr(0, 0x4e8880f0u); Gpr(1, 0x3761f65eu); Gpr(2, 0x10b62441u) ]
        [ Gpr(0, 0x7fff8000u); Gpr(1, 0x00000000u); Gpr(2, 0x80007fffu) ] ]
    let outputs =
      [ [ Gpr(0, 0xf65d1554u) ]
        [ Gpr(0, 0x1355e90eu) ]
        [ Gpr(0, 0x4000c000u) ] ]
    check false "e6310ff2" inputs outputs

  /// <summary>
  /// A8.8.176 SMC: smc 1. This checks that User mode refuses it and that every
  /// other mode reaches a call the lift does not model. It is not a value test
  /// because it takes an exception, which a user-mode run cannot return from.
  /// </summary>
  [<TestMethod>]
  member _.``A8.8.176 SMC``() =
    let run = runWith false "e1600071" [ CPSR 0x13u ] []
    let refused = refusedModes false "e1600071" [] []
    CollectionAssert.AreEqual([| 0x10u |], refused)
    Assert.AreEqual(Some SideEffect.UnsupportedInstruction, run.Effect)

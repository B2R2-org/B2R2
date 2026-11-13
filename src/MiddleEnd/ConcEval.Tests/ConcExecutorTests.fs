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

namespace B2R2.MiddleEnd.ConcEval.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.Executor
open B2R2.MiddleEnd.ConcEval

[<TestClass>]
type ConcExecutorTests() =
  let loadRawImage (bytes: byte[]) arch (ws: WordSize) =
    BinHandle.LoadRawImage(bytes, ISA(arch, ws), OS.Linux)

#if !EMULATION
  (* mul rax : the lifter marks SF as undefined *)
  let mulBytes = [| 0x48uy; 0xf7uy; 0xe0uy |]
#endif

  (* call rel32 1 (target 0x6) ; nop ; ret *)
  let hookedCall = [| 0xe8uy; 0x01uy; 0x00uy; 0x00uy; 0x00uy; 0x90uy; 0xc3uy |]

  (* call rel32 0x100 (target 0x105, outside the image) ; nop *)
  let externalCall = [| 0xe8uy; 0x00uy; 0x01uy; 0x00uy; 0x00uy; 0x90uy |]

  (* jal 0x20 ; nop (delay slot) ; nop -- a MIPS nop is a zero word *)
  let mipsCall =
    Array.append [| 0x0cuy; 0x00uy; 0x00uy; 0x08uy |] (Array.zeroCreate 8)

#if !EMULATION
  (* Only the non-EMULATION lifter writes an undefined value to SF here: under
     EMULATION `mul` leaves the flags to be worked out lazily and never writes
     SF at all, so neither undefined-value policy below is exercised. *)
  let runMulWithPresetSF policy =
    let hdl = loadRawImage mulBytes Architecture.Intel WordSize.Bit64
    let exec = ConcExecutor hdl
    let sf = hdl.RegisterFactory.GetRegisterID "SF"
    let st =
      exec.CreateState { Memory = BinSectionBackedMemory
                         Registers = [| sf, BitVector.One 1<rt> |] }
    let opts =
      { ConcRunOptions.Default [] with
          MaxInstructions = 1
          UndefinedValues = policy }
    exec.Run(0UL, st, opts) |> ignore
    st.TryGetReg sf
#endif

  let loadThumb hex =
    let isa = ISA(Endian.Little, false, ARM32Mode.Thumb)
    BinHandle.LoadRawImage(ByteArray.ofHexString hex, isa, OS.Linux)

  (* ite ne; movne r1, #1; moveq r1, #2; movs r3, #5; nop *)
  let itBlock = "14bf01210221052300bf"

  let runOneInstruction (hdl: BinHandle) =
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    let opts = ConcRunOptions.Default().WithMaxInstructions 1
    exec.Run(0UL, st, opts) |> ignore
    st

  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``Run makes progress past a side-effect instruction``() =
    (* syscall; nop; nop *)
    let bytes = [| 0x0fuy; 0x05uy; 0x90uy; 0x90uy |]
    let hdl = loadRawImage bytes Architecture.Intel WordSize.Bit64
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    let opts = ConcRunOptions.Default().StopAfterAddress 0x3UL
    let res = exec.Run(0UL, st, opts)
    Assert.AreEqual<bool>(true, res.IsStoppedAfterAddress 0x3UL)
    Assert.AreEqual<Addr>(0x4UL, res.FinalAddress)
    Assert.AreEqual<int>(3, res.InstructionCount)

  [<TestMethod>]
  member _.``ARM interworking switches the instruction set both ways``() =
    (* blx 0x8; mov r1, #7 in ARM, and at 0x8 movs r0, #42; bx lr in Thumb *)
    let bytes = ByteArray.ofHexString "000000fa0710a0e32a207047"
    let hdl = loadRawImage bytes Architecture.ARMv7 WordSize.Bit32
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    let res = exec.Run(0UL, st, ConcRunOptions.Default().WithMaxInstructions 4)
    let reg (name: string) = st.GetReg(hdl.RegisterFactory.GetRegisterID name)
    Assert.AreEqual<BitVector>(BitVector(42UL, 32<rt>), reg "R0")
    Assert.AreEqual<BitVector>(BitVector(7UL, 32<rt>), reg "R1")
    Assert.AreEqual<Addr>(0x8UL, res.FinalAddress)

  [<TestMethod>]
  member _.``An IT block decodes under the IT state CPSR holds``() =
    let hdl = loadThumb itBlock
    let rf = hdl.RegisterFactory
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    (* Thumb, with Z clear: NE holds and EQ does not *)
    st.SetReg(rf.GetRegisterID "CPSR", BitVector(0x20UL, 32<rt>))
    exec.Run(0UL, st, ConcRunOptions.Default().WithMaxInstructions 4)
    |> ignore
    let reg (name: string) = st.GetReg(rf.GetRegisterID name)
    Assert.AreEqual<BitVector>(BitVector(1UL, 32<rt>), reg "R1")
    Assert.AreEqual<BitVector>(BitVector(5UL, 32<rt>), reg "R3")

  [<TestMethod>]
  member _.``A run decodes as its own state says, not as the last run left``() =
    let hdl = loadThumb itBlock
    let exec = ConcExecutor hdl
    let opts = ConcRunOptions.Default()
    (* Stops inside the block, where the parser has an EQ still to come *)
    exec.Run(0UL, exec.CreateState(), opts.StopAtAddress 0x2UL) |> ignore
    let st = exec.CreateState()
    exec.Run(0x6UL, st, opts.WithMaxInstructions 1) |> ignore
    let r3 = st.GetReg(hdl.RegisterFactory.GetRegisterID "R3")
    Assert.AreEqual<BitVector>(BitVector(5UL, 32<rt>), r3)

  [<TestMethod>]
  member _.``A MIPS jump switches the encoding both ways``() =
    (* MIPS16e: jalx 0x10, with a nop in its slot; li v1, 7 *)
    let mips16 = "1c00000465006b07" + "0000000000000000"
    (* MIPS32 at 0x10: addiu v0, zero, 42; jr ra, with a nop in its slot *)
    let mips32 = "2402002a03e0000800000000"
    let bytes = ByteArray.ofHexString (mips16 + mips32)
    let flags = int MIPSISAMode.MIPS16
    let isa = ISA(Architecture.MIPS, Endian.Big, WordSize.Bit32, flags)
    let hdl = BinHandle.LoadRawImage(bytes, isa, OS.Linux)
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    let res = exec.Run(0UL, st, ConcRunOptions.Default().WithMaxInstructions 4)
    let reg (name: string) = st.GetReg(hdl.RegisterFactory.GetRegisterID name)
    Assert.AreEqual<BitVector>(BitVector(42UL, 32<rt>), reg "V0")
    Assert.AreEqual<BitVector>(BitVector(7UL, 32<rt>), reg "V1")
    Assert.AreEqual<Addr>(0x8UL, res.FinalAddress)

  [<TestMethod>]
  member _.``A decode mode nothing settles stops the run``() =
    (* mov r0, r0, under a CPSR that nothing has set *)
    let bytes = [| 0x00uy; 0x00uy; 0xa0uy; 0xe1uy |]
    let hdl = loadRawImage bytes Architecture.ARMv7 WordSize.Bit32
    let exec = ConcExecutor hdl
    let resolver = ConcDecodeModeResolver(fun _ _ -> ValueNone)
    let opts = ConcRunOptions.Default().ResolveDecodeModeWith resolver
    let res = exec.Run(0UL, exec.CreateState(), opts)
    match res.StopReasons with
    | [ ConcStopReason.UndeterminedDecodeMode addr ] ->
      Assert.AreEqual<Addr>(0UL, addr)
    | reasons ->
      Assert.Fail $"Unexpected stop reasons: {reasons}"

  [<TestMethod>]
  member _.``A resolver settles the decode mode the state leaves open``() =
    (* movw r0, #42 in Thumb, under a CPSR that nothing has set *)
    let bytes = [| 0x40uy; 0xf2uy; 0x2auy; 0x00uy |]
    let hdl = loadRawImage bytes Architecture.ARMv7 WordSize.Bit32
    let exec = ConcExecutor hdl
    let thumb =
      { IsThumb = true; ITState = 0uy; ISAMode = MIPSISAMode.MIPS }
    let resolver = ConcDecodeModeResolver(fun _ _ -> ValueSome thumb)
    let opts =
      ConcRunOptions.Default().ResolveDecodeModeWith(resolver)
        .WithMaxInstructions 1
    let st = exec.CreateState()
    exec.Run(0UL, st, opts) |> ignore
    let r0 = st.GetReg(hdl.RegisterFactory.GetRegisterID "R0")
    Assert.AreEqual<BitVector>(BitVector(42UL, 32<rt>), r0)

  [<TestMethod>]
  member _.``Return address register is not zeroed as caller context``() =
    (* ret *)
    let bytes = [| 0xc0uy; 0x03uy; 0x5fuy; 0xd6uy |]
    let hdl = loadRawImage bytes Architecture.ARMv8 WordSize.Bit64
    let st = runOneInstruction hdl
    match st.TryGetReg(hdl.RegisterFactory.GetRegisterID "x30") with
    | Undef -> ()
    | Def v -> Assert.Fail $"The return address register was zeroed to {v}."

  [<TestMethod>]
  member _.``Instruction limit is honored as given``() =
    (* jmp $ *)
    let bytes = [| 0xebuy; 0xfeuy |]
    let hdl = loadRawImage bytes Architecture.Intel WordSize.Bit64
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    let opts = ConcRunOptions.Default().WithMaxInstructions 7
    let res = exec.Run(0UL, st, opts)
    Assert.AreEqual<int>(7, res.InstructionCount)
    match res.StopReasons with
    | [ ConcStopReason.InstructionLimitReached(_, limit) ] ->
      Assert.AreEqual<int>(7, limit)
    | reasons ->
      Assert.Fail $"Unexpected stop reasons: {reasons}"

  [<TestMethod>]
  member _.``A user stop predicate ends the run``() =
    (* jmp $ *)
    let bytes = [| 0xebuy; 0xfeuy |]
    let hdl = loadRawImage bytes Architecture.Intel WordSize.Bit64
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    let predicate = StopPredicate(fun point -> point.InstructionCount = 3)
    let opts = ConcRunOptions.Default().StopWhen predicate
    let res = exec.Run(0UL, st, opts)
    Assert.AreEqual<int>(3, res.InstructionCount)
    Assert.AreEqual<bool>(true, res.IsUserStopConditionMet)
    match res.StopReasons with
    | [ ConcStopReason.UserStopConditionMet addr ] ->
      Assert.AreEqual<Addr>(0UL, addr)
    | reasons ->
      Assert.Fail $"Unexpected stop reasons: {reasons}"

  [<TestMethod>]
  member _.``Default options carry an instruction limit``() =
    let opts: ConcRunOptions = ConcRunOptions.Default []
    Assert.AreEqual<int>(50000, opts.MaxInstructions)

  [<TestMethod>]
  member _.``Evaluation failure ends the run without a stop condition``() =
    (* ret *)
    let bytes = [| 0xc0uy; 0x03uy; 0x5fuy; 0xd6uy |]
    let hdl = loadRawImage bytes Architecture.ARMv8 WordSize.Bit64
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    let opts = ConcRunOptions.Default().StopAtAddress 0xffffUL
    let res = exec.Run(0UL, st, opts)
    match res.StopReasons with
    | [ ConcStopReason.EvaluationError(addr, e) ] ->
      Assert.AreEqual<Addr>(0UL, addr)
      Assert.AreEqual<ErrorCase>(ErrorCase.InvalidExprEvaluation, e)
    | reasons ->
      Assert.Fail $"Unexpected stop reasons: {reasons}"

  [<TestMethod>]
  member _.``Caller context registers are zeroed``() =
    (* add rax, rbx *)
    let bytes = [| 0x48uy; 0x01uy; 0xd8uy |]
    let hdl = loadRawImage bytes Architecture.Intel WordSize.Bit64
    let st = runOneInstruction hdl
    match st.TryGetReg(hdl.RegisterFactory.GetRegisterID "RBX") with
    | Def v -> Assert.AreEqual<uint64>(0UL, v.ToUInt64())
    | Undef -> Assert.Fail "RBX was not materialized."

#if !EMULATION
  [<TestMethod>]
  member _.``Undefined writes leave the target undefined``() =
    let policy = ConcUndefinedValuePolicy.PreserveUndefinedValues
    match runMulWithPresetSF policy with
    | Undef ->
      ()
    | Def v ->
      Assert.Fail $"SF kept a stale value {v}."

  [<TestMethod>]
  member _.``Ignored undefined writes keep the previous value``() =
    match runMulWithPresetSF ConcUndefinedValuePolicy.IgnoreUndefinedWrites with
    | Def v ->
      Assert.AreEqual<uint64>(1UL, v.ToUInt64())
    | Undef ->
      Assert.Fail "SF was unset."
#endif

  [<TestMethod>]
  member _.``A call hook stands in for the call``() =
    let hdl = loadRawImage hookedCall Architecture.Intel WordSize.Bit64
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    ConcStateAccessor(hdl, st).InitializeDefaultStack()
    let hook (ctx: CallContext) (st: ConcState) =
      st.SetReg(ctx.ReturnRegister, BitVector(0x2aUL, ctx.WordType))
      Ok()
    let opts =
      ConcRunOptions.Default().WithMaxInstructions(1)
        .RegisterCallHook(0x6UL, hook)
    let res = exec.Run(0UL, st, opts)
    Assert.AreEqual<Addr>(0x5UL, res.FinalAddress)
    match st.TryGetReg(hdl.RegisterFactory.GetRegisterID "RAX") with
    | Def v ->
      Assert.AreEqual<uint64>(0x2aUL, v.ToUInt64())
    | Undef ->
      Assert.Fail "The hook did not set the return register."

  [<TestMethod>]
  member _.``An unhooked external call is reported``() =
    let hdl = loadRawImage externalCall Architecture.Intel WordSize.Bit64
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    let opts = ConcRunOptions.Default().WithCallHooks(CallHookRegistry())
    let res = exec.Run(0UL, st, opts)
    match res.StopReasons with
    | [ ConcStopReason.CallHandlingFailure(callSite, target, _) ] ->
      Assert.AreEqual<Addr>(0UL, callSite)
      Assert.AreEqual<Addr option>(Some 0x105UL, target)
    | reasons ->
      Assert.Fail $"Unexpected stop reasons: {reasons}"

  [<TestMethod>]
  member _.``A direct call leaving the binary is reported``() =
    let hdl = loadRawImage externalCall Architecture.Intel WordSize.Bit64
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    let res = exec.Run(0UL, st, ConcRunOptions.Default [])
    match res.StopReasons with
    | [ ConcStopReason.CallHandlingFailure(callSite, target, _) ] ->
      Assert.AreEqual<Addr>(0UL, callSite)
      Assert.AreEqual<Addr option>(Some 0x105UL, target)
    | reasons ->
      Assert.Fail $"Unexpected stop reasons: {reasons}"

  [<TestMethod>]
  member _.``A hooked MIPS call returns past its delay slot``() =
    let hdl = loadRawImage mipsCall Architecture.MIPS WordSize.Bit32
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    ConcStateAccessor(hdl, st).InitializeDefaultStack()
    let seen = ResizeArray<Addr>()
    let hook (ctx: CallContext) (_: ConcState) =
      seen.Add ctx.ReturnAddress
      Ok()
    let opts =
      ConcRunOptions.Default().WithMaxInstructions(1)
        .RegisterCallHook(0x20UL, hook)
    let res = exec.Run(0UL, st, opts)
    Assert.AreEqual<Addr>(0x8UL, res.FinalAddress)
    Assert.AreEqual<Addr>(0x8UL, Seq.exactlyOne seen)

  [<TestMethod>]
  member _.``Fluent options build what a record update builds``() =
    let hooks = CallHookRegistry()
    let zeroAny = ConcUninitializedRegisterPolicy.ZeroAnyRegister
    let expected =
      { ConcRunOptions.Default [] with
          MaxInstructions = 3
          Calls = CallPolicy.UseCallHooks hooks
          UndefinedValues = ConcUndefinedValuePolicy.StopOnUndefinedValue
          UninitializedRegisters = zeroAny }
    let actual =
      ConcRunOptions.Default()
        .WithMaxInstructions(3)
        .WithCallHooks(hooks)
        .StopOnUndefinedValue()
        .ZeroAnyRegister()
    Assert.AreEqual<ConcRunOptions>(expected, actual)

  [<TestMethod>]
  member _.``Stop conditions accumulate in the order they are added``() =
    let opts =
      ConcRunOptions.Default().StopAtAddress(0x1UL).StopAtReturn()
        .StopAfterAddress(0x2UL)
    let expected =
      [ ConcStopCondition.StopAtAddress 0x1UL
        ConcStopCondition.StopAtReturn
        ConcStopCondition.StopAfterAddress 0x2UL ]
    Assert.AreEqual<ConcStopCondition list>(expected, opts.StopConditions)

  [<TestMethod>]
  member _.``Registering a hook enables hook-based call handling``() =
    let hook (_: CallContext) (_: ConcState) = Ok()
    let opts = ConcRunOptions.Default().RegisterCallHook(0x6UL, hook)
    match opts.Calls with
    | CallPolicy.UseCallHooks hooks ->
      Assert.AreEqual<bool>(true, (hooks.TryFind 0x6UL).IsSome)
    | policy ->
      Assert.Fail $"Unexpected call policy: {policy}"

  [<TestMethod>]
  member _.``A result answers where it stopped without matching``() =
    (* syscall; nop; nop *)
    let bytes = [| 0x0fuy; 0x05uy; 0x90uy; 0x90uy |]
    let hdl = loadRawImage bytes Architecture.Intel WordSize.Bit64
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    let opts = ConcRunOptions.Default().StopAtSideEffect()
    let res = exec.Run(0UL, st, opts)
    Assert.AreEqual<bool>(true, res.IsStoppedAtSideEffect)
    Assert.AreEqual<bool>(false, res.IsStoppedAtReturn)
    Assert.AreEqual<bool>(false, res.IsFailed)

  [<TestMethod>]
  member _.``A result hands back the reason it could not go on``() =
    (* ret *)
    let bytes = [| 0xc0uy; 0x03uy; 0x5fuy; 0xd6uy |]
    let hdl = loadRawImage bytes Architecture.ARMv8 WordSize.Bit64
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    let res = exec.Run(0UL, st, ConcRunOptions.Default())
    Assert.AreEqual<bool>(true, res.IsFailed)
    match res.TryGetFailure() with
    | Some(ConcStopReason.EvaluationError(addr, _)) ->
      Assert.AreEqual<Addr>(0UL, addr)
    | failure ->
      Assert.Fail $"Unexpected failure: {failure}"

  [<TestMethod>]
  member _.``An instruction limit is not counted as a failure``() =
    (* jmp $ *)
    let bytes = [| 0xebuy; 0xfeuy |]
    let hdl = loadRawImage bytes Architecture.Intel WordSize.Bit64
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    let res = exec.Run(0UL, st, ConcRunOptions.Default().WithMaxInstructions 2)
    Assert.AreEqual<bool>(true, res.IsInstructionLimitReached)
    Assert.AreEqual<bool>(false, res.IsFailed)
    Assert.AreEqual<Option<ConcStopReason>>(None, res.TryGetFailure())

  [<TestMethod>]
  member _.``Every call policy setter selects the policy it names``() =
    let opts = ConcRunOptions.Default()
    let assertPolicy expected (opts: ConcRunOptions) =
      Assert.AreEqual<CallPolicy<ConcCallHook>>(expected, opts.Calls)
    assertPolicy CallPolicy.StopAtCalls (opts.StopAtCalls())
    assertPolicy CallPolicy.FollowDirectInternalCalls
                 (opts.FollowDirectInternalCalls())

  [<TestMethod>]
  member _.``Every undefined value setter selects the policy it names``() =
    let opts = ConcRunOptions.Default()
    let assertPolicy expected (opts: ConcRunOptions) =
      Assert.AreEqual<ConcUndefinedValuePolicy>(expected, opts.UndefinedValues)
    assertPolicy ConcUndefinedValuePolicy.StopOnUndefinedValue
                 (opts.StopOnUndefinedValue())
    assertPolicy ConcUndefinedValuePolicy.IgnoreUndefinedWrites
                 (opts.IgnoreUndefinedWrites())
    assertPolicy ConcUndefinedValuePolicy.PreserveUndefinedValues
                 (opts.PreserveUndefinedValues())

  [<TestMethod>]
  member _.``Every register setter selects the policy it names``() =
    let opts = ConcRunOptions.Default()
    let policyOf (opts: ConcRunOptions) = opts.UninitializedRegisters
    let stopOn = ConcUninitializedRegisterPolicy.StopOnUninitializedRegister
    let caller = ConcUninitializedRegisterPolicy.ZeroCallerContext
    let anyReg = ConcUninitializedRegisterPolicy.ZeroAnyRegister
    let assertPolicy expected actual =
      Assert.AreEqual<ConcUninitializedRegisterPolicy>(expected, actual)
    assertPolicy stopOn (policyOf (opts.StopOnUninitializedRegister()))
    assertPolicy caller (policyOf (opts.ZeroCallerContext()))
    assertPolicy anyReg (policyOf (opts.ZeroAnyRegister()))

  [<TestMethod>]
  member _.``Every stop condition shortcut adds the case it names``() =
    let opts =
      ConcRunOptions.Default()
        .StopAtAddresses([ 0x1UL; 0x2UL ])
        .StopAfterAddress(0x3UL)
        .StopAtReturn()
        .StopAfterReturn()
        .StopAtSideEffect()
    let expected =
      [ ConcStopCondition.StopAtAddress 0x1UL
        ConcStopCondition.StopAtAddress 0x2UL
        ConcStopCondition.StopAfterAddress 0x3UL
        ConcStopCondition.StopAtReturn
        ConcStopCondition.StopAfterReturn
        ConcStopCondition.StopAtSideEffect ]
    Assert.AreEqual<ConcStopCondition list>(expected, opts.StopConditions)

  [<TestMethod>]
  member _.``Replacing stop conditions drops the previous ones``() =
    let opts =
      ConcRunOptions.Default().StopAtReturn()
        .WithStopConditions [ ConcStopCondition.StopAtSideEffect ]
    let expected = [ ConcStopCondition.StopAtSideEffect ]
    Assert.AreEqual<ConcStopCondition list>(expected, opts.StopConditions)

  [<TestMethod>]
  member _.``Registering many hooks enables hook-based call handling``() =
    let hook (_: CallContext) (_: ConcState) = Ok()
    let opts =
      ConcRunOptions.Default().RegisterCallHooks [ 0x6UL, hook; 0x8UL, hook ]
    match opts.Calls with
    | CallPolicy.UseCallHooks hooks ->
      Assert.AreEqual<bool>(true, (hooks.TryFind 0x8UL).IsSome)
    | policy ->
      Assert.Fail $"Unexpected call policy: {policy}"

  [<TestMethod>]
  member _.``A call policy stop is reported as a call stop``() =
    let hdl = loadRawImage externalCall Architecture.Intel WordSize.Bit64
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    let res = exec.Run(0UL, st, ConcRunOptions.Default().StopAtCalls())
    Assert.AreEqual<bool>(true, res.IsStoppedAtCall)
    Assert.AreEqual<bool>(false, res.IsFailed)

  [<TestMethod>]
  member _.``A return is reported both before and after it executes``() =
    (* ret; nop *)
    let bytes = [| 0xc3uy; 0x90uy |]
    let hdl = loadRawImage bytes Architecture.Intel WordSize.Bit64
    let exec = ConcExecutor hdl
    let atState = exec.CreateState()
    ConcStateAccessor(hdl, atState).InitializeDefaultStack()
    let opts = ConcRunOptions.Default().StopAtReturn()
    let atRes = exec.Run(0UL, atState, opts)
    Assert.AreEqual<bool>(true, atRes.IsStoppedAtReturn)
    let afterState = exec.CreateState()
    let accessor = ConcStateAccessor(hdl, afterState)
    accessor.InitializeDefaultStack()
    accessor.PushPointer 0x1UL |> ignore
    let opts = ConcRunOptions.Default().StopAfterReturn()
    let res = exec.Run(0UL, afterState, opts)
    Assert.AreEqual<bool>(true, res.IsStoppedAfterReturn)

  [<TestMethod>]
  member _.``A stop point carries the instruction about to execute``() =
    (* jmp $ *)
    let bytes = [| 0xebuy; 0xfeuy |]
    let hdl = loadRawImage bytes Architecture.Intel WordSize.Bit64
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    let lengths = ResizeArray<uint32>()
    let predicate =
      StopPredicate(fun point ->
        point.Instruction |> Option.iter (fun ins -> lengths.Add ins.Length)
        false)
    let opts = ConcRunOptions.Default().StopWhen predicate
    exec.Run(0UL, st, opts.WithMaxInstructions 2) |> ignore
    Assert.AreEqual<uint32>(2u, Seq.head lengths)

  [<TestMethod>]
  member _.``A stop point has no instruction where none parses``() =
    (* jmp $ *)
    let bytes = [| 0xebuy; 0xfeuy |]
    let hdl = loadRawImage bytes Architecture.Intel WordSize.Bit64
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    let seen = ResizeArray<bool>()
    let predicate =
      StopPredicate(fun point -> seen.Add point.Instruction.IsSome; false)
    let opts = ConcRunOptions.Default().StopWhen predicate
    let res = exec.Run(0x100UL, st, opts)
    Assert.AreEqual<bool>(false, Seq.head seen)
    Assert.AreEqual<bool>(true, res.IsFailed)

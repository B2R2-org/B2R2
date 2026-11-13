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
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.MiddleEnd.ConcEval

[<TestClass>]
type EvaluatorTests() =
  let newState () =
    let st = ConcState()
    st.CurrentInsLen <- 2u
    st

  let liftIntel (bytes: byte[]) =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let hdl = BinHandle.LoadRawImage(bytes, isa, OS.Linux)
    let lu = hdl.NewLiftingUnit()
    hdl, lu.LiftInstruction(lu.ParseInstruction 0UL)

  let stateWithEveryRegisterSet (hdl: BinHandle) =
    let st = ConcState()
    let rf = hdl.RegisterFactory
    rf.GetAllRegVars()
    |> Array.iter (fun v ->
      let rid = rf.GetRegisterID v
      st.SetReg(rid, BitVector(1UL, rf.GetRegType rid)))
    st

  let registersAfter evalOne hdl (stmts: Stmt[]) =
    let st = stateWithEveryRegisterSet hdl
    st.PrepareInstrEval stmts
    stmts |> Array.iter (evalOne st)
    st.Registers.ToArray() |> Map.ofArray

  let differingRegisters unsafeRegs safeRegs =
    let unsafeKeys = Map.keys unsafeRegs |> Set.ofSeq
    Map.keys safeRegs
    |> Set.ofSeq
    |> Set.union unsafeKeys
    |> Set.filter (fun k -> Map.tryFind k unsafeRegs <> Map.tryFind k safeRegs)
    |> Set.toList

  let assertEvaluatorsAgree bytes =
    let hdl, stmts = liftIntel bytes
    let viaUnsafe = registersAfter Evaluator.evalStmt hdl stmts
    let viaSafe =
      registersAfter (fun st s -> SafeEvaluator.evalStmt st s |> ignore) hdl
                     stmts
    match differingRegisters viaUnsafe viaSafe with
    | [] -> ()
    | ks -> Assert.Fail $"The evaluators disagree on registers {ks}."

  let assertTerminatedWithPCAdvanced (st: ConcState) =
    Assert.AreEqual<bool>(true, st.IsInstrTerminated)
    Assert.AreEqual<Addr>(2UL, st.PC)

  let assertValue expected expr =
    Assert.AreEqual<BitVector>(expected, Evaluator.evalExpr (newState ()) expr)
    Assert.AreEqual(Ok(Def expected),
                    SafeEvaluator.evalExpr (newState ()) expr)

  let evalInstrWith safe st stmts =
    if safe then
      Assert.AreEqual(Ok(), SafeEvaluator.evalInstr st stmts)
    else
      Evaluator.evalInstr st stmts

  [<TestMethod>]
  member _.``Integral rounding preserves floating point values``() =
    for t in [ 32<rt>; 64<rt> ] do
      let num value =
        let bits = System.BitConverter.DoubleToUInt64Bits value
        BitVector.FCast(BitVector(bits, 64<rt>), t)
      let src = AST.num (num 2.5)
      AST.cast CastKind.RoundToIntegral t src |> assertValue (num 2.0)
      for mode, expected in
        [ RoundingMode.ToNearestEven, 2.0
          RoundingMode.TowardPositive, 3.0
          RoundingMode.TowardNegative, 2.0
          RoundingMode.TowardZero, 2.0 ] do
        AST.roundToIntegral mode t src |> assertValue (num expected)
      for value in [ -0.0; infinity; -infinity; 1e30 ] do
        let v = num value
        AST.cast CastKind.RoundToIntegral t (AST.num v) |> assertValue v
      AST.roundToIntegral RoundingMode.TowardZero t (AST.num (num -0.25))
      |> assertValue (num -0.0)

  [<TestMethod>]
  member _.``Floating equality handles zeros and NaNs``() =
    for t in [ 32<rt>; 64<rt> ] do
      let num (bits: uint64) =
        AST.num (BitVector.FCast(BitVector(bits, 64<rt>), t))
      let zero = num 0UL
      let negZero = num 0x8000000000000000UL
      let nan = num 0x7ff8000000000000UL
      AST.relop RelOpType.FEQ zero negZero
      |> assertValue (BitVector.One 1<rt>)
      AST.relop RelOpType.FEQ nan nan
      |> assertValue (BitVector.Zero 1<rt>)

  [<DataTestMethod>]
  [<DataRow(false, "0000781e", "V0A", 0x4006000000000000UL,
            "X0", 2UL)>]
  [<DataRow(true, "0000781e", "V0A", 0x4006000000000000UL,
            "X0", 2UL)>]
  [<DataRow(false, "0000781e", "V0A", 0xc006000000000000UL,
            "X0", 0xfffffffeUL)>]
  [<DataRow(true, "0000781e", "V0A", 0xc006000000000000UL,
            "X0", 0xfffffffeUL)>]
  [<DataRow(false, "0000639e", "X0", 4UL, "V0A", 0x4010000000000000UL)>]
  [<DataRow(true, "0000639e", "X0", 4UL, "V0A", 0x4010000000000000UL)>]
  member _.``AArch64 conversions``(safe, hex, src, value, dst, expected) =
    let bytes = ByteArray.ofHexString hex
    let hdl = BinHandle.LoadRawImage(bytes, ISA "aarch64", OS.Linux)
    let stmts = hdl.NewLiftingUnit().LiftInstruction(0UL)
    let rf = hdl.RegisterFactory
    let st = ConcState()
    for name, v in [ "FPCR", 0UL; "FPSR", 0UL; "V0B", 0UL; src, value ] do
      st.SetReg(rf.GetRegisterID name, BitVector((v: uint64), 64<rt>))
    evalInstrWith safe st stmts
    let actual = st.GetReg(rf.GetRegisterID(dst: string))
    Assert.AreEqual<BitVector>(BitVector((expected: uint64), 64<rt>), actual)

  [<TestMethod>]
  member _.``Safe side effect terminates the instruction by default``() =
    let st = newState ()
    match SafeEvaluator.evalStmt st (AST.sideEffect SysCall) with
    | Ok() -> assertTerminatedWithPCAdvanced st
    | Error e -> Assert.Fail $"Failed to evaluate a side effect: {e}"

  [<TestMethod>]
  member _.``Unsafe side effect terminates the instruction by default``() =
    let st = newState ()
    Evaluator.evalStmt st (AST.sideEffect SysCall)
    assertTerminatedWithPCAdvanced st

  [<DataTestMethod>]
  [<DataRow(false)>]
  [<DataRow(true)>]
  member _.``A LOCK-prefixed instruction does its work``(safe) =
    (* lock add dword ptr [rsp], 1 *)
    let hdl, stmts = liftIntel [| 0xf0uy; 0x83uy; 0x04uy; 0x24uy; 0x01uy |]
    let st = ConcState()
    let rsp = hdl.RegisterFactory.GetRegisterID "RSP"
    st.SetReg(rsp, BitVector(0x8000UL, 64<rt>))
    Memory.write 0x8000UL (BitVector(41UL, 32<rt>)) Endian.Little st.Memory
    evalInstrWith safe st stmts
    let actual = Memory.read 0x8000UL Endian.Little 32<rt> st.Memory
    Assert.AreEqual(Ok(BitVector(42UL, 32<rt>)), actual)
    Assert.AreEqual<Addr>(5UL, st.PC)

  [<DataTestMethod>]
  [<DataRow(false)>]
  [<DataRow(true)>]
  member _.``An aligned RISC-V load does its work``(safe) =
    (* fld ft0, 0(sp), which brackets an aligned access with AtomicBegin and
       AtomicEnd *)
    let bytes = [| 0x07uy; 0x30uy; 0x01uy; 0x00uy |]
    let isa = ISA(Architecture.RISCV, WordSize.Bit64)
    let hdl = BinHandle.LoadRawImage(bytes, isa, OS.Linux)
    let stmts = hdl.NewLiftingUnit().LiftInstruction(0UL)
    let rf = hdl.RegisterFactory
    let one = BitVector(0x3ff0000000000000UL, 64<rt>)
    let st = ConcState()
    st.SetReg(rf.GetRegisterID "X2", BitVector(0x8000UL, 64<rt>))
    st.SetReg(rf.GetRegisterID "F0", BitVector.Zero 64<rt>)
    Memory.write 0x8000UL one Endian.Little st.Memory
    evalInstrWith safe st stmts
    Assert.AreEqual<BitVector>(one, st.GetReg(rf.GetRegisterID "F0"))
    Assert.AreEqual<Addr>(4UL, st.PC)

  [<TestMethod>]
  member _.``Undefined expression raises a catchable exception``() =
    let st = newState ()
    let raised =
      try
        Evaluator.evalExpr st (AST.undef 32<rt> "t") |> ignore
        false
      with :? UndefinedExprException ->
        true
    Assert.AreEqual<bool>(true, raised)

  [<TestMethod>]
  member _.``An unbacked load raises a catchable exception``() =
    let st = newState ()
    let addr = 0xdeadbeefUL
    let expr = AST.loadLE 32<rt> (AST.num (BitVector(addr, 64<rt>)))
    let failed =
      try
        Evaluator.evalExpr st expr |> ignore
        None
      with InvalidMemoryReadException failedAddr ->
        Some failedAddr
    Assert.AreEqual<Addr option>(Some addr, failed)

  [<TestMethod>]
  member _.``Side effect handler keeps its own termination``() =
    let st = newState ()
    st.SideEffectEventHandler <- (fun _ state -> state.AbortInstr())
    match SafeEvaluator.evalStmt st (AST.sideEffect SysCall) with
    | Ok() ->
      Assert.AreEqual<bool>(true, st.IsInstrTerminated)
      Assert.AreEqual<Addr>(0UL, st.PC)
    | Error e ->
      Assert.Fail $"Failed to evaluate a side effect: {e}"

  [<TestMethod>]
  member _.``Both evaluators agree on a defined instruction``() =
    (* add rax, rbx *)
    assertEvaluatorsAgree [| 0x48uy; 0x01uy; 0xd8uy |]

  [<TestMethod>]
  member _.``Both evaluators agree on an undefining instruction``() =
    (* mul rax : the lifter marks SF, ZF, AF and PF as undefined *)
    assertEvaluatorsAgree [| 0x48uy; 0xf7uy; 0xe0uy |]

  [<TestMethod>]
  member _.``An application expression is not evaluable``() =
    let st = newState ()
    match SafeEvaluator.evalExpr st (AST.app "f" [] 64<rt>) with
    | Error _ -> ()
    | Ok v -> Assert.Fail $"An application evaluated to {v}."

  [<TestMethod>]
  member _.``A jump to an unknown label fails instead of raising``() =
    let st = newState ()
    let target = Label("nowhere", 0, 0UL) |> AST.jmpDest
    match SafeEvaluator.evalStmt st (AST.jmp target) with
    | Error _ -> ()
    | Ok() -> Assert.Fail "The jump to an unknown label succeeded."

  [<TestMethod>]
  member _.``evalInstr advances the PC past a side effect``() =
    (* syscall *)
    let _, stmts = liftIntel [| 0x0fuy; 0x05uy |]
    let st = ConcState()
    match SafeEvaluator.evalInstr st stmts with
    | Ok() -> Assert.AreEqual<Addr>(2UL, st.PC)
    | Error e -> Assert.Fail $"Failed to evaluate: {e}"

  [<TestMethod>]
  member _.``evalInstr skips failing statements when told to``() =
    (* add rax, rbx, over a state where both operands are uninitialized *)
    let _, stmts = liftIntel [| 0x48uy; 0x01uy; 0xd8uy |]
    let st = ConcState()
    st.IgnoreUndef <- true
    match SafeEvaluator.evalInstr st stmts with
    | Ok() -> ()
    | Error e -> Assert.Fail $"Failed to evaluate: {e}"

  [<TestMethod>]
  member _.``evalInstr reports a failure when not ignoring undef``() =
    let _, stmts = liftIntel [| 0x48uy; 0x01uy; 0xd8uy |]
    match SafeEvaluator.evalInstr (ConcState()) stmts with
    | Error _ -> ()
    | Ok() -> Assert.Fail "An uninitialized operand evaluated fine."

  [<TestMethod>]
  member _.``The raising evalInstr drives a whole instruction``() =
    let hdl, stmts = liftIntel [| 0x48uy; 0x01uy; 0xd8uy |]
    let st = stateWithEveryRegisterSet hdl
    Evaluator.evalInstr st stmts
    match st.TryGetReg(hdl.RegisterFactory.GetRegisterID "RAX") with
    | Def v -> Assert.AreEqual<uint64>(2UL, v.ToUInt64())
    | Undef -> Assert.Fail "RAX was not written."

  [<TestMethod>]
  member _.``A terminated instruction leaves its later statements alone``() =
    (* Optimization trims a trailing IEMark that follows an inter-jump, so the
       last statement of an instruction is not always its IEMark. *)
    let target = AST.num (BitVector(0xdeadUL, 64<rt>))
    let stmts =
      [| AST.ismark 4u
         AST.sideEffect SysCall
         AST.interjmp target InterJmpKind.Base |]
    let st = ConcState()
    match SafeEvaluator.evalInstr st stmts with
    | Ok() -> Assert.AreEqual<Addr>(4UL, st.PC)
    | Error e -> Assert.Fail $"Failed to evaluate: {e}"

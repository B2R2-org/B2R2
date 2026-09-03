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
    let st = EvalState()
    st.CurrentInsLen <- 2u
    st

  let liftIntel (bytes: byte[]) =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let hdl = BinHandle.LoadRawImage(bytes, isa, OS.Linux)
    let lu = hdl.NewLiftingUnit()
    hdl, lu.LiftInstruction(lu.ParseInstruction 0UL)

  let stateWithEveryRegisterSet (hdl: BinHandle) =
    let st = EvalState()
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

  let assertTerminatedWithIEMark (st: EvalState) =
    Assert.AreEqual<bool>(true, st.IsInstrTerminated)
    Assert.AreEqual<bool>(true, st.NeedToEvaluateIEMark)

  [<TestMethod>]
  member _.``Safe side effect terminates the instruction by default``() =
    let st = newState ()
    match SafeEvaluator.evalStmt st (AST.sideEffect SysCall) with
    | Ok() -> assertTerminatedWithIEMark st
    | Error e -> Assert.Fail $"Failed to evaluate a side effect: {e}"

  [<TestMethod>]
  member _.``Unsafe side effect terminates the instruction by default``() =
    let st = newState ()
    Evaluator.evalStmt st (AST.sideEffect SysCall)
    assertTerminatedWithIEMark st

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
      Assert.AreEqual<bool>(false, st.NeedToEvaluateIEMark)
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

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
open B2R2.MiddleEnd.ConcEval

[<TestClass>]
type ConcExecutorTests() =
  let loadRawImage (bytes: byte[]) arch (ws: WordSize) =
    BinHandle.LoadRawImage(bytes, ISA(arch, ws), OS.Linux)

  let runOneInstruction (hdl: BinHandle) =
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    let opts = { ConcRunOptions.Default [] with MaxInstructions = 1 }
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
    let res = exec.Run(0UL, st, ConcRunOptions.Default(StopAfterAddress 0x3UL))
    Assert.AreEqual<Addr>(0x4UL, res.FinalAddress)
    Assert.AreEqual<int>(3, res.InstructionCount)

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
    let opts = { ConcRunOptions.Default [] with MaxInstructions = 7 }
    let res = exec.Run(0UL, st, opts)
    Assert.AreEqual<int>(7, res.InstructionCount)
    match res.StopReasons with
    | [ InstructionLimitReached(_, limit) ] ->
      Assert.AreEqual<int>(7, limit)
    | reasons ->
      Assert.Fail $"Unexpected stop reasons: {reasons}"

  [<TestMethod>]
  member _.``Default options carry an instruction limit``() =
    let opts: ConcRunOptions<EvalState> = ConcRunOptions.Default []
    Assert.AreEqual<int>(50000, opts.MaxInstructions)

  [<TestMethod>]
  member _.``Evaluation failure ends the run without a stop condition``() =
    (* ret *)
    let bytes = [| 0xc0uy; 0x03uy; 0x5fuy; 0xd6uy |]
    let hdl = loadRawImage bytes Architecture.ARMv8 WordSize.Bit64
    let exec = ConcExecutor hdl
    let st = exec.CreateState()
    let res = exec.Run(0UL, st, ConcRunOptions.Default(StopAtAddress 0xffffUL))
    match res.StopReasons with
    | [ EvaluationError(addr, e) ] ->
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

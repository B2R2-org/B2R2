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

namespace B2R2.MiddleEnd.SymEval

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.Executor

/// Represents a symbolic executor over SymEval's evaluation state.
type SymExecutor(hdl: BinHandle) =
  let lifter = hdl.NewLiftingUnit()

  let createState = function
    | EmptyMemory -> SymState()
    | PreinitializedMemory mem -> SymState mem
    | BinSectionBackedMemory -> SymState(BinSectionSymMemory hdl)

  let initializeState start opts =
    let st = createState opts.Memory
    st.InitializeContext(start, opts.Registers)
    st

  let mkResult reasons addr n st =
    { StopReasons = reasons
      FinalAddress = addr
      InstructionCount = n
      State = st }

  let hasStopAtReturn (opts: ExecutionOptions<SymState>) =
    opts.StopConditions
    |> List.exists (function StopAtReturn -> true | _ -> false)

  let hasStopAfterReturn (opts: ExecutionOptions<SymState>) =
    opts.StopConditions
    |> List.exists (function StopAfterReturn -> true | _ -> false)

  let hasStopAtCall (opts: ExecutionOptions<SymState>) =
    opts.StopConditions
    |> List.exists (function StopAtCall -> true | _ -> false)

  let tryGetDirectTarget (ins: IInstruction) =
    match ins.DirectBranchTarget() with
    | true, target -> Some target
    | false, _ -> None

  let stopAtCall (opts: ExecutionOptions<SymState>) (ins: IInstruction) =
    if ins.IsCall then
      hasStopAtCall opts
      || match opts.Calls with
         | StopAtCalls -> true
         | FollowDirectInternalCalls -> false
         | UseCallHooks -> false
    else false

  let tryParseInstruction addr =
    if hdl.File.IsValidAddr addr then lifter.TryParseInstruction addr
    else Error ErrorCase.ParsingFailure

  let tryLiftInstruction (ins: IInstruction) =
    try lifter.LiftInstruction ins |> Ok
    with _ -> Error ErrorCase.ParsingFailure

  let toErrorCase = function
    | UnsupportedExpression _
    | UnsupportedOperation _
    | UnsupportedSymbolicAddress _
    | UninitializedRegister _
    | UninitializedTemporary _ -> ErrorCase.InvalidExprEvaluation
    | InvalidMemoryRead _ -> ErrorCase.InvalidMemoryRead
    | UnsupportedStatement _ -> ErrorCase.NotImplementedIR
    | SolverFailure _ -> ErrorCase.UnexpectedError

  let rec evalStmtsFrom (st: SymState) (stmts: Stmt[]) =
    let numStmts = Array.length stmts
    if st.StmtIdx >= numStmts then [ SymEvaluator.Continue st ]
    elif st.IsInstrTerminated then
      if st.NeedToEvaluateIEMark then
        SymEvaluator.evalStmt st stmts[numStmts - 1]
        |> evalSuccessor stmts
      else [ SymEvaluator.Continue st ]
    else
      SymEvaluator.evalStmt st stmts[st.StmtIdx]
      |> evalSuccessor stmts

  and evalSuccessor stmts = function
    | SymEvaluator.Continue st -> evalStmtsFrom st stmts
    | SymEvaluator.Fork(trueState, falseState) ->
      evalStmtsFrom trueState stmts @ evalStmtsFrom falseState stmts
    | SymEvaluator.Stopped _ as stopped -> [ stopped ]
    | SymEvaluator.EvalError _ as error -> [ error ]

  let evalInstr (st: SymState) stmts =
    st.PrepareInstrEval stmts
    evalStmtsFrom st stmts

  let collectPreInstrStopReasons st addr n
                                 (opts: ExecutionOptions<SymState>) =
    let point = { Address = addr; InstructionCount = n; State = st }
    opts.StopConditions
    |> List.choose (function
      | StopAtAddress stopAddr when stopAddr = addr ->
        Some(StoppedAtAddress addr)
      | StopAfterInstructionCount limit when n >= limit ->
        Some(InstructionLimitReached(addr, limit))
      | StopWhen predicate when predicate point ->
        Some(UserStopConditionMet addr)
      | _ -> None)

  let collectInstrStopReasons opts addr (ins: IInstruction) =
    [ if hasStopAtReturn opts && ins.IsRET then StoppedAtReturn addr
      if stopAtCall opts ins then
        let target = tryGetDirectTarget ins
        StoppedAtCall(addr, target) ]

  let collectPostInstrStopReasons opts addr (ins: IInstruction) =
    let reasons =
      opts.StopConditions
      |> List.choose (function
        | StopAfterAddress stopAddr when stopAddr = addr ->
          Some(StoppedAfterAddress addr)
        | _ -> None)
    if hasStopAfterReturn opts && ins.IsRET then
      reasons @ [ StoppedAfterReturn addr ]
    else reasons

  let run start (st: SymState) opts =
    let rec loop n =
      let addr = st.PC
      let reasons = collectPreInstrStopReasons st addr n opts
      if not (List.isEmpty reasons) then mkResult reasons addr n st
      else
        match tryParseInstruction addr with
        | Error _ ->
          mkResult [ InvalidInstructionAddress addr ] addr n st
        | Ok ins ->
          match tryLiftInstruction ins with
          | Error _ ->
            mkResult [ InvalidInstructionAddress addr ] addr n st
          | Ok stmts ->
            let reasons = collectInstrStopReasons opts addr ins
            if not (List.isEmpty reasons) then mkResult reasons addr n st
            else
              let postReasons = collectPostInstrStopReasons opts addr ins
              match evalInstr st stmts with
              | [ SymEvaluator.Continue st ] ->
                if List.isEmpty postReasons then loop (n + 1)
                else mkResult postReasons st.PC (n + 1) st
              | [ SymEvaluator.Stopped(_, SymEvaluator.SideEffectStop eff) ] ->
                mkResult [ StoppedAtSideEffect(addr, eff) ] st.PC n st
              | [ SymEvaluator.EvalError e ] ->
                mkResult [ EvaluationError(addr, toErrorCase e) ] st.PC n st
              | _ -> Terminator.futureFeature ()
    st.PC <- start
    loop 0

  interface IExecutor<SymState, ISymMemory, SymExpr> with

    member _.CreateState() = SymState()

    member _.CreateState options = initializeState 0UL options

    member _.Run(start, state, options) = run start state options

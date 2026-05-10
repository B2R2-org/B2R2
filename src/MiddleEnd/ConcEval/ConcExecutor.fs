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

namespace B2R2.MiddleEnd.ConcEval

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.Executor

type private InstructionEvalResult =
  | EvalOk
  | EvalError of ErrorCase
  | EvalUndef
  | EvalSideEffect of SideEffect

/// Represents a concrete executor over ConcEval's evaluation state.
type ConcExecutor(hdl: BinHandle) =
  let lifter = hdl.NewLiftingUnit()

  let createState (memory: InitialMemory<IMemory>) =
    match memory with
    | EmptyMemory -> EvalState()
    | PreinitializedMemory mem -> EvalState mem
    | BinSectionBackedMemory -> EvalState(BinSectionMemory hdl)

  let initializeState start opts =
    let st = createState opts.Memory
    st.InitializeContext(start, opts.Registers)
    st

  let mkResult reason addr n st =
    { StopReason = reason
      FinalAddress = addr
      InstructionCount = n
      State = st }

  let rec hasUndefExpr = function
    | Undefined _ -> true
    | ExprList(exprs, _) -> List.exists hasUndefExpr exprs
    | UnOp(_, e, _) -> hasUndefExpr e
    | BinOp(_, _, e1, e2, _) -> hasUndefExpr e1 || hasUndefExpr e2
    | RelOp(_, e1, e2, _) -> hasUndefExpr e1 || hasUndefExpr e2
    | Load(_, _, addr, _) -> hasUndefExpr addr
    | Ite(c, t, f, _) ->
      hasUndefExpr c || hasUndefExpr t || hasUndefExpr f
    | Cast(_, _, e, _) -> hasUndefExpr e
    | Extract(e, _, _, _) -> hasUndefExpr e
    | Num _
    | Var _
    | PCVar _
    | TempVar _
    | JmpDest _
    | FuncName _ -> false

  let isUndefWrite = function
    | Put(_, rhs, _) -> hasUndefExpr rhs
    | Store(_, _, value, _) -> hasUndefExpr value
    | _ -> false

  let stopAtSideEffect (opts: ExecutionOptions<EvalState>) =
    opts.StopConditions
    |> List.exists (function StopAtSideEffect -> true | _ -> false)

  let stopAtRet (opts: ExecutionOptions<EvalState>) (ins: IInstruction) =
    ins.IsRET &&
    opts.StopConditions
    |> List.exists (function StopAtReturn -> true | _ -> false)

  let hasStopAtCall (opts: ExecutionOptions<EvalState>) =
    opts.StopConditions
    |> List.exists (function StopAtCall -> true | _ -> false)

  let tryGetDirectTarget (ins: IInstruction) =
    match ins.DirectBranchTarget() with
    | true, target -> Some target
    | false, _ -> None

  let stopAtCall (opts: ExecutionOptions<EvalState>) (ins: IInstruction) =
    if ins.IsCall then
      hasStopAtCall opts
      || match opts.Calls with
         | StopAtCalls -> true
         | FollowDirectInternalCalls -> false
         | UseCallHooks -> false
    else false

  let handleCallHooks (opts: ExecutionOptions<EvalState>) (ins: IInstruction) =
    if ins.IsCall then
      match opts.Calls with
      (*
        TODO: IExecutor does not yet define how call hooks are registered or
        dispatched. Once the hook API is available, dispatch the matching hook
        here instead of lifting and evaluating the original call.
      *)
      | UseCallHooks -> Terminator.futureFeature ()
      | _ -> ()
    else ()

  let evalStmt (opts: ExecutionOptions<EvalState>) (st: EvalState) stmt =
    match opts.UndefinedValues with
    | StopOnUndefinedValue when isUndefWrite stmt -> EvalUndef
    | IgnoreUndefinedWrites when isUndefWrite stmt ->
      st.NextStmt()
      EvalOk
    (*
      TODO: EvalState stores only BitVector values, so it cannot remember that
      a register, temporary, or memory cell currently holds an undefined value.
      To preserve undefined values, we need to change EvalState's value domain
      or track undefined registers/memory locally in ConcExecutor.
    *)
    | PreserveUndefinedValues when isUndefWrite stmt ->
      Terminator.futureFeature ()
    | _ ->
      match SafeEvaluator.evalStmt st stmt with
      | Ok() -> EvalOk
      | Error e -> EvalError e

  let rec evalStmts opts (st: EvalState) (stmts: Stmt[]) =
    let numStmts = Array.length stmts
    let idx = st.StmtIdx
    if idx < numStmts then
      if st.IsInstrTerminated then
        if st.NeedToEvaluateIEMark then
          evalStmt opts st stmts[numStmts - 1]
        else EvalOk
      else
        match stmts[idx] with
        | SideEffect(eff, _) when stopAtSideEffect opts -> EvalSideEffect eff
        | stmt ->
          match evalStmt opts st stmt with
          | EvalOk -> evalStmts opts st stmts
          | EvalError e -> EvalError e
          | EvalUndef -> EvalUndef
          | EvalSideEffect eff -> EvalSideEffect eff
    else EvalOk

  let tryParseInstruction addr =
    if hdl.File.IsValidAddr addr then lifter.TryParseInstruction addr
    else Error ErrorCase.ParsingFailure

  let tryLiftInstruction (ins: IInstruction) =
    try lifter.LiftInstruction ins |> Ok
    with _ -> Error ErrorCase.ParsingFailure

  let checkStopConditions (st: EvalState) addr n
                          (opts: ExecutionOptions<EvalState>) =
    let point = { Address = addr; InstructionCount = n; State = st }
    opts.StopConditions
    |> List.tryPick (function
      | StopAtAddress stopAddr when stopAddr = addr ->
        Some(StoppedAtAddress addr)
      | StopAfterInstructionCount limit when n >= limit ->
        Some(InstructionLimitReached(addr, limit))
      | StopWhen predicate when predicate point ->
        Some(UserStopConditionMet addr)
      | _ -> None)

  let evalInstr opts (st: EvalState) stmts =
    st.PrepareInstrEval stmts
    evalStmts opts st stmts

  let run start (st: EvalState) (opts: ExecutionOptions<EvalState>) =
    let rec loop n =
      let addr = st.PC
      match checkStopConditions st addr n opts with
      | Some reason -> mkResult reason addr n st
      | None ->
        match tryParseInstruction addr with
        | Error _ -> mkResult (InvalidInstructionAddress addr) addr n st
        | Ok ins ->
          if stopAtRet opts ins then mkResult (Returned addr) addr n st
          elif stopAtCall opts ins then
            let target = tryGetDirectTarget ins
            mkResult (StoppedAtCall(addr, target)) addr n st
          else
            handleCallHooks opts ins
            match tryLiftInstruction ins with
            | Error _ -> mkResult (InvalidInstructionAddress addr) addr n st
            | Ok stmts ->
              match evalInstr opts st stmts with
              | EvalOk -> loop (n + 1)
              | EvalError e ->
                let reason = EvaluationError(addr, e)
                mkResult reason st.PC n st
              | EvalUndef -> mkResult (UndefinedValue addr) st.PC n st
              | EvalSideEffect eff ->
                let reason = StoppedAtSideEffect(addr, eff)
                mkResult reason st.PC n st
    st.PC <- start
    loop 0

  interface IExecutor<EvalState, IMemory, BitVector> with
    /// Create a fresh concrete evaluation state.
    member _.CreateState() = EvalState()

    /// Create a concrete evaluation state with the given initial memory and
    /// register values. Since the start address is not known yet, initialize
    /// PC to zero here; Run will set it to the actual start address.
    member _.CreateState options = initializeState 0UL options

    /// Run concrete execution from the given address.
    member _.Run(start, state, options) = run start state options

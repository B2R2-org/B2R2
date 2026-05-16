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
open B2R2.Collections
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.Executor

/// Represents a concrete stop point observed by a user-defined predicate.
type ConcStopPoint<'State> =
  { /// Current instruction address.
    Address: Addr
    /// Number of executed machine instructions.
    InstructionCount: int
    /// Concrete executor state.
    State: 'State }

/// Represents a concrete execution stop condition.
type ConcStopCondition<'State> =
  /// Stop before executing the instruction at the given address.
  | StopAtAddress of addr: Addr
  /// Stop after executing the instruction at the given address.
  | StopAfterAddress of addr: Addr
  /// Stop when a function return is observed.
  | StopAtReturn
  /// Stop after executing a function return.
  | StopAfterReturn
  /// Stop when a call instruction is observed.
  | StopAtCall
  /// Stop when a side-effect statement is observed.
  | StopAtSideEffect
  /// Stop after executing the given number of machine instructions.
  | StopAfterInstructionCount of count: int
  /// Stop when expression or statement evaluation fails.
  | StopOnEvaluationError
  /// Stop when a user-provided predicate holds.
  | StopWhen of predicate: (ConcStopPoint<'State> -> bool)

/// Represents the reason why concrete execution stopped.
type ConcStopReason =
  /// Execution reached an address requested by a stop condition.
  | StoppedAtAddress of addr: Addr
  /// Execution completed an instruction at the requested address.
  | StoppedAfterAddress of addr: Addr
  /// Execution reached a function return.
  | StoppedAtReturn of addr: Addr
  /// Execution completed a function return.
  | StoppedAfterReturn of addr: Addr
  /// Execution reached a call instruction. The target may be unknown.
  | StoppedAtCall of callSite: Addr * target: Addr option
  /// Execution reached a side-effect statement.
  | StoppedAtSideEffect of addr: Addr * sideEffect: SideEffect
  /// Execution stopped because an undefined value was observed.
  | UndefinedValue of addr: Addr
  /// Execution reached the configured instruction limit.
  | InstructionLimitReached of addr: Addr * limit: int
  /// Evaluation failed with a B2R2 error case.
  | EvaluationError of addr: Addr * error: ErrorCase
  /// A user-defined stop predicate requested termination.
  | UserStopConditionMet of addr: Addr
  /// No instruction could be fetched or lifted at the given address.
  | InvalidInstructionAddress of addr: Addr

/// Represents how the concrete executor should handle call instructions.
type ConcCallPolicy =
  /// Stop when any call instruction is observed.
  | StopAtCalls
  /// Follow direct calls whose target is inside the current binary.
  | FollowDirectInternalCalls
  /// Invoke registered call hooks when a matching target is observed.
  | UseCallHooks

/// Represents how concrete execution should handle undefined values.
type ConcUndefinedValuePolicy =
  /// Treat undefined values as evaluation failures.
  | StopOnUndefinedValue
  /// Ignore writes whose right-hand side is undefined.
  | IgnoreUndefinedWrites
  /// Preserve undefined values in the concrete evaluator state.
  | PreserveUndefinedValues

/// Represents how concrete execution should handle uninitialized register
/// reads.
type UninitializedRegisterPolicy =
  /// Treat uninitialized register reads as evaluation failures.
  | StopOnUninitializedRegister
  /// Materialize caller-provided context registers as zero on first read.
  | ZeroCallerContext
  /// Materialize any uninitialized register as zero on first read.
  | ZeroAnyRegister

/// Represents concrete execution configuration.
type ConcRunOptions<'State> =
  { /// Call-handling policy.
    Calls: ConcCallPolicy
    /// Undefined-value handling policy.
    UndefinedValues: ConcUndefinedValuePolicy
    /// Uninitialized register read handling policy.
    UninitializedRegisters: UninitializedRegisterPolicy
    /// Stop conditions used by Run.
    StopConditions: ConcStopCondition<'State> list }

/// Represents the result of a concrete execution run.
type ConcRunResult<'State> =
  { /// Reasons why execution stopped.
    StopReasons: ConcStopReason list
    /// Final instruction address or program counter.
    FinalAddress: Addr
    /// Number of executed machine instructions.
    InstructionCount: int
    /// Final concrete executor state.
    State: 'State }

type private InstructionEvalResult =
  | EvalOk
  | EvalError of ErrorCase
  | EvalUndef
  | EvalSideEffect of SideEffect

/// Represents a concrete executor over ConcEval's evaluation state.
type ConcExecutor(hdl: BinHandle) =
  let lifter = hdl.NewLiftingUnit()
  let regFactory = hdl.RegisterFactory

  let createState (memory: InitialMemory<IMemory>) =
    match memory with
    | EmptyMemory -> EvalState()
    | PreinitializedMemory mem -> EvalState mem
    | BinSectionBackedMemory -> EvalState(BinSectionMemory hdl)

  let initializeState start opts =
    let st = createState opts.Memory
    st.InitializeContext(start, opts.Registers)
    st

  let isRegisterNamed names rid =
    let name = regFactory.GetRegisterName rid
    names |> Array.exists ((=) name)

  let isControlRegister rid =
    regFactory.IsProgramCounter rid
    || regFactory.IsStackPointer rid
    || isRegisterNamed [| "PC"; "NPC"; "SP"; "RSP"; "ESP" |] rid

  let isReturnAddressRegister rid =
    isRegisterNamed [| "LR"; "RA" |] rid

  let isGlobalPointerRegister rid =
    isRegisterNamed [| "GP" |] rid

  let isCallerContextRegister rid =
    not (isControlRegister rid)
    && not (isReturnAddressRegister rid)
    && not (isGlobalPointerRegister rid)

  let zeroRegister rid =
    regFactory.GetRegType rid
    |> BitVector.Zero

  let tryGetDefaultRegisterValue opts rid =
    match opts.UninitializedRegisters with
    | StopOnUninitializedRegister -> None
    | ZeroCallerContext when isCallerContextRegister rid ->
      Some(zeroRegister rid)
    | ZeroCallerContext -> None
    | ZeroAnyRegister -> Some(zeroRegister rid)

  let mkResult reasons addr n st =
    { StopReasons = reasons
      FinalAddress = addr
      InstructionCount = n
      State = st }

  let collectStmtReadRegisters rset = function
    | Put(_, rhs, _) -> AST.updateRegsUses rset rhs
    | Store(_, addr, value, _) ->
      AST.updateRegsUses rset addr
      AST.updateRegsUses rset value
    | CJmp(cond, _, _, _) -> AST.updateRegsUses rset cond
    | InterJmp(target, _, _) -> AST.updateRegsUses rset target
    | InterCJmp(cond, target1, target2, _) ->
      AST.updateRegsUses rset cond
      AST.updateRegsUses rset target1
      AST.updateRegsUses rset target2
    | ExternalCall(args, _) -> AST.updateRegsUses rset args
    | ISMark _
    | IEMark _
    | LMark _
    | Jmp _
    | SideEffect _ -> ()

  let isUninitializedRegister (st: EvalState) rid =
    match st.TryGetReg rid with
    | Undef -> true
    | Def _ -> false

  let materializeRegister opts (st: EvalState) ridx =
    let rid = RegisterID.create ridx
    match tryGetDefaultRegisterValue opts rid with
    | Some v when isUninitializedRegister st rid -> st.SetReg(rid, v)
    | _ -> ()

  let materializeReadRegisters opts st stmt =
    let rset = RegisterSet()
    collectStmtReadRegisters rset stmt
    rset.Iterate(materializeRegister opts st)

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

  let stopAtSideEffect (opts: ConcRunOptions<EvalState>) =
    opts.StopConditions
    |> List.exists (function StopAtSideEffect -> true | _ -> false)

  let hasStopAtReturn (opts: ConcRunOptions<EvalState>) =
    opts.StopConditions
    |> List.exists (function StopAtReturn -> true | _ -> false)

  let hasStopAfterReturn (opts: ConcRunOptions<EvalState>) =
    opts.StopConditions
    |> List.exists (function StopAfterReturn -> true | _ -> false)

  let tryEvalBranchCondition opts (st: EvalState) = function
    | CJmp(cond, _, _, _)
    | InterCJmp(cond, _, _, _) ->
      let rset = RegisterSet()
      AST.updateRegsUses rset cond
      rset.Iterate(materializeRegister opts st)
      match SafeEvaluator.evalExpr st cond with
      | Ok(Def v) -> Some(v = EvalUtils.tr)
      | _ -> Some false
    | _ -> None

  let isConditionalBranchTaken opts st stmts =
    Array.tryPick (tryEvalBranchCondition opts st) stmts
    |> Option.defaultValue false

  let isReturnTaken opts (st: EvalState) (ins: IInstruction) stmts =
    ins.IsRET
    && (not ins.IsCondBranch || isConditionalBranchTaken opts st stmts)

  let hasStopAtCall (opts: ConcRunOptions<EvalState>) =
    opts.StopConditions
    |> List.exists (function StopAtCall -> true | _ -> false)

  let tryGetDirectTarget (ins: IInstruction) =
    match ins.DirectBranchTarget() with
    | true, target -> Some target
    | false, _ -> None

  let stopAtCall (opts: ConcRunOptions<EvalState>) (ins: IInstruction) =
    if ins.IsCall then
      hasStopAtCall opts
      || match opts.Calls with
         | StopAtCalls -> true
         | FollowDirectInternalCalls -> false
         | UseCallHooks -> false
    else false

  let handleCallHooks (opts: ConcRunOptions<EvalState>) (ins: IInstruction) =
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

  let evalStmt (opts: ConcRunOptions<EvalState>) (st: EvalState) stmt =
    materializeReadRegisters opts st stmt
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
      | Result.Error e -> EvalError e

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
    else Result.Error ErrorCase.ParsingFailure

  let tryLiftInstruction (ins: IInstruction) =
    try lifter.LiftInstruction ins |> Ok
    with _ -> Result.Error ErrorCase.ParsingFailure

  let collectPreInstrStopReasons (st: EvalState) addr n
                               (opts: ConcRunOptions<EvalState>) =
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

  let collectInstrStopReasons opts st addr (ins: IInstruction) stmts =
    [ if hasStopAtReturn opts && isReturnTaken opts st ins stmts then
        StoppedAtReturn addr
      if stopAtCall opts ins then
        let target = tryGetDirectTarget ins
        StoppedAtCall(addr, target) ]

  let collectPostInstrStopReasons opts st addr (ins: IInstruction) stmts =
    let reasons =
      opts.StopConditions
      |> List.choose (function
        | StopAfterAddress stopAddr when stopAddr = addr ->
          Some(StoppedAfterAddress addr)
        | _ -> None)
    if hasStopAfterReturn opts && isReturnTaken opts st ins stmts then
      reasons @ [ StoppedAfterReturn addr ]
    else reasons

  let evalInstr opts (st: EvalState) stmts =
    st.PrepareInstrEval stmts
    evalStmts opts st stmts

  let run start (st: EvalState) (opts: ConcRunOptions<EvalState>) =
    let rec loop n =
      let addr = st.PC
      let reasons = collectPreInstrStopReasons st addr n opts
      match tryParseInstruction addr with
      | Result.Error _ ->
        mkResult (reasons @ [ InvalidInstructionAddress addr ]) addr n st
      | Ok ins ->
        match tryLiftInstruction ins with
        | Result.Error _ ->
          mkResult (reasons @ [ InvalidInstructionAddress addr ]) addr n st
        | Ok stmts ->
          let reasons = reasons @ collectInstrStopReasons opts st addr ins stmts
          let postReasons = collectPostInstrStopReasons opts st addr ins stmts
          if List.isEmpty reasons then
            handleCallHooks opts ins
            match evalInstr opts st stmts with
            | EvalOk ->
              if List.isEmpty postReasons then loop (n + 1)
              else mkResult postReasons st.PC (n + 1) st
            | EvalError e ->
              mkResult [ EvaluationError(addr, e) ] st.PC n st
            | EvalUndef -> mkResult [ UndefinedValue addr ] st.PC n st
            | EvalSideEffect eff ->
              mkResult [ StoppedAtSideEffect(addr, eff) ] st.PC n st
          else
            mkResult reasons addr n st
    st.PC <- start
    loop 0

  /// Create a fresh concrete evaluation state.
  member _.CreateState() = EvalState()

  /// Create a concrete evaluation state with the given initial memory and
  /// register values. Since the start address is not known yet, initialize
  /// PC to zero here; Run will set it to the actual start address.
  member _.CreateState options = initializeState 0UL options

  /// Run concrete execution from the given address.
  member _.Run(start, state, options) = run start state options

  interface IExecutor<EvalState,
                      IMemory,
                      BitVector,
                      ConcRunOptions<EvalState>,
                      ConcRunResult<EvalState>> with
    /// Create a fresh concrete evaluation state.
    member this.CreateState() = this.CreateState()

    /// Create a concrete evaluation state with the given initial memory and
    /// register values. Since the start address is not known yet, initialize
    /// PC to zero here; Run will set it to the actual start address.
    member this.CreateState options = this.CreateState options

    /// Run concrete execution from the given address.
    member this.Run(start, state, options) =
      this.Run(start, state, options)

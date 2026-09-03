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
open B2R2.ABI
open B2R2.Collections
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.Executor

/// Represents a concrete stop point observed by a user-defined predicate.
type ConcStopPoint =
  { /// Current instruction address.
    Address: Addr
    /// Number of executed machine instructions.
    InstructionCount: int
    /// Concrete executor state.
    State: EvalState }

/// Represents a concrete execution stop condition.
[<RequireQualifiedAccess>]
type ConcStopCondition =
  /// Stop before executing the instruction at the given address.
  | StopAtAddress of addr: Addr
  /// Stop after executing the instruction at the given address.
  | StopAfterAddress of addr: Addr
  /// Stop when a function return is observed.
  | StopAtReturn
  /// Stop after executing a function return.
  | StopAfterReturn
  /// Stop when a side-effect statement is observed.
  | StopAtSideEffect
  /// Stop when a user-provided predicate holds.
  | StopWhen of predicate: ConcStopPredicate

/// Represents a user-provided predicate that decides whether concrete
/// execution should stop at the given stop point.
and ConcStopPredicate = delegate of ConcStopPoint -> bool

/// Represents the reason why concrete execution stopped.
[<RequireQualifiedAccess>]
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
  /// A call could not be handled under the configured call policy. The target
  /// is absent when the call is indirect.
  | CallHandlingFailure of callSite: Addr * target: Addr option * reason: string

/// Represents how the concrete executor should handle call instructions.
[<RequireQualifiedAccess>]
type ConcCallPolicy =
  /// Stop when any call instruction is observed.
  | StopAtCalls
  /// Follow calls, but reject a direct call whose target lies outside the
  /// current binary. An indirect call is followed wherever its concrete target
  /// leads, since only the direct target is known before the call runs.
  | FollowDirectInternalCalls
  /// Dispatch a registered hook in place of a call to a matching target, and
  /// follow a call to an unhooked internal target.
  | UseCallHooks of hooks: ConcCallHookRegistry

/// Represents how concrete execution should handle undefined values.
[<RequireQualifiedAccess>]
type ConcUndefinedValuePolicy =
  /// Treat undefined values as evaluation failures.
  | StopOnUndefinedValue
  /// Ignore writes whose right-hand side is undefined, leaving the target with
  /// whatever value it held before.
  | IgnoreUndefinedWrites
  /// Unset the register or temporary that an undefined write targets, so that
  /// it reads back as undefined instead of keeping a stale value. A store of
  /// an undefined value is skipped, since IMemory cannot mark a cell
  /// undefined.
  | PreserveUndefinedValues

/// Represents how concrete execution should handle uninitialized register
/// reads.
[<RequireQualifiedAccess>]
type ConcUninitializedRegisterPolicy =
  /// Treat uninitialized register reads as evaluation failures.
  | StopOnUninitializedRegister
  /// Materialize caller-provided context registers as zero on first read. The
  /// program counter, the stack pointer, and the register that holds the
  /// return address under the binary's ABI are left uninitialized.
  | ZeroCallerContext
  /// Materialize any uninitialized register as zero on first read.
  | ZeroAnyRegister

/// Represents concrete execution configuration.
type ConcRunOptions =
  { /// Call-handling policy.
    Calls: ConcCallPolicy
    /// Undefined-value handling policy.
    UndefinedValues: ConcUndefinedValuePolicy
    /// Uninitialized register read handling policy.
    UninitializedRegisters: ConcUninitializedRegisterPolicy
    /// Maximum machine instructions to execute. Zero means unlimited.
    MaxInstructions: int
    /// Stop conditions used by Run.
    StopConditions: ConcStopCondition list }
with
  static member Default(stopConditions: ConcStopCondition list) =
    { Calls = ConcCallPolicy.FollowDirectInternalCalls
      UndefinedValues = ConcUndefinedValuePolicy.IgnoreUndefinedWrites
      UninitializedRegisters = ConcUninitializedRegisterPolicy.ZeroCallerContext
      MaxInstructions = 50000
      StopConditions = stopConditions }

  static member Default(stopCondition: ConcStopCondition) =
    ConcRunOptions.Default [ stopCondition ]

/// Represents the result of a concrete execution run.
type ConcRunResult =
  { /// Reasons why execution stopped.
    StopReasons: ConcStopReason list
    /// Final instruction address or program counter.
    FinalAddress: Addr
    /// Number of executed machine instructions.
    InstructionCount: int
    /// Final concrete executor state.
    State: EvalState }
with
  /// Returns true when execution stopped before the given address.
  member this.IsStoppedAtAddress addr =
    this.StopReasons
    |> List.exists (function
      | ConcStopReason.StoppedAtAddress stopped -> stopped = addr
      | _ -> false)

type private InstructionEvalResult =
  | EvalOk
  | EvalError of ErrorCase
  | EvalUndef
  | EvalSideEffect of SideEffect
  | EvalStopped of ConcStopReason

/// Represents a concrete executor over ConcEval's evaluation state.
type ConcExecutor(hdl: BinHandle) =
  let lifter = hdl.NewLiftingUnit()
  let regFactory = hdl.RegisterFactory
  let wordType = hdl.ISA.WordSize |> WordSize.toRegType
  let endian = hdl.ISA.Endian
  let cc = hdl.Conventions.Calling
  (* An ABI that passes every integer argument on the stack, such as x86 cdecl,
     contributes no register here, so a hook reads those from the stack. *)
  let argumentRegisters =
    [| 0 .. 5 |]
    |> Array.choose (fun idx ->
      match cc.GetIntArgLocation idx with
      | ArgLocation.Reg rid -> Some rid
      | _ -> None)
  let defaultStateCreationOptions =
    { Memory = BinSectionBackedMemory
      Registers = [||] }

  let createState (memory: InitialMemory<IMemory>) =
    match memory with
    | EmptyMemory -> EvalState()
    | PreinitializedMemory mem -> EvalState mem
    | BinSectionBackedMemory -> EvalState(BinSectionMemory hdl)

  let initializeState start opts =
    let st = createState opts.Memory
    st.InitializeContext(start, opts.Registers)
    st

  let returnAddressRegister =
    match hdl.Conventions.Calling.ReturnAddressLocation with
    | InRegister rid -> Some rid
    | OnStack -> None

  let isReturnAddressRegister rid = returnAddressRegister = Some rid

  let isCallerContextRegister rid =
    not (regFactory.IsProgramCounter rid)
    && not (regFactory.IsStackPointer rid)
    && not (isReturnAddressRegister rid)

  let zeroRegister rid =
    regFactory.GetRegType rid
    |> BitVector.Zero

  let tryGetDefaultRegisterValue opts rid =
    match opts.UninitializedRegisters with
    | ConcUninitializedRegisterPolicy.StopOnUninitializedRegister ->
      None
    | ConcUninitializedRegisterPolicy.ZeroCallerContext ->
      if isCallerContextRegister rid then Some(zeroRegister rid) else None
    | ConcUninitializedRegisterPolicy.ZeroAnyRegister ->
      Some(zeroRegister rid)

  let mkResult reasons addr n st =
    { StopReasons = reasons
      FinalAddress = addr
      InstructionCount = n
      State = st }

  let collectStmtReadRegisters rset = function
    | Put(_, rhs, _) ->
      AST.updateRegsUses rset rhs
    | Store(_, addr, value, _) ->
      AST.updateRegsUses rset addr
      AST.updateRegsUses rset value
    | CJmp(cond, _, _, _) ->
      AST.updateRegsUses rset cond
    | InterJmp(target, _, _) ->
      AST.updateRegsUses rset target
    | InterCJmp(cond, target1, target2, _) ->
      AST.updateRegsUses rset cond
      AST.updateRegsUses rset target1
      AST.updateRegsUses rset target2
    | ExternalCall(args, _) ->
      AST.updateRegsUses rset args
    | ISMark _
    | IEMark _
    | LMark _
    | Jmp _
    | SideEffect _ ->
      ()

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
    | Ite(c, t, f, _) -> hasUndefExpr c || hasUndefExpr t || hasUndefExpr f
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

  let stopAtSideEffect (opts: ConcRunOptions) =
    opts.StopConditions |> List.contains ConcStopCondition.StopAtSideEffect

  let hasStopAtReturn (opts: ConcRunOptions) =
    opts.StopConditions |> List.contains ConcStopCondition.StopAtReturn

  let hasStopAfterReturn (opts: ConcRunOptions) =
    opts.StopConditions |> List.contains ConcStopCondition.StopAfterReturn

  let tryEvalBranchCondition opts (st: EvalState) = function
    | CJmp(cond, _, _, _)
    | InterCJmp(cond, _, _, _) ->
      let rset = RegisterSet()
      AST.updateRegsUses rset cond
      rset.Iterate(materializeRegister opts st)
      match SafeEvaluator.evalExpr st cond with
      | Ok(Def v) -> Some(v = EvalUtils.tr)
      | _ -> Some false
    | _ ->
      None

  let isConditionalBranchTaken opts st stmts =
    Array.tryPick (tryEvalBranchCondition opts st) stmts
    |> Option.defaultValue false

  let isReturnTaken opts (st: EvalState) (ins: IInstruction) stmts =
    ins.IsRET
    && (not ins.IsCondBranch || isConditionalBranchTaken opts st stmts)

  let tryGetDirectTarget (ins: IInstruction) =
    match ins.DirectBranchTarget() with
    | true, target -> Some target
    | false, _ -> None

  let stopAtCall (opts: ConcRunOptions) (ins: IInstruction) =
    ins.IsCall
    && match opts.Calls with
       | ConcCallPolicy.StopAtCalls -> true
       | ConcCallPolicy.FollowDirectInternalCalls -> false
       | ConcCallPolicy.UseCallHooks _ -> false

  (* A register or temporary with no entry reads back as Undef, so unsetting
     the target is all it takes to record that it now holds an undefined value.
     A memory cell has no such encoding: dropping it would expose whatever
     backs the address underneath, so an undefined store is left alone. *)
  let unsetUndefTarget (st: EvalState) = function
    | Put(Var(_, n, _, _), _, _) -> st.UnsetReg n
    | Put(TempVar(_, n, _), _, _) -> st.UnsetTmp n
    | _ -> ()

  let evalStmt (opts: ConcRunOptions) (st: EvalState) stmt =
    materializeReadRegisters opts st stmt
    match opts.UndefinedValues with
    | ConcUndefinedValuePolicy.StopOnUndefinedValue when isUndefWrite stmt ->
      EvalUndef
    | ConcUndefinedValuePolicy.IgnoreUndefinedWrites when isUndefWrite stmt ->
      st.NextStmt()
      EvalOk
    | ConcUndefinedValuePolicy.PreserveUndefinedValues when isUndefWrite stmt ->
      unsetUndefTarget st stmt
      st.NextStmt()
      EvalOk
    | _ ->
      match SafeEvaluator.evalStmt st stmt with
      | Ok() -> EvalOk
      | Result.Error e -> EvalError e

  let step opts st stmt =
    match stmt with
    | SideEffect(eff, _) when stopAtSideEffect opts ->
      Result.Error(EvalSideEffect eff)
    | _ ->
      match evalStmt opts st stmt with
      | EvalOk -> Ok()
      | stop -> Result.Error stop

  let tryParseInstruction addr =
    if hdl.File.IsValidAddr addr then lifter.TryParseInstruction addr
    else Result.Error ErrorCase.ParsingFailure

  (* Parsing already accepted the bytes, so a lifter that cannot express this
     instruction is the one expected failure; naming it keeps a defect in a
     lifter from being reported as a property of the input, which catching
     everything did, and under the wrong error case at that. *)
  let tryLiftInstruction (ins: IInstruction) =
    try lifter.LiftInstruction ins |> Ok
    with NotImplementedIRException _ -> Result.Error ErrorCase.NotImplementedIR

  let isInstructionLimitReached n (opts: ConcRunOptions) =
    match opts.MaxInstructions with
    | limit when limit > 0 && n >= limit -> Some limit
    | _ -> None

  let collectPreInstrStopReasons st addr n (opts: ConcRunOptions) =
    let point = { Address = addr; InstructionCount = n; State = st }
    let reasons =
      opts.StopConditions
      |> List.choose (function
        | ConcStopCondition.StopAtAddress stopAddr when stopAddr = addr ->
          Some(ConcStopReason.StoppedAtAddress addr)
        | ConcStopCondition.StopWhen predicate when predicate.Invoke point ->
          Some(ConcStopReason.UserStopConditionMet addr)
        | _ ->
          None)
    match isInstructionLimitReached n opts with
    | Some limit ->
      reasons @ [ ConcStopReason.InstructionLimitReached(addr, limit) ]
    | None ->
      reasons

  let collectInstrStopReasons opts st addr (ins: IInstruction) stmts =
    [ if hasStopAtReturn opts && isReturnTaken opts st ins stmts then
        ConcStopReason.StoppedAtReturn addr
      else
        ()
      if stopAtCall opts ins then
        let target = tryGetDirectTarget ins
        ConcStopReason.StoppedAtCall(addr, target)
      else
        () ]

  let collectPostInstrStopReasons opts st addr (ins: IInstruction) stmts =
    let reasons =
      opts.StopConditions
      |> List.choose (function
        | ConcStopCondition.StopAfterAddress stopAddr when stopAddr = addr ->
          Some(ConcStopReason.StoppedAfterAddress addr)
        | _ ->
          None)
    if hasStopAfterReturn opts && isReturnTaken opts st ins stmts then
      reasons @ [ ConcStopReason.StoppedAfterReturn addr ]
    else
      reasons

  let evalInstr opts (st: EvalState) stmts =
    st.PrepareInstrEval stmts
    match EvalUtils.tryEvalStmtsWith (step opts) st stmts with
    | Ok() -> EvalOk
    | Result.Error stop -> stop

  let isInternalTarget target = hdl.File.IsValidAddr target

  (* A MIPS call transfers control only after its delay slot has run, so the
     callee returns past that slot rather than to the next address. *)
  let getCallFallThroughAddr addr (ins: IInstruction) =
    match hdl.ISA with
    | MIPS ->
      let delaySlotAddr = addr + uint64 ins.Length
      match tryParseInstruction delaySlotAddr with
      | Ok delaySlot -> delaySlotAddr + uint64 delaySlot.Length
      | Result.Error _ -> delaySlotAddr + uint64 ins.Length
    | _ ->
      addr + uint64 ins.Length

  let mkCallContext callSite target returnAddress =
    { CallSite = callSite
      Target = target
      ReturnAddress = returnAddress
      WordType = wordType
      Endian = endian
      ArgumentRegisters = argumentRegisters
      ReturnRegister = cc.IntReturnRegister }

  let callFailure (ctx: ConcCallContext) msg =
    ConcStopReason.CallHandlingFailure(ctx.CallSite, Some ctx.Target, msg)
    |> Result.Error

  let pushReturnAddress (ctx: ConcCallContext) (st: EvalState) =
    let accessor = ConcStateAccessor(hdl, st)
    match accessor.TryPushToStack(accessor.WordValue ctx.ReturnAddress) with
    | Ok _ -> Ok()
    | Result.Error e -> callFailure ctx $"Cannot push a return address: {e}."

  let finishHook (ctx: ConcCallContext) (st: EvalState) =
    match ConcStateAccessor(hdl, st).TryPopFromStack() with
    | Ok v ->
      let retAddr = v.ToUInt64()
      if retAddr = ctx.ReturnAddress then
        st.PC <- ctx.ReturnAddress
        Ok()
      else
        callFailure ctx $"A hook returned to {retAddr:x}."
    | Result.Error e ->
      callFailure ctx $"A hook left the stack unbalanced: {e}."

  let dispatchCallHook (ctx: ConcCallContext) hook (st: EvalState) =
    match pushReturnAddress ctx st with
    | Result.Error reason ->
      Result.Error reason
    | Ok() ->
      match hook ctx st with
      | Ok() -> finishHook ctx st
      | Result.Error msg -> callFailure ctx msg

  let isExternalTarget target = not (isInternalTarget target)

  let callHandlingFailure addr target msg =
    ConcStopReason.CallHandlingFailure(addr, target, msg)
    |> Result.Error
    |> Some

  let tryHandleCall (opts: ConcRunOptions) st addr ins =
    if not (ins: IInstruction).IsCall then
      None
    else
      let target = tryGetDirectTarget ins
      match opts.Calls, target with
      | ConcCallPolicy.FollowDirectInternalCalls, Some t
        when isExternalTarget t ->
        let msg = $"A direct call targets {t:x}, outside the binary."
        callHandlingFailure addr target msg
      | ConcCallPolicy.UseCallHooks hooks, Some t ->
        match hooks.TryFind t with
        | Some hook ->
          let ctx = mkCallContext addr t (getCallFallThroughAddr addr ins)
          Some(dispatchCallHook ctx hook st)
        | None when isInternalTarget t ->
          None
        | None ->
          let msg = $"No call hook is registered for {t:x}."
          callHandlingFailure addr target msg
      | ConcCallPolicy.UseCallHooks _, None ->
        let msg = "Cannot dispatch a call hook without a direct target."
        callHandlingFailure addr None msg
      | _ ->
        None

  let evalCallOrInstr opts st addr ins stmts =
    match tryHandleCall opts st addr ins with
    | Some(Ok()) -> EvalOk
    | Some(Result.Error reason) -> EvalStopped reason
    | None -> evalInstr opts st stmts

  let run start (st: EvalState) (opts: ConcRunOptions) =
    let invalidInstr reasons addr n =
      let reason = ConcStopReason.InvalidInstructionAddress addr
      mkResult (reasons @ [ reason ]) addr n st
    let rec loop n =
      let addr = st.PC
      let reasons = collectPreInstrStopReasons st addr n opts
      match tryParseInstruction addr with
      | Result.Error _ ->
        invalidInstr reasons addr n
      | Ok ins ->
        match tryLiftInstruction ins with
        | Result.Error _ ->
          invalidInstr reasons addr n
        | Ok stmts ->
          let reasons = reasons @ collectInstrStopReasons opts st addr ins stmts
          let postReasons = collectPostInstrStopReasons opts st addr ins stmts
          if List.isEmpty reasons then
            match evalCallOrInstr opts st addr ins stmts with
            | EvalOk ->
              if List.isEmpty postReasons then loop (n + 1)
              else mkResult postReasons st.PC (n + 1) st
            | EvalStopped reason ->
              mkResult [ reason ] st.PC n st
            | EvalError e ->
              mkResult [ ConcStopReason.EvaluationError(addr, e) ] st.PC n st
            | EvalUndef ->
              mkResult [ ConcStopReason.UndefinedValue addr ] st.PC n st
            | EvalSideEffect eff ->
              let reason = ConcStopReason.StoppedAtSideEffect(addr, eff)
              mkResult [ reason ] st.PC n st
          else
            mkResult reasons addr n st
    st.PC <- start
    loop 0

  /// Create a fresh concrete evaluation state.
  member _.CreateState() = initializeState 0UL defaultStateCreationOptions

  /// Create a concrete evaluation state with the given initial memory and
  /// register values. Since the start address is not known yet, initialize
  /// PC to zero here; Run will set it to the actual start address.
  member _.CreateState options = initializeState 0UL options

  /// Runs concrete execution from the given address. Besides the configured
  /// stop conditions, a run always ends when an instruction cannot be parsed
  /// or lifted, when statement evaluation fails, or when an undefined value is
  /// observed under StopOnUndefinedValue; the stop reason says which.
  member _.Run(start, state, options) = run start state options

  /// Runs concrete execution from the given address with the default options
  /// for the given stop condition.
  member _.Run(start, state, stopCondition: ConcStopCondition) =
    ConcRunOptions.Default stopCondition
    |> run start state

  interface IExecutor<EvalState,
                      IMemory,
                      BitVector,
                      ConcRunOptions,
                      ConcRunResult> with
    /// Create a fresh concrete evaluation state.
    member this.CreateState() = this.CreateState()

    /// Create a concrete evaluation state with the given initial memory and
    /// register values. Since the start address is not known yet, initialize
    /// PC to zero here; Run will set it to the actual start address.
    member this.CreateState options = this.CreateState options

    /// Run concrete execution from the given address.
    member this.Run(start, state, options) = this.Run(start, state, options)

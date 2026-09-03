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
       | CallPolicy.StopAtCalls -> true
       | CallPolicy.FollowDirectInternalCalls -> false
       | CallPolicy.UseCallHooks _ -> false

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

  let collectPreInstrStopReasons point (opts: ConcRunOptions) =
    let addr, n = point.Address, point.InstructionCount
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

  let callFailure (ctx: CallContext) msg =
    ConcStopReason.CallHandlingFailure(ctx.CallSite, Some ctx.Target, msg)
    |> Result.Error

  let pushReturnAddress (ctx: CallContext) (st: EvalState) =
    let accessor = ConcStateAccessor(hdl, st)
    match accessor.TryPushToStack(accessor.WordValue ctx.ReturnAddress) with
    | Ok _ -> Ok()
    | Result.Error e -> callFailure ctx $"Cannot push a return address: {e}."

  let finishHook (ctx: CallContext) (st: EvalState) =
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

  let dispatchCallHook (ctx: CallContext) hook (st: EvalState) =
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
      | CallPolicy.FollowDirectInternalCalls, Some t
        when isExternalTarget t ->
        let msg = $"A direct call targets {t:x}, outside the binary."
        callHandlingFailure addr target msg
      | CallPolicy.UseCallHooks hooks, Some t ->
        match hooks.TryFind t with
        | Some hook ->
          let ctx = mkCallContext addr t (getCallFallThroughAddr addr ins)
          Some(dispatchCallHook ctx hook st)
        | None when isInternalTarget t ->
          None
        | None ->
          let msg = $"No call hook is registered for {t:x}."
          callHandlingFailure addr target msg
      | CallPolicy.UseCallHooks _, None ->
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
    let mkStopPoint addr n ins =
      { Address = addr; InstructionCount = n; Instruction = ins; State = st }
    let rec loop n =
      let addr = st.PC
      let parsed = tryParseInstruction addr
      let point = mkStopPoint addr n (Result.toOption parsed)
      let reasons = collectPreInstrStopReasons point opts
      match parsed with
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

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

namespace B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

open B2R2
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies.CFGRecoveryCommon

[<AutoOpen>]
module private CFGRecovery =
  let onAction (ctx: CFGBuildingContext<_, _>)
               cfgRec
               rules
               queue
               syscallAnalysis
               jmptblAnalysis
               sretAnalysis
               useTCHeuristic
               (action: CFGAction) =
    match action with
    | InitiateCFG ->
      let fnAddr = ctx.FunctionAddress
#if CFGDEBUG
      dbglog ctx.ThreadID (nameof InitiateCFG) $"{fnAddr:x}"
#endif
      let pp = ProgramPoint(fnAddr, 0)
      match scanBBLs ctx [ fnAddr ] with
      | Ok _ ->
        buildCFG ctx cfgRec rules syscallAnalysis useTCHeuristic queue [| pp |]
      | Error e ->
        FailStop e
    | ExpandCFG pps ->
#if CFGDEBUG
      let targets = pps |> Seq.map (fun pp -> $"{pp}") |> String.concat ";"
      dbglog ctx.ThreadID (nameof ExpandCFG)
      <| $"{targets} @ {ctx.FunctionAddress:x}"
#endif
      buildCFG ctx cfgRec rules syscallAnalysis useTCHeuristic queue pps
    | MakeCall(callSite, calleeAddr, calleeInfo) ->
#if CFGDEBUG
      dbglog ctx.ThreadID (nameof MakeCall)
      <| $"{ctx.FunctionAddress:x} to {calleeAddr:x}"
#endif
      connectCallEdge ctx cfgRec callSite calleeAddr calleeInfo false
    | MakeTlCall(callSite, calleeAddr, calleeInfo) ->
#if CFGDEBUG
      dbglog ctx.ThreadID (nameof MakeTlCall)
      <| $"{ctx.FunctionAddress:x} to {calleeAddr:x}"
#endif
      if isGivenUpGuess ctx calleeAddr then StopAndReload
      else connectCallEdge ctx cfgRec callSite calleeAddr calleeInfo true
    | MakeIndCall(callsiteAddr) ->
#if CFGDEBUG
      dbglog ctx.ThreadID (nameof MakeIndCall)
      <| $"{callsiteAddr:x} @ {ctx.FunctionAddress:x}"
#endif
      connectIndirectCallEdge ctx sretAnalysis cfgRec rules callsiteAddr
    | MakeSyscall(callsiteAddr, isExit) ->
#if CFGDEBUG
      dbglog ctx.ThreadID (nameof MakeSyscall) $"{ctx.FunctionAddress:x}"
#endif
      connectSyscallEdge ctx syscallAnalysis cfgRec callsiteAddr isExit
    | MakeIndEdges insAddr ->
#if CFGDEBUG
      dbglog ctx.ThreadID (nameof MakeIndEdges)
      <| $"{insAddr:x} @ {ctx.FunctionAddress:x}"
#endif
      recoverIndirectBranches ctx jmptblAnalysis queue insAddr
    | RetryIndEdges(insAddr, numEdges) ->
#if CFGDEBUG
      dbglog ctx.ThreadID (nameof RetryIndEdges)
      <| $"{insAddr:x} @ {ctx.FunctionAddress:x}"
#endif
      retryIndirectBranches ctx jmptblAnalysis queue insAddr numEdges
    | WaitForCallee calleeAddr ->
#if CFGDEBUG
      dbglog ctx.ThreadID (nameof WaitForCallee)
      <| $"{ctx.FunctionAddress:x} waits for {calleeAddr:x}"
#endif
      if not (ctx.PendingCallActions.ContainsKey calleeAddr) then
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof WaitForCallee) "-> move on"
#endif
        MoveOn
      elif isFailedBuilding ctx calleeAddr then
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof WaitForCallee) "-> failstop"
#endif
        if isGivenUpGuess ctx calleeAddr then StopAndReload
        else FailStop ErrorCase.FailedToRecoverCFG
      else
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof WaitForCallee) "-> wait"
#endif
        Wait (* yet resolved *)
    | StartTblRec(jmptbl, idx, dstAddr) ->
#if CFGDEBUG
      let fnAddr = ctx.FunctionAddress
      dbglog ctx.ThreadID (nameof StartTblRec)
      <| $"{jmptbl.InsAddr:x}[{idx}] -> {dstAddr:x} @ {fnAddr:x}"
#endif
      assert (if not jmptbl.IsSingleEntry then true else idx = 0)
      ctx.JumpTableRecoveryStatus.Push(jmptbl.TableAddress, idx)
      recoverJumpTableEntry ctx cfgRec rules idx jmptbl dstAddr
    | EndTblRec(jmptbl, idx) ->
#if CFGDEBUG
      dbglog ctx.ThreadID (nameof EndTblRec)
      <| $"{jmptbl.InsAddr:x}[{idx}] @ {ctx.FunctionAddress:x}"
#endif
      jmptbl.NumEntries <- idx + 1
      ctx.JumpTables[jmptbl.TableAddress] <- jmptbl
      ctx.JumpTableRecoveryStatus.Pop() |> ignore
      sendJmpTblRecoverySuccess ctx rules queue jmptbl idx
    | UpdateCallEdges(calleeAddr, calleeInfo) ->
#if CFGDEBUG
      let noret, unwinding = calleeInfo.Status, calleeInfo.Unwinding
      let fnAddr = ctx.FunctionAddress
      dbglog ctx.ThreadID (nameof UpdateCallEdges)
      <| $"{calleeAddr:x} changed to ({noret}:{unwinding}) @ {fnAddr:x}"
#endif
      updateCallEdges ctx cfgRec calleeAddr calleeInfo
    | ResumeAnalysis(_) ->
      Terminator.impossible ()
    | StartGapAnalysis(addr) ->
      assert (ctx.GapToAnalyze.IsNone)
      ctx.GapToAnalyze <- Some(addr)
      match scanBBLs ctx [ addr ] with
      | Ok(_) ->
        let pp = ProgramPoint(addr, 0)
        let v = getVertex ctx cfgRec pp
        ctx.CFG.AddRoot(v)
        recoverNoReturnFallThroughEdge ctx v
        buildCFG ctx cfgRec rules syscallAnalysis useTCHeuristic queue [ pp ]
      | Error e ->
        FailStop e
    | EndGapAnalysis ->
      assert (ctx.GapToAnalyze.IsSome)
      ctx.GapToAnalyze <- None
      MoveOn

/// Represents a base strategy for building a CFG.
type CFGRecovery<'FnCtx, 'GlCtx
  when 'FnCtx :> IResettable
  and 'FnCtx: (new: unit -> 'FnCtx)
  and 'GlCtx: (new: unit -> 'GlCtx)>
  public(summarizer: IFunctionSummarizable<'FnCtx, 'GlCtx>,
         jmptblAnalysis: IJmpTableAnalyzable<'FnCtx, 'GlCtx>,
         sretAnalysis: ISRetAnalyzable<'FnCtx, 'GlCtx>,
         syscallAnalysis: ISyscallAnalyzable,
         postAnalysis: ICFGAnalysis<_>,
         options: CFGRecoveryOptions) as this =

  let defaultRules = CFGRecoveryRules<'FnCtx, 'GlCtx>()

  let intelRules = IntelCFGRecoveryRules<'FnCtx, 'GlCtx>()

  let arm32Rules = ARM32CFGRecoveryRules<'FnCtx, 'GlCtx>()

  let mipsRules = MIPSCFGRecoveryRules<'FnCtx, 'GlCtx>()

  /// Returns the rules for the architecture of the binary that the given
  /// context builds a function of. The binary tells, rather than the ISA that
  /// the strategy may be made with, as a strategy made without one serves a
  /// binary of any architecture.
  let rulesOf (ctx: CFGBuildingContext<'FnCtx, 'GlCtx>) =
    match ctx.BinHandle.ISA with
    | Intel -> intelRules :> ICFGRecoveryRules<_, _>
    | ARM32 -> arm32Rules :> ICFGRecoveryRules<_, _>
    | MIPS -> mipsRules :> ICFGRecoveryRules<_, _>
    | _ -> defaultRules :> ICFGRecoveryRules<_, _>

  interface ICFGRecovery<'FnCtx, 'GlCtx> with
    member _.Summarizer with get() = summarizer

    member _.ActionPrioritizer with get() = prioritizer

    member _.RecoveryTargets with get() = options.RecoveryTargets

    member _.CreateFunctionContext() = new 'FnCtx()

    member _.ResetFunctionContext fnCtx = fnCtx.Reset()

    member _.CreateGlobalContext() = new 'GlCtx()

    member _.AnalyzeIndirectJump(ctx, srcVertex) =
      let insAddr = srcVertex.VData.Internals.LastInstruction.Address
      let callsite = LeafCallSite insAddr
      addCallerVertex ctx callsite srcVertex
      pushAction ctx <| MakeIndEdges insAddr
      None

    member _.AnalyzeIndirectCondJump(_, _) = None

    member _.OnAction(ctx, queue, action) =
      onAction ctx
               this
               (rulesOf ctx)
               queue
               syscallAnalysis
               jmptblAnalysis
               sretAnalysis
               options.UseTailcallHeuristic
               action

    member _.OnCreate _ctx = ()

    member _.OnFinish ctx = onFinish ctx this (rulesOf ctx) postAnalysis

    member _.OnCyclicDependency deps = onCyclicDependency deps

    member _.OnAddVertex(ctx, vertex) =
      if not options.UseSSA then markVertexAsPendingForAnalysis ctx vertex
      else ()

    member _.OnAddEdge(ctx, _srcVertex, dstVertex, _edgeKind) =
      if not options.UseSSA then markVertexAsPendingForAnalysis ctx dstVertex
      else ()
      rejudgeConditionalCall ctx dstVertex

    member _.OnRemoveVertex(ctx, vertex) =
      markVertexAsRemovalForAnalysis ctx vertex

    member _.FindCandidatesForPostProcessing _ = [||]

  interface ICFGRevisingStrategy<'FnCtx, 'GlCtx> with
    (* Without the heuristic, no jump calls a function, so building a function
       again would follow the same jumps within it. *)
    member _.FindFunctionsToRebuild builders =
      let tryContextOf (builder: IFunctionBuilder) =
        match builder with
        | :? ICFGBuildable<'FnCtx, 'GlCtx> as built -> Some built.Context
        | _ -> None
      match Array.tryPick tryContextOf builders with
      | Some ctx when options.UseTailcallHeuristic ->
        (rulesOf ctx).FindFunctionsToRebuild builders
      | _ ->
        [||]

  new() = CFGRecovery(CFGRecoveryOptions.Default)

  new(options: CFGRecoveryOptions) =
    let sretAnalysis =
      SRetAnalysis() :> ISRetAnalyzable<_, _>
    CFGRecovery(sretAnalysis, options)

  new(isa: ISA, options: CFGRecoveryOptions) =
    let sretAnalysis: ISRetAnalyzable<'FnCtx, 'GlCtx> =
      match isa with
      | X86 -> Intel32SRetAnalysis()
      | _ -> SRetAnalysis()
    CFGRecovery(sretAnalysis, options)

  new(sretAnalysis, options: CFGRecoveryOptions) =
    let summarizer = FunctionSummarizer()
    let syscallAnalysis = SyscallAnalysis()
    let calleeAnalyses =
      (CalleeClobberAnalysis() :> ICFGAnalysis<unit -> unit>)
      <+> PointerWriteAnalysis()
    let jmptblAnalysis, postAnalysis =
      if options.UseSSA then
        let ssaLifter = SSALifter() :> ICFGAnalysis<_>
        let onlyGraph (r: SSACFGWithDominance) = r.Graph
        let ssaOnly = ICFGAnalysis.map onlyGraph ssaLifter
        let jmpTableAnalysis =
          JmpTableAnalysis(Some ssaOnly) :> IJmpTableAnalyzable<_, _>
        let noret = ssaLifter <+> CondAwareNoretAnalysis()
        jmpTableAnalysis, noret <+> calleeAnalyses
      else
        let jmpTableAnalysis =
          JmpTableAnalysis None :> IJmpTableAnalyzable<_, _>
        let noret = CondAwareNoretAnalysis() :> ICFGAnalysis<unit -> unit>
        jmpTableAnalysis, noret <+> calleeAnalyses
    CFGRecovery(summarizer,
                jmptblAnalysis,
                sretAnalysis,
                syscallAnalysis,
                postAnalysis,
                options)

/// Represents a base strategy for building a CFG without any customizable
/// context.
type CFGRecovery =
  inherit CFGRecovery<DummyContext, DummyContext>

  new() = { inherit CFGRecovery<DummyContext, DummyContext>() }

  new(options: CFGRecoveryOptions) =
    { inherit CFGRecovery<DummyContext, DummyContext>(options) }

  new(isa: ISA, options: CFGRecoveryOptions) =
    { inherit CFGRecovery<DummyContext, DummyContext>(isa, options) }

  new(sretAnalysis: ISRetAnalyzable<DummyContext, DummyContext>,
      options: CFGRecoveryOptions) =
    { inherit CFGRecovery<DummyContext, DummyContext>(sretAnalysis, options) }

  new(summarizer,
      jmptblAnalysis,
      sretAnalysis,
      syscallAnalysis,
      postAnalysis,
      options: CFGRecoveryOptions) =
    { inherit CFGRecovery<DummyContext, DummyContext>(summarizer,
                                                      jmptblAnalysis,
                                                      sretAnalysis,
                                                      syscallAnalysis,
                                                      postAnalysis,
                                                      options) }

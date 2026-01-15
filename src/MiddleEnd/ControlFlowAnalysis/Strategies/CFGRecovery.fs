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

open System
open B2R2
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies.CFGRecoveryCommon

[<AutoOpen>]
module private CFGRecovery =
  let onAction (ctx: CFGBuildingContext<_, _>) cfgRec queue syscallAnalysis
               jmptblAnalysis useTCHeuristic (action: CFGAction) =
    try
      match action with
      | InitiateCFG ->
        let fnAddr = ctx.FunctionAddress
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof InitiateCFG) $"{fnAddr:x}"
#endif
        let pp = ProgramPoint(fnAddr, 0)
        match scanBBLs ctx [ fnAddr ] with
        | Ok _ ->
          buildCFG ctx cfgRec syscallAnalysis useTCHeuristic queue [| pp |]
        | Error e ->
          FailStop e
      | ExpandCFG pps ->
#if CFGDEBUG
        let targets = pps |> Seq.map (fun pp -> $"{pp}") |> String.concat ";"
        dbglog ctx.ThreadID (nameof ExpandCFG)
        <| $"{targets} @ {ctx.FunctionAddress:x}"
#endif
        buildCFG ctx cfgRec syscallAnalysis useTCHeuristic queue pps
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
        connectCallEdge ctx cfgRec callSite calleeAddr calleeInfo true
      | MakeIndCall(callsiteAddr) ->
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof MakeIndCall)
        <| $"{callsiteAddr:x} @ {ctx.FunctionAddress:x}"
#endif
        connectIndirectCallEdge ctx cfgRec callsiteAddr
      | MakeSyscall(callsiteAddr, isExit) ->
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof MakeSyscall) $"{ctx.FunctionAddress:x}"
#endif
        connectSyscallEdge ctx syscallAnalysis cfgRec callsiteAddr isExit
      | MakeIndEdges(bblAddr, insAddr) ->
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof MakeIndEdges)
        <| $"{bblAddr:x} @ {ctx.FunctionAddress:x}"
#endif
        recoverIndirectBranches ctx jmptblAnalysis queue insAddr bblAddr
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
          FailStop ErrorCase.FailedToRecoverCFG
        else
#if CFGDEBUG
          dbglog ctx.ThreadID (nameof WaitForCallee) "-> wait"
#endif
          Wait (* yet resolved *)
      | StartTblRec(jmptbl, idx, srcAddr, dstAddr) ->
#if CFGDEBUG
        let fnAddr = ctx.FunctionAddress
        dbglog ctx.ThreadID (nameof StartTblRec)
        <| $"{jmptbl.InsAddr:x}[{idx}] -> {dstAddr:x} @ {fnAddr:x}"
#endif
        assert (if not jmptbl.IsSingleEntry then true else idx = 0)
        ctx.JumpTableRecoveryStatus.Push(jmptbl.TableAddress, idx)
        recoverJumpTableEntry ctx cfgRec queue jmptbl.InsAddr srcAddr dstAddr
      | EndTblRec(jmptbl, idx) ->
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof EndTblRec)
        <| $"{jmptbl.InsAddr:x}[{idx}] @ {ctx.FunctionAddress:x}"
#endif
        jmptbl.NumEntries <- idx + 1
        ctx.JumpTables.Add jmptbl
        ctx.JumpTableRecoveryStatus.Pop() |> ignore
        sendJmpTblRecoverySuccess ctx queue jmptbl idx
      | UpdateCallEdges(calleeAddr, calleeInfo) ->
#if CFGDEBUG
        let noret, unwinding = calleeInfo
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
          buildCFG ctx cfgRec syscallAnalysis useTCHeuristic queue [ pp ]
        | Error e -> FailStop e
      | EndGapAnalysis ->
        assert (ctx.GapToAnalyze.IsSome)
        ctx.GapToAnalyze <- None
        MoveOn
    with e ->
      Console.Error.WriteLine $"OnAction failed:\n{e}"
      FailStop ErrorCase.FailedToRecoverCFG

/// Base strategy for building a CFG.
type CFGRecovery<'FnCtx,
                 'GlCtx when 'FnCtx :> IResettable
                         and 'FnCtx: (new: unit -> 'FnCtx)
                         and 'GlCtx: (new: unit -> 'GlCtx)>
  public(summarizer: IFunctionSummarizable<'FnCtx, 'GlCtx>,
         jmptblAnalysis: IJmpTableAnalyzable<'FnCtx, 'GlCtx>,
         syscallAnalysis: ISyscallAnalyzable,
         postAnalysis: ICFGAnalysis<_>,
         useTailcallHeuristic,
         allowBBLOverlap,
         useSSA) as this =

  interface ICFGRecovery<'FnCtx, 'GlCtx> with
    member _.Summarizer with get() = summarizer

    member _.ActionPrioritizer with get() = prioritizer

    member _.AllowBBLOverlap with get() = allowBBLOverlap

    member _.AnalyzeIndirectJump(ctx, _ppQueue, pp, srcVertex) =
      let insAddr = srcVertex.VData.Internals.LastInstruction.Address
      let callsite = LeafCallSite insAddr
      addCallerVertex ctx callsite srcVertex
      pushAction ctx <| MakeIndEdges(pp.Address, insAddr)
      None

    member _.AnalyzeIndirectCondJump(_, _, _, _) = None

    member _.FindCandidates(builders) = findCandidates builders

    member _.OnAction(ctx, queue, action) =
      onAction ctx this queue syscallAnalysis jmptblAnalysis
               useTailcallHeuristic action

    member _.OnCreate _ctx = ()

    member _.OnFinish ctx = onFinish ctx this postAnalysis

    member _.OnCyclicDependency deps = onCyclicDependency deps

    member _.OnAddVertex(ctx, vertex) =
      if not useSSA then markVertexAsPendingForAnalysis ctx vertex
      else ()

    member _.OnAddEdge(ctx, _srcVertex, dstVertex, _edgeKind) =
      if not useSSA then markVertexAsPendingForAnalysis ctx dstVertex
      else ()

    member _.OnRemoveVertex(ctx, vertex) =
      markVertexAsRemovalForAnalysis ctx vertex

    member _.FindCandidatesForPostProcessing _ = [||]

  new(allowBBLOverlap, useSSA) =
    let summarizer = FunctionSummarizer()
    let syscallAnalysis = SyscallAnalysis()
    let jmptblAnalysis, postAnalysis =
      if useSSA then
        let ssaLifter = SSALifter() :> ICFGAnalysis<_>
        JmpTableAnalysis(Some ssaLifter) :> IJmpTableAnalyzable<_, _>,
        ssaLifter <+> CondAwareNoretAnalysis()
      else
        JmpTableAnalysis None :> IJmpTableAnalyzable<_, _>,
        CondAwareNoretAnalysis()
    CFGRecovery(summarizer,
                jmptblAnalysis,
                syscallAnalysis,
                postAnalysis,
                true,
                allowBBLOverlap,
                useSSA)

/// Base strategy for building a CFG without any customizable context.
type CFGRecovery =
  inherit CFGRecovery<DummyContext, DummyContext>

  new() = { inherit CFGRecovery<DummyContext, DummyContext>(false, false) }

  new(allowBBLOverlap) =
    { inherit CFGRecovery<DummyContext, DummyContext>(allowBBLOverlap, false) }

  new(summarizer,
      jmptblAnalysis,
      syscallAnalysis,
      postAnalysis,
      useTailcallHeuristic,
      allowBBLOverlap) =
    { inherit CFGRecovery<DummyContext, DummyContext>(summarizer,
                                                      jmptblAnalysis,
                                                      syscallAnalysis,
                                                      postAnalysis,
                                                      useTailcallHeuristic,
                                                      allowBBLOverlap,
                                                      false) }

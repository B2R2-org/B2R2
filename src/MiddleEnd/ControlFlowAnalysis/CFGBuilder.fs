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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.FrontEnd.BinInterface
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

[<AutoOpen>]
module private CFGBuilder =
  /// In this function, we only consider a single instruction-level basic block.
  /// We parse its corresponding IR-level basic blocks as well as
  /// intra-instruction edges. But we don't add inter-instruction CFG edges.
  /// Instead, this function returns a list of CFGEvents to perform in the next
  /// iteration.
  let buildBBL hdl codeMgr func mode leaderAddr evts =
    match (codeMgr: CodeManager).ParseBBL hdl mode leaderAddr func evts with
    | Ok evts -> Ok evts
    | Error ErrorCase.ParsingFailure -> Error ErrorParsing
    | Error _ -> Utils.impossible ()

  let buildFunction hdl (codeMgr: CodeManager) dataMgr entry mode evts =
    match codeMgr.TryGetBBL entry with
    (* Need to split the existing bbl. *)
    | Some bbl when bbl.FunctionEntry <> entry ->
      codeMgr.HistoryManager.Record <| CreatedFunction entry
      if bbl.BlkRange.Min <> entry then
        let _, evts = codeMgr.SplitBlock bbl entry evts
        let _, evts = codeMgr.PromoteBBL hdl entry bbl dataMgr evts
        Ok evts
      else
        let _, evts = codeMgr.PromoteBBL hdl entry bbl dataMgr evts
        Ok evts
    | _ ->
      let func =
        match codeMgr.FunctionMaintainer.TryFindRegular entry with
        | Some func -> func
        | None -> codeMgr.FunctionMaintainer.GetOrAddFunction (hdl, entry)
      if func.HasVertex (ProgramPoint (entry, 0)) then Ok evts
      else buildBBL hdl codeMgr func mode entry evts (* Build new block *)

  let inline isIntrudingBlk (codeMgr: CodeManager) leader =
    match codeMgr.TryGetBBL leader with
    | Some bbl -> leader <> bbl.BlkRange.Min
    | None -> false

  let splitAndConnectEdge (codeMgr: CodeManager) fn src dst edge evts =
    let bbl = codeMgr.GetBBL dst
    if bbl.FunctionEntry <> (fn: RegularFunction).Entry then
      Error ErrorConnectingEdge
    else
      match codeMgr.SplitBlock bbl dst evts with
      | Some front, evts ->
        (* When a bbl is self-dividing itself, then the dst block should have a
           self-loop. For example, if a BBL has three instructions (a, b, c) and
           if c has a branch to b, then we split the block into (a) and (b, c),
           and the second block will have a self-loop. *)
        let src = if src = front then ProgramPoint (dst, 0) else src
        fn.AddEdge (src, ProgramPoint (dst, 0), edge)
        Ok evts
      | _, evts ->
        fn.AddEdge (src, ProgramPoint (dst, 0), edge)
        Ok evts

  let getCallee hdl (codeMgr: CodeManager) callee evts =
    match codeMgr.FunctionMaintainer.TryFind (addr=callee) with
    | Some calleeFunc -> calleeFunc, evts
    | None ->
      let calleeFunc = codeMgr.FunctionMaintainer.GetOrAddFunction (hdl, callee)
      let evts = CFGEvents.addFuncEvt callee ArchOperationMode.NoMode evts
      calleeFunc :> Function, evts

  /// If there is a tail-call from my function to a callee, and the callee is a
  /// returning function, then we know that my function should *not* no return.
  let markAsReturning (myfn: RegularFunction) isTailCall (calleeFn: Function) =
    if isTailCall
      && (calleeFn.NoReturnProperty = NotNoRet
          || calleeFn.NoReturnProperty = NotNoRetConfirmed)
    then myfn.NoReturnProperty <- NotNoRet
    else ()

  /// Sometimes we could find call 0 from static compiled binaries. In such
  /// case, we do not create function at address 0, nor mark it as returning.
  let buildNULLCall (codeMgr: CodeManager) fn callSite callee isTailCall evts =
    let callerBlk = Set.maxElement (codeMgr.GetBBL callSite).IRLeaders
    (fn: RegularFunction).AddEdge (callerBlk, callSite, callee, isTailCall)
    Ok evts

  let buildCall hdl codeMgr fn callSite callee isTailCall evts =
    if callee = 0UL then
      buildNULLCall codeMgr fn callSite callee isTailCall evts
    else
      let calleeFn, evts = getCallee hdl codeMgr callee evts
      let callerBlk = Set.maxElement (codeMgr.GetBBL callSite).IRLeaders
      (fn: RegularFunction).AddEdge (callerBlk, callSite, callee, isTailCall)
      markAsReturning fn isTailCall calleeFn
      Ok evts

  let buildIndCall (codeMgr: CodeManager) fn callSite evts =
    let callerBlk = Set.maxElement (codeMgr.GetBBL callSite).IRLeaders
    (fn: RegularFunction).AddEdge (callerBlk, callSite)
    Ok evts

  let buildTailCall hdl codeMgr fn caller callee evts =
    buildCall hdl codeMgr fn caller callee true evts

  let makeCalleeNoReturn (codeMgr: CodeManager) fn callee callSite =
    let callee = codeMgr.FunctionMaintainer.Find (addr=callee)
    let callBlk = codeMgr.GetBBL callSite
#if CFGDEBUG
    dbglog "CFGBuilder"
      "Ret edge connects to an existing func, %x must be noret" callee.Entry
#endif
    let srcPp = ProgramPoint (callBlk.BlkRange.Min, 0)
    let src = (fn: RegularFunction).FindVertex srcPp
    DiGraph.getSuccs fn.IRCFG src
    |> List.iter (fun dst -> fn.RemoveEdge (src, dst))
    callee.NoReturnProperty <- NoRet

  let buildRet codeMgr (fn: RegularFunction) callee ftAddr callSite evts =
    let fallBlk = (codeMgr: CodeManager).GetBBL ftAddr
    if fallBlk.FunctionEntry = fn.Entry then
      fn.AddEdge (callSite=callSite, callee=callee, ftAddr=ftAddr)
      Ok evts
    else
      makeCalleeNoReturn codeMgr fn callee callSite
      Ok evts

  let createJumpAfterLock (codeMgr: CodeManager) patternStart addrs =
    let last = List.rev addrs |> List.head
    let insInfo = codeMgr.GetInstruction last
    let addr = patternStart
    let size = last + uint64 insInfo.Instruction.Length - patternStart
    let wordSize = insInfo.Instruction.WordSize
    let stmts = insInfo.Stmts
    InlinedAssembly.Init addr (uint32 size) wordSize stmts

  /// Build a regular edge, which is any edge that is not a call, an indirect
  /// call, nor a ret edge.
  let buildRegularEdge hdl (codeMgr: CodeManager) dataMgr fn src dst edge evts =
    let mode = ArchOperationMode.NoMode (* XXX: put mode in the event. *)
    if not <| hdl.FileInfo.IsExecutableAddr (fn: RegularFunction).Entry then
      Error ErrorConnectingEdge (* Invalid bbl encountered. *)
    elif codeMgr.HasBBL dst then
      let dstPp = ProgramPoint (dst, 0)
      let dstBlk = codeMgr.GetBBL dst
      if fn.HasVertex dstPp then
        fn.AddEdge (src, ProgramPoint (dst, 0), edge)
        Ok evts
      elif edge = CallFallThroughEdge && dstBlk.FunctionEntry = dst then
        Ok evts (* Undetected no-return case, so we do not add fall-through. *)
      else (* Tail-call. *)
        buildFunction hdl codeMgr dataMgr dst mode evts
        |> Result.bind (buildCall hdl codeMgr fn src.Address dst true)
    elif isIntrudingBlk codeMgr dst then
      splitAndConnectEdge codeMgr fn src dst edge evts
    elif not (codeMgr.HasInstruction dst) (* Jump to the middle of an instr *)
      && fn.IsAddressCovered dst then
      match InlinedAssemblyPattern.checkInlinedAssemblyPattern hdl dst with
      | NotInlinedAssembly -> Error ErrorConnectingEdge
      | JumpAfterLock addrs ->
        let patternStart = List.head addrs
        let assembly = createJumpAfterLock codeMgr patternStart addrs
        let evts = codeMgr.ReplaceInlinedAssembly addrs assembly evts
        Ok evts
    elif dst = 0UL then Ok evts (* jmp 0 case, especially from libc *)
    else
      match buildBBL hdl codeMgr fn mode dst evts with
      | Ok evts -> fn.AddEdge (src, ProgramPoint (dst, 0), edge); Ok evts
      | Error e -> Error e

  let checkIfIndCallAnalysisRequired (fn: RegularFunction) exitNodes =
    exitNodes
    |> List.exists (fun (v: Vertex<IRBasicBlock>) ->
      v.VData.IsFakeBlock ()
      && fn.IsUnresolvedIndirectCall v.VData.FakeBlockInfo.CallSite)

  /// Does the vertex (v) end with a regular (returning) syscall?
  let inline isReturningSyscall hdl (noret: NoReturnFunctionIdentification) v =
    match (v: Vertex<IRBasicBlock>).VData.SyscallTail with
    | UnknownSyscallTail ->
      if noret.IsNoRetSyscallBlk hdl v then
        v.VData.SyscallTail <- ExitSyscallTail; false
      else
        v.VData.SyscallTail <- RegularSyscallTail; true
    | RegularSyscallTail -> true
    | _ -> false

  /// Scan all exit nodes and obtain two things: (1) a list of vertices that
  /// needs to be connected with fall-through edges; and (2) a set of function
  /// addresses which need to perform the no-ret analysis. We assume that the
  /// indirect call recovery is performed on the given function (fn).
  let scanCandidates hdl codeMgr noret fn exitNodes =
    exitNodes
    |> List.fold (fun (vs, toAnalyze) (v: Vertex<IRBasicBlock>) ->
      if not (v.VData.IsFakeBlock ()) then
        if isReturningSyscall hdl noret v then v :: vs, toAnalyze
        else vs, toAnalyze
      else
        let callSite = v.VData.FakeBlockInfo.CallSite
        (fn: RegularFunction).CallTargets callSite
        |> Set.fold (fun (vs, toAnalyze) calleeAddr ->
          let callee = (codeMgr: CodeManager).FunctionMaintainer.Find calleeAddr
          match callee.NoReturnProperty with
          | NotNoRetConfirmed | NotNoRet ->
            if v.VData.FakeBlockInfo.IsTailCall then vs, toAnalyze
            else v :: vs, toAnalyze
          | ConditionalNoRet arg ->
            let callerPp = Set.maxElement (codeMgr.GetBBL callSite).IRLeaders
            let callerV = fn.FindVertex callerPp
            if noret.HasNonZeroArg hdl callerV arg then vs, toAnalyze
            elif v.VData.FakeBlockInfo.IsTailCall then vs, toAnalyze
            else v :: vs, toAnalyze
          | UnknownNoRet ->
            if callee.Entry = fn.Entry then (* Recursive call *) vs, toAnalyze
            else vs, Set.add calleeAddr toAnalyze
          | _ -> vs, toAnalyze) (vs, toAnalyze)
    ) ([], Set.empty)

  let addFallThroughEvts (codeMgr: CodeManager) fn verticesToAddFalls evts =
    let evts =
      CFGEvents.addPerFuncAnalysisEvt (fn: RegularFunction).Entry evts
    verticesToAddFalls
    |> List.fold (fun evts (v: IRVertex) ->
      if v.VData.IsFakeBlock () then
        let callSite = v.VData.FakeBlockInfo.CallSite
        let callerPp = Set.maxElement (codeMgr.GetBBL callSite).IRLeaders
        let calleeAddr = v.VData.PPoint.Address
        let callerV = fn.FindVertex callerPp
        let last = callerV.VData.LastInstruction
        let ftAddr = last.Address + uint64 last.Length
        evts
        |> CFGEvents.addRetEvt fn calleeAddr ftAddr callSite
        |> CFGEvents.addEdgeEvt fn callerPp ftAddr CallFallThroughEdge
      else
        let pp = v.VData.PPoint
        let last = v.VData.LastInstruction
        let ftAddr = last.Address + uint64 last.Length
        evts |> CFGEvents.addEdgeEvt fn pp ftAddr FallThroughEdge
      ) evts

  let updateCalleeInfo (codeMgr: CodeManager) (func: RegularFunction) =
    DiGraph.iterVertex func.IRCFG (fun v ->
      if v.VData.IsFakeBlock () && v.VData.PPoint.Address <> 0UL then
        let calleeFunc = codeMgr.FunctionMaintainer.Find v.VData.PPoint.Address
        if calleeFunc.FunctionKind = FunctionKind.Regular then
          let calleeFunc = calleeFunc :?> RegularFunction
          v.VData.FakeBlockInfo <-
            { v.VData.FakeBlockInfo with
                UnwindingBytes = calleeFunc.AmountUnwinding
                GetPCThunkInfo = calleeFunc.GetPCThunkInfo }
        else
          v.VData.FakeBlockInfo <- { v.VData.FakeBlockInfo with IsPLT = true }
      else ())

  let runIndirectCallRecovery hdl codeMgr dataMgr entry indcall fn evts =
#if CFGDEBUG
    dbglog "CFGBuilder" "@%x Started indcall analysis" entry
#endif
    updateCalleeInfo codeMgr fn
    CFGEvents.addPerFuncAnalysisEvt fn.Entry evts
    |> (indcall: PerFunctionAnalysis).Run hdl codeMgr dataMgr fn

  let runIndirectJmpRecovery hdl codeMgr dataMgr entry indjmp fn evts =
#if CFGDEBUG
    dbglog "CFGBuilder" "@%x Started indjmp analysis" entry
#endif
    updateCalleeInfo codeMgr fn
    CFGEvents.addPerFuncAnalysisEvt fn.Entry evts
    |> (indjmp: PerFunctionAnalysis).Run hdl codeMgr dataMgr fn

  let private hasPath src dst evts =
    let map = evts.CalleeAnalysisEdges
    let visited = HashSet<Addr> ()
    let rec dfs addrs =
      let addr = List.head addrs
      if addr = dst then true, List.rev addrs
      elif visited.Contains addr then false, addrs
      else
        visited.Add addr |> ignore
        Map.tryFind addr map
        |> Option.defaultValue Set.empty
        |> Set.fold (fun (found, path) succ ->
          if found then found, path
          else dfs (succ :: addrs)) (false, addrs)
    dfs [src]

  /// We consider mutually recursive functions to be "returning", i.e., "not no
  /// ret". This is to make sure that our analysis to terminate. When there is a
  /// function call chain a -> b -> c -> a -> ..., then we cannot decide the
  /// no-ret property of each function because our analysis assumes that all the
  /// callees of a function should be analyzed first. Thus, when we detect
  /// mutual recursions,  we simply consider the first function in the chain as
  /// a returning function.
  let makeMutuallyRecursiveFunctionsNotNoRet codeMgr myAddr toAnalyze evts =
    toAnalyze
    |> Set.iter (fun addr ->
      match hasPath addr myAddr evts with
      | true, path ->
        let funcsInPath =
          path |> List.map (fun a ->
            (codeMgr: CodeManager).FunctionMaintainer.FindRegular (a))
        if funcsInPath
           |> List.exists (fun f -> f.NoReturnProperty <> UnknownNoRet)
        then () (* No need to worry about infinite loop. *)
        else
          funcsInPath
          |> List.choose (fun f ->
            if f.NoReturnProperty = UnknownNoRet then Some f else None)
          |> List.sortByDescending (fun callee ->
            let nextAddr = codeMgr.FunctionMaintainer.FindNextFunctionAddr callee
            nextAddr - callee.MaxAddr)
          |> List.tryHead (* Take the one with the biggest gap *)
          |> function
            | Some callee ->
#if CFGDEBUG
              dbglog "CFGBuilder" "Make %x as NotNoRet (%x -> %x)"
                callee.Entry addr myAddr
#endif
              callee.NoReturnProperty <- NotNoRet
            | None -> ()
      | false, _ -> ())

  /// Before we run the no-return analysis on this function (fn), we should
  /// first analyze the other callees, and come back later.
  let analyzeCalleesFirst codeMgr (fn: RegularFunction) toAnalyze evts =
    makeMutuallyRecursiveFunctionsNotNoRet codeMgr fn.Entry toAnalyze evts
    let evts = CFGEvents.addPerFuncAnalysisEvt fn.Entry evts
    toAnalyze
    |> Set.fold (fun evts entry ->
      CFGEvents.addPerFuncAnalysisEvt entry evts
      |> CFGEvents.addCalleeAnalysisEvt fn.Entry entry) evts
    |> Ok

  let retrieveStackAdjustment (ins: Instruction) =
    match ins.Immediate () with
    | true, v -> uint64 v
    | false, _ -> 0UL

  /// Assuming that "ret NN" instructions are used, compute how much stack
  /// unwinding is happening for the given function.
  ///
  /// TODO: We can extend this analysis further to make it more precise.
  let computeStackUnwindingAmount cfg =
    DiGraph.getExits cfg
    |> List.fold (fun acc (v: Vertex<IRBasicBlock>) ->
      if Option.isSome acc || v.VData.IsFakeBlock () then acc
      else
        let ins = v.VData.LastInstruction
        if ins.IsRET () then retrieveStackAdjustment ins |> Some
        else acc) None
    |> function
       | None -> 0UL
       | Some n -> n

  /// Update extra function information as we have finished all the per-function
  /// analyses.
  let finalizeFunctionInfo (func: RegularFunction) =
    let amountUnwinding = computeStackUnwindingAmount func.IRCFG
    if amountUnwinding <> 0UL then func.AmountUnwinding <- amountUnwinding
    else ()

  let runPerFuncAnalysis hdl codeMgr dataMgr entry noret indcall indjmp evts =
    let fn = (codeMgr: CodeManager).FunctionMaintainer.FindRegular (addr=entry)
    let exits = DiGraph.getExits (fn: RegularFunction).IRCFG
    let vsToAddFalls, toAnalyze = scanCandidates hdl codeMgr noret fn exits
    if not (List.isEmpty vsToAddFalls) then
      addFallThroughEvts codeMgr fn vsToAddFalls evts |> Ok
    elif not (fn.YetAnalyzedIndirectJumpAddrs |> Seq.isEmpty) then
      runIndirectJmpRecovery hdl codeMgr dataMgr entry indjmp fn evts
    elif checkIfIndCallAnalysisRequired fn exits then
      runIndirectCallRecovery hdl codeMgr dataMgr entry indcall fn evts
    elif Set.isEmpty toAnalyze |> not then
      analyzeCalleesFirst codeMgr fn toAnalyze evts
    else
#if CFGDEBUG
      dbglog "CFGBuilder" "@%x Finalize with no-ret analysis" entry
#endif
      finalizeFunctionInfo fn
      updateCalleeInfo codeMgr fn
      noret.Run hdl codeMgr dataMgr fn evts

/// This is the main class for building a CFG from a given binary.
type CFGBuilder (hdl, codeMgr: CodeManager, dataMgr: DataManager) as this =
  let noret = NoReturnFunctionIdentification ()
  let indcall = IndirectCallResolution ()
  let indjmp = IndirectJumpResolution (this)

#if CFGDEBUG
  let countEvts evts =
    "(" + (List.length evts.BasicEvents).ToString ()
        + ", "
        + (List.length evts.FunctionAnalysisAddrs).ToString ()
        + " left)"
#endif

  let rec update evts =
    match evts with
    | Ok ({ BasicEvents = CFGFunc (entry, mode) :: tl } as evts) ->
#if CFGDEBUG
      dbglog (nameof CFGBuilder) "@%x %s %s"
        entry (nameof CFGFunc) (countEvts evts)
#endif
      let evts = { evts with BasicEvents = tl }
      update (buildFunction hdl codeMgr dataMgr entry mode evts)
    | Ok ({ BasicEvents = CFGEdge (fn, src, dst, edge) :: tl } as evts) ->
#if CFGDEBUG
      dbglog (nameof CFGBuilder) "@%x %s (%x -> %x; %s) %s"
        fn.Entry (nameof CFGEdge) src.Address dst (CFGEdgeKind.toString edge)
        (countEvts evts)
#endif
      let evts = { evts with BasicEvents = tl }
      update (buildRegularEdge hdl codeMgr dataMgr fn src dst edge evts)
    | Ok ({ BasicEvents = CFGCall (fn, callSite, callee) :: tl } as evts) ->
#if CFGDEBUG
      dbglog (nameof CFGBuilder) "@%x %s (%x -> %x) %s"
        fn.Entry (nameof CFGCall) callSite callee (countEvts evts)
#endif
      let evts = { evts with BasicEvents = tl }
      update (buildCall hdl codeMgr fn callSite callee false evts)
    | Ok ({ BasicEvents = CFGIndCall (fn, callSite) :: tl } as evts) ->
#if CFGDEBUG
      dbglog (nameof CFGBuilder) "@%x %s (%x) %s"
        fn.Entry (nameof CFGIndCall) callSite (countEvts evts)
#endif
      let evts = { evts with BasicEvents = tl }
      update (buildIndCall codeMgr fn callSite evts)
    | Ok ({ BasicEvents = CFGRet (fn, callee, ft, callSite) :: tl } as evts) ->
#if CFGDEBUG
      dbglog (nameof CFGBuilder) "@%x %s (%x -> %x) (%x -> %x) %s"
        fn.Entry (nameof CFGRet) callSite ft callee ft (countEvts evts)
#endif
      let evts = { evts with BasicEvents = tl }
      update (buildRet codeMgr fn callee ft callSite evts)
    | Ok ({ BasicEvents = CFGTailCall (fn, callSite, callee) :: tl } as evts) ->
#if CFGDEBUG
      dbglog (nameof CFGBuilder) "@%x %s (%x -> %x) %s"
        fn.Entry (nameof CFGTailCall) callSite callee (countEvts evts)
#endif
      let evts = { evts with BasicEvents = tl }
      update (buildTailCall hdl codeMgr fn callSite callee evts)
    | Ok ({ BasicEvents = []
            FunctionAnalysisAddrs = fnAddr :: tl } as evts) ->
#if CFGDEBUG
      dbglog (nameof CFGBuilder) "@%x per-func-analysis %s"
        fnAddr (countEvts evts)
#endif
      let evts = { evts with FunctionAnalysisAddrs = tl }
      update (runPerFuncAnalysis
        hdl codeMgr dataMgr fnAddr noret indcall indjmp evts)
    | Ok ({ BasicEvents = [] }) -> (* FunctionAnalysisAddrs is empty *)
#if CFGDEBUG
      dbglog (nameof CFGBuilder) "Done %s" (nameof update)
#endif
      codeMgr.FunctionMaintainer.UpdateCallerCrossReferences () |> Ok
    | Error err -> Error err

  interface ICFGBuildable with
    member __.Update evts =
      update (Ok evts)

  /// Add new events to the event list (evts).
  member private __.AddNewFunction evts (entry, mode) =
    if codeMgr.FunctionMaintainer.Contains (addr=entry) then Ok evts
    elif not <| hdl.FileInfo.IsExecutableAddr entry then Error ErrorParsing
    else CFGEvents.addFuncEvt entry mode evts |> Ok

  /// This is the only function that is available to users, which takes in a
  /// list of known function entry infos and recover the whole CFGs, thereby
  /// updating both code manager and data manager. The return value is Error if
  /// a fatal error is encountered.
  member __.AddNewFunctions entries =
#if CFGDEBUG
    dbglog (nameof CFGBuilder) "Start by adding %d function(s) for %s"
      (List.length entries) (hdl.FileInfo.FilePath)
#endif
    (* List.foldBack is used here to preserve the order of input entries *)
    List.foldBack (fun elm evts ->
      match evts with
      | Ok evts -> __.AddNewFunction evts elm
      | Error e -> Error e) entries (Ok CFGEvents.empty)
    |> function
      | Ok evts -> (__ :> ICFGBuildable).Update evts
      | Error e -> Error e

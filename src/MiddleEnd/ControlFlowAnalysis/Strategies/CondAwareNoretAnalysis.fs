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

open System.Collections.Generic
open System.Runtime.InteropServices
open B2R2
open B2R2.ABI
open B2R2.BinIR
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ConcEval
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.DataFlow
open type UntouchedValueDomain.UntouchedTag

[<AutoOpen>]
module private CondAwareNoretAnalysisHelper =
  let hasNonZeroInRegister st rid =
    match (st: ConcState).TryGetReg rid with
    | Def bv -> not bv.IsZero
    | _ -> false

  let tryGetStackPointer (hdl: BinHandle) (st: ConcState) =
    hdl.RegisterFactory.StackPointer
    |> Option.bind (fun rid ->
      match st.TryGetReg rid with
      | Def sp -> Some sp
      | _ -> None)

  let hasNonZeroOnStack (hdl: BinHandle) st (layout: StackArgLayout) =
    match tryGetStackPointer hdl st with
    | Some sp ->
      let p = sp + BitVector(layout.FirstOffset, sp.Length)
      let rt = RegType.fromByteWidth layout.SlotSize
      match Memory.read (p.ToUInt64()) hdl.ISA.Endian rt st.Memory with
      | Ok v -> not v.IsZero
      | Error _ -> false
    | None ->
      false

  /// Locally analyzes the given basic block and checks if the argument at the
  /// given location, which the call ending the block passes, is non-zero.
  let hasNonZero hdl caller loc =
    let st = CFGEvaluator.evalBlockFromScratch hdl caller
    match loc with
    | ArgLocation.Reg rid -> hasNonZeroInRegister st rid
    | ArgLocation.Stack layout -> hasNonZeroOnStack hdl st layout
    | ArgLocation.RegPair _ -> false

/// Represents a non-returning function identification strategy that can check
/// conditionally non-returning functions. We currently support only those
/// simple patterns that are handled by compilers, but we may have to extend
/// this as the compilers evolve.
type CondAwareNoretAnalysis([<Optional; DefaultParameterValue(true)>] strict) =
  /// Default value used for unknown non-returning status.
  let defaultStatus = if strict then NoRet else NotNoRet

  let meet a b =
    match a, b with
    | _ when a = b -> a
    | UnknownNoRet, _ -> b
    | _, UnknownNoRet -> a
    | NotNoRet, _ -> a
    | _, NotNoRet -> b
    | NoRet, ConditionalNoRet _ -> b
    | ConditionalNoRet _, NoRet -> a
    (* Returning when one argument is zero on some paths and when another is
       on others is returning on no single condition. *)
    | ConditionalNoRet _, ConditionalNoRet _ -> NotNoRet
    | _ -> Terminator.impossible ()

  let tryGetValue (state: LowUIRSparseDataFlow.State<_>) v varKind =
    let defs = state.PerVertexIncomingDefs[v]
    match Map.tryFind varKind defs with
    | Some defVp -> state.GetAbsValue defVp |> Some
    | None -> None

  /// Gets the location of the argument that the given register holds on
  /// entry. A callee preserves none of the registers it takes arguments in,
  /// whichever convention a compiler picks for a function of its own.
  let tryGetRegArgLocation (hdl: BinHandle) rid =
    let cc = hdl.Conventions.Calling
    if cc.IsCalleeSaved rid || hdl.RegisterFactory.IsStackPointer rid then None
    else Some(ArgLocation.Reg rid)

  /// Gets the location of the argument that lies at the given offset from the
  /// stack pointer on entry, if the calling convention passes arguments there.
  let tryGetStackArgLocation (hdl: BinHandle) offset =
    match Array.tryLast hdl.Conventions.Calling.IntArgs with
    | Some(ArgLocation.Stack layout) when offset >= layout.FirstOffset ->
      Some(ArgLocation.Stack { layout with FirstOffset = offset })
    | _ ->
      None

  /// Gets the location of the argument that the function takes in the given
  /// variable of the IR-level data flow, whose stack offsets grow upward from
  /// the stack pointer on entry.
  let tryGetArgLocationFromIR hdl varKind =
    match varKind with
    | Regular rid -> tryGetRegArgLocation hdl rid
    | StackLocal offset -> tryGetStackArgLocation hdl offset
    | _ -> None

  let isStackPointer (hdl: BinHandle) dst =
    match dst with
    | LowUIR.Var(RegisterID = rid) -> hdl.RegisterFactory.IsStackPointer rid
    | _ -> false

  /// Gets the stack pointer on entry to the callee of the given abstract
  /// vertex, which the summary of the callee reads to adjust it.
  let tryGetCalleeEntrySP hdl (state: LowUIRSparseDataFlow.State<_>) absV =
    state.GetStmtInfos absV
    |> Array.tryPick (fun (stmt, pp) ->
      match stmt with
      | LowUIR.Put(Dst = dst) when isStackPointer hdl dst ->
        match state.EvaluateStackPointerExpr(pp, dst) with
        | StackPointerDomain.ConstSP sp -> Some sp
        | _ -> None
      | _ ->
        None)

  /// Finds the variable in which the caller of the given abstract vertex
  /// passes the callee its argument at the given location.
  let tryGetPassingVarFromIR hdl state absV loc =
    match loc with
    | ArgLocation.Reg rid ->
      Some(Regular rid)
    | ArgLocation.Stack layout ->
      tryGetCalleeEntrySP hdl state absV
      |> Option.map (fun sp ->
        let offset = LowUIRStackPointer.toFrameOffset (sp.ToUInt64())
        StackLocal(offset + layout.FirstOffset))
    | ArgLocation.RegPair _ ->
      None

  /// Finds where the caller of the given abstract vertex takes the argument
  /// that it passes the callee at the given location, if it passes on one of
  /// its own arguments untouched.
  let tryGetConnectedArgumentFromIRCFG hdl state absV loc =
    tryGetPassingVarFromIR hdl state absV loc
    |> Option.bind (fun varKind ->
      match tryGetValue state absV varKind with
      | Some(UntouchedValueDomain.Untouched(RegisterTag origin)) ->
        tryGetArgLocationFromIR hdl origin
      | Some _ ->
        None
      | None ->
        (* With no definition reaching the callee, the caller passes on what
           it took in the same variable. *)
        tryGetArgLocationFromIR hdl varKind)

  /// Collects the abstract vertices of the calls to conditionally
  /// non-returning functions, each with the location of the argument that
  /// decides whether its callee returns.
  let collectCondNoRetCallees (ctx: CFGBuildingContext<_, _>) =
    ctx.IntraCallTable.Callees
    |> Seq.fold (fun acc (KeyValue(cs, calleeKind)) ->
      match calleeKind with
      | RegularCallee callee ->
        if ctx.FunctionAddress = callee then acc
        else ProgramPoint(cs, callee, 0) :: acc
      | IndirectCallees callees ->
        Set.fold (fun acc c -> ProgramPoint(cs, c, 0) :: acc) acc callees
      | _ ->
        acc) []
    |> List.choose (fun pp ->
      let absV = ctx.Vertices[pp]
      match absV.VData.Internals.AbstractContent.ReturningStatus with
      | ConditionalNoRet loc -> Some(pp, absV, loc)
      | _ -> None)

  let collectConditionalNoRetCallsFromIRCFG ctx (state: Lazy<_>) =
    let hdl = (ctx: CFGBuildingContext<_, _>).BinHandle
    collectCondNoRetCallees ctx
    |> List.choose (fun (_, absV, loc) ->
      tryGetConnectedArgumentFromIRCFG hdl state.Value absV loc
      |> Option.map (fun callerLoc -> absV, callerLoc))

  let findSSAVertexByAddr (ssa: SSACFG) addr =
    ssa.FindVertexBy(fun v ->
      if v.VData.Internals.IsAbstract then false
      else v.VData.Internals.Range.IsIncluding addr)

  let tryGetFrameDistance (ctx: CFGBuildingContext<_, _>) callSite =
    match ctx.IntraCallTable.TryGetFrameDistance callSite with
    | true, dist -> Some dist
    | false, _ -> None

  /// Finds the variable in which the caller passes the callee its argument at
  /// the given location, where the frame of the callee lies at the given
  /// distance below the stack pointer of the caller on entry.
  let tryGetPassingVarFromSSA (hdl: BinHandle) frameDist loc =
    match loc, frameDist with
    | ArgLocation.Reg rid, _ ->
      let rt = hdl.RegisterFactory.GetRegType rid
      let name = hdl.RegisterFactory.GetRegisterName rid
      Some(SSA.RegVar(rt, rid, name))
    | ArgLocation.Stack layout, Some dist ->
      let rt = RegType.fromByteWidth layout.SlotSize
      Some(SSA.StackVar(rt, dist - layout.FirstOffset))
    | _ ->
      None

  /// Gets the location of the argument that the function takes in the given
  /// variable of the SSA-level data flow, whose stack offsets grow downward
  /// from the stack pointer on entry.
  let tryGetArgLocationFromSSA hdl varKind =
    match varKind with
    | Regular rid -> tryGetRegArgLocation hdl rid
    | StackLocal offset -> tryGetStackArgLocation hdl (-offset)
    | _ -> None

  let tryGetConnectedArgumentFromSSACFG ctx (ssa: SSACFG) dom state pp loc =
    let callSite = (pp: ProgramPoint).CallSite |> Option.get
    let callerSSAV = findSSAVertexByAddr ssa callSite.CallSiteAddress
    let absSSAV = ssa.GetSuccs callerSSAV |> Seq.exactlyOne
    let hdl = (ctx: CFGBuildingContext<_, _>).BinHandle
    let frameDist = tryGetFrameDistance ctx callSite
    tryGetPassingVarFromSSA hdl frameDist loc
    |> Option.bind (fun varKind ->
      match SSACFG.findReachingDef dom absSSAV varKind with
      | Some(SSA.Def(var, _))
      | Some(SSA.Phi(var, _)) ->
        match (state: SSASparseDataFlow.State<_>).GetRegValue var with
        | UntouchedValueDomain.Untouched(RegisterTag origin) ->
          tryGetArgLocationFromSSA hdl origin
        | _ ->
          None
      | Some _ ->
        None
      | None ->
        (* With no definition reaching the callee, the caller passes on what
           it took in the same variable. *)
        tryGetArgLocationFromSSA hdl (VarKind.ofSSAVarKind varKind))

  let getLazySSAState g (uva: SSAUntouchedValueAnalysis) =
    lazy ((uva :> IDataFlowComputable<_, _, _>).Compute g |> ignore
          uva.State)

  let getLazyIRState g (uva: UntouchedValueAnalysis) =
    lazy ((uva :> IDataFlowComputable<_, _, _>).Compute g |> ignore
          uva.State)

  let collectConditionalNoRetCallsFromSSACFG ctx ssaCFG dom =
    let hdl = (ctx: CFGBuildingContext<_, _>).BinHandle
    let state = SSAUntouchedValueAnalysis hdl |> getLazySSAState ssaCFG
    collectCondNoRetCallees ctx
    |> List.choose (fun (pp, absV, loc) ->
      tryGetConnectedArgumentFromSSACFG ctx ssaCFG dom state.Value pp loc
      |> Option.map (fun callerLoc -> absV, callerLoc))

  let tryFindCondNoRetDom (dom: IForwardDominance<_>) absVSet v =
    dom.Dominators v
    |> Seq.filter (fun v -> (absVSet: HashSet<_>).Contains v)
    |> fun doms ->
      if Seq.isEmpty doms then
        None
      else
        (* When there are two or more conditionally returning (and dominating)
           abstract vertices, we assume that they will be referring to the same
           callee. *)
        Some <| Seq.head doms

  let getStatusFromDominators dom absVSet (argMap: Dictionary<_, _>) exit =
    match tryFindCondNoRetDom dom absVSet exit with
    | None -> NotNoRet
    | Some dom -> ConditionalNoRet argMap[dom]

  /// Checks if the given exit vertex has a corrupted stack pointer value before
  /// executing the return instruction. This means we cannot statically decide
  /// whether the return instruction will jump to the caller or not.
  let hasUndecidableReturnTarget (ctx: CFGBuildingContext<_, _>) v =
    let hdl = ctx.BinHandle
    let st = CFGEvaluator.evalBlockFromScratch hdl v
    let rid = hdl.RegisterFactory.StackPointer.Value
    match st.TryGetReg(rid) with
    | Def(_) ->
      false
    | _ ->
#if CFGDEBUG
      let blkAddr = v.VData.Internals.PPoint.Address
      let fnAddr = ctx.FunctionAddress
      dbglog ctx.ThreadID (nameof CondAwareNoretAnalysis)
      <| $"[*] Undecidable return: {blkAddr:x} @ {fnAddr}"
#endif
      true

  let isTailCall (g: IDiGraph<_, _>) v =
    g.GetPredEdges v |> Array.exists (fun e -> e.Label = TailCallEdge)

  /// Judges whether the function returns through the given abstract vertex,
  /// which exits the function by calling a conditionally non-returning one
  /// that takes the argument deciding it at the given location. A call exits
  /// only once it is found to pass a non-zero argument, but a tail call
  /// returns for the function itself: on the same condition if the function
  /// passes on one of its own arguments.
  let judgeConditionalExit (ctx: CFGBuildingContext<_, _>) argMap v loc =
    let g = ctx.CFG
    if isTailCall g v then
      match (argMap: Dictionary<_, _>).TryGetValue v with
      | true, callerLoc ->
        ConditionalNoRet callerLoc
      | false, _ ->
        let caller = g.GetPreds v |> Seq.exactlyOne
        if hasNonZero ctx.BinHandle caller loc then NoRet else NotNoRet
    else
      NoRet

  let analyze (ctx: CFGBuildingContext<_, _>) condNoRetCalls =
    let df = Dominance.CooperDominanceFrontier()
    let dom = Dominance.LengauerTarjanDominance.create ctx.CFG df
    let exits = ctx.CFG.Exits
    let absVSet = HashSet(condNoRetCalls |> List.map fst)
    let argMap = Dictionary(condNoRetCalls |> Seq.map KeyValuePair)
    let mutable status = UnknownNoRet
    let mutable i = 0
    let updateStatus foundStatus = status <- meet status foundStatus
    while i < exits.Length && status <> NotNoRet do
      let v = exits[i]
      i <- i + 1
      let vData = v.VData :> ILowUIRBasicBlock
      if not vData.IsAbstract then
        if vData.LastInstruction.IsRET then
          if hasUndecidableReturnTarget ctx v then updateStatus NoRet
          else updateStatus (getStatusFromDominators dom absVSet argMap v)
        elif vData.LastInstruction.IsIndirectBranch then
          updateStatus NotNoRet
        else
          ()
      else
        match vData.AbstractContent.ReturningStatus with
        | ConditionalNoRet loc ->
          updateStatus (judgeConditionalExit ctx argMap v loc)
        | NotNoRet ->
          updateStatus (getStatusFromDominators dom absVSet argMap v)
        | status ->
          updateStatus status
    status

  (* Non-returning function identification for IR-based CFG. *)
  interface ICFGAnalysis<unit -> unit> with
    member _.Unwrap env =
      let ctx = env.Context
      fun () ->
        let hdl = ctx.BinHandle
        let g = ctx.CFG
        let state = UntouchedValueAnalysis(hdl, g.Vertices) |> getLazyIRState g
        let condNoRetCalls = collectConditionalNoRetCallsFromIRCFG ctx state
        match analyze ctx condNoRetCalls with
        | UnknownNoRet -> ctx.NonReturningStatus <- defaultStatus
        | status -> ctx.NonReturningStatus <- status
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof CondAwareNoretAnalysis)
        <| $"{ctx.FunctionAddress:x}: {ctx.NonReturningStatus}"
#endif

  (* Non-returning function identification for SSA-based CFG. *)
  interface ICFGAnalysis<SSACFGWithDominance -> unit> with
    member _.Unwrap env =
      let ctx = env.Context
      fun (r: SSACFGWithDominance) ->
        let condNoRetCalls =
          collectConditionalNoRetCallsFromSSACFG ctx r.Graph r.Dominance
        match analyze ctx condNoRetCalls with
        | UnknownNoRet -> ctx.NonReturningStatus <- defaultStatus
        | status -> ctx.NonReturningStatus <- status
#if CFGDEBUG
        dbglog ctx.ThreadID (nameof CondAwareNoretAnalysis)
        <| $"{ctx.FunctionAddress:x}: {ctx.NonReturningStatus} (w/ SSA)"
#endif

module CondAwareNoretAnalysis =
  /// Locally analyzes the given basic block and checks if the argument at the
  /// given location, which the call ending the block passes, is non-zero.
  let hasNonZero hdl caller loc =
    CondAwareNoretAnalysisHelper.hasNonZero hdl caller loc

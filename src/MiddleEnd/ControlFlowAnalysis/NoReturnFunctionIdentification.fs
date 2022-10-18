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

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinInterface
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.EvalHelper

type NoReturnDecision =
  | IsReturning
  | IsNoReturning
  | IsUndecidable

module NoReturnDecision =
  let meet a b =
    match a, b with
    | IsNoReturning, IsUndecidable
    | IsUndecidable, IsNoReturning
    | IsNoReturning, IsNoReturning -> IsNoReturning
    | _ -> IsReturning

[<AutoOpen>]
module private NoReturnFunctionIdentificationHelper =

  let hasConditionallyInvalidFallEdge codeMgr fn callSiteAddr entry =
    let callee = (codeMgr: CodeManager).FunctionMaintainer.Find (addr=entry)
    match callee.NoReturnProperty with
    | ConditionalNoRet _ ->
      let bbl = codeMgr.GetBBL callSiteAddr
      let caller = Set.maxElement bbl.IRLeaders
      let v = (fn: RegularFunction).FindVertex caller
      DiGraph.GetSuccs ((fn: RegularFunction).IRCFG, v)
      |> List.exists (fun w ->
        (* Since the fall-through edge exists, block-level constant propagation
           were not able to remove the edge. So this is a non-trivial case. *)
        fn.IRCFG.FindEdgeData (v, w) = CallFallThroughEdge)
    | _ -> false

  let isPotentiallyNonTrivialConditionalNoRet codeMgr (fn: RegularFunction) =
    fn.CallEdges
    |> Array.exists (fun (callSiteAddr, callee) ->
      match callee with
      | RegularCallee addr ->
        hasConditionallyInvalidFallEdge codeMgr fn callSiteAddr addr
      | IndirectCallees addrs ->
        addrs
        |> Set.exists (hasConditionallyInvalidFallEdge codeMgr fn callSiteAddr)
      | UnresolvedIndirectCallees _ | NullCallee -> false)

  /// We disregard jump trampolines and consider them as NotNoRet.
  let checkTrampoline (vertices: IRVertex list) =
    match vertices with
    | [ v ] when not (v.VData.IsFakeBlock ()) -> (* Only single exit node. *)
      let ins = v.VData.LastInstruction
      if ins.IsIndirectBranch () then (* This is really a trampoline. *) []
      else vertices
    | _ -> vertices

  let rec analyzeExits (codeMgr: CodeManager) fn cond = function
    | (v: IRVertex) :: tl when cond = IsNoReturning || cond = IsUndecidable ->
      if v.VData.IsFakeBlock () then
        let cond =
          (fn: RegularFunction).CallTargets v.VData.FakeBlockInfo.CallSite
          |> Set.fold (fun cond callee ->
            let calleeFunc = codeMgr.FunctionMaintainer.Find callee
            match calleeFunc.NoReturnProperty with
            (* Since we are analyzing exit nodes, the fall-through edge does
               not exist at this point. Thus, ConditionalNoRet here implies
               the call will not return. *)
            | NoRet | ConditionalNoRet _ ->
              NoReturnDecision.meet cond IsNoReturning
            | _ ->
              if v.VData.FakeBlockInfo.IsTailCall then IsReturning
              elif fn.EntryPoint = callee then cond
              else Utils.impossible () (* We are only considering exit nodes. *)
          ) cond
        analyzeExits codeMgr fn cond tl
      else
        let cond = NoReturnDecision.meet cond IsNoReturning
        analyzeExits codeMgr fn cond tl
    | _ -> cond

  /// The algorithm is simple: if there exists a return block (with a ret
  /// instruction), we consider it as a returning function.
  let performBasicNoRetAnalysis codeMgr (func: RegularFunction) =
    let decision =
      DiGraph.GetExits func.IRCFG
      |> checkTrampoline
      |> analyzeExits codeMgr func IsUndecidable
    match decision with
    | IsReturning -> func.NoReturnProperty <- NotNoRet
    | IsNoReturning -> func.NoReturnProperty <- NoRet
    | IsUndecidable ->
      (* This is an exceptional case, e.g., jump stubs, and compilers will not
         make it as a no-return function. So making it NotNoRet is safe. *)
      func.NoReturnProperty <- NotNoRet

  let confirmArgX86 fakeBlk (uvState: CPState<UVValue>) arg =
    match (fakeBlk: SSAVertex).VData.FakeBlockInfo.FrameDistance with
    | Some offset ->
      let argOffset = offset - 4 * arg
      let varKind = SSA.StackVar (32<rt>, argOffset)
      match SSACFG.findReachingDef fakeBlk varKind with
      | Some (SSA.Def (v, _)) ->
        match CPState.findReg uvState v with
        | Untouched (RegisterTag { Kind = SSA.StackVar (_, offset) }) ->
          Some (- offset / 4)
        | _ -> None
      | _ -> None
    | None -> None

  let ssaRegToArgX64 hdl (r: SSA.Variable) =
    match r.Kind with
    | SSA.RegVar (_, rid, _) ->
      if rid = CallingConvention.functionArgRegister hdl 1 then Some 1
      elif rid = CallingConvention.functionArgRegister hdl 2 then Some 2
      elif rid = CallingConvention.functionArgRegister hdl 3 then Some 3
      elif rid = CallingConvention.functionArgRegister hdl 4 then Some 4
      elif rid = CallingConvention.functionArgRegister hdl 5 then Some 5
      elif rid = CallingConvention.functionArgRegister hdl 6 then Some 6
      else None
    | _ -> None

  let confirmArgX64 hdl fakeBlk uvState arg =
    let rid = CallingConvention.functionArgRegister hdl arg
    let name = hdl.RegisterBay.RegIDToString rid
    let varKind = SSA.RegVar (64<rt>, rid, name)
    match SSACFG.findReachingDef fakeBlk varKind with
    | Some (SSA.Def (v, _)) ->
      match CPState.findReg uvState v with
      | Untouched (RegisterTag r) -> ssaRegToArgX64 hdl r
      | _ -> None
    | _ ->
      (* If no definition is found, this means the parameter register is
         untouched, thus, conditional no return. *)
      Some arg

  let confirmArg hdl fakeBlk uvState arg =
    match hdl.ISA.Arch with
    | Arch.IntelX86 -> confirmArgX86 fakeBlk uvState arg
    | Arch.IntelX64 -> confirmArgX64 hdl fakeBlk uvState arg
    | _ -> None

  /// For every conditionally no-returning function callee, check if the `func`
  /// only uses the constant value originated from the function argument. This
  /// function returns a set of confirmed call info (caller bbl, untouched
  /// argument number). We say a call to a conditionally no-returning function
  /// is "confirmed" if the function is called directly from an argument of the
  /// calling function `func`, and the argument is never redefined until it
  /// reaches the function call.
  let getConfirmedNoRets hdl codeMgr func ssaCFG uvState =
    (func: RegularFunction).CallEdges
    |> Array.fold (fun acc (callSiteAddr, callee) ->
      match callee with
      | RegularCallee entry ->
        let callee = (codeMgr: CodeManager).FunctionMaintainer.Find entry
        match callee.NoReturnProperty with
        | ConditionalNoRet arg ->
          let caller = SSACFG.findVertexByAddr ssaCFG callSiteAddr
          let fake =
            DiGraph.GetSuccs (ssaCFG, caller)
            |> List.find (fun w -> w.VData.IsFakeBlock ())
          match confirmArg hdl fake uvState arg with
          | Some arg -> Set.add (caller, arg) acc
          | None -> acc
        (* XXX: handling IndirectCallees? *)
        | _ -> acc
      | _ -> acc) Set.empty

  /// Since we removed all confirmed fall-through edges (which were all
  /// connected in the original graph), if all the exit nodes of the current CFG
  /// are either NoRet or ConditionalNoRet, then we can say that this function
  /// is a conditionally no-returning function.
  let isConditionalNoret (codeMgr: CodeManager) ssaCFG =
    DiGraph.GetExits ssaCFG
    |> List.forall (fun (v: SSAVertex) ->
      if v.VData.IsFakeBlock () then
        match codeMgr.FunctionMaintainer.TryFind v.VData.PPoint.Address with
        | Some callee ->
          match callee.NoReturnProperty with
          | NoRet | ConditionalNoRet _ -> true
          | _ -> false
        | None -> false
      else false)

  let removeFallThroughAndRetFromConfirmedBlocks ssaCFG norets =
    norets
    |> Set.fold (fun ssaCFG (caller, _) ->
      let ftNode =
        DiGraph.GetSuccs (ssaCFG, caller)
        |> List.find (fun w ->
          DiGraph.FindEdgeData (ssaCFG, caller, w) = CallFallThroughEdge)
      let fakeNode =
        DiGraph.GetSuccs (ssaCFG, caller)
        |> List.find (fun w ->
          DiGraph.FindEdgeData (ssaCFG, caller, w) = CallEdge)
      DiGraph.GetPreds (ssaCFG, ftNode)
      |> List.fold (fun acc u ->
        match DiGraph.FindEdgeData (ssaCFG, u, ftNode) with
        | CallFallThroughEdge when u = caller -> (u, ftNode) :: acc
        | RetEdge when u = fakeNode -> (u, ftNode) :: acc
        | _ -> acc) []
      |> List.fold (fun ssaCFG (v, w) ->
        DiGraph.RemoveEdge (ssaCFG, v, w)) ssaCFG
    ) ssaCFG

  let trimSSACFG ssaCFG ssaRoot norets =
    let ssaCFG = removeFallThroughAndRetFromConfirmedBlocks ssaCFG norets
    let reachables =
      Set.empty
      |> Traversal.foldPostorder ssaCFG [ssaRoot] (fun acc v -> Set.add v acc)
    let allVertices = DiGraph.GetVertices ssaCFG
    Set.difference allVertices reachables
    |> Set.fold (fun ssaCFG v -> DiGraph.RemoveVertex (ssaCFG, v)) ssaCFG

  let updateProperty codeMgr (func: RegularFunction) norets =
    let cond =
      norets
      |> Set.fold (fun acc (_, arg) -> Set.add arg acc) Set.empty
    if Set.count cond = 1 then
      let cond = Set.minElement cond
      func.NoReturnProperty <- ConditionalNoRet cond
    elif Set.count cond = 0 then
      (* We potentially had a wrong decision, so perform the basic analysis
         again. *)
      performBasicNoRetAnalysis codeMgr func
    else Utils.futureFeature () (* This is an interesting case. *)

  /// Since we cannot decide by simply looking at call instructions, we now
  /// perform a data-flow analysis on the function's parameters to know if one
  /// of the parameters defines the input of the conditionally no-returning
  /// function's parameter.
  let performParamAnalysis hdl codeMgr (fn: RegularFunction) =
    let ssaCFG, ssaRoot = fn.GetSSACFG hdl
    let uvp = UntouchedValuePropagation (hdl, ssaCFG)
    let uvState = uvp.Compute ssaRoot
    let norets = getConfirmedNoRets hdl codeMgr fn ssaCFG uvState
    let ssaCFG' = trimSSACFG ssaCFG ssaRoot norets
    if isConditionalNoret codeMgr ssaCFG' then updateProperty codeMgr fn norets
    else fn.NoReturnProperty <- NotNoRetConfirmed

  let hasNonZeroOnX86 st arg =
    let esp = (Intel.Register.ESP |> Intel.Register.toRegID)
    match readReg st esp with
    | Some sp ->
      let p = BitVector.Add (BitVector.OfInt32 (4 * arg) 32<rt>, sp)
      match readMem st p Endian.Little 32<rt> with
      | Some v -> v <> 0UL
      | None -> false
    | None -> false

  let hasNonZeroOnX64 hdl st arg =
    let reg = CallingConvention.functionArgRegister hdl arg
    match readReg st reg with
    | Some bv -> BitVector.ToUInt64 bv <> 0UL
    | None -> false

/// NoReturnFunctionIdentification has two roles: (1) identify whether a
/// function is non-returning or not, and (2) add return and fall-through edges
/// if callee function is non-returning.
type NoReturnFunctionIdentification () =
  inherit PerFunctionAnalysis ()

  override __.Name = "NoReturnFunctionIdentification"

  override __.Run hdl codeMgr _dataMgr func evts =
#if CFGDEBUG
    dbglog "NoRetAnalysis" "@%x before: %A"
      func.EntryPoint func.NoReturnProperty
#endif
    match func.NoReturnProperty with
    | UnknownNoRet -> performBasicNoRetAnalysis codeMgr func
    | NotNoRet when isPotentiallyNonTrivialConditionalNoRet codeMgr func ->
      performParamAnalysis hdl codeMgr func
    | _ -> ()
#if CFGDEBUG
    dbglog "NoRetAnalysis" "@%x after: %A" func.EntryPoint func.NoReturnProperty
#endif
    Ok evts

  /// Check whether the (nth) argument is always non-zero. This is used only for
  /// known error functions, which can conditionally become a no-ret function
  /// depending on the given argument value.
  member __.HasNonZeroArg hdl caller nth =
    let st = evalBlock hdl caller
    match hdl.ISA.Arch with
    | Arch.IntelX86 -> hasNonZeroOnX86 st nth
    | Arch.IntelX64 -> hasNonZeroOnX64 hdl st nth
    | _ -> Utils.futureFeature ()

  /// Check whether the given bbl has a no-return syscall (e.g., exit).
  member __.IsNoRetSyscallBlk hdl bbl =
    let st = evalBlock hdl bbl
    match hdl.FileInfo.FileFormat with
    | FileFormat.ELFBinary | FileFormat.RawBinary ->
      let arch = hdl.ISA.Arch
      let exitSyscall = LinuxSyscall.toNumber arch LinuxSyscall.Exit
      let exitGrpSyscall = LinuxSyscall.toNumber arch LinuxSyscall.ExitGroup
      let sigreturnSyscall = LinuxSyscall.toNumber arch LinuxSyscall.RtSigreturn
      let reg = CallingConvention.returnRegister hdl
      match readReg st reg with
      | None -> false
      | Some v ->
        let n = BitVector.ToInt32 v
        n = exitSyscall || n = exitGrpSyscall || n = sigreturnSyscall
    | _ -> false

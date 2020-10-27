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

namespace B2R2.MiddleEnd.Reclaimer

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinInterface
open B2R2.MiddleEnd.ConcEval
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinEssence
open B2R2.MiddleEnd.Lens
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.Reclaimer.EmulationHelper
open System.Collections.Generic

module private NoReturnHelper =

  let isExternalNoReturnFunction = function
    | "__assert_fail"
    | "__stack_chk_fail"
    | "abort"
    | "_abort"
    | "exit"
    | "_exit"
    | "__longjmp_chk"
    | "__cxa_throw"
    | "_Unwind_Resume"
    | "_ZSt20__throw_length_errorPKc"
    | "_gfortran_stop_numeric" -> true
    | _ -> false

  let isKnownNoReturnFunction ess entry =
    Map.containsKey entry ess.NoReturnInfo.NoReturnFuncs

  let sideEffectHandler _eff st =
    EvalState.NextStmt st

  let evalBlock (ess: BinEssence) (v: Vertex<IRBasicBlock>) =
    let hdl = ess.BinHandle
    let st = EvalState (emptyMemoryReader hdl, true)
    let addr = v.VData.PPoint.Address
    let lastAddr = v.VData.LastInstruction.Address
    let st = initRegs hdl |> EvalState.PrepareContext st 0 addr
    st.Callbacks.SideEffectEventHandler <- sideEffectHandler
    eval ess v st (fun last -> last.Address = lastAddr)

  let checkArgumentsX86 isOk args st =
    let esp = (Intel.Register.ESP |> Intel.Register.toRegID)
    match EvalState.GetReg st esp with
    | EvalValue.Def sp ->
      args
      |> Set.forall (fun arg ->
        let p = BitVector.add (BitVector.ofInt32 (4 * arg) 32<rt>) sp
        isOk <| readMem st p Endian.Little 32<rt>)
    | EvalValue.Undef -> false

  let tryGetArgX64 = function
    | 1 -> Some Intel.Register.RDI
    | 2 -> Some Intel.Register.RSI
    | 3 -> Some Intel.Register.RDX
    | 4 -> Some Intel.Register.RCX
    | 5 -> Some Intel.Register.R8
    | 6 -> Some Intel.Register.R9
    | _ -> None

  let checkArgumentsX64 isOk args st =
    args
    |> Set.forall (fun arg ->
      match tryGetArgX64 arg with
      | None -> false
      | Some reg ->
        match readReg st (Intel.Register.toRegID reg) with
        | Some bv -> BitVector.toUInt64 bv |> Some |> isOk
        | None -> isOk None)

  let checkArguments hdl isOk args = function
    | None -> false
    | Some st ->
      match hdl.ISA.Arch with
      | Arch.IntelX86 -> checkArgumentsX86 isOk args st
      | Arch.IntelX64 -> checkArgumentsX64 isOk args st
      | _ -> false

  let collectEdgesToFallThrough cfg edges (v: Vertex<IRBasicBlock>) =
    DiGraph.getPreds cfg v
    |> List.fold (fun acc pred ->
      match cfg.FindEdgeData pred v with
      | RetEdge | CallFallThroughEdge ->
        (pred, v) :: acc
      | _ -> acc) edges

  let isNoReturnFunction ess caller entry =
    match Map.tryFind entry ess.NoReturnInfo.NoReturnFuncs with
    | Some UnconditionalNoRet -> true
    | Some (ConditionalNoRet args) ->
      let isOk res =
        match res with
        | Some v -> v <> 0UL
        | None -> false
      evalBlock ess caller
      |> checkArguments ess.BinHandle isOk args
    | None -> false

  let collectFunctionCallFallThroughs ess cfg (v: Vertex<IRBasicBlock>) edges =
    if ProgramPoint.IsFake v.VData.PPoint then edges
    else
      let entry = v.VData.PPoint.Address
      DiGraph.getPreds cfg v
      |> List.fold (fun edges caller ->
        if isNoReturnFunction ess caller entry then
          DiGraph.getSuccs cfg v
          |> List.fold (collectEdgesToFallThrough cfg) edges
        else edges) edges

  let checkExitSyscall hdl = function
    | Some st when hdl.FileInfo.FileFormat = FileFormat.ELFBinary
                || hdl.FileInfo.FileFormat = FileFormat.RawBinary ->
      let arch = hdl.ISA.Arch
      let exitSyscall = LinuxSyscall.toNumber arch LinuxSyscall.Exit
      let exitGrpSyscall = LinuxSyscall.toNumber arch LinuxSyscall.ExitGroup
      let reg = CallingConvention.returnRegister hdl
      match readReg st reg with
      | None -> false
      | Some v ->
        let n = BitVector.toInt32 v
        n = exitSyscall || n = exitGrpSyscall
    | _ -> false

  let hasExitSyscall ess (v: Vertex<IRBasicBlock>) =
    if v.VData.IsFakeBlock () then false
    elif v.VData.GetLastStmt () = LowUIR.SideEffect SysCall then
      evalBlock ess v
      |> checkExitSyscall ess.BinHandle
    else false

  let collectSyscallFallThroughs ess cfg v edges =
    if hasExitSyscall ess v then
      DiGraph.getSuccs cfg v
      |> List.fold (fun acc w -> (v, w) :: acc) edges
    else edges

  let collectEdgesToRemove ess cfg =
    []
    |> DiGraph.foldVertex cfg (fun edges (v: Vertex<IRBasicBlock>) ->
      if v.VData.IsFakeBlock () then
        collectFunctionCallFallThroughs ess cfg v edges
      else collectSyscallFallThroughs ess cfg v edges)

  let removeFallThroughEdges (ess: BinEssence) entry =
    let cfg, _ = ess.GetFunctionCFG (entry, false) |> Result.get
    let ess, scfg =
      collectEdgesToRemove ess cfg
      |> List.fold (fun (ess, scfg) (src, dst) ->
        if src.VData.IsFakeBlock () then ess, scfg
        else
          let src = Map.find src.VData.PPoint ess.BBLStore.VertexMap
          let dst = Map.find dst.VData.PPoint ess.BBLStore.VertexMap
          let scfg = DiGraph.removeEdge scfg src dst
          let ess = BinEssence.addNoReturnCallSite ess src.VData.PPoint
          ess, scfg) (ess, ess.SCFG)
    { ess with SCFG = scfg }

  let returnsPossibly ess cfg root =
    true
    |> Traversal.foldPostorder cfg [root] (fun acc (v: Vertex<IRBasicBlock>) ->
      if DiGraph.getSuccs cfg v |> List.isEmpty then
        if v.VData.IsFakeBlock () then
          let ppoint = v.VData.PPoint
          if ProgramPoint.IsFake ppoint then false
          (* Including conditional noreturn functions *)
          elif isKnownNoReturnFunction ess ppoint.Address then acc
          else false
        elif v.VData.LastInstruction.IsInterrupt () then acc
        else false
      else acc)
    |> not

  let isUncertainNoRet ess caller entry =
    match Map.tryFind entry ess.NoReturnInfo.NoReturnFuncs with
    | Some (ConditionalNoRet args) ->
      let isOk res = Option.isSome res
      (* If we can't ensure that at least one of conditions are satisfied. *)
      evalBlock ess caller |> checkArguments ess.BinHandle isOk args |> not
    | _ -> false

  let collectUncertainNoRetCallers ess cfg acc (v: Vertex<IRBasicBlock>) =
    let ppoint = v.VData.PPoint
    if v.VData.IsFakeBlock () && not <| ProgramPoint.IsFake ppoint then
      if isKnownNoReturnFunction ess ppoint.Address then
        DiGraph.getPreds cfg v
        |> List.fold (fun acc p ->
          if isUncertainNoRet ess p ppoint.Address then p :: acc else acc) acc
      else acc
    else acc

  let disconnectPotentialFallThroughs ess cfg root =
    let callers =
      DiGraph.foldVertex cfg (collectUncertainNoRetCallers ess cfg) []
    let cfg =
      callers
      |> List.fold (fun cfg v ->
        DiGraph.getSuccs cfg v
        |> List.fold (collectEdgesToFallThrough cfg) []
        |> List.fold (fun cfg (src, dst) ->
          DiGraph.removeEdge cfg src dst) cfg) cfg
    let reachables =
      Traversal.foldPostorder cfg [root] (fun acc v -> Set.add v acc) Set.empty
    let unreachables = Set.difference (DiGraph.getVertices cfg) reachables
    let cfg =
      unreachables |> Set.fold (fun cfg v -> DiGraph.removeVertex cfg v) cfg
    cfg, List.filter (fun v -> Set.contains v reachables) callers

  let findRecentDef (v: Vertex<SSABBlock>) rdIns def =
    (rdIns: Dictionary<_, Set<SSA.Variable>>).[v.GetID ()]
    |> Set.toList
    |> List.find (fun v -> v.Kind = def)

  let transformArgX86 v spState udState rdIns arg =
    let sp =
      SSA.RegVar (32<rt>, Intel.Register.ESP |> Intel.Register.toRegID, "ESP")
      |> findRecentDef v rdIns
    let mem = findRecentDef v rdIns SSA.MemVar
    match spState.RegState.[sp] with
    | StackValue.Const bv ->
      let addr = BitVector.toUInt64 bv + uint64 (4 * arg)
      match CPState.findMem udState mem 32<rt> addr with
      | Tainted (MemoryTag from) when from >= 0x80000004UL ->
        (from - 0x80000000UL) / 4UL |> int |> Some
      | _ -> None
    | _ -> None

  let ssaRegToArgX64 (r: SSA.Variable) =
    match r.Kind with
    | SSA.RegVar (_, _, "RDI") -> Some 1
    | SSA.RegVar (_, _, "RSI") -> Some 2
    | SSA.RegVar (_, _, "RDX") -> Some 3
    | SSA.RegVar (_, _, "RCX") -> Some 4
    | SSA.RegVar (_, _, "R8") -> Some 5
    | SSA.RegVar (_, _, "R9") -> Some 6
    | _ -> None

  let transformArgX64 v udState rdIns arg =
    let reg = tryGetArgX64 arg
    match reg with
    | None -> None
    | Some reg ->
      let rid = Intel.Register.toRegID reg
      let name = Intel.Register.toString reg
      let reg = SSA.RegVar (64<rt>, rid, name) |> findRecentDef v rdIns
      match CPState.findReg udState reg with
      | Tainted (RegisterTag r) -> ssaRegToArgX64 r
      | _ -> None

  let transformArg hdl v spState udState rdIns arg =
    match hdl.ISA.Arch with
    | Arch.IntelX86 -> transformArgX86 v spState udState rdIns arg
    | Arch.IntelX64 -> transformArgX64 v udState rdIns arg
    | _ -> None

  let transformArgs hdl v spState udState rdIns args =
    args
    |> Set.fold (fun acc arg ->
      match acc with
      | None -> None
      | Some acc ->
        match transformArg hdl v spState udState rdIns arg with
        | None -> None
        | Some arg -> Set.add arg acc |> Some) (Some Set.empty)
    |> fun set ->
      match set with
      | None -> Set.empty
      | Some set -> set

  let accumulateNoReturnCondition ess spState udState rdIns cond v =
    let target = (v: Vertex<SSABBlock>).VData.PPoint.Address
    match cond, Map.tryFind target ess.NoReturnInfo.NoReturnFuncs with
    | None, _ -> cond
    | _, None -> None
    | _, Some UnconditionalNoRet -> cond
    | Some UnconditionalNoRet, Some (ConditionalNoRet args) ->
      let args = transformArgs ess.BinHandle v spState udState rdIns args
      if Set.isEmpty args then None
      else ConditionalNoRet args |> Some
    | Some (ConditionalNoRet args), Some (ConditionalNoRet args') ->
      let args' = transformArgs ess.BinHandle v spState udState rdIns args'
      let args = Set.intersect args args'
      if Set.isEmpty args then None
      else ConditionalNoRet args |> Some

  let computeNoReturnCondition ess cfg root callers =
    let lens = SSALens.Init ess
    let ssaCFG, ssaRoots = lens.Filter (cfg, [root], ess)
    let ssaRoot = List.head ssaRoots
    let sp = StackPointerPropagation.Init ess.BinHandle ssaCFG
    let spState = sp.Compute ess ssaRoot
    let mps = StackState.computeMemoryMergePoints ess ssaCFG spState
    let udProp = UndefPropagation.Init ess.BinHandle ssaCFG spState mps
    let udState = udProp.Compute ess ssaRoot
    let ssaRD = SSAReachingDefinitions (ssaCFG)
    let rdIns, _ = ssaRD.Compute ssaCFG ssaRoot
    callers
    |> List.fold (fun acc (v: Vertex<IRBasicBlock>) ->
      DiGraph.findVertexBy ssaCFG (fun w -> w.VData.PPoint = v.VData.PPoint)
      |> DiGraph.getSuccs ssaCFG
      |> List.filter (fun v -> v.VData.IsFakeBlock ())
      |> List.fold (accumulateNoReturnCondition ess spState udState rdIns) acc
      ) (Some UnconditionalNoRet)

  let checkNoReturnCondition (ess: BinEssence) entry =
    let cfg, root = ess.GetFunctionCFG (entry, false) |> Result.get
    if returnsPossibly ess cfg root then
      (* 1. Disconnect potential noreturn fall throughs *)
      let cfg, callers = disconnectPotentialFallThroughs ess cfg root
      (* 2. Compute intersection of conditions *)
      if returnsPossibly ess cfg root then None
      elif List.isEmpty callers then Some UnconditionalNoRet
      else computeNoReturnCondition ess cfg root callers
    else Some UnconditionalNoRet

  let addNoReturnFunctionFromExternal ess (v: Vertex<CallGraphBBlock>) entry =
    if isExternalNoReturnFunction v.VData.Name then
      BinEssence.addNoReturnFunction ess entry UnconditionalNoRet
    elif v.VData.Name = "error" || v.VData.Name = "error_at_line" then
      let cond = Set.singleton 1
      BinEssence.addNoReturnFunction ess entry (ConditionalNoRet cond)
    else ess

  let propagateNoReturnCondition ess (v: Vertex<CallGraphBBlock>) entry =
    let ess = removeFallThroughEdges ess entry
    match checkNoReturnCondition ess entry with
    | None -> ess
    | Some cond -> BinEssence.addNoReturnFunction ess entry cond

  let rec analysisLoop ess hint = function
    | [] -> ess, hint
    | (v: Vertex<CallGraphBBlock>) :: vs ->
      let entry = v.VData.PPoint.Address
      let ess =
        if v.VData.IsExternal then addNoReturnFunctionFromExternal ess v entry
        else propagateNoReturnCondition ess v entry
      let hint = AnalysisHint.markNoReturn entry hint
      analysisLoop ess hint vs

  let getTargetFunction hint (v: Vertex<CallGraphBBlock>) =
    Set.contains v.VData.PPoint.Address hint.NoReturnPerformed |> not

  let findNoReturnEdges ess hint =
    let lens = CallGraphLens.Init ()
    let cg, roots = lens.Filter (ess.SCFG, [], ess)
    Traversal.foldTopologically cg roots (fun acc v -> v :: acc) []
    |> List.filter (getTargetFunction hint)
    |> analysisLoop ess hint

type NoReturnAnalysis () =
  interface IAnalysis with
    member __.Name = "No-Return Analysis"

    member __.Run ess hint =
      NoReturnHelper.findNoReturnEdges ess hint

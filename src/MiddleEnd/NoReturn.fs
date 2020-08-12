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

namespace B2R2.MiddleEnd

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd
open B2R2.ConcEval
open B2R2.BinGraph
open B2R2.BinEssence
open B2R2.Lens
open B2R2.MiddleEnd.EmulationHelper

module private NoReturnHelper =

  let isKnownNoReturnFunction = function
    | "__assert_fail"
    | "__stack_chk_fail"
    | "abort"
    | "_abort"
    | "exit"
    | "_exit" -> true
    | _ -> false

  let hasError ess (v: Vertex<IRBasicBlock>) =
    if v.VData.IsFakeBlock () then
      let target = v.VData.PPoint.Address
      match ess.CalleeMap.Find target with
      | Some callee when callee.CalleeName = "error" -> true
      | _ -> false
    else false

  let hasNoRet noretAddrs (v: Vertex<IRBasicBlock>) =
    if v.VData.IsFakeBlock () then
      Set.contains v.VData.PPoint.Address noretAddrs
    else false

  let stmtHandler (bblAddr: Addr ref) = function
    | LowUIR.ISMark (addr, _) -> bblAddr := addr
    | _ -> ()

  let sideEffectHandler _eff st =
    EvalState.NextStmt st

  let checkExitSyscall reg exitSyscall exitGrpSyscall st =
    match readReg st reg with
    | None -> false
    | Some v ->
      let n = BitVector.toInt32 v
      n = exitSyscall || n = exitGrpSyscall

  let retrieveSyscallState (hdl: BinHandler) = function
    | Some st when hdl.FileInfo.FileFormat = FileFormat.ELFBinary
                || hdl.FileInfo.FileFormat = FileFormat.RawBinary ->
      let arch = hdl.ISA.Arch
      let exitSyscall = LinuxSyscall.toNumber arch LinuxSyscall.Exit
      let exitGrpSyscall = LinuxSyscall.toNumber arch LinuxSyscall.ExitGroup
      let reg = CallingConvention.returnRegister hdl
      checkExitSyscall reg exitSyscall exitGrpSyscall st
    | _ -> false

  let existSyscall cfg =
    DiGraph.foldVertex cfg (fun acc (v: Vertex<IRBasicBlock>) ->
      if v.VData.IsFakeBlock () then acc
      else
        match v.VData.GetLastStmt () with
        | LowUIR.SideEffect SysCall -> true
        | _ -> acc) false

  let findExitSyscalls hdl ess cfg (root: Vertex<IRBasicBlock>) =
    if existSyscall cfg then
      let addr = root.VData.PPoint.Address
      let st = EvalState (memoryReader hdl, true)
      let st = initRegs hdl |> EvalState.PrepareContext st 0 addr
      let bblAddr = ref 0UL
      st.Callbacks.StmtEvalEventHandler <- stmtHandler bblAddr
      st.Callbacks.SideEffectEventHandler <- sideEffectHandler
      try
        let isExit =
          eval ess root st (fun last -> last.IsInterrupt ())
          |> retrieveSyscallState hdl
        if isExit then Some !bblAddr else None
      with _ -> None
    else None

  let collectExitSyscallFallThroughs ess cfg root edges =
    let hdl = ess.BinHandler
    match findExitSyscalls hdl ess cfg root with
    | Some addr ->
      match DiGraph.tryFindVertexBy cfg (fun (v: Vertex<IRBasicBlock>) ->
        not (v.VData.IsFakeBlock ())
        && v.VData.PPoint.Address <= addr
        && (v.VData.LastInstruction.Address
          + uint64 v.VData.LastInstruction.Length) > addr) with
      | None -> edges
      | Some v ->
        DiGraph.getSuccs cfg v |> List.fold (fun acc w -> (v, w) :: acc) edges
    | None -> edges

  let checkFirstArgumentX86 st =
    let esp = (Intel.Register.ESP |> Intel.Register.toRegID)
    match EvalState.GetReg st esp with
    | Def sp ->
      let p = BitVector.add (BitVector.ofInt32 4 32<rt>) sp
      match readMem st p Endian.Little 32<rt> with
      | Some v -> v <> 0UL
      | None -> false
    | Undef -> false

  let checkFirstArgumentX64 st =
    match readReg st (Intel.Register.RDI |> Intel.Register.toRegID) with
    | Some bv -> BitVector.toUInt64 bv <> 0UL
    | None -> false

  let checkFirstArgument hdl = function
    | None -> false
    | Some st ->
      match hdl.ISA.Arch with
      | Arch.IntelX86 -> checkFirstArgumentX86 st
      | Arch.IntelX64 -> checkFirstArgumentX64 st
      | _ -> false

  let isNoReturnError ess (v: Vertex<IRBasicBlock>) =
    let hdl = ess.BinHandler
    let st = EvalState (memoryReader hdl, true)
    let addr = v.VData.PPoint.Address
    let lastAddr = v.VData.LastInstruction.Address
    let st = initRegs hdl |> EvalState.PrepareContext st 0 addr
    try
      eval ess v st (fun last -> last.Address = lastAddr)
      |> checkFirstArgument hdl
    with _ -> false

  let collectEdgesToFallThrough cfg edges (v: Vertex<IRBasicBlock>) =
    DiGraph.getPreds cfg v
    |> List.fold (fun acc pred ->
      match cfg.FindEdgeData pred v with
      | RetEdge | CallFallThroughEdge -> (pred, v) :: acc
      | _ -> acc) edges

  let collectErrorFallThroughs ess cfg edges =
    DiGraph.foldVertex cfg (fun acc v ->
      if hasError ess v then v :: acc else acc) []
    |> List.fold (fun acc v ->
      if List.exists (isNoReturnError ess) <| DiGraph.getPreds cfg v then
        List.fold (collectEdgesToFallThrough cfg) acc <| DiGraph.getSuccs cfg v
      else acc) edges

  let collectNoRetFallThroughs cfg noretAddrs edges =
    DiGraph.foldVertex cfg (fun acc v ->
      if hasNoRet noretAddrs v then v :: acc else acc) []
    |> List.fold (fun edges v ->
      DiGraph.getSuccs cfg v
      |> List.fold (collectEdgesToFallThrough cfg) edges) edges

  let collectNoRetFallThroughEdges ess cfg root noretAddrs =
    []
    |> collectExitSyscallFallThroughs ess cfg root
    |> collectErrorFallThroughs ess cfg
    |> collectNoRetFallThroughs cfg noretAddrs

  let rec removeUnreachables cfg root =
    let g = DiGraph.clone cfg
    let g =
      DiGraph.foldVertex g (fun acc (v: Vertex<IRBasicBlock>) ->
        if v.VData.IsFakeBlock () then v :: acc else acc) []
      |> List.fold DiGraph.removeVertex g
    let reachables =
      Traversal.foldPreorder cfg root (fun acc v -> v :: acc) []
    let cfg =
      DiGraph.foldVertex g (fun acc v ->
        if List.contains v reachables then acc else v :: acc) []
      |> List.map (fun v -> DiGraph.findVertexByData cfg v.VData)
      |> List.fold DiGraph.removeVertex cfg
    DiGraph.foldVertex cfg (fun acc v ->
      let isUnreachable =
        v.VData.IsFakeBlock () && DiGraph.getPreds cfg v |> List.length = 0
      if isUnreachable then v :: acc else acc) []
    |> List.fold DiGraph.removeVertex cfg

  let modifyCFG (ess: BinEssence) noretAddrs addr =
    let cfg, root = ess.GetFunctionCFG (addr, false)
    let cfg =
      collectNoRetFallThroughEdges ess cfg root noretAddrs
      |> List.fold (fun cfg (src, dst) -> DiGraph.removeEdge cfg src dst) cfg
    removeUnreachables cfg root

  let isAlreadyVisited noretAddrs (v: Vertex<CallGraphBBlock>) =
    Set.contains v.VData.PPoint.Address noretAddrs

  let isNoReturn ess noretAddrs (v: Vertex<CallGraphBBlock>) =
    let addr = v.VData.PPoint.Address
    if v.VData.IsExternal then isKnownNoReturnFunction v.VData.Name
    else
      let cfg = modifyCFG ess noretAddrs addr
      cfg.FoldVertex (fun acc (v: Vertex<IRBasicBlock>) ->
        if List.length <| DiGraph.getSuccs cfg v > 0 then acc
        elif v.VData.IsFakeBlock () then
          let target = v.VData.PPoint.Address
          let targetV = ess.CalleeMap.Find target |> Option.get
          if Set.contains target noretAddrs then acc
          elif isKnownNoReturnFunction targetV.CalleeName then acc
          elif targetV.CalleeName = "error" then acc
          else false
        elif v.VData.LastInstruction.IsInterrupt () then acc
        else false) true

  let rec findLoop ess cg visited noretVertices = function
    | [] ->
      let fresh =
        DiGraph.foldVertex cg (fun acc v ->
          if Set.contains v visited then acc else v :: acc) []
      if List.isEmpty fresh then noretVertices
      else findLoop ess cg visited noretVertices fresh
    | v :: vs ->
      let noretAddrs =
        noretVertices
        |> Set.map (fun (v: Vertex<CallGraphBBlock>) -> v.VData.PPoint.Address)
      if isAlreadyVisited noretAddrs v then
        let visited = Set.add v visited
        findLoop ess cg visited noretVertices vs
      elif isNoReturn ess noretAddrs v then
        let visited = Set.add v visited
        DiGraph.getPreds cg v @ vs
        |> findLoop ess cg visited (Set.add v noretVertices)
      else
        let visited = Set.add v visited
        findLoop ess cg visited noretVertices vs

  let getNoReturnFunctions ess noretVertices =
    let noretFuncs = ess.NoReturnInfo.NoReturnFuncs
    noretVertices
    |> Set.fold (fun acc (v: Vertex<CallGraphBBlock>) ->
      let addr = v.VData.PPoint.Address
      match ess.CalleeMap.Find (addr) with
      | None -> acc
      | Some _ -> Set.add addr acc) noretFuncs

  let getNoReturnCallSites ess noretFuncs =
    let callsites = ess.NoReturnInfo.NoReturnCallSites
    ess.CalleeMap.Entries
    |> Set.fold (fun acc addr ->
      let cfg, root = ess.GetFunctionCFG (addr, false)
      collectNoRetFallThroughEdges ess cfg root noretFuncs
      |> List.filter (fun (src, dst) -> cfg.FindEdgeData src dst <> RetEdge)
      |> List.map (fun (src, _) -> src.VData.PPoint)
      |> Set.ofList
      |> Set.union acc) callsites

  let findNoReturnEdges ess =
    let lens = CallGraphLens.Init ()
    let cg, _ = lens.Filter (ess.SCFG, [], ess)
    let noretFuncs =
      DiGraph.foldVertex cg (fun acc v ->
        if List.length <| DiGraph.getSuccs cg v = 0 then v :: acc else acc) []
      |> findLoop ess cg Set.empty Set.empty
      |> getNoReturnFunctions ess
    let noretCallsites = getNoReturnCallSites ess noretFuncs
    BinEssence.addNoReturnInfo ess noretFuncs noretCallsites

type NoReturnAnalysis () =
  interface IAnalysis with
    member __.Name = "No-Return Analysis"

    member __.Run ess =
      NoReturnHelper.findNoReturnEdges ess

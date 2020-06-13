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
open B2R2.BinCorpus
open B2R2.ConcEval
open B2R2.BinGraph
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

  let hasSyscall (v: Vertex<IRBasicBlock>) =
    if v.VData.IsFakeBlock () then false
    else
      match v.VData.GetLastStmt () with
      | LowUIR.SideEffect SideEffect.SysCall -> true
      | _ -> false

  let hasError app (v: Vertex<IRBasicBlock>) =
    if v.VData.IsFakeBlock () then
      let target = v.VData.PPoint.Address
      match app.CalleeMap.Find target with
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

  let findSyscalls hdl scfg (root: Vertex<IRBasicBlock>) =
    let addr = root.VData.PPoint.Address
    let st = EvalState (memoryReader hdl, true)
    let st = initRegs hdl |> EvalState.PrepareContext st 0 addr
    let bblAddr = ref 0UL
    st.Callbacks.StmtEvalEventHandler <- stmtHandler bblAddr
    st.Callbacks.SideEffectEventHandler <- sideEffectHandler
    try
      let isExit =
        eval scfg root st (fun last -> last.IsInterrupt ())
        |> retrieveSyscallState hdl
      if isExit then Some !bblAddr else None
    with _ -> None

  let collectSyscallFallThroughs hdl scfg (cfg: IRCFG) root edges =
    match findSyscalls hdl scfg root with
    | Some addr ->
      match cfg.TryFindVertexBy (fun v ->
        not (v.VData.IsFakeBlock ())
        && v.VData.PPoint.Address <= addr
        && (v.VData.LastInstruction.Address
          + uint64 v.VData.LastInstruction.Length) > addr) with
      | None -> edges
      | Some v -> v.Succs |> List.fold (fun acc w -> (v, w) :: acc) edges
    | None -> edges

  let checkFirstArgumentX86 hdl st =
    let esp = (Intel.Register.ESP |> Intel.Register.toRegID)
    match EvalState.GetReg st esp with
    | Def sp ->
      let p = BitVector.add (BitVector.ofInt32 4 32<rt>) sp
      match readMem st p Endian.Little 32<rt> with
      | Some v -> v <> 0UL
      | None -> false
    | Undef -> false

  let checkFirstArgumentX64 hdl st =
    match readReg st (Intel.Register.RDI |> Intel.Register.toRegID) with
    | Some bv -> BitVector.toUInt64 bv <> 0UL
    | None -> false

  let checkFirstArgument hdl = function
    | None -> false
    | Some st ->
      match hdl.ISA.Arch with
      | Arch.IntelX86 -> checkFirstArgumentX86 hdl st
      | Arch.IntelX64 -> checkFirstArgumentX64 hdl st
      | _ -> false

  let isNoReturnError hdl scfg (v: Vertex<IRBasicBlock>) =
    let st = EvalState (memoryReader hdl, true)
    let addr = v.VData.PPoint.Address
    let lastAddr = v.VData.LastInstruction.Address
    let st = initRegs hdl |> EvalState.PrepareContext st 0 addr
    try
      eval scfg v st (fun last -> last.Address = lastAddr)
      |> checkFirstArgument hdl
    with _ -> false

  let collectEdgesToFallThrough (cfg: IRCFG) edges (v: Vertex<IRBasicBlock>) =
    v.Preds
    |> List.fold (fun acc pred ->
      match cfg.FindEdgeData pred v with
      | RetEdge | CallFallThroughEdge -> (pred, v) :: acc
      | _ -> acc) edges

  let collectErrorFallThroughs hdl scfg app (cfg: IRCFG) root edges =
    cfg.FoldVertex (fun acc v ->
      if hasError app v then v :: acc else acc) []
    |> List.fold (fun acc v ->
      if List.exists (isNoReturnError hdl scfg) v.Preds then
        List.fold (collectEdgesToFallThrough cfg) edges v.Succs
      else edges) edges

  let collectNoRetFallThroughs (cfg: IRCFG) noretAddrs edges =
    cfg.FoldVertex (fun acc v ->
      if hasNoRet noretAddrs v then v :: acc else acc) []
    |> List.fold (fun edges v ->
      List.fold (collectEdgesToFallThrough cfg) edges v.Succs) edges

  let collectFallThroughEdges hdl scfg app cfg root noretAddrs =
    []
    |> collectSyscallFallThroughs hdl scfg cfg root
    |> collectErrorFallThroughs hdl scfg app cfg root
    |> collectNoRetFallThroughs cfg noretAddrs

  let rec removeUnreachables (cfg: IRCFG) root =
    let g = cfg.Clone ()
    g.FoldVertex (fun acc v ->
      if v.VData.IsFakeBlock () then v :: acc else acc) []
    |> List.iter g.RemoveVertex
    let reachables =
      Traversal.foldPreorder root (fun acc v -> v :: acc) []
    g.FoldVertex (fun acc v ->
      if List.contains v reachables then acc else v :: acc) []
    |> List.map (fun v -> cfg.FindVertexByData v.VData)
    |> List.iter cfg.RemoveVertex
    cfg.FoldVertex (fun acc v ->
      if v.VData.IsFakeBlock () && List.length v.Preds = 0 then v :: acc
      else acc) []
    |> List.iter cfg.RemoveVertex

  let modifyCFG hdl (scfg: SCFG) app noretAddrs addr =
    let cfg, root = scfg.GetFunctionCFG (addr, false)
    collectFallThroughEdges hdl scfg app cfg root noretAddrs
    |> List.iter (fun (src, dst) -> cfg.RemoveEdge src dst)
    removeUnreachables cfg root
    cfg

  let isNoReturn hdl (scfg: SCFG) app noretAddrs (v: Vertex<CallGraphBBlock>) =
    let addr = v.VData.PPoint.Address
    if Set.contains addr noretAddrs then false
    elif v.VData.IsExternal then isKnownNoReturnFunction v.VData.Name
    else
      let cfg = modifyCFG hdl scfg app noretAddrs addr
      cfg.FoldVertex (fun acc (v: Vertex<IRBasicBlock>) ->
        if List.length v.Succs > 0 then acc
        elif v.VData.IsFakeBlock () then acc
        elif v.VData.LastInstruction.IsInterrupt () then acc
        else false) true

  let rec findLoop hdl scfg app noretVertices = function
    | [] -> noretVertices
    | v :: vs ->
      let noretAddrs =
        noretVertices
        |> Set.map (fun (v: Vertex<CallGraphBBlock>) -> v.VData.PPoint.Address)
      if isNoReturn hdl scfg app noretAddrs v then
        findLoop hdl scfg app (Set.add v noretVertices) (v.Preds @ vs)
      else findLoop hdl scfg app noretVertices vs

  let getNoReturnFunctions app noretVertices =
    noretVertices
    |> Set.fold (fun acc (v: Vertex<CallGraphBBlock>) ->
      let addr = v.VData.PPoint.Address
      match app.CalleeMap.Find (addr) with
      | None -> acc
      | Some callee -> Set.add addr acc) Set.empty

  let getNoReturnEdges hdl (scfg: SCFG) app noretFuncs =
    Apparatus.getFunctionAddrs app
    |> Seq.fold (fun acc addr ->
      let cfg, root = scfg.GetFunctionCFG (addr, false)
      let edges =
        collectFallThroughEdges hdl scfg app cfg root noretFuncs
        |> List.map (fun (src, _) -> src.VData.PPoint)
      edges @ acc) []

  let findNoReturnEdges hdl (scfg: SCFG) app recoveredInfo =
    let lens = CallGraphLens.Init (scfg)
    let cg, _ = lens.Filter scfg.Graph [] app
    let noretFuncs =
      cg.FoldVertex (fun acc v ->
        if List.length v.Succs = 0 then v :: acc else acc) []
      |> findLoop hdl scfg app Set.empty
      |> getNoReturnFunctions app
    let edges = getNoReturnEdges hdl scfg app noretFuncs
    Apparatus.addNoReturnInfo hdl app recoveredInfo (noretFuncs, edges)

type NoReturnAnalysis () =
  interface IAnalysis with
    member __.Name = "No-Return Analysis"

    member __.Run hdl scfg app recoveredInfo =
      let app', recoveredInfo' =
        NoReturnHelper.findNoReturnEdges hdl scfg app recoveredInfo
      match SCFG.Init (hdl, app', recoveredInfo') with
      | Ok scfg -> scfg, app', recoveredInfo'
      | Error e -> failwithf "Failed to run no-return analysis due to %A" e

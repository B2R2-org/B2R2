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

  let stmtHandler (bblAddr: Addr ref) = function
    | LowUIR.ISMark (addr, _) -> bblAddr := addr
    | _ -> ()

  let sideEffectHandler eff st =
    match eff with
    | SysCall -> EvalState.AbortInstr st
    | _ -> st

  let checkExitSyscall reg exitSyscall exitGrpSyscall st =
    match readReg st reg with
    | None -> false
    | Some v ->
      let n = BitVector.toInt32 v
      n = exitSyscall || n = exitGrpSyscall

  let retrieveSyscallState (hdl: BinHandler) = function
    | None -> false
    | Some st ->
      let arch = hdl.ISA.Arch
      let exitSyscall = LinuxSyscall.toNumber arch LinuxSyscall.Exit
      let exitGrpSyscall = LinuxSyscall.toNumber arch LinuxSyscall.ExitGroup
      let reg = CallingConvention.returnRegister hdl
      checkExitSyscall reg exitSyscall exitGrpSyscall st

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

  let disconnectSyscallFallthroughs hdl scfg (cfg: IRCFG) root =
    match findSyscalls hdl scfg root with
    | Some addr ->
      match cfg.TryFindVertexBy (fun v ->
        not (v.VData.IsFakeBlock ())
        && v.VData.PPoint.Address <= addr
        && (v.VData.LastInstruction.Address
          + uint64 v.VData.LastInstruction.Length) > addr) with
      | None -> ()
      | Some v -> v.Succs |> List.iter (fun w -> cfg.RemoveEdge v w)
    | None -> ()

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

  let analyzeError hdl (scfg: SCFG) (v: Vertex<IRBasicBlock>) =
    let st = EvalState (memoryReader hdl, true)
    let addr = v.VData.PPoint.Address
    let lastAddr = v.VData.LastInstruction.Address
    let st = initRegs hdl |> EvalState.PrepareContext st 0 addr
    try
      eval scfg v st (fun last -> last.Address = lastAddr)
      |> checkFirstArgument hdl
    with _ -> false

  let disconnectErrorFallthroughs hdl scfg app (cfg: IRCFG) =
    cfg.FoldVertex (fun acc (v: Vertex<IRBasicBlock>) ->
      if not <| v.VData.IsFakeBlock () then
        let last = v.VData.LastInstruction
        if last.IsCall () then
          let b, addr = last.DirectBranchTarget ()
          if b then
            match app.CalleeMap.Find addr with
            | Some callee when callee.CalleeName = "error" -> v :: acc
            | _ -> acc
          else acc
        else acc
      else acc) []
    |> List.filter (fun v -> analyzeError hdl scfg v)
    |> List.iter (fun v ->
      v.Succs |> List.iter (fun w -> cfg.RemoveEdge v w))

  let collectNoReturns noretAddrs acc v =
    if (v: Vertex<IRBasicBlock>).VData.IsFakeBlock () then
      let addr = v.VData.PPoint.Address
      if Set.contains addr noretAddrs then Set.add v acc else acc
    else acc

  let collectCallers acc (v: Vertex<IRBasicBlock>) =
    List.fold (fun acc v -> Set.add v acc) acc v.Preds

  let collectEdges noReturns callers acc src dst = function
    | RetEdge ->
      if Set.contains src noReturns then (src, dst) :: acc else acc
    | CallFallThroughEdge ->
      if Set.contains src callers then (src, dst) :: acc else acc
    | _ -> acc

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

  let disconnectNoRetFallThroughs noretAddrs (cfg: IRCFG) root =
    let noReturns = cfg.FoldVertex (collectNoReturns noretAddrs) Set.empty
    let callers = Set.fold collectCallers Set.empty noReturns
    cfg.FoldEdge (collectEdges noReturns callers) []
    |> List.iter (fun (src, dst) -> cfg.RemoveEdge src dst)
    removeUnreachables cfg root

  let modifyCFG hdl (scfg: SCFG) app noretAddrs addr =
    let cfg, root = scfg.GetFunctionCFG (addr, false)
    disconnectSyscallFallthroughs hdl scfg cfg root (* From syscalls *)
    disconnectErrorFallthroughs hdl scfg app cfg (* From error *)
    disconnectNoRetFallThroughs noretAddrs cfg root (* From regular calls *)
    cfg

  let isNoReturn hdl (scfg: SCFG) app noretAddrs (v: Vertex<CallGraphBBlock>) =
    if v.VData.IsExternal then isKnownNoReturnFunction v.VData.Name
    else
      let cfg = modifyCFG hdl scfg app noretAddrs v.VData.PPoint.Address
      cfg.FoldVertex (fun acc (v: Vertex<IRBasicBlock>) ->
        if List.length v.Succs > 0 then acc
        elif v.VData.IsFakeBlock () then acc
        elif v.VData.LastInstruction.IsInterrupt () then acc
        else false) true

  let rec findLoop hdl scfg app noretVertices =
    let lens = CallGraphLens.Init (scfg)
    let cg, _ = lens.Filter scfg.Graph [] app
    let isChanged, noretVertices =
      cg.FoldVertex (fun (isChanged, noretVertices) v ->
        let noretAddrs =
          noretVertices
          |> Set.map (fun (v: Vertex<CallGraphBBlock>) ->
            v.VData.PPoint.Address)
        if isNoReturn hdl scfg app noretAddrs v then
          if Set.contains v.VData.PPoint.Address noretAddrs then
            isChanged, noretVertices
          else true, Set.add v noretVertices
        else isChanged, noretVertices) (false, noretVertices)
    /// Remove edges from call graph
    if isChanged then findLoop hdl scfg app noretVertices
    else noretVertices

  let findNoReturnEdges hdl (scfg: SCFG) app =
    findLoop hdl scfg app Set.empty
    |> Set.fold (fun app (v: Vertex<CallGraphBBlock>) ->
      match app.CalleeMap.Find (v.VData.PPoint.Address) with
      | None -> app
      | Some callee ->
        if not callee.IsNoReturn then
          callee.IsNoReturn <- true
          { app with Modified = true }
        else app) app

type NoReturnAnalysis () =
  interface IPostAnalysis with
    member __.Run hdl scfg app =
      let app' = NoReturnHelper.findNoReturnEdges hdl scfg app
      SCFG (hdl, app'), app'

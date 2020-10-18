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
open B2R2.MiddleEnd.Reclaimer.EmulationHelper

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
    Set.contains entry ess.NoReturnInfo.NoReturnFuncs

  let sideEffectHandler _eff st =
    EvalState.NextStmt st

  let evalBlock ess (v: Vertex<IRBasicBlock>) =
    let hdl = ess.BinHandle
    let st = EvalState (emptyMemoryReader hdl, true)
    let addr = v.VData.PPoint.Address
    let lastAddr = v.VData.LastInstruction.Address
    let st = initRegs hdl |> EvalState.PrepareContext st 0 addr
    st.Callbacks.SideEffectEventHandler <- sideEffectHandler
    eval ess v st (fun last -> last.Address = lastAddr)

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

  let isNoReturnError ess (caller: Vertex<IRBasicBlock>) target =
    let callee = ess.CalleeMap.Get target
    if callee.CalleeName = "error" then
      evalBlock ess caller
      |> checkFirstArgument ess.BinHandle
    else false

  let collectEdgesToFallThrough cfg edges (v: Vertex<IRBasicBlock>) =
    DiGraph.getPreds cfg v
    |> List.fold (fun acc pred ->
      match cfg.FindEdgeData pred v with
      | RetEdge | CallFallThroughEdge ->
        (pred, v) :: acc
      | _ -> acc) edges

  let collectFunctionCallFallThroughs ess cfg (v: Vertex<IRBasicBlock>) edges =
    if ProgramPoint.IsFake v.VData.PPoint then edges
    else
      let entry = v.VData.PPoint.Address
      DiGraph.getPreds cfg v
      |> List.fold (fun edges caller ->
        if isNoReturnError ess caller entry || isKnownNoReturnFunction ess entry
        then
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

  let checkNoReturnCondition (ess: BinEssence) entry =
    let cfg, _ = ess.GetFunctionCFG (entry, false) |> Result.get
    DiGraph.getExits cfg
    |> List.fold (fun acc (v: Vertex<IRBasicBlock>) ->
      if v.VData.IsFakeBlock () then
        if ProgramPoint.IsFake v.VData.PPoint then false
        else
          let target = v.VData.PPoint.Address
          let callee = ess.CalleeMap.Get target
          if Set.contains target ess.NoReturnInfo.NoReturnFuncs then acc
          elif isExternalNoReturnFunction callee.CalleeName then acc
          else false
      elif v.VData.LastInstruction.IsInterrupt () then acc
      else false) true

  let rec analysisLoop ess cg = function
    | [] -> ess
    | (v: Vertex<CallGraphBBlock>) :: vs ->
      if isKnownNoReturnFunction ess v.VData.PPoint.Address then
        analysisLoop ess cg vs
      elif v.VData.IsExternal then
        if isExternalNoReturnFunction v.VData.Name then
          let ess = BinEssence.addNoReturnFunction ess v.VData.PPoint.Address
          DiGraph.getPreds cg v @ vs
          |> analysisLoop ess cg
        else analysisLoop ess cg vs
      else
        let entry = v.VData.PPoint.Address
        let ess = removeFallThroughEdges ess entry
        if checkNoReturnCondition ess entry then
          let ess = BinEssence.addNoReturnFunction ess v.VData.PPoint.Address
          DiGraph.getPreds cg v @ vs
          |> analysisLoop ess cg
        else analysisLoop ess cg vs

  let getTargetFunctions hint cg =
    DiGraph.foldVertex cg (fun acc (v: Vertex<CallGraphBBlock>) ->
      let entry = v.VData.PPoint.Address
      if Set.contains entry hint.NoReturnPerformed then acc else v :: acc) []

  let findNoReturnEdges ess hint =
    let lens = CallGraphLens.Init ()
    let cg, _ = lens.Filter (ess.SCFG, [], ess)
    let ess = getTargetFunctions hint cg |> analysisLoop ess cg
    let hint =
      DiGraph.foldVertex cg (fun hint v ->
        AnalysisHint.markNoReturn v.VData.PPoint.Address hint) hint
    ess, hint

type NoReturnAnalysis () =
  interface IAnalysis with
    member __.Name = "No-Return Analysis"

    member __.Run ess hint =
      NoReturnHelper.findNoReturnEdges ess hint

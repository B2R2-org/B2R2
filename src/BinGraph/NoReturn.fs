(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>

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

namespace B2R2.BinGraph

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd
open B2R2.ConcEval
open B2R2.BinGraph.EmulationHelper

module private NoReturnHelper =

  let isKnownNoReturnFunction = function
    | "__assert_fail"
    | "abort"
    | "_abort"
    | "exit"
    | "_exit" -> true
    | _ -> false

  let sideEffectHandler eff st =
    match eff with
    | SysCall -> EvalState.AbortInstr st
    | _ -> st

  let checkExitForX86 st =
    match readReg st (Intel.Register.EAX |> Intel.Register.toRegID) with
    | None -> false
    | Some v ->
      let syscallNum = BitVector.toInt32 v
      syscallNum = 1 || syscallNum = 252

  let checkExitForX64 st =
    match readReg st (Intel.Register.RAX |> Intel.Register.toRegID) with
    | None -> false
    | Some v ->
      let syscallNum = BitVector.toInt64 v
      syscallNum = 60L || syscallNum = 231L

  let retrieveSyscallState (hdl: BinHandler) = function
    | None -> false
    | Some st ->
      match hdl.ISA.Arch with
      | Arch.IntelX86 -> checkExitForX86 st
      | Arch.IntelX64 -> checkExitForX64 st
      | _ -> false

  let isNoReturn hdl (scfg: SCFG) (v: Vertex<CallGraphBBlock>) =
    if v.Succs.IsEmpty then
      // check syscall
      let addr = v.VData.PPoint.Address
      match scfg.FindFunctionVertex addr with
      | None -> false
      | Some root ->
        let st = EvalState (memoryReader hdl, true)
        let st = initRegs hdl |> EvalState.PrepareContext st 0 addr
        st.Callbacks.SideEffectEventHandler <- sideEffectHandler
        try
          eval scfg root st (fun last -> last.IsInterrupt ())
          |> retrieveSyscallState hdl
        with _ -> false
    else
      isKnownNoReturnFunction v.VData.ID && v.VData.IsExternal

  let rec findLoop hdl scfg (cg: CallCFG) vmap =
    (* XXX: currently just perform a single scan. *)
    cg.FoldVertex (fun vmap v ->
      Map.add v (isNoReturn hdl scfg v) vmap
    ) vmap

  let findNoReturnEdges hdl (scfg: SCFG) app =
    let lens = CallGraphLens.Init (scfg)
    let cg, _ = lens.Filter scfg.Graph [] app
    let vmap = cg.FoldVertex (fun map v -> Map.add v false map) Map.empty
    let vmap = findLoop hdl scfg cg vmap
    Map.filter (fun _ v -> v) vmap
    |> Map.fold (fun app v _ ->
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
      NoReturnHelper.findNoReturnEdges hdl scfg app

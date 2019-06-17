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

module B2R2.BinGraph.NoReturn

open B2R2
open B2R2.BinFile
open B2R2.FrontEnd
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.ConcEval

let isExecutable (hdl: BinHandler) addr =
  match hdl.FileInfo.GetSections addr |> Seq.tryHead with
  | Some s -> s.Kind = SectionKind.ExecutableSection
  | _ -> false

let removeSelfCycle (fcg: CallGraph) =
  fcg.IterEdge (fun src dst ->
    if src = dst then fcg.RemoveEdge src dst)

let removeBackEdge (fcg: CallGraph) order src dst =
  if Map.find src order > Map.find dst order then
    fcg.RemoveEdge src dst

let removeBackEdges (fcg: CallGraph) =
  let dfsOrder = Algorithms.dfsTopologicalSort fcg
  fcg.IterEdge (removeBackEdge fcg dfsOrder)

let noReturnFuncs =
  [ "__assert_fail" ; "abort" ; "_abort" ; "exit" ; "_exit" ]

let isNoReturnCall hdl (fcg: CallGraph) target =
  if not <| isExecutable hdl target then
    let found, name = hdl.FileInfo.TryFindFunctionSymbolName target
    if found then List.contains name noReturnFuncs
    else false
  else
    let funcV =
      fcg.FindVertexBy (fun (v: Vertex<Function>) -> v.VData.Entry = target)
    funcV.VData.NoReturn

let findDisasmVertex addr (v: DisasmVertex) =
  let addrRange = v.VData.AddrRange
  addrRange.Min <= addr && addr < addrRange.Max

let removeVertex (disasmCFG: DisasmCFG) (irCFG: IRCFG) (v: IRVertex) =
  let b, ppoint = v.VData.GetPpoint ()
  if b then
    match disasmCFG.TryFindVertexBy (findDisasmVertex <| fst ppoint) with
    | Some w ->
      disasmCFG.RemoveVertex w
      irCFG.RemoveVertex v
    | None -> irCFG.RemoveVertex v
  else irCFG.RemoveVertex v

let rec getReachables reachSet = function
  | [] -> reachSet
  | hd :: tl when Set.contains hd reachSet -> getReachables reachSet tl
  | (hd: IRVertex) :: tl ->
    let reachSet = Set.add hd reachSet
    getReachables reachSet (hd.Succs @ tl)

let disconnectCall hdl (fcg: CallGraph) disasmCFG (irCFG: IRCFG) (v: IRVertex) =
  match irCFG.TryFindVertexByData v.VData with
  | Some _ ->
    let b, target = v.VData.GetTarget ()
    if b then
      if isNoReturnCall hdl fcg target then
        List.iter (fun w -> irCFG.RemoveEdge v w) v.Succs
        let reachSet = getReachables Set.empty [irCFG.GetRoot ()]
        irCFG.IterVertex (fun v ->
          if not <| Set.contains v reachSet then removeVertex disasmCFG irCFG v)
  | None -> ()

let getStackPtrRegID = function
  | Arch.IntelX86 -> Intel.Register.ESP |> Intel.Register.toRegID
  | Arch.IntelX64 -> Intel.Register.RSP |> Intel.Register.toRegID
  | _ -> failwith "Not supported arch."

let stackAddr t = Def (BitVector.ofInt32 0x1000000 t)

let dummyLoader _ _ = None

let initState hdl =
  let isa = hdl.ISA
  let st = EvalState (dummyLoader, true)
  let sp = getStackPtrRegID isa.Arch
  match isa.Arch with
  | Arch.IntelX86 -> EvalState.PrepareContext st 0 0UL [(sp, stackAddr 32<rt>)]
  | Arch.IntelX64 -> EvalState.PrepareContext st 0 0UL [(sp, stackAddr 64<rt>)]
  | _ -> failwith "Not supported arch."

let isIntel32NoReturnSysCall state =
  match EvalState.GetReg state (Intel.Register.toRegID Intel.Register.EAX) with
  | Def v -> BitVector.toUInt64 v = 1UL
  | _ -> false

let isIntel64NoReturnSysCall state =
  match EvalState.GetReg state (Intel.Register.toRegID Intel.Register.RAX) with
  | Def v -> BitVector.toUInt64 v = 60UL
  | _ -> false

let isNoReturnSysCall hdl (vData: IRVertexData) = function
  | SideEffect SysCall ->
    let b1, _ = vData.GetPpoint ()
    let b2, stmts = vData.GetStmts ()
    if b1 && b2 then
      let state = initState hdl
      let state = List.toArray stmts |> Evaluator.evalBlock state 0
      match hdl.ISA.Arch with
      | Arch.IntelX86 -> isIntel32NoReturnSysCall state
      | Arch.IntelX64 -> isIntel64NoReturnSysCall state
      | _ -> failwith "Not supported arch."
    else false
  | _ -> false

let disconnectSysCall hdl disasmCFG (irCFG: IRCFG) (v: IRVertex) =
  let vData = v.VData
  let b, stmt = vData.GetLastStmt ()
  if b then
    if isNoReturnSysCall hdl vData stmt then
      List.iter (fun w -> irCFG.RemoveEdge v w) v.Succs
      let reachSet = getReachables Set.empty [irCFG.GetRoot ()]
      irCFG.IterVertex (fun v ->
        if not <| Set.contains v reachSet then removeVertex disasmCFG irCFG v)
    else ()

let disconnect hdl fcg (v: Vertex<Function>) =
  let irCFG = v.VData.IRCFG
  let disasmCFG = v.VData.DisasmCFG
  irCFG.IterVertex (disconnectCall hdl fcg disasmCFG irCFG)
  irCFG.IterVertex (disconnectSysCall hdl disasmCFG irCFG)

let updateNoReturn (func: Function) =
  let irCFG = func.IRCFG
  let isNoReturn =
    List.forall (fun (v: IRVertex) ->
      let vData = v.VData
      let b, stmt = vData.GetLastStmt ()
      if b then
        match stmt with
        | InterJmp (_, _, InterJmpInfo.IsRet) -> false
        | InterJmp (_, _, InterJmpInfo.IsCall) -> false
        | _ -> true
      else true) irCFG.Exits
  if isNoReturn then func.NoReturn <- isNoReturn

let rec analNoReturn hdl fcg visited queue = function
  | [] -> () // XXX: Temporary patch. below expression causes infinite loop
    //if List.length queue <> 0 then analNoReturn hdl fcg visited [] queue
  | (v: Vertex<_>) :: vs ->
    if not <| Set.contains v visited then
      if List.forall (fun w -> Set.contains w visited) v.Succs then
        let visited = Set.add v visited
        disconnect hdl fcg v
        updateNoReturn v.VData
        let vs =
          List.fold (fun vs w ->
            if not <| Set.contains w visited then w :: vs else vs) vs v.Preds
        analNoReturn hdl fcg visited queue vs
      else
        let queue = if not <| Set.contains v visited then v :: queue else queue
        analNoReturn hdl fcg visited queue vs
    else analNoReturn hdl fcg visited queue vs

let noReturnAnalysis hdl (fcg: CallGraph) =
  if fcg.Size () <> 0 then
    let g = fcg.Clone ()
    removeSelfCycle g
    removeBackEdges g
    analNoReturn hdl g Set.empty [] g.Exits

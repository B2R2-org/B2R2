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
open B2R2.BinIR.LowUIR.Eval

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

let rec removeVertices domTree disasmCFG (irCFG: IRCFG) v =
  // TODO: Remove corresponding vertices from disasmCFG
  List.iter (removeVertices domTree disasmCFG irCFG) <| Map.find v domTree
  irCFG.RemoveVertex v

let disconnectCall hdl (fcg: CallGraph) disasmCFG (irCFG: IRCFG) (v: IRVertex) =
  let vData = v.VData
  let b, target = vData.GetTarget ()
  if b then
    if isNoReturnCall hdl fcg target then
      let ctxt = Dominator.initDominatorContext irCFG
      let tree, _ = Dominator.dominatorTree ctxt
      List.iter (removeVertices tree disasmCFG irCFG) <| Map.find v tree

let getStackPtrRegID = function
  | Arch.IntelX86 -> Intel.Register.ESP |> Intel.Register.toRegID
  | Arch.IntelX64 -> Intel.Register.RSP |> Intel.Register.toRegID
  | _ -> failwith "Not supported arch."

let stackAddr t = Def (BitVector.ofInt32 0x1000000 t)

let initState hdl startAddr =
  let isa = hdl.ISA
  let sp = getStackPtrRegID isa.Arch
  let vars =
    match isa.Arch with
    | Arch.IntelX86 -> Map.add sp (stackAddr 32<rt>) Map.empty
    | Arch.IntelX64 -> Map.add sp (stackAddr 64<rt>) Map.empty
    | _ -> failwith "Not supported arch."
  { PC = startAddr
    BlockEnd = false
    Vars = vars
    TmpVars = Map.empty
    Mems = Map.empty
    NextStmtIdx = 0
    LblMap = Map.empty }

let evalStmts hdl state stmts =
  Array.fold (fun state stmt ->
    try evalStmt state emptyCallBack stmt with
    | UnknownVarException (* Simply ignore exceptions *)
    | InvalidMemException -> state
  ) state stmts

let isIntel32NoReturnSysCall hdl state =
  match Map.tryFind (Intel.Register.toRegID Intel.Register.EAX) state.Vars with
  | Some (Def v) -> BitVector.toUInt64 v = 1UL
  | _ -> false

let isIntel64NoReturnSysCall hdl state =
  match Map.tryFind (Intel.Register.toRegID Intel.Register.RAX) state.Vars with
  | Some (Def v) -> BitVector.toUInt64 v = 60UL
  | _ -> false

let isNoReturnSysCall hdl (vData: IRVertexData) = function
  | SideEffect SysCall ->
    let b1, ppoint = vData.GetPpoint ()
    let b2, stmts = vData.GetStmts ()
    if b1 && b2 then
      let state = initState hdl <| fst ppoint
      let state = evalStmts hdl state <| List.toArray stmts
      match hdl.ISA.Arch with
      | Arch.IntelX86 -> isIntel32NoReturnSysCall hdl state
      | Arch.IntelX64 -> isIntel64NoReturnSysCall hdl state
      | _ -> failwith "Not supported arch."
    else false
  | stmt -> false

let disconnectSysCall hdl fcg disasmCFG irCFG (v: IRVertex) =
  let vData = v.VData
  let b, stmt = vData.GetLastStmt ()
  if b then
    if isNoReturnSysCall hdl vData stmt then
      let ctxt = Dominator.initDominatorContext irCFG
      let tree, _ = Dominator.dominatorTree ctxt
      List.iter (removeVertices tree disasmCFG irCFG) <| Map.find v tree

let disconnect hdl fcg (v: Vertex<Function>) =
  let entry = v.VData.Entry
  let irCFG = v.VData.IRCFG
  let disasmCFG = v.VData.DisasmCFG
  irCFG.IterVertex (disconnectCall hdl fcg disasmCFG irCFG)
  irCFG.IterVertex (disconnectSysCall hdl fcg disasmCFG irCFG)

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
  | [] ->
    if List.length queue <> 0 then analNoReturn hdl fcg visited [] queue
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
  let g = fcg.Clone ()
  removeSelfCycle g
  removeBackEdges g
  analNoReturn hdl g Set.empty [] g.Exits

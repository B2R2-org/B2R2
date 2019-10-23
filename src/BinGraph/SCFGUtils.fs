(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

[<RequireQualifiedAccess>]
module B2R2.BinGraph.SCFGUtils

open B2R2
open B2R2.BinIR.LowUIR
open System.Collections.Generic

type VMap = Dictionary<ProgramPoint, Vertex<IRBasicBlock>>

let hasNoFallThrough (stmts: Stmt []) =
  if stmts.Length > 0 then
    match stmts.[stmts.Length - 1] with
    | InterJmp (_, _, InterJmpInfo.IsCall) -> false
    | InterJmp (_, _, _)
    | SideEffect (BinIR.Halt) -> true
    | _ -> false
  else false

let private selectInfo app (myPoint: ProgramPoint) (nextLeader: ProgramPoint) =
  match app.InstrMap.TryGetValue (myPoint.Address) with
  | false, _ -> None, nextLeader
  | true, i ->
    if myPoint.Address <> nextLeader.Address then
      let nextInsAddr = i.Instruction.Address + uint64 i.Instruction.Length
      let nextPoint =
        if i.Stmts.Length > 0 && hasNoFallThrough i.Stmts then nextLeader
        else ProgramPoint (nextInsAddr, 0)
      if myPoint.Position > 0 then
        let delta = i.Stmts.Length - myPoint.Position
        let i' = { i with Stmts = Array.sub i.Stmts myPoint.Position delta }
        Some i', nextPoint
      else Some i, nextPoint
    else
      let delta = nextLeader.Position - myPoint.Position
      let i' = { i with Stmts = Array.sub i.Stmts myPoint.Position delta }
      Some i', nextLeader

let rec private gatherBB acc app (leaders: ProgramPoint []) myPoint nextIdx =
  if nextIdx >= leaders.Length then
    match app.InstrMap.TryGetValue ((myPoint: ProgramPoint).Address) with
    | false, _ -> List.rev acc |> List.toArray
    | true, i ->
      let nextInsAddr = i.Instruction.Address + uint64 i.Instruction.Length
      let nextPoint = ProgramPoint (nextInsAddr, 0)
      gatherBB (i :: acc) app leaders nextPoint nextIdx
  else
    let nextLeader = leaders.[nextIdx]
    if nextLeader > myPoint then
      match selectInfo app myPoint nextLeader with
      | None, _ -> [||]
      | Some info, nextPoint ->
        let acc = info :: acc
        if hasNoFallThrough info.Stmts then List.rev acc |> List.toArray
        else gatherBB acc app leaders nextPoint nextIdx
    elif nextLeader = myPoint then List.rev acc |> List.toArray
    (* Next point is beyond the next leader's point. This is possible when two
       control flows divide an instruction into two parts. This typically
       happens in obfuscated code. *)
    else gatherBB acc app leaders myPoint (nextIdx + 1)

let createNode (g: IRCFG) app (vmap: VMap) (leaders: ProgramPoint []) idx =
  let leader = leaders.[idx]
  let instrs = gatherBB [] app leaders leader (idx + 1)
  if instrs.Length = 0 then ()
  else
    let b = IRBasicBlock (instrs, leader)
    let v = g.AddVertex b
    vmap.[leader] <- v

let private addIntraEdge (g: IRCFG) app (vmap: VMap) src symbol edgeProp =
  let dstPos = Map.find symbol app.LabelMap |> ProgramPoint
  let dst =
    try vmap.[dstPos]
    (* This is a fatal error, and can only occur when the label is followed by
       IEMark. If that's the case, we should really fix our IR translation to
       have an explicit jump to the fall-through instruction. *)
    with _ -> failwithf "Failed to fetch block @ %s." (dstPos.ToString ())
  g.AddEdge src dst edgeProp

let private addInterEdge (g: IRCFG) (vmap: VMap) src addr edgeProp =
  let dstPos = ProgramPoint (addr, 0)
  match vmap.TryGetValue dstPos with
  | false, _ -> ()
  | true, dst -> g.AddEdge src dst edgeProp

let private addFallthroughEdge g vmap (src: Vertex<IRBasicBlock>) =
  let last = src.VData.LastInstruction
  let fallAddr = last.Address + uint64 last.Length
  addInterEdge g vmap src fallAddr FallThroughEdge

let private handleFallThrough (g: IRCFG) vmap src (nextLeader: ProgramPoint) =
  if nextLeader.Position = 0 then addFallthroughEdge g vmap src
  else g.AddEdge src vmap.[nextLeader] IntraJmpEdge

let private getIndirectDstNode (g: IRCFG) (vmap: VMap) callee =
  match callee.Addr with
  | None ->
    let fakePos = ProgramPoint.GetFake ()
    match vmap.TryGetValue fakePos with
    | false, _ ->
      let v = g.AddVertex (IRBasicBlock ([||], fakePos))
      vmap.[fakePos] <- v
      Some v
    | true, v -> Some v
  | Some addr ->
    match vmap.TryGetValue (ProgramPoint (addr, 0)) with
    | false, _ -> None
    | true, v -> Some v

let private addIndirectEdges (g: IRCFG) app vmap (src: Vertex<IRBasicBlock>) =
  let add callee =
    match getIndirectDstNode g vmap callee with
    | None -> ()
    | Some dst ->
      if ProgramPoint.IsFake dst.VData.PPoint then
        g.AddEdge src dst ExternalEdge
      else
        g.AddEdge src dst IndirectEdge
  let callerAddr = src.VData.PPoint.Address
  match app.CallerMap.TryGetValue callerAddr  with
  | false, _ -> ()
  | true, callees -> callees |> Set.iter add

let connectEdges _ (g: IRCFG) app (vmap: VMap) (leaders: ProgramPoint[]) idx =
  let leader = leaders.[idx]
  match vmap.TryGetValue leader with
  | false, _ -> ()
  | true, src ->
    match src.VData.GetLastStmt () with
    | Jmp (Name s) ->
      addIntraEdge g app vmap src s IntraJmpEdge
    | CJmp (_, Name s1, Name s2) ->
      addIntraEdge g app vmap src s1 IntraCJmpTrueEdge
      addIntraEdge g app vmap src s2 IntraCJmpFalseEdge
    | InterJmp (_, _, InterJmpInfo.IsRet) -> () (* Connect ret edges later. *)
    | InterJmp (_, Num addr, InterJmpInfo.IsCall) ->
      let target = BitVector.toUInt64 addr
      addInterEdge g vmap src target CallEdge
      if idx + 1 >= leaders.Length then () else addFallthroughEdge g vmap src
    | InterJmp (_, Num addr, _) ->
      addInterEdge g vmap src (BitVector.toUInt64 addr) InterJmpEdge
    | InterCJmp (_, _, Num addr1, Num addr2) ->
      addInterEdge g vmap src (BitVector.toUInt64 addr1) InterCJmpTrueEdge
      addInterEdge g vmap src (BitVector.toUInt64 addr2) InterCJmpFalseEdge
    | InterCJmp (_, _, Num addr, _) ->
      addInterEdge g vmap src (BitVector.toUInt64 addr) InterCJmpTrueEdge
    | InterCJmp (_, _, _, Num addr) ->
      addInterEdge g vmap src (BitVector.toUInt64 addr) InterCJmpFalseEdge
    | InterJmp (_, _, InterJmpInfo.IsCall) -> (* Indirect call *)
      if idx + 1 >= leaders.Length then () else addFallthroughEdge g vmap src
      addIndirectEdges g app vmap src
    | InterJmp (_)
    | InterCJmp (_) ->
      addIndirectEdges g app vmap src
    | SideEffect (BinIR.Halt) -> ()
    | _ -> (* Fall through case *)
      if idx + 1 >= leaders.Length then ()
      else handleFallThrough g vmap src leaders.[idx + 1]

let computeBoundaries app (vmap: VMap) =
  app.LeaderInfos
  |> Set.fold (fun set leader ->
    match vmap.TryGetValue leader.Point with
    | false, _ -> set
    | true, v -> IntervalSet.add v.VData.Range set) IntervalSet.empty

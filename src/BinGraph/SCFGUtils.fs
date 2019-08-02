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
    | InterJmp (_, _, InterJmpInfo.IsRet)
    | InterJmp (_, _, InterJmpInfo.Base)
    | InterJmp (_, _, InterJmpInfo.IsExit)
    | SideEffect (BinIR.Halt) -> true
    | _ -> false
  else false

let private selectPair app (myPoint: ProgramPoint) (nextLeader: ProgramPoint) =
  match app.InstrMap.TryGetValue (myPoint.Address) with
  | false, _ -> None, nextLeader
  | true, ((ins, stmts) as pair) ->
    if myPoint.Address <> nextLeader.Address then
      let nextInsAddr = ins.Address + uint64 ins.Length
      let nextPoint =
        if stmts.Length > 0 && hasNoFallThrough stmts then nextLeader
        else ProgramPoint (nextInsAddr, 0)
      if myPoint.Position > 0 then
        let delta = stmts.Length - myPoint.Position
        Some (ins, Array.sub stmts myPoint.Position delta), nextPoint
      else Some pair, nextPoint
    else
      let delta = nextLeader.Position - myPoint.Position
      Some (ins, Array.sub stmts myPoint.Position delta), nextLeader

let rec private gatherBBlock acc app (leaders: ProgramPoint []) myPoint nextIdx =
  if nextIdx >= leaders.Length then
    match app.InstrMap.TryGetValue ((myPoint: ProgramPoint).Address) with
    | false, _ -> List.rev acc |> List.toArray
    | true, ((ins, _) as pair) ->
      let nextInsAddr = ins.Address + uint64 ins.Length
      let nextPoint = ProgramPoint (nextInsAddr, 0)
      gatherBBlock (pair :: acc) app leaders nextPoint nextIdx
  else
    let nextLeader = leaders.[nextIdx]
    if nextLeader > myPoint then
      match selectPair app myPoint nextLeader with
      | None, _ -> [||]
      | Some pair, nextPoint ->
        gatherBBlock (pair :: acc) app leaders nextPoint nextIdx
    elif nextLeader = myPoint then List.rev acc |> List.toArray
    (* Next point is beyond the next leader's point. This is possible when two
       control flows divide an instruction into two parts. This typically
       happens on obfuscated code. *)
    else gatherBBlock acc app leaders myPoint (nextIdx + 1)

let createNode (g: IRCFG) app (vmap: VMap) (leaders: ProgramPoint []) idx =
  let leader = leaders.[idx]
  let pairs = gatherBBlock [] app leaders leader (idx + 1)
  if pairs.Length = 0 then ()
  else
    let b = IRBasicBlock (pairs, leader)
    let v = g.AddVertex b
    vmap.[leader] <- v

let private addIntraEdge (g: IRCFG) app (vmap: VMap) src symbol edgeProp =
  let dstPos = Map.find symbol app.LabelMap |> ProgramPoint
  let dst = vmap.[dstPos]
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
      // TODO: add PLT check
      addInterEdge g vmap src target CallEdge
      if idx + 1 >= leaders.Length then () else addFallthroughEdge g vmap src
    | InterJmp (_, Num addr, _) ->
      addInterEdge g vmap src (BitVector.toUInt64 addr) InterJmpEdge
    | InterCJmp (_, _, Num addr1, Num addr2) ->
      addInterEdge g vmap src (BitVector.toUInt64 addr1) InterCJmpTrueEdge
      addInterEdge g vmap src (BitVector.toUInt64 addr2) InterCJmpFalseEdge
    | InterJmp (_, _, InterJmpInfo.IsCall) -> (* Indirect call *)
      if idx + 1 >= leaders.Length then () else addFallthroughEdge g vmap src
    | InterJmp (_)
    | InterCJmp (_)
    | SideEffect (BinIR.Halt) -> ()
    | _ -> (* Fall through case *)
      if idx + 1 >= leaders.Length then ()
      else addFallthroughEdge g vmap src

let computeBoundaries app (vmap: VMap) =
  app.LeaderPositions
  |> Set.fold (fun set leader ->
    match vmap.TryGetValue leader with
    | false, _ -> set
    | true, v -> IntervalSet.add v.VData.Range set) IntervalSet.empty

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
module B2R2.BinGraph.CFGUtils

open B2R2
open B2R2.BinIR.LowUIR
open System.Collections.Generic

type CFG = ControlFlowGraph<IRBasicBlock, CFGEdgeKind>
type VMap = Dictionary<ProgramPoint, Vertex<IRBasicBlock>>

let rec private gatherBBlock acc app (leaders: ProgramPoint []) addr nextidx =
  match app.InstrMap.TryGetValue (addr) with
  | false, _ -> List.rev acc |> List.toArray
  | true, ((ins, stmts) as pair) ->
    let nextInsAddr = ins.Address + uint64 ins.Length
    if nextidx >= leaders.Length then
      gatherBBlock (pair :: acc) app leaders nextInsAddr nextidx
    else
      let nextLeader = leaders.[nextidx]
      let nextLeaderIns, _ = app.InstrMap.[nextLeader.Address]
      if ins.Address = nextLeader.Address then (* Intra jump cases *)
        let currLeader = leaders.[nextidx - 1]
        let delta = nextLeader.Position - currLeader.Position
        List.rev ((ins, Array.sub stmts currLeader.Position delta) :: acc)
        |> List.toArray
      elif nextInsAddr = nextLeaderIns.Address then
        let currPos = leaders.[nextidx - 1].Position
        if currPos > 0 then
          let count = stmts.Length - currPos
          List.rev ((ins, Array.sub stmts currPos count) :: acc) |> List.toArray
        else
          List.rev (pair :: acc) |> List.toArray
      (* Next instruction is beyond the next leader's address. This is possible
         when two control flows divide an instruction into two parts. This
         typically happens on obfuscated code. *)
      elif nextInsAddr > nextLeaderIns.Address then
        gatherBBlock (pair :: acc) app leaders nextInsAddr (nextidx + 1)
      else
        gatherBBlock (pair :: acc) app leaders nextInsAddr nextidx

let createNode (g: CFG) app (vertices: VMap) (leaders: ProgramPoint []) idx =
  let leader = leaders.[idx]
  let leaderAddr = leader.Address
  let pairs = gatherBBlock [] app leaders leaderAddr (idx + 1)
  let b = IRBasicBlock (pairs, leader)
  let v = g.AddVertex b
  vertices.[leader] <- v

let private addIntraEdge (g: CFG) app (vertices: VMap) src symbol edgeProp =
  let dstPos = Map.find symbol app.LabelMap |> ProgramPoint
  let dst = vertices.[dstPos]
  g.AddEdge src dst edgeProp

let private addInterEdge (g: CFG) (vertices: VMap) src addr edgeProp =
  let dstPos = ProgramPoint (addr, 0)
  let dst = vertices.[dstPos]
  g.AddEdge src dst edgeProp

let private addFallthroughEdge g vertices (src: Vertex<IRBasicBlock>) =
  let last = src.VData.LastInstruction
  let fallAddr = last.Address + uint64 last.Length
  addInterEdge g vertices src fallAddr FallThroughEdge

let connectEdges _ (g: CFG) app (vertices: VMap) (leaders: ProgramPoint[]) idx =
  let leader = leaders.[idx]
  let src = vertices.[leader]
  match src.VData.GetLastStmt () with
  | Jmp (Name s) ->
    addIntraEdge g app vertices src s IntraJmpEdge
  | CJmp (_, Name s1, Name s2) ->
    addIntraEdge g app vertices src s1 IntraCJmpTrueEdge
    addIntraEdge g app vertices src s2 IntraCJmpFalseEdge
  | InterJmp (_, _, InterJmpInfo.IsRet) -> () (* We connect ret edges later. *)
  | InterJmp (_, Num addr, InterJmpInfo.IsCall) ->
    let target = BitVector.toUInt64 addr
    // TODO: add PLT check
    addInterEdge g vertices src target CallEdge
    if idx + 1 >= leaders.Length then ()
    else addFallthroughEdge g vertices src
  | InterJmp (_, Num addr, _) ->
    addInterEdge g vertices src (BitVector.toUInt64 addr) InterJmpEdge
  | InterCJmp (_, _, Num addr1, Num addr2) ->
    addInterEdge g vertices src (BitVector.toUInt64 addr1) InterCJmpTrueEdge
    addInterEdge g vertices src (BitVector.toUInt64 addr2) InterCJmpFalseEdge
  | _ -> (* Fall through case *)
    if idx + 1 >= leaders.Length then ()
    else addFallthroughEdge g vertices src

let callTargets (g: CFG) =
  g.FoldEdge (fun acc _ dst e ->
    match e with
    | CallEdge -> dst.VData.Position.Address :: acc
    | _ -> acc) []

let computeBoundaries app (vertices: VMap) =
  app.LeaderPositions
  |> Set.fold (fun set leader ->
    let v = vertices.[leader]
    IntervalSet.add v.VData.Range set) IntervalSet.empty

let postAnalysis (g: CFG) app analyzers =
  // _libc_start_main
  // no_return
  // switch-case
  // implicit call edges
  app

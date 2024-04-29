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

namespace B2R2.MiddleEnd.ControlFlowGraph

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// Disassembly-based CFG, where each node contains disassembly code.
type DisasmCFG<'E when 'E: equality> = IGraph<DisasmBasicBlock, 'E>

[<RequireQualifiedAccess>]
module DisasmCFG =
  /// Constructor for DisasmCFG.
  type IConstructable<'E when 'E: equality> =
    /// Construct a DisasmCFG.
    abstract Construct: ImplementationType -> DisasmCFG<'E>

  /// Temporarily stores vertex information for creating DisasmCFG.
  type private TemporaryDisasmVertex<'E> = {
    Instructions: SortedList<Addr, Instruction>
    Successors: List<Addr * 'E>
    mutable Vertex: IVertex<DisasmBasicBlock>
  }

  type private DisasmVMap<'E> = Dictionary<Addr, TemporaryDisasmVertex<'E>>

  let private getTempVertex (vMap: DisasmVMap<_>) addr =
    match vMap.TryGetValue addr with
    | true, tmpV -> tmpV
    | false, _ ->
      let tmpV =
        { Instructions = SortedList ()
          Successors = List ()
          Vertex = null }
      vMap[addr] <- tmpV
      tmpV

  let private updateDisasmVertexInfo vMap (bbl: #IRBasicBlock<_>) =
    if bbl.IsAbstract then ()
    else
      let tmpV = getTempVertex vMap bbl.LiftedInstructions[0].BBLAddr
      let insList = tmpV.Instructions
      bbl.LiftedInstructions
      |> Array.iter (fun lifted ->
        let ins = lifted.Original
        if insList.ContainsKey ins.Address then ()
        else insList.Add (ins.Address, ins))

  let private updateSuccessor (succs: List<Addr * _>) = function
    | Some (succAddr, edge) -> succs.Add (succAddr, edge)
    | None -> ()

  let private updateDisasmEdgeInfo (vMap: DisasmVMap<_>) addr succ =
    let tmpV = vMap[addr]
    updateSuccessor tmpV.Successors succ

  let private accumulateDisasmCFGInfo (g: IRCFG<_, _, _>) vMap =
    g.IterVertex (fun v -> updateDisasmVertexInfo vMap v.VData)
    g.IterEdge (fun e ->
      let src, dst = e.First.VData, e.Second.VData
      if src.IsAbstract || dst.IsAbstract then ()
      else
        let srcAddr = src.LiftedInstructions[0].BBLAddr
        let dstAddr = dst.LiftedInstructions[0].BBLAddr
        let succ = if srcAddr = dstAddr then None else Some (dstAddr, e.Label)
        updateDisasmEdgeInfo vMap srcAddr succ)

  let private createDisasmCFGVertices (vMap: DisasmVMap<_>) newGraph =
    vMap |> Seq.fold (fun (g: DisasmCFG<_>) (KeyValue (addr, tmpV)) ->
      let ppoint = ProgramPoint (addr, 0)
      let instrs = tmpV.Instructions.Values |> Seq.toArray
      let bbl = DisasmBasicBlock (ppoint, instrs)
      let v, g = g.AddVertex bbl
      tmpV.Vertex <- v
      g) newGraph

  let private createDisasmCFGEdges (vMap: DisasmVMap<_>) newGraph =
    vMap.Values |> Seq.fold (fun (g: DisasmCFG<_>) tmpV ->
      let src = tmpV.Vertex
      tmpV.Successors |> Seq.fold (fun g (succ, label) ->
        let dst = vMap[succ].Vertex
        g.AddEdge (src, dst, label)
      ) g
    ) newGraph

  let private findVertexByAddr (g: DisasmCFG<_>) addr =
    g.FindVertexBy (fun v -> v.VData.PPoint.Address = addr)

  let private selectCallingVertices oldGraph newGraph =
    (oldGraph: IRCFG<_, _, _>).Edges
    |> Array.choose (fun edge ->
      let src = edge.First
      let dst = edge.Second
      if not dst.VData.IsAbstract then None
      else
        let succs = oldGraph.GetSuccs dst
        if Seq.isEmpty succs then None
        else
          assert (Seq.length succs = 1)
          let succ = Seq.head succs
          assert (not succ.VData.IsAbstract)
          let srcAddr = src.VData.PPoint.Address
          let succAddr = succ.VData.PPoint.Address
          Some (srcAddr, succAddr))
    |> Array.sortBy (fun (addr, _) -> addr)
    |> Array.map (fun (addr, ftAddr) ->
      findVertexByAddr newGraph addr, findVertexByAddr newGraph ftAddr)
    |> Array.toList

  let rec private mergeDisasmCFGCallVertices oldGraph newGraph =
    selectCallingVertices oldGraph newGraph
    |> mergeDisasmCFGCallVerticesAux newGraph null null

  and mergeDisasmCFGCallVerticesAux g prevVertex prevSucc = function
    | [] -> g
    | (v, succ) :: tl ->
      let merged, g =
        if prevSucc = v then mergeVertices g prevVertex succ
        else mergeVertices g v succ
      mergeDisasmCFGCallVerticesAux g merged succ tl

  and private mergeVertices g v1 v2 =
    let instrs1 = v1.VData.Instructions
    let instrs2 = v2.VData.Instructions
    let instrs = Array.concat [ instrs1; instrs2 ]
    let blk = DisasmBasicBlock (v1.VData.PPoint, instrs)
    let preds = g.GetPredEdges v1
    let succs = g.GetSuccEdges v2
    let g = g.RemoveVertex v1
    let g = g.RemoveVertex v2
    let v, g = g.AddVertex blk
    let g =
      preds
      |> Seq.fold (fun (g: DisasmCFG<_>) edge ->
        g.AddEdge (edge.First, v, edge.Label)) g
    let g =
      succs
      |> Seq.fold (fun (g: DisasmCFG<_>) edge ->
        g.AddEdge (v, edge.Second, edge.Label)) g
    v, g

  /// Create a new DisasmCFG from the given IRCFG.
  [<CompiledName "Create">]
  let create (g: IRCFG<'V, 'E, 'Abs>) =
    let newGraph =
      match g.ImplementationType with
      | Imperative ->
        ImperativeDiGraph<DisasmBasicBlock, 'E> () :> DisasmCFG<'E>
      | Persistent ->
        PersistentDiGraph<DisasmBasicBlock, 'E> () :> DisasmCFG<'E>
    let vMap = DisasmVMap ()
    accumulateDisasmCFGInfo g vMap
    newGraph
    |> createDisasmCFGVertices vMap
    |> createDisasmCFGEdges vMap
    |> mergeDisasmCFGCallVertices g

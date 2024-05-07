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

  let private updateDisasmVertexInfo vMap (bbl: #IRBasicBlock) =
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

  let private appendInstructionsInto srcInss (dstInss: SortedList<_, _>) =
    srcInss |> Seq.iter (fun (KeyValue (addr, ins)) -> dstInss.Add (addr, ins))

  let private updateDisasmCallerVertexInfo g vMap srcAddr edges =
    let e = Seq.exactlyOne edges
    let absV = (e: Edge<_, _>).Second
    match (g: IRCFG<_, _>).GetSuccs absV |> Seq.tryHead with
    | Some ftV when (g.GetPreds ftV).Count > 1 ->
      Some (ftV.VData.PPoint.Address, e.Label)
      |> updateDisasmEdgeInfo vMap srcAddr
    | Some ftV ->
      let ftAddr = ftV.VData.PPoint.Address
      let inss1 = vMap[srcAddr].Instructions
      let inss2 = vMap[ftAddr].Instructions
      let ftSuccs = vMap[ftAddr].Successors
      appendInstructionsInto inss2 inss1
      vMap.Remove ftAddr |> ignore
      for succ in ftSuccs do updateDisasmEdgeInfo vMap srcAddr <| Some succ
    | _ -> ()

  let private updateDisasmNormalVertexInfo vMap srcAddr edges =
    edges |> Seq.iter (fun (e: Edge<_, _>) ->
      let dstAddr = (e.Second.VData: IRBasicBlock).PPoint.Address
      let succ = if srcAddr = dstAddr then None else Some (dstAddr, e.Label)
      updateDisasmEdgeInfo vMap srcAddr succ)

  let rec private accumulateDisasmCFGInfo (g: IRCFG<_, _>) vMap =
    let sortedVertices =
      g.Vertices
      |> Array.sortByDescending (fun v -> v.VData.PPoint.Address)
    for v in sortedVertices do
      if v.VData.IsAbstract then ()
      else
        let vData = v.VData
        let edges = g.GetSuccEdges v
        let srcAddr = vData.PPoint.Address
        let hasAbs = edges |> Seq.exists (fun e -> e.Second.VData.IsAbstract)
        updateDisasmVertexInfo vMap vData
        if hasAbs then updateDisasmCallerVertexInfo g vMap srcAddr edges
        else updateDisasmNormalVertexInfo vMap srcAddr edges

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

  /// Create a new DisasmCFG from the given IRCFG.
  [<CompiledName "Create">]
  let create (g: IRCFG<'V, 'E>) =
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

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

  type private DisasmBBLStorage<'E> = {
    Instructions: SortedList<Addr, Instruction>
    Successors: List<Addr * 'E>
    mutable Vertex: IVertex<DisasmBasicBlock>
  }

  type private DisasmVMap<'E> = Dictionary<Addr, DisasmBBLStorage<'E>>

  let private updateSuccessor (succs: List<Addr * _>) = function
    | Some (succAddr, edge) -> succs.Add (succAddr, edge)
    | None -> ()

  let private updateVMap (vMap: DisasmVMap<_>) addr instrs succ =
    match vMap.TryGetValue addr with
    | true, storage -> updateSuccessor storage.Successors succ
    | false, _ ->
      let insList = SortedList ()
      let succList = List ()
      instrs |> Array.iter (fun lifted ->
        let ins = lifted.Original
        insList.Add (ins.Address, ins))
      updateSuccessor succList succ
      vMap[addr] <- { Instructions = insList
                      Successors = succList
                      Vertex = null }

  let private mergeVertices (g: IRCFG<_, _, _>) (vMap: DisasmVMap<_>) =
    g.IterEdge (fun e ->
      let src, dst = e.First.VData, e.Second.VData
      let srcAddr = src.LiftedInstructions[0].BBLAddr
      let dstAddr = dst.LiftedInstructions[0].BBLAddr
      let succ = if srcAddr = dstAddr then None else Some (dstAddr, e.Label)
      updateVMap vMap srcAddr src.LiftedInstructions succ)

  let private createVertices (vMap: DisasmVMap<_>) newGraph =
    vMap |> Seq.fold (fun (g: DisasmCFG<_>) (KeyValue (addr, storage)) ->
      let ppoint = ProgramPoint (addr, 0)
      let instrs = storage.Instructions.Values |> Seq.toArray
      let bbl = DisasmBasicBlock (ppoint, instrs)
      let v, g = g.AddVertex bbl
      storage.Vertex <- v
      g) newGraph

  let private createEdges (vMap: DisasmVMap<_>) newGraph =
    vMap.Values |> Seq.fold (fun (g: DisasmCFG<_>) storage ->
      let src = storage.Vertex
      storage.Successors |> Seq.fold (fun g (succ, label) ->
        let dst = vMap[succ].Vertex
        g.AddEdge (src, dst, label)
      ) g
    ) newGraph

  /// Create a new DisasmCFG from the given IRCFG.
  [<CompiledName "Create">]
  let create (g: IRCFG<'V, 'E, 'Abs>) (root: IVertex<'V>) =
    let newGraph =
      match g.ImplementationType with
      | Imperative ->
        ImperativeDiGraph<DisasmBasicBlock, 'E> () :> DisasmCFG<'E>
      | Persistent ->
        PersistentDiGraph<DisasmBasicBlock, 'E> () :> DisasmCFG<'E>
    let vMap = DisasmVMap ()
    mergeVertices g vMap
    newGraph
    |> createVertices vMap
    |> createEdges vMap
    |> fun newGraph ->
      let root =
        newGraph.FindVertexBy (fun v -> v.VData.PPoint = root.VData.PPoint)
      newGraph, root

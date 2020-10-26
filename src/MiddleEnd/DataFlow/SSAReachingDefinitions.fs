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

namespace B2R2.MiddleEnd.DataFlow

open B2R2
open B2R2.BinIR.SSA
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinEssence
open B2R2.MiddleEnd.Lens
open System.Collections.Generic

type SSARDMap = Dictionary<VertexID, Set<Variable>>

type SSAReachingDefinitions (cfg: DiGraph<SSABBlock, CFGEdgeKind>) as this =
  inherit TopologicalDataFlowAnalysis<Set<Variable>, SSABBlock> (Forward)

  let gens = SSARDMap ()
  let kills = SSARDMap ()

  do this.Initialize ()

  member private __.FindDefs (v: Vertex<SSABBlock>) =
    v.VData.SSAStmtInfos
    |> Array.fold (fun map (_, stmt) ->
      match stmt with
      | Def (v, _) -> Map.add v.Kind v map
      | Phi (v, _) -> Map.add v.Kind v map
      | _ -> map) Map.empty

  member private __.Initialize () =
    let vpPerVar = Dictionary<VariableKind, Set<Variable>> ()
    let vpPerVertex = Dictionary<VertexID, Set<Variable>> ()
    DiGraph.iterVertex cfg (fun v ->
      let vid = v.GetID ()
      let defs = __.FindDefs v
      let defSet = defs |> Seq.map (fun (KeyValue (_, v)) -> v) |> Set.ofSeq
      gens.[vid] <- defSet
      vpPerVertex.[vid] <- defSet
      defs |> Map.iter (fun vk v ->
        if vpPerVar.ContainsKey vk then vpPerVar.[vk] <- Set.add v vpPerVar.[vk]
        else vpPerVar.[vk] <- Set.singleton v)
    )
    DiGraph.iterVertex cfg (fun v ->
      let vid = v.GetID ()
      let vars = vpPerVertex.[vid] |> Set.map (fun v -> v.Kind)
      let vps = vpPerVertex.[vid]
      let alldefs =
        vars |> Set.fold (fun set v -> Set.union set vpPerVar.[v]) Set.empty
      kills.[vid] <- Set.difference alldefs vps
    )

  override __.Meet a b = Set.union a b

  override __.Top = Set.empty

  override __.Transfer i v =
    let vid = v.GetID ()
    Set.union gens.[vid] (Set.difference i kills.[vid])

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

namespace B2R2.DataFlow

open B2R2
open B2R2.BinGraph
open B2R2.BinIR.LowUIR
open System.Collections.Generic

type ReachingDefinitions (cfg: IRCFG) as this =
  inherit DataFlowAnalysis<Set<ProgramPoint>> (Forward)

  let gens = Dictionary<VertexID, Set<ProgramPoint>> ()
  let kills = Dictionary<VertexID, Set<ProgramPoint>> ()

  do this.Initialize ()

  member private __.FindDefs (v: Vertex<IRBasicBlock>) =
    let defmap = Dictionary<RegisterID, ProgramPoint> ()
    v.VData.GetInsInfos ()
    |> Array.iter (fun info ->
      info.Stmts |> Array.iteri (fun idx stmt ->
        match stmt with
        | Put (Var (_, id, _, _), _) ->
          defmap.[id] <- ProgramPoint (info.Instruction.Address, idx)
        | _ -> ()))
    defmap

  member private __.Initialize () =
    let regmap = Dictionary<RegisterID, Set<ProgramPoint>> ()
    let vmap = Dictionary<VertexID, Set<RegisterID>> ()
    cfg.IterVertex (fun v ->
      let vid = v.GetID ()
      let defmap = __.FindDefs v
      gens.[vid] <- defmap.Values |> Set.ofSeq
      vmap.[vid] <- Set.empty
      defmap.Keys |> Seq.iter (fun rid ->
        vmap.[vid] <- Set.add rid vmap.[vid]
        let pp = defmap.[rid]
        if regmap.ContainsKey rid then regmap.[rid] <- Set.add pp regmap.[rid]
        else regmap.[rid] <- Set.singleton pp)
    )
    cfg.IterVertex (fun v ->
      let vid = v.GetID ()
      kills.[vid] <-
        vmap.[vid]
        |> Set.fold (fun set rid -> Set.union set regmap.[rid]) Set.empty
    )

  override __.Meet a b = Set.union a b

  override __.Bottom = Set.empty

  override __.Worklist root =
    let q = Queue<Vertex<IRBasicBlock>> ()
    Traversal.iterRevPostorder root q.Enqueue
    q

  override __.Transfer i v =
    let vid = v.GetID ()
    Set.union gens.[vid] (Set.difference i kills.[vid])


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

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

type VarExpr =
  | Regular of RegisterID
  | Temporary of int
  | Memory

type VarPoint<'E> = {
  ProgramPoint: ProgramPoint
  VarExpr: 'E
}

type ReachingDefinition = {
  Ins: Set<VarPoint<VarExpr>>
  Outs: Set<VarPoint<VarExpr>>
}

type ReachingDefinitionAnalysis () =
  inherit DataFlowAnalysis<ReachingDefinition, VertexID,
                           IRBasicBlock, CFGEdgeKind> ()

  let gens = Dictionary<VertexID, Set<VarPoint<VarExpr>>> ()

  let kills = Dictionary<VertexID, Set<VarPoint<VarExpr>>> ()

  let findDefs (v: IVertex<IRBasicBlock>) =
    v.VData.LiftedInstructions
    |> Array.fold (fun list lifted ->
      lifted.Stmts
      |> Array.foldi (fun list idx stmt ->
        match stmt.S with
        | LowUIR.Put ({ LowUIR.E = LowUIR.TempVar (_, n) }, _) ->
          let pp = ProgramPoint (lifted.Original.Address, idx)
          { ProgramPoint = pp; VarExpr = Temporary n } :: list
        | LowUIR.Put ({ LowUIR.E = LowUIR.Var (_, id, _) }, _) ->
          let pp = ProgramPoint (lifted.Original.Address, idx)
          { ProgramPoint = pp; VarExpr = Regular id } :: list
        | _ -> list) list
      |> fst) []

  let initGensAndKills (g: IGraph<IRBasicBlock, CFGEdgeKind>) =
    let vpPerVar = Dictionary<VarExpr, Set<VarPoint<VarExpr>>> ()
    let vpPerVertex = Dictionary<VertexID, VarPoint<VarExpr> list> ()
    g.IterVertex (fun v ->
      let vid = v.ID
      let defs = findDefs v
      gens[vid] <- defs |> Set.ofList
      vpPerVertex[vid] <- defs
      defs |> List.iter (fun ({ VarExpr = v } as vp) ->
        if vpPerVar.ContainsKey v then vpPerVar[v] <- Set.add vp vpPerVar[v]
        else vpPerVar[v] <- Set.singleton vp
      )
    )
    g.IterVertex (fun v ->
      let vid = v.ID
      let defVarPoints = vpPerVertex[vid]
      let vars = defVarPoints |> List.map (fun vp -> vp.VarExpr)
      let vps = defVarPoints |> Set.ofList
      let alldefs =
        vars |> List.fold (fun acc v -> Set.union acc vpPerVar[v]) Set.empty
      kills[vid] <- Set.difference alldefs vps
    )

  member __.Gens with get() = gens

  member __.Kills with get() = kills

  override __.Bottom = { Ins = Set.empty; Outs = Set.empty }

  override __.InitializeWorkList g =
    initGensAndKills g
    let lst = List<VertexID> ()
    let roots = g.GetRoots () |> Seq.toList
    Traversal.iterRevPostorder g roots (fun v -> lst.Add v.ID)
    lst

  override __.Subsume (a, b) =
    a.Outs = b.Outs

  override __.Transfer (g, vid, s) =
    let v = g.FindVertexByID vid
    let preds = g.GetPreds v
    let ins = preds |> Seq.fold (fun acc pred ->
      let vid = pred.ID
      let absValue = __.GetAbsValue vid
      let outs = absValue.Outs
      Set.union acc outs) Set.empty
    let outs = Set.union gens[vid] (Set.difference s.Outs kills[vid])
    { Ins = ins; Outs = outs }

  override __.GetNextWorks (_g, v) = [| v |]

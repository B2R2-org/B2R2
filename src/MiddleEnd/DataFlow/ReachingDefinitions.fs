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

[<AbstractClass>]
type ReachingDefinitions<'Expr, 'BBL when 'Expr: comparison
                                      and 'BBL: equality
                                      and 'BBL :> BasicBlock>
                        (_cfg: DiGraph<'BBL, CFGEdgeKind>) =
  inherit TopologicalDataFlowAnalysis<Set<VarPoint<'Expr>>, 'BBL> (Forward)

  let gens = Dictionary<VertexID, Set<VarPoint<'Expr>>> ()
  let kills = Dictionary<VertexID, Set<VarPoint<'Expr>>> ()

  member __.Gens with get() = gens

  member __.Kills with get() = kills

  override __.Meet a b = Set.union a b

  override __.Top = Set.empty

  override __.Transfer i v =
    let vid = v.GetID ()
    Set.union gens[vid] (Set.difference i kills[vid])

/// Reaching definition analysis with a LowUIR-based CFG.
type LowUIRReachingDefinitions (cfg) as this =
  inherit ReachingDefinitions<VarExpr, IRBasicBlock> (cfg)

  do this.Initialize this.Gens this.Kills

  member private __.FindDefs (v: Vertex<IRBasicBlock>) =
    v.VData.InsInfos
    |> Array.fold (fun list info ->
      info.Stmts
      |> Array.foldi (fun list idx stmt ->
        match stmt.S with
        | LowUIR.Put ({ LowUIR.E = LowUIR.TempVar (_, n) }, _) ->
          let pp = ProgramPoint (info.Instruction.Address, idx)
          { ProgramPoint = pp; VarExpr = Temporary n } :: list
        | LowUIR.Put ({ LowUIR.E = LowUIR.Var (_, id, _, _) }, _) ->
          let pp = ProgramPoint (info.Instruction.Address, idx)
          { ProgramPoint = pp; VarExpr = Regular id } :: list
        | _ -> list) list
      |> fst) []

  member private __.Initialize
    (gens: Dictionary<_, _>) (kills: Dictionary<_, _>) =
    let vpPerVar = Dictionary<VarExpr, Set<VarPoint<VarExpr>>> ()
    let vpPerVertex = Dictionary<VertexID, VarPoint<VarExpr> list> ()
    DiGraph.iterVertex cfg (fun v ->
      let vid = v.GetID ()
      let defs = __.FindDefs v
      gens[vid] <- defs |> Set.ofList
      vpPerVertex[vid] <- defs
      defs |> List.iter (fun ({ VarExpr = v } as vp) ->
        if vpPerVar.ContainsKey v then vpPerVar[v] <- Set.add vp vpPerVar[v]
        else vpPerVar[v] <- Set.singleton vp
      )
    )
    DiGraph.iterVertex cfg (fun v ->
      let vid = v.GetID ()
      let defVarPoints = vpPerVertex[vid]
      let vars = defVarPoints |> List.map (fun vp -> vp.VarExpr)
      let vps = defVarPoints |> Set.ofList
      let alldefs =
        vars |> List.fold (fun set v -> Set.union set vpPerVar[v]) Set.empty
      kills[vid] <- Set.difference alldefs vps
    )

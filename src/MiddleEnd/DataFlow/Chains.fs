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
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

type DataFlowChain = {
  UseDefChain: Map<VarPoint<VarExpr>, Set<VarPoint<VarExpr>>>
  DefUseChain: Map<VarPoint<VarExpr>, Set<VarPoint<VarExpr>>>
}

module DataFlowChain =
  let private computeInBlockDefs pp u (outset: Set<VarPoint<VarExpr>>) =
    outset
    |> Seq.filter (fun vp ->
      vp.VarExpr = u
      && vp.ProgramPoint < (pp: ProgramPoint))
    |> Seq.sortBy (fun vp -> vp.ProgramPoint)
    |> Seq.tryLast (* Picking the def that has the largest position idx *)

  /// When there are more than one defs for the same variable, we should choose
  /// the last one.
  let private filterLastDefInBlock defs =
    defs
    |> Set.fold (fun map d ->
      let addr = d.ProgramPoint.Address
      match Map.tryFind addr map with
      | None -> Map.add addr d map
      | Some old ->
        if old.ProgramPoint.Position > d.ProgramPoint.Position then map
        else Map.add addr d map) Map.empty
    |> Map.toList
    |> List.map snd

  let private computeOutBlockDefs u (inset: Set<VarPoint<VarExpr>>) =
    inset
    |> Set.filter (fun d -> d.VarExpr = u)
    |> filterLastDefInBlock

  let private initUDChain cfg (ins: Dictionary<_,_>) (outs: Dictionary<_, _>) =
    Map.empty
    |> DiGraph.foldVertex cfg (fun map (v: Vertex<IRBasicBlock>) ->
      v.VData.InsInfos
      |> Array.fold (fun map info ->
        info.Stmts
        |> Array.foldi (fun map idx stmt ->
          let pp = ProgramPoint (info.Instruction.Address, idx)
          let inset = ins.[v.GetID ()]
          let outset = outs.[v.GetID ()]
          let uses = Utils.extractUses stmt
          uses |> Set.fold (fun map u ->
            let usepoint = { VarExpr = u; ProgramPoint = pp }
            let set = computeOutBlockDefs u inset |> Set.ofList
            let set =
              match computeInBlockDefs pp u outset with
              | Some def -> Set.add def set
              | None -> set
            Map.add usepoint set map
          ) map
        ) map |> fst
      ) map)

  let private initDUChain udchain =
    udchain
    |> Map.fold (fun map u ds ->
      ds
      |> Set.fold (fun map d ->
        match Map.tryFind d map with
        | None -> Map.add d (Set.singleton u) map
        | Some us -> Map.add d (Set.add u us) map) map) Map.empty

  let private normalizeVP (vp: VarPoint<VarExpr>) =
    let addr = vp.ProgramPoint.Address
    { vp with ProgramPoint = ProgramPoint (addr, 0) }

  let private filterDisasm isDisasmLevel chain =
    if not isDisasmLevel then chain
    else
      chain
      |> Map.fold (fun map vp set ->
        let vp = normalizeVP vp
        let newSet = set |> Set.map normalizeVP
        match Map.tryFind vp map with
        | None -> Map.add vp newSet map
        | Some old -> Map.add vp (Set.union old newSet) map) Map.empty

  [<CompiledName("Init")>]
  let init cfg root isDisasmLevel =
    let rd = LowUIRReachingDefinitions (cfg)
    let ins, outs = rd.Compute cfg root
    let udchain = initUDChain cfg ins outs |> filterDisasm isDisasmLevel
    let duchain = initDUChain udchain |> filterDisasm isDisasmLevel
    { UseDefChain = udchain; DefUseChain = duchain }

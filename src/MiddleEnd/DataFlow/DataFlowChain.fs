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
open B2R2.Collections
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// Data-flow chain that contains both Use-Def and Def-Use chains.
type DataFlowChain = {
  /// Use-def chain.
  UseDefChain: Map<VarPoint, Set<VarPoint>>
  /// Def-use chain.
  DefUseChain: Map<VarPoint, Set<VarPoint>>
}

module DataFlowChain =
  let private computeInBlockDefs pp u (outset: Set<VarPoint>) =
    outset
    |> Seq.filter (fun vp ->
      vp.VarKind = u
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

  let private computeOutBlockDefs u (inset: Set<VarPoint>) =
    inset
    |> Set.filter (fun d -> d.VarKind = u)
    |> filterLastDefInBlock

  let rec private extractUseFromExpr e acc =
    match e.E with
    | Var (_, id, _) -> Regular id :: acc
    | TempVar (_, n) -> Temporary n :: acc
    | UnOp (_, e) -> extractUseFromExpr e acc
    | BinOp (_, _, e1, e2) -> extractUseFromExpr e1 (extractUseFromExpr e2 acc)
    | RelOp (_, e1, e2) -> extractUseFromExpr e1 (extractUseFromExpr e2 acc)
    | Load (_, _, e) -> extractUseFromExpr e acc
    | Ite (c, e1, e2) ->
      extractUseFromExpr c (extractUseFromExpr e1 (extractUseFromExpr e2 acc))
    | Cast (_, _, e) -> extractUseFromExpr e acc
    | Extract (e, _, _) -> extractUseFromExpr e acc
    | _ -> []

  let private extractUseFromStmt s =
    match s.S with
    | Put (_, e)
    | Store (_, _, e)
    | Jmp (e)
    | CJmp (e, _, _)
    | InterJmp (e, _) -> extractUseFromExpr e []
    | InterCJmp (c, e1, e2) ->
      extractUseFromExpr c (extractUseFromExpr e1 (extractUseFromExpr e2 []))
    | _ -> []

  let private extractUses stmt =
    extractUseFromStmt stmt
    |> Set.ofList

  let private initUDChain cfg (st: IDataFlowState<_, _>) =
    Map.empty
    |> (cfg: IDiGraphAccessible<LowUIRBasicBlock, _>).FoldVertex (fun map v ->
      v.VData.Internals.LiftedInstructions
      |> Array.fold (fun map lifted ->
        lifted.Stmts
        |> Array.foldi (fun map idx stmt ->
          let pp = ProgramPoint (lifted.Original.Address, idx)
          let abs = st.GetAbsValue v.ID
          let uses = extractUses stmt
          uses |> Set.fold (fun map u ->
            let usepoint = { ProgramPoint = pp; VarKind = u }
            let set = computeOutBlockDefs u abs.Ins |> Set.ofList
            let set =
              match computeInBlockDefs pp u abs.Outs with
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

  let private normalizeVP (vp: VarPoint) =
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
  let init cfg isDisasmLevel =
    let rd = ReachingDefinitionAnalysis () :> IDataFlowAnalysis<_, _, _, _>
    let st = rd.InitializeState []
    let st = rd.Compute cfg st
    let udchain = initUDChain cfg st |> filterDisasm isDisasmLevel
    let duchain = initDUChain udchain |> filterDisasm isDisasmLevel
    { UseDefChain = udchain; DefUseChain = duchain }

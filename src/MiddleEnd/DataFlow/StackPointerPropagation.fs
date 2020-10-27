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
open B2R2.FrontEnd.BinInterface
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.Lens
open System.Collections.Generic

module StackState =

  let initRegister hdl (dict: Dictionary<_, _>) =
    match hdl.RegisterBay.StackPointer with
    | Some sp ->
      let rt = hdl.RegisterBay.RegIDToRegType sp
      let str = hdl.RegisterBay.RegIDToString sp
      let var = { Kind = RegVar (rt, sp, str); Identifier = 0 }
      dict.[var] <- Const (BitVector.ofUInt64 0x80000000UL rt)
      dict
    | None -> dict

  let private collectDefAddrs ess cfg st v addrs = function
    | _, Def (_, Store (_, rt, addr, _)) ->
      match StackTransfer.evalExpr ess cfg st v addr with
      | Const bv ->
        let addr = BitVector.toUInt64 bv
        let align = RegType.toByteWidth rt |> uint64
        if (rt = st.DefaultWordSize) && (addr % align = 0UL) then
          Set.add addr addrs
        else addrs
      | _ -> addrs
    | _ -> addrs

  let private recordMergePoint mergePoints v addr =
    match Map.tryFind v mergePoints with
    | Some addrs -> Map.add v (Set.add addr addrs) mergePoints
    | None -> Map.add v (Set.singleton addr) mergePoints

  let private updateMergePoint addrsPerNode addr (mps, visited, workList) v =
    if Set.contains v visited then mps, visited, workList
    else
      let mps = recordMergePoint mps v addr
      let visited = Set.add v visited
      let addrs = (addrsPerNode: Dictionary<SSAVertex, Set<Addr>>).[v]
      if not <| Set.contains addr addrs then mps, visited, v :: workList
      else mps, visited, workList

  let rec private foldVertices mergePoints visited addrsPerNode addr = function
    | [] -> mergePoints
    | (v: SSAVertex) :: workList ->
      let mergePoints, visited, workList =
        v.VData.Frontier
        |> List.fold (updateMergePoint addrsPerNode addr)
                      (mergePoints, visited, workList)
      foldVertices mergePoints visited addrsPerNode addr workList

  /// Memory merge point means an address of which the merging operation should
  /// be performed. Mempory merge point is necessary for dataflow analysis on
  /// SSA. Without this, every time we meet a phi statement of a memory, we
  /// should iterate memories and merge values at all exisitng addresses.
  let computeMemoryMergePoints ess cfg st =
    let defSites = Dictionary ()
    let defsPerNode = Dictionary ()
    DiGraph.iterVertex cfg (fun (v: Vertex<SSABBlock>) ->
      if v.VData.IsFakeBlock () then ()
      else
        let defs =
          v.VData.SSAStmtInfos
          |> Array.fold (collectDefAddrs ess cfg st v) Set.empty
        defsPerNode.[v] <- defs
        defs
        |> Set.iter (fun d ->
          if defSites.ContainsKey d then defSites.[d] <- Set.add v defSites.[d]
          else defSites.[d] <- Set.singleton v))
    defSites
    |> Seq.fold (fun mergePoints (KeyValue (addr, defs)) ->
      Set.toList defs
      |> foldVertices mergePoints Set.empty defsPerNode addr
      ) Map.empty

/// Variant of Constant Propagation. It only cares stack-related registers:
/// stack pointer and frame pointer.
type StackPointerPropagation (ssaCFG, spState) =
  inherit ConstantPropagation<StackValue> (ssaCFG, spState)

  static member Init hdl ssaCFG =
    let spState =
      CPState.initState hdl
                        ssaCFG
                        (StackState.initRegister hdl)
                        id
                        Undef
                        NotAConst
                        StackValue.goingUp
                        StackValue.meet
                        StackTransfer.evalStmt
    StackPointerPropagation (ssaCFG, spState)

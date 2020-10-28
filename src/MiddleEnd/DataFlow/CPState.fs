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
open B2R2.FrontEnd.BinInterface
open B2R2.BinIR.SSA
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinEssence
open B2R2.MiddleEnd.Lens
open System.Collections.Generic

/// An ID of an SSA memory instance.
type SSAMemID = int

type CPState<'L when 'L: equality> = {
  /// BinHandle of the current binary.
  BinHandle: BinHandle
  /// SSA edges
  SSAEdges: SSAEdges.EdgeInfo
  /// SSA var values.
  RegState : Dictionary<Variable, 'L>
  /// SSA mem values. Only store values of constant addresses.
  MemState : Dictionary<SSAMemID, Map<Addr, 'L> * Set<Addr>>
  /// Executable edges from vid to vid. If there's no element for an edge, that
  /// means the edge is not executable.
  ExecutableEdges: HashSet<VertexID * VertexID>
  /// Executed edges from vid to vid.
  ExecutedEdges: HashSet<VertexID * VertexID>
  /// Default word size of the current analysis.
  DefaultWordSize : RegType
  /// Worklist for blocks.
  FlowWorkList: Queue<VertexID * VertexID>
  /// Worklist for SSA stmt, this stack stores a list of def variables, and we
  /// will use SSAEdges to find all related SSA statements.
  SSAWorkList: Stack<Variable>
  UndefinedMemories: HashSet<Addr>
  Top: 'L
  Bottom: 'L
  GoingUp: 'L -> 'L -> bool
  Meet: 'L -> 'L -> 'L
  TransferFn: TransferFn<'L>
}

and TransferFn<'L when 'L: equality> =
  BinEssence
    -> DiGraph<SSABBlock, CFGEdgeKind>
    -> CPState<'L>
    -> Vertex<SSABBlock>
    -> ProgramPoint
    -> Stmt
    -> unit

module CPState =

  let initState hdl ssaCfg initRegister initMemory top bottom goingUp meet fn =
    { BinHandle = hdl
      SSAEdges = SSAEdges.compute ssaCfg
      RegState = Dictionary () |> initRegister
      MemState = Dictionary () |> initMemory
      ExecutableEdges = HashSet ()
      ExecutedEdges = HashSet ()
      DefaultWordSize = hdl.ISA.WordSize |> WordSize.toRegType
      FlowWorkList = Queue ()
      SSAWorkList = Stack ()
      UndefinedMemories = HashSet ()
      Top = top
      Bottom = bottom
      GoingUp = goingUp
      Meet = meet
      TransferFn = fn }

  let markExecutable st src dst =
    if st.ExecutableEdges.Add (src, dst) then st.FlowWorkList.Enqueue (src, dst)
    else ()

  let isExecuted st src dst =
    st.ExecutedEdges.Contains (src, dst)

  let tryFindReg st r =
    match st.RegState.TryGetValue r with
    | true, v -> Some v
    | false, _ ->
      if r.Identifier = 0 then Some st.Bottom
      else None

  let findReg st r =
    match st.RegState.TryGetValue r with
    | true, v -> v
    | false, _ -> st.Bottom

  let findMem st m rt addr =
    let mid = m.Identifier
    let align = RegType.toByteWidth rt |> uint64
    if st.MemState.ContainsKey mid then ()
    else st.MemState.[mid] <- (Map.empty, Set.empty)
    if (rt = st.DefaultWordSize) && (addr % align = 0UL) then
      match Map.tryFind addr <| fst st.MemState.[mid] with
      | Some c -> c
      | None ->
        let mem, updated = st.MemState.[mid]
        let mem = Map.add addr st.Bottom mem
        st.MemState.[mid] <- (mem, updated)
        st.UndefinedMemories.Add addr |> ignore
        st.Bottom
    else st.Bottom

  let copyMem st dstid srcid =
    st.MemState.[dstid] <- st.MemState.[srcid]

  let storeToFreshMem st mDst rt addr c =
    let align = RegType.toByteWidth rt |> uint64
    let dstid = mDst.Identifier
    let mem, updated = st.MemState.[dstid]
    if (rt = st.DefaultWordSize) && (addr % align = 0UL) then
      let mem = Map.add addr c mem
      st.MemState.[dstid] <- (mem, updated)
      st.SSAWorkList.Push mDst
    elif not <| Set.isEmpty updated then st.SSAWorkList.Push mDst

  let storeToDefinedMem oldMem st mDst rt addr c =
    let align = RegType.toByteWidth rt |> uint64
    let dstid = mDst.Identifier
    let mem, updated = st.MemState.[dstid]
    if (rt = st.DefaultWordSize) && (addr % align = 0UL) then
      match Map.tryFind addr oldMem with
      | Some c' when st.GoingUp c' c || c' = c ->
        let mem = Map.add addr c mem
        let updated = Set.remove addr updated
        st.MemState.[dstid] <- (mem, updated)
        if not <| Set.isEmpty updated then st.SSAWorkList.Push mDst
      | Some c' ->
        let mem = Map.add addr (st.Meet c c') mem
        let updated = Set.add addr updated
        st.MemState.[dstid] <- (mem, updated)
        st.SSAWorkList.Push mDst
      | _ ->
        let mem = Map.add addr c mem
        let updated = Set.add addr updated
        st.MemState.[dstid] <- (mem, updated)
        st.SSAWorkList.Push mDst
    elif not <| Set.isEmpty updated then st.SSAWorkList.Push mDst

  let freshMerge st mems =
    mems
    |> Array.reduce (fun mem1 mem2 ->
      mem2
      |> Map.fold (fun acc addr v2 ->
        if st.UndefinedMemories.Contains addr then Map.add addr st.Bottom acc
        else
          match Map.tryFind addr mem1 with
          | Some v1 when v1 = v2 -> acc
          | Some v1 -> Map.add addr (st.Meet v1 v2) acc
          | None -> Map.add addr v2 acc) mem1)

  /// Merge memory mapping and return true if changed.
  let mergeMemWithoutMergePoints st oldMem mDst srcids =
    let dstid = mDst.Identifier
    srcids
    |> Array.choose (fun mid ->
      if mid = dstid then oldMem
      else st.MemState.TryGetValue mid |> Utils.tupleToOpt)
    |> function
      | [||] -> ()
      | arr ->
        let mem = Array.map fst arr |> freshMerge st
        let updated, needEnqueue =
          mem
          |> Map.fold (fun (newUpdated, needEnqueue) addr c ->
            match oldMem with
            | Some (oldMem, _) ->
              match Map.tryFind addr oldMem with
              | Some c' when c = c' -> Set.remove addr newUpdated, needEnqueue
              | Some _ -> Set.add addr newUpdated, true
              | None -> Set.add addr newUpdated, true
            | None -> newUpdated, true) (Set.empty, false)
        st.MemState.[dstid] <- (mem, updated)
        if needEnqueue then st.SSAWorkList.Push mDst

  let mergeWithMergePoints st mergePoints oldMem mems =
    mergePoints
    |> Set.fold (fun (acc, updated, needEnqueue) addr ->
      if st.UndefinedMemories.Contains addr then
        Map.add addr st.Bottom acc, updated, needEnqueue
      else
        match Map.tryFind addr oldMem with
        | Some v when v = st.Bottom ->
          Map.add addr st.Bottom acc, updated, needEnqueue
        | v ->
          let v' =
            mems
            |> Array.map (fun mem -> Map.tryFind addr mem)
            |> Array.choose id
            |> fun arr ->
              if Array.isEmpty arr then st.Bottom else Array.reduce st.Meet arr
          match v with
          | Some v when v = v' -> Map.add addr v acc, updated, needEnqueue
          | Some v ->
            Map.add addr (st.Meet v v') acc, Set.add addr updated, true
          | None -> Map.add addr v' acc, Set.add addr updated, true
        ) (oldMem, Set.empty, false)

  /// Merge memory with pre-calculated merge points
  let mergeMemWithMergePoints st oldMem mergePoints mDst srcids =
    let dstid = mDst.Identifier
    srcids
    |> Array.choose (fun mid ->
      if mid = dstid then oldMem
      else st.MemState.TryGetValue mid |> Utils.tupleToOpt)
    |> function
      | [||] -> ()
      | arr ->
        let arr = Array.map fst arr
        let mem, updated, needEnqueue =
          match oldMem with
          | None -> freshMerge st arr, Set.empty, true
          | Some (oldMem, _) -> mergeWithMergePoints st mergePoints oldMem arr
        st.MemState.[dstid] <- (mem, updated)
        if needEnqueue then st.SSAWorkList.Push mDst

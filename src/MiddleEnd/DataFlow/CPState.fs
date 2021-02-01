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
open B2R2.MiddleEnd.ControlFlowGraph
open System.Collections.Generic

/// An ID of an SSA memory instance.
type SSAMemID = int

/// Constant propagation analysis state.
type CPState<'L when 'L: equality> = {
  /// BinHandle of the current binary.
  BinHandle: BinHandle
  /// SSA edges
  SSAEdges: SSAEdges.EdgeInfo
  /// SSA var values.
  RegState : Dictionary<Variable, 'L>
  /// SSA mem values. Only store values of constant addresses. The second set
  /// contains addresses changed throughout the analysis (after initialization).
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
  /// Uninitialized memory addresses found during CP.
  UninitializedMemAddrs: HashSet<Addr>
  /// CP core interface.
  CPCore: IConstantPropagationCore<'L>
}

/// The core interface of a Constant Propagation (CP) algorithm.
and IConstantPropagationCore<'L when 'L: equality> =
  /// Bottom of the lattice.
  abstract Bottom: 'L

  /// Check if toV is up in the lattice compared to fromV.
  abstract GoingUp: fromV: 'L -> toV: 'L -> bool

  /// The meet operator.
  abstract Meet: 'L -> 'L -> 'L

  /// The transfer function.
  abstract Transfer:
    CPState<'L>
    -> DiGraph<SSABasicBlock, CFGEdgeKind>
    -> Vertex<SSABasicBlock>
    -> ProgramPoint
    -> Stmt
    -> unit

  /// Read memory. Some analyses require reading data section values, and this
  /// function is used in such cases.
  abstract MemoryRead: Addr -> RegType -> BitVector option

module CPState =

  let initState hdl ssaCfg initRegs initMems core =
    { BinHandle = hdl
      SSAEdges = SSAEdges.compute ssaCfg
      RegState = initRegs
      MemState = initMems
      ExecutableEdges = HashSet ()
      ExecutedEdges = HashSet ()
      DefaultWordSize = hdl.ISA.WordSize |> WordSize.toRegType
      FlowWorkList = Queue ()
      SSAWorkList = Stack ()
      UninitializedMemAddrs = HashSet ()
      CPCore = core }

  let markExecutable st src dst =
    if st.ExecutableEdges.Add (src, dst) then st.FlowWorkList.Enqueue (src, dst)
    else ()

  let isExecuted st src dst =
    st.ExecutedEdges.Contains (src, dst)

  let markAllSuccessors st cfg (blk: SSAVertex) =
    let myid = blk.GetID ()
    DiGraph.getSuccs cfg blk
    |> List.iter (fun succ ->
      let succid = succ.GetID ()
      markExecutable st myid succid)

  let markExceptCallFallThrough st cfg (blk: SSAVertex) =
    let myid = blk.GetID ()
    DiGraph.getSuccs cfg blk
    |> List.iter (fun succ ->
      if DiGraph.findEdgeData cfg blk succ <> CallFallThroughEdge then
        let succid = succ.GetID ()
        markExecutable st myid succid
      else ())

  let getExecutableSources st cfg (blk: Vertex<_>) srcIDs =
    let preds = DiGraph.getPreds cfg blk |> List.toArray
    srcIDs
    |> Array.mapi (fun i srcID ->
      if isExecuted st (preds.[i].GetID ()) (blk.GetID ()) then Some srcID
      else None)
    |> Array.choose id

  let inline updateConst st r v =
    if not (st.RegState.ContainsKey r) then
      st.RegState.[r] <- v
      st.SSAWorkList.Push r
    elif st.RegState.[r] = v then ()
    elif st.CPCore.GoingUp st.RegState.[r] v then ()
    else
      st.RegState.[r] <- st.CPCore.Meet st.RegState.[r] v
      st.SSAWorkList.Push r

  let tryFindReg st lazyInit r =
    match st.RegState.TryGetValue r with
    | true, v -> Some v
    | false, _ ->
      if r.Identifier = 0 && lazyInit then Some st.CPCore.Bottom
      else None

  let findReg st r =
    match st.RegState.TryGetValue r with
    | true, v -> v
    | false, _ -> st.CPCore.Bottom

  let inline tryGetMemState st id =
    st.MemState.TryGetValue id |> Utils.tupleToOpt

  let inline private initMemState st mid =
    if st.MemState.ContainsKey mid then ()
    else st.MemState.[mid] <- (Map.empty, Set.empty)

  let inline private isAligned st rt addr =
    let align = RegType.toByteWidth rt |> uint64
    (rt = st.DefaultWordSize) && (addr % align = 0UL)

  let tryFindMem st m rt addr =
    let mid = m.Identifier
    initMemState st mid
    if isAligned st rt addr then Map.tryFind addr <| fst st.MemState.[mid]
    else st.CPCore.Bottom |> Some

  let updateUninitialized st m addr =
    let mid = m.Identifier
    let mem, updated = st.MemState.[mid]
    let mem = Map.add addr st.CPCore.Bottom mem
    st.MemState.[mid] <- (mem, updated)
    st.UninitializedMemAddrs.Add addr |> ignore
    st.CPCore.Bottom

  let copyMem st dstid srcid =
    st.MemState.[dstid] <- st.MemState.[srcid]

  let storeToFreshMem st mDst rt addr c =
    let dstid = mDst.Identifier
    let mem, updated = st.MemState.[dstid]
    if isAligned st rt addr then
      let mem = Map.add addr c mem
      st.MemState.[dstid] <- (mem, updated)
      st.SSAWorkList.Push mDst
    elif not <| Set.isEmpty updated then st.SSAWorkList.Push mDst
    else ()

  let private updateMemoryState st mem updated mDst addr v =
    let mem = Map.add addr v mem
    let updated = Set.add addr updated
    st.MemState.[mDst.Identifier] <- (mem, updated)
    st.SSAWorkList.Push mDst

  let storeToOldMem oldMem st mDst rt addr c =
    let dstid = mDst.Identifier
    let mem, updated = st.MemState.[dstid]
    if isAligned st rt addr then
      match Map.tryFind addr oldMem with
      | Some oldC when st.CPCore.GoingUp oldC c || oldC = c ->
        let mem = Map.add addr c mem
        let updated = Set.remove addr updated
        st.MemState.[dstid] <- (mem, updated)
        if not <| Set.isEmpty updated then st.SSAWorkList.Push mDst else ()
      | Some oldC ->
        updateMemoryState st mem updated mDst addr (st.CPCore.Meet c oldC)
      | _ -> updateMemoryState st mem updated mDst addr c
    elif not <| Set.isEmpty updated then st.SSAWorkList.Push mDst
    else ()

  let private freshMerge st mems =
    mems
    |> Array.reduce (fun mem1 mem2 ->
      mem2
      |> Map.fold (fun acc addr v2 ->
        if st.UninitializedMemAddrs.Contains addr then
          Map.add addr st.CPCore.Bottom acc
        else
          match Map.tryFind addr mem1 with
          | Some v1 when v1 = v2 -> acc
          | Some v1 -> Map.add addr (st.CPCore.Meet v1 v2) acc
          | None -> Map.add addr v2 acc) mem1)

  let private computeDelta oldMemState mergedMem =
    mergedMem
    |> Map.fold (fun (newUpdated, needEnqueue) addr c ->
      match oldMemState with
      | Some (oldMem, _) ->
        match Map.tryFind addr oldMem with
        | Some c' when c = c' -> newUpdated, needEnqueue
        | Some _ -> Set.add addr newUpdated, true
        | None -> Set.add addr newUpdated, true
      | None -> newUpdated, true) (Set.empty, false)

  /// Merge memory mapping.
  let mergeMemWithoutMergePoints st mDst srcids =
    let dstid = mDst.Identifier
    let oldMemState = tryGetMemState st dstid
    srcids
    |> Array.choose (fun sid ->
      if sid = dstid then oldMemState
      else st.MemState.TryGetValue sid |> Utils.tupleToOpt)
    |> function
      | [||] -> ()
      | arr ->
        let mem = Array.map fst arr |> freshMerge st
        let updated, needEnqueue = computeDelta oldMemState mem
        st.MemState.[dstid] <- (mem, updated)
        if needEnqueue then st.SSAWorkList.Push mDst else ()

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
open B2R2.FrontEnd
open B2R2.BinIR.SSA
open B2R2.BinGraph
open B2R2.Lens
open System.Collections.Generic

/// An ID of an SSA memory instance.
type SSAMemID = int

type CPState = {
  /// BinHandler of the current binary.
  BinHandler: BinHandler
  /// SSA edges
  SSAEdges: SSAEdges.EdgeInfo
  /// SSA var values.
  RegState : Dictionary<Variable, CPValue>
  /// SSA mem values. Only store values of constant addresses.
  MemState : Dictionary<SSAMemID, Map<Addr, CPValue * SSAMemID>>
  /// Executable edges from vid to vid. If there's no element for an edge, that
  /// means the edge is not executable.
  ExecutableEdges: HashSet<VertexID * VertexID>
  /// Executed edges from vid to vid.
  ExecutedEdges: HashSet<VertexID * VertexID>
  /// Default word size of the current analysis.
  DefaultWordSize : RegType
  /// Worklist for blocks.
  FlowWorkList: Queue<VertexID * VertexID>
  /// Worklist for SSA stmt, this queue stores a list of def variables, and we
  /// will use SSAEdges to find all related SSA statements.
  SSAWorkList: Queue<Variable>
}

module CPState =
  let private initStackRegister hdl (dict: Dictionary<_, _>) =
    match hdl.RegisterBay.StackPointer with
    | Some sp ->
      let rt = hdl.RegisterBay.RegIDToRegType sp
      let str = hdl.RegisterBay.RegIDToString sp
      let var = { Kind = RegVar (rt, sp, str); Identifier = 0 }
      dict.[var] <- Const (BitVector.ofUInt64 0x80000000UL rt)
      dict
    | None -> dict

  let private initMemory (dict: Dictionary<_, _>) =
    dict.[0] <- Map.empty
    dict

  let initState hdl ssaCfg =
    { BinHandler = hdl
      SSAEdges = SSAEdges.compute ssaCfg
      RegState = Dictionary () |> initStackRegister hdl
      MemState = Dictionary () |> initMemory
      ExecutableEdges = HashSet ()
      ExecutedEdges = HashSet ()
      DefaultWordSize = hdl.ISA.WordSize |> WordSize.toRegType
      FlowWorkList = Queue ()
      SSAWorkList = Queue () }

  let markExecutable st src dst =
    if st.ExecutableEdges.Add (src, dst) then st.FlowWorkList.Enqueue (src, dst)
    else ()

  let isExecuted st src dst =
    st.ExecutedEdges.Contains (src, dst)

  let tryFindReg st r =
    match st.RegState.TryGetValue r with
    | true, v -> Some v
    | false, _ ->
      if r.Identifier = 0 then Some NotAConst
      else None

  let findReg st r =
    match st.RegState.TryGetValue r with
    | true, v -> v
    | false, _ -> NotAConst

  let findMem st m rt addr =
    let mid = m.Identifier
    let align = RegType.toByteWidth rt |> uint64
    if st.MemState.ContainsKey mid then ()
    else st.MemState.[mid] <- Map.empty
    if (rt = st.DefaultWordSize) && (addr % align = 0UL) then
      match Map.tryFind addr st.MemState.[mid] with
      | Some (c, _) -> c
      | None -> NotAConst
    else NotAConst

  let copyMem st dstid srcid =
    if st.MemState.ContainsKey srcid then ()
    else st.MemState.[srcid] <- Map.empty
    st.MemState.[dstid] <- st.MemState.[srcid]

  let storeMem st mDst rt addr c =
    let align = RegType.toByteWidth rt |> uint64
    if (rt = st.DefaultWordSize) && (addr % align = 0UL) then
      let dstid = mDst.Identifier
      match Map.tryFind addr st.MemState.[dstid] with
      | Some (_, origin) when origin <> dstid ->
        st.MemState.[dstid] <- Map.add addr (c, dstid) st.MemState.[dstid]
        st.SSAWorkList.Enqueue mDst
      | Some (old, _) when CPValue.goingUp old c || old = c -> ()
      | _ ->
        st.MemState.[dstid] <- Map.add addr (c, dstid) st.MemState.[dstid]
        st.SSAWorkList.Enqueue mDst
    else ()

  let private mergeMemAux origin st1 st2 =
    let addrs = Map.fold (fun acc addr _ -> Set.add addr acc) Set.empty st1
    let addrs = Map.fold (fun acc addr _ -> Set.add addr acc) addrs st2
    addrs
    |> Set.fold (fun acc addr ->
      match Map.tryFind addr st1, Map.tryFind addr st2 with
      | Some (c, _), Some (c', _) ->
        Map.add addr (CPValue.meet c c', origin) acc
      | _ -> Map.add addr (NotAConst, origin) acc) Map.empty

  /// Merge memory mapping and return true if changed.
  let mergeMem st dstid srcids =
    srcids
    |> Array.choose (fun mid -> st.MemState.TryGetValue mid |> Utils.tupleToOpt)
    |> function
      | [||] -> false
      | arr ->
        let merged = Array.reduce (mergeMemAux dstid) arr
        if not (st.MemState.ContainsKey dstid)
          || st.MemState.[dstid] <> merged
        then st.MemState.[dstid] <- merged; true
        else false

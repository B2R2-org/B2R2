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

namespace B2R2.BinCorpus

open B2R2
open B2R2.FrontEnd
open B2R2.BinIR.LowUIR
open B2R2.BinGraph

/// Represents instruction-level basic block leader.
type LeaderInfo = {
  /// Instruction-level basic block boundary
  Boundary : AddrRange
  /// IR-level basic block leaders that are belonging to this basic block
  IRLeaders : Set<ProgramPoint>
}

type BasicBlockMap = {
  LeaderMap : Map<Addr, LeaderInfo>
  /// Represent area covered by SCFG
  Boundaries : IntervalSet
  VertexMap : Map<ProgramPoint, Vertex<IRBasicBlock>>
}
with
  static member Init () =
    { LeaderMap = Map.empty
      Boundaries = IntervalSet.empty
      VertexMap = Map.empty }

type EdgeInfo = (ProgramPoint * CFGEdgeKind) option * Addr

type SCFGAccumulator = {
  InstrMap : InstrMap
  BasicBlockMap : BasicBlockMap
  CalleeMap : CalleeMap
  Graph : DiGraph<IRBasicBlock, CFGEdgeKind>
  NoReturnInfo : NoReturnInfo
  IndirectBranchMap : Map<Addr, IndirectBranchInfo>
}

[<RequireQualifiedAccess>]
module SCFGUtils =
  let init () =
    { LeaderMap = Map.empty
      Boundaries = IntervalSet.empty
      VertexMap = Map.empty }

  let private getBoundary bblMap addr =
    match IntervalSet.tryFindByAddr addr bblMap.Boundaries with
    | Some range -> range
    | None -> Utils.impossible ()

  let private addLeaderInfo leaderInfo bblMap =
    let boundary = leaderInfo.Boundary
    { bblMap with
        LeaderMap = Map.add boundary.Min leaderInfo bblMap.LeaderMap
        Boundaries = IntervalSet.add boundary bblMap.Boundaries }

  let private removeLeaderInfoByAddr addr bblMap =
    let boundary = getBoundary bblMap addr
    let leaderInfo = Map.find boundary.Min bblMap.LeaderMap
    let bblMap =
      { bblMap with
          LeaderMap = Map.remove boundary.Min bblMap.LeaderMap
          Boundaries = IntervalSet.remove boundary bblMap.Boundaries }
    leaderInfo, bblMap

  let inline private alreadyHasLeader bblMap leader =
    Map.containsKey leader bblMap.LeaderMap

  let inline private isExecutableLeader hdl leader =
    hdl.FileInfo.IsExecutableAddr leader

  /// If a leader points already covered area but not a starting address of an
  /// instruction, then it means overlap.
  let inline private isOverlap (instrMap: InstrMap) bblMap leader =
    not <| instrMap.ContainsKey leader &&
      IntervalSet.containsAddr leader bblMap.Boundaries

  let inline private needToSplit (instrMap: InstrMap) bblMap leader =
    (* Maybe this condition is redundant because of isOverlap*)
    instrMap.ContainsKey leader &&
      IntervalSet.containsAddr leader bblMap.Boundaries

  let inline private isAlreadyParsed (instrMap: InstrMap) leader =
    instrMap.ContainsKey leader

  let private splitLeaderInfo prevLeaderInfo leaderPoint =
    let prevIRLeaders, newIRLeaders =
      prevLeaderInfo.IRLeaders
      |> Set.add leaderPoint
      |> Set.partition (fun ppoint -> ppoint < leaderPoint)
    let oldBoundary = prevLeaderInfo.Boundary
    let prevBoundary = AddrRange (oldBoundary.Min, leaderPoint.Address)
    let newBoundary = AddrRange (leaderPoint.Address, oldBoundary.Max)
    let prevInfo = { Boundary = prevBoundary ; IRLeaders = prevIRLeaders }
    let newInfo = { Boundary = newBoundary ; IRLeaders = newIRLeaders }
    prevInfo, newInfo

  let private modifyGraph bblMap g prevLeaderInfo leaderPoint =
    let irLeaders = prevLeaderInfo.IRLeaders
    (* Nothing to do *)
    if Set.contains leaderPoint prevLeaderInfo.IRLeaders then None, bblMap, g
    else
      let target =
        Set.partition (fun ppoint -> ppoint < leaderPoint) irLeaders
        |> fst |> Set.maxElement
      let targetV = Map.find target bblMap.VertexMap
      let incomings, cycleEdge =
        DiGraph.getPreds g targetV
        |> List.fold (fun (incomings, cycleEdge) p ->
          let e = DiGraph.findEdgeData g p targetV
          if p.GetID () = targetV.GetID () then incomings, Some e
          else
            (p, e) :: incomings, cycleEdge) ([], None)
      let outgoings, cycleEdge =
        DiGraph.getSuccs g targetV
        |> List.fold (fun (outgoings, cycleEdge) s ->
          let e = DiGraph.findEdgeData g targetV s
          if s.GetID () = targetV.GetID () then outgoings, Some e
          else
            (s, e) :: outgoings, cycleEdge) ([], cycleEdge)
      (* Remove Vertex *)
      let g = DiGraph.removeVertex g targetV
      let bblMap =
        { bblMap with
            VertexMap = Map.remove target bblMap.VertexMap }
      (* Split insInfo *)
      let insInfos = targetV.VData.GetInsInfos ()
      let srcInfos, dstInfos =
        insInfos
        |> Array.partition (fun insInfo ->
          insInfo.Instruction.Address < leaderPoint.Address)
      let srcData = IRBasicBlock (srcInfos, target)
      let dstData = IRBasicBlock (dstInfos, leaderPoint)
      (* Add vertices *)
      let src, g = DiGraph.addVertex g srcData
      let dst, g = DiGraph.addVertex g dstData
      (* Add Edges *)
      let g = DiGraph.addEdge g src dst FallThroughEdge
      let g =
        incomings |> List.fold (fun g (p, e) -> DiGraph.addEdge g p src e) g
      let g =
        outgoings |> List.fold (fun g (s, e) -> DiGraph.addEdge g dst s e) g
      let g =
        match cycleEdge with
        | Some e -> DiGraph.addEdge g dst src e
        | None -> g
      let vertexMap =
        bblMap.VertexMap |> Map.add target src |> Map.add leaderPoint dst
      let bblMap = { bblMap with VertexMap = vertexMap }
      Some (src.VData.PPoint), bblMap, g

  let private splitBlock hdl acc leader edgeInfos =
    (* 1. Remove previous block from bblMap *)
    let prevLeaderInfo, bblMap = removeLeaderInfoByAddr leader acc.BasicBlockMap
    let leaderPoint = ProgramPoint (leader, 0)
    (* 2. Update Graph *)
    let srcPoint, bblMap, g =
      modifyGraph bblMap acc.Graph prevLeaderInfo leaderPoint
    (* 3. Split leaderInfo *)
    let prevInfo, newInfo = splitLeaderInfo prevLeaderInfo leaderPoint
    (* 4. Add leaderInfos *)
    let bblMap = bblMap |> addLeaderInfo prevInfo |> addLeaderInfo newInfo
    (* 5. Update calleeMap *)
    let v = Map.find leaderPoint bblMap.VertexMap
    let calleeMap =
      match v.VData.GetLastStmt (), srcPoint with
      | InterJmp (_, Num addr, InterJmpInfo.IsCall), Some srcPoint ->
        let target = BitVector.toUInt64 addr
        acc.CalleeMap.ReplaceCaller hdl srcPoint.Address leader target
      | _ -> acc.CalleeMap
    let acc =
      { acc with BasicBlockMap = bblMap ; Graph = g ; CalleeMap = calleeMap }
    let edgeInfos =
      List.map (fun (edge, dst) ->
        match edge, srcPoint with
        | Some (srcPoint', edgeKind), Some srcPoint when srcPoint = srcPoint' ->
          Some (leaderPoint, edgeKind), dst
        | _ -> edge, dst) edgeInfos
    acc, edgeInfos

  let rec private getBlockWithInstrMap (instrMap: InstrMap) bblMap acc addr =
    if Map.containsKey addr bblMap.LeaderMap then List.rev acc
    else
      let instr = instrMap.[addr].Instruction
      if instr.IsExit () then List.rev acc
      else
        getBlockWithInstrMap instrMap bblMap acc <| addr + uint64 instr.Length

  let rec private getBlockWithAddrList bblMap acc = function
    | [] -> List.rev acc
    | addr :: addrs ->
      if Map.containsKey addr bblMap.LeaderMap then List.rev acc
      else getBlockWithAddrList bblMap (addr :: acc) addrs

  let private hasNoFallThrough (stmts: Stmt []) =
    if stmts.Length > 0 then
      match stmts.[stmts.Length - 1] with
      | InterJmp (_, _, InterJmpInfo.IsCall) -> false
      | InterJmp (_, _, _)
      | SideEffect (BinIR.Halt) -> true
      | _ -> false
    else false

  /// Construct an InstructionInfo for the given program point (myPoint).
  let private constructInfo (instrMap: InstrMap) ppoint nextLeader =
    match instrMap.TryGetValue ((ppoint: ProgramPoint).Address) with
    | false, _ -> None, nextLeader
    | true, i ->
      if ppoint.Address <> (nextLeader: ProgramPoint).Address then
        let nextInsAddr = i.Instruction.Address + uint64 i.Instruction.Length
        let nextPoint =
          if hasNoFallThrough i.Stmts then nextLeader
          else ProgramPoint (nextInsAddr, 0)
        if ppoint.Position > 0 then
          let delta = i.Stmts.Length - ppoint.Position
          let i' = { i with Stmts = Array.sub i.Stmts ppoint.Position delta }
          Some i', nextPoint
        else Some i, nextPoint
      else (* Intra-instruction case. *)
        let delta = nextLeader.Position - ppoint.Position
        let i' = { i with Stmts = Array.sub i.Stmts ppoint.Position delta }
        Some i', nextLeader

  let rec private gatherBB instrMap boundary leaders acc ppoint nextIdx =
    if nextIdx >= (leaders: ProgramPoint []).Length then
      (* No more leaders after the current. *)
      match (instrMap: InstrMap).TryGetValue (ppoint: ProgramPoint).Address with
      | false, _ -> List.rev acc |> List.toArray
      | true, i ->
        let acc = i :: acc
        let nextInsAddr = i.Instruction.Address + uint64 i.Instruction.Length
        let withinBoundary =
          (boundary: AddrRange).Min <= nextInsAddr && nextInsAddr < boundary.Max
        if withinBoundary then
          let nextPoint = ProgramPoint (nextInsAddr, 0)
          gatherBB instrMap boundary leaders acc nextPoint nextIdx
        else List.rev acc |> List.toArray
    else
      let nextLeader = leaders.[nextIdx]
      if nextLeader > ppoint then
        match constructInfo instrMap ppoint nextLeader with
        | None, _ -> [||]
        | Some info, nextPoint ->
          let acc = info :: acc
          if hasNoFallThrough info.Stmts then List.rev acc |> List.toArray
          else gatherBB instrMap boundary leaders acc nextPoint nextIdx
      elif nextLeader = ppoint then List.rev acc |> List.toArray
      (* Next point is beyond the next leader's point. This is possible when two
         control flows divide an instruction into two parts. This typically
         happens in obfuscated code. *)
      else gatherBB instrMap boundary leaders acc ppoint (nextIdx + 1)

  let private createNode instrMap boundary leaders bbls idx leader =
    let instrs = gatherBB instrMap boundary leaders [] leader (idx + 1)
    let b = IRBasicBlock (instrs, leader)
    Map.add leader b bbls

  let private buildVertices instrMap leaderInfo =
    let irLeaders = Set.toArray leaderInfo.IRLeaders
    irLeaders
    |> Array.foldi (createNode instrMap leaderInfo.Boundary irLeaders) Map.empty
    |> fst

  let getIntraEdge src symbol edgeProp edges =
    let dstPos =
      Map.find symbol (src: Vertex<IRBasicBlock>).VData.LastInsInfo.Labels
    (src.VData.PPoint, dstPos, edgeProp) :: edges

  let private getInterEdge (src: Vertex<IRBasicBlock>) addr edgeProp edges =
    let dstPos = ProgramPoint (addr, 0)
    (src.VData.PPoint, dstPos, edgeProp) :: edges

  let isNoReturn noRetInfo (src: Vertex<IRBasicBlock>) =
    noRetInfo.NoReturnCallSites
    |> Set.contains src.VData.PPoint

  let private getFallthroughEdge src isPseudo edges =
    let last = (src: Vertex<IRBasicBlock>).VData.LastInstruction
    let fallAddr = last.Address + uint64 last.Length
    let edge = if isPseudo then CallFallThroughEdge else FallThroughEdge
    getInterEdge src fallAddr edge edges

  let private getIndirectEdges indMap src isCall edges =
    let srcAddr = (src: Vertex<IRBasicBlock>).VData.PPoint.Address
    match Map.tryFind srcAddr indMap with
    | None ->
      if isCall then
        let fakePos = ProgramPoint.GetFake ()
        (src.VData.PPoint, fakePos, IndirectCallEdge) :: edges
      else edges
    | Some indInfo ->
      let edge = if isCall then IndirectCallEdge else IndirectJmpEdge
      indInfo.TargetAddresses
      |> Set.fold (fun edges target ->
        let targetPoint = ProgramPoint (target, 0)
        (src.VData.PPoint, targetPoint, edge) :: edges) edges

  let private getNextPPoint (src: Vertex<IRBasicBlock>) =
    let ppoints = src.VData.LastInsInfo.IRLeaders
    if Set.isEmpty ppoints then
      let last = src.VData.LastInstruction
      ProgramPoint (last.Address + uint64 last.Length, 0)
    else
      let _, bigger =
        Set.partition (fun ppoint -> ppoint <= src.VData.PPoint) ppoints
      if Set.isEmpty bigger then
        let last = src.VData.LastInstruction
        ProgramPoint (last.Address + uint64 last.Length, 0)
      else Set.minElement bigger

  let getEdges hdl acc edges (src: Vertex<IRBasicBlock>) =
    match src.VData.GetLastStmt () with
    | Jmp (Name s) ->
      acc, getIntraEdge src s IntraJmpEdge edges
    | CJmp (_, Name s1, Name s2) ->
      let edges =
        edges
        |> getIntraEdge src s1 IntraCJmpTrueEdge
        |> getIntraEdge src s2 IntraCJmpFalseEdge
      acc, edges
    | InterJmp (_, _, InterJmpInfo.IsRet) ->
      acc, edges (* Connect ret edges later. *)
    | InterJmp (_, Num addr, InterJmpInfo.IsCall) ->
      let target = BitVector.toUInt64 addr
      let calleeMap = acc.CalleeMap.AddEntry hdl target
      let edges = getInterEdge src target CallEdge edges
      let calleeMap =
        calleeMap.AddCaller hdl src.VData.PPoint.Address target
      let acc = { acc with CalleeMap = calleeMap }
      if isNoReturn acc.NoReturnInfo src then acc, edges
      else acc, getFallthroughEdge src true edges
    | InterJmp (_, Num addr, _) ->
      let edges = getInterEdge src (BitVector.toUInt64 addr) InterJmpEdge edges
      acc, edges
    | InterCJmp (_, _, Num addr1, Num addr2) ->
      let addr1 = BitVector.toUInt64 addr1
      let addr2 = BitVector.toUInt64 addr2
      let edges =
        edges
        |> getInterEdge src addr1 InterCJmpTrueEdge
        |> getInterEdge src addr2 InterCJmpFalseEdge
      acc, edges
    | InterCJmp (_, _, Num addr, _) ->
      src.VData.HasIndirectBranch <- true
      (* Need to connect indirect edge here also *)
      let edges =
        getInterEdge src (BitVector.toUInt64 addr) InterCJmpTrueEdge edges
      acc, edges
    | InterCJmp (_, _, _, Num addr) ->
      src.VData.HasIndirectBranch <- true
      (* Need to connect indirect edge here also *)
      let edges =
        getInterEdge src (BitVector.toUInt64 addr) InterCJmpFalseEdge edges
      acc, edges
    | InterJmp (_, _, InterJmpInfo.IsCall) -> (* Indirect call *)
      src.VData.HasIndirectBranch <- true
      let edges = getIndirectEdges acc.IndirectBranchMap src true edges
      (* XXX: Update callInfo here *)
      if isNoReturn acc.NoReturnInfo src then acc, edges
      else acc, getFallthroughEdge src true edges
    | InterJmp (_)
    | InterCJmp (_) ->
      src.VData.HasIndirectBranch <- true
      acc, getIndirectEdges acc.IndirectBranchMap src false edges
    | SideEffect (BinIR.Halt) -> acc, edges
    | SideEffect (BinIR.SysCall) when isNoReturn acc.NoReturnInfo src ->
      acc, edges
    | _ -> (* Fall through case *)
      let next = getNextPPoint src
      if next.Position = 0 then
        acc, getFallthroughEdge src false edges
      else acc, (src.VData.PPoint, next, IntraJmpEdge) :: edges

  let rec addEdgeLoop hdl acc edgeInfos = function
    | [] -> acc, edgeInfos
    | (srcPoint, dstPoint, e) :: edges when ProgramPoint.IsFake dstPoint ->
      let src = Map.find srcPoint acc.BasicBlockMap.VertexMap
      let bbl = IRBasicBlock ([||], dstPoint)
      let dst, g = DiGraph.addVertex acc.Graph bbl
      let g = DiGraph.addEdge g src dst e
      let acc = { acc with Graph = g }
      addEdgeLoop hdl acc edgeInfos edges
    | (srcPoint, dstPoint, e) :: edges ->
      match Map.tryFind dstPoint acc.BasicBlockMap.VertexMap with
      | Some dst ->
        let src = Map.find srcPoint acc.BasicBlockMap.VertexMap
        let g = DiGraph.addEdge acc.Graph src dst e
        let acc = { acc with Graph = g }
        if DiGraph.getSuccs g dst |> List.isEmpty then
          let acc, edges = getEdges hdl acc edges dst
          addEdgeLoop hdl acc edgeInfos edges
        else addEdgeLoop hdl acc edgeInfos edges
      | None ->
        if dstPoint.Position <> 0 then Utils.impossible ()
        let edgeInfos = (Some (srcPoint, e), dstPoint.Address) :: edgeInfos
        addEdgeLoop hdl acc edgeInfos edges

  let private buildBlock hdl acc leader addrs foundIndJmp edgeInfos edge =
    let lastAddr = List.rev addrs |> List.head
    let last = acc.InstrMap.[lastAddr].Instruction
    let boundary = AddrRange (leader, lastAddr + uint64 last.Length)
    let leaderPoint = ProgramPoint (leader, 0)
    let irLeaders =
      addrs
      |> List.fold (fun irLeaders addr ->
        let insInfo = acc.InstrMap.[addr]
        let leaders =
          Set.filter (fun (ppoint: ProgramPoint) ->
            let addr = ppoint.Address
            boundary.Min <= addr && addr < boundary.Max) insInfo.IRLeaders
        Set.union irLeaders leaders) (Set.singleton leaderPoint)
    let leaderInfo = { Boundary = boundary ; IRLeaders = irLeaders }
    let bblMap = addLeaderInfo leaderInfo acc.BasicBlockMap
    let vertices = buildVertices acc.InstrMap leaderInfo
    let vertexMap, g =
      vertices
      |> Map.fold (fun (vertexMap, g) ppoint bbl ->
        let v, g = DiGraph.addVertex g bbl
        Map.add ppoint v vertexMap, g) (bblMap.VertexMap, acc.Graph)
    let bblMap = { bblMap with VertexMap = vertexMap }
    let acc = { acc with BasicBlockMap = bblMap ; Graph = g }
    let hasIndBranch (bbl: IRBasicBlock) = bbl.HasIndirectBranch
    match edge with
    | Some (src, e) ->
      let acc, edgeInfos = addEdgeLoop hdl acc edgeInfos [(src, leaderPoint, e)]
      let foundIndJmp =
        if Map.exists (fun _ bbl  -> hasIndBranch bbl) vertices then true
        else foundIndJmp
      Ok (acc, foundIndJmp, edgeInfos)
    | None ->
      let acc, edges =
        getEdges hdl acc [] (Map.find leaderPoint acc.BasicBlockMap.VertexMap)
      let acc, edgeInfos = addEdgeLoop hdl acc edgeInfos edges
      let foundIndJmp =
        if Map.exists (fun _ bbl -> hasIndBranch bbl) vertices then true
        else foundIndJmp
      Ok (acc, foundIndJmp, edgeInfos)

  /// First prepare target basic block, then connect it with src block
  let connectLeader hdl parseMode acc foundIndJmp edgeInfo leader edgeInfos =
    (* BBL was already made *)
    if alreadyHasLeader acc.BasicBlockMap leader then
      match edgeInfo with
      | Some (src, e) ->
        let acc, edgeInfos =
          addEdgeLoop hdl acc edgeInfos [(src, ProgramPoint (leader, 0), e)]
        Ok (acc, foundIndJmp, edgeInfos)
      | None -> Ok (acc, foundIndJmp, edgeInfos)
    elif not <| isExecutableLeader hdl leader then Error ()
    elif isOverlap acc.InstrMap acc.BasicBlockMap leader then Error ()
    (* We need to split BBL *)
    elif needToSplit acc.InstrMap acc.BasicBlockMap leader then
      let acc, edgeInfos = splitBlock hdl acc leader edgeInfos
      match edgeInfo with
      | Some (srcPoint, e) ->
        let src = Map.find srcPoint acc.BasicBlockMap.VertexMap
        let dst =
          Map.find (ProgramPoint (leader, 0)) acc.BasicBlockMap.VertexMap
        let g = DiGraph.addEdge acc.Graph src dst e
        let acc = { acc with Graph = g }
        Ok (acc, foundIndJmp, edgeInfos)
      | None -> Ok (acc, foundIndJmp, edgeInfos)
    (* BBL was built before, but it was removed because it was unreachable. In
       this case, we need to reconstruct BBL again *)
    elif isAlreadyParsed acc.InstrMap leader then
      (* Collect instructions to next leader *)
      let block = getBlockWithInstrMap acc.InstrMap acc.BasicBlockMap [] leader
      buildBlock hdl acc leader block foundIndJmp edgeInfos edgeInfo
    (* Need to parse from leader *)
    else
      match InstrMap.parse hdl parseMode acc.InstrMap leader with
      | Ok (instrMap, addrs) ->
        let acc = { acc with InstrMap = instrMap }
        (* Filter addresses because they may overlap with existing basic block
           - fall-through to existing bbl case - *)
        let block = getBlockWithAddrList acc.BasicBlockMap [] addrs
        buildBlock hdl acc leader block foundIndJmp edgeInfos edgeInfo
      | Error _ -> Error ()

  let rec updateCFG hdl parseMode acc foundIndJmp = function
    | [] -> Ok (acc, foundIndJmp)
    | (edge, addr) :: edgeInfos ->
      match connectLeader hdl parseMode acc foundIndJmp edge addr edgeInfos with
      | Ok (acc, foundIndJmp, edgeInfos) ->
        updateCFG hdl parseMode acc foundIndJmp edgeInfos
      | Error () -> Error ()

  let removeNoReturnFallThroughEdges bblMap noRetInfo g =
    noRetInfo.NoReturnCallSites
    |> Set.fold (fun g ppoint ->
      match Map.tryFind ppoint bblMap.VertexMap with
      | None -> g
      | Some v ->
        DiGraph.getSuccs g v
        |> List.fold (fun acc s ->
          if DiGraph.findEdgeData g v s = FallThroughEdge then (v, s) :: acc
          elif DiGraph.findEdgeData g v s = CallFallThroughEdge then
            (v, s) :: acc
          else acc) []
        |> List.fold (fun g (src, dst) -> DiGraph.removeEdge g src dst) g) g

  let getUnreachables bblMap (calleeMap: CalleeMap) g =
    let reachables =
      calleeMap.Entries
      |> Set.fold (fun acc entry ->
        let ppoint = ProgramPoint (entry, 0)
        let v = Map.find ppoint bblMap.VertexMap
        let acc = Set.add ppoint acc
        Traversal.foldPostorder g v (fun acc v ->
          Set.add v.VData.PPoint acc) acc) Set.empty
    let ppoints =
      bblMap.VertexMap
      |> Map.fold (fun acc ppoint _ -> Set.add ppoint acc) Set.empty
    Set.difference ppoints reachables

  let removeNoReturnFallThroughs acc =
    let bblMap = acc.BasicBlockMap
    let g = removeNoReturnFallThroughEdges bblMap acc.NoReturnInfo acc.Graph
    let unreachables = getUnreachables bblMap acc.CalleeMap g
    (* Update calleeMap here *)
    let calleeMap, g =
      unreachables
      |> Set.fold (fun (calleeMap: CalleeMap, g) ppoint ->
        let v = Map.find ppoint bblMap.VertexMap
        let calleeMap =
          match v.VData.GetLastStmt () with
          | InterJmp (_, Num addr, InterJmpInfo.IsCall) ->
            let target = BitVector.toUInt64 addr
            calleeMap.RemoveCaller v.VData.PPoint.Address target
          | InterJmp (_, _, InterJmpInfo.IsCall) -> (* Indirect call *)
            (* XXX: Update callInfo here *)
            calleeMap
          | _ -> calleeMap
        let g = DiGraph.removeVertex g v
        calleeMap, g) (acc.CalleeMap, g)
    let bblMap =
      unreachables
      |> Set.fold (fun bblMap ppoint ->
        let addr = ppoint.Address
        match Map.tryFind addr bblMap.LeaderMap with
        | Some leaderInfo ->
          let boundary = leaderInfo.Boundary
          let newLeaderMap = Map.remove addr bblMap.LeaderMap
          let newBoundaries = IntervalSet.remove boundary bblMap.Boundaries
          let newVertexMap = Map.remove ppoint bblMap.VertexMap
          { bblMap with
              LeaderMap = newLeaderMap
              Boundaries = newBoundaries
              VertexMap = newVertexMap }
        | None ->
          { bblMap with VertexMap = Map.remove ppoint bblMap.VertexMap }) bblMap
    { acc with BasicBlockMap = bblMap ; CalleeMap = calleeMap ; Graph = g }

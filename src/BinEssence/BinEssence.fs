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

namespace B2R2.BinEssence

open B2R2
open B2R2.FrontEnd
open B2R2.BinIR.LowUIR
open B2R2.BinGraph
open System.Collections.Generic
open System.Runtime.InteropServices

/// Raised when the given address is not a start address of a function.
exception InvalidFunctionAddressException

/// <summary>
///   BinEssence is the main corpus of binary, which contains all the essential
///   information about parsed binary instructions, basic blocks, CFGs, as well
///   as intermediary information for recovering CFG. This is the key data
///   structure we maintain throughout the middle-end analyses.
/// </summary>
/// <remarks>
///   <para>B2R2's middle-end analyses roughly work as follows.</para>
///   <para>
///     We first start by creating an empty BinEssence, and recursively parse
///     (and lift) binary instructions starting from basic entry points we
///     obtained from the target binary. In this stage, we simply follow
///     concrete edges (including intra-instruction branches) appeared in
///     LowUIR. Therefore we may miss indirect branches in this stage, but we
///     will handle them later. After parsing all reachable instructions, we
///     obtain a mapping (InstrMap) from an address to an InsInfo.
///   </para>
///   <para>
///     We build the Super Control Flow Graph (SCFG) on the fly, but whenever
///     there is an edge that intersects existing basic block, we will split the
///     block into two.
///   </para>
///   <para>
///     We mark every call target encountered to build both CallerMap and
///     CalleeMap. Normally, being a call target (i.e., callee) implies being a
///     function entry. However, this is not always the case. We should not
///     always consider a callee as a function. Nevertheless, our lens-based
///     framework can provide a valid CFG at any callee, which can greatly help
///     further analyses.
///   </para>
///   <para>
///     Once we obtained basic information, i.e., BinEssence, to work with, we
///     perform some post analyses to improve the information. For example, we
///     remove unnecessary edges from the SCFG by disconnecting return edges
///     from a function that termiates the process (e.g., exit function), and we
///     recover indirect branch targets to discover more instructions. After the
///     post analyses, we may or may not have an updated Apparatus, in which
///     case we rerun the above steps to update our SCFG (with newly found
///     instructions, etc.).
///   </para>
/// </remarks>
type BinEssence = {
  BinHandler: BinHandler
  InstrMap: InstrMap
  BBLInfo: BBLInfo
  CalleeMap: CalleeMap
  SCFG: DiGraph<IRBasicBlock, CFGEdgeKind>
  NoReturnInfo: NoReturnInfo
  IndirectBranchMap: Map<Addr, IndirectBranchInfo>
  IgnoreIllegal: bool
}
with
  member __.IsNoReturn (src: Vertex<IRBasicBlock>) =
    __.NoReturnInfo.NoReturnCallSites
    |> Set.contains src.VData.PPoint

  /// Retrieve an IR-based CFG (subgraph) of a function starting at the given
  /// address (addr) from the SCFG, and the root node. When the
  /// preserveRecursiveEdge parameter is false, we create fake blocks for
  /// recursive calls, which is useful for intra-procedural analyses.
  member __.GetFunctionCFG (addr: Addr,
                            [<Optional; DefaultParameterValue(true)>]
                            preserveRecursiveEdge) =
    let newGraph = IRCFG.init PersistentGraph
    let vMap = Dictionary<ProgramPoint, Vertex<IRBasicBlock>> ()
    let visited = HashSet<ProgramPoint> ()
    let rec loop newGraph pos =
      if visited.Contains pos then newGraph
      else
        visited.Add pos |> ignore
        getVertex newGraph pos
        |> foldSuccessors (Map.find pos __.BBLInfo.VertexMap)
    and getVertex newGraph pos =
      match vMap.TryGetValue pos with
      | true, v -> v, newGraph
      | false, _ ->
        let oldV = Map.find pos __.BBLInfo.VertexMap
        let v, newGraph = DiGraph.addVertex newGraph oldV.VData
        vMap.[pos] <- v
        v, newGraph
    and foldSuccessors origVertex (curVertex, newGraph) =
      DiGraph.getSuccs __.SCFG origVertex
      |> List.fold (fun newGraph succ ->
        __.SCFG.FindEdgeData origVertex succ
        |> addEdge newGraph curVertex succ) newGraph
    and addEdge newGraph parent child e =
      match e with
      | ExternalCallEdge | ExternalJmpEdge | RetEdge | ImplicitCallEdge ->
        newGraph
      | CallEdge
        when preserveRecursiveEdge && child.VData.PPoint.Address = addr ->
        let child, newGraph = getVertex newGraph child.VData.PPoint
        DiGraph.addEdge newGraph parent child RecursiveCallEdge
      | CallEdge | IndirectCallEdge ->
        let last = parent.VData.LastInstruction
        let fallPp = ProgramPoint (last.Address + uint64 last.Length, 0)
        let childPp =
          if child.VData.IsFakeBlock () then ProgramPoint.GetFake ()
          else child.VData.PPoint
        let fake = IRBasicBlock ([||], childPp)
        let child, newGraph = DiGraph.addVertex newGraph fake
        let newGraph = DiGraph.addEdge newGraph parent child e
        if __.IsNoReturn parent then newGraph
        else
          try
            let fall, newGraph = getVertex newGraph fallPp
            DiGraph.addEdge newGraph child fall RetEdge
          with :? KeyNotFoundException ->
#if DEBUG
            printfn "[W] Illegal fall-through edge (%x) ignored." fallPp.Address
#endif
            newGraph
      | InterJmpEdge ->
        if __.CalleeMap.Contains child.VData.PPoint.Address then
          let childPp = child.VData.PPoint
          let fake = IRBasicBlock ([||], childPp)
          let child, newGraph = DiGraph.addVertex newGraph fake
          DiGraph.addEdge newGraph parent child CallEdge
        else
          let child, newGraph = getVertex newGraph child.VData.PPoint
          let newGraph = DiGraph.addEdge newGraph parent child e
          loop newGraph child.VData.PPoint
      | _ ->
        let child, newGraph = getVertex newGraph child.VData.PPoint
        let newGraph = DiGraph.addEdge newGraph parent child e
        loop newGraph child.VData.PPoint
    if __.CalleeMap.Contains addr then
      let rootPos = ProgramPoint (addr, 0)
      let newGraph = loop newGraph rootPos
      newGraph, vMap.[rootPos]
    else raise InvalidFunctionAddressException

  member private __.ReverseLookUp src =
    let queue = Queue<Vertex<IRBasicBlock>> ([ src ])
    let visited = HashSet<Vertex<IRBasicBlock>> ()
    let rec loop () =
      if queue.Count = 0 then None
      else
        let v = queue.Dequeue ()
        if visited.Contains v then loop ()
        else
          visited.Add v |> ignore
          let addr = v.VData.PPoint.Address
          if __.CalleeMap.Contains addr then Some v
          else
            DiGraph.getPreds __.SCFG v
            |> List.iter (fun v ->
              if visited.Contains v then ()
              else queue.Enqueue (v))
            loop ()
    loop ()

  /// Find a basic block (vertex) in the SCFG that the given address belongs to.
  member __.FindVertex (addr) =
    let bblInfo = __.BBLInfo
    bblInfo.Boundaries
    |> IntervalSet.findAll (AddrRange (addr, addr + 1UL))
    |> List.map (fun r -> ProgramPoint (AddrRange.GetMin r, 0))
    |> List.sortBy (fun p -> if p.Address = addr then -1 else 1)
    |> List.choose (fun p -> Map.tryFind p bblInfo.VertexMap)
    |> List.tryHead

  /// For a given address, find the first vertex of a function that the address
  /// belongs to.
  member __.FindFunctionVertex (addr) =
    let bblInfo = __.BBLInfo
    IntervalSet.findAll (AddrRange (addr, addr + 1UL)) bblInfo.Boundaries
    |> List.map (fun r ->
      let addr = AddrRange.GetMin r
      Map.find (ProgramPoint (addr, 0)) bblInfo.VertexMap)
    |> List.tryPick __.ReverseLookUp

[<RequireQualifiedAccess>]
module BinEssence =

  let private getBoundary bblInfo addr =
    match IntervalSet.tryFindByAddr addr bblInfo.Boundaries with
    | Some range -> range
    | None -> Utils.impossible ()

  let private addLeaderInfo leaderInfo bblInfo =
    let boundary = leaderInfo.Boundary
    { bblInfo with
        LeaderMap = Map.add boundary.Min leaderInfo bblInfo.LeaderMap
        Boundaries = IntervalSet.add boundary bblInfo.Boundaries }

  let private removeLeaderInfoByAddr addr bblInfo =
    let boundary = getBoundary bblInfo addr
    let leaderInfo = Map.find boundary.Min bblInfo.LeaderMap
    let bblInfo =
      { bblInfo with
          LeaderMap = Map.remove boundary.Min bblInfo.LeaderMap
          Boundaries = IntervalSet.remove boundary bblInfo.Boundaries }
    leaderInfo, bblInfo

  let inline private alreadyHasLeader bblInfo leader =
    Map.containsKey leader bblInfo.LeaderMap

  let inline private isExecutableLeader hdl leader =
    hdl.FileInfo.IsExecutableAddr leader

  /// If a leader points already covered area but not a starting address of an
  /// instruction, then it means overlap.
  let inline private isOverlap (instrMap: InstrMap) bblInfo leader =
    not <| instrMap.ContainsKey leader &&
      IntervalSet.containsAddr leader bblInfo.Boundaries

  let inline private needToSplit (instrMap: InstrMap) bblInfo leader =
    (* Maybe this condition is redundant because of isOverlap*)
    instrMap.ContainsKey leader &&
      IntervalSet.containsAddr leader bblInfo.Boundaries

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
    let prevInfo = { Boundary = prevBoundary; IRLeaders = prevIRLeaders }
    let newInfo = { Boundary = newBoundary; IRLeaders = newIRLeaders }
    prevInfo, newInfo

  let private modifyGraph bblInfo g prevLeaderInfo leaderPoint =
    let irLeaders = prevLeaderInfo.IRLeaders
    (* Nothing to do *)
    if Set.contains leaderPoint prevLeaderInfo.IRLeaders then None, bblInfo, g
    else
      let target =
        Set.partition (fun ppoint -> ppoint < leaderPoint) irLeaders
        |> fst |> Set.maxElement
      let targetV = Map.find target bblInfo.VertexMap
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
      let bblInfo =
        { bblInfo with
            VertexMap = Map.remove target bblInfo.VertexMap }
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
        bblInfo.VertexMap |> Map.add target src |> Map.add leaderPoint dst
      let bblInfo = { bblInfo with VertexMap = vertexMap }
      Some (src.VData.PPoint), bblInfo, g

  let private splitBlock ess leader edgeInfos =
    (* 1. Remove previous block from bblInfo *)
    let prevLeaderInfo, bblInfo = removeLeaderInfoByAddr leader ess.BBLInfo
    let leaderPoint = ProgramPoint (leader, 0)
    (* 2. Update Graph *)
    let srcPoint, bblInfo, g =
      modifyGraph bblInfo ess.SCFG prevLeaderInfo leaderPoint
    (* 3. Split leaderInfo *)
    let prevInfo, newInfo = splitLeaderInfo prevLeaderInfo leaderPoint
    (* 4. Add leaderInfos *)
    let bblInfo = bblInfo |> addLeaderInfo prevInfo |> addLeaderInfo newInfo
    (* 5. Update calleeMap *)
    let v = Map.find leaderPoint bblInfo.VertexMap
    let calleeMap =
      match v.VData.GetLastStmt (), srcPoint with
      | InterJmp (_, Num addr, InterJmpInfo.IsCall), Some srcPoint ->
        let target = BitVector.toUInt64 addr
        ess.CalleeMap.ReplaceCaller
          ess.BinHandler srcPoint.Address leader target
      | _ -> ess.CalleeMap
    let ess =
      { ess with BBLInfo = bblInfo; SCFG = g; CalleeMap = calleeMap }
    let edgeInfos =
      List.map (fun (edge, dst) ->
        match edge, srcPoint with
        | Some (srcPoint', edgeKind), Some srcPoint when srcPoint = srcPoint' ->
          Some (leaderPoint, edgeKind), dst
        | _ -> edge, dst) edgeInfos
    ess, edgeInfos

  let rec private getBlockWithInstrMap ess addrs addr =
    if Map.containsKey addr ess.BBLInfo.LeaderMap then List.rev addrs
    else
      let instr = ess.InstrMap.[addr].Instruction
      if instr.IsExit () then List.rev (addr :: addrs)
      else
        getBlockWithInstrMap ess (addr :: addrs) <| addr + uint64 instr.Length

  let rec private getBlockWithAddrList leaderMap acc = function
    | [] -> List.rev acc
    | addr :: addrs ->
      if Map.containsKey addr leaderMap then List.rev acc
      else getBlockWithAddrList leaderMap (addr :: acc) addrs

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
    let nextLeader =
      if nextIdx >= (leaders: ProgramPoint []).Length then
        ProgramPoint ((boundary: AddrRange).Max, 0)
      else leaders.[nextIdx]
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

  let getEdges ess edges (src: Vertex<IRBasicBlock>) =
    match src.VData.GetLastStmt () with
    | Jmp (Name s) ->
      ess, getIntraEdge src s IntraJmpEdge edges
    | CJmp (_, Name s1, Name s2) ->
      let edges =
        edges
        |> getIntraEdge src s1 IntraCJmpTrueEdge
        |> getIntraEdge src s2 IntraCJmpFalseEdge
      ess, edges
    | CJmp (_, Name s1, Undefined _) ->
      ess, getIntraEdge src s1 IntraCJmpTrueEdge edges
    | CJmp (_, Undefined _, Name s2) ->
      ess, getIntraEdge src s2 IntraCJmpFalseEdge edges
    | InterJmp (_, _, InterJmpInfo.IsRet) ->
      ess, edges (* Connect ret edges later. *)
    | InterJmp (_, Num addr, InterJmpInfo.IsCall) ->
      let target = BitVector.toUInt64 addr
      let calleeMap = ess.CalleeMap.AddEntry ess.BinHandler target
      let edges = getInterEdge src target CallEdge edges
      let calleeMap =
        calleeMap.AddCaller ess.BinHandler src.VData.PPoint.Address target
      let ess = { ess with CalleeMap = calleeMap }
      if ess.IsNoReturn src then ess, edges
      else ess, getFallthroughEdge src true edges
    | InterJmp (_, Num addr, _) ->
      let edges = getInterEdge src (BitVector.toUInt64 addr) InterJmpEdge edges
      ess, edges
    | InterCJmp (_, _, Num addr1, Num addr2) ->
      let addr1 = BitVector.toUInt64 addr1
      let addr2 = BitVector.toUInt64 addr2
      let edges =
        edges
        |> getInterEdge src addr1 InterCJmpTrueEdge
        |> getInterEdge src addr2 InterCJmpFalseEdge
      ess, edges
    | InterCJmp (_, _, Num addr, _) ->
      src.VData.HasIndirectBranch <- true
      (* Need to connect indirect edge here also *)
      let edges =
        getInterEdge src (BitVector.toUInt64 addr) InterCJmpTrueEdge edges
      ess, edges
    | InterCJmp (_, _, _, Num addr) ->
      src.VData.HasIndirectBranch <- true
      (* Need to connect indirect edge here also *)
      let edges =
        getInterEdge src (BitVector.toUInt64 addr) InterCJmpFalseEdge edges
      ess, edges
    | InterJmp (_, _, InterJmpInfo.IsCall) -> (* Indirect call *)
      src.VData.HasIndirectBranch <- true
      let edges = getIndirectEdges ess.IndirectBranchMap src true edges
      (* XXX: Update callInfo here *)
      if ess.IsNoReturn src then ess, edges
      else ess, getFallthroughEdge src true edges
    | InterJmp (_)
    | InterCJmp (_) ->
      src.VData.HasIndirectBranch <- true
      ess, getIndirectEdges ess.IndirectBranchMap src false edges
    | SideEffect (BinIR.Halt) -> ess, edges
    | SideEffect (BinIR.SysCall) when ess.IsNoReturn src ->
      ess, edges
    | _ -> (* Fall through case *)
      let next = getNextPPoint src
      if next.Position = 0 then
        ess, getFallthroughEdge src false edges
      else ess, (src.VData.PPoint, next, IntraJmpEdge) :: edges

  let rec addEdgeLoop ess edgeInfos = function
    | [] -> ess, edgeInfos
    | (srcPoint, dstPoint, e) :: edges when ProgramPoint.IsFake dstPoint ->
      let src = Map.find srcPoint ess.BBLInfo.VertexMap
      let bbl = IRBasicBlock ([||], dstPoint)
      let dst, g = DiGraph.addVertex ess.SCFG bbl
      let g = DiGraph.addEdge g src dst e
      addEdgeLoop { ess with SCFG = g } edgeInfos edges
    | (srcPoint, dstPoint, e) :: edges ->
      match Map.tryFind dstPoint ess.BBLInfo.VertexMap with
      | Some dst ->
        let src = Map.find srcPoint ess.BBLInfo.VertexMap
        let g = DiGraph.addEdge ess.SCFG src dst e
        let ess = { ess with SCFG = g }
        if DiGraph.getSuccs g dst |> List.isEmpty then
          let ess, edges = getEdges ess edges dst
          addEdgeLoop ess edgeInfos edges
        else addEdgeLoop ess edgeInfos edges
      | None ->
        if dstPoint.Position <> 0 then Utils.impossible ()
        let edgeInfos = (Some (srcPoint, e), dstPoint.Address) :: edgeInfos
        addEdgeLoop ess edgeInfos edges

  let private buildBlock ess leader addrs foundIndJmp edgeInfos edge =
    let lastAddr = List.rev addrs |> List.head
    let last = ess.InstrMap.[lastAddr].Instruction
    let boundary = AddrRange (leader, lastAddr + uint64 last.Length)
    let leaderPoint = ProgramPoint (leader, 0)
    let irLeaders =
      addrs
      |> List.fold (fun irLeaders addr ->
        let insInfo = ess.InstrMap.[addr]
        let leaders =
          Set.filter (fun (ppoint: ProgramPoint) ->
            let addr = ppoint.Address
            boundary.Min <= addr && addr < boundary.Max) insInfo.IRLeaders
        Set.union irLeaders leaders) (Set.singleton leaderPoint)
    let leaderInfo = { Boundary = boundary; IRLeaders = irLeaders }
    let bblInfo = addLeaderInfo leaderInfo ess.BBLInfo
    let vertices = buildVertices ess.InstrMap leaderInfo
    let vertexMap, g =
      vertices
      |> Map.fold (fun (vertexMap, g) ppoint bbl ->
        let v, g = DiGraph.addVertex g bbl
        Map.add ppoint v vertexMap, g) (bblInfo.VertexMap, ess.SCFG)
    let bblInfo = { bblInfo with VertexMap = vertexMap }
    let ess = { ess with BBLInfo = bblInfo; SCFG = g }
    let hasIndBranch (bbl: IRBasicBlock) = bbl.HasIndirectBranch
    match edge with
    | Some (src, e) ->
      let ess, edgeInfos = addEdgeLoop ess edgeInfos [(src, leaderPoint, e)]
      let foundIndJmp =
        if Map.exists (fun _ bbl  -> hasIndBranch bbl) vertices then true
        else foundIndJmp
      Ok (ess, foundIndJmp, edgeInfos)
    | None ->
      let ess, edges =
        getEdges ess [] (Map.find leaderPoint ess.BBLInfo.VertexMap)
      let ess, edgeInfos = addEdgeLoop ess edgeInfos edges
      let foundIndJmp =
        if Map.exists (fun _ bbl -> hasIndBranch bbl) vertices then true
        else foundIndJmp
      Ok (ess, foundIndJmp, edgeInfos)

  /// First prepare target basic block, then connect it with src block
  let connectLeader ess parseMode foundIndJmp edgeInfo leader edgeInfos =
    (* BBL was already made *)
    if alreadyHasLeader ess.BBLInfo leader then
      match edgeInfo with
      | Some (src, e) ->
        let ess, edgeInfos =
          addEdgeLoop ess edgeInfos [(src, ProgramPoint (leader, 0), e)]
        Ok (ess, foundIndJmp, edgeInfos)
      | None -> Ok (ess, foundIndJmp, edgeInfos)
    elif not <| isExecutableLeader ess.BinHandler leader then Error ()
    elif isOverlap ess.InstrMap ess.BBLInfo leader then Error ()
    (* We need to split BBL *)
    elif needToSplit ess.InstrMap ess.BBLInfo leader then
      let ess, edgeInfos = splitBlock ess leader edgeInfos
      match edgeInfo with
      | Some (srcPoint, e) ->
        let src = Map.find srcPoint ess.BBLInfo.VertexMap
        let dst =
          Map.find (ProgramPoint (leader, 0)) ess.BBLInfo.VertexMap
        let g = DiGraph.addEdge ess.SCFG src dst e
        let ess = { ess with SCFG = g }
        Ok (ess, foundIndJmp, edgeInfos)
      | None -> Ok (ess, foundIndJmp, edgeInfos)
    (* BBL was built before, but it was removed because it was unreachable. In
       this case, we need to reconstruct BBL again *)
    elif isAlreadyParsed ess.InstrMap leader then
      (* Collect instructions to next leader *)
      let block = getBlockWithInstrMap ess [] leader
      buildBlock ess leader block foundIndJmp edgeInfos edgeInfo
    (* Need to parse from leader *)
    else
      match InstrMap.parse ess.BinHandler parseMode ess.InstrMap leader with
      | Ok (instrMap, addrs) ->
        let ess = { ess with InstrMap = instrMap }
        (* Filter addresses because they may overlap with existing basic block
           - fall-through to existing bbl case - *)
        let block = getBlockWithAddrList ess.BBLInfo.LeaderMap [] addrs
        buildBlock ess leader block foundIndJmp edgeInfos edgeInfo
      | Error _ -> Error ()

  let rec updateCFG ess parseMode foundIndJmp = function
    | [] -> Ok (ess, foundIndJmp)
    | (edge, addr) :: edgeInfos ->
      match connectLeader ess parseMode foundIndJmp edge addr edgeInfos with
      | Ok (ess, foundIndJmp, edgeInfos) ->
        updateCFG ess parseMode foundIndJmp edgeInfos
      | Error () -> Error ()

  let private removeNoReturnFallThroughEdges ess =
    let bblInfo = ess.BBLInfo
    ess.NoReturnInfo.NoReturnCallSites
    |> Set.fold (fun g ppoint ->
      match Map.tryFind ppoint bblInfo.VertexMap with
      | None -> g
      | Some v ->
        DiGraph.getSuccs g v
        |> List.fold (fun acc s ->
          if DiGraph.findEdgeData g v s = FallThroughEdge then (v, s) :: acc
          elif DiGraph.findEdgeData g v s = CallFallThroughEdge then
            (v, s) :: acc
          else acc) []
        |> List.fold (fun g (src, dst) ->
          DiGraph.removeEdge g src dst) g) ess.SCFG

  let private getUnreachables bblInfo (calleeMap: CalleeMap) g =
    let reachables =
      calleeMap.Entries
      |> Set.fold (fun acc entry ->
        let ppoint = ProgramPoint (entry, 0)
        let v = Map.find ppoint bblInfo.VertexMap
        let acc = Set.add ppoint acc
        Traversal.foldPostorder g v (fun acc v ->
          Set.add v.VData.PPoint acc) acc) Set.empty
    let ppoints =
      bblInfo.VertexMap
      |> Map.fold (fun acc ppoint _ -> Set.add ppoint acc) Set.empty
    Set.difference ppoints reachables

  let private removeNoReturnFallThroughs ess =
    let bblInfo = ess.BBLInfo
    let g = removeNoReturnFallThroughEdges ess
    let unreachables = getUnreachables bblInfo ess.CalleeMap g
    (* Update calleeMap here *)
    let calleeMap, g =
      unreachables
      |> Set.fold (fun (calleeMap: CalleeMap, g) ppoint ->
        let v = Map.find ppoint bblInfo.VertexMap
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
        calleeMap, g) (ess.CalleeMap, g)
    let bblInfo =
      unreachables
      |> Set.fold (fun bblInfo ppoint ->
        let addr = ppoint.Address
        match Map.tryFind addr bblInfo.LeaderMap with
        | Some leaderInfo ->
          let boundary = leaderInfo.Boundary
          let newLeaderMap = Map.remove addr bblInfo.LeaderMap
          let newBoundaries = IntervalSet.remove boundary bblInfo.Boundaries
          let newVertexMap = Map.remove ppoint bblInfo.VertexMap
          { bblInfo with
              LeaderMap = newLeaderMap
              Boundaries = newBoundaries
              VertexMap = newVertexMap }
        | None ->
          { bblInfo with
              VertexMap = Map.remove ppoint bblInfo.VertexMap }) bblInfo
    { ess with BBLInfo = bblInfo; CalleeMap = calleeMap; SCFG = g }

  [<CompiledName("AddEntry")>]
  let addEntry ess parseMode entry =
    let ess =
      { ess with CalleeMap = ess.CalleeMap.AddEntry ess.BinHandler entry }
    match updateCFG ess parseMode false [(None, entry)] with
    | Ok (ess, _) -> Ok ess
    | Error () -> if ess.IgnoreIllegal then Error () else Utils.impossible ()

  [<CompiledName("AddEntries")>]
  let addEntries ess parseMode entries =
    entries
    |> Set.fold (fun ess entry ->
      match ess with
      | Ok ess -> addEntry ess parseMode entry
      | _ -> ess) (Ok ess)

  [<CompiledName("AddEdge")>]
  let addEdge ess parseMode src dst edgeKind =
    let edgeInfo = Some (ProgramPoint (src, 0), edgeKind), dst
    match updateCFG ess parseMode false [edgeInfo] with
    | Ok (ess, hasNewIndBranch) -> Ok (ess, hasNewIndBranch)
    | Error () -> if ess.IgnoreIllegal then Error () else Utils.impossible ()

  [<CompiledName("AddNoReturnInfo")>]
  let addNoReturnInfo ess noRetFuncs noRetCallSites =
    let noRetInfo = ess.NoReturnInfo
    let noRetFuncs = Set.union noRetFuncs noRetInfo.NoReturnFuncs
    let noRetCallSites = Set.union noRetCallSites noRetInfo.NoReturnCallSites
    let noRetInfo = NoReturnInfo.Init noRetFuncs noRetCallSites
    removeNoReturnFallThroughs { ess with NoReturnInfo = noRetInfo }

  [<CompiledName("AddIndirectBranchMap")>]
  let addIndirectBranchMap ess indMap' =
    let indMap = ess.IndirectBranchMap
    let indMap =
      indMap' |> Map.fold (fun m addr info -> Map.add addr info m) indMap
    { ess with IndirectBranchMap = indMap }

  /// This function returns an initial sequence of entry points obtained from
  /// the binary itself (e.g., from its symbol information). Therefore, if the
  /// binary is stripped, the returned sequence will be incomplete, and we need
  /// to expand it during the other analyses.
  let private getInitialEntryPoints hdl =
    let fi = hdl.FileInfo
    fi.GetFunctionAddresses ()
    |> Set.ofSeq
    |> fun set ->
      match fi.EntryPoint with
      | None -> set
      | Some entry -> Set.add entry set

  let private initialize hdl ignoreIllegal =
    { BinHandler = hdl
      InstrMap = InstrMap ()
      BBLInfo = BBLInfo.Init ()
      CalleeMap = CalleeMap (hdl)
      SCFG = IRCFG.init PersistentGraph
      NoReturnInfo = NoReturnInfo.Init Set.empty Set.empty
      IndirectBranchMap = Map.empty
      IgnoreIllegal = defaultArg ignoreIllegal true }

  [<CompiledName("Init")>]
  let init hdl =
    let ess = initialize hdl None
    match getInitialEntryPoints hdl |> addEntries ess None with
    | Ok ess -> ess
    | Error _ -> Utils.impossible ()

  [<CompiledName("InitByEntries")>]
  let initByEntries hdl entries =
    let ess = initialize hdl None
    addEntries ess None entries

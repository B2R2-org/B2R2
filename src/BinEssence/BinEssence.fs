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
  BBLStore: BBLStore
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
        |> foldSuccessors (Map.find pos __.BBLStore.VertexMap)
    and getVertex newGraph pos =
      match vMap.TryGetValue pos with
      | true, v -> v, newGraph
      | false, _ ->
        let oldV = Map.find pos __.BBLStore.VertexMap
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
    let bbls = __.BBLStore
    bbls.Boundaries
    |> IntervalSet.findAll (AddrRange (addr, addr + 1UL))
    |> List.map (fun r -> ProgramPoint (AddrRange.GetMin r, 0))
    |> List.sortBy (fun p -> if p.Address = addr then -1 else 1)
    |> List.choose (fun p -> Map.tryFind p bbls.VertexMap)
    |> List.tryHead

  /// For a given address, find the first vertex of a function that the address
  /// belongs to.
  member __.FindFunctionVertex (addr) =
    let bbls = __.BBLStore
    IntervalSet.findAll (AddrRange (addr, addr + 1UL)) bbls.Boundaries
    |> List.map (fun r ->
      let addr = AddrRange.GetMin r
      Map.find (ProgramPoint (addr, 0)) bbls.VertexMap)
    |> List.tryPick __.ReverseLookUp

[<RequireQualifiedAccess>]
module BinEssence =

  let private getBoundary bbls addr =
    match IntervalSet.tryFindByAddr addr bbls.Boundaries with
    | Some range -> range
    | None -> Utils.impossible ()

  let private removeBBLInfo addr bbls =
    let boundary = getBoundary bbls addr
    let bblInfo = Map.find boundary.Min bbls.BBLMap
    let bbls =
      { bbls with
          BBLMap = Map.remove boundary.Min bbls.BBLMap
          Boundaries = IntervalSet.remove boundary bbls.Boundaries }
    struct (bblInfo, bbls)

  let private addBBLInfo bblInfo bbls =
    let boundary = bblInfo.Boundary
    { bbls with
        BBLMap = Map.add boundary.Min bblInfo bbls.BBLMap
        Boundaries = IntervalSet.add boundary bbls.Boundaries }

  let inline private bblExists bbls addr =
    Map.containsKey addr bbls.BBLMap

  let inline private isExecutableLeader hdl addr =
    hdl.FileInfo.IsExecutableAddr addr

  let inline private isIntruding bbls leader =
    IntervalSet.containsAddr leader bbls.Boundaries

  let inline private isKnownInstruction (instrMap: InstrMap) leader =
    instrMap.ContainsKey leader

  let private computeNeighbors g targetV =
    let incomings, cycleEdge =
      DiGraph.getPreds g targetV
      |> List.fold (fun (incomings, cycleEdge) p ->
        let e = DiGraph.findEdgeData g p targetV
        if p.GetID () = targetV.GetID () then incomings, Some e
        else (p, e) :: incomings, cycleEdge) ([], None)
    let outgoings =
      DiGraph.getSuccs g targetV
      |> List.fold (fun outgoings s ->
        let e = DiGraph.findEdgeData g targetV s
        if s.GetID () = targetV.GetID () then outgoings
        else (s, e) :: outgoings) []
    struct (incomings, outgoings, cycleEdge)

  let splitIRBBlock g targetV (splitPoint: ProgramPoint) =
    let insInfos = (targetV: Vertex<IRBasicBlock>).VData.GetInsInfos ()
    let srcInfos, dstInfos =
      insInfos
      |> Array.partition (fun insInfo ->
        insInfo.Instruction.Address < splitPoint.Address)
    let srcBlk = IRBasicBlock (srcInfos, targetV.VData.PPoint)
    let dstBlk = IRBasicBlock (dstInfos, splitPoint)
    let src, g = DiGraph.addVertex g srcBlk
    let dst, g = DiGraph.addVertex g dstBlk
    let g = DiGraph.addEdge g src dst FallThroughEdge
    struct (src, dst, g)

  let private updateIRCFG bbls g prevBBL splitPoint target =
    if Set.contains splitPoint prevBBL.Leaders then
      (* The split point was one of the known IR-level leaders. So, we don't
         need to further split the vertex. *)
      struct (None, bbls, g)
    else
      let targetV = Map.find target bbls.VertexMap
      let struct (ins, outs, cycleEdge) = computeNeighbors g targetV
      let g = DiGraph.removeVertex g targetV
      let bbls = { bbls with VertexMap = Map.remove target bbls.VertexMap }
      let struct (src, dst, g) = splitIRBBlock g targetV splitPoint
      let g = ins |> List.fold (fun g (p, e) -> DiGraph.addEdge g p src e) g
      let g = outs |> List.fold (fun g (s, e) -> DiGraph.addEdge g dst s e) g
      let g =
        match cycleEdge with
        | Some e -> DiGraph.addEdge g dst src e
        | None -> g
      let vertexMap =
        bbls.VertexMap |> Map.add target src |> Map.add splitPoint dst
      let bbls = { bbls with VertexMap = vertexMap }
      struct (Some target, bbls, g)

  let private splitBBLInfo prevBBL fsts snds splitAddr bbls =
    let oldBoundary = prevBBL.Boundary
    let prevBoundary = AddrRange (oldBoundary.Min, splitAddr)
    let newBoundary = AddrRange (splitAddr, oldBoundary.Max)
    let prevInfo = { Boundary = prevBoundary; Leaders = fsts }
    let newInfo = { Boundary = newBoundary; Leaders = snds }
    bbls
    |> addBBLInfo prevInfo
    |> addBBLInfo newInfo

  let private updateCalleeMap ess bbls splitPoint fstLeader =
    let v = Map.find splitPoint bbls.VertexMap
    match v.VData.GetLastStmt (), (fstLeader: ProgramPoint option) with
    | InterJmp (_, Num addr, InterJmpInfo.IsCall), Some fstLeader ->
      let target = BitVector.toUInt64 addr
      ess.CalleeMap.ReplaceCaller
        ess.BinHandler fstLeader.Address splitPoint.Address target
    | _ -> ess.CalleeMap

  /// Split a block into two (by the given leader address).
  let private splitBlock ess leader elms =
    let splitPoint = ProgramPoint (leader, 0)
    (* 1. Remove previous block from bbls *)
    let struct (prevBBL, bbls) = removeBBLInfo leader ess.BBLStore
    (* 2. Split IR-level leaders into two: fsts (first leaders) and snds. *)
    let fsts, snds = Set.partition (fun pp -> pp < splitPoint) prevBBL.Leaders
    let snds = Set.add splitPoint snds
    (* 3. Update IR-level Graph *)
    let struct (fstLeader, bbls, g) =
      updateIRCFG bbls ess.SCFG prevBBL splitPoint (Set.maxElement fsts)
    (* 4. Split bblInfo *)
    let bbls = splitBBLInfo prevBBL fsts snds splitPoint.Address bbls
    (* 5. Update calleeMap *)
    let calleeMap = updateCalleeMap ess bbls splitPoint fstLeader
    let ess = { ess with BBLStore = bbls; SCFG = g; CalleeMap = calleeMap }
    let elms =
      List.map (fun elm ->
        match elm, fstLeader with
        | CFGEdge (src, edge, dst), Some fstLeader when fstLeader = src ->
          CFGEdge (splitPoint, edge, dst)
        | elm, _ -> elm) elms
    ess, elms

  let private hasNoFallThrough (stmts: Stmt []) =
    if stmts.Length > 0 then
      match stmts.[stmts.Length - 1] with
      | InterJmp (_, _, InterJmpInfo.IsCall) -> false
      | InterJmp (_, _, _)
      | SideEffect (BinIR.Halt)
      | SideEffect (BinIR.UndefinedInstr) -> true
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
    IRBasicBlock (instrs, leader) :: bbls

  let private buildVertices instrMap bblInfo =
    let pps = Set.toArray bblInfo.Leaders
    Array.foldi (createNode instrMap bblInfo.Boundary pps) [] pps
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
    let ppoints = src.VData.LastInsInfo.ReachablePPs
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
    | SideEffect (BinIR.SysCall) when ess.IsNoReturn src -> ess, edges
    | SideEffect (BinIR.Halt)
    | SideEffect (BinIR.UndefinedInstr) -> ess, edges
    | _ -> (* Fall through case *)
      let next = getNextPPoint src
      if next.Position = 0 then
        ess, getFallthroughEdge src false edges
      else ess, (src.VData.PPoint, next, IntraJmpEdge) :: edges

  let rec internal addEdgeLoop ess elms = function
    | [] -> ess, elms
    | (srcPoint, dstPoint, e) :: edges when ProgramPoint.IsFake dstPoint ->
      let src = Map.find srcPoint ess.BBLStore.VertexMap
      let bbl = IRBasicBlock ([||], dstPoint)
      let dst, g = DiGraph.addVertex ess.SCFG bbl
      let g = DiGraph.addEdge g src dst e
      addEdgeLoop { ess with SCFG = g } elms edges
    | (srcPoint, dstPoint, e) :: edges ->
      match Map.tryFind dstPoint ess.BBLStore.VertexMap with
      | Some dst ->
        let src = Map.find srcPoint ess.BBLStore.VertexMap
        let g = DiGraph.addEdge ess.SCFG src dst e
        let ess = { ess with SCFG = g }
        if DiGraph.getSuccs g dst |> List.isEmpty then
          let ess, edges = getEdges ess edges dst
          addEdgeLoop ess elms edges
        else addEdgeLoop ess elms edges
      | None -> (* Put edge info to elms as we didn't create the dst yet. *)
        if dstPoint.Position <> 0 then Utils.impossible () else ()
        let elms = CFGEdge (srcPoint, e, dstPoint.Address) :: elms
        addEdgeLoop ess elms edges

  let private connectEdges ess elms vertices edges foundIndJmp =
    let ess, elms = addEdgeLoop ess elms edges
    let foundIndJmp =
      if List.exists (fun (bbl: IRBasicBlock) -> bbl.HasIndirectBranch) vertices
      then true
      else foundIndJmp
    Ok <| struct (ess, foundIndJmp, elms)

  let private extractLeaders ess (boundary: AddrRange) fstLeader addrs =
    addrs
    |> List.fold (fun pps addr ->
      let insInfo = ess.InstrMap.[addr]
      let pps' =
        Set.filter (fun (ppoint: ProgramPoint) ->
          let addr = ppoint.Address
          boundary.Min <= addr && addr < boundary.Max) insInfo.ReachablePPs
      Set.union pps pps') (Set.singleton fstLeader)

  let private buildBlock ess leader addrs lastAddr foundIndJmp elms edgeInfo =
    let last = ess.InstrMap.[lastAddr].Instruction
    let boundary = AddrRange (leader, lastAddr + uint64 last.Length)
    let leader = ProgramPoint (leader, 0)
    let pps = extractLeaders ess boundary leader addrs
    let bblInfo = { Boundary = boundary; Leaders = pps }
    let bbls = addBBLInfo bblInfo ess.BBLStore
    let vertices = buildVertices ess.InstrMap bblInfo
    let vertexMap, g =
      vertices
      |> List.fold (fun (vertexMap, g) bbl ->
        let v, g = DiGraph.addVertex g bbl
        Map.add bbl.PPoint v vertexMap, g) (bbls.VertexMap, ess.SCFG)
    let bbls = { bbls with VertexMap = vertexMap }
    let ess = { ess with BBLStore = bbls; SCFG = g }
    match edgeInfo with
    | Some (src, e) ->
      connectEdges ess elms vertices [(src, leader, e)] foundIndJmp
    | None ->
      let ess, edges = getEdges ess [] (Map.find leader ess.BBLStore.VertexMap)
      connectEdges ess elms vertices edges foundIndJmp

  let internal parseNewBBL ess foundIndJmp elms ctxt addr edgeInfo =
    match InstrMap.parse ess.BinHandler ctxt ess.InstrMap ess.BBLStore addr with
    | Ok (instrMap, block, lastAddr) ->
      let ess = { ess with InstrMap = instrMap }
      buildBlock ess addr block lastAddr foundIndJmp elms edgeInfo
    | Error _ -> Error ()

  let rec private getBlockAddressesWithInstrMap ess addrs addr =
    let ins = ess.InstrMap.[addr].Instruction
    let nextAddr = addr + uint64 ins.Length
    if ins.IsExit () || Map.containsKey nextAddr ess.BBLStore.BBLMap then
      struct (List.rev (addr :: addrs), ins.Address)
    else getBlockAddressesWithInstrMap ess (addr :: addrs) nextAddr

  let internal updateCFGWithVertex ess foundIndJmp elms addr ctxt =
    if bblExists ess.BBLStore addr then Ok <| struct (ess, foundIndJmp, elms)
    elif not <| isExecutableLeader ess.BinHandler addr then Error ()
    elif isIntruding ess.BBLStore addr then
      if isKnownInstruction ess.InstrMap addr then (* Need to split *)
        let ess, elms = splitBlock ess addr elms
        Ok <| struct (ess, foundIndJmp, elms)
      else Error ()
    elif isKnownInstruction ess.InstrMap addr then
      let struct (block, lastAddr) = getBlockAddressesWithInstrMap ess [] addr
      buildBlock ess addr block lastAddr foundIndJmp elms None
    else parseNewBBL ess foundIndJmp elms ctxt addr None

  let private computeNextParsingContext ess src edge =
    let prevVertex = Map.find src ess.BBLStore.VertexMap
    let ctxt = prevVertex.VData.LastInstruction.NextParsingContext
    match ess.BinHandler.ISA.Arch with
    | Arch.ARMv7 ->
      match edge, prevVertex.VData.LastInstruction.AuxParsingContext with
      | CallFallThroughEdge, Some ctxt -> ctxt
      | _ -> ctxt
    | _ -> ctxt

  let internal updateCFGWithEdge ess foundIndJmp elms src edge dst =
    if bblExists ess.BBLStore dst then
      let ess, elms = addEdgeLoop ess elms [(src, ProgramPoint (dst, 0), edge)]
      Ok <| struct (ess, foundIndJmp, elms)
    elif not <| isExecutableLeader ess.BinHandler dst then Error ()
    elif isIntruding ess.BBLStore dst then
      if isKnownInstruction ess.InstrMap dst then (* Need to split *)
        let ess, elms = splitBlock ess dst elms
        let src = Map.find src ess.BBLStore.VertexMap
        let dst = Map.find (ProgramPoint (dst, 0)) ess.BBLStore.VertexMap
        let g = DiGraph.addEdge ess.SCFG src dst edge
        let ess = { ess with SCFG = g }
        Ok <| struct (ess, foundIndJmp, elms)
      else Error ()
    elif isKnownInstruction ess.InstrMap dst then
      let struct (block, lastAddr) = getBlockAddressesWithInstrMap ess [] dst
      buildBlock ess dst block lastAddr foundIndJmp elms (Some (src, edge))
    else
      let ctxt = computeNextParsingContext ess src edge
      parseNewBBL ess foundIndJmp elms ctxt dst (Some (src, edge))

  let rec internal updateCFG ess foundIndJmp = function
    | [] -> Ok (ess, foundIndJmp)
    | CFGEntry (addr, ctxt) :: elms ->
      match updateCFGWithVertex ess foundIndJmp elms addr ctxt with
      | Ok (ess, foundIndJmp, elms) -> updateCFG ess foundIndJmp elms
      | Error () -> Error ()
    | CFGEdge (src, edge, dst) :: elms ->
      match updateCFGWithEdge ess foundIndJmp elms src edge dst with
      | Ok (ess, foundIndJmp, elms) -> updateCFG ess foundIndJmp elms
      | Error () -> Error ()

  let private removeNoReturnFallThroughEdges ess =
    let bbls = ess.BBLStore
    ess.NoReturnInfo.NoReturnCallSites
    |> Set.fold (fun g ppoint ->
      match Map.tryFind ppoint bbls.VertexMap with
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

  let private getUnreachables bbls (calleeMap: CalleeMap) g =
    let reachables =
      calleeMap.Entries
      |> Set.fold (fun acc entry ->
        let ppoint = ProgramPoint (entry, 0)
        let v = Map.find ppoint bbls.VertexMap
        let acc = Set.add ppoint acc
        Traversal.foldPostorder g v (fun acc v ->
          Set.add v.VData.PPoint acc) acc) Set.empty
    let ppoints =
      bbls.VertexMap
      |> Map.fold (fun acc ppoint _ -> Set.add ppoint acc) Set.empty
    Set.difference ppoints reachables

  let private removeNoReturnFallThroughs ess =
    let bbls = ess.BBLStore
    let g = removeNoReturnFallThroughEdges ess
    let unreachables = getUnreachables bbls ess.CalleeMap g
    (* Update calleeMap here *)
    let calleeMap, g =
      unreachables
      |> Set.fold (fun (calleeMap: CalleeMap, g) ppoint ->
        let v = Map.find ppoint bbls.VertexMap
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
    let bbls =
      unreachables
      |> Set.fold (fun bbls ppoint ->
        let addr = ppoint.Address
        match Map.tryFind addr bbls.BBLMap with
        | Some bblInfo ->
          let boundary = bblInfo.Boundary
          let newBBLMap = Map.remove addr bbls.BBLMap
          let newBoundaries = IntervalSet.remove boundary bbls.Boundaries
          let newVertexMap = Map.remove ppoint bbls.VertexMap
          { bbls with
              BBLMap = newBBLMap
              Boundaries = newBoundaries
              VertexMap = newVertexMap }
        | None ->
          { bbls with
              VertexMap = Map.remove ppoint bbls.VertexMap }) bbls
    { ess with BBLStore = bbls; CalleeMap = calleeMap; SCFG = g }

  [<CompiledName("AddEntry")>]
  let addEntry ess (addr, ctxt) =
    let ess =
      { ess with CalleeMap = ess.CalleeMap.AddEntry ess.BinHandler addr }
    match updateCFG ess false [ CFGEntry (addr, ctxt) ] with
    | Ok (ess, _) -> Ok ess
    | Error () -> if ess.IgnoreIllegal then Error () else Utils.impossible ()

  [<CompiledName("AddEntries")>]
  let addEntries ess entries =
    entries
    |> List.fold (fun res entry ->
      match res with
      | Ok ess -> addEntry ess entry
      | _ -> res) (Ok ess)

  [<CompiledName("AddEdge")>]
  let addEdge ess src dst edgeKind =
    let edgeInfo = [ CFGEdge (ProgramPoint (src, 0), edgeKind, dst) ]
    match updateCFG ess false edgeInfo with
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
    let entries = fi.GetFunctionAddresses () |> Set.ofSeq
    let entries =
      fi.EntryPoint
      |> Option.fold (fun acc addr -> Set.add addr acc) entries
      |> Set.toList
    match hdl.ISA.Arch with
    | Arch.ARMv7 ->
      let thumbCtxt = ParsingContext.Init ArchOperationMode.ThumbMode
      let armCtxt = ParsingContext.Init ArchOperationMode.ARMMode
      List.map (fun addr ->
        if addr &&& 1UL = 1UL then addr - 1UL, thumbCtxt
        else addr, armCtxt) entries
    | _ ->
      List.map (fun addr -> addr, hdl.DefaultParsingContext) entries

  let private initialize hdl ignoreIllegal =
    { BinHandler = hdl
      InstrMap = InstrMap ()
      BBLStore = BBLStore.Init ()
      CalleeMap = CalleeMap (hdl)
      SCFG = IRCFG.init PersistentGraph
      NoReturnInfo = NoReturnInfo.Init Set.empty Set.empty
      IndirectBranchMap = Map.empty
      IgnoreIllegal = defaultArg ignoreIllegal true }

  [<CompiledName("Init")>]
  let init hdl =
    let ess = initialize hdl None
    match getInitialEntryPoints hdl |> addEntries ess with
    | Ok ess -> ess
    | Error _ -> Utils.impossible ()

  [<CompiledName("InitByEntries")>]
  let initByEntries hdl entries =
    let ess = initialize hdl None
    addEntries ess entries

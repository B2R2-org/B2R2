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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open System.Collections.Generic
open B2R2
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// A mapping from an address to a DisasmCFG vertex.
type DisasmVMap = Dictionary<Addr, DisasmVertex>

/// A graph lens for obtaining DisasmCFG.
[<RequireQualifiedAccess>]
module DisasmLens =

  let findBlockStart blockInfos addr =
    Map.findKey (fun _ (range: AddrRange, _) ->
      range.Min <= addr && addr <= range.Max) blockInfos

  let canBeMerged ircfg v =
    DiGraph.GetSuccs (ircfg, v)
    |> List.exists (fun w ->
      DiGraph.FindEdgeData (ircfg, v, w) = CallFallThroughEdge &&
        DiGraph.GetPreds (ircfg, w) |> List.length = 2)

  let getMergeMap blockInfos (ircfg: DiGraph<IRBasicBlock, _>) =
    ircfg.FoldVertex (fun mergeMap v ->
      if v.VData.IsFakeBlock () then mergeMap
      elif canBeMerged ircfg v then
        let bblAddr = findBlockStart blockInfos v.VData.PPoint.Address
        let range, _ = Map.find bblAddr blockInfos
        Map.add bblAddr (range.Max + 1UL) mergeMap
      else mergeMap) Map.empty

  let getEdgeInfos blockInfos (ircfg: DiGraph<IRBasicBlock, _>) =
    ircfg.FoldEdge (fun edges src dst e ->
      if src.VData.IsFakeBlock () || dst.VData.IsFakeBlock () then edges
      else
        let srcBBLAddr = findBlockStart blockInfos src.VData.PPoint.Address
        let dstBBLAddr = findBlockStart blockInfos dst.VData.PPoint.Address
        if e = IntraCJmpFalseEdge
          || e = IntraCJmpTrueEdge
          || e = IntraJmpEdge
        then
          edges
        elif srcBBLAddr <> dstBBLAddr then
          Map.add (srcBBLAddr, dstBBLAddr) e edges
        elif dstBBLAddr = dst.VData.PPoint.Address then
          Map.add (srcBBLAddr, dstBBLAddr) e edges
        else edges) Map.empty

  let rec resolveMerge codeMgr blockInfo vInfo edges mergeMap addr next addrs =
    let _, insAddrs = Map.find next blockInfo
    let instrs =
      insAddrs
      |> Set.toArray
      |> Array.map (fun addr ->
        (codeMgr: CodeManager).GetInstruction(addr).Instruction)
      |> Array.append (Map.find addr vInfo)
    let vInfo = Map.add addr instrs vInfo
    let edges =
      Map.fold (fun edges (src, dst) e ->
        if src = addr then edges
        elif src = next then Map.add (addr, dst) e edges
        else Map.add (src, dst) e edges) Map.empty edges
    let mergeMap =
      Map.fold (fun mergeMap fromAddr toAddr ->
        if fromAddr = addr then mergeMap
        elif fromAddr = next then Map.add addr toAddr mergeMap
        else Map.add fromAddr toAddr mergeMap) Map.empty mergeMap
    let addrs = List.filter (fun a -> a <> next) addrs
    match Map.tryFind addr mergeMap with
    | None -> vInfo, edges, mergeMap, addrs
    | Some next ->
      resolveMerge codeMgr blockInfo vInfo edges mergeMap addr next addrs

  let rec mergeInfosLoop codeMgr blockInfo vInfo edges mergeMap = function
    | [] -> vInfo, edges
    | addr :: addrs ->
      let _, insAddrs = Map.find addr blockInfo
      let instrs =
        insAddrs
        |> Set.toArray
        |> Array.map (fun addr ->
          (codeMgr: CodeManager).GetInstruction(addr).Instruction)
      let vInfo = Map.add addr instrs vInfo
      let vInfo, edges, mergeMap, addrs =
        match Map.tryFind addr mergeMap with
        | None -> vInfo, edges, mergeMap, addrs
        | Some next ->
          resolveMerge codeMgr blockInfo vInfo edges mergeMap addr next addrs
      mergeInfosLoop codeMgr blockInfo vInfo edges mergeMap addrs

  let mergeInfos codeMgr blockInfos edges mergeMap =
    let addrs = Map.toList blockInfos |> List.map fst
    mergeInfosLoop codeMgr blockInfos Map.empty edges mergeMap addrs

  let addVertex (g, vMap: DisasmVMap) addr instrs =
    let blk = DisasmBasicBlock (instrs, ProgramPoint (addr, 0))
    let v, g = DiGraph.AddVertex (g, blk)
    vMap.Add (addr, v)
    g, vMap

  let addEdge (vMap: DisasmVMap) g (src, dst) e =
    let src = vMap[src]
    let dst = vMap[dst]
    DiGraph.AddEdge (g, src, dst, e)

  let private buildCFG codeMgr blockInfos ircfg vMap dcfg =
    let mergeMap = getMergeMap blockInfos ircfg
    let edges = getEdgeInfos blockInfos ircfg
    let vertexInfo, edges = mergeInfos codeMgr blockInfos edges mergeMap
    let dcfg, vMap = Map.fold addVertex (dcfg, vMap) vertexInfo
    let dcfg = Map.fold (addEdge vMap) dcfg edges
    dcfg

  let filter codeMgr (g: DiGraph<_, _>) (root: IRVertex) =
    let blockInfos =
      (codeMgr: CodeManager).FoldBBLs (fun acc (KeyValue (addr, bblInfo)) ->
        if bblInfo.FunctionEntry = root.VData.PPoint.Address then
          Map.add addr (bblInfo.BlkRange, bblInfo.InstrAddrs) acc
        else acc) Map.empty
    let newGraph = DisasmCFG.init g.ImplementationType
    let vMap = DisasmVMap ()
    let newGraph = buildCFG codeMgr blockInfos g vMap newGraph
    let root = vMap[(root: IRVertex).VData.PPoint.Address]
    newGraph, root

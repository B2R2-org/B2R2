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

namespace B2R2.MiddleEnd.ControlFlowGraph

open B2R2
open B2R2.BinIR.SSA
open B2R2.MiddleEnd.BinGraph

/// SSA-based CFG, where each node contains disassembly code.
type SSACFG = ControlFlowGraph<SSABasicBlock, CFGEdgeKind>

[<RequireQualifiedAccess>]
module SSACFG =
  let private initializer core =
    SSACFG (core) :> DiGraph<SSABasicBlock, CFGEdgeKind>

  let private initImperative () =
    ImperativeCore<SSABasicBlock, CFGEdgeKind> (initializer, UnknownEdge)
    |> SSACFG
    :> DiGraph<SSABasicBlock, CFGEdgeKind>

  let private initPersistent () =
    PersistentCore<SSABasicBlock, CFGEdgeKind> (initializer, UnknownEdge)
    |> SSACFG
    :> DiGraph<SSABasicBlock, CFGEdgeKind>

  /// Initialize SSACFG based on the implementation type.
  let init = function
    | ImperativeGraph -> initImperative ()
    | PersistentGraph -> initPersistent ()

  let private getVertex g (vMap: SSAVMap) oldSrc =
    let vData = (oldSrc: Vertex<IRBasicBlock>).VData
    let pos = vData.PPoint
    match vMap.TryGetValue pos with
    | false, _ ->
      let instrs = vData.InsInfos
      let blk = SSABasicBlock.initRegular pos instrs
      let v, g = DiGraph.addVertex g blk
      vMap.Add (pos, v)
      v, g
    | true, v -> v, g

  let private getFakeVertex hdl g (fMap: FakeVMap) src ftPos =
    let srcPos = (src: Vertex<IRBasicBlock>).VData.PPoint
    let pos = (srcPos, ftPos)
    match fMap.TryGetValue pos with
    | false, _ ->
      let blk = SSABasicBlock.initFake hdl srcPos ftPos src.VData.FakeBlockInfo
      let v, g = DiGraph.addVertex g blk
      fMap.Add (pos, v)
      v, g
    | true, v -> v, g

  let private convertToSSA hdl irCFG ssaCFG vMap fMap root =
    let root, ssaCFG = getVertex ssaCFG vMap root
    let ssaCFG =
      ssaCFG
      |> DiGraph.foldEdge irCFG (fun ssaCFG src dst e ->
        (* If a node is fake, it is a call target. *)
        if (dst: Vertex<IRBasicBlock>).VData.IsFakeBlock () then
          let last = src.VData.LastInstruction
          let fall = ProgramPoint (last.Address + uint64 last.Length, 0)
          let srcV, ssaCFG = getVertex ssaCFG vMap src
          let dstV, ssaCFG = getFakeVertex hdl ssaCFG fMap dst fall
          DiGraph.addEdge ssaCFG srcV dstV e
        elif src.VData.IsFakeBlock () then
          let srcV, ssaCFG = getFakeVertex hdl ssaCFG fMap src dst.VData.PPoint
          let dstV, ssaCFG = getVertex ssaCFG vMap dst
          DiGraph.addEdge ssaCFG srcV dstV e
        else
          let srcV, ssaCFG = getVertex ssaCFG vMap src
          let dstV, ssaCFG = getVertex ssaCFG vMap dst
          DiGraph.addEdge ssaCFG srcV dstV e)
    ssaCFG, root

  /// Add phis and rename all the variables.
  let installPhis vertices ssaCFG ssaRoot =
    let defSites = DefSites ()
    SSAUtils.computeDominatorInfo ssaCFG ssaRoot
    |> SSAUtils.placePhis ssaCFG vertices defSites
    |> SSAUtils.renameVars ssaCFG defSites

  /// Convert IRCFG to an SSA CFG.
  let ofIRCFG hdl (g: DiGraph<_, _>) root =
    let ssaCFG = init g.ImplementationType
    let vMap = SSAVMap ()
    let fMap = FakeVMap ()
    let ssaCFG, root = convertToSSA hdl g ssaCFG vMap fMap root
    let vertices = Seq.append vMap.Values fMap.Values
    DiGraph.findVertexBy ssaCFG (fun v ->
      v.VData.PPoint = root.VData.PPoint && not <| v.VData.IsFakeBlock ())
    |> installPhis vertices ssaCFG
    DiGraph.iterVertex ssaCFG (fun v -> v.VData.UpdatePPoints ())
    struct (ssaCFG, root)

  /// Find SSAVertex that includes the given instruction address.
  let findVertexByAddr ssaCFG addr =
    DiGraph.findVertexBy ssaCFG (fun (v: SSAVertex) ->
      if v.VData.IsFakeBlock () then false
      else v.VData.Range.IsIncluding addr)

  /// Find the reaching definition of the given variable kind (targetVarKind) at
  /// the entry of node v. We simply follow the dominator tree of the given
  /// SSACFG until we find a definition.
  let rec findReachingDef (v: SSAVertex) targetVarKind =
    match v.VData.ImmDominator with
    | Some idom ->
      let stmtInfo =
        idom.VData.SSAStmtInfos
        |> Array.tryFindBack (fun (_, stmt) ->
          match stmt with
          | Def ({ Kind = k }, _) when k = targetVarKind -> true
          | _ -> false)
      match stmtInfo with
      | Some stmtInfo -> Some (snd stmtInfo)
      | None -> findReachingDef idom targetVarKind
    | None -> None

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
type SSACFG = IGraph<SSABasicBlock, CFGEdgeKind>

[<RequireQualifiedAccess>]
module SSACFG =
  let private initImperative () =
    ImperativeDiGraph<SSABasicBlock, CFGEdgeKind> ()
    :> SSACFG

  let private initPersistent () =
    PersistentDiGraph<SSABasicBlock, CFGEdgeKind> ()
    :> SSACFG

  /// Initialize SSACFG based on the implementation type.
  let init = function
    | Imperative -> initImperative ()
    | Persistent -> initPersistent ()

  let private getVertex hdl (g: IGraph<_, _>) (vMap: SSAVMap) oldSrc =
    let bbl = (oldSrc: IRVertex).VData
    let pos = bbl.PPoint
    match vMap.TryGetValue pos with
    | false, _ ->
      let instrs = bbl.LiftedInstructions
      let blk = SSABasicBlock.CreateRegular (hdl, pos, instrs)
      let v, g = g.AddVertex blk
      vMap.Add (pos, v)
      v, g
    | true, v -> v, g

  let private getFakeVertex hdl (g: IGraph<_, _>) (fMap: FakeVMap) src ftPos =
    let srcBbl = (src: IRVertex).VData
    let srcPos = srcBbl.PPoint
    let pos = (srcPos, ftPos)
    match fMap.TryGetValue pos with
    | false, _ ->
      let funcAbs = srcBbl.AbstractedContent
      let blk = SSABasicBlock.CreateAbstract (hdl, srcPos, funcAbs)
      let v, g = g.AddVertex blk
      fMap.Add (pos, v)
      v, g
    | true, v -> v, g

  let private convertToSSA hdl irCFG ssaCFG vMap fMap root =
    let root, ssaCFG = getVertex hdl ssaCFG vMap root
    let ssaCFG =
      ssaCFG
      |> (irCFG: IGraph<_, _>).FoldEdge (fun ssaCFG e ->
        let src, dst = e.First, e.Second
        (* If the node is an abstracted one, it is a call target. *)
        if (dst: IRVertex).VData.IsFake then
          let last = src.VData.LastInstruction
          let fall = ProgramPoint (last.Address + uint64 last.Length, 0)
          let srcV, ssaCFG = getVertex hdl ssaCFG vMap src
          let dstV, ssaCFG = getFakeVertex hdl ssaCFG fMap dst fall
          ssaCFG.AddEdge (srcV, dstV, e.Label)
        elif src.VData.IsFake then
          let dstPPoint = dst.VData.PPoint
          let srcV, ssaCFG = getFakeVertex hdl ssaCFG fMap src dstPPoint
          let dstV, ssaCFG = getVertex hdl ssaCFG vMap dst
          ssaCFG.AddEdge (srcV, dstV, e.Label)
        else
          let srcV, ssaCFG = getVertex hdl ssaCFG vMap src
          let dstV, ssaCFG = getVertex hdl ssaCFG vMap dst
          ssaCFG.AddEdge (srcV, dstV, e.Label))
    ssaCFG, root

  /// Add phis and rename all the variables.
  let installPhis vertices ssaCFG ssaRoot =
    let defSites = DefSites ()
    SSAUtils.computeDominatorInfo ssaCFG ssaRoot
    |> SSAUtils.placePhis ssaCFG vertices defSites
    |> SSAUtils.renameVars ssaCFG defSites

  /// Convert IRCFG to an SSA CFG.
  let ofIRCFG hdl (g: IGraph<_, _>) root =
    let ssaCFG = init g.ImplementationType
    let vMap = SSAVMap ()
    let fMap = FakeVMap ()
    let ssaCFG, root = convertToSSA hdl g ssaCFG vMap fMap root
    let vertices = Seq.append vMap.Values fMap.Values
    ssaCFG.FindVertexBy (fun v ->
      v.VData.PPoint = root.VData.PPoint && not v.VData.IsFake)
    |> installPhis vertices ssaCFG
    ssaCFG.IterVertex (fun v -> v.VData.UpdatePPoints ())
    struct (ssaCFG, root)

  /// Find SSAVertex that includes the given instruction address.
  let findVertexByAddr (ssaCFG: IGraph<_, _>) addr =
    ssaCFG.FindVertexBy (fun (v: SSAVertex) ->
      if v.VData.IsFake then false
      else v.VData.Range.IsIncluding addr)

  /// Find the definition of the given variable kind (targetVarKind) at the
  /// given node v. We simply follow the dominator tree of the given SSACFG
  /// until we find a definition.
  let rec findDef (v: SSAVertex) targetVarKind =
    let stmtInfo =
      v.VData.LiftedSSAStmts
      |> Array.tryFindBack (fun (_, stmt) ->
        match stmt with
        | Def ({ Kind = k }, _) when k = targetVarKind -> true
        | _ -> false)
    match stmtInfo with
    | Some stmtInfo -> Some (snd stmtInfo)
    | None ->
      match v.VData.ImmDominator with
      | Some idom ->
        findDef idom targetVarKind
      | None -> None

  /// Find the reaching definition of the given variable kind (targetVarKind) at
  /// the entry of node v. We simply follow the dominator tree of the given
  /// SSACFG until we find a definition.
  let findReachingDef (v: SSAVertex) targetVarKind =
    match v.VData.ImmDominator with
    | Some idom ->
      findDef idom targetVarKind
    | None -> None
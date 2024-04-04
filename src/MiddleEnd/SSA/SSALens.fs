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

namespace B2R2.MiddleEnd.SSA

open System.Collections.Generic
open B2R2
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// A mapping from an address to an SSACFG vertex.
type SSAVMap<'Abs when 'Abs: null> =
  Dictionary<ProgramPoint, SSAVertex<'Abs>>

/// This is a mapping from an edge to an abstract vertex (for external function
/// calls). We first separately create abstract vertices even if they are
/// associated with the same external function (address) in order to compute
/// dominance relationships without introducing incorrect paths or cycles. For
/// convenience, we will always consider as a key "a return edge" from an
/// abstract vertex to a fall-through vertex.
type AbstractVMap<'Abs when 'Abs: null> =
  Dictionary<ProgramPoint * ProgramPoint, SSAVertex<'Abs>>

[<RequireQualifiedAccess>]
module SSALens =
  let private getVertex ssaLifter vMap g (src: IVertex<_>) =
    let bbl: IRBasicBlock<_> = src.VData
    let ppoint = bbl.PPoint
    match (vMap: SSAVMap<_>).TryGetValue ppoint with
    | true, v -> v, g
    | false, _ ->
      let instrs = bbl.LiftedInstructions
      let blk = SSABasicBlock.CreateRegular (ssaLifter, ppoint, instrs)
      let v, g = (g: SSACFG<_, _>).AddVertex blk
      vMap.Add (ppoint, v)
      v, g

  let private getFakeVertex ssaLifter avMap g src ftPpoint =
    let srcBbl: IRBasicBlock<_> = (src: IVertex<_>).VData
    let srcPpoint = srcBbl.PPoint
    let key = srcPpoint, ftPpoint
    match (avMap: AbstractVMap<_>).TryGetValue key with
    | true, v -> v, g
    | false, _ ->
      let absContent = srcBbl.AbstractContent |> SSAFunctionAbstraction
      let blk = SSABasicBlock.CreateAbstract (ssaLifter, srcPpoint, absContent)
      let v, g = (g: SSACFG<_, _>).AddVertex blk
      avMap.Add (key, v)
      v, g

  let private convertToSSA ssaLifter irCFG vMap avMap ssaCFG root =
    let root, ssaCFG = getVertex ssaLifter vMap ssaCFG root
    let ssaCFG =
      ssaCFG
      |> (irCFG: IRCFG<_, _, _>).FoldEdge (fun ssaCFG e ->
        let src, dst = e.First, e.Second
        (* If a node is abstract, then it is a call target. *)
        if dst.VData.IsAbstract then
          let last = src.VData.LastInstruction
          let fallPp = ProgramPoint (last.Address + uint64 last.Length, 0)
          let srcV, ssaCFG = getVertex ssaLifter vMap ssaCFG src
          let dstV, ssaCFG = getFakeVertex ssaLifter avMap ssaCFG dst fallPp
          ssaCFG.AddEdge (srcV, dstV, e.Label)
        elif src.VData.IsAbstract then
          let dstPp = dst.VData.PPoint
          let srcV, ssaCFG = getFakeVertex ssaLifter avMap ssaCFG src dstPp
          let dstV, ssaCFG = getVertex ssaLifter vMap ssaCFG dst
          ssaCFG.AddEdge (srcV, dstV, e.Label)
        else
          let srcV, ssaCFG = getVertex ssaLifter vMap ssaCFG src
          let dstV, ssaCFG = getVertex ssaLifter vMap ssaCFG dst
          ssaCFG.AddEdge (srcV, dstV, e.Label)
      )
    ssaCFG, root

  /// Add phis and rename all the variables in the SSACFG.
  let private installPhis vertices ssaCFG root =
    let defSites = DefSites ()
    SSAUtils.computeDominatorInfo ssaCFG root
    |> SSAUtils.placePhis ssaCFG vertices defSites
    |> SSAUtils.renameVars ssaCFG defSites

  /// Convert an IRCFG to an SSACFG.
  [<CompiledName "Convert">]
  let convert (ssaLifter: SSALifter<_>)
              (postProcessor: IPostProcessor<_, _>)
              (g: IRCFG<'V, 'E, 'Abs>)
              (root: IVertex<#IRBasicBlock<'Abs>>) =
    let ssaCFG =
      match g.ImplementationType with
      | Imperative ->
        ImperativeDiGraph<SSABasicBlock<_>, 'E> () :> IGraph<_, _>
      | Persistent ->
        PersistentDiGraph<SSABasicBlock<_>, 'E> () :> IGraph<_, _>
    let vMap = SSAVMap ()
    let avMap = AbstractVMap ()
    let ssaCFG, root = convertToSSA ssaLifter g vMap avMap ssaCFG root
    let vertices = Seq.append vMap.Values avMap.Values
    ssaCFG.FindVertexBy (fun v ->
      v.VData.PPoint = root.VData.PPoint && not <| v.VData.IsAbstract)
    |> installPhis vertices ssaCFG
    ssaCFG.IterVertex (fun v -> v.VData.UpdatePPoints ())
    if isNull postProcessor then struct (ssaCFG, root)
    else postProcessor.PostProcess (ssaCFG, root)

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

namespace B2R2.Lens

open B2R2
open B2R2.BinGraph
open B2R2.BinEssence

/// A graph lens for obtaining SSACFG.
type SSALens (ess) =
  let getVertex g (vMap: SSAVMap) oldSrc =
    let vData = (oldSrc: Vertex<IRBasicBlock>).VData
    let pos = vData.PPoint
    match vMap.TryGetValue pos with
    | false, _ ->
      let instrs = vData.GetInsInfos ()
      let hasIndBranch = vData.HasIndirectBranch
      let bblock = SSABBlock (ess, pos, instrs, hasIndBranch)
      let v, g = DiGraph.addVertex g bblock
      vMap.Add (pos, v)
      v, g
    | true, v -> v, g

  let getFakeVertex g (fMap: FakeVMap) srcPos dstPos =
    let pos = (srcPos, dstPos)
    match fMap.TryGetValue pos with
    | false, _ ->
      let bblock = SSABBlock (ess, srcPos, dstPos, false)
      let v, g = DiGraph.addVertex g bblock
      fMap.Add (pos, v)
      v, g
    | true, v -> v, g

  let convertToSSA irCFG ssaCFG vMap fMap roots =
    let roots, ssaCFG =
      roots |> List.fold (fun (roots, ssaCFG) r ->
        let r, ssaCFG = getVertex ssaCFG vMap r
        r :: roots, ssaCFG) ([], ssaCFG)
    let ssaCFG =
      ssaCFG
      |> DiGraph.foldEdge irCFG (fun ssaCFG src dst e ->
        (* If a node is fake, it is a call target. *)
        if (dst: Vertex<IRBasicBlock>).VData.IsFakeBlock () then
          let last = src.VData.LastInstruction
          let fall = ProgramPoint (last.Address + uint64 last.Length, 0)
          let srcV, ssaCFG = getVertex ssaCFG vMap src
          let dstV, ssaCFG =
            getFakeVertex ssaCFG fMap dst.VData.PPoint fall
          DiGraph.addEdge ssaCFG srcV dstV e
        elif src.VData.IsFakeBlock () then
          let srcV, ssaCFG =
            getFakeVertex ssaCFG fMap src.VData.PPoint dst.VData.PPoint
          let dstV, ssaCFG = getVertex ssaCFG vMap dst
          DiGraph.addEdge ssaCFG srcV dstV e
        else
          let srcV, ssaCFG = getVertex ssaCFG vMap src
          let dstV, ssaCFG = getVertex ssaCFG vMap dst
          DiGraph.addEdge ssaCFG srcV dstV e)
    ssaCFG, roots

  interface ILens<SSABBlock> with
    member __.Filter (g, roots, _) =
      let ssaCFG = SSACFG.init g.ImplementationType
      let vMap = SSAVMap ()
      let fMap = FakeVMap ()
      let defSites = DefSites ()
      let ssaCFG, roots = convertToSSA g ssaCFG vMap fMap roots
      let root = List.head roots
      DiGraph.findVertexBy ssaCFG (fun v ->
        v.VData.PPoint = root.VData.PPoint && not <| v.VData.IsFakeBlock ())
      |> SSAUtils.computeFrontiers ssaCFG
      |> SSAUtils.placePhis ssaCFG vMap fMap defSites
      |> SSAUtils.renameVars ssaCFG defSites
      ssaCFG, roots

  static member Init ess =
    SSALens (ess) :> ILens<SSABBlock>

(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Soomin Kim <soomink@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.BinGraph

/// A graph lens for obtaining SSACFG.
type SSALens (scfg) =
  let getVertex g (vMap: SSAVMap) (old: Vertex<IRBasicBlock>) pos =
    match vMap.TryGetValue pos with
    | false, _ ->
      let pairs = old.VData.GetPairs ()
      let v = (g: SSACFG).AddVertex (SSABBlock (scfg, pos, pairs))
      vMap.Add (pos, v)
      v
    | true, v -> v

  let convertToSSA (irCFG: CFGUtils.CFG) ssaCFG vMap =
    irCFG.IterEdge (fun src dst e ->
      let srcPos = src.VData.Position
      let dstPos = dst.VData.Position
      let srcV = getVertex ssaCFG vMap src srcPos
      let dstV = getVertex ssaCFG vMap dst dstPos
      ssaCFG.AddEdge srcV dstV e)

  interface ILens<SSABBlock> with
    member __.Filter (g: CFGUtils.CFG) root =
      let ssaCFG = SSACFG ()
      let vMap = new SSAVMap ()
      let defSites = DefSites ()
      convertToSSA g ssaCFG vMap
      ssaCFG.FindVertexBy (fun v -> v.VData.Position = root.VData.Position)
      |> SSAUtils.computeFrontiers ssaCFG
      |> SSAUtils.placePhis vMap defSites
      |> SSAUtils.renameVars defSites
      ssaCFG :> DiGraph<SSABBlock, CFGEdgeKind>

  static member Init (scfg) = SSALens (scfg) :> ILens<SSABBlock>

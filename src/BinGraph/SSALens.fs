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

namespace B2R2.BinGraph

open B2R2

/// A graph lens for obtaining SSACFG.
type SSALens (hdl, scfg) =
  let getVertex g (vMap: SSAVMap) (oldSrc: Vertex<IRBasicBlock>) =
    let vData = oldSrc.VData
    let pos = vData.PPoint
    match vMap.TryGetValue pos with
    | false, _ ->
      let instrs = vData.GetInsInfos ()
      let hasIndBranch = vData.HasIndirectBranch
      let v =
        (g: SSACFG).AddVertex (SSABBlock (hdl, scfg, pos, instrs, hasIndBranch))
      vMap.Add (pos, v)
      v
    | true, v -> v

  let getFakeVertex g (fMap: FakeVMap) srcPos dstPos =
    let pos = (srcPos, dstPos)
    match fMap.TryGetValue pos with
    | false, _ ->
      let v =
        (g: SSACFG).AddVertex (SSABBlock (hdl, scfg, srcPos, dstPos, false))
      fMap.Add (pos, v)
      v
    | true, v -> v

  let convertToSSA (irCFG: IRCFG) ssaCFG vMap fMap roots =
    let roots = roots |> List.map (getVertex ssaCFG vMap)
    irCFG.IterEdge (fun src dst e ->
      (* If a node is fake, it is a call target. *)
      if dst.VData.IsFakeBlock () then
        let last = src.VData.LastInstruction
        let fall = ProgramPoint (last.Address + uint64 last.Length, 0)
        let srcV = getVertex ssaCFG vMap src
        let dstV = getFakeVertex ssaCFG fMap dst.VData.PPoint fall
        ssaCFG.AddEdge srcV dstV e
      elif src.VData.IsFakeBlock () then
        let srcV = getFakeVertex ssaCFG fMap src.VData.PPoint dst.VData.PPoint
        let dstV = getVertex ssaCFG vMap dst
        ssaCFG.AddEdge srcV dstV e
      else
        let srcV = getVertex ssaCFG vMap src
        let dstV = getVertex ssaCFG vMap dst
        ssaCFG.AddEdge srcV dstV e)
    roots

  interface ILens<SSABBlock> with
    member __.Filter (g: IRCFG) roots _ =
      let ssaCFG = SSACFG ()
      let vMap = SSAVMap ()
      let fMap = FakeVMap ()
      let defSites = DefSites ()
      let roots = convertToSSA g ssaCFG vMap fMap roots
      let root = List.head roots
      ssaCFG.FindVertexBy (fun v ->
        v.VData.PPoint = root.VData.PPoint && not <| v.VData.IsFakeBlock ())
      |> SSAUtils.computeFrontiers ssaCFG
      |> SSAUtils.placePhis vMap fMap defSites
      |> SSAUtils.renameVars defSites
      ssaCFG, roots

  static member Init hdl scfg = SSALens (hdl, scfg) :> ILens<SSABBlock>

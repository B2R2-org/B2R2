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

namespace B2R2.DataFlow

open B2R2
open B2R2.BinGraph
open B2R2.BinIR.LowUIR
open System.Collections.Generic

type ConstantPropagation () =
  inherit DataFlowAnalysis<Map<VarExpr, Constant>, IRBasicBlock> (Forward)

  override __.Meet a b =
    a
    |> Map.fold (fun acc vp c ->
      match Map.tryFind vp acc with
      | Some c' ->
        let c = Constant.join c c'
        Map.add vp c acc
      | None -> Map.add vp c acc) b

  override __.Top = Map.empty

  override __.Worklist root =
    let q = Queue<Vertex<IRBasicBlock>> ()
    Traversal.iterRevPostorder root q.Enqueue
    q

  override __.Transfer i v =
    let ppoint = v.VData.PPoint
    v.VData.GetIRStatements ()
    |> Array.fold (fun acc stmts ->
      stmts
      |> Array.fold ConstantPropagationHelper.evalStmt acc) (ppoint, i)
    |> snd

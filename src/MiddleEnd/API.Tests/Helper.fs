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

namespace B2R2.MiddleEnd.Tests

open System.Collections.Generic
open B2R2
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

[<AutoOpen>]
module Helper =
  let scanBBLs (bblFactory: BBLFactory) addrs =
    bblFactory.ScanBBLs addrs
    |> Async.AwaitTask
    |> Async.RunSynchronously
    |> ignore

  let extractInsBBLPairs (bblFactory: BBLFactory) ppoint =
    let bbl = bblFactory.Find ppoint
    bbl.Internals.LiftedInstructions
    |> Array.map (fun li -> li.Original.Address, li.BBLAddr)

  let extractBBLRange (bblFactory: BBLFactory) ppoint =
    let bbl = bblFactory.Find ppoint
    bbl.Internals.Range.Min, bbl.Internals.Range.Max

  let makeMap keys values =
    List.fold2 (fun map k v -> Map.add k v map) Map.empty keys values

  let extractCallEdgeArray (callees: SortedList<CallSite, CalleeKind>) =
    callees
    |> Seq.map (fun (KeyValue(k, v)) -> k, v)
    |> Seq.toList

  let foldVertexNoFake m (v: IVertex<LowUIRBasicBlock>) =
    if v.VData.Internals.IsAbstract then m
    else Map.add v.VData.Internals.PPoint v m

  let foldEdge m (e: Edge<LowUIRBasicBlock, _>) =
    let v1, v2 = e.First, e.Second
    Map.add (v1.VData.Internals.PPoint, v2.VData.Internals.PPoint) e m

  let foldEdgeNoFake m (e: Edge<LowUIRBasicBlock, _>) =
    let v1, v2 = e.First, e.Second
    if v1.VData.Internals.IsAbstract || v2.VData.Internals.IsAbstract then m
    else Map.add (v1.VData.Internals.PPoint, v2.VData.Internals.PPoint) e m

  let collectInsBBLAddrPairs (fn: Function) =
    fn.CFG.FoldVertex((fun acc v ->
      if v.VData.Internals.IsAbstract then acc
      else
        v.VData.Internals.LiftedInstructions
        |> Array.map (fun li -> li.Original.Address, li.BBLAddr)
        |> fun arr -> arr :: acc
    ), [])
    |> Array.concat

  let getDisasmVertexRanges disasmBuilder (cfg: LowUIRCFG) =
    let dcfg = DisasmCFG(disasmBuilder, cfg)
    dcfg.Vertices
    |> Array.map (fun v ->
      v.VData.Internals.Range.Min, v.VData.Internals.Range.Max)
    |> Array.sortBy fst

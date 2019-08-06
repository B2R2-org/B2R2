(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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
open B2R2.BinGraph
open System.Collections.Generic

/// Basic block type for a call graph (CallCFG).
type CallGraphBBlock (addr, name, isFake) =
  inherit BasicBlock ()

  member __.Name with get () = name

  override __.PPoint = ProgramPoint (addr, 0)

  override __.Range = AddrRange (addr, addr + 1UL)

  override __.IsFakeBlock () = isFake

  override __.ToVisualBlock (_) =
    let term = "CallGraphBB(" + addr.ToString ("X") + ")" |> String
    [ [ term ] ]

/// Call graph, where each node represents a function.
type CallCFG = ControlFlowGraph<CallGraphBBlock, CFGEdgeKind>

/// A mapping from an address to a CallCFG vertex.
type CallVMap = Dictionary<Addr, Vertex<CallGraphBBlock>>

/// A graph lens for obtaining CallGraph.
type CallGraphLens (scfg: SCFG) =
  let getFunctionVertex g vMap (old: Vertex<IRBasicBlock>) addr app =
    match (vMap: CallVMap).TryGetValue addr with
    | false, _ ->
      let isFake = old.VData.IsFakeBlock ()
      match app.CalleeMap.Find (addr) with
      | None -> None
      | Some callee ->
        let name = callee.CalleeName
        let v = (g: CallCFG).AddVertex (CallGraphBBlock (addr, name, isFake))
        vMap.Add (addr, v)
        Some v
    | true, v -> Some v

  let getVertex g vMap old addr app =
    match scfg.FindFunctionEntry addr with
    | None -> None
    | Some entry -> getFunctionVertex g vMap old entry app

  let buildCallGraph callCFG (g: IRCFG) vMap app =
    g.IterEdge (fun src dst e ->
      match e with
      | IntraJmpEdge
      | IndirectEdge
      | ExternalEdge
      | CallEdge ->
        let srcAddr = src.VData.PPoint.Address
        let dstAddr = dst.VData.PPoint.Address
        let srcV = getVertex callCFG vMap src srcAddr app
        let dstV = getVertex callCFG vMap dst dstAddr app
        match srcV, dstV with
        | Some s, Some d -> callCFG.AddEdge s d e
        | _ -> ()
      | _ -> ())

  interface ILens<CallGraphBBlock> with
    member __.Filter (g: IRCFG) _ app =
      let callCFG = CallCFG ()
      let vMap = CallVMap ()
      buildCallGraph callCFG g vMap app
      callCFG, []

  static member Init (scfg) = CallGraphLens (scfg) :> ILens<CallGraphBBlock>

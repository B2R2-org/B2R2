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
open B2R2.FrontEnd
open B2R2.BinCorpus
open System
open System.Collections.Generic

/// Basic block type for a disassembly-based CFG (DisasmCFG).
type DisasmBBlock (instrs: Instruction [], pp, app: Apparatus) =
  inherit BasicBlock()

  let mutable instructions = instrs

  let symbolize (ins: Instruction) (words: AsmWord []) =
    let last = words.[words.Length - 1]
    if ins.IsBranch () && last.AsmWordKind = AsmWordKind.Value then
      let addr = Convert.ToUInt64 (last.AsmWordValue, 16)
      match app.CalleeMap.Find (addr) with
      | Some callee ->
        words.[words.Length - 1] <-
          { AsmWordKind = AsmWordKind.Value; AsmWordValue = callee.CalleeID }
      | None -> ()
      words
    else words

  override __.PPoint = pp

  override __.Range =
    let last = instructions.[instructions.Length - 1]
    AddrRange (last.Address, last.Address + uint64 last.Length)

  override __.IsFakeBlock () = Array.isEmpty instructions

  override __.ToVisualBlock () =
    instructions
    |> Array.map (fun i -> i.Decompose () |> symbolize i)

  member __.Instructions
    with get () = instructions
    and set (i) = instructions <- i

  member __.Disassemblies
    with get () =
      instructions |> Array.map (fun i -> i.Disasm ())

  override __.ToString () =
    if instrs.Length = 0 then "DisasmBBLK(Dummy)"
    else "DisasmBBLK(" + __.PPoint.Address.ToString("X") + ")"

/// Disassembly-based CFG, where each node contains disassembly code.
type DisasmCFG = ControlFlowGraph<DisasmBBlock, CFGEdgeKind>

[<RequireQualifiedAccess>]
module DisasmCFG =
  let private initializer core =
    DisasmCFG (core) :> DiGraph<DisasmBBlock, CFGEdgeKind>

  let private initImperative () =
    ImperativeCore<DisasmBBlock, CFGEdgeKind> (initializer, UnknownEdge)
    |> DisasmCFG
    :> DiGraph<DisasmBBlock, CFGEdgeKind>

  let private initPersistent () =
    PersistentCore<DisasmBBlock, CFGEdgeKind> (initializer, UnknownEdge)
    |> DisasmCFG
    :> DiGraph<DisasmBBlock, CFGEdgeKind>

  /// Initialize IRCFG based on the implementation type.
  let init = function
    | DefaultGraph -> initPersistent ()
    | ImperativeGraph -> initImperative ()
    | PersistentGraph -> initPersistent ()

/// A mapping from an address to a DisasmCFG vertex.
type DisasmVMap = Dictionary<Addr, Vertex<DisasmBBlock>>

/// A graph lens for obtaining DisasmCFG.
type DisasmLens (app) =
  let getVertex g (vMap: DisasmVMap) oldVertex addr =
    match vMap.TryGetValue addr with
    | false, _ ->
      let instrs = (oldVertex: Vertex<IRBasicBlock>).VData.GetInstructions ()
      let blk = DisasmBBlock (instrs, oldVertex.VData.PPoint, app)
      let v, g = DiGraph.addVertex g blk
      vMap.Add (addr, v)
      v, g
    | true, v -> v, g

  let dfs fnMerge fnEdge ircfg newGraph (roots: Vertex<IRBasicBlock> list) =
    let visited = HashSet<ProgramPoint> ()
    let rec traverse newGraph = function
      | [] -> newGraph
      | (addr, v: Vertex<IRBasicBlock>) :: rest ->
        if visited.Contains v.VData.PPoint then traverse newGraph rest
        else
          visited.Add v.VData.PPoint |> ignore
          let acc, newGraph =
            DiGraph.getSuccs ircfg v
            |> List.fold (succFold addr v) (rest, newGraph)
          traverse newGraph acc
    and succFold addr v (acc, newGraph) succ =
      match DiGraph.findEdgeData ircfg v succ with
      | ExternalJmpEdge
      | ExternalCallEdge
      | CallEdge
      | RetEdge -> acc, newGraph
      | CallFallThroughEdge
          when DiGraph.getPreds ircfg succ |> List.length <= 2 ->
        (* Two edges: (1) RetEdge from a fake node; (2) CallFallThroughEdge. *)
        let newGraph = fnMerge newGraph addr v succ
        if visited.Contains succ.VData.PPoint then acc, newGraph
        else (addr, succ) :: acc, newGraph
      | IntraCJmpTrueEdge
      | IntraCJmpFalseEdge
      | IntraJmpEdge ->
        let newGraph = fnMerge newGraph addr v succ
        if visited.Contains succ.VData.PPoint then acc, newGraph
        else (addr, succ) :: acc, newGraph
      | e ->
        let newGraph = fnEdge newGraph addr v succ e
        if visited.Contains succ.VData.PPoint then acc, newGraph
        else (succ.VData.PPoint.Address, succ) :: acc, newGraph
    roots
    |> List.map (fun r -> r.VData.PPoint.Address, r)
    |> traverse newGraph

  let merge vMap newGraph addr v (succ: Vertex<IRBasicBlock>) =
    let srcV, newGraph = getVertex newGraph vMap v addr
    Array.append srcV.VData.Instructions (succ.VData.GetInstructions ())
    |> Array.fold (fun m i -> Map.add i.Address i m) Map.empty
    |> Map.toArray (* Remove overlapping instructions in an inefficient way. *)
    |> Array.map snd
    |> fun instrs -> srcV.VData.Instructions <- instrs
    newGraph

  let addEdge vMap newGraph sAddr src dst e =
    let dstAddr = (dst: Vertex<IRBasicBlock>).VData.PPoint.Address
    let srcV, newGraph = getVertex newGraph vMap src sAddr
    let dstV, newGraph = getVertex newGraph vMap dst dstAddr
    DiGraph.addEdge newGraph srcV dstV e

  interface ILens<DisasmBBlock> with
    member __.Filter (g, roots, _) =
      let newGraph = DisasmCFG.init g.ImplementationType
      let vMap = DisasmVMap ()
      let roots', newGraph =
        roots (* Add nodes to newGraph. *)
        |> List.fold (fun (roots, newGraph) r ->
          let r, newGraph = getVertex newGraph vMap r r.VData.PPoint.Address
          r :: roots, newGraph) ([], newGraph)
      let newGraph = dfs (merge vMap) (addEdge vMap) g newGraph roots
      newGraph, roots'

  static member Init (app) = DisasmLens (app) :> ILens<DisasmBBlock>

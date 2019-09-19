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

open B2R2
open B2R2.FrontEnd
open System.Collections.Generic

/// Basic block type for a disassembly-based CFG (DisasmCFG).
type DisasmBBlock (instrs: Instruction [], pp, hdl: BinHandler) =
  inherit BasicBlock()

  let mutable instructions = instrs

  override __.PPoint = pp

  override __.Range =
    let last = instructions.[instructions.Length - 1]
    AddrRange (last.Address, last.Address + uint64 last.Length)

  override __.IsFakeBlock () = Array.isEmpty instructions

  override __.ToVisualBlock () =
    instructions
    |> Array.map (fun i -> [ Address (Addr.toString hdl.ISA.WordSize i.Address)
                             String (i.Disasm ()) ])
    |> Array.toList

  member __.Instructions
    with get () = instructions
    and set (i) = instructions <- i

  member __.Disassemblies
    with get () =
      instructions |> Array.map (fun i -> i.Disasm ())

/// Disassembly-based CFG, where each node contains disassembly code.
type DisasmCFG = ControlFlowGraph<DisasmBBlock, CFGEdgeKind>

/// A mapping from an address to a DisasmCFG vertex.
type DisasmVMap = Dictionary<Addr, Vertex<DisasmBBlock>>

/// A graph lens for obtaining DisasmCFG.
type DisasmLens (hdl) =
  let getVertex g (vMap: DisasmVMap) (oldVertex: Vertex<IRBasicBlock>) addr =
    match vMap.TryGetValue addr with
    | false, _ ->
      let instrs = oldVertex.VData.GetInstructions ()
      let blk = DisasmBBlock (instrs, oldVertex.VData.PPoint, hdl)
      let v = (g: DisasmCFG).AddVertex blk
      vMap.Add (addr, v)
      v
    | true, v -> v

  let dfs fnMerge fnEdge (ircfg: IRCFG) (roots: Vertex<IRBasicBlock> list) =
    let visited = HashSet<ProgramPoint> ()
    let rec traverse = function
      | [] -> ()
      | (addr, v: Vertex<IRBasicBlock>) :: rest ->
        if visited.Contains v.VData.PPoint then traverse rest
        else
          visited.Add v.VData.PPoint |> ignore
          let acc = v.Succs |> List.fold (succFold addr v) rest
          traverse acc
    and succFold addr v acc succ =
      match ircfg.FindEdgeData v succ with
      | IndirectEdge
      | ExternalEdge
      | CallEdge
      | RetEdge -> acc
      | IntraCJmpTrueEdge
      | IntraCJmpFalseEdge
      | IntraJmpEdge ->
        fnMerge addr v succ
        if visited.Contains succ.VData.PPoint then acc
        else (addr, succ) :: acc
      | e ->
        fnEdge addr v succ e
        if visited.Contains succ.VData.PPoint then acc
        else (succ.VData.PPoint.Address, succ) :: acc
    roots
    |> List.map (fun r -> r.VData.PPoint.Address, r)
    |> traverse

  let merge newGraph vMap addr v (succ: Vertex<IRBasicBlock>) =
    let srcV = getVertex newGraph vMap v addr
    Array.append srcV.VData.Instructions (succ.VData.GetInstructions ())
    |> Array.fold (fun m i -> Map.add i.Address i m) Map.empty
    |> Map.toArray
    |> Array.map snd
    |> fun instrs -> srcV.VData.Instructions <- instrs

  let addEdge newGraph vMap sAddr src dst e =
    let dstAddr = (dst: Vertex<IRBasicBlock>).VData.PPoint.Address
    let srcV = getVertex newGraph vMap src sAddr
    let dstV = getVertex newGraph vMap dst dstAddr
    newGraph.AddEdge srcV dstV e

  interface ILens<DisasmBBlock> with
    member __.Filter (g: IRCFG) roots _ =
      let newGraph = DisasmCFG ()
      let vMap = DisasmVMap ()
      let roots' =
        roots
        |> List.map (fun r -> getVertex newGraph vMap r r.VData.PPoint.Address)
      dfs (merge newGraph vMap) (addEdge newGraph vMap) g roots
      newGraph, roots'

  static member Init (hdl) = DisasmLens (hdl) :> ILens<DisasmBBlock>

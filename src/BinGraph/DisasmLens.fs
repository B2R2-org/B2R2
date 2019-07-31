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
type DisasmBBlock (instructions: Instruction [], pp) =
  inherit BasicBlock()

  override __.PPoint = pp

  override __.Range =
    let last = instructions.[instructions.Length - 1]
    AddrRange (last.Address, last.Address + uint64 last.Length)

  override __.IsDummyBlock () = Array.isEmpty instructions

  override __.ToVisualBlock (binhandler) =
    __.Disassemblies (binhandler)
    |> Array.toList
    |> List.map (fun disasm -> [ String disasm ])

  member __.Disassemblies
    with get (binhandler) =
      match binhandler with
      | None ->
        instructions |> Array.map (fun i -> i.Disasm ())
      | Some hdl ->
        instructions |> Array.map (fun i -> i.Disasm (true, true, hdl.FileInfo))

/// Disassembly-based CFG, where each node contains disassembly code.
type DisasmCFG = ControlFlowGraph<DisasmBBlock, CFGEdgeKind>

/// A mapping from an address to a DisasmCFG vertex.
type DisasmVMap = Dictionary<Addr, Vertex<DisasmBBlock>>

/// A graph lens for obtaining DisasmCFG.
type DisasmLens () =
  let getVertex g (vMap: DisasmVMap) (oldVertex: Vertex<IRBasicBlock>) addr =
    match vMap.TryGetValue addr with
    | false, _ ->
      let instrs = oldVertex.VData.GetInstructions ()
      let blk = DisasmBBlock (instrs, oldVertex.VData.PPoint)
      let v = (g: DisasmCFG).AddVertex blk
      vMap.Add (addr, v)
      v
    | true, v -> v

  interface ILens<DisasmBBlock> with
    member __.Filter (g: CFGUtils.CFG) root =
      let newGraph = DisasmCFG ()
      let vMap = new DisasmVMap ()
      let root = getVertex newGraph vMap root root.VData.PPoint.Address
      g.IterEdge (fun src dst e ->
        match e with
        | IntraCJmpTrueEdge
        | IntraCJmpFalseEdge
        | IntraJmpEdge
        | CallEdge
        | RetEdge -> ()
        | e ->
          let srcAddr = src.VData.PPoint.Address
          let dstAddr = dst.VData.PPoint.Address
          let srcV = getVertex newGraph vMap src srcAddr
          let dstV = getVertex newGraph vMap dst dstAddr
          newGraph.AddEdge srcV dstV e)
      newGraph, root

  static member Init () = DisasmLens () :> ILens<DisasmBBlock>

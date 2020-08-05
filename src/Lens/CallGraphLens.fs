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
open B2R2.FrontEnd
open B2R2.BinGraph
open B2R2.BinEssence
open System.Collections.Generic

/// Basic block type for a call graph (CallCFG).
type CallGraphBBlock (addr, id, name, isFake, isExternal) =
  inherit BasicBlock ()

  member __.ID with get () = id

  member __.Name with get () = name

  member __.IsExternal with get () = isExternal

  override __.PPoint = ProgramPoint (addr, 0)

  override __.Range = AddrRange (addr, addr + 1UL)

  override __.IsFakeBlock () = isFake

  override __.ToVisualBlock () =
    [| [| { AsmWordKind = AsmWordKind.Address
            AsmWordValue = Addr.toString WordSize.Bit32 addr }
          { AsmWordKind = AsmWordKind.String
            AsmWordValue = ": " }
          { AsmWordKind = AsmWordKind.Value
            AsmWordValue = id } |] |]

/// Call graph, where each node represents a function.
type CallCFG = ControlFlowGraph<CallGraphBBlock, CFGEdgeKind>

module CallCFG =
  let private initializer core =
    CallCFG (core) :> DiGraph<CallGraphBBlock, CFGEdgeKind>

  let private initImperative () =
    ImperativeCore<CallGraphBBlock, CFGEdgeKind> (initializer, UnknownEdge)
    |> CallCFG
    :> DiGraph<CallGraphBBlock, CFGEdgeKind>

  let private initPersistent () =
    PersistentCore<CallGraphBBlock, CFGEdgeKind> (initializer, UnknownEdge)
    |> CallCFG
    :> DiGraph<CallGraphBBlock, CFGEdgeKind>

  /// Initialize CallCFG based on the implementation type.
  let init = function
    | ImperativeGraph -> initImperative ()
    | PersistentGraph -> initPersistent ()

/// A mapping from an address to a CallCFG vertex.
type CallVMap = Dictionary<Addr, Vertex<CallGraphBBlock>>

/// A graph lens for obtaining CallGraph.
type CallGraphLens (scfg: SCFG) =
  let getFunctionVertex g vMap (old: Vertex<IRBasicBlock>) addr ess =
    match (vMap: CallVMap).TryGetValue addr with
    | false, _ ->
      let fake = old.VData.IsFakeBlock ()
      match ess.SCFG.CalleeMap.Find (addr) with
      | None -> None
      | Some callee ->
        let id = callee.CalleeID
        let name = callee.CalleeName
        let ext = callee.CalleeKind = ExternalCallee
        let v, g =
          DiGraph.addVertex g (CallGraphBBlock (addr, id, name, fake, ext))
        vMap.Add (addr, v)
        Some (v, g)
    | true, v -> Some (v, g)

  let getVertex g vMap (old: Vertex<IRBasicBlock>) ess =
    let addr = old.VData.PPoint.Address
    match ess.SCFG.CalleeMap.Find (addr) with
    | None -> None
    | Some _ -> getFunctionVertex g vMap old addr ess

  let buildCG callCFG _ vMap ess =
    callCFG
    |> DiGraph.foldEdge scfg.Graph (fun callCFG src dst e ->
      match e with
      | IntraJmpEdge
      | IndirectJmpEdge
      | IndirectCallEdge
      | ExternalJmpEdge
      | ExternalCallEdge
      | CallEdge ->
        (* XXX: Should be fixed *)
        match scfg.FindFunctionVertex src.VData.PPoint.Address with
        | None -> callCFG
        | Some src ->
          match getVertex callCFG vMap src ess with
          | None -> callCFG
          | Some (s, callCFG) ->
            match getVertex callCFG vMap dst ess with
            | None -> callCFG
            | Some (d, callCFG) -> DiGraph.addEdge callCFG s d e
      | _ -> callCFG)

  interface ILens<CallGraphBBlock> with
    member __.Filter (g, _, ess) =
      let vMap = CallVMap ()
      let callCFG = buildCG (CallCFG.init g.ImplementationType) g vMap ess
      callCFG, DiGraph.getUnreachables callCFG |> Seq.toList

  static member Init (scfg) =
    CallGraphLens (scfg) :> ILens<CallGraphBBlock>

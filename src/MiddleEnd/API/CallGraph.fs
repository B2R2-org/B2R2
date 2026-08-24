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

namespace B2R2.MiddleEnd

open System.Collections.Generic
open B2R2
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Provides a lens that converts a BinaryBrew to a CallCFG.
[<RequireQualifiedAccess>]
module CallGraph =
  /// Represents a mapping from an address to a CallCFG vertex.
  type private CallVMap = Dictionary<Addr, IVertex<CallBasicBlock>>

  let private getVertex (brew: BinaryBrew<_, _>) vMap (callCFG: CallCFG) addr =
    match (vMap: CallVMap).TryGetValue addr with
    | false, _ ->
      let fn = brew.Functions[addr]
      let wordSize = brew.BinHandle.ISA.WordSize
      let blk = CallBasicBlock(wordSize, addr, fn.Name, fn.IsExternal)
      let v = callCFG.AddVertex blk
      vMap.Add(addr, v)
      v
    | true, v ->
      v

  let private addEdge brew vMap (callCFG: CallCFG) entryPoint target =
    let src = getVertex brew vMap callCFG entryPoint
    let dst = getVertex brew vMap callCFG target
    callCFG.AddEdge(src, dst, CallEdge)

  let private buildCG callCFG vMap (brew: BinaryBrew<_, _>) =
    for func in brew.Functions.Sequence do
      if isNull func.Callees then
        ()
      else
        for KeyValue(_, callee) in func.Callees do
          match callee with
          | RegularCallee target ->
            addEdge brew vMap callCFG func.EntryPoint target
          | IndirectCallees targets ->
            for target in targets do
              addEdge brew vMap callCFG func.EntryPoint target
          | SyscallCallee _
          | UnresolvedIndirectCallees
          | NullCallee ->
            ()

  /// Creates a CallCFG from a BinaryBrew.
  [<CompiledName "Create">]
  let create implType brew =
    let callGraph = CallCFG implType
    buildCG callGraph (CallVMap()) brew
    callGraph

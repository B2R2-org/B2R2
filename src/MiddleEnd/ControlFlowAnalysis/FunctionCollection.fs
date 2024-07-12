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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open System.Collections.Generic
open B2R2
open B2R2.MiddleEnd.ControlFlowGraph

/// Collection of recovered functions.
type FunctionCollection<'V,
                        'E,
                        'FnCtx,
                        'GlCtx when 'V :> IRBasicBlock
                                and 'V: equality
                                and 'E: equality
                                and 'FnCtx :> IResettable
                                and 'FnCtx: (new: unit -> 'FnCtx)
                                and 'GlCtx: (new: unit -> 'GlCtx)>
  public (builders: ICFGBuildable<'V, 'E, 'FnCtx, 'GlCtx>[]) =

  let addrToFunction = Dictionary<Addr, Function<'V, 'E>> ()

  let nameToFunction = Dictionary<string, List<Function<'V, 'E>>> ()

  /// Callee to callers.
  let callTable = Dictionary<Addr, List<Addr>> ()

  let addToCallTable caller callee =
    match callTable.TryGetValue callee with
    | true, callers -> callers.Add caller
    | false, _ ->
      let callers = List<Addr> ()
      callers.Add caller
      callTable.Add (callee, callers)

  let analyzeCallRelationship (fn: Function<_, _>) =
    if isNull fn.Callees then ()
    else
      for callee in fn.Callees.Values do
        match callee with
        | RegularCallee calleeAddr -> addToCallTable fn.EntryPoint calleeAddr
        | IndirectCallees calleeAddrs ->
          for calleeAddr in calleeAddrs do
            addToCallTable fn.EntryPoint calleeAddr
        | _ -> ()

  let updateCallers (fn: Function<_, _>) =
    match callTable.TryGetValue fn.EntryPoint with
    | true, callers ->
      for caller in callers do fn.Callers.Add caller |> ignore
    | false, _ -> ()

  let createFunctions () =
    builders
    |> Array.map (fun builder ->
      let fn = builder.ToFunction ()
      analyzeCallRelationship fn
      fn)

  let updateCollection fns =
    fns
    |> Array.iter (fun (fn: Function<_, _>) ->
      updateCallers fn
      addrToFunction.Add (fn.EntryPoint, fn)
      match nameToFunction.TryGetValue fn.Name with
      | false, _ ->
        let fns = List<Function<'V, 'E>> ()
        fns.Add fn
        nameToFunction.Add (fn.Name, fns)
      | true, fns -> fns.Add fn)

  let findByAddr addr =
    match addrToFunction.TryGetValue addr with
    | true, fn -> fn
    | _ -> raise (KeyNotFoundException ($"Function not found: {addr:x}"))

  do createFunctions () |> updateCollection

  /// Sequence of functions.
  member _.Sequence with get() = addrToFunction.Values

  /// Addresses of functions.
  member _.Addresses with get() = addrToFunction.Keys

  /// Number of functions in the collection.
  member _.Count with get() = addrToFunction.Count

  /// Find a function by its address.
  member _.Item with get(addr: Addr) = findByAddr addr

  /// Find a function by its address.
  member _.Find (addr: Addr) = findByAddr addr

  /// Find a function by its name. If there are multiple functions with the same
  /// name, this function returns all of them.
  member _.Find (name: string) =
    match nameToFunction.TryGetValue name with
    | true, fns -> fns
    | false, _ -> raise (KeyNotFoundException ($"Function not found: {name}"))

  /// Find a function by its function ID.
  member _.FindByID (id: string) =
    findByAddr <| Addr.ofFuncName id

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

type FunctionCollection<'V,
                        'E,
                        'Abs,
                        'FnCtx,
                        'GlCtx when 'V :> IRBasicBlock<'Abs>
                                and 'V: equality
                                and 'E: equality
                                and 'Abs: null
                                and 'FnCtx :> IResettable
                                and 'FnCtx: (new: unit -> 'FnCtx)
                                and 'GlCtx: (new: unit -> 'GlCtx)>
  public (builders: IFunctionBuildable<'V, 'E, 'Abs, 'FnCtx, 'GlCtx>[]) =

  let addrToFunction = Dictionary<Addr, Function<'V, 'E, 'Abs>> ()

  let nameToFunction = Dictionary<string, List<Function<'V, 'E, 'Abs>>> ()

  let findByAddr addr =
    match addrToFunction.TryGetValue addr with
    | true, fn -> fn
    | _ -> raise (KeyNotFoundException ($"Function not found: {addr:x}"))

  do builders
     |> Array.iter (fun builder ->
       let fn = builder.ToFunction ()
       addrToFunction.Add (fn.EntryPoint, fn)
       match nameToFunction.TryGetValue fn.Name with
       | false, _ ->
         let fns = List<Function<'V, 'E, 'Abs>> ()
         fns.Add fn
         nameToFunction.Add (fn.Name, fns)
       | true, fns -> fns.Add fn)

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

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

namespace B2R2.RearEnd.Transformer

open System.Threading
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// The `dot` action.
type DOTAction() =
  let vToStr (v: IVertex<LowUIRBasicBlock>) =
    let addr = v.VData.Internals.BlockAddress.ToString "x"
    let instrs =
      v.VData.Internals.Instructions
      |> Array.map (fun ins ->
        let bld = StringDisasmBuilder(true, null, WordSize.Bit64)
        ins.Disasm bld)
      |> String.concat "\\l"
    $"[label=\"[{addr:x}]\\l{instrs}\\l\"]"

  let toDOT cancellationToken o =
    let cancellationToken: CancellationToken = cancellationToken
    cancellationToken.ThrowIfCancellationRequested()
    let artifact =
      match unbox<CFG> o with
      | CFG(addr, cfg, _) ->
        let name = Addr.toFuncName addr
        { Name = name
          Extension = ".dot"
          Content =
            Serializer.ToDOT(cfg, name, vToStr, (fun e -> e.ToString())) }
      | NoCFG e ->
        { Name = "cfg-error"
          Extension = ".txt"
          Content = $"Failed to construct CFG: {e}" }
    box artifact

  let transform cancellationToken collection =
    { Values = collection.Values |> Array.map (toDOT cancellationToken) }

  interface IAction with
    member _.ActionID with get() = "dot"
    member _.Signature with get() = "CFG -> TextArtifact"
    member _.Description with get() =
      """
    Take in a CFG as input, and returns a string representation of the CFG in
    DOT format.
"""
    member _.Transform(args, collection) =
      match args with
      | [] -> transform CancellationToken.None collection
      | _ -> invalidArg (nameof args) "Invalid argument."

  interface ICancellableAction with
    member _.Transform(args, collection, cancellationToken) =
      match args with
      | [] -> transform cancellationToken collection
      | _ -> invalidArg (nameof args) "Invalid argument."

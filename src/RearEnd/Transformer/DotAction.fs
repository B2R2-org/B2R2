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

open B2R2
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// The `dot` action.
type DOTAction () =
  let vToStr (v: IVertex<IRBasicBlock>) =
    let id = v.VData.FirstInsInfo.BBLAddr.ToString "x"
    let instrs =
      v.VData.Instructions
      |> Array.map (fun ins -> ins.Disasm (true, null))
      |> String.concat "\\l"
    $"n_{id}", $"[label=\"{instrs}\\l\"]"

  let toDOT o =
    match unbox<CFG> o with
    | CFG (addr, cfg) ->
      let name = Addr.toFuncName addr
      cfg.ToDOTStr (name, vToStr, (fun _ -> ""))
    | NoCFG e -> $"Failed to construct CFG: {e}"

  interface IAction with
    member __.ActionID with get() = "dot"
    member __.Signature with get() = "CFG -> string"
    member __.Description with get() = """
    Take in a CFG as input, and returns a string representation of the CFG in
    DOT format.
"""
    member __.Transform _args collection =
      { Values = [| collection.Values |> Array.map toDOT |] }

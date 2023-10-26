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
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinEssence
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// The `cfg` action.
type CFGAction () =
  let vToStr (v: Vertex<IRBasicBlock>) =
    let id = v.VData.FirstInsInfo.BBLAddr.ToString "x"
    let instrs =
      v.VData.Instructions
      |> Array.map (fun ins -> ins.Disasm (true, null))
      |> String.concat "\\l"
    $"n_{id}", $"[label=\"{instrs}\\l\"]"

  let printOut hdl (fn: RegularFunction) = function
    | Ok () ->
      let addr = fn.MinAddr
      fn.IRCFG.ToDOTStr ($"func_{addr:x}", vToStr, (fun _ -> "e"))
    | Error e -> e.ToString ()

  let getCFG (input: obj) =
    match input with
    | :? Binary as bin ->
      let hdl = Binary.Handle bin
      let ess = BinEssence.empty hdl
      let ep = hdl.File.EntryPoint |> Option.defaultValue 0UL
      let fn = ess.CodeManager.FunctionMaintainer.GetOrAddFunction ep
      let eAddr = uint64 hdl.File.Length - 1UL
      let mode = hdl.Parser.OperationMode
      let builder = CFGBuilder (hdl, ess.CodeManager, ess.DataManager)
      let evts = CFGEvents.empty
      ess.CodeManager.ParseSequence hdl mode ep eAddr fn evts
      |> Result.bind (fun evts ->
        (builder :> ICFGBuildable).Update (evts, true)
        |> Result.mapError (fun _ -> ErrorCase.FailedToRecoverCFG))
      |> printOut hdl fn
    | _ -> invalidArg (nameof input) "Invalid argument."

  interface IAction with
    member __.ActionID with get() = "cfg"
    member __.Signature with get() = "Binary -> CFG"
    member __.Description with get() = """
    Take in a Binary as input and returns a control flow graph as output (in the
    DOT format). This action assumes that the given binary is well-formed,
    meaning that it has no bad instructions, and the control does not flow in
    the middle of an instruction. Any indirect branches will be simply ignored,
    i.e., it does not perform heavy analyses in our middle-end.
"""
    member __.Transform _args collection =
      { Values = [| collection.Values |> Array.map getCFG |] }

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

open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

/// The `cfg` action.
type CFGAction () =
  let getCFG (input: obj) =
    match input with
    | :? Binary as bin ->
      let hdl = Binary.Handle bin
      let brew = BinaryBrew hdl
      brew.Functions[0UL].CFG
      |> DisasmCFG.create
      |> box
    | _ -> invalidArg (nameof input) "Invalid argument."

  interface IAction with
    member __.ActionID with get() = "cfg"
    member __.Signature with get() = "Binary -> CFG"
    member __.Description with get() = """
    Take in a Binary as input and returns an IR-level Control Flow Graph (CFG)
    as output. This action assumes that the given binary is well-formed, meaning
    that it has no bad instructions, and the control does not flow in the middle
    of an instruction. Any indirect branches will be simply ignored, i.e., it
    does not perform any of the heavy analyses in our middle-end.
"""
    member __.Transform _args collection =
      { Values = collection.Values |> Array.map getCFG }

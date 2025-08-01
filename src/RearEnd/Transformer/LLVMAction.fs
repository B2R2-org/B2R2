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

open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.LLVM

/// The `llvm` action.
type LLVMAction() =

  let printOut hdl (fn: Function) =
    let builder = LLVMTranslator.createBuilder hdl fn.EntryPoint
    fn.CFG.IterVertex(fun bbl ->
      let succs =
        fn.CFG.GetSuccs bbl
        |> Array.map (fun s -> s.VData.Internals.PPoint.Address)
        |> Array.toList
      let bblAddr = bbl.VData.Internals.PPoint.Address
      bbl.VData.Internals.LiftedInstructions
      |> Array.collect (fun ins -> ins.Stmts)
      |> LLVMTranslator.translate builder bblAddr succs
    )
    builder.ToString()

  let translate (o: obj) =
    let bin = unbox<Binary> o
    let hdl = Binary.Handle bin
    let brew = BinaryBrew hdl
    let entryPoint = hdl.File.EntryPoint |> Option.defaultValue 0UL
    let fn = brew.Functions[entryPoint]
    printOut hdl fn

  interface IAction with
    member _.ActionID with get() = "llvm"
    member _.Signature with get() = "Binary -> string"
    member _.Description with get() = """
    Take in a parsed binary and lift it to an LLVM function, and then dump the
    lifted function to a string.
"""
    member _.Transform(args, collection) =
      match args with
      | [] -> { Values = [| collection.Values |> Array.map translate |] }
      | _ -> invalidArg (nameof args) "Invalid argument."

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
open B2R2.MiddleEnd.BinEssence
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.LLVM

/// The `llvm` action.
type LLVMAction () =
  let printOut hdl (fn: RegularFunction) = function
    | Ok () ->
      let builder = LLVMTranslator.createBuilder hdl fn.MinAddr
      fn.IRCFG.IterVertex (fun bbl ->
        let succs =
          fn.IRCFG.GetSuccs bbl
          |> Seq.toList
          |> List.map (fun s -> s.VData.PPoint.Address)
        let bblAddr = bbl.VData.PPoint.Address
        bbl.VData.IRStatements
        |> Array.concat
        |> LLVMTranslator.translate builder bblAddr succs
      )
      builder.ToString ()
    | Error e -> e.ToString ()

  let translate (o: obj) =
    let bin = unbox<Binary> o
    let hdl = Binary.Handle bin
    let ess = BinEssence.empty hdl
    let ep = hdl.File.EntryPoint |> Option.defaultValue 0UL
    let fn = ess.CodeManager.FunctionMaintainer.GetOrAddFunction ep
    let eAddr = uint64 hdl.File.Length - 1UL
    let mode = hdl.Parser.OperationMode
    let builder = CFGBuilder (hdl, ess.CodeManager, ess.JumpTables)
    let evts = CFGEvents.empty
    ess.CodeManager.ParseSequence hdl mode ep eAddr fn evts
    |> Result.bind (fun evts ->
      (builder :> ICFGBuildable).Update (evts, true)
      |> Result.mapError (fun _ -> ErrorCase.FailedToRecoverCFG))
    |> printOut hdl fn

  interface IAction with
    member __.ActionID with get() = "llvm"
    member __.Signature with get() = "Binary -> string"
    member __.Description with get() = """
    Take in a parsed binary and lift it to an LLVM function, and then dump the
    lifted function to a string.
"""
    member __.Transform args collection =
      match args with
      | [] -> { Values = [| collection.Values |> Array.map translate |] }
      | _ -> invalidArg (nameof args) "Invalid argument."

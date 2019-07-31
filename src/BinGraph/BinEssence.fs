(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
          Soomin Kim <soomink@kaist.ac.kr>

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

namespace B2R2.BinGraph

open B2R2.FrontEnd

/// Represent the "essence" of a binary code. This is the primary data structure
/// for storing various information about a binary, such as its CFG, FileFormat
/// information, etc.
type BinEssence = {
  /// BInary handler.
  BinHandler: BinHandler
  /// Binary apparatus holds crucial machinery about binary code and their
  /// lifted statements. For example, it provides a convenient mapping from an
  /// address to the corresponding instruction and IR statements.
  BinaryApparatus: BinaryApparatus
  /// Super Control Flow Graph.
  SCFG: SCFG
}
with
  static member private BuildFoundation hdl app =
    let scfg = SCFG (hdl, app)
    let app =
      CFGUtils.callTargets scfg.Graph
      |> BinaryApparatus.updateFuncs hdl app
    struct (scfg, app)

  static member private Analysis hdl app (scfg: SCFG) analyzers =
    let app' = CFGUtils.postAnalysis scfg.Graph app analyzers
    if app' = app then
      { BinHandler = hdl
        BinaryApparatus = app'
        SCFG = scfg }
    else
      let struct (scfg', app') = BinEssence.BuildFoundation hdl app'
      BinEssence.Analysis hdl app' scfg' analyzers

  static member Init hdl =
    let app = BinaryApparatus.init hdl
    let struct (scfg, app) = BinEssence.BuildFoundation hdl app
    BinEssence.Analysis hdl app scfg []

#if false
  static member Init _verbose hdl =
    (* Currently no other choice *)
    let funcs = CFGUtils.construct hdl (CFGBuilder ()) Default
    let funcs = CFGUtils.analCalls funcs
    let callGraph = ControlFlowGraph ()
    CFGUtils.buildCallGraph hdl funcs callGraph
    NoReturn.noReturnAnalysis hdl callGraph
    { BinHandler = hdl
      Functions = funcs
      CallGraph = callGraph }

  static member FindFuncByEntry entry ess =
    ess.Functions.Values |> List.ofSeq
    |> List.find (fun (func: Function) -> func.Entry = entry)

  static member TryFindFuncByEntry entry ess =
    ess.Functions.Values |> List.ofSeq
    |> List.tryPick (fun (func: Function) ->
        if func.Entry = entry then Some func else None)

  static member TryFindFuncByName name ess =
    ess.Functions.Values |> List.ofSeq
    |> List.tryPick (fun (func: Function) ->
        if func.Name = name then Some func else None)

  static member DisasmVertexToDOT v =
    "\"" + CFGUtils.disasmVertexToString v + "\""

  static member IrVertexToDOT v =
    "\"" + CFGUtils.irVertexToString v + "\""

  static member EdgeToDOT (Edge e) = // FIXME
    sprintf "%A" e

  static member ShowDisasmDOT name (disasmCFG: DisasmCFG) =
    disasmCFG.ToDOTStr name BinEssence.DisasmVertexToDOT BinEssence.EdgeToDOT
    |> System.Console.WriteLine

  static member ShowIRDOT name (irCFG: IRCFG) =
    irCFG.ToDOTStr name BinEssence.IrVertexToDOT BinEssence.EdgeToDOT
    |> System.Console.WriteLine

  static member ShowDot ess =
    ess.Functions.Values
    |> Seq.iter (fun (func: Function) ->
        let name = "\"" + func.Entry.ToString ("X") + "\""
        BinEssence.ShowDisasmDOT name func.DisasmCFG
        BinEssence.ShowIRDOT name func.IRCFG)
#endif

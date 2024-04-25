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

open System
open System.Diagnostics
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// <summary>
///   BinaryBrew is a potent brew of analyzed (and recovered) information about
///   the target binary, such as instructions, IRs, functions, CFGs, and
///   exception information, etc.
/// </summary>
type BinaryBrew<'V,
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
  public (hdl: BinHandle,
          strategy: IFunctionBuildingStrategy<_, _, _, _, _>) =

  let exnInfo = ExceptionInfo (hdl)

  let instrs = InstructionCollection (LinearSweepInstructionCollector hdl)

  let cfgConstructor =
    { new IRCFG.IConstructable<'V, 'E, 'Abs> with
        member _.Construct _ =
          ImperativeDiGraph<'V, 'E> () :> IRCFG<'V, 'E, 'Abs> }

  let taskManager =
    TaskManager<'V, 'E, 'Abs, 'FnCtx, 'GlCtx>
      (hdl, instrs, cfgConstructor, strategy)

  let getFunctionOperationMode (hdl: BinHandle) entry =
    match hdl.File.ISA.Arch with
    | Architecture.ARMv7 ->
      if entry &&& 1UL = 1UL then
        entry - 1UL, ArchOperationMode.ThumbMode
      else entry, ArchOperationMode.ARMMode
    | _ -> entry, ArchOperationMode.NoMode

  /// This function returns an initial sequence of entry points obtained from
  /// the binary itself (e.g., from its symbol information). Therefore, if the
  /// binary is stripped, the returned sequence will be incomplete, and we need
  /// to expand it during the main recovery phase.
  let getInitialEntryPoints () =
    let file = hdl.File
    let entries =
      file.GetFunctionAddresses ()
      |> Set.ofSeq
      |> Set.union exnInfo.FunctionEntryPoints
    file.EntryPoint
    |> Option.fold (fun acc addr ->
      if file.Type = FileType.LibFile && addr = 0UL then acc
      else Set.add addr acc) entries
    |> Set.toArray
    |> Array.map (getFunctionOperationMode hdl)

  let recoverFunctions () =
    #if DEBUG
    let sw = Stopwatch ()
    Console.WriteLine "[*] CFG recovery started."
    sw.Start ()
    #endif
    let funcs = taskManager.RecoverCFGs <| getInitialEntryPoints ()
    #if DEBUG
    sw.Stop ()
    let ts = sw.Elapsed
    Console.WriteLine $"[*] Total {ts.TotalSeconds}s elapsed."
    #endif
    funcs

  let funcs = recoverFunctions ()

  /// Low-level access to binary code and data.
  member _.BinHandle with get(): BinHandle = hdl

  /// Recovered functions.
  member _.Functions with get() = funcs

  /// Exception information.
  member _.ExceptionInfo with get() = exnInfo

  /// Get the instruction at the given address.
  member _.Instructions with get() = instrs

/// Default BinaryBrew type that internally uses SSA IR to recover CFGs.
type DefaultBinaryBrew =
  BinaryBrew<IRBasicBlock<BaseFunctionSummary>,
             CFGEdgeKind,
             BaseFunctionSummary,
             Strategies.DummyContext,
             Strategies.DummyContext>

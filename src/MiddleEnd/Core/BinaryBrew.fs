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
open B2R2.FrontEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

/// <summary>
///   BinaryBrew is a potent brew of analyzed (and recovered) information about
///   the target binary, such as instructions, IRs, functions, CFGs, and
///   exception information, etc.
/// </summary>
type BinaryBrew<'FnCtx,
                'GlCtx when 'FnCtx :> IResettable
                        and 'FnCtx: (new: unit -> 'FnCtx)
                        and 'GlCtx: (new: unit -> 'GlCtx)>
  public (hdl: BinHandle,
          exnInfo: ExceptionInfo,
          strategies: ICFGBuildingStrategy<_, _>[],
          allowBBLOverlap) =

  let instrs = InstructionCollection (LinearSweepInstructionCollector hdl)

  let cfgConstructor =
    { new LowUIRCFG.IConstructable with
        member _.AllowBBLOverlap with get() = allowBBLOverlap
        member _.Construct _ =
          ImperativeDiGraph<LowUIRBasicBlock, CFGEdgeKind> () :> LowUIRCFG }

  let builders = CFGBuilderTable (hdl, exnInfo, instrs, cfgConstructor)

  let missions = strategies |> Array.map RecoveryMission<'FnCtx, 'GlCtx>

  let buildersToFunctions (builders: CFGBuilderTable<_, _>) =
    builders.Values
    |> Array.filter (fun builder -> builder.BuilderState = Finished)
    |> FunctionCollection

  let recoverFunctions () =
    let sw = Stopwatch ()
    Console.WriteLine "[*] CFG recovery started."
    sw.Start ()
    let funcs =
      missions
      |> Array.fold (fun builders mission -> mission.Execute builders) builders
      |> buildersToFunctions
    sw.Stop ()
    let ts = sw.Elapsed
    Console.WriteLine $"[*] Total {ts.TotalSeconds}s elapsed."
    funcs

  let funcs = recoverFunctions ()

  new (hdl: BinHandle, strategies) =
    let exnInfo = ExceptionInfo (hdl)
    BinaryBrew (hdl, exnInfo, strategies, false)

  /// Low-level access to binary code and data.
  member _.BinHandle with get(): BinHandle = hdl

  /// Recovered functions.
  member _.Functions with get() = funcs

  /// Exception information.
  member _.ExceptionInfo with get() = exnInfo

  /// Get the instruction at the given address.
  member _.Instructions with get() = instrs

/// Default BinaryBrew type that internally uses SSA IR to recover CFGs.
type BinaryBrew =
  inherit BinaryBrew<DummyContext, DummyContext>

  new (hdl: BinHandle, exnInfo, strategies, allowBBLOverlap) =
    { inherit BinaryBrew<DummyContext, DummyContext>
        (hdl, exnInfo, strategies, allowBBLOverlap) }

  new (hdl: BinHandle, exnInfo, strategies) =
    { inherit BinaryBrew<DummyContext, DummyContext>
        (hdl, exnInfo, strategies, false) }

  new (hdl: BinHandle, strategies) =
    { inherit BinaryBrew<DummyContext, DummyContext> (hdl, strategies) }

  new (hdl: BinHandle) =
    let exnInfo = ExceptionInfo hdl
    let funcId = FunctionIdentification (hdl, exnInfo)
    let strategies =
      [| funcId :> ICFGBuildingStrategy<_, _>
         CFGRecovery () |]
    { inherit BinaryBrew<DummyContext, DummyContext> (hdl,
                                                      exnInfo,
                                                      strategies,
                                                      false) }

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

open System.Runtime.InteropServices
open System
open System.Diagnostics
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

/// <namespacedoc>
///   <summary>
///   Contains the APIs for the B2R2 middle-end, which is responsible for
///   recovering functions and their control flow graphs (CFGs) from the target
///   binary.
///   </summary>
/// </namespacedoc>
/// <summary>
/// BinaryBrew is a potent brew of analyzed (and recovered) information about
/// the target binary, such as instructions, IRs, functions, CFGs, and exception
/// information, etc.
/// </summary>
type BinaryBrew<'FnCtx,
                'GlCtx when 'FnCtx :> IResettable
                        and 'FnCtx: (new: unit -> 'FnCtx)
                        and 'GlCtx: (new: unit -> 'GlCtx)>
  public(hdl: BinHandle,
         exnInfo: ExceptionInfo,
         funcID: IFunctionIdentifiable,
         cfgBuilder: ICFGBuildingStrategy<_, _>,
         irBlkOptimizer: IIRBlockOptimizable) =

  let numThreads = Environment.ProcessorCount / 2

  let instrs = InstructionCollection(LinearSweepInstructionCollector hdl)

  let builders = CFGBuilderTable(hdl, exnInfo, instrs, irBlkOptimizer)

  let buildersToFunctions (builders: CFGBuilderTable<_, _>) =
    builders.Values
    |> Array.filter (fun builder -> builder.BuilderState = Finished)
    |> FunctionCollection

  let recoverFunctions () =
    let sw = Stopwatch()
    Console.WriteLine "[*] CFG recovery started."
    sw.Start()
    let candidates = funcID.Identify()
    let manager = TaskManager<'FnCtx, 'GlCtx>(builders, cfgBuilder, numThreads)
    manager.StartAndWait candidates
    sw.Stop()
    let ts = sw.Elapsed
    Console.WriteLine $"[*] Total {ts.TotalSeconds}s elapsed."
    buildersToFunctions builders

  let funcs = recoverFunctions ()

  new(hdl: BinHandle, funcId, cfgRecovery) =
    let exnInfo = ExceptionInfo hdl
    BinaryBrew(hdl, exnInfo, funcId, cfgRecovery, null)

  new(hdl: BinHandle, funcId, cfgBuilder, irBlkOptimizer) =
    let exnInfo = ExceptionInfo hdl
    BinaryBrew(hdl, exnInfo, funcId, cfgBuilder, irBlkOptimizer)

  new(hdl: BinHandle, exnInfo, funcId, cfgBuilder) =
    BinaryBrew(hdl, exnInfo, funcId, cfgBuilder, null)

  /// Low-level access to binary code and data.
  member _.BinHandle with get(): BinHandle = hdl

  /// Recovered functions.
  member _.Functions with get() = funcs

  /// Exception information.
  member _.ExceptionInfo with get() = exnInfo

  /// Get the instruction at the given address.
  member _.Instructions with get() = instrs

  member _.Builders with get() = builders

/// Default BinaryBrew type that internally uses SSA IR to recover CFGs.
type BinaryBrew =
  inherit BinaryBrew<DummyContext, DummyContext>

  new(hdl: BinHandle, exnInfo: ExceptionInfo, cfgBuilder) =
    let funcId = FunctionIdentification(hdl, exnInfo)
    { inherit BinaryBrew<DummyContext, DummyContext>(hdl, exnInfo, funcId,
                                                     cfgBuilder) }

  new(hdl: BinHandle, funcId, cfgBuilder) =
    { inherit BinaryBrew<DummyContext, DummyContext>(hdl, funcId, cfgBuilder) }

  new(hdl: BinHandle,
      [<Optional; DefaultParameterValue(false)>] allowBBLOverlap) =
    let exnInfo = ExceptionInfo hdl
    let funcId = FunctionIdentification(hdl, exnInfo)
    let cfgBuilder = CFGRecovery(allowBBLOverlap) :> ICFGBuildingStrategy<_, _>
    { inherit BinaryBrew<DummyContext, DummyContext>(hdl,
                                                     exnInfo,
                                                     funcId,
                                                     cfgBuilder) }

  new(hdl: BinHandle, targets) =
    let exnInfo = ExceptionInfo hdl
    let funcId = FunctionIdentification(hdl, exnInfo)
    let cfgBuilder = CFGRecovery(false, targets) :> ICFGBuildingStrategy<_, _>
    BinaryBrew(hdl, funcId, cfgBuilder)

/// Default BinaryBrew type that uses EVM-specific user context.
type EVMBinaryBrew =
  inherit BinaryBrew<EVMFuncUserContext, DummyContext>

  new(hdl: BinHandle, cfgBuilder) =
    let optimizer =
      { new IIRBlockOptimizable with
          (* Dead Code Analysis can disturb the data-flow analysis in
             an inter-procedural level, so we disable it. *)
          member _.Optimize stmts =
            LocalOptimizer.Optimize(stmts, ConstantFolding.optimize) }
    let funcId =
      { new IFunctionIdentifiable with
          member _.Identify() = [| 0x0UL |] }
    { inherit BinaryBrew<EVMFuncUserContext, DummyContext>(hdl,
                                                           funcId,
                                                           cfgBuilder,
                                                           optimizer) }

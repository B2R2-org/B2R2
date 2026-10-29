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

namespace B2R2.MiddleEnd.Tests

open System
open System.Collections.Concurrent
open System.IO
open System.Runtime.CompilerServices
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

[<TestClass>]
type BinaryBrewTests() =
  let recoverFunctions name =
    let bytes = readZippedBinary name
    BinaryBrew(BinHandle.LoadFileBytes(bytes, ISA "x64")).Functions

  /// Wraps the default strategy, letting a test take over how it handles each
  /// action and how it makes and resets its contexts.
  let wrapStrategy onAction (contexts: IContextProvidable<_, _>) =
    let inner = CFGRecovery() :> ICFGBuildingStrategy<_, _>
    { new ICFGBuildingStrategy<DummyContext, DummyContext> with
        member _.CreateFunctionContext() = contexts.CreateFunctionContext()
        member _.ResetFunctionContext ctx = contexts.ResetFunctionContext ctx
        member _.CreateGlobalContext() = contexts.CreateGlobalContext()
        member _.ActionPrioritizer = inner.ActionPrioritizer
        member _.RecoveryTargets = inner.RecoveryTargets
        member _.OnAction(ctx, queue, action) = onAction inner ctx queue action
        member _.OnCreate ctx = inner.OnCreate ctx
        member _.OnFinish ctx = inner.OnFinish ctx
        member _.OnCyclicDependency deps = inner.OnCyclicDependency deps
        member _.FindCandidatesForPostProcessing builders =
          inner.FindCandidatesForPostProcessing builders }

  /// Wraps the default strategy so that every action first runs the given
  /// hook, which lets a test make the recovery fail on purpose.
  let hookStrategy hook =
    let onAction (inner: ICFGBuildingStrategy<_, _>) ctx queue action =
      hook ctx
      inner.OnAction(ctx, queue, action)
    wrapStrategy onAction (CFGRecovery())

  let throwingHook (_: CFGBuildingContext<DummyContext, DummyContext>) =
    raise (InvalidOperationException "boom")

  /// Brews a one-instruction binary whose only function is at address zero.
  let brewRetWith strategy =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let hdl = BinHandle.LoadRawImage([| 0xc3uy |], isa)
    let funcId =
      { new IFunctionIdentifiable with
          member _.Identify() = [| 0UL |] }
    BinaryBrew(hdl, funcId, strategy)

  let brewRet hook = brewRetWith (hookStrategy hook)

  /// Makes and resets contexts like the default strategy, logging each call.
  let loggingContexts (log: ConcurrentQueue<string>) =
    { new IContextProvidable<DummyContext, DummyContext> with
        member _.CreateFunctionContext() =
          log.Enqueue "create"
          DummyContext()
        member _.ResetFunctionContext _ = log.Enqueue "reset"
        member _.CreateGlobalContext() =
          log.Enqueue "global"
          DummyContext() }

  /// Handles actions like the default strategy, except that the very first
  /// one asks for the builder to be reloaded, which resets its context.
  let reloadOnce () =
    let reloaded = ref false
    fun (inner: ICFGBuildingStrategy<_, _>) ctx queue action ->
      if reloaded.Value then
        inner.OnAction(ctx, queue, action)
      else
        reloaded.Value <- true
        StopAndReload

  /// Brews a one-instruction binary and drops the brew, handing back only a
  /// weak reference to the binary. Inlining it would let a local of the caller
  /// keep the binary alive.
  [<MethodImpl(MethodImplOptions.NoInlining)>]
  static member private BrewAndDrop() =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let hdl = BinHandle.LoadRawImage([| 0xc3uy |], isa)
    BinaryBrew hdl |> ignore
    WeakReference hdl

  [<TestMethod>]
  member _.``BinaryBrew lets go of its binary once it is dropped``() =
    let binary = BinaryBrewTests.BrewAndDrop()
    GC.Collect()
    GC.WaitForPendingFinalizers()
    GC.Collect()
    Assert.AreEqual<bool>(false, binary.IsAlive)

  [<TestMethod>]
  member _.``BinaryBrew recovers functions its import table resolves to``() =
    (* The two IRELATIVE slots of this static binary resolve to its own ifunc
       resolvers, resolve_f and resolve_g. *)
    let addrs = (recoverFunctions "elf_x64_iplt").Addresses
    CollectionAssert.IsSubsetOf([| 0x2012f0UL; 0x201300UL |], addrs)

  [<TestMethod>]
  member _.``BinaryBrew tags stubs to its own functions as PLT references``() =
    (* The .iplt stubs of this static binary jump through slots that its own
       resolvers fill, so each stub refers to a function of the binary. *)
    let fns = recoverFunctions "elf_x64_iplt"
    let stubs =
      [ 0x201340UL; 0x201350UL ]
      |> List.map (fun addr -> fns[addr].Name, fns[addr].IsExternal)
    let expected = [ "f@plt", true; "g@plt", true ]
    Assert.AreEqual<(string * bool) list>(expected, stubs)

  [<TestMethod>]
  member _.``BinaryBrew tags slots of its own functions as GOT references``() =
    (* Built with -fno-plt, entry calls helper through a GLOB_DAT slot that is
       bound to the helper of this very library, unless another interposes. *)
    let named =
      (recoverFunctions "elf_x64_noplt").Sequence
      |> Seq.sortBy (fun fn -> fn.EntryPoint)
      |> Seq.map (fun fn -> fn.Name, fn.IsExternal)
      |> Seq.toList
    let expected = [ "helper", false; "entry", false; "helper@got", true ]
    Assert.AreEqual<(string * bool) list>(expected, named)

  [<TestMethod>]
  member _.``BinaryBrew writes nothing to the console``() =
    use captured = new StringWriter()
    let stdout, stderr = Console.Out, Console.Error
    Console.SetOut captured
    Console.SetError captured
    try
      brewRet throwingHook |> ignore
    finally
      Console.SetOut stdout
      Console.SetError stderr
    Assert.AreEqual<string>("", captured.ToString())

  [<TestMethod>]
  member _.``BinaryBrew reports a function whose recovery throws``() =
    let brew = brewRet throwingHook
    let failures =
      brew.RecoveryFailures
      |> Array.map (fun f -> f.EntryPoint, f.Exception.Message)
      |> Array.toList
    Assert.AreEqual<(Addr * string) list>([ 0UL, "boom" ], failures)
    Assert.AreEqual<int>(0, brew.Functions.Count)

  [<TestMethod>]
  member _.``BinaryBrew aborts when its global context fails to update``() =
    let hook (ctx: CFGBuildingContext<DummyContext, DummyContext>) =
      ctx.ManagerChannel.UpdateGlobalContext(fun _ ->
        raise (InvalidOperationException "boom"))
    Assert.Throws<AggregateException>(fun () -> brewRet hook |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``BinaryBrew aborts when its recovery runs out of memory``() =
    let hook (_: CFGBuildingContext<DummyContext, DummyContext>) =
      raise (OutOfMemoryException())
    Assert.Throws<AggregateException>(fun () -> brewRet hook |> ignore)
    |> ignore

  [<TestMethod>]
  member _.``BinaryBrew makes and resets contexts through its strategy``() =
    let log = ConcurrentQueue<string>()
    wrapStrategy (reloadOnce ()) (loggingContexts log)
    |> brewRetWith
    |> ignore
    let calls = log |> Seq.distinct |> Seq.sort |> Seq.toList
    Assert.AreEqual<string list>([ "create"; "global"; "reset" ], calls)

  [<TestMethod>]
  member _.``BinaryBrew keeps what callers know of each finished function``() =
    let bytes = readZippedBinary "elf_x64_iplt"
    let brew = BinaryBrew(BinHandle.LoadFileBytes(bytes, ISA "x64"))
    let builders =
      brew.Builders.Values
      |> Array.filter (fun builder -> builder.BuilderState = Finished)
    let expected =
      builders
      |> Array.map (fun builder ->
        let ctx = builder.Context
        { Status = ctx.NonReturningStatus
          Unwinding = ctx.UnwindingBytes
          Clobbered = Set.ofSeq ctx.ClobberedRegs
          IsExternal = builder.IsExternal })
      |> Array.toList
    let actual = builders |> Array.map (fun b -> b.CalleeInfo) |> Array.toList
    Assert.AreNotEqual<int>(0, builders.Length)
    Assert.AreEqual<CalleeInfo list>(expected, actual)

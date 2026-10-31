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
open B2R2.ABI
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

[<TestClass>]
type BinaryBrewTests() =
  let recoverFunctions name =
    let bytes = readZippedBinary name
    BinaryBrew(BinHandle.LoadFileBytes(bytes, ISA "x64")).Functions

  /// Collects the blocks that the indirect branch of the given jump table
  /// reaches through the table, in address order.
  let jumpTargets (fn: Function) (jmptbl: JmpTableInfo) =
    let jmp =
      fn.CFG.FindVertexBy(fun v ->
        not v.VData.Internals.IsAbstract
        && v.VData.Internals.LastInstruction.Address = jmptbl.InsAddr)
    fn.CFG.GetSuccEdges jmp
    |> Array.filter (fun e -> e.Label = IndirectJmpEdge)
    |> Array.map (fun e -> e.Second.VData.Internals.BlockAddress)
    |> Array.sort
    |> Array.toList

  /// Lists the jump tables of the given function in the order of their
  /// indirect branches, each with its address, its size, and its targets.
  let jumpTablesOf (fn: Function) =
    fn.JumpTables
    |> Array.sortBy (fun jmptbl -> jmptbl.InsAddr)
    |> Array.map (fun jmptbl ->
      jmptbl.TableAddress, jmptbl.NumEntries, jumpTargets fn jmptbl)
    |> Array.toList

  /// Lists the addresses of the given number of cases that follow one another
  /// from start, each taking the given number of bytes.
  let casesFrom (start: Addr) size count =
    [ for i in 0 .. count - 1 -> start + uint64 (size * i) ]

  /// Tells what the given function makes of the callee of its call at
  /// callAddr: whether the callee returns, how many bytes it pops on return,
  /// and whether the call returns to the code after it.
  let summarizeCall (fn: Function) callAddr =
    let callee =
      fn.CFG.FindVertexBy(fun v ->
        v.VData.Internals.IsAbstract
        && v.VData.Internals.PPoint.CallSite = Some(LeafCallSite callAddr))
    let summary = callee.VData.Internals.AbstractContent
    let returns =
      fn.CFG.GetSuccEdges callee |> Array.exists (fun e -> e.Label = RetEdge)
    summary.ReturningStatus, summary.UnwindingBytes, returns

  /// Makes the status of an x86 function that does not return when its
  /// argument at the given offset on the stack is non-zero.
  let condNoRetOnStack offset =
    ConditionalNoRet(ArgLocation.Stack { FirstOffset = offset; SlotSize = 4 })

  /// Wraps the default strategy, letting a test take over how it orders and
  /// handles each action and how it makes and resets its contexts.
  let wrapStrategyWith judge onAction (contexts: IContextProvidable<_, _>) =
    let inner = CFGRecovery() :> ICFGBuildingStrategy<_, _>
    { new ICFGBuildingStrategy<DummyContext, DummyContext> with
        member _.CreateFunctionContext() = contexts.CreateFunctionContext()
        member _.ResetFunctionContext ctx = contexts.ResetFunctionContext ctx
        member _.CreateGlobalContext() = contexts.CreateGlobalContext()
        member _.ActionPrioritizer = judge inner.ActionPrioritizer
        member _.RecoveryTargets = inner.RecoveryTargets
        member _.OnAction(ctx, queue, action) = onAction inner ctx queue action
        member _.OnCreate ctx = inner.OnCreate ctx
        member _.OnFinish ctx = inner.OnFinish ctx
        member _.OnCyclicDependency deps = inner.OnCyclicDependency deps
        member _.FindCandidatesForPostProcessing builders =
          inner.FindCandidatesForPostProcessing builders }

  let wrapStrategy onAction contexts = wrapStrategyWith id onAction contexts

  /// Wraps the default strategy so that every action first runs the given
  /// hook, which lets a test make the recovery fail on purpose.
  let hookStrategy hook =
    let onAction (inner: ICFGBuildingStrategy<_, _>) ctx queue action =
      hook ctx
      inner.OnAction(ctx, queue, action)
    wrapStrategy onAction (CFGRecovery())

  let throwingHook (_: CFGBuildingContext<DummyContext, DummyContext>) =
    raise (InvalidOperationException "boom")

  /// Brews the given x64 code, whose first function is at address zero.
  let brewCodeWith code strategy =
    let isa = ISA(Architecture.Intel, WordSize.Bit64)
    let hdl = BinHandle.LoadRawImage(code, isa)
    let funcId =
      { new IFunctionIdentifiable with
          member _.Identify() = [| 0UL |] }
    BinaryBrew(hdl, funcId, strategy)

  /// Brews a one-instruction binary whose only function is at address zero.
  let brewRetWith strategy = brewCodeWith [| 0xc3uy |] strategy

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

  /// Orders actions like the given prioritizer, logging each action it judges.
  let loggingPrioritizer (log: ConcurrentQueue<_>) (inner: IPrioritizable) =
    { new IPrioritizable with
        member _.GetPriority action =
          log.Enqueue action
          inner.GetPriority action }

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
  member _.``BinaryBrew reads a jump table past its dummy entries``() =
    (* The cases pick leaves out are unreachable, so clang points their entries
       at the end of pick, where the padding before next begins. Such an entry
       adds no edge, yet the table goes on after it. *)
    let fn = (recoverFunctions "elf_x64_jmptbl")[0x201300UL]
    let jmptbl = Array.exactlyOne fn.JumpTables
    let expected = 6, [ 0x201312UL; 0x201319UL; 0x201322UL; 0x20132aUL ]
    let actual = jmptbl.NumEntries, jumpTargets fn jmptbl
    Assert.AreEqual<int * Addr list>(expected, actual)

  [<TestMethod>]
  member _.``BinaryBrew starts a nested jump table at its first case``() =
    (* Cases 4 to 9 of pick switch again on the same register, which GCC thus
       knows to hold 4 to 9 there. Instead of checking the range, it folds case
       4 into the table address, which points four entries before the inner
       table, into the outer one. *)
    let fn = (recoverFunctions "elf_x86_nestedjmptbl")[0x4011d4UL]
    let outer =
      [ 0x4011f6UL; 0x4011fdUL; 0x401205UL; 0x40120eUL; 0x401217UL; 0x401262UL ]
    let inner =
      [ 0x401223UL; 0x40122bUL; 0x401235UL; 0x401241UL; 0x40124dUL; 0x401259UL ]
    let expected = [ 0x400118UL, 11, outer; 0x400144UL, 6, inner ]
    Assert.AreEqual<(Addr * int * Addr list) list>(expected, jumpTablesOf fn)

  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``BinaryBrew leaves a range-checked jump table in place``() =
    (* Only case 2 of checked reaches its second switch on the same register,
       but that switch checks its range itself and so needs no enclosing switch
       to bound it: its table starts at case 0, where the code computes it. *)
    let fn = (recoverFunctions "elf_x86_samevarjmptbl")[0x401154UL]
    let outer = [ 0x401167UL; 0x40116dUL; 0x401173UL; 0x401179UL ]
    let inner = [ 0x401185UL; 0x40118bUL; 0x401191UL; 0x401197UL ]
    let expected = [ 0x400130UL, 4, outer; 0x400140UL, 4, inner ]
    Assert.AreEqual<(Addr * int * Addr list) list>(expected, jumpTablesOf fn)

  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``BinaryBrew rebases no jump table on an entry past a table end``() =
    (* The second table of overread follows the first right away, so reading
       on past the end of the first one, which is not known yet, reaches the
       second jump through what is the first entry of the second table. *)
    let fn = (recoverFunctions "elf_x86_samevarjmptbl")[0x4011a0UL]
    let outer = [ 0x4011b0UL; 0x4011b6UL; 0x4011bcUL ]
    let inner = [ 0x4011c9UL; 0x4011d0UL ]
    let expected = [ 0x400118UL, 3, outer; 0x400124UL, 2, inner ]
    Assert.AreEqual<(Addr * int * Addr list) list>(expected, jumpTablesOf fn)

  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``BinaryBrew bounds a jump table by a strict range check``() =
    (* strict leaves its first switch through jae when its index reaches 4, so
       the index takes 0 to 3 alone, and the second table, right after the
       first, holds none of its entries. *)
    let fn = (recoverFunctions "elf_x86_jccjmptbl")[0x4011a8UL]
    let outer = [ 0x4011bbUL; 0x4011c1UL; 0x4011c7UL; 0x4011cdUL ]
    let inner = [ 0x4011d9UL; 0x4011dfUL; 0x4011e5UL; 0x4011ebUL ]
    let expected = [ 0x400118UL, 4, outer; 0x400128UL, 4, inner ]
    Assert.AreEqual<(Addr * int * Addr list) list>(expected, jumpTablesOf fn)

  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``BinaryBrew bounds a jump table by the branch its check takes``() =
    (* taken reaches its first switch through jb, the branch its range check
       takes, so it is that branch that bounds the index to 0 to 3. *)
    let fn = (recoverFunctions "elf_x86_jccjmptbl")[0x4011f4UL]
    let outer = [ 0x40120aUL; 0x401210UL; 0x401216UL; 0x40121cUL ]
    let inner = [ 0x401228UL; 0x40122eUL; 0x401234UL; 0x40123aUL ]
    let expected = [ 0x40013cUL, 4, outer; 0x40014cUL, 4, inner ]
    Assert.AreEqual<(Addr * int * Addr list) list>(expected, jumpTablesOf fn)

  [<TestMethod>]
  member _.``BinaryBrew bounds a jump table by a signed range check``() =
    (* nested checks its index with js and jge, signed comparisons, before it
       switches twice on it, folding case 4 into its second table address as
       the nested fixture does. *)
    let fn = (recoverFunctions "elf_x86_jccjmptbl")[0x401243UL]
    let outer =
      [ 0x401257UL; 0x40125dUL; 0x401263UL; 0x401269UL; 0x40126fUL; 0x40129aUL ]
    let inner =
      [ 0x401276UL; 0x40127cUL; 0x401282UL; 0x401288UL; 0x40128eUL; 0x401294UL ]
    let expected = [ 0x400160UL, 11, outer; 0x40018cUL, 6, inner ]
    Assert.AreEqual<(Addr * int * Addr list) list>(expected, jumpTablesOf fn)

  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``BinaryBrew starts a folded jump table after one of its own``() =
    (* samefn checks the range of its second switch by a conditional jump
       before a call, so the address of the table has case 4 folded in. That
       address lies four entries into the table of its first switch. *)
    let fn = (recoverFunctions "elf_x86_foldjmptbl")[0x4011cdUL]
    let first = casesFrom 0x4011e2UL 7 8
    let second = casesFrom 0x40122cUL 7 6
    let expected = [ 0x400118UL, 8, first; 0x400138UL, 6, second ]
    Assert.AreEqual<(Addr * int * Addr list) list>(expected, jumpTablesOf fn)

  [<TestMethod>]
  [<Timeout(10000)>]
  member _.``BinaryBrew starts a folded jump table after one of another``() =
    (* nfn and nfn2 switch like the second switch of samefn, but their folded
       addresses lie in the tables of tfn and tfn2. tfn precedes nfn in the
       code and tfn2 follows nfn2, so either one may register its table first;
       when nfn2 goes first, its folded entry 0 points into tfn2. *)
    let fns = recoverFunctions "elf_x86_foldjmptbl"
    let expected =
      [ 0x400154UL, 8, casesFrom 0x40126aUL 6 8
        0x400174UL, 6, casesFrom 0x4012b6UL 7 6
        0x4001b0UL, 6, casesFrom 0x4012fdUL 7 6
        0x400190UL, 8, casesFrom 0x40133bUL 6 8 ]
    let actual =
      [ 0x40125aUL; 0x40129dUL; 0x4012e4UL; 0x40132bUL ]
      |> List.collect (fun addr -> jumpTablesOf fns[addr])
    Assert.AreEqual<(Addr * int * Addr list) list>(expected, actual)

  [<TestMethod>]
  member _.``BinaryBrew ends an indirect call its next code has unwound``() =
    (* joined pushes two words for the callee of its indirect call, but the
       call frame information says the code after the call runs with them
       gone, which no callee popping its arguments explains: the call never
       returns, and that code is where the branch around it lands. *)
    let fn = (recoverFunctions "elf_x86_indcall")[0x4011d4UL]
    let expected = NoRet, 0, false
    let actual = summarizeCall fn 0x4011e2UL
    Assert.AreEqual<NonReturningStatus * int * bool>(expected, actual)

  [<TestMethod>]
  member _.``BinaryBrew pops nothing the frame keeps on an indirect call``() =
    (* unpopped passes a pointer into its frame last and drops one word less
       than it pushed right after the call, the way an sret call goes, yet the
       call frame information says the callee pops nothing. *)
    let fn = (recoverFunctions "elf_x86_indcall")[0x4011f2UL]
    let expected = NotNoRet, 0, true
    let actual = summarizeCall fn 0x4011fdUL
    Assert.AreEqual<NonReturningStatus * int * bool>(expected, actual)

  [<TestMethod>]
  member _.``BinaryBrew pops the word the frame drops on an indirect call``() =
    (* popped passes no pointer into its frame, unlike an sret call, but the
       call frame information says the code after the call runs with the word
       it pushed gone, which only a callee popping it explains. *)
    let fn = (recoverFunctions "elf_x86_indcall")[0x4011e7UL]
    let expected = NotNoRet, 4, true
    let actual = summarizeCall fn 0x4011efUL
    Assert.AreEqual<NonReturningStatus * int * bool>(expected, actual)

  [<TestMethod>]
  member _.``BinaryBrew looks past padding for the code after a call``() =
    (* padded is joined with nops after its indirect call, as GCC aligns the
       code after a call that never returns. The nops run at whatever depth the
       call left, so it is the code after them that tells. *)
    let fn = (recoverFunctions "elf_x86_indcall")[0x401206UL]
    let expected = NoRet, 0, false
    let actual = summarizeCall fn 0x401214UL
    Assert.AreEqual<NonReturningStatus * int * bool>(expected, actual)

  [<TestMethod>]
  member _.``BinaryBrew ends an indirect call that ends its frame``() =
    (* last pushes nothing for the callee of its indirect call, so _start,
       which follows it, runs as deep in its own frame as the call does in the
       frame of last. But the call is where that frame ends, so there is no
       code of its function for the call to return to. *)
    let fn = (recoverFunctions "elf_x86_indcall")[0x401223UL]
    let expected = NoRet, 0, false
    let actual = summarizeCall fn 0x401227UL
    Assert.AreEqual<NonReturningStatus * int * bool>(expected, actual)

  [<TestMethod>]
  member _.``BinaryBrew passes the condition of error on to a wrapper``() =
    (* wrap hands its first argument to error as the status, so it returns
       when, and only when, that argument is zero. *)
    let fn = (recoverFunctions "elf_x86_condnoret")[0x401241UL]
    Assert.AreEqual<NonReturningStatus>(condNoRetOnStack 4, fn.NoRet)

  [<TestMethod>]
  member _.``BinaryBrew passes the condition of error on in a register``() =
    (* The x86-64 wrap hands error the status it gets in RDI, untouched. *)
    let fn = (recoverFunctions "elf_x64_condnoret")[0x201379UL]
    let rdi = Intel.Register.toRegID Intel.Register.RDI
    let expected = ConditionalNoRet(ArgLocation.Reg rdi)
    Assert.AreEqual<NonReturningStatus>(expected, fn.NoRet)

  [<TestMethod>]
  member _.``BinaryBrew ends a call passing a non-zero status to a wrapper``() =
    (* _start calls wrap with a zero status and then with one, after which
       wrap never returns, so the code after the second call is not its. *)
    let fn = (recoverFunctions "elf_x86_condnoret")[0x40122cUL]
    let status = condNoRetOnStack 4
    let expected = [ status, 0, true; status, 0, false ]
    let actual = [ summarizeCall fn 0x401230UL; summarizeCall fn 0x40123cUL ]
    Assert.AreEqual<(NonReturningStatus * int * bool) list>(expected, actual)

  [<TestMethod>]
  member _.``BinaryBrew passes the condition of a tail call on``() =
    (* tailwrap jumps to error with the arguments it got, so it returns on
       the same condition, while die sets the status to one first, so it
       never returns. *)
    let fns = recoverFunctions "elf_x86_condnoret"
    let expected = [ condNoRetOnStack 4; NoRet ]
    let actual = [ fns[0x401254UL].NoRet; fns[0x401259UL].NoRet ]
    Assert.AreEqual<NonReturningStatus list>(expected, actual)

  [<TestMethod>]
  member _.``BinaryBrew with SSA passes the condition of a tail call on``() =
    (* tailwrap jumps before it moves the stack pointer, so the frame of
       error starts right where its own does. *)
    let bytes = readZippedBinary "elf_x86_condnoret"
    let hdl = BinHandle.LoadFileBytes(bytes, ISA "x86")
    let options = { CFGRecoveryOptions.Default with UseSSA = true }
    let fns = BinaryBrew(hdl, options).Functions
    let expected = [ condNoRetOnStack 4; condNoRetOnStack 4; NoRet ]
    let actual =
      [ 0x401241UL; 0x401254UL; 0x401259UL ] |> List.map (fun a -> fns[a].NoRet)
    Assert.AreEqual<NonReturningStatus list>(expected, actual)

  [<TestMethod>]
  member _.``BinaryBrew returns from calls conditioned on two arguments``() =
    (* pick passes error its first argument on one path and its second on
       the other, so whether it returns is up to the path as well, which no
       single argument decides. *)
    let fn = (recoverFunctions "elf_x86_condnoret")[0x401266UL]
    Assert.AreEqual<NonReturningStatus>(NotNoRet, fn.NoRet)

  [<TestMethod>]
  member _.``BinaryBrew recovers functions while the thread pool is stuck``() =
    (* The workers block on replies from the manager, so if handing over a
       request or a reply ever waited for a pool thread, a pool that stops
       running work would stall the whole recovery for good. *)
    let count = ref 0
    let finished =
      runWithoutThreadPool (TimeSpan.FromSeconds 60.0) (fun () ->
        count.Value <- (recoverFunctions "elf_x64_jmptbl").Count)
    Assert.AreEqual<bool * bool>((true, true), (finished, count.Value > 0))

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
      ctx.UpdateGlobalContext(fun _ ->
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
  member _.``BinaryBrew orders every action by its strategy prioritizer``() =
    let judged = ConcurrentQueue<CFGAction>()
    let handled = ConcurrentQueue<CFGAction>()
    let onAction (inner: ICFGBuildingStrategy<_, _>) ctx queue action =
      handled.Enqueue action
      inner.OnAction(ctx, queue, action)
    let judge = loggingPrioritizer judged
    let strategy = wrapStrategyWith judge onAction (CFGRecovery())
    (* call 5; ret *)
    brewCodeWith [| 0xe8uy; 0uy; 0uy; 0uy; 0uy; 0xc3uy |] strategy |> ignore
    (* Every push is judged, so no action is handled more than judged. *)
    let count action actions = Seq.filter ((=) action) actions |> Seq.length
    let unjudged =
      Seq.distinct handled
      |> Seq.filter (fun action -> count action handled > count action judged)
      |> Seq.toList
    Assert.AreEqual<CFGAction list>([], unjudged)

  [<TestMethod>]
  member _.``BinaryBrew keeps what callers know of each finished function``() =
    let bytes = readZippedBinary "elf_x64_iplt"
    let brew = BinaryBrew(BinHandle.LoadFileBytes(bytes, ISA "x64"))
    let builders =
      brew.Builders.Values
      |> Array.choose (function
        | :? ICFGBuildable<DummyContext, DummyContext> as builder
          when builder.BuilderState = Finished -> Some builder
        | _ -> None)
    let expected =
      builders
      |> Array.map (fun builder ->
        let ctx = builder.Context
        { Status = ctx.NonReturningStatus
          Unwinding = ctx.UnwindingBytes
          Clobbered = Set.ofSeq ctx.ClobberedRegs
          IsExternal = false })
      |> Array.toList
    let actual = builders |> Array.map (fun b -> b.CalleeInfo) |> Array.toList
    Assert.AreNotEqual<int>(0, builders.Length)
    Assert.AreEqual<CalleeInfo list>(expected, actual)

  [<TestMethod>]
  member _.``BinaryBrew records the callers of an external function``() =
    let fns = recoverFunctions "elf_x64_noplt"
    let find name = fns.Sequence |> Seq.find (fun fn -> fn.Name = name)
    let callers = (find "helper@got").Callers |> Seq.toList
    Assert.AreEqual<Addr list>([ (find "entry").EntryPoint ], callers)

  [<TestMethod>]
  member _.``CFGBuildingContext shows strategies only what they may use``() =
    let names =
      typeof<CFGBuildingContext<DummyContext, DummyContext>>.GetProperties()
      |> Array.map (fun p -> p.Name)
      |> Array.sort
      |> Array.toList
    let expected =
      [ "BBLFactory"
        "BinHandle"
        "CFG"
        "CP"
        "Callers"
        "ClobberedRegs"
        "ExnInfo"
        "FunctionAddress"
        "FunctionName"
        "GapAnalysisVertices"
        "IntraCallTable"
        "JumpTables"
        "NonReturningStatus"
        "UnwindingBytes"
        "UserContext"
        "Vertices" ]
    Assert.AreEqual<string list>(expected, names)

  [<TestMethod>]
  member _.``BinaryBrew builds only the functions defined in the binary``() =
    let bytes = readZippedBinary "elf_x64_noplt"
    let brew = BinaryBrew(BinHandle.LoadFileBytes(bytes, ISA "x64"))
    let kinds =
      brew.Builders.Values
      |> Array.map (fun builder ->
        let isBuildable = builder :? ICFGBuildable<DummyContext, DummyContext>
        builder.IsExternal, isBuildable)
      |> Array.distinct
      |> Array.sort
      |> Array.toList
    Assert.AreEqual<(bool * bool) list>([ false, true; true, false ], kinds)

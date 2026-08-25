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

namespace B2R2.MiddleEnd.SSA.Tests

open System.Collections.Generic
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.BinIR.SSA
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.SSA

[<TestClass>]
type SSALifterTests() =
  /// Records what an IStmtPostProcessor is handed, so that a test can tell
  /// whether the processor it passed to the factory is the one the lifter ran.
  let recordingProcessor wordSize =
    let seen = List<Stmt>()
    let processor =
      { new IStmtPostProcessor with
          member _.WordSize with get() = wordSize
          member _.PostProcess stmt = seen.Add stmt; stmt }
    processor, seen

  /// Records the graph and the dominance an observer is handed, once per time
  /// it is called.
  let recordingObserver () =
    let seen = List<SSACFG * IForwardDominance<SSABasicBlock>>()
    let observer =
      { new ISSAStackPointerObserver with
          member _.Observe(g, dom, _) = seen.Add(g, dom) }
    observer, seen

  /// Nests a load of the address inside the address of every store, which is
  /// the shape a store through a pointer held in a stack slot takes. No
  /// lifter of this repository emits it today, but a post-processor is free
  /// to, and the promotion has to read the load it holds either way.
  let wrappingProcessor wordSize =
    let rt = wordSize |> WordSize.toRegType
    { new IStmtPostProcessor with
        member _.WordSize with get() = wordSize
        member _.PostProcess stmt =
          match stmt with
          | Def(dst, Store(mem, storeRt, addr, src)) ->
            Def(dst, Store(mem, storeRt, Load(mem, rt, addr), src))
          | _ ->
            stmt }

  let vertexAt (g: SSACFG) addr =
    g.Vertices
    |> Array.find (fun v -> v.VData.Internals.PPoint.Address = addr)

  static member GraphTypes = [| [| box Persistent |]; [| box Mutable |] |]

  [<TestMethod>]
  [<DynamicData(nameof SSALifterTests.GraphTypes)>]
  member _.``Lift keeps the shape of the given CFG``(t) =
    let cfg = buildDiamondCFG t
    let lifter = SSALifterFactory.Create hdl
    let ssaCFG = (lifter.Lift cfg).Graph
    Assert.AreEqual<int>(cfg.VertexCount, ssaCFG.VertexCount)
    Assert.AreEqual<int>(cfg.EdgeCount, ssaCFG.EdgeCount)
    Assert.AreEqual<int>(cfg.Roots.Length, ssaCFG.Roots.Length)
    let rootPPoint = ssaCFG.Roots[0].VData.Internals.PPoint
    Assert.AreEqual<uint64>(0x00UL, rootPPoint.Address)

  [<TestMethod>]
  member _.``Lift places phis only where a definition flows in twice``() =
    (* Of the four blocks of the diamond only the join is in a dominance
       frontier at all, so every phi of this graph belongs to it. *)
    let cfg = buildDiamondCFG Mutable
    let lifter = SSALifterFactory.Create hdl
    let ssaCFG = (lifter.Lift cfg).Graph
    let counts =
      ssaCFG.Vertices
      |> Array.map (fun v -> v.VData.Internals.PPoint.Address, phiCountOf v)
      |> Array.sortBy fst
    let atJoin = counts |> Array.filter (fun (addr, _) -> addr = joinAddr)
    let elsewhere = counts |> Array.filter (fun (addr, _) -> addr <> joinAddr)
    Assert.AreEqual<int>(1, atJoin.Length)
    Assert.AreNotEqual<int>(0, snd atJoin[0])
    Assert.AreEqual<int>(3, elsewhere.Length)
    Assert.AreEqual<int>(0, elsewhere |> Array.sumBy snd)

  [<TestMethod>]
  [<DynamicData(nameof SSALifterTests.GraphTypes)>]
  member _.``Lift leaves no variable unrenamed``(t) =
    (* A variable the lifter never reached keeps the -1 identifier it is born
       with, so a negative identifier anywhere is renaming that did not run. *)
    let cfg = buildDiamondCFG t
    let lifter = SSALifterFactory.Create hdl
    let ssaCFG = (lifter.Lift cfg).Graph
    let variables =
      statementsOf ssaCFG |> Array.collect (variablesOf >> List.toArray)
    let unrenamed = variables |> Array.filter (fun v -> v.Identifier < 0)
    Assert.AreNotEqual<int>(0, variables.Length)
    Assert.AreEqual<int>(0, unrenamed.Length)

  [<TestMethod>]
  member _.``Lift runs the given statement post-processor``() =
    let processor, seen = recordingProcessor hdl.ISA.WordSize
    let lifter = SSALifterFactory.Create processor
    let ssaCFG = (lifter.Lift(buildDiamondCFG Mutable)).Graph
    Assert.AreNotEqual<int>(0, seen.Count)
    Assert.AreEqual<int>(4, ssaCFG.VertexCount)

  [<TestMethod>]
  member _.``Lift reads the word size off the given post-processor``() =
    (* The processor's word size is what the PC of a lifted block is sized by,
       so a processor that answers 32 bits over a 64-bit binary is enough to
       tell whether the lifter asked it at all. *)
    let processor, _ = recordingProcessor WordSize.Bit32
    let lifter = SSALifterFactory.Create processor
    let ssaCFG = (lifter.Lift(buildDiamondCFG Mutable)).Graph
    let pcRegTypes =
      statementsOf ssaCFG
      |> Array.collect (variablesOf >> List.toArray)
      |> Array.choose (fun v ->
        match v.Kind with
        | PCVar rt -> Some rt
        | _ -> None)
      |> Array.distinct
    CollectionAssert.AreEqual([| 32<rt> |], pcRegTypes)

  [<TestMethod>]
  member _.``Promote reaches a stack load in the address of a store``() =
    (* A load whose address the stack pointer analysis knows reads a stack
       slot, and promotion turns it into a variable of that slot wherever it
       sits. The address of a store is a place it sits. *)
    let lifter = SSALifterFactory.Create(wrappingProcessor hdl.ISA.WordSize)
    let promoter = SSAPromoterFactory.Create hdl
    let lifted = lifter.Lift(buildDiamondCFG Mutable)
    let ssaCFG = (promoter.Promote lifted).Graph
    let addrs = storeAddressesOf ssaCFG
    let unpromoted =
      addrs |> Array.filter (fun e ->
        match e with
        | Load _ -> true
        | _ -> false)
    Assert.AreNotEqual<int>(0, addrs.Length)
    Assert.AreEqual<int>(0, unpromoted.Length)

  [<TestMethod>]
  member _.``Promote shows the propagation once, on the graph it answers``() =
    (* One call, not one per vertex, so that every reader of the propagation
       sees one and the same graph rather than one rewritten up to wherever
       the promotion has got to. *)
    let observer, seen = recordingObserver ()
    let lifter = SSALifterFactory.Create hdl
    let promoter = SSAPromoterFactory.Create(hdl, observer)
    let result = lifter.Lift(buildDiamondCFG Mutable) |> promoter.Promote
    Assert.AreEqual<int>(1, seen.Count)
    let g, dom = seen[0]
    Assert.AreSame(result.Graph, g)
    Assert.AreSame(result.Dominance, dom)

  [<TestMethod>]
  member _.``Lift alone leaves the stack alone``() =
    (* Promotion is what turns a stack slot into a variable of its own, so a
       caller that only lifts pays for none of it and sees none of it. *)
    let observer, seen = recordingObserver ()
    let lifter = SSALifterFactory.Create hdl
    let promoter = SSAPromoterFactory.Create(hdl, observer)
    let lifted = lifter.Lift(buildDiamondCFG Mutable)
    let stackVarsOf (g: SSACFG) =
      statementsOf g
      |> Array.collect (variablesOf >> List.toArray)
      |> Array.filter (fun v ->
        match v.Kind with
        | StackVar _ -> true
        | _ -> false)
    Assert.AreEqual<int>(0, seen.Count)
    Assert.AreEqual<int>(0, (stackVarsOf lifted.Graph).Length)
    let promoted = promoter.Promote lifted
    Assert.AreEqual<int>(1, seen.Count)
    Assert.AreNotEqual<int>(0, (stackVarsOf promoted.Graph).Length)

  [<TestMethod>]
  member _.``Lift answers the dominance of the graph it returns``() =
    (* The entry of a diamond dominates every block of it, and the join is
       reached from both arms, so the entry is what immediately dominates it. *)
    let cfg = buildDiamondCFG Mutable
    let lifter = SSALifterFactory.Create hdl
    let result = lifter.Lift cfg
    let ssaCFG, dom = result.Graph, result.Dominance
    let entry = vertexAt ssaCFG 0x00UL
    let join = vertexAt ssaCFG joinAddr
    Assert.AreEqual<int>(1, dom.DominatorTree.Roots.Count)
    Assert.AreSame(entry, dom.DominatorTree.Roots[0])
    Assert.AreSame(entry, dom.ImmediateDominator join)

  [<TestMethod>]
  member _.``A lifter lifts more than once``() =
    (* The lifter holds no state of a lift, so one is reusable, and each lift
       answers a graph of its own rather than the one before it. *)
    let lifter = SSALifterFactory.Create hdl
    let first = (lifter.Lift(buildDiamondCFG Mutable)).Graph
    let second = (lifter.Lift(buildDiamondCFG Mutable)).Graph
    Assert.AreNotSame(first, second)
    Assert.AreEqual<int>(first.VertexCount, second.VertexCount)
    Assert.AreEqual<int>(first.EdgeCount, second.EdgeCount)

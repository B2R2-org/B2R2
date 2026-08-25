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

  /// Records the vertices a callback is fired on, along with the graph and the
  /// dominance it is handed for each of them.
  let recordingCallback () =
    let seen = List<SSACFG * IForwardDominance<SSABasicBlock> * SSAVertex>()
    let callback =
      { new ISSAVertexCallback with
          member _.OnVertexCreation(g, dom, _, v) = seen.Add(g, dom, v) }
    callback, seen

  let vertexAt (g: SSACFG) addr =
    g.Vertices
    |> Array.find (fun v -> v.VData.Internals.PPoint.Address = addr)

  static member GraphTypes = [| [| box Persistent |]; [| box Mutable |] |]

  [<TestMethod>]
  [<DynamicData(nameof SSALifterTests.GraphTypes)>]
  member _.``Lift keeps the shape of the given CFG``(t) =
    let cfg = buildDiamondCFG t
    let lifter = SSALifterFactory.Create hdl
    let ssaCFG, _ = lifter.Lift cfg
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
    let ssaCFG, _ = lifter.Lift cfg
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
    let ssaCFG, _ = lifter.Lift cfg
    let variables =
      statementsOf ssaCFG |> Array.collect (variablesOf >> List.toArray)
    let unrenamed = variables |> Array.filter (fun v -> v.Identifier < 0)
    Assert.AreNotEqual<int>(0, variables.Length)
    Assert.AreEqual<int>(0, unrenamed.Length)

  [<TestMethod>]
  member _.``Lift runs the given statement post-processor``() =
    let processor, seen = recordingProcessor hdl.ISA.WordSize
    let lifter = SSALifterFactory.Create(hdl, processor)
    let ssaCFG, _ = lifter.Lift(buildDiamondCFG Mutable)
    Assert.AreNotEqual<int>(0, seen.Count)
    Assert.AreEqual<int>(4, ssaCFG.VertexCount)

  [<TestMethod>]
  member _.``Lift reads the word size off the given post-processor``() =
    (* The processor's word size is what the PC of a lifted block is sized by,
       so a processor that answers 32 bits over a 64-bit binary is enough to
       tell whether the lifter asked it at all. *)
    let processor, _ = recordingProcessor WordSize.Bit32
    let lifter = SSALifterFactory.Create(hdl, processor)
    let ssaCFG, _ = lifter.Lift(buildDiamondCFG Mutable)
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
  member _.``Lift reports every vertex of the graph it returns``() =
    let callback, seen = recordingCallback ()
    let lifter = SSALifterFactory.Create(hdl, callback)
    let ssaCFG, dom = lifter.Lift(buildDiamondCFG Mutable)
    let reported = seen |> Seq.map (fun (_, _, v) -> v) |> Seq.toArray
    Assert.AreEqual<int>(ssaCFG.VertexCount, reported.Length)
    Assert.AreEqual<int>(reported.Length, (Array.distinct reported).Length)
    CollectionAssert.AreEquivalent(ssaCFG.Vertices, reported)
    for g, d, _ in seen do
      Assert.AreSame(ssaCFG, g)
      Assert.AreSame(dom, d)

  [<TestMethod>]
  member _.``Lift runs both a post-processor and a callback``() =
    let processor, stmts = recordingProcessor hdl.ISA.WordSize
    let callback, vertices = recordingCallback ()
    let lifter = SSALifterFactory.Create(hdl, processor, callback)
    let ssaCFG, _ = lifter.Lift(buildDiamondCFG Mutable)
    Assert.AreNotEqual<int>(0, stmts.Count)
    Assert.AreEqual<int>(ssaCFG.VertexCount, vertices.Count)

  [<TestMethod>]
  member _.``Lift answers the dominance of the graph it returns``() =
    (* The entry of a diamond dominates every block of it, and the join is
       reached from both arms, so the entry is what immediately dominates it. *)
    let cfg = buildDiamondCFG Mutable
    let lifter = SSALifterFactory.Create hdl
    let ssaCFG, dom = lifter.Lift cfg
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
    let first, _ = lifter.Lift(buildDiamondCFG Mutable)
    let second, _ = lifter.Lift(buildDiamondCFG Mutable)
    Assert.AreNotSame(first, second)
    Assert.AreEqual<int>(first.VertexCount, second.VertexCount)
    Assert.AreEqual<int>(first.EdgeCount, second.EdgeCount)

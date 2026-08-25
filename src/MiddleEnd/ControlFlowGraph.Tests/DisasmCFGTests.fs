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

namespace B2R2.MiddleEnd.ControlFlowGraph.Tests

open System.Collections.Generic
open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph

/// Represents a stand-in instruction, which answers the address and the length
/// that building a DisasmCFG reads, and nothing else.
type private FakeInstruction(addr: Addr, len: uint32) =
  interface IInstruction with
    member _.Address = addr
    member _.Length = len
    member _.IsBranch = false
    member _.IsModeChanging = false
    member _.IsDirectBranch = false
    member _.IsIndirectBranch = false
    member _.IsCondBranch = false
    member _.IsCJmpOnTrue = false
    member _.IsCall = false
    member _.IsRET = false
    member _.IsPush = false
    member _.IsPop = false
    member _.IsInterrupt = false
    member _.IsExit = false
    member _.IsNop = false
    member _.IsInlinedAssembly = false
    member _.IsTerminator _ = false
    member _.DirectBranchTarget(_: byref<Addr>) = false
    member _.IndirectTrampolineAddr(_: byref<Addr>) = false
    member _.MemoryDereferences(_: byref<Addr[]>) = false
    member _.Immediate(_: byref<int64>) = false
    member _.GetNextInstrAddrs() = [||]
    member _.InterruptNum(_: byref<int64>) = false
    member _.Translate _ = [||]
    member _.TranslateToList _ = List()
    member _.Disasm(_: IDisasmBuilder) = ""
    member _.Disasm() = ""
    member _.Decompose _ = [||]

[<TestClass>]
type DisasmCFGTests() =
  let disasmBuilder =
    StringDisasmBuilder(false, null, WordSize.Bit64) :> IDisasmBuilder

  let liftedIns addr len =
    { Original = FakeInstruction(addr, len) :> IInstruction
      Stmts = [||]
      BBLAddr = addr }

  let addBlock (g: LowUIRCFG) addr idx inss =
    g.AddVertex(LowUIRBasicBlock.CreateRegular(inss, ProgramPoint(addr, idx)))

  let addrOf (v: IVertex<DisasmBasicBlock>) = v.VData.Internals.PPoint.Address

  let edgeAddrs (g: DisasmCFG) =
    g.Edges
    |> Array.map (fun e -> addrOf e.First, addrOf e.Second)
    |> Array.sort

  (* An instruction carrying an intra-jump has its block cut in two, and the
     cut halves share the one address. A path leading from the second half back
     to the first is a path that reaches the first block twice, and the block
     it falls through to is a block the traversal must still take in hand once,
     lest the merged block come to hold an edge onto itself. *)
  [<TestMethod>]
  member _.``DisasmCFG Intra Jump Loop Test``() =
    let g = LowUIRCFG.create Mutable
    let head = liftedIns 0x1000UL 2u
    let v1 = addBlock g 0x1000UL 0 [| head |]
    let v2 = addBlock g 0x1000UL 1 [| head |]
    let v3 = addBlock g 0x3000UL 0 [| liftedIns 0x3000UL 2u |]
    let v4 = addBlock g 0x1002UL 0 [| liftedIns 0x1002UL 2u |]
    g.AddEdge(v1, v2, IntraJmpEdge)
    g.AddEdge(v2, v3, InterJmpEdge)
    g.AddEdge(v3, v1, InterJmpEdge)
    g.AddEdge(v1, v4, FallThroughEdge)
    g.SetRoots [ v1 ]
    let dcfg = DisasmCFG.create disasmBuilder g
    let merged = dcfg.FindVertexBy(fun v -> addrOf v = 0x1000UL)
    Assert.AreEqual<int>(2, dcfg.VertexCount)
    Assert.AreEqual<int>(2, merged.VData.Internals.Instructions.Length)
    let expected = [| 0x1000UL, 0x3000UL; 0x3000UL, 0x1000UL |]
    CollectionAssert.AreEqual(expected, edgeAddrs dcfg)

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

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.MiddleEnd.SSA
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

[<TestClass>]
type CFG2Tests () =

  /// This is a raw x86 binary code generated from the following C code:
  /// static inline void *copy(void *d, const void *s, unsigned int n) {
  ///   asm volatile ("rep movsb"
  ///                 : "=D" (d),
  ///                   "=S" (s),
  ///                   "=c" (n)
  ///                 : "0" (d),
  ///                   "1" (s),
  ///                   "2" (n)
  ///                 : "memory");
  ///   return d;
  /// }
  ///
  /// void _start(void)
  /// {
  ///   char buf[32];
  ///   copy(buf, "hello world", 32);
  ///   return;
  /// }
  /// binary: 5756b920000000e81800000005341e000083ec2089e78db0e8e1fffff3a483c4205e5fc38b0424c3
  let binary =
     [| 0x57uy; 0x56uy; 0xb9uy; 0x20uy; 0x00uy; 0x00uy; 0x00uy; 0xe8uy; 0x18uy;
        0x00uy; 0x00uy; 0x00uy; 0x05uy; 0x34uy; 0x1euy; 0x00uy; 0x00uy; 0x83uy;
        0xecuy; 0x20uy; 0x89uy; 0xe7uy; 0x8duy; 0xb0uy; 0xe8uy; 0xe1uy; 0xffuy;
        0xffuy; 0xf3uy; 0xa4uy; 0x83uy; 0xc4uy; 0x20uy; 0x5euy; 0x5fuy; 0xc3uy;
        0x8buy; 0x04uy; 0x24uy; 0xc3uy; |]

  let isa = ISA.Init Architecture.IntelX86 Endian.Little
  let hdl = BinHandle (binary, isa, ArchOperationMode.NoMode, None, false)
  let exnInfo = ExceptionInfo hdl
  let instrs = InstructionCollection (LinearSweepInstructionCollector hdl)
  let funcId = FunctionIdentification (hdl, exnInfo)
  let strategies = [| funcId :> ICFGBuildingStrategy<_, _>; CFGRecovery () |]

  [<TestMethod>]
  member _.``InstructionCollection Test 1`` () =
    Assert.AreEqual<int> (15, instrs.Count)

  [<TestMethod>]
  member _.``InstructionCollection Test 2`` () =
    let addrs =
      [ 0x00UL; 0x01UL; 0x02UL; 0x07UL; 0x0cUL; 0x11UL; 0x14UL; 0x16UL
        0x1cUL; 0x1eUL; 0x21UL; 0x22UL; 0x23UL; 0x24UL; 0x27UL ]
    addrs
    |> List.iter (fun addr ->
      let ins = instrs.Find addr
      Assert.AreEqual<uint64> (addr, ins.Address))

  [<TestMethod>]
  member _.``BBLFactory Test 1`` () =
    let bblFactory = BBLFactory (hdl, instrs)
    let bblAddrs = [| 0x00UL; 0x0cUL; 0x24UL |]
    scanBBLs bblFactory ArchOperationMode.NoMode bblAddrs
    let expected =
      [| (0x00UL, 0x00UL); (0x01UL, 0x00UL); (0x02UL, 0x00UL); (0x07UL, 0x00UL)
         (0x0cUL, 0x0cUL); (0x11UL, 0x0cUL); (0x14UL, 0x0cUL); (0x16UL, 0x0cUL)
         (0x1cUL, 0x0cUL); (0x1eUL, 0x0cUL); (0x21UL, 0x0cUL); (0x22UL, 0x0cUL)
         (0x23UL, 0x0cUL); (0x24UL, 0x24UL); (0x27UL, 0x24UL) |]
    let actual =
      [| for addr in [ 0x00UL; 0x0cUL; 0x1cUL; 0x1eUL; 0x24UL ] do
           extractInsBBLPairs bblFactory (ProgramPoint (addr, 0)) |]
      |> Array.concat
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member _.``BBLFactory Test 2`` () =
    let bblFactory = BBLFactory (hdl, instrs)
    let bblAddrs = [| 0x00UL; 0x0cUL; 0x24UL |]
    let pps = [| ProgramPoint (0x0UL, 0)
                 ProgramPoint (0xcUL, 0)
                 ProgramPoint (0x1cUL, 0)
                 ProgramPoint (0x1cUL, 2)
                 ProgramPoint (0x1cUL, 8)
                 ProgramPoint (0x1eUL, 0)
                 ProgramPoint (0x24UL, 0) |]
    scanBBLs bblFactory ArchOperationMode.NoMode bblAddrs
    Assert.AreEqual<int> (7, bblFactory.Count)
    let expected = [| (0x00UL, 0x0bUL); (0x0cUL, 0x1bUL); (0x1cUL, 0x1dUL)
                      (0x1cUL, 0x1dUL); (0x1cUL, 0x1dUL); (0x1eUL, 0x23UL);
                      (0x24UL, 0x27UL) |]
    let actual = [| for pp in pps do extractBBLRange bblFactory pp |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member _.``Functions Test 1`` () =
    let brew = BinaryBrew hdl
    let expected = [| 0UL; 0x24UL |]
    let actual = brew.Functions.Addresses |> Seq.toArray
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member _.``Functions Test 2`` () =
    let brew = BinaryBrew hdl
    let bblAddrs = [ 0x00UL; 0x24UL ]
    let callees = [ [ (0x07UL, RegularCallee 0x24UL) ]; [] ]
    (* CallEdges test *)
    let expected = makeMap bblAddrs callees
    let actual =
      brew.Functions.Sequence
      |> Seq.fold (fun acc fn ->
        Map.add fn.EntryPoint (extractCallEdgeArray fn.Callees) acc) Map.empty
    bblAddrs
    |> List.iter (fun addr ->
      Assert.AreEqual (Map.find addr expected, Map.find addr actual))

  [<TestMethod>]
  member _.``BBL Test`` () =
    let brew = BinaryBrew hdl
    let expected =
      [| (0x00UL, 0x00UL); (0x01UL, 0x00UL); (0x02UL, 0x00UL); (0x07UL, 0x00UL)
         (0x0cUL, 0x0cUL); (0x11UL, 0x0cUL); (0x14UL, 0x0cUL); (0x16UL, 0x0cUL)
         (0x1cUL, 0x0cUL); (0x1cUL, 0x0cUL); (0x1cUL, 0x0cUL); (0x1eUL, 0x0cUL)
         (0x21UL, 0x0cUL); (0x22UL, 0x0cUL); (0x23UL, 0x0cUL); (0x24UL, 0x24UL)
         (0x27UL, 0x24UL) |]
    let actual =
      brew.Functions.Sequence
      |> Seq.toArray
      |> Array.collect collectInsBBLAddrPairs
      |> Array.sortBy fst
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member _.``CFG Vertex Test: _start`` () =
    let brew = BinaryBrew hdl
    let cfg = brew.Functions[0x0UL].CFG
    Assert.AreEqual<int> (7, cfg.Size)
    let vMap = cfg.FoldVertex foldVertexNoFake Map.empty
    Assert.AreEqual<int> (6, vMap.Count)
    let leaders =
      [| ProgramPoint (0x00UL, 0); ProgramPoint (0x0CUL, 0);
         ProgramPoint (0x1CUL, 0); ProgramPoint (0x1CUL, 2);
         ProgramPoint (0x1CUL, 8); ProgramPoint (0x1EUL, 0) |]
    let actual =
      leaders |> Array.map (fun l -> (Map.find l vMap).VData.Internals.Range)
    let expected =
      [| AddrRange (0x00UL, 0x0bUL); AddrRange (0x0cUL, 0x1bUL)
         AddrRange (0x1cUL, 0x1dUL); AddrRange (0x1cUL, 0x1dUL)
         AddrRange (0x1cUL, 0x1dUL); AddrRange (0x1eUL, 0x23UL) |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member _.``CFG Edge Test: _start`` () =
    let brew = BinaryBrew hdl
    let cfg = brew.Functions[0x0UL].CFG
    let vMap = cfg.FoldVertex foldVertexNoFake Map.empty
    let leaders =
      [| ProgramPoint (0x00UL, 0); ProgramPoint (0x0CUL, 0);
         ProgramPoint (0x1CUL, 0); ProgramPoint (0x1CUL, 2);
         ProgramPoint (0x1CUL, 8); ProgramPoint (0x1EUL, 0) |]
    let vertices = leaders |> Array.map (fun l -> Map.find l vMap)
    let eMap = cfg.FoldEdge foldEdge Map.empty
    Assert.AreEqual<int> (7, eMap.Count)
    let eMap = cfg.FoldEdge foldEdgeNoFake Map.empty
    Assert.AreEqual<int> (5, eMap.Count)
    let actual =
      [| cfg.FindEdge(vertices[1], vertices[2]).Label
         cfg.FindEdge(vertices[2], vertices[3]).Label
         cfg.FindEdge(vertices[2], vertices[4]).Label
         cfg.FindEdge(vertices[3], vertices[2]).Label
         cfg.FindEdge(vertices[4], vertices[5]).Label |]
    let expected =
      [| FallThroughEdge; IntraCJmpFalseEdge
         IntraCJmpTrueEdge; InterJmpEdge; InterJmpEdge |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member _.``DisasmCFG Test: _start`` () =
    let brew = BinaryBrew hdl
    let cfg = brew.Functions[0x0UL].CFG
    let dcfg = DisasmCFG cfg
    Assert.AreEqual<int> (1, dcfg.Size)
    let vMap = dcfg.FoldVertex (fun m v ->
      Map.add v.VData.Internals.PPoint.Address v m) Map.empty
    let v = Map.find 0x00UL vMap
    Assert.AreEqual<int> (13, v.VData.Internals.Disassemblies.Length)
    let eMap = dcfg.FoldEdge (fun m e ->
      let v1, v2 = e.First, e.Second
      let key =
        v1.VData.Internals.PPoint.Address, v2.VData.Internals.PPoint.Address
      Map.add key e m) Map.empty
    Assert.AreEqual<int> (0, eMap.Count)

  [<TestMethod>]
  member _.``SSAGraph Vertex Test: _start`` () =
    let brew = BinaryBrew hdl
    let cfg = brew.Functions[0x0UL].CFG
    let ssaLifter = SSALifterFactory.Create hdl
    let ssacfg = ssaLifter.Lift cfg
    Assert.AreEqual<int> (7, ssacfg.Size)

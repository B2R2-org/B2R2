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

open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.BinEssence
open Microsoft.VisualStudio.TestTools.UnitTesting

module Utils =
  type IRNode = Vertex<IRBasicBlock>

  let foldVertexNoFake m (v: IRNode) =
    if v.VData.IsFakeBlock () then m
    else Map.add v.VData.PPoint v m

  let foldEdge m (v1: IRNode) (v2: IRNode) e =
    Map.add (v1.VData.PPoint, v2.VData.PPoint) e m

  let foldEdgeNoFake m (v1: IRNode) (v2: IRNode) e =
    if v1.VData.IsFakeBlock () || v2.VData.IsFakeBlock () then m
    else Map.add (v1.VData.PPoint, v2.VData.PPoint) e m

[<TestClass>]
type CFGTest1 () =

  /// This is a raw x86-64 binary code generated from the following C code:
  /// int foo(int a);
  /// void bar(int a);
  ///
  /// void _start()
  /// {
  ///     int x = 42;
  ///
  ///     if (x * foo(1) % 42 == 0) {
  ///         x = 1;
  ///     } else {
  ///         x = foo(2) + x;
  ///     }
  ///
  ///     bar(x);
  /// }
  ///
  /// int foo(int a)
  /// {
  ///     return a + 42;
  /// }
  ///
  /// void bar(int a)
  /// {
  ///     asm ( "mov $60, %rax" );
  ///     asm ( "syscall" );
  /// }
  ///
  /// binary: 554889e54883ec10c745fc2a000000bf01000000e8490000000faf45fc89c1ba310cc33089c8f7eac1fa0389c8c1f81f29c289d06bc02a29c189c885c07509c745fc01000000eb0dbf02000000e8100000000145fc8b45fc89c7e81200000090c9c3554889e5897dfc8b45fc83c02a5dc3554889e5897dfc48c7c03c0000000f05905dc3

  let binary =
     [| 0x55uy; 0x48uy; 0x89uy; 0xe5uy; 0x48uy; 0x83uy; 0xecuy; 0x10uy; 0xc7uy;
        0x45uy; 0xfcuy; 0x2auy; 0x00uy; 0x00uy; 0x00uy; 0xbfuy; 0x01uy; 0x00uy;
        0x00uy; 0x00uy; 0xe8uy; 0x49uy; 0x00uy; 0x00uy; 0x00uy; 0x0fuy; 0xafuy;
        0x45uy; 0xfcuy; 0x89uy; 0xc1uy; 0xbauy; 0x31uy; 0x0cuy; 0xc3uy; 0x30uy;
        0x89uy; 0xc8uy; 0xf7uy; 0xeauy; 0xc1uy; 0xfauy; 0x03uy; 0x89uy; 0xc8uy;
        0xc1uy; 0xf8uy; 0x1fuy; 0x29uy; 0xc2uy; 0x89uy; 0xd0uy; 0x6buy; 0xc0uy;
        0x2auy; 0x29uy; 0xc1uy; 0x89uy; 0xc8uy; 0x85uy; 0xc0uy; 0x75uy; 0x09uy;
        0xc7uy; 0x45uy; 0xfcuy; 0x01uy; 0x00uy; 0x00uy; 0x00uy; 0xebuy; 0x0duy;
        0xbfuy; 0x02uy; 0x00uy; 0x00uy; 0x00uy; 0xe8uy; 0x10uy; 0x00uy; 0x00uy;
        0x00uy; 0x01uy; 0x45uy; 0xfcuy; 0x8buy; 0x45uy; 0xfcuy; 0x89uy; 0xc7uy;
        0xe8uy; 0x12uy; 0x00uy; 0x00uy; 0x00uy; 0x90uy; 0xc9uy; 0xc3uy; 0x55uy;
        0x48uy; 0x89uy; 0xe5uy; 0x89uy; 0x7duy; 0xfcuy; 0x8buy; 0x45uy; 0xfcuy;
        0x83uy; 0xc0uy; 0x2auy; 0x5duy; 0xc3uy; 0x55uy; 0x48uy; 0x89uy; 0xe5uy;
        0x89uy; 0x7duy; 0xfcuy; 0x48uy; 0xc7uy; 0xc0uy; 0x3cuy; 0x00uy; 0x00uy;
        0x00uy; 0x0fuy; 0x05uy; 0x90uy; 0x5duy; 0xc3uy; |]

  let isa = ISA.Init Architecture.IntelX64 Endian.Little
  let hdl = BinHandle (binary, isa, None, false)
  let ess = BinEssence.init hdl [] [] []

  [<TestMethod>]
  member __.``CFGInfo: Instruction Map Test`` () =
    Assert.AreEqual (41, ess.CodeManager.InstructionCount)
    let expected =
      [ (0x00UL, 0x00UL); (0x01UL, 0x00UL); (0x04UL, 0x00UL); (0x08UL, 0x00UL);
        (0x0fUL, 0x00UL); (0x14UL, 0x00UL); (0x19UL, 0x19UL); (0x1dUL, 0x19UL);
        (0x1fUL, 0x19UL); (0x24UL, 0x19UL); (0x26UL, 0x19UL); (0x28UL, 0x19UL);
        (0x2bUL, 0x19UL); (0x2dUL, 0x19UL); (0x30UL, 0x19UL); (0x32UL, 0x19UL);
        (0x34UL, 0x19UL); (0x37UL, 0x19UL); (0x39UL, 0x19UL); (0x3bUL, 0x19UL);
        (0x3dUL, 0x19UL); (0x3fUL, 0x3fUL); (0x46UL, 0x3fUL); (0x48UL, 0x48UL);
        (0x4dUL, 0x48UL); (0x52UL, 0x52UL); (0x55UL, 0x55UL); (0x58UL, 0x55UL);
        (0x5aUL, 0x55UL); (0x62UL, 0x62UL); (0x63UL, 0x62UL); (0x66UL, 0x62UL);
        (0x69UL, 0x62UL); (0x6cUL, 0x62UL); (0x6fUL, 0x62UL); (0x70UL, 0x62UL);
        (0x71UL, 0x71UL); (0x72UL, 0x71UL); (0x75UL, 0x71UL); (0x78UL, 0x71UL);
        (0x7fUL, 0x71UL) ]
      |> List.toArray
    let actual =
      ess.CodeManager.FoldInstructions (fun acc (KeyValue (insAddr, bbl)) ->
        Set.add (insAddr, bbl.BBLAddr) acc) Set.empty
      |> Set.toArray
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``CFGInfo: Instruction BBLMap Test`` () =
    Assert.AreEqual (8, ess.CodeManager.BBLCount)
    (* BlkRange test *)
    let expected =
      [ (0x00UL, 0x18UL); (0x19UL, 0x3eUL); (0x3fUL, 0x47UL); (0x48UL, 0x51UL);
        (0x52UL, 0x54UL); (0x55UL, 0x5eUL); (0x62UL, 0x70UL); (0x71UL, 0x80UL) ]
      |> List.toArray
    let actual =
      ess.CodeManager.FoldBBLs (fun acc (KeyValue (_, bblInfo)) ->
        let range = bblInfo.BlkRange
        Set.add (range.Min, range.Max) acc) Set.empty
      |> Set.toArray
    CollectionAssert.AreEqual (expected, actual)
    let expectedBBLAddrs =
      [| 0x00UL; 0x19UL; 0x3fUL; 0x48UL; 0x52UL; 0x55UL; 0x62UL; 0x71UL |]
    let actualBBLAddrs =
      ess.CodeManager.FoldBBLs (fun acc (KeyValue (addr, _)) ->
        Set.add addr acc) Set.empty
      |> Set.toArray
    CollectionAssert.AreEqual (expectedBBLAddrs, actualBBLAddrs)
    (* InstrAddrs test *)
    let expected =
      Map.empty
      |> Map.add 0x00UL [| 0x00UL; 0x01UL; 0x04UL; 0x08UL; 0x0fUL; 0x14UL |]
      |> Map.add 0x19UL [| 0x19UL; 0x1dUL; 0x1fUL; 0x24UL; 0x26UL; 0x28UL;
                           0x2bUL; 0x2dUL; 0x30UL; 0x32UL; 0x34UL; 0x37UL;
                           0x39UL; 0x3bUL; 0x3dUL |]
      |> Map.add 0x3fUL [| 0x3fUL; 0x46UL |]
      |> Map.add 0x48UL [| 0x48UL; 0x4dUL |]
      |> Map.add 0x52UL [| 0x52UL |]
      |> Map.add 0x55UL [| 0x55UL; 0x58UL; 0x5aUL |]
      |> Map.add 0x62UL [| 0x62UL; 0x63UL; 0x66UL; 0x69UL; 0x6cUL; 0x6fUL;
                           0x70UL |]
      |> Map.add 0x71UL [| 0x71UL; 0x72UL; 0x75UL; 0x78UL; 0x7fUL |]
    let actual =
      ess.CodeManager.FoldBBLs (fun acc (KeyValue (addr, bblInfo)) ->
        Map.add addr (Set.toArray bblInfo.InstrAddrs) acc) Map.empty
    [ 0x00UL; 0x19UL; 0x3fUL; 0x48UL; 0x52UL; 0x55UL; 0x62UL ]
    |> List.iter (fun addr ->
      CollectionAssert.AreEqual (Map.find addr expected, Map.find addr actual))
    (* IRLeaders test *)
    let expected =
      Map.empty
      |> Map.add 0x00UL [| (0x00UL, 0) |]
      |> Map.add 0x19UL [| (0x19UL, 0) |]
      |> Map.add 0x3fUL [| (0x3fUL, 0) |]
      |> Map.add 0x48UL [| (0x48UL, 0) |]
      |> Map.add 0x52UL [| (0x52UL, 0) |]
      |> Map.add 0x55UL [| (0x55UL, 0) |]
      |> Map.add 0x62UL [| (0x62UL, 0) |]
      |> Map.add 0x71UL [| (0x71UL, 0) |]
    let actual =
      ess.CodeManager.FoldBBLs (fun acc (KeyValue (addr, bblInfo)) ->
        let leaders =
          bblInfo.IRLeaders
          |> Set.map (fun pp -> pp.Address, pp.Position)
          |> Set.toArray
        Map.add addr leaders acc) Map.empty
    [ 0x00UL; 0x19UL; 0x3fUL; 0x48UL; 0x52UL; 0x55UL; 0x62UL ]
    |> List.iter (fun addr ->
      CollectionAssert.AreEqual (Map.find addr expected, Map.find addr actual))
    (* Entry point test*)
    let expected =
      [ (0x00UL, 0x00UL); (0x19UL, 0x00UL); (0x3fUL, 0x00UL); (0x48UL, 0x00UL);
        (0x52UL, 0x00UL); (0x55UL, 0x00UL); (0x62UL, 0x62UL); (0x71UL, 0x71UL) ]
      |> List.toArray
    let actual =
      ess.CodeManager.FoldBBLs (fun acc (KeyValue (addr, bblInfo)) ->
        Set.add (addr, bblInfo.FunctionEntry) acc) Set.empty
      |> Set.toArray
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``CFGInfo: IRLevelBBLs Test`` () =
    let cnt =
      ess.CodeManager.FunctionMaintainer.RegularFunctions
      |> Seq.fold (fun cnt f -> f.CountRegularVertices + cnt) 0
    Assert.AreEqual (8, cnt)
    let expected =
      [ (0x00UL, 0); (0x19UL, 0); (0x3fUL, 0); (0x48UL, 0); (0x52UL, 0);
        (0x55UL, 0); (0x62UL, 0); (0x71UL, 0) ]
      |> List.toArray
    let actual =
      ess.CodeManager.FunctionMaintainer.RegularFunctions
      |> Seq.fold (fun acc f ->
        f.FoldRegularVertices (fun acc (KeyValue (pp,_)) ->
          Set.add (pp.Address, pp.Position) acc) acc) Set.empty
      |> Set.toArray
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``CFGInfo: BBLBounds Test`` () =
    let expected =
      [ (0x00UL, 0x18UL); (0x19UL, 0x3EUL); (0x3FUL, 0x47UL); (0x48UL, 0x51UL);
        (0x52UL, 0x54UL); (0x55UL, 0x5EUL); (0x62UL, 0x70UL); (0x71UL, 0x80UL) ]
      |> List.toArray
    expected
    |> Array.iter (fun (minAddr, maxAddr) ->
      let bbl = ess.CodeManager.GetBBL minAddr
      let f = ess.CodeManager.FunctionMaintainer.FindRegular bbl.FunctionEntry
      for addr in minAddr .. maxAddr - 1UL do
        Assert.IsTrue (f.IsAddressCovered addr)
    )

  [<TestMethod>]
  member __.``CFGInfo: Funcs Test`` () =
    Assert.AreEqual (3, ess.CodeManager.FunctionMaintainer.Count)
    (* Entry point test *)
    let expected = [ 0UL; 0x62UL; 0x71UL ] |> List.toArray
    let actual = ess.CodeManager.FunctionMaintainer.Entries |> Seq.toArray
    CollectionAssert.AreEqual (expected, actual)
    (* Function test except CFG *)
    (* CallEdges test *)
    let expected =
      Map.empty
      |> Map.add 0x00UL [| (0x14UL, RegularCallee 0x62UL);
                           (0x4dUL, RegularCallee 0x62UL);
                           (0x5aUL, RegularCallee 0x71UL) |]
      |> Map.add 0x62UL [| |]
      |> Map.add 0x71UL [| |]
    let actual =
      ess.CodeManager.FunctionMaintainer.RegularFunctions
      |> Seq.fold (fun acc func ->
        Map.add func.EntryPoint func.CallEdges acc) Map.empty
    [ 0x00UL; 0x62UL; 0x71UL ]
    |> List.iter (fun addr ->
      CollectionAssert.AreEqual (Map.find addr expected, Map.find addr actual))
    (* Callers test *)
    let expected =
      Map.empty
      |> Map.add 0x00UL [| |]
      |> Map.add 0x62UL [| 0x00UL |]
      |> Map.add 0x71UL [| 0x00UL |]
    let actual =
      ess.CodeManager.FunctionMaintainer.Functions
      |> Seq.fold (fun acc func ->
        Map.add func.EntryPoint (Seq.toArray func.Callers) acc) Map.empty
    [ 0x00UL; 0x62UL; 0x71UL ]
    |> List.iter (fun addr ->
      CollectionAssert.AreEqual (Map.find addr expected, Map.find addr actual))
    (* SyscallSites test *)
    let expected =
      Map.empty
      |> Map.add 0x00UL [| |]
      |> Map.add 0x62UL [| |]
      |> Map.add 0x71UL [| 0x7fUL |]
    let actual =
      ess.CodeManager.FunctionMaintainer.RegularFunctions
      |> Seq.fold (fun acc func ->
        let syscallSites = func.SyscallSites |> Seq.toArray
        Map.add func.EntryPoint syscallSites acc) Map.empty
    [ 0x00UL; 0x62UL; 0x71UL ]
    |> List.iter (fun addr ->
      CollectionAssert.AreEqual (Map.find addr expected, Map.find addr actual))

  [<TestMethod>]
  member __.``CFG Vertex Test: _start`` () =
    let cfg, _ = BinEssence.getFunctionCFG ess 0UL |> Result.get
    Assert.AreEqual (9, DiGraph.GetSize cfg)
    let vMap = cfg.FoldVertex Utils.foldVertexNoFake Map.empty
    Assert.AreEqual (6, vMap.Count)
    let leaders =
      [| ProgramPoint (0x00UL, 0); ProgramPoint (0x19UL, 0);
         ProgramPoint (0x3FUL, 0); ProgramPoint (0x48UL, 0);
         ProgramPoint (0x52UL, 0); ProgramPoint (0x55UL, 0); |]
    let actual = leaders |> Array.map (fun l -> (Map.find l vMap).VData.Range)
    let expected =
      [| AddrRange (0x00UL, 0x18UL); AddrRange (0x19UL, 0x3EUL);
         AddrRange (0x3FUL, 0x47UL); AddrRange (0x48UL, 0x51UL);
         AddrRange (0x52UL, 0x54UL); AddrRange (0x55UL, 0x5EUL); |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``CFG Edge Test: _start`` () =
    let cfg, _ = BinEssence.getFunctionCFG ess 0UL |> Result.get
    let vMap = cfg.FoldVertex Utils.foldVertexNoFake Map.empty
    let leaders =
      [| ProgramPoint (0x00UL, 0); ProgramPoint (0x19UL, 0);
         ProgramPoint (0x3FUL, 0); ProgramPoint (0x48UL, 0);
         ProgramPoint (0x52UL, 0); ProgramPoint (0x55UL, 0); |]
    let vertices = leaders |> Array.map (fun l -> Map.find l vMap)
    let eMap = cfg.FoldEdge Utils.foldEdge Map.empty
    Assert.AreEqual (11, eMap.Count)
    let eMap = cfg.FoldEdge Utils.foldEdgeNoFake Map.empty
    Assert.AreEqual (6, eMap.Count)
    [ ProgramPoint (0x00UL, 0), ProgramPoint (0x19UL, 0);
      ProgramPoint (0x19UL, 0), ProgramPoint (0x3FUL, 0);
      ProgramPoint (0x19UL, 0), ProgramPoint (0x48UL, 0);
      ProgramPoint (0x3FUL, 0), ProgramPoint (0x55UL, 0);
      ProgramPoint (0x48UL, 0), ProgramPoint (0x52UL, 0);
      ProgramPoint (0x52UL, 0), ProgramPoint (0x55UL, 0); ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x eMap)
    let actual =
      [| cfg.FindEdgeData (vertices[0], vertices[1])
         cfg.FindEdgeData (vertices[1], vertices[2])
         cfg.FindEdgeData (vertices[1], vertices[3])
         cfg.FindEdgeData (vertices[2], vertices[5])
         cfg.FindEdgeData (vertices[3], vertices[4])
         cfg.FindEdgeData (vertices[4], vertices[5]) |]
    let expected =
      [| CallFallThroughEdge; InterCJmpFalseEdge; InterCJmpTrueEdge;
         InterJmpEdge; CallFallThroughEdge; FallThroughEdge; |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``CFG Vertex Test: foo`` () =
    let cfg, _ = BinEssence.getFunctionCFG ess 0x62UL |> Result.get
    Assert.AreEqual (1, DiGraph.GetSize cfg)
    let vMap = cfg.FoldVertex Utils.foldVertexNoFake Map.empty
    let leaders = [| ProgramPoint (0x62UL, 0) |]
    let actual = leaders |> Array.map (fun l -> (Map.find l vMap).VData.Range)
    let expected = [| AddrRange (0x62UL, 0x70UL) |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``CFG Edge Test: foo`` () =
    let cfg, _ = BinEssence.getFunctionCFG ess 0x62UL |> Result.get
    let eMap = cfg.FoldEdge Utils.foldEdge Map.empty
    Assert.AreEqual (0, eMap.Count)

  [<TestMethod>]
  member __.``CFG Vertex Test: bar`` () =
    let cfg, _ = BinEssence.getFunctionCFG ess 0x71UL |> Result.get
    Assert.AreEqual (1, DiGraph.GetSize cfg)
    let vMap = cfg.FoldVertex Utils.foldVertexNoFake Map.empty
    let leaders = [| ProgramPoint (0x71UL, 0) |]
    let actual = leaders |> Array.map (fun l -> (Map.find l vMap).VData.Range)
    let expected = [| AddrRange (0x71UL, 0x80UL) |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``CFG Edge Test: bar`` () =
    let cfg, _ = BinEssence.getFunctionCFG ess 0x71UL |> Result.get
    let eMap = cfg.FoldEdge Utils.foldEdge Map.empty
    Assert.AreEqual (0, eMap.Count)

  [<TestMethod>]
  member __.``CFG SSAGraph Vertex Test: _start`` () =
    let cfg, root = BinEssence.getFunctionCFG ess 0UL |> Result.get
    let struct (ssacfg, _) = SSACFG.ofIRCFG hdl cfg root
    Assert.AreEqual (9, DiGraph.GetSize ssacfg)

[<TestClass>]
type CFGTest2 () =

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
  let hdl = BinHandle (binary, isa, None, false)
  let ess = BinEssence.init hdl [] [] []

  [<TestMethod>]
  member __.``CFGInfo: Instruction Map Test`` () =
    Assert.AreEqual (15, ess.CodeManager.InstructionCount)
    let expected =
      [ (0x00UL, 0x00UL); (0x01UL, 0x00UL); (0x02UL, 0x00UL); (0x07UL, 0x00UL);
        (0x0cUL, 0x0cUL); (0x11UL, 0x0cUL); (0x14UL, 0x0cUL); (0x16UL, 0x0cUL);
        (0x1cUL, 0x0cUL); (0x1eUL, 0x0cUL); (0x21UL, 0x0cUL); (0x22UL, 0x0cUL);
        (0x23UL, 0x0cUL); (0x24UL, 0x24UL); (0x27UL, 0x24UL) ]
      |> List.toArray
    let actual =
      ess.CodeManager.FoldInstructions (fun acc (KeyValue (insAddr, bbl)) ->
        Set.add (insAddr, bbl.BBLAddr) acc) Set.empty
      |> Set.toArray
    CollectionAssert.AreEqual (expected, actual)

#if !EMULATION
  [<TestMethod>]
  member __.``CFGInfo: Instruction BBLMap Test`` () =
    Assert.AreEqual (3, ess.CodeManager.BBLCount)
    (* BlkRange test *)
    let expected =
      [ (0x00UL, 0x0bUL); (0x0cUL, 0x23UL); (0x24UL, 0x27UL) ]
      |> List.toArray
    let actual =
      ess.CodeManager.FoldBBLs (fun acc (KeyValue (_, bblInfo)) ->
        let range = bblInfo.BlkRange
        Set.add (range.Min, range.Max) acc) Set.empty
      |> Set.toArray
    CollectionAssert.AreEqual (expected, actual)
    let expectedBBLAddrs =
      [| 0x00UL; 0x0cUL; 0x24UL |]
    let actualBBLAddrs =
      ess.CodeManager.FoldBBLs (fun acc (KeyValue (addr, _)) ->
        Set.add addr acc) Set.empty
      |> Set.toArray
    CollectionAssert.AreEqual (expectedBBLAddrs, actualBBLAddrs)
    (* InstrAddrs test *)
    let expected =
      Map.empty
      |> Map.add 0x00UL [| 0x00UL; 0x01UL; 0x02UL; 0x07UL |]
      |> Map.add 0x0cUL [| 0x0cUL; 0x11UL; 0x14UL; 0x16UL; 0x1cUL; 0x1eUL;
                           0x21UL; 0x22UL; 0x23UL |]
      |> Map.add 0x24UL [| 0x24UL; 0x27UL |]
    let actual =
      ess.CodeManager.FoldBBLs (fun acc (KeyValue (addr, bblInfo)) ->
        Map.add addr (Set.toArray bblInfo.InstrAddrs) acc) Map.empty
    [ 0x00UL; 0x0cUL; 0x24UL ]
    |> List.iter (fun addr ->
      CollectionAssert.AreEqual (Map.find addr expected, Map.find addr actual))
    (* IRLeaders test *)
    let expected =
      Map.empty
      |> Map.add 0x00UL [| (0x00UL, 0) |]
      |> Map.add 0x0cUL [| (0x0cUL, 0); (0x1cUL, 0); (0x1cUL, 2); (0x1cUL, 8);
                           (0x1eUL, 0) |]
      |> Map.add 0x24UL [| (0x24UL, 0) |]
    let actual =
      ess.CodeManager.FoldBBLs (fun acc (KeyValue (addr, bblInfo)) ->
        let leaders =
          bblInfo.IRLeaders
          |> Set.map (fun pp -> pp.Address, pp.Position)
          |> Set.toArray
        Map.add addr leaders acc) Map.empty
    [ 0x00UL; 0x0cUL; 0x24UL ]
    |> List.iter (fun addr ->
      CollectionAssert.AreEqual (Map.find addr expected, Map.find addr actual))
    (* Entry point test*)
    let expected =
      [ (0x00UL, 0x00UL); (0x0cUL, 0x00UL); (0x24UL, 0x24UL) ]
      |> List.toArray
    let actual =
      ess.CodeManager.FoldBBLs (fun acc (KeyValue (addr, bblInfo)) ->
        Set.add (addr, bblInfo.FunctionEntry) acc) Set.empty
      |> Set.toArray
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``CFGInfo: IRLevelBBLs Test`` () =
    let cnt =
      ess.CodeManager.FunctionMaintainer.RegularFunctions
      |> Seq.fold (fun cnt f -> f.CountRegularVertices + cnt) 0
    Assert.AreEqual (7, cnt)
    let expected =
      [ (0x00UL, 0); (0x0cUL, 0); (0x1cUL, 0); (0x1cUL, 2); (0x1cUL, 8);
        (0x1eUL, 0); (0x24UL, 0) ]
      |> List.toArray
    let actual =
      ess.CodeManager.FunctionMaintainer.RegularFunctions
      |> Seq.fold (fun acc f ->
        f.FoldRegularVertices (fun acc (KeyValue (pp,_)) ->
          Set.add (pp.Address, pp.Position) acc) acc) Set.empty
      |> Set.toArray
    CollectionAssert.AreEqual (expected, actual)
#endif

  [<TestMethod>]
  member __.``CFGInfo: BBLBounds Test`` () =
    let expected =
      [ (0x00UL, 0x0bUL); (0x0cUL, 0x23UL); (0x24UL, 0x27UL) ]
      |> List.toArray
    expected
    |> Array.iter (fun (minAddr, maxAddr) ->
      let bbl = ess.CodeManager.GetBBL minAddr
      let f = ess.CodeManager.FunctionMaintainer.FindRegular bbl.FunctionEntry
      for addr in minAddr .. maxAddr - 1UL do
        Assert.IsTrue (f.IsAddressCovered addr)
    )

  [<TestMethod>]
  member __.``CFGInfo: Funcs Test`` () =
    Assert.AreEqual (2, ess.CodeManager.FunctionMaintainer.Count)
    (* Entry point test *)
    let expected = [ 0UL; 0x24UL ] |> List.toArray
    let actual = ess.CodeManager.FunctionMaintainer.Entries |> Seq.toArray
    CollectionAssert.AreEqual (expected, actual)
    (* Function test except CFG *)
    (* CallEdges test *)
    let expected =
      Map.empty
      |> Map.add 0x00UL [| (0x07UL, RegularCallee 0x24UL) |]
      |> Map.add 0x24UL [| |]
    let actual =
      ess.CodeManager.FunctionMaintainer.RegularFunctions
      |> Seq.fold (fun acc func ->
        Map.add func.EntryPoint func.CallEdges acc) Map.empty
    [ 0x00UL; 0x24UL ]
    |> List.iter (fun addr ->
      CollectionAssert.AreEqual (Map.find addr expected, Map.find addr actual))
    (* Callers test *)
    let expected =
      Map.empty
      |> Map.add 0x00UL [| |]
      |> Map.add 0x24UL [| 0x00UL |]
    let actual =
      ess.CodeManager.FunctionMaintainer.Functions
      |> Seq.fold (fun acc func ->
        Map.add func.EntryPoint (Seq.toArray func.Callers) acc) Map.empty
    [ 0x00UL; 0x24UL ]
    |> List.iter (fun addr ->
      CollectionAssert.AreEqual (Map.find addr expected, Map.find addr actual))
    (* SyscallSites test *)
    let expected =
      Map.empty
      |> Map.add 0x00UL [| |]
      |> Map.add 0x24UL [| |]
    let actual =
      ess.CodeManager.FunctionMaintainer.RegularFunctions
      |> Seq.fold (fun acc func ->
        let syscallSites = func.SyscallSites |> Seq.toArray
        Map.add func.EntryPoint syscallSites acc) Map.empty
    [ 0x00UL; 0x24UL ]
    |> List.iter (fun addr ->
      CollectionAssert.AreEqual (Map.find addr expected, Map.find addr actual))

#if !EMULATION
  [<TestMethod>]
  member __.``CFG Vertex Test: _start`` () =
    let cfg, _ = BinEssence.getFunctionCFG ess 0UL |> Result.get
    Assert.AreEqual (7, DiGraph.GetSize cfg)
    let vMap = cfg.FoldVertex Utils.foldVertexNoFake Map.empty
    let leaders =
      [| ProgramPoint (0x00UL, 0); ProgramPoint (0x0CUL, 0);
         ProgramPoint (0x1CUL, 0); ProgramPoint (0x1CUL, 2);
         ProgramPoint (0x1CUL, 8); ProgramPoint (0x1EUL, 0) |]
    let actual =
      leaders
      |> Array.map (fun l ->
        match (Map.find l vMap).VData.LastStmt.S with
        | IEMark _ -> 0
        | InterJmp _ -> 1
        | InterCJmp _ -> 2
        | Jmp _ -> 3
        | CJmp _ -> 4
        | _ -> -1)
    let expected =
      [| 1; 0; 4; 1; 1; 1 |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``CFG Edge Test: _start`` () =
    let cfg, _ = BinEssence.getFunctionCFG ess 0UL |> Result.get
    let vMap = cfg.FoldVertex Utils.foldVertexNoFake Map.empty
    let leaders =
      [| ProgramPoint (0x00UL, 0); ProgramPoint (0x0CUL, 0);
         ProgramPoint (0x1CUL, 0); ProgramPoint (0x1CUL, 2);
         ProgramPoint (0x1CUL, 8); ProgramPoint (0x1EUL, 0) |]
    let vertices = leaders |> Array.map (fun l -> Map.find l vMap)
    let eMap = cfg.FoldEdge Utils.foldEdge Map.empty
    Assert.AreEqual (8, eMap.Count)
    let eMap = cfg.FoldEdge Utils.foldEdgeNoFake Map.empty
    Assert.AreEqual (6, eMap.Count)
    [ (ProgramPoint (0x00UL, 0), ProgramPoint (0x0CUL, 0));
      (ProgramPoint (0x0CUL, 0), ProgramPoint (0x1CUL, 0));
      (ProgramPoint (0x1CUL, 0), ProgramPoint (0x1CUL, 2));
      (ProgramPoint (0x1CUL, 0), ProgramPoint (0x1CUL, 8));
      (ProgramPoint (0x1CUL, 2), ProgramPoint (0x1CUL, 0));
      (ProgramPoint (0x1CUL, 8), ProgramPoint (0x1EUL, 0)); ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x eMap)
    let actual =
      [| cfg.FindEdgeData (vertices[0], vertices[1])
         cfg.FindEdgeData (vertices[1], vertices[2])
         cfg.FindEdgeData (vertices[2], vertices[3])
         cfg.FindEdgeData (vertices[2], vertices[4])
         cfg.FindEdgeData (vertices[3], vertices[2])
         cfg.FindEdgeData (vertices[4], vertices[5]) |]
    let expected =
      [| CallFallThroughEdge; FallThroughEdge; IntraCJmpFalseEdge;
         IntraCJmpTrueEdge; InterJmpEdge; InterJmpEdge |]
    CollectionAssert.AreEqual (expected, actual)
#endif

  [<TestMethod>]
  member __.``DisasmLens Test: _start`` () =
    let cfg, root = BinEssence.getFunctionCFG ess 0UL |> Result.get
    let cfg, _ = DisasmLens.filter ess.CodeManager cfg root
    Assert.AreEqual (1, DiGraph.GetSize cfg)
    let vMap = cfg.FoldVertex (fun m v ->
      Map.add v.VData.PPoint.Address v m) Map.empty
    let leaders = [| 0x00UL |]
    let vertices = leaders |> Array.map (fun l -> Map.find l vMap)
    let disasmLens = [| 13 |]
    Array.zip vertices disasmLens
    |> Array.iter (fun (v, len) ->
      Assert.AreEqual (len, v.VData.Disassemblies.Length))
    let eMap = cfg.FoldEdge (fun m v1 v2 e ->
      let key = v1.VData.PPoint.Address, v2.VData.PPoint.Address
      Map.add key e m) Map.empty
    Assert.AreEqual (0, eMap.Count)

  [<TestMethod>]
  member __.``SSAGraph Vertex Test: _start`` () =
    let cfg, root = BinEssence.getFunctionCFG ess 0UL |> Result.get
    let struct (ssacfg, _) = SSACFG.ofIRCFG hdl cfg root
    Assert.AreEqual (7, DiGraph.GetSize ssacfg)

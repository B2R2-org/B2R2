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

open System.Collections.Generic
open B2R2
open B2R2.BinIR.LowUIR
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.SSA
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies
open Microsoft.VisualStudio.TestTools.UnitTesting

[<AutoOpen>]
module Utils =
  let scanBBLs (bblFactory: BBLFactory) mode addrs =
    bblFactory.ScanBBLs mode addrs
    |> Async.AwaitTask
    |> Async.RunSynchronously
    |> ignore

  let extractInsBBLPairs (bblFactory: BBLFactory) ppoint =
    let bbl = bblFactory.Find ppoint
    bbl.LiftedInstructions
    |> Array.map (fun li -> li.Original.Address, li.BBLAddr)

  let extractBBLRange (bblFactory: BBLFactory) ppoint =
    let bbl = bblFactory.Find ppoint
    bbl.Range.Min, bbl.Range.Max

  let makeMap keys values =
    List.fold2 (fun map k v -> Map.add k v map) Map.empty keys values

  let extractCallEdgeArray (callees: SortedList<Addr, CalleeKind>) =
    callees
    |> Seq.map (fun (KeyValue (k, v)) -> k, v)
    |> Seq.toList

  let foldVertexNoFake m (v: IVertex<IRBasicBlock>) =
    if v.VData.IsAbstract then m
    else Map.add v.VData.PPoint v m

  let foldEdge m (e: Edge<IRBasicBlock, _>) =
    let v1, v2 = e.First, e.Second
    Map.add (v1.VData.PPoint, v2.VData.PPoint) e m

  let foldEdgeNoFake m (e: Edge<IRBasicBlock, _>) =
    let v1, v2 = e.First, e.Second
    if v1.VData.IsAbstract || v2.VData.IsAbstract then m
    else Map.add (v1.VData.PPoint, v2.VData.PPoint) e m

  let collectInsBBLAddrPairs (fn: Function<_, _>) =
    fn.CFG.FoldVertex (fun acc v ->
      if v.VData.IsAbstract then acc
      else
        v.VData.LiftedInstructions
        |> Array.map (fun li -> li.Original.Address, li.BBLAddr)
        |> fun arr -> arr :: acc
    ) []
    |> Array.concat

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
  let hdl = BinHandle (binary, isa, ArchOperationMode.NoMode, None, false)
  let instrs = InstructionCollection (LinearSweepInstructionCollector hdl)
  let strategy = BaseStrategy<DummyContext, DummyContext> ()

  [<TestMethod>]
  member __.``InstructionCollection Test 1`` () =
    Assert.AreEqual (47, instrs.Count)

  [<TestMethod>]
  member __.``InstructionCollection Test 2`` () =
    let addrs =
      [ 0x00UL; 0x01UL; 0x04UL; 0x08UL; 0x0fUL; 0x14UL; 0x19UL; 0x1dUL; 0x1fUL
        0x24UL; 0x26UL; 0x28UL; 0x2bUL; 0x2dUL; 0x30UL; 0x32UL; 0x34UL; 0x37UL
        0x39UL; 0x3bUL; 0x3dUL; 0x3fUL; 0x46UL; 0x48UL; 0x4dUL; 0x52UL; 0x55UL
        0x58UL; 0x5aUL; 0x62UL; 0x63UL; 0x66UL; 0x69UL; 0x6cUL; 0x6fUL; 0x70UL
        0x71UL; 0x72UL; 0x75UL; 0x78UL; 0x7fUL ]
    addrs
    |> List.iter (fun addr ->
      let ins = instrs.Find addr
      Assert.AreEqual (addr, ins.Address))

  [<TestMethod>]
  member __.``BBLFactory Test 1`` () =
    let bblFactory = BBLFactory (hdl, instrs)
    let bblAddrs = [| 0x00UL; 0x62UL |]
    scanBBLs bblFactory ArchOperationMode.NoMode bblAddrs
    let expected =
      [| (0x00UL, 0x00UL); (0x01UL, 0x00UL); (0x04UL, 0x00UL); (0x08UL, 0x00UL)
         (0x0fUL, 0x00UL); (0x14UL, 0x00UL); (0x62UL, 0x62UL); (0x63UL, 0x62UL)
         (0x66UL, 0x62UL); (0x69UL, 0x62UL); (0x6cUL, 0x62UL); (0x6fUL, 0x62UL)
         (0x70UL, 0x62UL)|]
    let actual =
      [| for addr in bblAddrs do
           extractInsBBLPairs bblFactory (ProgramPoint (addr, 0)) |]
      |> Array.concat
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``BBLFactory Test 2`` () =
    let bblFactory = BBLFactory (hdl, instrs)
    let bblAddrs = [| 0x00UL; 0x62UL |]
    scanBBLs bblFactory ArchOperationMode.NoMode bblAddrs
    Assert.AreEqual (2, bblFactory.Count)
    let expected = [| (0x00UL, 0x18UL); (0x62UL, 0x70UL) |]
    let actual =
      [| for addr in bblAddrs do
           extractBBLRange bblFactory (ProgramPoint (addr, 0)) |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``Functions Test 1`` () =
    let brew = BinaryBrew (hdl, strategy)
    let expected = [| 0UL; 0x62UL; 0x71UL |]
    let actual = brew.Functions.Addresses |> Seq.toArray
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``Functions Test 2`` () =
    let brew = BinaryBrew (hdl, strategy)
    let bblAddrs = [ 0x00UL; 0x62UL; 0x71UL ]
    let callees = [ [ (0x14UL, RegularCallee 0x62UL)
                      (0x4dUL, RegularCallee 0x62UL)
                      (0x5aUL, RegularCallee 0x71UL) ]; []; [] ]
    let expected = makeMap bblAddrs callees
    let actual =
      brew.Functions.Sequence
      |> Seq.fold (fun acc fn ->
        Map.add fn.EntryPoint (extractCallEdgeArray fn.Callees) acc) Map.empty
    bblAddrs
    |> List.iter (fun addr ->
      Assert.AreEqual (Map.find addr expected, Map.find addr actual))

  [<TestMethod>]
  member __.``Functions Test 3`` () =
    let brew = BinaryBrew (hdl, strategy)
    let bblAddrs = [ 0x00UL; 0x62UL; 0x71UL ]
    let callers = [ []; [ 0x00UL ]; [ 0x00UL ] ]
    let expected = makeMap bblAddrs callers
    let actual =
      brew.Functions.Sequence
      |> Seq.fold (fun acc fn ->
        Map.add fn.EntryPoint (Seq.toList fn.Callers) acc) Map.empty
    bblAddrs
    |> List.iter (fun addr ->
      printfn "%A" <| Map.find addr actual
      Assert.AreEqual (Map.find addr expected, Map.find addr actual))

  [<TestMethod>]
  member __.``BBL Test 1`` () =
    let brew = BinaryBrew (hdl, strategy)
    let expected =
      [| (0x00UL, 0x00UL); (0x01UL, 0x00UL); (0x04UL, 0x00UL); (0x08UL, 0x00UL)
         (0x0fUL, 0x00UL); (0x14UL, 0x00UL); (0x19UL, 0x19UL); (0x1dUL, 0x19UL)
         (0x1fUL, 0x19UL); (0x24UL, 0x19UL); (0x26UL, 0x19UL); (0x28UL, 0x19UL)
         (0x2bUL, 0x19UL); (0x2dUL, 0x19UL); (0x30UL, 0x19UL); (0x32UL, 0x19UL)
         (0x34UL, 0x19UL); (0x37UL, 0x19UL); (0x39UL, 0x19UL); (0x3bUL, 0x19UL)
         (0x3dUL, 0x19UL); (0x3fUL, 0x3fUL); (0x46UL, 0x3fUL); (0x48UL, 0x48UL)
         (0x4dUL, 0x48UL); (0x52UL, 0x52UL); (0x55UL, 0x55UL); (0x58UL, 0x55UL)
         (0x5aUL, 0x55UL); (0x62UL, 0x62UL); (0x63UL, 0x62UL); (0x66UL, 0x62UL)
         (0x69UL, 0x62UL); (0x6cUL, 0x62UL); (0x6fUL, 0x62UL); (0x70UL, 0x62UL)
         (0x71UL, 0x71UL); (0x72UL, 0x71UL); (0x75UL, 0x71UL); (0x78UL, 0x71UL)
         (0x7fUL, 0x71UL) |]
    let actual =
      brew.Functions.Sequence
      |> Seq.toArray
      |> Array.map collectInsBBLAddrPairs
      |> Array.concat
      |> Array.sortBy fst
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``BBL Test 2`` () =
    let brew = BinaryBrew (hdl, strategy)
    Assert.AreEqual (8, brew.Functions.Count)
    let expected =
      [ (0x00UL, 0x18UL); (0x19UL, 0x3eUL); (0x3fUL, 0x47UL); (0x48UL, 0x51UL)
        (0x52UL, 0x54UL); (0x55UL, 0x5eUL); (0x62UL, 0x70UL); (0x71UL, 0x80UL) ]
      |> List.toArray
    let actual =
      brew.Functions.Sequence
      |> Seq.toArray
      |> Array.map collectInsBBLAddrPairs
      |> Array.concat
      |> Array.sortBy fst
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``BBL Test 3`` () =
    let brew = BinaryBrew (hdl, strategy)
    let cnt =
      brew.Functions.Sequence
      |> Seq.fold (fun cnt fn ->
        fn.CFG.FoldVertex (fun cnt _ -> cnt + 1) cnt + cnt) 0
    Assert.AreEqual (8, cnt)
    let expected =
      [| (0x00UL, 0); (0x19UL, 0); (0x3fUL, 0); (0x48UL, 0); (0x52UL, 0)
         (0x55UL, 0); (0x62UL, 0); (0x71UL, 0) |]
    let actual =
      brew.Functions.Sequence
      |> Seq.fold (fun acc fn ->
        fn.CFG.FoldVertex (fun acc v ->
          let pp = v.VData.PPoint
          Set.add (pp.Address, pp.Position) acc) acc) Set.empty
      |> Set.toArray
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``CFG Vertex Test: _start`` () =
    let brew = BinaryBrew (hdl, strategy)
    let cfg = brew.Functions[0x0UL].CFG
    Assert.AreEqual (9, cfg.Size)
    let vMap = cfg.FoldVertex foldVertexNoFake Map.empty
    Assert.AreEqual (6, vMap.Count)
    let leaders =
      [| ProgramPoint (0x00UL, 0); ProgramPoint (0x19UL, 0);
         ProgramPoint (0x3FUL, 0); ProgramPoint (0x48UL, 0);
         ProgramPoint (0x52UL, 0); ProgramPoint (0x55UL, 0); |]
    let actual =
      leaders |> Array.map (fun l -> (Map.find l vMap).VData.Range)
    let expected =
      [| AddrRange (0x00UL, 0x18UL); AddrRange (0x19UL, 0x3EUL);
         AddrRange (0x3FUL, 0x47UL); AddrRange (0x48UL, 0x51UL);
         AddrRange (0x52UL, 0x54UL); AddrRange (0x55UL, 0x5EUL); |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``CFG Edge Test: _start`` () =
    let brew = BinaryBrew (hdl, strategy)
    let cfg = brew.Functions[0x0UL].CFG
    let vMap = cfg.FoldVertex foldVertexNoFake Map.empty
    let leaders =
      [| ProgramPoint (0x00UL, 0); ProgramPoint (0x19UL, 0);
         ProgramPoint (0x3FUL, 0); ProgramPoint (0x48UL, 0);
         ProgramPoint (0x52UL, 0); ProgramPoint (0x55UL, 0); |]
    let vertices = leaders |> Array.map (fun l -> Map.find l vMap)
    let eMap = cfg.FoldEdge foldEdge Map.empty
    Assert.AreEqual (11, eMap.Count)
    let eMap = cfg.FoldEdge foldEdgeNoFake Map.empty
    Assert.AreEqual (6, eMap.Count)
    [ ProgramPoint (0x00UL, 0), ProgramPoint (0x19UL, 0);
      ProgramPoint (0x19UL, 0), ProgramPoint (0x3FUL, 0);
      ProgramPoint (0x19UL, 0), ProgramPoint (0x48UL, 0);
      ProgramPoint (0x3FUL, 0), ProgramPoint (0x55UL, 0);
      ProgramPoint (0x48UL, 0), ProgramPoint (0x52UL, 0);
      ProgramPoint (0x52UL, 0), ProgramPoint (0x55UL, 0); ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x eMap)
    let actual =
      [| cfg.FindEdge(vertices[0], vertices[1]).Label
         cfg.FindEdge(vertices[1], vertices[2]).Label
         cfg.FindEdge(vertices[1], vertices[3]).Label
         cfg.FindEdge(vertices[2], vertices[5]).Label
         cfg.FindEdge(vertices[3], vertices[4]).Label
         cfg.FindEdge(vertices[4], vertices[5]).Label |]
    let expected =
      [| (* CallFallThroughEdge; *) InterCJmpFalseEdge; InterCJmpTrueEdge;
         InterJmpEdge; (* CallFallThroughEdge; *) FallThroughEdge; |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``CFG Vertex Test: foo`` () =
    let brew = BinaryBrew (hdl, strategy)
    let cfg = brew.Functions[0x62UL].CFG
    Assert.AreEqual (1, cfg.Size)
    let vMap = cfg.FoldVertex foldVertexNoFake Map.empty
    let leaders = [| ProgramPoint (0x62UL, 0) |]
    let actual =
      leaders |> Array.map (fun l -> (Map.find l vMap).VData.Range)
    let expected = [| AddrRange (0x62UL, 0x70UL) |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``CFG Edge Test: foo`` () =
    let brew = BinaryBrew (hdl, strategy)
    let cfg = brew.Functions[0x62UL].CFG
    let eMap = cfg.FoldEdge foldEdge Map.empty
    Assert.AreEqual (0, eMap.Count)

  [<TestMethod>]
  member __.``CFG Vertex Test: bar`` () =
    let brew = BinaryBrew (hdl, strategy)
    let cfg = brew.Functions[0x71UL].CFG
    Assert.AreEqual (1, cfg.Size)
    let vMap = cfg.FoldVertex foldVertexNoFake Map.empty
    let leaders = [| ProgramPoint (0x71UL, 0) |]
    let actual =
      leaders |> Array.map (fun l -> (Map.find l vMap).VData.Range)
    let expected = [| AddrRange (0x71UL, 0x80UL) |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``CFG Edge Test: bar`` () =
    let brew = BinaryBrew (hdl, strategy)
    let cfg = brew.Functions[0x71UL].CFG
    let eMap = cfg.FoldEdge foldEdge Map.empty
    Assert.AreEqual (0, eMap.Count)

  [<TestMethod>]
  member __.``CFG SSAGraph Vertex Test: _start`` () =
    let brew = BinaryBrew (hdl, strategy)
    let cfg = brew.Functions[0x0UL].CFG
    let root = cfg.TryGetSingleRoot () |> Option.get
    let ssaLifter = SSALifter ()
    let ssacfg, _ = ssaLifter.Lift cfg root
    Assert.AreEqual (9, ssacfg.Size)

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
  let hdl = BinHandle (binary, isa, ArchOperationMode.NoMode, None, false)
  let strategy = BaseStrategy<DummyContext, DummyContext> ()
  let brew = BinaryBrew (hdl, strategy)

  [<TestMethod>]
  member __.``InstructionCollection Test 1`` () =
    Assert.AreEqual (15, brew.Instructions.Count)

  [<TestMethod>]
  member __.``InstructionCollection Test 2`` () =
    let addrs =
      [ 0x00UL; 0x01UL; 0x02UL; 0x07UL; 0x0cUL; 0x11UL; 0x14UL; 0x16UL
        0x1cUL; 0x1eUL; 0x21UL; 0x22UL; 0x23UL; 0x24UL; 0x27UL ]
    addrs
    |> List.iter (fun addr ->
      let ins = brew.Instructions.Find addr
      Assert.AreEqual (addr, ins.Address))

  [<TestMethod>]
  member __.``BBLFactory Test 1`` () =
    let bblFactory = BBLFactory (hdl, brew.Instructions)
    let extractBBLInfo ppoint =
      match bblFactory.TryFind ppoint with
      | Ok bbl ->
        bbl.LiftedInstructions
        |> Array.map (fun li -> li.Original.Address, li.BBLAddr)
      | Error e -> [||]
    bblFactory.ScanBBLs ArchOperationMode.NoMode [ 0x0UL ]
    |> Async.AwaitTask
    |> Async.RunSynchronously
    |> ignore
    let bblAddrs = [| 0x00UL; 0x0cUL; 0x24UL |]
    let expected =
      [| (0x00UL, 0x00UL); (0x01UL, 0x00UL); (0x02UL, 0x00UL); (0x07UL, 0x00UL)
         (0x0cUL, 0x0cUL); (0x11UL, 0x0cUL); (0x14UL, 0x0cUL); (0x16UL, 0x0cUL)
         (0x1cUL, 0x0cUL); (0x1eUL, 0x0cUL); (0x21UL, 0x0cUL); (0x22UL, 0x0cUL)
         (0x23UL, 0x0cUL); (0x24UL, 0x24UL); (0x27UL, 0x24UL) |]
    let actual =
      [| for addr in bblAddrs do extractBBLInfo (ProgramPoint (addr, 0)) |]
      |> Array.concat
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``BBLFactory Test 2`` () =
    let bblFactory = BBLFactory (hdl, brew.Instructions)
    let extractBBLInfo ppoint =
      let bbl = bblFactory.Find ppoint
      bbl.Range.Min, bbl.Range.Max
    bblFactory.ScanBBLs ArchOperationMode.NoMode [ 0x0UL ]
    |> Async.AwaitTask
    |> Async.RunSynchronously
    |> ignore
    Assert.AreEqual (3, bblFactory.Count)
    let bblAddrs = [| 0x00UL; 0x0cUL; 0x24UL |]
    let expected = [| (0x00UL, 0x0bUL); (0x0cUL, 0x23UL); (0x24UL, 0x27UL) |]
    let actual =
      [| for addr in bblAddrs do extractBBLInfo (ProgramPoint (addr, 0)) |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``Functions Test 1`` () =
    let expected = [| 0UL; 0x24UL |]
    let actual = brew.Functions.Addresses |> Seq.toArray
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``Functions Test 2`` () =
    (* CallEdges test *)
    let expected =
      Map.empty
      |> Map.add 0x00UL [| (0x07UL, RegularCallee 0x24UL) |]
      |> Map.add 0x24UL [| |]
    let actual =
      brew.Functions.Sequence
      |> Seq.fold (fun acc fn ->
        Map.add fn.EntryPoint fn.Callees acc) Map.empty
    [ 0x00UL; 0x24UL ]
    |> List.iter (fun addr ->
      CollectionAssert.AreEqual (Map.find addr expected, Map.find addr actual))
    (* Callers test *)
    let expected =
      Map.empty
      |> Map.add 0x00UL [| |]
      |> Map.add 0x24UL [| 0x00UL |]
    let actual =
      brew.Functions.Sequence
      |> Seq.fold (fun acc fn ->
        Map.add fn.EntryPoint (Seq.toArray fn.Callers) acc) Map.empty
    [ 0x00UL; 0x24UL ]
    |> List.iter (fun addr ->
      CollectionAssert.AreEqual (Map.find addr expected, Map.find addr actual))

  [<TestMethod>]
  member __.``IRLevelBBLs Test`` () =
    let cnt =
      brew.Functions.Sequence
      |> Seq.fold (fun cnt fn ->
        fn.CFG.FoldVertex (fun cnt _ -> cnt + 1) cnt + cnt) 0
    Assert.AreEqual (7, cnt)
    let expected =
      [ (0x00UL, 0); (0x0cUL, 0); (0x1cUL, 0); (0x1cUL, 2); (0x1cUL, 8);
        (0x1eUL, 0); (0x24UL, 0) ]
      |> List.toArray
    let actual =
      brew.Functions.Sequence
      |> Seq.fold (fun acc fn ->
        fn.CFG.FoldVertex (fun acc v ->
          let pp = v.VData.PPoint
          Set.add (pp.Address, pp.Position) acc) acc) Set.empty
      |> Set.toArray
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``CFG Vertex Test: _start`` () =
    let cfg = brew.Functions[0x0UL].CFG
    Assert.AreEqual (7, cfg.Size)
    let vMap = cfg.FoldVertex foldVertexNoFake Map.empty
    let leaders =
      [| ProgramPoint (0x00UL, 0); ProgramPoint (0x0CUL, 0);
         ProgramPoint (0x1CUL, 0); ProgramPoint (0x1CUL, 2);
         ProgramPoint (0x1CUL, 8); ProgramPoint (0x1EUL, 0) |]
    let actual =
      leaders
      |> Array.map (fun leader ->
        let bbl = Map.find leader vMap
        let lastStmts = bbl.VData.LastLiftedInstruction.Stmts
        match lastStmts[lastStmts.Length - 1].S with
        | IEMark _ -> 0
        | InterJmp _ -> 1
        | InterCJmp _ -> 2
        | Jmp _ -> 3
        | CJmp _ -> 4
        | _ -> -1)
    let expected = [| 1; 0; 4; 1; 1; 1 |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``CFG Edge Test: _start`` () =
    let cfg = brew.Functions[0x0UL].CFG
    let vMap = cfg.FoldVertex foldVertexNoFake Map.empty
    let leaders =
      [| ProgramPoint (0x00UL, 0); ProgramPoint (0x0CUL, 0);
         ProgramPoint (0x1CUL, 0); ProgramPoint (0x1CUL, 2);
         ProgramPoint (0x1CUL, 8); ProgramPoint (0x1EUL, 0) |]
    let vertices = leaders |> Array.map (fun l -> Map.find l vMap)
    let eMap = cfg.FoldEdge foldEdge Map.empty
    Assert.AreEqual (8, eMap.Count)
    let eMap = cfg.FoldEdge foldEdgeNoFake Map.empty
    Assert.AreEqual (6, eMap.Count)
    [ (ProgramPoint (0x00UL, 0), ProgramPoint (0x0CUL, 0));
      (ProgramPoint (0x0CUL, 0), ProgramPoint (0x1CUL, 0));
      (ProgramPoint (0x1CUL, 0), ProgramPoint (0x1CUL, 2));
      (ProgramPoint (0x1CUL, 0), ProgramPoint (0x1CUL, 8));
      (ProgramPoint (0x1CUL, 2), ProgramPoint (0x1CUL, 0));
      (ProgramPoint (0x1CUL, 8), ProgramPoint (0x1EUL, 0)); ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x eMap)
    let actual =
      [| cfg.FindEdge(vertices[0], vertices[1]).Label
         cfg.FindEdge(vertices[1], vertices[2]).Label
         cfg.FindEdge(vertices[2], vertices[3]).Label
         cfg.FindEdge(vertices[2], vertices[4]).Label
         cfg.FindEdge(vertices[3], vertices[2]).Label
         cfg.FindEdge(vertices[4], vertices[5]).Label |]
    let expected =
      [| (* CallFallThroughEdge; *) FallThroughEdge; IntraCJmpFalseEdge;
         IntraCJmpTrueEdge; InterJmpEdge; InterJmpEdge |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``DisasmCFG Test: _start`` () =
    let cfg = brew.Functions[0x0UL].CFG
    let cfg = DisasmCFG.create cfg
    Assert.AreEqual (1, cfg.Size)
    let vMap = cfg.FoldVertex (fun m v ->
      Map.add v.VData.PPoint.Address v m) Map.empty
    let leaders = [| 0x00UL |]
    let vertices = leaders |> Array.map (fun l -> Map.find l vMap)
    let disasmLens = [| 13 |]
    Array.zip vertices disasmLens
    |> Array.iter (fun (v, len) ->
      Assert.AreEqual (len, v.VData.Disassemblies.Length))
    let eMap = cfg.FoldEdge (fun m e ->
      let v1, v2 = e.First, e.Second
      let key = v1.VData.PPoint.Address, v2.VData.PPoint.Address
      Map.add key e m) Map.empty
    Assert.AreEqual (0, eMap.Count)

  [<TestMethod>]
  member __.``SSAGraph Vertex Test: _start`` () =
    let cfg = brew.Functions[0x0UL].CFG
    let root = cfg.TryGetSingleRoot () |> Option.get
    let ssaLifter = SSALifter ()
    let ssacfg, _ = ssaLifter.Lift cfg root
    Assert.AreEqual (7, ssacfg.Size)

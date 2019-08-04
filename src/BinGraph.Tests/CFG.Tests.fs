namespace B2R2.BinGraph.Tests

open B2R2
open B2R2.FrontEnd
open B2R2.BinGraph
open B2R2.BinIR.LowUIR
open Microsoft.VisualStudio.TestTools.UnitTesting

module Utils =
  type IRNode = Vertex<IRBasicBlock>

  let foldVertexNoDummy m (v: IRNode) =
    if v.VData.IsDummyBlock () then m
    else Map.add v.VData.PPoint v m

  let foldEdge m (v1: IRNode) (v2: IRNode) e =
    Map.add (v1.VData.PPoint, v2.VData.PPoint) e m

  let foldEdgeNoDummy m (v1: IRNode) (v2: IRNode) e =
    if v1.VData.IsDummyBlock () || v2.VData.IsDummyBlock () then m
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
  let hdl = BinHandler.Init (isa, binary)
  let ess = BinEssence.Init hdl

  [<TestMethod>]
  member __.``Boundary Test: Function Identification`` () =
    let funcs = BinaryApparatus.getFunctionAddrs ess.BinaryApparatus
    Assert.AreEqual (3, Seq.length funcs)
    let expected = [ 0UL; 0x62UL; 0x71UL ] |> List.toArray
    let actual = Seq.toArray funcs
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``Boundary Test: Leader Identification`` () =
    let vertices = ess.SCFG.Vertices
    let boundaries = ess.SCFG.Boundaries
    Assert.AreEqual (10, vertices.Count)
    [ (0x00UL, 0x19UL); (0x19UL, 0x3FUL); (0x3FUL, 0x48UL); (0x48UL, 0x52UL);
      (0x52UL, 0x55UL); (0x55UL, 0x5FUL); (0x5FUL, 0x62UL); (0x62UL, 0x71UL);
      (0x71UL, 0x81UL); (0x81UL, 0x84UL); ]
    |> List.iter (fun r ->
         Assert.IsTrue <| IntervalSet.contains (AddrRange r) boundaries)

  [<TestMethod>]
  member __.``Vertex Test: _start`` () =
    let cfg, _ = ess.SCFG.GetFunctionCFG 0x00UL
    Assert.AreEqual (9, cfg.Size ())
    let vMap = cfg.FoldVertex Utils.foldVertexNoDummy Map.empty
    Assert.AreEqual (7, vMap.Count)
    let leaders =
      [| ProgramPoint (0x00UL, 0); ProgramPoint (0x19UL, 0);
         ProgramPoint (0x3FUL, 0); ProgramPoint (0x48UL, 0);
         ProgramPoint (0x52UL, 0); ProgramPoint (0x55UL, 0);
         ProgramPoint (0x5FUL, 0) |]
    let actual = leaders |> Array.map (fun l -> (Map.find l vMap).VData.Range)
    let expected =
      [| AddrRange (0x00UL, 0x19UL); AddrRange (0x19UL, 0x3FUL);
         AddrRange (0x3FUL, 0x48UL); AddrRange (0x48UL, 0x52UL);
         AddrRange (0x52UL, 0x55UL); AddrRange (0x55UL, 0x5FUL);
         AddrRange (0x5FUL, 0x62UL) |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``Edge Test: _start`` () =
    let cfg, _ = ess.SCFG.GetFunctionCFG 0x00UL
    let vMap = cfg.FoldVertex Utils.foldVertexNoDummy Map.empty
    let leaders =
      [| ProgramPoint (0x00UL, 0); ProgramPoint (0x19UL, 0);
         ProgramPoint (0x3FUL, 0); ProgramPoint (0x48UL, 0);
         ProgramPoint (0x52UL, 0); ProgramPoint (0x55UL, 0);
         ProgramPoint (0x5FUL, 0) |]
    let vertices = leaders |> Array.map (fun l -> Map.find l vMap)
    let eMap = cfg.FoldEdge Utils.foldEdge Map.empty
    Assert.AreEqual (13, eMap.Count)
    let eMap = cfg.FoldEdge Utils.foldEdgeNoDummy Map.empty
    Assert.AreEqual (7, eMap.Count)
    [ ProgramPoint (0x00UL, 0), ProgramPoint (0x19UL, 0);
      ProgramPoint (0x19UL, 0), ProgramPoint (0x3FUL, 0);
      ProgramPoint (0x19UL, 0), ProgramPoint (0x48UL, 0);
      ProgramPoint (0x3FUL, 0), ProgramPoint (0x55UL, 0);
      ProgramPoint (0x48UL, 0), ProgramPoint (0x52UL, 0);
      ProgramPoint (0x52UL, 0), ProgramPoint (0x55UL, 0);
      ProgramPoint (0x55UL, 0), ProgramPoint (0x5FUL, 0); ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x eMap)
    let actual =
      [| cfg.FindEdgeData vertices.[0] vertices.[1]
         cfg.FindEdgeData vertices.[1] vertices.[2]
         cfg.FindEdgeData vertices.[1] vertices.[3]
         cfg.FindEdgeData vertices.[2] vertices.[5]
         cfg.FindEdgeData vertices.[3] vertices.[4]
         cfg.FindEdgeData vertices.[4] vertices.[5]
         cfg.FindEdgeData vertices.[5] vertices.[6] |]
    let expected =
      [| FallThroughEdge; InterCJmpFalseEdge; InterCJmpTrueEdge; InterJmpEdge;
         FallThroughEdge; FallThroughEdge; FallThroughEdge |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``Vertex Test: foo`` () =
    let cfg, _ = ess.SCFG.GetFunctionCFG 0x62UL
    Assert.AreEqual (1, cfg.Size ())
    let vMap = cfg.FoldVertex Utils.foldVertexNoDummy Map.empty
    let leaders = [| ProgramPoint (0x62UL, 0) |]
    let actual = leaders |> Array.map (fun l -> (Map.find l vMap).VData.Range)
    let expected = [| AddrRange (0x62UL, 0x71UL) |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``Edge Test: foo`` () =
    let cfg, _ = ess.SCFG.GetFunctionCFG 0x62UL
    let eMap = cfg.FoldEdge Utils.foldEdge Map.empty
    Assert.AreEqual (0, eMap.Count)

  [<TestMethod>]
  member __.``Vertex Test: bar`` () =
    let cfg, _ = ess.SCFG.GetFunctionCFG 0x71UL
    Assert.AreEqual (2, cfg.Size ())
    let vMap = cfg.FoldVertex Utils.foldVertexNoDummy Map.empty
    let leaders = [| ProgramPoint (0x71UL, 0); ProgramPoint (0x81UL, 0) |]
    let actual = leaders |> Array.map (fun l -> (Map.find l vMap).VData.Range)
    let expected = [| AddrRange (0x71UL, 0x81UL); AddrRange (0x81UL, 0x84UL) |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``Edge Test: bar`` () =
    let cfg, _ = ess.SCFG.GetFunctionCFG 0x71UL
    let vMap = cfg.FoldVertex Utils.foldVertexNoDummy Map.empty
    let leaders = [| ProgramPoint (0x71UL, 0); ProgramPoint (0x81UL, 0) |]
    let vertices = leaders |> Array.map (fun l -> Map.find l vMap)
    let eMap = cfg.FoldEdge Utils.foldEdge Map.empty
    Assert.AreEqual (1, eMap.Count)
    [ ProgramPoint (0x71UL, 0), ProgramPoint (0x81UL, 0) ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x eMap)
    let actual = [| cfg.FindEdgeData vertices.[0] vertices.[1] |]
    let expected = [| FallThroughEdge |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``SSAGraph Vertex Test: _start`` () =
    let cfg, root = ess.SCFG.GetFunctionCFG 0x0UL
    let lens = SSALens.Init (ess.SCFG)
    let ssacfg, _ = lens.Filter cfg root ess.BinaryApparatus
    Assert.AreEqual (9, ssacfg.Size ())

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
  let binary =
     [| 0x57uy; 0x56uy; 0xb9uy; 0x20uy; 0x00uy; 0x00uy; 0x00uy; 0xe8uy; 0x18uy;
        0x00uy; 0x00uy; 0x00uy; 0x05uy; 0x34uy; 0x1euy; 0x00uy; 0x00uy; 0x83uy;
        0xecuy; 0x20uy; 0x89uy; 0xe7uy; 0x8duy; 0xb0uy; 0xe8uy; 0xe1uy; 0xffuy;
        0xffuy; 0xf3uy; 0xa4uy; 0x83uy; 0xc4uy; 0x20uy; 0x5euy; 0x5fuy; 0xc3uy;
        0x8buy; 0x04uy; 0x24uy; 0xc3uy; |]

  let isa = ISA.Init Architecture.IntelX86 Endian.Little
  let hdl = BinHandler.Init (isa, binary)
  let ess = BinEssence.Init hdl

  [<TestMethod>]
  member __.``Boundary Test: Function Identification`` () =
    let funcs = BinaryApparatus.getFunctionAddrs ess.BinaryApparatus
    Assert.AreEqual (2, Seq.length funcs)
    let expected = [ 0UL; 0x24UL ] |> List.toArray
    let actual = Seq.toArray funcs
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``Boundary Test: Leader Identification`` () =
    let vertices = ess.SCFG.Vertices
    let boundaries = ess.SCFG.Boundaries
    Assert.AreEqual (7, vertices.Count)
    [ (0x00UL, 0x0CUL); (0x0CUL, 0x1CUL); (0x1CUL, 0x1EUL); (0x1CUL, 0x1EUL);
      (0x1CUL, 0x1EUL); (0x1EUL, 0x24UL); (0x24UL, 0x28UL); ]
    |> List.iter (fun r ->
         Assert.IsTrue <| IntervalSet.contains (AddrRange r) boundaries)

  [<TestMethod>]
  member __.``Vertex Test: _start`` () =
    let cfg, _ = ess.SCFG.GetFunctionCFG 0x00UL
    Assert.AreEqual (7, cfg.Size ())
    let vMap = cfg.FoldVertex Utils.foldVertexNoDummy Map.empty
    let leaders =
      [| ProgramPoint (0x00UL, 0); ProgramPoint (0x0CUL, 0);
         ProgramPoint (0x1CUL, 0); ProgramPoint (0x1CUL, 2);
         ProgramPoint (0x1CUL, 8); ProgramPoint (0x1EUL, 0) |]
    let actual =
      leaders
      |> Array.map (fun l ->
        match (Map.find l vMap).VData.GetLastStmt () with
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
  member __.``Edge Test: _start`` () =
    let cfg, _ = ess.SCFG.GetFunctionCFG 0x00UL
    let vMap = cfg.FoldVertex Utils.foldVertexNoDummy Map.empty
    let leaders =
      [| ProgramPoint (0x00UL, 0); ProgramPoint (0x0CUL, 0);
         ProgramPoint (0x1CUL, 0); ProgramPoint (0x1CUL, 2);
         ProgramPoint (0x1CUL, 8); ProgramPoint (0x1EUL, 0) |]
    let vertices = leaders |> Array.map (fun l -> Map.find l vMap)
    let eMap = cfg.FoldEdge Utils.foldEdge Map.empty
    Assert.AreEqual (8, eMap.Count)
    let eMap = cfg.FoldEdge Utils.foldEdgeNoDummy Map.empty
    Assert.AreEqual (6, eMap.Count)
    [ (ProgramPoint (0x00UL, 0), ProgramPoint (0x0CUL, 0));
      (ProgramPoint (0x0CUL, 0), ProgramPoint (0x1CUL, 0));
      (ProgramPoint (0x1CUL, 0), ProgramPoint (0x1CUL, 2));
      (ProgramPoint (0x1CUL, 0), ProgramPoint (0x1CUL, 8));
      (ProgramPoint (0x1CUL, 2), ProgramPoint (0x1CUL, 0));
      (ProgramPoint (0x1CUL, 8), ProgramPoint (0x1EUL, 0)); ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x eMap)
    let actual =
      [| cfg.FindEdgeData vertices.[0] vertices.[1]
         cfg.FindEdgeData vertices.[1] vertices.[2]
         cfg.FindEdgeData vertices.[2] vertices.[3]
         cfg.FindEdgeData vertices.[2] vertices.[4]
         cfg.FindEdgeData vertices.[3] vertices.[2]
         cfg.FindEdgeData vertices.[4] vertices.[5] |]
    let expected =
      [| FallThroughEdge; FallThroughEdge; IntraCJmpFalseEdge;
         IntraCJmpTrueEdge; InterJmpEdge; InterJmpEdge |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``DisasmLens Test: _start`` () =
    let cfg, root = ess.SCFG.GetFunctionCFG 0x00UL
    let lens = DisasmLens.Init ()
    let cfg, _ = lens.Filter cfg root ess.BinaryApparatus
    Assert.AreEqual (4, cfg.Size ())
    let vMap = cfg.FoldVertex (fun m v ->
      Map.add v.VData.PPoint.Address v m) Map.empty
    let leaders = [| 0x00UL; 0x0CUL; 0x1CUL; 0x1EUL |]
    let vertices = leaders |> Array.map (fun l -> Map.find l vMap)
    let disasmLens = [| 4; 4; 1; 4 |]
    Array.zip vertices disasmLens
    |> Array.iter (fun (v, len) ->
      Assert.AreEqual (len, v.VData.Disassemblies(None).Length))
    let eMap = cfg.FoldEdge (fun m v1 v2 e ->
      let key = v1.VData.PPoint.Address, v2.VData.PPoint.Address
      Map.add key e m) Map.empty
    Assert.AreEqual (4, eMap.Count)
    let actual =
      [| cfg.FindEdgeData vertices.[0] vertices.[1]
         cfg.FindEdgeData vertices.[1] vertices.[2]
         cfg.FindEdgeData vertices.[2] vertices.[2]
         cfg.FindEdgeData vertices.[2] vertices.[3] |]
    let expected =
      [| FallThroughEdge; FallThroughEdge; InterJmpEdge; InterJmpEdge |]
    CollectionAssert.AreEqual (expected, actual)

  [<TestMethod>]
  member __.``SSAGraph Vertex Test: _start`` () =
    let cfg, root = ess.SCFG.GetFunctionCFG 0x0UL
    let lens = SSALens.Init (ess.SCFG)
    let ssacfg, _ = lens.Filter cfg root ess.BinaryApparatus
    Assert.AreEqual (7, ssacfg.Size ())

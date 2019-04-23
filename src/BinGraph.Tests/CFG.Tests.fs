namespace B2R2.BinGraph.Tests

open B2R2
open B2R2.FrontEnd
open B2R2.BinGraph
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type CFGTestClass () =

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
  let builder, funcs = CFGUtils.construct hdl (Some [ 0UL ])

  let disasmVertexFolder acc (v: DisasmVertex) =
    Map.add v.VData.AddrRange.Min v acc

  let disasmEdgeFolder
      (cfg: DisasmCFG) acc (src: DisasmVertex) (dst: DisasmVertex) =
    let sAddr = src.VData.AddrRange.Min
    let dAddr = dst.VData.AddrRange.Min
    let e = cfg.FindEdge src dst
    Map.add (sAddr, dAddr) e acc

  let irVertexFolder acc (v: IRVertex) =
    Map.add v.VData.Ppoint v acc

  let irEdgeFolder (cfg: IRCFG) acc (src: IRVertex) (dst: IRVertex) =
    let sPpoint = src.VData.Ppoint
    let dPpoint = dst.VData.Ppoint
    let e = cfg.FindEdge src dst
    Map.add (sPpoint, dPpoint) e acc

  let ssaEdgeFolder (cfg: SSACFG) acc (src: SSAVertex) (dst: SSAVertex) =
    let e = cfg.FindEdge src dst
    e :: acc

  [<TestMethod>]
  member __.``Boundary Test: Function Identification`` () =
    let addrs =
      Seq.fold (fun acc (KeyValue(addr, _)) -> Set.add addr acc) Set.empty funcs 
    Assert.AreEqual (3, Set.count addrs)
    [ 0UL ; 0x62UL ; 0x71UL ]
    |> List.iter (fun x -> Assert.IsTrue <| Set.contains x addrs) 

  [<TestMethod>]
  member __.``Boundary Test: Disassembly Leader Identification`` () =
    let disasmLeaders = builder.GetDisasmBoundaries ()
    Assert.AreEqual (8, List.length disasmLeaders)
    (*
    [ (0x00UL, 0x19UL) ; (0x19UL, 0x3FUL) ; (0x3FUL, 0x48UL) ;
      (0x48UL, 0x52UL) ; (0x52UL, 0x55UL) ; (0x55UL, 0x5fUL) ;
      (0x5FUL, 0x62UL) ; (0x62UL, 0x71UL) ; (0x71UL, 0x81UL) ;
      (0x81UL, 0x84UL) ]
    |> List.iter (fun x -> Assert.IsTrue <| List.contains x disasmLeaders) 
    *)

  [<TestMethod>]
  member __.``Boundary Test: IR Leader Identification`` () =
    let irLeaders = builder.GetIRBoundaries ()
    Assert.AreEqual (12, List.length irLeaders)
    (*
    [ (0x0UL, 0) ; (0x3DUL, 2) ; (0x3FUL, 0) ; (0x46UL, 2) ; (0x48UL, 0) ;
      (0x55UL, 0) ; (0x61UL, 4) ; (0x62UL, 0) ; (0x70UL, 4) ; (0x71UL, 0) ;
      (0x81UL, 0) ; (0x83UL, 4) ]
    |> List.iter (fun x -> Assert.IsTrue <| List.contains x irLeaders)
    *)

  [<TestMethod>]
  member __.``DisasmGraph Vertex Test: _start`` () =
    let cfg = funcs.[0UL].DisasmCFG
    Assert.AreEqual (4, cfg.Size ())
    let vMap = cfg.FoldVertex disasmVertexFolder Map.empty
    [ 0x0UL ; 0x3FUL ; 0x48UL ; 0x55UL ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x vMap)
    let v00 = Map.find 0x0UL vMap
    let v3F = Map.find 0x3FUL vMap
    let v48 = Map.find 0x48UL vMap
    let v55 = Map.find 0x55UL vMap
    let vList = [ v00 ; v3F ; v48 ; v55 ]
    let bblList = List.map (fun (x: Vertex<_>) -> x.VData) vList
    let addrRangeList =
      [ AddrRange (0x0UL, 0x3FUL) ; AddrRange (0x3FUL, 0x48UL) ;
        AddrRange (0x48UL, 0x55UL) ; AddrRange (0x55UL, 0x62UL) ]
    List.zip addrRangeList bblList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y.AddrRange))

  [<TestMethod>]
  member __.``DisasmGraph Edge Test: _start`` () =
    let cfg = funcs.[0UL].DisasmCFG
    let vMap = cfg.FoldVertex disasmVertexFolder Map.empty
    let v00 = Map.find 0x0UL vMap
    let v3F = Map.find 0x3FUL vMap
    let v48 = Map.find 0x48UL vMap
    let v55 = Map.find 0x55UL vMap
    let eMap = cfg.FoldEdge (disasmEdgeFolder cfg) Map.empty
    Assert.AreEqual (4, eMap.Count)
    [ (0x0UL, 0x3FUL) ; (0x0UL, 0x48UL) ; (0x3FUL, 0x55UL) ; (0x48UL, 0x55UL) ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x eMap)
    let edge003F = cfg.FindEdge v00 v3F
    let edge0048 = cfg.FindEdge v00 v48
    let edge3F55 = cfg.FindEdge v3F v55
    let edge4855 = cfg.FindEdge v48 v55
    let eList = [ edge003F ; edge0048 ; edge3F55 ; edge4855 ]
    let edgeTypeList = [ CJmpFalseEdge ; CJmpTrueEdge ; JmpEdge ; JmpEdge ]
    List.zip edgeTypeList eList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y))

  [<TestMethod>]
  member __.``DisasmGraph Vertex Test: foo`` () =
    let cfg = funcs.[0x62UL].DisasmCFG
    Assert.AreEqual (1, cfg.Size ())
    let vMap = cfg.FoldVertex disasmVertexFolder Map.empty
    [ 0x62UL ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x vMap)
    let v62 = Map.find 0x62UL vMap
    let vList = [ v62 ]
    let bblList = List.map (fun (x: Vertex<_>) -> x.VData) vList
    let addrRangeList = [ AddrRange (0x62UL, 0x71UL) ]
    List.zip addrRangeList bblList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y.AddrRange))

  [<TestMethod>]
  member __.``DisasmGraph Edge Test: foo`` () =
    let cfg = funcs.[0x62UL].DisasmCFG
    let eMap = cfg.FoldEdge (disasmEdgeFolder cfg) Map.empty
    Assert.AreEqual (0, eMap.Count)

  [<TestMethod>]
  member __.``DisasmGraph Vertex Test: bar`` () =
    let cfg = funcs.[0x71UL].DisasmCFG
    Assert.AreEqual (1, cfg.Size ())
    let vMap = cfg.FoldVertex disasmVertexFolder Map.empty
    [ 0x71UL ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x vMap)
    let v71 = Map.find 0x71UL vMap
    let vList = [ v71 ]
    let bblList = List.map (fun (x: Vertex<_>) -> x.VData) vList
    let addrRangeList = [ AddrRange (0x71UL, 0x81UL) ]
    List.zip addrRangeList bblList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y.AddrRange))

  [<TestMethod>]
  member __.``DisasmGraph Edge Test: bar`` () =
    let cfg = funcs.[0x71UL].DisasmCFG
    let eMap = cfg.FoldEdge (disasmEdgeFolder cfg) Map.empty
    Assert.AreEqual (0, eMap.Count)
    /// XXX: What about a bbl starting from 0x81? ( nop ; pop rbp ; ret )

  [<TestMethod>]
  member __.``IRGraph Vertex Test: _start`` () =
    let cfg = funcs.[0UL].IRCFG
    Assert.AreEqual (4, cfg.Size ())
    let vMap = cfg.FoldVertex irVertexFolder Map.empty
    [ (0x0UL, 0) ; (0x3FUL, 0) ; (0x48UL, 0) ; (0x55UL, 0) ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x vMap)
    let v000 = Map.find (0x0UL, 0) vMap
    let v3F0 = Map.find (0x3FUL, 0) vMap
    let v480 = Map.find (0x48UL, 0) vMap
    let v550 = Map.find (0x55UL, 0) vMap
    let vList = [ v000 ; v3F0 ; v480 ; v550 ]
    let bblList = List.map (fun (x: Vertex<_>) -> x.VData) vList
    let pPointList = [ (0x0UL, 0) ; (0x3FUL, 0) ; (0x48UL, 0) ; (0x55UL, 0) ]
    List.zip pPointList bblList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y.Ppoint))

  [<TestMethod>]
  member __.``IRGraph Edge Test: _start`` () =
    let cfg = funcs.[0UL].IRCFG
    let vMap = cfg.FoldVertex irVertexFolder Map.empty
    let v000 = Map.find (0x0UL, 0) vMap
    let v3F0 = Map.find (0x3FUL, 0) vMap
    let v480 = Map.find (0x48UL, 0) vMap
    let v550 = Map.find (0x55UL, 0) vMap
    let eMap = cfg.FoldEdge (irEdgeFolder cfg) Map.empty
    Assert.AreEqual (4, eMap.Count)
    [ ((0x0UL, 0), (0x3FUL, 0)) ; ((0x0UL, 0), (0x48UL, 0)) ;
      ((0x3FUL, 0), (0x55UL, 0)) ; ((0x48UL, 0), (0x55UL, 0)) ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x eMap)
    let edge0003F0 = cfg.FindEdge v000 v3F0
    let edge000480 = cfg.FindEdge v000 v480
    let edge3F0550 = cfg.FindEdge v3F0 v550
    let edge480550 = cfg.FindEdge v480 v550
    let eList = [ edge0003F0 ; edge000480 ; edge3F0550 ; edge480550 ]
    let edgeTypeList = [ CJmpFalseEdge ; CJmpTrueEdge ; JmpEdge ; JmpEdge ]
    List.zip edgeTypeList eList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y))

  [<TestMethod>]
  member __.``IRGraph Vertex Test: foo`` () =
    let cfg = funcs.[0x62UL].IRCFG
    Assert.AreEqual (1, cfg.Size ())
    let vMap = cfg.FoldVertex irVertexFolder Map.empty
    [ (0x62UL, 0) ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x vMap)
    let v620 = Map.find (0x62UL, 0) vMap
    let vList = [ v620 ]
    let bblList = List.map (fun (x: Vertex<_>) -> x.VData) vList
    let pPointList = [ (0x62UL, 0) ]
    List.zip pPointList bblList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y.Ppoint))

  [<TestMethod>]
  member __.``IRGraph Edge Test: foo`` () =
    let cfg = funcs.[0x62UL].IRCFG
    let eMap = cfg.FoldEdge (irEdgeFolder cfg) Map.empty
    Assert.AreEqual (0, eMap.Count)

  [<TestMethod>]
  member __.``IRGraph Vertex Test: bar`` () =
    let cfg = funcs.[0x71UL].IRCFG
    Assert.AreEqual (2, cfg.Size ())
    let vMap = cfg.FoldVertex irVertexFolder Map.empty
    [ (0x71UL, 0) ; (0x81UL, 0) ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x vMap)
    let v710 = Map.find (0x71UL, 0) vMap
    let v810 = Map.find (0x81UL, 0) vMap
    let vList = [ v710 ; v810 ]
    let bblList = List.map (fun (x: Vertex<_>) -> x.VData) vList
    let pPointList = [ (0x71UL, 0) ; (0x81UL, 0) ]
    List.zip pPointList bblList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y.Ppoint))

  [<TestMethod>]
  member __.``IRGraph Edge Test: bar`` () =
    let cfg = funcs.[0x71UL].IRCFG
    let vMap = cfg.FoldVertex irVertexFolder Map.empty
    let v710 = Map.find (0x71UL, 0) vMap
    let v810 = Map.find (0x81UL, 0) vMap
    let eMap = cfg.FoldEdge (irEdgeFolder cfg) Map.empty
    Assert.AreEqual (1, eMap.Count)
    let edge710810 = cfg.FindEdge v710 v810
    let eList = [ edge710810 ]
    let edgeTypeList = [ JmpEdge ]
    List.zip edgeTypeList eList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y))

  [<TestMethod>]
  member __.``SSAGraph Vertex Test: _start`` () =
    let cfg = funcs.[0UL].SSACFG
    Assert.AreEqual (4, cfg.Size ())

  [<TestMethod>]
  member __.``SSAGraph Edge Test: _start`` () =
    let cfg = funcs.[0UL].SSACFG
    let eList = cfg.FoldEdge (ssaEdgeFolder cfg) [] |> List.rev
    Assert.AreEqual (4, List.length eList)
    let edgeTypeList = [ CJmpFalseEdge ; CJmpTrueEdge ; JmpEdge ; JmpEdge ]
    List.zip edgeTypeList eList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y))

  [<TestMethod>]
  member __.``SSAGraph Vertex Test: foo`` () =
    let cfg = funcs.[0x62UL].SSACFG
    Assert.AreEqual (1, cfg.Size ())

  [<TestMethod>]
  member __.``SSAGraph Edge Test: foo`` () =
    let cfg = funcs.[0x62UL].SSACFG
    let eList = cfg.FoldEdge (ssaEdgeFolder cfg) []
    Assert.AreEqual (0, List.length eList)

  [<TestMethod>]
  member __.``SSAGraph Vertex Test: bar`` () =
    let cfg = funcs.[0x71UL].SSACFG
    Assert.AreEqual (2, cfg.Size ())

  [<TestMethod>]
  member __.``SSAGraph Edge Test: bar`` () =
    let cfg = funcs.[0x71UL].SSACFG
    let eList = cfg.FoldEdge (ssaEdgeFolder cfg) [] |> List.rev
    Assert.AreEqual (1, List.length eList)
    let edgeTypeList = [ JmpEdge ]
    List.zip edgeTypeList eList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y))

  /// TODO: SSA translation functionality test

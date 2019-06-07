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
  let _, funcs_ = CFGUtils.construct hdl (Some [ 0UL ])
  let funcs_ = CFGUtils.analCalls funcs_
  let callGraph = SimpleDiGraph ()
  let _ = CFGUtils.buildCallGraph hdl funcs_ callGraph
  let _ = NoReturn.noReturnAnalysis hdl callGraph

  let disasmVertexFolder acc (v: DisasmVertex) =
    Map.add v.VData.AddrRange.Min v acc

  let disasmEdgeFolder
      (cfg: DisasmCFG) acc (src: DisasmVertex) (dst: DisasmVertex) =
    let sAddr = src.VData.AddrRange.Min
    let dAddr = dst.VData.AddrRange.Min
    let e = cfg.FindEdge src dst
    Map.add (sAddr, dAddr) e acc

  let irVertexFolder acc (v: IRVertex) =
    let _, ppoint = v.VData.GetPpoint ()
    Map.add ppoint v acc

  let irBBLFolder acc (v: IRVertex) =
    let b, ppoint = v.VData.GetPpoint ()
    if b then Map.add ppoint v acc else acc

  let irCallFolder acc (v: IRVertex) =
    let b, target = v.VData.GetTarget ()
    if b then Map.add target v acc else acc

  let irEdgeFolder (cfg: IRCFG) acc (src: IRVertex) (dst: IRVertex) =
    let _, sPpoint = src.VData.GetPpoint ()
    let _, dPpoint = dst.VData.GetPpoint ()
    let e = cfg.FindEdge src dst
    Map.add (sPpoint, dPpoint) e acc

  let irNormalEdgeFolder (cfg: IRCFG) acc (src: IRVertex) (dst: IRVertex) =
    let sb, sPpoint = src.VData.GetPpoint ()
    let db, dPpoint = dst.VData.GetPpoint ()
    if sb && db then
      let e = cfg.FindEdge src dst
      Map.add (sPpoint, dPpoint) e acc
    else acc

  let irCallEdgeFolder (cfg: IRCFG) acc (src: IRVertex) (dst: IRVertex) =
    let sb, ppoint = src.VData.GetPpoint ()
    let db, target = dst.VData.GetTarget ()
    if sb && db then
      let e = cfg.FindEdge src dst
      Map.add (ppoint, target) e acc
    else acc

  let irRetEdgeFolder (cfg: IRCFG) acc (src: IRVertex) (dst: IRVertex) =
    let sb, target = src.VData.GetTarget ()
    let db, ppoint = dst.VData.GetPpoint ()
    if sb && db then
      let e = cfg.FindEdge src dst
      Map.add (target, ppoint) e acc
    else acc

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
    let disasmBoundaries = builder.GetDisasmBoundaries ()
    Assert.AreEqual (10, List.length disasmBoundaries)
    [ (0x00UL, 0x19UL) ; (0x19UL, 0x3FUL) ; (0x3FUL, 0x48UL) ;
      (0x48UL, 0x52UL) ; (0x52UL, 0x55UL) ; (0x55UL, 0x5FUL) ;
      (0x5FUL, 0x62UL) ; (0x62UL, 0x71UL) ; (0x71UL, 0x81UL) ;
      (0x81UL, 0x84UL) ]
    |> List.iter (fun x -> Assert.IsTrue <| List.contains x disasmBoundaries)

  [<TestMethod>]
  member __.``Boundary Test: IR Leader Identification`` () =
    let irBoundaries = builder.GetIRBoundaries ()
    Assert.AreEqual (10, List.length irBoundaries)
    [ ((0x00UL, 0), (0x14UL, 3)) ; ((0x19UL, 0), (0x3DUL, 1)) ;
      ((0x3FUL, 0), (0x46UL, 1)) ; ((0x48UL, 0), (0x4DUL, 3)) ;
      ((0x52UL, 0), (0x52UL, 13)) ; ((0x55UL, 0), (0x5AUL, 3)) ;
      ((0x5FUL, 0), (0x61UL, 3)) ; ((0x62UL, 0), (0x70UL, 3)) ;
      ((0x71UL, 0), (0x7FUL, 1)) ; ((0x81UL, 0), (0x83UL, 3)) ]
    |> List.iter (fun x -> Assert.IsTrue <| List.contains x irBoundaries)

  [<TestMethod>]
  member __.``DisasmGraph Vertex Test: _start`` () =
    let cfg = funcs.[0x00UL].DisasmCFG
    Assert.AreEqual (7, cfg.Size ())
    let vMap = cfg.FoldVertex disasmVertexFolder Map.empty
    [ 0x00UL ; 0x19UL ; 0x3FUL ; 0x48UL ; 0x52UL ; 0x55UL ; 0x5FUL ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x vMap)
    let v00 = Map.find 0x00UL vMap
    let v19 = Map.find 0x19UL vMap
    let v3F = Map.find 0x3FUL vMap
    let v48 = Map.find 0x48UL vMap
    let v52 = Map.find 0x52UL vMap
    let v55 = Map.find 0x55UL vMap
    let v5F = Map.find 0x5FUL vMap
    let vList = [ v00 ; v19 ; v3F ; v48 ; v52 ; v55 ; v5F ]
    let bblList = List.map (fun (x: Vertex<_>) -> x.VData) vList
    let addrRangeList =
      [ AddrRange (0x00UL, 0x19UL) ; AddrRange (0x19UL, 0x3FUL) ;
        AddrRange (0x3FUL, 0x48UL) ; AddrRange (0x48UL, 0x52UL) ;
        AddrRange (0x52UL, 0x55UL) ; AddrRange (0x55UL, 0x5FUL) ;
        AddrRange (0x5FUL, 0x62UL) ]
    List.zip addrRangeList bblList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y.AddrRange))

  [<TestMethod>]
  member __.``DisasmGraph Edge Test: _start`` () =
    let cfg = funcs.[0x00UL].DisasmCFG
    let vMap = cfg.FoldVertex disasmVertexFolder Map.empty
    let v00 = Map.find 0x00UL vMap
    let v19 = Map.find 0x19UL vMap
    let v3F = Map.find 0x3FUL vMap
    let v48 = Map.find 0x48UL vMap
    let v52 = Map.find 0x52UL vMap
    let v55 = Map.find 0x55UL vMap
    let v5F = Map.find 0x5FUL vMap
    let eMap = cfg.FoldEdge (disasmEdgeFolder cfg) Map.empty
    Assert.AreEqual (7, eMap.Count)
    [ (0x00UL, 0x19UL) ; (0x19UL, 0x3FUL) ; (0x19UL, 0x48UL) ;
      (0x3FUL, 0x55UL) ; (0x48UL, 0x52UL) ; (0x52UL, 0x55UL) ;
      (0x55UL, 0x5FUL) ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x eMap)
    let edge0019 = cfg.FindEdge v00 v19
    let edge193F = cfg.FindEdge v19 v3F
    let edge1948 = cfg.FindEdge v19 v48
    let edge3F55 = cfg.FindEdge v3F v55
    let edge4852 = cfg.FindEdge v48 v52
    let edge5255 = cfg.FindEdge v52 v55
    let edge555F = cfg.FindEdge v55 v5F
    let eList =
      [ edge0019 ; edge193F ; edge1948 ; edge3F55 ; edge4852 ; edge5255 ;
        edge555F ]
    let edgeTypeList =
      [ JmpEdge ; CJmpFalseEdge ; CJmpTrueEdge ; JmpEdge ; JmpEdge ; JmpEdge ;
        JmpEdge ]
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
    Assert.AreEqual (2, cfg.Size ())
    let vMap = cfg.FoldVertex disasmVertexFolder Map.empty
    [ 0x71UL ; 0x81UL ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x vMap)
    let v71 = Map.find 0x71UL vMap
    let v81 = Map.find 0x81UL vMap
    let vList = [ v71 ; v81 ]
    let bblList = List.map (fun (x: Vertex<_>) -> x.VData) vList
    let addrRangeList =
      [ AddrRange (0x71UL, 0x81UL) ; AddrRange (0x81UL, 0x84UL) ]
    List.zip addrRangeList bblList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y.AddrRange))

  [<TestMethod>]
  member __.``DisasmGraph Edge Test: bar`` () =
    let cfg = funcs.[0x71UL].DisasmCFG
    let vMap = cfg.FoldVertex disasmVertexFolder Map.empty
    let v71 = Map.find 0x71UL vMap
    let v81 = Map.find 0x81UL vMap
    let eMap = cfg.FoldEdge (disasmEdgeFolder cfg) Map.empty
    Assert.AreEqual (1, eMap.Count)
    [ (0x71UL, 0x81UL) ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x eMap)
    let edge7181 = cfg.FindEdge v71 v81
    let eList = [ edge7181 ]
    let edgeTypeList = [ JmpEdge ]
    List.zip edgeTypeList eList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y))

  [<TestMethod>]
  member __.``IRGraph Vertex Test: _start`` () =
    let cfg = funcs.[0x00UL].IRCFG
    Assert.AreEqual (7, cfg.Size ())
    let vMap = cfg.FoldVertex irVertexFolder Map.empty
    [ (0x00UL, 0) ; (0x19UL, 0) ; (0x3FUL, 0) ; (0x48UL, 0) ; (0x52UL, 0) ;
      (0x55UL, 0) ; (0x5FUL, 0) ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x vMap)
    let v000 = Map.find (0x00UL, 0) vMap
    let v190 = Map.find (0x19UL, 0) vMap
    let v3F0 = Map.find (0x3FUL, 0) vMap
    let v480 = Map.find (0x48UL, 0) vMap
    let v520 = Map.find (0x52UL, 0) vMap
    let v550 = Map.find (0x55UL, 0) vMap
    let v5F0 = Map.find (0x5FUL, 0) vMap
    let vList = [ v000 ; v190 ; v3F0 ; v480 ; v520 ; v550 ; v5F0 ]
    let bblList = List.map (fun (x: IRVertex) -> x.VData) vList
    let pPointList =
      [ (0x00UL, 0) ; (0x19UL, 0) ; (0x3FUL, 0) ; (0x48UL, 0) ; (0x52UL, 0) ;
        (0x55UL, 0) ; (0x5FUL, 0) ]
    List.zip pPointList bblList
    |> List.iter (fun (x, y) ->
        let _, ppoint = y.GetPpoint ()
        Assert.AreEqual (x, ppoint))

  [<TestMethod>]
  member __.``IRGraph Edge Test: _start`` () =
    let cfg = funcs.[0x00UL].IRCFG
    let vMap = cfg.FoldVertex irVertexFolder Map.empty
    let v000 = Map.find (0x00UL, 0) vMap
    let v190 = Map.find (0x19UL, 0) vMap
    let v3F0 = Map.find (0x3FUL, 0) vMap
    let v480 = Map.find (0x48UL, 0) vMap
    let v520 = Map.find (0x52UL, 0) vMap
    let v550 = Map.find (0x55UL, 0) vMap
    let v5F0 = Map.find (0x5FUL, 0) vMap
    let eMap = cfg.FoldEdge (irEdgeFolder cfg) Map.empty
    Assert.AreEqual (7, eMap.Count)
    [ ((0x00UL, 0), (0x19UL, 0)) ; ((0x19UL, 0), (0x3FUL, 0)) ;
      ((0x19UL, 0), (0x48UL, 0)) ; ((0x3FUL, 0), (0x55UL, 0)) ;
      ((0x48UL, 0), (0x52UL, 0)) ; ((0x52UL, 0), (0x55UL, 0)) ;
      ((0x55UL, 0), (0x5FUL, 0)) ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x eMap)
    let edge000190 = cfg.FindEdge v000 v190
    let edge1903F0 = cfg.FindEdge v190 v3F0
    let edge190480 = cfg.FindEdge v190 v480
    let edge3F0550 = cfg.FindEdge v3F0 v550
    let edge480520 = cfg.FindEdge v480 v520
    let edge520550 = cfg.FindEdge v520 v550
    let edge5505F0 = cfg.FindEdge v550 v5F0
    let eList =
      [ edge000190 ; edge1903F0 ; edge190480 ; edge3F0550 ; edge480520 ;
        edge520550 ; edge5505F0 ]
    let edgeTypeList =
      [ FallThroughEdge ; CJmpFalseEdge ; CJmpTrueEdge ; JmpEdge ;
        FallThroughEdge ; JmpEdge ; FallThroughEdge ]
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
    let bblList = List.map (fun (x: IRVertex) -> x.VData) vList
    let pPointList = [ (0x62UL, 0) ]
    List.zip pPointList bblList
    |> List.iter (fun (x, y) ->
        let _, ppoint = y.GetPpoint ()
        Assert.AreEqual (x, ppoint))

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
    let bblList = List.map (fun (x: IRVertex) -> x.VData) vList
    let pPointList = [ (0x71UL, 0) ; (0x81UL, 0) ]
    List.zip pPointList bblList
    |> List.iter (fun (x, y) ->
        let _, ppoint = y.GetPpoint ()
        Assert.AreEqual (x, ppoint))

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
    let edgeTypeList = [ FallThroughEdge ]
    List.zip edgeTypeList eList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y))

  [<TestMethod>]
  member __.``SSAGraph Vertex Test: _start`` () =
    let cfg = funcs.[0x00UL].SSACFG
    Assert.AreEqual (7, cfg.Size ())

  [<TestMethod>]
  member __.``SSAGraph Edge Test: _start`` () =
    let cfg = funcs.[0x00UL].SSACFG
    let eList = cfg.FoldEdge (ssaEdgeFolder cfg) [] |> List.rev
    Assert.AreEqual (7, List.length eList)
    let edgeTypeList =
      [ FallThroughEdge ; CJmpFalseEdge ; CJmpTrueEdge ; JmpEdge ;
        FallThroughEdge ; JmpEdge ; FallThroughEdge ]
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
    let edgeTypeList = [ FallThroughEdge ]
    List.zip edgeTypeList eList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y))

  /// TODO: SSA translation functionality test

  [<TestMethod>]
  member __.``DisasmGraph Vertex Test after Call Analysis: bar`` () =
    let cfg = funcs_.[0x71UL].DisasmCFG
    Assert.AreEqual (1, cfg.Size ())
    let vMap = cfg.FoldVertex disasmVertexFolder Map.empty
    [ 0x71UL ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x vMap)
    let v71 = Map.find 0x71UL vMap
    let vList = [ v71 ]
    let bblList = List.map (fun (x: Vertex<_>) -> x.VData) vList
    let addrRangeList =
      [ AddrRange (0x71UL, 0x81UL) ]
    List.zip addrRangeList bblList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y.AddrRange))

  [<TestMethod>]
  member __.``DisasmGraph Edge Test after Call Analysis: bar`` () =
    let cfg = funcs_.[0x71UL].DisasmCFG
    let eMap = cfg.FoldEdge (disasmEdgeFolder cfg) Map.empty
    Assert.AreEqual (0, eMap.Count)

  [<TestMethod>]
  member __.``IRGraph Vertex Test after Call Analysis: _start`` () =
    let cfg = funcs_.[0x00UL].IRCFG
    Assert.AreEqual (9, cfg.Size ())
    let bblMap = cfg.FoldVertex irBBLFolder Map.empty
    Assert.AreEqual (7, bblMap.Count)
    [ (0x00UL, 0) ; (0x19UL, 0) ; (0x3FUL, 0) ; (0x48UL, 0) ; (0x52UL, 0) ;
      (0x55UL, 0) ; (0x5FUL, 0) ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x bblMap)
    let v000 = Map.find (0x00UL, 0) bblMap
    let v190 = Map.find (0x19UL, 0) bblMap
    let v3F0 = Map.find (0x3FUL, 0) bblMap
    let v480 = Map.find (0x48UL, 0) bblMap
    let v520 = Map.find (0x52UL, 0) bblMap
    let v550 = Map.find (0x55UL, 0) bblMap
    let v5F0 = Map.find (0x5FUL, 0) bblMap
    let vList = [ v000 ; v190 ; v3F0 ; v480 ; v520 ; v550 ; v5F0 ]
    let bblList = List.map (fun (x: IRVertex) -> x.VData) vList
    let pPointList =
      [ (0x00UL, 0) ; (0x19UL, 0) ; (0x3FUL, 0) ; (0x48UL, 0) ; (0x52UL, 0) ;
        (0x55UL, 0) ; (0x5FUL, 0) ]
    List.zip pPointList bblList
    |> List.iter (fun (x, y) ->
        let _, ppoint = y.GetPpoint ()
        Assert.AreEqual (x, ppoint))
    let callMap = cfg.FoldVertex irCallFolder Map.empty
    Assert.AreEqual (2, callMap.Count)
    [ 0x62UL ; 0x71UL ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x callMap)
    let c62 = Map.find 0x62UL callMap
    let c71 = Map.find 0x71UL callMap
    let cList = [ c62 ; c71 ]
    let bblList = List.map (fun (x: IRVertex) -> x.VData) cList
    let targetList = [ 0x62UL ; 0x71UL ]
    List.zip targetList bblList
    |> List.iter (fun (x, y) ->
        let _, target = y.GetTarget ()
        Assert.AreEqual (x, target))

  [<TestMethod>]
  member __.``IRGraph Edge Test after Call Analysis: _start`` () =
    let cfg = funcs_.[0x00UL].IRCFG
    let bblMap = cfg.FoldVertex irBBLFolder Map.empty
    let v000 = Map.find (0x00UL, 0) bblMap
    let v190 = Map.find (0x19UL, 0) bblMap
    let v3F0 = Map.find (0x3FUL, 0) bblMap
    let v480 = Map.find (0x48UL, 0) bblMap
    let v520 = Map.find (0x52UL, 0) bblMap
    let v550 = Map.find (0x55UL, 0) bblMap
    let v5F0 = Map.find (0x5FUL, 0) bblMap
    let callMap = cfg.FoldVertex irCallFolder Map.empty
    let c62 = Map.find 0x62UL callMap
    let c71 = Map.find 0x71UL callMap
    let normalEdges = cfg.FoldEdge (irNormalEdgeFolder cfg) Map.empty
    Assert.AreEqual (7, normalEdges.Count)
    [ ((0x00UL, 0), (0x19UL, 0)) ; ((0x19UL, 0), (0x3FUL, 0)) ;
      ((0x19UL, 0), (0x48UL, 0)) ; ((0x3FUL, 0), (0x55UL, 0)) ;
      ((0x48UL, 0), (0x52UL, 0)) ; ((0x52UL, 0), (0x55UL, 0)) ;
      ((0x55UL, 0), (0x5FUL, 0)) ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x normalEdges)
    let edge000190 = cfg.FindEdge v000 v190
    let edge1903F0 = cfg.FindEdge v190 v3F0
    let edge190480 = cfg.FindEdge v190 v480
    let edge3F0550 = cfg.FindEdge v3F0 v550
    let edge480520 = cfg.FindEdge v480 v520
    let edge520550 = cfg.FindEdge v520 v550
    let edge5505F0 = cfg.FindEdge v550 v5F0
    let eList =
      [ edge000190 ; edge1903F0 ; edge190480 ; edge3F0550 ; edge480520 ;
        edge520550 ; edge5505F0 ]
    let edgeTypeList =
      [ FallThroughEdge ; CJmpFalseEdge ; CJmpTrueEdge ; JmpEdge ;
        FallThroughEdge ; JmpEdge ; FallThroughEdge ]
    List.zip edgeTypeList eList
    |> List.iter (fun (x, y) -> Assert.AreEqual (x, y))
    let callEdges = cfg.FoldEdge (irCallEdgeFolder cfg) Map.empty
    Assert.AreEqual (3, callEdges.Count)
    let retEdges = cfg.FoldEdge (irRetEdgeFolder cfg) Map.empty
    Assert.AreEqual (3, retEdges.Count)

  [<TestMethod>]
  member __.``IRGraph Vertex Test after Call Analysis: foo`` () =
    let cfg = funcs_.[0x62UL].IRCFG
    Assert.AreEqual (1, cfg.Size ())
    let bblMap = cfg.FoldVertex irBBLFolder Map.empty
    [ (0x62UL, 0) ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x bblMap)
    let v620 = Map.find (0x62UL, 0) bblMap
    let vList = [ v620 ]
    let bblList = List.map (fun (x: IRVertex) -> x.VData) vList
    let pPointList = [ (0x62UL, 0) ]
    List.zip pPointList bblList
    |> List.iter (fun (x, y) ->
        let _, ppoint = y.GetPpoint ()
        Assert.AreEqual (x, ppoint))
    let callMap = cfg.FoldVertex irCallFolder Map.empty
    Assert.AreEqual (0, callMap.Count)

  [<TestMethod>]
  member __.``IRGraph Edge Test after Call Analysis: foo`` () =
    let cfg = funcs_.[0x62UL].IRCFG
    let normalEdges = cfg.FoldEdge (irNormalEdgeFolder cfg) Map.empty
    Assert.AreEqual (0, normalEdges.Count)
    let callEdges = cfg.FoldEdge (irCallEdgeFolder cfg) Map.empty
    Assert.AreEqual (0, callEdges.Count)
    let retEdges = cfg.FoldEdge (irRetEdgeFolder cfg) Map.empty
    Assert.AreEqual (0, retEdges.Count)

  [<TestMethod>]
  member __.``IRGraph Vertex Test after Call Analysis: bar`` () =
    let cfg = funcs_.[0x71UL].IRCFG
    Assert.AreEqual (1, cfg.Size ())
    let bblMap = cfg.FoldVertex irVertexFolder Map.empty
    [ (0x71UL, 0) ]
    |> List.iter (fun x -> Assert.IsTrue <| Map.containsKey x bblMap)
    let v710 = Map.find (0x71UL, 0) bblMap
    let vList = [ v710 ]
    let bblList = List.map (fun (x: IRVertex) -> x.VData) vList
    let pPointList = [ (0x71UL, 0) ]
    List.zip pPointList bblList
    |> List.iter (fun (x, y) ->
        let _, ppoint = y.GetPpoint ()
        Assert.AreEqual (x, ppoint))
    let callMap = cfg.FoldVertex irCallFolder Map.empty
    Assert.AreEqual (0, callMap.Count)

  [<TestMethod>]
  member __.``IRGraph Edge Test after Call Analysis: bar`` () =
    let cfg = funcs_.[0x71UL].IRCFG
    let normalEdges = cfg.FoldEdge (irNormalEdgeFolder cfg) Map.empty
    Assert.AreEqual (0, normalEdges.Count)
    let callEdges = cfg.FoldEdge (irCallEdgeFolder cfg) Map.empty
    Assert.AreEqual (0, callEdges.Count)
    let retEdges = cfg.FoldEdge (irRetEdgeFolder cfg) Map.empty
    Assert.AreEqual (0, retEdges.Count)

  [<TestMethod>]
  member __.``SSAGraph Vertex Test after Call Analysis: _start`` () =
    let cfg = funcs_.[0x00UL].SSACFG
    Assert.AreEqual (9, cfg.Size ())

  [<TestMethod>]
  member __.``SSAGraph Edge Test after Call Analysis: _start`` () =
    let cfg = funcs_.[0x00UL].SSACFG
    let eList = cfg.FoldEdge (ssaEdgeFolder cfg) [] |> List.rev
    Assert.AreEqual (13, List.length eList)

  [<TestMethod>]
  member __.``SSAGraph Vertex Test after Call Analysis: foo`` () =
    let cfg = funcs_.[0x62UL].SSACFG
    Assert.AreEqual (1, cfg.Size ())

  [<TestMethod>]
  member __.``SSAGraph Edge Test after Call Analysis: foo`` () =
    let cfg = funcs_.[0x62UL].SSACFG
    let eList = cfg.FoldEdge (ssaEdgeFolder cfg) []
    Assert.AreEqual (0, List.length eList)

  [<TestMethod>]
  member __.``SSAGraph Vertex Test after Call Analysis: bar`` () =
    let cfg = funcs_.[0x71UL].SSACFG
    Assert.AreEqual (1, cfg.Size ())

  [<TestMethod>]
  member __.``SSAGraph Edge Test after Call Analysis: bar`` () =
    let cfg = funcs_.[0x71UL].SSACFG
    let eList = cfg.FoldEdge (ssaEdgeFolder cfg) [] |> List.rev
    Assert.AreEqual (0, List.length eList)

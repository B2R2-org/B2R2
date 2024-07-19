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

namespace B2R2.MiddleEnd.DataFlow.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open System.Diagnostics

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd
open B2R2.MiddleEnd.SSA
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowGraph

[<TestClass>]
type PersistentDataFlowTests () =

#if !EMULATION
  [<TestMethod>]
  member __.``Reaching Definitions Test 1``() =
    let brew = TestCases.brew1
    let cfg = brew.Functions[0UL].CFG
    let dfa = ReachingDefinitionAnalysis () :> IDataFlowAnalysis<_, _, _, _>
    dfa.Compute cfg
    let v = cfg.FindVertexBy (fun b -> b.VData.PPoint.Address = 0xEUL) (* 2nd *)
    let rd = dfa.GetAbsValue v.ID
    let ins =
      rd.Ins |> Set.filter (fun v ->
      match v.VarKind with
      | Regular _ -> true
      | _ -> false)
    let solution = [
      { ProgramPoint = ProgramPoint (0UL, 1)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.EDX) }
      { ProgramPoint = ProgramPoint (4UL, 1)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.ESP) }
      { ProgramPoint = ProgramPoint (5UL, 1)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.ESI) }
      { ProgramPoint = ProgramPoint (5UL, 2)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.OF) }
      { ProgramPoint = ProgramPoint (5UL, 3)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.CF) }
      { ProgramPoint = ProgramPoint (5UL, 4)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.SF) }
      { ProgramPoint = ProgramPoint (5UL, 5)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.ZF) }
      { ProgramPoint = ProgramPoint (5UL, 6)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.PF) }
      { ProgramPoint = ProgramPoint (5UL, 7)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.AF) }
      { ProgramPoint = ProgramPoint (7UL, 1)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.ECX) }
      { ProgramPoint = ProgramPoint (0xAUL, 4)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.CF) }
      { ProgramPoint = ProgramPoint (0xAUL, 5)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.OF) }
      { ProgramPoint = ProgramPoint (0xAUL, 6)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.AF) }
      { ProgramPoint = ProgramPoint (0xAUL, 7)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.SF) }
      { ProgramPoint = ProgramPoint (0xAUL, 8)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.ZF) }
      { ProgramPoint = ProgramPoint (0xAUL, 11)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.PF) } ]
    Assert.AreEqual (Set.ofList solution, ins)
#endif

  [<TestMethod>]
  member __.``Use-Def Test 1``() =
    let brew = TestCases.brew1
    let cfg = brew.Functions[0UL].CFG
    let chain = DataFlowChain.init cfg false
    let vp =
      { ProgramPoint = ProgramPoint (0xEUL, 1)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.EDX) }
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [|
      { ProgramPoint = ProgramPoint (0x0UL, 1)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.EDX) } |]
    CollectionAssert.AreEqual (solution, res)

  [<TestMethod>]
  member __.``Use-Def Test 2``() =
    let brew = TestCases.brew1
    let cfg = brew.Functions[0UL].CFG
    let chain = DataFlowChain.init cfg true
    let vp =
      { ProgramPoint = ProgramPoint (0xEUL, 0)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.EDX) }
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [|
      { ProgramPoint = ProgramPoint (0x0UL, 0)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.EDX) } |]
    CollectionAssert.AreEqual (solution, res)

#if !EMULATION
  [<TestMethod>]
  member __.``Use-Def Test 3``() =
    let brew = TestCases.brew1
    let cfg = brew.Functions[0UL].CFG
    let chain = DataFlowChain.init cfg false
    let vp =
      { ProgramPoint = ProgramPoint (0x1AUL, 1)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.EDX) }
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [|
      { ProgramPoint = ProgramPoint (0x12UL, 3)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.EDX) }
      { ProgramPoint = ProgramPoint (0x1AUL, 3)
        VarKind = Regular (Intel.Register.toRegID Intel.Register.EDX) } |]
    CollectionAssert.AreEqual (solution, res)
#endif

  [<TestMethod>]
  member __.``SSA Constant Propagation Test 1`` () =
    let brew = TestCases.brew2
    let fn = brew.Functions[0UL]
    let lifter = SSALifterFactory<CFGEdgeKind>.Create (brew.BinHandle)
    let cfg = lifter.Lift fn.CFG
    let cp = SSA.SSAConstantPropagation brew.BinHandle
    let dfa = cp :> IDataFlowAnalysis<_, _, _, _>
    dfa.Compute cfg
    cfg.IterVertex (fun v ->
      Debug.Print $"[Vertex {v.VData.PPoint.Address:x}]"
      let inss = v.VData.LiftedSSAStmts
      let stmts = inss |> Array.map (fun (_, stmt) -> stmt)
      Debug.Print <| $"{SSA.Pp.stmtsToString stmts}")
    let rt = 64<rt>
    let genRegularVar r id =
      let rid = Intel.Register.toRegID r
      let rstr = Intel.Register.toString r
      let v = SSA.RegVar (rt, rid, rstr)
      SSA.SSAVarPoint.RegularSSAVar { Kind = v; Identifier = id }
    let genMemVar memId addr = SSA.SSAVarPoint.MemorySSAVar (memId, addr)
    let regularVarEq r id c =
      let vp = genRegularVar r id
      (vp, c)
    let memVarEq memId addr c =
      let vp = genMemVar memId addr
      (vp, c)
    let regularVarNotConst r id =
      regularVarEq r id ConstantDomain.NotAConst
    let regularVarConst r id value =
      regularVarEq r id (ConstantDomain.Const (BitVector.OfUInt64 value rt))
    let regularVarUndef r id =
      regularVarEq r id ConstantDomain.Undef
    let memVarNotConst memId addr =
      memVarEq memId addr ConstantDomain.NotAConst
    let memVarConst memId addr value =
      memVarEq memId addr (ConstantDomain.Const (BitVector.OfUInt64 value rt))
    let memVarUndef memId addr =
      memVarEq memId addr ConstantDomain.Undef
    let varAnsMap =
      [ regularVarConst Intel.Register.RSP 0 0x80000000UL
        regularVarConst Intel.Register.RSP 1 0x7ffffff8UL
        regularVarUndef Intel.Register.RBP 0
        regularVarConst Intel.Register.RBP 1 0x7ffffff8UL
        memVarUndef 1 0x7ffffff8UL
        memVarConst 5 (0x7ffffff8UL - 0xcUL) 0x2UL
        memVarConst 6 (0x7ffffff8UL - 0x8UL) 0x3UL
        memVarConst 7 (0x7ffffff8UL - 0xcUL) 0x3UL
        memVarConst 8 (0x7ffffff8UL - 0x8UL) 0x2UL
        memVarNotConst 3 (0x7ffffff8UL - 0xcUL)
        memVarNotConst 3 (0x7ffffff8UL - 0x8UL)
        regularVarNotConst Intel.Register.RAX 1
        regularVarNotConst Intel.Register.RDX 1
        regularVarNotConst Intel.Register.RAX 2
        regularVarNotConst Intel.Register.RBP 2
        regularVarConst Intel.Register.RSP 2 (0x7ffffff8UL + 0x8UL)
        regularVarConst Intel.Register.RSP 3 (0x7ffffff8UL + 0x10UL) ]
    varAnsMap |> List.iter (fun (var, ans) ->
      let out = dfa.GetAbsValue var
      Debug.Print <| sprintf "%A: %A <-> %A" var ans out
      Assert.AreEqual (ans, out))

  [<TestMethod>]
  member __.``Incremental Data Flow Test 1``() =
    let brew = TestCases.brew2
    let cfg = brew.Functions[0UL].CFG
    let rt = 64<rt>
    let roots = cfg.GetRoots ()
    let regValues =
      (Intel.Register.RSP, Constants.InitialStackPointer)
      |> fun (r, v) -> Intel.Register.toRegID r, BitVector.OfUInt64 v rt
      |> Seq.singleton
      |> Map.ofSeq
    let genRegularVar addr i r =
      let rid = Intel.Register.toRegID r
      let pp = ProgramPoint (addr, i)
      let varKind = VarKind.Regular rid
      { ProgramPoint = pp; VarKind = varKind }
    let genMemVar addr i memAddr =
      let pp = ProgramPoint (addr, i)
      let varKind = VarKind.Memory (Some memAddr)
      { ProgramPoint = pp; VarKind = varKind }
    let regularVarEq addr i r c =
      let vp = genRegularVar addr i r
      vp, c
    let memVarEq addr i memAddr c =
      let vp = genMemVar addr i memAddr
      vp, c
    let regularVarConst addr i r value =
      regularVarEq addr i r (ConstantDomain.Const (BitVector.OfUInt64 value rt))
    let regularVarUndef addr i r =
      regularVarEq addr i r ConstantDomain.Undef
    let memVarNotConst addr i memAddr =
      memVarEq addr i memAddr ConstantDomain.NotAConst
    let memVarDWordConst addr i memAddr v =
      memVarEq addr i memAddr
        (ConstantDomain.Const (BitVector.OfUInt32 v 32<rt>))
    let memVarUndef addr i memAddr =
      memVarEq addr i memAddr ConstantDomain.Undef
    let varAnsMap =
      [ regularVarConst 0x0UL 0 Intel.Register.RSP 0x80000000UL
        regularVarConst 0x4UL 1 Intel.Register.RSP 0x7ffffff8UL
        regularVarUndef 0x5UL 0 Intel.Register.RBP
        regularVarConst 0x5UL 1 Intel.Register.RBP 0x7ffffff8UL
        memVarUndef 0xbUL 1 0x7ffffff8UL
        memVarDWordConst 0x11UL 1 (0x7ffffff8UL - 0xcUL) 0x2ul
        memVarDWordConst 0x18UL 1 (0x7ffffff8UL - 0x8UL) 0x3ul
        memVarDWordConst 0x21UL 1 (0x7ffffff8UL - 0xcUL) 0x3ul
        memVarDWordConst 0x28UL 1 (0x7ffffff8UL - 0x8UL) 0x2ul
        memVarNotConst 0x2fUL 0 (0x7ffffff8UL - 0xcUL)
        memVarNotConst 0x2fUL 0 (0x7ffffff8UL - 0x8UL)
        regularVarConst 0x3bUL 2 Intel.Register.RSP (0x7ffffff8UL + 0x8UL)
        regularVarConst 0x3cUL 2 Intel.Register.RSP (0x7ffffff8UL + 0x10UL) ]
    let idfa =
      { new IncrementalDataFlowAnalysis<int, CFGEdgeKind> () with
        member __.Bottom = 0
        member __.Transfer (_, _, _, _) = None
        member __.IsSubsumable (_, _) = true
        member __.Join (_, _) = 0 }
    let dfa = idfa :> IDataFlowAnalysis<_, _, _, _>
    Seq.iter idfa.PushWork roots
    idfa.SetInitialRegisterConstants regValues
    dfa.Compute cfg
    varAnsMap |> List.iter (fun (vp, ans) ->
      let out = idfa.GetConstant vp
      Assert.AreEqual (ans, out))

  [<TestMethod>]
  member __.``Untouched Value Analysis 1``() =
    let brew = TestCases.brew3
    let cfg = brew.Functions[0UL].CFG
    let rt = 64<rt>
    let roots = cfg.GetRoots ()
    let regValues =
      (Intel.Register.RSP, Constants.InitialStackPointer)
      |> fun (r, v) -> Intel.Register.toRegID r, BitVector.OfUInt64 v rt
      |> Seq.singleton
      |> Map.ofSeq
    let genRegularVar addr i r =
      let rid = Intel.Register.toRegID r
      let pp = ProgramPoint (addr, i)
      let varKind = VarKind.Regular rid
      { ProgramPoint = pp; VarKind = varKind }
    let genMemVar addr i memAddr =
      let pp = ProgramPoint (addr, i)
      let varKind = VarKind.Memory (Some memAddr)
      { ProgramPoint = pp; VarKind = varKind }
    let regularVarEq addr i r c =
      let vp = genRegularVar addr i r
      vp, c
    let memVarEq addr i memAddr c =
      let vp = genMemVar addr i memAddr
      vp, c
    let regularVarTouched addr i r =
      let v = UntouchedValueDomain.Touched
      regularVarEq addr i r v
    let regularVarUntouched addr i r srcReg =
      let varKind = VarKind.Regular (Intel.Register.toRegID srcReg)
      let tag = UntouchedValueDomain.RegisterTag varKind
      let v = UntouchedValueDomain.Untouched tag
      regularVarEq addr i r v
    let memVarTouched addr i memAddr =
      let v = UntouchedValueDomain.Touched
      memVarEq addr i memAddr v
    let memVarUntouched addr i memAddr r =
      let varKind = VarKind.Regular (Intel.Register.toRegID r)
      let tag = UntouchedValueDomain.RegisterTag varKind
      let v = UntouchedValueDomain.Untouched tag
      memVarEq addr i memAddr v
    let varAnsMap =
      [ memVarUntouched 0xcUL 1 (0x7ffffff8UL - 0x14UL) Intel.Register.RDI
        memVarUntouched 0xfUL 1 (0x7ffffff8UL - 0x18UL) Intel.Register.RSI
        memVarUntouched 0x15UL 1 (0x7ffffff8UL - 0x10UL) Intel.Register.RDI
        memVarTouched 0x1eUL 1 (0x7ffffff8UL - 0xcUL)
        regularVarTouched 0x32UL 1 Intel.Register.RCX
        regularVarTouched 0x35UL 1 Intel.Register.RDX
        regularVarTouched 0x38UL 1 Intel.Register.RSI
        regularVarUntouched 0x3bUL 1 Intel.Register.RAX Intel.Register.RDI ]
    let uva = UntouchedValueAnalysis<CFGEdgeKind> ()
    let dfa = uva :> IDataFlowAnalysis<_, _, _, _>
    Seq.iter uva.PushWork roots
    uva.SetInitialRegisterConstants regValues
    dfa.Compute cfg
#if DEBUG
    cfg.IterVertex (fun v ->
      v.VData.LiftedInstructions
      |> Array.iter (fun ins ->
        let stmts = ins.Stmts
        stmts |> Array.iteri (fun i stmt ->
          let s = LowUIR.Pp.stmtToString stmt
          let addr = ins.Original.Address
          Debug.Print <| sprintf "%x:%i -> %s" addr i s)))
#endif
    varAnsMap |> List.iter (fun (vp, ans) ->
      let out = dfa.GetAbsValue vp
      Assert.AreEqual (ans, out))

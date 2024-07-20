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
open B2R2.FrontEnd.BinLifter.Intel
open B2R2.MiddleEnd.SSA
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowGraph

[<TestClass>]
type PersistentDataFlowTests () =
  let isRegular (v: VarPoint) =
    match v.VarKind with
    | Regular _ -> true
    | _ -> false

  let reg addr idx reg =
    { ProgramPoint = ProgramPoint (addr, idx)
      VarKind = Regular (Register.toRegID reg) }

  let mkConst v rt =
    ConstantDomain.Const (BitVector.OfUInt32 v rt)

  let ssaReg r id rt =
    let rid = Register.toRegID r
    let rstr = Register.toString r
    let k = SSA.RegVar (rt, rid, rstr)
    SSA.SSAVarPoint.RegularSSAVar { Kind = k; Identifier = id }

  let ssaStk offset id rt =
    let k = SSA.StackVar (rt, offset)
    SSA.SSAVarPoint.RegularSSAVar { Kind = k; Identifier = id }

  let cmp vp c = vp, c

#if !EMULATION
  [<TestMethod>]
  member __.``Reaching Definitions Test 1``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let dfa = ReachingDefinitionAnalysis () :> IDataFlowAnalysis<_, _, _, _>
    dfa.Compute cfg
    let v = cfg.FindVertexBy (fun b -> b.VData.PPoint.Address = 0xEUL) (* 2nd *)
    let rd = dfa.GetAbsValue v.ID
    let ins = rd.Ins |> Set.filter isRegular
    let solution =
      [ reg 0x0UL 1 Register.EDX
        reg 0x4UL 1 Register.ESP
        reg 0x5UL 1 Register.ESI
        reg 0x5UL 2 Register.OF
        reg 0x5UL 3 Register.CF
        reg 0x5UL 4 Register.SF
        reg 0x5UL 5 Register.ZF
        reg 0x5UL 6 Register.PF
        reg 0x5UL 7 Register.AF
        reg 0x7UL 1 Register.ECX
        reg 0xAUL 4 Register.CF
        reg 0xAUL 5 Register.OF
        reg 0xAUL 6 Register.AF
        reg 0xAUL 7 Register.SF
        reg 0xAUL 8 Register.ZF
        reg 0xAUL 11 Register.PF ]
    Assert.AreEqual (Set.ofList solution, ins)
#endif

  [<TestMethod>]
  member __.``Use-Def Test 1``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let chain = DataFlowChain.init cfg false
    let vp = reg 0xEUL 1 Register.EDX
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [| reg 0x0UL 1 Register.EDX |]
    CollectionAssert.AreEqual (solution, res)

  [<TestMethod>]
  member __.``Use-Def Test 2``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let chain = DataFlowChain.init cfg true
    let vp = reg 0xEUL 0 Register.EDX
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [| reg 0x0UL 0 Register.EDX |]
    CollectionAssert.AreEqual (solution, res)

#if !EMULATION
  [<TestMethod>]
  member __.``Use-Def Test 3``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let chain = DataFlowChain.init cfg false
    let vp = reg 0x1AUL 1 Register.EDX
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [| reg 0x12UL 3 Register.EDX
                      reg 0x1AUL 3 Register.EDX |]
    CollectionAssert.AreEqual (solution, res)
#endif

  [<TestMethod>]
  member __.``SSA Constant Propagation Test 1`` () =
    let brew = Binaries.loadOne Binaries.sample2
    let cfg = brew.Functions[0UL].CFG
    let lifter = SSALifterFactory<CFGEdgeKind>.Create (brew.BinHandle)
    let ssaCFG = lifter.Lift cfg
    let cp = SSA.SSAConstantPropagation brew.BinHandle
    let dfa = cp :> IDataFlowAnalysis<_, _, _, _>
    dfa.Compute ssaCFG
    [ ssaReg Register.RSP 0 64<rt> |> cmp <| mkConst 0x80000000u 64<rt>
      ssaReg Register.RSP 1 64<rt> |> cmp <| mkConst 0x7ffffff8u 64<rt>
      ssaReg Register.RBP 0 64<rt> |> cmp <| ConstantDomain.Undef
      ssaReg Register.RBP 1 64<rt> |> cmp <| mkConst 0x7ffffff8u 64<rt>
      ssaStk (8 + 0xc) 2 32<rt> |> cmp <| mkConst 0x2u 32<rt>
      ssaStk (8 + 0x8) 2 32<rt> |> cmp <| mkConst 0x3u 32<rt>
      ssaStk (8 + 0xc) 3 32<rt> |> cmp <| mkConst 0x3u 32<rt>
      ssaStk (8 + 0x8) 3 32<rt> |> cmp <| mkConst 0x2u 32<rt>
      ssaStk (8 + 0xc) 1 32<rt> |> cmp <| ConstantDomain.NotAConst
      ssaStk (8 + 0x8) 1 32<rt> |> cmp <| ConstantDomain.NotAConst
      ssaReg Register.RAX 1 64<rt> |> cmp <| ConstantDomain.NotAConst
      ssaReg Register.RDX 1 64<rt> |> cmp <| ConstantDomain.NotAConst
      ssaReg Register.RAX 2 64<rt> |> cmp <| ConstantDomain.NotAConst
      ssaReg Register.RBP 2 64<rt> |> cmp <| ConstantDomain.Undef
      ssaReg Register.RSP 2 64<rt> |> cmp <| mkConst 0x80000000u 64<rt>
      ssaReg Register.RSP 3 64<rt> |> cmp <| mkConst 0x80000008u 64<rt> ]
    |> List.iter (fun (var, ans) ->
      let out = dfa.GetAbsValue var
      Debug.Print $"{var}: {ans} <-> {out}"
      Assert.AreEqual (ans, out))

#if !EMULATION
  [<TestMethod>]
  member __.``Incremental Data Flow Test 1``() =
    let brew = Binaries.loadOne Binaries.sample2
    let cfg = brew.Functions[0UL].CFG
    let rt = 64<rt>
    let roots = cfg.GetRoots ()
    let regValues =
      (Register.RSP, Constants.InitialStackPointer)
      |> fun (r, v) -> Register.toRegID r, BitVector.OfUInt64 v rt
      |> Seq.singleton
      |> Map.ofSeq
    let genRegularVar addr i r =
      let rid = Register.toRegID r
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
      [ regularVarConst 0x0UL 0 Register.RSP 0x80000000UL
        regularVarConst 0x4UL 1 Register.RSP 0x7ffffff8UL
        regularVarUndef 0x5UL 0 Register.RBP
        regularVarConst 0x5UL 1 Register.RBP 0x7ffffff8UL
        memVarUndef 0xbUL 1 0x7ffffff8UL
        memVarDWordConst 0x11UL 1 (0x7ffffff8UL - 0xcUL) 0x2ul
        memVarDWordConst 0x18UL 1 (0x7ffffff8UL - 0x8UL) 0x3ul
        memVarDWordConst 0x21UL 1 (0x7ffffff8UL - 0xcUL) 0x3ul
        memVarDWordConst 0x28UL 1 (0x7ffffff8UL - 0x8UL) 0x2ul
        memVarNotConst 0x2fUL 0 (0x7ffffff8UL - 0xcUL)
        memVarNotConst 0x2fUL 0 (0x7ffffff8UL - 0x8UL)
        regularVarConst 0x3bUL 2 Register.RSP (0x7ffffff8UL + 0x8UL)
        regularVarConst 0x3cUL 2 Register.RSP (0x7ffffff8UL + 0x10UL) ]
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
#endif

  [<TestMethod>]
  member __.``Untouched Value Analysis 1``() =
    let brew = Binaries.loadOne Binaries.sample3
    let cfg = brew.Functions[0UL].CFG
    let rt = 64<rt>
    let roots = cfg.GetRoots ()
    let regValues =
      (Register.RSP, Constants.InitialStackPointer)
      |> fun (r, v) -> Register.toRegID r, BitVector.OfUInt64 v rt
      |> Seq.singleton
      |> Map.ofSeq
    let genRegularVar addr i r =
      let rid = Register.toRegID r
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
      let varKind = VarKind.Regular (Register.toRegID srcReg)
      let tag = UntouchedValueDomain.RegisterTag varKind
      let v = UntouchedValueDomain.Untouched tag
      regularVarEq addr i r v
    let memVarTouched addr i memAddr =
      let v = UntouchedValueDomain.Touched
      memVarEq addr i memAddr v
    let memVarUntouched addr i memAddr r =
      let varKind = VarKind.Regular (Register.toRegID r)
      let tag = UntouchedValueDomain.RegisterTag varKind
      let v = UntouchedValueDomain.Untouched tag
      memVarEq addr i memAddr v
    let varAnsMap =
      [ memVarUntouched 0xcUL 1 (0x7ffffff8UL - 0x14UL) Register.RDI
        memVarUntouched 0xfUL 1 (0x7ffffff8UL - 0x18UL) Register.RSI
        memVarUntouched 0x15UL 1 (0x7ffffff8UL - 0x10UL) Register.RDI
        memVarTouched 0x1eUL 1 (0x7ffffff8UL - 0xcUL)
        regularVarTouched 0x32UL 1 Register.RCX
        regularVarTouched 0x35UL 1 Register.RDX
        regularVarTouched 0x38UL 1 Register.RSI
        regularVarUntouched 0x3bUL 1 Register.RAX Register.RDI ]
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

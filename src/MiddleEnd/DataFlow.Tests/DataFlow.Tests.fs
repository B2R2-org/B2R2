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
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.SSA

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

  let irReg addr idx r =
    let rid = Register.toRegID r
    let pp = ProgramPoint (addr, idx)
    let varKind = VarKind.Regular rid
    { ProgramPoint = pp; VarKind = varKind }

  let irMem add idx offset =
    let pp = ProgramPoint (add, idx)
    let varKind = VarKind.Memory (Some offset)
    { ProgramPoint = pp; VarKind = varKind }

  let mkUntouchedReg r =
    VarKind.Regular (Register.toRegID r)
    |> UntouchedValueDomain.RegisterTag
    |> UntouchedValueDomain.Untouched

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
    let hdl = brew.BinHandle
    let cfg = brew.Functions[0UL].CFG
    let roots = cfg.GetRoots ()
    let idfa = IncrementalDataFlowAnalysis.createDummy<CFGEdgeKind> hdl
    let dfa = idfa :> IDataFlowAnalysis<_, _, _, _>
    Seq.iter idfa.PushWork roots
    dfa.Compute cfg
    [ irReg 0x0UL 0 Register.RSP |> cmp <| mkConst 0x80000000u 64<rt>
      irReg 0x4UL 1 Register.RSP |> cmp <| mkConst 0x7ffffff8u 64<rt>
      irReg 0x5UL 0 Register.RBP |> cmp <| ConstantDomain.Undef
      irReg 0x5UL 1 Register.RBP |> cmp <| mkConst 0x7ffffff8u 64<rt>
      irMem 0xbUL 1 0x7ffffff8UL |> cmp <| ConstantDomain.Undef
      irMem 0x11UL 1 (0x7ffffff8UL - 0xcUL) |> cmp <| mkConst 0x2u 32<rt>
      irMem 0x18UL 1 (0x7ffffff8UL - 0x8UL) |> cmp <| mkConst 0x3u 32<rt>
      irMem 0x21UL 1 (0x7ffffff8UL - 0xcUL) |> cmp <| mkConst 0x3u 32<rt>
      irMem 0x28UL 1 (0x7ffffff8UL - 0x8UL) |> cmp <| mkConst 0x2u 32<rt>
      irMem 0x2fUL 0 (0x7ffffff8UL - 0xcUL) |> cmp <| ConstantDomain.NotAConst
      irMem 0x2fUL 0 (0x7ffffff8UL - 0x8UL) |> cmp <| ConstantDomain.NotAConst
      irReg 0x3bUL 2 Register.RSP |> cmp <| mkConst 0x80000000u 64<rt>
      irReg 0x3cUL 2 Register.RSP |> cmp <| mkConst 0x80000008u 64<rt> ]
    |> List.iter (fun (vp, ans) ->
      let out = idfa.GetConstant vp
      Assert.AreEqual (ans, out))
#endif

  [<TestMethod>]
  member __.``Untouched Value Analysis 1``() =
    let brew = Binaries.loadOne Binaries.sample3
    let cfg = brew.Functions[0UL].CFG
    let roots = cfg.GetRoots ()
    let uva = UntouchedValueAnalysis<CFGEdgeKind> brew.BinHandle
    let dfa = uva :> IDataFlowAnalysis<_, _, _, _>
    Seq.iter uva.PushWork roots
    let rbp = 0x7ffffff8UL
    dfa.Compute cfg
    [ irMem 0xcUL 1 (rbp - 0x14UL) |> cmp <| mkUntouchedReg Register.RDI
      irMem 0xfUL 1 (rbp - 0x18UL) |> cmp <| mkUntouchedReg Register.RSI
      irMem 0x15UL 1 (rbp - 0x10UL) |> cmp <| mkUntouchedReg Register.RDI
      irMem 0x1eUL 1 (rbp - 0xcUL) |> cmp <| UntouchedValueDomain.Touched
      irReg 0x32UL 1 Register.RCX |> cmp <| UntouchedValueDomain.Touched
      irReg 0x35UL 1 Register.RDX |> cmp <| UntouchedValueDomain.Touched
      irReg 0x38UL 1 Register.RSI |> cmp <| UntouchedValueDomain.Touched
      irReg 0x3bUL 1 Register.RAX |> cmp <| mkUntouchedReg Register.RDI ]
    |> List.iter (fun (vp, ans) ->
      let out = dfa.GetAbsValue vp
      Assert.AreEqual (ans, out))

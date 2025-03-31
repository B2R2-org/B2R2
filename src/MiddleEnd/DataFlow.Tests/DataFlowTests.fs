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

open B2R2
open B2R2.FrontEnd.Register
open B2R2.BinIR
open B2R2.MiddleEnd.DataFlow
open B2R2.MiddleEnd.SSA
open B2R2.MiddleEnd.ControlFlowGraph

[<TestClass>]
type DataFlowTests () =
  let isRegular (v: VarPoint) =
    match v.VarKind with
    | Regular _ -> true
    | _ -> false

  let reg addr idx reg =
    { ProgramPoint = ProgramPoint (addr, idx)
      VarKind = Regular (IntelRegister.ID reg) }

  let mkConst v rt =
    ConstantDomain.Const (BitVector.OfUInt32 v rt)

  let rec findVarDefFromStmts (stmts: _[]) vaddr idx addr kind =
    if idx < stmts.Length then
      match stmts[idx] with
      | (pp: ProgramPoint), SSA.Def (v, _) when v.Kind = kind ->
        if pp.Address = addr then Some v
        else findVarDefFromStmts stmts vaddr (idx + 1) addr kind
      | _, SSA.Phi (v, _) when v.Kind = kind ->
        if vaddr = addr then Some v
        else findVarDefFromStmts stmts vaddr (idx + 1) addr kind
      | _ -> findVarDefFromStmts stmts vaddr (idx + 1) addr kind
    else None

  let rec findSSAVarDef (ssaCFG: SSACFG) vidx addr kind =
    if vidx < ssaCFG.Vertices.Length then
      let v = ssaCFG.Vertices[vidx]
      let stmts = v.VData.Internals.Statements
      findVarDefFromStmts stmts v.VData.Internals.PPoint.Address 0 addr kind
      |> function
        | Some v -> v
        | None -> findSSAVarDef ssaCFG (vidx + 1) addr kind
    else failwith $"variable {kind} @ {addr:x} not found"

  let ssaReg ssaCFG r addr rt =
    let rid = IntelRegister.ID r
    let rstr = IntelRegister.String r
    let k = SSA.RegVar (rt, rid, rstr)
    let v = findSSAVarDef ssaCFG 0 addr k
    SSA.SSAVarPoint.RegularSSAVar { Kind = k; Identifier = v.Identifier }

  let ssaRegInitial r rt =
    let rid = IntelRegister.ID r
    let rstr = IntelRegister.String r
    let k = SSA.RegVar (rt, rid, rstr)
    SSA.SSAVarPoint.RegularSSAVar { Kind = k; Identifier = 0 }

  let ssaStk ssaCFG offset addr rt =
    let kind = SSA.StackVar (rt, offset)
    let v = findSSAVarDef ssaCFG 0 addr kind
    SSA.SSAVarPoint.RegularSSAVar { Kind = v.Kind; Identifier = v.Identifier }

  let irReg addr idx r =
    let rid = IntelRegister.ID r
    let pp = ProgramPoint (addr, idx)
    let varKind = Regular rid
    { ProgramPoint = pp; VarKind = varKind }

  let irStk addr idx offset =
    let pp = ProgramPoint (addr, idx)
    let varKind = StackLocal offset
    { ProgramPoint = pp; VarKind = varKind }

  let mkUntouchedReg r =
    Regular (IntelRegister.ID r)
    |> UntouchedValueDomain.RegisterTag
    |> UntouchedValueDomain.Untouched

  let cmp vp c = vp, c

#if !EMULATION
  [<TestMethod>]
  member __.``Reaching Definitions Test 1``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let dfa = ReachingDefinitionAnalysis () :> IDataFlowAnalysis<_, _, _, _>
    let state = dfa.InitializeState []
    let state = dfa.Compute cfg state
    let v = cfg.FindVertex (fun b -> b.VData.Internals.PPoint.Address = 0xEUL)
    let rd = (state :> IDataFlowState<_, _>).GetAbsValue v.ID (* 2nd vertex *)
    let ins = rd.Ins |> Set.filter isRegular
    let solution =
      [ reg 0x0UL 1 Intel.EDX
        reg 0x4UL 1 Intel.ESP
        reg 0x5UL 1 Intel.ESI
        reg 0x5UL 2 Intel.OF
        reg 0x5UL 3 Intel.CF
        reg 0x5UL 4 Intel.SF
        reg 0x5UL 5 Intel.ZF
        reg 0x5UL 6 Intel.PF
        reg 0x5UL 7 Intel.AF
        reg 0x7UL 1 Intel.ECX
        reg 0xAUL 4 Intel.CF
        reg 0xAUL 5 Intel.OF
        reg 0xAUL 6 Intel.AF
        reg 0xAUL 7 Intel.SF
        reg 0xAUL 8 Intel.ZF
        reg 0xAUL 11 Intel.PF ]
    Assert.AreEqual (Set.ofList solution, ins)
#endif

  [<TestMethod>]
  member __.``Use-Def Test 1``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let chain = DataFlowChain.init cfg false
    let vp = reg 0xEUL 1 Intel.EDX
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [| reg 0x0UL 1 Intel.EDX |]
    CollectionAssert.AreEqual (solution, res)

  [<TestMethod>]
  member __.``Use-Def Test 2``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let chain = DataFlowChain.init cfg true
    let vp = reg 0xEUL 0 Intel.EDX
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [| reg 0x0UL 0 Intel.EDX |]
    CollectionAssert.AreEqual (solution, res)

#if !EMULATION
  [<TestMethod>]
  member __.``Use-Def Test 3``() =
    let brew = Binaries.loadOne Binaries.sample1
    let cfg = brew.Functions[0UL].CFG
    let chain = DataFlowChain.init cfg false
    let vp = reg 0x1AUL 1 Intel.EDX
    let res = chain.UseDefChain |> Map.find vp |> Set.toArray
    let solution = [| reg 0x12UL 3 Intel.EDX
                      reg 0x1AUL 3 Intel.EDX |]
    CollectionAssert.AreEqual (solution, res)
#endif

  [<TestMethod>]
  member __.``SSA Constant Propagation Test 1`` () =
    let brew = Binaries.loadOne Binaries.sample2
    let cfg = brew.Functions[0UL].CFG
    let lifter = SSALifterFactory.Create (brew.BinHandle)
    let g = lifter.Lift cfg
    let cp = SSA.SSAConstantPropagation brew.BinHandle
    let dfa = cp :> IDataFlowAnalysis<_, _, _, _>
    let state = dfa.InitializeState []
    let state = dfa.Compute g state
    [ ssaRegInitial Intel.RSP 64<rt> |> cmp <| mkConst 0x80000000u 64<rt>
      ssaRegInitial Intel.RBP 64<rt> |> cmp <| ConstantDomain.Undef
      ssaReg g Intel.RSP 0x4UL 64<rt> |> cmp <| mkConst 0x7ffffff8u 64<rt>
      ssaReg g Intel.RBP 0x5UL 64<rt> |> cmp <| mkConst 0x7ffffff8u 64<rt>
      ssaStk g (8 + 0xc) 0x11UL 32<rt> |> cmp <| mkConst 0x2u 32<rt>
      ssaStk g (8 + 0x8) 0x18UL 32<rt> |> cmp <| mkConst 0x3u 32<rt>
      ssaStk g (8 + 0xc) 0x21UL 32<rt> |> cmp <| mkConst 0x3u 32<rt>
      ssaStk g (8 + 0x8) 0x28UL 32<rt> |> cmp <| mkConst 0x2u 32<rt>
      ssaStk g (8 + 0xc) 0x2fUL 32<rt> |> cmp <| ConstantDomain.NotAConst
      ssaStk g (8 + 0x8) 0x2fUL 32<rt> |> cmp <| ConstantDomain.NotAConst
      ssaReg g Intel.RAX 0x32UL 64<rt> |> cmp <| ConstantDomain.NotAConst
      ssaReg g Intel.RDX 0x2fUL 64<rt> |> cmp <| ConstantDomain.NotAConst
      ssaReg g Intel.RAX 0x35UL 64<rt> |> cmp <| ConstantDomain.NotAConst
      ssaReg g Intel.RBP 0x3bUL 64<rt> |> cmp <| ConstantDomain.Undef
      ssaReg g Intel.RSP 0x3bUL 64<rt> |> cmp <| mkConst 0x80000000u 64<rt>
      ssaReg g Intel.RSP 0x3CUL 64<rt> |> cmp <| mkConst 0x80000008u 64<rt> ]
    |> List.iter (fun (var, ans) ->
      let out = (state :> IDataFlowState<_, _>).GetAbsValue var
      Assert.AreEqual<ConstantDomain.Lattice> (ans, out))

#if !EMULATION
  [<TestMethod>]
  member __.``Constant Propagation Test 1``() =
    let brew = Binaries.loadOne Binaries.sample2
    let hdl = brew.BinHandle
    let cfg = brew.Functions[0UL].CFG
    let varDfa = ConstantPropagation hdl
    let dfa = varDfa :> IDataFlowAnalysis<_, _, _, _>
    let state = dfa.InitializeState cfg.Vertices
    let state = dfa.Compute cfg state
    let rbp = -8 (* stack offset of old rbp *)
    [ irStk 0xbUL 1 rbp |> cmp <| ConstantDomain.Undef
      irStk 0x11UL 1 (rbp - 0xc) |> cmp <| mkConst 0x2u 32<rt>
      irStk 0x18UL 1 (rbp - 0x8) |> cmp <| mkConst 0x3u 32<rt>
      irStk 0x21UL 1 (rbp - 0xc) |> cmp <| mkConst 0x3u 32<rt>
      irStk 0x28UL 1 (rbp - 0x8) |> cmp <| mkConst 0x2u 32<rt>
      irReg 0x2fUL 1 Intel.RDX |> cmp <| ConstantDomain.NotAConst ]
    |> List.iter (fun (vp, ans) ->
      let out = (state :> IDataFlowState<_, _>).GetAbsValue vp
      Assert.AreEqual<ConstantDomain.Lattice> (ans, out))
#endif

  [<TestMethod>]
  member __.``Untouched Value Analysis 1``() =
    let brew = Binaries.loadOne Binaries.sample3
    let cfg = brew.Functions[0UL].CFG
    let roots = cfg.Roots
    let uva = UntouchedValueAnalysis brew.BinHandle
    let dfa = uva :> IDataFlowAnalysis<_, _, _, _>
    let state = dfa.InitializeState roots
    cfg.IterVertex state.MarkVertexAsPending
    let state = dfa.Compute cfg state
    let rbp = -8 (* stack offset of old rbp *)
    [ irStk 0xcUL 1 (rbp - 0x14) |> cmp <| mkUntouchedReg Intel.RDI
      irStk 0xfUL 1 (rbp - 0x18) |> cmp <| mkUntouchedReg Intel.RSI
      irStk 0x15UL 1 (rbp - 0x10) |> cmp <| mkUntouchedReg Intel.RDI
      irStk 0x1eUL 1 (rbp - 0xc) |> cmp <| UntouchedValueDomain.Touched
      irReg 0x32UL 1 Intel.RCX |> cmp <| UntouchedValueDomain.Touched
      irReg 0x35UL 1 Intel.RDX |> cmp <| UntouchedValueDomain.Touched
      irReg 0x38UL 1 Intel.RSI |> cmp <| UntouchedValueDomain.Touched
      irReg 0x3bUL 1 Intel.RAX |> cmp <| mkUntouchedReg Intel.RDI ]
    |> List.iter (fun (vp, ans) ->
      let out = (state :> IDataFlowState<_, _>).GetAbsValue vp
      Assert.AreEqual<UntouchedValueDomain.Lattice> (ans, out))
